/**
 * Sophon workbench route tests. The handlers run in a bare Hono app so the
 * global admin middleware is not involved; the DO namespace is mocked.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { sophonProfilesHandler, sophonInvestigateHandler } from '../../src/routes/agent';

function setup(): Hono<{ Bindings: Env }> {
  const app = new Hono<{ Bindings: Env }>();
  app.get('/api/v1/agent/sophon/profiles', sophonProfilesHandler);
  app.post('/api/v1/agent/sophon', sophonInvestigateHandler);
  return app;
}

function mockEnv(
  fetchImpl: (input: string | Request, init?: RequestInit) => Promise<Response> = async () =>
    Response.json({ ok: true })
): Env {
  const namespace = {
    idFromName: (_name: string) => 'stub-id' as unknown as DurableObjectId,
    get: () => ({ fetch: fetchImpl }),
  };
  return { INVESTIGATOR_AGENT: namespace } as unknown as Env;
}

beforeEach(() => vi.restoreAllMocks());

describe('GET /api/v1/agent/sophon/profiles', () => {
  it('returns ten method profiles and the workflow, with the attribution note', async () => {
    const res = await setup().request('/api/v1/agent/sophon/profiles', {}, mockEnv());
    expect(res.status).toBe(200);
    const body = (await res.json()) as { profiles: Array<{ id: string; specialists: string[] }>; workflow: string[] };
    expect(body.profiles).toHaveLength(10);
    expect(body.profiles.every((p) => p.specialists.length > 0)).toBe(true);
    expect(body.workflow).toEqual(['main', 'planner', 'worker', 'review', 'report']);
    expect(res.headers.get('cache-control')).toContain('max-age');
  });
});

describe('POST /api/v1/agent/sophon', () => {
  const post = (body: unknown, env = mockEnv()) =>
    setup().request(
      '/api/v1/agent/sophon',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      },
      env
    );

  it('rejects a missing query or scope before spending any LLM work', async () => {
    expect((await post({ query: '', missionScope: 'example.com' })).status).toBe(400);
    expect((await post({ query: 'assess', missionScope: '' })).status).toBe(400);
  });

  it('rejects a scope with no parseable target', async () => {
    const res = await post({ query: 'assess the web app', missionScope: 'please be careful' });
    expect(res.status).toBe(400);
  });

  it('starts a DO run with the profile, query type and mission scope', async () => {
    const seen: string[] = [];
    const env = mockEnv(async (_req, init) => {
      seen.push(String(init?.body ?? ''));
      return Response.json({ ok: true });
    });
    const res = await post({ query: 'scan example.com', missionScope: 'example.com', profile: 'web-pentest' }, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; profile: string; scopeTargets: number; status: string };
    expect(body.profile).toBe('web-pentest');
    expect(body.scopeTargets).toBeGreaterThan(0);
    expect(body.status).toBe('running');
    const forwarded = JSON.parse(seen[0]!) as {
      sophonProfile: string;
      missionScope: string;
      queryType: string;
      maxSteps: number;
    };
    expect(forwarded.sophonProfile).toBe('web-pentest');
    expect(forwarded.missionScope).toBe('example.com');
    expect(forwarded.queryType).toBe('domain');
    expect(forwarded.maxSteps).toBeGreaterThan(0);
  });

  it('suggests a profile when none is supplied', async () => {
    const seen: string[] = [];
    const env = mockEnv(async (_req, init) => {
      seen.push(String(init?.body ?? ''));
      return Response.json({ ok: true });
    });
    const res = await post({ query: 'review this APK', missionScope: '*.corp.test' }, env);
    expect(res.status).toBe(201);
    expect(((await res.json()) as { profile: string }).profile).toBe('mobile-reverse');
    expect((JSON.parse(seen[0]!) as { sophonProfile: string }).sophonProfile).toBe('mobile-reverse');
  });
});
