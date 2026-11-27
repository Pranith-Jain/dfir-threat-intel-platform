/** Route tests for the PRTF CC BY 4.0 mirror. */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { prtfRouter } from '../../src/routes/prtf-edge-tools';
import { _resetPrtfCacheForTests } from '../../src/lib/prtf-manifest';

const INDEX = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'PRTF',
  sourceUrl: 'https://redteam.vip/prtf/',
  license: 'CC BY 4.0',
  version: '1.1',
  counts: { tactics: 1, techniques: 1 },
  tactics: [{ id: 'PRTF-1', name: 'Reconnaissance', description: 'Gather info', count: 1 }],
  techniques: [
    {
      id: 'PRTF-1.01',
      name: 'OSINT',
      tacticId: 'PRTF-1',
      tacticName: 'Reconnaissance',
      summary: 'Public sources',
      toolCount: 1,
      url: 'https://redteam.vip/prtf/#PRTF-1.01',
    },
  ],
};
const BODY = { ...INDEX.techniques[0], description: 'full', tools: [], chains: [], blue: null };

function env(): Env {
  return {
    ASSETS: {
      fetch: async (req: Request) => {
        const p = new URL(req.url).pathname;
        const body = p.endsWith('/index.json') ? INDEX : p.endsWith('PRTF-1.01.json') ? BODY : null;
        return body
          ? new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
          : new Response(null, { status: 404 });
      },
    },
  } as unknown as Env;
}

function app(): Hono<{ Bindings: Env }> {
  const a = new Hono<{ Bindings: Env }>();
  a.route('/api/v1', prtfRouter);
  return a;
}

describe('PRTF routes', () => {
  it('serves index, tactics and filtered techniques', async () => {
    _resetPrtfCacheForTests();
    const a = app();
    const index = await a.request('/api/v1/prtf/', {}, env());
    expect(((await index.json()) as { counts: { techniques: number } }).counts.techniques).toBe(1);
    const list = await a.request('/api/v1/prtf/techniques?q=osint', {}, env());
    expect(((await list.json()) as { count: number }).count).toBe(1);
  });

  it('validates the id and serves a technique body', async () => {
    _resetPrtfCacheForTests();
    const a = app();
    expect((await a.request('/api/v1/prtf/techniques/CVE-2026-1', {}, env())).status).toBe(400);
    const one = await a.request('/api/v1/prtf/techniques/PRTF-1.01', {}, env());
    expect(((await one.json()) as { description: string }).description).toBe('full');
  });

  it('reports stats and attribution', async () => {
    _resetPrtfCacheForTests();
    const res = await app().request('/api/v1/prtf/stats', {}, env());
    const body = (await res.json()) as { license: string; counts: { tactics: number } };
    expect(body.license).toBe('CC BY 4.0');
    expect(body.counts.tactics).toBe(1);
  });
});
