/** Route tests for the OWASP GenAI STIX mirror. */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { aiCtiRouter } from '../../src/routes/ai-cti-feed-edge-tools';
import { _resetAiCtiCacheForTests } from '../../src/lib/ai-cti-feed-manifest';

const row = (id: string, name: string) => ({
  id,
  slug: id.split('--')[1] ?? id,
  name,
  category: 'A',
  created: null,
  labels: [],
  refCount: 1,
});
const INDEX = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'OWASP GenAI Threat Intelligence Initiative',
  sourceUrl: 'https://aithreatintelfeed.org/stix/threat-actors-ai-stix2.1.json',
  repoUrl: 'https://github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative',
  license: 'metadata only',
  counts: {
    objects: 2,
    actors: 1,
    techniques: 1,
    malware: 0,
    reports: 0,
    indicators: 1,
    relationships: 0,
    categoryA: 1,
    categoryB: 0,
  },
  actors: [row('intrusion-set--a', 'Actor A')],
  techniques: [row('attack-pattern--b', 'Technique B')],
  malware: [],
  reports: [],
  indicators: [{ id: 'indicator--c', name: 'IOC', category: 'A', labels: [], created: null }],
};

function env(): Env {
  return {
    ASSETS: {
      fetch: async () => new Response(JSON.stringify(INDEX), { headers: { 'content-type': 'application/json' } }),
    },
  } as unknown as Env;
}

function app(): Hono<{ Bindings: Env }> {
  const a = new Hono<{ Bindings: Env }>();
  a.route('/api/v1', aiCtiRouter);
  return a;
}

describe('AI-CTI routes', () => {
  it('index includes the lists the SPA renders', async () => {
    _resetAiCtiCacheForTests();
    const res = await app().request('/api/v1/ai-cti-feed/', {}, env());
    expect(res.status).toBe(200);
    const body = (await res.json()) as { actors: unknown[]; techniques: unknown[]; indicators: unknown[] };
    expect(body.actors).toHaveLength(1);
    expect(body.techniques).toHaveLength(1);
    expect(body.indicators).toHaveLength(1);
  });

  it('filters actors and exposes counts', async () => {
    _resetAiCtiCacheForTests();
    const a = app();
    const list = await a.request('/api/v1/ai-cti-feed/actors?category=A', {}, env());
    expect(((await list.json()) as { count: number }).count).toBe(1);
    const stats = await a.request('/api/v1/ai-cti-feed/stats', {}, env());
    expect(((await stats.json()) as { counts: { objects: number } }).counts.objects).toBe(2);
  });
});
