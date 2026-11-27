/** Route tests for the BlueTeam-Tools metadata catalog. */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { blueTeamToolsRouter } from '../../src/routes/blue-team-tools-edge-tools';
import { _resetBttCacheForTests } from '../../src/lib/blue-team-tools-manifest';

const INDEX = {
  generatedAt: '2026-11-27T00:00:00.000Z',
  source: 'BlueTeam-Tools',
  sourceUrl: 'https://github.com/A-poc/BlueTeam-Tools',
  license: 'metadata only',
  counts: { categories: 1, tools: 2, withLinks: 1 },
  categories: [{ name: 'Threat Hunting', statedCount: '2 tools', toolCount: 2, tools: ['hunt-io', 'validin'] }],
  tools: [
    {
      slug: 'hunt-io',
      name: 'hunt.io',
      category: 'Threat Hunting',
      summary: 'C2 hunting',
      url: 'https://hunt.io',
      upstreamUrl: 'https://example/a',
    },
    {
      slug: 'validin',
      name: 'Validin',
      category: 'Threat Hunting',
      summary: 'DNS pivots',
      url: null,
      upstreamUrl: 'https://example/b',
    },
  ],
};

function app(): Hono<{ Bindings: Env }> {
  const a = new Hono<{ Bindings: Env }>();
  a.route('/api/v1', blueTeamToolsRouter);
  return a;
}

function env(): Env {
  return {
    ASSETS: {
      fetch: async () => new Response(JSON.stringify(INDEX), { headers: { 'content-type': 'application/json' } }),
    },
  } as unknown as Env;
}

describe('blue-team-tools routes', () => {
  it('serves the slim index with counts', async () => {
    _resetBttCacheForTests();
    const res = await app().request('/api/v1/blue-team-tools/', {}, env());
    expect(res.status).toBe(200);
    const body = (await res.json()) as { counts: { tools: number }; tools: unknown[] };
    expect(body.counts.tools).toBe(2);
    expect(body.tools).toHaveLength(2);
  });

  it('filters tools and resolves a slug', async () => {
    _resetBttCacheForTests();
    const a = app();
    const filtered = await a.request('/api/v1/blue-team-tools/tools?linked=true', {}, env());
    expect(((await filtered.json()) as { count: number }).count).toBe(1);
    const one = await a.request('/api/v1/blue-team-tools/tools/hunt-io', {}, env());
    expect(((await one.json()) as { name: string }).name).toBe('hunt.io');
    const missing = await a.request('/api/v1/blue-team-tools/tools/missing', {}, env());
    expect(missing.status).toBe(404);
  });

  it('exposes stats with cache state', async () => {
    _resetBttCacheForTests();
    const res = await app().request('/api/v1/blue-team-tools/stats', {}, env());
    const body = (await res.json()) as { counts: { categories: number }; cache: { tools: number } };
    expect(body.counts.categories).toBe(1);
    expect(body.cache.tools).toBe(2);
  });
});
