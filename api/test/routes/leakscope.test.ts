/**
 * Tests for the LeakScope leak-index route.
 *
 *   GET /api/v1/threat-intel/leakscope
 *
 * The route reads the manifest through env.ASSETS, so it is stubbed with an
 * in-memory map (same approach as the dPhish route tests).
 *
 * What is worth pinning here is the search contract. The index holds
 * ~12k rows and the Worker does the searching, so the query, filter, sort
 * and pagination semantics are the whole surface — and they are the part
 * that is easy to get subtly wrong (a sort that silently ignores an
 * unknown column, a page number that is not clamped, a filter that matches
 * on a field nobody meant to search).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { leakScopeHandler } from '../../src/routes/osint-verticals';
import { clearLeakIntelCaches } from '../../src/lib/forum-intel-manifest';

function makeAssets() {
  const data = new Map<string, unknown>();

  data.set('/data/threat-intel/leakscope/index.json', {
    schemaVersion: 'leakscope-v1',
    source: 'LeakScope',
    sourceUrl: 'https://github.com/Ivancastl/LeakScope',
    description: 'Breach and dark-forum leak thread index — metadata only.',
    license: 'MIT (metadata index only)',
    syncedAt: '2026-10-20T00:00:00.000Z',
    counts: {
      total: 4,
      breach: 2,
      darkforum: 2,
      authors: 3,
      prefixes: 1,
      with_ransomware_note: 1,
    },
    entries: [
      {
        tid: '9001',
        source: 'darkforum',
        prefix: 'DATABASE',
        title: 'acme-corporate-hr-dump',
        author: 'LeakBase',
        published_at: '2026-10-18T10:00:00.000Z',
        replies: 4,
        views: 900,
        pages: 1,
        attachments: 0,
        last_post_at: '2026-10-19T10:00:00.000Z',
        last_post_by: 'LeakBase',
        status: 'New posts.',
      },
      {
        tid: '9002',
        source: 'darkforum',
        prefix: 'DATABASE',
        title: 'globex payroll spreadsheet',
        author: 'Tanaka',
        published_at: '2026-10-15T10:00:00.000Z',
        replies: 1,
        views: 150,
        pages: 1,
        attachments: 2,
        last_post_at: '2026-10-15T10:00:00.000Z',
        last_post_by: 'Tanaka',
        status: 'New posts.',
      },
      {
        tid: '9003',
        source: 'breach',
        prefix: null,
        title: 'initech customer records exposed',
        author: 'emo',
        published_at: '2026-10-20T10:00:00.000Z',
        replies: 12,
        views: 4200,
        pages: 2,
        attachments: 1,
        last_post_at: '2026-10-20T10:00:00.000Z',
        last_post_by: 'emo',
        status: 'no leido',
      },
      {
        tid: '9004',
        source: 'breach',
        prefix: null,
        title: 'ransomware payment log — acme',
        author: 'LeakBase',
        published_at: null,
        replies: 0,
        views: 30,
        pages: 1,
        attachments: 0,
        last_post_at: null,
        last_post_by: '',
        status: '',
      },
    ],
  });

  return {
    fetch: async (req: Request) => {
      const url = new URL(req.url);
      const hit = data.get(url.pathname);
      if (hit === undefined) return new Response('not found', { status: 404 });
      return new Response(JSON.stringify(hit), {
        headers: { 'content-type': 'application/json' },
      });
    },
  } as unknown as Fetcher;
}

function makeEnv(): Env {
  return { ASSETS: makeAssets() } as Env;
}

function setup() {
  const app = new Hono<{ Bindings: Env }>();
  app.get('/api/v1/threat-intel/leakscope', leakScopeHandler);
  return app;
}

beforeEach(() => {
  // The manifest loader caches in module state; clear it so each test sees
  // the stub it set up.
  clearLeakIntelCaches();
});

describe('LeakScope route', () => {
  it('returns the index metadata and the entries', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope', {}, makeEnv());
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      source: string;
      counts: Record<string, number>;
      total: number;
      entries: Array<{ tid: string; title: string; views: number }>;
    };
    expect(body.source).toBe('LeakScope');
    expect(body.counts.total).toBe(4);
    expect(body.total).toBe(4);
    expect(body.entries).toHaveLength(4);
  });

  it('sorts newest-first by default', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope', {}, makeEnv());
    const body = (await r.json()) as { entries: Array<{ tid: string }> };
    // 2026-10-20, 2026-10-18, 2026-10-15, then the undated one.
    expect(body.entries.map((e) => e.tid)).toEqual(['9003', '9001', '9002', '9004']);
  });

  it('sorts by views when asked', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?sort=views', {}, makeEnv());
    const body = (await r.json()) as { entries: Array<{ tid: string }> };
    expect(body.entries.map((e) => e.tid)).toEqual(['9003', '9001', '9002', '9004']);
  });

  it('sorts by views ascending when asked', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?sort=views&dir=asc', {}, makeEnv());
    const body = (await r.json()) as { entries: Array<{ tid: string }> };
    expect(body.entries.map((e) => e.tid)).toEqual(['9004', '9002', '9001', '9003']);
  });

  it('falls back to the default sort for an unknown column', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?sort=notacolumn', {}, makeEnv());
    const body = (await r.json()) as { entries: Array<{ tid: string }> };
    expect(body.entries.map((e) => e.tid)).toEqual(['9003', '9001', '9002', '9004']);
  });

  it('filters by source', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?source=breach', {}, makeEnv());
    const body = (await r.json()) as { total: number; entries: Array<{ source: string }> };
    expect(body.total).toBe(2);
    expect(body.entries.every((e) => e.source === 'breach')).toBe(true);
  });

  it('searches the title', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=globex', {}, makeEnv());
    const body = (await r.json()) as { total: number; entries: Array<{ title: string }> };
    expect(body.total).toBe(1);
    expect(body.entries[0]?.title).toBe('globex payroll spreadsheet');
  });

  it('searches the author', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=tanaka', {}, makeEnv());
    const body = (await r.json()) as { total: number };
    expect(body.total).toBe(1);
  });

  it('searches the prefix', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=database', {}, makeEnv());
    const body = (await r.json()) as { total: number };
    expect(body.total).toBe(2);
  });

  it('is case-insensitive', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=GLOBEX', {}, makeEnv());
    const body = (await r.json()) as { total: number };
    expect(body.total).toBe(1);
  });

  it('combines a query with a source filter', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=acme&source=breach', {}, makeEnv());
    const body = (await r.json()) as { total: number; entries: Array<{ tid: string }> };
    expect(body.total).toBe(1);
    expect(body.entries[0]?.tid).toBe('9004');
  });

  it('returns an empty result set rather than an error for no match', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?q=zzzznope', {}, makeEnv());
    expect(r.status).toBe(200);
    const body = (await r.json()) as { total: number; entries: unknown[] };
    expect(body.total).toBe(0);
    expect(body.entries).toEqual([]);
  });

  it('paginates', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?limit=2&page=2', {}, makeEnv());
    const body = (await r.json()) as { total: number; page: number; pages: number; limit: number };
    expect(body.total).toBe(4);
    expect(body.pages).toBe(2);
    expect(body.page).toBe(2);
    expect(body.limit).toBe(2);
  });

  it('clamps a page number past the end', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?page=99', {}, makeEnv());
    const body = (await r.json()) as { page: number; pages: number };
    expect(body.page).toBe(body.pages);
  });

  it('clamps a negative page number to 1', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?page=-5', {}, makeEnv());
    const body = (await r.json()) as { page: number };
    expect(body.page).toBe(1);
  });

  it('clamps the limit to 200', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope?limit=100000', {}, makeEnv());
    const body = (await r.json()) as { limit: number };
    expect(body.limit).toBe(200);
  });

  it('never surfaces a URL to the leak', async () => {
    const r = await setup().request('/api/v1/threat-intel/leakscope', {}, makeEnv());
    const body = (await r.json()) as {
      source_url: string;
      entries: Array<Record<string, unknown>>;
    };

    // No entry may carry a URL-shaped key, and no entry value may look like
    // a URL. The one URL in the whole response is `source_url` — the GitHub
    // repository of the *tool*, which is the same thing the upstream app
    // shows and links to nothing that was leaked.
    for (const entry of body.entries) {
      for (const key of Object.keys(entry)) {
        expect(key).not.toMatch(/url|href|link/i);
      }
      for (const value of Object.values(entry)) {
        if (typeof value === 'string') {
          expect(value).not.toMatch(/https?:\/\//i);
        }
      }
    }
    expect(body.source_url).toBe('https://github.com/Ivancastl/LeakScope');
  });

  it('503s when the manifest has not been built', async () => {
    const env = { ASSETS: { fetch: async () => new Response('nope', { status: 404 }) } } as unknown as Env;
    const r = await setup().request('/api/v1/threat-intel/leakscope', {}, env);
    expect(r.status).toBe(503);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe('leakscope_unavailable');
  });
});
