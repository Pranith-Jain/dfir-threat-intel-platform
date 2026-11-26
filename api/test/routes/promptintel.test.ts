/**
 * PromptIntel routes — the keyless mirror surface and the key gate.
 *
 * The mirror is read from a mocked ASSETS fetcher (the committed
 * public/data/promptintel/ tree in production). `caches.default` comes from
 * the Workers pool, so `kvBackedGet`/`kvBackedPut` work without a stub.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import {
  promptintelTaxonomyHandler,
  promptintelEntryHandler,
  promptintelMappingsHandler,
  promptintelTranslateHandler,
  promptintelFrameworksHandler,
  promptintelPromptsHandler,
  promptintelCheckGetHandler,
  promptintelArtifactLookupHandler,
  promptintelQuotaHandler,
} from '../../src/routes/promptintel';
import { _resetPromptIntelCacheForTests } from '../../src/lib/promptintel-manifest';

const INDEX = {
  source: 'PromptIntel',
  sourceUrl: 'https://promptintel.securitybreak.io/taxonomy/',
  license: 'metadata mirrored with attribution',
  syncedAt: '2026-11-26T00:00:00.000Z',
  taxonomyVersion: '2.2.0',
  counts: { domains: 2, techniques: 2, frameworks: 2, mappings: 3 },
  frameworks: [
    { name: 'OWASP Top 10 for LLM Applications', version: '2026', url: 'https://genai.owasp.org/llm-top-10/' },
    { name: 'MITRE ATLAS', version: '2026.10', url: 'https://atlas.mitre.org/' },
  ],
  domains: [
    { id: 'T1', name: 'Instruction & Input Injection', description: 'Injection.', techniques: ['IOPC-T1.001'] },
    { id: 'T5', name: 'Disclosure & Output Integrity', description: 'Disclosure.', techniques: ['IOPC-T5.001'] },
  ],
  entries: [
    {
      id: 'IOPC-T1.001',
      name: 'Direct Prompt Injection',
      domain: 'T1',
      domainName: 'Instruction & Input Injection',
      summary: 'Attacker-authored instructions in direct input.',
      url: 'https://promptintel.securitybreak.io/taxonomy/IOPC-T1.001/',
      maturity: 'active',
      evidence: 'mixed',
      reviewed: '2026-11-12',
      frameworks: ['OWASP Top 10 for LLM Applications', 'MITRE ATLAS'],
      mappingCount: 2,
    },
    {
      id: 'IOPC-T5.001',
      name: 'System Prompt Disclosure',
      domain: 'T5',
      domainName: 'Disclosure & Output Integrity',
      summary: 'The system prompt is revealed.',
      url: 'https://promptintel.securitybreak.io/taxonomy/IOPC-T5.001/',
      maturity: 'experimental',
      evidence: null,
      reviewed: null,
      frameworks: ['OWASP Top 10 for LLM Applications'],
      mappingCount: 1,
    },
  ],
  mappings: [
    {
      entry: 'IOPC-T1.001',
      name: 'Direct Prompt Injection',
      domain: 'T1',
      framework: 'OWASP Top 10 for LLM Applications',
      ref: 'LLM01',
      item: 'Prompt Injection',
      relationship: 'narrower_than',
    },
    {
      entry: 'IOPC-T1.001',
      name: 'Direct Prompt Injection',
      domain: 'T1',
      framework: 'MITRE ATLAS',
      ref: 'AML.T0051',
      item: 'LLM Prompt Injection',
      relationship: 'narrower_than',
    },
    {
      entry: 'IOPC-T5.001',
      name: 'System Prompt Disclosure',
      domain: 'T5',
      framework: 'OWASP Top 10 for LLM Applications',
      ref: 'LLM07',
      item: 'System Prompt Leakage',
      relationship: 'related',
    },
  ],
};

const ENTRY = {
  id: 'IOPC-T1.001',
  name: 'Direct Prompt Injection',
  domain: 'T1',
  domainName: 'Instruction & Input Injection',
  description: 'Attacker-authored instructions supplied directly.',
  differs: 'Canonical form of IOPC-R001.',
  maturity: 'active',
  evidence: 'mixed',
  reviewed: '2026-11-12',
  statusLine: 'active, evidence: mixed, reviewed 2026-11-12.',
  mappings: INDEX.mappings
    .slice(0, 2)
    .map((m) => ({ framework: m.framework, ref: m.ref, name: m.item, relationship: m.relationship })),
  url: 'https://promptintel.securitybreak.io/taxonomy/IOPC-T1.001/',
};

function assets(): Fetcher {
  const files: Record<string, unknown> = {
    '/data/promptintel/index.json': INDEX,
    '/data/promptintel/entries/IOPC-T1.001.json': ENTRY,
  };
  return {
    fetch: async (req: Request) => {
      const path = new URL(req.url).pathname;
      const data = files[path];
      if (!data) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

function setup(): Hono<{ Bindings: Env }> {
  const app = new Hono<{ Bindings: Env }>();
  app.get('/api/v1/promptintel/taxonomy', promptintelTaxonomyHandler);
  app.get('/api/v1/promptintel/taxonomy/entries/:id', promptintelEntryHandler);
  app.get('/api/v1/promptintel/taxonomy/mappings', promptintelMappingsHandler);
  app.get('/api/v1/promptintel/taxonomy/translate', promptintelTranslateHandler);
  app.get('/api/v1/promptintel/frameworks', promptintelFrameworksHandler);
  app.get('/api/v1/promptintel/prompts', promptintelPromptsHandler);
  app.get('/api/v1/promptintel/check', promptintelCheckGetHandler);
  app.get('/api/v1/promptintel/artifacts/lookup', promptintelArtifactLookupHandler);
  app.get('/api/v1/promptintel/quota', promptintelQuotaHandler);
  return app;
}

function mockCtx(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
}

function env(key = false): Env {
  return { ASSETS: assets(), ...(key ? { PROMPTINTEL_API_KEY: 'test-key' } : {}) } as unknown as Env;
}

beforeEach(() => {
  _resetPromptIntelCacheForTests();
  vi.restoreAllMocks();
});

describe('PromptIntel keyless mirror', () => {
  it('serves the taxonomy with no key and tags the source', async () => {
    const res = await setup().request('/api/v1/promptintel/taxonomy', {}, env(), mockCtx());
    expect(res.status).toBe(200);
    expect(res.headers.get('x-source')).toBe('promptintel-mirror');
    const body = (await res.json()) as typeof INDEX;
    expect(body.taxonomyVersion).toBe('2.2.0');
    expect(body.entries).toHaveLength(2);
    expect(body.mappings).toHaveLength(3);
  });

  it('filters by domain and keyword', async () => {
    const app = setup();
    const byDomain = await app.request('/api/v1/promptintel/taxonomy?domain=t5', {}, env(), mockCtx());
    expect(((await byDomain.json()) as typeof INDEX).entries.map((e) => e.id)).toEqual(['IOPC-T5.001']);
    const byQ = await app.request('/api/v1/promptintel/taxonomy?q=atlas', {}, env(), mockCtx());
    expect(((await byQ.json()) as typeof INDEX).entries.map((e) => e.id)).toEqual(['IOPC-T1.001']);
  });

  it('returns one entry body, but refuses a non-IoPC id before it reaches ASSETS', async () => {
    const app = setup();
    const ok = await app.request('/api/v1/promptintel/taxonomy/entries/iopc-t1.001', {}, env(), mockCtx());
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as typeof ENTRY).mappings).toHaveLength(2);
    const bad = await app.request('/api/v1/promptintel/taxonomy/entries/..%2F..%2Fetc', {}, env(), mockCtx());
    expect(bad.status).toBe(400);
    expect((await bad.json()) as { error: string }).toHaveProperty('error', 'bad_entry_id');
  });

  it('filters the flat mapping table by framework and ref, accepting framework ids', async () => {
    const res = await setup().request(
      '/api/v1/promptintel/taxonomy/mappings?framework=MITRE_ATLAS&ref=AML.T0051',
      {},
      env(),
      mockCtx()
    );
    const body = (await res.json()) as { count: number; mappings: typeof INDEX.mappings };
    expect(body.count).toBe(1); // MITRE_ATLAS is an alias for the mirror's human-readable name
    expect(body.mappings[0]!.entry).toBe('IOPC-T1.001');
    const byRef = await setup().request('/api/v1/promptintel/taxonomy/mappings?ref=aml.t0051', {}, env(), mockCtx());
    expect(((await byRef.json()) as { count: number }).count).toBe(1);
  });

  it('translates a framework item across IoPC into the other frameworks', async () => {
    const res = await setup().request(
      '/api/v1/promptintel/taxonomy/translate?framework=OWASP%20Top%2010%20for%20LLM%20Applications&ref=LLM01',
      {},
      env(),
      mockCtx()
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { source: { ref: string }; matches: Array<{ ref: string; via: string[] }> };
    expect(body.source.ref).toBe('LLM01');
    expect(body.matches.map((m) => m.ref)).toContain('AML.T0051');
    expect(body.matches.find((m) => m.ref === 'AML.T0051')?.via).toContain('IOPC-T1.001');
  });

  it('narrows translation to one target framework', async () => {
    const res = await setup().request(
      '/api/v1/promptintel/taxonomy/translate?framework=OWASP%20Top%2010%20for%20LLM%20Applications&ref=LLM01&to=MITRE%20ATLAS',
      {},
      env(),
      mockCtx()
    );
    const body = (await res.json()) as { matches: Array<{ framework: string }> };
    expect(body.matches).toHaveLength(1);
    expect(body.matches[0]!.framework).toBe('MITRE ATLAS');
  });

  it('rejects a translate call without framework and ref', async () => {
    const res = await setup().request('/api/v1/promptintel/taxonomy/translate', {}, env(), mockCtx());
    expect(res.status).toBe(400);
  });

  it('serves the framework list', async () => {
    const res = await setup().request('/api/v1/promptintel/frameworks', {}, env(), mockCtx());
    expect(((await res.json()) as { frameworks: unknown[] }).frameworks).toHaveLength(2);
  });
});

describe('PromptIntel keyed routes', () => {
  it('returns a setup hint, not a generic 502, when no key is configured', async () => {
    const app = setup();
    for (const path of [
      '/api/v1/promptintel/prompts',
      '/api/v1/promptintel/check?value=x',
      '/api/v1/promptintel/quota',
    ]) {
      const res = await app.request(path, {}, env(), mockCtx());
      expect(res.status).toBe(501);
      expect((await res.json()) as { error: string }).toHaveProperty('error', 'promptintel_key_missing');
    }
  });

  it('validates hash and indicator inputs before spending an upstream request', async () => {
    const app = setup();
    expect(
      (await app.request('/api/v1/promptintel/artifacts/lookup?sha256=not-a-hash', {}, env(true), mockCtx())).status
    ).toBe(400);
    expect((await app.request('/api/v1/promptintel/check', {}, env(true), mockCtx())).status).toBe(400);
  });

  it('accepts repeated sha256 parameters as well as comma-separated ones', async () => {
    const a = 'a'.repeat(64);
    const b = 'b'.repeat(64);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
    vi.stubGlobal('fetch', fetchMock);
    const res = await setup().request(
      `/api/v1/promptintel/artifacts/lookup?sha256=${a}&sha256=${b}`,
      {},
      env(true),
      mockCtx()
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining(`sha256=${a}%2C${b}`), expect.anything());
  });

  it('rejects a wrong API host response instead of parsing HTML as JSON', async () => {
    // Simulates the old NovaHunting host returning an HTML redirect: the
    // upstream helper keeps the text, and the route surfaces a 502 rather
    // than silently returning an empty feed.
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response('<html>301 moved</html>', { status: 301, headers: { 'content-type': 'text/html' } })
      );
    vi.stubGlobal('fetch', fetchMock);
    const res = await setup().request('/api/v1/promptintel/prompts', {}, env(true), mockCtx());
    expect(res.status).toBe(502);
    expect((await res.json()) as { error: string }).toHaveProperty('error', 'upstream_redirect');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('https://api.promptintel.securitybreak.io/api/v1/prompts'),
      expect.anything()
    );
  });
});
