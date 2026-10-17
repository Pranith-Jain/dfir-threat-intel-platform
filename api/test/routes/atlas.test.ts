/**
 * GET /api/v1/atlas/technique.
 *
 * The upstream contract moved in 2026-10: the STIX JSON bundle 404s and the
 * data now ships as ATLAS v6 YAML behind a `ATLAS-latest.yaml` symlink whose
 * target raw.githubusercontent.com serves as plain text. These tests pin the
 * two-step resolution, the v6 index build (tactic via `relationships[].achieves`,
 * sub-techniques via `specializes`), and the error mapping.
 *
 * Ordering matters in this file: the route keeps an in-memory index cache for
 * a day, so the upstream-failure case runs BEFORE any successful fetch.
 */
import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';

const ATLAS_INDEX_KV_KEY = 'atlas:technique-index:v1';

const V6_YAML = `format-version: '6.0.0'
collection:
  name: ATLAS
tactics:
  AML.TA0002:
    name: Reconnaissance
techniques:
  AML.T0000:
    name: Search Open Technical Databases
    description: Adversaries may search for publicly available research.
  AML.T0000.000:
    name: Journals and Conference Proceedings
    description: Papers accepted at conferences.
  AML.T0005:
    name: Create Proxy AI Model
    description: Proxy models.
relationships:
  AML.T0000:
    achieves:
    - source: AML.T0000
      target: AML.TA0002
      relationship-type: achieves
  AML.T0000.000:
    achieves:
    - source: AML.T0000.000
      target: AML.TA0002
    specializes:
    - source: AML.T0000.000
      target: AML.T0000
  AML.T0005: {}
`;

function urlOf(input: Request | string | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** Mock the pointer fetch + the versioned YAML fetch. */
function mockAtlasUpstream(doc: string, pointerBody = 'ATLAS-2026.09.yaml') {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = urlOf(input as Request | string | URL);
    if (url.includes('/dist/v6/ATLAS-latest.yaml')) {
      return new Response(pointerBody, { status: 200 });
    }
    if (url.includes('/dist/v6/ATLAS-2026.09.yaml')) {
      return new Response(doc, { status: 200 });
    }
    return new Response(`unexpected upstream ${url}`, { status: 500 });
  });
}

describe('GET /api/v1/atlas/technique', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects missing param', async () => {
    const r = await SELF.fetch('https://x/api/v1/atlas/technique');
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error?: string };
    expect(body.error).toContain('missing');
  });

  it('rejects invalid technique ID format', async () => {
    const r = await SELF.fetch('https://x/api/v1/atlas/technique?technique=invalid');
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error?: string };
    expect(body.error).toContain('invalid');
  });

  it('maps an unreachable upstream to atlas_upstream 502 (must run before the success case)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('nope', { status: 503 }));
    const r = await SELF.fetch('https://x/api/v1/atlas/technique?technique=AML.T0000');
    expect(r.status).toBe(502);
    const body = (await r.json()) as { error?: string; upstream?: string; upstream_status?: number };
    expect(body.error).toBe('atlas_upstream');
    expect(body.upstream).toBe('raw.githubusercontent.com');
    expect(body.upstream_status).toBe(503);
  });

  it('resolves the pointer, parses v6 YAML, and serves the technique', async () => {
    if (env.KV_CACHE) await env.KV_CACHE.delete(ATLAS_INDEX_KV_KEY);
    mockAtlasUpstream(V6_YAML);
    const r = await SELF.fetch('https://x/api/v1/atlas/technique?technique=AML-T0000');
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      technique: { id: string; name: string; tactic: string | null; tacticId: string | null; url: string };
      relatedTechniques: string[];
    };
    expect(body.technique.id).toBe('AML-T0000');
    expect(body.technique.name).toBe('Search Open Technical Databases');
    expect(body.technique.tactic).toBe('Reconnaissance');
    expect(body.technique.tacticId).toBe('AML.TA0002');
    expect(body.technique.url).toContain('/techniques/AML-T0000');
    // Sub-techniques found via `specializes`.
    expect(body.relatedTechniques).toContain('AML.T0000.000');
    // The extracted index lands in KV for the next isolate.
    if (env.KV_CACHE) {
      const cached = await env.KV_CACHE.get(ATLAS_INDEX_KV_KEY);
      expect(cached).toBeTruthy();
    }
  });

  it('returns the parent for a sub-technique (served from the cached index)', async () => {
    const r = await SELF.fetch('https://x/api/v1/atlas/technique?technique=AML.T0000.000');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { technique: { name: string }; relatedTechniques: string[] };
    expect(body.technique.name).toBe('Journals and Conference Proceedings');
    expect(body.relatedTechniques).toContain('AML.T0000');
  });

  it('404s for a technique absent from the document', async () => {
    const r = await SELF.fetch('https://x/api/v1/atlas/technique?technique=AML.T9999');
    expect(r.status).toBe(404);
  });
});
