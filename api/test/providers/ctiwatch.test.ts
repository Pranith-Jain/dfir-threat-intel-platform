import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ctiwatch } from '../../src/providers/ctiwatch';
import type { ProviderEnv } from '../../src/providers/types';
import { getCtiwatchSession } from '../../src/lib/ctiwatch';

vi.mock('../../src/lib/ctiwatch', () => ({
  getCtiwatchSession: vi.fn(async () => 'cti_anon_test_cookie'),
}));

const mockedSession = vi.mocked(getCtiwatchSession);

const env: ProviderEnv = {
  VT_API_KEY: '',
  ABUSEIPDB_API_KEY: '',
  SHODAN_API_KEY: '',
  CENSYS_PAT: '',
  CENSYS_ORG_ID: '',
  NETLAS_API_KEY: '',
  OTX_API_KEY: '',
  URLSCAN_API_KEY: '',
  HYBRID_ANALYSIS_API_KEY: '',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Live-shaped hit: a T-Pot honeypot observation (verified 2026-10-17). */
function hit(over: Record<string, unknown> = {}) {
  return {
    found: true,
    id: '4e144130-4e7d-49d4-8dbc-46921c16e0c4',
    type: 'ip',
    value: '47.88.5.56',
    confidence_score: 85,
    source_id: 'ab146ebd-9956-45d4-b768-f4287f8b8edb',
    threat_actor_id: null,
    first_seen: '2026-10-17T10:04:04.570Z',
    last_seen: '2026-10-17T10:04:04.570Z',
    is_active: true,
    tags: ['honeypot', 'tpot', 'p0f', 'suricata', 'fatt', 'h0neytr4p'],
    context: 'T-Pot honeypot: 9 hits; types=[P0f,Suricata,Fatt,H0neytr4p]; ports=[443]',
    metadata: null,
    source: { id: 'ab146ebd-9956-45d4-b768-f4287f8b8edb', name: 'T-Pot Honeypot', type: 'honeypot' },
    threat_actor: null,
    ...over,
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockedSession.mockClear();
  mockedSession.mockResolvedValue('cti_anon_test_cookie');
});

describe('ctiwatch adapter', () => {
  it('maps a high-confidence hit to malicious with upstream tags', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(hit()));
    const r = await ctiwatch({ type: 'ipv4', value: '47.88.5.56' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('ok');
    expect(r.source).toBe('ctiwatch');
    expect(r.score).toBe(85);
    expect(r.verdict).toBe('malicious');
    expect(r.tags).toContain('honeypot');
    expect(r.tags).toContain('ioc-db');
    expect(r.raw_summary).toMatchObject({
      found: true,
      confidence_score: 85,
      is_active: true,
      source_name: 'T-Pot Honeypot',
      source_type: 'honeypot',
    });
    expect(r.cached).toBe(false);
  });

  it('maps a mid-confidence hit to suspicious (found in DB is never clean)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse(
        hit({
          type: 'domain',
          value: 'sbhhe93865.workers.dev',
          confidence_score: 50,
          tags: ['threatfox', 'payload_delivery'],
          context: 'ThreatFox payload_delivery (php.shin_webshell)',
          source: { id: 'x', name: 'ThreatFox', type: 'api' },
        })
      )
    );
    const r = await ctiwatch({ type: 'domain', value: 'sbhhe93865.workers.dev' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('ok');
    expect(r.score).toBe(50);
    expect(r.verdict).toBe('suspicious');
    expect(r.tags).toContain('threatfox');
  });

  it('coerces a string confidence_score, like the live payload does', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(hit({ confidence_score: '72' })));
    const r = await ctiwatch({ type: 'ipv4', value: '47.88.5.56' }, env, AbortSignal.timeout(2000));
    expect(r.score).toBe(72);
    expect(r.verdict).toBe('malicious');
  });

  it('maps the documented miss (404 + found:false) to clean', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse({ found: false, value: '8.8.8.8' }, 404));
    const r = await ctiwatch({ type: 'ipv4', value: '8.8.8.8' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('ok');
    expect(r.score).toBe(0);
    expect(r.verdict).toBe('clean');
    expect(r.raw_summary).toMatchObject({ found: false });
  });

  it('treats a 200 without found:true as a clean miss', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse({ value: 'x.example' }));
    const r = await ctiwatch({ type: 'domain', value: 'x.example' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('ok');
    expect(r.verdict).toBe('clean');
  });

  it('replays the anonymous session cookie on the session path', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(hit()));
    await ctiwatch({ type: 'ipv4', value: '47.88.5.56' }, env, AbortSignal.timeout(2000));
    expect(mockedSession).toHaveBeenCalledOnce();
    const init = spy.mock.calls[0]?.[1] as RequestInit | undefined;
    expect((init?.headers as Record<string, string>).cookie).toBe('cti_anon=cti_anon_test_cookie');
    expect(String(spy.mock.calls[0]?.[0])).toContain('/api/v1/iocs/lookup?value=47.88.5.56');
  });

  it('prefers an API key over the session mint', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(hit()));
    await ctiwatch(
      { type: 'ipv4', value: '47.88.5.56' },
      { ...env, CTIWATCH_API_KEY: 'ctw_test_key' },
      AbortSignal.timeout(2000)
    );
    expect(mockedSession).not.toHaveBeenCalled();
    const init = spy.mock.calls[0]?.[1] as RequestInit | undefined;
    expect((init?.headers as Record<string, string>)['X-Api-Key']).toBe('ctw_test_key');
  });

  it('returns unsupported for non-IOC indicator types', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const r = await ctiwatch({ type: 'cve', value: 'CVE-2026-1234' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('unsupported');
    expect(spy).not.toHaveBeenCalled();
  });

  it('surfaces 429 and 401 as typed errors', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    spy.mockResolvedValueOnce(new Response('slow down', { status: 429 }));
    const limited = await ctiwatch({ type: 'ipv4', value: '1.2.3.4' }, env, AbortSignal.timeout(2000));
    expect(limited.status).toBe('error');
    expect(limited.error_code).toBe('rate_limited');

    spy.mockResolvedValueOnce(new Response('auth', { status: 401 }));
    const unauth = await ctiwatch({ type: 'ipv4', value: '1.2.3.4' }, env, AbortSignal.timeout(2000));
    expect(unauth.status).toBe('error');
    expect(unauth.error_code).toBe('unauthorized');
  });

  it('surfaces a parse failure as a typed error (not a false clean)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('not json', { status: 200, headers: { 'content-type': 'application/json' } })
    );
    const r = await ctiwatch({ type: 'ipv4', value: '1.2.3.4' }, env, AbortSignal.timeout(2000));
    expect(r.status).toBe('error');
    expect(r.error_code).toBe('parse');
  });
});
