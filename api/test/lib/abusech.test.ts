import { describe, it, expect } from 'vitest';
import {
  LEGACY_ABUSECH_URLS,
  THREATFOX_API_URL,
  THREATFOX_MAX_DAYS,
  abuseChHeaders,
  abuseChExportUrl,
  abuseChApiUrl,
  abuseChFeedRequest,
  abuseChFeedRequestForEnv,
  fetchThreatfoxExport,
  looksLikeJson,
} from '../../src/lib/abusech';
import type { Env } from '../../src/env';

// ─── abuseChHeaders ─────────────────────────────────────────────────────────

describe('abuseChHeaders', () => {
  it('adds Auth-Key only when a key is present', () => {
    expect(abuseChHeaders('k1')).toEqual({ 'Auth-Key': 'k1' });
    expect(abuseChHeaders()).toEqual({});
    expect(abuseChHeaders('')).toEqual({});
  });

  it('merges caller headers instead of replacing them', () => {
    const h = abuseChHeaders('k1', { 'Content-Type': 'application/json', 'user-agent': 'x' });
    expect(h).toEqual({ 'Auth-Key': 'k1', 'Content-Type': 'application/json', 'user-agent': 'x' });
  });

  it('lets the caller override Auth-Key explicitly', () => {
    const h = abuseChHeaders('k1', { 'Auth-Key': 'override' });
    expect(h['Auth-Key']).toBe('override');
  });

  it('accepts Headers instances and arrays', () => {
    expect(abuseChHeaders('k', new Headers({ a: 'b' }))).toEqual({ 'Auth-Key': 'k', a: 'b' });
    expect(abuseChHeaders('k', [['a', 'b']])).toEqual({ 'Auth-Key': 'k', a: 'b' });
  });
});

// ─── abuseChExportUrl / abuseChApiUrl ───────────────────────────────────────

describe('abuseChExportUrl', () => {
  it('embeds the key in the path for the v2 file exports', () => {
    expect(abuseChExportUrl('urlhaus', 'KEY')).toBe('https://urlhaus-api.abuse.ch/v2/files/exports/KEY/recent.csv');
    expect(abuseChExportUrl('malwarebazaar', 'KEY')).toBe('https://mb-api.abuse.ch/v2/files/exports/KEY/recent.csv');
  });

  it('encodes the key as a single path segment', () => {
    const url = abuseChExportUrl('urlhaus', 'a/b c');
    expect(url).toContain('/files/exports/a%2Fb%20c/recent.csv');
  });

  it('falls back to the legacy anonymous export without a key', () => {
    expect(abuseChExportUrl('urlhaus')).toBe(LEGACY_ABUSECH_URLS.urlhaus);
    expect(abuseChExportUrl('malwarebazaar', '')).toBe(LEGACY_ABUSECH_URLS.malwarebazaar);
  });
});

describe('abuseChApiUrl', () => {
  it('returns the JSON API endpoints with a key', () => {
    expect(abuseChApiUrl('threatfox', 'K')).toBe(THREATFOX_API_URL);
    expect(abuseChApiUrl('malwarebazaar', 'K')).toBe('https://mb-api.abuse.ch/api/v1/');
    expect(abuseChApiUrl('urlhaus', 'K')).toBe('https://urlhaus-api.abuse.ch/v2/');
  });

  it('returns the legacy anonymous endpoints without a key', () => {
    expect(abuseChApiUrl('threatfox')).toBe(LEGACY_ABUSECH_URLS.threatfox);
    expect(abuseChApiUrl('malwarebazaar')).toBe(LEGACY_ABUSECH_URLS.malwarebazaar);
    expect(abuseChApiUrl('urlhaus')).toBe(LEGACY_ABUSECH_URLS.urlhaus);
  });
});

// ─── abuseChFeedRequest ─────────────────────────────────────────────────────

describe('abuseChFeedRequest', () => {
  it('builds an authenticated GET for the urlhaus CSV export', () => {
    const req = abuseChFeedRequest('urlhaus', 'KEY');
    expect(req.url).toBe('https://urlhaus-api.abuse.ch/v2/files/exports/KEY/recent.csv');
    expect(req.init.method).toBeUndefined();
    expect((req.init.headers as Record<string, string>)['Auth-Key']).toBe('KEY');
    expect(req.init.body).toBeUndefined();
  });

  it('builds the ThreatFox JSON POST with the Auth-Key header', () => {
    const req = abuseChFeedRequest('threatfox', 'KEY', { days: 3 });
    expect(req.url).toBe(THREATFOX_API_URL);
    expect(req.init.method).toBe('POST');
    expect((req.init.headers as Record<string, string>)['Auth-Key']).toBe('KEY');
    expect((req.init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    expect(JSON.parse(String(req.init.body))).toEqual({ query: 'get_iocs', days: 3 });
  });

  it('clamps the ThreatFox window to the upstream 7-day max', () => {
    expect(JSON.parse(String(abuseChFeedRequest('threatfox', 'K', { days: 99 }).init.body)).days).toBe(
      THREATFOX_MAX_DAYS
    );
    expect(JSON.parse(String(abuseChFeedRequest('threatfox', 'K', { days: 0 }).init.body)).days).toBe(1);
    // Default = max window.
    expect(JSON.parse(String(abuseChFeedRequest('threatfox', 'K').init.body)).days).toBe(THREATFOX_MAX_DAYS);
  });

  it('without a key, resolves to the legacy anonymous URL (loud 410, not silence)', () => {
    const req = abuseChFeedRequest('threatfox');
    expect(req.url).toBe(LEGACY_ABUSECH_URLS.threatfox);
    expect(req.init.method).toBeUndefined();
    expect((req.init.headers as Record<string, string>)['Auth-Key']).toBeUndefined();
  });

  it('passes caller init through and merges its headers last', () => {
    const req = abuseChFeedRequest('malwarebazaar', 'K', { init: { headers: { 'x-trace': '1' } } });
    const headers = req.init.headers as Record<string, string>;
    expect(headers['Auth-Key']).toBe('K');
    expect(headers['x-trace']).toBe('1');
  });
});

describe('abuseChFeedRequestForEnv', () => {
  it('reads ABUSECH_AUTH_KEY off the env', () => {
    const env = { ABUSECH_AUTH_KEY: 'ENVKEY' } as Env;
    const req = abuseChFeedRequestForEnv(env, 'malwarebazaar');
    expect(req.url).toBe('https://mb-api.abuse.ch/v2/files/exports/ENVKEY/recent.csv');
  });

  it('falls back to the legacy URL for an undefined env', () => {
    const req = abuseChFeedRequestForEnv(undefined, 'urlhaus');
    expect(req.url).toBe(LEGACY_ABUSECH_URLS.urlhaus);
  });
});

// ─── fetchThreatfoxExport ───────────────────────────────────────────────────

describe('fetchThreatfoxExport', () => {
  const jsonBody = JSON.stringify({ query_status: 'ok', data: [] });

  it('POSTs get_iocs to the JSON API and returns the body text', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(jsonBody, { status: 200 });
    }) as typeof globalThis.fetch;

    const body = await fetchThreatfoxExport('KEY', { fetchImpl });
    expect(body).toBe(jsonBody);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(THREATFOX_API_URL);
    expect(calls[0]!.init.method).toBe('POST');
    expect((calls[0]!.init.headers as Record<string, string>)['Auth-Key']).toBe('KEY');
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ query: 'get_iocs', days: THREATFOX_MAX_DAYS });
  });

  it('throws on upstream errors so callers can fall back to last-good data', async () => {
    const fetchImpl = (async () => new Response('gone', { status: 410 })) as typeof globalThis.fetch;
    await expect(fetchThreatfoxExport('KEY', { fetchImpl })).rejects.toThrow('threatfox feed 410');
  });

  it('throws on an empty 200 body', async () => {
    const fetchImpl = (async () => new Response('  ', { status: 200 })) as typeof globalThis.fetch;
    await expect(fetchThreatfoxExport('KEY', { fetchImpl })).rejects.toThrow('empty body');
  });
});

// ─── looksLikeJson ──────────────────────────────────────────────────────────

describe('looksLikeJson', () => {
  it('detects JSON objects and arrays, ignoring leading whitespace', () => {
    expect(looksLikeJson('{"query_status":"ok"}')).toBe(true);
    expect(looksLikeJson('\n\t [1,2]')).toBe(true);
    expect(looksLikeJson('# metadata comment\n"id","url"')).toBe(false);
    expect(looksLikeJson('"first_seen","sha256"')).toBe(false);
    expect(looksLikeJson('')).toBe(false);
  });
});
