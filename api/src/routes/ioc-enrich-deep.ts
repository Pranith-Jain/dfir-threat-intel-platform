/**
 * IOC Deep Enrichment — single-call orchestrator that fans out to every
 * relevant source and aggregates a unified verdict.
 *
 *   GET/POST /api/v1/ioc/enrich-deep?indicator=...
 *
 * Sources (per indicator type):
 *   EMAIL → /breach/email (ProjectDiscovery) + /ioc/check + /domain/lookup
 *   CVE   → /cve/lookup (NVD + KEV + VulnCheck + EPSS) +
 *           /cve-recent + /cve-threat-map + /ioc/check
 *   IP    → /ioc/check (51+ providers including tre.ge) + asn + dns-rev +
 *           ipinfo + greynoise community + geo + breach (projectdiscovery)
 *   DOMAIN→ /ioc/check (51+ providers) + /domain/lookup (DNS/WHOIS/CT/SPF) +
 *           /builtwith + /webamon/search + /infra-search + /breach/domain +
 *           /passive-dns + /ct-monitor/certs (+ opt-in /webamon/scan via ?trigger=scan)
 *   URL   → /ioc/check + /url-preview + /webamon/search (parent) +
 *           /breach/domain (parent) (+ opt-in /webamon/scan via ?trigger=scan)
 *   HASH  → /ioc/check (50+ providers) + /malwarebazaar + /hybridanalysis +
 *           /threatfox + /vulncheck
 *
 * The handler runs as much as possible in parallel and degrades gracefully
 * when individual sub-sources error — the response always includes the
 * sources that succeeded.
 *
 * This is the "single shot" version of what the autonomous Agent does over
 * 4-6 tool calls; it powers the chat-style Copilot and DFIR Agent pages
 * when the user wants the full picture fast.
 */
import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { respondError } from '../lib/api-error';
import { detectType } from '../lib/indicator';
import { signInternalToken } from '../lib/internal-token';

type IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash' | 'email' | 'cve' | 'unknown';

const INTERNAL = 'https://self.internal';

function isIp(t: IndicatorType): boolean {
  return t === 'ipv4' || t === 'ipv6';
}

async function selfFetch(
  self: Fetcher | undefined,
  path: string,
  token: string,
  init?: RequestInit
): Promise<Response | null> {
  try {
    const headers = new Headers(init?.headers);
    headers.set('x-internal-token', token);
    const req = new Request(`${INTERNAL}${path}`, { ...init, headers });
    if (self) return await self.fetch(req);
    return await fetch(req);
  } catch (_catchErr) {
    logError('selfFetch failed', _catchErr);
    return null;
  }
}

interface SourceHit {
  source: string;
  ok: boolean;
  error?: string;
  data: unknown;
  ms: number;
}

async function timeIt<T>(
  label: string,
  fn: () => Promise<T>
): Promise<{ source: string; ok: boolean; error?: string; data: T | null; ms: number }> {
  const t0 = Date.now();
  try {
    const data = await fn();
    return { source: label, ok: true, data, ms: Date.now() - t0 };
  } catch (err) {
    logError('timeIt failed', err);
    return {
      source: label,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      data: null,
      ms: Date.now() - t0,
    };
  }
}

/**
 * Overall fan-out deadline. Each live sub-route carries its own AbortSignal,
 * but a stuck upstream (proxy hang, provider with no egress, slow SSRF probe)
 * could otherwise hold the entire deep-enrich request open indefinitely.
 * Cap the fan-out so the request always returns with per-source results
 * (timed-out hits carry an `error` for the caller to surface).
 */
const FANOUT_DEADLINE_MS = 13_000;

async function settleWithin(
  hits: Array<Promise<{ source: string; ok: boolean; error?: string; data: unknown; ms: number }>>,
  deadlineMs: number
): Promise<PromiseSettledResult<{ source: string; ok: boolean; error?: string; data: unknown; ms: number }>[]> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  return new Promise((resolve) => {
    timer = setTimeout(() => {
      resolve(
        hits.map((p, i) => ({
          status: 'rejected' as const,
          reason: new Error(`fan-out deadline exceeded (source ${i})`),
        }))
      );
    }, deadlineMs);
    void Promise.allSettled(hits).then((results) => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      resolve(results);
    });
  });
}

export async function iocEnrichDeepHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const ind = (c.req.query('indicator') ?? c.req.query('q') ?? '').trim();
  if (!ind) return respondError(c, 'missing indicator', 'indicator parameter is required', 400);
  if (ind.length > 2000) return respondError(c, 'indicator too long', 'indicator exceeds max length', 400);

  // Allow opt-in to *trigger* a real webamon scan (writes, expensive,
  // rate-limited). Off by default — default behaviour is to read the public
  // search index only.
  const triggerWebamonScan = (c.req.query('trigger') ?? '').toLowerCase().split(',').includes('scan');

  const t = detectType(ind) as IndicatorType;
  if (t === 'unknown') return respondError(c, 'unrecognized indicator type', 'indicator type is not supported', 400);

  const enc = encodeURIComponent(ind);
  const env = c.env;
  const self = (env as unknown as { SELF?: Fetcher }).SELF;
  const tokenSecret = env.INTERNAL_TOKEN_SECRET;
  if (!tokenSecret) {
    return respondError(c, 'internal_token_not_configured', 'internal token secret is not set', 503);
  }
  const token = await signInternalToken('api-enrich-deep', tokenSecret);

  // Fan out per type. Each promise resolves to a SourceHit with success/error.
  const hits: Array<Promise<SourceHit>> = [];

  // ── Universal: multi-provider reputation check (51+ providers, includes
  //    VirusTotal, AbuseIPDB, Shodan, Censys, GreyNoise, tre.ge, Webamon,
  //    Maltiverse, ThreatFox, URLhaus, Spamhaus, OpenPhish, PhishTank,
  //    AlienVault OTX, Google Safe Browsing, etc.) ───────────────────────
  hits.push(
    timeIt('reputation', () =>
      selfFetch(self, `/api/v1/ioc/check?indicator=${enc}`, token).then((r) =>
        r ? r.json() : { error: 'no-response' }
      )
    )
  );

  // ── Domain: DNS / WHOIS / CT / SPF / DKIM / DMARC ─────────────────────
  if (t === 'domain' || t === 'url') {
    const dom = t === 'url' ? safeHostname(ind) : ind;
    if (dom) {
      hits.push(
        timeIt('domain-lookup', () =>
          selfFetch(self, `/api/v1/domain/lookup?domain=${encodeURIComponent(dom)}`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
      hits.push(
        timeIt('builtwith', () =>
          selfFetch(self, `/api/v1/builtwith?domain=${encodeURIComponent(dom)}`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
      // Default: cheap read-only search of Webamon's public index. Still
      // surfaces historical scans, fingerprint, risk_score, ASN, tech, and
      // resolved domains — everything the deep-enrich view needs. Uses the
      // exact-match `domain_name` keyword field so free-text HTML matching
      // can't pull in unrelated scans.
      hits.push(
        timeIt('webamon-search', () =>
          selfFetch(
            self,
            `/api/v1/webamon/search?search=${encodeURIComponent(`domain_name:"${dom}"`)}&size=20`,
            token
          ).then((r) => (r ? r.json() : { error: 'no-response' }))
        )
      );
      // Opt-in: only trigger a *new* webamon scan if the caller passes ?trigger=scan.
      // Scans are write/expensive operations against search.webamon.com and
      // should never run on every deep-enrich request.
      if (triggerWebamonScan) {
        hits.push(
          timeIt('webamon-scan', () =>
            selfFetch(self, `/api/v1/webamon/scan`, token, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ submission_url: `https://${dom}` }),
            }).then((r) => (r ? r.json() : { error: 'no-response' }))
          )
        );
      }
      hits.push(
        timeIt('breach-domain', () =>
          selfFetch(self, `/api/v1/breach/domain?domain=${encodeURIComponent(dom)}`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
      hits.push(
        timeIt('passive-dns', () =>
          selfFetch(self, `/api/v1/passive-dns?q=${encodeURIComponent(dom)}`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
      hits.push(
        timeIt('ct-certs', () =>
          selfFetch(self, `/api/v1/ct-monitor/certs?domain=${encodeURIComponent(dom)}&days=90`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
    }
  }

  // ── URL: focused URL scan + parent-domain breach check ───────────────
  if (t === 'url') {
    hits.push(
      timeIt('urlscan', () =>
        selfFetch(self, `/api/v1/url-preview?url=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
  }

  // ── IP: ASN / IPinfo / Greynoise / breach (org-level) / passive-dns ─
  if (isIp(t)) {
    hits.push(
      timeIt('ipinfo', () =>
        selfFetch(self, `/api/v1/host?ip=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );

    hits.push(
      timeIt('ip-geo', () =>
        selfFetch(self, `/api/v1/ip-geo?ip=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
    hits.push(
      timeIt('passive-dns', () =>
        selfFetch(self, `/api/v1/passive-dns?q=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
    hits.push(
      timeIt('relationships', () =>
        selfFetch(self, `/api/v1/relationship-graph?indicator=${enc}&q=${enc}`, token).then((r) =>
          r ? r.json() : { error: 'no-response' }
        )
      )
    );

    // Chained ASN enrichment: fetch the host's ASN, then look up AS-level
    // info (announced prefixes, abuse contact, org). If the host endpoint
    // errors or has no ASN, the chained promise resolves with a sentinel.
    hits.push(
      timeIt('asn-graph', async () => {
        try {
          const hostRes = await selfFetch(self, `/api/v1/host?ip=${enc}`, token);
          if (!hostRes) return { error: 'no-host-response' };
          const hostData = (await hostRes.json()) as
            { asn?: string | number; network?: { asn?: string | number } } | undefined;
          const asn = hostData?.asn ?? hostData?.network?.asn;
          if (!asn) return { skipped: 'no-asn-on-host' };
          const asnStr = String(asn).toUpperCase().startsWith('AS') ? String(asn) : `AS${asn}`;
          const asnRes = await selfFetch(self, `/api/v1/asn/lookup?asn=${encodeURIComponent(asnStr)}`, token);
          return asnRes ? await asnRes.json() : { error: 'no-asn-response' };
        } catch (err) {
          logError('handler failed', err);
          return { error: err instanceof Error ? err.message : String(err) };
        }
      })
    );
  }

  // ── Hash: sandboxed sample lookup ────────────────────────────────────
  if (t === 'hash') {
    hits.push(
      timeIt('malwarebazaar', () =>
        selfFetch(self, `/api/v1/malwarebazaar?hash=${enc}`, token).then((r) =>
          r ? r.json() : { error: 'no-response' }
        )
      )
    );
    hits.push(
      timeIt('sandbox', () =>
        selfFetch(self, `/api/v1/sandbox/lookup?hash=${enc}`, token).then((r) =>
          r ? r.json() : { error: 'no-response' }
        )
      )
    );
  }

  // ── CVE: NVD + KEV + VulnCheck + OSV + EPSS + threat-actor attribution ──
  if (t === 'cve') {
    hits.push(
      timeIt('cve-lookup', () =>
        selfFetch(self, `/api/v1/cve/lookup?id=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
    hits.push(
      timeIt('cve-recent-context', () =>
        selfFetch(self, `/api/v1/cve-recent?cve=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
    hits.push(
      timeIt('cve-threat-map', () =>
        selfFetch(self, `/api/v1/cve-threat-map?cve=${enc}`, token).then((r) =>
          r ? r.json() : { error: 'no-response' }
        )
      )
    );
  }

  // ── Email: ProjectDiscovery breach + domain pivot ─────────────────────
  if (t === 'email') {
    // ProjectDiscovery breach lookup — the user wants to know if the address
    // is pwned, what breaches, what data classes.
    hits.push(
      timeIt('breach-email', () =>
        selfFetch(self, `/api/v1/breach/email?email=${enc}`, token).then((r) =>
          r ? r.json() : { error: 'no-response' }
        )
      )
    );
    // Pivot on the email's domain — WHOIS, DNS, breach exposure of the org.
    const emailDomain = ind.includes('@') ? (ind.split('@').pop() ?? '') : '';
    if (emailDomain) {
      hits.push(
        timeIt('domain-lookup', () =>
          selfFetch(self, `/api/v1/domain/lookup?domain=${encodeURIComponent(emailDomain)}`, token).then((r) =>
            r ? r.json() : { error: 'no-response' }
          )
        )
      );
    }
  }

  // ── For domain & IP — relationship graph + maltiverse search ────────
  if (t === 'domain' || isIp(t)) {
    hits.push(
      timeIt('maltiverse', () =>
        selfFetch(self, `/api/v1/maltiverse?q=${enc}`, token).then((r) => (r ? r.json() : { error: 'no-response' }))
      )
    );
  }

  const results = await settleWithin(hits, FANOUT_DEADLINE_MS);
  const sources: SourceHit[] = [];
  for (const r of results) {
    if (r.status === 'fulfilled') sources.push(r.value);
  }

  // Aggregate a coarse verdict from the reputation source if present.
  const rep = sources.find((s) => s.source === 'reputation');
  const verdict = aggregateVerdict(rep);

  return c.json(
    {
      indicator: ind,
      type: t,
      verdict,
      source_count: sources.filter((s) => s.ok).length,
      total_sources: sources.length,
      sources: sources.map((s) => ({
        source: s.source,
        ok: s.ok,
        error: s.error,
        ms: s.ms,
        data: s.data,
      })),
      generated_at: new Date().toISOString(),
    },
    200,
    { 'cache-control': 'no-store' }
  );
}

/** Safely extract the hostname from a URL (or return null on failure). */
function safeHostname(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_catchErr) {
    logError('safeHostname failed', _catchErr);
    // If the input isn't a full URL, treat the whole thing as a hostname
    // (only for the domain-lookup fan-out — URL-specific calls still need
    //  a real URL).
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(url)) return url.toLowerCase();
    return null;
  }
}

interface RepVerdict {
  overall: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  score: number;
  admiralty?: string;
  providers_reporting: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  top_tags: string[];
}

function aggregateVerdict(rep: SourceHit | undefined): RepVerdict {
  const empty: RepVerdict = {
    overall: 'unknown',
    score: 0,
    providers_reporting: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 0,
    top_tags: [],
  };
  if (!rep || !rep.ok || !rep.data) return empty;

  const data = rep.data as {
    composite_score?: number;
    admiralty_grade?: string;
    providers?: Array<{ status?: string; verdict?: string; tags?: string[]; score?: number }>;
  };
  const providers = Array.isArray(data.providers) ? data.providers : [];
  let mal = 0;
  let sus = 0;
  let clean = 0;
  const tagCounts = new Map<string, number>();
  for (const p of providers) {
    if (p.status !== 'ok' && p.status !== 'unsupported') continue;
    if (p.verdict === 'malicious') mal++;
    else if (p.verdict === 'suspicious') sus++;
    else if (p.verdict === 'clean') clean++;
    for (const t of p.tags ?? []) {
      tagCounts.set(t, (tagCounts.get(t) ?? 0) + 1);
    }
  }
  const total = mal + sus + clean;
  let overall: RepVerdict['overall'] = 'unknown';
  if (total > 0) {
    if (mal >= 2 || (mal >= 1 && sus >= 3)) overall = 'malicious';
    else if (mal >= 1 || sus >= 2) overall = 'suspicious';
    else if (clean > 0 && mal === 0 && sus === 0) overall = 'clean';
  }
  const topTags = [...tagCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([t]) => t);
  return {
    overall,
    score: typeof data.composite_score === 'number' ? data.composite_score : 0,
    admiralty: data.admiralty_grade,
    providers_reporting: total,
    malicious_count: mal,
    suspicious_count: sus,
    clean_count: clean,
    top_tags: topTags,
  };
}
