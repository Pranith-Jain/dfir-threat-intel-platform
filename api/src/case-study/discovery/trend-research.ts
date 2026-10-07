import type { Candidate, DedupRecord, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { severityScore, noveltyScore, finalScore } from '../scoring';
import { dayOfYear } from './rotation';
import { selfFetchJson } from '../../lib/self-fetch';
import { verifyUrls, type LinkStatus } from '../../lib/verify-url';

/**
 * Trend research — the replacement for the old `agentic-trends` runner.
 *
 * The previous runner asked an LLM to invent three story ideas from a
 * category pool, then tried to catch the inventions afterwards with a
 * fabricated-host blocklist and an NVD existence probe. It needed all of that
 * because the fundamental approach was wrong: asking a model to recall what
 * is trending produces confident, well-structured, entirely fictional
 * stories. The blocklist was a tourniquet on that.
 *
 * This runner inverts the order. It asks the platform's OWN corpus what
 * actually moved, and only uses the LLM afterwards — to phrase and rank
 * material that already exists, never to supply the material.
 *
 * The corpus it reads:
 *   - cvemon trending CVEs (social hype + rank)
 *   - newly-added CISA KEV entries in the last 48h
 *   - CVEs whose EPSS spiked relative to the platform's own recent baseline
 *   - writeups and disclosures in the last 24h
 *   - darkweb monitor hits in the last 24h
 *
 * Every candidate that survives carries at least one real, verified URL. If
 * the corpus is quiet, the runner returns nothing rather than filling the
 * gap — a quiet day should produce no post, not an invented one.
 */

// ── Corpus signals ───────────────────────────────────────────────────────

export interface TrendSignal {
  kind: 'trending-cve' | 'new-kev' | 'epss-spike' | 'writeup' | 'disclosure' | 'darkweb';
  /** Short machine label for the stable key. */
  key: string;
  title: string;
  /** What makes this worth a post, in one line. */
  rationale: string;
  /** Best available source URL. Must resolve for the candidate to be kept. */
  url: string;
  /** Extra facts merged into the candidate evidence. */
  facts: Record<string, unknown>;
  /** Suggested content type. */
  type: CaseStudyType;
  /** 0-1. Prior likelihood this is worth publishing. */
  weight: number;
}

type SelfFetcher = { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> };
type Fetcher = SelfFetcher | undefined;

/**
 * Coerce a self-fetch payload into an array of row objects.
 *
 * The envelope key varies per endpoint (`vulnerabilities` for cisa-kev,
 * `cves` for cve-recent, `items` for the monitor surfaces). Missing one here
 * silently yields an empty corpus and the runner correctly produces nothing,
 * which is indistinguishable from a quiet day — so the list is kept broad.
 */
function asArray(v: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(v)) return v.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object');
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    for (const k of [
      'vulnerabilities',
      'items',
      'results',
      'cves',
      'writeups',
      'hits',
      'posts',
      'breaches',
      'entries',
      'data',
    ]) {
      if (Array.isArray(o[k])) return asArray(o[k]);
    }
  }
  return [];
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
}

function num(v: unknown): number | undefined {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number.parseFloat(v) : Number.NaN;
  return Number.isFinite(n) ? n : undefined;
}

const CVE_ID_RE = /\bCVE-\d{4}-\d{4,7}\b/i;

/** Title for a CVE deep-dive. Keeps the id first so it survives truncation. */
function cveHeadline(cveId: string, detail: string): string {
  const cleaned = detail
    .replace(CVE_ID_RE, '')
    .replace(/^[\s,.:;-]+/, '')
    .replace(/\s+/g, ' ')
    .trim();
  // First sentence of the description, capped — the headline is a pointer,
  // not the story.
  const firstClause = (cleaned.split(/(?<=[.!?])\s/)[0] ?? cleaned).slice(0, 110).trim();
  return firstClause ? `${cveId}: ${firstClause}` : cveId;
}

interface CorpusFetch {
  trending: unknown;
  kev: unknown;
  recent: unknown;
  writeups: unknown;
  darkweb: unknown;
}

async function fetchCorpus(self: Fetcher, env: { INTERNAL_TOKEN_SECRET?: string }): Promise<CorpusFetch> {
  const empty: CorpusFetch = { trending: null, kev: null, recent: null, writeups: null, darkweb: null };
  if (!self || !env.INTERNAL_TOKEN_SECRET) return empty;
  const f: SelfFetcher = self;
  const paths = {
    trending: '/api/v1/cve-trends?limit=20',
    kev: '/api/v1/cisa-kev?days=2&limit=40',
    recent: '/api/v1/cve-recent?limit=120',
    writeups: '/api/v1/writeups?limit=15&since=24h',
    darkweb: '/api/v1/darkweb-monitor?limit=15&since=24h',
  };
  const settled = await Promise.all(Object.values(paths).map((p) => selfFetchJson<unknown>(f, p, env)));
  const [trending, kev, recent, writeups, darkweb] = settled;
  return { trending, kev, recent, writeups, darkweb };
}

// ── Signal extraction ────────────────────────────────────────────────────

/** CVEs the platform's own feeds are reporting on right now, with scores. */
function signalsFromTrending(data: unknown): TrendSignal[] {
  const out: TrendSignal[] = [];
  for (const c of asArray(data)) {
    {
      const id = (str(c.id) || str(c.cve_id)).toUpperCase();
      if (!CVE_ID_RE.test(id)) continue;
      const hype = num(c.hype_score) ?? num(c.hypeScore) ?? 0;
      const rank = num(c.rank) ?? 99;
      const description = str(c.description).slice(0, 300);
      out.push({
        kind: 'trending-cve',
        key: `trending-${id}`,
        title: cveHeadline(id, description),
        rationale: `Rank ${rank} on the social trending feed with a hype score of ${hype}${
          description ? `: ${description.slice(0, 120)}` : ''
        }`,
        url: `https://nvd.nist.gov/vuln/detail/${id}`,
        facts: { cveId: id, hypeScore: hype, rank, description },
        // A hype score of 8+ means it is genuinely being discussed. Rank 1-3
        // is meaningful even at a lower score.
        weight: Math.min(1, hype / 15 + (rank <= 3 ? 0.25 : 0)),
        type: 'vulnfaq',
      });
    }
  }
  return out;
}

/**
 * KEV entries added in the window.
 *
 * These are the highest-signal items the platform ever sees: CISA added them
 * because they are being exploited right now.
 *
 * The window is 26 hours, not one hour. Discovery runs once a day
 * (`5 0 * * *`), so a narrow window would miss every entry added in the hours
 * between cron ticks — including all of them, on most days. 26h gives one day
 * of slack so the daily run reliably covers everything since the last one.
 * Duplicate coverage across two ticks is harmless: the dedup map suppresses a
 * key that was already surfaced.
 */
function signalsFromKev(data: unknown, now: Date): TrendSignal[] {
  const windowMs = 26 * 60 * 60 * 1000;
  const out: TrendSignal[] = [];
  for (const v of asArray(data)) {
    const id = (str(v.cveId) || str(v.cveID)).toUpperCase();
    if (!CVE_ID_RE.test(id)) continue;
    const added = Date.parse(str(v.dateAdded) || str(v.date_added));
    if (Number.isNaN(added) || now.getTime() - added > windowMs) continue;

    const vendor = str(v.vendorProject) || str(v.vendor);
    const product = str(v.product);
    const name = str(v.vulnerabilityName) || str(v.vulnerability_name);
    const ransomware = str(v.knownRansomwareCampaignUse) === 'Known';
    out.push({
      kind: 'new-kev',
      key: `newkev-${id}`,
      title: `${id}${name ? `: ${name.slice(0, 90)}` : ''}`,
      rationale:
        `CISA added ${id} to the Known Exploited Vulnerabilities catalog today` +
        `${vendor || product ? `, affecting ${[vendor, product].filter(Boolean).join(' ')}` : ''}` +
        `${ransomware ? '. Flagged as used in a known ransomware campaign' : ''}. Confirmed in-the-wild exploitation.`,
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${id}`,
      facts: {
        cveId: id,
        vendor,
        product,
        kev: true,
        kevAdded: str(v.dateAdded),
        kevDue: str(v.dueDate),
        knownRansomware: ransomware,
        shortDescription: str(v.shortDescription).slice(0, 400),
      },
      weight: 1,
      // A fresh KEV flagged for ransomware use is an exploitation story;
      // otherwise it is an explainer.
      type: ransomware ? 'exploit' : 'vulnfaq',
    });
  }
  return out;
}

/**
 * EPSS outliers: CVEs scoring far above the cohort they appear in.
 *
 * EPSS is a probability, and probabilities are not comparable across
 * severity in a useful way without context — a 0.9 on a network-reachable
 * pre-auth RCE is a very different operational problem from a 0.9 on an
 * authenticated local privilege escalation. The median of whatever the
 * platform is currently tracking is the context.
 */
function signalsFromEpss(data: unknown): TrendSignal[] {
  const rows = asArray(data)
    .map((c) => ({
      id: (str(c.id) || str(c.cve_id)).toUpperCase(),
      score: num(c.score) ?? num(c.cvss),
      epss: num(c.epss),
      description: str(c.description).slice(0, 300),
      reachable: str(c.description).match(/\bunauthenticated|pre-auth|remote/i) !== null,
      kev: c.kev === true,
    }))
    .filter((r) => CVE_ID_RE.test(r.id) && r.epss !== undefined && r.epss > 0);

  if (rows.length < 8) return [];

  const sorted = [...rows].sort((a, b) => (a.epss ?? 0) - (b.epss ?? 0));
  const median = sorted[Math.floor(sorted.length / 2)]?.epss ?? 0;
  const threshold = Math.max(0.3, median * 2);

  const out: TrendSignal[] = [];
  for (const r of rows.filter((x) => (x.epss ?? 0) >= threshold && x.reachable).slice(0, 10)) {
    out.push({
      kind: 'epss-spike',
      key: `epss-${r.id}`,
      title: cveHeadline(r.id, r.description),
      rationale:
        `EPSS probability of ${((r.epss ?? 0) * 100).toFixed(1)}% over the next 30 days, more than double ` +
        `the ${(median * 100).toFixed(1)}% median across current CVEs${r.kev ? ', and it is in CISA KEV' : ''}. Remotely reachable.`,
      url: `https://nvd.nist.gov/vuln/detail/${r.id}`,
      facts: { cveId: r.id, epss: r.epss, epssMedian: median, description: r.description, cvss: r.score },
      weight: 0.6,
      type: 'exploit',
    });
  }
  return out;
}

/** Writeups and disclosures published in the window. */
function signalsFromWriteups(data: unknown, now: Date): TrendSignal[] {
  const windowMs = 48 * 60 * 60 * 1000;
  const out: TrendSignal[] = [];
  for (const w of asArray(data)) {
    const title = str(w.title).trim();
    const url = str(w.url) || (str(w.slug) ? `https://pranithjain.qzz.io/threatintel/writeups/${str(w.slug)}` : '');
    if (!title || !url.startsWith('http')) continue;
    const published = Date.parse(str(w.published_at) || str(w.publishedAt) || str(w.date));
    if (Number.isNaN(published) || now.getTime() - published > windowMs) continue;

    const summary = str(w.summary).slice(0, 300);
    const cve = (title.match(CVE_ID_RE) ?? [])[0]?.toUpperCase();
    const entities = asArray(w.entities)
      .map((e) => str(e))
      .filter(Boolean);
    out.push({
      kind: 'writeup',
      key: `writeup-${str(w.slug) || title.slice(0, 40)}`,
      title: title.slice(0, 160),
      rationale:
        summary ||
        `Published on the platform in the last 48 hours${entities.length ? `: ${entities.slice(0, 4).join(', ')}` : ''}.`,
      url,
      facts: { cveId: cve, summary, entities, sourceUrl: url, sourceTitle: title },
      weight: 0.5,
      type: cve ? 'vulnfaq' : 'intel',
    });
  }
  return out;
}

/** Darkweb monitor hits. */
function signalsFromDarkweb(data: unknown, now: Date): TrendSignal[] {
  const windowMs = 48 * 60 * 60 * 1000;
  const out: TrendSignal[] = [];
  for (const d of asArray(data)) {
    const title = str(d.title) || str(d.name);
    const source = str(d.source) || str(d.source_name) || 'darkweb monitor';
    if (!title) continue;
    const detected = str(d.detected_at) || str(d.date) || str(d.first_seen);
    const ts = Date.parse(detected);
    if (detected && !Number.isNaN(ts) && now.getTime() - ts > windowMs) continue;

    const url = str(d.url);
    const cve = (title.match(CVE_ID_RE) ?? [])[0]?.toUpperCase();
    out.push({
      kind: 'darkweb',
      key: `darkweb-${str(d.id) || title.slice(0, 40)}`,
      title: title.slice(0, 160),
      rationale: `Observed on ${source}${detected ? ` on ${detected.slice(0, 10)}` : ''}. Underground telemetry on this topic.`,
      url: url.startsWith('http') ? url : 'https://pranithjain.qzz.io/threatintel/darknet-intel',
      facts: { title, source, detectedAt: detected, cveId: cve, url },
      weight: 0.55,
      type: 'darkweb',
    });
  }
  return out;
}

// ── Runner ───────────────────────────────────────────────────────────────

export interface TrendResearchDeps {
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
  /** SELF binding. Absent = no signals (correctly yields no candidates). */
  self?: { fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response> };
  internalTokenSecret?: string;
  /** Verify candidate URLs resolve. Off in cron to save subrequests. */
  deepVerify?: boolean;
}

/**
 * Turn platform corpus signals into candidates.
 *
 * Returns an empty array whenever the corpus is unavailable or empty. This
 * is deliberate: the old runner guaranteed three candidates per day by
 * inventing them, and that guarantee was the problem.
 */
export async function discoverTrendResearch(deps: TrendResearchDeps): Promise<Candidate[]> {
  const { now, getDedup, self } = deps;
  if (!self || !deps.internalTokenSecret) return [];

  const corpus = await fetchCorpus(self, { INTERNAL_TOKEN_SECRET: deps.internalTokenSecret }).catch(
    (): CorpusFetch => ({ trending: null, kev: null, recent: null, writeups: null, darkweb: null })
  );

  const signals: TrendSignal[] = [
    ...signalsFromKev(corpus.kev, now),
    ...signalsFromTrending(corpus.trending),
    ...signalsFromEpss(corpus.recent),
    ...signalsFromWriteups(corpus.writeups, now),
    ...signalsFromDarkweb(corpus.darkweb, now),
  ];

  if (signals.length === 0) return [];

  // Rank, then verify only the ones that could plausibly publish. Verifying
  // every signal would blow the subrequest budget on items that never make
  // the cut.
  signals.sort((a, b) => b.weight - a.weight);
  const shortlist = signals.slice(0, 12);

  // One batched verification for the whole shortlist.
  const statuses: Record<string, LinkStatus> = {};
  if (shortlist.some((s) => !/nvd\.nist\.gov|known-exploited-vulnerabilities/.test(s.url))) {
    try {
      const results = await verifyUrls(
        shortlist.map((s) => s.url),
        3000,
        { deepSoft404: deps.deepVerify === true }
      );
      for (const [url, r] of results) statuses[url] = r.linkStatus;
    } catch {
      return [];
    }
  }

  const candidates: Candidate[] = [];
  const seenKeys = new Set<string>();
  const seenUrls = new Set<string>();

  for (const signal of shortlist) {
    const key = topicKey(signal.kind.split('-')[0] ?? 'trend', signal.key);
    if (seenKeys.has(key)) continue;

    // Canonical-authority URLs are constructed from the id and need no probe.
    const canonical = /nvd\.nist\.gov|known-exploited-vulnerabilities/.test(signal.url);
    const status = canonical ? 'ok' : statuses[signal.url];
    // An unverified URL is exactly where a fabricated citation hides, and
    // unlike the old LLM runner every candidate here is anchored to a real
    // corpus record — so 'unchecked' is not good enough.
    if (!canonical && status !== 'ok') continue;

    const dedup = await getDedup(key);
    if (dedup?.publishedSlug) continue;

    if (seenUrls.has(signal.url)) continue;
    seenKeys.add(key);
    seenUrls.add(signal.url);

    const score = finalScore({
      recency: 1,
      severity: severityScore({}),
      novelty: noveltyScore(dedup, now),
      sourceWeight: signal.weight,
    });
    const adjusted = Number((score * 0.65 + signal.weight * 0.35).toFixed(4));

    candidates.push({
      key,
      type: signal.type,
      title: signal.title,
      rationale: signal.rationale,
      score: adjusted,
      evidence: {
        ...signal.facts,
        url: signal.url,
        sources: [signal.url],
        signal: signal.kind,
        signalWeight: signal.weight,
        linkStatus: status,
        source: 'trend-research',
        generatedAt: now.toISOString(),
        // Surface which corpus signal produced this so an operator reviewing
        // the Pending tab can see the justification without opening sources.
        provenance: `platform corpus · ${signal.kind} · day ${dayOfYear(now)}`,
      },
      discoveredAt: now.toISOString(),
      status: 'pending',
    });
  }

  return candidates;
}
