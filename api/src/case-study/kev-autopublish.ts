/**
 * KEV auto-publish — "a CVE landed in CISA KEV" → publish a post about it now.
 *
 * Every other path in the content engine is a *suggestion*: discovery offers a
 * candidate, a human approves it, the planner finds it a slot, the publisher
 * writes it. This module exists because one trigger is categorically different.
 * A CISA KEV addition is not a lead — it is a confirmed, actively-exploited
 * vulnerability, published by an authority, with a date. Waiting up to a week
 * for it to surface through the daily queue (and then for a slot) means the
 * write-up lands after the exploitation window it was supposed to cover.
 *
 * So KEV additions bypass both gates:
 *   - the per-type/per-topic discovery budget (they are not discovered, they
 *     are *observed* — the hourly cron below reads the KEV feed directly), and
 *   - the draft/approval gate (`BLOG_APPROVAL_REQUIRED` is for editorial
 *     judgement on topics we chose; here the topic was chosen for us).
 *
 * What it deliberately does NOT bypass:
 *   - the republish block. A key that already has a `publishedSlug` inside the
 *     30-day window is skipped, so a feed glitch that re-lists an old entry
 *     cannot produce a second post about the same CVE.
 *   - the per-tick cap (`KEV_AUTOPUBLISH_MAX_PER_TICK`). A KEV batch of 30
 *     additions must not fire 30 LLM generations in one invocation; the rest
 *     are picked up by the following ticks since the window is 26h wide.
 *
 * The window is 48h. `dateAdded` is DATE-ONLY, so an entry added "yesterday"
 * parses to yesterday 00:00 UTC — at 23:00 today that is 47h old. Any window
 * narrower than 48h therefore drops yesterday's additions for every tick after
 * 10:00 UTC, and since the feed is what we read (not an event stream), a
 * missed entry is missed permanently. A wider window is only safe *because* of
 * the republish guard below: re-reading an entry we already published is a
 * no-op, so the window can be generous while the publish decision cannot
 * double-fire.
 */
import type { Candidate, DedupRecord } from './types';
import { cveKey } from './stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from './scoring';

export const KEV_FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** The subset of CISA's KEV record this module consumes. */
export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse?: string;
}

/**
 * Entries added within this window are eligible for immediate publication.
 * 48h because `dateAdded` is date-only (see the header): the current and the
 * previous calendar day at any hour of the day.
 */
export const KEV_AUTOPUBLISH_WINDOW_HOURS = 48;

/**
 * Cap per cron tick. The cron is hourly, so this is a rate limit, not a daily
 * quota — a big KEV batch drains over the next few ticks and the window keeps
 * every entry eligible that whole time.
 */
export const KEV_AUTOPUBLISH_MAX_PER_TICK = 2;

/** Published keys stay blocked this long (same window discovery uses). */
const REPUBLISH_BLOCK_MS = 30 * 24 * 3600 * 1000;

export type DedupLookup = Record<string, DedupRecord>;

export interface FetchKevOptions {
  /** Injectable for tests; defaults to the fetch passed by the caller. */
  fetch: typeof globalThis.fetch;
  now: Date;
  windowHours?: number;
}

/**
 * Read CISA KEV and return only the entries added inside the window.
 *
 * One subrequest, no enrichment — this runs hourly, so it must stay cheap.
 * A malformed/absent `dateAdded` is treated as *not* fresh rather than fresh:
 * publishing is irreversible, so an unparseable date must fail closed.
 */
export async function fetchKevAdditions(opts: FetchKevOptions): Promise<KevEntry[]> {
  const windowHours = opts.windowHours ?? KEV_AUTOPUBLISH_WINDOW_HOURS;
  const cutoff = opts.now.getTime() - windowHours * 3600 * 1000;
  const r = await opts.fetch(KEV_FEED_URL, {
    headers: { 'User-Agent': 'pranithjain.qzz.io case-study-kev-autopublish', accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`KEV feed ${r.status}`);
  const body = (await r.json()) as { vulnerabilities?: KevEntry[] };
  const out: KevEntry[] = [];
  for (const e of body.vulnerabilities ?? []) {
    if (!e?.cveID || !e.dateAdded) continue;
    const added = Date.parse(`${e.dateAdded}T00:00:00Z`);
    if (!Number.isFinite(added) || added < cutoff) continue;
    out.push(e);
  }
  return out;
}

/**
 * Has this key already been published (or suppressed) recently?
 *
 * The guard the auto-publish path must never lose: a key with a published slug
 * inside the republish window is skipped outright, so no feed re-listing can
 * double-post a CVE. `suppressedUntil` is honored too — the failure path below
 * writes a 24h suppression so a generation that keeps throwing is retried
 * tomorrow, not every hour.
 */
export function isKevPublishEligible(rec: DedupRecord | null, now: Date): boolean {
  if (!rec) return true;
  if (rec.suppressedUntil) {
    const until = Date.parse(rec.suppressedUntil);
    if (Number.isFinite(until) && now.getTime() < until) return false;
  }
  if (rec.publishedSlug) {
    const seen = Date.parse(rec.lastSeenAt);
    if (!Number.isFinite(seen) || now.getTime() - seen < REPUBLISH_BLOCK_MS) return false;
  }
  return true;
}

export interface BuildKevCandidateDeps {
  now: Date;
  /** Dedup lookup — drives the novelty term of the score. */
  getDedup: (key: string) => Promise<DedupRecord | null>;
  /**
   * Optional NVD enrichment (CVSS, affected versions, CWE). Injected so the
   * selector is testable offline and so the caller controls the subrequest
   * budget; absent = the evidence carries only what KEV itself states.
   */
  enrich?: (cveId: string) => Promise<Record<string, unknown>>;
}

/**
 * Turn one KEV addition into a `cve` candidate — the same shape the daily
 * `cve` discovery runner produces, so the generator, templates and dedup keys
 * all treat it identically.
 */
export async function buildKevCandidate(entry: KevEntry, deps: BuildKevCandidateDeps): Promise<Candidate> {
  const stable = cveKey(entry.cveID);
  const dedup = await deps.getDedup(stable);
  const extra: Record<string, unknown> = deps.enrich
    ? await deps.enrich(entry.cveID).catch((): Record<string, unknown> => ({}))
    : {};
  const addedIso = new Date(`${entry.dateAdded}T00:00:00Z`).toISOString();
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(entry.cveID)}`;

  const evidence: Record<string, unknown> = {
    cveId: entry.cveID,
    vendor: entry.vendorProject,
    product: entry.product,
    name: entry.vulnerabilityName,
    description: entry.shortDescription,
    kev: true,
    kevAddedAt: addedIso,
    ransomwareUse: entry.knownRansomwareCampaignUse === 'Known',
    urls: [nvdUrl],
    // Marks the origin for the admin: this post was not human-approved, it was
    // triggered by the KEV feed. Without it a new post appearing in /admin has
    // no visible reason for existing.
    kevAutoPublish: true,
    ...extra,
  };

  return {
    key: stable,
    type: 'cve',
    title: formatKevTitle(entry),
    rationale:
      `Auto-published: added to CISA KEV ${entry.dateAdded}` + (evidence.ransomwareUse ? '; known ransomware use' : ''),
    score: finalScore({
      recency: recencyScore(addedIso, deps.now),
      severity: severityScore({ kev: true, cvss: (extra.cvss as { score?: number } | undefined)?.score }),
      novelty: noveltyScore(dedup, deps.now),
      sourceWeight: 1.0,
    }),
    evidence,
    discoveredAt: deps.now.toISOString(),
    status: 'pending',
  };
}

/**
 * KEV's `vulnerabilityName` is usually the full NVD title, which already
 * contains vendor and product — naive concatenation produced titles like
 * "Microsoft Microsoft Exchange Server ...". Shared with the daily `cve`
 * runner so both surfaces name the same CVE the same way.
 */
export function formatKevTitle(k: Pick<KevEntry, 'cveID' | 'vendorProject' | 'product' | 'vulnerabilityName'>): string {
  const product = k.product ?? '';
  const vendor = k.vendorProject ?? '';
  const name = k.vulnerabilityName ?? '';
  const titleVendor = vendor.charAt(0).toUpperCase() + vendor.slice(1);
  const nameIncludesVendor = name.toLowerCase().startsWith(titleVendor.toLowerCase());
  const nameIncludesProduct = product ? name.toLowerCase().includes(product.toLowerCase()) : false;
  const productAlreadyHasVendor = product.toLowerCase().includes(vendor.toLowerCase());
  const titleName =
    nameIncludesVendor || nameIncludesProduct
      ? name
      : productAlreadyHasVendor || !vendor
        ? `${product} ${name}`.trim()
        : `${titleVendor} ${product} ${name}`;
  return `${k.cveID} — ${titleName}`;
}

/**
 * Pick this tick's batch: eligibility-filtered, newest KEV addition first,
 * score as the tie-break, capped at `maxPerTick`.
 *
 * Pure — the caller supplies the candidates and the dedup snapshot, so the
 * "never double-publish, never exceed the cap" rules are unit-testable without
 * a KV namespace or an LLM.
 */
export function selectKevBatch(
  candidates: Candidate[],
  dedup: DedupLookup,
  now: Date,
  maxPerTick: number = KEV_AUTOPUBLISH_MAX_PER_TICK
): Candidate[] {
  const cap = Number.isFinite(maxPerTick) && maxPerTick > 0 ? Math.floor(maxPerTick) : 0;
  if (cap === 0) return [];
  return candidates
    .filter((c) => isKevPublishEligible(dedup[c.key] ?? null, now))
    .sort((a, b) => {
      const ra = Date.parse(String((a.evidence as { kevAddedAt?: string }).kevAddedAt ?? a.discoveredAt));
      const rb = Date.parse(String((b.evidence as { kevAddedAt?: string }).kevAddedAt ?? b.discoveredAt));
      if (Number.isFinite(ra) && Number.isFinite(rb) && ra !== rb) return rb - ra;
      return b.score - a.score;
    })
    .slice(0, cap);
}
