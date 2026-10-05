/**
 * feed-curation.ts
 *
 * The curated layer over the open-source IOC feed ecosystem, audited against
 * the community-maintained catalogue at
 * `github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds` (ThreatIntelFeeds.csv,
 * 152 entries across 12 categories).
 *
 * # Why this file exists
 *
 * That catalogue is a *curated list of lists*, not a liveness oracle. Probing
 * all 152 entries (2026-10-05) showed three distinct failure modes that a
 * "the URL is in the CSV so it must work" assumption misses entirely:
 *
 *  1. **38 entries are marked `Offline`** — and re-probing confirmed nearly all
 *     are genuinely gone (repo deleted, host decommissioned, DNS failure).
 *  2. **7 entries are marked `Active` but are NOT machine-readable feeds.**
 *     They return HTTP 200 with an HTML page (a docs site, a ToS interstitial,
 *     a JS bundle), or an empty stub body. Silently treating a 200-with-HTML as
 *     a feed is the worst case: it looks healthy in a naive status check while
 *     contributing zero indicators forever.
 *  3. **Every `github.com/…/blob/…` URL is an HTML page**, not raw file
 *     content. The catalogue lists them as feeds; consuming them literally
 *     yields a `<!DOCTYPE html>` body.
 *
 * So this module records the audit result as code: `RETIRED_FEEDS` pins the
 * URLs we deliberately do NOT consume and why, and `CURATED_FEEDS` is the
 * verified-live set that the live-IOC registry draws from. Re-audit cadence and
 * the re-probe command live in `docs/loops/feed-curation-re-audit.md`.
 *
 * # Not a network module
 *
 * Pure data + tiny helpers. `verifyFeedHealth` is the one function that does
 * I/O, and it is only used by the audit script / tests — never on the hot path.
 */

import type { IocType } from './ioc-feed-parsers';

/** How a feed failed, used to decide whether a fix could ever restore it. */
export type RetiredReason =
  /** Upstream gone for good: repo deleted, domain decommissioned, DNS dead. */
  | 'dead'
  /** HTTP 200 but the body is an HTML page / JS bundle, not feed data. */
  | 'html-not-feed'
  /** HTTP 200 but the body is a stub with no indicator rows. */
  | 'empty-stub'
  /** HTTP 200 and readable, but so small it is operationally useless. */
  | 'negligible-volume'
  /** Replaced by a better source; kept here so it is not silently re-added. */
  | 'superseded';

export interface RetiredFeed {
  url: string;
  reason: RetiredReason;
  /** Human-readable note — what the probe actually returned. */
  note: string;
  /** Replacement source id in `CURATED_FEEDS`, when there is a real swap. */
  replacedBy?: string;
}

/**
 * Feeds audited and deliberately excluded. Every entry was probed on
 * 2026-10-05; the recorded HTTP status is the observed one.
 *
 * Do not delete an entry because a feed looks interesting again — re-probe it,
 * confirm it returns real indicator rows, then move it to `CURATED_FEEDS`.
 * This list exists so a future sync does not re-introduce known-dead upstreams
 * on the strength of a stale third-party CSV.
 */
export const RETIRED_FEEDS: readonly RetiredFeed[] = [
  // ── Marked Offline upstream, confirmed dead on re-probe ────────────────
  {
    url: 'https://www.talosintelligence.com/documents/ip-blacklist',
    reason: 'dead',
    note: 'HTTP 403 on both http and https — Cisco retired the public IP blacklist document.',
  },
  {
    url: 'https://iocfeed.mrlooquer.com/feed.csv',
    reason: 'dead',
    note: 'HTTP 404 — host no longer serves the feed.',
  },
  {
    url: 'https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt',
    reason: 'dead',
    note: 'HTTP 404 — the montysecurity/C2-Tracker repo itself 404s. All 20 of its per-tool lists are equally gone.',
  },
  {
    url: 'https://urlabuse.com/public/data/data.txt',
    reason: 'dead',
    note: 'HTTP 403 — urlabuse now gates every list behind auth.',
  },
  {
    url: 'https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt',
    reason: 'dead',
    note: 'DNS/connection failure — host does not resolve.',
  },
  {
    url: 'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
    reason: 'dead',
    note: 'DNS/connection failure — host does not resolve.',
  },
  {
    url: 'https://api.cybercure.ai/feed/get_ips?type=csv',
    reason: 'dead',
    note: 'HTTP 520 origin error from Cloudflare — upstream app is down.',
  },
  {
    url: 'https://api.cybercure.ai/feed/get_url?type=csv',
    reason: 'dead',
    note: 'HTTP 520 origin error from Cloudflare — upstream app is down.',
  },
  {
    url: 'https://nocdn.nrd-list.com/0/nrd-list-32-days.txt',
    reason: 'dead',
    note: 'DNS/connection failure.',
  },
  {
    url: 'https://nocdn.threat-list.com/0/domains.txt',
    reason: 'dead',
    note: 'DNS/connection failure — the whole nocdn.threat-list.com host is gone.',
  },
  {
    url: 'https://blocklists.0dave.ch/ssh.txt',
    reason: 'dead',
    note: 'HTTP 404 — the cydave blocklists host serves a landing page only, no list paths.',
  },

  // ── Marked "Active" upstream but NOT machine-readable ──────────────────
  // These are the dangerous ones: a naive liveness check (status code only)
  // passes them. `fetchText` catches the HTML-body case, which is why they
  // never produced data rather than poisoning the response with markup.
  {
    url: 'https://cdn.ellio.tech/community-feed',
    reason: 'html-not-feed',
    note: 'HTTP 200 but returns a 171KB JS/HTML app shell, not a feed. Ellio moved its feed behind the dashboard.',
  },
  {
    url: 'https://trends.netcraft.com/cybercrime/tlds',
    reason: 'html-not-feed',
    note: 'HTTP 200 but returns a 40KB HTML page. NetCraft publishes cybercrime TLDs as a web report, not a file.',
  },
  {
    url: 'https://snort.org/downloads/ip-block-list',
    reason: 'html-not-feed',
    note: 'HTTP 200 but returns a ToS interstitial page; the list requires accepting terms per-request.',
  },
  {
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
    reason: 'empty-stub',
    note: 'HTTP 200 but 545 bytes of banner comments and zero rows — abuse.ch gated the SSLBL IP list.',
  },
  {
    url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv',
    reason: 'empty-stub',
    note: 'HTTP 200 but a 545-byte empty stub, same SSLBL gating.',
  },
  {
    url: 'https://lists.blocklist.de/lists/1.txt',
    reason: 'dead',
    note: 'HTTP 404 — blocklist.de has named lists (all/ssh/mail/bots/…), never a numeric 1.txt.',
  },
  {
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    reason: 'negligible-volume',
    note: 'HTTP 200 but 5 rows. abuse.ch deprecated Feodo Tracker as a standalone C2 feed; keep ThreatFox instead.',
  },
];

/**
 * Feeds that are demoted but STILL IN USE. Separate from `RETIRED_FEEDS`
 * because that list means "do not consume this URL" and is enforced by a drift
 * test — a demoted feed that is still a registered primary (or a last-resort
 * fallback) must not appear there, or the two states contradict each other.
 *
 * Recorded so the audit trail survives the demotion: without this, the next
 * re-audit sees a 9-row feed still wired up and has to re-derive why.
 */
export interface DemotedFeed {
  url: string;
  /** Where it still appears in the registry. */
  role: string;
  note: string;
}

export const DEMOTED_FEEDS: readonly DemotedFeed[] = [
  {
    url: 'https://www.botvrij.eu/data/ioclist.url.raw',
    role: 'primary of `botvrij-urls`, last-resort fallback of `botvrij-domain`',
    note: 'HTTP 200 but shrunk to 9 URLs (one a malformed `ttp://` row). Kept wired because a 9-row niche feed still beats a hole; `botvrij-domain` (3,894 domains) carries the real volume.',
  },
  {
    url: 'https://www.joewein.net/dl/bl/dom-bl.txt',
    role: 'primary of `domains-blacklist`',
    note: 'HTTP 200 but only 181 domains. Kept as primary because it is high-precision curated malicious domains; added the 51,672-row tsirolnik list as its first fallback.',
  },
];

/**
 * Feeds that are LIVE and were audited, but are deliberately not ingested
 * because their contents cannot be represented as discrete indicators.
 *
 * Kept separate from `RETIRED_FEEDS` because the distinction matters: these are
 * not broken, and re-probing them will keep returning 200. They are excluded on
 * format grounds, so listing them as "retired" would be a lie that hides the
 * real reason.
 */
export interface ExcludedByDesign {
  url: string;
  reason: string;
}

/**
 * CIDR-network feeds. Every row is a NETWORK (`1.10.16.0/20`, `0.0.0.0/8`), not
 * a host an analyst can act on, and a live-IOC stream keyed on
 * `value + kind` has no way to render one. FireHOL L1 additionally leads with
 * bogon space (RFC1918/reserved), which the `isBenign` allowlist already
 * discards. These belong in an egress-firewall / ASN-blocklist surface, not in
 * an indicator stream — surfacing them here would emit either 4,642 useless
 * network objects or 4,642 copies of the allowlist-rejected ranges.
 */
export const EXCLUDED_BY_DESIGN: readonly ExcludedByDesign[] = [
  {
    url: 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset',
    reason: 'CIDR networks only (4,642 rows, mostly bogon space); not discrete indicators.',
  },
  {
    url: 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset',
    reason: 'CIDR networks only (12,818 rows); not discrete indicators.',
  },
  {
    url: 'https://www.spamhaus.org/drop/drop_v4.json',
    reason: 'CIDR + SBL allocations (1,642 rows); a network-blocklist surface, not an indicator stream.',
  },
  {
    url: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt',
    reason: 'Already ingested as `bitwire-inbound`, and 66MB — the largest body in the roster by 3x.',
  },
];

/** A verified-live feed from the wider open-source ecosystem. */
export interface CuratedFeed {
  /** Registry source id — must match the live-iocs FEED_SOURCES entry. */
  id: string;
  /** Display name for SOURCE_META / briefing attribution. */
  name: string;
  url: string;
  kind: IocType;
  /**
   * Short description rendered as the IOC `context`. A function form appends
   * the parsed row's own detail — matching `TextFeedConfig['context']` in
   * live-iocs.ts so these entries can be spread straight into `textFeedSource`.
   */
  context: string | ((e: { context?: string }) => string | undefined);
  /**
   * Tried in order when the primary fails. Every entry here was probed and
   * returns real rows — a fallback that 404s is worse than no fallback because
   * it makes the debug view misleading.
   */
  fallbackUrls?: string[];
  /**
   * `1` = must survive the synchronous cold-start fan-out's subrequest budget.
   * `2` = best-effort there; the queue path (batched, one slice per batch) is
   * the primary refresh model and has no per-source ceiling.
   *
   * Tier 1 is the evidence-bearing feeds: named C2 infrastructure with
   * per-entry timestamps and machine-family attribution. Tier 2 is high-volume
   * but context-free IP/domain blocklists that overlap heavily with each other.
   */
  priority: 1 | 2;
  /**
   * Approximate rows at the 2026-10-05 audit. Used by the audit script to
   * detect a feed that has silently collapsed to near-empty since onboarding.
   */
  auditRows: number;
}

/**
 * Verified-live feeds adopted from the open-source catalogue.
 *
 * Selection criteria, applied in order:
 *  1. Returns real indicator rows on an unauthenticated GET (no key, no ToS,
 *     no HTML shell, no empty stub).
 *  2. Adds coverage the existing 29-source registry does not already have —
 *     mostly named C2 frameworks (Cobalt Strike), which the current roster has
 *     only as a single untyped C2IntelFeeds list.
 *  3. Static file on a stable host (raw.githubusercontent / a vendor path), so it
 *     does not rot the way an interactive-docs URL does.
 *  4. Bounded body size. Several candidates are 10–66MB; a 66MB parse per
 *     hourly refresh is a colo memory risk for no marginal coverage.
 */
export const CURATED_FEEDS: readonly CuratedFeed[] = [
  // ── Tier 1: named C2 infrastructure ─────────────────────────────────────
  {
    id: 'foxit-cobaltstrike',
    name: 'Fox-IT Cobalt Strike servers',
    url: 'https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/cobaltstrike-servers.csv',
    kind: 'ipv4',
    context: 'Cobalt Strike team server (extraneous space scan)',
    fallbackUrls: ['https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/combined-report.csv'],
    priority: 1,
    auditRows: 9587,
  },
  {
    id: 'carbonblack-c2',
    name: 'Carbon Black active C2 (Cobalt Strike)',
    url: 'https://raw.githubusercontent.com/carbonblack/active_c2_ioc_public/main/cobaltstrike/actor-specific/cobaltstrike_pyxie.csv',
    kind: 'ipv4',
    context: 'Cobalt Strike C2 (Carbon Black active C2 program)',
    priority: 1,
    auditRows: 228,
  },
  {
    id: 'threatview-c2',
    name: 'Threatview.io Cobalt Strike C2',
    url: 'https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt',
    kind: 'ipv4',
    context: 'high confidence Cobalt Strike C2',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt'],
    priority: 1,
    auditRows: 1178,
  },
  {
    id: 'c2intel-domains',
    name: 'C2IntelFeeds C2 domains',
    url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURL-30day-filter-abused.csv',
    kind: 'domain',
    context: entryContextFor('C2IntelFeeds 30-day C2 domain'),
    fallbackUrls: ['https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv'],
    priority: 1,
    auditRows: 92,
  },
  {
    id: 'threatfox-hostfile',
    name: 'abuse.ch ThreatFox hostfile',
    url: 'https://threatfox.abuse.ch/downloads/hostfile/',
    // NB: domain, not IP. The file is hosts(5)-format and its address column is
    // the literal `127.0.0.1` placeholder on all 38,123 rows (audited
    // 2026-10-05) — upstream ships a DOMAIN blocklist in hosts syntax. See
    // `parseThreatfoxHostfile`.
    kind: 'domain',
    context: 'ThreatFox botnet C2 host',
    fallbackUrls: ['https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv'],
    priority: 1,
    auditRows: 38122,
  },
  {
    id: 'threatfox-urls',
    name: 'abuse.ch ThreatFox recent URLs',
    url: 'https://threatfox.abuse.ch/export/csv/urls/recent/',
    kind: 'url',
    context: entryContextFor('ThreatFox payload delivery'),
    fallbackUrls: ['https://urlhaus.abuse.ch/downloads/csv_recent/'],
    priority: 1,
    auditRows: 328,
  },
  {
    id: 'threatcluster-ip',
    name: 'ThreatCluster public IOCs (IP)',
    url: 'https://threatcluster.io/api/iocs/public/ips.txt',
    kind: 'ipv4',
    context: 'community-submitted malicious IP',
    fallbackUrls: ['https://threatcluster.io/api/iocs/public/domains.txt'],
    priority: 1,
    auditRows: 103,
  },
  {
    id: 'threatcluster-domains',
    name: 'ThreatCluster public IOCs (domain)',
    url: 'https://threatcluster.io/api/iocs/public/domains.txt',
    kind: 'domain',
    context: 'community-submitted malicious domain',
    fallbackUrls: ['https://threatcluster.io/api/iocs/public/ips.txt'],
    priority: 1,
    auditRows: 451,
  },

  // ── Tier 2: high-volume blocklists ───────────────────────────────────────
  {
    id: 'greensnow',
    name: 'GreenSnow',
    url: 'https://blocklist.greensnow.co/greensnow.txt',
    kind: 'ipv4',
    context: 'GreenSnow — SSH brute-force / scanning source',
    fallbackUrls: ['https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt'],
    priority: 2,
    auditRows: 4583,
  },
  {
    id: 'siberkapan',
    name: 'SiberKapan',
    url: 'https://siberkapan.org/api/v1/list/txt',
    kind: 'ipv4',
    context: 'SiberKapan — attack source',
    fallbackUrls: ['https://lists.blocklist.de/lists/all.txt'],
    priority: 2,
    auditRows: 53498,
  },
  {
    id: 'bruteforce-login',
    name: 'Blocklist.de bruteforcelogin',
    url: 'https://lists.blocklist.de/lists/bruteforcelogin.txt',
    kind: 'ipv4',
    context: 'brute-force / credential-stuffing source',
    fallbackUrls: ['https://danger.rulez.sk/projects/bruteforceblocker/blist.php'],
    priority: 2,
    auditRows: 159,
  },
  {
    id: 'bl-de-ssh',
    name: 'Blocklist.de SSH attackers',
    url: 'https://lists.blocklist.de/lists/ssh.txt',
    kind: 'ipv4',
    context: 'SSH attack source',
    fallbackUrls: ['https://blocklist.greensnow.co/greensnow.txt'],
    priority: 2,
    auditRows: 1557,
  },
  {
    id: 'tsirolnik-spam',
    name: 'tsirolnik spam domains',
    url: 'https://raw.githubusercontent.com/tsirolnik/spam-domains-list/master/spamdomains.txt',
    kind: 'domain',
    context: 'spam / malvertising domain',
    fallbackUrls: [
      'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    ],
    priority: 2,
    auditRows: 51672,
  },
  {
    id: 'botvrij-domain',
    name: 'Botvrij.eu domains',
    url: 'https://www.botvrij.eu/data/blocklist/blocklist_domain.csv',
    kind: 'domain',
    context: 'Botvrij malicious domain',
    fallbackUrls: ['https://www.botvrij.eu/data/ioclist.url.raw'],
    priority: 2,
    auditRows: 3894,
  },
  {
    id: 'sslbl-ja3',
    name: 'abuse.ch SSLBL JA3 fingerprints',
    url: 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv',
    kind: 'hash',
    // A JA3 fingerprint is the MD5 of a hashed TLS ClientHello, so `hash` is the
    // correct IocType — it drops straight into hash/JA3 detection rules.
    context: entryContextFor('SSLBL JA3 client fingerprint'),
    priority: 2,
    auditRows: 97,
  },
];

/** Wrap a static description so tier-1 feeds can append per-row detail. */
function entryContextFor(base: string) {
  return (e: { context?: string }): string | undefined => (e.context ? `${base}: ${e.context}` : base);
}

/** Every curated url + fallback, for the audit script and the drift test. */
export function curatedUrls(): string[] {
  const out: string[] = [];
  for (const f of CURATED_FEEDS) {
    out.push(f.url);
    for (const fb of f.fallbackUrls ?? []) out.push(fb);
  }
  return out;
}

/** True when `url` is a known-dead upstream that must not be reintroduced. */
export function isRetiredUrl(url: string): boolean {
  return RETIRED_FEEDS.some((r) => r.url === url);
}

/** Look up a curated feed by registry source id. */
export function curatedFeed(id: string): CuratedFeed | undefined {
  return CURATED_FEEDS.find((f) => f.id === id);
}

export interface FeedHealthReport {
  url: string;
  ok: boolean;
  status?: number;
  rows: number;
  bytes: number;
  /** `true` when the body is an HTML page — a 200 that is NOT a feed. */
  html: boolean;
  note?: string;
}

/**
 * Probe one URL and classify the result the way `fetchText` does, so the audit
 * script and the runtime agree on what counts as a usable feed.
 *
 * NOT on the hot path — the audit script and tests only. It deliberately
 * duplicates `fetchText`'s HTML-body check rather than importing it, because
 * `fetchText` lives in the route module and pulls in the whole live-iocs
 * dependency graph (budget accounting, D1, confidence scoring).
 */
export async function verifyFeedHealth(url: string, timeoutMs = 20_000): Promise<FeedHealthReport> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: '*/*' },
    });
    const body = res.ok ? await res.text() : '';
    const head = body.trimStart().slice(0, 16);
    const html = head.startsWith('<!DOCTYPE') || head.startsWith('<html');
    const rows = body.split('\n').filter((l) => {
      const t = l.trim();
      return t.length > 0 && !t.startsWith('#') && !t.startsWith(';') && !t.startsWith('!');
    }).length;
    return {
      url,
      ok: res.ok && !html && rows > 0,
      status: res.status,
      rows,
      bytes: body.length,
      html,
      note: !res.ok
        ? `HTTP ${res.status}`
        : html
          ? 'HTML page, not a feed'
          : rows === 0
            ? 'no indicator rows'
            : undefined,
    };
  } catch (e) {
    return {
      url,
      ok: false,
      rows: 0,
      bytes: 0,
      html: false,
      note: e instanceof Error ? e.message.slice(0, 120) : 'unknown error',
    };
  } finally {
    clearTimeout(timer);
  }
}
