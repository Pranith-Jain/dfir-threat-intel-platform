import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { SOURCE_RELIABILITY_REGISTRY } from '../lib/confidence';
import { SNAPSHOT_CACHE_KEY } from './snapshot';
import { CVE_RECENT_CACHE_KEY } from './cve-recent';
import { CVE_TRENDS_CACHE_KEY } from '../lib/cvemon';
import { CVE_DIGEST_CACHE_KEY } from './cve-digest';
import { MALWARE_SAMPLES_CACHE_KEY } from './malware-samples';
import { PHISHING_URLS_CACHE_KEY } from './phishing-urls';
import { REDDIT_FEED_CACHE_KEY } from './reddit-feed';
import { X_FEED_CACHE_KEY } from './x-feed';
import { TELEGRAM_FEED_CACHE_KEY } from './telegram-feed';
import { RANSOMWARE_RECENT_CACHE_KEY } from './ransomware-recent';
import { ONION_WATCH_CACHE_KEY } from './onion-watch';
import { THREAT_MAP_CACHE_KEY } from './threat-map';
import { DETECTION_RULES_CACHE_KEY } from './detection-rules';
import { IOC_CORRELATION_CACHE_KEY } from './ioc-correlation';
import { ACTOR_TIMELINE_CACHE_KEY } from './actor-timeline';
import { VICTIM_RELEAKS_CACHE_KEY } from './victim-releaks';
import { LIVE_IOCS_CACHE_KEY } from './live-iocs';
import { CYBERCRIME_CACHE_KEY } from './cybercrime';
import { DEEPDARKCTI_CACHE_KEY } from './deepdarkcti';
import { rlProxyCacheKey } from './ransomwarelive';
import { NEGOTIATIONS_CACHE_KEY } from './negotiations';
import { STEALER_FORUM_INTEL_CACHE_KEY } from './stealer-forum-intel';
import { BREACH_FORUMS_CACHE_KEY } from './breach-forums';
import { INTEL_BUNDLE_CACHE_KEY } from './intel-bundle';
import { concurrentMap } from '../lib/concurrent-map';
import { safeNullLog } from '../lib/safe-catch';

/**
 * Feed-status dashboard. Reads every per-feed edge-cache entry directly
 * (cache.match) so we get exactly the body a real user request would see.
 *
 * We CAN'T fetch /api/v1/<feed> from inside the worker — Cloudflare blocks
 * same-zone subrequests with HTTP 522. So the original "probe over HTTP"
 * design failed, and we now read the Cache API entries each feed handler
 * writes. When a cache entry doesn't exist we report status='cold' — the
 * feed isn't broken per se, just hasn't been hit yet (or its cache TTL
 * lapsed and no one re-requested).
 */

const CACHE_TTL = 5 * 60;
export const FEED_STATUS_CACHE_KEY = 'https://feed-status-cache.internal/v4-af-ddc';

type Status = 'ok' | 'degraded' | 'down' | 'cold';

interface FeedStatusRow {
  id: string;
  label: string;
  page_path: string;
  api_path: string;
  status: Status;
  reason: string;
  metrics?: Record<string, number>;
  upstream_age_s?: number;
  /** Admiralty source reliability grade (A–F), mapped from SOURCE_RELIABILITY_REGISTRY */
  reliability?: string;
  /** Source category from registry */
  category?: string;
  /** Human-readable description */
  description?: string;
  /**
   * NATO Admiralty information credibility (1–6), computed from live feed
   * health + freshness. Distinct from `reliability` (a fixed property of the
   * source): credibility grades the *current data point*.
   *   1 Confirmed     — ok & fresh (<30min)
   *   2 Probably true — ok but older
   *   3 Possibly true — degraded
   *   4 Doubtful      — down w/ last-good fallback
   *   5 Improbable    — down w/o fallback
   *   6 Cannot judge  — cold (no data ever)
   */
  info_credibility?: number;
  /** Combined Admiralty grade in standard "B-2" notation. */
  admiralty_grade?: string;
}

export interface FeedStatusResponse {
  generated_at: string;
  rows: FeedStatusRow[];
  overall: Status;
  /** Per-status aggregate counts */
  total_sources: number;
  healthy: number;
  degraded: number;
  down: number;
  cold: number;
  /**
   * Per-NATO-Admiralty-reliability (A–F) distribution across rows. Sources
   * without a registered reliability letter are bucketed as 'ungraded' so
   * they still show in the histogram. Used by the dashboard widget to show
   * a quick "how authoritative is the source mix" read.
   */
  reliability_distribution: Record<string, number>;
  /**
   * Compact list of source IDs that are not fully healthy. Lets the UI
   * badge a single page link / banner without re-walking the rows array.
   * Each entry includes the row's `reason` for the badge tooltip.
   */
  degraded_sources: Array<{ id: string; status: Status; reason: string; page_path: string }>;
}

interface FeedProbeSpec {
  id: string;
  label: string;
  page_path: string;
  api_path: string;
  cache_key: string;
  reliability?: string; // Admiralty grade (A–F)
  category?: string;
  description?: string;
  /**
   * Registry source IDs this probe aggregates. When set and `reliability`
   * isn't, the probe's reliability is derived as the highest Admiralty
   * grade among the sources ("best evidence wins" for a composite signal).
   * Probes that don't map to a single fixed source set should set
   * `reliability` explicitly instead.
   */
  sourceIds?: string[];
  evaluate: (body: unknown) => { status: Status; reason: string; metrics?: Record<string, number>; ageS?: number };
}

// NATO Admiralty ranks in descending order of authority. Used to pick the
// "best evidence" letter from a set of aggregated source reliabilities.
const RELIABILITY_RANK: Record<string, number> = { A: 6, B: 5, C: 4, D: 3, E: 2, F: 1 };

/**
 * Pick the highest Admiralty reliability letter from a set of source IDs.
 * Returns undefined when no source is registered. Lower rank = weaker
 * signal, so the probe reports its strongest backing. Exported for tests.
 */
export function aggregateReliability(sourceIds: string[] | undefined): string | undefined {
  if (!sourceIds || sourceIds.length === 0) return undefined;
  let best: string | undefined;
  let bestRank = 0;
  for (const id of sourceIds) {
    const entry = SOURCE_RELIABILITY_REGISTRY[id];
    if (!entry) continue;
    const rank = RELIABILITY_RANK[entry.reliability] ?? 0;
    if (rank > bestRank) {
      bestRank = rank;
      best = entry.reliability;
    }
  }
  return best;
}

function ageSeconds(iso: string | undefined): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.max(0, Math.round((Date.now() - t) / 1000));
}

/**
 * Map (status, age-seconds) → NATO Admiralty information credibility (1–6).
 * Lives next to the probe helpers so the mapping is kept in sync with the
 * rest of the status vocabulary.
 *
 *   1 Confirmed     — ok & fresh
 *   2 Probably true — ok & older
 *   3 Possibly true — degraded
 *   4 Doubtful      — down w/ last-good (served stale data)
 *   5 Improbable    — down w/o fallback
 *   6 Cannot judge  — cold (no cached payload ever)
 */
function infoCredibilityFor(status: Status, ageS: number | undefined): number {
  if (status === 'ok') {
    if (ageS !== undefined && ageS < 1800) return 1;
    return 2;
  }
  if (status === 'degraded') return 3;
  if (status === 'down') {
    // Down is graded by whether a last-good fallback is serving. feed-status
    // doesn't see the cache body, so we use age as the proxy: very fresh
    // age means we're still serving last-good; missing age means no fallback.
    if (ageS !== undefined) return 4;
    return 5;
  }
  return 6; // cold
}

function intField(obj: unknown, key: string): number | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  const v = (obj as Record<string, unknown>)[key];
  return typeof v === 'number' ? v : undefined;
}

function strField(obj: unknown, key: string): string | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  const v = (obj as Record<string, unknown>)[key];
  return typeof v === 'string' ? v : undefined;
}

function arrField(obj: unknown, key: string): unknown[] | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  const v = (obj as Record<string, unknown>)[key];
  return Array.isArray(v) ? v : undefined;
}

/**
 * Authoritative probe → registry source mapping. Each entry lists the
 * source IDs (keys in SOURCE_RELIABILITY_REGISTRY) that back a probe.
 * Used two ways:
 *   1. probeOne derives the probe's Admiralty reliability as the highest
 *      letter across its source set ("best evidence wins" for a composite
 *      signal).
 *   2. buildPassiveProbes skips any source already covered by a probe, so
 *      a single real row per upstream (no duplicate probe + passive pair
 *      for, say, 'cisa-kev' when 'cve-recent' is the user-facing probe).
 *
 * Keep this in sync with the `sourceIds` field on every PROBES entry.
 * Declared before PROBES so each probe can pull its source list at
 * module-initialization time without a forward-reference error.
 */
export const PROBE_SOURCES: Record<string, string[]> = {
  'live-iocs': ['abusech-urlhaus', 'abusech-threatfox', 'abusech-malwarebazaar'],
  'phishing-urls': ['phish-tank', 'openphish'],
  'x-feed': ['x-twitter', 'bluesky'],
  'stealer-forum-intel': ['hudson-rock'],
  // dbu.gs (B) sits alongside the A-grade advisory sources: it is a gap-filler,
  // so NVD/KEV remain the probe's reliability anchor and the aggregate stays A.
  'cve-recent': ['nvd', 'cisa-kev', 'dbugs', 'exploitgrid'],
  // The 24h digest is anchored on ctiwatch (B) with VulnTracker volume for
  // context — best-evidence-wins keeps it at B.
  'cve-digest': ['ctiwatch', 'vulntracker'],
  'cve-trends': ['cvemon'],
  'malware-samples': ['abusech-malwarebazaar'],
  'ransomware-recent': ['ransomlook'],
  'onion-watch': ['ransomlook'],
  'victim-releaks': ['ransomlook'],
  'actor-timeline': ['ransomlook', 'ransomwarelive'],
  negotiations: ['ransomlook', 'ransomwarelive'],
  'rl-cyberattacks': ['ransomwarelive'],
  'telegram-feed': ['telegram-feed'],
  'reddit-feed': ['reddit'],
  'breach-forums': ['deepdarkcti'],
};

export const PROBES: FeedProbeSpec[] = [
  {
    id: 'snapshot',
    label: 'Snapshot (composite)',
    page_path: '/threatintel',
    api_path: '/api/v1/snapshot',
    cache_key: SNAPSHOT_CACHE_KEY,
    // Composite of 6 underlying composer sources (ransomware/telegram/scam/
    // threat_intel/tech_ai/briefings). Most are B–C primary/secondary. The
    // composite is at most as authoritative as its strongest leg, which is
    // B (ransomware lookups, telegram leaks). Marked as B.
    reliability: 'B',
    category: 'primary',
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'generated_at'));
      // Keep in sync with routes/snapshot.ts — the composite snapshot
      // emits one top-level key per composer source. This list was
      // stale (onion/threat_map/rules were retired in favour of
      // scam/threat_intel/tech_ai) which made the probe report 3/6
      // "down" despite every source being healthy.
      const sources = ['ransomware', 'telegram', 'scam', 'threat_intel', 'tech_ai', 'briefings'];
      const okCount = sources.filter((k) => {
        const v = (body as Record<string, unknown>)[k];
        return v && typeof v === 'object' && (v as { ok?: boolean }).ok === true;
      }).length;
      const status: Status = okCount >= 5 ? 'ok' : okCount >= 2 ? 'degraded' : 'down';
      return {
        status,
        reason: `${okCount} / ${sources.length} composer sources reporting ok`,
        metrics: { sources_ok: okCount, sources_total: sources.length },
        ageS,
      };
    },
  },
  {
    id: 'cve-recent',
    label: 'CVE — NVD + CISA KEV',
    page_path: '/threatintel/cve-list',
    api_path: '/api/v1/cve-recent',
    cache_key: CVE_RECENT_CACHE_KEY,
    sourceIds: PROBE_SOURCES['cve-recent'],
    evaluate: (body) => {
      const count = intField(body, 'count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const sources = arrField(body, 'sources') ?? [];
      const find = (id: string) =>
        sources.find((s) => (s as { id?: string }).id === id) as { count?: number } | undefined;
      const nvdCount = find('nvd-published-14d')?.count ?? 0;
      const kevCount = find('cisa-kev-added-30d')?.count ?? 0;
      const dbugsCount = find('dbugs')?.count ?? 0;
      const exploitGridCount = find('exploitgrid')?.count ?? 0;
      const status: Status = nvdCount > 0 && kevCount > 0 ? 'ok' : count > 0 ? 'degraded' : 'down';
      return {
        status,
        reason:
          nvdCount > 0 && kevCount > 0
            ? `NVD ${nvdCount} + KEV ${kevCount} entries${dbugsCount > 0 || exploitGridCount > 0 ? ` + ${dbugsCount} dbu.gs / ${exploitGridCount} exploitgrid gap-fills` : ''}`
            : nvdCount === 0
              ? 'NVD rate-limited — serving KEV only'
              : 'KEV unreachable — serving NVD only',
        // Gap-filler counts ride along as metrics so a drop to 0 is visible here
        // rather than only as a missing row on the CVE list.
        metrics: { count, nvd: nvdCount, kev: kevCount, dbugs: dbugsCount, exploitgrid: exploitGridCount },
        ageS,
      };
    },
  },
  {
    id: 'cve-trends',
    label: 'CVE trending — social attention (cvemon)',
    page_path: '/threatintel/cve-intel?tab=trending',
    api_path: '/api/v1/cve-trends',
    cache_key: CVE_TRENDS_CACHE_KEY,
    sourceIds: PROBE_SOURCES['cve-trends'],
    evaluate: (body) => {
      const count = intField(body, 'count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const stale = (body as { stale?: boolean }).stale === true;
      // cvemon is a single upstream with no fallback tiers, so there is no
      // partial-degradation story: either it answered or we are on the KV
      // last-good payload. `stale` is surfaced in the reason because a stale
      // trending list is actively misleading — it looks like "nothing is
      // trending" when it really means "we could not ask".
      const status: Status = count > 0 && !stale ? 'ok' : count > 0 ? 'degraded' : 'down';
      return {
        status,
        reason:
          count > 0
            ? stale
              ? 'cvemon unreachable — serving cached rankings'
              : `${count} CVEs trending on social`
            : 'cvemon returned no trending CVEs',
        metrics: { count },
        ageS,
      };
    },
  },
  {
    id: 'cve-digest',
    label: 'CVE digest — last 24h (CTIWatch)',
    page_path: '/threatintel/cves/digest',
    api_path: '/api/v1/cve-digest',
    cache_key: CVE_DIGEST_CACHE_KEY,
    sourceIds: PROBE_SOURCES['cve-digest'],
    evaluate: (body) => {
      const count = intField(body, 'count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const partial = (body as { partial?: unknown }).partial === true;
      const sources = arrField(body, 'sources') ?? [];
      const ctw = sources.find((s) => (s as { id?: string }).id === 'ctiwatch') as
        { ok?: boolean; count?: number } | undefined;
      const status: Status = count > 0 ? (partial ? 'degraded' : 'ok') : ctw?.ok === false ? 'down' : 'down';
      return {
        status,
        reason:
          count > 0
            ? `${count} CVEs in the last 24h${partial ? ' (partial — anonymous offset ceiling hit)' : ''}`
            : ctw?.ok === false
              ? 'CTIWatch unreachable (session mint failed)'
              : 'no CVEs in window or cache cold',
        metrics: { count },
        ageS,
      };
    },
  },
  {
    id: 'malware-samples',
    label: 'Malware samples (MalwareBazaar)',
    page_path: '/threatintel/live-iocs',
    api_path: '/api/v1/malware-samples',
    cache_key: MALWARE_SAMPLES_CACHE_KEY,
    sourceIds: PROBE_SOURCES['malware-samples'],
    evaluate: (body) => {
      const count = intField(body, 'count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = count >= 20 ? 'ok' : count > 0 ? 'degraded' : 'down';
      return {
        status,
        reason: count > 0 ? `${count} samples from MalwareBazaar recent CSV` : 'MalwareBazaar upstream unreachable',
        metrics: { count },
        ageS,
      };
    },
  },
  {
    id: 'phishing-urls',
    label: 'Phishing URLs (PhishTank + OpenPhish)',
    page_path: '/threatintel/live-iocs',
    api_path: '/api/v1/phishing-urls',
    cache_key: PHISHING_URLS_CACHE_KEY,
    sourceIds: PROBE_SOURCES['phishing-urls'],
    evaluate: (body) => {
      const total = intField(body, 'total') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const sources = arrField(body, 'sources') ?? [];
      const okSrc = sources.filter((s) => (s as { ok?: boolean }).ok === true).length;
      const status: Status = okSrc >= 2 ? 'ok' : okSrc === 1 ? 'degraded' : 'down';
      return {
        status,
        reason: `${okSrc} / ${sources.length} sources reachable · ${total} URLs`,
        metrics: { total, sources_ok: okSrc },
        ageS,
      };
    },
  },
  {
    id: 'reddit-feed',
    label: 'Reddit firehose',
    page_path: '/threatintel/reddit',
    api_path: '/api/v1/reddit-feed',
    cache_key: REDDIT_FEED_CACHE_KEY,
    sourceIds: PROBE_SOURCES['reddit-feed'],
    evaluate: (body) => {
      const items = (arrField(body, 'items') ?? []).length;
      const subs = arrField(body, 'subs') ?? [];
      const ok = subs.filter((s) => (s as { ok?: boolean }).ok === true).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = ok >= subs.length * 0.7 ? 'ok' : ok >= 2 ? 'degraded' : 'down';
      return {
        status,
        reason: `${ok} / ${subs.length} subreddits returning · ${items} posts`,
        metrics: { items, subs_ok: ok, subs_total: subs.length },
        ageS,
      };
    },
  },
  {
    id: 'x-feed',
    label: 'Social firehose (Bluesky + Mastodon)',
    page_path: '/threatintel/x',
    api_path: '/api/v1/x-feed',
    cache_key: X_FEED_CACHE_KEY,
    sourceIds: PROBE_SOURCES['x-feed'],
    evaluate: (body) => {
      const items = (arrField(body, 'items') ?? []).length;
      const handles = arrField(body, 'handles') ?? [];
      const ok = handles.filter((h) => (h as { ok?: boolean }).ok === true).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = ok >= handles.length * 0.6 ? 'ok' : ok >= 2 ? 'degraded' : 'down';
      return {
        status,
        reason: `${ok} / ${handles.length} accounts returning · ${items} posts`,
        metrics: { items, handles_ok: ok, handles_total: handles.length },
        ageS,
      };
    },
  },
  {
    id: 'telegram-feed',
    label: 'Telegram firehose',
    page_path: '/threatintel/cybersec',
    api_path: '/api/v1/telegram-feed',
    cache_key: TELEGRAM_FEED_CACHE_KEY,
    sourceIds: PROBE_SOURCES['telegram-feed'],
    evaluate: (body) => {
      const items = (arrField(body, 'items') ?? []).length;
      const channels = arrField(body, 'channels') ?? [];
      const ok = channels.filter((c) => (c as { ok?: boolean }).ok === true).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = ok >= channels.length * 0.7 ? 'ok' : ok >= 2 ? 'degraded' : 'down';
      return {
        status,
        reason: `${ok} / ${channels.length} channels returning · ${items} messages`,
        metrics: { items, channels_ok: ok, channels_total: channels.length },
        ageS,
      };
    },
  },
  {
    id: 'ransomware-recent',
    label: 'Ransomware activity (Ransomlook)',
    page_path: '/threatintel/ransomware-activity',
    api_path: '/api/v1/ransomware-recent',
    cache_key: RANSOMWARE_RECENT_CACHE_KEY,
    sourceIds: PROBE_SOURCES['ransomware-recent'],
    evaluate: (body) => {
      const count = intField(body, 'count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = count >= 20 ? 'ok' : count > 0 ? 'degraded' : 'down';
      return {
        status,
        reason: count > 0 ? `${count} recent leak-site claims` : 'Ransomlook upstream unreachable',
        metrics: { count },
        ageS,
      };
    },
  },
  {
    id: 'onion-watch',
    label: 'Onion mirror inventory (Ransomlook)',
    page_path: '/threatintel/onion-watch',
    api_path: '/api/v1/onion-watch',
    cache_key: ONION_WATCH_CACHE_KEY,
    sourceIds: PROBE_SOURCES['onion-watch'],
    evaluate: (body) => {
      const groups = (arrField(body, 'groups') ?? []).length;
      const reachable = intField(body, 'reachable_count') ?? 0;
      const total = intField(body, 'total_count') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status =
        total >= 20 && reachable === 0
          ? 'degraded'
          : reachable >= groups * 0.5
            ? 'ok'
            : reachable > 0
              ? 'degraded'
              : 'down';
      return {
        status,
        reason:
          total >= 20 && reachable === 0
            ? `Ransomlook prober offline (0 reachable across ${total} mirrors)`
            : `${reachable} / ${groups} groups reachable · ${total} mirrors`,
        metrics: { groups, reachable, total },
        ageS,
      };
    },
  },
  {
    id: 'threat-map',
    label: 'Threat map (geo + IOC types)',
    page_path: '/threatintel/threat-map',
    api_path: '/api/v1/threat-map',
    cache_key: THREAT_MAP_CACHE_KEY,
    // Inferred from multiple IP blocklists (ipsum/cinsarmy/bitwire/etc.)
    // rolled up at query time. No single underlying source — grade as C
    // (secondary, consensus-based) per admiralty guidance for derived
    // signals.
    reliability: 'C',
    category: 'secondary',
    evaluate: (body) => {
      const totalIps = intField(body, 'total_ips') ?? 0;
      const countries = (arrField(body, 'countries') ?? []).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = totalIps >= 100 ? 'ok' : totalIps > 0 ? 'degraded' : 'down';
      return {
        status,
        reason: `${totalIps} IPs across ${countries} countries`,
        metrics: { total_ips: totalIps, countries },
        ageS,
      };
    },
  },
  {
    id: 'detection-rules',
    label: 'Detection rules (multi-source commits)',
    page_path: '/threatintel/rules',
    api_path: '/api/v1/rules',
    cache_key: DETECTION_RULES_CACHE_KEY,
    // Author-curated multi-repo fan-out (Sigma/Elastic/Splunk/etc.). B:
    // primary enough that the rules are authoritative for what they detect,
    // but coverage gaps are common so not A.
    reliability: 'B',
    category: 'primary',
    evaluate: (body) => {
      const sources = (arrField(body, 'sources') ?? []).length;
      const commits = arrField(body, 'recent_commits') ?? [];
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = sources >= 8 && commits.length >= 30 ? 'ok' : sources > 0 ? 'degraded' : 'down';
      return {
        status,
        reason: `${sources} repos · ${commits.length} recent commits`,
        metrics: { sources, commits: commits.length },
        ageS,
      };
    },
  },
  {
    id: 'victim-releaks',
    label: 'Victim re-leak detection (Ransomlook)',
    page_path: '/threatintel/re-leaks',
    api_path: '/api/v1/victim-releaks',
    cache_key: VICTIM_RELEAKS_CACHE_KEY,
    sourceIds: PROBE_SOURCES['victim-releaks'],
    evaluate: (body) => {
      const releaks = (arrField(body, 'releaks') ?? []).length;
      const scanned = intField(body, 'victims_scanned') ?? 0;
      const groups = intField(body, 'groups_scanned') ?? 0;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = groups >= 5 ? 'ok' : groups > 0 ? 'degraded' : 'down';
      return {
        status,
        reason:
          groups > 0
            ? `${groups} groups · ${scanned.toLocaleString()} victims scanned · ${releaks} re-leaks`
            : 'Ransomlook unreachable',
        metrics: { releaks, scanned, groups },
        ageS,
      };
    },
  },
  {
    id: 'actor-timeline',
    label: 'Actor activity timeline (Ransomlook + MITRE)',
    page_path: '/threatintel/actor-timeline',
    api_path: '/api/v1/actor-timeline',
    cache_key: ACTOR_TIMELINE_CACHE_KEY,
    sourceIds: PROBE_SOURCES['actor-timeline'],
    evaluate: (body) => {
      const groupRows = arrField(body, 'groups') ?? [];
      const groups = groupRows.length;
      // Per-group fetch failures are now backfilled from /api/recent rather
      // than warned about; `partial` rows are the new "ransomlook was flaky"
      // signal. Surface that count so observability isn't lost.
      const partial = groupRows.filter(
        (g) => typeof g === 'object' && g !== null && (g as { partial?: unknown }).partial === true
      ).length;
      const warnings = (arrField(body, 'warnings') ?? []).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = groups >= 5 ? 'ok' : groups > 0 ? 'degraded' : 'down';
      return {
        status,
        reason:
          groups > 0
            ? `${groups} active groups${partial > 0 ? ` · ${partial} recent-feed backfilled` : ''}`
            : 'Ransomlook per-group endpoints unreachable',
        metrics: { groups, partial, warnings },
        ageS,
      };
    },
  },
  {
    id: 'live-iocs',
    label: 'Live IOC stream',
    page_path: '/threatintel/live-iocs',
    api_path: '/api/v1/live-iocs',
    cache_key: LIVE_IOCS_CACHE_KEY,
    sourceIds: PROBE_SOURCES['live-iocs'],
    evaluate: (body) => {
      const total = intField(body, 'total') ?? 0;
      const sources = arrField(body, 'sources') ?? [];
      const okSrc = sources.filter((s) => (s as { ok?: boolean }).ok === true).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status = okSrc >= sources.length * 0.6 && total > 0 ? 'ok' : okSrc >= 2 ? 'degraded' : 'down';
      return {
        status,
        reason: `${okSrc} / ${sources.length} sources · ${total} live indicators`,
        metrics: { total, sources_ok: okSrc },
        ageS,
      };
    },
  },
  {
    id: 'ioc-correlation',
    label: 'Cross-source IOC correlation',
    page_path: '/threatintel/correlation',
    api_path: '/api/v1/ioc-correlation',
    cache_key: IOC_CORRELATION_CACHE_KEY,
    // Inferred signal — score is derived from "X of N feeds saw this IOC".
    // B because the underlying feeds are A/B primary; the inference itself
    // adds noise so the composite is at most B.
    reliability: 'B',
    category: 'primary',
    evaluate: (body) => {
      const totals = (body as { totals?: { correlated_indicators?: number; indicators_scanned?: number } }).totals;
      const correlated = totals?.correlated_indicators ?? 0;
      const scanned = totals?.indicators_scanned ?? 0;
      const sources = arrField(body, 'sources') ?? [];
      const okSrc = sources.filter((s) => (s as { ok?: boolean }).ok === true).length;
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const status: Status =
        okSrc >= sources.length * 0.7 && correlated > 0 ? 'ok' : okSrc >= sources.length * 0.4 ? 'degraded' : 'down';
      return {
        status,
        reason: `${okSrc} / ${sources.length} feeds · ${correlated} correlated of ${scanned.toLocaleString()} scanned`,
        metrics: { correlated, scanned, sources_ok: okSrc },
        ageS,
      };
    },
  },
  {
    id: 'af-datamarkets',
    label: 'AF Datamarkets',
    page_path: '/threatintel/cyber-crime',
    api_path: '/api/v1/cyber-crime',
    cache_key: CYBERCRIME_CACHE_KEY,
    // AndreaFortuna scrapes, single human-curated source. Not in the
    // registry; treat as C (secondary) — useful, but the editorial pipeline
    // is opaque.
    reliability: 'C',
    category: 'secondary',
    evaluate: (body) => {
      const sources = (body as { sources?: Array<{ label?: string; ok?: boolean; count?: number; stale?: boolean }> })
        ?.sources;
      const row = Array.isArray(sources) ? sources.find((s) => s.label === 'AndreaFortuna Datamarkets') : undefined;
      if (!row) return { status: 'cold' as const, reason: 'no AF row in cybercrime cache' };
      if (row.ok && !row.stale)
        return { status: 'ok' as const, reason: `${row.count ?? 0} items`, metrics: { items: row.count ?? 0 } };
      if (row.ok && row.stale) return { status: 'degraded' as const, reason: 'serving stale (last-good fallback)' };
      return { status: 'down' as const, reason: 'upstream failed; no fallback' };
    },
  },
  {
    id: 'deepdarkcti',
    label: 'deepdarkCTI Index',
    page_path: '/threatintel/deepdarkcti',
    api_path: '/api/v1/deepdarkcti',
    cache_key: DEEPDARKCTI_CACHE_KEY,
    // deepdarkCTI's GitHub-indexed CSVs (forums/marketplaces/leaks). Not in
    // the registry as a single entry; treat as C — primary content, but the
    // ingest is best-effort and missing a chunk of files at any time.
    reliability: 'C',
    category: 'secondary',
    evaluate: (body) => {
      const b = body as {
        sources?: Array<{ ok?: boolean; stale?: boolean }>;
        total?: number;
      };
      if (!b || !Array.isArray(b.sources)) {
        return { status: 'cold' as const, reason: 'no cached payload (visit the page once to warm the cache)' };
      }
      const total = b.total ?? 0;
      const files = b.sources.length;
      if (total === 0) return { status: 'down' as const, reason: 'all sources empty' };
      const anyStale = b.sources.some((s) => s.stale);
      const anyHardFail = b.sources.some((s) => !s.ok && !s.stale);
      if (anyHardFail || anyStale) {
        return {
          status: 'degraded' as const,
          reason: anyStale ? 'serving stale slices (last-good)' : 'some sources failed',
          metrics: { files, entries: total },
        };
      }
      return { status: 'ok' as const, reason: `${total} entries`, metrics: { files, entries: total } };
    },
  },
  {
    id: 'negotiations',
    label: 'Ransomware negotiations (RL PRO fan-out + Casualtek)',
    page_path: '/threatintel/negotiations',
    api_path: '/api/v1/negotiations',
    cache_key: NEGOTIATIONS_CACHE_KEY,
    sourceIds: PROBE_SOURCES['negotiations'],
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const count = (arrField(body, 'negotiations') ?? []).length;
      const groups = (arrField(body, 'groups') ?? []).length;
      const status: Status = count > 0 ? 'ok' : 'down';
      return {
        status,
        reason: count > 0 ? `${count} negotiations · ${groups} groups` : 'no negotiation records',
        metrics: { negotiations: count, groups },
        ageS,
      };
    },
  },
  {
    id: 'rl-cyberattacks',
    label: 'Ransomware cyber-attacks (ransomware.live PRO)',
    page_path: '/dfir/yara',
    api_path: '/api/v1/rl/cyberattacks',
    cache_key: rlProxyCacheKey('cyberattacks'),
    sourceIds: PROBE_SOURCES['rl-cyberattacks'],
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'fetched_at'));
      const data = (body as { data?: unknown } | null)?.data;
      let count = 0;
      if (Array.isArray(data)) count = data.length;
      else if (data && typeof data === 'object') {
        for (const k of ['victims', 'attacks', 'results', 'data', 'items']) {
          const v = (data as Record<string, unknown>)[k];
          if (Array.isArray(v)) {
            count = v.length;
            break;
          }
        }
      }
      const status: Status = count > 0 ? 'ok' : 'down';
      return {
        status,
        reason: count > 0 ? `${count} recent attacks` : 'no attack records in cached payload',
        metrics: { attacks: count },
        ageS,
      };
    },
  },
  {
    id: 'stealer-forum-intel',
    label: 'Combo & stealer-forum intel (deepdarkCTI + chatter)',
    page_path: '/threatintel/infostealer',
    api_path: '/api/v1/stealer-forum-intel',
    cache_key: STEALER_FORUM_INTEL_CACHE_KEY,
    sourceIds: PROBE_SOURCES['stealer-forum-intel'],
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const forums = arrField(body, 'forums') ?? [];
      const tracked = (body as { totals?: { tracked_sources?: number } } | null)?.totals?.tracked_sources ?? 0;
      const status: Status = forums.length > 0 ? 'ok' : 'down';
      return {
        status,
        reason: forums.length > 0 ? `${tracked} tracked sources · ${forums.length} categories` : 'no directory rows',
        metrics: { tracked_sources: tracked, categories: forums.length },
        ageS,
      };
    },
  },
  {
    id: 'breach-forums',
    label: 'Breach / leak-forum tracker (deepdarkCTI + curated)',
    page_path: '/threatintel/breach-forums',
    api_path: '/api/v1/breach-forums',
    cache_key: BREACH_FORUMS_CACHE_KEY,
    // deepdarkCTI isn't in the registry as a single entry (no admiralty
    // letter has been assigned), so we can't aggregate. Marked C: same
    // rationale as the deepdarkcti probe above.
    reliability: 'C',
    category: 'secondary',
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const rows = (arrField(body, 'rows') ?? []).length;
      // The curated list is always present; healthy = curated + directory.
      const dir = (body as { totals?: { directory?: number } } | null)?.totals?.directory ?? 0;
      const status: Status = rows > 0 ? (dir > 0 ? 'ok' : 'degraded') : 'down';
      return {
        status,
        reason: rows > 0 ? `${rows} forums (${dir} from directory)` : 'no rows',
        metrics: { rows, directory: dir },
        ageS,
      };
    },
  },
  {
    id: 'intel-bundle',
    label: 'STIX 2.1 intel-bundle pipeline',
    page_path: '/threatintel',
    api_path: '/api/v1/intel-bundle',
    cache_key: INTEL_BUNDLE_CACHE_KEY,
    // Derived: a STIX bundle synthesizes from all upstream sources. The
    // source-mix is A/B so the composite inherits B; the pipeline adds
    // shape-validity risk so not higher.
    reliability: 'B',
    category: 'primary',
    evaluate: (body) => {
      const ageS = ageSeconds(strField(body, 'generated_at'));
      const bundles = intField(body, 'bundles') ?? 0;
      const iocs = intField(body, 'ioc_total') ?? 0;
      const actors = intField(body, 'actor_total') ?? 0;
      const malware = intField(body, 'malware_total') ?? 0;
      // Bulk-enrich budget telemetry from the most recent build. Sustained
      // high `last_dropped` is the signal that MAX_FRESH_SUBREQUESTS=35 is
      // biting and the cap (or the provider list) needs retuning.
      const lastFresh = intField(body, 'last_fresh_subrequests') ?? 0;
      const lastDropped = intField(body, 'last_dropped_subrequests') ?? 0;
      const lastOverflow = intField(body, 'last_overflow') ?? 0;
      let status: Status = bundles > 0 ? 'ok' : 'cold';
      // Heavy drop ratio on the latest build → degraded. Bundles still
      // ship, but a meaningful share of provider depth was sheared off.
      if (status === 'ok' && lastFresh + lastDropped > 0) {
        const dropRatio = lastDropped / (lastFresh + lastDropped);
        if (dropRatio >= 0.5) status = 'degraded';
      }
      const reason =
        bundles > 0
          ? `${bundles} bundles · ${iocs} IoCs · ${actors} actors · ${malware} malware` +
            (lastDropped > 0 ? ` · ${lastDropped} provider lookups dropped on last build` : '') +
            (lastOverflow > 0 ? ` · ${lastOverflow} IoCs overflowed` : '')
          : 'no bundles yet (open any /threatintel page to warm)';
      return {
        status,
        reason,
        metrics: {
          bundles,
          ioc_total: iocs,
          actor_total: actors,
          malware_total: malware,
          last_fresh_subrequests: lastFresh,
          last_dropped_subrequests: lastDropped,
          last_overflow: lastOverflow,
        },
        ageS,
      };
    },
  },
];

// ── Passive probes from registry sources not covered by Cache API ─────────

function buildPassiveProbes(): FeedProbeSpec[] {
  const cacheProbeIds = new Set(PROBES.map((p) => p.id));
  const covered = new Set<string>(cacheProbeIds);
  for (const ids of Object.values(PROBE_SOURCES)) ids.forEach((id) => covered.add(id));

  const passive: FeedProbeSpec[] = [];
  for (const [id, entry] of Object.entries(SOURCE_RELIABILITY_REGISTRY)) {
    if (covered.has(id)) continue;
    passive.push({
      id,
      label: entry.name,
      page_path: '',
      api_path: '',
      cache_key: '',
      reliability: entry.reliability,
      category: entry.category,
      description: entry.description,
      evaluate: () => ({ status: 'cold' as Status, reason: 'Passive source — no direct Cache API probe' }),
    });
  }
  return passive;
}

export const ALL_PROBES: FeedProbeSpec[] = [...PROBES, ...buildPassiveProbes()];

async function probeOne(spec: FeedProbeSpec): Promise<FeedStatusRow> {
  const reg = spec.id
    ? (SOURCE_RELIABILITY_REGISTRY[spec.id] ?? SOURCE_RELIABILITY_REGISTRY[`${spec.id}-feed`])
    : undefined;
  // Three-step reliability resolution:
  //   1) Explicit on the probe (composite / inferred / un-registered sources)
  //   2) Direct registry hit on the probe's own ID
  //   3) Aggregated: highest Admiralty letter from the probe's sourceIds
  const reliability = spec.reliability ?? reg?.reliability ?? aggregateReliability(spec.sourceIds);
  const toRow = (status: Status, reason: string, ageS?: number): FeedStatusRow => {
    const info_credibility = infoCredibilityFor(status, ageS);
    return {
      id: spec.id,
      label: spec.label,
      page_path: spec.page_path,
      api_path: spec.api_path,
      status,
      reason,
      ...(ageS !== undefined ? { upstream_age_s: ageS } : {}),
      reliability,
      category: spec.category ?? reg?.category,
      description: spec.description ?? reg?.description,
      info_credibility,
      admiralty_grade: reliability ? `${reliability}-${info_credibility}` : undefined,
    };
  };
  // Passive sources have no cache key — skip the cache.match
  // (which would throw on empty URL) and report 'cold'.
  if (!spec.cache_key) {
    return toRow('cold', 'no cache key (passive source)');
  }
  const cache = (caches as unknown as { default: Cache }).default;
  try {
    const cached = await cache.match(spec.cache_key);
    if (!cached) {
      return toRow('cold', 'no cached payload (visit the page once to warm the cache)');
    }
    const body = (await cached.json()) as unknown;
    const evaluated = spec.evaluate(body);
    return toRow(evaluated.status, evaluated.reason, evaluated.ageS);
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return toRow('down', 'cache read error');
  }
}

export async function feedStatusHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    const cacheReq = new Request(FEED_STATUS_CACHE_KEY);
    const cached = await safeNullLog('cache-match-feed-status', cache.match(cacheReq));
    if (cached) return new Response(cached.body, cached);

    // Split probes: those with cache keys get concurrency-limited probes;
    // passive sources (no cache key) always return 'cold' — aggregate them
    // into a single summary row to keep the response small and fast.
    const activeProbes = ALL_PROBES.filter((p) => p.cache_key);
    const passiveCount = ALL_PROBES.length - activeProbes.length;
    const activeRows = await concurrentMap(activeProbes, probeOne, 6);
    const rows: FeedStatusRow[] = activeRows;
    if (passiveCount > 0) {
      rows.push({
        id: '_passive',
        label: `${passiveCount} passive sources`,
        page_path: '',
        api_path: '',
        status: 'cold',
        reason: `${passiveCount} source-reliability entries not backed by a cache key. Create a dedicated feed-status probe to track them.`,
      });
    }
    const healthy = rows.filter((r) => r.status === 'ok').length;
    const degraded = rows.filter((r) => r.status === 'degraded').length;
    const down = rows.filter((r) => r.status === 'down').length;
    const cold = rows.filter((r) => r.status === 'cold').length;
    const overall: Status =
      down >= 3 ? 'down' : down >= 1 || degraded >= 3 ? 'degraded' : cold >= rows.length / 2 ? 'cold' : 'ok';

    // Aggregate A–F distribution across the active rows. Rows without a
    // registered reliability letter (e.g. the synthetic _passive row, or
    // a probe whose registry key was removed) land in 'ungraded'.
    const reliability_distribution: Record<string, number> = {
      A: 0,
      B: 0,
      C: 0,
      D: 0,
      E: 0,
      F: 0,
      ungraded: 0,
    };
    for (const r of rows) {
      const key = r.reliability && /^[A-F]$/.test(r.reliability) ? r.reliability : 'ungraded';
      reliability_distribution[key] = (reliability_distribution[key] ?? 0) + 1;
    }

    const body: FeedStatusResponse = {
      generated_at: new Date().toISOString(),
      rows,
      overall,
      total_sources: rows.length,
      healthy,
      degraded,
      down,
      cold,
      reliability_distribution,
      degraded_sources: rows
        .filter((r) => r.status === 'degraded' || r.status === 'down')
        .map((r) => ({ id: r.id, status: r.status, reason: r.reason, page_path: r.page_path })),
    };

    const response = new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${CACHE_TTL / 3}`,
      },
    });
    c.executionCtx.waitUntil(
      cache.put(cacheReq, response.clone()).catch(() => {
        /* non-fatal */
      })
    );
    return response;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    // Fallback: return a minimal response so the frontend never sees 503
    return new Response(
      JSON.stringify({
        generated_at: new Date().toISOString(),
        rows: [],
        overall: 'cold',
        total_sources: 0,
        healthy: 0,
        degraded: 0,
        down: 0,
        cold: 0,
        reliability_distribution: { A: 0, B: 0, C: 0, D: 0, E: 0, F: 0, ungraded: 0 },
        degraded_sources: [],
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=30' },
      }
    );
  }
}
