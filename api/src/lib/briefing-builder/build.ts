import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../../env';
import { type IocEntry } from '../ioc-feed-parsers';
import { fetchMtiSource, type MtiCveRecord } from '../mythreatintel-api';
import { fetchRansomwareRecent, type RansomwareVictim } from '../../routes/ransomware-recent';
import { readAiLlmIntelSlice } from '../../routes/ai-llm-intel';
import { AI_LLM_BASE } from '../ai-llm-intel';
import { getCampaignIntel, type WebamonCampaignIntel } from '../webamon-campaigns';
import { normalizeGroup } from '../group-normalize';
import { computeDailyWindow, computeLiveDailyWindow } from '../briefing-window';
import { fetchCveFeedHighSeverity, type CveFeedEntry } from '../../routes/cve-recent';
import { BRIEFING_MAX_AGE_DAYS, IOC_FEED_SOURCES, RELATED_LIMIT, RELATED_MAX_CANDIDATES } from './config';
import { stampRelatedBriefings } from './related';
import {
  withLastGood,
  fetchKev,
  fetchNvdRecent,
  fetchCirclRecent,
  fetchNvdByIds,
  fetchFeedResilient,
  fetchMaliciousPackages,
  fetchDailyHuntIocFamilies,
  fetchDbugsRecent,
  type MaliciousPackageEntry,
  type DailyHuntIocFamily,
  type DbugsVuln,
} from './feeds';
import { fetchVulnTrackerDaily, type VulnTrackerBlogPost, type VulnTrackerDayCounts } from '../vulntracker';
import {
  isoDate,
  isoYearWeek,
  startOfIsoWeek,
  findingFromNvd,
  findingFromKev,
  buildSections,
  bucketIocs,
  buildStats,
  buildIocDump,
  buildLlmExecutiveSummary,
  severityFromCvss,
  deriveMitreTechniques,
  withinRange,
  normalizeVictimKey,
  aggregateWeeklyFromDailies,
  mergeWeeklyWithDailies,
  safeJsonParse,
} from './aggregate';
import type { Briefing, BriefingType, BriefingFinding, BriefingStats, Severity, NvdCve, KevEntry } from './types';

/**
 * Median daily CVE count across the VulnTracker archive, for the volume
 * section's blurb. Median, not mean — VulnTracker's daily totals swing hard
 * (single digits on weekends, 800+ on patch-Tuesday), and a mean would make a
 * normal day read as quiet. Ignores entries with no total so a malformed row
 * can't drag the figure.
 */
function medianDailyCount(archive: VulnTrackerDayCounts[]): number {
  const totals = archive
    .map((d) => d.total_count)
    .filter((n): n is number => Number.isFinite(n) && n > 0)
    .sort((a, b) => a - b);
  if (totals.length === 0) return 0;
  const mid = Math.floor(totals.length / 2);
  const lo = totals[mid - 1];
  const hi = totals[mid];
  if (hi === undefined) return 0;
  return totals.length % 2 === 1 ? hi : Math.round(((lo ?? hi) + hi) / 2);
}

/**
 * Map a VulnTracker/dbu.gs uppercase severity label onto the builder's
 * lowercase `Severity` union. UNKNOWN falls back to the CVSS-derived bucket so
 * an unscored-but-rated row still lands in a real severity section instead of
 * being dropped by `buildSections` (which has no bucket for 'unknown').
 */
function normalizeSeverity(label: string, score: number | null): Severity {
  switch (label) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return severityFromCvss(score ?? undefined);
  }
}

export async function buildBriefing(
  type: BriefingType,
  anchor: Date = new Date(),
  opts: { nvdApiKey?: string; env?: Env; live?: boolean } = {}
): Promise<Briefing> {
  let rangeStart: Date;
  let rangeEnd: Date;
  let dateLabel: string;
  let rangeLabel: string;
  let slug: string;
  let title: string;

  if (type === 'daily') {
    const w = opts.live ? computeLiveDailyWindow(anchor) : computeDailyWindow(anchor);
    rangeStart = w.start;
    rangeEnd = w.end;
    dateLabel = w.slug.replace(/^daily-/, '');
    rangeLabel = w.rangeLabel;
    slug = w.slug;
    title = `Daily Threat Briefing — ${dateLabel}`;
  } else {
    const end = startOfIsoWeek(anchor);
    const start = new Date(end.getTime() - 7 * 86400_000);
    rangeStart = start;
    rangeEnd = end;
    dateLabel = isoDate(start);
    rangeLabel = `${isoDate(start)} – ${isoDate(new Date(end.getTime() - 86400_000))}`;
    slug = `weekly-${isoYearWeek(start)}`;
    title = `Weekly Threat Briefing — ${rangeLabel}`;
  }

  const startMs = rangeStart.getTime();
  const endMs = rangeEnd.getTime();

  // ── Weekly rollup-first (free-plan subrequest budget) ─────────────────
  // The weekly build used to run the FULL live fan-out (~45-50 subrequests:
  // 7-day NVD pagination + up to 15 individual KEV CVE lookups + the 9-source
  // ransomware merge + 4 IOC feeds + OSSF + Webamon + LLM) and THEN merged
  // the daily rollup into it. On the free plan the invocation cap is 50, and
  // the weekly cron ALSO runs landscape sync + the TI dashboard build +
  // watchlist digest in the same invocation — so the build blew the cap,
  // Cloudflare aborted it with HTTP 503, and no row was ever persisted (the
  // hourly heal failed the same way; e.g. weekly-2026-W31 was missing while
  // all 7 of its dailies were rich).
  //
  // Fix: for weekly builds, read the D1 daily rollup FIRST. When the dailies
  // cover the window with real data, assemble the weekly from the rollup
  // alone (D1 reads only — ~0 subrequests) and skip the live fan-out. The
  // live path stays as the fallback for a window with no/missing dailies.
  const weeklyRollup =
    type === 'weekly' && opts.env?.BRIEFINGS_DB
      ? await aggregateWeeklyFromDailies(
          opts.env.BRIEFINGS_DB,
          isoDate(rangeStart),
          isoDate(new Date(rangeEnd.getTime() - 86400_000))
        ).catch(() => null)
      : null;
  const rollupUsable =
    weeklyRollup !== null &&
    weeklyRollup.dailyCount > 0 &&
    (weeklyRollup.findings.length > 0 || weeklyRollup.iocsTotal > 0);

  if (rollupUsable) {
    const r = weeklyRollup!;
    const findings = r.findings;
    const rwFindings = r.ransomwareFindings;
    const iocSources = r.sources.filter((s) => IOC_FEED_SOURCES.has(s));
    const sections = buildSections(findings);
    const groupCounts = new Map<string, number>();
    if (rwFindings.length > 0) {
      for (const f of rwFindings) {
        const m = /claimed by\s+([^(]+?)(?:\s*\(.*\))?\s*$/.exec(f.title);
        if (m?.[1]) {
          const g = m[1].trim();
          groupCounts.set(g, (groupCounts.get(g) ?? 0) + 1);
        }
      }
      const topGroups = [...groupCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([group, count]) => `${group} (${count})`)
        .join(', ');
      sections.push({
        id: 'ransomware-activity',
        title: 'Ransomware activity (ransomware.live + peers)',
        count: rwFindings.length,
        blurb: `Victim claims rolled up from the ${r.dailyCount} daily briefings covering this window${
          topGroups ? `. Most active groups: ${topGroups}.` : ''
        }`,
        findings: rwFindings,
      });
    }
    const ransomwareGroups = [...groupCounts.entries()].map(([group, count]) => ({ group, count })).slice(0, 12);
    const stats = buildStats(findings, sections, r.iocsTotal, rwFindings.length);
    const executive_summary = await buildLlmExecutiveSummary(
      {
        type,
        range_label: rangeLabel,
        findings,
        iocs: r.iocBuckets,
        iocsRawTotal: r.iocsTotal,
        iocSources,
        ransomwareGroups,
        ransomwareSectors: [],
        ransomwareTotal: rwFindings.length,
      },
      opts.env
    );
    const techniqueSet = new Set<string>();
    for (const f of findings) for (const t of f.mitre_techniques) techniqueSet.add(t);
    const sources: string[] = [];
    if (findings.some((f) => f.source === 'CISA KEV')) sources.push('CISA KEV');
    if (findings.some((f) => f.source === 'NVD')) sources.push('NVD');
    if (findings.some((f) => f.source === 'cvefeed.io')) sources.push('cvefeed.io');
    if (findings.some((f) => f.source === 'MyThreatIntel')) sources.push('MyThreatIntel');
    if (rwFindings.length > 0) sources.push('ransomware.live');
    if (findings.some((f) => f.source === 'Webamon')) sources.push('Webamon');
    if (findings.some((f) => f.source === 'ossf/malicious-packages')) sources.push('ossf/malicious-packages');
    if (findings.some((f) => f.source === 'Daily-Hunt')) sources.push('Daily-Hunt');
    sources.push(...iocSources);
    // ioc_dump is intentionally NOT persisted here. It is a plain-text
    // re-serialization of the `iocs` buckets that are stored right below it,
    // and for a 24h window that duplication costs ~196 KB per daily row
    // (2,026 indicators: 666 urls / 617 hashes / 449 ips / 294 domains).
    //
    // That payload is what pushed the build past the free-plan CPU limit:
    // a 509 KB body had to be JSON.stringify'd on write and re-parsed on
    // every read, inside a 10ms CPU budget. `briefings.ts` already derives
    // the dump on read via `ensureIocDump()` for exactly this case, so
    // /iocs.txt and the page keep working unchanged - they just build it
    // lazily from `iocs` instead of reading a copy we paid to store.
    return {
      slug,
      type,
      title,
      date: dateLabel,
      date_range: rangeLabel,
      range_start: isoDate(rangeStart),
      range_end: isoDate(new Date(rangeEnd.getTime() - 86400_000)),
      generated_at: new Date().toISOString(),
      executive_summary,
      stats,
      sections,
      iocs: r.iocBuckets,
      mitre_techniques: Array.from(techniqueSet).sort(),
      sources,
    };
  }

  const wrap = <T>(p: Promise<T>, fallback: T) =>
    p.then((v) => ({ ok: true, v })).catch(() => ({ ok: false, v: fallback }));
  /** Like `wrap` but unwraps an optional slice read. */
  const wrapOpt = <T>(p: Promise<T | null>) =>
    p.then((v) => ({ ok: v !== null, v })).catch(() => ({ ok: false, v: null as T | null }));
  const mtiEnv = opts.env;
  const [
    kevR,
    urlhaus,
    malwarebazaar,
    threatfox,
    tweetfeed,
    aiHoneypots,
    llmThreatintel,
    aiLlmIntel,
    nvdR,
    ransomwareBundle,
    mtiCveItems,
    cvefeedItems,
    webamonIntel,
    malpkgEntries,
    dailyHuntFamilies,
    vulntrackerBundle,
    dbugsBundle,
  ] = await Promise.all([
    wrap(withLastGood(mtiEnv, 'briefing-kev', fetchKev), [] as KevEntry[]),
    fetchFeedResilient(mtiEnv, 'urlhaus', { startMs, endMs }),
    fetchFeedResilient(mtiEnv, 'malwarebazaar', { startMs, endMs }),
    fetchFeedResilient(mtiEnv, 'threatfox', { startMs, endMs }),
    fetchFeedResilient(mtiEnv, 'tweetfeed'),
    // AI/LLM threat intel. Two indicator feeds + the narrative payload, so the
    // briefing covers LLM-abuse campaigns (ClickFix lures, malicious MCP
    // servers, prompt injection) alongside classic malware. All three are
    // fetch-resilient with a last-good mirror, and each adds exactly 1
    // subrequest — the build's fan-out stays inside the free-plan cap.
    fetchFeedResilient(mtiEnv, 'ai-honeypots'),
    fetchFeedResilient(mtiEnv, 'llm-threatintel'),
    // Read the warmed slice, never build it here: this fan-out runs inside the
    // daily briefing build, and an inline build would put 5 third-party
    // upstreams on the briefing's subrequest budget for a payload the hourly
    // cron already keeps warm. Null when cold → the section is simply omitted.
    wrapOpt(readAiLlmIntelSlice()),
    wrap(
      withLastGood(mtiEnv, `briefing-nvd?s=${startMs}&e=${endMs}`, async () => {
        try {
          const r = await fetchNvdRecent(rangeStart, rangeEnd, opts.nvdApiKey);
          if (r.length > 0) return r;
        } catch {
          /* noop */
        }
        return fetchCirclRecent(rangeStart, rangeEnd);
      }),
      [] as NvdCve[]
    ),
    mtiEnv
      ? fetchRansomwareRecent(mtiEnv)
          .then((r) => r?.body)
          .catch(() => ({
            generated_at: '',
            source: '',
            count: 0,
            groups: [],
            sectors: [],
            victims: [] as RansomwareVictim[],
          }))
      : Promise.resolve({
          generated_at: '',
          source: '',
          count: 0,
          groups: [],
          sectors: [],
          victims: [] as RansomwareVictim[],
        }),
    mtiEnv
      ? fetchMtiSource(mtiEnv, 'cve', { limit: 200 })
          .then((r) => (r.ok ? (r.items as MtiCveRecord[]) : []))
          .catch(() => [] as MtiCveRecord[])
      : Promise.resolve([] as MtiCveRecord[]),
    fetchCveFeedHighSeverity().catch(() => [] as CveFeedEntry[]),
    mtiEnv?.WEBAMON_API_KEY
      ? getCampaignIntel(mtiEnv).catch(() => null as WebamonCampaignIntel | null)
      : Promise.resolve(null as WebamonCampaignIntel | null),
    fetchMaliciousPackages(mtiEnv, { since: rangeStart, until: rangeEnd }).catch(() => [] as MaliciousPackageEntry[]),
    fetchDailyHuntIocFamilies(mtiEnv, { since: rangeStart, until: rangeEnd }).catch(() => [] as DailyHuntIocFamily[]),
    // VulnTracker is date-addressed: the digest for THIS window's date, plus
    // the 30-day archive (volume trend) and the blog RSS (narrative). The three
    // surfaces degrade independently inside fetchVulnTrackerDaily — only the
    // per-day digest gates `ok`, since that's what the CVE findings rest on.
    //
    // DAILY ONLY: the digest endpoint addresses one date, and the daily cron
    // (00:30) plus the hourly heal both build today's window, so this stays a
    // fixed 3 subrequests on the daily path. Weekly reads the D1 daily rollup
    // instead and skips the fan-out entirely, so it must not pay for a
    // date-addressed fetch it can't window correctly.
    type === 'daily'
      ? fetchVulnTrackerDaily(dateLabel).catch(() => ({
          digest: null,
          archive: [] as VulnTrackerDayCounts[],
          blog: [] as VulnTrackerBlogPost[],
          ok: false,
        }))
      : Promise.resolve({
          digest: null,
          archive: [] as VulnTrackerDayCounts[],
          blog: [] as VulnTrackerBlogPost[],
          ok: false,
        }),
    fetchDbugsRecent().catch(() => ({ vulns: [] as DbugsVuln[], ok: false })),
  ]);
  let degraded = !kevR.ok && !nvdR.ok;
  const kev = kevR.v;
  const nvdRecent = nvdR.v;

  const kevWindow = kev.filter((k) => withinRange(k.dateAdded, startMs, endMs));
  // Pre-populate from the already-fetched NVD/CIRCL results so we only
  // make individual API calls for KEV CVEs not already in the bulk result.
  // This dramatically cuts subrequests (the free-plan cap is 50/invocation).
  const nvdMap = new Map<string, NvdCve>();
  for (const c of nvdRecent) nvdMap.set(c.id, c);
  // Only fetch individual CVEs when the bulk result has data (NVD/CIRCL
  // was reachable). When nvdRecent is empty the API is down — individual
  // lookups will also fail and would waste subrequests on the free plan.
  if (nvdRecent.length > 0) {
    const missingKevCves = kevWindow.map((k) => k.cveID).filter((id) => !nvdMap.has(id));
    if (missingKevCves.length > 0) {
      const enriched = await fetchNvdByIds(missingKevCves, opts.nvdApiKey).catch(() => new Map<string, NvdCve>());
      for (const [k, v] of enriched) nvdMap.set(k, v);
    }
  }
  const kevFindings = kevWindow.map((k) => findingFromKev(k, nvdMap.get(k.cveID)));
  const kevIds = new Set(kevFindings.map((f) => f.id.toUpperCase()));
  // NVD pagination can hand back the same CVE on consecutive pages; the
  // cross-source sets below are case-insensitive, so make the within-source
  // dedup case-insensitive too (nvdFindings may otherwise ship duplicates).
  const seenNvd = new Set(kevIds);
  const nvdFindings = nvdRecent
    .filter((c) => {
      const id = c.id.toUpperCase();
      if (seenNvd.has(id)) return false;
      seenNvd.add(id);
      return true;
    })
    .map(findingFromNvd)
    .filter((f) => f.severity === 'critical' || f.severity === 'high');
  const existingCveIds = new Set([...kevFindings, ...nvdFindings].map((f) => f.id.toUpperCase()));
  const mtiCveFindings: BriefingFinding[] = [];
  for (const m of mtiCveItems) {
    const id = m.cve?.trim().toUpperCase();
    if (!id || existingCveIds.has(id)) continue;
    const pub = m.published?.trim();
    if (!pub || !withinRange(pub.replace(' ', 'T'), startMs, endMs)) continue;
    const score = m.score != null && m.score !== '' ? Number.parseFloat(String(m.score)) : NaN;
    const sevText = String(m.severity ?? '').toLowerCase();
    const severity: Severity = Number.isFinite(score)
      ? severityFromCvss(score)
      : sevText === 'critical' || sevText === 'high' || sevText === 'medium' || sevText === 'low'
        ? (sevText as Severity)
        : 'unknown';
    if (severity !== 'critical' && severity !== 'high') continue;
    existingCveIds.add(id);
    const desc = m.description?.trim() || id;
    mtiCveFindings.push({
      id,
      title: desc.length > 90 ? `${id}: ${desc.slice(0, 87)}…` : `${id}: ${desc}`,
      description: desc,
      severity,
      ...(Number.isFinite(score) ? { cvss: score } : {}),
      source: 'MyThreatIntel',
      source_url: m.url || 'https://mythreatintel.com/',
      mitre_techniques: [],
    });
  }
  const cvefeedFindings: BriefingFinding[] = [];
  for (const e of cvefeedItems) {
    const id = e.cve_id.toUpperCase();
    if (existingCveIds.has(id)) continue;
    if (!withinRange(e.published, startMs, endMs)) continue;
    existingCveIds.add(id);
    const titleText = e.title?.trim() || id;
    cvefeedFindings.push({
      id,
      title: titleText.length > 90 ? `${id}: ${titleText.slice(0, 87)}…` : `${id}: ${titleText}`,
      description: `[cvefeed.io] ${titleText}`,
      severity: 'high',
      source: 'cvefeed.io',
      source_url: e.link,
      mitre_techniques: deriveMitreTechniques(titleText),
    });
  }

  // ── VulnTracker: daily digest counts + the (gated) top criticals ───────
  // Two different jobs, deliberately kept separate:
  //
  //   a) The COUNTS are the point. `total_count` / `critical_count` /
  //      `exploited_count` are how many CVEs VulnTracker recorded landing that
  //      calendar day — a volume figure no other source in this builder
  //      reports. They go into the stats block and a "daily CVE volume"
  //      section so a reader can see 322-new-CVEs days without us having to
  //      enumerate them.
  //
  //   b) The TOP_CVES (≤7, subscription-gated) become gap-fill findings. They
  //      arrive with vendor + product + base_score already resolved, which is
  //      cheaper than the per-CVE NVD lookups `fetchNvdByIds` would spend on
  //      the same rows. Skipped when KEV/NVD/cvefeed/MTI already has the ID.
  const vtDigest = vulntrackerBundle.digest;
  const vtCveFindings: BriefingFinding[] = [];
  for (const c of vtDigest?.top_cves ?? []) {
    const id = c.cve_id.toUpperCase();
    if (existingCveIds.has(id)) continue;
    // The digest is addressed by date but its rows carry their own
    // published_date; honour the window rather than trusting the digest's
    // date label, or a boundary-shifted row leaks into the wrong briefing.
    if (c.published_date && !withinRange(c.published_date, startMs, endMs)) continue;
    existingCveIds.add(id);
    const headline = c.vulnerability_name || id;
    const where = [c.vendor_name, c.product_name].filter(Boolean).join(' ');
    vtCveFindings.push({
      id,
      title: headline.length > 90 ? `${id}: ${headline.slice(0, 87)}…` : `${id}: ${headline}`,
      description: `[VulnTracker digest] ${where ? `${where} — ` : ''}${headline}${
        c.is_exploited ? ' — confirmed exploited in the wild.' : ''
      }`,
      severity: normalizeSeverity(c.severity, c.base_score),
      ...(c.base_score !== null ? { cvss: c.base_score } : {}),
      source: 'VulnTracker',
      source_url: `https://vulntracker.io/digest/${vtDigest?.date ?? dateLabel}`,
      mitre_techniques: deriveMitreTechniques(`${headline} ${where}`),
      ...(c.vendor_name ? { vendor: c.vendor_name } : {}),
      ...(c.product_name ? { product: c.product_name } : {}),
    });
  }

  // ── dbu.gs: windowed gap-fillers with vendor/product/CWE + fix flags ────
  // Same shape as the cvefeed tier: a source whose rows are authoritative for
  // vendor/product but whose prose is thin, so it fills only IDs no prior tier
  // has. `has_exploit` is called out in the description because "a PoC exists"
  // is the single most actionable thing this source contributes.
  const dbugsFindings: BriefingFinding[] = [];
  for (const v of dbugsBundle.vulns) {
    const id = v.cve_id.toUpperCase();
    if (existingCveIds.has(id)) continue;
    const created = Date.parse(`${v.created}T12:00:00Z`);
    if (Number.isNaN(created) || created < startMs || created >= endMs) continue;
    existingCveIds.add(id);
    const where = [v.vendor, v.product].filter(Boolean).join(' ');
    const flags = [v.has_exploits ? 'public exploit available' : null, v.has_fix ? 'fix available' : null]
      .filter(Boolean)
      .join(', ');
    dbugsFindings.push({
      id,
      title: where ? `${id}: ${where}` : id,
      description: `[dbu.gs] ${v.impacts.slice(0, 2).join('; ') || 'Tracked vulnerability'}${flags ? ` (${flags})` : ''}`,
      severity: normalizeSeverity(v.severity, v.score),
      ...(v.score !== null ? { cvss: v.score } : {}),
      ...(v.cwes.length > 0 ? { cwes: v.cwes } : {}),
      source: 'dbu.gs',
      source_url: v.reference ?? `https://dbu.gs/vulnerability/${v.cve_id}`,
      mitre_techniques: deriveMitreTechniques(`${where} ${v.impacts.join(' ')}`),
      ...(v.vendor ? { vendor: v.vendor } : {}),
      ...(v.product ? { product: v.product } : {}),
    });
  }

  // dbu.gs joins the main `findings` array (and so gets categorized into the
  // CWE/technique sections like every other CVE source). The VulnTracker
  // criticals deliberately do NOT — they surface in the `cve-volume` section
  // below, which carries the daily counts alongside them.
  let findings = [...kevFindings, ...nvdFindings, ...mtiCveFindings, ...cvefeedFindings, ...dbugsFindings];

  const matchTimestamp = (e: IocEntry) =>
    e.timestamp ? withinRange(e.timestamp.replace(' ', 'T'), startMs, endMs) : false;
  const iocPerSource: Record<string, number> = {};
  const urlhausMatched = urlhaus.filter(matchTimestamp);
  const malwarebazaarMatched = malwarebazaar.filter(matchTimestamp);
  const threatfoxMatched = threatfox.filter(matchTimestamp);
  const tweetfeedMatched = tweetfeed.filter(matchTimestamp);
  const aiHoneypotsMatched = aiHoneypots.filter(matchTimestamp);
  const llmThreatintelMatched = llmThreatintel.filter(matchTimestamp);
  if (urlhausMatched.length > 0) iocPerSource['URLhaus'] = urlhausMatched.length;
  if (malwarebazaarMatched.length > 0) iocPerSource['MalwareBazaar'] = malwarebazaarMatched.length;
  if (threatfoxMatched.length > 0) iocPerSource['ThreatFox'] = threatfoxMatched.length;
  if (tweetfeedMatched.length > 0) iocPerSource['TweetFeed'] = tweetfeedMatched.length;
  if (aiHoneypotsMatched.length > 0) iocPerSource['AI Honeypot Observatory'] = aiHoneypotsMatched.length;
  if (llmThreatintelMatched.length > 0) iocPerSource['LLM ThreatIntel'] = llmThreatintelMatched.length;

  const seenIoc = new Set<string>();
  const allIocs = [
    ...urlhausMatched,
    ...malwarebazaarMatched,
    ...threatfoxMatched,
    ...tweetfeedMatched,
    ...aiHoneypotsMatched,
    ...llmThreatintelMatched,
  ].filter((e) => {
    const k = `${e.type}|${e.value.trim().toLowerCase()}`;
    if (seenIoc.has(k)) return false;
    seenIoc.add(k);
    return true;
  });

  let iocsRawTotal = allIocs.length;
  let iocs = bucketIocs(allIocs);
  const iocSources: string[] = [];
  if (urlhausMatched.length > 0) iocSources.push('URLhaus');
  if (malwarebazaarMatched.length > 0) iocSources.push('MalwareBazaar');
  if (threatfoxMatched.length > 0) iocSources.push('ThreatFox');
  if (tweetfeedMatched.length > 0) iocSources.push('TweetFeed');
  if (aiHoneypotsMatched.length > 0) iocSources.push('AI Honeypot Observatory');
  if (llmThreatintelMatched.length > 0) iocSources.push('LLM ThreatIntel');

  const ransomwareVictims = ransomwareBundle.victims;
  const ransomwareGroups = ransomwareBundle.groups;
  const ransomwareSectors = ransomwareBundle.sectors;
  let ransomwareFindings: BriefingFinding[] = [];
  const seenRwVictim = new Set<string>();
  for (const v of ransomwareVictims) {
    const discovered = v.discovered;
    if (!discovered) continue;
    if (!withinRange(discovered, startMs, endMs)) continue;
    const victim = v.victim?.trim();
    if (!victim) continue;
    const group = normalizeGroup(v.group);
    if (!group || group === 'unknown') continue;
    const day = discovered.slice(0, 10);
    // Semantic victim key (strip punctuation/suffixes/casing drift) so the
    // same claim reported by two trackers with slightly different spellings
    // collapses to one entry — matches the weekly rollup's dedup key.
    const dedupeKey = `${group}|${normalizeVictimKey(victim)}|${day}`;
    if (seenRwVictim.has(dedupeKey)) continue;
    seenRwVictim.add(dedupeKey);
    const desc = v.description?.trim();
    const location = v.country ? ` (${v.country})` : '';
    ransomwareFindings.push({
      id: `rw-${group.replace(/[^a-z0-9]+/g, '-')}-${victim
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .slice(0, 40)}-${day}`,
      title: `${victim} — claimed by ${group}${location}`,
      description: desc && desc.length > 280 ? `${desc.slice(0, 277)}…` : desc || `${victim} listed by ${group}.`,
      severity: 'high',
      source: 'ransomware.live',
      source_url: v.source_url || 'https://www.ransomware.live/',
      mitre_techniques: [],
    });
  }
  ransomwareFindings.sort((a, b) => {
    const dayA = a.id.slice(-10);
    const dayB = b.id.slice(-10);
    if (dayA === dayB) return a.title.localeCompare(b.title);
    return dayA < dayB ? 1 : -1;
  });

  if (type === 'weekly' && weeklyRollup) {
    const rollup = weeklyRollup;
    if (rollup.dailyCount > 0) {
      const merged = mergeWeeklyWithDailies(
        { findings, ransomwareFindings, iocsRawTotal, iocBuckets: iocs, sources: iocSources },
        rollup
      );
      findings = merged.findings;
      ransomwareFindings = merged.ransomwareFindings;
      iocsRawTotal = merged.iocsRawTotal;
      iocs = merged.iocBuckets;
      for (const s of rollup.sources) {
        if (IOC_FEED_SOURCES.has(s) && !iocSources.includes(s)) iocSources.push(s);
      }
      if (findings.length > 0) degraded = false;
    }
  }

  const sections = buildSections(findings);
  if (ransomwareFindings.length > 0) {
    const topGroups = ransomwareGroups
      .slice(0, 3)
      .map((g) => `${g.group} (${g.count})`)
      .join(', ');
    const topSectors = ransomwareSectors
      .filter((s) => s.sector && s.sector !== 'Unknown' && s.count > 0)
      .slice(0, 3)
      .map((s) => `${s.sector} ${s.pct}%`)
      .join(', ');
    const blurbParts = [
      'Victim claims observed across ransomware.live, Ransomlook, cti.fyi, ransomfeed, ransomwatch, andreafortuna, and MyThreatIntel CTI feeds within this window.',
    ];
    if (topGroups) blurbParts.push(`Most active groups: ${topGroups}.`);
    if (topSectors) blurbParts.push(`Top sectors: ${topSectors}.`);
    sections.push({
      id: 'ransomware-activity',
      title: 'Ransomware activity (ransomware.live + peers)',
      count: ransomwareFindings.length,
      blurb: blurbParts.join(' '),
      findings: ransomwareFindings,
    });
  }

  const webamonFindings: BriefingFinding[] = [];
  if (webamonIntel?.ok) {
    const deltaSev = (delta: number): Severity => (delta >= 300 ? 'critical' : delta >= 50 ? 'high' : 'medium');
    for (const camp of webamonIntel.top_campaigns.slice(0, 8)) {
      const delta = camp.delta_24h ?? 0;
      if (delta <= 0) continue;
      const tags = camp.tags?.length ? ` [${camp.tags.slice(0, 4).join(', ')}]` : '';
      webamonFindings.push({
        id: `webamon-${camp.campaign_id}`,
        title: `${camp.name} — +${delta.toLocaleString()} domains (24h)`,
        description: `Fastest-growing Webamon estate: ${delta} new domains in 24h, ${camp.unique_domains_total.toLocaleString()} tracked total${tags}.`,
        severity: deltaSev(delta),
        source: 'Webamon',
        source_url: 'https://intel.webamon.com',
        mitre_techniques: [],
      });
    }
    const offlineByCampaign = new Map<string, { name: string; count: number }>();
    for (const e of webamonIntel.changes) {
      const off = e.new_counts?.went_offline ?? 0;
      if (off <= 0) continue;
      const cur = offlineByCampaign.get(e.campaign_id) ?? { name: e.campaign_name, count: 0 };
      cur.count += off;
      offlineByCampaign.set(e.campaign_id, cur);
    }
    const takedowns = [...offlineByCampaign.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 5);
    for (const [id, t] of takedowns) {
      webamonFindings.push({
        id: `webamon-takedown-${id}`,
        title: `${t.name} — ${t.count.toLocaleString()} domains taken offline`,
        description: 'Takedowns / expiry confirmed by double-checked DNS within the window.',
        severity: t.count >= 300 ? 'high' : 'medium',
        source: 'Webamon',
        source_url: 'https://intel.webamon.com',
        mitre_techniques: [],
      });
    }
    for (const cl of webamonIntel.clusters.top.slice(0, 5)) {
      if (cl.severity === 'watch') continue;
      webamonFindings.push({
        id: `webamon-cluster-${cl.cluster_id.replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`,
        title: `Emerging ${cl.fingerprint_type} cluster — ${cl.unique_domains.toLocaleString()} domains (+${cl.delta_24h}/24h)`,
        description: `Not yet promoted to a tracked campaign. Seed query: ${cl.seed_query}`,
        severity: cl.severity === 'critical' ? 'critical' : 'high',
        source: 'Webamon',
        source_url: 'https://intel.webamon.com',
        mitre_techniques: [],
      });
    }
  }
  if (webamonFindings.length > 0 && webamonIntel) {
    const t = webamonIntel.totals;
    const blurb = `Automated campaign intelligence from Webamon (intel.webamon.com). ${t.campaigns_with_activity} campaigns with activity in-window: ${t.new_domains.toLocaleString()} new domains, ${t.went_offline.toLocaleString()} taken offline, ${t.infra_changes.toLocaleString()} infrastructure changes, ${t.new_titles.toLocaleString()} new page-title lures.`;
    sections.push({
      id: 'webamon-campaigns',
      title: 'Phishing & malware campaign activity (Webamon)',
      count: webamonFindings.length,
      blurb,
      findings: webamonFindings,
    });
  }

  // ── OSSF Malicious Packages (windowed) ───────────────────────────────
  // The ossf/malicious-packages repo is a curated mirror of npm/PyPI/RubyGems/
  // Maven/Go/crates.io malware reports. fetchMaliciousPackages now uses the
  // GitHub Commits API on the `osv/malicious` path with since/until, so each
  // finding is a package whose advisory directory was *added* in this
  // briefing window — not the full cumulative catalog. Analysts click
  // through for the version-range detail.
  const malpkgFindings: BriefingFinding[] = [];
  const malpkgByEco: Record<string, number> = {};
  for (const p of malpkgEntries) {
    malpkgByEco[p.ecosystem] = (malpkgByEco[p.ecosystem] ?? 0) + 1;
    const added = p.publishedAt ? ` First disclosed ${p.publishedAt.slice(0, 10)}.` : '';
    malpkgFindings.push({
      id: `malpkg-${p.ecosystem}-${p.name}`.replace(/[^a-z0-9-]/gi, '-').slice(0, 80),
      title: `${p.name} (${p.ecosystem})`,
      description: `Newly disclosed malicious package in the OpenSSF malicious-packages directory.${added} Review version ranges and installation provenance.`,
      severity: 'high',
      source: 'ossf/malicious-packages',
      source_url: p.ossf_url,
      mitre_techniques: [],
    });
  }
  if (malpkgFindings.length > 0) {
    const ecoBreakdown = Object.entries(malpkgByEco)
      .sort((a, b) => b[1] - a[1])
      .map(([eco, n]) => `${eco} (${n})`)
      .join(', ');
    sections.push({
      id: 'malicious-packages',
      title: 'Malicious packages (OpenSSF)',
      count: malpkgFindings.length,
      blurb: `Supply-chain threats newly disclosed in the ossf/malicious-packages directory during this window. ${malpkgFindings.length} packages across ${Object.keys(malpkgByEco).length} ecosystems: ${ecoBreakdown}.`,
      findings: malpkgFindings,
    });
  }

  // ── Daily-Hunt IOC families (windowed) ───────────────────────────────
  // TheRavenFile/Daily-Hunt is a knowledge base of IOC families (ransomware,
  // malware, APT, C2, phishing, stealer). Each family file contains raw
  // indicators (hashes, IPs, domains) plus MITRE technique references. The
  // build script (scripts/build-threat-intel.mjs) slices these into per-slug
  // JSON with a slim index entry carrying a `firstSeen` (earliest date parsed
  // from the upstream markdown). For a time-boxed briefing we surface only
  // families whose firstSeen falls inside the window — the full catalog is
  // reference material, not daily intel, and is browsable via the
  // threat-intel vertical (ti_get_ioc MCP tool / /api/v1/threat-intel/iocs/:slug).
  const dailyHuntFindings: BriefingFinding[] = [];
  const dhByCategory: Record<string, number> = {};
  for (const f of dailyHuntFamilies) {
    dhByCategory[f.category] = (dhByCategory[f.category] ?? 0) + 1;
    const techs = f.mitreTechniques?.slice(0, 8) ?? [];
    dailyHuntFindings.push({
      id: `dh-${f.slug}`.slice(0, 80),
      title: `${f.family} (${f.category})`,
      description: f.description || `${f.family} — ${f.indicatorCount} indicators tracked. Category: ${f.category}.`,
      severity: f.category === 'ransomware' || f.category === 'apt' ? 'high' : 'medium',
      source: 'Daily-Hunt',
      source_url: `https://github.com/TheRavenFile/Daily-Hunt`,
      mitre_techniques: techs,
    });
  }
  if (dailyHuntFindings.length > 0) {
    const catBreakdown = Object.entries(dhByCategory)
      .sort((a, b) => b[1] - a[1])
      .map(([cat, n]) => `${cat} (${n})`)
      .join(', ');
    sections.push({
      id: 'daily-hunt-ioc-families',
      title: 'IOC families (Daily-Hunt)',
      count: dailyHuntFindings.length,
      blurb: `Threat-actor and malware-family IOC catalogs from TheRavenFile/Daily-Hunt whose firstSeen falls in this window. ${dailyHuntFindings.length} families across ${Object.keys(dhByCategory).length} categories: ${catBreakdown}. Pivot to the threat-intel vertical for full indicator lists.`,
      findings: dailyHuntFindings,
    });
  }

  // ── VulnTracker daily CVE volume ───────────────────────────────────────
  // Its own section rather than a fold-into-`findings` contribution, for two
  // reasons: the counts describe the whole day's CVE volume (conflating them
  // with `findings`, which is only the critical/high subset, would imply the
  // briefing enumerated every CVE published that day), and the VT criticals
  // carry more context here — vendor, product, CVSS, exploited flag — than a
  // generic category bucket preserves. Like the Webamon / Daily-Hunt sections
  // they stay OUT of `findings` so nothing renders twice, but they DO feed the
  // technique rollup further down.
  if (vtDigest) {
    const gatedNote = vtDigest.is_gated
      ? ` VulnTracker gates the full CVE list behind a subscription — the ${vtCveFindings.length} below are the ${vtDigest.top_cves.length} top criticals it exposes, minus any already covered by NVD/KEV/cvefeed. Not the complete set.`
      : '';
    const archiveNote =
      vulntrackerBundle.archive.length > 0
        ? ` 30-day archive available (median ${medianDailyCount(vulntrackerBundle.archive)} CVEs/day).`
        : '';
    sections.push({
      id: 'cve-volume',
      title: 'Daily CVE volume (VulnTracker digest)',
      count: vtCveFindings.length,
      blurb:
        `VulnTracker recorded ${vtDigest.total_count.toLocaleString()} CVEs landing on ${vtDigest.date}, ` +
        `${vtDigest.critical_count.toLocaleString()} of them critical` +
        `${vtDigest.exploited_count !== null ? ` and ${vtDigest.exploited_count.toLocaleString()} flagged as exploited` : ''}.` +
        gatedNote +
        archiveNote,
      findings: vtCveFindings,
    });
  }

  // ── VulnTracker blog: exploit-in-the-wild narrative ────────────────────
  // Windowed by the RSS pubDate like every other source. These posts are
  // hand-written analysis of confirmed exploitation, which is the framing no
  // structured feed in this builder provides.
  const vtBlogFindings: BriefingFinding[] = [];
  const seenVtBlog = new Set<string>();
  for (const post of vulntrackerBundle.blog) {
    if (!withinRange(post.published, startMs, endMs)) continue;
    if (seenVtBlog.has(post.link)) continue;
    seenVtBlog.add(post.link);
    const primaryId = post.cve_ids[0];
    // Posts about a CVE already surfaced keep the advisory record's id so
    // dedupeCveFindings collapses them; only genuinely-new topics get a slug.
    const findingId =
      primaryId && !existingCveIds.has(primaryId.toUpperCase())
        ? primaryId.toUpperCase()
        : `vt-blog-${post.link.split('/').pop() ?? post.link}`.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 90);
    // A post about an already-surfaced CVE is still recorded — the written
    // analysis is the value, not the CVE id — but it takes a slug id instead of
    // the CVE id so it can't be deduped away by dedupeCveFindings.
    vtBlogFindings.push({
      id: findingId,
      title: post.title.length > 120 ? `${post.title.slice(0, 117)}…` : post.title,
      description: post.description ? `[VulnTracker] ${post.description.slice(0, 400)}` : `[VulnTracker] ${post.title}`,
      severity: post.cve_ids.length > 0 ? 'high' : 'medium',
      source: 'VulnTracker',
      source_url: post.link,
      mitre_techniques: deriveMitreTechniques(post.title),
    });
  }
  if (vtBlogFindings.length > 0) {
    const cveCount = new Set(vtBlogFindings.filter((f) => f.id.startsWith('CVE-')).map((f) => f.id)).size;
    sections.push({
      id: 'vulntracker-analysis',
      title: 'Exploitation analysis (VulnTracker)',
      count: vtBlogFindings.length,
      blurb: `Hand-written exploitation analysis published by VulnTracker within this window, covering ${cveCount} CVE${cveCount === 1 ? '' : 's'}.`,
      findings: vtBlogFindings,
    });
  }

  // ── AI/LLM threat intel: campaigns, write-ups, and blog ────────────────
  // Reads the hourly-warmed slice rather than fetching, so this adds 0
  // subrequests to the briefing build. Two sections because they answer
  // different questions: campaigns say WHAT is being attacked, the narrative
  // feed says HOW it works.
  let aiLlmSectionsEmitted = false;
  if (aiLlmIntel?.ok && aiLlmIntel.v) {
    const intel = aiLlmIntel.v;

    // Actors/campaigns first_seen within the window, newest first.
    const actorFindings: BriefingFinding[] = [];
    const seenActors = new Set<string>();
    for (const a of intel.actors) {
      if (a.first_seen && !withinRange(a.first_seen, startMs, endMs)) continue;
      // An actor with no first_seen is undated upstream — skip it rather than
      // asserting a date we don't have and letting it into a time-boxed brief.
      if (!a.first_seen) continue;
      if (seenActors.has(a.id)) continue;
      seenActors.add(a.id);
      actorFindings.push({
        id: `llm-campaign-${a.id}`.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 90),
        title: a.names[0] || a.id,
        description: [
          a.description?.slice(0, 400),
          a.ttps?.length ? `Techniques: ${a.ttps.slice(0, 6).join('; ')}` : '',
          a.distribution?.length ? `Distribution: ${a.distribution.slice(0, 4).join('; ')}` : '',
        ]
          .filter(Boolean)
          .join('\n'),
        // A tracked campaign is an active intrusion concern, not a CVE. 'medium'
        // is the floor here; a LLM-abuse campaign with a credential-harvesting
        // TTPP set should read as high, which the mitre list signals.
        severity: a.ttps?.some((t) => /T1059|T1552|T1204|T1190/.test(t)) ? 'high' : 'medium',
        source: 'LLM ThreatIntel',
        source_url: `${AI_LLM_BASE}/#${a.id}`,
        mitre_techniques: a.ttps ?? [],
      });
    }
    if (actorFindings.length > 0) {
      sections.push({
        id: 'llm-campaigns',
        title: 'AI/LLM campaigns',
        count: actorFindings.length,
        blurb: `LLM-abuse campaigns and supply-chain clusters first observed in this window, with ATT&CK mapping and delivery channels.`,
        findings: actorFindings,
      });
    }

    // Write-ups + blog merged, windowed by post date.
    const narrativeFindings: BriefingFinding[] = [];
    const seenNarrative = new Set<string>();
    for (const post of [...intel.posts, ...intel.blog]) {
      if (!withinRange(post.date, startMs, endMs)) continue;
      if (seenNarrative.has(post.id)) continue;
      seenNarrative.add(post.id);
      narrativeFindings.push({
        id: `llm-intel-${post.id}`.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 90),
        title: post.title.length > 120 ? `${post.title.slice(0, 117)}…` : post.title,
        description: [post.excerpt?.slice(0, 400), post.tags.length ? `Tags: ${post.tags.join(', ')}` : '']
          .filter(Boolean)
          .join('\n'),
        // Analysis of an active abuse technique; high when the tags name a
        // delivery/persistence mechanism rather than a topic.
        severity: post.tags.some((t) => /clickfix|phishing|injection|mcp|exfiltrat|malware|rat|stealer/.test(t))
          ? 'high'
          : 'medium',
        source: 'LLM ThreatIntel',
        source_url: post.url,
        mitre_techniques: [],
      });
    }
    if (narrativeFindings.length > 0) {
      sections.push({
        id: 'llm-narrative',
        title: 'AI/LLM threat analysis',
        count: narrativeFindings.length,
        blurb: `Analyst write-ups on LLM-specific abuse — ClickFix lures, malicious MCP servers, prompt injection, agent hijacking — published in this window.`,
        findings: narrativeFindings,
      });
    }

    if (actorFindings.length > 0 || narrativeFindings.length > 0) aiLlmSectionsEmitted = true;
  }

  const stats = buildStats(findings, sections, iocsRawTotal, ransomwareFindings.length);
  const summaryArgs = {
    type,
    range_label: rangeLabel,
    findings,
    iocs,
    iocsRawTotal,
    iocSources,
    iocPerSource,
    ransomwareGroups,
    ransomwareSectors,
    ransomwareTotal: ransomwareFindings.length,
  };
  const executive_summary = degraded
    ? `This ${type} briefing is incomplete: both CISA KEV and NVD were unreachable from the edge at build time (${rangeLabel}). This is an upstream-availability gap, NOT an all-clear — do not read the absence of findings as "no new vulnerabilities". The briefing rebuilds automatically every hour and will be replaced as soon as the feeds respond.`
    : await buildLlmExecutiveSummary(summaryArgs, opts.env);
  const techniqueSet = new Set<string>();
  for (const f of findings) for (const t of f.mitre_techniques) techniqueSet.add(t);
  for (const f of dailyHuntFindings) for (const t of f.mitre_techniques) techniqueSet.add(t);
  // The VulnTracker criticals live in their own section rather than in
  // `findings`, so their techniques have to be folded in explicitly or the
  // briefing's MITRE coverage silently drops them.
  for (const f of vtCveFindings) for (const t of f.mitre_techniques) techniqueSet.add(t);

  const sources: string[] = [];
  if (findings.some((f) => f.source === 'CISA KEV')) sources.push('CISA KEV');
  if (findings.some((f) => f.source === 'NVD')) sources.push('NVD');
  if (findings.some((f) => f.source === 'cvefeed.io')) sources.push('cvefeed.io');
  if (findings.some((f) => f.source === 'MyThreatIntel')) sources.push('MyThreatIntel');
  if (vtDigest || vtBlogFindings.length > 0) sources.push('VulnTracker');
  if (dbugsBundle.vulns.length > 0) sources.push('dbu.gs');
  if (ransomwareFindings.length > 0) sources.push('ransomware.live');
  if (webamonFindings.length > 0) sources.push('Webamon');
  // Declared `sources` lives below the AI/LLM block, so the block records its
  // own emission into a flag this reads.
  if (aiLlmSectionsEmitted) sources.push('LLM ThreatIntel');
  if (malpkgFindings.length > 0) sources.push('ossf/malicious-packages');
  if (dailyHuntFindings.length > 0) sources.push('Daily-Hunt');
  sources.push(...iocSources);

  // ioc_dump is derived on read by `ensureIocDump()` in routes/briefings.ts
  // rather than stored here — see the note in buildBriefing. For a weekly
  // window the duplication was ~1.7 MB per row.

  return {
    slug,
    type,
    title,
    date: dateLabel,
    date_range: rangeLabel,
    range_start: isoDate(rangeStart),
    range_end: opts.live ? isoDate(rangeEnd) : isoDate(new Date(rangeEnd.getTime() - 86400_000)),
    generated_at: new Date().toISOString(),
    executive_summary,
    stats,
    sections,
    iocs,
    mitre_techniques: Array.from(techniqueSet).sort(),
    sources,
    ...(degraded ? { degraded: true } : {}),
  };
}

/**
 * D1 caps a single row/value at 2,000,000 bytes; exceed it and the INSERT
 * throws `D1_ERROR: string or blob too big: SQLITE_TOOBIG`, so the whole
 * briefing fails to persist (no briefing at all). The body is one JSON blob in
 * the `body` column, and the IOC dump + ransomware victim list are
 * intentionally uncapped, so a busy window can push it past the limit.
 *
 * Trim only the two unbounded arrays — IOC indicators first (they dominate and
 * are stored twice: structured `iocs` buckets + the `ioc_dump` text), then the
 * ransomware-activity findings — just enough to fit under `budget`. CVE/KEV
 * findings, the executive summary and stats are preserved, and the trimming is
 * recorded (`ioc_dump.truncated`, section `count`) so it is visible, not
 * silent. Returns the input untouched when it already fits.
 */
const D1_VALUE_LIMIT_BYTES = 2_000_000;
// Budget sits 200 KB below the hard limit, leaving headroom for the other bound
// columns (stats_json, sources_json, …) that share the same row plus a margin
// for re-encoding.
const BRIEFING_BODY_BUDGET_BYTES = D1_VALUE_LIMIT_BYTES - 200_000;

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

export function capBriefingForStorage(input: Briefing, budget = BRIEFING_BODY_BUDGET_BYTES): Briefing {
  if (utf8ByteLength(JSON.stringify(input)) <= budget) return input;

  // Shallow-clone the parts we mutate so the caller's object is left intact.
  const b: Briefing = {
    ...input,
    iocs: { ...input.iocs },
    sections: input.sections.map((s) => ({ ...s, findings: s.findings.slice() })),
    ...(input.ioc_dump ? { ioc_dump: { ...input.ioc_dump } } : {}),
  };

  const iocKinds = ['urls', 'domains', 'ipv4s', 'hashes'] as const;
  const totalIocs = () => iocKinds.reduce((n, k) => n + b.iocs[k].length, 0);
  const rwSection = b.sections.find((s) => s.id === 'ransomware-activity');
  const observedRawTotal = b.ioc_dump?.rawTotal ?? totalIocs();

  // Reduce the combined IOC count to `target`, dropping from the tails of the
  // largest buckets first, then rebuild the txt dump so both views stay in sync.
  const trimIocsTo = (target: number) => {
    let over = totalIocs() - target;
    while (over > 0) {
      const largest = [...iocKinds].sort((a, c) => b.iocs[c].length - b.iocs[a].length)[0];
      if (!largest || b.iocs[largest].length === 0) break;
      const take = Math.min(over, Math.max(1, Math.ceil(b.iocs[largest].length * 0.25)));
      b.iocs[largest] = b.iocs[largest].slice(0, b.iocs[largest].length - take);
      over -= take;
    }
    if (b.ioc_dump) {
      const rebuilt = buildIocDump(b.iocs, observedRawTotal);
      b.ioc_dump = rebuilt
        ? { ...rebuilt, rawTotal: observedRawTotal, truncated: true }
        : { count: 0, rawTotal: observedRawTotal, content: '', truncated: true };
    }
  };

  let guard = 0;
  while (utf8ByteLength(JSON.stringify(b)) > budget && guard++ < 200) {
    const size = utf8ByteLength(JSON.stringify(b));
    const ratio = budget / size; // < 1; how much of the current payload fits
    const iocN = totalIocs();
    const rwN = rwSection ? rwSection.findings.length : 0;

    if (iocN >= rwN && iocN > 0) {
      // Shrink IOCs toward the fitting ratio (×0.9 margin so we converge down).
      trimIocsTo(Math.max(0, Math.floor(iocN * ratio * 0.9)));
    } else if (rwN > 0 && rwSection) {
      rwSection.findings = rwSection.findings.slice(0, Math.max(0, Math.floor(rwN * ratio * 0.9)));
      rwSection.count = rwSection.findings.length;
    } else {
      // Nothing left in the unbounded arrays to trim; stop to avoid spinning.
      break;
    }
  }
  return b;
}

export async function writeBriefing(
  db: D1Database,
  briefing: Briefing,
  options?: { skipIfExists?: boolean }
): Promise<{ written: boolean; reason?: string }> {
  if (options?.skipIfExists) {
    const existing = await db.prepare('SELECT 1 FROM briefings WHERE slug = ?').bind(briefing.slug).first();
    if (existing) return { written: false, reason: 'already_exists' };
  }

  const bodyJson = JSON.stringify(briefing);
  if (bodyJson.length < 100) {
    return { written: false, reason: 'empty_body_refused' };
  }

  const hasNoFindings = briefing.stats.findings === 0;
  if (hasNoFindings) {
    const prior = await db
      .prepare('SELECT stats_json, body FROM briefings WHERE slug = ?')
      .bind(briefing.slug)
      .first<{ stats_json?: string; body?: string }>();
    if (prior) {
      const priorBodyKnown = prior.body !== undefined && prior.body !== null;
      if (priorBodyKnown && prior.body!.trim().length < 100) {
        await db.prepare('DELETE FROM briefings WHERE slug = ?').bind(briefing.slug).run();
      } else {
        const ps = safeJsonParse<Partial<BriefingStats>>(prior.stats_json, {});
        if ((ps.findings ?? 0) > 0) {
          return { written: false, reason: 'kept_richer_existing' };
        }
      }
    }
    return { written: false, reason: 'empty_body_refused' };
  }

  // D1 rejects any single row/value over 2 MB with SQLITE_TOOBIG. The uncapped
  // IOC dump + ransomware victim list can push the body past that, which would
  // fail the whole INSERT (no briefing at all) — trim to fit before persisting.
  const storable = capBriefingForStorage(briefing);

  // Case-triage linkage: stamp prior-briefing relations (IOC overlap +
  // tactic keywords) into the body so every reader carries them. Best-effort
  // — a scan failure must never block the write.
  await stampRelatedBriefings(db, storable, { limit: RELATED_LIMIT, maxCandidates: RELATED_MAX_CANDIDATES });

  await db
    .prepare(
      `INSERT OR REPLACE INTO briefings (slug, type, title, date, date_range, range_start, range_end, stats_json, sources_json, body)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      storable.slug,
      storable.type,
      storable.title,
      storable.date,
      storable.date_range,
      storable.range_start,
      storable.range_end,
      JSON.stringify(storable.stats),
      JSON.stringify(storable.sources),
      JSON.stringify(storable)
    )
    .run();

  try {
    await db
      .prepare(`DELETE FROM intel_bundles WHERE source_id = 'briefings' AND item_ref = ?`)
      .bind(briefing.slug)
      .run();
  } catch {
    /* noop */
  }
  return { written: true };
}

export async function sweepOldBriefings(
  db: D1Database,
  maxAgeDays = BRIEFING_MAX_AGE_DAYS,
  now: Date = new Date()
): Promise<{ deleted: string[]; kept: number }> {
  const cutoff = new Date(now.getTime() - maxAgeDays * 86400_000).toISOString().slice(0, 10);
  const toDelete = await db.prepare('SELECT slug FROM briefings WHERE date < ?').bind(cutoff).all<{ slug: string }>();
  const deleted = (toDelete.results ?? []).map((r) => r.slug);
  if (deleted.length > 0) {
    await db.prepare('DELETE FROM briefings WHERE date < ?').bind(cutoff).run();
  }
  const remaining = await db.prepare('SELECT COUNT(*) as count FROM briefings').first<{ count: number }>();
  return { deleted, kept: (remaining as { count: number } | null)?.count ?? 0 };
}

// sql-audit: accept-reason `${whereSql}` is assembled only from fixed string
// literals pushed by this function (`type = ?`, the LIKE/ESCAPE clause); the
// resulting fragment is always `''` or `' WHERE ' + <those literals>`. User
// input (filter.q) reaches D1 exclusively through `.bind(...whereParams)`, and
// its LIKE metacharacters are escaped for `% _ \`.
export async function listBriefings(
  db: D1Database,
  filter?: { type?: 'daily' | 'weekly' | 'landscape'; q?: string; limit?: number; offset?: number }
): Promise<{ items: Array<{ slug: string; metadata: Record<string, unknown> }>; total: number }> {
  const limit = filter?.limit ?? 50;
  const offset = filter?.offset ?? 0;

  const where: string[] = [];
  const whereParams: unknown[] = [];
  if (filter?.type) {
    where.push('type = ?');
    whereParams.push(filter.type);
  }
  const q = filter?.q?.trim();
  if (q) {
    const like = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
    where.push("(title LIKE ? ESCAPE '\\' OR date_range LIKE ? ESCAPE '\\' OR slug LIKE ? ESCAPE '\\')");
    whereParams.push(like, like, like);
  }
  const whereSql = where.length ? ` WHERE ${where.join(' AND ')}` : '';

  const countRow = await db
    .prepare(`SELECT COUNT(*) as cnt FROM briefings${whereSql}`)
    .bind(...whereParams)
    .first<{ cnt: number }>();
  const total = countRow?.cnt ?? 0;

  const result = await db
    .prepare(
      `SELECT slug, type, title, date, date_range, range_end, stats_json, sources_json FROM briefings${whereSql} ORDER BY range_end DESC, date DESC LIMIT ? OFFSET ?`
    )
    .bind(...whereParams, limit, offset)
    .all<{
      slug: string;
      type: string;
      title: string;
      date: string;
      date_range: string;
      range_end: string;
      stats_json: string;
      sources_json: string;
    }>();
  return {
    items: (result.results ?? []).map((row) => ({
      slug: row.slug,
      metadata: {
        type: row.type,
        title: row.title,
        date: row.date,
        range_end: row.range_end,
        date_range: row.date_range,
        stats: safeJsonParse(row.stats_json, {}),
        sources: safeJsonParse(row.sources_json, []),
      },
    })),
    total,
  };
}

export async function readBriefing(db: D1Database, slug: string): Promise<Briefing | null> {
  const row = await db
    .prepare('SELECT body FROM briefings WHERE LOWER(slug) = LOWER(?)')
    .bind(slug)
    .first<{ body: string }>();
  if (!row) return null;
  return safeJsonParse((row as { body: string }).body, null);
}
