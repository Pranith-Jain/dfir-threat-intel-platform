/**
 * ti-manifests MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 *
 * All tools here read static JSON manifests through the ASSETS binding,
 * so the whole group stays unregistered when ASSETS is unbound — matching
 * the `if (h.env.ASSETS)` block this was extracted from.
 *
 * ASYNC BY DESIGN: this group contains `await import()` calls before some
 * registrations (ti_search_* / ti_export_stix). It must stay async and be
 * awaited at the same position in init(), or those tools register after
 * the tools/list response is served.
 */

import { dbCacheStats, filterBriefs, getDbBrief, loadDbIndex } from '../lib/daily-briefs-manifest';
import type { DbBriefType } from '../lib/daily-briefs-manifest';

import { filterFlowvizTechniques, loadFlowvizTechniques } from '../lib/flowviz-manifest';
import { loadProcedureRules, relevantRules } from '../lib/procedure-manifest';
import { malwareAnalyzerLookup } from '../lib/malwareanalyzer';
import { untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import {
  actorsCacheStats,
  filterActors,
  getActor,
  listAptmapDataFiles,
  loadActorIndex,
  loadAptmapDataFile,
} from '../lib/etda-actors-manifest';
import {
  checkDestroylistDomain,
  filterIocs,
  filterCves,
  filterDarknetSites,
  filterDphishIndicators,
  filterLists,
  filterLivingThreatIncidents,
  filterCtiwatchVulns,
  filterOffseqThreats,
  filterMaFeed,
  filterTcClusters,
  filterTcEntities,
  filterTcExploits,
  filterTcIocs,
  filterTcVictims,
  filterTcVulns,
  filterThreaticonActors,
  filterThreaticonCoverage,
  getDarknetCategory,
  getDarknetSite,
  getDphishIndicator,
  getCtiwatchVulnerability,
  getCtiwatchVictim,
  getOffseqThreat,
  getLivingThreatIncident,
  getMaFeed,
  getTcCluster,
  getTcEntity,
  getTcExploit,
  getTcVuln,
  getThreaticonActor,
  getTiCve,
  getTiIoc,
  getTiList,
  getTiSector,
  loadDarknetIndex,
  loadDestroylistIndex,
  loadDphishIndex,
  loadKevSnapshot,
  loadLivingThreatIndex,
  loadMaIndex,
  loadCtiwatchIndex,
  loadOffseqIndex,
  loadTcEntities,
  loadTcIocs,
  loadTcMispEvents,
  loadThreatClusterIndex,
  loadThreaticonCoverage,
  loadThreaticonIndex,
  loadTiIndex,
  searchListEntries,
  tiCacheStats,
} from '../lib/threat-intel-manifest';
import {
  filterWdtbBriefs,
  getWdtbBrief,
  getWdtbLatest,
  loadWdtbIndex,
  wdtbCacheStats,
} from '../lib/webamon-dtb-manifest';
import type { ActorCategory } from '../lib/etda-actors-manifest';
import type { TcEntityType, TiIocIndexEntry, TiSeverity } from '../lib/threat-intel-manifest';
export async function registerTiManifestsTools(h: McpToolHost): Promise<void> {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── Threat Intel (TI) tools ────────────────────────────────────
  // CVE/KEV catalog, IOC family database, and sector briefings.
  // Data shipped in public/data/threat-intel/ via weekly sync.

  h.tools(
    'ti_list_cves',
    'List CVEs from the threat-intel vertical (NVD + CISA KEV). CVEs are enriched with priority scoring (CVSS + KEV + recency). Filter by severity, KEV-only, vendor, recency, or keyword.',
    {
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by CVSS v3 severity band'),
      kevOnly: z.boolean().optional().describe('Only return CVEs in CISA Known Exploited Vulnerabilities catalog'),
      vendor: z.string().optional().describe('Case-insensitive substring match against vendor field'),
      daysBack: z.number().int().min(1).max(365).optional().describe('Only CVEs published within this many days'),
      minPriority: z.number().int().min(0).max(100).optional().describe('Minimum priority score (0-100)'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against CVE ID / vendor / product / description'),
      minArgusScore: z
        .number()
        .int()
        .min(0)
        .max(100)
        .optional()
        .describe('Minimum Argus trending hype score (0-100). CVEs without Argus data are excluded when set.'),
      limit: z.number().int().min(1).max(200).optional().describe('Max CVEs to return (default 50)'),
    },
    async ({ severity, kevOnly, vendor, daysBack, minPriority, keyword, minArgusScore, limit }) => {
      const idx = await loadTiIndex(ASSETS);
      const cves = filterCves(idx, {
        severity: severity as TiSeverity | undefined,
        kevOnly,
        vendor,
        daysBack,
        minPriority,
        keyword,
        minArgusScore,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.counts.cves,
        kevTotal: idx.counts.kevTotal,
        returned: cves.length,
        lastSyncedAt: idx.lastSyncedAt,
        cves,
      });
    }
  );

  h.tools(
    'ti_get_cve',
    'Return the full CVE body with CVSS vector, CWE IDs, references, and (where populated) BSI description and LLM summary/recommended action. Use ti_list_cves first to discover CVE IDs.',
    {
      cveId: z.string().describe('CVE ID, e.g. "CVE-2026-1001". Case-insensitive.'),
    },
    async ({ cveId }) => {
      const body = await getTiCve(ASSETS, cveId);
      if (!body) {
        return untrustedToolResult({
          error: 'cve_not_found',
          cveId,
          hint: 'Call ti_list_cves first to see available CVEs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ti_list_kev',
    'Return the full CISA Known Exploited Vulnerabilities (KEV) snapshot — actively exploited CVEs with required actions and due dates. Each entry includes vendor, product, short description, required action, and due date.',
    {
      vendor: z.string().optional().describe('Filter by vendor (case-insensitive substring)'),
      limit: z.number().int().min(1).max(500).optional().describe('Max KEV entries to return (default 100)'),
    },
    async ({ vendor, limit }) => {
      const kev = await loadKevSnapshot(ASSETS);
      const needle = vendor?.toLowerCase();
      const out = needle ? kev.filter((e) => e.vendor.toLowerCase().includes(needle)) : kev;
      const sliced = out.slice(0, limit ?? 100);
      return untrustedToolResult({
        total: kev.length,
        returned: sliced.length,
        vendorFilter: vendor ?? null,
        entries: sliced,
      });
    }
  );

  h.tools(
    'ti_list_iocs',
    'List IOC families (ransomware, malware, APT groups, C2 frameworks, stealers, phishing kits) from the threat-intel vertical, sourced from Daily-Hunt references and tracked by this Worker.',
    {
      category: z
        .enum(['ransomware', 'malware', 'apt', 'c2', 'phishing', 'stealer', 'other'])
        .optional()
        .describe('Filter by IOC category'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against slug / family name / aliases / description'),
      limit: z.number().int().min(1).max(100).optional().describe('Max families to return (default 50)'),
    },
    async ({ category, keyword, limit }) => {
      const idx = await loadTiIndex(ASSETS);
      const iocs = filterIocs(idx, {
        category: category as TiIocIndexEntry['category'] | undefined,
        keyword,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.counts.iocs,
        returned: iocs.length,
        iocs,
      });
    }
  );

  h.tools(
    'ti_get_ioc',
    'Return the full IOC family body with indicators, MITRE techniques, context, and (where populated) LLM summary. Use ti_list_iocs first to discover family slugs.',
    {
      slug: z.string().describe('IOC family slug, e.g. "lockbit-4-0-ransomware". Get these from ti_list_iocs.'),
    },
    async ({ slug }) => {
      const body = await getTiIoc(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'ioc_family_not_found',
          slug,
          hint: 'Call ti_list_iocs to see available families.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ti_brief_sector',
    'Return a sector-specific threat brief (Financial, Healthcare, or Government) from the threat-intel vertical. Each brief includes an executive summary, top N sector-relevant threats with risk assessments and recommended actions.',
    {
      sector: z.enum(['financial', 'healthcare', 'government']).describe('Target sector for the brief'),
    },
    async ({ sector }) => {
      const body = await getTiSector(ASSETS, sector);
      if (!body) {
        return untrustedToolResult({
          error: 'sector_not_found',
          sector,
          hint: 'Available sectors: financial, healthcare, government.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ti_stats',
    'Return cache + manifest stats for the Threat Intel data: index loaded, KEV loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.',
    {},
    async () => {
      const idx = await loadTiIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        lastSyncedAt: idx.lastSyncedAt,
        cache: tiCacheStats(),
      });
    }
  );

  h.tools(
    'ti_list_detection_lists',
    'List SOC/DFIR detection lists (suspicious named pipes, ports, user-agents, mutexes, ransomware extensions, etc.) sourced from mthcht/awesome-lists. Each list is a curated CSV of indicators with metadata (tool, severity, category, reference). Filter by category or keyword.',
    {
      category: z
        .string()
        .optional()
        .describe('Filter by list category: windows, network, ransomware, hardware, cloud, general'),
      keyword: z.string().optional().describe('Case-insensitive substring match against slug / title / description'),
      limit: z.number().int().min(1).max(100).optional().describe('Max lists to return (default 50)'),
    },
    async ({ category, keyword, limit }) => {
      const idx = await loadTiIndex(ASSETS);
      const lists = filterLists(idx, { category, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.counts.lists,
        returned: lists.length,
        lists,
      });
    }
  );

  h.tools(
    'ti_get_detection_list',
    'Return the full detection list body with all entries (indicator values + metadata: description, tool, severity, category, reference, regex). Optionally search within the list by keyword or severity. Use ti_list_detection_lists first to discover slugs.',
    {
      slug: z
        .string()
        .describe('Detection list slug, e.g. "suspicious-named-pipes". Get these from ti_list_detection_lists.'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against entry value / description / tool / category'),
      severity: z.string().optional().describe('Filter entries by severity (critical, high, medium, low, info)'),
      limit: z.number().int().min(1).max(2000).optional().describe('Max entries to return (default 500)'),
    },
    async ({ slug, keyword, severity, limit }) => {
      const body = await getTiList(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'detection_list_not_found',
          slug,
          hint: 'Call ti_list_detection_lists to see available lists.',
        });
      }
      const entries = searchListEntries(body, { keyword, severity, limit: limit ?? 500 });
      return untrustedToolResult({
        slug: body.slug,
        title: body.title,
        category: body.category,
        description: body.description,
        valueColumn: body.valueColumn,
        totalEntries: body.entryCount,
        returned: entries.length,
        entries,
      });
    }
  );

  // ── Threat Intel — Darknet directory (darknetlist.is) ──────────
  // A Tor site directory replicated from darknetlist.is. 108 sites
  // across 9 categories, each with live up/down status, onion URLs,
  // response codes, and fingerprints. Data ships in
  // public/data/threat-intel/darknet/.

  h.tools(
    'ti_list_darknet',
    'List Tor-accessible sites from the darknetlist.is directory (markets, forums, news, security, comms, crypto, tools, AI). Each site has live up/down status, onion URL, response code, and fingerprint. Filter by category, status, recommended, or keyword.',
    {
      category: z
        .string()
        .optional()
        .describe('Filter by category: markets, search, forums, news, security, communications, crypto, tools, ai'),
      status: z.enum(['up', 'down']).optional().describe('Filter by live status (up = responding, down = unreachable)'),
      recommended: z.boolean().optional().describe('Only return sites marked as recommended by darknetlist.is'),
      onionOnly: z.boolean().optional().describe('Only return .onion sites (exclude clearnet mirrors)'),
      keyword: z.string().optional().describe('Case-insensitive substring match against site name / DWD ID / category'),
      limit: z.number().int().min(1).max(500).optional().describe('Max sites to return (default 200)'),
    },
    async ({ category, status, recommended, onionOnly, keyword, limit }) => {
      const idx = await loadDarknetIndex(ASSETS);
      const sites = filterDarknetSites(idx, {
        category,
        status,
        recommendedOnly: recommended,
        onionOnly,
        keyword,
        limit: limit ?? 200,
      });
      return untrustedToolResult({
        source: idx.source,
        rebuiltAt: idx.rebuiltAt,
        counts: idx.counts,
        returned: sites.length,
        sites,
      });
    }
  );

  h.tools(
    'ti_get_darknet_site',
    'Return the full site body from the darknetlist.is directory: name, DWD ID, category, onion URL, clearnet URL (if any), live status, mirror counts, latency, HTTP code, page size, and fingerprint. Use ti_list_darknet first to discover site slugs (DWD IDs).',
    {
      slug: z.string().describe('Site slug (DWD ID lowercased, e.g. "dwd-3c9c-715"). Get these from ti_list_darknet.'),
    },
    async ({ slug }) => {
      const body = await getDarknetSite(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'darknet_site_not_found',
          slug,
          hint: 'Call ti_list_darknet to see available site slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ti_get_darknet_category',
    'Return all sites in a darknetlist.is category (markets, search, forums, news, security, communications, crypto, tools, ai) with full details: onion URLs, status, latency, HTTP codes, fingerprints.',
    {
      category: z
        .string()
        .describe('Category ID: markets, search, forums, news, security, communications, crypto, tools, ai'),
    },
    async ({ category }) => {
      const body = await getDarknetCategory(ASSETS, category);
      if (!body) {
        return untrustedToolResult({
          error: 'darknet_category_not_found',
          category,
          hint: 'Valid categories: markets, search, forums, news, security, communications, crypto, tools, ai.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── Threat Cluster feeds (threatcluster.io) ────────────────────
  // Replicated public feeds: top-50 trending threat clusters, CVE
  // vulnerability + exploit feeds, dark-web ransomware victims, a
  // high-confidence IOC blocklist, and a slim MISP manifest
  // pass-through. Data ships in public/data/threat-intel/threatcluster/.

  h.tools(
    'tc_feed',
    'List ThreatCluster (threatcluster.io) public feed summaries: trending threat clusters, CVE vulnerabilities, exploits with public PoCs, dark-web victims, and the IOC blocklist — with per-feed counts and last build dates.',
    {
      feed: z
        .enum(['clusters', 'vulnerabilities', 'exploits', 'victims', 'iocs', 'misp'])
        .optional()
        .describe('Which feed to inspect (default clusters)'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against titles / CVE IDs / victim names / IOC values'),
      limit: z.number().int().min(1).max(500).optional().describe('Max items to return (default 50)'),
    },
    async ({ feed, keyword, limit }) => {
      const idx = await loadThreatClusterIndex(ASSETS);
      const kind = feed ?? 'clusters';
      let items: unknown[] = [];
      if (kind === 'clusters') items = filterTcClusters(idx, { keyword, limit: limit ?? 50 });
      else if (kind === 'vulnerabilities') items = filterTcVulns(idx, { keyword, limit: limit ?? 50 });
      else if (kind === 'exploits') items = filterTcExploits(idx, { keyword, limit: limit ?? 50 });
      else if (kind === 'victims') items = filterTcVictims(idx, { keyword, limit: limit ?? 50 });
      else if (kind === 'iocs') {
        const body = await loadTcIocs(ASSETS);
        items = body ? filterTcIocs(body.iocs, { keyword, limit: limit ?? 50 }) : [];
      }
      return untrustedToolResult({
        source: idx.source,
        syncedAt: idx.syncedAt,
        lastBuildDates: idx.lastBuildDates,
        counts: idx.counts,
        feed: kind,
        returned: items.length,
        [kind]: items,
      });
    }
  );

  h.tools(
    'tc_get_cluster',
    'Return the full ThreatCluster trending-cluster body: title, publication date, source count, link to the cluster page (summary + timeline + source articles), and full description with key points. Use tc_feed with feed=clusters to discover slugs.',
    {
      slug: z.string().describe('Cluster slug (last segment of the cluster URL, e.g. "windows-afdsys-zero-f15d3d54").'),
    },
    async ({ slug }) => {
      const body = await getTcCluster(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'tc_cluster_not_found',
          slug,
          hint: 'Call tc_feed with feed=clusters to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'tc_get_cve',
    'Return a single ThreatCluster CVE item from the vulnerabilities feed (7-day window) or the exploits feed (30-day window, public PoCs). Full description, severity, CISA KEV status (exploits only), and a link to the ThreatCluster CVE page. Use tc_feed with feed=vulnerabilities or feed=exploits first.',
    {
      cveId: z.string().describe('CVE ID, e.g. "CVE-2026-63030"'),
      feed: z
        .enum(['vulnerabilities', 'exploits'])
        .optional()
        .describe('Which feed to read from (default vulnerabilities)'),
    },
    async ({ cveId, feed }) => {
      const id = cveId.toUpperCase();
      const body =
        feed === 'exploits'
          ? await getTcExploit(ASSETS, id)
          : ((await getTcVuln(ASSETS, id)) ?? (await getTcExploit(ASSETS, id)));
      if (!body) {
        return untrustedToolResult({
          error: 'tc_cve_not_found',
          cveId: id,
          hint: 'Call tc_feed with feed=vulnerabilities or feed=exploits to see covered CVEs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'tc_list_victims',
    'List newly observed ransomware leak-site victims from the ThreatCluster Dark Web Victims feed (14-day window). Filter by ransom group, sector, country, or keyword. Each entry has a victim name, claiming group, sector, country, and publication date.',
    {
      group: z.string().optional().describe('Filter by ransomware group name (case-insensitive)'),
      sector: z.string().optional().describe('Filter by victim sector, e.g. "Technology"'),
      country: z.string().optional().describe('Filter by victim country code, e.g. "US"'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against victim / group / sector / country'),
      limit: z.number().int().min(1).max(500).optional().describe('Max victims to return (default 100)'),
    },
    async ({ group, sector, country, keyword, limit }) => {
      const idx = await loadThreatClusterIndex(ASSETS);
      const victims = filterTcVictims(idx, { group, sector, country, keyword, limit: limit ?? 100 });
      return untrustedToolResult({
        source: idx.source,
        syncedAt: idx.syncedAt,
        total: idx.counts.victims,
        returned: victims.length,
        victims,
      });
    }
  );

  h.tools(
    'tc_list_iocs',
    'List high-confidence malicious domains and IPs from the ThreatCluster IOC blocklist (last 30 days). Each IOC has a type, reason, first/last seen, and the source articles that reported it. Ready for firewall / Pi-hole / pfSense blocklists.',
    {
      type: z.string().optional().describe('Filter by indicator type: domain, ipv4, ipv6'),
      keyword: z.string().optional().describe('Case-insensitive substring match against value / reason / source'),
      limit: z.number().int().min(1).max(1000).optional().describe('Max IOCs to return (default 200)'),
    },
    async ({ type, keyword, limit }) => {
      const idx = await loadThreatClusterIndex(ASSETS);
      const body = await loadTcIocs(ASSETS);
      const iocs = body ? filterTcIocs(body.iocs, { type, keyword, limit: limit ?? 200 }) : [];
      return untrustedToolResult({
        source: idx.source,
        syncedAt: idx.syncedAt,
        generatedAt: body?.generatedAt ?? null,
        total: body?.count ?? 0,
        returned: iocs.length,
        iocs,
      });
    }
  );

  h.tools(
    'tc_list_misp_events',
    'List the slim MISP manifest pass-through from ThreatCluster (misp/manifest.json): event UUID, title, date, threat level, and tags per event. For full MISP ingestion use the upstream remote feed directly (https://threatcluster.io/misp/manifest.json).',
    {
      keyword: z.string().optional().describe('Case-insensitive match against event title or tags'),
      limit: z.number().int().min(1).max(500).optional().describe('Max events to return (default 100)'),
    },
    async ({ keyword, limit }) => {
      const idx = await loadThreatClusterIndex(ASSETS);
      const body = await loadTcMispEvents(ASSETS);
      let events = body?.events ?? [];
      const needle = keyword?.toLowerCase();
      if (needle) {
        events = events.filter(
          (e) => (e.info ?? '').toLowerCase().includes(needle) || e.tags.some((t) => t.toLowerCase().includes(needle))
        );
      }
      events = events.slice(0, limit ?? 100);
      return untrustedToolResult({
        source: idx.source,
        syncedAt: idx.syncedAt,
        total: body?.eventCount ?? 0,
        returned: events.length,
        events,
      });
    }
  );

  h.tools(
    'tc_list_entities',
    'List ThreatCluster-derived entity profiles: threat actors (MISP galaxy attribution), ransomware groups and sectors (dark-web victims), malware families (Daily-Hunt dictionary matching), and CVEs (feed + cluster-text extraction). Filter by type, keyword, or minimum mention count. Each entry has a name, aliases, mention count, and first/last seen dates. Deterministic build-time extraction — no LLM in the loop.',
    {
      type: z
        .enum(['actor', 'group', 'malware', 'cve', 'sector'])
        .optional()
        .describe('Restrict to one entity type (default all five)'),
      keyword: z.string().optional().describe('Case-insensitive substring match against name or aliases'),
      minMentions: z.number().int().min(0).optional().describe('Only entities mentioned at least this many times'),
      limit: z.number().int().min(1).max(500).optional().describe('Max entities to return (default 100)'),
    },
    async ({ type, keyword, minMentions, limit }) => {
      const idx = await loadTcEntities(ASSETS);
      const entities = filterTcEntities(idx, {
        type: type as TcEntityType | undefined,
        keyword,
        minMentions,
        limit: limit ?? 100,
      });
      return untrustedToolResult({
        source: idx.source,
        builtAt: idx.builtAt,
        counts: idx.counts,
        returned: entities.length,
        entities,
      });
    }
  );

  h.tools(
    'tc_get_entity',
    'Return the full ThreatCluster entity profile: threat summary, mention frequency by day (first/last seen), recent activity (clusters / victims / CVEs / MISP events), and a weighted related-entity graph derived from record-level co-occurrence (e.g. a ransomware group links to the sectors and countries it hit, a threat actor links to the malware and CVEs co-mentioned with it). Use tc_list_entities to discover slugs.',
    {
      type: z
        .enum(['actor', 'group', 'malware', 'cve', 'sector'])
        .describe('Entity type (actor, group, malware, cve, sector)'),
      slug: z.string().describe('Entity slug, e.g. "lazarus-group", "clop", "CVE-2024-27253" (case-insensitive)'),
      activityLimit: z.number().int().min(1).max(50).optional().describe('Max recent-activity items (default 12)'),
    },
    async ({ type, slug, activityLimit }) => {
      const ent = await getTcEntity(ASSETS, type as TcEntityType, slug);
      if (!ent) {
        return untrustedToolResult({
          error: 'tc_entity_not_found',
          type,
          slug,
          hint: 'Call tc_list_entities to see available entities. Note entity slugs are the lowercase dashed name, e.g. "lazarus-group".',
        });
      }
      if (activityLimit) ent.recentActivity = ent.recentActivity.slice(0, activityLimit);
      return untrustedToolResult(ent);
    }
  );

  // ── Threaticon (threaticon.com) ────────────────────────────────
  // Replicated STIX 2.1 actor catalog + malware dictionary + ATT&CK
  // detection-coverage dataset + country-level threat map. Data ships
  // in public/data/threat-intel/threaticon/ (own sync + build scripts).

  h.tools(
    'ti_list_threaticon_actors',
    'List threat-actor profiles from the Threaticon catalog (threaticon.com): name, MITRE ATT&CK ID, status, TLP, confidence, types, origin country, and per-actor technique/tool/geo counts. Filter by type, country, TLP, status, MITRE presence, or keyword. Use ti_get_threaticon_actor to fetch the full profile.',
    {
      type: z.string().optional().describe('Substring filter on actor types (e.g. "nation", "criminal", "hacktivist")'),
      country: z
        .string()
        .optional()
        .describe('Two-letter origin country code (case-insensitive), e.g. "ru", "cn", "kp", "ir"'),
      tlp: z.enum(['white', 'green', 'amber', 'red']).optional().describe('Traffic-light-protocol level'),
      status: z.string().optional().describe('Activity status (e.g. "active", "dormant", "unknown")'),
      hasMitre: z.boolean().optional().describe('Only actors that map to a MITRE ATT&CK group ID'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against name, MITRE ID, types, or origin'),
      limit: z.number().int().min(1).max(1000).optional().describe('Max actors to return (default 100)'),
    },
    async ({ type, country, tlp, status, hasMitre, keyword, limit }) => {
      const idx = await loadThreaticonIndex(ASSETS);
      const actors = filterThreaticonActors(idx, {
        type,
        country,
        tlp,
        status,
        hasMitre,
        keyword,
        limit: limit ?? 100,
      });
      return untrustedToolResult({
        source: idx.source,
        syncedAt: idx.syncedAt,
        total: idx.counts.actors,
        returned: actors.length,
        filters: { type, country, tlp, status, hasMitre, keyword },
        actors,
      });
    }
  );

  h.tools(
    'ti_get_threaticon_actor',
    'Return the full Threaticon actor profile: executive summary, key capabilities, goals & targeting, MITRE ATT&CK tactics and techniques (T-numbers), software/tooling, IOC patterns, recommended actions, campaigns & victims, targeted sectors and countries, aliases, and confidence. Use ti_list_threaticon_actors to discover slugs.',
    {
      slug: z.string().describe('Actor slug, e.g. "lazarus-group", "apt41" (case-insensitive)'),
    },
    async ({ slug }) => {
      const actor = await getThreaticonActor(ASSETS, slug);
      if (!actor) {
        return untrustedToolResult({
          error: 'threaticon_actor_not_found',
          slug,
          hint: 'Call ti_list_threaticon_actors to see available slugs.',
        });
      }
      return untrustedToolResult(actor);
    }
  );

  // ── FlowViz attack-flow visualization (edge port, MIT) ──────────
  // Technique search + graph validation run fully on the edge (ASSETS +
  // pure functions). Analysis/assistant calls need the platform LLM
  // chain — use the REST routes POST /api/v1/flowviz/analyze and
  // POST /api/v1/flowviz/assistant for those.

  h.tools(
    'flowviz_list_techniques',
    'Search the FlowViz ATT&CK technique index (MITRE enterprise techniques with tactic names) used for attack-flow action nodes and autocomplete. Filter by keyword (id or name) and/or tactic id (e.g. TA0001). Upstream: davidljohnson/flowviz (MIT).',
    {
      q: z.string().optional().describe('Substring match against technique id or name, e.g. "phish", "T1078"'),
      tactic: z.string().optional().describe('Tactic id filter, e.g. "TA0001" (Initial Access)'),
      limit: z.number().int().min(1).max(200).optional().describe('Max techniques to return (default 50)'),
    },
    async ({ q, tactic, limit }) => {
      const all = await loadFlowvizTechniques(ASSETS);
      const techniques = filterFlowvizTechniques(all, { q, tactic, limit: limit ?? 50 });
      return untrustedToolResult({
        source: 'FlowViz (edge port) — upstream davidljohnson/flowviz (MIT); ATT&CK® © MITRE',
        total: all.length,
        returned: techniques.length,
        techniques,
      });
    }
  );

  h.tools(
    'flowviz_validate_graph',
    'Validate a FlowViz attack-flow graph ({nodes[], edges[]}) structurally: node types, technique-id shape, dangling edges, source-excerpt grounding. Returns errors + warnings without calling any LLM.',
    {
      graph: z
        .record(z.string(), z.unknown())
        .describe('Graph object with nodes[] and edges[] arrays (FlowViz/analysisPrompt schema)'),
    },
    async ({ graph }) => {
      const rec = (graph ?? {}) as { nodes?: unknown[]; edges?: unknown[] };
      const nodes = Array.isArray(rec.nodes) ? rec.nodes : [];
      const edges = Array.isArray(rec.edges) ? rec.edges : [];
      const errors: string[] = [];
      const warnings: string[] = [];
      if (!Array.isArray(rec.nodes)) errors.push('nodes-missing');
      if (!Array.isArray(rec.edges)) errors.push('edges-missing');
      const ids = new Set<string>();
      const NODE_TYPES = [
        'action',
        'tool',
        'malware',
        'asset',
        'infrastructure',
        'url',
        'vulnerability',
        'AND_operator',
        'OR_operator',
      ];
      for (const n of nodes.slice(0, 500)) {
        const o = (n ?? {}) as Record<string, unknown>;
        const id = typeof o.id === 'string' ? o.id : '';
        const type = typeof o.type === 'string' ? o.type : '';
        if (!id) errors.push('node-missing-id');
        else if (ids.has(id)) errors.push(`duplicate-node-id:${id}`);
        else ids.add(id);
        if (!NODE_TYPES.includes(type)) errors.push(`bad-node-type:${id || '?'}:${type || '?'}`);
        const data = o.data as Record<string, unknown> | undefined;
        if (!data || typeof data !== 'object') errors.push(`node-missing-data:${id || '?'}`);
        const tid = data && typeof data.technique_id === 'string' ? data.technique_id : '';
        if (type === 'action' && tid && !/^T\d{4}(\.\d{3})?$/.test(tid)) errors.push(`bad-technique-id:${id}:${tid}`);
      }
      for (const e of edges.slice(0, 1000)) {
        const o = (e ?? {}) as Record<string, unknown>;
        const s = typeof o.source === 'string' ? o.source : '';
        const t = typeof o.target === 'string' ? o.target : '';
        if (!s || !t) errors.push('edge-missing-endpoints');
        else {
          if (!ids.has(s)) errors.push(`edge-dangling-source:${s}`);
          if (!ids.has(t)) errors.push(`edge-dangling-target:${t}`);
        }
      }
      return untrustedToolResult({
        ok: errors.length === 0,
        nodeCount: nodes.length,
        edgeCount: edges.length,
        errors: errors.slice(0, 50),
        warnings,
      });
    }
  );

  // ── Procedure extraction (edge port, Apache-2.0 design) ──────────
  // Learned-rules read path. Job submit/review need an admin session —
  // use POST /api/v1/procedures/jobs and /review for those.

  h.tools(
    'proc_list_rules',
    'List learned procedure-extraction rules (analyst corrections promoted to guardrails): technique-grounding, exploit-mapping, provenance. Optionally rank by relevance to a report excerpt. Upstream design: netandneedle/procedure-extraction-pipeline (Apache-2.0).',
    {
      reportExcerpt: z
        .string()
        .optional()
        .describe('Report text (up to ~10k chars) to rank rules against by keyword overlap'),
      limit: z.number().int().min(1).max(50).optional().describe('Max rules to return (default 10)'),
    },
    async ({ reportExcerpt, limit }) => {
      const rules = await loadProcedureRules(ASSETS);
      const picked =
        reportExcerpt && reportExcerpt.trim()
          ? relevantRules(rules, reportExcerpt.slice(0, 10000), limit ?? 10)
          : rules.slice(0, limit ?? 10);
      return untrustedToolResult({
        source: 'Procedure extraction (edge port) — upstream netandneedle/procedure-extraction-pipeline (Apache-2.0)',
        total: rules.length,
        returned: picked.length,
        rules: picked,
      });
    }
  );

  h.tools(
    'ti_threaticon_coverage',
    'Return the Threaticon ATT&CK detection-coverage dataset: every technique the platform ships detection content for, its tactic, and the number of detection rules, plus per-tactic coverage percentages. Filter by tactic, minimum rule count, or keyword. Use for gap analysis when planning detection coverage.',
    {
      tactic: z
        .string()
        .optional()
        .describe('Restrict to one tactic (case-insensitive), e.g. "reconnaissance", "execution"'),
      minRules: z.number().int().min(0).optional().describe('Only techniques with at least this many detection rules'),
      keyword: z.string().optional().describe('Case-insensitive substring match against technique ID or name'),
      limit: z.number().int().min(1).max(5000).optional().describe('Max techniques to return (default 500)'),
    },
    async ({ tactic, minRules, keyword, limit }) => {
      const body = await loadThreaticonCoverage(ASSETS);
      if (!body) {
        return untrustedToolResult({
          error: 'threaticon_coverage_not_found',
          hint: 'Run node scripts/sync-threaticon.mjs && node scripts/build-threaticon.mjs.',
        });
      }
      const techniques = filterThreaticonCoverage(body, { tactic, minRules, keyword, limit: limit ?? 500 });
      return untrustedToolResult({
        source: body.source,
        syncedAt: body.syncedAt,
        techniqueCount: body.techniqueCount,
        tactics: body.tactics,
        returned: techniques.length,
        techniques,
      });
    }
  );

  // ── dPhish phishing feed (dphish.com, TAXII 2.1) ────────────────
  // Public TAXII 2.1 collection of phishing indicators: malicious
  // domains, phishing URLs, sender IPs, phone numbers, and
  // attachment rules. Data ships in public/data/threat-intel/dphish/.

  h.tools(
    'ti_list_dphish',
    'List phishing indicators from the dPhish public TAXII 2.1 collection (dphish.com): malicious domains, phishing URLs, sender IPs, phone numbers, and attachment detection rules — with active/revoked status, STIX observable type, confidence, OpenCTI score, and validity window. Filter by category, active-only, or keyword. Use ti_get_dphish_indicator to fetch the full STIX body (pattern, description, labels).',
    {
      category: z
        .enum(['domain', 'ipv4', 'ipv6', 'url', 'phone', 'file', 'email', 'other'])
        .optional()
        .describe('Filter by indicator category'),
      activeOnly: z
        .boolean()
        .optional()
        .describe('Only indicators that are live right now (not revoked, within validity window)'),
      keyword: z.string().optional().describe('Case-insensitive substring match against value / description'),
      limit: z.number().int().min(1).max(1000).optional().describe('Max indicators to return (default 100)'),
    },
    async ({ category, activeOnly, keyword, limit }) => {
      const idx = await loadDphishIndex(ASSETS);
      const indicators = filterDphishIndicators(idx, { category, activeOnly, keyword, limit: limit ?? 100 });
      return untrustedToolResult({
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        syncedAt: idx.syncedAt,
        counts: idx.counts,
        returned: indicators.length,
        indicators,
      });
    }
  );

  h.tools(
    'ti_get_dphish_indicator',
    'Return the full dPhish indicator body for one slug: STIX id, observable value, category, pattern (STIX or YARA), description, created/modified dates, validity window, revoked status, confidence, OpenCTI score, labels, and indicator types. Use ti_list_dphish to discover slugs (e.g. "melbetegypt.com-1a2b3c").',
    {
      slug: z
        .string()
        .describe('Indicator slug (lowercased, e.g. "185.225.19.240-59c41c"). Get these from ti_list_dphish.'),
    },
    async ({ slug }) => {
      const body = await getDphishIndicator(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'dphish_indicator_not_found',
          slug,
          hint: 'Call ti_list_dphish to see available indicator slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── OffSeq Threat Radar (radar.offseq.com) ─────────────────────
  // Aggregated threat feed with AI-enriched summaries, KEV correlation
  // and Mirage honeypot exploitation telemetry. Data ships in
  // public/data/threat-intel/offseq/.

  h.tools(
    'ti_list_offseq_threats',
    'List recent threats from the OffSeq Threat Radar (radar.offseq.com): AI-enriched threat records across ~40 upstream sources (CVEs, malware, breaches, security news) with severity, CVSS, KEV/exploitation telemetry (Mirage honeypot), tags, and CVE ids. Filter by type, severity, exploited-only, or keyword. Use ti_get_offseq_threat for the full body (AI summary, impact, references, affected countries).',
    {
      type: z
        .string()
        .optional()
        .describe('Filter by threat type (e.g. "vulnerability", "malware", "breach", "security-news")'),
      severity: z.string().optional().describe('Filter by severity (critical, high, medium, low)'),
      exploited: z.boolean().optional().describe('Only threats with observed in-the-wild exploitation'),
      keyword: z.string().optional().describe('Case-insensitive substring match against title / CVE id / tags'),
      limit: z.number().int().min(1).max(500).optional().describe('Max threats to return (default 50)'),
    },
    async ({ type, severity, exploited, keyword, limit }) => {
      const idx = await loadOffseqIndex(ASSETS);
      const threats = filterOffseqThreats(idx, {
        type,
        severity,
        exploitedOnly: exploited,
        keyword,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        syncedAt: idx.syncedAt,
        counts: idx.counts,
        returned: threats.length,
        threats,
      });
    }
  );

  h.tools(
    'ti_get_offseq_threat',
    'Return the full OffSeq threat body for one slug: title, description, severity, CVSS, CVE ids, AI-generated summary and impact, Mirage exploitation telemetry (countries), patch availability, known threat actors, affected countries, references, and tags. Use ti_list_offseq_threats to discover slugs.',
    {
      slug: z.string().describe('Threat slug (lowercased). Get these from ti_list_offseq_threats.'),
    },
    async ({ slug }) => {
      const body = await getOffseqThreat(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'offseq_threat_not_found',
          slug,
          hint: 'Call ti_list_offseq_threats to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── CTIWatch (ctiwatch.com) ────────────────────────────────────
  // Public vulnerability + IOC database (2M+ IOCs, 400k+ CVEs, 4k+ KEV,
  // 10k+ threat actors, 35k+ victims). Data ships in
  // public/data/threat-intel/ctiwatch/.

  h.tools(
    'ti_list_ctiwatch_vulns',
    'List recent CVEs from CTIWatch (ctiwatch.com): CVE id, title, severity, CVSS, KEV flag, exploit status, published date, CWEs, vendor/product, priority score, and EPSS. Filter by KEV-only, severity, or keyword. Use ti_get_ctiwatch_vuln for the full body (description, references, affected products).',
    {
      kevOnly: z.boolean().optional().describe('Only KEV-listed CVEs'),
      severity: z.string().optional().describe('Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)'),
      keyword: z.string().optional().describe('Case-insensitive substring match against CVE id / title / tags'),
      limit: z.number().int().min(1).max(500).optional().describe('Max CVEs to return (default 50)'),
    },
    async ({ kevOnly, severity, keyword, limit }) => {
      const idx = await loadCtiwatchIndex(ASSETS);
      const vulns = filterCtiwatchVulns(idx, { kevOnly, severity, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        syncedAt: idx.syncedAt,
        counts: idx.counts,
        returned: vulns.length,
        vulnerabilities: vulns,
      });
    }
  );

  h.tools(
    'ti_get_ctiwatch_vuln',
    'Return the full CTIWatch vulnerability body for one CVE id: title, description, severity, CVSS, KEV flag, exploit status, published date, CWEs, vendor/product, priority score, EPSS, references, and affected products. Use ti_list_ctiwatch_vulns to discover CVE ids.',
    {
      cveId: z.string().describe('CVE id (e.g. "CVE-2026-1234"). Get these from ti_list_ctiwatch_vulns.'),
    },
    async ({ cveId }) => {
      const body = await getCtiwatchVulnerability(ASSETS, cveId);
      if (!body) {
        return untrustedToolResult({
          error: 'ctiwatch_vuln_not_found',
          cveId,
          hint: 'Call ti_list_ctiwatch_vulns to see available CVE ids.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ti_get_ctiwatch_victim',
    'Return the full CTIWatch victim record for one id: name, group, country, sector, attack date, website, and description. Use the CTIWatch index (ti_list is not paginated for victims — fetch /api/v1/threat-intel/ctiwatch and read .victims).',
    {
      id: z.string().describe('Victim id (UUID). Get these from the ctiwatch index .victims array.'),
    },
    async ({ id }) => {
      const body = await getCtiwatchVictim(ASSETS, id);
      if (!body) {
        return untrustedToolResult({
          error: 'ctiwatch_victim_not_found',
          id,
          hint: 'Fetch /api/v1/threat-intel/ctiwatch and read .victims for available ids.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── Destroylist (phishdestroy/destroylist, MIT) ────────────────
  // Phishing & scam domain blacklist: primary curated feed replicated
  // as hash-bucketed sorted arrays under public/data/threat-intel/
  // destroylist/ (membership via ASSETS + binary search); community
  // aggregate reachable through the keyless api.destroy.tools lookup.

  h.tools(
    'dl_check_domain',
    'Check whether a domain (or URL host) is on the Destroylist phishing/scam blacklist (github.com/phishdestroy/destroylist, MIT): ~193k curated primary domains replicated locally (zero egress) plus parent-domain matching, so a phishing page on a listed apex matches too. Returns listed status, matched feed entry, verdict, and feed sync timestamp.',
    {
      domain: z.string().describe('Domain or URL to check (e.g. "0-collab.land" or "https://evil.example.com/login")'),
    },
    async ({ domain }) => {
      const result = await checkDestroylistDomain(ASSETS, domain);
      if (result === null) {
        return untrustedToolResult({
          error: 'destroylist_manifest_unavailable',
          hint: 'Run scripts/sync-destroylist.mjs && scripts/build-destroylist.mjs',
        });
      }
      const idx = await loadDestroylistIndex(ASSETS).catch(() => null);
      return untrustedToolResult({
        domain,
        listed: result.listed,
        matched: result.matched,
        verdict: result.listed ? 'malicious' : 'clean',
        feed: 'primary',
        syncedAt: idx?.syncedAt,
      });
    }
  );

  h.tools(
    'dl_stats',
    'Return Destroylist feed statistics: primary/community/DNS-active domain counts, root-domain rollup count, last sync time, bucket layout, and per-isolate bucket cache health. Use before bulk checks to confirm the manifest is loaded.',
    {},
    async () => {
      const idx = await loadDestroylistIndex(ASSETS);
      if (!idx) {
        return untrustedToolResult({
          error: 'destroylist_manifest_unavailable',
          hint: 'Data ships via scripts/sync-destroylist.mjs && scripts/build-destroylist.mjs.',
        });
      }
      return untrustedToolResult({ ...idx, cache: tiCacheStats().destroylist });
    }
  );

  // ── Living Threat Repository (living-threat.rabitanoor.com) ────
  // Real-world incidents continuously mapped to MITRE ATT&CK tactics +
  // techniques, with per-kill-chain-stage detection/remediation notes,
  // CVEs, actors, tools and priority scoring (MIT, keyless bootstrap
  // API, newest 5000 incidents of ~21k). Bodies ship in sharded JSON;
  // see scripts/sync-living-threat.mjs + scripts/build-living-threat.mjs.

  h.tools(
    'ti_list_living_threat',
    'List incidents from the Living Threat Repository (living-threat.rabitanoor.com): real-world incidents mapped to MITRE ATT&CK tactic/technique chains, with severity, priority score, CVEs/actor/tool counts. Filter by tactic, technique ID (e.g. T1190), severity, actor name, keyword, or minimum priority score. Use ti_get_living_threat_incident to fetch the full incident (per-kill-chain-stage analyses, detection + remediation notes, hunt-pack guidance).',
    {
      tactic: z.string().optional().describe('Filter by ATT&CK tactic name (e.g. "Initial Access", "Persistence")'),
      technique: z.string().optional().describe('Filter by ATT&CK technique ID (e.g. "T1190", "T1059.004")'),
      severity: z.string().optional().describe('Filter by severity (Critical, High, Moderate, Low)'),
      actor: z.string().optional().describe('Filter by threat-actor name (substring)'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against title / source / actors / techniques'),
      minPriority: z
        .number()
        .int()
        .min(0)
        .max(100)
        .optional()
        .describe('Only incidents at/above this priority score (0-100)'),
      limit: z.number().int().min(1).max(1000).optional().describe('Max incidents to return (default 100)'),
    },
    async ({ tactic, technique, severity, actor, keyword, minPriority, limit }) => {
      const idx = await loadLivingThreatIndex(ASSETS);
      const incidents = filterLivingThreatIncidents(idx, {
        tactic,
        technique,
        severity,
        actor,
        keyword,
        minPriority,
        limit: limit ?? 100,
      });
      return untrustedToolResult({
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        repoUrl: idx.repoUrl,
        syncedAt: idx.syncedAt,
        meta: idx.meta,
        counts: idx.counts,
        returned: incidents.length,
        filters: { tactic, technique, severity, actor, keyword, minPriority },
        incidents,
      });
    }
  );

  h.tools(
    'ti_get_living_threat_incident',
    'Return the full Living Threat Repository incident for one slug: per-kill-chain-stage analyses with ATT&CK tactic/technique mappings, per-stage detection + remediation notes, CVEs, threat actors, tools, behavioral / data-exfiltration indicators, detection rules, diamond-model + kill-chain summaries, priority/relevance scores, pyramid of pain, and post-incident recommendations. Use ti_list_living_threat to discover slugs (e.g. "amnesiastealer-macos-malware-021625").',
    {
      slug: z
        .string()
        .describe(
          'Incident slug (title + sequence, e.g. "AmnesiaStealer__macOS_Malware_Leveraging_ClickFix_Attacks-021625"). Get these from ti_list_living_threat.'
        ),
    },
    async ({ slug }) => {
      const body = await getLivingThreatIncident(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'living_threat_incident_not_found',
          slug,
          hint: 'Call ti_list_living_threat to see available incident slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── MalwareAnalyzer by Cyble (malwareanalyzer.com) ──────────────
  // Free, keyless public API: live malicious / newly-observed URL
  // feeds + on-demand IOC reputation lookups (70k+ public sample
  // corpus, 46 engines). Feeds ship in
  // public/data/threat-intel/malwareanalyzer/; lookups are live.

  h.tools(
    'ti_list_malwareanalyzer',
    'List URL entries from the MalwareAnalyzer by Cyble public feeds (malwareanalyzer.com): verdict=malicious URLs (live malicious feed) or newly-observed scans. Each entry has url, hostname, apex, verdict, score, brands, categories, and scan time. Filter by verdict, category, or keyword. For per-IOC intelligence on any indicator, call ti_malwareanalyzer_lookup.',
    {
      feed: z.enum(['malicious', 'newly-observed']).optional().describe('Which feed to list (default malicious)'),
      verdict: z.string().optional().describe('Filter by verdict (e.g. "malicious", "unknown", "suspicious")'),
      category: z.string().optional().describe('Filter by category (e.g. "suspicious-infrastructure", "phishing")'),
      keyword: z.string().optional().describe('Case-insensitive substring match against url / hostname / apex'),
      limit: z.number().int().min(1).max(200).optional().describe('Max entries to return (default 200)'),
    },
    async ({ feed, verdict, category, keyword, limit }) => {
      const idx = await loadMaIndex(ASSETS);
      const name = feed ?? 'malicious';
      const entries = await getMaFeed(ASSETS, name);
      const out = filterMaFeed(entries, { verdict, category, keyword, limit: limit ?? 200 });
      return untrustedToolResult({
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        syncedAt: idx.syncedAt,
        feed: name,
        counts: idx.counts,
        returned: out.length,
        filters: { verdict, category, keyword },
        entries: out,
      });
    }
  );

  h.tools(
    'ti_malwareanalyzer_lookup',
    'Live reputation lookup for a single IOC (IPv4/IPv6, domain, URL, or hash) against MalwareAnalyzer by Cyble (malwareanalyzer.com, keyless): verdict, 0-100 score, first/last seen, prevalence, tags like benigne/malicious categories. Use for enrichment during an investigation. For bulk URL feeds use ti_list_malwareanalyzer.',
    {
      indicator: z
        .string()
        .describe(
          'IOC to look up — IP / domain / URL / hash (e.g. "8.8.8.8", "malwareanalyzer.com") — max 1024 chars, no spaces'
        ),
    },
    async ({ indicator }) => {
      const res = await malwareAnalyzerLookup(indicator);
      return untrustedToolResult(res);
    }
  );

  // ── Daily Briefs (DB) tools ─────────────────────────────────────
  // AI-generated intelligence briefs: OT/ICS cyber, deepfake/GenAI,
  // and global disaster assessments. Data from
  // agentic-ai-daily-reports.netlify.app, parsed into
  // public/data/daily-briefs/.

  h.tools(
    'db_list_briefs',
    'List available daily intelligence briefs by type (cyber, deepfake, disaster). Returns dates and metadata. Use db_get_brief to retrieve the full brief body.',
    {
      type: z.enum(['cyber', 'deepfake', 'disaster', 'maritime']).optional().describe('Filter by brief type'),
      dateFrom: z.string().optional().describe('Start date filter (YYYY-MM-DD)'),
      dateTo: z.string().optional().describe('End date filter (YYYY-MM-DD)'),
      limit: z.number().int().min(1).max(365).optional().describe('Max briefs to return (default 50)'),
    },
    async ({ type, dateFrom, dateTo, limit }) => {
      const idx = await loadDbIndex(ASSETS);
      const briefs = filterBriefs(idx, {
        type: type as DbBriefType | undefined,
        dateFrom,
        dateTo,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        counts: idx.counts,
        returned: briefs.length,
        briefs,
      });
    }
  );

  h.tools(
    'db_get_brief',
    'Return the full daily intelligence brief for a given type and date. Includes executive summary, key findings, events/incidents, and structured data. Use db_list_briefs to discover available dates.',
    {
      type: z.enum(['cyber', 'deepfake', 'disaster', 'maritime']).describe('Brief type'),
      date: z.string().describe('Brief date (YYYY-MM-DD). Get available dates from db_list_briefs.'),
    },
    async ({ type, date }) => {
      const body = await getDbBrief(ASSETS, type as DbBriefType, date);
      if (!body) {
        return untrustedToolResult({
          error: 'brief_not_found',
          type,
          date,
          hint: 'Call db_list_briefs to see available dates.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'db_stats',
    'Return cache + manifest stats for the Daily Briefs data: index loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.',
    {},
    async () => {
      const idx = await loadDbIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        generatedAt: idx.generatedAt,
        cache: dbCacheStats(),
      });
    }
  );

  // ── Webamon Daily Threat Brief (WDTB) tools ───────────────────
  // Campaign intelligence from webamon-org/Daily-Threat-Brief (Apache-2.0).
  // Phishing/malware estate tracking: domain growth, takedowns, infra
  // rotation, lure refreshes, emerging clusters.

  h.tools(
    'wdtb_list_briefs',
    'List available Webamon Daily Threat Briefs. Returns dates and metadata (KPI count, campaign count, movement count). Use wdtb_get_brief to retrieve the full brief.',
    {
      dateFrom: z.string().optional().describe('Start date filter (YYYY-MM-DD)'),
      dateTo: z.string().optional().describe('End date filter (YYYY-MM-DD)'),
      keyword: z.string().optional().describe('Case-insensitive substring match against brief title'),
      limit: z.number().int().min(1).max(200).optional().describe('Max briefs to return (default 50)'),
    },
    async ({ dateFrom, dateTo, keyword, limit }) => {
      const idx = await loadWdtbIndex(ASSETS);
      const briefs = filterWdtbBriefs(idx, { dateFrom, dateTo, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.counts.briefs,
        returned: briefs.length,
        source: idx.source,
        license: idx.license,
        briefs,
      });
    }
  );

  h.tools(
    'wdtb_get_brief',
    'Return the full Webamon Daily Threat Brief for a given date. Includes estate stats, KPIs (new domains, takedowns, infra changes), notable movements (growth/takedown/rotation/lure-refresh), campaigns worth a look, and emerging clusters. Use wdtb_list_briefs to discover dates.',
    {
      date: z.string().describe('Brief date (YYYY-MM-DD). Get available dates from wdtb_list_briefs.'),
    },
    async ({ date }) => {
      const body = await getWdtbBrief(ASSETS, date);
      if (!body) {
        return untrustedToolResult({
          error: 'brief_not_found',
          date,
          hint: 'Call wdtb_list_briefs to see available dates.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'wdtb_latest',
    'Return the most recent Webamon Daily Threat Brief. Includes estate stats, KPIs, notable movements, campaigns, and emerging clusters.',
    {},
    async () => {
      const body = await getWdtbLatest(ASSETS);
      if (!body) {
        return untrustedToolResult({ error: 'no_briefs_available' });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'wdtb_stats',
    'Return cache + manifest stats for the Webamon DTB data: index loaded, body-cache sizes and hit ratios.',
    {},
    async () => {
      const idx = await loadWdtbIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        generatedAt: idx.generatedAt,
        cache: wdtbCacheStats(),
      });
    }
  );

  // ── Live Threat Intel Enrichment ──────────────────────────────
  // Query-specific search tools that hit OTX, ThreatFox, MalwareBazaar,
  // and ransomware.live in real time. Unlike get_live_iocs (aggregated
  // feed), these let an LLM ask targeted questions.

  {
    const { searchOtxPulses, searchThreatfox, searchMalwarebazaar, searchRansomwareLive } =
      await import('../lib/ti-live-enrich');

    h.tools(
      'ti_search_otx',
      'Search AlienVault OTX for threat pulses matching a query. Returns pulse metadata (name, tags, TLP, malware families, MITRE ATT&CK IDs) and indicators for the top 5 pulses. Requires OTX_API_KEY (free at otx.alienvault.com).',
      {
        query: z.string().describe('Search query, e.g. "LockBit", "Emotet", "CVE-2024-1234"'),
      },
      async ({ query }) => {
        const result = await searchOtxPulses(query, h.env.OTX_API_KEY);
        return untrustedToolResult(result);
      }
    );

    h.tools(
      'ti_search_threatfox',
      "Search ThreatFox (abuse.ch) for IOCs matching a search term. Returns IOC type, value, malware family, confidence, timestamps, and reporter. Free API — no key required. Useful for looking up specific IPs, domains, URLs, or hashes against ThreatCrowd's crowdsourced IOC database.",
      {
        query: z
          .string()
          .describe('Search term — can be an IOC value (IP, domain, URL, hash), malware family name, or actor name'),
      },
      async ({ query }) => {
        const result = await searchThreatfox(query);
        return untrustedToolResult(result);
      }
    );

    h.tools(
      'ti_search_malwarebazaar',
      'Search MalwareBazaar (abuse.ch) for malware samples by tag or signature. Returns SHA-256, MD5, file name, type, malware family signature, tags, and timestamps. Tries tag search first, falls back to signature. Free API — no key required.',
      {
        query: z.string().describe('Malware family name or tag, e.g. "Emotet", "LockBit", "AgentTesla"'),
      },
      async ({ query }) => {
        const result = await searchMalwarebazaar(query);
        return untrustedToolResult(result);
      }
    );

    h.tools(
      'ti_search_ransomware_live',
      'Search ransomware.live for ransomware group profiles. Returns group description, .onion leak-site URLs, recent victims (with country/sector), MITRE ATT&CK TTPs, and known tools. Free public API — no key required.',
      {
        query: z.string().describe('Ransomware group name, e.g. "LockBit", "BlackCat", "Cl0p"'),
      },
      async ({ query }) => {
        const result = await searchRansomwareLive(query);
        return untrustedToolResult(result);
      }
    );
  }

  // ── TI STIX 2.1 Export ─────────────────────────────────────────
  // Generate STIX 2.1 bundles from the threat-intel vertical's IOC data.
  {
    const { buildStixBundle } = await import('../lib/cti-ioc-export');

    h.tools(
      'ti_export_stix',
      'Export IOC family indicators as a STIX 2.1 bundle. Reads the IOC family body from the threat-intel manifest, converts each indicator to a STIX indicator object with pattern, and wraps in a bundle with TLP marking. Importable into OpenCTI, MISP, or any TAXII 2.1 consumer.',
      {
        slug: z.string().describe('IOC family slug, e.g. "lockbit-4-0-ransomware". Get these from ti_list_iocs.'),
        tlp: z
          .enum(['WHITE', 'GREEN', 'AMBER', 'RED'])
          .optional()
          .describe('TLP marking for the bundle (default: GREEN)'),
        limit: z.number().int().min(1).max(500).optional().describe('Max indicators to include (default: 100)'),
      },
      async ({ slug, tlp, limit }) => {
        const body = await getTiIoc(ASSETS, slug);
        if (!body) {
          return untrustedToolResult({
            error: 'ioc_family_not_found',
            slug,
            hint: 'Call ti_list_iocs to see available families.',
          });
        }

        const stixTypeMap: Record<string, string> = {
          ipv4: 'ipv4-addr',
          ipv6: 'ipv6-addr',
          domain: 'domain-name',
          email: 'email-addr',
          md5: 'file:hashes.MD5',
          sha1: 'file:hashes.SHA-1',
          sha256: 'file:hashes.SHA-256',
          onion: 'domain-name',
        };
        const indicators = (body.indicators ?? [])
          .slice(0, limit ?? 100)
          .map((ind: { type: string; value: string }) => ({
            value: ind.value,
            type: (stixTypeMap[ind.type] || ind.type) as Parameters<typeof buildStixBundle>[0][0]['type'],
            label: `${body.family} — ${ind.type}`,
            description: `IOC from ${body.family} (${body.category})`,
            confidence: 50,
            tlp: (tlp ?? 'GREEN') as 'GREEN',
            tags: [body.category, body.family],
          }));

        if (indicators.length === 0) {
          return untrustedToolResult({
            error: 'no_indicators',
            slug,
            message: 'This IOC family has no extracted indicators. The source may not have structured IOC data.',
          });
        }

        const bundle = buildStixBundle(indicators, {
          bundleName: `${body.family} — TI Export`,
          defaultTlp: tlp ?? 'GREEN',
          source: 'PANOPTICON TI',
        });

        return untrustedToolResult({
          family: body.family,
          category: body.category,
          tlp: tlp ?? 'GREEN',
          indicator_count: indicators.length,
          stix_object_count: bundle.objects.length,
          stix_bundle: bundle,
        });
      }
    );
  }

  // ── APT Actors (ETDA) tools ──────────────────────────────────
  // 504 threat actors (416 APT, 54 other, 34 unknown) from ETDA
  // Thailand's Threat Group Cards portal, enriched with showcard
  // metadata (sectors, tools, operations, MITRE references) and
  // the APTmap relationship graph. Data shipped in
  // public/data/apt-actors/ via weekly sync.

  h.tools(
    'etda_list_actors',
    'List APT threat actors from the ETDA Threat Group Cards vertical. 504 actors (416 APT, 54 other, 34 unknown). Filter by category, country, MITRE ATT&CK reference, or keyword. Each entry includes aliases, country, sponsor, motivation, observed period, and counts of tools/operations.',
    {
      category: z.enum(['apt', 'other', 'unknown']).optional().describe('Filter by actor category'),
      country: z.string().optional().describe('Case-insensitive substring match against actor country of origin'),
      hasMitre: z.boolean().optional().describe('Only return actors with a MITRE ATT&CK group ID'),
      hasTools: z.boolean().optional().describe('Only return actors with known tool associations'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against slug / name / aliases / description'),
      limit: z.number().int().min(1).max(200).optional().describe('Max actors to return (default 50)'),
    },
    async ({ category, country, hasMitre, hasTools, keyword, limit }) => {
      const idx = await loadActorIndex(ASSETS);
      const actors = filterActors(idx, {
        category: category as ActorCategory | undefined,
        country: country || undefined,
        hasMitre,
        hasTools,
        keyword: keyword || undefined,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.counts.actors,
        apt: idx.counts.apt,
        returned: actors.length,
        lastSyncedAt: idx.lastSyncedAt,
        actors,
      });
    }
  );

  h.tools(
    'etda_get_actor',
    'Return the full actor body for a single APT threat actor from the ETDA Threat Group Cards vertical. Includes names (with vendor sources), aliases, country, sponsor, motivation, description, sectors, tools, operations, counter operations, MITRE ATT&CK link, and information references. Use etda_list_actors first to discover slugs.',
    {
      slug: z.string().describe('Actor slug, e.g. "apt-41" or "lazarus-group". Get these from etda_list_actors.'),
    },
    async ({ slug }) => {
      const body = await getActor(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'actor_not_found',
          slug,
          hint: 'Call etda_list_actors to see available actors.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'etda_list_sectors',
    'List all observed target sectors across the ETDA actor database. Returns the count of actors that target each sector.',
    {
      minActors: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe('Minimum number of actors targeting the sector to include it'),
    },
    async ({ minActors }) => {
      const idx = await loadActorIndex(ASSETS);
      const sectorMap = new Map<string, number>();
      for (const a of idx.actorIndex) {
        if (a.sectorCount === 0) continue;
        const body = await getActor(ASSETS, a.slug);
        if (!body) continue;
        for (const s of body.sectors) {
          sectorMap.set(s, (sectorMap.get(s) || 0) + 1);
        }
      }
      const threshold = minActors ?? 1;
      const sectors = [...sectorMap.entries()]
        .filter(([, count]) => count >= threshold)
        .sort(([, a], [, b]) => b - a)
        .map(([sector, count]) => ({ sector, actorCount: count }));
      return untrustedToolResult({
        total: sectors.length,
        minActors: threshold,
        sectors,
      });
    }
  );

  h.tools(
    'etda_stats',
    'Return cache + manifest stats for the APT Actors data: index loaded, APTmap loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.',
    {},
    async () => {
      const idx = await loadActorIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        lastSyncedAt: idx.lastSyncedAt,
        aptmap: idx.aptmap,
        cache: actorsCacheStats(),
      });
    }
  );

  h.tools(
    'etda_list_aptmap_data',
    'List all available APTmap malware analysis data files from the AndreaCristaldi/APTmap repo. These contain frequency-distribution statistics from 29GB of PE malware samples attributed to APT groups. Includes certificates, exports, functions, hashes, imports, resources, sections, strings, xrefs, file types, and file sizes.',
    {},
    async () => {
      const idx = await loadActorIndex(ASSETS);
      const files = listAptmapDataFiles(idx);
      return untrustedToolResult({
        total: files.length,
        files: files.map((f) => ({
          name: f.name,
          sizeKB: Math.round(f.sizeBytes / 1024),
        })),
      });
    }
  );

  h.tools(
    'etda_get_aptmap_data',
    'Return a specific APTmap malware analysis data file by filename. These are frequency-distribution statistics from 29GB of PE malware samples attributed to APT groups. Use etda_list_aptmap_data first to discover available files.',
    {
      filename: z
        .string()
        .describe('Filename, e.g. "certificates_count.json" or "hashes.json". Get these from etda_list_aptmap_data.'),
    },
    async ({ filename }) => {
      const data = await loadAptmapDataFile(ASSETS, filename);
      if (!data) {
        return untrustedToolResult({
          error: 'aptmap_data_not_found',
          filename,
          hint: 'Call etda_list_aptmap_data to see available files.',
        });
      }
      return untrustedToolResult(data);
    }
  );
}
