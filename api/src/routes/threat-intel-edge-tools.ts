/**
 * Threat Intel edge tools — REST surface for CVE/KEV/IOC/sector data.
 *
 * Endpoints (all under /api/v1/threat-intel/):
 *   GET  /threat-intel/                — slim index
 *   GET  /threat-intel/cves            — list CVEs with filters (severity, kevOnly, vendor, etc.)
 *   GET  /threat-intel/cves/:cveId     — full CVE body
 *   GET  /threat-intel/kev             — CISA KEV snapshot (all entries)
 *   GET  /threat-intel/iocs            — list IOC families with filters
 *   GET  /threat-intel/iocs/:slug      — full IOC family body
 *   GET  /threat-intel/sectors         — list available sectors
 *   GET  /threat-intel/sectors/:sector — sector brief
 *   GET  /threat-intel/lists           — list detection lists (awesome-lists)
 *   GET  /threat-intel/lists/:slug     — full detection list with entries
 *   GET  /threat-intel/stats           — cache + manifest stats
 *   GET  /threat-intel/threatcluster/* — ThreatCluster feeds (clusters, vulns,
 *                                        exploits, victims, iocs, misp,
 *                                        entities)
 *   GET  /threat-intel/threaticon/*    — Threaticon actor catalog, malware
 *                                        dictionary, detection coverage, map
 *   GET  /threat-intel/dphish/*        — dPhish phishing indicators
 *                                        (TAXII 2.1 collection)
 *   GET  /threat-intel/living-threat/* — Living Threat Repository incidents
 *                                        mapped to MITRE ATT&CK chains
 *   GET  /threat-intel/malwareanalyzer/* — MalwareAnalyzer by Cyble feeds +
 *                                        live IOC reputation lookup
 *
 * The actual logic lives in worker/lib/threat-intel-manifest.ts (symlinked).
 * Routes read from env.ASSETS — no D1, no KV, no public fetch.
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { badRequest, internalError, notFound, badGateway, serviceUnavailable } from '../lib/api-error';
import { logError } from '../lib/logger';
import { malwareAnalyzerLookup } from '../lib/malwareanalyzer';

async function loadTiMod() {
  return await import('../lib/threat-intel-manifest');
}

export const threatIntelRouter = new Hono<{ Bindings: Env }>();

// ─── Slim index ────────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      license: idx.license,
      replicatedAt: idx.replicatedAt,
      lastSyncedAt: idx.lastSyncedAt,
      counts: idx.counts,
    });
  } catch (e) {
    logError('loadTiMod failed', e);
    return internalError(c, `ti_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── List CVEs ──────────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/cves', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];
    const severityRaw = c.req.query('severity');
    const severity =
      severityRaw && VALID_SEVERITIES.includes(severityRaw)
        ? (severityRaw as NonNullable<Parameters<typeof mod.filterCves>[1]>['severity'])
        : undefined;
    const kevOnly = c.req.query('kev_only') === 'true';
    const vendor = c.req.query('vendor');
    const daysBackRaw = c.req.query('days_back');
    const daysBack = daysBackRaw ? Math.min(365, Math.max(1, Number(daysBackRaw) || 1)) : undefined;
    const minPriorityRaw = c.req.query('min_priority');
    const minPriority = minPriorityRaw ? Number(minPriorityRaw) || undefined : undefined;
    const minArgusScoreRaw = c.req.query('min_argus_score');
    const minArgusScore = minArgusScoreRaw ? Number(minArgusScoreRaw) || undefined : undefined;
    const keyword = c.req.query('q');
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(1000, Math.max(1, Number(limitRaw) || 100)) : undefined;

    const cves = mod.filterCves(idx, {
      severity,
      kevOnly: kevOnly || undefined,
      vendor: vendor || undefined,
      daysBack,
      minPriority,
      minArgusScore,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.cves, returned: cves.length, cves });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_cves_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single CVE ─────────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/cves/:cveId', async (c) => {
  const cveId = c.req.param('cveId');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTiCve(c.env.ASSETS, cveId);
    if (!body) return notFound(c, `cve_not_found: ${cveId}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_cve_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── KEV snapshot ──────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/kev', async (c) => {
  try {
    const mod = await loadTiMod();
    const kev = await mod.loadKevSnapshot(c.env.ASSETS);
    const vendor = c.req.query('vendor');
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const needle = vendor?.toLowerCase();
    const out = needle ? kev.filter((e: { vendor: string }) => e.vendor.toLowerCase().includes(needle)) : kev;
    const sliced = limit ? out.slice(0, limit) : out;
    return c.json({ total: kev.length, returned: sliced.length, entries: sliced });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_kev_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── List IOCs ─────────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/iocs', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    const category = c.req.query('category');
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(100, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;

    const iocs = mod.filterIocs(idx, {
      category: (category as NonNullable<Parameters<typeof mod.filterIocs>[1]>['category']) || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.iocs, returned: iocs.length, iocs });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_iocs_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single IOC family ─────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/iocs/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTiIoc(c.env.ASSETS, slug);
    if (!body) return notFound(c, `ioc_family_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_ioc_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── List sectors ──────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/sectors', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    return c.json({ sectors: idx.sectors });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_sectors_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single sector brief ───────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/sectors/:sector', async (c) => {
  const sector = c.req.param('sector').toLowerCase();
  if (!['financial', 'healthcare', 'government'].includes(sector)) {
    return badRequest(c, `invalid_sector: ${sector} — must be financial, healthcare, or government`);
  }
  try {
    const mod = await loadTiMod();
    const body = await mod.getTiSector(c.env.ASSETS, sector);
    if (!body) return notFound(c, `sector_not_found: ${sector}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_sector_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Stats ─────────────────────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/stats', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    const cache = mod.tiCacheStats();
    return c.json({
      counts: idx.counts,
      source: idx.source,
      license: idx.license,
      replicatedAt: idx.replicatedAt,
      lastSyncedAt: idx.lastSyncedAt,
      cache,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_stats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── List detection lists ──────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/lists', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTiIndex(c.env.ASSETS);
    const category = c.req.query('category');
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(100, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;

    const lists = mod.filterLists(idx, {
      category: category || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.lists ?? 0, returned: lists.length, lists });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_lists_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Single detection list ─────────────────────────────────────────────
threatIntelRouter.get('/threat-intel/lists/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTiList(c.env.ASSETS, slug);
    if (!body) return notFound(c, `detection_list_not_found: ${slug}`);
    const keyword = c.req.query('q');
    const severity = c.req.query('severity');
    const limit = c.req.query('limit') ? Math.min(2000, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const entries = mod.searchListEntries(body, {
      keyword: keyword || undefined,
      severity: severity || undefined,
      limit,
    });
    return c.json({
      slug: body.slug,
      title: body.title,
      category: body.category,
      description: body.description,
      valueColumn: body.valueColumn,
      totalEntries: body.entryCount,
      returned: entries.length,
      entries,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_list_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Darknet directory (darknetlist.is) ────────────────────────────────
//
// A Tor site directory replicated from darknetlist.is. 108 sites across
// 9 categories (markets, search, forums, news, security, comms, crypto,
// tools, AI), each with live up/down status, onion URLs, response codes,
// and fingerprints. Data ships in public/data/threat-intel/darknet/.

threatIntelRouter.get('/threat-intel/darknet', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDarknetIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      url: idx.url,
      description: idx.description,
      rebuiltAt: idx.rebuiltAt,
      syncedAt: idx.syncedAt,
      counts: idx.counts,
      categories: idx.categories,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_darknet_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/darknet/sites', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDarknetIndex(c.env.ASSETS);
    const category = c.req.query('category');
    const statusRaw = c.req.query('status');
    const status = statusRaw === 'up' || statusRaw === 'down' ? statusRaw : undefined;
    const recommendedOnly = c.req.query('recommended') === 'true';
    const onionOnly = c.req.query('onion_only') === 'true';
    const keyword = c.req.query('q');
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(500, Math.max(1, Number(limitRaw) || 200)) : undefined;

    const sites = mod.filterDarknetSites(idx, {
      category: category || undefined,
      status,
      recommendedOnly: recommendedOnly || undefined,
      onionOnly: onionOnly || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.sites, returned: sites.length, sites });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_darknet_sites_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/darknet/sites/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getDarknetSite(c.env.ASSETS, slug);
    if (!body) return notFound(c, `darknet_site_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_darknet_site_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/darknet/categories', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDarknetIndex(c.env.ASSETS);
    return c.json({ categories: idx.categories });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_darknet_categories_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/darknet/categories/:category', async (c) => {
  const category = c.req.param('category').toLowerCase();
  try {
    const mod = await loadTiMod();
    const body = await mod.getDarknetCategory(c.env.ASSETS, category);
    if (!body) return notFound(c, `darknet_category_not_found: ${category}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_darknet_category_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── ThreatCluster feeds (threatcluster.io) ────────────────────────────
//
// Replicated public feeds from threatcluster.io: top-50 trending threat
// clusters, CVE vulnerabilities + exploits feeds, dark-web ransomware
// victims, a high-confidence IOC blocklist, and a slim MISP manifest
// pass-through. Data ships in public/data/threat-intel/threatcluster/.

threatIntelRouter.get('/threat-intel/threatcluster', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      url: idx.url,
      description: idx.description,
      syncedAt: idx.syncedAt,
      lastBuildDates: idx.lastBuildDates,
      counts: idx.counts,
      feeds: idx.feeds,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/clusters', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const clusters = mod.filterTcClusters(idx, { keyword: keyword || undefined, limit });
    return c.json({ total: idx.counts.clusters, returned: clusters.length, clusters });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_clusters_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/clusters/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTcCluster(c.env.ASSETS, slug);
    if (!body) return notFound(c, `tc_cluster_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_cluster_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/vulnerabilities', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const vulnerabilities = mod.filterTcVulns(idx, { keyword: keyword || undefined, limit });
    return c.json({ total: idx.counts.vulnerabilities, returned: vulnerabilities.length, vulnerabilities });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_vulns_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/vulnerabilities/:cveId', async (c) => {
  const cveId = c.req.param('cveId');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTcVuln(c.env.ASSETS, cveId);
    if (!body) return notFound(c, `tc_vuln_not_found: ${cveId}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_vuln_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/exploits', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const severityRaw = c.req.query('severity');
    const severity = severityRaw ? severityRaw.toUpperCase() : undefined;
    const kevOnly = c.req.query('kev_only') === 'true';
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const exploits = mod.filterTcExploits(idx, {
      severity: severity || undefined,
      kevOnly: kevOnly || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.exploits, returned: exploits.length, exploits });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_exploits_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/exploits/:cveId', async (c) => {
  const cveId = c.req.param('cveId');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTcExploit(c.env.ASSETS, cveId);
    if (!body) return notFound(c, `tc_exploit_not_found: ${cveId}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_exploit_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/victims', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const group = c.req.query('group');
    const sector = c.req.query('sector');
    const country = c.req.query('country');
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const victims = mod.filterTcVictims(idx, {
      group: group || undefined,
      sector: sector || undefined,
      country: country || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: idx.counts.victims, returned: victims.length, victims });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_victims_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/victims/:id', async (c) => {
  const id = c.req.param('id');
  try {
    const mod = await loadTiMod();
    const body = await mod.getTcVictim(c.env.ASSETS, id);
    if (!body) return notFound(c, `tc_victim_not_found: ${id}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_victim_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/iocs', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const body = await mod.loadTcIocs(c.env.ASSETS);
    const type = c.req.query('type');
    const keyword = c.req.query('q');
    const limit = c.req.query('limit') ? Math.min(1000, Math.max(1, Number(c.req.query('limit')) || 200)) : undefined;
    if (!body) return c.json({ total: idx.counts.iocs, returned: 0, iocs: [] });
    const iocs = mod.filterTcIocs(body.iocs, {
      type: type || undefined,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({ total: body.count, returned: iocs.length, iocs });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_iocs_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/misp', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreatClusterIndex(c.env.ASSETS);
    const body = await mod.loadTcMispEvents(c.env.ASSETS);
    if (!body) return c.json({ total: idx.counts.mispEvents, returned: 0, events: [] });
    const keyword = c.req.query('q')?.toLowerCase();
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    let events = body.events;
    if (keyword) {
      events = events.filter(
        (e: { info: string | null; tags: string[] }) =>
          (e.info ?? '').toLowerCase().includes(keyword) || e.tags.some((t) => t.toLowerCase().includes(keyword))
      );
    }
    if (limit) events = events.slice(0, limit);
    return c.json({ total: body.eventCount, returned: events.length, events });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_misp_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── ThreatCluster entity intelligence ─────────────────────────────────
//
// Derived entity profiles (actors, ransomware groups, malware, CVEs,
// sectors) with mention frequency and a weighted related-entity graph.
// Deterministic build-time extraction — see scripts/build-tc-entities.mjs.

threatIntelRouter.get('/threat-intel/threatcluster/entities', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadTcEntities(c.env.ASSETS);
    const keyword = c.req.query('q');
    const typeRaw = c.req.query('type');
    const type = mod.getTcEntityTypeOrNull(typeRaw ?? undefined) ?? undefined;
    const minMentionsRaw = c.req.query('min_mentions');
    const minMentions = minMentionsRaw ? Math.max(0, Number(minMentionsRaw) || 0) : undefined;
    const limit = c.req.query('limit') ? Math.min(500, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const entities = mod.filterTcEntities(idx, { type, keyword: keyword || undefined, minMentions, limit });
    return c.json({
      builtAt: idx.builtAt,
      counts: idx.counts,
      total: Object.values(idx.counts).reduce((a: number, b: number) => a + b, 0),
      returned: entities.length,
      entities,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_entities_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/entities/:type', async (c) => {
  const typeRaw = c.req.param('type');
  try {
    const mod = await loadTiMod();
    const type = mod.getTcEntityTypeOrNull(typeRaw);
    if (!type) return badRequest(c, `invalid_entity_type: ${typeRaw} — must be actor, group, malware, cve, or sector`);
    const idx = await mod.loadTcEntities(c.env.ASSETS);
    const keyword = c.req.query('q');
    const minMentionsRaw = c.req.query('min_mentions');
    const minMentions = minMentionsRaw ? Math.max(0, Number(minMentionsRaw) || 0) : undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(500, Math.max(1, Number(limitRaw) || 100)) : undefined;
    const entities = mod.filterTcEntities(idx, { type, keyword: keyword || undefined, minMentions, limit });
    return c.json({ type, total: idx.counts[type] ?? 0, returned: entities.length, entities });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_entities_type_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threatcluster/entities/:type/:slug', async (c) => {
  const typeRaw = c.req.param('type');
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const type = mod.getTcEntityTypeOrNull(typeRaw);
    if (!type) return badRequest(c, `invalid_entity_type: ${typeRaw} — must be actor, group, malware, cve, or sector`);
    const body = await mod.getTcEntity(c.env.ASSETS, type, slug);
    if (!body) return notFound(c, `tc_entity_not_found: ${type}/${slug}`);
    const activityLimit = c.req.query('activity_limit')
      ? Math.min(50, Math.max(1, Number(c.req.query('activity_limit')) || 12))
      : undefined;
    if (activityLimit) body.recentActivity = body.recentActivity.slice(0, activityLimit);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `tc_entity_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Threaticon (threaticon.com) ────────────────────────────────────────
//
// A replicated threat-actor catalog + malware dictionary + ATT&CK
// detection-coverage dataset + country-level threat map. Data ships in
// public/data/threat-intel/threaticon/. Build: scripts/sync-threaticon.mjs
// && scripts/build-threaticon.mjs.

threatIntelRouter.get('/threat-intel/threaticon', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreaticonIndex(c.env.ASSETS);
    const stats = mod.tiCacheStats().threaticon;
    return c.json({
      source: idx.source,
      url: idx.url,
      description: idx.description,
      syncedAt: idx.syncedAt,
      builtAt: idx.builtAt,
      counts: idx.counts,
      tactics: idx.tactics,
      cache: { indexLoaded: stats.indexLoaded, actorsLoaded: stats.actors.size > 0 },
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threaticon/actors', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadThreaticonIndex(c.env.ASSETS);
    const keyword = c.req.query('q');
    const type = c.req.query('type') || undefined;
    const country = c.req.query('country') || undefined;
    const tlp = c.req.query('tlp') || undefined;
    const status = c.req.query('status') || undefined;
    const hasMitre = c.req.query('has_mitre') === 'true';
    const limit = c.req.query('limit') ? Math.min(1000, Math.max(1, Number(c.req.query('limit')) || 100)) : undefined;
    const actors = mod.filterThreaticonActors(idx, {
      type,
      country,
      tlp,
      status,
      hasMitre,
      keyword: keyword || undefined,
      limit,
    });
    return c.json({
      total: idx.counts.actors,
      returned: actors.length,
      filters: { type, country, tlp, status, hasMitre, keyword: keyword || undefined },
      actors,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_actors_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threaticon/actors/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getThreaticonActor(c.env.ASSETS, slug);
    if (!body) return notFound(c, `ti_threaticon_actor_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_actor_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threaticon/malware', async (c) => {
  try {
    const mod = await loadTiMod();
    const body = await mod.loadThreaticonMalware(c.env.ASSETS);
    if (!body) return notFound(c, 'ti_threaticon_malware_not_found: run scripts/build-threaticon.mjs');
    const category = c.req.query('category') || undefined;
    const keyword = c.req.query('q') || undefined;
    const minConfidenceRaw = c.req.query('min_confidence');
    const minConfidence = minConfidenceRaw ? Math.max(0, Number(minConfidenceRaw) || 0) : undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(10000, Math.max(1, Number(limitRaw) || 200)) : undefined;
    const families = mod.filterThreaticonMalware(body, { category, keyword, minConfidence, limit });
    return c.json({
      syncedAt: body.syncedAt,
      familyCount: body.familyCount,
      byCategory: body.byCategory,
      returned: families.length,
      families,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_malware_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threaticon/coverage', async (c) => {
  try {
    const mod = await loadTiMod();
    const body = await mod.loadThreaticonCoverage(c.env.ASSETS);
    if (!body) return notFound(c, 'ti_threaticon_coverage_not_found: run scripts/build-threaticon.mjs');
    const tactic = c.req.query('tactic') || undefined;
    const minRulesRaw = c.req.query('min_rules');
    const minRules = minRulesRaw ? Math.max(0, Number(minRulesRaw) || 0) : undefined;
    const keyword = c.req.query('q') || undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(5000, Math.max(1, Number(limitRaw) || 500)) : undefined;
    const techniques = mod.filterThreaticonCoverage(body, { tactic, minRules, keyword, limit });
    return c.json({
      syncedAt: body.syncedAt,
      techniqueCount: body.techniqueCount,
      tactics: body.tactics,
      returned: techniques.length,
      techniques,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_coverage_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/threaticon/map', async (c) => {
  try {
    const mod = await loadTiMod();
    const body = await mod.loadThreaticonMap(c.env.ASSETS);
    if (!body) return notFound(c, 'ti_threaticon_map_not_found: run scripts/build-threaticon.mjs');
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_threaticon_map_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── dPhish phishing feed (dphish.com, TAXII 2.1) ───────────────────────
// Public TAXII 2.1 collection of phishing indicators (malicious domains,
// phishing URLs, sender IPs, phone numbers, attachment rules). Data ships
// in public/data/threat-intel/dphish/. Build: scripts/sync-dphish.mjs &&
// scripts/build-dphish.mjs.

threatIntelRouter.get('/threat-intel/dphish', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDphishIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      collectionId: idx.collectionId,
      collectionUrl: idx.collectionUrl,
      description: idx.description,
      license: idx.license,
      syncedAt: idx.syncedAt,
      counts: idx.counts,
      indicators: idx.indicators,
      stats: mod.tiCacheStats().dphish,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_dphish_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/dphish/indicators', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDphishIndex(c.env.ASSETS);
    const category = c.req.query('category') || undefined;
    const activeOnly = c.req.query('active_only') === 'true';
    const keyword = c.req.query('q') || undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(1000, Math.max(1, Number(limitRaw) || 100)) : undefined;
    const indicators = mod.filterDphishIndicators(idx, { category, activeOnly, keyword, limit });
    return c.json({
      total: idx.counts.indicators,
      returned: indicators.length,
      filters: { category, active_only: activeOnly || undefined, keyword },
      indicators,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_dphish_indicators_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/dphish/indicators/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getDphishIndicator(c.env.ASSETS, slug);
    if (!body) return notFound(c, `ti_dphish_indicator_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_dphish_indicator_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── OffSeq Threat Radar (radar.offseq.com) ─────────────────────────────
// Aggregated threat-intel feed with AI-enriched summaries, KEV correlation
// and Mirage honeypot exploitation telemetry. Build: scripts/sync-offseq.mjs
// && scripts/build-offseq.mjs. Served through env.ASSETS.

threatIntelRouter.get('/threat-intel/offseq', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_offseq_no_assets');
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadOffseqIndex(assets);
    return c.json({ ...idx, cache: mod.tiCacheStats().offseq });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_offseq_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/offseq/threats', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_offseq_no_assets');
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadOffseqIndex(assets);
    const type = c.req.query('type') || undefined;
    const severity = c.req.query('severity') || undefined;
    const exploitedOnly = c.req.query('exploited') === 'true' || c.req.query('exploited') === '1';
    const keyword = c.req.query('q') || c.req.query('keyword') || undefined;
    const limitRaw = Number(c.req.query('limit') ?? 50);
    const limit = Math.min(200, Math.max(1, Number.isFinite(limitRaw) ? limitRaw : 50));
    const out = mod.filterOffseqThreats(idx, { type, severity, exploitedOnly, keyword, limit });
    return c.json({ count: out.length, threats: out });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_offseq_threats_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/offseq/threats/:slug', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_offseq_no_assets');
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getOffseqThreat(assets, slug);
    if (!body) return notFound(c, `ti_offseq_threat_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_offseq_threat_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── CTIWatch (ctiwatch.com) ───────────────────────────────────────────
// Public vulnerability + IOC database. Build: scripts/sync-ctiwatch.mjs &&
// scripts/build-ctiwatch.mjs. Served through env.ASSETS.

threatIntelRouter.get('/threat-intel/ctiwatch', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_ctiwatch_no_assets');
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadCtiwatchIndex(assets);
    return c.json({ ...idx, cache: mod.tiCacheStats().ctiwatch });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_ctiwatch_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/ctiwatch/vulnerabilities', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_ctiwatch_no_assets');
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadCtiwatchIndex(assets);
    const kevOnly = c.req.query('kev') === 'true' || c.req.query('kev') === '1';
    const severity = c.req.query('severity') || undefined;
    const keyword = c.req.query('q') || c.req.query('keyword') || undefined;
    const limit = Math.min(500, Math.max(1, Number(c.req.query('limit') ?? 100)));
    const out = mod.filterCtiwatchVulns(idx, { kevOnly, severity, keyword, limit });
    return c.json({ count: out.length, vulnerabilities: out });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_ctiwatch_vulns_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/ctiwatch/vulnerabilities/:cveId', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_ctiwatch_no_assets');
  const cveId = c.req.param('cveId');
  try {
    const mod = await loadTiMod();
    const body = await mod.getCtiwatchVulnerability(assets, cveId);
    if (!body) return notFound(c, `ti_ctiwatch_vuln_not_found: ${cveId}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_ctiwatch_vuln_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/ctiwatch/victims/:id', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_ctiwatch_no_assets');
  const id = c.req.param('id');
  try {
    const mod = await loadTiMod();
    const body = await mod.getCtiwatchVictim(assets, id);
    if (!body) return notFound(c, `ti_ctiwatch_victim_not_found: ${id}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_ctiwatch_victim_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Destroylist (phishdestroy/destroylist, MIT) ────────────────────────
// Phishing & scam domain blacklist — primary curated feed replicated as
// hash-bucketed sorted arrays in public/data/threat-intel/destroylist/
// (membership via ASSETS + binary search, no egress). The community
// aggregate is reachable through the keyless api.destroy.tools live lookup.

threatIntelRouter.get('/threat-intel/destroylist', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadDestroylistIndex(c.env.ASSETS);
    if (!idx)
      return serviceUnavailable(c, 'destroylist manifest not built — run sync-destroylist && build-destroylist');
    return c.json({
      source: idx.source,
      license: idx.license,
      syncedAt: idx.syncedAt,
      counts: idx.counts,
      bucketCount: idx.bucketCount,
      stats: mod.tiCacheStats().destroylist,
      feeds: {
        primary: 'https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt',
        community: 'https://raw.githubusercontent.com/phishdestroy/destroylist/main/community/blocklist.txt',
        liveApi: 'https://api.destroy.tools',
      },
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_destroylist_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/destroylist/check', async (c) => {
  const domain = c.req.query('domain') || c.req.query('q');
  if (!domain) return badRequest(c, 'domain query parameter required');
  try {
    const mod = await loadTiMod();
    const result = await mod.checkDestroylistDomain(c.env.ASSETS, domain);
    if (result === null) return serviceUnavailable(c, 'destroylist manifest unavailable');
    const idx = await mod.loadDestroylistIndex(c.env.ASSETS).catch(() => null);
    return c.json({
      domain,
      listed: result.listed,
      matched: result.matched,
      verdict: result.listed ? 'malicious' : 'clean',
      feed: 'primary',
      syncedAt: idx?.syncedAt,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_destroylist_check_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

/** Bulk check — up to 100 domains per request. */
threatIntelRouter.post('/threat-intel/destroylist/check', async (c) => {
  try {
    const body = await c.req.json<{ domains?: unknown }>().catch(() => null);
    const domains = Array.isArray(body?.domains) ? body!.domains.filter((d): d is string => typeof d === 'string') : [];
    if (domains.length === 0) return badRequest(c, 'domains array required');
    if (domains.length > 100) return badRequest(c, 'max 100 domains per request');
    const mod = await loadTiMod();
    const results = await Promise.all(
      domains.map(async (domain) => {
        const r = await mod.checkDestroylistDomain(c.env.ASSETS, domain);
        return { domain, listed: r?.listed ?? null, matched: r?.matched ?? null };
      })
    );
    return c.json({
      checked: results.length,
      listedCount: results.filter((r) => r.listed).length,
      results,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_destroylist_bulk_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

/** Root-domain search over the primary rollup (prefix/substring match). */
threatIntelRouter.get('/threat-intel/destroylist/search', async (c) => {
  const q = (c.req.query('q') || '').trim().toLowerCase();
  if (q.length < 3) return badRequest(c, 'q must be at least 3 characters');
  const limitRaw = c.req.query('limit');
  const limit = limitRaw ? Math.min(500, Math.max(1, Number(limitRaw) || 50)) : 50;
  try {
    const mod = await loadTiMod();
    const roots = await mod.loadDestroylistRoots(c.env.ASSETS);
    if (!roots) return serviceUnavailable(c, 'destroylist manifest not built');
    const matches = roots.filter((d) => d.includes(q)).slice(0, limit);
    return c.json({
      query: q,
      total: matches.length,
      truncated: roots.filter((d) => d.includes(q)).length > matches.length,
      roots: matches,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_destroylist_search_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

/**
 * Plain-text root-domain list for DNS/firewall subscription (Pi-hole,
 * AdGuard Home, RPZ converters). Root domains only — per upstream guidance
 * that full lists carry hosting-platform subdomains unsuitable for
 * firewall rules. Cached at the edge for 6h.
 */
threatIntelRouter.get('/threat-intel/destroylist/roots.txt', async (c) => {
  try {
    const mod = await loadTiMod();
    const roots = await mod.loadDestroylistRoots(c.env.ASSETS);
    if (!roots) return serviceUnavailable(c, 'destroylist manifest not built');
    const idx = await mod.loadDestroylistIndex(c.env.ASSETS).catch(() => null);
    const body =
      `# destroylist primary root domains (${roots.length}) — github.com/phishdestroy/destroylist (MIT)\n` +
      `# synced ${idx?.syncedAt ?? 'unknown'}\n` +
      roots.join('\n') +
      '\n';
    return c.body(body, 200, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=21600',
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_destroylist_roots_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Living Threat Repository (living-threat.rabitanoor.com) ───────────
// Real-world incidents continuously mapped to MITRE ATT&CK tactics +
// techniques with per-kill-chain-stage detection/remediation notes
// (github.com/HudKSD/Living-Threat, MIT, keyless bootstrap API — newest
// 5000 incidents of ~21k). Data ships in public/data/threat-intel/
// living-threat/ (index + sharded bodies). Build: scripts/
// sync-living-threat.mjs && scripts/build-living-threat.mjs.

threatIntelRouter.get('/threat-intel/living-threat', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadLivingThreatIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      repoUrl: idx.repoUrl,
      description: idx.description,
      license: idx.license,
      syncedAt: idx.syncedAt,
      meta: idx.meta,
      counts: idx.counts,
      topTechniques: idx.topTechniques.slice(0, 60),
      topActors: idx.topActors.slice(0, 40),
      topTools: idx.topTools.slice(0, 40),
      topSources: idx.topSources.slice(0, 12),
      stats: mod.tiCacheStats().livingThreat,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_living_threat_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/living-threat/incidents', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadLivingThreatIndex(c.env.ASSETS);
    const tactic = c.req.query('tactic') || undefined;
    const technique = c.req.query('technique') || undefined;
    const severity = c.req.query('severity') || undefined;
    const actor = c.req.query('actor') || undefined;
    const keyword = c.req.query('q') || undefined;
    const minPriorityRaw = c.req.query('min_priority');
    const minPriority = minPriorityRaw ? Math.max(0, Math.min(100, Number(minPriorityRaw) || 0)) : undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(1000, Math.max(1, Number(limitRaw) || 100)) : undefined;
    const incidents = mod.filterLivingThreatIncidents(idx, {
      tactic,
      technique,
      severity,
      actor,
      keyword,
      minPriority,
      limit,
    });
    return c.json({
      total: idx.counts.incidents,
      returned: incidents.length,
      filters: { tactic, technique, severity, actor, keyword, min_priority: minPriority },
      incidents,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_living_threat_incidents_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/living-threat/incidents/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const body = await mod.getLivingThreatIncident(c.env.ASSETS, slug);
    if (!body) return notFound(c, `ti_living_threat_incident_not_found: ${slug}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_living_threat_incident_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── MalwareAnalyzer by Cyble (malwareanalyzer.com) ────────────────────
// Free, keyless public API: live malicious / newly-observed URL feeds
// (staged in public/data/threat-intel/malwareanalyzer/) + on-demand
// live reputation lookups (worker/lib/malwareanalyzer.ts).

threatIntelRouter.get('/threat-intel/malwareanalyzer', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadMaIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      apiBase: idx.apiBase,
      description: idx.description,
      license: idx.license,
      syncedAt: idx.syncedAt,
      counts: idx.counts,
      topApexes: idx.topApexes,
      stats: mod.tiCacheStats().malwareanalyzer,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_malwareanalyzer_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/malwareanalyzer/feed/:name', async (c) => {
  const name = c.req.param('name');
  if (name !== 'malicious' && name !== 'newly-observed') {
    return badRequest(c, `ti_malwareanalyzer_feed_invalid: ${name} (expected malicious | newly-observed)`);
  }
  try {
    const mod = await loadTiMod();
    await mod.loadMaIndex(c.env.ASSETS); // warm the LRU cache
    const verdict = c.req.query('verdict') || undefined;
    const category = c.req.query('category') || undefined;
    const keyword = c.req.query('q') || undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(200, Math.max(1, Number(limitRaw) || 200)) : undefined;
    const entries = await mod.getMaFeed(c.env.ASSETS, name);
    const out = mod.filterMaFeed(entries, { verdict, category, keyword, limit });
    return c.json({
      feed: name,
      total: entries.length,
      returned: out.length,
      filters: { verdict, category, keyword },
      entries: out,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_malwareanalyzer_feed_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/malwareanalyzer/lookup', async (c) => {
  const indicator = c.req.query('indicator');
  if (!indicator) return badRequest(c, 'ti_malwareanalyzer_lookup_missing_indicator');
  try {
    const result = await malwareAnalyzerLookup(indicator);
    if (!result.success && result.error) return badGateway(c, `ti_malwareanalyzer_lookup_failed: ${result.error}`);
    return c.json(result);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_malwareanalyzer_lookup_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── cve.now (cve.now — free public vulnerability feed) ─────────────────
// Deduplicated cross-source vulnerability feed (CVE List, NVD, CISA KEV,
// GitHub Advisories, OSV, EUVD, EPSS, Exploit-DB, Metasploit, Nuclei,
// PoC-in-GitHub) staged in public/data/threat-intel/cve-now/.

threatIntelRouter.get('/threat-intel/cve-now', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadCveNowIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      repoUrl: idx.repoUrl,
      description: idx.description,
      license: idx.license,
      syncedAt: idx.syncedAt,
      meta: idx.meta,
      counts: idx.counts,
      topProducts: idx.topProducts,
      sourcesHealth: idx.sourcesHealth,
      stats: mod.tiCacheStats().cveNow,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_cve_now_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/cve-now/entries', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadCveNowIndex(c.env.ASSETS);
    const severity = c.req.query('severity') || undefined;
    const product = c.req.query('product') || undefined;
    const keyword = c.req.query('q') || undefined;
    const kevParam = c.req.query('kev');
    const fixParam = c.req.query('has-fix');
    if (kevParam !== undefined && kevParam !== 'true' && kevParam !== 'false') {
      return badRequest(c, `ti_cve_now_kev_invalid: ${kevParam} (expected true | false)`);
    }
    if (fixParam !== undefined && fixParam !== 'true' && fixParam !== 'false') {
      return badRequest(c, `ti_cve_now_fix_invalid: ${fixParam} (expected true | false)`);
    }
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(240, Math.max(1, Number(limitRaw) || 100)) : undefined;
    const out = mod.filterCveNowEntries(idx, {
      severity,
      product,
      keyword,
      kev: kevParam === undefined ? undefined : kevParam === 'true',
      hasFix: fixParam === undefined ? undefined : fixParam === 'true',
      limit,
    });
    return c.json({
      source: idx.source,
      syncedAt: idx.syncedAt,
      total: idx.counts.entries,
      returned: out.length,
      filters: { severity, product, keyword, kev: kevParam, hasFix: fixParam },
      entries: out,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_cve_now_entries_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/cve-now/entries/:id', async (c) => {
  const assets = c.env.ASSETS;
  if (!assets) return internalError(c, 'ti_cve_now_no_assets');
  const id = c.req.param('id').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return badRequest(c, `ti_cve_now_id_invalid: ${id}`);
  try {
    const mod = await loadTiMod();
    const body = await mod.getCveNowEntry(assets, id);
    if (!body) return notFound(c, `ti_cve_now_entry_not_found: ${id}`);
    return c.json(body);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_cve_now_entry_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Incident Desk (iamnicholasmartin.co.uk/incidents) ──────────────────
// Identity-lens incident briefings from the public RSS feed, staged in
// public/data/threat-intel/incident-desk/.

threatIntelRouter.get('/threat-intel/incident-desk', async (c) => {
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadIncidentDeskIndex(c.env.ASSETS);
    const keyword = c.req.query('q') || undefined;
    const limitRaw = c.req.query('limit');
    const limit = limitRaw ? Math.min(50, Math.max(1, Number(limitRaw) || 50)) : undefined;
    const briefs = mod.filterIncidentDeskBriefs(idx, { keyword, limit });
    return c.json({
      source: idx.source,
      sourceUrl: idx.sourceUrl,
      description: idx.description,
      license: idx.license,
      syncedAt: idx.syncedAt,
      meta: idx.meta,
      counts: idx.counts,
      returned: briefs.length,
      briefs,
    });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_incident_desk_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

threatIntelRouter.get('/threat-intel/incident-desk/briefs/:slug', async (c) => {
  const slug = c.req.param('slug');
  try {
    const mod = await loadTiMod();
    const idx = await mod.loadIncidentDeskIndex(c.env.ASSETS);
    const brief = mod.getIncidentDeskBrief(idx, slug);
    if (!brief) return notFound(c, `ti_incident_desk_brief_not_found: ${slug}`);
    return c.json(brief);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `ti_incident_desk_brief_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

// ─── Live enrichment search routes ──────────────────────────────────────
const SEARCH_TIMEOUT_MS = 20_000;

threatIntelRouter.get('/threat-intel/search/otx', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'missing q parameter');
  const apiKey = c.env.OTX_API_KEY;
  if (!apiKey) return serviceUnavailable(c, 'OTX_API_KEY not configured');
  try {
    const res = await fetch(`https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(q)}&limit=20`, {
      headers: { 'X-OTX-API-KEY': apiKey, accept: 'application/json' },
      signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
    });
    if (!res.ok) return badGateway(c, `OTX returned ${res.status}`);
    const data = (await res.json()) as {
      results?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
        indicator_count: number;
        malware_families: unknown[];
        attack_ids: Array<{ display_name: string }>;
      }>;
    };
    const pulses = (data.results ?? []).map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description,
      tags: p.tags,
      indicator_count: p.indicator_count,
      malware_families: (p.malware_families ?? [])
        .map((m) => (typeof m === 'string' ? m : ((m as Record<string, string>)?.display_name ?? '')))
        .filter(Boolean),
      attack_ids: (p.attack_ids ?? []).map((a) => a.display_name ?? '').filter(Boolean),
    }));
    return c.json({ query: q, total: pulses.length, pulses });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
});

threatIntelRouter.get('/threat-intel/search/threatfox', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'missing q parameter');
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: q }),
      signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
    });
    if (!res.ok) return badGateway(c, `ThreatFox returned ${res.status}`);
    const data = (await res.json()) as {
      query_status: string;
      data?: Array<{
        ioc_type: string;
        ioc: string;
        malware_printable: string;
        confidence_level: number;
        first_seen: string;
        last_seen: string;
        tags: string[];
        reporter: string;
      }>;
    };
    if (data.query_status === 'no_data') return c.json({ query: q, total: 0, iocs: [] });
    if (data.query_status !== 'ok') return badGateway(c, `query_status: ${data.query_status}`);
    const iocs = (data.data ?? []).slice(0, 100).map((i) => ({
      ioc_type: i.ioc_type,
      ioc_value: i.ioc,
      malware: i.malware_printable,
      confidence: i.confidence_level != null ? i.confidence_level / 100 : 0,
      first_seen: i.first_seen,
      last_seen: i.last_seen,
      tags: i.tags,
      reporter: i.reporter,
    }));
    return c.json({ query: q, total: iocs.length, iocs });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
});

threatIntelRouter.get('/threat-intel/search/malwarebazaar', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'missing q parameter');
  try {
    let res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ query: 'get_taginfo', tag: q, limit: '50' }),
      signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
    });
    let data = (await res.json()) as {
      query_status: string;
      data?: Array<{ sha256_hash: string; file_name: string; signature: string; tags: string[]; first_seen: string }>;
    };
    let mode = 'tag';
    if (data.query_status === 'no_results' || !data.data?.length) {
      mode = 'signature';
      res = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ query: 'get_siginfo', signature: q, limit: '50' }),
        signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
      });
      data = (await res.json()) as typeof data;
    }
    if (data.query_status === 'no_results') return c.json({ query: q, search_mode: mode, total: 0, samples: [] });
    if (data.query_status !== 'ok') return badGateway(c, `query_status: ${data.query_status}`);
    const samples = (data.data ?? []).map((s) => ({
      sha256: s.sha256_hash,
      file_name: s.file_name,
      signature: s.signature,
      tags: s.tags,
      first_seen: s.first_seen,
    }));
    return c.json({ query: q, search_mode: mode, total: samples.length, samples });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
});

threatIntelRouter.get('/threat-intel/search/ransomware-live', async (c) => {
  const q = c.req.query('q');
  if (!q) return badRequest(c, 'missing q parameter');
  const headers = { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'application/json' };
  try {
    const groupsRes = await fetch('https://api.ransomware.live/v2/groups', {
      headers,
      signal: AbortSignal.timeout(15_000),
    });
    if (!groupsRes.ok) return badGateway(c, `ransomware.live returned ${groupsRes.status}`);
    const allGroups = (await groupsRes.json()) as Array<{ name: string }>;
    const matched = allGroups.filter((g) => (g.name ?? '').toLowerCase().includes(q.toLowerCase())).slice(0, 5);
    if (!matched.length) return c.json({ query: q, total: 0, groups: [] });
    const fetchDetail = async (name: string) => {
      try {
        const r = await fetch(`https://api.ransomware.live/v2/group/${encodeURIComponent(name)}`, {
          headers,
          signal: AbortSignal.timeout(10_000),
        });
        const text = await r.text();
        if (!text.trim().startsWith('{')) return null;
        const d = JSON.parse(text) as {
          name: string;
          description?: string;
          locations?: Array<{ fqdn?: string }>;
          ttps?: string[];
          tools?: string[];
          _victim_count?: number;
        };
        return {
          name: d.name ?? name,
          description: d.description ?? '',
          onion_urls: (d.locations ?? []).filter((l) => l.fqdn?.includes('.onion')).map((l) => l.fqdn!),
          ttps: d.ttps ?? [],
          tools: d.tools ?? [],
          victim_count: d._victim_count ?? 0,
        };
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return null;
      }
    };
    const details = (await Promise.all(matched.map((g) => fetchDetail(g.name)))).filter(Boolean);
    return c.json({ query: q, total: details.length, groups: details });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
});

// ── Entity relationship graph ──────────────────────────────────────────
import { registerEntityGraphRoute } from './entity-graph';
registerEntityGraphRoute(threatIntelRouter);

// ── STIX 2.1 export ────────────────────────────────────────────────────
//
// Bundles the replicated verticals (ThreatCluster entities + IOC
// blocklist, Daily-Hunt IOC families, darknet directory, Threaticon
// catalog) into a STIX 2.1 bundle with deterministic object ids.
// Built on the fly from env.ASSETS — no storage write, no external call.
//
//   GET /threat-intel/export/stix?include=entities,iocs&max=200
//   GET /threat-intel/export/stix?format=stix2.1&download=1

const STIX_SOURCE_IDS = ['entities', 'iocs', 'darknet', 'threaticon'] as const;

threatIntelRouter.get('/threat-intel/export/stix', async (c) => {
  try {
    const mod = await loadTiMod();
    const stix = await import('../lib/stix-export');

    const includeRaw = c.req.query('include');
    const include = includeRaw
      ? (includeRaw.split(',').filter((s) => (STIX_SOURCE_IDS as readonly string[]).includes(s)) as Array<
          (typeof STIX_SOURCE_IDS)[number]
        >)
      : undefined;
    const maxRaw = c.req.query('max');
    const max = maxRaw ? Math.min(2000, Math.max(1, Number(maxRaw) || 500)) : 500;

    const sources: {
      threatcluster?: {
        entities: Awaited<ReturnType<typeof mod.loadTcEntities>>;
        iocs: NonNullable<Awaited<ReturnType<typeof mod.loadTcIocs>>>['iocs'];
      };
      iocFamilies?: NonNullable<Awaited<ReturnType<typeof mod.getTiIoc>>>[];
      darknet?: NonNullable<Awaited<ReturnType<typeof mod.loadDarknetIndex>>>;
      threaticon?: Awaited<ReturnType<typeof mod.loadThreaticonIndex>>;
    } = {};

    if (!include || include.includes('entities') || include.includes('iocs')) {
      const tcIndex = await mod.loadTcEntities(c.env.ASSETS);
      const tcIocs = await mod.loadTcIocs(c.env.ASSETS);
      if (tcIocs) sources.threatcluster = { entities: tcIndex, iocs: tcIocs.iocs };
    }
    if (!include || include.includes('iocs')) {
      const tiIndex = await mod.loadTiIndex(c.env.ASSETS);
      const iocBodies: NonNullable<Awaited<ReturnType<typeof mod.getTiIoc>>>[] = [];
      const cap = Math.min(max, 25);
      for (const entry of tiIndex.iocIndex.slice(0, cap)) {
        const body = await mod.getTiIoc(c.env.ASSETS, entry.slug);
        if (body) iocBodies.push(body);
      }
      if (iocBodies.length > 0) sources.iocFamilies = iocBodies;
    }
    if (!include || include.includes('darknet')) {
      const dn = await mod.loadDarknetIndex(c.env.ASSETS);
      if (dn) sources.darknet = dn;
    }
    if (!include || include.includes('threaticon')) {
      const ti = await mod.loadThreaticonIndex(c.env.ASSETS);
      if (ti) sources.threaticon = ti;
    }

    const bundle = await stix.buildStixBundle(sources, { include, maxPerSource: max });
    const json = JSON.stringify(bundle, null, 2);
    if (c.req.query('download') === '1') {
      c.header('content-disposition', 'attachment; filename="threat-intel-bundle.json"');
    }
    return c.body(json, 200, { 'content-type': 'application/json; charset=utf-8' });
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, `stix_export_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});
