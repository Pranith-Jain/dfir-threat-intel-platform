/**
 * reference-manifests MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 *
 * All tools here read static JSON manifests through the ASSETS binding,
 * so the whole group stays unregistered when ASSETS is unbound — matching
 * the `if (h.env.ASSETS)` block this was extracted from.
 */

import { capecCacheStats, getCapec, listCapec, loadCapecIndex } from '../lib/capec-manifest';
import { carCacheStats, getCar, listCar, loadCarIndex } from '../lib/car-manifest';
import { engageCacheStats, getEngage, listEngage, loadEngageIndex } from '../lib/engage-manifest';
import { getHijacklib, hijacklibsCacheStats, listHijacklibs, loadHijacklibsIndex } from '../lib/hijacklibs-manifest';
import { getLots, listLots, loadLotsIndex, lotsCacheStats } from '../lib/lots-manifest';
import { getMalapi, listMalapi, loadMalapiIndex, malapiCacheStats } from '../lib/malapi-manifest';
import { getPortal, listPortals, loadOsintIndex, osintCacheStats } from '../lib/osint-manifest';
import type { OsintCategory } from '../lib/osint-manifest';
import { getVeris, listVeris, loadVerisIndex, verisCacheStats } from '../lib/veris-manifest';
import { untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import { campaignsCacheStats, getCampaign, listCampaigns, loadCampaignsIndex } from '../lib/campaigns-manifest';
import {
  ctiBookmarksCacheStats,
  getBookmark,
  listBookmarks,
  loadCtiBookmarksIndex,
} from '../lib/cti-bookmarks-manifest';
import { getReport, listReports, loadReportsIndex, reportsCacheStats } from '../lib/reports-manifest';
import type { CampaignCategory, CampaignStatus } from '../lib/campaigns-manifest';
import type { CtiBookmarkStatus } from '../lib/cti-bookmarks-manifest';
import type { ReportCategory } from '../lib/reports-manifest';
export function registerReferenceManifestsTools(h: McpToolHost): void {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── OSINT Portal Directory tools ──────────────────────────────
  // Curated directory of 40 OSINT portals and resources. Data ships
  // in public/data/osint/ built by scripts/build-osint-manifest.mjs.

  h.tools(
    'osint_list_portals',
    'List OSINT portals and resources from the curated directory. Filter by category (threat-intel, paste-monitoring, dark-web, reputation, certificate, dns, domain, ip, hash, email, username, social-media, phone, crypto, breach, whois, forensics, misc), keyword, or free/paid status.',
    {
      category: z.string().optional().describe('Filter by portal category'),
      keyword: z.string().optional().describe('Search keyword in name/description/tags'),
      freeOnly: z.boolean().optional().describe('Only free portals'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
    },
    async ({ category, keyword, freeOnly, limit }) => {
      const idx = await loadOsintIndex(ASSETS);
      const portals = listPortals(idx, {
        category: category as OsintCategory | undefined,
        keyword,
        freeOnly,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.count,
        returned: portals.length,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        portals,
      });
    }
  );

  h.tools(
    'osint_get_portal',
    'Return the full details of a single OSINT portal entry by slug. Use osint_list_portals first to discover slugs.',
    {
      slug: z
        .string()
        .describe('Portal slug, e.g. "virus-total", "shodan", "ahmia". Get these from osint_list_portals.'),
    },
    async ({ slug }) => {
      const idx = await loadOsintIndex(ASSETS);
      const portal = getPortal(idx, slug);
      if (!portal) {
        return untrustedToolResult({
          error: 'portal_not_found',
          slug,
          hint: 'Call osint_list_portals to see available slugs.',
        });
      }
      return untrustedToolResult(portal);
    }
  );

  h.tools(
    'osint_stats',
    'Return cache + manifest stats for the OSINT Portal Directory: total portals, indexed categories, and index cache status.',
    {},
    async () => {
      const idx = await loadOsintIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: osintCacheStats(),
      });
    }
  );

  // ── CTI Bookmarks tools ─────────────────────────────────────
  // 387 curated CTI links (Operational/Tactical/Strategic/Tools) from
  // Chick3nHawk01/Open_Source-CTI-Tooling. Each entry is tagged
  // live/reference/missing against this platform's integrations.
  // Data ships in public/data/cti-bookmarks/ built by
  // scripts/build-cti-bookmarks.mjs.

  h.tools(
    'cti_bookmarks_list',
    'List curated CTI bookmarks (threat intel links, tools, feeds, frameworks). Filter by level (Operational, Tactical, Strategic, Tools), category, integration status (live, reference, missing), or keyword.',
    {
      level: z.string().optional().describe('Filter by intel level: Operational, Tactical, Strategic, Tools'),
      category: z.string().optional().describe('Filter by category, e.g. "IoC Feeds & Sharing"'),
      status: z.enum(['live', 'reference', 'missing']).optional().describe('Filter by platform integration status'),
      keyword: z.string().optional().describe('Search keyword in name/description/host/tags'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ level, category, status, keyword, limit }) => {
      const idx = await loadCtiBookmarksIndex(ASSETS);
      const bookmarks = listBookmarks(idx, {
        level,
        category,
        status: status as CtiBookmarkStatus | undefined,
        keyword,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.count,
        returned: bookmarks.length,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        statusCounts: idx.statusCounts,
        bookmarks,
      });
    }
  );

  h.tools(
    'cti_bookmarks_get',
    'Return the full details of a single CTI bookmark by slug. Use cti_bookmarks_list first to discover slugs.',
    {
      slug: z
        .string()
        .describe('Bookmark slug, e.g. "threatfox", "lolbas", "malapi-io". Get these from cti_bookmarks_list.'),
    },
    async ({ slug }) => {
      const idx = await loadCtiBookmarksIndex(ASSETS);
      const bookmark = getBookmark(idx, slug);
      if (!bookmark) {
        return untrustedToolResult({
          error: 'bookmark_not_found',
          slug,
          hint: 'Call cti_bookmarks_list to see available slugs.',
        });
      }
      return untrustedToolResult(bookmark);
    }
  );

  h.tools(
    'cti_bookmarks_stats',
    'Return cache + manifest stats for the CTI Bookmarks directory: totals by level and integration status (live/reference/missing gap counts).',
    {},
    async () => {
      const idx = await loadCtiBookmarksIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        levels: idx.levels,
        categories: idx.categories,
        statusCounts: idx.statusCounts,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: ctiBookmarksCacheStats(),
      });
    }
  );

  // ── LOTS Project tools ──────────────────────────────────────
  // 175 trusted sites abusable for phishing/C2/exfil/download.
  // Data ships in public/data/lots/ built by
  // scripts/build-lots-manifest.mjs.

  h.tools(
    'lots_list',
    'List Living Off Trusted Sites (LOTS): legitimate domains attackers abuse for phishing, C2, exfiltration, or downloads. Filter by tag (Phishing, C&C, Download, Exfiltration), provider, or keyword.',
    {
      tag: z.string().optional().describe('Filter by abuse tag: Phishing, C&C, Download, Exfiltration'),
      provider: z.string().optional().describe('Filter by service provider, e.g. "Microsoft", "Google"'),
      keyword: z.string().optional().describe('Search keyword in website/provider/description'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ tag, provider, keyword, limit }) => {
      const idx = await loadLotsIndex(ASSETS);
      const sites = listLots(idx, { tag, provider, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: sites.length,
        tags: idx.tags,
        tagCounts: idx.tagCounts,
        sites,
      });
    }
  );

  h.tools(
    'lots_get',
    'Return the full details of a single LOTS site by slug, including abuse description. Use lots_list first to discover slugs.',
    {
      slug: z.string().describe('Site slug, e.g. "github-com", "discord-com". Get these from lots_list.'),
    },
    async ({ slug }) => {
      const idx = await loadLotsIndex(ASSETS);
      const site = getLots(idx, slug);
      if (!site) {
        return untrustedToolResult({
          error: 'lots_not_found',
          slug,
          hint: 'Call lots_list to see available slugs.',
        });
      }
      return untrustedToolResult(site);
    }
  );

  h.tools(
    'lots_stats',
    'Return cache + manifest stats for the LOTS directory: total sites and per-tag counts.',
    {},
    async () => {
      const idx = await loadLotsIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        tags: idx.tags,
        tagCounts: idx.tagCounts,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: lotsCacheStats(),
      });
    }
  );

  // ── MalAPI.io tools ─────────────────────────────────────────
  // 370 Windows APIs abused by attackers, with library, attack
  // categories, and MS docs links. Data ships in
  // public/data/malapi/ built by scripts/build-malapi-manifest.mjs.

  h.tools(
    'malapi_list',
    'List Windows APIs abused by attackers (MalAPI.io catalog). Filter by attack category (Enumeration, Injection, Evasion, Spying, Internet, Anti-Debugging, Ransomware, Helper), DLL library, or keyword.',
    {
      category: z.string().optional().describe('Filter by attack category, e.g. "Injection"'),
      library: z.string().optional().describe('Filter by DLL, e.g. "Kernel32.dll"'),
      keyword: z.string().optional().describe('Search keyword in name/description/attacks'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ category, library, keyword, limit }) => {
      const idx = await loadMalapiIndex(ASSETS);
      const apis = listMalapi(idx, { category, library, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: apis.length,
        categories: idx.categories,
        apis,
      });
    }
  );

  h.tools(
    'malapi_get',
    'Return the full details of a single Windows API by slug: description, library, attack categories, and Microsoft docs link. Use malapi_list first to discover slugs.',
    {
      slug: z.string().describe('API slug, e.g. "process32first", "createremotethread". Get these from malapi_list.'),
    },
    async ({ slug }) => {
      const idx = await loadMalapiIndex(ASSETS);
      const api = getMalapi(idx, slug);
      if (!api) {
        return untrustedToolResult({
          error: 'malapi_not_found',
          slug,
          hint: 'Call malapi_list to see available slugs.',
        });
      }
      return untrustedToolResult(api);
    }
  );

  h.tools(
    'malapi_stats',
    'Return cache + manifest stats for the MalAPI catalog: total APIs and attack categories.',
    {},
    async () => {
      const idx = await loadMalapiIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        categories: idx.categories,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: malapiCacheStats(),
      });
    }
  );

  // ── MITRE CAR tools ─────────────────────────────────────────
  // 102 cyber analytics with ATT&CK coverage + D3FEND mappings.
  // Data ships in public/data/car/ built by
  // scripts/build-car-manifest.mjs.

  h.tools(
    'car_list',
    'List MITRE Cyber Analytics Repository (CAR) analytics: validated detection ideas mapped to ATT&CK techniques. Filter by technique ID (e.g. "T1059"), platform, or keyword.',
    {
      technique: z.string().optional().describe('Filter by ATT&CK technique ID, e.g. "T1059", "T1547.001"'),
      platform: z.string().optional().describe('Filter by platform, e.g. "Windows", "Linux"'),
      keyword: z.string().optional().describe('Search keyword in title/description/techniques'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ technique, platform, keyword, limit }) => {
      const idx = await loadCarIndex(ASSETS);
      const analytics = listCar(idx, { technique, platform, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: analytics.length,
        techniqueCount: idx.techniqueCount,
        analytics,
      });
    }
  );

  h.tools(
    'car_get',
    'Return the full details of a single CAR analytic by slug: ATT&CK coverage, D3FEND mappings, and implementation names. Use car_list first to discover slugs.',
    {
      slug: z.string().describe('Analytic slug, e.g. "car-2013-01-002". Get these from car_list.'),
    },
    async ({ slug }) => {
      const idx = await loadCarIndex(ASSETS);
      const analytic = getCar(idx, slug);
      if (!analytic) {
        return untrustedToolResult({
          error: 'car_not_found',
          slug,
          hint: 'Call car_list to see available slugs.',
        });
      }
      return untrustedToolResult(analytic);
    }
  );

  h.tools(
    'car_stats',
    'Return cache + manifest stats for the CAR directory: total analytics and covered technique count.',
    {},
    async () => {
      const idx = await loadCarIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        techniqueCount: idx.techniqueCount,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: carCacheStats(),
      });
    }
  );

  // ── MITRE CAPEC tools ───────────────────────────────────────
  // 615 attack patterns with CWE/ATT&CK cross-references.
  // Data ships in public/data/capec/ built by
  // scripts/build-capec-manifest.mjs.

  h.tools(
    'capec_list',
    'List MITRE CAPEC attack patterns: how adversaries exploit weaknesses, with CWE and ATT&CK links. Filter by abstraction (Meta, Standard, Detailed), status, domain, CWE ID, technique ID, or keyword.',
    {
      abstraction: z.string().optional().describe('Filter by abstraction: Meta, Standard, Detailed'),
      status: z.string().optional().describe('Filter by status: Stable, Draft, Deprecated'),
      domain: z.string().optional().describe('Filter by domain, e.g. "Software", "Hardware"'),
      cwe: z.string().optional().describe('Filter by CWE ID, e.g. "CWE-79"'),
      technique: z.string().optional().describe('Filter by ATT&CK technique ID, e.g. "T1498"'),
      keyword: z.string().optional().describe('Search keyword in name/description/CWE'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ abstraction, status, domain, cwe, technique, keyword, limit }) => {
      const idx = await loadCapecIndex(ASSETS);
      const patterns = listCapec(idx, { abstraction, status, domain, cwe, technique, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: patterns.length,
        byAbstraction: idx.byAbstraction,
        byStatus: idx.byStatus,
        patterns,
      });
    }
  );

  h.tools(
    'capec_get',
    'Return the full details of a single CAPEC attack pattern by slug: abstraction, likelihood, severity, prerequisites, CWE/ATT&CK links. Use capec_list first to discover slugs.',
    {
      slug: z.string().describe('Pattern slug, e.g. "capec-87", "capec-125". Get these from capec_list.'),
    },
    async ({ slug }) => {
      const idx = await loadCapecIndex(ASSETS);
      const pattern = getCapec(idx, slug);
      if (!pattern) {
        return untrustedToolResult({
          error: 'capec_not_found',
          slug,
          hint: 'Call capec_list to see available slugs.',
        });
      }
      return untrustedToolResult(pattern);
    }
  );

  h.tools(
    'capec_stats',
    'Return cache + manifest stats for the CAPEC directory: totals by abstraction and status.',
    {},
    async () => {
      const idx = await loadCapecIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        byAbstraction: idx.byAbstraction,
        byStatus: idx.byStatus,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: capecCacheStats(),
      });
    }
  );

  // ── HijackLibs tools ────────────────────────────────────────
  // 608 DLL hijacking candidates with vulnerable executables.
  // Data ships in public/data/hijacklibs/ built by
  // scripts/build-hijacklibs-manifest.mjs.

  h.tools(
    'hijacklibs_list',
    'List HijackLibs DLL hijacking candidates: DLLs abusable for sideloading/phantom/search-order/environment-variable hijacking (T1574.001). Filter by hijack type, vendor, CVE presence, or keyword.',
    {
      type: z
        .string()
        .optional()
        .describe('Filter by hijack type: Sideloading, Phantom, Search Order, Environment Variable'),
      vendor: z.string().optional().describe('Filter by DLL vendor'),
      cveOnly: z.boolean().optional().describe('Only entries with a known CVE'),
      keyword: z.string().optional().describe('Search keyword in DLL name/vendor/description'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ type, vendor, cveOnly, keyword, limit }) => {
      const idx = await loadHijacklibsIndex(ASSETS);
      const dlls = listHijacklibs(idx, { type, vendor, cveOnly, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: dlls.length,
        hijackTypes: idx.hijackTypes,
        typeCounts: idx.typeCounts,
        dlls,
      });
    }
  );

  h.tools(
    'hijacklibs_get',
    'Return the full details of a single HijackLibs DLL by slug: vulnerable executables, expected locations, CVE. Use hijacklibs_list first to discover slugs.',
    {
      slug: z.string().describe('DLL slug, e.g. "version-dll". Get these from hijacklibs_list.'),
    },
    async ({ slug }) => {
      const idx = await loadHijacklibsIndex(ASSETS);
      const dll = getHijacklib(idx, slug);
      if (!dll) {
        return untrustedToolResult({
          error: 'hijacklib_not_found',
          slug,
          hint: 'Call hijacklibs_list to see available slugs.',
        });
      }
      return untrustedToolResult(dll);
    }
  );

  h.tools(
    'hijacklibs_stats',
    'Return cache + manifest stats for the HijackLibs directory: totals by hijack type and CVE count.',
    {},
    async () => {
      const idx = await loadHijacklibsIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        hijackTypes: idx.hijackTypes,
        typeCounts: idx.typeCounts,
        withCve: idx.withCve,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: hijacklibsCacheStats(),
      });
    }
  );

  // ── VERIS Framework tools ───────────────────────────────────
  // 68 incident-taxonomy fields (Actor/Action/Asset/Attribute + more).
  // Data ships in public/data/veris/ built by
  // scripts/build-veris-manifest.mjs.

  h.tools(
    'veris_list_fields',
    'List VERIS incident-taxonomy fields: the standard vocabulary for describing who did what to which asset with what result (actor.external.motive, action.hacking.variety, asset.assets.variety…). Filter by section (action, actor, asset, attribute, victim, impact, timeline, discovery_method, …) or keyword.',
    {
      section: z.string().optional().describe('Filter by taxonomy section, e.g. "action", "actor", "asset"'),
      keyword: z.string().optional().describe('Search keyword in path/values/labels'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ section, keyword, limit }) => {
      const idx = await loadVerisIndex(ASSETS);
      const fields = listVeris(idx, { section, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: fields.length,
        sections: idx.sections,
        fields,
      });
    }
  );

  h.tools(
    'veris_get_field',
    'Return the full enumerated values + human labels for a single VERIS taxonomy field. Use veris_list_fields first to discover slugs.',
    {
      slug: z.string().describe('Field slug, e.g. "action-hacking-variety". Get these from veris_list_fields.'),
    },
    async ({ slug }) => {
      const idx = await loadVerisIndex(ASSETS);
      const field = getVeris(idx, slug);
      if (!field) {
        return untrustedToolResult({
          error: 'veris_not_found',
          slug,
          hint: 'Call veris_list_fields to see available slugs.',
        });
      }
      return untrustedToolResult(field);
    }
  );

  h.tools(
    'veris_stats',
    'Return cache + manifest stats for the VERIS taxonomy: field counts by section.',
    {},
    async () => {
      const idx = await loadVerisIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        sections: idx.sections,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: verisCacheStats(),
      });
    }
  );

  // ── MITRE Engage tools ──────────────────────────────────────
  // 53 adversary-engagement approaches across 9 goals.
  // Data ships in public/data/engage/ built by
  // scripts/build-engage-manifest.mjs.

  h.tools(
    'engage_list',
    'List MITRE Engage adversary-engagement approaches: deception/denial techniques organized by goal (Collect, Detect, Prevent, Direct, Disrupt, Reassure, Motivate, Elicit…) and phase (Prepare, Engage, Understand). Filter by goal, phase, or keyword.',
    {
      goal: z.string().optional().describe('Filter by goal, e.g. "Collect", "Disrupt", "Elicit"'),
      phase: z.string().optional().describe('Filter by phase: Prepare, Engage, Understand'),
      keyword: z.string().optional().describe('Search keyword in name/goal/phase'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ goal, phase, keyword, limit }) => {
      const idx = await loadEngageIndex(ASSETS);
      const approaches = listEngage(idx, { goal, phase, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.count,
        returned: approaches.length,
        phases: idx.phases,
        goals: idx.goals,
        approaches,
      });
    }
  );

  h.tools(
    'engage_get',
    'Return the details of a single Engage approach by slug: goal, phase, and matrix link. Use engage_list first to discover slugs.',
    {
      slug: z.string().describe('Approach slug, e.g. "lures", "personas". Get these from engage_list.'),
    },
    async ({ slug }) => {
      const idx = await loadEngageIndex(ASSETS);
      const approach = getEngage(idx, slug);
      if (!approach) {
        return untrustedToolResult({
          error: 'engage_not_found',
          slug,
          hint: 'Call engage_list to see available slugs.',
        });
      }
      return untrustedToolResult(approach);
    }
  );

  h.tools(
    'engage_stats',
    'Return cache + manifest stats for the Engage matrix: phases, goals, approach count.',
    {},
    async () => {
      const idx = await loadEngageIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        phases: idx.phases,
        goals: idx.goals,
        source: idx.source,
        replicatedAt: idx.replicatedAt,
        cache: engageCacheStats(),
      });
    }
  );

  // ── Active Campaigns tools ──────────────────────────────────
  // Curated directory of currently active threat campaigns. Data
  // ships in public/data/campaigns/ built by scripts/build-campaigns-manifest.mjs.

  h.tools(
    'campaigns_list',
    'List currently active threat campaigns from the curated tracker. Filter by status (active, dormant, concluded), category (ransomware, apt, malware, phishing, c2, supply-chain, cyber-espionage, hacktivism, other), or keyword.',
    {
      status: z.string().optional().describe('Filter by campaign status: active, dormant, concluded'),
      category: z.string().optional().describe('Filter by campaign category'),
      keyword: z.string().optional().describe('Search keyword in name/description/tags'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
    },
    async ({ status, category, keyword, limit }) => {
      const idx = await loadCampaignsIndex(ASSETS);
      const campaigns = listCampaigns(idx, {
        status: status as CampaignStatus | undefined,
        category: category as CampaignCategory | undefined,
        keyword,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.count,
        returned: campaigns.length,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        campaigns,
      });
    }
  );

  h.tools(
    'campaigns_get',
    'Return the full details of a single threat campaign entry by slug, including writeup links, TTPs, targets, and geography. Use campaigns_list first to discover slugs.',
    {
      slug: z
        .string()
        .describe('Campaign slug, e.g. "lockbit-4-0", "clop", "solarwinds". Get these from campaigns_list.'),
    },
    async ({ slug }) => {
      const idx = await loadCampaignsIndex(ASSETS);
      const campaign = getCampaign(idx, slug);
      if (!campaign) {
        return untrustedToolResult({
          error: 'campaign_not_found',
          slug,
          hint: 'Call campaigns_list to see available slugs.',
        });
      }
      return untrustedToolResult(campaign);
    }
  );

  h.tools(
    'campaigns_stats',
    'Return cache + manifest stats for the Active Campaigns tracker: total campaigns, active vs dormant/concluded breakdown, categories, and index cache status.',
    {},
    async () => {
      const idx = await loadCampaignsIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: campaignsCacheStats(),
      });
    }
  );

  // ── Reports & Reading Library tools ──────────────────────────
  // Curated directory of 28 security reports, frameworks, standards,
  // and learning resources. Data ships in public/data/reports/ built
  // by scripts/build-reports-manifest.mjs.

  h.tools(
    'reports_list',
    'List reports and reading resources from the curated library. Filter by category (annual-threat-report, reference, framework, standard, learning, whitepaper, research), keyword, year, or publisher.',
    {
      category: z.string().optional().describe('Filter by report category'),
      keyword: z.string().optional().describe('Search keyword in title/description/tags'),
      year: z.number().int().optional().describe('Filter by publication year'),
      publisher: z.string().optional().describe('Filter by publisher name (substring match)'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
    },
    async ({ category, keyword, year, publisher, limit }) => {
      const idx = await loadReportsIndex(ASSETS);
      const reports = listReports(idx, {
        category: category as ReportCategory | undefined,
        keyword,
        year,
        publisher,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.count,
        returned: reports.length,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        reports,
      });
    }
  );

  h.tools(
    'reports_get',
    'Return the full details of a single report entry by slug. Use reports_list first to discover slugs.',
    {
      slug: z
        .string()
        .describe(
          'Report slug, e.g. "crowdstrike-global-threat-report-2025", "mitre-attack-framework". Get these from reports_list.'
        ),
    },
    async ({ slug }) => {
      const idx = await loadReportsIndex(ASSETS);
      const report = getReport(idx, slug);
      if (!report) {
        return untrustedToolResult({
          error: 'report_not_found',
          slug,
          hint: 'Call reports_list to see available slugs.',
        });
      }
      return untrustedToolResult(report);
    }
  );

  h.tools(
    'reports_stats',
    'Return cache + manifest stats for the Reports & Reading Library: total entries, categories, and index cache status.',
    {},
    async () => {
      const idx = await loadReportsIndex(ASSETS);
      return untrustedToolResult({
        count: idx.count,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: reportsCacheStats(),
      });
    }
  );
}
