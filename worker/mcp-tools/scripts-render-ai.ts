/**
 * scripts-render-ai MCP tool registrations.
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

import { getScript, loadScriptsIndex } from '../lib/si-manifest';
import { heatwaveLookup, heatwaveVerdict, normalizeHeatwaveDomain } from '../lib/heatwave';
import { isValidChannelHandle, tgLiveSearch } from '../lib/tg-live-search';
import { renderDashboard } from '../lib/si-svg-renderer';
import type { RenderManifest } from '../lib/si-svg-renderer';
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
  escapeCacheStats,
  escapeTimelineBuckets,
  filterEscapes,
  getEscapeIncident,
  loadEscapeGuardrails,
  loadEscapeIndex,
  loadEscapeTrackers,
} from '../lib/ai-escape-manifest';
import { aiThreatsCacheStats, filterThreats, getAiThreat, loadAiThreatsIndex } from '../lib/ai-threats-manifest';
import { filterFeeds, getOssFeedsByCategory, loadOssFeedsIndex, ossFeedsCacheStats } from '../lib/oss-feeds-manifest';
import {
  filterRansomwareGroups,
  getRansomwareGroup,
  loadRansomwareGroupsIndex,
} from '../lib/ransomware-groups-manifest';
import { errMessage } from '../lib/err';
export function registerScriptsRenderAiTools(h: McpToolHost): void {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── PowerShell + detection-manifest scripts (round 3) ──────
  h.tools(
    'si_list_scripts',
    'List the detection-manifest assets that ship in the SI bundle: example-detection-manifest.json (input template), sentinel-chokepoint-rules.json (detection rules), sentinel-ingestion-drilldown.md (companion guide).',
    {},
    async () => {
      const idx = await loadScriptsIndex(ASSETS);
      return untrustedToolResult(idx);
    }
  );

  h.tools(
    'si_get_script',
    'Return the raw body of a detection-manifest asset. Use si_list_scripts to discover filenames.',
    {
      name: z
        .string()
        .describe(
          'Asset filename, e.g. "example-detection-manifest.json", "sentinel-chokepoint-rules.json", "sentinel-ingestion-drilldown.md".'
        ),
    },
    async ({ name }) => {
      const body = await getScript(ASSETS, name);
      if (!body) {
        return untrustedToolResult({
          error: 'script_not_found',
          name,
          hint: 'Call si_list_scripts to see available filenames.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── Server-side SVG rendering (round 3, E) ────────────────────
  // Renders the manifest to a self-contained <svg> string. Supports
  // 6 widget types (title-banner, kpi-card, score-card, donut-chart,
  // stacked-bar-chart, table-widget); unsupported widgets fall back
  // to a dashed "use si_render_svg_dashboard" stub so the layout
  // still renders.
  h.tools(
    'si_render_svg',
    'Render an SVG dashboard from a manifest + data. Returns a self-contained <svg> string with inline styles, no external dependencies. Use si_render_svg_dashboard(slug) to get the canonical manifest for a skill, then pass its body as manifestYaml here. Supports all 14 widget types: title-banner, kpi-card, delta-kpi-card, score-card, donut-chart, stacked-bar-chart, horizontal-bar-chart, line-chart, waterfall-chart, sparkline, progress-bar, table-widget, recommendation-cards, assessment-banner, coverage-matrix. Unknown types render as a dashed warning panel.',
    {
      manifest_yaml: z
        .string()
        .describe('YAML manifest body. Pull from si_render_svg_dashboard(slug).manifestYaml, or write your own.'),
      data_json: z
        .string()
        .optional()
        .describe(
          'Optional JSON string mapping widget-name → data object. The renderer merges per-widget data with the global map.'
        ),
    },
    async ({ manifest_yaml, data_json }) => {
      // The Worker has no YAML parser. We expect callers to send the
      // manifest as a parsed JS object via JSON; if it looks like
      // YAML text, we surface a clear error.
      if (
        manifest_yaml.trim().startsWith('canvas:') ||
        manifest_yaml.trim().startsWith('palette:') ||
        manifest_yaml.trim().startsWith('widgets:')
      ) {
        return untrustedToolResult({
          error: 'yaml_not_supported',
          hint: 'The Worker has no YAML parser. Send the manifest as JSON via the si_render_svg JSON arg, or use the HTTP /api/v1/si/render route which accepts YAML and parses it with the lighter approach (each top-level field on its own line).',
        });
      }
      let manifest: RenderManifest;
      try {
        manifest = JSON.parse(manifest_yaml);
      } catch (e) {
        console.error('handler failed:', errMessage(e));
        return untrustedToolResult({
          error: 'parse_failed',
          message: errMessage(e),
          hint: 'manifest_yaml must be a JSON-encoded RenderManifest object.',
        });
      }
      let data: Record<string, unknown> = {};
      if (data_json) {
        try {
          data = JSON.parse(data_json);
        } catch (e) {
          console.error('handler failed:', errMessage(e));
          return untrustedToolResult({
            error: 'data_parse_failed',
            message: errMessage(e),
          });
        }
      }
      try {
        const svg = renderDashboard(manifest, data);
        return untrustedToolResult({ svg, bytes: svg.length, widgetCount: (manifest.widgets ?? []).length });
      } catch (e) {
        console.error('handler failed:', errMessage(e));
        return untrustedToolResult({ error: 'render_failed', message: errMessage(e) });
      }
    }
  );

  // Renders the same manifest to a PNG byte array via @resvg/resvg-wasm.
  // Useful when the LLM client wants to drop the dashboard into a
  // markdown image, email, or social-preview that can't render SVG.
  // The response is a base64-encoded PNG (MCP text fields can't carry
  // raw binary) with {bytes, width, hash} metadata.
  h.tools(
    'si_render_png',
    'Render an SVG dashboard and rasterise it to PNG (base64-encoded in the JSON response). Same manifest + data shape as si_render_svg, but the output is a portable bitmap you can embed in markdown, email, or social previews. Uses the bundled @resvg/resvg-wasm + Hanken Grotesk TTF.',
    {
      manifest_json: z
        .string()
        .describe(
          'JSON-encoded RenderManifest object. Same shape as si_render_svg(manifest_yaml=JSON.stringify(manifest)).'
        ),
      data_json: z.string().optional().describe('Optional JSON string mapping widget-name → data object.'),
      width: z
        .number()
        .int()
        .min(400)
        .max(2800)
        .optional()
        .describe(
          'Output width in CSS pixels (default 1400). Height is derived from the manifest canvas aspect ratio.'
        ),
    },
    async ({ manifest_json, data_json, width }) => {
      let manifest: RenderManifest;
      let data: Record<string, unknown> = {};
      try {
        manifest = JSON.parse(manifest_json);
      } catch (e) {
        console.error('handler failed:', errMessage(e));
        return untrustedToolResult({ error: 'parse_failed', message: errMessage(e) });
      }
      if (data_json) {
        try {
          data = JSON.parse(data_json);
        } catch (e) {
          console.error('handler failed:', errMessage(e));
          return untrustedToolResult({
            error: 'data_parse_failed',
            message: errMessage(e),
          });
        }
      }
      try {
        const svg = renderDashboard(manifest, data);
        const { svgDashboardToPng } = await import('../lib/si-svg-png');
        const png = await svgDashboardToPng(h.env as unknown as import('../env').Env, svg, {
          width: width ?? 1400,
        });
        // MCP text fields are strings — return the PNG base64-encoded.
        // Encode in chunks: `btoa(String.fromCharCode(...png))` spreads the
        // entire byte array as function arguments, which throws RangeError
        // (Maximum call stack size exceeded) on multi-MB PNGs.
        let binary = '';
        const CHUNK = 0x8000; // 32 KB per slice
        for (let i = 0; i < png.length; i += CHUNK) {
          binary += String.fromCharCode(...png.subarray(i, i + CHUNK));
        }
        const b64 = btoa(binary);
        return untrustedToolResult({
          png_base64: b64,
          bytes: png.length,
          width: width ?? 1400,
          svg_bytes: svg.length,
          hint: 'Decode png_base64 (standard base64) and write to a .png file. The bytes are a valid PNG (IHDR / IDAT / IEND chunks).',
        });
      } catch (e) {
        console.error('arguments failed:', errMessage(e));
        return untrustedToolResult({
          error: 'png_render_failed',
          message: errMessage(e),
        });
      }
    }
  );

  // ── AI Threat Actors: Cybershujin tracker ──────────────────────────
  h.tools(
    'ai_threats_list',
    'List AI-capable threat actors from the Cybershujin tracker (79 entries, MIT). Each entry documents real-world confirmed use of AI/LLMs by threat actors. Filter by table (main/deepfake), category, TTP, or keyword.',
    {
      table: z.enum(['main', 'deepfake']).optional().describe('Filter by tracker table'),
      category: z.string().optional().describe('Filter by AI-use category (e.g. "LLM-enhanced scripting techniques")'),
      ttp: z.string().optional().describe('Filter by MITRE ATT&CK TTP ID (e.g. "T1588")'),
      keyword: z.string().optional().describe('Case-insensitive search across name, aliases, brief, TTPs, categories'),
      limit: z.number().int().min(1).max(200).optional().describe('Max entries to return (default 79)'),
    },
    async ({ table, category, ttp, keyword, limit }) => {
      const idx = await loadAiThreatsIndex(ASSETS);
      const entries = filterThreats(idx, {
        table,
        category,
        ttp,
        keyword,
        limit: limit ?? 200,
      });
      return untrustedToolResult({
        total: idx.counts.total,
        returned: entries.length,
        lastSyncedAt: idx.lastSyncedAt,
        entries,
      });
    }
  );

  h.tools(
    'ai_threats_get',
    'Return the full entry body for an AI-capable threat actor — includes full brief, aliases, raw TTP markdown, reported/activity dates, and MITRE technique IDs. Use ai_threats_list first to discover slugs.',
    {
      slug: z.string().describe('Entry slug, e.g. "fancy-bear". Get these from ai_threats_list.'),
    },
    async ({ slug }) => {
      const body = await getAiThreat(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'entry_not_found',
          slug,
          hint: 'Call ai_threats_list to see available entries.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'ai_threats_stats',
    'Return cache + manifest stats for the AI Threat Actors data: total entries, index load state, body-cache hit ratios.',
    {},
    async () => {
      const idx = await loadAiThreatsIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        lastSyncedAt: idx.lastSyncedAt,
        cache: aiThreatsCacheStats(),
      });
    }
  );

  // ── Ransomware Groups directory (620 leak sites) ──────────────────
  h.tools(
    'ransom_groups_list',
    'List ransomware leak-site groups from the directory (620 groups, Ransomlook + ransomware.live). Filter by keyword, leak-site status (online/offline/unknown), active-this-week, or profile presence. Sort by recent activity, victim count, or name.',
    {
      q: z.string().optional().describe('Keyword across slug, name, blurb'),
      status: z
        .enum(['online', 'offline', 'unknown'])
        .optional()
        .describe('Leak-site reachability at last probe (unknown = never enriched)'),
      activeWeek: z.boolean().optional().describe('Only groups with victims in the last 7 days'),
      hasProfile: z.boolean().optional().describe('Only groups with an enriched profile'),
      sort: z.enum(['recent', 'victims', 'name']).optional().describe('Sort order (default recent)'),
      limit: z.number().int().min(1).max(620).optional().describe('Max groups (default 100)'),
    },
    async ({ q, status, activeWeek, hasProfile, sort, limit }) => {
      const idx = await loadRansomwareGroupsIndex(ASSETS);
      const groups = filterRansomwareGroups(idx, { q, status, activeWeek, hasProfile, sort, limit: limit ?? 100 });
      return untrustedToolResult({ total: idx.counts.groups, counts: idx.counts, returned: groups.length, groups });
    }
  );

  h.tools(
    'ransom_group_get',
    'Return one ransomware group: victim counts, last seen, leak-site mirrors (.onion needs Tor), victim sample, abridged profile meta. Use ransom_groups_list first to discover slugs.',
    {
      slug: z.string().describe('Group slug, e.g. "akira", "clop", "qilin". Get these from ransom_groups_list.'),
    },
    async ({ slug }) => {
      const body = await getRansomwareGroup(ASSETS, slug.toLowerCase());
      if (!body) {
        return untrustedToolResult({
          error: 'group_not_found',
          slug,
          hint: 'Call ransom_groups_list to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  // ── AI Escape Watch (agent containment-failure registry) ──────────
  h.tools(
    'escape_list',
    'List AI agent containment-failure incidents (15-entry seed registry, CBS-scored). Filter by class (containment-breach/agent-hijack/supply-chain/tool-misuse/injection), severity, evidence tier, absent guardrail, autonomy, or keyword.',
    {
      klass: z
        .enum(['containment-breach', 'agent-hijack', 'supply-chain', 'tool-misuse', 'injection'])
        .optional()
        .describe('Failure class'),
      sev: z.enum(['critical', 'severe', 'notable', 'contained']).optional().describe('Severity'),
      tier: z.enum(['A', 'B', 'C', 'D', 'X']).optional().describe('Evidence tier'),
      guardrail: z
        .string()
        .optional()
        .describe('Absent guardrail, e.g. EGRESS, TELEMETRY, OBJECTIVE (see escape_stats)'),
      autonomous: z.boolean().optional().describe('Only autonomous boundary crossings'),
      q: z.string().optional().describe('Keyword across id, title, developer, assigned task'),
      limit: z.number().int().min(1).max(100).optional().describe('Max incidents (default 100)'),
    },
    async ({ klass, sev, tier, guardrail, autonomous, q, limit }) => {
      const idx = await loadEscapeIndex(ASSETS);
      const incidents = filterEscapes(idx, { klass, sev, tier, guardrail, autonomous, q, limit: limit ?? 100 });
      return untrustedToolResult({
        total: idx.stats.entries,
        stats: idx.stats,
        returned: incidents.length,
        incidents,
      });
    }
  );

  h.tools(
    'escape_get',
    'Return one incident docket: assigned task, summary, 7-stage containment chain, absent guardrails, disputed figures, sources. Use escape_list first to discover ids.',
    {
      id: z.string().describe('Incident id, e.g. "CB-2026-0010". Get these from escape_list.'),
    },
    async ({ id }) => {
      const body = await getEscapeIncident(ASSETS, id.toUpperCase());
      if (!body) {
        return untrustedToolResult({
          error: 'incident_not_found',
          id,
          hint: 'Call escape_list to see available ids.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'escape_stats',
    'Registry stats (entries, Tier A, eval-env breaches, autonomous count, median dwell, most-absent guardrail, days-since clock inputs), per-guardrail absent counts, month timeline buckets, and the 10 guardrail definitions + provenance trackers.',
    {},
    async () => {
      const idx = await loadEscapeIndex(ASSETS);
      const [guardrails, trackers] = await Promise.all([loadEscapeGuardrails(ASSETS), loadEscapeTrackers(ASSETS)]);
      return untrustedToolResult({
        stats: idx.stats,
        guardrailCounts: idx.guardrailCounts,
        timeline: escapeTimelineBuckets(idx),
        guardrails,
        trackers,
        cache: escapeCacheStats(),
      });
    }
  );

  // ── Heatwave sender-domain blocklist + live TG search ─────────────
  h.tools(
    'heatwave_lookup',
    'Check a SENDING domain against the Validity Heatwave cold-email blocklist (keyless). Returns listed status (warming/active/pre-warming), stage, relative score band, observation ages, DNS answer, and related listed domains. Warming ≠ phishing; not-listed ≠ clean. Never apply to URL/content/DKIM verdicts.',
    {
      domain: z.string().describe('Bare sending domain, e.g. "example.com" (no URLs, emails, or IPs)'),
    },
    async ({ domain }) => {
      const clean = normalizeHeatwaveDomain(domain);
      if (!clean) {
        return untrustedToolResult({ error: 'invalid_domain', domain, hint: 'Bare sending domain only.' });
      }
      const result = await heatwaveLookup(clean);
      if (!result) {
        return untrustedToolResult({ error: 'lookup_unavailable', domain: clean });
      }
      const v = heatwaveVerdict(result);
      return untrustedToolResult({
        ...result,
        verdict: v.verdict,
        score: v.score,
        tags: v.tags,
        source_url: `https://lookup.validity.tools/?domain=${encodeURIComponent(clean)}`,
      });
    }
  );

  h.tools(
    'tg_live_search',
    'Keyword-search public Telegram channels LIVE (t.me/s previews matched in memory, nothing stored). AND-semantics across tokens. Returns snippets + permalinks + per-channel diagnostics. Sequential fetches; keep to ≤8 channels.',
    {
      q: z.string().describe('Keywords, e.g. "CVE-2026-1234 rce" or "LockBit victim"'),
      channels: z
        .string()
        .optional()
        .describe(
          'Comma-separated handles (default: CVE/breach batch: CVEDetector, CyberMonitum, DWI_CVE_Alerts, FBI_Watchdog, DarkfeedNews, brutsecurity, IntCyberDigest, ctiwatch). Max 8.'
        ),
      maxResults: z.number().int().min(1).max(50).optional().describe('Max hits (default 50)'),
    },
    async ({ q, channels, maxResults }) => {
      const list = (
        channels
          ? channels.split(',')
          : [
              'CVEDetector',
              'CyberMonitum',
              'DWI_CVE_Alerts',
              'FBI_Watchdog',
              'DarkfeedNews',
              'brutsecurity',
              'IntCyberDigest',
              'ctiwatch',
            ]
      )
        .map((handle) => handle.trim())
        .filter(Boolean)
        .slice(0, 8);
      if (!q || !q.trim() || list.length === 0) {
        return untrustedToolResult({ error: 'invalid_query', hint: 'Provide q and 1-8 channel handles.' });
      }
      for (const h of list) {
        if (!isValidChannelHandle(h)) {
          return untrustedToolResult({ error: 'invalid_handle', handle: h });
        }
      }
      return untrustedToolResult(await tgLiveSearch(q, list, { maxResults: maxResults ?? 50 }));
    }
  );

  // ── OSS Feed Registry: Bert-JanP feed catalog ──────────────────
  h.tools(
    'oss_feeds_list',
    'List open-source threat intel feeds from the curated catalog (145+ feeds, BSD-3-Clause). Filter by vendor, category, status, or keyword. Each entry shows vendor, description, category, and feed status.',
    {
      vendor: z.string().optional().describe('Filter by vendor name (case-insensitive substring)'),
      category: z
        .string()
        .optional()
        .describe('Filter by IOC type: IP, DNS, URL, MD5, SHA1, SHA256, CVEID, SSL, JA3, NamePipe, RANSOMWARELEAK'),
      status: z.string().optional().describe('Filter by feed status: Active or Offline'),
      keyword: z.string().optional().describe('Case-insensitive search across vendor, description, category'),
      limit: z.number().int().min(1).max(200).optional().describe('Max feeds to return (default 145)'),
    },
    async ({ vendor, category, status, keyword, limit }) => {
      const idx = await loadOssFeedsIndex(ASSETS);
      const feeds = filterFeeds(idx, { vendor, category, status, keyword, limit: limit ?? 200 });
      return untrustedToolResult({
        total: idx.counts.total,
        returned: feeds.length,
        categories: idx.categories,
        feeds,
      });
    }
  );

  h.tools(
    'oss_feeds_get_category',
    'Return all feeds in a specific category with full URLs. Use oss_feeds_list first to discover category names.',
    {
      category: z
        .string()
        .describe('Category slug, e.g. "ip", "dns", "url", "cveid". Get from oss_feeds_list categories.'),
    },
    async ({ category }) => {
      const body = await getOssFeedsByCategory(ASSETS, category);
      if (!body) {
        return untrustedToolResult({
          error: 'category_not_found',
          category,
          hint: 'Call oss_feeds_list to see available categories.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'oss_feeds_stats',
    'Return cache + manifest stats for the OSS Feed Registry: total feeds, category breakdown, status breakdown, cache state.',
    {},
    async () => {
      const idx = await loadOssFeedsIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        lastSyncedAt: idx.lastSyncedAt,
        cache: ossFeedsCacheStats(),
      });
    }
  );
}
