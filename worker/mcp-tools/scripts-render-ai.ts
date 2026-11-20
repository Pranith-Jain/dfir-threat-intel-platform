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
import { untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import { filterEscapes, getEscapeIncident, loadEscapeIndex } from '../lib/ai-escape-manifest';
import { filterThreats, getAiThreat, loadAiThreatsIndex } from '../lib/ai-threats-manifest';
import {
  filterRansomwareGroups,
  getRansomwareGroup,
  loadRansomwareGroupsIndex,
} from '../lib/ransomware-groups-manifest';
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
}
