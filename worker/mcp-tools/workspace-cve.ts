/**
 * workspace-cve MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { apiFetch, untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

export function registerWorkspaceCveTools(h: McpToolHost): void {
  // ── CTI Workspace Tools (AEAD Lifecycle) ──────────────────────────
  h.tools(
    'ws_list',
    'List investigation workspaces. Each workspace is a full AEAD-lifecycle case with subjects, connections, findings, and timeline.',
    {
      status: z.enum(['open', 'active', 'archived']).optional().describe('Filter by status'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    async ({ status, limit }) => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (limit) params.set('limit', String(limit));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/workspaces?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_create',
    'Create a new investigation workspace for AEAD lifecycle tracking.',
    {
      title: z.string().describe('Workspace title (e.g. "Phishing — example.com")'),
      description: z.string().optional().describe('Brief summary'),
      target: z.string().optional().describe('Primary target (domain, IP, email, etc.)'),
      target_type: z
        .enum(['person', 'domain', 'org', 'username', 'email', 'ip', 'other'])
        .optional()
        .describe('Target type (default: domain)'),
      tags: z.array(z.string()).optional().describe('Tags for classification'),
    },
    async ({ title, description, target, target_type, tags }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/workspaces', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({ title, description, target, target_type, tags }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_get',
    'Get a workspace with all subjects, connections, findings, and timeline.',
    {
      id: z.string().describe('Workspace ID'),
    },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_add_subject',
    'Register a subject (entity) in a workspace investigation.',
    {
      workspace_id: z.string().describe('Workspace ID'),
      subject_type: z
        .enum([
          'person',
          'domain',
          'org',
          'username',
          'email',
          'ip',
          'phone',
          'location',
          'asset',
          'device',
          'crypto',
          'custom',
        ])
        .describe('Entity type'),
      label: z.string().describe('Human-readable label'),
      value: z.string().optional().describe('Raw value (IP, email, domain, etc.)'),
      confidence: z.number().optional().describe('Confidence 0-100'),
      trust_score: z.number().optional().describe('Trust score 1-5'),
    },
    async ({ workspace_id, subject_type, label, value, confidence, trust_score }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/subjects`,
        h.apiKey,
        { method: 'POST', body: JSON.stringify({ subject_type, label, value, confidence, trust_score }) }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_add_connection',
    'Define a relationship between two subjects in a workspace.',
    {
      workspace_id: z.string().describe('Workspace ID'),
      from_subject_id: z.string().describe('Source subject ID'),
      to_subject_id: z.string().describe('Target subject ID'),
      relationship: z
        .string()
        .describe('Relationship type (owns, uses, works_at, linked_to, alias, communicated_with)'),
      strength: z.enum(['confirmed', 'probable', 'possible']).optional().describe('Connection strength'),
    },
    async ({ workspace_id, from_subject_id, to_subject_id, relationship, strength }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/connections`,
        h.apiKey,
        { method: 'POST', body: JSON.stringify({ from_subject_id, to_subject_id, relationship, strength }) }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_add_finding',
    'Log a finding with source, trust score, and confidence in a workspace.',
    {
      workspace_id: z.string().describe('Workspace ID'),
      subject_id: z.string().optional().describe('Related subject ID'),
      finding_type: z
        .enum(['infrastructure', 'identity', 'exposure', 'credential', 'behavioral', 'legal', 'ioc'])
        .optional()
        .describe('Finding type'),
      weight: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional().describe('Severity weight'),
      description: z.string().describe('Finding description'),
      source_url: z.string().optional().describe('Source URL'),
      confidence: z.number().optional().describe('Confidence 0-100'),
    },
    async ({ workspace_id, subject_id, finding_type, weight, description, source_url, confidence }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/findings`,
        h.apiKey,
        {
          method: 'POST',
          body: JSON.stringify({ subject_id, finding_type, weight, description, source_url, confidence }),
        }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_exposure',
    'Calculate composite exposure score (0-100) for a target based on IOC reputation, breach exposure, infrastructure, attack surface, and threat intel.',
    {
      target: z.string().describe('Target to score (domain, IP, email)'),
      target_type: z.string().optional().describe('Target type'),
      ioc_reputation: z
        .object({})
        .passthrough()
        .optional()
        .describe('IOC reputation signals (abuseScore, vtPositives, etc.)'),
      breach_exposure: z.object({}).passthrough().optional().describe('Breach exposure signals'),
      infrastructure: z.object({}).passthrough().optional().describe('Infrastructure exposure signals'),
      attack_surface: z.object({}).passthrough().optional().describe('Attack surface signals'),
      threat_intel: z.object({}).passthrough().optional().describe('Threat intelligence signals'),
    },
    async (args) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/cti/exposure', h.apiKey, {
        method: 'POST',
        body: JSON.stringify(args),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_export_stix',
    'Export workspace indicators as STIX 2.1 bundle or flat IOC list.',
    {
      workspace_id: z.string().describe('Workspace ID'),
      format: z.enum(['stix', 'flat']).optional().describe('Output format (default: stix)'),
      default_tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).optional().describe('Default TLP marking'),
    },
    async ({ workspace_id, format, default_tlp: _default_tlp }) => {
      // KNOWN GAP (pre-existing, not introduced by the module split): the
      // backend GET /api/v1/workspaces/:id/export ignores BOTH `format` and
      // `default_tlp`. `exportWorkspaceHandler` in
      // api/src/routes/cti-workspaces.ts unconditionally returns
      // { workspace, subjects, connections, findings, timeline } — it never
      // emits a STIX bundle or a flat IOC list, despite this tool's
      // description promising both.
      //
      // Both params stay in the zod schema (clients may already send them, and
      // the advertised tool signature must not change), so they are accepted
      // and ignored. Wiring them up means changing the endpoint, which is a
      // behaviour change beyond this refactor's scope.
      const url =
        format === 'flat'
          ? `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/export?format=flat`
          : `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/export?format=stix`;
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, url, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_render_graph',
    'Render an ASCII box-drawing relationship graph, timeline, or risk heatmap from workspace data.',
    {
      type: z.enum(['entities', 'timeline', 'risk']).describe('Graph type'),
      nodes: z.array(z.object({}).passthrough()).optional().describe('Graph nodes (for entities type)'),
      edges: z.array(z.object({}).passthrough()).optional().describe('Graph edges (for entities type)'),
      events: z.array(z.object({}).passthrough()).optional().describe('Timeline events'),
      dimensions: z.array(z.object({}).passthrough()).optional().describe('Risk dimensions'),
      title: z.string().optional().describe('Graph title'),
    },
    async (args) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/cti/render/graph', h.apiKey, {
        method: 'POST',
        body: JSON.stringify(args),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_workflow_advance',
    'Advance a workspace to the next AEAD phase (Acquire→Enrich→Assess→Deliver→Complete).',
    {
      workspace_id: z.string().describe('Workspace ID'),
    },
    async ({ workspace_id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/workflow/advance`,
        h.apiKey,
        { method: 'POST' }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ws_workflow_summary',
    'Get workspace summary: phase progress, findings breakdown, recommended commands.',
    {
      workspace_id: z.string().describe('Workspace ID'),
    },
    async ({ workspace_id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/workflow/summary`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── CVE Intelligence (from CVE-Intel) ──────────────────────────────
  h.tools(
    'poc_scan',
    'Search GitHub for public exploit/PoC repositories for a CVE. Returns repo URLs, star counts, language, age, and whether the repo has actual code. Bypasses GitHub 1000-result limit via monthly pagination.',
    { cve_id: z.string().describe('CVE identifier, e.g. CVE-2024-3094') },
    async ({ cve_id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/cve-poc-scan?id=${encodeURIComponent(cve_id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'cve_poc_map',
    'Get the cached CVE-to-GitHub-repo mapping. Pass ?id=CVE-XXXX-XXXXX for a single CVE, or ?year=YYYY for a year-scoped index of all mapped CVEs. Results are KV-cached for 24h.',
    {
      cve_id: z.string().optional().describe('CVE ID (optional if year is provided)'),
      year: z.number().optional().describe('Year for index lookup (optional if cve_id is provided)'),
    },
    async ({ cve_id, year }) => {
      const params = new URLSearchParams();
      if (cve_id) params.set('id', cve_id);
      if (year) params.set('year', String(year));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/cve-poc-map?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'cyber_news',
    'Aggregate cybersecurity news from 11 RSS feeds across 5 tiers (Advisory, Exploit, Research, Vendor, Community). Supports tier filtering and keyword search. Sources: CISA, Rapid7, Packet Storm, BleepingComputer, Hacker News, GitHub Security, ZDI, Reddit netsec/exploitdev/bugbounty.',
    {
      tier: z.number().optional().describe('Filter by tier: 1=Advisory, 2=Exploit, 3=Research, 4=Vendor, 5=Community'),
      query: z.string().optional().describe('Keyword filter (searches title + description)'),
      limit: z.number().optional().describe('Max articles to return (default 100)'),
    },
    async ({ tier, query, limit }) => {
      const params = new URLSearchParams({ limit: String(limit ?? 100) });
      if (tier) params.set('tier', String(tier));
      if (query) params.set('q', query);
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/cyber-news?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'soc_cve_report',
    'Generate a SOC CVE intelligence report. Takes a list of up to 50 CVE IDs and bundles CVE lookup + PoC scan + health check into a downloadable CSV or Markdown report. Returns executive summary, CVSS/EPSS/KEV details, PoC repos, and pipeline health.',
    {
      cves: z.array(z.string()).describe('List of CVE IDs to include in the report (max 50)'),
      format: z.enum(['csv', 'markdown']).optional().describe('Output format: csv or markdown (default markdown)'),
    },
    async ({ cves, format }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/soc-cve-report/json', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cves, format: format ?? 'markdown' }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Telegram Intelligence Search (TraceOn-inspired) ──────────────
  h.tools(
    'tg_boolean_search',
    'Search Telegram leak messages with boolean AND/OR/NOT operators and field qualifiers. Fields: text, channel.title, channel.username, severity, leak_type. Supports wildcards (prefix*) and exact phrases ("quoted").',
    {
      q: z.string().describe('Boolean query (e.g. ransomware AND channel.title:TeamPCP NOT tutorial)'),
      mode: z.enum(['boolean', 'general']).optional().describe('Search mode (default: boolean)'),
      channel: z.string().optional().describe('Filter by channel handle'),
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by severity'),
      from: z.string().optional().describe('Date from (ISO date)'),
      to: z.string().optional().describe('Date to (ISO date)'),
      sort: z.enum(['newest', 'oldest']).optional().describe('Sort order (default: newest)'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    async (args) => {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(args)) {
        if (v !== undefined && v !== null) params.set(k, String(v));
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/tg-search?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'tg_timeline',
    'Get Telegram message volume timeline data (messages per day) with severity breakdown. Useful for visualizing activity spikes.',
    {
      q: z.string().optional().describe('Boolean query to filter timeline'),
      channel: z.string().optional().describe('Filter by channel handle'),
      days: z.number().optional().describe('Number of days to look back (default 30, max 365)'),
    },
    async (args) => {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(args)) {
        if (v !== undefined && v !== null) params.set(k, String(v));
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/tg-timeline?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools('tg_saved_searches_list', 'List saved Telegram boolean search queries.', {}, async () => {
    const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/tg-saved-searches', h.apiKey);
    return untrustedToolResult(data);
  });
  h.tools(
    'tg_saved_search_create',
    'Save a Telegram boolean search query for one-click reuse.',
    {
      name: z.string().describe('Saved search name (e.g. "Daily Stealer Monitor")'),
      query: z.string().describe('Boolean query to save'),
      mode: z.enum(['boolean', 'general']).optional().describe('Search mode'),
      sort_order: z.enum(['newest', 'oldest']).optional().describe('Sort order'),
    },
    async ({ name, query, mode, sort_order }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/tg-saved-searches', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({ name, query, mode, sort_order }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'tg_saved_search_delete',
    'Delete a saved Telegram search query.',
    {
      id: z.string().describe('Saved search ID'),
    },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/tg-saved-searches/${encodeURIComponent(id)}`,
        h.apiKey,
        { method: 'DELETE' }
      );
      return untrustedToolResult(data);
    }
  );
}
