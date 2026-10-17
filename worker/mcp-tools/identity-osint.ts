/**
 * identity-osint MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { adminApiFetch, apiFetch, untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

export function registerIdentityOsintTools(h: McpToolHost): void {
  // ── PromptIntel IoPC registry (NovaHunting) ────────────────────────
  h.tools(
    'pi_search_prompts',
    'Search the PromptIntel Indicators-of-Prompt-Compromise feed: adversarial AI prompts with severity and category filters. Requires server-side PROMPTINTEL_API_KEY.',
    {
      search: z.string().optional().describe('Search in prompt titles and content'),
      severity: z.string().optional().describe('Filter by severity level'),
      category: z.string().optional().describe('One of manipulation, abuse, patterns, outputs'),
      limit: z.number().int().min(1).max(100).optional().describe('Items to return (default 20, max 100)'),
    },
    async ({ search, severity, category, limit }) => {
      const p = new URLSearchParams();
      if (search) p.set('search', search);
      if (severity) p.set('severity', severity);
      if (category) p.set('category', category);
      p.set('limit', String(limit ?? 20));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/promptintel/prompts?${p}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'pi_get_entry',
    'Retrieve a single IoPC taxonomy entry (e.g. IOPC-T1.001 or IOPC-R012) with framework mappings and relationships. Requires server-side PROMPTINTEL_API_KEY.',
    { id: z.string().describe('IoPC entry id, e.g. IOPC-T1.001') },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/promptintel/taxonomy/entries/${encodeURIComponent(id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'digest_analyze',
    'Get the analyst note for a Webamon daily threat brief or PCMedicalist digest: deterministic key signals plus a cached LLM assessment. Nothing generates on read — briefs are immutable per date.',
    {
      kind: z.enum(['wdtb', 'pcm']).describe('wdtb = Webamon brief, pcm = PCMedicalist digest'),
      date: z.string().describe('Date YYYY-MM-DD'),
    },
    async ({ kind, date }) => {
      const path =
        kind === 'wdtb'
          ? `/api/v1/webamon-dtb/briefs/${encodeURIComponent(date)}/analysis`
          : `/api/v1/pcmedicalist/digests/${encodeURIComponent(date)}/analysis`;
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, path, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── HudsonRock Cavalier (infostealer intelligence) ───────────────────
  h.tools(
    'hr_search_email',
    'Search for compromised credentials by email address via Hudson Rock Cavalier API. Returns infostealer infections, stealer families, compromised URLs, and credential types (employee/user/third-party).',
    { email: z.string().describe('Email address to search') },
    async ({ email }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/breach/hudsonrock?email=${encodeURIComponent(email)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_search_domain',
    'Search for domain-wide infostealer compromises via Hudson Rock Cavalier API. Returns compromised employees, users, and third-party exposures with stealer families and infection dates.',
    {
      domain: z.string().describe('Domain name, e.g. example.com'),
      types: z
        .array(z.enum(['employees', 'users', 'third_parties']))
        .optional()
        .describe('Filter by credential type'),
      keywords: z.array(z.string()).optional().describe('Filter URLs by keyword (e.g. sso, vpn, admin)'),
    },
    async ({ domain, types, keywords }) => {
      const p = new URLSearchParams({ domain });
      if (types) p.set('types', types.join(','));
      if (keywords) p.set('keywords', keywords.join(','));
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/breach/hudsonrock/domain?${p}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_domain_overview',
    'Get domain compromise overview statistics from Hudson Rock — compromised employee/user counts, last compromise dates, and upload timelines. Useful for risk posture assessment.',
    { domain: z.string().describe('Domain name, e.g. example.com') },
    async ({ domain }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/hudsonrock/domain-overview?domain=${encodeURIComponent(domain)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_assets_discovery',
    'Discover all compromised URLs for a domain (attack surface mapping). Returns URLs where credentials were stolen, occurrence counts, and compromise types.',
    {
      domain: z.string().describe('Domain name, e.g. example.com'),
      types: z.array(z.enum(['employees', 'users'])).optional(),
      keywords: z.array(z.string()).optional().describe('Filter by URL keyword'),
    },
    async ({ domain, types, keywords }) => {
      const p = new URLSearchParams({ domain });
      if (types) p.set('types', types.join(','));
      if (keywords) p.set('keywords', keywords.join(','));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/hudsonrock/discovery?${p}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_third_party_risk',
    'Assess third-party / supply-chain risk for a domain. Returns employee URLs, third-party service URLs, and user URLs where credentials were compromised — indicating supply chain exposure.',
    { domain: z.string().describe('Domain name to assess') },
    async ({ domain }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/hudsonrock/assessment?domain=${encodeURIComponent(domain)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_infection_analysis',
    'AI-powered infection source analysis for a specific stealer log. Returns the likely infection URL, confidence score, timeline of suspicious activity, and analyst summary. Works best with Lumma stealers.',
    { stealer: z.string().describe('Stealer ID from a previous search result') },
    async ({ stealer }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/hudsonrock/infection-analysis?stealer=${encodeURIComponent(stealer)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_search_username',
    'Search for compromised credentials by username via Hudson Rock Cavalier API.',
    { username: z.string().describe('Username to search') },
    async ({ username }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/hudsonrock/username?username=${encodeURIComponent(username)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_search_ip',
    'Search for compromises by IP address or CIDR range via Hudson Rock Cavalier API. Useful for IR when you have a suspicious IP.',
    { ip: z.string().describe('IP address or CIDR range') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/hudsonrock/ip?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'hr_account',
    'Check Hudson Rock Cavalier API account status, permissions, and quota. Use to verify the API key is valid.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/hudsonrock/account', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Email Registration Checker (site-specific API-based) ─────────────
  h.tools(
    'email_check_registration',
    'Check which platforms an email address is registered on using site-specific APIs (not just HTTP status codes). Returns rich profile metadata when available. Inspired by kaifcodec/user-scanner (MIT, 2.4k stars). Checks 20+ platforms: GitHub, GitLab, Instagram, TikTok, Etsy, Spotify, Steam, and more.',
    {
      email: z.string().describe('Email address to check'),
      platforms: z
        .array(z.string())
        .optional()
        .describe('Filter to specific platforms (e.g. ["github","instagram","etsy"])'),
    },
    async ({ email, platforms }) => {
      const p = new URLSearchParams({ email });
      if (platforms?.length) p.set('platforms', platforms.join(','));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/email-registration?${p}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'email_list_registration_platforms',
    'List all platforms available for email registration checking. Returns platform IDs, names, and categories.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/email-registration/platforms',
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Username OSINT: Patterns + Profile Scraping ─────────────────────
  h.tools(
    'username_generate_patterns',
    'Generate username variations for typosquatting detection and OSINT. Returns common patterns: leetspeak, double letters, prefix/suffix variations, dot/underscore/hyphen separators, number suffixes.',
    {
      username: z.string().describe('Base username to generate patterns for'),
    },
    async ({ username }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/username-osint/patterns?username=${encodeURIComponent(username)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'username_scrape_profiles',
    'Scrape profile metadata (display name, bio, avatar, follower counts) from platforms where the username is found. Returns rich profile data, not just found/not-found.',
    {
      username: z.string().describe('Username to scrape profiles for'),
    },
    async ({ username }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/username-osint/profile?username=${encodeURIComponent(username)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Passive DNS Correlation Engine ──────────────────────────────────
  h.tools(
    'passive_dns_query',
    'Query passive DNS for a domain or IP. Returns historical DNS resolutions, infrastructure migrations, and fast-flux detection. Sources: VirusTotal, URLscan, crt.sh, CIRCL.',
    {
      query: z.string().describe('Domain or IP address to query'),
      force: z.boolean().optional().describe('Force fresh query (bypass D1 cache)'),
    },
    async ({ query, force }) => {
      const params = new URLSearchParams({ query });
      if (force) params.set('force', '1');
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/passive-dns?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'passive_dns_reverse',
    'Reverse passive DNS lookup: find all domains that historically resolved to a given IP. Reads from accumulated D1 cache.',
    { ip: z.string().describe('IP address to reverse-lookup') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/passive-dns/reverse?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'passive_dns_overlap',
    'Find IPs shared between multiple domains (infrastructure overlap detection). Useful for mapping shared malicious hosting.',
    { domains: z.string().describe('Comma-separated list of domains (min 2)') },
    async ({ domains }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/passive-dns/overlap?domains=${encodeURIComponent(domains)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── IOC Watchlist ───────────────────────────────────────────────────
  h.tools(
    'ioc_watchlist_add',
    'Add an IOC to the watchlist for proactive alerting. Supported types: ip, domain, url, hash, cve, email. Alerts fire when the IOC appears in feeds.',
    {
      indicator: z.string().describe('The IOC value to watch'),
      indicator_type: z.enum(['ip', 'domain', 'url', 'hash', 'cve', 'email']).describe('IOC type'),
      label: z.string().optional().describe('Human-readable label'),
      webhook_url: z.string().optional().describe('Webhook URL (Discord, Slack, Telegram, custom)'),
      min_confidence: z.number().optional().describe('Minimum confidence to trigger (0-100, default 50)'),
      tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).optional().describe('TLP marking'),
    },
    async (args) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/ioc-watchlist', h.apiKey, {
        method: 'POST',
        body: JSON.stringify(args),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ioc_watchlist_list',
    'List all watched IOCs. Optionally filter by type.',
    {
      type: z.enum(['ip', 'domain', 'url', 'hash', 'cve', 'email']).optional().describe('Filter by IOC type'),
      limit: z.number().optional().describe('Max results (default 100)'),
    },
    async ({ type, limit }) => {
      const params = new URLSearchParams();
      if (type) params.set('type', type);
      if (limit) params.set('limit', String(limit));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/ioc-watchlist?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ioc_watchlist_alerts',
    'List recent alerts from the IOC watchlist.',
    {
      indicator: z.string().optional().describe('Filter by indicator'),
      since: z.string().optional().describe('ISO 8601 lower bound'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    async ({ indicator, since, limit }) => {
      const params = new URLSearchParams();
      if (indicator) params.set('indicator', indicator);
      if (since) params.set('since', since);
      if (limit) params.set('limit', String(limit));
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/ioc-watchlist/alerts?${params}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'ioc_watchlist_stats',
    'Get watchlist dashboard stats: total watches, alerts by type, webhook delivery rate.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/ioc-watchlist/stats', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Investigation Notebooks ────────────────────────────────────────
  h.tools(
    'notebook_list',
    'List investigation notebooks. Each notebook is a persistent investigation session with notes, IOCs, findings, and timeline entries stored in D1.',
    {
      status: z.enum(['open', 'investigating', 'resolved', 'archived']).optional().describe('Filter by status'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    async ({ status, limit }) => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (limit) params.set('limit', String(limit));
      const data = await adminApiFetch<Record<string, unknown>>(h, `/api/v1/notebooks?${params}`);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'notebook_create',
    'Create a new investigation notebook.',
    {
      title: z.string().describe('Notebook title (e.g. "Phishing Campaign — example.com")'),
      description: z.string().optional().describe('Brief summary'),
      severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('Severity (default: info)'),
    },
    async ({ title, description, severity }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/notebooks', {
        method: 'POST',
        body: JSON.stringify({ title, description, severity }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'notebook_get',
    'Get a notebook with all its entries.',
    {
      id: z.string().describe('Notebook ID'),
    },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/notebooks/${encodeURIComponent(id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'notebook_add_entry',
    'Add a note, IOC, finding, timeline event, or artifact to a notebook.',
    {
      notebook_id: z.string().describe('Notebook ID'),
      entry_type: z
        .enum(['note', 'ioc', 'finding', 'timeline', 'artifact'])
        .optional()
        .describe('Entry type (default: note)'),
      content: z.string().describe('Entry content'),
    },
    async ({ notebook_id, entry_type, content }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/notebooks/${encodeURIComponent(notebook_id)}/entries`,
        h.apiKey,
        { method: 'POST', body: JSON.stringify({ entry_type, content }) }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'notebook_update',
    'Update a notebook title, description, status, or severity.',
    {
      id: z.string().describe('Notebook ID'),
      title: z.string().optional().describe('New title'),
      description: z.string().optional().describe('New description'),
      status: z.enum(['open', 'investigating', 'resolved', 'archived']).optional().describe('New status'),
      severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('New severity'),
    },
    async ({ id, title, description, status, severity }) => {
      const body: Record<string, unknown> = {};
      if (title !== undefined) body.title = title;
      if (description !== undefined) body.description = description;
      if (status !== undefined) body.status = status;
      if (severity !== undefined) body.severity = severity;
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/notebooks/${encodeURIComponent(id)}`,
        h.apiKey,
        { method: 'PUT', body: JSON.stringify(body) }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'notebook_delete',
    'Delete a notebook and all its entries.',
    {
      id: z.string().describe('Notebook ID'),
    },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/notebooks/${encodeURIComponent(id)}`,
        h.apiKey,
        { method: 'DELETE' }
      );
      return untrustedToolResult(data);
    }
  );
}
