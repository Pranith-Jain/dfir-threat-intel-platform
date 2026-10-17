/**
 * api-proxy MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { adminApiFetch, apiFetch, apiFetchSse, untrustedToolResult } from './core';
import { kqlToAhUrl, kqlToAhUrlMarkdown } from '../lib/kql-to-ah-url';
import { z } from 'zod';

import type { McpToolHost } from './host';
import { errMessage } from '../lib/err';

export function registerApiProxyTools(h: McpToolHost): void {
  // ── IOC Check ────────────────────────────────────────────────────────
  h.tools(
    'check_ioc',
    'Check reputation of an IP address, domain, URL, or file hash (MD5/SHA1/SHA256) across 30+ threat intelligence providers. Returns composite score, admiralty grade, and per-provider verdicts.',
    { indicator: z.string().describe('The IOC to check — IP, domain, URL, or hash') },
    async ({ indicator }) => {
      // /ioc/check streams per-provider results over SSE — read the whole
      // stream and return the aggregated events (metadata + per-provider).
      const data = await apiFetchSse(
        h.env.SELF,
        `/api/v1/ioc/check?indicator=${encodeURIComponent(indicator)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── OpenSourceMalware Check ──────────────────────────────────────────
  h.tools(
    'si_osm_check',
    'Check whether a package, container image, repository, URL, domain, IP, or crypto wallet is flagged as malicious in the OpenSourceMalware community threat database. Covers supply-chain threats (npm, PyPI, Maven, NuGet, etc.), container registries (Docker Hub, GHCR, Quay), and attacker infrastructure (domains, IPs, wallets).',
    {
      report_type: z
        .enum(['package', 'container', 'repository', 'url', 'domain', 'ip', 'wallet'])
        .describe('Type of resource to check'),
      resource: z
        .string()
        .describe('Resource identifier — package name, image name, repo URL, domain, IP, wallet address, etc.'),
      ecosystem: z
        .string()
        .optional()
        .describe(
          'Ecosystem for packages (npm, pypi, maven, nuget, rubygems, packagist, crates, go, vscode, openvsx, brew, skills) or registry for containers (dockerhub, ghcr, quay)'
        ),
      version: z.string().optional().describe('Specific package or container version'),
    },
    async ({ report_type, resource, ecosystem, version }) => {
      const p = new URLSearchParams({ report_type, resource });
      if (ecosystem) p.set('ecosystem', ecosystem);
      if (version) p.set('version', version);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/opensourcemalware/check?${p.toString()}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'si_osm_latest',
    'Retrieve the 100 most recent verified threat reports from OpenSourceMalware for any supported ecosystem (npm, pypi, crates, nuget, maven, go, packagist, rubygems, vscode, openvsx, brew, skills) or asset type (repository, domain, wallet, ip, url, container).',
    {
      ecosystem: z.string().optional().describe('Ecosystem or asset type (default: npm)'),
    },
    async ({ ecosystem }) => {
      const p = new URLSearchParams();
      if (ecosystem) p.set('ecosystem', ecosystem);
      const qs = p.toString();
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/opensourcemalware/latest${qs ? `?${qs}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── CVE Lookup ───────────────────────────────────────────────────────
  h.tools(
    'lookup_cve',
    'Look up a CVE by ID. Returns description, CVSS score, EPSS probability, CISA KEV status, affected products, and references.',
    { cve_id: z.string().describe('CVE identifier, e.g. CVE-2024-3094') },
    async ({ cve_id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/cve/lookup?id=${encodeURIComponent(cve_id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // (search_cve removed — the API has no keyword CVE search; /cve/search is
  //  an alias of /cve/lookup and only accepts ?id=, so the tool duplicated
  //  lookup_cve while advertising keyword search it couldn't deliver.)

  // ── CISA KEV Catalog ───────────────────────────────────────────────
  h.tools(
    'lookup_cisa_kev',
    'Search the CISA Known Exploited Vulnerabilities (KEV) catalog. Filter by CVE ID, vendor, product, keyword, recency (days), or ransomware-only. Returns matching KEV entries with date_added, due_date, and ransomware status. The full catalog has 1,200+ actively-exploited vulnerabilities.',
    {
      q: z.string().optional().describe('Free-text search across CVE ID, vendor, product, and vulnerability name'),
      cve: z.string().optional().describe('Exact CVE ID, e.g. CVE-2024-3094'),
      vendor: z.string().optional().describe('Vendor/project name filter (partial match)'),
      product: z.string().optional().describe('Product name filter (partial match)'),
      days: z.number().int().optional().describe('Only entries added in the last N days'),
      ransomware_only: z.boolean().optional().describe('Only entries with known ransomware campaign use'),
    },
    async (args) => {
      const p = new URLSearchParams();
      if (args.q) p.set('q', args.q);
      if (args.cve) p.set('cve', args.cve);
      if (args.vendor) p.set('vendor', args.vendor);
      if (args.product) p.set('product', args.product);
      if (args.days) p.set('days', String(args.days));
      if (args.ransomware_only) p.set('ransomware_only', 'true');
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/cisa-kev${p.toString() ? `?${p.toString()}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Threat Actor Enrichment ──────────────────────────────────────────
  h.tools(
    'enrich_actor',
    'Get a threat actor profile. Returns aliases, country attribution, MITRE ATT&CK techniques, known campaigns, and associated malware families.',
    { actor: z.string().describe('Threat actor name or slug, e.g. APT28, lazarus-group') },
    async ({ actor }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/actor-enrich?name=${encodeURIComponent(actor)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Malpedia Search ──────────────────────────────────────────────────
  h.tools(
    'search_malpedia',
    'Search Malpedia for malware families or threat actors. Returns matching entries with descriptions and references.',
    { q: z.string().describe('Search query — malware family name or actor name') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/malpedia/search?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Domain Lookup ────────────────────────────────────────────────────
  h.tools(
    'lookup_domain',
    'Domain intelligence lookup. Returns DNS records (A, AAAA, MX, NS, TXT, SOA), WHOIS/RDAP registration data, CT log (certificate transparency) entries, SPF/DKIM/DMARC email authentication analysis, and threat intel hits from blocklists and IOC feeds.',
    { domain: z.string().describe('Fully qualified domain name, e.g. example.com') },
    async ({ domain }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/domain/lookup?domain=${encodeURIComponent(domain)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── ASN Lookup ───────────────────────────────────────────────────────
  h.tools(
    'lookup_asn',
    'ASN intelligence lookup. Returns AS name, country, network ranges, RIR registration, and BGP peer info.',
    { asn: z.string().describe('AS number, e.g. AS13335 or 13335') },
    async ({ asn }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/asn/lookup?asn=${encodeURIComponent(asn)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Triage Search ────────────────────────────────────────────────────
  h.tools(
    'search_triage',
    'Search Recorded Future Triage sandbox for malware samples by family, tag, hash, URL, or domain. Returns analysis results, behavioral reports, and extracted configs.',
    { q: z.string().describe('Triage search query — family:name, tag:ransomware, md5:..., url:...') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/triage/search?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Today's Briefing ─────────────────────────────────────────────────
  h.tools(
    'get_today_briefing',
    "Get today's threat intelligence briefing. A curated digest of the latest CVEs, ransomware activity, data breaches, and emerging threats from the past 24 hours. When format=markdown returns a TI Mindmap HUB-style rich formatted report.",
    {
      format: z
        .enum(['json', 'markdown'])
        .optional()
        .describe('Output format: json (default) or markdown for rich formatted briefing'),
    },
    async ({ format }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/briefings/today', h.apiKey);
      if (data && typeof data === 'object' && 'slug' in data && format === 'markdown') {
        const slug = (data as Record<string, string>).slug;
        const result = await apiFetch<{ markdown: string }>(h.env.SELF, `/api/v1/briefings/${slug}/render`, h.apiKey);
        return untrustedToolResult({ markdown: result.markdown });
      }
      return untrustedToolResult(data);
    }
  );

  // ── List Briefings ───────────────────────────────────────────────────
  h.tools(
    'list_briefings',
    'List recent threat intelligence briefings (daily and weekly). Returns slug, date, type, and summary for each.',
    { limit: z.number().optional().describe('Max briefings to return (default 10)') },
    async ({ limit }) => {
      const qs = limit ? `?limit=${limit}` : '';
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/briefings/list${qs}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Related Briefings (case-triage linkage) ─────────────────────────
  h.tools(
    'briefings_related',
    'Find prior briefings related to a given briefing — links by shared IOCs (domains/IPs/hashes/URL hosts) or shared tactic keywords, ranked by match count then severity then recency. Case-triage linkage (port of the CTI case-queue related-case matcher).',
    {
      slug: z.string().describe('Briefing slug, e.g. daily-2026-08-18'),
      limit: z.number().optional().describe('Max related briefings (default 5)'),
    },
    async ({ slug, limit }) => {
      const qs = `?slug=${encodeURIComponent(slug)}${limit ? `&limit=${limit}` : ''}`;
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/briefings/related${qs}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Ransomware Recent ────────────────────────────────────────────────
  h.tools(
    'get_ransomware_activity',
    'Get recent ransomware activity — latest victims, group activity, and leak-site posts from ransomware.live and other trackers.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/ransomware-recent', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Supply Chain Attacks ─────────────────────────────────────────────
  h.tools(
    'get_supply_chain_attacks',
    'Software supply-chain compromise incidents (npm/PyPI/container/AI-agent ecosystems) from supplychainattack.org — title, status, severity, ecosystems, attack vectors, blast radius, remediation, package IOCs, and GHSA sources. Filter by ecosystem/status/severity.',
    {
      ecosystem: z.string().optional().describe('Ecosystem filter, e.g. npm/pypi'),
      status: z.string().optional().describe('Incident status: active/contained/resolved'),
      severity: z.string().optional().describe('Severity: critical/high/medium/low'),
      limit: z.number().optional().describe('Max incidents'),
    },
    async ({ ecosystem, status, severity, limit }) => {
      const p = new URLSearchParams();
      if (ecosystem) p.set('ecosystem', ecosystem);
      if (status) p.set('status', status);
      if (severity) p.set('severity', severity);
      if (limit) p.set('limit', String(limit));
      const qs = p.toString();
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/supply-chain-attacks${qs ? `?${qs}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── CERT-In Advisories ───────────────────────────────────────────────
  h.tools(
    'get_cert_in_advisories',
    'CERT-In (Indian Computer Emergency Response Team) advisories — vendor-reported vulnerabilities affecting Indian enterprises, with severity, CVEs, products affected, and the official CIAD-YYYY-NNNN ID. Filter by CVE, year, severity, or keyword.',
    {
      q: z.string().optional().describe('Free-text search across title, description, products, CVEs'),
      cve: z.string().optional().describe('CVE ID, e.g. CVE-2025-0110'),
      year: z.string().optional().describe('Filter by year, e.g. 2025'),
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Severity filter'),
      id: z.string().optional().describe('Specific CERT-In advisory ID, e.g. CIAD-2025-0010'),
      limit: z.number().optional().describe('Max advisories (default: all)'),
    },
    async ({ q, cve, year, severity, id, limit }) => {
      const p = new URLSearchParams();
      if (q) p.set('q', q);
      if (cve) p.set('cve', cve);
      if (year) p.set('year', year);
      if (severity) p.set('severity', severity);
      if (id) p.set('id', id);
      if (limit) p.set('limit', String(limit));
      const qs = p.toString();
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/cert-in${qs ? `?${qs}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Phishing Analyze ─────────────────────────────────────────────────
  h.tools(
    'analyze_phishing_email',
    'Analyze raw email source for phishing indicators. Parses headers, checks SPF/DKIM/DMARC, extracts URLs, and computes a risk score with flags.',
    { raw_email: z.string().describe('Full raw email source (headers + body)') },
    async ({ raw_email }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/phishing/analyze', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: raw_email,
      });
      return untrustedToolResult(data);
    }
  );

  // ── Unified Search ───────────────────────────────────────────────────
  h.tools(
    'unified_search',
    'Cross-source search across all threat intelligence feeds. Search by keyword, IOC, actor name, malware family, or CVE to find matching entries across briefings, live feeds, ransomware data, and more.',
    { q: z.string().describe('Search query') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/unified-search?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Detections ───────────────────────────────────────────────────────
  h.tools(
    'get_detections',
    'Get the latest detection rules feed — Sigma, YARA, and Snort rules mapped to threat actors, malware families, and MITRE ATT&CK techniques.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/detections', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Threat Pulse ─────────────────────────────────────────────────────
  h.tools(
    'get_threat_pulse',
    'Get a global threat overview — top active threat actors, trending malware families, most exploited CVEs, and geopolitical cyber events from the past week.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/threat-pulse', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── IOC Correlation ──────────────────────────────────────────────────
  h.tools(
    'correlate_iocs',
    'Search correlated IOCs. Find relationships between indicators — shared infrastructure, overlapping campaigns, and linked threat actors.',
    { q: z.string().describe('IOC or keyword to correlate') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/ioc-correlation?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Breach Check ─────────────────────────────────────────────────────
  h.tools(
    'check_breach',
    'Check if an email address or domain has been exposed in known data breaches. Returns breach names, dates, and exposed data types.',
    {
      target: z.string().describe('Email address or domain to check'),
      type: z.enum(['email', 'domain']).describe('Whether the target is an email or domain'),
    },
    async ({ target, type }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/breach/${type}?${type}=${encodeURIComponent(target)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── BreachVIP search (direct, full field set) ──────────────────────
  // Calls the BreachVIP API (https://breach.vip/api/search) directly so an
  // MCP client can query the 10B+ record corpus across ALL supported fields
  // (email, username, domain, ip, phone, password, name, uuid, steamid,
  // discordid) — not just the email/domain subset that /api/v1/breach/* fans
  // out. Returns metadata-only grouped results (breach name + record count +
  // exposed data classes); raw credential values are never surfaced.
  h.tools(
    'breach_vip_search',
    'Search the BreachVIP breach corpus (10B+ records, 1000+ datasets) directly. Supports 10 field types (email, username, domain, ip, phone, password, name, uuid, steamid, discordid). Returns grouped metadata: breach name, record count, and exposed data classes — raw credentials are never surfaced.',
    {
      term: z.string().min(1).max(100).describe('Search term (e.g. an email, domain, username, or IP)'),
      fields: z
        .array(
          z.enum(['email', 'password', 'domain', 'username', 'ip', 'name', 'uuid', 'steamid', 'phone', 'discordid'])
        )
        .min(1)
        .max(10)
        .describe('Field(s) to search the term against'),
      wildcard: z.boolean().optional().describe('Treat * and ? in the term as wildcard operators (default false)'),
      case_sensitive: z.boolean().optional().describe('Case-sensitive search (default false)'),
    },
    async ({ term, fields, wildcard, case_sensitive }) => {
      const UA = 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)';
      const body = JSON.stringify({
        term,
        fields,
        ...(wildcard !== undefined ? { wildcard } : {}),
        ...(case_sensitive !== undefined ? { case_sensitive } : {}),
      });
      try {
        const res = await fetch('https://breach.vip/api/search', {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': UA },
          body,
          signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) {
          return untrustedToolResult({
            error: `breach.vip returned HTTP ${res.status}`,
            note: 'The site sits behind a Cloudflare managed challenge that may block server-side egress.',
          });
        }
        const ct = res.headers.get('content-type') ?? '';
        if (!ct.includes('json')) {
          return untrustedToolResult({
            error: 'breach.vip returned a non-JSON response (likely a Cloudflare challenge page)',
            results: [],
          });
        }
        const data = (await res.json()) as { results?: Array<{ source: string; [k: string]: unknown }> };
        const results = data.results ?? [];
        // Group by breach source — same metadata-only approach as the route.
        const FIELD_LABELS: Record<string, string> = {
          email: 'Email addresses',
          password: 'Passwords',
          username: 'Usernames',
          name: 'Names',
          phone: 'Phone numbers',
          domain: 'Domains',
          ip: 'IP addresses',
          uuid: 'Minecraft UUIDs',
          steamid: 'Steam IDs',
          discordid: 'Discord IDs',
        };
        const groups = new Map<string, { count: number; fields: Set<string> }>();
        for (const r of results) {
          const name = r.source || 'Unknown';
          const g = groups.get(name) ?? { count: 0, fields: new Set<string>() };
          g.count++;
          for (const key of Object.keys(r)) {
            if (key !== 'source' && key !== 'categories' && FIELD_LABELS[key]) g.fields.add(key);
          }
          groups.set(name, g);
        }
        const grouped = Array.from(groups.entries())
          .sort((a, b) => b[1].count - a[1].count)
          .slice(0, 50)
          .map(([name, g]) => ({
            breach: name,
            record_count: g.count,
            data_classes: Array.from(g.fields)
              .map((f) => FIELD_LABELS[f])
              .filter((v): v is string => Boolean(v)),
          }));
        return untrustedToolResult({
          total_records: results.length,
          breaches_returned: grouped.length,
          breaches: grouped,
          note: 'Metadata only — record counts and data-class labels. Raw credential values are never surfaced. BreachVIP rate limit: 15 req/min.',
        });
      } catch (err) {
        return untrustedToolResult({
          error: `breach.vip request failed: ${errMessage(err)}`,
          results: [],
        });
      }
    }
  );

  // ── Feed Status ──────────────────────────────────────────────────────
  h.tools(
    'get_feed_status',
    'Get the health and freshness status of all 30+ threat intelligence feed sources. Shows last update time, error rates, and data volume.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/feed-status', h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── MITRE Technique ──────────────────────────────────────────────────
  h.tools(
    'lookup_mitre',
    'Look up a MITRE ATT&CK technique by ID. Returns technique name, description, tactics, mitigations, and detection guidance.',
    { technique_id: z.string().describe('MITRE ATT&CK technique ID, e.g. T1566.001') },
    async ({ technique_id }) => {
      // The route validates ?id= but the handler reads ?technique= — send both.
      const enc = encodeURIComponent(technique_id);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/mitre/technique?id=${enc}&technique=${enc}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Relationship Graph ───────────────────────────────────────────────
  h.tools(
    'get_relationships',
    'Get the relationship graph for an IOC — shows connections to threat actors, malware families, campaigns, CVEs, and other indicators.',
    { indicator: z.string().describe('The IOC to get relationships for') },
    async ({ indicator }) => {
      // The route validates ?indicator= but the handler reads ?q= — send both.
      const enc = encodeURIComponent(indicator);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/relationship-graph?indicator=${enc}&q=${enc}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── IP Geolocation & Privacy ─────────────────────────────────────────
  h.tools(
    'lookup_ip_geo',
    'Get IP geolocation, ASN, company, and privacy detection (VPN/proxy/tor/hosting). Uses IPinfo and Spur.us for anonymization detection.',
    { ip: z.string().describe('IPv4 or IPv6 address') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/ip-geo?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Generate Blocklists ──────────────────────────────────────────────
  h.tools(
    'get_blocklists',
    'Get pre-generated firewall blocklists in pfSense, iptables, and Suricata formats. Derived from aggregated threat intel feeds.',
    {
      format: z
        .enum(['pfsense', 'iptables', 'suricata', 'meta'])
        .optional()
        .describe('Blocklist format (default: meta)'),
    },
    async ({ format }) => {
      const fmt = format ?? 'meta';
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/blocklists/${fmt}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Wayback Machine ─────────────────────────────────────────────────
  h.tools(
    'wayback_lookup',
    'Check the Wayback Machine (archive.org) for historical snapshots of a URL. Useful for tracking website changes or recovering deleted content.',
    { url: z.string().describe('URL to look up in the Wayback Machine') },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/wayback/cdx?url=${encodeURIComponent(url)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Phishing Analysis ───────────────────────────────────────────────
  h.tools(
    'analyze_phishing_url',
    'Analyze a URL for phishing indicators. Checks against PhishTank, OpenPhish, URLhaus, and performs visual similarity analysis.',
    { url: z.string().describe('URL to analyze') },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/phishing/analyze`, h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── URL Risk Correlation (IntelX port) ──────────────────────────────
  h.tools(
    'analyze_url_risk',
    'Correlate a URL across VirusTotal, Google Safe Browsing, urlscan.io, AbuseIPDB, and WHOIS domain age using the weighted IntelX risk engine. Returns a 0-100 risk score, verdict (Critical/High/Suspicious/Low/No Strong Threat Evidence), confidence, static heuristic flags (punycode, shorteners, keywords, @-symbol, IP hosts), and a per-provider evidence chain with score breakdown.',
    { url: z.string().describe('http(s) URL to score') },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/url-risk/analyze`, h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Web Scan ────────────────────────────────────────────────────────
  h.tools(
    'scan_website',
    'Scan a website for security issues — checks security headers, SSL certificate, technologies, and potential vulnerabilities.',
    { url: z.string().describe('URL to scan') },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/web-scan?url=${encodeURIComponent(url)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Google Dorks ────────────────────────────────────────────────────
  h.tools(
    'google_dorks',
    'Generate and execute Google dork queries for a domain. Useful for finding exposed files, login pages, and sensitive information.',
    {
      domain: z.string().describe('Domain to dork'),
      dork_type: z.enum(['files', 'login', 'sensitive', 'all']).optional().describe('Type of dorks to run'),
    },
    async ({ domain, dork_type }) => {
      // The route validates ?domain= but the handler runs ?q= as the actual
      // Google query — send the domain (for the schema) plus a dork built
      // from the requested category.
      const dorks: Record<string, string> = {
        files: `site:${domain} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:txt OR ext:log OR ext:bak)`,
        login: `site:${domain} (inurl:login OR inurl:admin OR inurl:signin OR intitle:"log in")`,
        sensitive: `site:${domain} (ext:env OR ext:sql OR ext:bak OR ext:config OR intitle:"index of" OR intext:"password")`,
        all: `site:${domain}`,
      };
      const q = dorks[dork_type ?? 'all'] ?? `site:${domain}`;
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/google-dorks?domain=${encodeURIComponent(domain)}&q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Crypto Trace ────────────────────────────────────────────────────
  h.tools(
    'trace_crypto_address',
    'Trace a cryptocurrency wallet address. Returns balance, transaction history, and associated entities from blockchain explorers.',
    {
      address: z.string().describe('Crypto wallet address'),
      chain: z.enum(['bitcoin', 'ethereum', 'monero']).optional().describe('Blockchain (default: auto-detect)'),
    },
    async ({ address, chain }) => {
      const qs = new URLSearchParams({ address });
      if (chain) qs.set('chain', chain);
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/crypto-trace?${qs}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Report Parser ───────────────────────────────────────────────────
  h.tools(
    'parse_threat_report',
    'Parse a threat intelligence report or article to extract structured data: IOCs (IPs, domains, URLs, hashes), threat actors, malware families, MITRE ATT&CK techniques, CVEs, targeted sectors, and an executive summary. Use this when analyzing threat reports, blog posts, or incident write-ups.',
    {
      text: z.string().optional().describe('The report text to analyze'),
      url: z.string().optional().describe('URL of the report to fetch and analyze'),
    },
    async ({ text, url }) => {
      if (!text && !url) {
        throw new Error('Either text or url must be provided');
      }
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/report/parse', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text, url }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── IOC Lifecycle ───────────────────────────────────────────────────
  h.tools(
    'get_ioc_lifecycle',
    'Get the lifecycle data for an IOC — when it first appeared, last seen, activity trend, and decay rate. Use this to understand if an indicator is still active or dormant.',
    { indicator: z.string().describe('The IOC to get lifecycle data for') },
    async ({ indicator }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/ioc-lifecycle?indicator=${encodeURIComponent(indicator)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Trending IOCs ───────────────────────────────────────────────────
  h.tools(
    'get_trending_iocs',
    'Get the most active IOCs in the last 24 hours. Returns indicators with highest observation counts and scores, useful for identifying emerging threats.',
    {
      limit: z.number().optional().describe('Max results (default 50, max 200)'),
      type: z.enum(['ipv4', 'domain', 'url', 'hash']).optional().describe('Filter by indicator type'),
    },
    async ({ limit, type }) => {
      const params = new URLSearchParams();
      if (limit) params.set('limit', String(limit));
      if (type) params.set('type', type);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/ioc-lifecycle/trending?${params}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── YARA Rule Generator ─────────────────────────────────────────────
  h.tools(
    'generate_yara_rule',
    'Generate a YARA detection rule using AI. Provide a description of what to detect, and optionally known strings, malware family name, and target file type. Returns a syntactically valid YARA rule with metadata.',
    {
      description: z.string().describe('What the rule should detect (e.g., "Cobalt Strike beacon DLL")'),
      strings: z.array(z.string()).optional().describe('Known malicious strings to match'),
      family: z.string().optional().describe('Malware family name'),
      filetype: z.string().optional().describe('Target file type (PE, ELF, document, etc.)'),
      complexity: z.enum(['basic', 'standard', 'advanced']).optional().describe('Rule complexity level'),
    },
    async ({ description, strings, family, filetype, complexity }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/yara/generate', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ description, strings, family, filetype, complexity }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── YARA Rule Validator ─────────────────────────────────────────────
  h.tools(
    'validate_yara_rule',
    'Validate a YARA rule syntax. Checks for balanced braces, required sections, and proper string definitions.',
    {
      rule: z.string().describe('The YARA rule text to validate'),
    },
    async ({ rule }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/yara/validate', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rule }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── CT Domain Monitor ───────────────────────────────────────────────
  h.tools(
    'watch_domain_ct',
    'Add a domain to Certificate Transparency monitoring. Alerts on new subdomains, suspicious patterns, wildcard certs, and more. Uses crt.sh for unlimited free CT log queries.',
    {
      domain: z.string().describe('Domain to monitor (e.g., example.com)'),
      alert_types: z
        .array(z.enum(['new_subdomain', 'suspicious_name', 'wildcard', 'ca_change', 'short_validity', 'ip_cert']))
        .optional()
        .describe('Types of alerts to generate'),
    },
    async ({ domain, alert_types }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/ct-monitor/watch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ domain, alert_types }),
      });
      return untrustedToolResult(data);
    }
  );

  h.tools(
    'get_domain_certs',
    'Get recent certificates for a domain from Certificate Transparency logs. Shows new subdomains, certificate details, and any alerts.',
    {
      domain: z.string().describe('Domain to query'),
      days: z.number().optional().describe('Look back period in days (default 30)'),
      limit: z.number().optional().describe('Max results (default 100)'),
    },
    async ({ domain, days, limit }) => {
      const params = new URLSearchParams({ domain });
      if (days) params.set('days', String(days));
      if (limit) params.set('limit', String(limit));
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/ct-monitor/certs?${params}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── WHOIS History ────────────────────────────────────────────────
  h.tools(
    'get_domain_history',
    'Get the WHOIS history for a domain. Returns all historical registration snapshots, ownership changes, registrar changes, and nameserver changes over time. Essential for tracking domain ownership transfers and identifying infrastructure reuse by threat actors.',
    { domain: z.string().describe('Domain to get history for, e.g. evil-example.com') },
    async ({ domain }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/domain/history?domain=${encodeURIComponent(domain)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  h.tools(
    'pivot_domain',
    'Pivot across domains by shared registrant attributes. Find other domains owned by the same entity by matching registrant email, organization, nameservers, or registrar. Critical for mapping attacker infrastructure — if a malicious domain shares its registrant email with 50 other domains, those are likely all owned by the same threat actor.',
    {
      domain: z.string().describe('Domain to pivot from'),
      type: z
        .enum(['email', 'org', 'nameserver', 'registrar', 'all'])
        .optional()
        .describe(
          'Pivot type (default: all) — email pivots by registrant email, org by organization, nameserver by shared NS, registrar by same registrar'
        ),
    },
    async ({ domain, type }) => {
      const params = new URLSearchParams({ domain });
      if (type) params.set('type', type);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/domain/history/pivot?${params}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  h.tools(
    'search_registrant',
    'Search for all domains registered by a specific email address or organization name. Returns domains, registration dates, and snapshot counts. Useful for finding all infrastructure operated by a known threat actor.',
    {
      email: z.string().optional().describe('Registrant email to search for'),
      org: z.string().optional().describe('Registrant organization name to search for (partial match)'),
    },
    async ({ email, org }) => {
      const params = new URLSearchParams();
      if (email) params.set('email', email);
      if (org) params.set('org', org);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/domain/history/search?${params}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Phase 4b: threatintel-flavored MCP tools ────────────────────────
  // Six new tools that expose the per-report AI pipeline + the curated
  // landscape endpoints to MCP-aware clients (VS Code Copilot, Claude,
  // custom agents). All are thin wrappers over existing /api/v1 routes.

  // 1. extract_ttps — MITRE ATT&CK mapping for a free-text report.
  h.tools(
    'extract_ttps',
    'Extract MITRE ATT&CK techniques from a free-text threat report. Returns technique IDs, tactic labels, confidence (high/medium/low), and the supporting evidence string. Combines a deterministic keyword scanner with an LLM pass and merges the results.',
    {
      text: z.string().min(30).max(50_000).describe('Report text (30 chars – 50KB)'),
      use_llm: z
        .boolean()
        .optional()
        .describe('Run the LLM branch too (default true). Set false for cheap keyword-only extraction.'),
    },
    async ({ text, use_llm }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/ttp-extract', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({ text, useLlm: use_llm ?? true }),
      });
      return untrustedToolResult(data);
    }
  );

  // 2. extract_fivew — Who/What/When/Where/Why summary.
  h.tools(
    'extract_fivew',
    'Extract the classic 5W grid (who/what/when/where/why) from a free-text report. Single LLM call; returns structured JSON with a per-grid confidence score.',
    {
      text: z.string().min(100).max(50_000).describe('Report text (100 chars – 50KB)'),
    },
    async ({ text }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/fivew', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({ text }),
      });
      return untrustedToolResult(data);
    }
  );

  // 3. extract_iocs_from_image — OCR an image URL for embedded indicators.
  h.tools(
    'extract_iocs_from_image',
    'Fetch an image and run Workers AI vision over it to extract IOCs that are only visible in screenshots (IPs, domains, URLs, hashes, CVEs, emails). Returns the OCR text + the per-IOC confidence band.',
    {
      url: z.string().url().describe('HTTP(S) URL of the image to analyze (max 5MB)'),
    },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/image-ioc', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({ url }),
      });
      return untrustedToolResult(data);
    }
  );

  // 4. analyze_report — the unified per-report orchestrator.
  h.tools(
    'analyze_report',
    'Unified per-report analyzer. Runs summary + IOC extraction (with allowlist + confidence) + MITRE ATT&CK TTP mapping + 5W context + CVE extraction + image-OCR + STIX 2.1 bundle in a single round-trip. Accepts text, URL, or both; optionally takes image URLs to OCR. When format=markdown returns a TI Mindmap HUB-style rich formatted markdown report.',
    {
      text: z.string().max(80_000).optional().describe('Report text (optional if url provided)'),
      url: z.string().url().optional().describe('Report URL to fetch (optional if text provided)'),
      image_urls: z.array(z.string().url()).max(8).optional().describe('Image URLs to OCR for embedded IOCs (max 8)'),
      title: z.string().optional().describe('Display title for the report'),
      format: z
        .enum(['json', 'markdown'])
        .optional()
        .describe('Output format: json (default) or markdown for rich formatted report'),
      severity: z
        .enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
        .optional()
        .describe('Override severity classification'),
      tags: z.array(z.string()).max(8).optional().describe('Tags to include in report frontmatter'),
    },
    async ({ text, url, image_urls, title, format, severity, tags }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/report-analyzer', h.apiKey, {
        method: 'POST',
        body: JSON.stringify({
          text,
          url,
          imageUrls: image_urls,
          title,
        }),
      });
      if (format === 'markdown') {
        const result = await apiFetch<{ markdown: string }>(h.env.SELF, '/api/v1/report-analyzer/render', h.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ output: data, severity, tags }),
        });
        return { content: [{ type: 'text', text: result.markdown }] };
      }
      return untrustedToolResult(data);
    }
  );

  // 5. get_cross_report_graph — knowledge graph snapshot.
  h.tools(
    'get_cross_report_graph',
    'Cross-report knowledge-graph snapshot. Returns the top N most-referenced nodes (IOCs, actors, malware, CVEs, techniques, campaigns) across every ingested source, with the edges that connect them. Filter by node type and time window.',
    {
      types: z
        .array(z.enum(['ip', 'domain', 'hash', 'url', 'actor', 'malware', 'campaign', 'cve', 'technique']))
        .optional()
        .describe('Node types to include (default: all)'),
      days: z
        .number()
        .int()
        .min(0)
        .max(3650)
        .optional()
        .describe('Only consider nodes seen in the last N days (default 90; 0 = all)'),
      limit: z.number().int().min(10).max(1000).optional().describe('Max nodes to return (default 200, max 1000)'),
      min_conn: z.number().int().min(0).max(50).optional().describe('Minimum edge count to include a node (default 0)'),
    },
    async ({ types, days, limit, min_conn }) => {
      const params = new URLSearchParams();
      if (types && types.length > 0) params.set('types', types.join(','));
      if (days !== undefined) params.set('days', String(days));
      if (limit !== undefined) params.set('limit', String(limit));
      if (min_conn !== undefined && min_conn > 0) params.set('minConn', String(min_conn));
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/graph/cross-report?${params.toString()}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // 6. get_live_iocs — paginated, allowlist-filtered live IOC feed.
  h.tools(
    'get_live_iocs',
    'Get the most recent live IOCs aggregated from 12+ providers (URLhaus, ThreatFox, AlienVault OTX, SANS ISC, etc). Items are normalized, allowlist-filtered (RFC 5737, vendor docs), and confidence-scored. Supports filtering by IOC kind.',
    {
      kind: z.enum(['ip', 'url', 'domain', 'hash']).optional().describe('Filter to a single IOC kind'),
      limit: z.number().int().min(1).max(500).optional().describe('Max items to return (default 50)'),
    },
    async ({ kind, limit }) => {
      const params = new URLSearchParams();
      if (kind) params.set('kind', kind);
      if (limit) params.set('limit', String(limit));
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/live-iocs?${params.toString()}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  // ── KQL → Defender XDR Advanced Hunting deep link (no ASSETS needed) ──
  h.tools(
    'si_kql_to_ah_url',
    'Encode a KQL query into a Defender XDR Advanced Hunting deep link. Mirrors upstream kql_to_ah_url.py: UTF-16LE → GZip → Base64url. Optionally append &tid=<tenant_id> for cross-tenant linking. Returns the URL.',
    {
      kql: z
        .string()
        .describe(
          'KQL query string, e.g. "DeviceInfo | where Timestamp > ago(7d) | take 10". Newlines are normalized to CRLF automatically.'
        ),
      tenant_id: z.string().optional().describe('Azure AD tenant GUID. Omit to produce a tenant-agnostic link.'),
      markdown: z
        .boolean()
        .optional()
        .describe(
          'If true, return as a markdown link "[Run in Advanced Hunting](<url>)" ready to paste into a report.'
        ),
    },
    async ({ kql, tenant_id, markdown }) => {
      try {
        const url = await kqlToAhUrl(kql, tenant_id ? { tenantId: tenant_id } : {});
        if (markdown) {
          return untrustedToolResult({ url, markdown: await kqlToAhUrlMarkdown(kql, { tenantId: tenant_id }) });
        }
        return untrustedToolResult({ url, kqlBytes: kql.length, encodedBytes: url.length - 50 });
      } catch (e) {
        console.error('handler failed:', errMessage(e));
        return untrustedToolResult({ error: 'encode_failed', message: errMessage(e) });
      }
    }
  );
}
