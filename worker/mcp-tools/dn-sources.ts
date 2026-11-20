/**
 * dn-sources MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { apiFetch, untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

export function registerDnSourcesTools(h: McpToolHost): void {
  // ── GreyNoise (free community tier) ──────────────────────────────
  h.tools(
    'dn_greynoise_ip',
    'Look up an IP on GreyNoise Community: classification (benign/malicious/unknown), internet scanner detection, ASN, country. Free, no API key required.',
    { ip: z.string().describe('IPv4 address to look up') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/greynoise/ip?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Pulsedive (free, optional key) ───────────────────────────────
  h.tools(
    'dn_pulsedive_indicator',
    'Look up an indicator (IP, domain, URL, or hash) on Pulsedive: risk level, threats, feeds, and linked indicators. Free, no key required.',
    {
      type: z.enum(['ip', 'domain', 'url', 'hash']).describe('Indicator type'),
      value: z.string().describe('Indicator value'),
    },
    async ({ type, value }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/pulsedive/indicator?type=${type}&value=${encodeURIComponent(value)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_pulsedive_search',
    'Search Pulsedive indicators by value. Returns matching indicators with risk levels. Free, no key.',
    { q: z.string().describe('Search term') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/pulsedive/search?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_pulsedive_explore',
    'Explore linked indicators using Pulsedive advanced queries. Returns related IOCs with risk levels. Free, no key.',
    { indicator: z.string().describe('Indicator to explore from (IP, domain, URL, or hash)') },
    async ({ indicator }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/pulsedive/explore?indicator=${encodeURIComponent(indicator)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Vulners (free, optional key for search) ──────────────────────
  h.tools(
    'dn_vulners_id',
    'Look up a vulnerability by ID (CVE, EDB, GHSA) on Vulners. Returns CVSS, description, affected products, and exploit availability. Free, no key.',
    { id: z.string().describe('Vulnerability ID (e.g. CVE-2024-3094, EDB-12345)') },
    async ({ id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/vulners/id?id=${encodeURIComponent(id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_vulners_search',
    'Search the Vulners vulnerability database using Lucene queries. Returns matching CVEs/exploits with CVSS scores. Free.',
    {
      query: z.string().describe('Lucene search query'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 20)'),
    },
    async ({ query, limit }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/vulners/search',
        h.apiKey,
        {
          method: 'POST',
          body: JSON.stringify({ query, limit }),
        }
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_vulners_exploit',
    'Search specifically for exploits (ExploitDB entries) on Vulners. Returns exploit code references and details. Free.',
    {
      query: z.string().describe('Search query (CVE, keyword, or product name)'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 20)'),
    },
    async ({ query, limit }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/vulners/exploit',
        h.apiKey,
        {
          method: 'POST',
          body: JSON.stringify({ query, limit }),
        }
      );
      return untrustedToolResult(data);
    }
  );

  // ── AbuseIPDB (key required) ─────────────────────────────────────
  h.tools(
    'dn_abuseipdb_check',
    'Check an IP address on AbuseIPDB for abuse reports: confidence score, ISP, country, report count, categories. Requires ABUSEIPDB_API_KEY.',
    { ip: z.string().describe('IPv4 address to check') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abuseipdb/check?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_abuseipdb_reports',
    'Get individual abuse reports for an IP from AbuseIPDB with detailed comments and categories. Requires ABUSEIPDB_API_KEY.',
    { ip: z.string().describe('IPv4 address') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abuseipdb/reports?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_abuseipdb_blacklist',
    'Get AbuseIPDB blacklist of the most reported malicious IP addresses. Requires ABUSEIPDB_API_KEY.',
    {
      confidence: z.string().optional().describe('Minimum confidence score (default 90)'),
      limit: z.string().optional().describe('Max entries (default 10000)'),
    },
    async ({ confidence, limit }) => {
      const params = new URLSearchParams();
      if (confidence) params.set('confidence', confidence);
      if (limit) params.set('limit', limit);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abuseipdb/blacklist${params.toString() ? `?${params}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_abuseipdb_check_block',
    'Check an entire CIDR network block for abuse reports on AbuseIPDB. Requires ABUSEIPDB_API_KEY.',
    { network: z.string().describe('CIDR block (e.g. "118.208.0.0/16")') },
    async ({ network }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abuseipdb/check-block?network=${encodeURIComponent(network)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Deep Ransomware Intelligence (free) ──────────────────────────
  h.tools(
    'dn_ransomware_victims',
    'Get all victims claimed by a specific ransomware group from ransomware.live. Free, no key.',
    { name: z.string().describe('Ransomware group name') },
    async ({ name }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/ransomware/victims?name=${encodeURIComponent(name)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_ransomware_search',
    'Search ransomware victims by keyword (company name, domain, etc.) across ransomware.live. Free, no key.',
    { q: z.string().describe('Search keyword') },
    async ({ q }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/ransomware/search?q=${encodeURIComponent(q)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_ransomware_country',
    'Get ransomware victims filtered by ISO 3166-1 alpha-2 country code from ransomware.live. Free, no key.',
    { code: z.string().describe('ISO 3166-1 alpha-2 country code (e.g. "US", "GB", "DE")') },
    async ({ code }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/ransomware/country?code=${encodeURIComponent(code)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_ransomware_sector',
    'Get ransomware victims filtered by sector/industry from ransomware.live. Free, no key.',
    { sector: z.string().describe('Sector name (e.g. "healthcare", "finance", "education")') },
    async ({ sector }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/ransomware/sector?sector=${encodeURIComponent(sector)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_ransomlook_groups',
    'List all ransomware groups tracked by RansomLook (582+). Free, no key.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/ransomware/ransomlook-groups',
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_ransomlook_recent',
    'Fetch the most recent ransomware posts and victim claims from RansomLook. Free, no key.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/ransomware/ransomlook-recent',
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Deep HIBP Breach Intelligence ────────────────────────────────
  h.tools(
    'dn_hibp_breach',
    'Get details of a specific data breach by name from HIBP: description, data classes, pwn count, breach date. Free, no key.',
    { name: z.string().describe('Breach name (e.g. "Adobe", "LinkedIn", "Collection1")') },
    async ({ name }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/hibp/breach?name=${encodeURIComponent(name)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools('dn_hibp_latest', 'Get the most recently added data breaches from HIBP. Free, no key.', {}, async () => {
    const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/darknet-intel/hibp/latest', h.apiKey);
    return untrustedToolResult(data);
  });
  h.tools(
    'dn_hibp_data_classes',
    'List all data classes (types of compromised data) known to HIBP: emails, passwords, credit cards, SSNs, etc. Free, no key.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/hibp/data-classes',
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_hibp_password',
    'Check if a password has appeared in known breaches using HIBP k-anonymity (only SHA-1 prefix sent). Returns breach count. Free, no key.',
    { password: z.string().describe('Password to check') },
    async ({ password }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/hibp/password?password=${encodeURIComponent(password)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Deep abuse.ch (ThreatFox, URLhaus, MalwareBazaar — free) ────
  h.tools(
    'dn_threatfox_iocs',
    'Get recent IOCs from ThreatFox reported in the last N days. Free, no key.',
    { days: z.number().int().min(1).max(30).optional().describe('Days to look back (default 3, max 30)') },
    async ({ days }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abusech/threatfox-iocs?days=${days ?? 3}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_threatfox_tag',
    'Search ThreatFox IOCs by tag (e.g. Cobalt Strike, Emotet, AgentTesla). Free, no key.',
    {
      tag: z.string().describe('Tag name'),
      limit: z.number().int().min(1).max(500).optional().describe('Max results (default 50)'),
    },
    async ({ tag, limit }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abusech/threatfox-tag?tag=${encodeURIComponent(tag)}${limit ? `&limit=${limit}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_urlhaus_lookup',
    'Look up a URL or host in URLhaus for malware distribution. Free, no key.',
    {
      url: z.string().optional().describe('URL to look up'),
      host: z.string().optional().describe('Host to look up'),
    },
    async ({ url, host }) => {
      const params = new URLSearchParams();
      if (url) params.set('url', url);
      if (host) params.set('host', host);
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abusech/urlhaus?${params}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_urlhaus_tag',
    'Search URLhaus entries by tag. Free, no key.',
    { tag: z.string().describe('Tag name') },
    async ({ tag }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abusech/urlhaus-tag?tag=${encodeURIComponent(tag)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_bazaar_hash',
    'Look up a malware sample in MalwareBazaar by MD5, SHA1, or SHA256 hash. Returns tags, signature, file type, first/last seen. Free, no key.',
    { hash: z.string().describe('MD5, SHA1, or SHA256 hash') },
    async ({ hash }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/abusech/bazaar-hash?hash=${encodeURIComponent(hash)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_bazaar_recent',
    'Get the most recently submitted malware samples from MalwareBazaar (last 100). Free, no key.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        '/api/v1/darknet-intel/abusech/bazaar-recent',
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Deep AlienVault OTX (free, optional key) ────────────────────
  h.tools(
    'dn_otx_ip',
    'Look up threat intelligence for an IP address on AlienVault OTX: pulse info, reputation, country, ASN, associated malware. Free, no key.',
    { ip: z.string().describe('IPv4 address') },
    async ({ ip }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/otx/ip?ip=${encodeURIComponent(ip)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_otx_domain',
    'Look up threat intelligence for a domain on AlienVault OTX: pulse info, WHOIS, reputation, associated malware. Free, no key.',
    { domain: z.string().describe('Domain name') },
    async ({ domain }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/otx/domain?domain=${encodeURIComponent(domain)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_otx_hash',
    'Look up threat intelligence for a file hash (MD5, SHA1, SHA256) on AlienVault OTX. Free, no key.',
    { hash: z.string().describe('File hash (MD5, SHA1, or SHA256)') },
    async ({ hash }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/otx/hash?hash=${encodeURIComponent(hash)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_otx_cve',
    'Look up threat intelligence for a CVE on AlienVault OTX: related pulses, indicators, and exploitation activity. Free, no key.',
    { cve: z.string().describe('CVE ID (e.g. "CVE-2024-3094")') },
    async ({ cve }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/otx/cve?cve=${encodeURIComponent(cve)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Hybrid Analysis (key required) ───────────────────────────────
  h.tools(
    'dn_hybrid_search',
    'Search Hybrid Analysis sandbox by file hash: verdict, AV detection rate, MITRE ATT&CK techniques, network indicators. Requires HYBRID_ANALYSIS_API_KEY.',
    { hash: z.string().describe('File hash (MD5, SHA1, or SHA256)') },
    async ({ hash }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/darknet-intel/hybrid/search?hash=${encodeURIComponent(hash)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'dn_hybrid_feed',
    'Get the latest malware detonation feed from Hybrid Analysis: recently analyzed samples with verdicts and threat scores. Requires HYBRID_ANALYSIS_API_KEY.',
    {},
    async () => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/darknet-intel/hybrid/feed', h.apiKey);
      return untrustedToolResult(data);
    }
  );
}
