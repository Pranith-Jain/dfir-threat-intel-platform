/**
 * telegram-darknet-agent MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { apiFetch, untrustedToolResult } from './core';
import { signInternalToken } from '../../api/src/lib/internal-token';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import {
  btcAbuseCheck,
  onionLookup,
  torExitCheck,
  torExitDetails,
  torExitNodes,
  torScrapeOnion,
  torSearchOnion,
  torStatus,
} from '../lib/darknet';
export function registerTelegramDarknetAgentTools(h: McpToolHost): void {
  // ── Dark Web: Tor Network ──────────────────────────────────────────────
  h.tools(
    'tor_status',
    'Check the dark web access gateway status. Uses public tor2web gateways to reach .onion sites (no local Tor daemon required). Returns available gateways and method info.',
    {},
    async () => {
      const r = await torStatus();
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'tor_scrape_onion',
    'Fetch and parse a .onion site via tor2web gateway. Returns structured data: title, links, body text, status code. Useful for extracting content from dark web sites.',
    {
      url: z
        .string()
        .describe('Full .onion URL, e.g. http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion/'),
      gateway: z
        .number()
        .int()
        .min(0)
        .max(3)
        .optional()
        .describe('Tor2Web gateway index (0=tor2web.io, 1=onion.ws, 2=onion.sh, 3=tor2web.org). Default: 0.'),
    },
    async ({ url, gateway }) => {
      const r = await torScrapeOnion(url, gateway ?? 0);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'tor_search_onion',
    'Search for .onion sites using the Ahmia.fi search engine. Returns matching pages with title, URL, and description. Note: Ahmia selectively indexes .onion sites; not all dark web content is discoverable.',
    {
      q: z.string().describe('Search query, e.g. "marketplace", "breach", "company-name"'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default: 20)'),
    },
    async ({ q, limit }) => {
      const r = await torSearchOnion(q, limit ?? 20);
      return untrustedToolResult({ query: q, count: r.length, results: r });
    }
  );

  h.tools(
    'tor_exit_nodes',
    'Get current Tor exit node IP addresses from the official Tor Project bulk exit list. Useful for identifying if traffic originates from the Tor network.',
    {
      limit: z.number().int().min(1).max(10000).optional().describe('Max IPs to return (default: all)'),
    },
    async ({ limit }) => {
      const ips = await torExitNodes(limit);
      return untrustedToolResult({ count: ips.length, ips });
    }
  );

  h.tools(
    'tor_exit_check',
    'Check if a specific IP address is a known Tor exit node. Returns boolean and the queried IP.',
    {
      ip: z.string().describe('IPv4 or IPv6 address to check'),
    },
    async ({ ip }) => {
      const r = await torExitCheck(ip);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'tor_exit_details',
    'Get detailed Tor exit node information including fingerprints, published timestamps, and exit addresses. More comprehensive than the bulk exit list.',
    {
      limit: z.number().int().min(1).max(5000).optional().describe('Max entries to return (default: all)'),
    },
    async ({ limit }) => {
      const r = await torExitDetails(limit);
      return untrustedToolResult({ count: r.length, exits: r });
    }
  );

  // ── Dark Web: CIRCL Onion Lookup ──────────────────────────────────────
  h.tools(
    'onion_lookup',
    'Look up metadata for a .onion address via the CIRCL AIL Project. Returns first/last seen dates, status, tags, PGP keys, certificates, open ports, page title, and associated Bitcoin addresses. No API key required.',
    {
      address: z
        .string()
        .describe('.onion address to look up, e.g. "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"'),
    },
    async ({ address }) => {
      const r = await onionLookup(address);
      return untrustedToolResult(r);
    }
  );

  // ── Dark Web: BTC Abuse Check ─────────────────────────────────────────
  h.tools(
    'btc_abuse_check',
    'Check a Bitcoin address for abuse/scam reports on ChainAbuse. Returns the `verdict` field, which is authoritative: "flagged" means abuse reports exist, "clean" means the lookup completed and found none, and "unknown" means the lookup did NOT complete (missing CHAINABUSE_API_KEY or upstream error) — an "unknown" verdict is NOT evidence of a clean address and must not be reported as such. On "flagged", reports include categories (phishing, ransomware, scam, etc.), descriptions, and associated scam types. Useful for tracing illicit crypto transactions.',
    {
      address: z.string().describe('Bitcoin address to check, e.g. "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"'),
    },
    async ({ address }) => {
      const r = await btcAbuseCheck(address, h.env.CHAINABUSE_API_KEY);
      return untrustedToolResult(r);
    }
  );

  // ── Phone OSINT ──────────────────────────────────────────────────────
  h.tools(
    'phone_osint',
    'Investigate a phone number — E.164 parsing, carrier/line-type detection, country lookup, messaging platform checks (WhatsApp/Telegram), breach exposure, and Google dorks. Returns structured JSON with parsed phone details, lookup URLs, and security flags.',
    {
      phone: z
        .string()
        .describe('Phone number in E.164 (+15551234567), local (5551234567), or formatted ((555) 123-4567) format'),
    },
    async ({ phone }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/phone-osint?phone=${encodeURIComponent(phone)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Reverse Image Search ─────────────────────────────────────────────
  h.tools(
    'reverse_image_search',
    'Generate reverse image search URLs across 8+ engines (Google Lens, Yandex, TinEye, Bing, Baidu, SauceNAO, IQDB, KarmaDecay). Validates image reachability and returns categorized deep links for manual investigation.',
    {
      url: z.string().describe('Image URL to search for across reverse image engines'),
    },
    async ({ url }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/reverse-image-search?url=${encodeURIComponent(url)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Wi-Fi / BSSID Investigation ──────────────────────────────────────
  h.tools(
    'wifi_investigation',
    'Investigate a wireless network by BSSID (MAC address) or SSID (network name). Returns OUI vendor lookup, MAC bit analysis (privacy/multicast), default SSID detection, WiGLE.net links, and security flags for rogue AP detection.',
    {
      bssid: z.string().optional().describe('BSSID/MAC address, e.g. "AA:BB:CC:DD:EE:FF"'),
      ssid: z.string().optional().describe('SSID/network name, e.g. "MyWiFi"'),
    },
    async ({ bssid, ssid }) => {
      const param = bssid ? `bssid=${encodeURIComponent(bssid)}` : `ssid=${encodeURIComponent(ssid ?? '')}`;
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, `/api/v1/wifi-investigation?${param}`, h.apiKey);
      return untrustedToolResult(data);
    }
  );

  // ── Tie-Agent: IOC enrichment agent (cookbook pattern) ──────────
  h.tools(
    'si_enrich_agent',
    "Enrich a single IOC (IP/hash/domain/URL) using the Threat Intel Enrichment Agent. Runs a multi-step autonomous investigation across 30+ providers (VirusTotal, AbuseIPDB, Shodan, PhantomCandle, Malpedia, etc.), extracts MITRE ATT&CK TTPs, and returns a structured threat assessment with per-provider diagnostics. For deep analysis, set 'deep: true' to run the full multi-step chain with report generation (takes 10-30s).",
    {
      ioc: z.string().describe('The indicator to enrich — IPv4, IPv6, file hash (MD5/SHA1/SHA256), domain, or URL.'),
      ioc_type: z
        .enum(['ip', 'hash', 'domain', 'url'])
        .describe(
          'Type of the indicator (ip, hash, domain, or url). Auto-detection is not supported; specify explicitly.'
        ),
      deep: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          'When true, runs the multi-step autonomous investigator agent (3-5 steps, synthesizes a full report with QA). Takes 10-30s. When false (default), runs a fast deterministic enrichment (< 1s).'
        ),
    },
    async ({ ioc, ioc_type, deep }) => {
      if (deep) {
        // Deep mode: trigger the autonomous investigator DO
        const agentNs = h.env.INVESTIGATOR_AGENT;
        if (!agentNs) {
          return untrustedToolResult({ error: 'unavailable', detail: 'INVESTIGATOR_AGENT Durable Object not bound' });
        }
        const id = crypto.randomUUID();
        const doId = agentNs.idFromName(id);
        const stub = agentNs.get(doId);
        const prompt = `Enrich this IOC: ${ioc} (type: ${ioc_type}). Investigate thoroughly — check reputation across multiple providers, map to known malware/actors if applicable, extract MITRE ATT&CK techniques, and assess overall risk. Return a structured threat assessment with an executive summary, key findings, risk score, and recommended actions.`;
        await stub.fetch('https://agent/investigate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id, query: prompt, queryType: ioc_type, maxSteps: 4 }),
        });

        // Poll up to 30s for the result (20 polls × 1.5s stays within subrequest budget)
        for (let i = 0; i < 20; i++) {
          await new Promise((r) => setTimeout(r, 1500));
          const stateRes = await stub.fetch(`https://agent/state?id=${encodeURIComponent(id)}`);
          if (!stateRes.ok) break;
          const state = (await stateRes.json()) as {
            status: string;
            report?: string;
            steps?: unknown[];
            error?: string;
          };
          if (state.status === 'done') {
            return untrustedToolResult({ report: state.report ?? null, status: 'done' });
          }
          if (state.status === 'error') {
            return untrustedToolResult({ error: state.error ?? 'unknown', status: 'error' });
          }
        }
        return untrustedToolResult({ error: 'timeout', status: 'error' });
      }

      // Fast path: deterministic enrichment via SELF
      const self = h.env.SELF;
      if (!self) {
        return untrustedToolResult({ error: 'unavailable', detail: 'SELF service binding not available' });
      }
      const { enrichIoc } = await import('../lib/tie-enrich');
      const secret = h.env.INTERNAL_TOKEN_SECRET;
      const internalToken = secret ? await signInternalToken('tie-enrich', secret) : undefined;
      const result = await enrichIoc(self, ioc, ioc_type, internalToken);
      return untrustedToolResult(result);
    }
  );

  // ── NL → STIX Translation ─────────────────────────────────────────
  h.tools(
    'stix_translate',
    'Translate a natural language threat intelligence question into structured STIX 2.1 query parameters. Given plain English, returns the classified intent, extracted entities, and filter parameters to use with stix_query_bundles. Supports actors, malware, CVEs, sectors, countries, campaigns, time ranges, and strategic queries.',
    {
      query: z
        .string()
        .describe(
          'Natural language threat intelligence question, e.g. "What is APT29 doing in healthcare?" or "Show me ransomware targeting finance this week"'
        ),
    },
    async ({ query }) => {
      const { translateQuery } = await import('../../api/src/lib/agent/stix-translator');
      const result = translateQuery(query);
      return untrustedToolResult(result);
    }
  );

  // ── STIX Bundle Query (PostgREST-style) ───────────────────────────
  h.tools(
    'stix_query_bundles',
    'Query the STIX 2.1 intelligence bundle store with PostgREST-style filters. Returns threat intelligence bundles matching your criteria. Use stix_translate first to convert natural language to structured filter parameters. Supports filters: source_type (eq.osint/eq.darknet), threat_actors (cs.{APT29}), malware_names, sectors, countries_target, vulnerabilities, date ranges (stix_published_at=gte.), and more. Supports select, order, limit, offset.',
    {
      select: z
        .string()
        .optional()
        .describe(
          'Comma-separated columns: bundle_id,source_type,threat_actors,malware_names,sectors,countries_target,vulnerabilities,title,stix_published_at,api_created_at'
        ),
      threat_actors: z
        .string()
        .optional()
        .describe('Array contains filter, e.g. cs.{APT29} or cs.{Lazarus Group,APT38}'),
      malware_names: z.string().optional().describe('Array contains filter, e.g. cs.{Emotet} or cs.{Trickbot,LockBit}'),
      sectors: z
        .string()
        .optional()
        .describe('Array contains filter for target sectors, e.g. cs.{Healthcare} or cs.{Finance,Government}'),
      countries_target: z.string().optional().describe('Array contains filter for target countries, e.g. cs.{Germany}'),
      vulnerabilities: z.string().optional().describe('Array contains filter for CVE IDs, e.g. cs.{CVE-2024-3094}'),
      source_type: z.string().optional().describe('Source type filter, e.g. eq.osint or eq.darknet'),
      stix_published_at: z.string().optional().describe('Date filter, e.g. gte.2026-01-01T00:00:00Z'),
      order: z.string().optional().describe('Sort order, e.g. stix_published_at.desc or api_created_at.desc'),
      limit: z.string().optional().describe('Max rows (default 50)'),
      offset: z.string().optional().describe('Row offset for pagination'),
    },
    async (args) => {
      const qp = new URLSearchParams();
      for (const [k, v] of Object.entries(args)) {
        if (v !== undefined && v !== '') qp.set(k, v);
      }
      const qs = qp.toString();
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/stix_bundles${qs ? `?${qs}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Actionable IOCs Query (PostgREST-style) ───────────────────────
  h.tools(
    'stix_query_iocs',
    'Query the threat intelligence IOC store with PostgREST-style filters. Returns indicators of compromise with their type, validity period, and source bundle reference. Supports filtering by ioc_type (eq.ipv4, eq.domain, eq.hash_sha256), date ranges, and source. Also supports per-type active IOC queries via ioc_type filter. Use seq_id for incremental sync.',
    {
      select: z
        .string()
        .optional()
        .describe('Comma-separated columns: ioc_value,ioc_type,valid_until,source_bundle_id,seq_id,created_at'),
      ioc_type: z
        .string()
        .optional()
        .describe(
          'IOC type filter, e.g. eq.ipv4, eq.ipv6, eq.domain, eq.url, eq.hash_md5, eq.hash_sha1, eq.hash_sha256'
        ),
      valid_until: z.string().optional().describe('Validity filter, e.g. gt.now() for active only, or gte.2026-01-01'),
      seq_id: z.string().optional().describe('Sequence ID filter for incremental sync, e.g. gt.12345'),
      ioc_value: z.string().optional().describe('Exact IOC value lookup, e.g. eq.203.0.113.42'),
      order: z.string().optional().describe('Sort order, e.g. seq_id.asc, valid_until.desc, created_at.desc'),
      limit: z.string().optional().describe('Max rows (default 50)'),
      offset: z.string().optional().describe('Row offset for pagination'),
    },
    async (args) => {
      const qp = new URLSearchParams();
      for (const [k, v] of Object.entries(args)) {
        if (v !== undefined && v !== '') qp.set(k, v);
      }
      const qs = qp.toString();
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/actionable_iocs${qs ? `?${qs}` : ''}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── List available analyst roles ──────────────────────────────────

  // ══════════════════════════════════════════════════════════════════
  // DARKNET INTEL TOOLS — GreyNoise, Pulsedive, Vulners, IntelX,
  // AbuseIPDB, deep ransomware, HIBP, abuse.ch, OTX, Hybrid Analysis
  // ══════════════════════════════════════════════════════════════════
}
