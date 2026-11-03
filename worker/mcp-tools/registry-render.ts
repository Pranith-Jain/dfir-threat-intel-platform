/**
 * registry-render MCP tool registrations.
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

import { apiFetch, untrustedToolResult, computeConfidence, buildTags, buildDescription } from './core';
import { buildStixBundle } from '../lib/cti-ioc-export';
import type { StixIndicator } from '../lib/cti-ioc-export';
import { cerastSearch } from '../lib/cerast';
import { dehashLookup } from '../lib/dehash';
import { enrichIp, enrichIpsBatch, isValidIp } from '../lib/si-enrich';
import { fbiWantedList, fbiWantedSearch } from '../lib/fbi-wanted';
import { fullhuntDomainDetails, fullhuntSubdomains } from '../lib/fullhunt';
import { getTool, listTools, loadToolsIndex } from '../lib/tools-manifest';
import type { ToolCategory } from '../lib/tools-manifest';
import { intelxPhonebook, intelxSearch } from '../lib/intelx';
import { interpolNoticeDetail, interpolSearch } from '../lib/interpol';
import { mozillaTlsScan } from '../lib/mozilla-tls';
import { opencveGetCve } from '../lib/opencve';
import { opensanctionsEntity, opensanctionsSearch, opensanctionsStats } from '../lib/opensanctions';
import { threatmonInfostealerSearch } from '../lib/threatmon-infostealer';
import { traceixLookup } from '../lib/traceix';
import { truecallerLookup } from '../lib/truecaller';
import { virusheeCheck } from '../lib/virushee';
import { whoxyReverseWhois } from '../lib/whoxy';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import {
  catalogSummary as nhiCatalog,
  parseFleet as nhiParseFleet,
  reportToJson as nhiReportJson,
  reportToMarkdown as nhiReportMarkdown,
  scan as nhiScanFleet,
} from '../../api/src/lib/nhi-scan';
import {
  getCampaignIntel as webamonGetCampaignIntel,
  getCampaignStats as webamonGetCampaignStats,
  listCampaigns as webamonListCampaigns,
  listChanges as webamonListChanges,
  listClusters as webamonListClusters,
} from '../../api/src/lib/webamon-campaigns';
import { getDoc, getRef, getRoutingPrompt, getSiSkill, loadDocsIndex } from '../lib/si-manifest';
import type { WebamonClusterSeverity } from '../lib/webamon-campaigns';
export function registerRegistryRenderTools(h: McpToolHost): void {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── Tools Directory ───────────────────────────────────────────
  // Curated catalog of 50+ offensive and defensive security tools
  // with filtering by category, keyword, and offensive/defensive scope.

  h.tools(
    'tools_list',
    'List security tools from the curated Tools Directory. Filter by category (recon, exploitation, post-exploitation, defense, detection, forensics, osint, c2, phishing, crypto, mobile, cloud, network, reverse-engineering, web, misc), keyword, or offensive/defensive scope.',
    {
      category: z
        .enum([
          'recon',
          'exploitation',
          'post-exploitation',
          'defense',
          'detection',
          'forensics',
          'osint',
          'c2',
          'phishing',
          'crypto',
          'mobile',
          'cloud',
          'network',
          'reverse-engineering',
          'web',
          'misc',
        ])
        .optional()
        .describe('Filter by tool category'),
      keyword: z.string().optional().describe('Search keyword in name/description/tags'),
      offensive: z.boolean().optional().describe('Filter by offensive tools (true) or defensive (false)'),
      limit: z.number().int().min(1).max(200).optional().describe('Max results (default 50)'),
    },
    async ({ category, keyword, offensive, limit }) => {
      const idx = await loadToolsIndex(ASSETS).catch(() => null);
      if (!idx) return untrustedToolResult({ error: 'tools index not loaded' });
      const results = listTools(idx, {
        category: category as ToolCategory | undefined,
        keyword,
        offensive,
        limit: limit ?? 50,
      });
      return untrustedToolResult({ count: results.length, tools: results });
    }
  );

  h.tools(
    'tools_get',
    'Get the full profile for a specific security tool by slug.',
    {
      slug: z.string().describe('Tool slug (e.g. "amass", "volatility", "metasploit")'),
    },
    async ({ slug }) => {
      const body = await getTool(ASSETS, slug);
      if (!body) return untrustedToolResult({ error: 'tool_not_found', slug });
      return untrustedToolResult(body);
    }
  );

  // ── R2 SVG dashboard renderer ─────────────────────────────────
  // Returns the SVG widget manifest for a skill (the YAML body
  // embedded in the skill JSON), plus a reference to the
  // svg-dashboard skill's component library. Clients render the
  // SVG client-side using the widget library + the manifest.
  h.tools(
    'si_render_svg_dashboard',
    'Return the SVG widget manifest (YAML) for a skill that ships one (14 of 25 skills do). The manifest declares canvas, palette, and a list of widget instances to render. Pair with si_get_skill({slug: "svg-dashboard"}) for the component-library reference. Returns {hasManifest:false,...} if the skill has no SVG manifest.',
    {
      slug: z.string().describe('Skill slug, e.g. "threat-pulse", "mitre-coverage-report".'),
    },
    async ({ slug }) => {
      const skill = await getSiSkill(ASSETS, slug);
      if (!skill) {
        return untrustedToolResult({ error: 'skill_not_found', slug });
      }
      const yaml = (skill as unknown as Record<string, unknown>).svgWidgetsYaml as string | undefined;
      return untrustedToolResult({
        slug,
        hasManifest: !!yaml,
        manifestYaml: yaml ?? null,
        manifestSizeBytes: yaml ? yaml.length : 0,
        hint: yaml
          ? 'Parse manifestYaml client-side and render widgets per the svg-dashboard skill component library.'
          : 'This skill does not ship an SVG manifest. Use the freeform mode of svg-dashboard with ad-hoc data.',
      });
    }
  );

  // ── R3 Knowledge base: 10 deep-dive docs ──────────────────────
  h.tools(
    'si_list_docs',
    'List the 10 deep-dive knowledge-base docs from the upstream repo (Sentinel Exposure Graph guide, signinlog anomalies KQL cookbook, identity protection, honeypot investigation, ingestion cost best practices, etc). Each is a long-form markdown guide.',
    {},
    async () => {
      const idx = await loadDocsIndex(ASSETS);
      return untrustedToolResult(idx);
    }
  );

  h.tools(
    'si_get_doc',
    'Return the full markdown body of a single knowledge-base doc. Get slugs from si_list_docs.',
    {
      slug: z
        .string()
        .describe(
          'Doc slug, e.g. "sentinel-exposure-graph-mcp-guide", "signinlogs_anomalies_kql_cl", "identity_protection".'
        ),
    },
    async ({ slug }) => {
      const doc = await getDoc(ASSETS, slug);
      if (!doc) {
        return untrustedToolResult({
          error: 'doc_not_found',
          slug,
          hint: 'Call si_list_docs to see available slugs.',
        });
      }
      return untrustedToolResult(doc);
    }
  );

  // ── R4 Routing prompt (copilot-instructions.md) ───────────────
  h.tools(
    'si_get_routing_prompt',
    'Return the upstream .github/copilot-instructions.md verbatim — the universal skill-detection / routing prompt. Clients should load this once at session start to learn how to map natural language to the right si_* tool. ~91 KB.',
    {},
    async () => {
      const text = await getRoutingPrompt(ASSETS);
      return untrustedToolResult({
        source: 'github.com/SCStelz/security-investigator/.github/copilot-instructions.md',
        license: 'MIT',
        bytes: text.length,
        promptMarkdown: text,
        usage:
          "Inject this into the client's system prompt at session start. It contains the skill-detection logic that maps user natural language to si_* tool calls.",
      });
    }
  );

  // ── R5 Reference data: MITRE catalog + known KQL tables + M365 coverage ─
  h.tools(
    'si_list_ref',
    'List the reference datasets available via si_get_ref: MITRE ATT&CK enterprise catalog, known KQL tables for the M365 platform, M365 platform coverage matrix, and the 11 Sentinel ingestion-scan query schemas.',
    {},
    async () => {
      // We don't have a separate ref-index, so we probe by trying each known filename.
      const known = [
        'mitre-attck-enterprise',
        'known-kql-tables',
        'm365-platform-coverage',
        'ingestion-q2',
        'ingestion-q6a',
        'ingestion-q6b',
        'ingestion-q6c',
        'ingestion-q9',
        'ingestion-q9b',
        'ingestion-q10',
        'ingestion-q12',
        'ingestion-q13',
        'ingestion-q16',
        'ingestion-q17',
      ];
      const found: Array<{ name: string; bytes: number }> = [];
      for (const name of known) {
        const v = await getRef<unknown>(ASSETS, name);
        if (v !== null) {
          const json = JSON.stringify(v);
          found.push({ name, bytes: json.length });
        }
      }
      return untrustedToolResult({
        source: 'github.com/SCStelz/security-investigator/.github/skills/',
        license: 'MIT',
        count: found.length,
        refs: found,
      });
    }
  );

  h.tools(
    'si_get_ref',
    'Return a reference dataset by name. Get names from si_list_ref. Common: mitre-attck-enterprise (MITRE ATT&CK enterprise matrix, ~32 KB), known-kql-tables (M365 Defender table inventory, ~17 KB), m365-platform-coverage (coverage map, ~16 KB), ingestion-qN (Sentinel ingestion-scan query result schemas).',
    {
      name: z
        .string()
        .describe(
          'Reference dataset name without .json, e.g. "mitre-attck-enterprise", "known-kql-tables", "m365-platform-coverage", "ingestion-q9".'
        ),
    },
    async ({ name }) => {
      const v = await getRef<unknown>(ASSETS, name);
      if (v === null) {
        return untrustedToolResult({
          error: 'ref_not_found',
          name,
          hint: 'Call si_list_ref to see available datasets.',
        });
      }
      return untrustedToolResult({
        name,
        data: v,
        bytes: JSON.stringify(v).length,
      });
    }
  );

  // ── IP enrichment (ported from upstream enrich_ips.py) ──────
  // Hits existing platform providers through env.SELF (in-process,
  // no public internet hop). Mirrors the enrich_ips.py output
  // shape so upstream clients (and Python notebooks) get the same
  // record layout.
  h.tools(
    'si_enrich_ip',
    "Enrich a single IPv4/IPv6 address using the platform's IPinfo / AbuseIPDB / Shodan / Shodan-InternetDB / VPNAPI providers. Returns the same shape as upstream security-investigator/enrich_ips.py. Use si_enrich_ip_batch for up to 25 IPs in one call.",
    {
      ip: z.string().describe('IPv4 or IPv6 address, e.g. "203.0.113.42" or "2001:db8::1".'),
    },
    async ({ ip }) => {
      if (!isValidIp(ip)) {
        return untrustedToolResult({ error: 'invalid_ip', ip, hint: 'Pass a valid IPv4 or IPv6 address.' });
      }
      const r = await enrichIp(h.env as unknown as Parameters<typeof enrichIp>[0], ip);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'si_enrich_ip_batch',
    'Enrich up to 25 IP addresses in one call. Returns an array of the same shape as si_enrich_ip. Order is preserved. IPs that fail validation are returned with a single "validator:failed" diagnostic and empty enrichment fields.',
    {
      ips: z.array(z.string()).min(1).max(25).describe('Array of IPv4/IPv6 addresses (max 25).'),
    },
    async ({ ips }) => {
      const results = await enrichIpsBatch(h.env as unknown as Parameters<typeof enrichIp>[0], ips);
      return untrustedToolResult({ count: results.length, results });
    }
  );

  // ── IP enrichment → STIX 2.1 bundle ─────────────────────────────
  h.tools(
    'si_enrich_ip_stix',
    'Enrich an IP address and return the results as a STIX 2.1 bundle. Combines si_enrich_ip (IPinfo/AbuseIPDB/Shodan/VPNAPI) with STIX 2.1 indicator, vulnerability, and relationship objects. The bundle is importable into OpenCTI, MISP, or any TAXII 2.1 consumer. Returns both the enrichment data and the STIX bundle.',
    {
      ip: z.string().describe('IPv4 or IPv6 address, e.g. "203.0.113.42".'),
      tlp: z
        .enum(['WHITE', 'GREEN', 'AMBER', 'RED'])
        .optional()
        .describe('TLP marking for the bundle (default: GREEN)'),
      source: z.string().optional().describe('Source name for the STIX identity object (default: "DFIR MCP")'),
    },
    async ({ ip, tlp, source }) => {
      if (!isValidIp(ip)) {
        return untrustedToolResult({ error: 'invalid_ip', ip, hint: 'Pass a valid IPv4 or IPv6 address.' });
      }
      const enrichResult = await enrichIp(h.env as unknown as Parameters<typeof enrichIp>[0], ip);

      // Build STIX indicators from enrichment data
      const indicators: StixIndicator[] = [];

      // Primary IP indicator
      const isV6 = ip.includes(':');
      indicators.push({
        value: ip,
        type: isV6 ? 'ipv6-addr' : 'ipv4-addr',
        label: `IP: ${ip}`,
        confidence: computeConfidence(enrichResult),
        tlp: (tlp ?? 'GREEN') as StixIndicator['tlp'],
        tags: buildTags(enrichResult),
        description: buildDescription(enrichResult),
      });

      // ASN indicator
      if (enrichResult.asn) {
        indicators.push({
          value: enrichResult.asn,
          type: 'autonomous-system',
          label: `ASN: ${enrichResult.asn} (${enrichResult.org ?? 'unknown'})`,
          confidence: computeConfidence(enrichResult),
          tlp: (tlp ?? 'GREEN') as StixIndicator['tlp'],
          tags: ['asn', 'infrastructure'],
        });
      }

      // Shodan vulns → STIX vulnerability patterns
      const vulns = enrichResult.shodan_vulns ?? [];
      const stixIndicators = buildStixBundle(indicators, {
        bundleName: `IP Enrichment: ${ip}`,
        defaultTlp: tlp ?? 'GREEN',
        source: source ?? 'DFIR MCP',
      });

      // Add vulnerability objects for each Shodan CVE
      for (const cve of vulns.slice(0, 20)) {
        stixIndicators.objects.push({
          type: 'vulnerability',
          spec_version: '2.1',
          id: `vulnerability--${cve.toLowerCase()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: cve,
          description: `${cve} detected on ${ip} via Shodan`,
        });
        // Relationship: indicator → uses → vulnerability
        stixIndicators.objects.push({
          type: 'relationship',
          spec_version: '2.1',
          id: `relationship--${ip}-${cve}`.toLowerCase(),
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          relationship_type: 'indicates',
          source_ref: `indicator--${ip}`,
          target_ref: `vulnerability--${cve.toLowerCase()}`,
        });
      }

      return untrustedToolResult({
        enrichment: enrichResult,
        stix_bundle: stixIndicators,
        stix_object_count: stixIndicators.objects.length,
      });
    }
  );

  // ── Batch IP enrichment → single STIX 2.1 bundle ────────────────
  h.tools(
    'si_enrich_ip_stix_batch',
    'Enrich up to 10 IP addresses and return all results in a single STIX 2.1 bundle. Each IP produces indicator + optional ASN + vulnerability objects. The combined bundle is importable into OpenCTI/MISP. Returns per-IP enrichment data plus the merged STIX bundle.',
    {
      ips: z.array(z.string()).min(1).max(10).describe('Array of IPv4/IPv6 addresses (max 10).'),
      tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).optional().describe('TLP marking (default: GREEN)'),
      source: z.string().optional().describe('Source name for the STIX identity object'),
    },
    async ({ ips, tlp, source }) => {
      const validIps = ips.filter((ip) => isValidIp(ip));
      const invalidIps = ips.filter((ip) => !isValidIp(ip));
      const enrichResults = await enrichIpsBatch(h.env as unknown as Parameters<typeof enrichIp>[0], validIps);

      const allIndicators: StixIndicator[] = [];
      const allVulns: Array<{ ip: string; cve: string }> = [];

      for (const r of enrichResults) {
        const isV6 = r.ip.includes(':');
        allIndicators.push({
          value: r.ip,
          type: isV6 ? 'ipv6-addr' : 'ipv4-addr',
          label: `IP: ${r.ip}`,
          confidence: computeConfidence(r),
          tlp: (tlp ?? 'GREEN') as StixIndicator['tlp'],
          tags: buildTags(r),
          description: buildDescription(r),
        });
        if (r.asn) {
          allIndicators.push({
            value: r.asn,
            type: 'autonomous-system',
            label: `ASN: ${r.asn} (${r.org ?? 'unknown'})`,
            confidence: computeConfidence(r),
            tlp: (tlp ?? 'GREEN') as StixIndicator['tlp'],
            tags: ['asn', 'infrastructure'],
          });
        }
        for (const cve of (r.shodan_vulns ?? []).slice(0, 10)) {
          allVulns.push({ ip: r.ip, cve });
        }
      }

      const bundle = buildStixBundle(allIndicators, {
        bundleName: `Batch IP Enrichment (${validIps.length} IPs)`,
        defaultTlp: tlp ?? 'GREEN',
        source: source ?? 'DFIR MCP',
      });

      for (const { ip, cve } of allVulns) {
        bundle.objects.push({
          type: 'vulnerability',
          spec_version: '2.1',
          id: `vulnerability--${cve.toLowerCase()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: cve,
          description: `${cve} detected on ${ip} via Shodan`,
        });
        bundle.objects.push({
          type: 'relationship',
          spec_version: '2.1',
          id: `relationship--${ip}-${cve}`.toLowerCase(),
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          relationship_type: 'indicates',
          source_ref: `indicator--${ip}`,
          target_ref: `vulnerability--${cve.toLowerCase()}`,
        });
      }

      return untrustedToolResult({
        enrichments: enrichResults,
        invalid_ips: invalidIps,
        stix_bundle: bundle,
        stix_object_count: bundle.objects.length,
      });
    }
  );

  // ── Traceix hash enrichment ──────────────────────────────
  h.tools(
    'traceix_lookup',
    'Look up a SHA-256 file hash against traceix.com (PCEF) for antivirus/reputation results. Returns per-engine verdicts (Safe/Malicious/Unknown/Failed). Powered by Perkins Fund AI. Requires TRACEIX_API_KEY secret.',
    {
      hash: z
        .string()
        .describe(
          'SHA-256 hash (64 hex characters), e.g. "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".'
        ),
    },
    async ({ hash }) => {
      const r = await traceixLookup(h.env as { TRACEIX_API_KEY?: string }, hash);
      return untrustedToolResult(r);
    }
  );

  // ── NHI Scanner — non-human & agent identity risk tiers + OWASP NHI Top 10 ──
  // Port of github.com/rpmsft9/nhi-scan (MIT). Deterministic, local, no LLM.
  h.tools(
    'nhi_scan',
    "Scan a non-human & agent identity (NHI) inventory and get a risk report: per-identity Tier 1-4 (critical→baseline) from a transparent floor-tier rules engine, plus OWASP NHI Top 10 findings (NHI1-NHI10) each with evidence and a least-privilege remediation. Input is the inventory JSON (a list of NHI records or {'identities': [...]}); only id and name are required per record — fields like type, privilege, credential, secret_storage, last_rotated_days, last_used_days, exposure, scopes, autonomous, third_party, human_used, shared_across_env, used_by fall back to safe defaults. Returns the full report as JSON, or Markdown with format=markdown.",
    {
      inventory: z
        .string()
        .describe(
          'The NHI inventory as a JSON string: an array of NHI records, or an object with an "identities" array. Each record needs only id and name. Example record: {"id":"svc-payments","name":"payments-batch-runner","type":"service_account","environment":"prod","privilege":"admin","credential":"static_secret","secret_storage":"vault","last_rotated_days":410,"scopes":["payments:*"]}'
        ),
      format: z.enum(['json', 'markdown']).optional().describe('Output format: json (default) or markdown report'),
    },
    async ({ inventory, format }) => {
      const raw = JSON.parse(inventory) as unknown;
      const result = nhiScanFleet(nhiParseFleet(raw));
      if (format === 'markdown') {
        return { content: [{ type: 'text', text: nhiReportMarkdown(result) }] };
      }
      return { content: [{ type: 'text', text: JSON.stringify(nhiReportJson(result), null, 2) }] };
    }
  );

  h.tools(
    'nhi_inventory',
    "Summarize a non-human & agent identity (NHI) inventory: counts by identity type and risk tier, plus orphaned and long-lived-secret tallies. Input is the inventory JSON (a list of NHI records or {'identities': [...]}); only id and name are required per record. Deterministic, local, no LLM.",
    {
      inventory: z
        .string()
        .describe(
          'The NHI inventory as a JSON string: an array of NHI records, or an object with an "identities" array'
        ),
    },
    async ({ inventory }) => {
      const raw = JSON.parse(inventory) as unknown;
      const result = nhiScanFleet(nhiParseFleet(raw));
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                total_identities: result.total,
                by_type: result.typeCounts,
                tier_counts: result.tierCounts,
                orphaned: result.orphaned,
                long_lived_secrets: result.longLived,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  h.tools(
    'nhi_owasp_catalog',
    'Return the OWASP Non-Human Identities (NHI) Top 10 — 2025 catalog (NHI1-NHI10 with titles and summaries), the tiering-rule inventory the NHI scanner enforces (rule id, floor tier, rationale), policy thresholds (rotation/staleness windows, wildcard scope tokens), and the allowed inventory field values (types, privileges, credentials). Use this to understand what nhi_scan checks before running an inventory.',
    {},
    async () => {
      return { content: [{ type: 'text', text: JSON.stringify(nhiCatalog(), null, 2) }] };
    }
  );

  // ── Whoxy — reverse WHOIS by email/name/company/keyword ─────
  h.tools(
    'whoxy_reverse_whois',
    'Reverse WHOIS lookup via whoxy.com — find all domains associated with an email, owner name, company, or keyword. Searches 705M+ WHOIS records. Returns domain names, registrant info, and dates. Requires WHOXY_API_KEY secret.',
    {
      query: z.string().describe('Search term: email address, owner name, company name, or domain keyword.'),
      type: z
        .enum(['email', 'name', 'company', 'keyword'])
        .optional()
        .describe('Search type (default: "email"). Use "keyword" to match domain name prefixes.'),
    },
    async ({ query, type }) => {
      const r = await whoxyReverseWhois(h.env as { WHOXY_API_KEY?: string }, query, type ?? 'email');
      return untrustedToolResult(r);
    }
  );

  // ── Truecaller — reverse phone lookup ─────────────────────────────
  h.tools(
    'truecaller_lookup',
    'Reverse phone number lookup via Truecaller — get caller name, carrier, spam score, and location data. Requires TRUECALLER_API_KEY secret (register at truecaller.com).',
    {
      phone: z.string().describe('Phone number to look up (any format — E.164, local, with/without +).'),
    },
    async ({ phone }) => {
      const r = await truecallerLookup(h.env as { TRUECALLER_API_KEY?: string }, phone);
      return untrustedToolResult(r);
    }
  );

  // ── IntelligenceX — leaked-data search + phonebook ───────────────
  h.tools(
    'intelx_search',
    'Search IntelligenceX for leaked data, paste sites, breach archives, and dark-web content. Supports emails, domains, URLs, BTC addresses, IBANs, credit cards, phone numbers. Requires INTELX_API_KEY (paid).',
    {
      q: z.string().describe('Search term — email, domain, keyword, BTC address, IBAN, etc.'),
      max_results: z.number().optional().describe('Max results (default 20)'),
    },
    async ({ q, max_results }) => {
      const r = await intelxSearch(h.env as { INTELX_API_KEY?: string }, q, { maxResults: max_results });
      return untrustedToolResult(r);
    }
  );
  h.tools(
    'intelx_phonebook',
    'IntelligenceX Phonebook — find emails, domains, and URLs associated with a search term (name, domain, keyword). Requires INTELX_API_KEY (paid).',
    {
      q: z.string().describe('Search term — name, domain, or keyword'),
      max_results: z.number().optional().describe('Max results (default 20)'),
    },
    async ({ q, max_results }) => {
      const r = await intelxPhonebook(h.env as { INTELX_API_KEY?: string }, q, { maxResults: max_results });
      return untrustedToolResult(r);
    }
  );

  // ── Webamon — campaign intelligence (intel.webamon.com estate brief) ──
  h.tools(
    'webamon_campaigns',
    'List tracked phishing / malware-delivery campaigns from Webamon campaign intelligence (intel.webamon.com). Returns campaign cards with 24h domain delta, 7d activity, unique-domain totals, tags, and first/last seen. Sort by delta_24h to see the fastest-growing estates. Requires WEBAMON_API_KEY secret.',
    {
      tag: z.string().optional().describe('Filter by analyst tag, e.g. "gambling", "clickfix".'),
      search: z.string().optional().describe('Free-text search over campaign names/descriptions.'),
      size: z.number().optional().describe('Max campaigns to return (default 25, max 100).'),
      sort_by: z
        .string()
        .optional()
        .describe('Sort field: delta_24h (default), recent_7d, unique_domains_total, first_seen, last_seen.'),
    },
    async ({ tag, search, size, sort_by }) => {
      const r = await webamonListCampaigns(h.env as { WEBAMON_API_KEY?: string }, {
        tag,
        search,
        size: size ?? 25,
        sortBy: sort_by ?? 'delta_24h',
        order: 'desc',
      });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'webamon_campaign_changes',
    'Webamon per-campaign change events — the daily-digest feed. For each campaign: new domains, IPs, ASNs, cert issuers, page titles, and domains that went offline / came online within the window. Powers the "by the numbers" estate brief. Requires WEBAMON_API_KEY secret.',
    {
      since: z
        .string()
        .optional()
        .describe('ISO datetime lower bound (default: last 24h), e.g. "2026-07-28T00:00:00.000Z".'),
      campaign_id: z.string().optional().describe('Restrict to one campaign id.'),
      has_changes: z
        .boolean()
        .optional()
        .describe('Only return campaigns that changed in the window (default true-ish).'),
      size: z.number().optional().describe('Max events (default 100, max 200).'),
    },
    async ({ since, campaign_id, has_changes, size }) => {
      const r = await webamonListChanges(h.env as { WEBAMON_API_KEY?: string }, {
        since,
        campaignId: campaign_id,
        hasChanges: has_changes,
        size: size ?? 100,
      });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'webamon_clusters',
    'Webamon emerging fingerprint clusters — groups of domains sharing a fingerprint (links/ssl/dom/domains/asn/scripts/tech) not yet promoted to tracked campaigns. Returns severity (critical/high/watch), unique-domain count, 24h delta, and the seed_query to pivot into search. Requires WEBAMON_API_KEY secret.',
    {
      severity: z.enum(['critical', 'high', 'watch']).optional().describe('Filter by cluster severity.'),
      fingerprint_type: z
        .string()
        .optional()
        .describe('Filter by fingerprint type: links, ssl, dom, domains, asn, scripts, tech.'),
      size: z.number().optional().describe('Max clusters (default 25, max 100).'),
    },
    async ({ severity, fingerprint_type, size }) => {
      const r = await webamonListClusters(h.env as { WEBAMON_API_KEY?: string }, {
        severity: severity as WebamonClusterSeverity | undefined,
        fingerprintType: fingerprint_type,
        size: size ?? 25,
      });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'webamon_campaign_stats',
    'Webamon global estate rollup — total tracked campaigns, unique domains, online percentage, and aggregate activity. The headline numbers for the campaign-intelligence estate. Requires WEBAMON_API_KEY secret.',
    {},
    async () => {
      const r = await webamonGetCampaignStats(h.env as { WEBAMON_API_KEY?: string });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'webamon_campaign_intel',
    'Webamon aggregated daily-brief digest in one call: global stats + top campaigns by 24h delta + change events in the window + emerging clusters, rolled up into "by the numbers" totals (new domains, takedowns, infra changes, new lure titles). Requires WEBAMON_API_KEY secret.',
    {
      since: z.string().optional().describe('ISO datetime lower bound (default: last 24h).'),
    },
    async ({ since }) => {
      const r = await webamonGetCampaignIntel(h.env as { WEBAMON_API_KEY?: string }, { since });
      return untrustedToolResult(r);
    }
  );

  // ── depx — supply-chain malicious package intelligence ──────
  h.tools(
    'depx_feed',
    'Feed of recently disclosed malicious packages from the OpenSSF Malicious Packages database. Returns packages disclosed within the time window, with ecosystem breakdown and disclosure age. Inspired by projectdiscovery/depx.',
    {
      since: z.string().optional().describe('Time window: "24h", "7d" (default), "30d". E.g. "3d" for last 3 days.'),
      ecosystem: z
        .string()
        .optional()
        .describe('Filter by ecosystem: npm, pypi, maven, go, rubygems, crates.io, nuget, packagist.'),
      limit: z.number().optional().describe('Max entries (default 100, max 500).'),
    },
    async ({ since, ecosystem, limit }) => {
      const params = new URLSearchParams();
      if (since) params.set('since', since);
      if (ecosystem) params.set('ecosystem', ecosystem);
      if (limit) params.set('limit', String(limit));
      const r = await apiFetch(h.env.SELF, `/api/v1/depx/feed?${params}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'depx_check',
    'Check if a specific package is known-malicious. Queries the OpenSSF Malicious Packages database and OSV. Returns verdict (clean/malicious/unknown) with advisory details. Inspired by projectdiscovery/depx.',
    {
      ref: z
        .string()
        .optional()
        .describe('Package reference in ecosystem:name format, e.g. "npm:lodash" or "pypi:requests".'),
      ecosystem: z.string().optional().describe('Ecosystem: npm, pypi, maven, go, rubygems, crates.io.'),
      package: z.string().optional().describe('Package name to check.'),
    },
    async ({ ref, ecosystem, package: pkg }) => {
      const params = new URLSearchParams();
      if (ref) params.set('ref', ref);
      else if (ecosystem && pkg) {
        params.set('ecosystem', ecosystem);
        params.set('package', pkg);
      }
      const r = await apiFetch(h.env.SELF, `/api/v1/depx/feed/check?${params}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'depx_stats',
    'Supply-chain intelligence statistics — ecosystem breakdown, recent advisory counts, and disclosure trends from the OpenSSF Malicious Packages database.',
    {},
    async () => {
      const r = await apiFetch(h.env.SELF, '/api/v1/depx/feed/stats', h.apiKey);
      return untrustedToolResult(r);
    }
  );

  // ── AI Security hub — realtime AI vulns / advisories / research ──
  h.tools(
    'ai_vulns',
    'Realtime AI vulnerability tracking — EUVD + NVD + OSV watchlist (litellm, vllm, langchain, mcp, transformers…), CISA/EU KEV overlap, FIRST EPSS exploit-probability and an AI/agent stack facet. KEV-listed rows sort first.',
    {
      q: z.string().optional().describe('Search CVE/GHSA ids, packages, vendors, e.g. "litellm" or "mcp".'),
      kev_only: z.boolean().optional().describe('Only KEV-listed (actively exploited) vulns.'),
      min_epss: z.number().optional().describe('Minimum EPSS exploit probability 0-1, e.g. 0.5.'),
      source: z.string().optional().describe('Source filter: euvd, nvd, osv, kev.'),
      stack: z
        .string()
        .optional()
        .describe('AI/agent stack facet: mcp | agents | inference | retrieval | mlops | runtime | apps.'),
      limit: z.number().optional().describe('Max entries (default 100).'),
    },
    async ({ q, kev_only, min_epss, source, stack, limit }) => {
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (kev_only) params.set('kev_only', 'true');
      if (min_epss !== undefined) params.set('min_epss', String(min_epss));
      if (source) params.set('source', source);
      if (stack) params.set('stack', stack);
      if (limit) params.set('limit', String(limit));
      const r = await apiFetch(h.env.SELF, `/api/v1/ai-security/vulns?${params}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'ai_vuln_get',
    'Full body for one AI vuln: description, references, aliases, affected packages, KEV dates, EPSS percentile. Call ai_vulns first to discover IDs.',
    {
      id: z.string().describe('Vuln ID, e.g. "CVE-2026-42271" or a GHSA id.'),
    },
    async ({ id }) => {
      const r = await apiFetch(h.env.SELF, `/api/v1/ai-security/vulns/${encodeURIComponent(id)}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'ai_advisories',
    'AI advisory firehose — per-package GHSA advisories, cvelistV5 CVE commits matched to known AI CVEs, tool release trains (garak, PyRIT, promptfoo, litellm, vllm, ollama, langchain, MCP SDK, MITRE ATLAS, OWASP GenAI), ExploitDB PoCs.',
    {
      q: z.string().optional().describe('Search titles, sources, CVE ids.'),
      source: z
        .string()
        .optional()
        .describe(
          'Source filter: ghsa, cvelistV5, garak, pyrit, promptfoo, litellm, vllm, ollama, langchain, mcp-sdk, mitre-atlas, owasp-llm-top10, owasp-threat-intel, owasp-acs, exploitdb.'
        ),
      kind: z.string().optional().describe('Kind filter: advisory, cve, release, exploit.'),
      limit: z.number().optional().describe('Max entries (default 100).'),
    },
    async ({ q, source, kind, limit }) => {
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (source) params.set('source', source);
      if (kind) params.set('kind', kind);
      if (limit) params.set('limit', String(limit));
      const r = await apiFetch(h.env.SELF, `/api/v1/ai-security/advisories?${params}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'ai_research',
    'AI security research feed — Hacktron, Palo Alto Unit42, Cloud Security Alliance, BleepingComputer AI-filtered items with links back upstream.',
    {
      q: z.string().optional().describe('Search titles and sources, e.g. "heist" or "rce".'),
      source: z.string().optional().describe('Source filter: hacktron, unit42, csa, bleepingcomputer.'),
      limit: z.number().optional().describe('Max entries (default 100).'),
    },
    async ({ q, source, limit }) => {
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (source) params.set('source', source);
      if (limit) params.set('limit', String(limit));
      const r = await apiFetch(h.env.SELF, `/api/v1/ai-security/research?${params}`, h.apiKey);
      return untrustedToolResult(r);
    }
  );

  // ── FullHunt — attack surface discovery ────────────────────
  h.tools(
    'fullhunt_domain',
    'Discover attack surface for a domain via FullHunt: open ports, technologies, subdomains, ASN, cloud provider, and WHOIS data. Requires FULLHUNT_API_KEY secret (free at fullhunt.io).',
    {
      domain: z.string().describe('Domain name to investigate, e.g. "example.com".'),
    },
    async ({ domain }) => {
      const r = await fullhuntDomainDetails(h.env as { FULLHUNT_API_KEY?: string }, domain);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'fullhunt_subdomains',
    'Enumerate subdomains for a domain via FullHunt. Returns discovered subdomain names. Requires FULLHUNT_API_KEY secret.',
    {
      domain: z.string().describe('Domain name to enumerate subdomains for.'),
    },
    async ({ domain }) => {
      const r = await fullhuntSubdomains(h.env as { FULLHUNT_API_KEY?: string }, domain);
      return untrustedToolResult(r);
    }
  );

  // ── OpenSanctions — sanctions / PEP / crime entity search ──
  // NOTE: the hosted OpenSanctions API has required `Authorization: ApiKey …`
  // since 2025 — these tools need OPENSANCTIONS_API_KEY set.
  h.tools(
    'opensanctions_search',
    'Search OpenSanctions for entities (individuals, companies, vessels) flagged in sanctions lists, PEP (politically exposed persons) databases, and crime watchlists. Requires OPENSANCTIONS_API_KEY (free for public-interest work at opensanctions.org).',
    {
      q: z.string().min(2).describe('Search query — entity name, domain, or email address.'),
      limit: z.number().int().min(1).max(100).optional().describe('Max results (default 20, max 100).'),
    },
    async ({ q, limit }) => {
      const r = await opensanctionsSearch(q, limit, h.env as { OPENSANCTIONS_API_KEY?: string });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'opensanctions_entity',
    'Get detailed entity information from OpenSanctions by ID. Returns full properties, associated datasets, topics, and schema. Use after opensanctions_search to explore a specific match. Requires OPENSANCTIONS_API_KEY.',
    {
      id: z.string().describe('OpenSanctions entity ID (e.g. from opensanctions_search results).'),
    },
    async ({ id }) => {
      const r = await opensanctionsEntity(id, h.env as { OPENSANCTIONS_API_KEY?: string });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'opensanctions_stats',
    'Get OpenSanctions dataset statistics: total entities, datasets, countries covered, and schema counts. Requires OPENSANCTIONS_API_KEY.',
    {},
    async () => {
      const r = await opensanctionsStats(h.env as { OPENSANCTIONS_API_KEY?: string });
      return untrustedToolResult(r);
    }
  );

  // ── OpenCVE Cloud — enriched CVE records ────────────────────
  // Requires OPENCVE_API_TOKEN (free org token at app.opencve.io).
  h.tools(
    'opencve_get_cve',
    'Get an enriched CVE record from OpenCVE Cloud: summary, CVSS v3.1/v4.0, severity, KEV flag, EPSS, vendors/products, CWE weaknesses, and references. Requires OPENCVE_API_TOKEN (free org token at app.opencve.io).',
    {
      cve_id: z
        .string()
        .regex(/^CVE-\d{4}-\d{4,}$/i, 'Must look like CVE-2024-3094')
        .describe('CVE ID, e.g. "CVE-2024-3094".'),
    },
    async ({ cve_id }) => {
      const r = await opencveGetCve(cve_id, h.env as { OPENCVE_API_TOKEN?: string });
      return untrustedToolResult(r);
    }
  );

  // ── Dehash.lt — hash decryption / reverse lookup ────────────
  h.tools(
    'dehash_lookup',
    'Look up a cryptographic hash (md5/sha1/sha256/sha384/sha512) against Dehash.lt to find its plaintext value. Useful for cracking password hashes or identifying known hash values. No API key required.',
    {
      hash: z
        .string()
        .describe(
          'Hash value to look up. Supports md5 (32 hex), sha1 (40 hex), sha256 (64 hex), sha384 (96 hex), sha512 (128 hex).'
        ),
    },
    async ({ hash }) => {
      const r = await dehashLookup(hash);
      return untrustedToolResult(r);
    }
  );

  // ── FBI Wanted — wanted persons database ───────────────────
  h.tools(
    'fbi_wanted_search',
    'Search the FBI Wanted database for wanted persons by name. Returns titles, descriptions, reward amounts, and field offices. No API key required.',
    {
      q: z.string().min(2).describe('Search query — person name to search for in FBI wanted database.'),
    },
    async ({ q }) => {
      const r = await fbiWantedSearch(q);
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'fbi_wanted_list',
    'List current FBI wanted persons with pagination. No API key required.',
    {
      page: z.number().int().min(1).optional().describe('Page number (default 1).'),
      pageSize: z.number().int().min(1).max(50).optional().describe('Results per page (default 20, max 50).'),
    },
    async ({ page, pageSize }) => {
      const r = await fbiWantedList(page, pageSize);
      return untrustedToolResult(r);
    }
  );

  // ── Interpol Red Notices — wanted persons database ─────────
  h.tools(
    'interpol_search',
    'Search INTERPOL Red Notices for wanted persons by name, forename, or nationality. Returns entity IDs, charges, and issuing countries. No API key required.',
    {
      name: z.string().optional().describe('Family/surname of the wanted person.'),
      forename: z.string().optional().describe('Given/forename of the wanted person.'),
      nationality: z.string().optional().describe('Two-letter nationality code (e.g. "US", "FR", "GB").'),
    },
    async ({ name, forename, nationality }) => {
      const r = await interpolSearch({ name, forename, nationality });
      return untrustedToolResult(r);
    }
  );

  h.tools(
    'interpol_notice_detail',
    'Get details of a specific INTERPOL Red Notice by entity ID. Returns full charge info, arrest warrant details, and physical description. No API key required.',
    {
      noticeId: z.string().describe('Interpol Red Notice entity ID (e.g. from interpol_search results).'),
    },
    async ({ noticeId }) => {
      const r = await interpolNoticeDetail(noticeId);
      return untrustedToolResult(r);
    }
  );

  // ── Mozilla Observatory — security grade scanning ──────────
  h.tools(
    'mozilla_tls_scan',
    "Scan a domain's security posture using the Mozilla Observatory (successor to the retired TLS Observatory). Returns grade (A+ through F) and test counts. No API key required.",
    {
      url: z.string().describe('URL or domain to scan (e.g. "example.com" or "https://example.com").'),
    },
    async ({ url }) => {
      const r = await mozillaTlsScan(url);
      return untrustedToolResult(r);
    }
  );

  // ── Virushee — multi-engine hash scan ──────────────────────
  h.tools(
    'virushee_check',
    'Check a file hash (MD5/SHA1/SHA256) against the Virushee multi-engine AV database. Returns detection ratio and per-engine results. No API key required.',
    {
      hash: z.string().describe('File hash to check (MD5, SHA1, or SHA256 hex string).'),
    },
    async ({ hash }) => {
      const r = await virusheeCheck(hash);
      return untrustedToolResult(r);
    }
  );

  // ── Cerast Intelligence — domain exposure search ────────────
  h.tools(
    'cerast_domain_search',
    'Search Cerast Intelligence for exposed paths and misconfigurations on observed domains. Returns domain, path, category, impact level, OpenPageRank score, version, and first-seen date. Useful for discovering staging/dev environments, exposed admin panels, and misconfigured endpoints.',
    {
      query: z
        .string()
        .min(3)
        .describe(
          'Substring to search for in domain names (case-insensitive, min 3 chars). E.g. "staging.", ".org", "test-".'
        ),
    },
    async ({ query }) => {
      const r = await cerastSearch(query);
      return untrustedToolResult(r);
    }
  );

  // ── ThreatMon Infostealer — stealer log investigation ───────
  h.tools(
    'threatmon_infostealer_search',
    'Search ThreatMon IntelHub for compromised credentials and infected devices linked to a domain via real stealer malware logs. Returns compromised URLs, IPs, usernames, dates, and employee/user classification. Data sourced from ~2.18B compromised users and ~10.47B leaked credentials.',
    {
      domain: z.string().describe('Domain name to search, e.g. "example.com"'),
      scope: z
        .enum(['company', 'third-party'])
        .optional()
        .describe(
          'Search scope: "company" for company URLs, "third-party" for third-party service URLs. Default: company.'
        ),
    },
    async ({ domain, scope }) => {
      const r = await threatmonInfostealerSearch(domain, scope ?? 'company');
      return untrustedToolResult(r);
    }
  );
}
