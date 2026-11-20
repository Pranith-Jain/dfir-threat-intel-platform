/**
 * detection-manifests MCP tool registrations.
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

import { filterBreaches, getBwBreach, listGroups, loadBwIndex } from '../lib/breach-watch-manifest';
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
  filterDwSecurityAuditingEvents,
  filterDwTechniques,
  filterDwWindowsProviders,
  getDwAttackTechnique,
  getDwLab,
  loadDwAttackIndex,
  loadDwLabs,
  loadDwPlatformDetail,
  loadDwPlatforms,
  loadDwRules,
  loadDwSecurityAuditing,
  loadDwTechniques,
  loadDwWindows,
} from '../lib/detection-wiki-manifest';
import {
  filterPcmDigests,
  getPcmDigest,
  getPcmLatest,
  loadPcmIndex,
  searchPcmItems,
} from '../lib/pcmedicalist-manifest';
import {
  filterIocs as filterSigBaseIocs,
  filterYara,
  getSigBaseIoc,
  getSigBaseYara,
  loadSigBaseIndex,
  searchIocEntries as searchSigBaseIocEntries,
} from '../lib/sigbase-manifest';
import {
  filterTamGroups,
  filterTamSources,
  filterTamTechniques as filterTamTechniquesMcp,
  getTamGroup,
  loadTamGroups,
  loadTamSources,
  loadTamTechniques,
} from '../lib/threat-monitor-manifest';
export function registerDetectionManifestsTools(h: McpToolHost): void {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── Detection Wiki tools ────────────────────────────────────────
  // Full detection.wiki mirror — 15,957 rules, 218 techniques across 14 tactics,
  // 103k Windows events (1,518 providers), 426 Security-Auditing events, 6 labs with KQL.
  // Source: https://detection.wiki (public, Cloudflare-protected, built via Playwright)

  h.tools(
    'dw_list_techniques',
    'List MITRE ATT&CK techniques indexed by detection.wiki: technique ID, name, tactic, and number of detection rules. Filter by tactic, keyword, minimum rule count, or subtechnique inclusion. Use dw_get_technique to fetch a single technique.',
    {
      tactic: z
        .string()
        .optional()
        .describe('Filter by ATT&CK tactic (e.g. "Execution", "Initial Access", "Defense Evasion")'),
      q: z.string().optional().describe('Free-text search across technique ID, name, and tactic'),
      min_rules: z.number().int().min(0).optional().describe('Only techniques with at least this many detection rules'),
      subtechniques: z.boolean().optional().describe('Include sub-techniques (default true)'),
      limit: z.number().int().min(1).max(218).optional().describe('Max techniques to return (default 50)'),
    },
    async ({ tactic, q, min_rules, subtechniques, limit }) => {
      const idx = await loadDwTechniques(ASSETS);
      const filtered = filterDwTechniques(idx.all, { tactic, q, minRules: min_rules, subtechniques });
      return untrustedToolResult({
        total: idx.all.length,
        returned: Math.min(filtered.length, limit ?? 50),
        techniques: filtered.slice(0, limit ?? 50),
      });
    }
  );

  h.tools(
    'dw_get_technique',
    'Return a single MITRE ATT&CK technique from the detection.wiki mirror: name, tactic, detection rule count, and whether it is a sub-technique. Use dw_list_techniques first to discover IDs.',
    { id: z.string().describe('Technique ID, e.g. "T1059.001" or "T1078". Get these from dw_list_techniques.') },
    async ({ id }) => {
      const idx = await loadDwTechniques(ASSETS);
      const found = idx.all.find((t) => t.id.toLowerCase() === id.toLowerCase());
      if (!found)
        return untrustedToolResult({
          error: 'technique_not_found',
          id,
          hint: 'Call dw_list_techniques to see available IDs.',
        });
      return untrustedToolResult(found);
    }
  );

  h.tools(
    'dw_list_platforms',
    'List the 17 platform telemetry catalogs indexed by detection.wiki: Windows, AWS, Azure, M365, GCP, Kubernetes, Okta, GitHub, and more. Each entry has event count and rule coverage.',
    {},
    async () => {
      const platforms = await loadDwPlatforms(ASSETS);
      return untrustedToolResult({ total: platforms.length, platforms });
    }
  );

  h.tools(
    'dw_list_windows_providers',
    'List Windows Event Log providers from the detection.wiki Windows catalog: provider name, slug, event count, samples with field definitions, and detection-rule coverage. Covers 1,518 providers (74 sampled with counts, 103,315 total events). Filter by keyword or whether they have rules.',
    {
      q: z.string().optional().describe('Free-text search across provider name and channel'),
      has_rules: z
        .boolean()
        .optional()
        .describe('Only providers that have at least one mapped detection rule (true) or none (false)'),
      limit: z.number().int().min(1).max(100).optional().describe('Max providers to return (default 50)'),
    },
    async ({ q, has_rules, limit }) => {
      const cat = await loadDwWindows(ASSETS);
      if (!cat) return untrustedToolResult({ error: 'windows_catalog_not_found' });
      const filtered = filterDwWindowsProviders(cat.providers, { q, hasRules: has_rules, limit: limit ?? 50 });
      return untrustedToolResult({
        totalProviders: cat.totalProviders,
        sampledProviders: cat.providers.length,
        totalEvents: cat.totalEvents,
        returned: filtered.length,
        providers: filtered,
      });
    }
  );

  h.tools(
    'dw_get_windows_provider',
    'Return a single Windows Event Log provider by slug: event count, samples, rules, and channel. Use dw_list_windows_providers first to discover slugs.',
    {
      slug: z
        .string()
        .describe(
          'Provider slug, e.g. "microsoft-windows-security-auditing" or "service-control-manager". Get these from dw_list_windows_providers.'
        ),
    },
    async ({ slug }) => {
      const cat = await loadDwWindows(ASSETS);
      if (!cat) return untrustedToolResult({ error: 'windows_catalog_not_found' });
      const prov = cat.providers.find((p) => p.slug.toLowerCase() === slug.toLowerCase());
      if (!prov)
        return untrustedToolResult({
          error: 'provider_not_found',
          slug,
          hint: 'Call dw_list_windows_providers to see available slugs.',
        });
      return untrustedToolResult(prov);
    }
  );

  h.tools(
    'dw_list_security_auditing_events',
    'List Microsoft-Windows-Security-Auditing events (Security channel, 426 total): event ID, title, and whether it has sample data or a mapped detection rule. Filter by keyword, ATT&CK tactic, sample/rule presence. Use dw_get_security_auditing_event to fetch a single event.',
    {
      q: z.string().optional().describe('Free-text search across event ID, title, tactic'),
      tactic: z
        .string()
        .optional()
        .describe('Filter by ATT&CK tactic (e.g. "Execution", "Credential Access", "Persistence")'),
      has_sample: z.boolean().optional().describe('Only events that have sample data (true) or not (false)'),
      has_rule: z.boolean().optional().describe('Only events that have a mapped detection rule'),
      limit: z.number().int().min(1).max(426).optional().describe('Max events to return (default 100)'),
    },
    async ({ q, tactic, has_sample, has_rule, limit }) => {
      const cat = await loadDwSecurityAuditing(ASSETS);
      if (!cat) return untrustedToolResult({ error: 'security_auditing_not_found' });
      const filtered = filterDwSecurityAuditingEvents(cat.events, {
        q,
        tactic,
        hasSample: has_sample,
        hasRule: has_rule,
        limit: limit ?? 100,
      });
      return untrustedToolResult({
        provider: cat.provider,
        channel: cat.channel,
        totalEvents: cat.eventCount,
        returned: filtered.length,
        events: filtered,
      });
    }
  );

  h.tools(
    'dw_get_security_auditing_event',
    'Return a single Microsoft-Windows-Security-Auditing event by Event ID: title, channel, sample/rule flags, and ATT&CK tactic. Use dw_list_security_auditing_events first to discover IDs.',
    {
      id: z
        .number()
        .int()
        .describe('Event ID, e.g. 4624, 4688, 4720. Get these from dw_list_security_auditing_events.'),
    },
    async ({ id }) => {
      const cat = await loadDwSecurityAuditing(ASSETS);
      if (!cat) return untrustedToolResult({ error: 'security_auditing_not_found' });
      const ev = cat.events.find((e) => e.id === id);
      if (!ev)
        return untrustedToolResult({
          error: 'event_not_found',
          id,
          hint: 'Call dw_list_security_auditing_events to see available IDs.',
        });
      return untrustedToolResult(ev);
    }
  );

  h.tools(
    'dw_list_labs',
    'List hands-on detection labs from detection.wiki: title, author, date, description, and mapped ATT&CK techniques. Filter by keyword. Use dw_get_lab to fetch the full body with KQL queries.',
    {
      q: z.string().optional().describe('Free-text search across title, description, or technique IDs'),
      limit: z.number().int().min(1).max(20).optional().describe('Max labs to return (default 10)'),
    },
    async ({ q, limit }) => {
      const labs = await loadDwLabs(ASSETS);
      const filtered = q
        ? labs.filter((l) =>
            `${l.title} ${l.description} ${l.techniques.join(' ')}`.toLowerCase().includes(q.toLowerCase())
          )
        : labs;
      return untrustedToolResult({
        total: labs.length,
        returned: Math.min(filtered.length, limit ?? 10),
        labs: filtered.slice(0, limit ?? 10),
      });
    }
  );

  h.tools(
    'dw_get_lab',
    'Return the full body of a single detection.wiki lab: title, description, ATT&CK techniques, KQL queries, and raw markdown body. Use dw_list_labs first to discover slugs.',
    {
      slug: z
        .string()
        .describe('Lab slug, e.g. "clickonce-abuse" or "byovd-and-ksld-sys". Get these from dw_list_labs.'),
    },
    async ({ slug }) => {
      const body = await getDwLab(ASSETS, slug);
      if (!body)
        return untrustedToolResult({
          error: 'lab_not_found',
          slug,
          hint: 'Call dw_list_labs to see available slugs.',
        });
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'dw_get_platform',
    'Return detailed event catalog for a single detection.wiki platform (e.g. macOS ESF, auditd, AWS CloudTrail, Defender XDR, Entra ID): total events, sampled event types, and source URL. Use dw_list_platforms first to discover slugs.',
    {
      slug: z
        .string()
        .describe(
          'Platform slug, e.g. "auditd", "aws", "macos", "entra-id", "gcp", "kubernetes". Get these from dw_list_platforms.'
        ),
    },
    async ({ slug }) => {
      const detail = await loadDwPlatformDetail(ASSETS, slug);
      if (!detail)
        return untrustedToolResult({
          error: 'platform_not_found',
          slug,
          hint: 'Call dw_list_platforms to see available slugs.',
        });
      return untrustedToolResult(detail);
    }
  );

  h.tools(
    'dw_get_attack',
    'Return the MITRE ATT&CK coverage index from detection.wiki: tactics with total rules per tactic and technique counts. This mirrors https://detection.wiki/attack/ and https://detection.wiki/rules/.',
    {},
    async () => {
      const attack = await loadDwAttackIndex(ASSETS);
      if (!attack) return untrustedToolResult({ error: 'attack_index_not_found' });
      return untrustedToolResult(attack);
    }
  );

  h.tools(
    'dw_get_attack_technique',
    'Return a single ATT&CK technique body as it appears under https://detection.wiki/attack/Txxxx/: technique metadata, rule count, tactic, and cross-references. Use dw_list_techniques or dw_get_attack first to discover IDs.',
    { id: z.string().describe('Technique ID, e.g. "T1589" or "T1059.001". Get these from dw_list_techniques.') },
    async ({ id }) => {
      const body = await getDwAttackTechnique(ASSETS, id);
      if (!body)
        return untrustedToolResult({
          error: 'attack_technique_not_found',
          id,
          hint: 'Call dw_list_techniques to see available IDs.',
        });
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'dw_list_rules',
    'List sampled detection rules from detection.wiki (15,957 total): rule ID, title, vendor (Sigma/Elastic/Splunk/Kusto/YARA-L/Panther/Sublime), technique, tactic, platform, and status. Full rule bodies live at detection.wiki per technique; use dw_get_attack_technique for per-technique coverage.',
    {
      vendor: z
        .string()
        .optional()
        .describe('Filter by vendor (Sigma, Elastic, Splunk, Kusto, YARA-L, Panther, Sublime MQL)'),
      platform: z.string().optional().describe('Filter by platform (Windows, AWS, Azure, GCP, etc.)'),
      technique: z.string().optional().describe('Filter by technique ID (e.g. T1059)'),
      q: z.string().optional().describe('Free-text search across title, technique, tactic'),
      limit: z.number().int().min(1).max(100).optional().describe('Max rules to return (default 30)'),
    },
    async ({ vendor, platform, technique, q, limit }) => {
      const idx = await loadDwRules(ASSETS);
      if (!idx) return untrustedToolResult({ error: 'rules_not_found' });
      let rules = idx.rules;
      if (vendor) rules = rules.filter((r) => r.vendor.toLowerCase() === vendor.toLowerCase());
      if (platform) rules = rules.filter((r) => r.platform.toLowerCase() === platform.toLowerCase());
      if (technique) rules = rules.filter((r) => r.technique.toLowerCase() === technique.toLowerCase());
      if (q) {
        const needle = q.toLowerCase();
        rules = rules.filter((r) => `${r.title} ${r.technique} ${r.tactic} ${r.vendor}`.toLowerCase().includes(needle));
      }
      return untrustedToolResult({
        totalRules: idx.totalRules,
        sampled: idx.sampledRules,
        returned: Math.min(rules.length, limit ?? 30),
        rules: rules.slice(0, limit ?? 30),
      });
    }
  );

  // ── Global Threat Actor Monitor tools (hero-itsme replication) ──
  // Full replication of https://github.com/hero-itsme/Global-Threat-Actor-Monitor
  // 40 APT groups + 148 aliases upstream (81 groups expanded), 29 techniques upstream
  // (108 expanded) -> Kill Chain, 30 OSINT feeds upstream (39 expanded). Data ships in
  // public/data/threat-monitor/ built by scripts/build-threat-monitor.mjs (MIT).

  h.tools(
    'tam_list_groups',
    'List APT threat-actor groups from the Global Threat Actor Monitor replication. Upstream 40 groups + expanded to 81 covering Russia/China/NK/Iran eCrime/ransomware/infostealer. Filter by origin country, keyword, or upstream-only. Use tam_get_group to fetch full aliases + sectors.',
    {
      q: z.string().optional().describe('Free-text search across group name, aliases, origin, sectors, MITRE ID'),
      origin: z.string().optional().describe('Filter by suspected origin (e.g. Russia, China, Iran, North Korea)'),
      upstream_only: z.boolean().optional().describe('Only the 40 upstream groups (true) vs all 81 (false, default)'),
      limit: z.number().int().min(1).max(81).optional().describe('Max groups to return (default 50)'),
    },
    async ({ q, origin, upstream_only, limit }) => {
      const file = await loadTamGroups(ASSETS);
      const filtered = filterTamGroups(file.groups, { q, origin, upstreamOnly: upstream_only, limit: limit ?? 50 });
      return untrustedToolResult({
        total: file.totalGroups,
        upstream: file.upstreamGroups,
        expanded: file.expandedGroups,
        returned: filtered.length,
        groups: filtered,
      });
    }
  );

  h.tools(
    'tam_get_group',
    'Return a single APT group body: aliases, MITRE Group ID, suspected_origin, target_sectors, and upstream flag. Use tam_list_groups first to discover names/slugs.',
    {
      slug: z
        .string()
        .describe('Group slug or name, e.g. "apt29", "lazarus-group", "Volt Typhoon". Get these from tam_list_groups.'),
    },
    async ({ slug }) => {
      const body = await getTamGroup(ASSETS, slug);
      if (!body)
        return untrustedToolResult({
          error: 'group_not_found',
          slug,
          hint: 'Call tam_list_groups to see available groups.',
        });
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'tam_list_techniques',
    'List MITRE ATT&CK techniques curated for the Threat Actor Monitor (29 upstream -> 108 expanded) with Kill Chain mapping and detection keywords. Filter by tactic, kill chain stage, or keyword. Use for killchain_mapper scoring.',
    {
      q: z.string().optional().describe('Free-text search across technique ID, name, tactic, kill_chain, keywords'),
      tactic: z
        .string()
        .optional()
        .describe('Filter by ATT&CK tactic (e.g. "Initial Access", "Execution", "Defense Evasion")'),
      kill_chain: z
        .string()
        .optional()
        .describe(
          'Filter by Kill Chain stage (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives)'
        ),
      limit: z.number().int().min(1).max(108).optional().describe('Max techniques to return (default 50)'),
    },
    async ({ q, tactic, kill_chain, limit }) => {
      const file = await loadTamTechniques(ASSETS);
      const filtered = filterTamTechniquesMcp(file.techniques, { q, tactic, kill_chain, limit: limit ?? 50 });
      return untrustedToolResult({
        total: file.totalTechniques,
        upstream: file.upstreamTechniques,
        expanded: file.expandedTechniques,
        returned: filtered.length,
        techniques: filtered,
        killChainStages: file.killChainStages,
      });
    }
  );

  h.tools(
    'tam_list_sources',
    'List OSINT RSS/Atom feed sources polled by the Global Threat Actor Monitor (30 upstream -> 39 expanded): name, URL, category (news/vendor/gov), upstream flag. Filter by category or keyword. Feeds are polled every 10 minutes with concurrent bounded fetch.',
    {
      q: z.string().optional().describe('Free-text search across feed name, URL, category'),
      category: z.string().optional().describe('Filter by category (news, vendor, gov)'),
      upstream_only: z.boolean().optional().describe('Only the 30 upstream feeds (true) vs all 39 (false, default)'),
      limit: z.number().int().min(1).max(50).optional().describe('Max feeds to return (default 50)'),
    },
    async ({ q, category, upstream_only, limit }) => {
      const file = await loadTamSources(ASSETS);
      const filtered = filterTamSources(file.sources, {
        q,
        category,
        upstreamOnly: upstream_only,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: file.totalSources,
        upstream: file.upstreamSources,
        expanded: file.expandedSources,
        categories: file.categories,
        returned: filtered.length,
        sources: filtered,
      });
    }
  );

  // ── PCMedicalist feed tools ────────────────────────────────────
  // Daily security-intel digest from the PCMedicalist Intelligence
  // Network. Slim static mirror in public/data/pcmedicalist/
  // (index + per-day top-items bodies) + a live deep-dive search
  // over the full ~4.6MB day feed via the /api/v1/pcmedicalist proxy.
  // Source: github.com/PCMedicalist/pcmedicalist-intellegence-feed
  // License: CC BY 4.0 (attribution via in-data "source" field satisfies)

  h.tools(
    'pcm_list_digests',
    'List PCMedicalist Intelligence Feed digests. Filter by date range or keyword. Each entry has date, run metrics (feeds/items raw vs deduped), and per-layer counts.',
    {
      dateFrom: z.string().optional().describe('YYYY-MM-DD — only digests on or after this date'),
      dateTo: z.string().optional().describe('YYYY-MM-DD — only digests on or before this date'),
      keyword: z.string().optional().describe('Case-insensitive match against layer names/counts'),
      limit: z.number().int().min(1).max(500).optional().describe('Max digests to return (default 50)'),
    },
    async ({ dateFrom, dateTo, keyword, limit }) => {
      const idx = await loadPcmIndex(ASSETS);
      const digests = filterPcmDigests(idx, {
        dateFrom: dateFrom ?? undefined,
        dateTo: dateTo ?? undefined,
        keyword: keyword ?? undefined,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        totalDigests: idx.counts.digests,
        returned: digests.length,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        digests,
      });
    }
  );

  h.tools(
    'pcm_get_digest',
    'Return a single PCMedicalist Intelligence Feed digest body for a date: run summary, the two generated social posts, and the top items per intelligence layer (11-layer taxonomy).',
    {
      date: z.string().describe('Digest date, YYYY-MM-DD. Get these from pcm_list_digests.'),
    },
    async ({ date }) => {
      const digest = await getPcmDigest(ASSETS, date);
      if (!digest) {
        return untrustedToolResult({
          error: 'digest_not_found',
          date,
          hint: 'Call pcm_list_digests to see available dates.',
        });
      }
      return untrustedToolResult(digest);
    }
  );

  h.tools(
    'pcm_get_latest_digest',
    'Return the most recent PCMedicalist Intelligence Feed digest: run summary + social posts + top items per layer.',
    {},
    async () => {
      const digest = await getPcmLatest(ASSETS);
      if (!digest) {
        return untrustedToolResult({
          error: 'no_digests',
          hint: 'The mirror is empty; run the sync/build scripts.',
        });
      }
      return untrustedToolResult(digest);
    }
  );

  h.tools(
    'pcm_search_items',
    'Search items within a PCMedicalist digest body. Filters against the mirrored top-items per layer (capped): filter by layer id, keyword, CVE, or limit.',
    {
      date: z.string().describe('Digest date, YYYY-MM-DD.'),
      layer: z
        .number()
        .int()
        .min(1)
        .max(11)
        .optional()
        .describe(
          'Intelligence layer id (1 Standards, 3 Cryptography, 5 Security News, 6 Vendor Research, 8 Vulnerability Intel, 10 AI Security, ...)'
        ),
      keyword: z.string().optional().describe('Case-insensitive substring match against title/summary/source/category'),
      cve: z.string().optional().describe('CVE id to match against the item cves array'),
      limit: z.number().int().min(1).max(200).optional().describe('Max items to return (default 50)'),
    },
    async ({ date, layer, keyword, cve, limit }) => {
      const digest = await getPcmDigest(ASSETS, date);
      if (!digest) {
        return untrustedToolResult({
          error: 'digest_not_found',
          hint: 'Call pcm_list_digests to see available dates.',
        });
      }
      const items = searchPcmItems(digest, { layer, keyword, cve, limit: limit ?? 50 });
      return untrustedToolResult({ date, returned: items.length, items });
    }
  );

  // ── Signature-Base tools ───────────────────────────────────────
  // YARA rule set + IOC lists from Neo23x0/signature-base (DRL 1.1).
  // 746 rule files / 5784 rules + 4 IOC lists (hashes, C2, filenames,
  // keywords). Data ships in public/data/sigbase/ built by
  // scripts/build-sigbase-manifest.mjs from the upstream repo
  // github.com/Neo23x0/signature-base.

  h.tools(
    'sigbase_list_rules',
    'List YARA rule files from the Neo23x0 signature-base feed. Filter by category tag (apt, malware, expl, gen, thr...), author, or free-text keyword. Each file contains 1+ rules with metadata (description, author, date, score, references).',
    {
      tag: z
        .string()
        .optional()
        .describe(
          'Category tag from the filename prefix (apt, malware, expl, gen, thr, cve, webshell, yara_mixed, etc.)'
        ),
      author: z.string().optional().describe('Filter by author (case-insensitive substring, e.g. "Florian Roth")'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against slug, filename, identifier, author, or tags'),
      externalVars: z
        .boolean()
        .optional()
        .describe('When true, only return rule files that need LOKI/THOR external variables'),
      limit: z.number().int().min(1).max(746).optional().describe('Max rule files to return (default 50)'),
    },
    async ({ tag, author, keyword, externalVars, limit }) => {
      const idx = await loadSigBaseIndex(ASSETS);
      const rules = filterYara(idx, { tag, author, keyword, externalVars, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.counts.yaraFiles,
        totalRules: idx.counts.yaraRules,
        returned: rules.length,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        rules,
      });
    }
  );

  h.tools(
    'sigbase_get_rule',
    'Return the full YARA source of a single rule file by slug, plus its parsed rule blocks (name + meta: description, author, reference, date, hash, score, id). Use sigbase_list_rules first to discover slugs. Bodies include the header comment and the raw .yar text.',
    {
      slug: z
        .string()
        .describe('Rule file slug, e.g. "apt_apt28" or "gen_mimikatz". Get these from sigbase_list_rules.'),
    },
    async ({ slug }) => {
      const body = await getSigBaseYara(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'rule_not_found',
          slug,
          hint: 'Call sigbase_list_rules to see available slugs.',
        });
      }
      return untrustedToolResult({
        slug: body.slug,
        filename: body.filename,
        source: body.source,
        license: body.license,
        headerComment: body.headerComment,
        rules: body.rules.map((r) => ({ name: r.name, meta: r.meta })),
        externalVars: body.externalVars,
        body: body.body,
      });
    }
  );

  h.tools(
    'sigbase_list_iocs',
    'List the IOC lists in the Neo23x0 signature-base feed (hashes, C2 servers, filenames, keywords). Returns entry counts per list. Use sigbase_get_ioc to fetch entries.',
    {
      type: z.enum(['hash', 'c2', 'filename', 'keyword']).optional().describe('Restrict to a single IOC type'),
      keyword: z.string().optional().describe('Case-insensitive substring match against list slug or title'),
      limit: z.number().int().min(1).max(10).optional().describe('Max lists to return (default 10)'),
    },
    async ({ type, keyword, limit }) => {
      const idx = await loadSigBaseIndex(ASSETS);
      const lists = filterSigBaseIocs(idx, { type, keyword, limit: limit ?? 10 });
      return untrustedToolResult({
        total: idx.counts.iocFiles,
        totalEntries: idx.counts.iocEntries,
        returned: lists.length,
        source: idx.source,
        license: idx.license,
        lists,
      });
    }
  );

  h.tools(
    'sigbase_get_ioc',
    'Return the entries of a single IOC list by slug: hashes (md5/sha1/sha256 + comment), C2 domains/IPs, filename regexes (with score + false-positive exclusion), or malicious keywords. Optional keyword filter narrows entries.',
    {
      slug: z
        .string()
        .describe(
          'IOC list slug: "hash-iocs", "c2-iocs", "filename-iocs", or "keywords". Get these from sigbase_list_iocs.'
        ),
      keyword: z.string().optional().describe('Case-insensitive substring match against value, comment, or category'),
      limit: z.number().int().min(1).max(5000).optional().describe('Max entries to return (default 1000)'),
    },
    async ({ slug, keyword, limit }) => {
      const body = await getSigBaseIoc(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'ioc_list_not_found',
          slug,
          hint: 'Call sigbase_list_iocs to see available slugs.',
        });
      }
      const entries = searchSigBaseIocEntries(body, keyword, limit ?? 1000);
      return untrustedToolResult({
        slug: body.slug,
        title: body.title,
        type: body.type,
        source: body.source,
        license: body.license,
        total: body.entryCount,
        returned: entries.length,
        entries,
      });
    }
  );

  // ── Breach Watch tools ────────────────────────────────────────
  // Live breach/leak data from 6 free public trackers
  // (ransomware.live + ransomlook.io + Darkfield +
  // RecentBreaches.com + CTI.FYI + XposedOrNot). Data ships in
  // public/data/breach-watch/ built by scripts/build-breach-watch.mjs.

  h.tools(
    'bw_list_breaches',
    'List live breach/leak/ransomware claims from free public trackers. Filter by threat actor group, category (ransomware, data_breach, combo_list, source_code, credential_leak), severity, country, days back, or free-text keyword.',
    {
      group: z.string().optional().describe('Filter by threat actor group name (e.g. dragonforce, qilin, lockbit)'),
      category: z
        .enum(['ransomware', 'data_breach', 'combo_list', 'source_code', 'credential_leak', 'other'])
        .optional()
        .describe('Restrict to a single breach category'),
      severity: z
        .enum(['critical', 'high', 'medium', 'low', 'unknown'])
        .optional()
        .describe('Filter by severity level'),
      country: z.string().optional().describe('Filter by victim country (ISO name or code)'),
      daysBack: z.number().int().min(1).max(365).optional().describe('Only breaches within this many days'),
      keyword: z.string().optional().describe('Case-insensitive substring match against slug / title / group'),
      limit: z.number().int().min(1).max(200).optional().describe('Max breaches to return (default 100)'),
    },
    async ({ group, category, severity, country, daysBack, keyword, limit }) => {
      const idx = await loadBwIndex(ASSETS);
      const breaches = filterBreaches(idx, {
        group: group || undefined,
        category: (category as NonNullable<Parameters<typeof filterBreaches>[1]>['category']) || undefined,
        severity: (severity as NonNullable<Parameters<typeof filterBreaches>[1]>['severity']) || undefined,
        country: country || undefined,
        daysBack,
        keyword: keyword || undefined,
        limit: limit ?? 100,
      });
      return untrustedToolResult({
        total: idx.counts.breaches,
        returned: breaches.length,
        source: idx.source,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        breaches,
      });
    }
  );

  h.tools(
    'bw_get_breach',
    'Return the full body of a single breach/leak claim by slug. Includes description, source URL, activity sector, and references. Use bw_list_breaches first to discover slugs.',
    {
      slug: z
        .string()
        .describe(
          'Breach slug, e.g. "dragonforce-southport-outdoor-living-2026-07-16". Get these from bw_list_breaches.'
        ),
    },
    async ({ slug }) => {
      const body = await getBwBreach(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'breach_not_found',
          slug,
          hint: 'Call bw_list_breaches to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'bw_list_groups',
    'List threat actor groups tracked in the Breach Watch database with their breach counts and top category. Filter by keyword or minimum count.',
    {
      keyword: z.string().optional().describe('Filter groups by name substring'),
      minCount: z.number().int().min(1).optional().describe('Only groups with at least this many breaches'),
      limit: z.number().int().min(1).max(200).optional().describe('Max groups to return (default 100)'),
    },
    async ({ keyword, minCount, limit }) => {
      const idx = await loadBwIndex(ASSETS);
      const groups = listGroups(idx, { keyword: keyword || undefined, minCount, limit: limit ?? 100 });
      return untrustedToolResult({
        total: idx.groups.length,
        returned: groups.length,
        source: idx.source,
        groups,
      });
    }
  );
}
