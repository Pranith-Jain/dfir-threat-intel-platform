/**
 * dfir-manifests MCP tool registrations.
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
  aiPlaybookStats,
  filterAiPlaybookRiskIds,
  getAiPlaybookCveRefs,
  getAiPlaybookLayer,
  getAiPlaybookRiskId,
  listAiPlaybookLayers,
  loadAiPlaybookIndex,
  riskIdsForLayer,
} from '../lib/ai-playbook-manifest';
import {
  anarchyCacheStats,
  filterAnarchyCourses,
  getAnarchyCourse,
  loadAnarchyIndex,
  recommendAnarchyCourses,
  similarAnarchyCourses,
} from '../lib/anarchy-manifest';
import {
  cairnCacheStats,
  filterCairnFilters,
  getCairnFamily,
  getCairnRule,
  listCairnFamilies,
  listCairnRules,
  loadCairnArchetypes,
  loadCairnFilters,
  loadCairnIndex,
  scanCairnText,
} from '../lib/cairn-manifest';
import {
  classifyConsent,
  denaliCacheStats,
  evaluateFailedSignins,
  evaluateRiskySequences,
  getDenaliDoc,
  getDenaliRule,
  listDenaliDocs,
  listDenaliRules,
  loadDenaliIndex,
  loadDenaliRules,
  loadDenaliTaxonomy,
} from '../lib/denali-manifest';
import {
  getNovaRule,
  listNovaRules,
  loadNovaIndex,
  loadNovaTaxonomy,
  novaCacheStats,
  scanNovaPrompt,
} from '../lib/nova-manifest';

// ORCA AI Incident Archive (CC BY 4.0) + MMD toolkit catalog
import {
  filterOrcaIncidents,
  getOrcaIncident,
  loadOrcaIndex,
  loadOrcaStats,
  orcaCacheStats,
} from '../lib/orca-manifest';
import { getMmdCategory, listMmdTools, loadMmdCommits, loadMmdIndex, mmdCacheStats } from '../lib/mmd-manifest';
import { filterArtifacts, getWinRegArtifact, loadWinRegIndex, winRegCacheStats } from '../lib/winreg-manifest';
import type { DenaliActivity } from '../lib/denali-manifest';
export function registerDfirManifestsTools(h: McpToolHost): void {
  // Was: `if (h.env.ASSETS) { const ASSETS = h.env.ASSETS; ... }`
  const ASSETS = h.env.ASSETS;
  if (!ASSETS) return;

  // ── WinReg DFIR tools ──────────────────────────────────────────
  // Windows Registry forensic artifact reference. 292 artifacts, 16
  // categories, mapped to MITRE ATT&CK. Data ships in
  // public/data/winreg/ built from the upstream schema at
  // github.com/dfir-scripts/dfir-scripts.github.io (MIT).
  // Upstream: https://dfir-scripts.github.io/registry/

  h.tools(
    'winreg_list_artifacts',
    'List Windows Registry forensic artifacts from the WinReg DFIR reference. Filter by category, hive, MITRE technique, or free-text keyword.',
    {
      category: z.string().optional().describe('Restrict to a single category key (e.g. "autostart_and_persistence")'),
      hive: z
        .string()
        .optional()
        .describe('Filter by registry hive (NTUSER, SOFTWARE, SYSTEM, SAM, SECURITY, AMCACHE, USRCLASS)'),
      technique: z.string().optional().describe('Filter by MITRE ATT&CK technique ID (e.g. "T1547.001")'),
      keyword: z
        .string()
        .optional()
        .describe('Case-insensitive substring match against name, category, hive, technique, or tool'),
      limit: z.number().int().min(1).max(292).optional().describe('Max artifacts to return (default 50)'),
    },
    async ({ category, hive, technique, keyword, limit }) => {
      const idx = await loadWinRegIndex(ASSETS);
      const artifacts = filterArtifacts(idx, { category, hive, technique, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.counts.artifacts,
        returned: artifacts.length,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        artifacts,
      });
    }
  );

  h.tools(
    'winreg_get_artifact',
    'Return the full body of a single Windows Registry forensic artifact by slug. Includes registry keys, description, forensic value, parsers, and MITRE mapping. Use winreg_list_artifacts first to discover slugs.',
    {
      slug: z
        .string()
        .describe(
          'Artifact slug, e.g. "autostart-and-persistence-run-runonce-autostart-keys". Get these from winreg_list_artifacts.'
        ),
    },
    async ({ slug }) => {
      const body = await getWinRegArtifact(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'artifact_not_found',
          slug,
          hint: 'Call winreg_list_artifacts to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'winreg_list_categories',
    'List the Windows Registry artifact categories in the WinReg DFIR reference. Returns category keys, names, descriptions, and artifact counts.',
    {},
    async () => {
      const idx = await loadWinRegIndex(ASSETS);
      return untrustedToolResult({
        total: idx.categories.length,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        categories: idx.categories,
      });
    }
  );

  h.tools(
    'anarchy_list_courses',
    'List courses from the Anarchy (kazamadono.github.io) portal — 1708 courses across 20 tracks (AI/ML, Low Level, PsyOps, Defensive, Offensive, OSINT, Game Hacking, BugBounty, Crypto, Reversing, Cloud, Forensics, CTF, Blockchain, IoT/HW, Dev/CS, Math). Filter by tag, difficulty, provider, hours, or free-text query. Daily sync from https://kazamadono.github.io/courses.json.',
    {
      tag: z
        .string()
        .optional()
        .describe(
          'Filter by tag: aiml, exploits, psyops, bio, infra, blue, red, osint, game, webappsec, crypto, re, mobile, cloud, forensics, ctf, blockchain, iot, dev, math, project'
        ),
      q: z.string().optional().describe('Free-text search across title, preview, tags, provider'),
      difficulty: z.enum(['beginner', 'intermediate', 'advanced']).optional().describe('Filter by difficulty'),
      provider: z
        .string()
        .optional()
        .describe('Filter by provider name/host substring (e.g. "TryHackMe", "github.com")'),
      maxHours: z.number().int().min(1).max(12).optional().describe('Only courses <= this many hours'),
      sort: z.enum(['id', 'hours', 'difficulty']).optional().describe('Sort results'),
      limit: z.number().int().min(1).max(500).optional().describe('Max courses to return (default 50)'),
    },
    async ({ tag, q, difficulty, provider, maxHours, sort, limit }) => {
      const idx = await loadAnarchyIndex(ASSETS);
      const filtered = filterAnarchyCourses(idx, {
        tag,
        q,
        difficulty,
        provider,
        maxHours,
        sort,
        limit: limit ?? 50,
      });
      return untrustedToolResult({
        total: idx.counts.courses,
        returned: filtered.length,
        categories: idx.categories,
        syncedAt: idx.syncedAt,
        builtAt: idx.builtAt,
        source: idx.source,
        sourceUrl: idx.url,
        courses: filtered,
      });
    }
  );

  h.tools(
    'anarchy_recommend',
    'Rank Anarchy courses for a user library. Deterministic scorer (no LLM): tag affinity with saved/done/doing courses, same-provider affinity, and a difficulty ladder one rung above completed courses. Excludes library courses. Empty library returns beginner-friendly popular picks.',
    {
      saved: z.array(z.string()).optional().describe('Bookmarked course IDs, e.g. ["0001","0042"]'),
      done: z.array(z.string()).optional().describe('Completed course IDs'),
      doing: z.array(z.string()).optional().describe('In-progress course IDs'),
      maxHours: z.number().int().min(1).max(12).optional().describe('Only courses within this many hours'),
      limit: z.number().int().min(1).max(50).optional().describe('Max recommendations (default 12)'),
    },
    async ({ saved, done, doing, maxHours, limit }) => {
      const idx = await loadAnarchyIndex(ASSETS);
      const recs = recommendAnarchyCourses(idx, { saved, done, doing, maxHours, limit: limit ?? 12 });
      return untrustedToolResult({
        total: idx.counts.courses,
        returned: recs.length,
        recommendations: recs.map((r) => ({ ...r.course, score: r.score, reasons: r.reasons })),
      });
    }
  );

  h.tools(
    'anarchy_similar',
    'Courses similar to one Anarchy course: shared tracks first, then same provider, then same difficulty. Use anarchy_list_courses first to discover IDs.',
    {
      id: z.string().describe('Course ID, e.g. "0001".'),
      limit: z.number().int().min(1).max(20).optional().describe('Max similar courses (default 4)'),
    },
    async ({ id, limit }) => {
      const idx = await loadAnarchyIndex(ASSETS);
      const sims = similarAnarchyCourses(idx, id, limit ?? 4);
      if (sims.length === 0)
        return untrustedToolResult({
          error: `anarchy course not found: ${id}`,
          hint: 'Call anarchy_list_courses to see available IDs.',
        });
      return untrustedToolResult({
        id,
        returned: sims.length,
        similar: sims.map((r) => ({ ...r.course, score: r.score, reasons: r.reasons })),
      });
    }
  );

  h.tools(
    'anarchy_get_course',
    'Return the full body of a single Anarchy course by ID. Includes title, full description, tags, and external href. Use anarchy_list_courses first to discover IDs.',
    {
      id: z.string().describe('Course ID, e.g. "0001" or "0420". Get these from anarchy_list_courses.'),
    },
    async ({ id }) => {
      const body = await getAnarchyCourse(ASSETS, String(id).padStart(4, '0'));
      if (!body)
        return untrustedToolResult({
          error: `anarchy course not found: ${id}`,
          hint: 'Call anarchy_list_courses to see available IDs.',
        });
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'anarchy_stats',
    'Return cache + manifest stats for the Anarchy course catalog: course counts, top tags, sync timestamps, and LRU cache hit/miss ratios.',
    {},
    async () => {
      const idx = await loadAnarchyIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        categories: idx.categories,
        topTags: idx.topTags,
        source: idx.source,
        sourceUrl: idx.url,
        syncedAt: idx.syncedAt,
        builtAt: idx.builtAt,
        author: idx.author,
        authorUrl: idx.authorUrl,
        cache: anarchyCacheStats(),
      });
    }
  );

  h.tools(
    'winreg_stats',
    'Return cache + manifest stats for the WinReg DFIR data: artifact counts, hive types, MITRE technique coverage, and LRU body-cache hit/miss ratios.',
    {},
    async () => {
      const idx = await loadWinRegIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        hives: idx.hives,
        tactics: idx.tactics,
        techniques: idx.techniques,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: winRegCacheStats(),
      });
    }
  );

  // ── CAIRN tools ─────────────────────────────────────────────────
  // Cisco-Talos Cognitive Artifact Intelligence Research Network (MIT):
  // 26 tiered YARA rules (T1 primitive / T2 behavioral / T3 family
  // attribution) over VT-metadata scan text, 27 acquisition filters,
  // A0–A11 archetypes, 10 family reports. Edge scan engine is a TS port
  // of cairn/rules.py (substring hits + condition subset, fail-closed).

  h.tools(
    'cairn_list_rules',
    'List CAIRN cognitive-artifact detection rules (26 total: 9 T1 primitive, 8 T2 behavioral, 9 T3 family attribution). Filter by tier, family, or keyword.',
    {
      tier: z.enum(['T1', 'T2', 'T3']).optional().describe('Filter by rule tier'),
      family: z.string().optional().describe('Filter by attributed family (e.g. "PromptLock")'),
      keyword: z.string().optional().describe('Substring match against name, class, or description'),
      limit: z.number().int().min(1).max(26).optional().describe('Max rules (default 50, capped at 26)'),
    },
    async ({ tier, family, keyword, limit }) => {
      const idx = await loadCairnIndex(ASSETS);
      const rules = listCairnRules(idx, { tier, family, keyword, limit: limit ?? 50 });
      return untrustedToolResult({ total: idx.counts.rules, returned: rules.length, source: idx.source, rules });
    }
  );

  h.tools(
    'cairn_get_rule',
    'Return the full body of a CAIRN rule: strings, condition, confidence, artifact class, family, and reference. Use cairn_list_rules first to discover names.',
    {
      name: z.string().describe('Rule name, e.g. "T3-PromptLock_LLM_Lua_Ransomware".'),
    },
    async ({ name }) => {
      const body = await getCairnRule(ASSETS, name);
      if (!body) {
        return untrustedToolResult({
          error: 'rule_not_found',
          name,
          hint: 'Call cairn_list_rules to see available names.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'cairn_scan_text',
    'Run CAIRN tiered rules over pasted VT-metadata scan text (AV labels, PE strings, sandbox IOCs, ScriptBlock text). Returns T1/T2/T3 matches sorted with family attribution first. Pure local matching, no binary needed.',
    {
      text: z.string().min(1).max(200000).describe('Scan text to evaluate (up to 200KB)'),
      tier: z.enum(['T1', 'T2', 'T3']).optional().describe('Only evaluate rules at this tier'),
      rule: z.string().optional().describe('Only evaluate a single rule by name'),
      limit: z.number().int().min(1).max(26).optional().describe('Max matches to return'),
    },
    async ({ text, tier, rule, limit }) => {
      const idx = await loadCairnIndex(ASSETS);
      let names = idx.rules.map((r) => r.name);
      if (rule) names = names.filter((n) => n.toLowerCase() === rule.toLowerCase());
      if (tier) names = names.filter((n) => idx.rules.find((r) => r.name === n)?.tier === tier);
      if (names.length === 0) {
        return untrustedToolResult({
          error: 'no_rules_match_filter',
          hint: 'Call cairn_list_rules to see available names.',
        });
      }
      const full = (await Promise.all(names.map((n) => getCairnRule(ASSETS, n)))).filter((r) => r !== null);
      const matches = scanCairnText(full, text);
      const capped = typeof limit === 'number' ? matches.slice(0, limit) : matches;
      const tiers = [...new Set(capped.map((m) => m.tier))];
      return untrustedToolResult({
        matched: capped.length > 0,
        rulesEvaluated: full.length,
        topTier: tiers.includes('T3') ? 'T3' : tiers.includes('T2') ? 'T2' : tiers.includes('T1') ? 'T1' : null,
        families: [...new Set(capped.map((m) => m.family).filter(Boolean))],
        matches: capped,
      });
    }
  );

  h.tools(
    'cairn_list_families',
    'List the 10 published CAIRN AI-malware families (PROMPTLOCK, HONESTCUE, CLOSEDQUORUM, TEAMPCP, LAMEHUG, …) with platform and archetype. Filter by archetype (A0–A11) or keyword.',
    {
      archetype: z.string().optional().describe('Filter by archetype, e.g. "A1" or "A3"'),
      keyword: z.string().optional().describe('Substring match against name, platform, or summary'),
    },
    async ({ archetype, keyword }) => {
      const families = await listCairnFamilies(ASSETS, { archetype, keyword });
      return untrustedToolResult({ total: families.length, families });
    }
  );

  h.tools(
    'cairn_get_family',
    'Return the full CAIRN family report (summary + verbatim markdown body): samples, binary details, TTPs, detection guidance. Use cairn_list_families first to discover slugs.',
    {
      slug: z.string().describe('Family slug, e.g. "promptlock".'),
    },
    async ({ slug }) => {
      const body = await getCairnFamily(ASSETS, slug);
      if (!body) {
        return untrustedToolResult({
          error: 'family_not_found',
          slug,
          hint: 'Call cairn_list_families to see available slugs.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'cairn_list_filters',
    'List the 27 CAIRN VirusTotal acquisition channels (24 enabled): discovery/prompt/agentic/runtime/api/evasion/offensive/script/hunt queries with min detections. Filter by category or keyword.',
    {
      category: z
        .string()
        .optional()
        .describe('Filter by category (discovery, prompt, agentic, runtime, api, evasion, offensive, script, hunt)'),
      enabled_only: z.boolean().optional().describe('Only enabled channels'),
      keyword: z.string().optional().describe('Substring match against name, description, or query text'),
    },
    async ({ category, enabled_only, keyword }) => {
      const data = await loadCairnFilters(ASSETS);
      const filters = filterCairnFilters(data, { category, enabledOnly: enabled_only, keyword });
      return untrustedToolResult({
        total: data.total,
        enabled: data.enabled,
        categories: data.categories,
        returned: filters.length,
        filters,
      });
    }
  );

  h.tools(
    'cairn_stats',
    'Return CAIRN manifest stats: rule counts by tier, filter/family/archetype counts, source + license, and edge cache ratios.',
    {},
    async () => {
      const idx = await loadCairnIndex(ASSETS);
      const arch = await loadCairnArchetypes(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        filterCategories: idx.filterCategories,
        archetypes: arch.archetypes.map((a) => ({ id: a.id, name: a.name, families: a.families })),
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        cache: cairnCacheStats(),
      });
    }
  );

  // ── NOVA tools ──────────────────────────────────────────────────
  // Prompt pattern matching (Nova-Hunting/nova-framework engine +
  // nova-rules collection, MIT): 69 .nov rules with
  // keywords/semantics/llm/condition sections. Edge evaluates keywords
  // only; semantics/llm stages are fail-closed gates.

  h.tools(
    'nova_list_rules',
    'List NOVA prompt-hunting rules (69 total across jailbreak, injection, encoding, exfiltration, incidents). Filter by category (e.g. "prompt_manipulation/jailbreak"), severity, or keyword.',
    {
      category: z.string().optional().describe('Filter by category slug'),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'unknown']).optional().describe('Filter by severity'),
      keyword: z.string().optional().describe('Substring match against name, file, or description'),
      keyword_only: z.boolean().optional().describe('Only fully edge-evaluable rules (no semantics/llm gates)'),
      limit: z.number().int().min(1).max(69).optional().describe('Max rules (default 50)'),
    },
    async ({ category, severity, keyword, keyword_only, limit }) => {
      const idx = await loadNovaIndex(ASSETS);
      const rules = listNovaRules(idx, {
        category,
        severity,
        keyword,
        keywordOnly: keyword_only,
        limit: limit ?? 50,
      });
      return untrustedToolResult({ total: idx.counts.rules, returned: rules.length, source: idx.source, rules });
    }
  );

  h.tools(
    'nova_get_rule',
    'Return the full body of a NOVA rule: keyword/regex patterns, semantic prompts + thresholds, LLM prompts + thresholds, and the condition. Use nova_list_rules first to discover names.',
    {
      name: z.string().describe('Rule name, e.g. "PromptInjectionJailbreak".'),
    },
    async ({ name }) => {
      const body = await getNovaRule(ASSETS, name);
      if (!body) {
        return untrustedToolResult({
          error: 'rule_not_found',
          name,
          hint: 'Call nova_list_rules to see available names.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'nova_scan_prompt',
    'Scan a prompt against NOVA rules on the edge (keyword/regex stage with Unicode normalization). Rules gated on semantics/LLM evaluation return needs-semantics/needs-llm instead of a false negative. Never sends the prompt anywhere.',
    {
      prompt: z.string().min(1).max(50000).describe('Prompt text to scan (up to 50KB)'),
      rule: z.string().optional().describe('Scan a single rule by name'),
      category: z.string().optional().describe('Only scan rules in this category'),
      severity: z.string().optional().describe('Only scan rules at this severity'),
      keyword_only: z.boolean().optional().describe('Only scan fully edge-evaluable rules'),
      limit: z.number().int().min(1).max(69).optional().describe('Max rules to evaluate'),
    },
    async ({ prompt, rule, category, severity, keyword_only, limit }) => {
      const idx = await loadNovaIndex(ASSETS);
      let slim = idx.rules;
      if (rule) slim = slim.filter((r) => r.name.toLowerCase() === rule.toLowerCase());
      if (category) slim = slim.filter((r) => (r.category ?? '').toLowerCase() === category.toLowerCase());
      if (severity) slim = slim.filter((r) => (r.severity ?? '').toLowerCase() === severity.toLowerCase());
      if (keyword_only) slim = slim.filter((r) => r.keywordOnly);
      if (typeof limit === 'number') slim = slim.slice(0, limit);
      if (slim.length === 0) {
        return untrustedToolResult({
          error: 'no_rules_match_filter',
          hint: 'Call nova_list_rules to see available names.',
        });
      }
      const full = (await Promise.all(slim.map((r) => getNovaRule(ASSETS, r.name)))).filter((r) => r !== null);
      const results = full.map((r) => scanNovaPrompt(r, prompt));
      const matched = results.filter((r) => r.matched);
      const gated = results.filter((r) => r.verdict === 'needs-semantics' || r.verdict === 'needs-llm');
      return untrustedToolResult({
        matched: matched.length > 0,
        rulesEvaluated: full.length,
        matches: matched.map((m) => ({
          rule: m.ruleName,
          matchingKeywords: m.matchingKeywords,
          condition: m.condition,
        })),
        gated: gated.map((g) => ({ rule: g.ruleName, verdict: g.verdict, warnings: g.evaluationWarnings })),
      });
    }
  );

  h.tools(
    'nova_taxonomy',
    'Return the NOVA threat taxonomy: 4 categories (prompt manipulation, abusing legitimate functions, suspicious prompt patterns, abnormal outputs) with 38 threat types and examples.',
    {},
    async () => {
      const tax = await loadNovaTaxonomy(ASSETS);
      return untrustedToolResult(tax);
    }
  );

  h.tools(
    'nova_stats',
    'Return NOVA manifest stats: rule/pattern counts, severity mix, keyword-only coverage, source + license, and edge cache ratios.',
    {},
    async () => {
      const idx = await loadNovaIndex(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        byCategory: idx.byCategory,
        bySeverity: idx.bySeverity,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        engineSource: idx.engineSource,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        edgeNote: idx.edgeNote,
        cache: novaCacheStats(),
      });
    }
  );

  // ── ORCA tools ──────────────────────────────────────────────────
  // Open database of real-world AI agent security incidents
  // (Continuum-AI-Corp/Orca-AI-Incident-Archive, CC BY 4.0). 417 records,
  // 2024-12 → 2026-11, every record with ≥1 clickable primary source.

  h.tools(
    'orca_list_incidents',
    'List AI agent security incidents from the ORCA AI Incident Archive (417 records, 2024-12 → 2026-11). Filter by kind (incident/vulnerability/research/report/policy), severity, attack type (e.g. SUPPLY/WEAPON/MCP/IPI), real_harm, region, month, landmark, or keyword. kind=policy/report rows are informational moves, not incidents.',
    {
      kind: z
        .enum(['incident', 'vulnerability', 'research', 'report', 'policy'])
        .optional()
        .describe('Filter by record kind'),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional().describe('Filter by severity'),
      type: z.string().optional().describe('Attack type code, e.g. SUPPLY, WEAPON, MCP, IPI, CRED'),
      harm: z
        .enum(['true', 'false', 'null'])
        .optional()
        .describe("real_harm: 'true' = confirmed victim, 'false' = research demo, 'null' = policy/report"),
      region: z.string().optional().describe('e.g. GLOBAL, US, EU, CN'),
      month: z
        .string()
        .regex(/^\d{4}-\d{2}$/)
        .optional()
        .describe('Month, e.g. 2026-07'),
      landmark: z.boolean().optional().describe('Only landmark entries'),
      keyword: z.string().optional().describe('Substring match against title, types, regions'),
      limit: z.number().int().min(1).max(200).optional().describe('Max rows (default 30, capped at 200)'),
    },
    async ({ kind, severity, type, harm, region, month, landmark, keyword, limit }) => {
      const idx = await loadOrcaIndex(ASSETS);
      const realHarm = harm === undefined ? undefined : harm === 'null' ? null : harm === 'true' ? true : false;
      const rows = filterOrcaIncidents(idx.incidents, {
        kind,
        severity,
        type,
        realHarm,
        region,
        month,
        landmark,
        keyword,
        limit: limit ?? 30,
      });
      return untrustedToolResult({
        total: idx.counts.records,
        returned: rows.length,
        upstreamVersion: idx.upstreamVersion,
        source: idx.source,
        license: idx.license,
        incidents: rows,
      });
    }
  );

  h.tools(
    'orca_get_incident',
    'Return the full ORCA incident record: summary, confirmed sources with URLs, dates, severity, real_harm, ai_involvement, and a deep link to the upstream Markdown record. Use orca_list_incidents first to discover ids.',
    {
      id: z.string().describe('Record id, e.g. "2026-07-09-openai-agents-breach-huggingface".'),
    },
    async ({ id }) => {
      const body = await getOrcaIncident(ASSETS, id);
      if (!body) {
        return untrustedToolResult({
          error: 'incident_not_found',
          id,
          hint: 'Call orca_list_incidents to see available ids.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'orca_stats',
    'Return ORCA archive stats: counts by severity/kind/type/region/real_harm, monthly volume, source totals, source + license, and cache state.',
    {},
    async () => {
      const idx = await loadOrcaIndex(ASSETS);
      const stats = await loadOrcaStats(ASSETS);
      return untrustedToolResult({
        upstreamVersion: idx.upstreamVersion,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        stats: stats ?? idx.stats,
        cache: orcaCacheStats(),
      });
    }
  );

  // ── MMD tools ───────────────────────────────────────────────────
  // MalwareMustDie (MMD) shared codes & tools catalog
  // (github.com/unixfreaxjp/malwaremustdie): 228 malware-analysis files
  // across 12 language categories + recent commit activity feed.

  h.tools(
    'mmd_list_tools',
    'List tools & scripts from the MalwareMustDie (MMD) shared codes repository (228 files across Python/Bash/Perl/C/radare2/…). Filter by category (language directory), kind (script/source/doc/webtool/binary), file extension, or keyword. Every entry deep-links the upstream file.',
    {
      category: z
        .string()
        .optional()
        .describe(
          'Language dir: Python, Bash, Perl, Clang, Autoit, batch, HTML, etc, radare2stuff, radare2test, slides, wiki'
        ),
      kind: z.string().optional().describe('script, source, doc, webtool, slides, archive, binary, image, resource'),
      ext: z.string().optional().describe('File extension, e.g. sh, py, pl, c'),
      keyword: z.string().optional().describe('Substring match against the repo path'),
      limit: z.number().int().min(1).max(250).optional().describe('Max files (default 50, capped at 250)'),
    },
    async ({ category, kind, ext, keyword, limit }) => {
      const idx = await loadMmdIndex(ASSETS);
      const tools = listMmdTools(idx, { category, kind, ext, keyword, limit: limit ?? 50 });
      return untrustedToolResult({
        total: idx.counts.files,
        returned: tools.length,
        lastCommit: idx.lastCommit,
        source: idx.source,
        license: idx.license,
        tools,
      });
    }
  );

  h.tools(
    'mmd_get_category',
    'Return one MMD category (language directory) with its full file listing and sizes. Use mmd_list_tools or mmd_stats to discover categories.',
    {
      category: z.string().describe('e.g. "Python", "Bash", "radare2stuff".'),
    },
    async ({ category }) => {
      const body = await getMmdCategory(ASSETS, category);
      if (!body) {
        return untrustedToolResult({
          error: 'category_not_found',
          category,
          hint: 'Categories: Python, Bash, Perl, Clang, Autoit, batch, HTML, etc, radare2stuff, radare2test, slides, wiki.',
        });
      }
      return untrustedToolResult(body);
    }
  );

  h.tools(
    'mmd_recent_activity',
    'Return recent MMD upstream commits (activity feed) plus repository counts. The manifest rebuilds weekly, so new upstream pushes surface here.',
    {},
    async () => {
      const idx = await loadMmdIndex(ASSETS);
      const commits = await loadMmdCommits(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        lastCommit: idx.lastCommit,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        commits: commits?.commits ?? idx.recentCommits,
        cache: mmdCacheStats(),
      });
    }
  );

  // ── Denali tools ────────────────────────────────────────────────
  // Evidence-led AI security reference (transilienceai/denali,
  // Apache-2.0): 9 deterministic issue/detection rules, 16-kind asset
  // taxonomy, 38 ADR/guide docs, plus stateless sliding-window checks
  // over caller-supplied activity JSON (no Postgres, no credentials).

  h.tools(
    'denali_list_rules',
    'List the 9 deterministic Denali correlation rules (3 issue + 6 runtime detection) with exact UIDs, thresholds, and evidence bounds. Filter by kind or keyword.',
    {
      kind: z.enum(['issue', 'runtime_detection']).optional().describe('Filter by rule kind'),
      keyword: z.string().optional().describe('Substring match against UID, title, or description'),
      limit: z.number().int().min(1).max(20).optional().describe('Max rules (default 20)'),
    },
    async ({ kind, keyword, limit }) => {
      const data = await loadDenaliRules(ASSETS);
      const rules = listDenaliRules(data, { kind, keyword, limit: limit ?? 20 });
      return untrustedToolResult({ total: data.total, kinds: data.kinds, returned: rules.length, rules });
    }
  );

  h.tools(
    'denali_get_rule',
    'Return the full semantics of one Denali rule: inputs, thresholds/windows/scopes, and what the evidence does NOT prove. Use denali_list_rules first to discover UIDs.',
    {
      uid: z.string().describe('Rule UID, e.g. "DENALI-RUNTIME-ENTRA-FAILURES-001".'),
    },
    async ({ uid }) => {
      const data = await loadDenaliRules(ASSETS);
      const rule = getDenaliRule(data, uid);
      if (!rule) {
        return untrustedToolResult({
          error: 'rule_not_found',
          uid,
          hint: 'Call denali_list_rules to see available UIDs.',
        });
      }
      return untrustedToolResult(rule);
    }
  );

  h.tools(
    'denali_evaluate_activity',
    'Run Denali stateless checks over runtime activity JSON: repeated failed AI sign-ins (≥3/24h per actor+app), high-impact consent grants, retrieval→mutation sequences (5-min window). Proves sequence + identity only — never intent.',
    {
      activities: z
        .array(
          z.object({
            category: z.string(),
            outcome: z.string(),
            occurredAt: z.string(),
            actorUid: z.string().optional(),
            appId: z.string().optional(),
            session: z.string().optional(),
            operation: z.string().optional(),
            scopes: z.array(z.string()).optional(),
          })
        )
        .min(1)
        .max(500)
        .describe(
          'Runtime activities (max 500): category/outcome/occurredAt plus actorUid/appId/session/operation/scopes as applicable'
        ),
    },
    async ({ activities }) => {
      const acts = activities as DenaliActivity[];
      const signins = evaluateFailedSignins(acts);
      const consents = acts
        .map((a) => ({ activity: a, verdict: classifyConsent(a) }))
        .filter((x) => x.verdict.isHighImpactConsent);
      const sequences = evaluateRiskySequences(acts);
      return untrustedToolResult({
        activitiesEvaluated: acts.length,
        findingCount: signins.candidates.length + consents.length + sequences.candidates.length,
        failedSignins: signins,
        highImpactConsents: {
          count: consents.length,
          ruleUid: 'DENALI-RUNTIME-ENTRA-CONSENT-001',
          items: consents.map((x) => ({ operation: x.activity.operation, scopes: x.verdict.highImpactScopes })),
        },
        riskySequences: sequences,
        evidenceNote: 'Sequence and identity only — no claim about intent, permission exercise, or execution.',
      });
    }
  );

  h.tools(
    'denali_list_docs',
    'List the 38 Denali architecture ADRs + guides (onboarding contracts, code-to-cloud, runtime AIDR, hosted multi-tenancy). Filter by kind or keyword.',
    {
      kind: z.enum(['adr', 'guide']).optional().describe('Filter by doc kind'),
      keyword: z.string().optional().describe('Substring match against slug, title, or summary'),
    },
    async ({ kind, keyword }) => {
      const docs = await listDenaliDocs(ASSETS, { kind, keyword });
      return untrustedToolResult({ total: docs.length, docs });
    }
  );

  h.tools(
    'denali_get_doc',
    'Return a verbatim Denali ADR/guide body (markdown): onboarding contracts, correlation semantics, runtime detection design. Use denali_list_docs first to discover slugs.',
    {
      slug: z.string().describe('Doc slug, e.g. "0018-self-service-aws-connections".'),
    },
    async ({ slug }) => {
      const doc = await getDenaliDoc(ASSETS, slug);
      if (!doc) {
        return untrustedToolResult({
          error: 'doc_not_found',
          slug,
          hint: 'Call denali_list_docs to see available slugs.',
        });
      }
      return untrustedToolResult(doc);
    }
  );

  h.tools(
    'denali_stats',
    'Return Denali manifest stats: rule/taxonomy/doc counts, evidence principles, source + license, and edge cache ratios.',
    {},
    async () => {
      const idx = await loadDenaliIndex(ASSETS);
      const tax = await loadDenaliTaxonomy(ASSETS);
      return untrustedToolResult({
        counts: idx.counts,
        assetKinds: tax.assetKinds.map((k) => k.id),
        coverageStates: tax.coverageStates.map((s) => s.id),
        evidencePrinciples: tax.evidencePrinciples,
        source: idx.source,
        sourceUrl: idx.sourceUrl,
        license: idx.license,
        replicatedAt: idx.replicatedAt,
        edgeNote: idx.edgeNote,
        cache: denaliCacheStats(),
      });
    }
  );

  // ── AI Security Playbook tools ────────────────────────────────────
  // Taxonomy layer from aisecurity.zone: 8 system divisions (44 chapters) and
  // 20 risk identifiers (OWASP LLM01-10 + the author's ASI01-10).
  //
  // LICENCE: upstream declares no reuse licence, so this surface is
  // STRUCTURE ONLY — divisions, identifiers, CVE references and deep links.
  // No chapter prose. See scripts/build-ai-playbook.mjs.

  h.tools(
    'ai_playbook_list_layers',
    'List the 8 system divisions of the AI Security Playbook (I model .. VIII governance), with chapter counts and the risk identifiers each division defines.',
    {},
    async () => {
      const layers = await listAiPlaybookLayers(ASSETS);
      return untrustedToolResult({ total: layers.length, layers });
    }
  );

  h.tools(
    'ai_playbook_get_layer',
    'Get one AI Security Playbook division by roman id (I..VIII) or slug, including the risk identifiers it defines.',
    {
      id: z
        .string()
        .describe(
          'Roman numeral (I, II, ... VIII) or slug (model, context, loop, protocol, infra, method, program, govern)'
        ),
    },
    async ({ id }) => {
      const layer = await getAiPlaybookLayer(ASSETS, id);
      if (!layer)
        return untrustedToolResult({
          error: `layer '${id}' not found`,
          valid: ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII'],
        });
      const idx = await loadAiPlaybookIndex(ASSETS);
      return untrustedToolResult({ ...layer, riskIdsDetailed: riskIdsForLayer(idx, layer.id) });
    }
  );

  h.tools(
    'ai_playbook_list_risk_ids',
    'List the 20 AI-security risk identifiers: OWASP Top 10 for LLM Applications (LLM01-LLM10) and the Agentic Security Index (ASI01-ASI10). Filter by scheme or layer, or search by id/name.',
    {
      scheme: z.enum(['owasp-llm', 'agentic-asi']).optional().describe('Filter by taxonomy'),
      layer: z.string().optional().describe('Filter by defining division (I..VIII)'),
      q: z.string().optional().describe('Substring match against id or name'),
      limit: z.number().int().min(1).max(20).optional().describe('Max identifiers (default 20)'),
    },
    async ({ scheme, layer, q, limit }) => {
      const ids = await filterAiPlaybookRiskIds(ASSETS, { scheme, layer, q, limit });
      return untrustedToolResult({ total: ids.length, scope: 'structure-only', riskIds: ids });
    }
  );

  h.tools(
    'ai_playbook_get_risk_id',
    'Get one AI-security risk identifier by id (e.g. LLM01, ASI06), with its name, taxonomy and defining division.',
    { id: z.string().describe('Risk identifier, e.g. LLM01 or ASI06') },
    async ({ id }) => {
      const risk = await getAiPlaybookRiskId(ASSETS, id);
      if (!risk) return untrustedToolResult({ error: `unknown risk identifier '${id}'` });
      return untrustedToolResult(risk);
    }
  );

  h.tools(
    'ai_playbook_cve_refs',
    'CVE references cited by the AI Security Playbook, enriched against our local CISA KEV snapshot so you can see which are known-exploited. Enrichment comes from our own feed, never upstream.',
    {
      kev_only: z.boolean().optional().describe('Only references present in our CISA KEV snapshot'),
    },
    async ({ kev_only }) => {
      const refs = await getAiPlaybookCveRefs(ASSETS);
      const out = kev_only ? refs.filter((r) => r.kev) : refs;
      return untrustedToolResult({
        total: out.length,
        kevMatched: refs.filter((r) => r.kev).length,
        enrichmentSource: 'local CISA KEV snapshot',
        cves: out,
      });
    }
  );

  h.tools(
    'ai_playbook_stats',
    'AI Security Playbook manifest stats: division/chapter/identifier counts, KEV matches, licence scope, and edge cache state.',
    {},
    async () => untrustedToolResult(await aiPlaybookStats(ASSETS))
  );
}
