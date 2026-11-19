/**
 * Specialist agent types for the multi-agent mesh.
 *
 * Each specialist is a domain expert that owns a subset of tools and has
 * its own planner prompt, exit conditions, and guardrails. The orchestrator
 * routes queries to the appropriate specialist(s) and merges their results.
 */

import type { AgentTool, AgentStep, AgentToolCall } from './types';
import type { ExitCondition, Guardrail } from './loop-engine';
import { classifyIntent } from './stix-translator';

export type SpecialistRole =
  | 'ioc-reputation'
  | 'threat-actor'
  | 'vulnerability'
  | 'domain-host'
  | 'malware-analysis'
  | 'detection-rules'
  | 'phishing'
  | 'ransomware'
  | 'campaign-correlation'
  | 'dark-web'
  | 'strategic-intel'
  | 'supply-chain'
  | 'soc-automation';

export interface SpecialistDef {
  role: SpecialistRole;
  label: string;
  description: string;
  handlesQueryTypes: string[];
  maxSteps: number;
  exitConditions: ExitCondition<SpecialistView>[];
  guardrails: Guardrail<SpecialistView, AgentToolCall>[];
  buildPlannerPrompt(tools: AgentTool[], step: number, maxSteps: number, query: string, steps: AgentStep[]): string;
}

export interface SpecialistView {
  stepNum: number;
  maxSteps: number;
  steps: AgentStep[];
  role: SpecialistRole;
}

export interface OrchestratorPlan {
  specialistCalls: SpecialistDispatch[];
  reasoning: string;
}

export interface SpecialistDispatch {
  role: SpecialistRole;
  query: string;
  queryType: string;
  context: Record<string, unknown>;
  maxSteps: number;
}

export interface SpecialistResult {
  role: SpecialistRole;
  steps: AgentStep[];
  findings: SpecialistFinding[];
  report: string | null;
  error: string | null;
}

export interface SpecialistFinding {
  type: 'ioc' | 'actor' | 'cve' | 'domain' | 'hash' | 'technique' | 'campaign' | 'intel';
  value: string;
  confidence: 'high' | 'medium' | 'low';
  source: string;
  detail: string;
}

function countOkResults(steps: AgentStep[]): number {
  return steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'ok').length, 0);
}

function hasToolBeenCalled(steps: AgentStep[], toolName: string): boolean {
  return steps.some((s) => s.toolCalls.some((tc) => tc.tool === toolName));
}

function okResultsForTool(steps: AgentStep[], toolName: string): number {
  return steps.reduce((n, s) => n + s.results.filter((r) => r.tool === toolName && r.status === 'ok').length, 0);
}

// ── Specialist registry ───────────────────────────────────────────────────

export const SPECIALIST_REGISTRY: Record<SpecialistRole, SpecialistDef> = {
  'ioc-reputation': {
    role: 'ioc-reputation',
    label: 'IOC Reputation Specialist',
    description: 'Checks indicators against reputation sources, correlates across feeds, assesses maliciousness.',
    handlesQueryTypes: ['ip', 'hash', 'domain', 'url'],
    maxSteps: 4,
    exitConditions: [
      {
        name: 'enough-verdicts',
        met: (v) => okResultsForTool(v.steps, 'check_ioc') >= 1 || okResultsForTool(v.steps, 'enrich_ioc_deep') >= 1,
        reason: () => 'IOC reputation verdict collected',
      },
      {
        name: 'lifecycle-mapped',
        met: (v) => hasToolBeenCalled(v.steps, 'get_ioc_lifecycle') && hasToolBeenCalled(v.steps, 'get_relationships'),
        reason: () => 'Lifecycle and relationships mapped',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'ioc-only-tools',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['ioc-reputation']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
      {
        name: 'no-duplicate-ioc-checks',
        filter: (calls, view) => {
          const seen = new Set(
            view.steps.flatMap((s) => s.toolCalls.map((tc) => `${tc.tool}:${JSON.stringify(tc.args)}`))
          );
          return calls.filter((c) => !seen.has(`${c.tool}:${JSON.stringify(c.args)}`));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, steps) => {
      const ok = countOkResults(steps);
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the IOC Reputation Specialist. Your job: determine if this indicator is malicious.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}. Results so far: ${ok} successful.

Strategy:
- Step 1: enrich_ioc_deep (single-call fan-out to all reputation sources)
- Step 2: get_relationships + get_ioc_lifecycle (map connections, assess activity)
- Step 3: generate_yara_rule + generate_hunting_queries (detection content for malicious indicators)
- Step 4: Synthesize. Do NOT retry tools that already returned results.

After ${ok >= 3 ? '3+ results' : 'enough data'}, synthesize immediately.`;
    },
  },

  'threat-actor': {
    role: 'threat-actor',
    label: 'Threat Actor Specialist',
    description: 'Profiles threat actors, maps their TTPs, tracks campaigns and victims.',
    handlesQueryTypes: ['actor', 'ransomware'],
    maxSteps: 4,
    exitConditions: [
      {
        name: 'actor-profiled',
        met: (v) => hasToolBeenCalled(v.steps, 'enrich_actor') && okResultsForTool(v.steps, 'enrich_actor') >= 1,
        reason: () => 'Actor profile collected',
      },
      {
        name: 'ransomware-profiled',
        met: (v) =>
          hasToolBeenCalled(v.steps, 'get_ransomware_group_profile') &&
          okResultsForTool(v.steps, 'get_ransomware_group_profile') >= 1,
        reason: () => 'Ransomware group profile collected',
      },
      {
        name: 'timeline-mapped',
        met: (v) => hasToolBeenCalled(v.steps, 'actor_timeline'),
        reason: () => 'Actor timeline collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'actor-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['threat-actor']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, steps) => {
      const ok = countOkResults(steps);
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      const enrichOk = okResultsForTool(steps, 'enrich_actor');
      const enrichRichesGuidance =
        enrichOk >= 1
          ? ''
          : '\nIMPORTANT: enrich_actor returned empty. The query name may be a ransomware group not indexed by Malpedia/OTX. Try get_ransomware_group_profile as your primary data source — it covers 100+ ransomware groups including Qilin, BlackBasta, LockBit, etc. Also try get_ransomware_activity and get_victim_releaks.';

      return `You are the Threat Actor Specialist. Your job: build a complete actor profile.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}. Results so far: ${ok} successful.

Strategy:
- Step 1: enrich_actor (profile, aliases, MITRE, CVEs)
- If enrich_actor returned empty: call get_ransomware_group_profile (primary ransomware group data — TTPs, tools, exploited CVEs, victim lists, leak URLs, YARA rules) + get_ransomware_activity (recent victims, leak postings) + get_victim_releaks (re-leak detection)
- Step 2: actor_timeline (recent campaigns, victims, posting cadence for non-ransomware actors)
- Step 3: actor_cves (CVEs exploited by this actor) + analyze_campaign
- Step 4: Synthesize with full profile.
${enrichRichesGuidance}`;
    },
  },

  vulnerability: {
    role: 'vulnerability',
    label: 'Vulnerability Specialist',
    description: 'Analyzes CVEs with CVSS/EPSS/KEV scoring, exploit status, patch intelligence.',
    handlesQueryTypes: ['cve', 'exploit-db', 'bug-bounty', 'security-updates'],
    maxSteps: 4,
    exitConditions: [
      {
        name: 'cve-looked-up',
        met: (v) => hasToolBeenCalled(v.steps, 'lookup_cve') && okResultsForTool(v.steps, 'lookup_cve') >= 1,
        reason: () => 'CVE data collected from NVD/KEV',
      },
      {
        name: 'exploit-status-known',
        met: (v) => hasToolBeenCalled(v.steps, 'lookup_exploit_db') || hasToolBeenCalled(v.steps, 'lookup_cisa_kev'),
        reason: () => 'Exploit status determined',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'vuln-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['vulnerability']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, steps) => {
      const ok = countOkResults(steps);
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Vulnerability Specialist. Your job: fully characterize this CVE.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}. Results so far: ${ok} successful.

Strategy:
- Step 1: lookup_cve (CVSS, EPSS, KEV, affected products, references, CWE)
- Step 2: lookup_exploit_db (PoC/exploit references) OR lookup_cisa_kev (ransomware/exploitation context)
- Step 3: unified_search for additional exploitation intel
- Step 4: Synthesize. Do NOT call enrich_actor for CVE queries.`;
    },
  },

  'domain-host': {
    role: 'domain-host',
    label: 'Domain & Host Specialist',
    description: 'DNS, WHOIS, certificate transparency, passive DNS, tech stack, IP geolocation, ASN.',
    handlesQueryTypes: ['domain', 'ip'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'dns-resolved',
        met: (v) => hasToolBeenCalled(v.steps, 'lookup_domain') || hasToolBeenCalled(v.steps, 'lookup_ipinfo'),
        reason: () => 'DNS/host data collected',
      },
      {
        name: 'footprint-complete',
        met: (v) =>
          hasToolBeenCalled(v.steps, 'lookup_certificate_transparency') ||
          hasToolBeenCalled(v.steps, 'lookup_builtwith') ||
          hasToolBeenCalled(v.steps, 'lookup_asn'),
        reason: () => 'Infrastructure footprint collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'domain-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['domain-host']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, steps) => {
      const ok = countOkResults(steps);
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Domain & Host Specialist. Your job: map the infrastructure.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}. Results so far: ${ok} successful.

Strategy:
- Step 1: lookup_domain (DNS/WHOIS/RDAP/CT) or lookup_ipinfo (IP geolocation/ASN/hosting)
- Step 2: lookup_certificate_transparency + lookup_builtwith (tech stack) or lookup_asn
- Step 3: generate_yara_rule + generate_hunting_queries (detection content for malicious indicators)
- Step 4: Synthesize with infrastructure map.`;
    },
  },

  'malware-analysis': {
    role: 'malware-analysis',
    label: 'Malware Analysis Specialist',
    description: 'Sample scanning, family profiling, sandbox verdicts, config extraction.',
    handlesQueryTypes: ['hash'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'sample-scanned',
        met: (v) => hasToolBeenCalled(v.steps, 'sample_scan') && okResultsForTool(v.steps, 'sample_scan') >= 1,
        reason: () => 'Sample scan completed',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'malware-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['malware-analysis']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, steps) => {
      const ok = countOkResults(steps);
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Malware Analysis Specialist. Your job: identify and profile this malware sample.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}. Results so far: ${ok} successful.

Strategy:
- Step 1: sample_scan (multi-provider hash fan-out: VirusTotal, MalwareBazaar, Triage, sandboxes)
- Step 2: malware_family_detail OR search_malpedia (family profile, YARA references) + search_triage
- Step 3: Synthesize with family attribution, detection verdicts, and sandbox links.`;
    },
  },

  'detection-rules': {
    role: 'detection-rules',
    label: 'Detection Rules Specialist',
    description: 'Generates YARA, Sigma, KQL, and Splunk detection rules from IOCs and TTPs.',
    handlesQueryTypes: ['cve', 'actor', 'hash', 'campaign', 'ip', 'domain'],
    maxSteps: 2,
    exitConditions: [
      {
        name: 'rules-generated',
        met: (v) =>
          hasToolBeenCalled(v.steps, 'generate_yara_rule') || hasToolBeenCalled(v.steps, 'generate_hunting_queries'),
        reason: () => 'Detection rules generated',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'detection-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['detection-rules']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Detection Rules Specialist. Your job: generate actionable detection rules.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: generate_yara_rule (YARA + Sigma + KQL from the threat data)
- Step 2: generate_hunting_queries (Splunk/Elastic hunt queries) + get_detections
- Always include the malware family name and known strings from collected data.`;
    },
  },

  phishing: {
    role: 'phishing',
    label: 'Phishing Specialist',
    description: 'Analyzes phishing URLs, emails, and campaigns. Extracts IOCs, identifies infrastructure.',
    handlesQueryTypes: ['phishing', 'url'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'phishing-analyzed',
        met: (v) =>
          hasToolBeenCalled(v.steps, 'analyze_phishing_url') || hasToolBeenCalled(v.steps, 'analyze_phishing_email'),
        reason: () => 'Phishing content analyzed',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'phishing-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['phishing']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Phishing Specialist. Your job: analyze this phishing attempt.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: analyze_phishing_url (verdict, extraction) or analyze_phishing_email
- Step 2: check_ioc on extracted IOCs + lookup_domain on extracted domains
- Step 3: Synthesize with verdict, extracted IOCs, and infrastructure map.`;
    },
  },

  ransomware: {
    role: 'ransomware',
    label: 'Ransomware Specialist',
    description: 'Tracks ransomware group activity, negotiations, victims, and sector targeting.',
    handlesQueryTypes: ['ransomware'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'activity-collected',
        met: (v) => hasToolBeenCalled(v.steps, 'get_ransomware_activity'),
        reason: () => 'Ransomware activity data collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'ransomware-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['ransomware']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Ransomware Specialist. Your job: track this ransomware group's activity.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: get_ransomware_activity (recent victims, leak sites, posting cadence)
- Step 2: get_ransomware_negotiations (settlement patterns, demands, discounts) + get_victim_releaks (re-leak detection — victims appearing under multiple groups) + get_ransomware_group_profile (full group TTPs, tools, exploited CVEs, locations)
- Step 3: get_ransomware_stats (global ransomware volume context) + get_cyber_crime_news (current developments)
- Step 4: get_blocklists + unified_search for additional context. Synthesize.`;
    },
  },

  'campaign-correlation': {
    role: 'campaign-correlation',
    label: 'Campaign Correlation Specialist',
    description: 'Cross-correlates IOCs, actors, and TTPs across campaigns. Finds connections.',
    handlesQueryTypes: ['campaign'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'campaign-analyzed',
        met: (v) => hasToolBeenCalled(v.steps, 'analyze_campaign') || hasToolBeenCalled(v.steps, 'cross_correlate'),
        reason: () => 'Campaign analysis complete',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'campaign-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['campaign-correlation']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Campaign Correlation Specialist. Your job: map this campaign's connections.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: unified_search (find related intel) + cross_correlate
- Step 2: analyze_campaign (lifecycle, kill chain, attribution) + briefings_related (link this campaign to prior briefings sharing IOCs)
- Step 3: Synthesize with campaign map, kill chain, and attributed actors.`;
    },
  },

  'dark-web': {
    role: 'dark-web',
    label: 'Dark Web & Cybercrime Specialist',
    description: 'Searches breach forums, Telegram leaks, dark web markets.',
    handlesQueryTypes: ['generic'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'breach-searched',
        met: (v) => hasToolBeenCalled(v.steps, 'get_breach_forums') || hasToolBeenCalled(v.steps, 'breach_check'),
        reason: () => 'Breach data collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'darkweb-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['dark-web']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Dark Web & Cybercrime Specialist. Your job: find exposure on underground forums.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: breach_check (exposure check) + search_telegram_leaks
- Step 2: get_breach_forums (forum activity) + trace_crypto_address if relevant
- Step 3: Synthesize with exposure assessment and dark web presence.`;
    },
  },

  'strategic-intel': {
    role: 'strategic-intel',
    label: 'Strategic Intel Specialist',
    description: 'Generates threat landscape assessments, PIR-driven briefings.',
    handlesQueryTypes: ['generic'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'pulse-collected',
        met: (v) => hasToolBeenCalled(v.steps, 'get_threat_pulse') || hasToolBeenCalled(v.steps, 'unified_search'),
        reason: () => 'Strategic intel collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'strategic-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['strategic-intel']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Strategic Intel Specialist. Your job: provide a threat landscape assessment.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: get_threat_pulse (current threat landscape) + unified_search
- Step 2: get_ransomware_map + get_supply_chain_attacks for context + briefings_related (link to prior briefs)
- Step 3: Synthesize with strategic assessment.`;
    },
  },
  'supply-chain': {
    role: 'supply-chain',
    label: 'Supply Chain Specialist',
    description: 'Tracks malicious packages (npm/pypi/gem), dependency vulnerabilities, and OSSF disclosures.',
    handlesQueryTypes: ['supply-chain', 'dependencies', 'package'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'depx-checked',
        met: (v) => hasToolBeenCalled(v.steps, 'depx_check') || hasToolBeenCalled(v.steps, 'depx_feed'),
        reason: () => 'Supply-chain data collected',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'supply-chain-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['supply-chain']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the Supply Chain Specialist. Your job: assess whether a package or dependency is known-malicious and surface related vulnerabilities.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: depx_check (is the package known-malicious?) + scan_package/scan_dependencies
- Step 2: ti_list_cves / lookup_cve for related vulnerabilities
- Step 3: Synthesize with verdict (clean/malicious/unknown) + CVEs.`;
    },
  },
  'soc-automation': {
    role: 'soc-automation',
    label: 'SOC Automation Specialist',
    description:
      'Manages SOC playbooks, generates IR playbooks, creates detection rules, and provides situational awareness for SOC analysts.',
    handlesQueryTypes: ['soc', 'incident', 'alert', 'playbook', 'detection'],
    maxSteps: 3,
    exitConditions: [
      {
        name: 'playbook-or-detection-generated',
        met: (v) =>
          hasToolBeenCalled(v.steps, 'generate_ir_playbook') ||
          hasToolBeenCalled(v.steps, 'generate_yara_rule') ||
          hasToolBeenCalled(v.steps, 'generate_hunting_queries') ||
          hasToolBeenCalled(v.steps, 'soc_playbook_execute') ||
          hasToolBeenCalled(v.steps, 'soc_cve_report'),
        reason: () => 'SOC automation output generated',
      },
      {
        name: 'max-steps',
        met: (v) => v.stepNum >= v.maxSteps,
        reason: () => 'Specialist step budget exhausted',
      },
    ],
    guardrails: [
      {
        name: 'soc-tools-only',
        filter: (calls) => {
          const allowed = new Set(SPECIALIST_TOOLS['soc-automation']);
          return calls.filter((c) => allowed.has(c.tool));
        },
      },
    ],
    buildPlannerPrompt: (tools, step, maxSteps, query, _steps) => {
      const toolList = tools.map((t) => `  - ${t.name}: ${t.description.split('.')[0]}`).join('\n');
      return `You are the SOC Automation Specialist. Your job: provide SOC-ready outputs — IR playbooks, detection rules, CVE reports, live IOC streams, and situational awareness.

Query: ${query}

Available tools:
${toolList}

Step ${step}/${maxSteps}.

Strategy:
- Step 1: Assess the situation — get_today_briefing / get_threat_pulse / get_live_iocs / get_trending_iocs for current threat landscape
- Step 2: Generate output — generate_ir_playbook (for incident response), generate_yara_rule / generate_hunting_queries (for detection), soc_cve_report (for CVE analysis), or soc_playbook_create (for automation)
- Step 3: Enrich — check_ioc / enrich_ioc_deep for indicators, lookup_cve / lookup_cisa_kev for vulnerabilities, fbi_wanted_search / interpol_search for threat actors
- Synthesize with SOC-ready recommendations: detection rules, hunting queries, IR playbook steps, and prioritized actions.`;
    },
  },
};

// ── Tool subset mapping ───────────────────────────────────────────────────

export const SPECIALIST_TOOLS: Record<SpecialistRole, string[]> = {
  'ioc-reputation': [
    'check_ioc',
    'enrich_ioc_deep',
    'get_relationships',
    'get_ioc_lifecycle',
    'maltiverse_verify',
    'correlate_iocs',
    'lookup_tre_ge',
    'urlscan_ip_search',
    'generate_yara_rule',
    'generate_hunting_queries',
    'passive_dns_reverse',
    'ioc_watchlist_stats',
    'hr_search_ip',
  ],
  'threat-actor': [
    'enrich_actor',
    'actor_timeline',
    'actor_cves',
    'search_malpedia',
    'search_actor_usernames',
    'analyze_campaign',
    'get_blocklists',
    'get_cyber_crime_news',
    'get_ransomware_group_profile',
    'get_ransomware_activity',
    'get_victim_releaks',
    'etda_list_actors',
    'etda_get_actor',
  ],
  vulnerability: [
    'lookup_cve',
    'lookup_exploit_db',
    'lookup_cisa_kev',
    'lookup_security_updates',
    'unified_search',
    'scan_package',
    'scan_dependencies',
    'poc_scan',
    'cve_health',
    'ti_list_cves',
    'ti_get_cve',
    'ti_list_kev',
  ],
  'domain-host': [
    'lookup_domain',
    'lookup_dns',
    'lookup_reverse_dns',
    'lookup_builtwith',
    'lookup_certificate_transparency',
    'lookup_ip_geo',
    'lookup_ipinfo',
    'lookup_asn',
    'passive_dns_lookup',
    'pivot_domain',
    'search_registrant',
    'get_domain_certs',
    'get_domain_history',
    'wayback_lookup',
    'lookup_wayback_advanced',
    'scan_website',
    'webamon_search',
    'webamon_domain',
    'webamon_scan',
    'webamon_server',
    'webamon_report',
    'webamon_resource',
    'maltiverse_verify',
    'generate_yara_rule',
    'generate_hunting_queries',
    'passive_dns_reverse',
    'hr_search_domain',
    'hr_domain_overview',
    'whoxy_reverse_whois',
    'truecaller_lookup',
    'intelx_search',
    'intelx_phonebook',
  ],
  'malware-analysis': [
    'sample_scan',
    'malware_family_detail',
    'search_triage',
    'search_malpedia',
    'traceix_lookup',
    'dn_bazaar_hash',
  ],
  'detection-rules': [
    'generate_yara_rule',
    'generate_hunting_queries',
    'get_yara_rules',
    'get_detections',
    'build_stix_bundle',
    'lookup_mitre',
    'generate_ir_playbook',
    'sigbase_list_rules',
    'sigbase_list_iocs',
  ],
  phishing: ['analyze_phishing_url', 'analyze_phishing_email', 'check_ioc', 'lookup_domain'],
  ransomware: [
    'get_ransomware_activity',
    'get_ransomware_negotiations',
    'get_ransomware_group_profile',
    'get_ransomware_stats',
    'get_victim_releaks',
    'get_cyber_crime_news',
    'get_blocklists',
  ],
  'campaign-correlation': [
    'analyze_campaign',
    'cross_campaign_correlate',
    'cross_correlate',
    'reconstruct_attack_chain',
    'parse_threat_report',
    'briefings_related',
  ],
  'dark-web': [
    'get_breach_forums',
    'search_telegram_leaks',
    'trace_crypto_address',
    'breach_check',
    'breach_disclosures_recent',
    'ti_list_darknet',
    'ti_get_darknet_site',
    'ti_get_darknet_category',
    'breach_vip_search',
    'dn_greynoise_check',
    'dn_abuseipdb_check',
    'dn_hibp_latest',
    'dn_threatfox_search',
    'dn_bazaar_hash',
    'dn_otx_ip',
    'dn_otx_domain',
    'dn_otx_hash',
    'dn_pulsedive_indicator',
    'dn_intelx_search',
    'dn_hybrid_search',
    'dn_ransomware_group',
    'dn_ransomware_search',
    'dn_urlhaus_lookup',
    'hr_search_email',
    'hr_search_domain',
    'hr_search_username',
    'hr_domain_overview',
    'hr_third_party_risk',
    'bw_list_breaches',
    'bw_get_breach',
  ],
  'strategic-intel': [
    'get_threat_pulse',
    'get_ransomware_map',
    'get_c2_tracker',
    'get_predictive_forecasts',
    'get_supply_chain_attacks',
    'get_ransomware_stats',
    'get_cyber_crime_news',
    'campaigns_list',
    'campaigns_get',
    'reports_list',
    'reports_get',
    'db_list_briefs',
    'db_get_brief',
    'ai_threats_list',
    'ai_threats_get',
    'nhi_scan',
    'nhi_inventory',
    'nhi_owasp_catalog',
    'briefings_related',
  ],
  'supply-chain': [
    'depx_feed',
    'depx_check',
    'depx_stats',
    'scan_package',
    'scan_dependencies',
    'get_supply_chain_attacks',
    'ti_list_cves',
    'lookup_cve',
  ],
  'soc-automation': [
    'soc_playbook_list',
    'soc_playbook_get',
    'soc_playbook_create',
    'soc_playbook_execute',
    'soc_playbook_runs',
    'soc_playbook_run_get',
    'soc_playbook_stats',
    'soc_cve_report',
    'generate_ir_playbook',
    'generate_yara_rule',
    'generate_hunting_queries',
    'get_detections',
    'get_live_iocs',
    'get_trending_iocs',
    'get_feed_status',
    'get_today_briefing',
    'list_briefings',
    'check_ioc',
    'enrich_ioc_deep',
    'lookup_cve',
    'lookup_cisa_kev',
    'unified_search',
    'get_threat_pulse',
    'get_ransomware_activity',
    'get_cyber_crime_news',
    'fbi_wanted_search',
    'interpol_search',
    'analyze_report',
  ],
};

// ── Query-type to specialist routing ─────────────────────────────────────

const ROUTING_TABLE: Record<string, SpecialistRole[]> = {
  cve: ['vulnerability', 'detection-rules'],
  'exploit-db': ['vulnerability', 'detection-rules'],
  'bug-bounty': ['vulnerability'],
  'security-updates': ['vulnerability'],
  ip: ['ioc-reputation', 'domain-host', 'detection-rules'],
  domain: ['domain-host', 'ioc-reputation', 'detection-rules'],
  hash: ['malware-analysis', 'ioc-reputation', 'detection-rules'],
  url: ['phishing', 'domain-host'],
  actor: ['threat-actor', 'campaign-correlation'],
  ransomware: ['ransomware', 'threat-actor'],
  phishing: ['phishing', 'ioc-reputation'],
  campaign: ['campaign-correlation', 'threat-actor'],
  'supply-chain': ['supply-chain', 'vulnerability'],
  package: ['supply-chain'],
  soc: ['soc-automation', 'detection-rules'],
  incident: ['soc-automation', 'ioc-reputation'],
  alert: ['soc-automation', 'ioc-reputation'],
  playbook: ['soc-automation'],
  detection: ['detection-rules', 'soc-automation'],
  generic: ['strategic-intel', 'dark-web', 'ioc-reputation'],
};

export function getSpecialistsForQueryType(queryType: string, query?: string): SpecialistRole[] {
  const resolved = query ? resolveRoutingQueryType(query, queryType) : queryType;
  return ROUTING_TABLE[resolved] ?? ['strategic-intel', 'ioc-reputation'];
}

/**
 * Refine an ambiguous ('generic'/'unknown') query type into a more specific
 * routing key using the query text. Explicit indicators in the text win (most
 * specific signal); otherwise falls back to pattern-based intent classification
 * (actor / malware / campaign). A already-specific queryType is returned
 * unchanged so explicit routes are never overridden.
 */
export function resolveRoutingQueryType(query: string, queryType: string): string {
  if (queryType && queryType !== 'generic' && queryType !== 'unknown') return queryType;

  if (/\bCVE-\d{4}-\d{4,}\b/i.test(query)) return 'cve';
  if (/\b[a-f0-9]{64}\b/i.test(query)) return 'hash';
  if (/\b[a-f0-9]{32}\b/i.test(query)) return 'hash';
  if (/\bhttps?:\/\/\S+/i.test(query)) return 'url';
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(query)) return 'ip';

  switch (classifyIntent(query).intent) {
    case 'threat_actor':
      return 'actor';
    case 'malware':
      return 'ransomware';
    case 'campaign':
      return 'campaign';
    case 'supply_chain':
      return 'supply-chain';
    case 'soc':
      return 'soc';
    default:
      return queryType;
  }
}

export function getToolsForSpecialist(role: SpecialistRole, allTools: AgentTool[]): AgentTool[] {
  // Keep the union in sync with filterToolsForQueryType: the planner may
  // select an always-available tool (e.g. the new HI/OH/KP sources) and the
  // executor must accept it too.
  const allowed = new Set<string>([...ALWAYS_AVAILABLE_TOOLS, ...SPECIALIST_TOOLS[role]]);
  return allTools.filter((t) => allowed.has(t.name));
}

/**
 * Always-available utility tools that every query type needs regardless of
 * specialist routing. These are the "glue" tools — search, correlation,
 * STIX export, and synthesis helpers that any investigation may call.
 */
const ALWAYS_AVAILABLE_TOOLS = new Set([
  'unified_search',
  'cross_correlate',
  'get_relationships',
  'build_stix_bundle',
  'lookup_mitre',
  'get_threat_pulse',
  'get_cyber_crime_news',
  'get_blocklists',
  'parse_threat_report',
  'extract_ttps',
  // Fleet-parity capabilities (recipes + validation + extraction + triage)
  'get_recipe',
  'validate_detection_rule',
  'convert_sigma_rule',
  'extract_observables_fast',
  'static_triage_file',
  'detect_c2_beaconing',
  'detect_dns_tunneling',
  // Endpoint acquisition (Velociraptor bridge) + report delivery
  'velo_list_clients',
  'velo_get_client',
  'velo_list_flows',
  'velo_collect_artifact',
  'velo_get_flow_status',
  'velo_get_flow_results',
  'share_saved_report',
  'velo_create_hunt',
  'velo_get_hunt',
  'velo_list_hunts',
  'submit_sample_for_analysis',
  'get_sample_analysis_status',
  'ti_list_cves',
  'ti_get_cve',
  'ti_list_kev',
  'ti_list_iocs',
  'ti_list_darknet',
  'ti_stats',
  'briefings_related',
  // New 2026-11 source families (hacking incidents, offsec harnesses,
  // kitploit feeds). Without these the planner cannot see the new sources.
  'hi_list_incidents',
  'hi_get_incident',
  'hi_stats',
  'oh_list_harnesses',
  'oh_get_harness',
  'oh_sources',
  'kp_list_tools',
  'kp_list_exploits',
  'kp_get_feed',
  'kp_stats',
]);

/**
 * Context-aware tool filtering for the planner.
 *
 * Instead of passing ALL ~291 tools to the planner (which wastes ~5,800
 * tokens of context on tool descriptions), this function returns only the
 * tools relevant to the query type — the union of tools from all routed
 * specialists, plus a small set of always-available utility tools.
 *
 * This cuts the planner's tool-description context from ~5,800 tokens to
 * ~1,500-2,500 tokens (depending on query type), leaving more context for
 * working memory and investigation data.
 */
export function filterToolsForQueryType(
  queryType: string,
  query: string | undefined,
  allTools: AgentTool[]
): AgentTool[] {
  const specialists = getSpecialistsForQueryType(queryType, query);
  const relevantToolNames = new Set<string>(ALWAYS_AVAILABLE_TOOLS);
  for (const role of specialists) {
    for (const name of SPECIALIST_TOOLS[role]) {
      relevantToolNames.add(name);
    }
  }
  const filtered = allTools.filter((t) => relevantToolNames.has(t.name));
  // Fallback: if filtering produced too few tools (e.g. unknown query type
  // with no routed specialists), return all tools rather than starving the
  // planner.
  return filtered.length >= 5 ? filtered : allTools;
}
