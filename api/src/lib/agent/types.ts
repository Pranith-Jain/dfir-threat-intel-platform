/** Core types for the autonomous DFIR/ThreatIntel investigator agent. */

// ── Infrastructure artifacts (extracted from tool step results) ──────────
/** Real attacker infrastructure pulled from raw tool JSON — leak-site .onion
 *  URLs, payment addresses, C2 IPs/domains, name servers, subdomains. Distinct
 *  from the IOC list (which is regex-scraped from the prose report). */
export interface InfrastructureArtifact {
  type:
    | 'leak_site'
    | 'onion'
    | 'payment_address'
    | 'c2_ip'
    | 'c2_domain'
    | 'nameserver'
    | 'subdomain'
    | 'resolved_ip'
    | 'port_service';
  value: string;
  context: string;
  source: string;
}

// ── Tool definitions ─────────────────────────────────────────────────────

export interface AgentToolParam {
  name: string;
  type: 'string' | 'number' | 'enum' | 'boolean';
  description: string;
  required: boolean;
  enum?: string[];
}

export interface AgentTool {
  name: string;
  description: string;
  params: AgentToolParam[];
  /** Execute the tool via the API. Returns arbitrary JSON. */
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

// ── Agent state ──────────────────────────────────────────────────────────

export type AgentStepStatus = 'pending' | 'running' | 'done' | 'error';
export type AgentSessionStatus = 'running' | 'done' | 'error';

export interface AgentToolCall {
  tool: string;
  args: Record<string, unknown>;
  reasoning: string;
}

export interface AgentStep {
  stepNumber: number;
  plan: string;
  toolCalls: AgentToolCall[];
  results: AgentToolResult[];
  status: AgentStepStatus;
  startedAt?: string;
  completedAt?: string;
  /** LLM's observation after seeing results */
  observation?: string;
  /**
   * Structured findings extracted by the observer for this step. Persisted on
   * the step (unlike the ephemeral in-memory WorkingMemory) so cross-alarm
   * rebuilds of working memory don't lose accumulated IOCs/MITRE/facts.
   */
  observerFindings?: {
    iocs: string[];
    actors?: string[];
    cves?: string[];
    malware?: string[];
    mitre: string[];
    keyFacts: string[];
    confidence?: 'high' | 'medium' | 'low';
    gaps: string[];
    /** 'llm' = observer LLM produced these findings; 'fallback' = heuristic stub. */
    provenance?: 'llm' | 'fallback';
    /** Fleet-style hypothesis updates from the observer (new/promoted/refuted). */
    hypothesisUpdates?: Array<{
      text: string;
      status: 'proposed' | 'testing' | 'supported' | 'refuted';
      evidence?: string;
    }>;
  };
  /** Whether the agent decided to continue or synthesize */
  nextAction?: 'continue' | 'synthesize';
  /**
   * Tool calls the planner proposed but the guardrails dropped (unknown
   * tools, duplicate args, banned dump tools, or calls beyond the per-step
   * cap). Surfaced to the observer/planner so a dropped intent isn't a silent
   * gap.
   */
  droppedCalls?: AgentToolCall[];
}

export interface AgentToolResult {
  tool: string;
  args: Record<string, unknown>;
  status: 'ok' | 'error';
  data?: unknown;
  error?: string;
  durationMs: number;
  /**
   * Per-tool follow-up hints surfaced to the observer/planner (observation
   * contract). On success these are the natural next enrichment steps for
   * the tool's domain (e.g. check_ioc → correlate_iocs, enrich_actor); on
   * error they are the documented alternatives (mirrors tool-retry.ts).
   * Deterministic — never LLM-derived — so the observer gets a stable handle
   * for "what to do next" without parsing raw JSON.
   */
  nextActions?: string[];
}

export interface AgentState {
  id: string;
  query: string;
  queryType: string;
  status: AgentSessionStatus;
  steps: AgentStep[];
  currentStep: number;
  maxSteps: number;
  report: string | null;
  modelUsed: string | null;
  startedAt: string;
  completedAt: string | null;
  error: string | null;
  /** Analyst role (ciso/detection/ir/cti) for role-aware prompting. */
  role?: string;
  /** Tool names allowed for this investigation. */
  allowedTools?: string[] | null;
  /** Role-specific preamble injected into the planner. */
  rolePreamble?: string;
  /** Role-specific response format instruction. */
  responseFormat?: string;
  /** User-provided TI-Mindmap-Hub API key (per-session, never persisted).
   *  When set, the TI-Mindmap MCP tools (timindmap_*) are bridged into the
   *  agent's tool registry so it can search the knowledge graph during
   *  investigations. */
  tiMindmapApiKey?: string;
  /** CTI investigation methodology playbook loaded at step 1 (matched to the
   *  query via trigger keywords). Injected into the specialist context so the
   *  planner follows the right methodology (IOC pivot, ransomware deep-dive,
   *  CVE triage, APT profiling, etc.). */
  ctiSkillPlaybook?: { slug: string; name: string; playbook: string };
  /** Sophon-style authorized workbench session: task profile + mission scope.
   *  The scope is enforced deterministically on every proposed tool call. */
  sophon?: {
    profileId: string;
    scope: string;
    parsedTargets: number;
    blockedCalls: number;
  };
  /** Current specialist role in the mesh (e.g. 'vulnerability', 'ioc-reputation'). */
  currentSpecialist?: string;
  /** QA verification results (populated after QA phase) */
  qa?: {
    qualityScore: number;
    flaggedClaims: string[];
    missingFacts: string[];
  };
  /** Structured action card for SOC analyst triage. */
  actionCard?: ReportActionCard;
  /** Structured investigation log for observability. */
  log?: InvestigationLogEntry[];
  /**
   * Source metadata derived from tool results — produced by doSynthesize().
   * Each entry aggregates all results from one tool, giving the UI a
   * "badge bar" of the data sources that fed the report.
   */
  sources?: Array<{ name: string; items: number }>;
  /**
   * Typed findings (IOC/actor/CVE/domain/hash) extracted deterministically from
   * tool results via the orchestrator's `extractFindings`. Feeds the action
   * card's IOC table so it reflects tool-grounded data, not just prose regex.
   */
  findings?: import('./specialist-types').SpecialistFinding[];
  /** True when the step-1 parallel specialist burst ran (observability). */
  usedParallelBurst?: boolean;
  /** Prior-intelligence note from related past investigations (memory loop). */
  priorIntelligence?: string;
  /** Estimated LLM cost/usage for the investigation (telemetry). */
  cost?: { usd: number; tokens: number; llmCalls: number };
  /**
   * Report version history — captured when self-correction produces a second
   * draft. Compact (no full text) so D1 rows stay small; the live report text
   * is in `report`.
   */
  reportVersioning?: {
    versions: Array<{ version: number; qualityScore: number; modelUsed: string; reason: string }>;
    diff?: {
      fromVersion: number;
      toVersion: number;
      fromScore: number;
      toScore: number;
      additions: number;
      deletions: number;
    };
  };
  /** 5-axis self-evaluation scorecard (accuracy, completeness, clarity, actionability, conciseness). */
  selfEval?: import('./self-eval').SelfEvalResult;
  /** Structured tool-failure introspection (what was missed + diagnosis). */
  dataGaps?: import('./introspection').ToolFailure[];
}

/** Structured log entry for the investigation loop. */
export interface InvestigationLogEntry {
  ts: string;
  role: 'planner' | 'specialist' | 'observer' | 'synthesizer' | 'qa-verifier' | 'system';
  message: string;
  durationMs?: number;
  tool?: string;
  toolCount?: number;
  modelUsed?: string;
}

// ── Planner output ───────────────────────────────────────────────────────

export interface PlannerOutput {
  /** What the agent plans to do and why */
  reasoning: string;
  /** Tools to call in this step (1-3 for parallel execution) */
  toolCalls: AgentToolCall[];
  /** Whether the agent has enough info to synthesize */
  shouldSynthesize: boolean;
  /**
   * Number of JSON-parse retries the planner needed (0 = first attempt parsed
   * cleanly). Surfaced in telemetry so model degradation (more malformed JSON)
   * is observable instead of hidden inside the planner's internal retry loop.
   */
  parseRetries?: number;
}

// ── Synthesizer output ───────────────────────────────────────────────────

/**
 * Structured action card — produced by the synthesizer alongside the prose
 * report. The UI consumes this to render the severity banner, MITRE heat-map
 * table, IOC table, follow-up action buttons, and the action triage list. The
 * prose report is the human narrative; this object is the analyst's
 * "what to do next" checklist.
 */
export interface MitreTechniqueEntry {
  /** MITRE ATT&CK technique ID, e.g. "T1059.001". */
  id: string;
  /** Technique name as known to MITRE, e.g. "PowerShell". */
  name?: string;
  /** Parent tactic, e.g. "Execution". */
  tactic?: string;
  /** Brief context from the investigation. */
  evidence?: string;
  /** Whether the investigation surfaced a detection for this technique. */
  detection?: 'yara' | 'sigma' | 'kql' | 'splunk' | 'none';
}

export interface IocEntry {
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash' | 'email' | 'cve' | 'actor' | 'malware';
  value: string;
  /** Confidence label from the synthesizer. */
  confidence: 'Confirmed' | 'Probable' | 'Possible';
  /** Where in the report this was first mentioned. */
  source?: string;
}

export interface ActionItem {
  /** Urgency bucket — drives the severity banner color. */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** What the analyst should do. */
  action: string;
  /** Which IOC/CVE/actor this applies to (optional). */
  target?: string;
  /** Tool the agent already used to surface the data. */
  source?: string;
  /** Category for filtering / grouping in the UI. */
  category: 'contain' | 'eradicate' | 'recover' | 'detect' | 'hunt' | 'inform';
  /** Which teams should see this action (drives the stakeholder filter). */
  stakeholders?: ActionStakeholder[];
}

export interface ReportVerdict {
  /** 1-line "in plain English" verdict. */
  headline: string;
  /** Confidence in the verdict. */
  confidence: 'high' | 'medium' | 'low';
  /** Why this confidence level (data-quality-grounded). */
  confidence_rationale?: string;
  /** Whether this is an active incident, recon, post-exploit, or informational. */
  posture: 'active' | 'reconnaissance' | 'post-exploit' | 'informational' | 'unknown';
  /** TLP marking default for the report. */
  tlp: 'CLEAR' | 'GREEN' | 'AMBER' | 'RED';
}

/** Stakeholder teams that should be notified for a given action. */
export type ActionStakeholder =
  'cti' | 'soc' | 'ir' | 'vuln' | 'redteam' | 'appsec' | 'awareness' | 'exec' | 'legal' | 'tprm';

/** Diamond Model — adversary / capability / infrastructure / victim. */
export interface DiamondModel {
  adversary?: string;
  capability?: string[];
  infrastructure?: string[];
  victim?: string;
}

/** A Prioritized Intelligence Requirement — drives the executive narrative. */
export interface PirLink {
  pir: string;
  relevant: boolean;
  bluf?: string;
  businessOutcome?: string;
}

export interface ReportActionCard {
  verdict: ReportVerdict;
  /** Severity banner level — synthesised from the worst ActionItem. */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Ordered, deduplicated action checklist for the analyst. */
  actions: ActionItem[];
  /** MITRE ATT&CK techniques, sorted by tactic for the heat-map table. */
  mitre: MitreTechniqueEntry[];
  /** Tabular IOC list with type + confidence. */
  iocs: IocEntry[];
  /** True if any tool surfaced CISA KEV-listed data. */
  kev: boolean;
  /** CISA KEV listing date (YYYY-MM-DD) — only set when kev=true. */
  kev_date?: string | null;
  /** CVSS v3.1 score + vector + severity bucket. */
  cvss?: { score: number | null; vector: string | null; severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null };
  /** EPSS exploitation probability + percentile. */
  epss?: { score: number | null; percentile: number | null };
  /** Known / Suspected ransomware use of this CVE. */
  ransomware_use?: 'Known' | 'Suspected' | null;
  /** Threat actors attributed to exploiting this CVE. */
  threat_actors?: string[];
  /** Exploit code / weaponization status. */
  exploit_status?: 'poc-public' | 'weaponized' | 'in-the-wild' | null;
  /** Vendor advisory URL with the fix. */
  patch_url?: string | null;
  /** True if the investigation mentioned ransomware payment / wallet. */
  ransomware: boolean;
  /** True if the investigation found a known threat-actor attribution. */
  attributed: boolean;
  /** For actor / ransomware queries, a brief timeline. */
  timeline?: Array<{ date?: string; event: string; source?: string }>;
  /** MITRE ATT&CK Navigator layer (just the techniques + scores; the
   *  UI serialises it to the v4 layer JSON for export). */
  navigatorLayer?: {
    name: string;
    description: string;
    techniques: Array<{ id: string; score: number; comment?: string }>;
  };
  /** Diamond Model — adversary / capability / infrastructure / victim. */
  diamond?: DiamondModel;
  /** Prioritized Intelligence Requirements the report addresses. */
  pirs?: PirLink[];
  /** Structured BLUF panel parsed from the synthesizer's report-header
   *  block. Drives the dashboard's hero card. */
  reportHeader?: import('./synthesizer').ReportHeader;
  /**
   * IOC/actor/CVE/MITRE relationship graph derived deterministically from the
   * tool results (not the LLM). Rendered by the UI as an interactive graph.
   */
  graph?: import('./ioc-graph').GraphData;
}

export interface SynthesizerOutput {
  report: string;
  modelUsed: string;
  keyFindings: string[];
  confidence: 'high' | 'medium' | 'low';
  iocsExtracted: string[];
  mitreTechniques: string[];
  /** Structured action card. Optional for backward compat. */
  actionCard?: ReportActionCard;
  /** Real attacker infrastructure extracted from tool step results — leak-site
   *  .onion URLs, payment addresses, C2 IPs/domains, name servers, subdomains.
   *  Distinct from iocsExtracted (which is regex-scraped from the prose) — this
   *  is pulled directly from the raw tool JSON so citation URLs and victim
   *  domains never contaminate it. */
  infrastructure?: InfrastructureArtifact[];
}

// ── D1 row shape ─────────────────────────────────────────────────────────

export interface AgentSessionRow {
  id: string;
  query: string;
  query_type: string;
  status: string;
  steps_json: string | null;
  report_json: string | null;
  model_used: string | null;
  total_steps: number;
  created_at: string;
  updated_at: string;
}
