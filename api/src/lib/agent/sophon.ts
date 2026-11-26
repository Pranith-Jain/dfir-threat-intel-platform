/**
 * Sophon-style authorized-security-testing workbench.
 *
 * This ports the WORKFLOW of github.com/i11us0ry/Sophon — Main Agent →
 * Planner → Worker → review/report, with an explicit mission scope and
 * evidence-backed findings — onto this platform's existing InvestigatorAgentDO.
 *
 * Upstream has NO project licence (all rights reserved), so none of its prose,
 * role prompts, skills or code is vendored. The profiles below are original,
 * short method hints; they provide guidance only, never identity or permissions.
 * All enforcement lives in this module and in the agent's existing guardrails.
 */

import { LoopEngine, type Guardrail, type LoopDefinition } from './loop-engine';
import type { AgentToolCall } from './types';

export type SophonProfileId =
  | 'default'
  | 'web-pentest'
  | 'java-code-audit'
  | 'dotnet-code-audit'
  | 'php-code-audit'
  | 'cloud-audit'
  | 'post-exploitation'
  | 'binary-analysis'
  | 'mobile-reverse'
  | 'ctf';

export interface SophonProfile {
  id: SophonProfileId;
  label: string;
  /** Original one-sentence method hint. Never upstream prose. */
  description: string;
  /** Existing query type this profile routes to. */
  queryType: string;
  /** Existing specialist roles, in dispatch order. */
  specialists: string[];
  /** Short method guidance injected into the planner context. */
  methodHint: string;
  /** Suggested step ceiling for this profile. */
  maxSteps: number;
}

/** Task profiles are method guidance, not identities or tool grants. */
export const SOPHON_PROFILES: Record<SophonProfileId, SophonProfile> = {
  default: {
    id: 'default',
    label: 'General assessment',
    description: 'Open-ended, scoped security assessment with the full tool registry.',
    queryType: 'generic',
    specialists: ['ioc-reputation', 'vulnerability'],
    methodHint: 'Map the attack surface first, then verify one hypothesis at a time.',
    maxSteps: 6,
  },
  'web-pentest': {
    id: 'web-pentest',
    label: 'Web application test',
    description: 'Authorized web testing: exposure, configuration, authentication and injection surfaces.',
    queryType: 'domain',
    specialists: ['domain-host', 'vulnerability', 'ioc-reputation'],
    methodHint:
      'Enumerate reachable surfaces; confirm each candidate with an independent observation before calling it a finding.',
    maxSteps: 7,
  },
  'java-code-audit': {
    id: 'java-code-audit',
    label: 'Java source review',
    description: 'Java/JVM source review: routing, authorization, data flow and injection sinks.',
    queryType: 'cve',
    specialists: ['vulnerability', 'supply-chain'],
    methodHint: 'Trace request input to the executing sink; a dangerous API alone is not proof of a flaw.',
    maxSteps: 7,
  },
  'dotnet-code-audit': {
    id: 'dotnet-code-audit',
    label: '.NET source review',
    description: '.NET/C# source review: routing, auth, deserialization and configuration risks.',
    queryType: 'cve',
    specialists: ['vulnerability', 'supply-chain'],
    methodHint: 'Follow request flow through middleware and model binding before judging a sink.',
    maxSteps: 7,
  },
  'php-code-audit': {
    id: 'php-code-audit',
    label: 'PHP source review',
    description: 'PHP source review: routing, file handling, injection and framework misuse.',
    queryType: 'cve',
    specialists: ['vulnerability', 'supply-chain'],
    methodHint: 'Confirm that attacker-controlled input reaches a reachable execution branch.',
    maxSteps: 7,
  },
  'cloud-audit': {
    id: 'cloud-audit',
    label: 'Cloud posture review',
    description: 'Cloud configuration and identity exposure review across providers.',
    queryType: 'generic',
    specialists: ['domain-host', 'strategic-intel', 'ioc-reputation'],
    methodHint: 'Check identity boundaries and public exposure before scoring any single misconfiguration.',
    maxSteps: 6,
  },
  'post-exploitation': {
    id: 'post-exploitation',
    label: 'Post-exploitation review',
    description: 'Defensive review of identity, lateral movement and persistence exposure in an authorized estate.',
    queryType: 'actor',
    specialists: ['threat-actor', 'dark-web', 'ioc-reputation'],
    methodHint: 'Correlate observed tradecraft with known actor behaviour; keep every claim tied to an observation.',
    maxSteps: 6,
  },
  'binary-analysis': {
    id: 'binary-analysis',
    label: 'Binary analysis',
    description: 'Static/dynamic review of executables and packaged artifacts.',
    queryType: 'hash',
    specialists: ['malware-analysis', 'ioc-reputation'],
    methodHint: 'Start with the hash and provenance; treat reputation hits as leads, not verdicts.',
    maxSteps: 6,
  },
  'mobile-reverse': {
    id: 'mobile-reverse',
    label: 'Mobile app review',
    description: 'Authorized mobile application and protocol review.',
    queryType: 'hash',
    specialists: ['malware-analysis', 'supply-chain'],
    methodHint: 'Separate client-side hardening from server-side trust before ranking findings.',
    maxSteps: 6,
  },
  ctf: {
    id: 'ctf',
    label: 'CTF exercise',
    description: 'Challenge solving inside an explicitly authorized lab or event scope.',
    queryType: 'generic',
    specialists: ['vulnerability', 'ioc-reputation'],
    methodHint: 'Prefer a reproducible proof over a speculative flag; record the exact steps that worked.',
    maxSteps: 8,
  },
};

export const SOPHON_PROFILE_IDS = Object.keys(SOPHON_PROFILES) as SophonProfileId[];

export function getSophonProfile(raw: string | undefined | null): SophonProfile | null {
  if (!raw) return null;
  const norm = (s: string) =>
    s
      .trim()
      .toLowerCase()
      .replace(/[\s_]+/g, '-');
  const key = norm(raw);
  if (key in SOPHON_PROFILES) return SOPHON_PROFILES[key as SophonProfileId];
  // Allow display labels ("Java source review") to resolve too.
  return Object.values(SOPHON_PROFILES).find((p) => norm(p.label) === key) ?? null;
}

/** Deterministic profile suggestion from the query text — never an LLM call. */
export function suggestSophonProfile(query: string): SophonProfileId {
  const q = query.toLowerCase();
  if (/\b(apk|ipa|android|ios|mobile app)\b/.test(q)) return 'mobile-reverse';
  if (/\b(exe|dll|elf|malware sample|binary|sha256)\b/.test(q)) return 'binary-analysis';
  if (/\b(java|spring|mybatis|jsp)\b/.test(q)) return 'java-code-audit';
  if (/\b(\.net|csharp|c#|asp\.net)\b/.test(q)) return 'dotnet-code-audit';
  if (/\bphp\b/.test(q)) return 'php-code-audit';
  if (/\b(aws|azure|gcp|cloud|iam role|s3 bucket)\b/.test(q)) return 'cloud-audit';
  if (/\b(lateral|persistence|post-exploit|active directory)\b/.test(q)) return 'post-exploitation';
  if (/\bctf\b|capture the flag/.test(q)) return 'ctf';
  if (
    /\b(website|web app|domain|subdomain|http)\b/.test(q) ||
    /\b[a-z0-9-]+\.(com|net|org|io|dev|app|test|local)\b/.test(q)
  )
    return 'web-pentest';
  return 'default';
}

/* ─── Mission scope ────────────────────────────────────────────────────── */

export interface MissionScope {
  /** Raw authorized-scope statement, kept for the audit trail. */
  raw: string;
  /** Explicit targets parsed from the statement. Empty means "unrestricted". */
  targets: string[];
  /** Wildcard suffixes, e.g. `.example.com`. */
  suffixes: string[];
  /** IPv4 networks in CIDR form. */
  networks: string[];
}

const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const WILDCARD_DOMAIN_RE = /\*\.((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
const TOKEN_RE = /\b[\w*.-]{3,120}\b/g;

/** Parse an authorized-scope statement. Deterministic and offline. */
export function parseMissionScope(raw: string | undefined | null): MissionScope {
  const text = String(raw ?? '')
    .trim()
    .slice(0, 2000);
  const targets = new Set<string>();
  const suffixes = new Set<string>();
  const networks = new Set<string>();

  for (const m of text.matchAll(WILDCARD_DOMAIN_RE)) suffixes.add(`.${m[1]!.toLowerCase()}`);
  for (const m of text.matchAll(DOMAIN_RE)) {
    const d = m[0].toLowerCase();
    targets.add(d);
  }
  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[0];
    if (ip.includes('/')) networks.add(ip);
    else targets.add(ip);
  }
  // Explicit wildcard tokens such as `*.example.com` are matched by DOMAIN_RE
  // already; bare globs are kept as targets so they can be compared directly.
  for (const m of text.matchAll(TOKEN_RE)) {
    const t = m[0];
    if (t.includes('*') && !t.includes('://')) targets.add(t.toLowerCase());
  }

  return { raw: text, targets: [...targets], suffixes: [...suffixes], networks: [...networks] };
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return -1;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function inNetwork(host: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const a = ipv4ToInt(host);
  const b = ipv4ToInt(base ?? '');
  if (a < 0 || b < 0 || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

function hostAllowed(host: string, scope: MissionScope): boolean {
  const h =
    host
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split(/[/?#:]/)[0] ?? '';
  if (!h) return true;
  for (const t of scope.targets) {
    if (t === h) return true;
    // An explicit domain covers its subdomains (example.com → sub.example.com).
    if (/^[a-z0-9.-]+$/.test(t) && h.endsWith(`.${t}`)) return true;
    if (t.includes('*')) {
      const pattern = t.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      if (new RegExp(`^${pattern}$`).test(h)) return true;
    }
  }
  if (scope.suffixes.some((s) => h === s.slice(1) || h.endsWith(s))) return true;
  if (scope.networks.some((n) => inNetwork(h, n))) return true;
  return false;
}

/** Host-like values from a tool call. CVE ids are intel, not active targets. */
function hostFromArgs(args: Record<string, unknown>): string | null {
  for (const key of ['domain', 'url', 'ip', 'host', 'target', 'hostname', 'value', 'query', 'valueToCheck']) {
    const raw = args[key];
    if (typeof raw !== 'string' || raw.length > 512) continue;
    const hostMatch = raw.match(DOMAIN_RE)?.[0] ?? raw.match(IPV4_RE)?.[0];
    if (hostMatch) return hostMatch;
  }
  return null;
}

/**
 * Deterministic mission-policy guardrail. Blocks an active-target tool call
 * when its host is outside the authorized scope. With no explicit scope, the
 * guardrail is a no-op (the UI requires a scope statement to start a run).
 */
export function filterSophonToolCalls(calls: readonly AgentToolCall[], scope: MissionScope): AgentToolCall[] {
  if (!scope.targets.length && !scope.suffixes.length && !scope.networks.length) return [...calls];
  return calls.filter((call) => {
    const host = hostFromArgs(call.args);
    return host === null || hostAllowed(host, scope);
  });
}

/* ─── Context injected into the planner ────────────────────────────────── */

export function buildSophonContext(profile: SophonProfile, scope: MissionScope): string {
  const scopeLine =
    scope.raw ||
    'No explicit target statement was supplied; keep all work read-only and report only what the tools return.';
  return [
    '<mission_policy>',
    `Authorized scope: ${scopeLine}`,
    'Work only inside that scope. Out-of-scope tool calls are blocked before execution.',
    'This is read-only assessment and review: no exploitation, credential use, destructive requests or payload delivery.',
    '</mission_policy>',
    '<workflow>',
    'Main: confirm scope and dispatch. Planner: form one testable hypothesis. Worker: execute one step and collect evidence.',
    'Review: challenge the conclusion using an independent observation. Report: findings, evidence, gaps and retest steps.',
    '</workflow>',
    '<evidence_standard>',
    `Method hint: ${profile.methodHint}`,
    'A finding must cite the tool result and observed value that supports it, and say what remains unverified.',
    'Separate confirmed observations from inference. A missing result is not proof of safety.',
    '</evidence_standard>',
  ].join('\n');
}

/* ─── Sophon-specific loop (separate from the pinned CTI loop) ─────────── */

export interface SophonLoopState {
  stepNum: number;
  maxSteps: number;
  okResults: number;
  evidenceCandidates: number;
  allCallsBlocked: boolean;
}

const noOutOfScope: Guardrail<SophonLoopState, AgentToolCall> = {
  name: 'no-out-of-scope-targets',
  filter: (_calls, state) => (state.allCallsBlocked ? [] : [..._calls]),
};

export const SOPHON_LOOP: LoopDefinition<SophonLoopState, AgentToolCall> = {
  goal: 'Finish with evidence-backed findings inside the authorized scope.',
  maxIterations: (s) => s.maxSteps,
  exitConditions: [
    {
      name: 'scope-exhausted',
      met: (s) => s.allCallsBlocked,
      reason: () => 'Every proposed target was outside the authorized scope; stop and report the block.',
    },
    {
      name: 'enough-evidence',
      met: (s) => s.okResults >= 3 && s.evidenceCandidates >= 2,
      reason: () => 'Enough corroborated observations to synthesize evidence-backed findings.',
    },
    {
      name: 'max-steps',
      met: (s) => s.stepNum >= s.maxSteps,
      reason: () => 'Step ceiling reached; synthesize with the evidence gathered.',
    },
  ],
  guardrails: [noOutOfScope],
};

export const sophonLoop = new LoopEngine(SOPHON_LOOP);
