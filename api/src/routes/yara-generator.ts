import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError } from '../lib/api-error';

/**
 * AI Rule Generator — generates detection rules in multiple formats.
 *
 * Improvements over v1:
 *   - Groq (llama-4-scout) primary → Workers AI (llama-3.3-70b) fallback
 *   - Few-shot examples per format for higher syntactic accuracy
 *   - Self-healing: validation failures are fed back to the LLM for a retry
 *   - Deeper structural validators (not just keyword presence)
 *   - Expanded MITRE ATT&CK mapping (40+ techniques)
 *   - Format-specific post-processing (indentation, cleanup)
 *
 * Supported formats:
 *   - YARA: File pattern matching for malware detection
 *   - Sigma: SIEM-agnostic log detection rules (YAML)
 *   - KQL: Microsoft Sentinel / Defender queries
 *   - Splunk: Splunk SPL queries
 *   - Lucene: Elasticsearch queries
 *   - EQL: Elastic Event Query Language
 *   - Snort/Suricata: Network IDS rules
 *   - PowerShell: Detection scripts
 *   - DLP: Data loss prevention regex patterns
 *   - Supply-chain: Semgrep patterns for supply chain attacks
 *
 * POST /api/v1/rules/generate
 * POST /api/v1/rules/validate
 */

export type RuleType =
  'yara' | 'sigma' | 'kql' | 'splunk' | 'lucene' | 'eql' | 'snort' | 'powershell' | 'dlp' | 'supplychain';

const MAX_STRINGS = 50;
const MAX_DESCRIPTION_LENGTH = 5000;

interface GenerateRequest {
  type: RuleType;
  description: string;
  strings?: string[];
  family?: string;
  filetype?: string;
  complexity?: 'basic' | 'standard' | 'advanced';
  logsource?: string;
  table?: string;
}

interface GeneratedRule {
  rule_id: string;
  rule_type: RuleType;
  rule_name: string;
  rule_content: string;
  description: string;
  detection_logic: string[];
  syntax_confidence: 'high' | 'medium' | 'low';
  detection_confidence: 'high' | 'medium' | 'low';
  testing_notes: string;
  mitre_techniques: string[];
  meta: {
    generated_at: string;
    model: string;
    complexity: string;
    retries: number;
  };
}

// ── AI Client (Groq primary → Workers AI fallback) ─────────────────────

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = 'openai/gpt-oss-120b';
const CF_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast' as const;
const CF_MODEL_FALLBACK = '@cf/meta/llama-3.1-8b-instruct-fp8' as const;

interface LlmInput {
  system: string;
  user: string;
  maxTokens?: number;
  temperature?: number;
}

interface LlmOutput {
  text: string;
  modelUsed: string;
}

async function runGroq(key: string, input: LlmInput): Promise<string> {
  const res = await fetch(GROQ_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    // LLM calls are slow (3–15s typical). 30s ceiling matches the
    // expected streaming response time for a YARA rule generation.
    signal: AbortSignal.timeout(30_000),
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        { role: 'system', content: input.system },
        { role: 'user', content: input.user },
      ],
      max_completion_tokens: input.maxTokens ?? 2500,
      temperature: input.temperature ?? 0.2,
      reasoning_effort: 'medium',
    }),
  });
  if (res.status === 429) throw new Error('groq rate-limited');
  if (!res.ok) throw new Error(`groq HTTP ${res.status}`);
  const j = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
  const text = j?.choices?.[0]?.message?.content;
  if (typeof text !== 'string' || !text.trim()) throw new Error('groq empty response');
  return text;
}

async function runWorkersAi(ai: NonNullable<Env['AI']>, model: string, input: LlmInput): Promise<string> {
  const res = (await ai.run(
    model as Parameters<typeof ai.run>[0],
    {
      messages: [
        { role: 'system', content: input.system },
        { role: 'user', content: input.user },
      ],
      max_tokens: input.maxTokens ?? 2500,
      temperature: input.temperature ?? 0.2,
    } as Parameters<typeof ai.run>[1]
  )) as { response?: string };
  if (!res || typeof res.response !== 'string' || !res.response.trim()) {
    throw new Error(`Empty response from ${model}`);
  }
  return res.response;
}

async function callNvidia(nvidiaKey: string, input: LlmInput): Promise<{ text: string; model: string }> {
  const models = ['minimaxai/minimax-m2.7', 'z-ai/glm-5.2'];
  for (const model of models) {
    try {
      const res = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${nvidiaKey}`, 'content-type': 'application/json' },
        signal: AbortSignal.timeout(30_000),
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: input.system },
            { role: 'user', content: input.user },
          ],
          max_tokens: input.maxTokens ?? 2500,
          temperature: input.temperature ?? 0.2,
        }),
      });
      if (!res.ok) continue;
      const j = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const text = j?.choices?.[0]?.message?.content;
      if (typeof text === 'string' && text.trim()) return { text, model };
    } catch (_catchErr) {
      logError('callNvidia failed', _catchErr);
      /* try next model */
    }
  }
  throw new Error('nvidia models unavailable');
}

async function runLlm(
  ai: Env['AI'],
  groqKey: string | undefined,
  nvidiaKey: string | undefined,
  input: LlmInput
): Promise<LlmOutput> {
  // 1. Groq primary (better model, own quota)
  if (groqKey) {
    try {
      const text = await runGroq(groqKey, input);
      return { text, modelUsed: `groq:${GROQ_MODEL}` };
    } catch (err) {
      const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
      if (msg.includes('rate') || msg.includes('429')) {
        // rate-limited — fall through to next provider
      } else {
        logError('runLlm groq failed', err);
      }
    }
  }

  // 2. NVIDIA fallback
  if (nvidiaKey) {
    try {
      const { text, model: nvidiaModel } = await callNvidia(nvidiaKey, input);
      return { text, modelUsed: `nvidia:${nvidiaModel}` };
    } catch (err) {
      logError('runLlm nvidia failed', err);
    }
  }

  // 3. Workers AI fallback (70b primary, 8b tertiary)
  if (ai) {
    const aiClient = ai as NonNullable<Env['AI']>;
    for (const model of [CF_MODEL, CF_MODEL_FALLBACK]) {
      try {
        const text = await runWorkersAi(aiClient, model, input);
        return { text, modelUsed: model };
      } catch (err) {
        logError('handler failed', err);
        const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
        if (msg.includes('rate') || msg.includes('429') || msg.includes('quota')) {
          throw new Error('AI rate-limited/quota exceeded — try again later or configure GROQ_API_KEY');
        }
      }
    }
  }

  throw new Error('No AI provider available (Workers AI missing and no API keys)');
}

// ── Validation Functions ─────────────────────────────────────────────────

function validateYaraSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Rule declaration
  const ruleDecl = rule.match(/\brule\s+(\w+)/);
  if (!ruleDecl) {
    errors.push('Missing rule declaration (expected: rule <name> { ... })');
  } else if (ruleDecl[1] && !/^[a-zA-Z_]\w*$/.test(ruleDecl[1])) {
    errors.push(`Invalid rule name "${ruleDecl[1]}" — must be alphanumeric + underscore, starting with letter`);
  }

  // Braces
  const openBraces = (rule.match(/{/g) ?? []).length;
  const closeBraces = (rule.match(/}/g) ?? []).length;
  if (openBraces !== closeBraces) errors.push(`Unbalanced braces: ${openBraces} open, ${closeBraces} close`);

  // Condition section
  if (!rule.includes('condition:')) {
    errors.push('Missing condition section');
  } else {
    // Check condition references defined strings
    const stringDefs = (rule.match(/\$([a-zA-Z_]\w*)\s*=/g) ?? []).map((m) => m.match(/\$(\w+)/)?.[1]);
    const conditionBlock = rule.split('condition:')[1] ?? '';
    if (stringDefs.length > 0 && !conditionBlock.match(/\$/)) {
      warnings.push('Condition does not reference any defined strings');
    }
  }

  // Strings section
  if (rule.includes('strings:')) {
    const stringDefs = rule.match(/\$[a-zA-Z_]\w*\s*=/g);
    if (!stringDefs || stringDefs.length === 0) {
      errors.push('Strings section declared but no string definitions found');
    } else {
      // Check for hex string syntax errors
      for (const match of rule.matchAll(/\$\w+\s*=\s*\{([^}]+)\}/g)) {
        const hex = (match[1] ?? '').replace(/\s+/g, '');
        if (!/^[0-9a-fA-F?*\s]+$/.test(hex)) {
          warnings.push('Possible invalid hex string detected');
          break;
        }
      }
    }
  }

  // Metadata
  if (!rule.includes('meta:')) warnings.push('No metadata section — consider adding author, description, date');

  return { valid: errors.length === 0, errors, warnings };
}

function validateSigmaSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.includes('title:')) errors.push('Missing title field');
  if (!rule.includes('detection:')) errors.push('Missing detection section');
  if (!rule.includes('condition:')) errors.push('Missing condition in detection section');
  if (!rule.includes('logsource:')) warnings.push('Missing logsource section (recommended for SigmaHQ compliance)');

  // Check for selection definitions
  const selections = rule.match(/\b\w*selection\w*\s*:/gi) ?? [];
  if (selections.length === 0 && rule.includes('condition:')) {
    warnings.push('No selection definitions found — condition may reference undefined selections');
  }

  // Check condition references valid selections
  const conditionBlock = rule.split('condition:')[1]?.split('\n').slice(0, 3).join(' ') ?? '';
  if (conditionBlock.includes(' and ') || conditionBlock.includes(' or ')) {
    // Good — has boolean logic
  } else if (selections.length > 1) {
    warnings.push('Multiple selections defined but condition may not combine them');
  }

  // Metadata
  if (!rule.includes('status:')) warnings.push('Missing status field (recommended: experimental, test, stable)');
  if (!rule.includes('author:')) warnings.push('Missing author field');
  if (!rule.includes('tags:')) warnings.push('Missing tags field — consider adding attack.* tags');

  // JSON vs YAML check
  if (rule.includes('{') && rule.includes('}') && !rule.includes('selection:')) {
    errors.push('Possible JSON format detected — Sigma uses YAML format');
  }

  return { valid: errors.length === 0, errors, warnings };
}

function validateKqlSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.includes('|')) errors.push('Missing pipe operators — KQL uses pipe-based syntax');

  const operators =
    rule.match(
      /\b(where|extend|project|summarize|join|union|mv-expand|parse|make-series|top|sort|count|distinct|take|limit)\b/gi
    ) ?? [];
  if (operators.length === 0) errors.push('No KQL operators found (where, extend, project, summarize, etc.)');

  // Parentheses balance
  const openParens = (rule.match(/\(/g) ?? []).length;
  const closeParens = (rule.match(/\)/g) ?? []).length;
  if (openParens !== closeParens) errors.push(`Unbalanced parentheses: ${openParens} open, ${closeParens} close`);

  // Check for common mistakes
  if (rule.match(/\bSELECT\b/i) && !rule.match(/\bproject\b/i)) {
    warnings.push('Possible SQL syntax — KQL uses project, not SELECT');
  }
  if (rule.match(/\bFROM\b/i) && !rule.match(/^\s*\w+/m)) {
    warnings.push('Possible SQL syntax — KQL starts with table name directly, not FROM');
  }

  return { valid: errors.length === 0, errors, warnings };
}

function validateSplunkSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.includes('index=') && !rule.includes('sourcetype=') && !rule.match(/\b(tstats|datamodel)\b/))
    errors.push('Missing index, sourcetype, or tstats specification');
  if (!rule.includes('|') && !rule.match(/^(search|tstats|eventstats|\|)/im))
    errors.push('Missing pipe operators or search command');

  // Check for common Splunk commands
  const commands =
    rule.match(
      /\b(search|where|eval|stats|rex|lookup|table|fields|sort|head|tail|dedup|bin|timechart|chart|foreach|append|join|makemv|spath|coalesce|if|null)\b/gi
    ) ?? [];
  if (commands.length === 0) warnings.push('No Splunk commands detected — verify SPL syntax');

  return { valid: errors.length === 0, errors, warnings };
}

function validateLuceneSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.match(/(AND|OR|NOT|:)/i)) errors.push('Missing Lucene operators (AND, OR, NOT, field:value)');

  const openParens = (rule.match(/\(/g) ?? []).length;
  const closeParens = (rule.match(/\)/g) ?? []).length;
  if (openParens !== closeParens) errors.push('Unbalanced parentheses');

  // Check for quotes balance
  const quotes = (rule.match(/"/g) ?? []).length;
  if (quotes % 2 !== 0) warnings.push('Unbalanced double quotes');

  return { valid: errors.length === 0, errors, warnings };
}

function validateEqlSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.match(/\b(process|file|network|registry|dns|api|library|driver)\b/i))
    errors.push('Missing entity type (process, file, network, registry, dns, etc.)');
  if (!rule.match(/\bwhere\b/i)) errors.push('Missing where clause');

  // Sequence detection
  if (rule.match(/\bsequence\b/i)) {
    if (!rule.match(/\bby\b/i)) warnings.push('Sequence query without by clause — consider grouping');
    if (!rule.match(/\bwith\s+maxspan\b/i)) warnings.push('Sequence without maxspan — consider adding a time window');
  }

  return { valid: errors.length === 0, errors, warnings };
}

function validateSnortSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.match(/\b(alert|drop|reject|pass)\b/)) errors.push('Missing action (alert/drop/reject/pass)');
  if (!rule.includes('msg:')) errors.push('Missing msg keyword');
  if (!rule.includes('sid:')) errors.push('Missing sid (signature ID)');
  if (!rule.includes('(') || !rule.includes(')')) errors.push('Missing rule options in parentheses');
  if (!rule.match(/\brev:\s*\d+/)) warnings.push('Missing rev (revision number)');

  // Protocol check
  if (!rule.match(/\b(tcp|udp|icmp|ip|http|ftp|smtp|dns|tls|ssl)\b/i)) warnings.push('No protocol specified');

  // Content check
  if (!rule.includes('content:') && !rule.includes('pcre:'))
    warnings.push('No content or pcre matching — rule may not match anything');

  return { valid: errors.length === 0, errors, warnings };
}

function validatePowershellSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.match(/\$(\w+|\{)/)) errors.push('Missing PowerShell variables');
  if (
    !rule.match(
      /\b(Get-|Select-|Where-|ForEach-|Import-|Write-|New-|Start-|Invoke-|Test-|Measure-|Compare-|ConvertFrom-|ConvertTo-)\b/i
    )
  )
    errors.push('Missing PowerShell cmdlets');

  // Check for common patterns
  if (rule.match(/\bGet-WinEvent\b/) && !rule.match(/\b-FilterHashtable\b|\b-FilterXPath\b|\b-LogName\b/))
    warnings.push('Get-WinEvent without filter — consider adding -FilterHashtable for performance');

  return { valid: errors.length === 0, errors, warnings };
}

function validateDlpSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    const json = JSON.parse(rule);
    if (!json.patterns && !json.rules && !json.match) errors.push('Missing patterns/rules/match field');
    if (json.patterns && Array.isArray(json.patterns)) {
      for (const p of json.patterns) {
        if (!p.regex && !p.pattern) warnings.push('Pattern entry missing regex/pattern field');
        try {
          new RegExp(p.regex ?? p.pattern ?? '');
        } catch (_catchErr) {
          logError('validateDlpSyntax failed', _catchErr);
          errors.push(`Invalid regex in pattern: ${p.regex ?? p.pattern}`);
        }
      }
    }
  } catch (_catchErr) {
    logError('validateDlpSyntax failed', _catchErr);
    if (!rule.includes('pattern') && !rule.includes('regex') && !rule.includes('match')) {
      errors.push('Invalid JSON or missing pattern definitions');
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

function validateSupplychainSyntax(rule: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!rule.includes('rules:') && !rule.includes('patterns:') && !rule.includes('pattern:'))
    errors.push('Missing rules or patterns section');
  if (
    !rule.includes('pattern') &&
    !rule.includes('regex') &&
    !rule.includes('pattern-either') &&
    !rule.includes('pattern-regex')
  )
    errors.push('Missing pattern definitions');
  if (!rule.includes('severity:') && !rule.includes('message:')) warnings.push('Missing severity or message field');

  return { valid: errors.length === 0, errors, warnings };
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

function validateRule(type: RuleType, rule: string): ValidationResult {
  switch (type) {
    case 'yara':
      return validateYaraSyntax(rule);
    case 'sigma':
      return validateSigmaSyntax(rule);
    case 'kql':
      return validateKqlSyntax(rule);
    case 'splunk':
      return validateSplunkSyntax(rule);
    case 'lucene':
      return validateLuceneSyntax(rule);
    case 'eql':
      return validateEqlSyntax(rule);
    case 'snort':
      return validateSnortSyntax(rule);
    case 'powershell':
      return validatePowershellSyntax(rule);
    case 'dlp':
      return validateDlpSyntax(rule);
    case 'supplychain':
      return validateSupplychainSyntax(rule);
    default:
      return { valid: false, errors: ['Unknown rule type'], warnings: [] };
  }
}

// ── Post-processing ──────────────────────────────────────────────────────

function postProcess(type: RuleType, rule: string): string {
  let out = rule;

  // Strip markdown code blocks (model may still emit them despite instructions)
  const codeBlock = out.match(/```(?:\w+)?\s*([\s\S]*?)```/);
  if (codeBlock?.[1]) out = codeBlock[1].trim();

  // Strip leading/trailing explanatory text
  const lines = out.split('\n');
  const formatDetectors: Record<RuleType, (line: string) => boolean> = {
    yara: (l) => /^\s*(rule\s+\w+|strings:|condition:|meta:|import\s)/.test(l),
    sigma: (l) => /^\s*(title:|detection:|logsource:|status:|description:)/.test(l),
    kql: (l) => /\|/.test(l) || /^\w+\s*$/.test(l),
    splunk: (l) => /\|/.test(l) || /^index=/.test(l) || /^sourcetype=/.test(l),
    lucene: (l) => /\b(AND|OR|NOT|:)\b/.test(l),
    eql: (l) => /\b(process|file|network|registry|dns)\b.*\bwhere\b/i.test(l) || /^\s*\w+\s+where\b/.test(l),
    snort: (l) => /^\s*(alert|drop|reject|pass)\s/.test(l),
    powershell: (l) => /\$/.test(l) || /\b(Get-|Select-|Where-|ForEach-)\b/.test(l),
    dlp: (l) => l.trim().startsWith('{') || /^\s*"(name|patterns|match)"\s*:/.test(l),
    supplychain: (l) => /^\s*(rules:|pattern:|id:|message:|severity:)/.test(l),
  };

  const detector = formatDetectors[type];
  let start = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] && detector(lines[i]!)) {
      start = i;
      break;
    }
  }
  let end = lines.length - 1;
  for (let i = lines.length - 1; i >= start; i--) {
    if (lines[i]?.trim()) {
      end = i;
      break;
    }
  }
  out = lines
    .slice(start, end + 1)
    .join('\n')
    .trim();

  // Format-specific cleanup
  switch (type) {
    case 'yara':
      // Ensure proper indentation
      out = out.replace(/\t/g, '  ');
      break;
    case 'sigma':
      // Ensure YAML starts with document marker or title
      if (!out.startsWith('title:') && !out.startsWith('---')) {
        const titleIdx = out.indexOf('title:');
        if (titleIdx > 0) out = out.slice(titleIdx);
      }
      break;
    case 'snort':
      // Ensure rule is on one line (Snort convention)
      out = out.replace(/\n\s*/g, ' ').replace(/\s+/g, ' ').trim();
      break;
  }

  return out;
}

function extractRuleName(type: RuleType, rule: string): string {
  switch (type) {
    case 'yara': {
      const match = rule.match(/rule\s+(\w+)/);
      return match?.[1] ?? 'generated_yara_rule';
    }
    case 'sigma': {
      const match = rule.match(/title:\s*(.+)/);
      return match?.[1]?.trim().replace(/\s+/g, '_').toLowerCase() ?? 'generated_sigma_rule';
    }
    case 'snort': {
      const match = rule.match(/msg:\s*"([^"]+)"/);
      return match?.[1]?.replace(/\s+/g, '_').toLowerCase() ?? 'generated_snort_rule';
    }
    case 'kql':
      return 'generated_kql_query';
    case 'splunk':
      return 'generated_splunk_query';
    case 'eql':
      return 'generated_eql_query';
    case 'powershell':
      return 'generated_hunt_script';
    case 'dlp': {
      try {
        const json = JSON.parse(rule);
        if (json.name) return json.name.replace(/\s+/g, '_').toLowerCase();
      } catch (_catchErr) {
        logError('extractRuleName failed', _catchErr);
        /* ok */
      }
      return 'generated_dlp_rule';
    }
    case 'supplychain': {
      const match = rule.match(/id:\s*(.+)/);
      return match?.[1]?.trim() ?? 'generated_semgrep_rule';
    }
    default:
      return 'generated_rule';
  }
}

// ── Few-shot Examples ────────────────────────────────────────────────────

const YARA_EXAMPLE = `rule CobaltStrike_Beacon_Strings {
  meta:
    author = "DFIR Toolkit"
    description = "Detects Cobalt Strike beacon by named pipe and config patterns"
    date = "2024-01-15"
    reference = "https://attack.mitre.org/software/S0154/"
    severity = "critical"
  strings:
    $pipe1 = "\\\\%s\\\\pipe\\\\msagent_%x" ascii
    $pipe2 = "\\\\%s\\\\pipe\\\\MSSE-%d-server" ascii
    $config1 = { 69 00 6E 00 74 00 65 00 72 00 6E 00 65 00 74 }
    $beacon = "beacon.dll" ascii nocase
    $sleep_mask = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }
  condition:
    uint16(0) == 0x5A4D and
    filesize < 2MB and
    (2 of ($pipe*) or ($config1 and $beacon) or $sleep_mask)
}`;

const SIGMA_EXAMPLE = `title: Suspicious PowerShell Encoded Command Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell execution with Base64 encoded commands, commonly used by attackers to evade detection
author: DFIR Toolkit
date: 2024/01/15
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-Enc '
      - '-ec '
      - 'FromBase64String'
  selection_encoded_long:
    CommandLine|re: '[A-Za-z0-9+/]{50,}={0,2}'
  condition: selection_img and (selection_encoded or selection_encoded_long)
falsepositives:
  - Legitimate administrative scripts using encoded commands
  - Software deployment tools
level: high`;

const KQL_EXAMPLE = `// Detect suspicious process creation from Office applications
// MITRE ATT&CK: T1059.001 - PowerShell, T1204.002 - User Execution: Malicious File
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("WINWORD.EXCEL.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc`;

const SPLUNK_EXAMPLE = `index=windows sourcetype=WinEventLog:Security EventCode=4688
| where match(Image, "(?i)\\\\(cmd|powershell|pwsh|wscript|cscript|mshta|certutil|bitsadmin)\\.exe$")
| where match(ParentImage, "(?i)\\\\(winword|excel|powerpnt|outlook|acrobat|chrome|firefox)\\.exe$")
| stats count by Image, ParentImage, CommandLine, ComputerName, Account_Name
| where count > 0
| sort - count`;

const LUCENE_EXAMPLE = `process.name:(cmd.exe OR powershell.exe OR pwsh.exe OR wscript.exe OR cscript.exe OR mshta.exe)
AND process.parent.name:(WINWORD.EXE OR EXCEL.EXE OR POWERPNT.EXE OR OUTLOOK.EXE OR chrome.exe OR firefox.exe)
AND NOT process.command_line:("*\\Microsoft*" OR "*\\Windows\\*")`;

const EQL_EXAMPLE = `sequence by host.name with maxspan=5m
  [process where process.name in ("cmd.exe", "powershell.exe", "pwsh.exe") and
    process.parent.name in ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")]
  [network where destination.port in (443, 8443) and not destination.address in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
  [file where event.type == "creation" and file.path : "*\\AppData\\*"]`;

const SNORT_EXAMPLE = `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
  msg:"MALWARE-COBALTSTRIKE Beacon C2 Checkin";
  flow:established,to_server;
  content:"GET";
  http_method;
  content:"/submit.php";
  http_uri;
  content:"id=";
  http_client_body;
  pcre:"/id=[A-Za-z0-9+/]{20,}={0,2}/P";
  classtype:trojan-activity;
  sid:1000001;
  rev:1;
)`;

const POWERSHELL_EXAMPLE = `# Hunt for suspicious scheduled task creation
# MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TaskScheduler/Operational'
        Id = 106, 140, 141
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue

    $suspicious = $events | Where-Object {
        $xml = [xml]$_.ToXml()
        $taskName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskName' } | Select-Object -ExpandProperty '#text'
        $taskName -match '\\\\(Update|Temp|System|Microsoft|Windows)\\\\' -or
        $taskName -match '\\.tmp$' -or
        $taskName -match '[A-Za-z0-9]{20,}'
    }

    if ($suspicious) {
        $suspicious | Select-Object TimeCreated, @{
            Name = 'TaskName'
            Expression = { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TaskName' } | Select-Object -ExpandProperty '#text' }
        } | Format-Table -AutoSize
    } else {
        Write-Host "No suspicious scheduled task creation found." -ForegroundColor Green
    }
} catch {
    Write-Error "Error querying scheduled tasks: $_"
}`;

const DLP_EXAMPLE = `{
  "name": "API Keys and Access Tokens Detection",
  "description": "Detects common API keys, access tokens, and secrets in documents and communications",
  "severity": "critical",
  "match": "any",
  "patterns": [
    {
      "id": "aws-access-key",
      "field": "content",
      "regex": "(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
      "context_regex": "(?i)(aws|amazon|access.?key)"
    },
    {
      "id": "github-token",
      "field": "content",
      "regex": "gh[ps]_[A-Za-z0-9_]{36,}",
      "context_regex": "(?i)(github|token|pat)"
    },
    {
      "id": "slack-webhook",
      "field": "content",
      "regex": "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
      "context_regex": ""
    },
    {
      "id": "generic-api-key",
      "field": "content",
      "regex": "(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\\s*[:=]\\s*['\\"]?[A-Za-z0-9_\\-]{20,}['\\"]?",
      "context_regex": ""
    }
  ],
  "exceptions": [
    {
      "field": "content",
      "regex": "(?i)(example|test|sample|placeholder|your[_-]?key|xxx+)"
    }
  ]
}`;

const SUPPLYCHAIN_EXAMPLE = `rules:
  - id: npm-typosquatting-install-script
    patterns:
      - pattern: |
          {
            "scripts": {
              "preinstall": "...",
              "postinstall": "..."
            }
          }
      - pattern-regex: '(?:pre|post)install\\s*:\\s*["' + "'" + '].*(?:curl|wget|eval|exec|child_process|base64|decode|fetch)'
    message: >
      Detected npm package with suspicious install scripts that may indicate
      supply chain attack (typosquatting or dependency confusion).
    severity: WARNING
    languages:
      - json
    metadata:
      cwe:
        - "CWE-506: Embedded Malicious Code"
      owasp:
        - A08:2021 - Software and Data Integrity Failures
      confidence: HIGH
    fix: |
      Remove the suspicious install script and verify the package source.
      Check the package author, download count, and repository link.`;

const FEW_SHOT_EXAMPLES: Record<RuleType, string> = {
  yara: YARA_EXAMPLE,
  sigma: SIGMA_EXAMPLE,
  kql: KQL_EXAMPLE,
  splunk: SPLUNK_EXAMPLE,
  lucene: LUCENE_EXAMPLE,
  eql: EQL_EXAMPLE,
  snort: SNORT_EXAMPLE,
  powershell: POWERSHELL_EXAMPLE,
  dlp: DLP_EXAMPLE,
  supplychain: SUPPLYCHAIN_EXAMPLE,
};

// ── Prompt Templates ─────────────────────────────────────────────────────

function buildYaraPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple rule with 2-4 string matches and a straightforward condition.',
    standard: 'Generate a balanced rule with 5-10 string matches, conditions, and metadata.',
    advanced:
      'Generate a comprehensive rule with multiple string types (text, hex, regex), detailed conditions, full metadata, and PE/ELF module imports when relevant.',
  };

  return {
    system: `You are a YARA rule expert. Generate syntactically valid YARA rules.

STRICT RULES:
- Return ONLY the YARA rule text. No explanations, no markdown code blocks, no commentary.
- Rule name must be a valid identifier (alphanumeric + underscore, starting with letter).
- Every string definition must use correct syntax: $name = "text" ascii, $name = { hex }, $name = /regex/
- The condition section MUST reference defined strings.
- Include metadata: author, description, date, reference.

EXAMPLE OF A VALID YARA RULE:
${FEW_SHOT_EXAMPLES.yara}`,
    user: `Generate a YARA rule for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.filetype ? `Target file type: ${req.filetype}` : ''}
${req.strings ? `Known strings to match:\n${req.strings.map((s, i) => `$s${i} = "${s}"`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the YARA rule.`,
  };
}

function buildSigmaPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const logsource = req.logsource || 'windows/process_creation';

  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple Sigma rule with one selection and a condition.',
    standard: 'Generate a Sigma rule with 2-4 selections, proper condition logic, and metadata.',
    advanced:
      'Generate a comprehensive Sigma rule with aggregations, time windows, multiple log sources, and full SigmaHQ-compliant metadata.',
  };

  return {
    system: `You are a Sigma rule expert. Generate syntactically valid Sigma rules in YAML format following SigmaHQ conventions.

STRICT RULES:
- Return ONLY the Sigma rule YAML. No explanations, no markdown code blocks.
- Use SigmaHQ naming: selection_*, filter_*, condition.
- Include: title, id (UUID), status, description, author, date, references, tags, logsource, detection, falsepositives, level.
- Tags must use attack.* format (e.g., attack.execution, attack.t1059.001).
- Level must be one of: informational, low, medium, high, critical.

EXAMPLE OF A VALID SIGMA RULE:
${FEW_SHOT_EXAMPLES.sigma}`,
    user: `Generate a Sigma rule for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known indicators:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Log Source: ${logsource}
Complexity: ${complexityInstructions[complexity]}

Return ONLY the Sigma rule YAML.`,
  };
}

function buildKqlPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const table = req.table || 'DeviceProcessEvents';

  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple KQL query with where filtering and project.',
    standard: 'Generate a KQL query with multiple where clauses, extend, and summarize.',
    advanced: 'Generate a comprehensive KQL query with joins, subqueries, time windows, and anomaly detection.',
  };

  return {
    system: `You are a KQL expert for Microsoft Sentinel and Microsoft Defender for Endpoint. Generate syntactically valid KQL queries.

STRICT RULES:
- Return ONLY the KQL query. No explanations, no markdown code blocks.
- Start with the table name, then pipe operators.
- Use proper KQL: where, extend, project, summarize, join, union, mv-expand.
- Use datetime functions (ago(), now()) for time filtering.
- Add comments (//) explaining complex logic.

EXAMPLE OF A VALID KQL QUERY:
${FEW_SHOT_EXAMPLES.kql}`,
    user: `Generate a KQL query for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known indicators:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Primary Table: ${table}
Complexity: ${complexityInstructions[complexity]}

Return ONLY the KQL query.`,
  };
}

function buildSplunkPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple Splunk query with index, where, and stats.',
    standard: 'Generate a Splunk query with eval, rex, stats, and time range.',
    advanced: 'Generate a comprehensive Splunk query with subsearches, lookups, tstats, and advanced analytics.',
  };

  return {
    system: `You are a Splunk SPL expert. Generate syntactically valid Splunk queries.

STRICT RULES:
- Return ONLY the Splunk query. No explanations, no markdown code blocks.
- Start with index= or sourcetype= or | tstats.
- Use proper SPL commands: search, where, eval, stats, rex, lookup, table, sort.
- Use match() and regex for pattern matching.
- Add inline comments with | eval comment="...".

EXAMPLE OF A VALID SPLUNK QUERY:
${FEW_SHOT_EXAMPLES.splunk}`,
    user: `Generate a Splunk query for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known indicators:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the Splunk query.`,
  };
}

function buildLucenePrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple Lucene query with field:value and AND/OR.',
    standard: 'Generate a Lucene query with boolean operators, wildcards, and grouping.',
    advanced: 'Generate a comprehensive Lucene query with wildcards, proximity, ranges, and boosting.',
  };

  return {
    system: `You are an Elasticsearch Lucene query expert for Kibana. Generate syntactically valid Lucene queries.

STRICT RULES:
- Return ONLY the Lucene query. No explanations, no markdown code blocks.
- Use field:value syntax with AND, OR, NOT operators.
- Use parentheses for grouping.
- Use wildcards (*) and ranges ([min TO max]) where appropriate.
- Use quotes for exact phrases.

EXAMPLE OF A VALID LUCENE QUERY:
${FEW_SHOT_EXAMPLES.lucene}`,
    user: `Generate a Lucene query for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known indicators:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the Lucene query.`,
  };
}

function buildEqlPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple EQL query with basic event filtering.',
    standard: 'Generate an EQL query with sequence and by grouping.',
    advanced: 'Generate a comprehensive EQL query with sequences, maxspan, by fields, and joins.',
  };

  return {
    system: `You are an Elastic EQL (Event Query Language) expert. Generate syntactically valid EQL queries.

STRICT RULES:
- Return ONLY the EQL query. No explanations, no markdown code blocks.
- Start with entity type (process, file, network, registry, dns) or sequence.
- Use where clause with proper operators.
- Use stringContains, startsWith, endsWith for string matching.
- Use by keyword for grouping and with maxspan for sequences.

EXAMPLE OF A VALID EQL QUERY:
${FEW_SHOT_EXAMPLES.eql}`,
    user: `Generate an EQL query for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known indicators:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the EQL query.`,
  };
}

function buildSnortPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple Snort rule with content matching.',
    standard: 'Generate a Snort rule with multiple content matches, flow, and metadata.',
    advanced: 'Generate a comprehensive Snort rule with PCRE, byte tests, flowbits, and threshold.',
  };

  return {
    system: `You are a Snort/Suricata IDS rule expert. Generate syntactically valid Snort rules.

STRICT RULES:
- Return ONLY the Snort rule. No explanations, no markdown code blocks.
- Start with action (alert/drop/reject/pass).
- Specify protocol, source/dest IPs and ports.
- Include msg, content/pcre, classtype, sid (1000000+), rev.
- Use flow, threshold, and metadata keywords.

EXAMPLE OF A VALID SNORT RULE:
${FEW_SHOT_EXAMPLES.snort}`,
    user: `Generate a Snort rule for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known patterns:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the Snort rule.`,
  };
}

function buildPowershellPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate a simple PowerShell script with Get-WinEvent and filtering.',
    standard: 'Generate a PowerShell script with event queries, filtering, and formatted output.',
    advanced: 'Generate a comprehensive PowerShell script with CIM/WMI, remote queries, and alerting.',
  };

  return {
    system: `You are a PowerShell security expert for threat hunting. Generate syntactically valid PowerShell scripts.

STRICT RULES:
- Return ONLY the PowerShell script. No explanations, no markdown code blocks.
- Use Get-WinEvent with -FilterHashtable for performance.
- Include try/catch error handling.
- Use Where-Object for filtering, Select-Object for output.
- Add comments explaining the detection logic.

EXAMPLE OF A VALID POWERSHELL SCRIPT:
${FEW_SHOT_EXAMPLES.powershell}`,
    user: `Generate a PowerShell script for this detection requirement:

Description: ${req.description}
${req.family ? `Malware family: ${req.family}` : ''}
${req.strings ? `Known patterns:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the PowerShell script.`,
  };
}

function buildDlpPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate simple DLP regex patterns for common sensitive data.',
    standard: 'Generate DLP rules with multiple patterns, context regexes, and confidence scoring.',
    advanced: 'Generate comprehensive DLP rules with context-aware patterns, exceptions, and validation.',
  };

  return {
    system: `You are a Data Loss Prevention (DLP) expert. Generate DLP detection rules in JSON format.

STRICT RULES:
- Return ONLY valid JSON. No explanations, no markdown code blocks.
- Include "name", "description", "severity", "match", "patterns", "exceptions".
- Each pattern needs "id", "field", "regex".
- Use context_regex to reduce false positives.
- All regex must be valid and tested.

EXAMPLE OF A VALID DLP RULE:
${FEW_SHOT_EXAMPLES.dlp}`,
    user: `Generate a DLP rule for this detection requirement:

Description: ${req.description}
${req.strings ? `Known patterns:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the DLP JSON rule.`,
  };
}

function buildSupplychainPrompt(req: GenerateRequest, complexity: string): { system: string; user: string } {
  const complexityInstructions: Record<string, string> = {
    basic: 'Generate simple Semgrep patterns for supply chain detection.',
    standard: 'Generate Semgrep rules with multiple patterns and metadata.',
    advanced: 'Generate comprehensive Semgrep rules with metavariables, taint tracking, and deep matching.',
  };

  return {
    system: `You are a Semgrep/static analysis expert for supply chain security. Generate syntactically valid Semgrep rules.

STRICT RULES:
- Return ONLY the Semgrep YAML rule. No explanations, no markdown code blocks.
- Include rules array with id, message, severity, languages, patterns/pattern-regex.
- Add metadata with cwe and owasp references.
- Include fix suggestions when applicable.

EXAMPLE OF A VALID SEMGREP RULE:
${FEW_SHOT_EXAMPLES.supplychain}`,
    user: `Generate a Semgrep rule for this supply chain detection requirement:

Description: ${req.description}
${req.family ? `Package/library: ${req.family}` : ''}
${req.strings ? `Known patterns:\n${req.strings.map((s) => `- ${s}`).join('\n')}` : ''}

Complexity: ${complexityInstructions[complexity]}

Return ONLY the Semgrep YAML rule.`,
  };
}

// ── MITRE ATT&CK Extraction ─────────────────────────────────────────────

function extractMitreTechniques(description: string): string[] {
  const techniques: string[] = [];
  const descLower = description.toLowerCase();

  const mappings: [string[], string][] = [
    // Initial Access
    [['phishing', 'email', 'spearphish', 'attachment', 'lure'], 'T1566'],
    [['exploit', 'vulnerability', 'cve', 'rce', 'buffer overflow', 'zero-day', '0day'], 'T1190'],
    [['supply chain', 'trojanized', 'dependency', 'typosquat'], 'T1195'],
    [['drive-by', 'watering hole', 'browser exploit'], 'T1189'],
    // Execution
    [['powershell', 'ps1', 'invoke-'], 'T1059.001'],
    [['cmd', 'command', 'cmd.exe', 'cmd /c'], 'T1059.003'],
    [['wscript', 'cscript', 'vbs', 'vbscript', 'jscript'], 'T1059.005'],
    [['mshta', 'html application', 'hta'], 'T1218.005'],
    [['javascript', 'js execution', 'node'], 'T1059.007'],
    [['python', 'py ', 'python3'], 'T1059.006'],
    [['wmic', 'wmi', 'win32_'], 'T1047'],
    [['scheduled', 'task', 'schtasks', 'at.exe'], 'T1053'],
    [['msiexec', 'installer', 'msi'], 'T1218.007'],
    [['rundll32', 'rundll'], 'T1218.011'],
    [['regsvr32', 'regsvr'], 'T1218.010'],
    // Persistence
    [
      [
        'registry',
        'run key',
        'runonce',
        'autorun',
        'hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run',
      ],
      'T1547',
    ],
    [['service', 'sc.exe', 'new-service', 'svchost'], 'T1543.003'],
    [['startup', 'startup folder', 'shell:startup'], 'T1547.001'],
    [['dll', 'sideload', 'hijack', 'proxying', 'dll search order'], 'T1574'],
    [['com object', 'clsid', 'com hijack'], 'T1546.015'],
    [['bootkit', 'boot record', 'mbr', 'vbr'], 'T1553.003'],
    // Privilege Escalation
    [['uac', 'bypass', 'elevation', 'runas'], 'T1548.002'],
    [['process', 'injection', 'hollow', 'inject', 'reflective'], 'T1055'],
    [['token', 'impersonat', 'steal token', 'privilege'], 'T1134'],
    // Defense Evasion
    [['obfuscat', 'pack', 'encode', 'base64', 'xor', 'encrypt payload'], 'T1027'],
    [['amsi', 'bypass', 'antimalware scan'], 'T1562.001'],
    [['disable', 'defender', 'av', 'antivirus', 'tamper'], 'T1562'],
    [['masquerad', 'renam', 'legitimate name', 'spoof'], 'T1036'],
    [['timestomp', 'timestamp', 'file time', 'change date'], 'T1070.006'],
    [['clear', 'log', 'event log', 'wevtutil', 'log delete'], 'T1070.001'],
    [['process ghosting', 'process doppelganging', 'herpaderping'], 'T1055.013'],
    // Credential Access
    [['credential', 'password', 'mimikatz', 'dump', 'lsass', 'sam', 'ntds'], 'T1003'],
    [['kerberoast', 'kerberos', 'tgs', 'asrep'], 'T1558'],
    [['brute', 'force', 'password spray', 'credential stuffing'], 'T1110'],
    [['keylog', 'keystroke', 'input capture'], 'T1056'],
    [['browser', 'cookie', 'credential store', 'password manager'], 'T1555'],
    // Discovery
    [['discovery', 'recon', 'enumerate', 'whoami', 'ipconfig', 'systeminfo', 'net user', 'net group'], 'T1082'],
    [['network', 'scan', 'port scan', 'nmap', 'internal recon'], 'T1046'],
    [['ad ', 'active directory', 'ldap', 'domain trust'], 'T1482'],
    // Lateral Movement
    [['lateral', 'move', 'smb', 'psexec', 'wmic /node'], 'T1021.002'],
    [['rdp', 'remote desktop', 'terminal services'], 'T1021.001'],
    [['ssh', 'remote shell', 'putty'], 'T1021.004'],
    [['winrm', 'powershell remoting', 'enter-pssession'], 'T1021.006'],
    // Collection
    [['screen', 'capture', 'screenshot', 'screencap'], 'T1113'],
    [['keylog', 'input capture', 'keystroke'], 'T1056'],
    [['archive', 'compress', 'zip', 'rar', '7z', 'exfil package'], 'T1560'],
    [['clipboard', 'cliplog'], 'T1115'],
    // Exfiltration
    [['exfil', 'data', 'steal', 'exfiltration', 'data transfer', 'upload'], 'T1041'],
    [['dns tunnel', 'dns exfil', 'dns query long'], 'T1048.003'],
    [['cloud', 'storage', 'dropbox', 'drive', 'mega.nz'], 'T1567'],
    // C2
    [['c2', 'command and control', 'beacon', 'cobalt', 'cobaltstrike', 'covenant', 'sliver', 'metasploit'], 'T1071'],
    [['dns tunnel', 'dns c2', 'dns query', 'dns request long'], 'T1071.004'],
    [['http', 'https', 'web request', 'callback', 'c2 over http'], 'T1071.001'],
    [['domain fronting', 'cdn', 'cloudfront'], 'T1090.004'],
    [['tor', 'onion', 'proxy', 'anonymiz'], 'T1090.003'],
    // Impact
    [['ransom', 'encrypt', 'ransomware', 'bitcoin', 'decrypt', 'lockbit', 'conti', 'revil'], 'T1486'],
    [['wiper', 'destroy', 'shred', 'disk wipe'], 'T1485'],
    [['deface', 'website', 'modify content'], 'T1491'],
  ];

  for (const [keywords, technique] of mappings) {
    if (keywords.some((kw) => descLower.includes(kw))) {
      techniques.push(technique);
    }
  }

  return [...new Set(techniques)].slice(0, 10);
}

// ── Self-healing retry ──────────────────────────────────────────────────

const MAX_RETRIES = 2;

interface GenerateOpts {
  ai: Env['AI'];
  groqKey?: string;
  nvidiaKey?: string;
  req: GenerateRequest;
  complexity: string;
  promptBuilders: Record<RuleType, (req: GenerateRequest, c: string) => { system: string; user: string }>;
}

async function generateWithRetry(
  opts: GenerateOpts
): Promise<{ content: string; validation: ValidationResult; retries: number; modelUsed: string }> {
  const { ai, groqKey, nvidiaKey, req, complexity, promptBuilders } = opts;
  const { system, user } = promptBuilders[req.type](req, complexity);

  let lastContent = '';
  let lastValidation: ValidationResult = { valid: false, errors: [], warnings: [] };
  let modelUsed = '';
  let actualRetries = 0;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    let promptUser = user;

    // On retry, append the previous failure as context
    if (attempt > 0) {
      actualRetries = attempt;
      promptUser = `${user}

---
PREVIOUS ATTEMPT (had errors):
${lastContent}

ERRORS TO FIX:
${lastValidation.errors.map((e) => `- ${e}`).join('\n')}

Please return the corrected rule ONLY. No explanations.`;
    }

    const result = await runLlm(ai, groqKey, nvidiaKey, {
      system,
      user: promptUser,
      maxTokens: 2500,
      temperature: Math.max(0.1, 0.2 - attempt * 0.05),
    });

    modelUsed = result.modelUsed;
    lastContent = postProcess(req.type, result.text);
    lastValidation = validateRule(req.type, lastContent);

    if (lastValidation.valid) break;
  }

  return { content: lastContent, validation: lastValidation, retries: actualRetries, modelUsed };
}

// ── Route Handlers ───────────────────────────────────────────────────────

const VALID_TYPES: RuleType[] = [
  'yara',
  'sigma',
  'kql',
  'splunk',
  'lucene',
  'eql',
  'snort',
  'powershell',
  'dlp',
  'supplychain',
];

export async function ruleGeneratorHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const body = await c.req.json<GenerateRequest>();

    if (!body.type || !VALID_TYPES.includes(body.type)) {
      return badRequest(c, `type must be one of: ${VALID_TYPES.join(', ')}`);
    }
    if (!body.description) return badRequest(c, 'description is required');
    if (body.description.length > MAX_DESCRIPTION_LENGTH) {
      return badRequest(c, `description too long (max ${MAX_DESCRIPTION_LENGTH} chars)`);
    }
    if (body.strings && body.strings.length > MAX_STRINGS) {
      return badRequest(c, `too many strings (max ${MAX_STRINGS})`);
    }

    const complexity = body.complexity ?? 'standard';

    const promptBuilders: Record<RuleType, (req: GenerateRequest, c: string) => { system: string; user: string }> = {
      yara: buildYaraPrompt,
      sigma: buildSigmaPrompt,
      kql: buildKqlPrompt,
      splunk: buildSplunkPrompt,
      lucene: buildLucenePrompt,
      eql: buildEqlPrompt,
      snort: buildSnortPrompt,
      powershell: buildPowershellPrompt,
      dlp: buildDlpPrompt,
      supplychain: buildSupplychainPrompt,
    };

    const { content, validation, retries, modelUsed } = await generateWithRetry({
      ai: c.env.AI,
      groqKey: c.env.GROQ_API_KEY,
      nvidiaKey: c.env.NVIDIA_API_KEY,
      req: body,
      complexity,
      promptBuilders,
    });

    const ruleName = extractRuleName(body.type, content);
    const mitreTechniques = extractMitreTechniques(body.description);

    const result: GeneratedRule = {
      rule_id: crypto.randomUUID(),
      rule_type: body.type,
      rule_name: ruleName,
      rule_content: content,
      description: body.description,
      detection_logic: body.strings?.map((s) => `Matches "${s}"`) ?? ['Pattern-based detection'],
      syntax_confidence: validation.valid ? 'high' : validation.warnings.length > 0 ? 'medium' : 'low',
      detection_confidence: body.strings && body.strings.length > 0 ? 'high' : 'medium',
      testing_notes: validation.valid
        ? `${body.type.toUpperCase()} syntax validated. Test in your environment before deployment.`
        : `Syntax issues: ${validation.errors.join('; ')}. Manual review recommended.`,
      mitre_techniques: mitreTechniques,
      meta: {
        generated_at: new Date().toISOString(),
        model: modelUsed,
        complexity,
        retries,
      },
    };

    return c.json(result, 200, { 'Cache-Control': 'no-store' });
  } catch (err) {
    logError('Rule generator error:', err);
    return internalError(c, err);
  }
}

export async function ruleValidateHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    const body = await c.req.json<{ type: RuleType; rule: string }>();

    if (!body.type || !VALID_TYPES.includes(body.type)) {
      return badRequest(c, `type must be one of: ${VALID_TYPES.join(', ')}`);
    }
    if (!body.rule) return badRequest(c, 'rule is required');

    const validation = validateRule(body.type, body.rule);
    const ruleName = extractRuleName(body.type, body.rule);

    let analysis: Record<string, unknown> = {};

    if (body.type === 'yara') {
      const stringMatches = body.rule.match(/\$[a-zA-Z_]\w*\s*=/g) ?? [];
      const hexStrings = body.rule.match(/\$\w+\s*=\s*\{/g) ?? [];
      const regexStrings = body.rule.match(/\$\w+\s*=\s*\//g) ?? [];
      const textStrings = body.rule.match(/\$\w+\s*=\s*"/g) ?? [];
      analysis = {
        string_count: stringMatches.length,
        hex_count: hexStrings.length,
        regex_count: regexStrings.length,
        text_count: textStrings.length,
        has_conditions: body.rule.includes('condition:'),
        has_metadata: body.rule.includes('meta:'),
        has_imports: body.rule.includes('import '),
        has_pe_module: body.rule.includes('pe.'),
        has_elf_module: body.rule.includes('elf.'),
        has_math_module: body.rule.includes('math.'),
        complexity: stringMatches.length > 10 ? 'advanced' : stringMatches.length > 3 ? 'standard' : 'basic',
      };
    } else if (body.type === 'sigma') {
      const selections = (body.rule.match(/\b\w*selection\w*\s*:/gi) ?? []).length;
      const filters = (body.rule.match(/\b\w*filter\w*\s*:/gi) ?? []).length;
      analysis = {
        selection_count: selections,
        filter_count: filters,
        has_logsource: body.rule.includes('logsource:'),
        has_detection: body.rule.includes('detection:'),
        has_condition: body.rule.includes('condition:'),
        has_metadata: body.rule.includes('tags:') || body.rule.includes('author:'),
        has_falsepositives: body.rule.includes('falsepositives:'),
        has_level: body.rule.includes('level:'),
        has_id: body.rule.includes('id:'),
        complexity: selections > 5 ? 'advanced' : selections > 2 ? 'standard' : 'basic',
      };
    } else if (body.type === 'kql') {
      const operators =
        body.rule.match(
          /\b(where|extend|project|summarize|join|union|mv-expand|parse|make-series|top|sort|count|distinct|take|limit)\b/gi
        ) ?? [];
      analysis = {
        operator_count: operators.length,
        has_where: operators.some((o) => o.toLowerCase() === 'where'),
        has_summarize: operators.some((o) => o.toLowerCase() === 'summarize'),
        has_join: operators.some((o) => o.toLowerCase() === 'join'),
        has_extend: operators.some((o) => o.toLowerCase() === 'extend'),
        has_project: operators.some((o) => o.toLowerCase() === 'project'),
        pipe_count: (body.rule.match(/\|/g) ?? []).length,
        complexity: operators.length > 5 ? 'advanced' : operators.length > 2 ? 'standard' : 'basic',
      };
    }

    return c.json({
      type: body.type,
      valid: validation.valid,
      errors: validation.errors,
      warnings: validation.warnings,
      rule_name: ruleName,
      analysis,
    });
  } catch (err) {
    logError('handler failed', err);
    return internalError(c, err);
  }
}
