/**
 * Minimal YARA / Sigma rule "matcher" for the rule playground.
 *
 * This is intentionally NOT a full parser:
 *  - YARA: extract `strings:` (text, hex, regex variants), test each against
 *    the sample. Condition is informational only - we don't evaluate boolean
 *    logic; the analyst can read the condition and reason about it.
 *  - Sigma: walk the `detection:` block, pull out keyword / contains / equals
 *    leaves and test each as a substring match. Modifiers like |contains and
 *    |startswith are honoured at the leaf level. Logsource / condition are
 *    surfaced for context but not evaluated.
 *
 * The goal is "show what a rule would highlight" for teaching and triage,
 * not to be a drop-in replacement for the real engines.
 */
import { errMessage } from '../log';

export type RuleKind = 'yara' | 'sigma' | 'unknown';

export interface RuleStringMatch {
  /** Display name for the matched string ($a, keyword[2], etc.). */
  name: string;
  /** What was actually matched in the sample. */
  text: string;
  /** Index inside the sample. */
  index: number;
  /** Origin tag - yara_string, yara_hex, yara_regex, sigma_keyword. */
  kind: 'yara_string' | 'yara_hex' | 'yara_regex' | 'sigma_keyword';
}

export interface ParsedRule {
  kind: RuleKind;
  /** Rule name (best-effort from `rule X` or `title:`). */
  name: string;
  /** Plain-text condition (YARA) or condition string (Sigma). */
  condition: string;
  /** Strings / keywords the rule looks for. */
  needles: Array<{ name: string; pattern: RegExp; kind: RuleStringMatch['kind'] }>;
  /** Anything we want to surface to the user (logsource, tags, etc.). */
  meta: Array<{ k: string; v: string }>;
  /** Parser-level errors / warnings. */
  warnings: string[];
}

export function detectKind(rule: string): RuleKind {
  const trimmed = rule.trim();
  if (/^\s*rule\s+\w+/i.test(trimmed) && /\bcondition\s*:/i.test(trimmed)) return 'yara';
  if (/^\s*(title|logsource|detection)\s*:/im.test(trimmed)) return 'sigma';
  return 'unknown';
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Cheap ReDoS guard: reject user-supplied regex sources that contain a nested
 * unbounded quantifier (e.g. `(a+)+`, `(a*)*`, `(a+)*`) - the classic
 * catastrophic-backtracking shape. Not exhaustive, but blocks the trivially
 * pathological patterns from hanging the tab.
 */
function isLikelyCatastrophicRegex(source: string): boolean {
  return /\([^)]*[+*][^)]*\)\s*[+*]/.test(source);
}

// ─────────────────────────────────────────────────────────────────────────
// YARA parser
// ─────────────────────────────────────────────────────────────────────────

function hexPatternToRegex(hex: string): RegExp {
  // Strip comments + whitespace
  const cleaned = hex.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  // Wildcards: ?? -> any byte, [n-m] -> n..m bytes (we use {n,m})
  let re = '';
  let i = 0;
  while (i < cleaned.length) {
    const c = cleaned[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i++;
      continue;
    }
    if (c === '?') {
      // ?? = any byte; ?X / X? = nibble wildcards (approximate as any byte)
      const next = cleaned[i + 1] ?? '';
      if (next === '?') {
        re += '[\\s\\S]'; // 1 char
        i += 2;
        continue;
      }
      re += '[\\s\\S]';
      i += 2;
      continue;
    }
    if (c === '[') {
      const end = cleaned.indexOf(']', i);
      if (end < 0) {
        i = cleaned.length;
        break;
      }
      const inside = cleaned.slice(i + 1, end).trim();
      const range = inside.split('-').map((s) => parseInt(s.trim(), 10));
      if (range.length === 2 && !isNaN(range[0]!) && !isNaN(range[1]!)) {
        re += `[\\s\\S]{${range[0]!},${range[1]!}}`;
      } else if (range.length === 1 && !isNaN(range[0]!)) {
        re += `[\\s\\S]{${range[0]!}}`;
      }
      i = end + 1;
      continue;
    }
    // Take 2 hex digits as one char
    const pair = cleaned.slice(i, i + 2);
    if (/^[0-9a-fA-F]{2}$/.test(pair)) {
      // Encode as the literal byte's char-code; we treat the sample as text,
      // so this only matches if the hex bytes correspond to printable / matching
      // chars - good enough for teaching. Use \\xNN for safety.
      re += `\\x${pair}`;
      i += 2;
      continue;
    }
    i++;
  }
  return new RegExp(re);
}

export function parseYaraRule(rule: string): ParsedRule {
  const warnings: string[] = [];
  const meta: Array<{ k: string; v: string }> = [];
  const needles: ParsedRule['needles'] = [];

  const nameMatch = rule.match(/\brule\s+(\w+)/i);
  const name = nameMatch?.[1] ?? '(unnamed)';

  const stringsBlock = rule.match(/strings\s*:\s*([\s\S]*?)\s*condition\s*:/i);
  const condMatch = rule.match(/condition\s*:\s*([\s\S]*?)\s*\}\s*$/i);

  if (stringsBlock) {
    const body = stringsBlock[1];
    // Match: $name = "literal" modifiers OR $name = { hex } OR $name = /regex/
    const rx = /\$(\w+)\s*=\s*("([^"\\]|\\.)*"|\{[^}]*\}|\/((?:[^/\\]|\\.)+)\/[a-z]*)\s*([a-z\s]*)/gi;
    let m: RegExpExecArray | null;
    while ((m = rx.exec(body!)) !== null) {
      const id = `$${m[1]!}`;
      const raw = m[2]!;
      const mods = (m[5] ?? '').toLowerCase();
      try {
        if (raw.startsWith('"')) {
          const literal = raw.slice(1, -1).replace(/\\(.)/g, '$1');
          const flags = mods.includes('nocase') ? 'i' : '';
          if (mods.includes('wide')) {
            // wide = UTF-16LE - interleave NULs. We can't rely on the sample
            // being binary, so fall back to a relaxed pattern.
            const w = literal
              .split('')
              .map((c) => escapeRegex(c))
              .join('\\x00?');
            needles.push({ name: id, pattern: new RegExp(w, flags || undefined), kind: 'yara_string' });
          } else {
            needles.push({
              name: id,
              pattern: new RegExp(escapeRegex(literal), flags || undefined),
              kind: 'yara_string',
            });
          }
        } else if (raw.startsWith('{')) {
          needles.push({ name: id, pattern: hexPatternToRegex(raw.slice(1, -1)), kind: 'yara_hex' });
        } else if (raw.startsWith('/')) {
          // /regex/ flags
          const lastSlash = raw.lastIndexOf('/');
          const body = raw.slice(1, lastSlash);
          const flags = raw.slice(lastSlash + 1);
          const cleaned = flags.replace(/[^gimsuy]/g, '');
          if (isLikelyCatastrophicRegex(body)) {
            warnings.push(`String ${id}: regex skipped - nested unbounded quantifier (ReDoS risk).`);
          } else {
            needles.push({ name: id, pattern: new RegExp(body, cleaned), kind: 'yara_regex' });
          }
        }
      } catch (e) {
        warnings.push(`String ${id}: ${errMessage(e, 'invalid')}`);
      }
    }
  } else {
    warnings.push('No "strings:" block found - rule has no patterns to test.');
  }

  // Surface metadata
  const metaBlock = rule.match(/meta\s*:\s*([\s\S]*?)\s*(strings|condition)\s*:/i);
  if (metaBlock) {
    const lines = metaBlock[1]!.split(/\r?\n/);
    for (const ln of lines) {
      const mm = ln.match(/^\s*(\w+)\s*=\s*"([^"]*)"/);
      if (mm) meta.push({ k: mm[1]!, v: mm[2]! });
    }
  }

  return {
    kind: 'yara',
    name,
    condition: condMatch?.[1]?.trim() ?? '',
    needles,
    meta,
    warnings,
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Sigma parser (very minimal - no full YAML)
// ─────────────────────────────────────────────────────────────────────────

interface SigmaLeaf {
  field?: string;
  modifier?: string;
  values: string[];
}

function dedent(lines: string[]): string[] {
  const indents = lines.filter((l) => l.trim().length > 0).map((l) => l.match(/^\s*/)![0].length);
  const min = indents.length ? Math.min(...indents) : 0;
  return lines.map((l) => l.slice(min));
}

function parseSigmaDetection(detectionBody: string): SigmaLeaf[] {
  const leaves: SigmaLeaf[] = [];
  // Each top-level key (selection, filter, …) maps to a YAML mapping or list.
  const lines = detectionBody.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    const top = line.match(/^\s{2,}(\w+):\s*$/);
    if (!top) {
      i++;
      continue;
    }
    // Collect block
    const blockIndent = (line.match(/^\s+/)?.[0].length ?? 0) + 2;
    const block: string[] = [];
    i++;
    while (i < lines.length && (lines[i]!.length === 0 || (lines[i]!.match(/^\s+/)?.[0].length ?? 0) >= blockIndent)) {
      block.push(lines[i]!);
      i++;
    }
    const dd = dedent(block);
    // Walk lines inside block
    for (let j = 0; j < dd.length; j++) {
      const ln = dd[j]!.trim();
      if (!ln) continue;
      // "field|modifier:" followed by either inline value or list of values
      const fm = ln.match(/^([\w-]+)(?:\|([\w-]+))?\s*:\s*(.*)$/);
      if (!fm) {
        // bare keyword list item (`- "foo"`)
        const kw = ln.match(/^-\s+(.+)$/);
        if (kw) {
          const v = kw[1]!.trim().replace(/^['"]|['"]$/g, '');
          leaves.push({ values: [v] });
        }
        continue;
      }
      const [, field, modifier, rest = ''] = fm;
      if (rest.trim()) {
        // inline single value
        const v = rest.trim().replace(/^['"]|['"]$/g, '');
        leaves.push({ field, modifier, values: [v] });
      } else {
        // collect list / multi-line
        const vals: string[] = [];
        let k = j + 1;
        while (k < dd.length && /^\s*-\s+/.test(dd[k]!)) {
          vals.push(
            dd[k]!.replace(/^\s*-\s+/, '')
              .trim()
              .replace(/^['"]|['"]$/g, '')
          );
          k++;
        }
        if (vals.length) leaves.push({ field, modifier, values: vals });
        j = k - 1;
      }
    }
  }
  return leaves;
}

export function parseSigmaRule(rule: string): ParsedRule {
  const warnings: string[] = [];
  const meta: Array<{ k: string; v: string }> = [];
  const needles: ParsedRule['needles'] = [];

  const titleMatch = rule.match(/^title\s*:\s*(.+)$/m);
  const name = titleMatch?.[1]?.trim() ?? '(untitled)';

  const conditionMatch = rule.match(/^\s*condition\s*:\s*(.+)$/m);
  const condition = conditionMatch?.[1]?.trim() ?? '';

  // Surface logsource as meta
  const logsourceBlock = rule.match(/^logsource:\s*([\s\S]*?)(?=^\w|^$)/m);
  if (logsourceBlock) {
    const lines = logsourceBlock[1]!.split(/\r?\n/);
    for (const ln of lines) {
      const mm = ln.match(/^\s+(\w+)\s*:\s*(.+)$/);
      if (mm) meta.push({ k: `logsource.${mm[1]}`, v: mm[2]!.trim() });
    }
  }

  const tagsLine = rule.match(/^tags\s*:\s*\[?(.+?)\]?$/m);
  if (tagsLine) meta.push({ k: 'tags', v: tagsLine[1]! });

  // Detection block
  const detectionMatch = rule.match(/^detection\s*:\s*$([\s\S]*?)(?=^\S|^$)/m);
  if (!detectionMatch) {
    warnings.push('No `detection:` block found.');
    return { kind: 'sigma', name, condition, needles, meta, warnings };
  }
  const leaves = parseSigmaDetection(detectionMatch[1]!);

  let idx = 0;
  for (const leaf of leaves) {
    for (const v of leaf.values) {
      const tagName = leaf.field
        ? `${leaf.field}${leaf.modifier ? '|' + leaf.modifier : ''}[${idx}]`
        : `keyword[${idx}]`;
      idx++;
      const mod = (leaf.modifier ?? '').toLowerCase();
      let pattern: RegExp;
      try {
        if (mod === 'startswith') {
          pattern = new RegExp(escapeRegex(v), 'i');
        } else if (mod === 'endswith') {
          pattern = new RegExp(escapeRegex(v), 'i');
        } else if (mod === 're') {
          if (isLikelyCatastrophicRegex(v)) {
            warnings.push(`Sigma value ${tagName}: regex skipped - nested unbounded quantifier (ReDoS risk).`);
            continue;
          }
          pattern = new RegExp(v, 'i');
        } else {
          pattern = new RegExp(escapeRegex(v), 'i');
        }
        needles.push({ name: tagName, pattern, kind: 'sigma_keyword' });
      } catch (e) {
        warnings.push(`Sigma value ${tagName}: ${errMessage(e, 'invalid')}`);
      }
    }
  }

  return { kind: 'sigma', name, condition, needles, meta, warnings };
}

export function parseRule(raw: string): ParsedRule {
  const k = detectKind(raw);
  if (k === 'yara') return parseYaraRule(raw);
  if (k === 'sigma') return parseSigmaRule(raw);
  return {
    kind: 'unknown',
    name: '(unknown)',
    condition: '',
    needles: [],
    meta: [],
    warnings: [
      'Could not detect rule format. Paste a YARA rule (starts with `rule X { … }`) or a Sigma rule (YAML with title / detection).',
    ],
  };
}

export interface RuleMatchResult {
  parsed: ParsedRule;
  matches: RuleStringMatch[];
}

export function matchRule(rule: string, sample: string): RuleMatchResult {
  const parsed = parseRule(rule);
  const matches: RuleStringMatch[] = [];
  const MAX_SAMPLE = 64 * 1024;
  if (sample.length > MAX_SAMPLE) {
    parsed.warnings.push(`Sample truncated to ${MAX_SAMPLE} chars for matching.`);
    sample = sample.slice(0, MAX_SAMPLE);
  }
  for (const n of parsed.needles) {
    let m: RegExpExecArray | null;
    const re = new RegExp(n.pattern.source, n.pattern.flags.includes('g') ? n.pattern.flags : n.pattern.flags + 'g');
    while ((m = re.exec(sample)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++; // avoid infinite loop on zero-width
        continue;
      }
      matches.push({ name: n.name, text: m[0], index: m.index, kind: n.kind });
      if (matches.length > 500) break;
    }
  }
  return { parsed, matches };
}
