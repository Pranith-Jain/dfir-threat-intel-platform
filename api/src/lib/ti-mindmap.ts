/**
 * TI Mindmap port — pure pipeline helpers.
 *
 * Research lineage: format81/TI-Mindmap-GPT (GPLv3) and the public
 * TI Mindmap HUB research documentation (CC BY-NC 4.0,
 * github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-research). This is an
 * independent edge-native reimplementation, NOT upstream code: no source
 * lines were copied. The Mermaid mindmap syntax constraints, tweet-free
 * summary artefact, execution-ordered TTP timeline, and ATT&CK Navigator
 * layer artefact follow the behaviour documented by those projects; the
 * prompt text, validators, and builders here are original.
 *
 * Everything here is pure and synchronous (unit-testable without network):
 *   - buildTweetPrompt / buildMindmapPrompt / buildAssistantPrompt
 *   - sanitizeMermaidMindmap + parseMermaidTree  (LLM output hardening)
 *   - orderTtpsByExecution + buildMermaidTimeline
 *   - buildNavigatorLayer + navigatorFileName
 *   - parseTweetResponse (tolerant JSON, mirrors parseLlmJson discipline)
 *
 * MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
 */

import type { TtpHit } from './ttp-extract';
import { fenceUntrusted } from './prompt-fence';

/** Upper bound on source text sent to the LLM per call. */
export const TIMINDMAP_MAX_SOURCE_CHARS = 50_000;
/** Tweet summary stays inside a two-tweet budget. */
export const TIMINDMAP_MAX_TWEET_CHARS = 280;
/** Hard caps on the generations san Mermaid text. */
export const TIMINDMAP_MAX_NODES = 60;
export const TIMINDMAP_MAX_DEPTH = 4;
export const TIMINDMAP_SOFT_BRANCH_CAP = 4; // upstream methodology: ≤4 themes
export const TIMINDMAP_HARD_BRANCH_CAP = 8;
export const TIMINDMAP_MAX_NODE_LABEL = 60;

export interface MermaidTree {
  label: string;
  depth: number;
  children: MermaidTree[];
}

export interface SanitizedMindmap {
  ok: boolean;
  /** The cleaned Mermaid source (no fences, no preamble, valid labels). */
  text: string;
  tree: MermaidTree | null;
  warnings: string[];
  /** Node count that survived sanitation (0 when not ok). */
  nodes: number;
}

// ── Label cleanup ──────────────────────────────────────────────────────

/**
 * Make one node label safe for Mermaid mindmap syntax:
 * no nested parentheses (the (..) delimiters are shape syntax), no
 * square-bracket or quote delimiters, no closing dots, no markdown
 * emphasis, one whitespace run, bounded length. Runs of "//" collapse.
 */
export function cleanNodeText(raw: string, max = TIMINDMAP_MAX_NODE_LABEL): string {
  let s = raw.trim();
  // Strip one layer of the outer node delimiter some models wrap the
  // text in; keeps repeated sanitation idempotent.
  if (
    (s.startsWith('(') && s.endsWith(')')) ||
    (s.startsWith('[') && s.endsWith(']')) ||
    (s.startsWith('"') && s.endsWith('"'))
  ) {
    s = s.slice(1, -1).trim();
  }
  // Mermaid mindmap treats ( ) [ ] " ** __ as syntax; neutralise them.
  s = s
    .replace(/[()[\]{}]/g, '/')
    .replace(/\/{2,}/g, '/')
    .replace(/\*\*|__|~~|`/g, '')
    .replace(/#/g, '')
    .replace(/;;/g, '')
    .replace(/:/g, ' ')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/"/g, '')
    .trim();
  // Strip a leading list marker some models emit inside the label.
  s = s.replace(/^[*-]\s+/, '');
  // No trailing dots before the closing delimiter (upstream constraint 12).
  s = s.replace(/\.+$/, '');
  // Expressive pictographs are banned upstream; drop non-wordy glyphs.
  s = s.replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{2190}-\u{21FF}]/gu, '');
  // Final trim collapses the leftover leading/trailing space an emoji or
  // dot removal can leave behind.
  s = s.trim();
  if (s.length > max) s = `${s.slice(0, max - 1).trimEnd()}…`;
  return s || 'unnamed node';
}

// ── Sanitizer + tree parser ────────────────────────────────────────────

interface RawLine {
  depth: number; // 0 = root line
  label: string;
}

/** Parse indented mindmap lines into raw depth/label rows. Pure. */
export function parseMermaidTreeLines(text: string): RawLine[] | null {
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\t/g, '  '));
  // Find the `mindmap` header (tolerate a "mermaid" fence-word before it).
  let i = lines.findIndex(
    (l) =>
      l
        .trim()
        .replace(/^mermaid$/i, '')
        .trim() === 'mindmap'
  );
  if (i < 0) return null;
  const body: Array<{ indent: number; text: string }> = [];
  let seen = false; // any map row observed yet
  for (i = i + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();
    if (/^root[(]{1,2}/.test(trimmed)) {
      const inner = trimmed.slice(trimmed.indexOf('(') + 1).replace(/\)+$/, '');
      body.push({ indent: 0, text: inner });
      seen = true;
      continue;
    }
    if (indent === 0) {
      // Flush non-root line: prose inside the map area (leading junk is
      // skipped entirely, post-map prose ends the parse).
      if (seen) break;
      continue;
    }
    seen = true;
    body.push({ indent, text: trimmed });
  }
  // Indent unit = smallest positive indent (mitigates models that indent
  // the first level two or four spaces).
  const indents = body.map((b) => b.indent).filter((n) => n > 0);
  const unit = indents.length ? Math.min(...indents) : 2;
  const rows: RawLine[] = body.map((b) => ({ depth: Math.round(b.indent / unit), label: b.text }));
  return rows.length > 0 ? rows : null;
}

/** Build a nested tree from raw rows, clamping depth jumps. */
export function parseMermaidTree(rows: RawLine[]): MermaidTree | null {
  const rootRow = rows.find((r) => r.depth === 0) ?? { depth: 0, label: 'Threat Report' };
  const root: MermaidTree = { label: rootRow.label, depth: 0, children: [] };
  // Stack of ancestors; stack[0] is always the root, every element's
  // `depth` equals its index (root == 0, primary branch == 1, ...).
  const stack: MermaidTree[] = [root];
  let count = 0;
  for (const row of rows) {
    if (row.depth === 0) {
      // Root already placed; a second root row is treated as a primary
      // child labelled with its text (some models repeat the title).
      if (count === 0) continue;
    }
    count++;
    if (count > TIMINDMAP_MAX_NODES) break;
    const d = Math.max(1, Math.min(row.depth, TIMINDMAP_MAX_DEPTH));
    // Pop until the top is shallower than the requested depth.
    while (stack.length > 1 && stack[stack.length - 1]!.depth >= d) stack.pop();
    const parent = stack[stack.length - 1]!;
    const node: MermaidTree = { label: cleanNodeText(row.label), depth: parent.depth + 1, children: [] };
    parent.children.push(node);
    stack.push(node);
  }
  return count > 0 ? root : null;
}

/**
 * Lead the horse to water: turn raw LLM output into a sanitized
 * `mindmap` block plus a parallel tree the SPA can render natively.
 * Never throws; degrades with warnings.
 */
export function sanitizeMermaidMindmap(raw: string): SanitizedMindmap {
  const warnings: string[] = [];
  let src = (raw ?? '').trim();
  // Strip a ```fence``` wrapper in one shot.
  const fence = src.match(/```(?:mermaid)?\s*([\s\S]*?)```/i);
  if (fence) src = fence[1]!.trim();
  if (!/^mindmap\b/m.test(src)) {
    // Some models prepend a title line; find the header anywhere.
    const head = src.search(/^mindmap\b/m);
    if (head < 0) {
      return { ok: false, text: '', tree: null, warnings: ['no `mindmap` header found'], nodes: 0 };
    }
    warnings.push('preamble stripped before `mindmap` header');
    src = src.slice(head);
  }
  const rows = parseMermaidTreeLines(src);
  if (!rows || rows.length === 0) {
    return { ok: false, text: '', tree: null, warnings: [...warnings, 'no node rows parsed'], nodes: 0 };
  }
  if (!rows.some((r) => r.depth === 0)) {
    warnings.push('no root() row; top node promoted to root');
  }
  const primary = rows.filter((r) => r.depth === 1);
  if (primary.length > TIMINDMAP_SOFT_BRANCH_CAP) {
    warnings.push(
      `${primary.length} primary branches (methodology suggests <=${TIMINDMAP_SOFT_BRANCH_CAP}); kept all up to hard cap ${TIMINDMAP_HARD_BRANCH_CAP}`
    );
  }
  const tree = parseMermaidTree(rows);
  if (tree && tree.children.length > TIMINDMAP_HARD_BRANCH_CAP) {
    const dropped = tree.children.length - TIMINDMAP_HARD_BRANCH_CAP;
    tree.children = tree.children.slice(0, TIMINDMAP_HARD_BRANCH_CAP);
    warnings.push(`dropped ${dropped} primary branches over hard cap ${TIMINDMAP_HARD_BRANCH_CAP}`);
  }
  // Rebuild a deterministic source text from the tree so the text shown
  // to the analyst matches the tree exactly (single source of truth).
  const text = mermaidTreeToText(tree);
  // Count kept nodes.
  let nodes = 0;
  const walk = (n: MermaidTree | null): void => {
    if (!n) return;
    nodes += n.depth === 0 ? 0 : 1;
    for (const c of n.children) walk(c);
  };
  walk(tree);
  return { ok: true, text, tree, warnings, nodes };
}

/** Render a parsed tree back to Mermaid mindmap text (deterministic). */
export function mermaidTreeToText(tree: MermaidTree | null): string {
  if (!tree) return '';
  const out: string[] = ['mindmap', `root(${cleanNodeText(tree.label)})`];
  let total = 0;
  const emit = (node: MermaidTree): void => {
    if (node.depth >= 1) {
      total++;
      if (total > TIMINDMAP_MAX_NODES) return;
      out.push(`${'  '.repeat(node.depth)}(${node.label})`);
    }
    const cap = node.depth === 0 ? TIMINDMAP_HARD_BRANCH_CAP : node.children.length;
    for (const c of node.children.slice(0, cap)) if (total <= TIMINDMAP_MAX_NODES) emit(c);
  };
  for (const child of tree.children) emit(child);
  return out.join('\n');
}

// ── TTP ordering + timeline ────────────────────────────────────────────

/** Execution-order sort: ATT&CK kill-chain order, ties keep input order. */
export function orderTtpsByExecution(ttps: TtpHit[], tacticOrder: string[]): TtpHit[] {
  const idx = new Map(tacticOrder.map((t, i) => [t.toLowerCase(), i] as const));
  return ttps
    .map((hit, i) => ({ hit, i }))
    .sort((a, b) => {
      const ai = idx.get(a.hit.tactic.trim().toLowerCase());
      const bi = idx.get(b.hit.tactic.trim().toLowerCase());
      if (ai !== undefined && bi !== undefined && ai !== bi) return ai - bi;
      if (ai !== undefined && bi === undefined) return -1;
      if (ai === undefined && bi !== undefined) return 1;
      return a.i - b.i;
    })
    .map((x) => x.hit);
}

/** Timeline syntax is line-based and rejects bare `: ; # {}`. */
function cleanTimelineText(s: string): string {
  return s
    .replace(/[:;#{}"']/g, ' ')
    .replace(/[[\]()]/g, '')
    .replace(/[-]{2,}/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
}

/** Deterministic Mermaid `timeline` block, grouped by tactic. */
export function buildMermaidTimeline(ordered: TtpHit[], title = 'TTP Execution Timeline'): string {
  if (ordered.length === 0) return '';
  const byTactic = new Map<string, TtpHit[]>();
  for (const t of ordered) {
    const key = t.tactic.trim() || 'Unknown';
    const list = byTactic.get(key) ?? [];
    list.push(t);
    byTactic.set(key, list);
  }
  const out: string[] = ['timeline', `    title ${cleanTimelineText(title)}`];
  for (const [tactic, hits] of byTactic) {
    out.push(`    section ${cleanTimelineText(tactic)}`);
    for (const hit of hits.slice(0, 5)) {
      const name = cleanTimelineText(hit.name || hit.id);
      out.push(`        ${name} : ${sanitizeTechniqueId(hit.id)}`);
    }
  }
  return out.join('\n');
}

/** ATT&CK technique-id shape check used across this port. */
export function sanitizeTechniqueId(id: string): string {
  const m = /^\s*(T\d{4}(?:\.\d{3})?)\b/i.exec(id ?? '');
  return m ? m[1]!.toUpperCase() : '';
}

// ── ATT&CK Navigator layer ─────────────────────────────────────────────

export interface NavigatorTechnique {
  techniqueID: string;
  score: number;
  comment?: string;
  enabled?: boolean;
}

export interface NavigatorLayer {
  name: string;
  domain: string;
  versions: { attack: string; navigator: string; layer: string };
  description: string;
  filters: { platforms: string[]; disableTech: Record<string, never> };
  sorting: number;
  layout: { layout: string; showID: boolean; showName: boolean };
  hideUnmapped: boolean;
  gradient: { colors: string[]; minValue: number; maxValue: number };
  legendItems: Array<{ label: string; color: string; score: number }>;
  techniques: NavigatorTechnique[];
}

const CONF_SCORE: Record<TtpHit['confidence'], number> = { high: 100, medium: 60, low: 30 };

/**
 * Deterministic ATT&CK Navigator layer from ordered TTP hits.
 * Confidence maps to score so the heatmap reads threat weight.
 */
export function buildNavigatorLayer(args: {
  name: string;
  ttps: TtpHit[];
  description?: string;
  ordered?: boolean;
}): NavigatorLayer {
  const dedup = new Map<string, NavigatorTechnique>();
  for (const hit of args.ttps) {
    const id = sanitizeTechniqueId(hit.id);
    if (!id) continue;
    const score = CONF_SCORE[hit.confidence] ?? 30;
    const prev = dedup.get(id);
    if (!prev || score > prev.score) {
      dedup.set(id, { techniqueID: id, score, comment: hit.evidence.slice(0, 120) });
    }
  }
  return {
    name: args.name.slice(0, 120),
    domain: 'enterprise-attack',
    versions: { attack: '14', navigator: '5.1.0', layer: '4.5' },
    description: (args.description ?? `Navigator layer generated from ${dedup.size} observed techniques`).slice(0, 280),
    filters: { platforms: [], disableTech: {} },
    sorting: 0,
    layout: { layout: 'side', showID: true, showName: true },
    hideUnmapped: false,
    gradient: { colors: ['#ff6666', '#ffe766', '#8ec843'], minValue: 30, maxValue: 100 },
    legendItems: [
      { label: 'High confidence observation', color: '#8ec843', score: 100 },
      { label: 'Medium confidence observation', color: '#ffe766', score: 60 },
      { label: 'Low confidence observation', color: '#ff6666', score: 30 },
    ],
    techniques: Array.from(dedup.values()).sort((a, b) => (a.techniqueID < b.techniqueID ? -1 : 1)),
  };
}

/** Filesystem-safe export name. */
export function navigatorFileName(title: string): string {
  const slug = (title || 'ti-mindmap')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return `${slug || 'ti-mindmap'}.navigator.json`;
}

// ── Prompt builders (original wording implementing the constraints) ────

const MINDMAP_SYNTAX_RULES = `Mermaid mindmap syntax rules (hard requirements):
1. First line is exactly: mindmap
2. Second line is the root: root(Report Title)
3. Keep at most 4 primary branches directly under the root.
4. Nest with two-space indentation; each level is one indent deeper than its parent.
5. Node text inside single parentheses: (some finding text)  -- never nested parentheses, never square brackets, never quotes.
6. No hyphens or dashes inside node text; use slashes or "and" instead.
7. No emoji, no markdown emphasis, no trailing dots.
8. Write indicators bare: mail.example.com, 203.0.113.7, not defanged and not bracketed.
9. Total output is ONLY the mindmap block: no prose, no code fences, no explanations.
10. Keep every node short (<=60 chars). Depth at most 4 levels below the root.`;

const MINDMAP_EXAMPLE = `Typed example of the expected shape (structure only):
mindmap
root((YoroTrooper Espionage))
  (Origin and Attribution)
    (Kazakhstan linked)
    (Disguises origin as Azerbaijan)
  (Targets)
    (CIS government entities)
    (Embassies and NGOs)
  (TTPs)
    (Spear phishing sites)
    (VPN exit via Azerbaijan)
    (Credential harvesting)
  (Malware)
    (Custom Rust loader)
    (PowerShell stager)`;

/**
 * User prompt for the single Mermaid mindmap generation call. The source
 * arrives fenced (the route applies fenceUntrusted); the example keeps a
 * fixed shape, and the analyzer enforces the syntax deterministically.
 */
export function buildMindmapPrompt(args: { text: string; language?: string }): string {
  const lang = args.language?.trim() || 'English';
  return (
    `${MINDMAP_SYNTAX_RULES}\n\n${MINDMAP_EXAMPLE}\n\n` +
    `Task: produce a Mermaid mindmap in ${lang} that organises the threat report below for a threat analyst.\n` +
    `Order primary branches by narrative importance: attribution, targets, tradecraft (TTPs), infrastructure or IOCs, then mitigations when present.\n\n` +
    `${args.text}`
  );
}

/** Tweet-length analyst summary (two-tweet budget, single line). */
export function buildTweetPrompt(args: { text: string; language?: string }): string {
  const lang = args.language?.trim() || 'English';
  return (
    `You are a threat intelligence analyst writing a compact social summary in ${lang}.\n` +
    `Return STRICT JSON and nothing else:\n` +
    `{"tweet_summary": "<=280 chars, single paragraph, ends with the #TIMindmap tag",` +
    ` "actor": "<threat actor or provided attribution or 'unattributed'>",` +
    ` "malware": ["<=8 items, malware families or tools named in the report"],` +
    ` "sectors": ["<=5 victim sectors named in the report"],` +
    ` "headline": "<report headline or best short title>"}` +
    `\nRules: never invent an actor, malware family, or sector that the report does not name. ` +
    `No markdown, no code fences.\n\nREPORT:\n${args.text}`
  );
}

export interface TweetDossier {
  tweet_summary: string;
  actor: string | null;
  malware: string[];
  sectors: string[];
  headline: string | null;
}

const cap = (list: unknown, max: number): string[] =>
  Array.isArray(list)
    ? list
        .filter((x): x is string => typeof x === 'string')
        .map((s) => s.replace(/\s+/g, ' ').trim().slice(0, 80))
        .filter(Boolean)
        .slice(0, max)
    : [];

/**
 * Tolerant parse + per-field validation of the tweet JSON. Any failure
 * degrades to partial content rather than rejecting the whole result.
 */
export function parseTweetResponse(raw: string): TweetDossier {
  let obj: unknown = null;
  const text = (raw ?? '').trim();
  // Prefer a balanced {...} extraction; fall back to fence stripping.
  const start = text.indexOf('{');
  if (start >= 0) {
    let depth = 0;
    let inStr = false;
    let esc = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i]!;
      if (esc) {
        esc = false;
        continue;
      }
      if (inStr && ch === '\\') {
        esc = true;
        continue;
      }
      if (ch === '"') inStr = !inStr;
      if (inStr) continue;
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          try {
            obj = JSON.parse(text.slice(start, i + 1)) as unknown;
          } catch {
            obj = null;
          }
          break;
        }
      }
    }
  }
  const record = (obj && typeof obj === 'object' ? obj : { tweet_summary: text }) as Record<string, unknown>;
  const tweet =
    typeof record.tweet_summary === 'string'
      ? record.tweet_summary
      : typeof record.tweet === 'string'
        ? record.tweet
        : '';
  return {
    tweet_summary: tweet
      .replace(/^["'`]|["'`]$/g, '')
      .replace(/\s*#+\s*$/, '')
      .trim()
      .slice(0, TIMINDMAP_MAX_TWEET_CHARS + 60),
    actor: typeof record.actor === 'string' && record.actor.trim() ? record.actor.trim().slice(0, 80) : null,
    malware: cap(record.malware, 8),
    sectors: cap(record.sectors, 5),
    headline:
      typeof record.headline === 'string' && record.headline.trim() ? record.headline.trim().slice(0, 200) : null,
  };
}

/** Chat-with-report prompt for the assistant endpoint (source arrives fenced). */
export function buildAssistantPrompt(args: { question: string; text: string }): string {
  return (
    `${fenceUntrusted('REPORT', args.text)}\n\nQuestion: ${args.question}\n` +
    'Answer strictly from the report above. If the report does not answer the question, say so plainly.'
  );
}
