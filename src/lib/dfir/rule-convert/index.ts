/**
 * Rule converter - heuristic, any-to-any detection translation.
 *
 *     source text ──parse──▶ RuleIR ──emit──▶ target text
 *
 * This barrel exposes the public surface: `convertRule` and every type / table
 * a UI needs (RuleFormat list, FORMAT_LABELS, ConvertResult). Each side of the
 * pipeline lives in a focused module:
 *
 *   types.ts     - IR + format tables + small shared helpers
 *   parsers.ts   - text → IR (Sigma faithful; rest regex-heuristic)
 *   emitters.ts  - IR → text (Sigma/KQL/SPL/Lucene/EQL/YARA/DLP/supply-chain)
 *
 * Pure module - no DOM / no network - so it stays unit-testable in isolation.
 */

import { FORMAT_LABELS, uniq, type ConvertResult, type RuleFormat, type RuleIR } from './types';
import { errMessage } from '../../log';
import {
  parseDlp,
  parseEql,
  parseKql,
  parseLucene,
  parseSigma,
  parseSplunk,
  parseSupplychain,
  parseYara,
} from './parsers';
import {
  emitDlp,
  emitEql,
  emitKql,
  emitLucene,
  emitPowerShell,
  emitSigma,
  emitSnort,
  emitSplunk,
  emitSupplyChain,
  emitYara,
} from './emitters';

export {
  FORMAT_LABELS,
  SOURCE_FORMATS,
  TARGET_FORMATS,
  type ConvertResult,
  type Predicate,
  type RuleFormat,
  type RuleIR,
  type SelectionGroup,
  type MatchOp,
} from './types';
export { FIELD_MAPS, findFieldMap, type FieldMap } from './field-maps';

/**
 * Options for `convertRule`. `fieldMap` rewrites IR predicate field names
 * after parse, before emit - every source field is looked up in the map;
 * unmapped fields pass through unchanged and are surfaced as a warning so
 * the analyst knows what the chosen preset didn't cover.
 */
export interface ConvertOptions {
  fieldMap?: Record<string, string>;
  /** Used only for warning text - the human label of the preset. */
  fieldMapLabel?: string;
}

/**
 * Apply a field map to every predicate in the IR. Returns the set of
 * field names the map didn't cover (for a warning) and the rewritten IR.
 * Pure - does not mutate the input.
 */
function applyFieldMap(ir: RuleIR, map: Record<string, string>): { ir: RuleIR; unmapped: string[]; mapped: string[] } {
  const unmapped = new Set<string>();
  const mapped = new Set<string>();
  const rewritten: RuleIR = {
    ...ir,
    groups: ir.groups.map((g) => ({
      ...g,
      predicates: g.predicates?.map((p) => {
        const replacement = map[p.field];
        if (replacement) {
          mapped.add(p.field);
          return { ...p, field: replacement };
        }
        if (g.kind === 'fields') unmapped.add(p.field);
        return p;
      }),
    })),
  };
  return { ir: rewritten, unmapped: [...unmapped], mapped: [...mapped] };
}

const PARSERS: Record<RuleFormat, (s: string) => RuleIR | { error: string }> = {
  sigma: parseSigma,
  kql: parseKql,
  splunk: parseSplunk,
  lucene: parseLucene,
  eql: parseEql,
  yara: parseYara,
  dlp: parseDlp,
  supplychain: parseSupplychain,
  // No native parser for Snort/PowerShell yet - they're target-only. The
  // FE prevents picking either as a source; if a caller bypasses that we
  // return an explicit error rather than misclassify the input.
  snort: () => ({ error: 'Snort/Suricata is target-only - pick a different source format.' }),
  powershell: () => ({ error: 'PowerShell is target-only - pick a different source format.' }),
};

export function convertRule(
  src: string,
  from: RuleFormat,
  to: RuleFormat,
  options: ConvertOptions = {}
): ConvertResult {
  if (!src.trim()) return { ok: false, error: 'empty input' };

  const parsed = PARSERS[from](src);
  if ('error' in parsed) return { ok: false, error: parsed.error };

  const warnings = [...parsed.warnings];
  if (from !== 'sigma') warnings.unshift(`${FORMAT_LABELS[from]} → IR is heuristic; verify the result.`);
  if (from === to) warnings.push('Source and target are the same format - output is a normalised round-trip.');

  // Apply field-map remap, if any. Surfaces what was rewritten and what
  // the chosen preset doesn't cover so the analyst can spot fields the
  // emitter is passing through unchanged.
  let ir: RuleIR = parsed;
  if (options.fieldMap && Object.keys(options.fieldMap).length > 0) {
    const remap = applyFieldMap(parsed, options.fieldMap);
    ir = remap.ir;
    if (remap.mapped.length > 0) {
      warnings.push(
        `Field map (${options.fieldMapLabel ?? 'custom'}) rewrote ${remap.mapped.length} field(s): ${remap.mapped.join(', ')}.`
      );
    }
    if (remap.unmapped.length > 0) {
      warnings.push(
        `Field map has no entry for ${remap.unmapped.length} field(s) - emitted as-is: ${remap.unmapped.join(', ')}.`
      );
    }
  }

  try {
    let output: string;
    switch (to) {
      case 'sigma':
        output = emitSigma(ir);
        break;
      case 'kql':
        output = emitKql(ir);
        break;
      case 'splunk':
        output = emitSplunk(ir);
        break;
      case 'lucene':
        output = emitLucene(ir);
        break;
      case 'eql':
        output = emitEql(ir);
        warnings.push('EQL output omits sequence/time logic; it is a single-event `… where` expression.');
        break;
      case 'yara':
        output = emitYara(ir, warnings);
        break;
      case 'dlp':
        output = emitDlp(ir, warnings);
        break;
      case 'supplychain':
        output = emitSupplyChain(ir, warnings);
        break;
      case 'snort':
        output = emitSnort(ir, warnings);
        break;
      case 'powershell':
        output = emitPowerShell(ir, warnings);
        break;
      default:
        return { ok: false, error: `unknown target format` };
    }
    return { ok: true, output, warnings: uniq(warnings) };
  } catch (e) {
    return { ok: false, error: `conversion failed: ${errMessage(e)}` };
  }
}

/**
 * Parse-only entry point - returns the IR (or an error) without emitting.
 * Powers the lab's "what the parser saw" inspector panel so the analyst
 * can debug a failing conversion by reading the structured intermediate.
 */
export function parseToIr(src: string, from: RuleFormat): RuleIR | { error: string } {
  if (!src.trim()) return { error: 'empty input' };
  return PARSERS[from](src);
}

/**
 * Multi-rule conversion. Today only Sigma supports a clean multi-doc
 * split (YAML `---` separators), so this is restricted to from='sigma'.
 * Empty docs and pure-comment docs are skipped so a trailing `---\n`
 * doesn't produce a phantom error row.
 *
 * Returns one BatchEntry per input doc, in input order. Successful
 * entries carry the emitted target text; failures carry the parser
 * error string. Callers that want a "stop on first error" behaviour
 * can early-return when `.ok === false`.
 */
export interface BatchEntry {
  index: number;
  title?: string;
  ok: boolean;
  output?: string;
  error?: string;
  warnings: string[];
}

export function convertBatch(
  src: string,
  from: RuleFormat,
  to: RuleFormat,
  options: ConvertOptions = {}
): BatchEntry[] {
  if (from !== 'sigma') {
    return [
      {
        index: 0,
        ok: false,
        error: 'Batch mode is currently Sigma-only (multi-doc YAML with `---` separators).',
        warnings: [],
      },
    ];
  }
  // Split on a line that's exactly `---` (optional trailing whitespace).
  // YAML's stream-of-documents convention; matches what SigmaHQ uses.
  const docs = src
    .split(/^\s*---\s*$/m)
    .map((d) => d.trim())
    .filter((d) => d.length > 0 && !/^#/.test(d.split('\n')[0] ?? ''));
  return docs.map((doc, i) => {
    const r = convertRule(doc, from, to, options);
    const title = /^title:\s*(.+)$/m.exec(doc)?.[1]?.trim();
    if (r.ok) return { index: i, title, ok: true, output: r.output, warnings: r.warnings };
    return { index: i, title, ok: false, error: r.error, warnings: [] };
  });
}
