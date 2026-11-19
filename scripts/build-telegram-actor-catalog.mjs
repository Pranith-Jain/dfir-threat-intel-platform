#!/usr/bin/env node
/**
 * Build the static `threat-actor-telegram-catalog.ts` consumed by the
 * Telegram → Actor correlation helper
 * (`api/src/lib/telegram-actor-correlate.ts`).
 *
 * Reads the in-repo TypeScript catalog and emits a slim TS module that
 * exports a flat array of `{id, name, country, type, telegram_handles,
 * telegram_handles_source}` records. The slim bundle is bundled into the
 * Worker by esbuild — no runtime JSON parsing, no extra subrequest, and
 * the types stay compile-time-checked.
 *
 * Re-run after editing `src/data/threatintel/threat-actor-catalog.ts`.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const SRC = join(ROOT, 'src/data/threatintel/threat-actor-catalog.ts');
const OUT = join(ROOT, 'api/src/lib/_telegram-actor-catalog.generated.ts');

if (!existsSync(SRC)) {
  console.error(`build-telegram-actor-catalog: source not found at ${SRC}`);
  process.exit(1);
}

const src = readFileSync(SRC, 'utf8');
const startToken = 'export const THREAT_ACTORS: ThreatActor[] = [';
const startIdx = src.indexOf(startToken);
if (startIdx < 0) {
  console.error('build-telegram-actor-catalog: THREAT_ACTORS export not found');
  process.exit(1);
}

function findArrayEnd(text, fromIdx) {
  let i = fromIdx;
  const len = text.length;
  let inString = false;
  let stringDelim = '';
  let depth = 1;
  while (i < len) {
    const c = text[i];
    if (inString) {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === stringDelim) inString = false;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      inString = true;
      stringDelim = c;
      i++;
      continue;
    }
    if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

const endIdx = findArrayEnd(src, startIdx + startToken.length);
if (endIdx < 0) {
  console.error('build-telegram-actor-catalog: could not find end of THREAT_ACTORS array');
  process.exit(1);
}

const arrayBody = src.slice(startIdx + startToken.length, endIdx);

function findObjectBoundaries(text) {
  const objects = [];
  let i = 0;
  const len = text.length;
  let inString = false;
  let stringDelim = '';
  let depth = 0;
  let start = -1;
  while (i < len) {
    const c = text[i];
    if (inString) {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === stringDelim) inString = false;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      inString = true;
      stringDelim = c;
      i++;
      continue;
    }
    if (c === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        objects.push(text.slice(start, i + 1));
        start = -1;
      }
    }
    i++;
  }
  return objects;
}

const rawObjects = findObjectBoundaries(arrayBody);

function matchStringField(text, field) {
  let i = 0;
  const len = text.length;
  while (i < len) {
    const idx = text.indexOf(field, i);
    if (idx < 0) return null;
    const prev = idx > 0 ? text[idx - 1] : ' ';
    if (!/[\s,{]/.test(prev)) {
      i = idx + 1;
      continue;
    }
    let j = idx + field.length;
    while (j < len && /\s/.test(text[j])) j++;
    if (text[j] !== ':') {
      i = idx + 1;
      continue;
    }
    j++;
    while (j < len && /\s/.test(text[j])) j++;
    const delim = text[j];
    if (delim !== "'" && delim !== '"' && delim !== '`') {
      i = idx + 1;
      continue;
    }
    j++;
    let buf = '';
    while (j < len) {
      const c = text[j];
      if (c === '\\') {
        buf += text[j + 1];
        j += 2;
        continue;
      }
      if (c === delim) return buf;
      buf += c;
      j++;
    }
    return null;
  }
  return null;
}

function matchStringArrayField(text, field) {
  let i = 0;
  const len = text.length;
  while (i < len) {
    const idx = text.indexOf(field, i);
    if (idx < 0) return null;
    const prev = idx > 0 ? text[idx - 1] : ' ';
    if (!/[\s,{]/.test(prev)) {
      i = idx + 1;
      continue;
    }
    let j = idx + field.length;
    while (j < len && /\s/.test(text[j])) j++;
    if (text[j] !== ':') {
      i = idx + 1;
      continue;
    }
    j++;
    while (j < len && /\s/.test(text[j])) j++;
    if (text[j] !== '[') {
      i = idx + 1;
      continue;
    }
    j++;
    const items = [];
    while (j < len) {
      while (j < len && /[\s,]/.test(text[j])) j++;
      if (text[j] === ']') return items;
      const delim = text[j];
      if (delim !== "'" && delim !== '"' && delim !== '`') {
        j++;
        continue;
      }
      j++;
      let buf = '';
      while (j < len) {
        const c = text[j];
        if (c === '\\') {
          buf += text[j + 1];
          j += 2;
          continue;
        }
        if (c === delim) break;
        buf += c;
        j++;
      }
      items.push(buf);
      j++;
    }
    return items;
  }
  return null;
}

const actors = [];
for (const obj of rawObjects) {
  const id = matchStringField(obj, 'id');
  if (!id) continue;
  const handles = matchStringArrayField(obj, 'telegram_handles');
  const sources = matchStringArrayField(obj, 'telegram_handles_source');
  if (!handles || handles.length === 0) continue;
  actors.push({
    id,
    name: matchStringField(obj, 'name') ?? id,
    country: matchStringField(obj, 'country') ?? '',
    type: matchStringField(obj, 'type') ?? 'unknown',
    telegram_handles: handles,
    telegram_handles_source: sources ?? [],
  });
}

// JSON-quote all strings, then convert to TS object literal syntax:
//   "id": "apt28"  →  id: 'apt28'
// Strings are kept in single quotes to avoid escaping the catalog content
// (em-dashes, emoji, etc.). Values are otherwise JSON-compatible so we
// reuse JSON.stringify as the formatter.
// Format drift must never silently wipe the committed correlation catalog.
if (actors.length === 0) {
  console.error('build-telegram-actor-catalog: parsed 0 actors — refusing to overwrite the generated catalog');
  process.exit(1);
}
const json = JSON.stringify(actors, null, 2);
const tsBody = json
  .replace(/"([a-zA-Z_][a-zA-Z0-9_]*)":/g, '$1:') // unquote object keys
  .replace(/"/g, "'"); // switch string delimiters

const lines = [
  '// ─── AUTO-GENERATED by scripts/build-telegram-actor-catalog.mjs — do not edit. ───',
  '// Re-run after editing src/data/threatintel/threat-actor-catalog.ts.',
  '// Only entries with `telegram_handles: [...]` are included — everything else is',
  '// noise for the correlation helper.',
  '',
  'export interface TelegramActorCatalogEntry {',
  '  id: string;',
  '  name: string;',
  '  country: string;',
  '  type: string;',
  '  telegram_handles: string[];',
  '  telegram_handles_source: string[];',
  '}',
  '',
  'export const TELEGRAM_ACTOR_CATALOG: TelegramActorCatalogEntry[] = ' + tsBody + ';',
  '',
];
writeFileSync(OUT, lines.join('\n'));
console.log(`build-telegram-actor-catalog: wrote ${actors.length} actors with telegram_handles → ${OUT}`);
