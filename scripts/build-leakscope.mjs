#!/usr/bin/env node
/**
 * Build the LeakScope manifest under public/data/threat-intel/leakscope/.
 *
 * Reads staging in ./threat-intel-staging/leakscope/ (created by
 * `node scripts/sync-leakscope.mjs`) and emits:
 *   index.json    — the slim entry list the page searches and sorts over
 *
 * The index carries every field the table renders, so the page needs one
 * fetch and can search locally — no round trip per keystroke across 12k
 * rows. A per-entry body file would double the artifact count for data the
 * table already shows.
 *
 * The manifest is read at runtime by worker/lib/threat-intel-manifest.ts
 * through env.ASSETS — no D1, no KV, no public fetch.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'leakscope');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'leakscope');

function readStaging(file) {
  const p = join(STAGING, file);
  if (!existsSync(p)) {
    console.error(`  ⚠ no staging file at ${p} — run \`node scripts/sync-leakscope.mjs\` first`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(p, 'utf8'));
}

/**
 * Order entries newest-first.
 *
 * Threads with no parseable publish date sink to the bottom rather than
 * scrambling the page — an undated thread is not "today's thread", and
 * letting it sort as if it were would misrepresent the leak's recency.
 */
function byRecency(a, b) {
  const at = a.published_at ?? '';
  const bt = b.published_at ?? '';
  if (!at && !bt) return (b.views ?? 0) - (a.views ?? 0);
  if (!at) return 1;
  if (!bt) return -1;
  return bt.localeCompare(at);
}

function main() {
  if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  const source = readStaging('source.json');
  const darkforum = readStaging('databases_progreso.csv').entries;
  const breach = readStaging('db_leaks_progreso.csv').entries;

  const entries = [...breach, ...darkforum].sort(byRecency);

  const authors = new Set(entries.map((e) => e.author).filter(Boolean));
  const prefixes = new Set(entries.map((e) => e.prefix).filter(Boolean));

  const index = {
    schemaVersion: 'leakscope-v1',
    source: source.source,
    sourceUrl: source.sourceUrl,
    description: source.description,
    license: source.license,
    syncedAt: source.synced_at,
    counts: {
      total: entries.length,
      breach: breach.length,
      darkforum: darkforum.length,
      authors: authors.size,
      prefixes: prefixes.size,
      with_ransomware_note: entries.filter((e) => /ransom|extort/i.test(`${e.title ?? ''} ${e.prefix ?? ''}`))
        .length,
    },
    entries,
  };

  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  console.log(`  ✓ ${entries.length} entries (${breach.length} breach, ${darkforum.length} dark forum)`);
  console.log(`  ✓ ${authors.size} authors, ${prefixes.size} prefixes`);
  console.log(`  → ${OUT}\n`);
}

main();
