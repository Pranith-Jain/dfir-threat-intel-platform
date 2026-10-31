#!/usr/bin/env node
/**
 * Build the Incident Desk manifest under
 * public/data/threat-intel/incident-desk/.
 *
 * Reads staging in ./threat-intel-staging/incident-desk/ (created by
 * `node scripts/sync-incident-desk.mjs`) and emits a single index.json —
 * the whole feed is ~17 briefs of a few hundred bytes each, so a shard/
 * batch split would add a fetch per brief for no asset-size benefit.
 *
 * The manifest is read at runtime by worker/lib/threat-intel-manifest.ts
 * through env.ASSETS — no D1, no KV, no public fetch.
 *
 * Source: iamnicholasmartin.co.uk/incidents (public RSS 2.0; briefs link
 * back to the canonical post).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'incident-desk');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'incident-desk');

function ensureOut() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
}

function main() {
  const stagedPath = join(STAGING, 'posts.json');
  if (!existsSync(stagedPath)) {
    console.error(`  ✘ staging missing: ${stagedPath} — run scripts/sync-incident-desk.mjs first`);
    process.exit(1);
  }
  const staged = JSON.parse(readFileSync(stagedPath, 'utf8'));
  const items = Array.isArray(staged.items) ? staged.items : [];
  if (items.length === 0) {
    console.error('  ✘ staging holds zero briefs — refusing to wipe the built manifest');
    process.exit(1);
  }

  // Months covered is the only derived stat worth shipping — the page shows
  // the publishing cadence at a glance.
  const byMonth = {};
  for (const it of items) {
    const m = typeof it.published === 'string' ? it.published.slice(0, 7) : null;
    if (m) byMonth[m] = (byMonth[m] ?? 0) + 1;
  }

  // The index IS the bodies at this scale: every field the page needs ships
  // inline (title/link/dates/summary/image). No per-post fetches.
  const index = {
    source: staged.source ?? 'iamnicholasmartin.co.uk/incidents',
    sourceUrl: staged.sourceUrl ?? 'https://iamnicholasmartin.co.uk/incidents',
    description: staged.description,
    license: staged.license ?? 'Copyright the author; briefs link back to the source',
    syncedAt: staged.syncedAt ?? new Date().toISOString(),
    meta: {
      feedUrl: staged.feedUrl ?? 'https://iamnicholasmartin.co.uk/incidents/feed.xml',
      feedTitle: staged.feedTitle ?? null,
    },
    counts: {
      briefs: items.length,
      withImage: items.filter((i) => i.imageUrl).length,
      byMonth,
    },
    briefs: items,
  };

  ensureOut();
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));
  const idxBytes = Buffer.byteLength(JSON.stringify(index), 'utf8');
  const months = Object.keys(byMonth).length;
  console.log(`  ✔ built incident-desk manifest: ${items.length} briefs, ${months} months, INDEX ${(idxBytes / 1e3).toFixed(0)} KB`);
}

main();
