#!/usr/bin/env node
/**
 * Upload the build-time page OG PNGs (.og-cache/pages/*.png, from
 * scripts/generate-page-og.mjs) into the KV_CACHE namespace under
 * `ogpage:v1:<dot-id>.png`.
 *
 * The runtime handler (worker/og-route.ts) reads these keys FIRST — serving
 * a card costs one KV read instead of an in-Worker resvg rasterization,
 * which is what kept tripping X's crawler (10ms-CPU cold rasterizations +
 * per-colo cache misses → failed image fetch → X caches the failure for
 * days and renders the image-less fallback chip).
 *
 * Runs as part of `npm run deploy` (after build, before wrangler deploy)
 * so every deployment has its full set of cards in KV before going live.
 *
 * QUOTA: the free plan allows only 1,000 KV writes/day — a full 269-card
 * upload eats a quarter of that, and multiple deploys per day would exhaust
 * it (observed live: error 10048 "reached the free usage limit"). So this
 * script keeps an md5 manifest (.og-cache/uploaded.json) of what it last
 * uploaded SUCCESSFULLY and skips byte-identical files. Cards change rarely
 * (only when route copy changes), so steady-state deploys cost ~0 writes.
 * Pass --force to ignore the manifest and re-upload everything.
 *
 * Requires wrangler auth (CLOUDFLARE_API_TOKEN or OAuth login).
 */
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(root, '.og-cache', 'pages');
const MANIFEST = join(root, '.og-cache', 'uploaded.json');
const CONCURRENCY = 6;
const FORCE = process.argv.includes('--force');
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const UPSTASH_TTL = 30 * 24 * 3600;
if (UPSTASH_URL && UPSTASH_TOKEN) console.log('  external cache: Upstash REST (KV fallback only)');

let files;
try {
  files = readdirSync(DIR).filter((f) => f.endsWith('.png'));
} catch {
  console.log('  no .og-cache/pages — run scripts/generate-page-og.mjs first');
  process.exit(0);
}
if (files.length === 0) {
  console.log('  no page OG cards to upload');
  process.exit(0);
}

// md5 of what each local card's bytes were when they were last uploaded OK.
// A missing/failed upload never enters the manifest, so failures self-heal on
// the next run. --force bypasses the skip entirely.
let uploaded = {};
try {
  uploaded = JSON.parse(readFileSync(MANIFEST, 'utf8'));
} catch {
  /* first run or corrupted manifest → treat as empty */
}

const md5 = (p) => createHash('md5').update(readFileSync(p)).digest('hex');

const pending = [];
let skipped = 0;
for (const f of files) {
  if (!FORCE && uploaded[f] && uploaded[f] === md5(join(DIR, f))) {
    skipped += 1;
    continue;
  }
  pending.push(f);
}
console.log(
  `Uploading page OG cards to KV_CACHE… ${pending.length} to write` +
    (skipped ? ` (${skipped} unchanged, skipped)` : '') +
    (FORCE ? ' [--force]' : '')
);
if (pending.length === 0) process.exit(0);

let done = 0;
let failed = 0;
const failures = [];

async function upload(file) {
  const key = `ogpage:v1:${file}`;
  const path = join(DIR, file);
  try {
    if (UPSTASH_URL && UPSTASH_TOKEN) {
      const res = await fetch(UPSTASH_URL, {
        method: 'POST',
        headers: { authorization: `Bearer ${UPSTASH_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify(['SET', key, readFileSync(path).toString('base64'), 'EX', UPSTASH_TTL]),
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`Upstash ${res.status}`);
      const body = await res.json();
      if (body.error) throw new Error(body.error);
    } else {
      execSync(`npx wrangler kv key put ${JSON.stringify(key)} --path ${JSON.stringify(path)} --binding KV_CACHE --remote`, {
        cwd: root,
        stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 60_000,
      });
    }
    // Record ONLY after success so quota-exhausted runs retry next time.
    uploaded[file] = md5(path);
    done += 1;
    if (done % 25 === 0) console.log(`  ${done}/${pending.length}`);
  } catch (e) {
    failed += 1;
    failures.push(file);
    console.warn(`  ✗ ${file}: ${e.message?.split('\n')[0] ?? e}`);
  }
}

// Simple concurrency pool.
let idx = 0;
async function worker() {
  while (idx < pending.length) {
    const f = pending[idx++];
    await upload(f);
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

if (done > 0) {
  try {
    writeFileSync(MANIFEST, JSON.stringify(uploaded, null, 2));
  } catch (e) {
    console.warn(`  ⚠ could not write manifest: ${e.message}`);
  }
}

console.log(`Uploaded ${done}/${pending.length} (${failed} failed; ${skipped} skipped as unchanged)`);
if (failed > 0) {
  console.warn(`  ${failed} uploads failed — deploy will continue; missing cards fall back to dynamic rasterization`);
  if (/free usage limit/i.test(failures.join(' ') + '')) {
    console.warn('  ⚠ KV daily WRITE quota hit (resets 00:00 UTC). Re-run `node scripts/upload-page-og.mjs` after reset.');
  }
}
if (failures.length > 0) console.warn(`  failed files: ${failures.slice(0, 5).join(', ')}${failures.length > 5 ? '…' : ''}`);
