#!/usr/bin/env node
/**
 * Sync AI Threat Actors tracker data from Cybershujin into staging.
 *
 * Sources:
 *   - tracker.json  — 158 entries, structured JSON with TTP mappings
 *   - STIX 2.1 bundle — available at ./stix/threat-actors-ai-stix2.1.json
 *
 * Run:
 *   node scripts/sync-ai-threats.mjs
 *
 * Then:
 *   node scripts/build-ai-threats.mjs
 */
import { existsSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'ai-threats-staging');

const TRACKER_URL = 'https://cybershujin.github.io/Threat-Actors-use-of-Artifical-Intelligence/tracker.json';
const STIX_URL = 'https://cybershujin.github.io/Threat-Actors-use-of-Artifical-Intelligence/stix/threat-actors-ai-stix2.1.json';

function ensureStaging() {
  if (existsSync(STAGING)) rmSync(STAGING, { recursive: true });
  mkdirSync(STAGING, { recursive: true });
}

async function fetchJson(url, dest) {
  console.log(`  → ${url}`);
  const res = await fetch(url, {
    headers: { 'user-agent': 'pranithjain-ai-threats-sync/1.0 (+https://pranithjain.qzz.io)' },
  });
  if (!res.ok) throw new Error(`fetch failed: ${url} → ${res.status} ${res.statusText}`);
  const text = await res.text();
  writeFileSync(dest, text);
  console.log(`    wrote ${text.length} bytes to ${dest}`);
  return JSON.parse(text);
}

async function main() {
  console.log('AI Threat Actors sync — staging into', STAGING);
  ensureStaging();
  await fetchJson(TRACKER_URL, join(STAGING, 'tracker.json'));
  try {
    await fetchJson(STIX_URL, join(STAGING, 'stix.json'));
  } catch {
    console.warn('  ⚠ STIX bundle unavailable — continuing without it');
  }
  console.log('\n✔ Staged. Next: node scripts/build-ai-threats.mjs');
}

main().catch((err) => {
  console.error('✘ sync failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
