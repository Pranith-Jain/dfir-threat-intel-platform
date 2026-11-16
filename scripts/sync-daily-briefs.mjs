#!/usr/bin/env node
/**
 * Sync Daily Briefs from agentic-ai-daily-reports.netlify.app.
 *
 * Fetches HTML from four endpoints into daily-briefs-staging/:
 *   - /cyber     → OT/ICS Cyber Threat Intelligence
 *   - /deepfake  → DeepFake and Generative AI Intelligence
 *   - /disaster  → Global Disaster Intelligence
 *   - /maritime  → Maritime Cyber Threat Intelligence
 *   - /water     → Minnesota Water System Attack assessment
 *   - /french    → Refrigeration Systems Attacks assessment
 *
 * After sync, run `node scripts/build-daily-briefs.mjs` to parse
 * the HTML into structured JSON under public/data/daily-briefs/.
 */
import { existsSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'daily-briefs-staging');

const BRIEF_TYPES = ['cyber', 'deepfake', 'disaster', 'maritime', 'water', 'french'];
const BASE_URL = 'https://agentic-ai-daily-reports.netlify.app';

function ensureStaging() {
  if (existsSync(STAGING)) rmSync(STAGING, { recursive: true });
  mkdirSync(STAGING, { recursive: true });
}

async function fetchBrief(type) {
  const url = `${BASE_URL}/${type}`;
  console.log(`  → ${url}`);
  const res = await fetch(url, {
    headers: { 'user-agent': 'pranithjain-daily-briefs-sync/1.0 (+https://pranithjain.qzz.io)' },
  });
  if (!res.ok) throw new Error(`fetch failed: ${url} → ${res.status} ${res.statusText}`);
  const html = await res.text();
  const dest = join(STAGING, `${type}.html`);
  writeFileSync(dest, html);
  console.log(`    wrote ${html.length} bytes to ${dest}`);
}

async function main() {
  console.log('Daily Briefs sync — staging into', STAGING);
  ensureStaging();

  for (const type of BRIEF_TYPES) {
    try {
      await fetchBrief(type);
    } catch (err) {
      console.error(`  ⚠ Failed to fetch ${type}: ${err instanceof Error ? err.message : err}`);
    }
  }

  console.log('\n✔ Staged. Next: node scripts/build-daily-briefs.mjs');
}

main().catch((err) => {
  console.error('✘ sync failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
