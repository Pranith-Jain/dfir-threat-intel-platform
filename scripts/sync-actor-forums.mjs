#!/usr/bin/env node
/**
 * Sync the Actores Maliciosos forum-actor dump.
 *
 * Source: github.com/Ivancastl/actores-maliciosos-search — a MyBB forum
 * database dump (`users_full`, ~324k accounts) published for defensive
 * OSINT: search the accounts of actors on compromised forums.
 *
 * The upstream artifact is stored in Git LFS (149 MB), so it is fetched
 * through the LFS batch API rather than as a raw file. The batch endpoint
 * is public for public repositories and returns a pre-signed URL.
 *
 * ## What is dropped, and why
 *
 * The dump contains credential material for real accounts. This sync copies
 * none of it:
 *
 *   password, salt, loginkey, password_algorithm, password_encryption,
 *   password_downgraded   — credential material. Replicating 324k password
 *                            hashes would turn this repository into a
 *                            credential-stuffing target.
 *
 *   pmfolders, notepad, buddylist, ignorelist, myalerts_disabled_alert_types
 *                           — private per-user state with no analyst value.
 *
 *   pow, ougc_*, classicpostbit, postbitbg, pmprune, showcodebuttons, …
 *                           — presentation state, dropped wholesale.
 *
 * Email addresses are handled separately: they are kept out of the shipped
 * index and stored as a salted SHA-256 lookup table instead, so a search
 * for a known address still works without the plaintext corpus being
 * replicated here. See build-actor-forums.mjs.
 *
 * Run by:
 *   1. GitHub Action (.github/workflows/threat-intel-sync.yml)
 *   2. Manual: `node scripts/sync-actor-forums.mjs`
 *
 * After sync, run `node scripts/build-actor-forums.mjs`.
 */
import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging');
const OUT = join(STAGING, 'actor-forums');
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';

export const ACTOR_FORUMS = {
  source: 'Actores Maliciosos Search',
  sourceUrl: 'https://github.com/Ivancastl/actores-maliciosos-search',
  description:
    'MyBB forum account directory — usernames, activity and registration IPs for actors on compromised forums.',
  license: 'MIT (tool) — underlying forum data is third-party and is used defensively',
  lfsRepo: 'https://github.com/Ivancastl/actores-maliciosos-search.git',
};

/** The LFS object id of `databoose_full.db`, read from the repository's LFS pointer. */
const LFS_OID = '4c67f900cf470ab61222c7a9698878843cab678c1bb553f990c4e401a956cfac';
const LFS_SIZE = 149356544;

const LFS_BATCH_URL = 'https://github.com/Ivancastl/actores-maliciosos-search.git/info/lfs/objects/batch';
const FETCH_TIMEOUT_MS = 300_000;
/** The database is 149 MB; allow a little headroom but not a mirror. */
const MAX_DB_BYTES = 200 * 1024 * 1024;

/**
 * Ask the LFS batch API for a download URL.
 *
 * The API is public for public repositories; no token is needed and none
 * should ever be added to this file.
 */
async function lfsDownloadUrl() {
  const res = await fetch(LFS_BATCH_URL, {
    method: 'POST',
    headers: {
      accept: 'application/vnd.git-lfs+json',
      'content-type': 'application/vnd.git-lfs+json',
      'user-agent': UA,
    },
    body: JSON.stringify({
      operation: 'download',
      transfers: ['basic'],
      objects: [{ oid: LFS_OID, size: LFS_SIZE }],
    }),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`LFS batch API HTTP ${res.status}`);
  const json = await res.json();
  const obj = json?.objects?.[0];
  if (!obj?.actions?.download?.href) {
    const msg = obj?.error?.message ?? 'no download action returned';
    throw new Error(`LFS batch API: ${msg}`);
  }
  return obj.actions.download.href;
}

async function main() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
  console.log('• Actores Maliciosos — forum actor dump');

  const dbPath = join(OUT, 'databoose_full.db');

  try {
    const href = await lfsDownloadUrl();
    console.log('  · downloading (149 MB)…');
    const res = await fetch(href, {
      headers: { 'user-agent': UA },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`LFS download HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_DB_BYTES) {
      throw new Error(`${buf.length} bytes exceeds the ${MAX_DB_BYTES} byte cap`);
    }
    writeFileSync(dbPath, buf);
    console.log(`  ✓ ${(buf.length / 1024 / 1024).toFixed(1)} MB`);
  } catch (err) {
    console.error(`  ✗ download failed: ${err.message ?? err}`);
    process.exitCode = 1;
  }

  if (existsSync(dbPath)) {
    console.log(`  ✓ staged at ${dbPath} (${(statSync(dbPath).size / 1024 / 1024).toFixed(1)} MB)`);
  }

  writeFileSync(
    join(OUT, 'source.json'),
    JSON.stringify(
      { ...ACTOR_FORUMS, synced_at: new Date().toISOString(), lfs_oid: LFS_OID },
      null,
      2
    )
  );
  console.log(`  → ${OUT}\n`);
}

main().catch((err) => {
  console.error(`  ✗ ${err.message ?? err}`);
  process.exit(1);
});
