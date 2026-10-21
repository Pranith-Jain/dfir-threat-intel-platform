#!/usr/bin/env node
/**
 * Build the Actores Maliciosos actor manifest under
 * public/data/threat-intel/actor-forums/.
 *
 * Reads staging in ./threat-intel-staging/actor-forums/ (created by
 * `node scripts/sync-actor-forums.mjs`) and emits:
 *   index.json              — counts, shard list, and the email-lookup salt
 *   actors/<shard>.json     — actors, sharded by the first character
 *   emails/<shard>.json     — salted email-hash → uid, sharded by hash prefix
 *
 * ## Why sharded
 *
 * The dump holds 324k accounts. A single index would be a ~60 MB JSON file
 * that no Worker could hold in memory (the runtime cap is 128 MB) and no
 * browser should download. Sharding by the first character of the username
 * means a prefix lookup — the actual query pattern, "I have this handle" —
 * loads exactly one shard.
 *
 * ## Why emails are hashed
 *
 * Email addresses are personal data. The upstream tool searches by them, so
 * the capability is kept, but the plaintext corpus is not replicated here:
 * the manifest carries a salted SHA-256 of each address, and a search hashes
 * the query the same way. The salt is public, so this is not a defence
 * against someone determined — it is a decision not to make this repository
 * the place where 324k addresses sit in the clear.
 *
 * ## What never leaves the staging directory
 *
 * Password hashes, salts, loginkeys and the private per-user blobs
 * (pmfolders, notepad, buddylist, ignorelist). They are not selected, not
 * written, and not present in any emitted artifact.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'actor-forums');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'actor-forums');

/**
 * Columns that must never be copied out of the staging database.
 *
 * `password`, `salt` and `loginkey` are credential material for real
 * accounts. The rest are private per-user state or forum presentation
 * settings with no analyst value.
 */
const FORBIDDEN_COLUMNS = new Set([
  'password',
  'salt',
  'loginkey',
  'password_algorithm',
  'password_encryption',
  'password_downgraded',
  'pmfolders',
  'notepad',
  'buddylist',
  'ignorelist',
  'myalerts_disabled_alert_types',
  'pow',
  'ougc_awards',
  'ougc_awards_owner',
  'ougc_awards_preset',
  'classicpostbit',
  'postbitbg',
  'pmprune',
  'showcodebuttons',
  'myalerts_disabled',
  'has_my2fa',
  'loginlockoutexpiry',
  'loginattempts',
  'awaydate',
  'returndate',
  'awayreason',
  'away',
  'sourceeditor',
  'socialsites',
]);

/** The columns that are actually carried into the manifest. */
const KEPT_COLUMNS = [
  'uid',
  'username',
  'email',
  'usergroup',
  'additionalgroups',
  'displaygroup',
  'usertitle',
  'postnum',
  'threadnum',
  'reputation',
  'regdate',
  'lastactive',
  'lastvisit',
  'lastpost',
  'website',
  'skype',
  'google',
  'birthday',
  'regip',
  'lastip',
  'timezone',
  'language',
  'warningpoints',
  'timeonline',
  'referrals',
];

/**
 * The salt for the email-hash lookup table.
 *
 * Regenerated on every build. It is not a secret — it is published in the
 * manifest — it is only there to stop the hashes from being trivially
 * reversible with a precomputed table of every possible address.
 */
const EMAIL_SALT = createHash('sha256')
  .update(`${Date.now()}:${process.pid}:actor-forums`)
  .digest('hex')
  .slice(0, 32);

/** The shard a username belongs to. */
export function usernameShard(username) {
  const first = (username ?? '').trim().toLowerCase().charAt(0);
  if (first >= 'a' && first <= 'z') return first;
  if (first >= '0' && first <= '9') return first;
  return '_';
}

/** The shard an email-hash belongs to — the first two hex characters. */
export function emailShard(hash) {
  return hash.slice(0, 2);
}

/**
 * Salted SHA-256 of a lowercased email address, truncated to 128 bits.
 *
 * 128 bits is far more than enough to make a collision across 324k entries
 * impossible in practice, and it halves the size of the lookup table
 * (24 MB → 13 MB) against the full 256-bit hash.
 */
export function hashEmail(email, salt = EMAIL_SALT) {
  return createHash('sha256')
    .update(`${salt}:${email.trim().toLowerCase()}`)
    .digest('hex')
    .slice(0, 32);
}

/**
 * Convert a MyBB-stored IP to dotted-decimal.
 *
 * MyBB stores registration and last-seen addresses either as a hex string
 * (`0x7f000001`) or as a plain integer. The upstream tool converts both;
 * so does this, because the point of the field is to pivot an address into
 * another tool.
 */
export function formatIp(value) {
  if (!value || value === '0') return null;
  const s = String(value).trim();
  if (!/^0x[0-9a-f]+$/i.test(s) && !/^\d+$/.test(s)) return s;
  let n;
  if (s.toLowerCase().startsWith('0x')) n = Number.parseInt(s.slice(2), 16);
  else n = Number.parseInt(s, 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  return [24, 16, 8, 0].map((shift) => (n >>> shift) & 0xff).join('.');
}

/** A Unix timestamp as an ISO string, or null. */
export function formatTimestamp(value) {
  const n = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n * 1000).toISOString();
}

/* ─── Row validation ──────────────────────────────────────────────────────── */

/**
 * Validate that a row's values actually correspond to its columns.
 *
 * The upstream dump merges rows from several forum schemas, and a small
 * number of them (131 of 323,986 at the time of writing) were written with
 * a different column order than the table declares. In those rows the
 * `email` column holds a password salt, `postnum` holds a password hash and
 * `regip` holds a signature — which would put the string "hydrocodone" into
 * an IP field and send an analyst pivoting on garbage.
 *
 * A row that fails any of these checks is dropped, and the count is
 * reported in the manifest. A misaligned row is worse than a missing one:
 * a missing actor is an absence, a misaligned actor is a false lead.
 */
export function validateRow(row) {
  const s = (v) => String(v ?? '').trim();
  const isIntegerish = (v) => {
    const x = s(v);
    return x === '' || x === '0' || /^-?\d+$/.test(x);
  };
  const isTimestampish = (v) => {
    const x = s(v);
    return x === '' || x === '0' || /^\d+$/.test(x);
  };
  const isIpish = (v) => {
    const x = s(v);
    return (
      x === '' ||
      x === '0' ||
      /^0x[0-9a-f]+$/i.test(x) ||
      /^\d+$/.test(x) ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(x)
    );
  };
  const isEmailish = (v) => {
    const x = s(v);
    return x === '' || x === '0' || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x);
  };

  if (!/^\d+$/.test(s(row.uid))) return false;
  if (!s(row.username)) return false;
  if (!isIntegerish(row.postnum)) return false;
  if (!isIntegerish(row.threadnum)) return false;
  if (!isIntegerish(row.reputation)) return false;
  if (!isTimestampish(row.regdate)) return false;
  if (!isTimestampish(row.lastactive)) return false;
  if (!isTimestampish(row.lastvisit)) return false;
  if (!isTimestampish(row.lastpost)) return false;
  if (!isIpish(row.regip)) return false;
  if (!isIpish(row.lastip)) return false;
  if (!isEmailish(row.email)) return false;
  return true;
}

/**
 * Open the staged SQLite database.
 *
 * `node:sqlite` is unflagged from Node 22.13 and 23.4 onwards; on older
 * Node 22 it needs `--experimental-sqlite`. Rather than pinning a Node
 * version in CI, the script re-executes itself with the flag when the
 * module cannot be imported — so it runs on any Node the workflow happens
 * to be using.
 */
function openDatabase(dbPath) {
  const require = createRequire(import.meta.url);
  let sqlite;
  try {
    sqlite = require('node:sqlite');
  } catch (err) {
    // `node:sqlite` exists but is flagged on this runtime.
    if (!process.env.__OSINTELERATORUM_REEXEC && String(err?.message ?? '').includes('SQLite')) {
      const { spawnSync } = require('node:child_process');
      const result = spawnSync(
        process.execPath,
        ['--experimental-sqlite', ...process.execArgv, ...process.argv.slice(1)],
        { stdio: 'inherit', env: { ...process.env, __OSINTELERATORUM_REEXEC: '1' } }
      );
      process.exit(result.status ?? 1);
    }
    throw new Error(
      `node:sqlite is unavailable (${err.message}). Node 22.13+ and 24+ expose it without a flag; ` +
        'on older Node run this script with --experimental-sqlite.'
    );
  }
  return new sqlite.DatabaseSync(dbPath, { readOnly: true });
}

function readStaging(file) {
  const p = join(STAGING, file);
  if (!existsSync(p)) {
    console.error(`  ⚠ no staging file at ${p} — run \`node scripts/sync-actor-forums.mjs\` first`);
    process.exit(1);
  }
  return readFileSync(p, 'utf8');
}

function main() {
  if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  mkdirSync(join(OUT, 'actors'), { recursive: true });
  mkdirSync(join(OUT, 'emails'), { recursive: true });

  const source = JSON.parse(readStaging('source.json'));
  const dbPath = join(STAGING, 'databoose_full.db');
  if (!existsSync(dbPath)) {
    console.error(`  ⚠ no staged database at ${dbPath} — run \`node scripts/sync-actor-forums.mjs\` first`);
    process.exit(1);
  }

  const db = openDatabase(dbPath);

  // Verify the schema before reading, and refuse to read a database whose
  // columns do not match what the SELECT below expects.
  const table = db
    .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users_full'")
    .get();
  if (!table?.sql) {
    console.error('  ✗ the staged database has no `users_full` table');
    process.exit(1);
  }
  const available = new Set(
    db
      .prepare('PRAGMA table_info(users_full)')
      .all()
      .map((r) => String(r.name))
  );
  const missing = KEPT_COLUMNS.filter((c) => !available.has(c));
  if (missing.length > 0) {
    console.error(`  ✗ the staged database is missing expected columns: ${missing.join(', ')}`);
    process.exit(1);
  }

  const selectColumns = KEPT_COLUMNS.filter((c) => !FORBIDDEN_COLUMNS.has(c)).join(', ');
  const rows = db.prepare(`SELECT ${selectColumns} FROM users_full`).all();
  console.log(`  · ${rows.length} accounts`);

  const actorShards = new Map();
  const emailShards = new Map();
  let withEmail = 0;
  let withIp = 0;
  let misaligned = 0;

  for (const raw of rows) {
    const row = raw;
    const username = String(row.username ?? '').trim();
    if (!username) continue;

    // Drop the misaligned rows — see `validateRow`.
    if (!validateRow(row)) {
      misaligned++;
      continue;
    }

    const regIp = formatIp(row.regip);
    const lastIp = formatIp(row.lastip);
    if (regIp || lastIp) withIp++;

    // Only non-empty, non-zero fields are written. Most of the 324k
    // accounts have an empty title, no website, no warning points and no
    // IPs — emitting those keys anyway is what pushed the bundle past
    // 130 MB.
    const actor = { uid: String(row.uid ?? ''), username };
    const put = (key, value) => {
      if (value === null || value === undefined || value === '' || value === 0) return;
      actor[key] = value;
    };
    put('usergroup', String(row.usergroup ?? ''));
    put('display_group', String(row.displaygroup ?? ''));
    put('title', String(row.usertitle ?? ''));
    put('posts', Number.parseInt(String(row.postnum ?? '0'), 10) || 0);
    put('threads', Number.parseInt(String(row.threadnum ?? '0'), 10) || 0);
    put('reputation', Number.parseInt(String(row.reputation ?? '0'), 10) || 0);
    put('registered_at', formatTimestamp(row.regdate));
    put('last_active_at', formatTimestamp(row.lastactive));
    put('last_post_at', formatTimestamp(row.lastpost));
    put('registration_ip', regIp);
    put('last_ip', lastIp);
    put('website', String(row.website ?? ''));
    put('timezone', String(row.timezone ?? ''));
    put('warning_points', Number.parseInt(String(row.warningpoints ?? '0'), 10) || 0);

    const shard = usernameShard(username);
    let bucket = actorShards.get(shard);
    if (!bucket) {
      bucket = [];
      actorShards.set(shard, bucket);
    }
    bucket.push(actor);

    const email = String(row.email ?? '').trim();
    if (email && email !== '0') {
      withEmail++;
      const hash = hashEmail(email);
      const eshard = emailShard(hash);
      let ebucket = emailShards.get(eshard);
      if (!ebucket) {
        ebucket = [];
        emailShards.set(eshard, ebucket);
      }
      ebucket.push([hash, actor.uid, actor.username]);
    }
  }

  // Sort each actor shard by username so prefix lookups can binary-search
  // or stop early.
  for (const bucket of actorShards.values()) {
    bucket.sort((a, b) => a.username.localeCompare(b.username));
  }

  const shardStats = [];
  for (const [shard, bucket] of [...actorShards.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    writeFileSync(join(OUT, 'actors', `${shard}.json`), JSON.stringify({ shard, actors: bucket }));
    shardStats.push({ shard, actors: bucket.length });
  }

  for (const [shard, bucket] of [...emailShards.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    // The table maps hash → { uid, username }. The username is carried so a
    // hash hit can be resolved by loading exactly ONE username shard —
    // without it, resolving an email to its actor would mean reading every
    // shard.
    const map = {};
    for (const [hash, uid, username] of bucket) map[hash] = { uid, username };
    writeFileSync(join(OUT, 'emails', `${shard}.json`), JSON.stringify(map));
  }

  const index = {
    schemaVersion: 'actor-forums-v1',
    source: source.source,
    sourceUrl: source.sourceUrl,
    description: source.description,
    license: source.license,
    syncedAt: source.synced_at,
    email_salt: EMAIL_SALT,
    counts: {
      accounts: rows.length,
      misaligned_dropped: misaligned,
      actors: [...actorShards.values()].reduce((n, b) => n + b.length, 0),
      with_email: withEmail,
      with_ip: withIp,
      actor_shards: actorShards.size,
      email_shards: emailShards.size,
    },
    actor_shards: shardStats,
    excluded_columns: [...FORBIDDEN_COLUMNS].sort(),
  };

  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  db.close();

  console.log(`  ✓ ${index.counts.actors} actors across ${actorShards.size} shards`);
  console.log(`  ✓ ${misaligned} misaligned rows dropped (fields did not match their columns)`);
  console.log(`  ✓ ${withEmail} email hashes across ${emailShards.size} shards`);
  console.log(`  ✓ ${FORBIDDEN_COLUMNS.size} columns excluded (credentials, session keys, private state)`);
  console.log(`  → ${OUT}\n`);
}

main();
