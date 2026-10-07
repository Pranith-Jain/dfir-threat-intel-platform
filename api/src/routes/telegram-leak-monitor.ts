import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, internalError } from '../lib/api-error';
import { requireAdmin } from '../lib/admin-auth';
import type { TelegramFeedItem } from './telegram-feed';
import { fetchHtml, fetchTelegramFeed, parseChannelHtml } from './telegram-feed';

/**
 * Safely extract the number of affected rows from a D1 batch result entry.
 * D1's typing is incomplete — the actual runtime object has meta.changes
 * but the TS type doesn't expose it. This helper avoids unsafe `as never`
 * casts throughout the file.
 */
function d1Changes(result: unknown): number {
  if (typeof result !== 'object' || result === null) return 0;
  const meta = (result as Record<string, unknown>).meta;
  if (typeof meta !== 'object' || meta === null) return 0;
  const changes = (meta as Record<string, unknown>).changes;
  return typeof changes === 'number' ? changes : 0;
}

// ─── types ─────────────────────────────────────────────────────────────────────

interface LeakScanResult {
  channel_handle: string;
  message_link: string;
  message_text: string;
  leak_type: 'credential' | 'paste_link' | 'file_link' | 'keyword' | 'ioc' | 'cve';
  credential_count: number;
  domains_found: string[];
  matched_keywords: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

// ─── constants ─────────────────────────────────────────────────────────────────

const LEAK_KEYWORDS = [
  'leak',
  'breach',
  'dump',
  'credential',
  'password',
  'combolist',
  'combo list',
  'database leaked',
  'data leak',
  'db dump',
  'email:password',
  'email:pass',
  'user:pass',
  'username:password',
  'sql dump',
  'million records',
  'billion records',
  'pwned',
  'exposed',
  'stolen data',
  'hacked database',
  'pastes',
  'leaked accounts',
  'account dump',
  'fullz',
  'cvv',
  'cc dump',
  'logs',
  'access log',
  'mail access',
  'smtp',
  'imap',
  'pop3',
];

const CREDENTIAL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:|\t]\s*\S{3,}/g;
const PASTE_LINK_RE =
  /https?:\/\/(?:pastebin\.com|ghostbin\.com|rentry\.co|ix\.io|paste\.ee|hastebin\.com|dpaste\.org|dumpz\.org|defbin\.com)\/[a-zA-Z0-9]+/g;
const FILE_LINK_RE = /https?:\/\/[^\s]+\.(?:txt|csv|json|sql|xlsx?|zip|7z|rar)\b/gi;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const TELEGRAM_LINK_RE = /(?:https?:\/\/)?t\.me\/(?:s\/)?([a-zA-Z0-9_]{4,32})/gi;
const JOIN_LINK_RE = /https?:\/\/t\.me\/(?:\+|joinchat\/[a-zA-Z0-9_-]+)/gi;

// ─── IOC / CVE patterns ─────────────────────────────────────────────────────

/**
 * SHA256 (64 hex), SHA1 (40 hex), MD5 (32 hex) — word-boundaried.
 * Post-filtered via looksLikeHash() to reject all-digit, all-hex-letter,
 * or skewed strings that are unlikely to be real cryptographic hashes.
 */
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;

function looksLikeHash(s: string, minDigits: number, minLetters: number): boolean {
  const digits = (s.match(/\d/g) || []).length;
  const letters = (s.match(/[a-fA-F]/g) || []).length;
  return digits >= minDigits && letters >= minLetters;
}
/** IP:port combos — common C2/malware infrastructure indicator. */
const IP_PORT_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b/g;
/** CVE identifiers. */
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/g;
/** Bitcoin / Ethereum / Monero addresses. */
const CRYPTO_RE = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;
/** Known malware family keywords for detector context. */
const IOC_KEYWORDS = [
  'ioc',
  'indicator',
  'hash',
  'sha256',
  'sha1',
  'md5',
  'c2',
  'c&c',
  'command & control',
  'malware',
  'payload',
  'trojan',
  'ransomware',
  'backdoor',
  'dropper',
  'loader',
  'botnet',
  'rat',
  'stealer',
  'infostealer',
  'worm',
  'cve',
  '0day',
  'zero-day',
  'zero day',
  'exploit',
  'poc',
  'proof of concept',
  'vulnerability',
  'patch now',
  'critical',
  'remote code execution',
  'rce',
  'arbitrary code',
  'xss',
  'sqli',
  'csrf',
  'ssrf',
  'lfi',
  'buffer overflow',
  'phishing',
  'phish kit',
  'fake page',
  'lookalike domain',
  'typosquatting',
  'crypto drainer',
  'wallet drainer',
  'dns',
  'domain',
  'ip address',
  'threat actor',
  'apt',
  'ttps',
  'sigma rule',
  'yara rule',
  'snort rule',
];

// ─── scanning logic ──────────────────────────────────────────────────────────

export function scanMessageForLeaks(msg: TelegramFeedItem): LeakScanResult | null {
  const text = msg.text;
  if (!text || text.length < 10) return null;

  const matchedKeywords: string[] = [];
  const domainsFound: Set<string> = new Set();
  let credentialCount = 0;
  let leakType: LeakScanResult['leak_type'] = 'keyword';
  let iocCount = 0;
  let cveCount = 0;

  const lower = text.toLowerCase();

  for (const kw of LEAK_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) {
      matchedKeywords.push(kw);
    }
  }

  // Credential detection
  const credMatches = text.match(CREDENTIAL_RE);
  if (credMatches) {
    credentialCount = credMatches.length;
    leakType = 'credential';
  }

  // Paste / file link detection
  const pasteMatches = text.match(PASTE_LINK_RE);
  if (pasteMatches) {
    if (leakType === 'keyword') leakType = 'paste_link';
    matchedKeywords.push('paste_site');
  }

  const fileMatches = text.match(FILE_LINK_RE);
  if (fileMatches) {
    if (leakType === 'keyword') leakType = 'file_link';
    matchedKeywords.push('file_host');
  }

  // Extract domains from email addresses
  const domainMatches = text.match(EMAIL_RE);
  if (domainMatches) {
    for (const email of domainMatches) {
      const parts = email.split('@');
      if (parts.length === 2) domainsFound.add(parts[1]!.toLowerCase());
    }
  }

  // ─── IOC detection ───────────────────────────────────────────────────
  const hashMatches = [
    ...(text.match(MD5_RE) ?? []).filter((s) => looksLikeHash(s, 3, 3)),
    ...(text.match(SHA1_RE) ?? []).filter((s) => looksLikeHash(s, 4, 4)),
    ...(text.match(SHA256_RE) ?? []).filter((s) => looksLikeHash(s, 6, 6)),
  ];
  if (hashMatches.length > 0) {
    iocCount += hashMatches.length;
    matchedKeywords.push('hash_ioc');
  }

  const ipPortMatches = text.match(IP_PORT_RE);
  if (ipPortMatches) {
    iocCount += ipPortMatches.length;
    matchedKeywords.push('ip_port_ioc');
  }

  // ─── CVE detection ────────────────────────────────────────────────────
  const cveMatches = text.match(CVE_RE);
  if (cveMatches) {
    cveCount = cveMatches.length;
    matchedKeywords.push('cve');
    for (const cve of cveMatches.slice(0, 5)) {
      matchedKeywords.push(cve.toLowerCase());
    }
  }

  // ─── Crypto address detection ──────────────────────────────────────────
  const cryptoMatches = text.match(CRYPTO_RE);
  if (cryptoMatches) {
    matchedKeywords.push('crypto_address');
  }

  // ─── IOC keyword context ──────────────────────────────────────────────
  for (const kw of IOC_KEYWORDS) {
    if (lower.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  // If a message has IOCs or CVEs but zero leak keywords, still flag it.
  const hasLeakKeywords = matchedKeywords.some((k) => LEAK_KEYWORDS.some((lk) => k.includes(lk)));
  if (!hasLeakKeywords && iocCount === 0 && cveCount === 0) return null;

  // Determine type priority: credential > ioc > cve > file_link > paste_link > keyword
  if (iocCount > 0 && leakType === 'keyword') leakType = 'ioc';
  if (cveCount > 0 && (leakType === 'keyword' || leakType === 'ioc')) {
    // If both IOCs and CVEs, keep as ioc (more actionable)
    if (leakType !== 'ioc') leakType = 'cve';
  }

  // Severity scoring
  const keywordCount = matchedKeywords.length;
  const severity: LeakScanResult['severity'] =
    credentialCount > 100
      ? 'critical'
      : credentialCount > 10
        ? 'high'
        : iocCount >= 5
          ? 'critical'
          : iocCount >= 2
            ? 'high'
            : cveCount >= 3
              ? 'high'
              : cveCount >= 1
                ? 'medium'
                : leakType === 'credential'
                  ? 'high'
                  : keywordCount >= 5
                    ? 'medium'
                    : 'low';

  return {
    channel_handle: msg.channel_handle,
    message_link: msg.permalink,
    message_text: text.slice(0, 2000),
    leak_type: leakType,
    credential_count: credentialCount,
    domains_found: Array.from(domainsFound).slice(0, 20),
    matched_keywords: matchedKeywords.slice(0, 15),
    severity,
  };
}

export function extractChannelLinks(text: string): string[] {
  const handles: Set<string> = new Set();
  let m: RegExpExecArray | null;

  const linkRe = new RegExp(TELEGRAM_LINK_RE.source, 'g');
  while ((m = linkRe.exec(text)) !== null) {
    if (m[1]) handles.add(m[1].toLowerCase());
  }

  return Array.from(handles);
}

function extractJoinLinks(text: string): string[] {
  const links: Set<string> = new Set();
  let m: RegExpExecArray | null;
  const joinRe = new RegExp(JOIN_LINK_RE.source, 'g');
  while ((m = joinRe.exec(text)) !== null) {
    links.add(m[0]);
  }
  return Array.from(links);
}

// ─── D1 operations ───────────────────────────────────────────────────────────

export async function ensureWatchedChannel(db: D1Database, handle: string, category?: string): Promise<void> {
  const existing = await db
    .prepare('SELECT handle FROM telegram_watched_channels WHERE handle = ?')
    .bind(handle)
    .first();

  if (existing) return;

  await db
    .prepare(
      `INSERT INTO telegram_watched_channels (handle, category, added_by, added_at)
     VALUES (?, ?, 'auto', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))`
    )
    .bind(handle, category || 'auto-discovered')
    .run();
}

// ─── main scan function ─────────────────────────────────────────────────────

export async function runTelegramLeakScanner(
  db: D1Database,
  items: TelegramFeedItem[]
): Promise<{ leaks_found: number; channels_discovered: number }> {
  const now = new Date()
    .toISOString()
    .replace('T', 'T')
    .replace(/\.\d+Z/, 'Z');
  const joinedLeaksStmt = db.prepare(
    `INSERT OR IGNORE INTO telegram_leak_entries
      (channel_handle, message_link, message_text, leak_type, credential_count, domains_found, severity, discovered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const channelUpdateStmt = db.prepare(
    `UPDATE telegram_watched_channels
       SET last_leak_found = ?,
           leak_count = leak_count + 1
     WHERE handle = ?`
  );
  const discoveredInsertStmt = db.prepare(
    `INSERT OR IGNORE INTO telegram_discovered_channels (handle, source_message, discovered_at)
     VALUES (?, ?, ?)`
  );

  // Pre-fetch watched handles so we can skip SELECT-per-channel later.
  const watchedRows = await db
    .prepare('SELECT handle FROM telegram_watched_channels WHERE active = 1')
    .all<{ handle: string }>();
  const watchedSet = new Set(watchedRows.results?.map((r) => r.handle.toLowerCase()) ?? []);

  // Pre-fetch operator-dismissed handles (reviewed but NOT added to watch) so a
  // rejected channel stays rejected — a new source message mentioning it must
  // not resurface it in the review queue. See telegramRejectChannelHandler.
  const dismissedRows = await db
    .prepare('SELECT DISTINCT handle FROM telegram_discovered_channels WHERE reviewed = 1 AND added_to_watch = 0')
    .all<{ handle: string }>();
  const dismissedSet = new Set(dismissedRows.results?.map((r) => r.handle.toLowerCase()) ?? []);

  // Collect everything, then batch.
  const leakStmts: ReturnType<typeof db.prepare>[] = [];
  const updateStmts: ReturnType<typeof db.prepare>[] = [];
  const discoveredHandles = new Map<string, string | null>();

  for (const item of items) {
    const chLinks = extractChannelLinks(item.text);
    for (const handle of chLinks) {
      const h = handle.toLowerCase();
      if (!watchedSet.has(h) && !dismissedSet.has(h) && !discoveredHandles.has(h)) {
        discoveredHandles.set(h, item.permalink);
      }
    }

    const extLinks = extractJoinLinks(item.text);
    for (const link of extLinks) {
      const hash = link.split('/+')[1] || link.split('joinchat/')[1] || link;
      if (hash) {
        const jh = 'join:' + hash;
        if (!dismissedSet.has(jh) && !discoveredHandles.has(jh)) {
          discoveredHandles.set(jh, item.permalink);
        }
      }
    }

    const result = scanMessageForLeaks(item);
    if (result) {
      leakStmts.push(
        joinedLeaksStmt.bind(
          result.channel_handle,
          result.message_link,
          result.message_text,
          result.leak_type,
          result.credential_count,
          JSON.stringify(result.domains_found),
          result.severity,
          now
        )
      );
      updateStmts.push(channelUpdateStmt.bind(now, result.channel_handle));
    }
  }

  // Batch discovered-channel inserts (skip watched).
  const discStmts: ReturnType<typeof db.prepare>[] = [];
  for (const [handle, source] of discoveredHandles) {
    if (!watchedSet.has(handle) && !dismissedSet.has(handle)) {
      discStmts.push(discoveredInsertStmt.bind(handle, source, now));
    }
  }

  // Execute batches.
  const results = await Promise.all([
    discStmts.length > 0 ? db.batch(discStmts) : [],
    leakStmts.length > 0 ? db.batch(leakStmts) : [],
    updateStmts.length > 0 ? db.batch(updateStmts) : [],
  ]);

  // Count changes via affected rows (D1 batch returns arrays of results
  // where each result has meta.changes). Sum them up.
  const batchResults = results.flat();
  const channelsDiscovered = batchResults.slice(0, discStmts.length).reduce((sum, r) => sum + d1Changes(r), 0);
  const leaksFound = batchResults
    .slice(discStmts.length, discStmts.length + leakStmts.length)
    .reduce((sum, r) => sum + d1Changes(r), 0);

  return { leaks_found: leaksFound, channels_discovered: channelsDiscovered };
}

// ─── Tier-1 active scrape of the watched leak channels ───────────────────────

/**
 * The hourly feed scanner only sees the curated news/OSINT feed, so the
 * channels an operator explicitly adds to `telegram_watched_channels` were
 * never fetched — `last_scraped` stayed NULL and they produced 0 leaks. This
 * fetches each active watched channel's `t.me/s/<handle>` preview, runs the
 * same leak scan over its messages, and stamps `last_scraped`. Channels with
 * no public preview (Telegram 302s the request) still get a `last_scraped`
 * stamp with `message_count = 0` — those need the Tier-2 bot as a member.
 */
const WATCHED_SCRAPE_CONCURRENCY = 4;
const MAX_WATCHED_PER_RUN = 25;

export async function scrapeWatchedChannels(
  db: D1Database
): Promise<{ channels_scraped: number; leaks_found: number; channels_discovered: number }> {
  // Oldest-scraped first (SQLite sorts NULL before any value in ASC), so a
  // backlog rotates through over successive hourly runs.
  const watched = await db
    .prepare('SELECT handle FROM telegram_watched_channels WHERE active = 1 ORDER BY last_scraped ASC LIMIT ?')
    .bind(MAX_WATCHED_PER_RUN)
    .all<{ handle: string }>();
  const channels = (watched.results ?? []).filter((r) => r.handle);
  if (channels.length === 0) return { channels_scraped: 0, leaks_found: 0, channels_discovered: 0 };

  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const scrapeUpdateStmt = db.prepare(
    'UPDATE telegram_watched_channels SET last_scraped = ?, message_count = ? WHERE handle = ?'
  );
  const updateStmts: ReturnType<typeof db.prepare>[] = [];
  const allItems: TelegramFeedItem[] = [];

  // Bounded concurrency so we don't burst Telegram or exhaust the subrequest budget.
  let idx = 0;
  const worker = async (): Promise<void> => {
    while (idx < channels.length) {
      const ch = channels[idx++];
      if (!ch?.handle) continue;
      const html = await fetchHtml(`https://telegram.me/s/${encodeURIComponent(ch.handle)}`);
      const msgs = html ? parseChannelHtml(html) : [];
      for (const m of msgs) {
        allItems.push({
          channel_handle: ch.handle,
          channel_name: ch.handle,
          channel_topic: 'leaks',
          channel_blurb: '',
          permalink: m.permalink,
          datetime: m.datetime,
          text: m.text,
          views: m.views,
        });
      }
      // Record the attempt regardless — a 302/private channel still updates
      // last_scraped (message_count 0) so the watched list reflects reality.
      updateStmts.push(scrapeUpdateStmt.bind(now, msgs.length, ch.handle));
    }
  };
  await Promise.all(Array.from({ length: Math.min(WATCHED_SCRAPE_CONCURRENCY, channels.length) }, () => worker()));

  if (updateStmts.length > 0) {
    try {
      await db.batch(updateStmts);
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* non-fatal — last_scraped is best-effort */
    }
  }

  // Reuse the existing scanner for leak insertion + onward channel discovery.
  const scan =
    allItems.length > 0 ? await runTelegramLeakScanner(db, allItems) : { leaks_found: 0, channels_discovered: 0 };

  return {
    channels_scraped: channels.length,
    leaks_found: scan.leaks_found,
    channels_discovered: scan.channels_discovered,
  };
}

// ─── API handlers ────────────────────────────────────────────────────────────

export async function telegramLeakSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  const q = c.req.query('q');
  const channel = c.req.query('channel');
  const severity = c.req.query('severity') as string | undefined;
  const limit = Math.min(Number(c.req.query('limit')) || 50, 200);
  const offset = Number(c.req.query('offset')) || 0;

  let sql =
    'SELECT id, channel_handle, message_link, message_text, leak_type, credential_count, file_url, file_name, domains_found, severity, discovered_at, raw_content FROM telegram_leak_entries WHERE 1=1';
  const binds: unknown[] = [];

  if (q) {
    sql += ' AND (message_text LIKE ? OR channel_handle LIKE ? OR domains_found LIKE ?)';
    const pattern = `%${q}%`;
    binds.push(pattern, pattern, pattern);
  }
  if (channel) {
    sql += ' AND channel_handle = ?';
    binds.push(channel);
  }
  if (severity && ['low', 'medium', 'high', 'critical'].includes(severity)) {
    sql += ' AND severity = ?';
    binds.push(severity);
  }

  sql += ' ORDER BY discovered_at DESC LIMIT ? OFFSET ?';
  binds.push(limit, offset);

  try {
    const { results } = await db
      .prepare(sql)
      .bind(...binds)
      .all();
    return c.json(
      {
        entries: results,
        count: results.length,
        offset,
        limit,
      },
      200,
      { 'Cache-Control': 'public, max-age=60' }
    );
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'query failed');
  }
}

export async function telegramDiscoveredChannelsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  const reviewed = c.req.query('reviewed');
  let sql =
    'SELECT id, handle, source_message, discovered_at, reviewed, added_to_watch FROM telegram_discovered_channels';
  const binds: unknown[] = [];

  if (reviewed === 'true') {
    sql += ' WHERE reviewed = 1';
  } else if (reviewed === 'false') {
    sql += ' WHERE reviewed = 0';
  }

  sql += ' ORDER BY discovered_at DESC LIMIT 200';

  try {
    const { results } = await db
      .prepare(sql)
      .bind(...binds)
      .all();
    return c.json({ channels: results }, 200, { 'Cache-Control': 'public, max-age=60' });
  } catch (e) {
    logError('telegramDiscoveredChannelsHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'query failed');
  }
}

export async function telegramWatchedChannelsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  try {
    const { results } = await db
      .prepare(
        'SELECT handle, title, category, discovered_from, added_by, added_at, last_scraped, last_leak_found, message_count, leak_count, active, tags FROM telegram_watched_channels WHERE active = 1 ORDER BY last_leak_found DESC'
      )
      .all();
    // Previously sent with no Cache-Control, so every /threatintel/telegram
    // page view re-read the table. `last_scraped` / `last_leak_found` only move
    // on a scrape tick (every 30 min for active channels) or an
    // approve/reject, so 5 minutes is well inside the staleness anyone would
    // notice on a channel list.
    //
    // `private`, not `public`: this route sits behind the API-key middleware,
    // and RFC 9111 lets a shared cache store an authenticated response only if
    // it says `public`/`s-maxage`. Marking it `public` would therefore let the
    // edge cache an API-key-gated body and replay it to callers who present no
    // key at all. `private` still gets the win that matters here — the browser
    // reuses the response across in-app navigation, so the D1 read happens once
    // per 5 minutes per client instead of once per page view.
    return c.json({ channels: results }, 200, { 'Cache-Control': 'private, max-age=300' });
  } catch (e) {
    logError('telegramWatchedChannelsHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'query failed');
  }
}

export async function telegramApproveChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;

  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  const body = (await c.req.json()) as { handle?: string; category?: string };
  const handle = body.handle;
  if (!handle) return badRequest(c, 'handle required');

  const category = body.category || 'auto-discovered';

  try {
    await db
      .prepare('UPDATE telegram_discovered_channels SET reviewed = 1, added_to_watch = 1 WHERE handle = ?')
      .bind(handle)
      .run();

    await ensureWatchedChannel(db, handle, category);

    // Also add to KV custom channel list so the feed scraper fetches it.
    const kv = c.env.KV_CACHE;
    if (kv) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            const raw = await kv.get('tg:custom-channels:v1');
            const existing: Array<{ handle: string; name: string }> = raw ? JSON.parse(raw) : [];
            if (!existing.some((ch) => ch.handle.toLowerCase() === handle.toLowerCase())) {
              existing.push({ handle, name: handle });
              await kv.put('tg:custom-channels:v1', JSON.stringify(existing));
            }
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
            /* non-critical */
          }
        })()
      );
    }

    return c.json({ ok: true, handle, category }, 200);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'failed');
  }
}

/**
 * Reject (dismiss) a discovered channel so it stops cluttering the review queue
 * AND never gets re-surfaced. "Sticky": we mark every row for the handle
 * reviewed=1, added_to_watch=0, and the scanner skips re-inserting handles in
 * that state (see runTelegramLeakScanner's dismissedSet) — so a fresh source
 * message mentioning the same handle won't make it reappear. Also deactivates +
 * unsubscribes it if it had previously been approved (idempotent un-approve).
 */
export async function telegramRejectChannelHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;

  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  const body = (await c.req.json()) as { handle?: string };
  const handle = body.handle;
  if (!handle) return badRequest(c, 'handle required');

  try {
    const res = await db
      .prepare('UPDATE telegram_discovered_channels SET reviewed = 1, added_to_watch = 0 WHERE handle = ?')
      .bind(handle)
      .run();

    // If it was previously approved, un-watch it so the scraper stops fetching.
    await db.prepare('UPDATE telegram_watched_channels SET active = 0 WHERE handle = ?').bind(handle).run();

    // Drop it from the KV custom-channels list the feed scraper reads.
    const kv = c.env.KV_CACHE;
    if (kv) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            const raw = await kv.get('tg:custom-channels:v1');
            if (!raw) return;
            const existing: Array<{ handle: string; name: string }> = JSON.parse(raw);
            const next = existing.filter((ch) => ch.handle.toLowerCase() !== handle.toLowerCase());
            if (next.length !== existing.length) {
              await kv.put('tg:custom-channels:v1', JSON.stringify(next));
            }
          } catch (_catchErr) {
            logError('handler failed', _catchErr);
            /* non-critical */
          }
        })()
      );
    }

    return c.json({ ok: true, handle, rows: res.meta?.changes ?? 0 }, 200);
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'failed');
  }
}

// ─── stats endpoint ──────────────────────────────────────────────────────────

export async function telegramLeakStatsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  try {
    // `total` used to be a separate bare `SELECT COUNT(*) FROM
    // telegram_leak_entries` — an unconditional full scan of the largest table
    // in the schema, on every page view of /threatintel/telegram (TelegramHub
    // fetches this endpoint on mount). Summing the severity rollup yields the
    // identical total and removes one full scan from the request.
    const [severityRollup, topChannels, topDomains, recent24h] = await Promise.all([
      db
        .prepare(
          `SELECT severity, COUNT(*) as n FROM telegram_leak_entries
         GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`
        )
        .all<{ severity: string; n: number }>(),
      db
        .prepare(
          `SELECT channel_handle, COUNT(*) as n FROM telegram_leak_entries
         GROUP BY channel_handle ORDER BY n DESC LIMIT 10`
        )
        .all<{ channel_handle: string; n: number }>(),
      // Ordered so this is served by idx_leak_entries_discovered_at and reads
      // only the newest 100 rows. Without the ORDER BY, SQLite scanned forward
      // from the table start until it happened to collect 100 non-empty blobs,
      // which on a sparse table meant walking the whole thing — and the sample
      // was arbitrary. "Most recent 100" is both bounded and more useful.
      db
        .prepare(
          `SELECT json_extract(domains_found, '$') as domain_blob FROM telegram_leak_entries
         WHERE domains_found IS NOT NULL AND domains_found != '[]'
         ORDER BY discovered_at DESC LIMIT 100`
        )
        .all<{ domain_blob: string }>(),
      db
        .prepare(
          `SELECT COUNT(*) as n FROM telegram_leak_entries
         WHERE discovered_at >= datetime('now', '-1 day')`
        )
        .first<{ n: number }>(),
    ]);

    const total = (severityRollup.results ?? []).reduce((sum, r) => sum + r.n, 0);

    // Aggregate domains from the sampled blob entries.
    const domainCounts = new Map<string, number>();
    for (const row of topDomains.results ?? []) {
      try {
        const parsed = JSON.parse(row.domain_blob);
        if (Array.isArray(parsed)) {
          for (const d of parsed) {
            domainCounts.set(d, (domainCounts.get(d) ?? 0) + 1);
          }
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* skip malformed */
      }
    }
    const topDomainsList = Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));

    return c.json(
      {
        total_entries: total,
        last_24h: recent24h?.n ?? 0,
        severity_distribution: severityRollup.results ?? [],
        top_channels: topChannels.results ?? [],
        top_domains: topDomainsList,
      },
      200,
      { 'Cache-Control': 'public, max-age=120' }
    );
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'stats failed');
  }
}

// ─── cleanup (call from cron) ────────────────────────────────────────────────

export async function cleanupLeakEntries(db: D1Database, maxAgeDays = 30): Promise<number> {
  const result = await db
    .prepare(`DELETE FROM telegram_leak_entries WHERE discovered_at < datetime('now', ? || ' days')`)
    .bind(String(-maxAgeDays))
    .run();
  return d1Changes(result);
}

// ─── manual trigger (one-time diagnostic, will be removed) ──────────────────

export async function telegramLeakScanTriggerHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  const kv = c.env.KV_CACHE;
  if (!db) return internalError(c, 'D1 not configured');

  try {
    const feed = await fetchTelegramFeed(kv, c.env);
    if (!feed?.items?.length) return c.json({ error: 'no feed items', feed_items: 0 });
    const result = await runTelegramLeakScanner(db, feed.items);
    return c.json({
      ok: true,
      feed_items: feed.items.length,
      leaks_found: result.leaks_found,
      channels_discovered: result.channels_discovered,
    });
  } catch (e) {
    logError('telegramLeakScanTriggerHandler failed', e);
    return internalError(c, e instanceof Error ? e.message : String(e));
  }
}

// ─── Telegram Leak Geo ──────────────────────────────────────────────────────

export async function telegramLeakGeoHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return internalError(c, 'D1 not configured');

  try {
    const rows = (await db
      .prepare(
        `SELECT domains_found FROM telegram_leak_entries
       WHERE discovered_at > datetime('now', '-24 hours')
       AND domains_found != '[]' AND domains_found IS NOT NULL
       LIMIT 100`
      )
      .all()) as { results?: Array<{ domains_found: string }> };

    const domainSet = new Set<string>();
    for (const row of rows.results ?? []) {
      try {
        const domains = JSON.parse(row.domains_found) as string[];
        for (const d of domains) {
          if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i.test(d)) {
            domainSet.add(d.toLowerCase());
          }
        }
      } catch (_catchErr) {
        logError('telegramLeakGeoHandler failed', _catchErr);
        /* skip malformed json */
      }
    }

    // Hard-cap total domains BEFORE the loop. The old code counted only
    // successes, so failed lookups (2 fetches each) ran unbounded and could
    // blow the Free-plan 50-subrequest cap. Cap at 20 (1 D1 read + ≤20 DoH +
    // 1 batched geo POST = ≤22 subrequests), then batch the geo step.
    const domains = Array.from(domainSet).slice(0, 20);
    const resolved: Array<{ domain: string; ip: string }> = [];
    for (const domain of domains) {
      try {
        const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
          headers: { accept: 'application/dns-json' },
          signal: AbortSignal.timeout(3000),
        });
        if (!dnsRes.ok) continue;
        const dnsData = (await dnsRes.json()) as { Answer?: Array<{ data: string }> };
        const ip = dnsData.Answer?.[0]?.data;
        if (ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) resolved.push({ domain, ip });
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* skip */
      }
    }

    const geoPoints: Array<{ domain: string; ip: string; country: string; countryCode: string }> = [];
    if (resolved.length) {
      try {
        const res = await fetch('http://ip-api.com/batch?fields=query,status,country,countryCode', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(resolved.map((r) => ({ query: r.ip }))),
          signal: AbortSignal.timeout(4000),
        });
        if (res.ok) {
          const arr = (await res.json()) as Array<{
            query: string;
            status?: string;
            country?: string;
            countryCode?: string;
          }>;
          const byIp = new Map(arr.map((g) => [g.query, g]));
          for (const r of resolved) {
            const g = byIp.get(r.ip);
            if (g && g.status === 'success' && g.country && g.countryCode) {
              geoPoints.push({ domain: r.domain, ip: r.ip, country: g.country, countryCode: g.countryCode });
            }
          }
        }
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        /* skip */
      }
    }

    return c.json(
      {
        generated_at: new Date().toISOString(),
        total_domains: domainSet.size,
        total_geo: geoPoints.length,
        points: geoPoints,
      },
      200,
      { 'Cache-Control': 'public, max-age=300' }
    );
  } catch (e) {
    logError('handler failed', e);
    return internalError(c, e instanceof Error ? e.message : 'geo failed');
  }
}
