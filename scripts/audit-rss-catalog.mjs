#!/usr/bin/env node
/**
 * audit-rss-catalog.mjs
 *
 * Static + live audit of the RSS catalog in src/data/rssFeeds.ts.
 *
 * # Why this exists
 *
 * scripts/audit-feed-health.mjs covers the IOC registry (live-iocs.ts /
 * feed-curation.ts). The *RSS catalog* had no equivalent check, which is how
 * three separate failures sat in production at once:
 *
 *   1. **Allowlist drift** — `blog.trailofbits.com` was listed in the proxy
 *      allowlist (feeds.ts) but not the aggregator's copy, so the route the
 *      SPA actually calls answered `host_not_in_allowlist` for a healthy feed.
 *      Adding a feed to rssFeeds.ts without touching the allowlist produces the
 *      same failure, which is why `radar.offseq.com` could not be added.
 *   2. **Empty upstreams** — `hackread.com/category/security/data-breach/feed/`
 *      and `redhuntlabs.com/blog/feed/` return HTTP 200 with a valid but EMPTY
 *      channel (0 items). A status-code check passes them forever; the feed
 *      silently contributes nothing.
 *   3. **Egress-blocked origins** — helpnetsecurity.com (empty body), the
 *      securityweek cybercrime category feed and venturebeat.com (429) all
 *      refuse Cloudflare Worker egress. Only discoverable from inside the
 *      Worker, but the upstream signatures are stable enough to detect here.
 *
 * # What it checks
 *
 *   - every catalog URL parses and its host is in the shared allowlist
 *     (api/src/lib/feed-hosts.ts — one list, both routes)
 *   - every id in the landing / feed-id lists exists in the catalog
 *   - no duplicate ids
 *   - live upstream probe: HTTP status, content type, parsed <item>/<entry>
 *     count, newest pubDate, and a STALE verdict when the newest item is
 *     older than the staleness window
 *   - synthesised same-origin feeds (mti-ransomware, ransomware-merged) are
 *     reported as skipped — they resolve in-process inside the Worker
 *
 * # Usage
 *
 *   node scripts/audit-rss-catalog.mjs            # catalog
 *   node scripts/audit-rss-catalog.mjs --json
 *   node scripts/audit-rss-catalog.mjs --no-probe # static checks only
 *
 * Exit 1 when any catalog feed is broken, so it can gate CI. `--json` output
 * shape matches audit-feed-health.mjs (registered[] + summary).
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

const argv = new Set(process.argv.slice(2));
const AS_JSON = argv.has('--json');
const NO_PROBE = argv.has('--no-probe');

const UA = {
  'user-agent':
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
  accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
  'accept-language': 'en-US,en;q=0.9',
};
const TIMEOUT_MS = 60_000;
const CONCURRENCY = 4;
/** One retry with backoff. Several upstreams (Bing News, hnrss.org, CNAME-heavy
 *  hosts) rate-limit or reset bursty probes from a single IP; a retry keeps a
 *  transient blip from being reported as feed rot. */
const RETRY_BASE_MS = 3_000;
const MAX_RETRIES = 1;
/** Newest item older than this many days ⇒ stale-but-serving. */
const STALE_DAYS = 45;

/** Same-origin feeds the aggregator builds in-process — never probe upstream. */
const SYNTHESISED = new Set(['mti-ransomware', 'ransomware-merged']);

/**
 * Feeds that publish on a multi-month cadence. Their newest item being older
 * than STALE_DAYS is expected, not rot — a status/staleness failure on these
 * every run is exactly the "trained everyone to ignore the audit" noise this
 * script exists to avoid (same reasoning as NOT_PLAIN_GET in
 * audit-feed-health.mjs).
 *
 * Measured 2026-10-16. When a publisher here starts posting again, drop it
 * from this list and let the staleness check guard it again.
 */
const LOW_FREQUENCY = new Map([
  ['infostealers-techniques', 'technique profiles; upstream newest Sep 2023, dormant category'],
  ['vpnmentor-research', 'exposed-DB research reports; newest Oct 2025'],
  ['rekt-news', 'long-form exploit post-mortems; newest Apr 2026 (a handful per year)'],
  ['mandiant', 'canonical Blogger feed; newest Apr 2026 (FeedBurner-stale, repointed)'],
  ['gnews-investment-cyber', 'Bing News search; few high-signal investment-bank incidents surface at a time'],
  ['dfir-report', 'in-depth IR writeups; newest Aug 2026'],
  ['red-canary', 'detection engineering blog; newest Aug 2026'],
  ['objective-see', 'macOS/iOS research; newest Aug 2026'],
  ['idtheftcenter', 'quarterly breach reports; newest Aug 2026'],
  ['tisiphone', 'personal DFIR blog; newest Jul 2026'],
]);

/** Extract quoted strings from a Set literal / array literal body. */
function quotedList(body) {
  return [...body.matchAll(/'([^']+)'/g)].map((m) => m[1]);
}

async function readAllowlist() {
  const src = await readFile(join(ROOT, 'api/src/lib/feed-hosts.ts'), 'utf8');
  const start = src.indexOf('new Set<string>([');
  if (start === -1) throw new Error('FEED_ALLOWED_HOSTS not found in api/src/lib/feed-hosts.ts');
  const open = src.indexOf('[', start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === '[') depth++;
    else if (ch === ']') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) throw new Error('could not find end of FEED_ALLOWED_HOSTS');
  return new Set(quotedList(src.slice(open + 1, end).replace(/\/\/[^\n]*/g, '')));
}

async function readCatalog() {
  const src = await readFile(join(ROOT, 'src/data/rssFeeds.ts'), 'utf8');
  const feeds = [];
  // Objects in the catalog: `{ … id: '…', … url: '…', … }`. Two wrinkles:
  // prettier may put a line break after the colon, and entries (the synthesised
  // same-origin feeds) carry `// comment` lines between `{` and `id:` — allowed
  // explicitly, since \s* does not match comments and the two synthesised
  // entries would otherwise drop out of the audit.
  const re = /\{\s*(?:\/\/[^\n]*\n\s*)*id:\s*'([^']+)',[\s\S]*?url:\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    // Only the catalog literal (before the first `export const landing`/etc.).
    if (m.index > src.indexOf('export const defaultFeeds')) break;
    feeds.push({ id: m[1], url: m[2] });
  }
  // Id lists that reference the catalog. A dangling id means the page renders
  // an empty section, which is how dead feeds lingered after retirement.
  const lists = [];
  const listRe = /export const (\w*(?:Feeds|FEEDS)\w*)\s*(?::\s*string\[\])?\s*=\s*\[([\s\S]*?)\];/g;
  while ((m = listRe.exec(src)) !== null) lists.push({ name: m[1], ids: quotedList(m[2]) });
  return { feeds, lists };
}

/** Parse RSS/Atom/JSON-Feed bodies the same way the aggregator does. */
function parseItems(body) {
  const trimmed = body.trimStart();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.items)) {
        return parsed.items.map((i) => ({
          date: i?.date_published || i?.date_modified || '',
          link: typeof i?.url === 'string' ? i.url : typeof i?.id === 'string' ? i.id : '',
        }));
      }
    } catch {
      /* fall through to XML */
    }
  }
  const items = [];
  const itemRe = /<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  let m;
  while ((m = itemRe.exec(body)) !== null) {
    const inner = m[2];
    const link =
      /<link\b[^>]*>([\s\S]*?)<\/link>/i.exec(inner)?.[1]?.trim() ??
      /<link\b[^>]*\bhref=["']([^"']+)["']/i.exec(inner)?.[1] ??
      /<guid\b[^>]*>([\s\S]*?)<\/guid>/i.exec(inner)?.[1]?.trim() ??
      '';
    const date =
      /<pubDate\b[^>]*>([\s\S]*?)<\/pubDate>/i.exec(inner)?.[1] ??
      /<updated\b[^>]*>([\s\S]*?)<\/updated>/i.exec(inner)?.[1] ??
      /<published\b[^>]*>([\s\S]*?)<\/published>/i.exec(inner)?.[1] ??
      '';
    items.push({ date: date.trim(), link: link.trim() });
  }
  return items;
}

function isHtml(body) {
  const head = body.trimStart().slice(0, 40).toLowerCase();
  return head.startsWith('<!doctype') || head.startsWith('<html');
}

async function probe(url, id) {
  const ac = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    ac.abort();
  }, TIMEOUT_MS);
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: ac.signal, redirect: 'follow', headers: UA });
    const body = res.ok ? await res.text() : '';
    const ms = Date.now() - t0;
    if (!res.ok) return { ok: false, status: res.status, ms, note: `HTTP ${res.status}` };
    if (isHtml(body)) {
      return { ok: false, status: res.status, ms, note: 'HTML page, not a feed (bot challenge?)' };
    }
    const items = parseItems(body);
    if (items.length === 0) {
      return { ok: false, status: res.status, ms, items: 0, note: '200 but feed has 0 items (empty upstream)' };
    }
    const dates = items
      .map((i) => Date.parse(i.date))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => b - a);
    const newest = dates.length ? new Date(dates[0]).toISOString() : null;
    const ageDays = dates.length ? (Date.now() - dates[0]) / 86_400_000 : null;
    const stale = ageDays !== null && ageDays > STALE_DAYS;
    if (stale) {
      const known = LOW_FREQUENCY.get(id);
      const note = `newest ${newest?.slice(0, 10)} (${Math.round(ageDays)}d old)`;
      // Known low-frequency publishers report but don't fail; anything else
      // going quiet is rot and must fail the run.
      return {
        ok: !!known,
        stale: true,
        status: res.status,
        ms,
        items: items.length,
        newest,
        note: known ? `${note} — low-frequency publisher: ${known}` : `no item newer than ${STALE_DAYS}d: ${note}`,
      };
    }
    return { ok: true, status: res.status, ms, items: items.length, newest, note: undefined };
  } catch (e) {
    // An abort is almost always OUR 20s deadline, not a dead feed — say so.
    // A degraded local link otherwise reads exactly like upstream rot, and the
    // two have opposite fixes. Re-probe a timeout before acting on it.
    const note = timedOut
      ? `timeout after ${TIMEOUT_MS / 1000}s — slow link or oversized feed? re-probe before treating as rot`
      : e instanceof Error
        ? e.message.slice(0, 60)
        : 'error';
    return { ok: false, status: 0, ms: Date.now() - t0, note };
  } finally {
    clearTimeout(timer);
  }
}

const ICONS = { ok: '✔', bad: '✘' };

async function main() {
  const allow = await readAllowlist();
  const { feeds, lists } = await readCatalog();
  if (feeds.length === 0) throw new Error('parsed 0 catalog feeds from src/data/rssFeeds.ts');

  const problems = [];
  const seen = new Set();
  const results = [];
  for (const f of feeds) {
    if (seen.has(f.id)) problems.push(`duplicate catalog id: ${f.id}`);
    seen.add(f.id);
    let host = null;
    try {
      host = new URL(f.url).hostname.toLowerCase();
    } catch {
      problems.push(`${f.id}: unparseable url ${f.url}`);
    }
    // Synthesised feeds carry a cosmetic placeholder host — the aggregator
    // intercepts their pathname and builds them in-process before the
    // allowlist check (see fetchOne in feeds-aggregate.ts).
    if (host && !allow.has(host) && !SYNTHESISED.has(f.id)) {
      problems.push(
        `${f.id}: host not in feed-hosts.ts → ${host} (add it, or the aggregator answers host_not_in_allowlist)`
      );
    }
    results.push({
      id: f.id,
      url: f.url,
      host,
      ...(SYNTHESISED.has(f.id) || NO_PROBE
        ? { skipped: true, skipReason: SYNTHESISED.has(f.id) ? 'synthesised' : 'no-probe' }
        : {}),
    });
  }
  for (const list of lists) {
    for (const id of list.ids) {
      if (!seen.has(id)) problems.push(`${list.name} references unknown feed id: ${id}`);
    }
  }

  if (!NO_PROBE) {
    for (let i = 0; i < results.length; i += CONCURRENCY) {
      const slice = results.slice(i, i + CONCURRENCY);
      const probed = await Promise.all(
        slice.map(async (r) => {
          if (r.skipped) return r;
          let out = await probe(r.url, r.id);
          for (let attempt = 1; attempt <= MAX_RETRIES && !out.ok; attempt++) {
            await new Promise((res) => setTimeout(res, RETRY_BASE_MS * attempt));
            out = await probe(r.url, r.id);
            if (out.ok) break;
          }
          return { ...r, ...out, retried: out.ok };
        })
      );
      results.splice(i, slice.length, ...probed);
      if (!AS_JSON) process.stderr.write('.');
    }
    if (!AS_JSON) process.stderr.write('\n');
    for (const r of results) {
      if (r.skipped) continue;
      if (!r.ok) problems.push(`${r.id}: ${r.note}`);
    }
  }

  const live = results.filter((r) => !r.skipped);
  const healthy = live.filter((r) => r.ok).length;
  const stale = live.filter((r) => r.ok && r.stale);

  if (AS_JSON) {
    console.log(
      JSON.stringify(
        {
          audited_at: new Date().toISOString(),
          registered: results,
          summary: {
            catalog: feeds.length,
            healthy,
            unhealthy: live.length - healthy,
            stale_low_frequency: stale.length,
            skipped: results.length - live.length,
            static_problems: problems.length,
          },
          problems,
        },
        null,
        2
      )
    );
    process.exit(problems.length > 0 ? 1 : 0);
  }

  console.log('\n  RSS CATALOG');
  console.log(`  ${'─'.repeat(96)}`);
  for (const r of results.sort((a, b) => a.id.localeCompare(b.id))) {
    if (r.skipped) {
      const tag = r.skipReason === 'synthesised' ? 'synthesised' : 'not probed';
      const hint =
        r.skipReason === 'synthesised'
          ? ' (built in-process by the Worker)'
          : ' (run without --no-probe to check liveness)';
      console.log(`  ~ ${r.id.padEnd(26)} ${'—'.padEnd(4)} ${tag.padStart(11)}${hint}`);
      continue;
    }
    const icon = r.stale ? '!' : r.ok ? ICONS.ok : ICONS.bad;
    const newest = r.newest ? ` newest=${r.newest.slice(0, 10)}` : '';
    console.log(
      `  ${icon} ${r.id.padEnd(26)} ${String(r.status ?? 'ERR').padEnd(4)} ${String(r.items ?? 0).padStart(5)} items  ${String(r.ms ?? '').padStart(5)}ms${newest}${r.note ? `  └─ ${r.note}` : ''}`
    );
  }
  console.log(
    `  ${'─'.repeat(96)}\n  ${healthy}/${live.length} probed feeds healthy · ${stale.length} low-frequency (reported, not failing) · ${feeds.length} in catalog · ${results.length - live.length} skipped`
  );
  if (problems.length) {
    console.log(`\n  ${ICONS.bad} ${problems.length} problem(s):`);
    for (const p of problems) console.log(`      ${p}`);
    process.exit(1);
  }
  console.log(`\n  ${ICONS.ok} catalog healthy: every url parses, every host allowlisted, every probe returns items\n`);
}

main().catch((e) => {
  console.error('audit-rss-catalog failed:', e);
  process.exit(2);
});
