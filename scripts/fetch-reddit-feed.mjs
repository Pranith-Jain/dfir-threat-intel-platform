import { writeFileSync } from 'node:fs';

// Writes the built feed to reddit-feed.json. The GitHub workflow publishes that
// file to the `reddit-feed-data` branch and the Worker reads it from GitHub
// raw — no Cloudflare KV / API token involved.
const OUT_FILE = 'reddit-feed.json';

// Keep in sync with api/src/routes/reddit-feed.ts
const SUBS = [
  {
    name: 'netsec',
    label: 'r/netsec',
    blurb: 'Practical netsec — research, advisories, deep-dives',
    topic: 'research',
  },
  { name: 'cybersecurity', label: 'r/cybersecurity', blurb: 'General cybersec news + career', topic: 'news' },
  { name: 'blueteamsec', label: 'r/blueteamsec', blurb: 'Defensive security — DFIR, hunting, IR', topic: 'blue-team' },
  { name: 'redteamsec', label: 'r/redteamsec', blurb: 'Red team tradecraft + offensive research', topic: 'red-team' },
  { name: 'AskNetsec', label: 'r/AskNetsec', blurb: 'Q&A — practical netsec problems', topic: 'help' },
  { name: 'Malware', label: 'r/Malware', blurb: 'Malware analysis + reverse engineering', topic: 'malware' },
  {
    name: 'ReverseEngineering',
    label: 'r/ReverseEngineering',
    blurb: 'RE — IDA, Ghidra, binary internals, CTFs',
    topic: 'malware',
  },
  {
    name: 'computerforensics',
    label: 'r/computerforensics',
    blurb: 'Digital forensics — disk, memory, mobile, cloud',
    topic: 'blue-team',
  },
  { name: 'OSINT', label: 'r/OSINT', blurb: 'Open-source intelligence tradecraft', topic: 'osint' },
  { name: 'threatintel', label: 'r/threatintel', blurb: 'CTI — actors, campaigns, IOCs', topic: 'research' },
  {
    name: 'crowdstrike',
    label: 'r/crowdstrike',
    blurb: 'CrowdStrike Falcon user community, detections',
    topic: 'blue-team',
  },
  {
    name: 'AzureSentinel',
    label: 'r/AzureSentinel',
    blurb: 'Microsoft Sentinel — KQL hunts, content packs',
    topic: 'blue-team',
  },
  {
    name: 'Scams',
    label: 'r/Scams',
    blurb: 'Largest scam-victim community — fresh-scam reporting + advice',
    topic: 'scams',
  },
  {
    name: 'IdentityTheft',
    label: 'r/IdentityTheft',
    blurb: 'ID theft + credit-card-fraud victim reports, recovery tradecraft',
    topic: 'scams',
  },
  {
    name: 'phishing',
    label: 'r/phishing',
    blurb: 'Phishing-campaign samples + analysis · educator-friendly',
    topic: 'scams',
  },
  {
    name: 'scambait',
    label: 'r/scambait',
    blurb: 'Scam-baiting community — surfaces fresh fraud playbooks + tactics in real-time',
    topic: 'scams',
  },
];

const CONCURRENCY = 1;
const MAX_POSTS_PER_SUB = 100;
const MAX_POST_AGE_DAYS = 7;
const MAX_TEXT_LEN = 400;
const FETCH_TIMEOUT_MS = 15_000;
// Pacing between subreddits.
//
// Was 45s, which made a full pass arithmetically impossible: 15 gaps x 45s
// = 11.25 min of sleeping against a 14 min MAX_RUN_MS, leaving 10.3s per sub
// while FETCH_TIMEOUT_MS alone is 15s. Any single slow response or 429 blew the
// budget, so runs stopped at 8 of 16 subs and published
// "time budget reached - publishing partial feed". r/Scams, r/phishing,
// r/scambait and the r/* forensics set were never reaching the feed at all.
//
// 20s keeps deliberate spacing while fitting the whole list inside the budget
// with room for slow responses: 15 gaps x 20s = 5 min of pacing, leaving ample
// time inside the 20-min ceiling even with 429 cooldowns. Deliberately not
// lower — measured while adding subreddits, Reddit returned 429 within a few
// requests at 18s spacing from a single host, so the aggressive end of the
// range trades completeness for throttling.
//
// The 429 defences below are unchanged and still carry the load if Reddit does
// throttle: per-sub Retry-After honouring, one retry with exponential backoff,
// a 90s cooldown, and MASS_THROTTLE_ABORT_AFTER which bails out and leaves the
// last-good feed on the branch rather than overwriting it with a truncated one.
const DELAY_BETWEEN_MS = 20_000;
const MAX_RETRIES = 1;
const RETRY_BASE_MS = 90_000;
const COOLDOWN_MS = 90_000;
// If the first few subs ALL 429, the runner IP is throttled by Reddit as a
// whole (shared GitHub runner pool). Abort fast instead of grinding through
// every sub and burning the run — the last-good feed stays on the branch.
const MASS_THROTTLE_ABORT_AFTER = 3;
// Hard ceiling for a run. A partially-throttled IP (some subs 429 with long
// cooldowns) can grind past every sane window; publish what we have instead.
// Raised 14 -> 20 min. The workflow runs every 30 min on a GitHub runner with
// a 6h default timeout, so there is ample headroom — at 12s pacing the full 16
// subs take ~4 min of wall clock, leaving the ceiling as a real backstop for a
// throttled IP rather than a constraint that truncates a healthy run.
const MAX_RUN_MS = 20 * 60_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Time-slot rotation of the fetch order.
 *
 * When Reddit throttles the runner the run hits MAX_RUN_MS and publishes a
 * partial feed — but with a FIXED order that partial feed is always the same
 * prefix, so the tail subs (r/threatintel, r/Scams, r/phishing, r/scambait and
 * the forensics set) were never fetched at all: every published feed listed
 * exactly the same first 8-9 subs. Rotating the start offset per 30-minute
 * slot (the workflow's cron interval) means consecutive runs truncate at a
 * different point, so within a couple of runs every sub gets fetched early
 * enough for its posts to reach the branch.
 */
const SLOT_MS = 30 * 60_000;

function rotatedSubs(now = Date.now()) {
  const offset = Math.floor(now / SLOT_MS) % SUBS.length;
  return [...SUBS.slice(offset), ...SUBS.slice(0, offset)];
}

function normalizeTopic(t) {
  if (!['news', 'research', 'red-team', 'blue-team', 'osint', 'malware', 'help', 'scams'].includes(t)) {
    return 'news';
  }
  return t;
}

function stripHtml(s) {
  if (!s) return '';
  const withBreaks = s.replace(/<br\s*\/?>/gi, '\n').replace(/<p[^>]*>/gi, '\n');
  return withBreaks.replace(/<[^>]+>/g, '').trim();
}

function parseFeedItems(xml, spec) {
  const items = [];
  const isAtom = xml.includes('<feed') && xml.includes('xmlns="http://www.w3.org/2005/Atom"');

  if (isAtom) {
    const entryRegex = /<entry>([\s\S]*?)<\/entry>/gi;
    let m;
    while ((m = entryRegex.exec(xml)) !== null) {
      const block = m[1];
      const get = (tag) => {
        const r = new RegExp(`<${tag}[^>]*>(.*?)</${tag}>`, 'is');
        const x = r.exec(block);
        return x ? x[1].trim() : '';
      };
      const title = get('title');
      const pubDate = get('published') || get('updated');
      const linkMatch = /<link[^>]*href="([^"]*)"/.exec(block);
      const link = linkMatch ? linkMatch[1] : '';
      const authorMatch = /<author>[\s\S]*?<name>(.*?)<\/name>[\s\S]*?<\/author>/i.exec(block);
      const author = authorMatch ? authorMatch[1].trim() : '';
      let content = get('content') || get('summary');
      content = stripHtml(content);

      if (!title || !link || !pubDate) continue;

      const cutoff = Date.now() - MAX_POST_AGE_DAYS * 86_400_000;
      const t = Date.parse(pubDate);
      if (!Number.isFinite(t) || t < cutoff) continue;

      items.push({
        sub: spec.name,
        sub_label: spec.label,
        sub_topic: normalizeTopic(spec.topic),
        sub_blurb: spec.blurb,
        title: title.slice(0, 240),
        link,
        pub_date: new Date(pubDate).toISOString(),
        text: content.slice(0, MAX_TEXT_LEN),
        author,
      });
    }
  } else {
    const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
    let m;
    while ((m = itemRegex.exec(xml)) !== null) {
      const block = m[1];
      const get = (tag) => {
        const r = new RegExp(`<${tag}[^>]*>(.*?)</${tag}>`, 'is');
        const x = r.exec(block);
        return x ? x[1].trim() : '';
      };
      const title = get('title');
      const pubDate = get('pubDate');
      const link = get('link');
      const author = (get('author') || get('dc:creator')).replace(/^\/u\//, '');
      let content = get('content:encoded') || get('description');
      content = stripHtml(content);

      if (!title || !link || !pubDate) continue;

      const cutoff = Date.now() - MAX_POST_AGE_DAYS * 86_400_000;
      const t = Date.parse(pubDate);
      if (!Number.isFinite(t) || t < cutoff) continue;

      items.push({
        sub: spec.name,
        sub_label: spec.label,
        sub_topic: normalizeTopic(spec.topic),
        sub_blurb: spec.blurb,
        title: title.slice(0, 240),
        link,
        pub_date: new Date(pubDate).toISOString(),
        text: content.slice(0, MAX_TEXT_LEN),
        author,
      });
    }
  }
  return items;
}

async function fetchSub(spec) {
  const url = `https://www.reddit.com/r/${encodeURIComponent(spec.name)}/.rss?limit=${MAX_POSTS_PER_SUB}`;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const backoff = RETRY_BASE_MS * 2 ** (attempt - 1) + Math.random() * 3_000;
      console.log(`  retry ${attempt}/${MAX_RETRIES} for r/${spec.name} in ${Math.round(backoff)}ms`);
      await sleep(backoff);
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const r = await fetch(url, {
        signal: ctrl.signal,
        headers: {
          'user-agent': 'pranithjain-dfir/1.0 (RSS reader; +https://pranithjain.qzz.io)',
          accept: 'application/atom+xml, application/rss+xml, application/xml, text/xml',
        },
      });
      if (r.status === 429) {
        const retryAfter = Math.min(Number(r.headers.get('retry-after')) || 0, 300);
        const wait = retryAfter > 0 ? retryAfter * 1000 : COOLDOWN_MS + Math.random() * 30_000;
        console.log(`  r/${spec.name} 429 — Retry-After: ${retryAfter}s, cooling down ${Math.round(wait / 1000)}s`);
        await sleep(wait);
        continue;
      }
      if (!r.ok) return { ok: false, items: [], error: `HTTP ${r.status}` };
      const xml = await r.text();
      if (!xml || xml.length < 100) return { ok: false, items: [], error: 'empty response' };
      const items = parseFeedItems(xml, spec);
      return { ok: true, items };
    } catch (e) {
      if (attempt < MAX_RETRIES) continue;
      return { ok: false, items: [], error: e.message };
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, items: [], error: 'rate limited after retries' };
}

async function buildFeed() {
  const warnings = [];
  const subStatus = [];
  const allItems = [];

  const queue = rotatedSubs();
  let consecutiveFails = 0;
  const startedAt = Date.now();
  async function worker() {
    while (queue.length > 0) {
      const spec = queue.shift();
      if (!spec) return;
      const r = await fetchSub(spec);
      if (!r.ok) {
        consecutiveFails++;
        warnings.push(`could not fetch r/${spec.name} (${r.error})`);
        if (consecutiveFails >= MASS_THROTTLE_ABORT_AFTER && allItems.length === 0) {
          warnings.push('mass 429 — runner IP throttled by Reddit; aborting to keep last-good data');
          queue.length = 0; // drain: stop fetching the remaining subs
        }
      } else {
        consecutiveFails = 0;
      }
      subStatus.push({
        name: spec.name,
        label: spec.label,
        topic: normalizeTopic(spec.topic),
        ok: r.ok,
        count: r.items.length,
      });
      allItems.push(...r.items);
      if (queue.length > 0) {
        if (Date.now() - startedAt >= MAX_RUN_MS && allItems.length > 0) {
          warnings.push('time budget reached — publishing partial feed');
          queue.length = 0;
        } else {
          await sleep(DELAY_BETWEEN_MS);
        }
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  allItems.sort((a, b) => b.pub_date.localeCompare(a.pub_date));

  return {
    generated_at: new Date().toISOString(),
    subs: subStatus.sort((a, b) => a.label.localeCompare(b.label)),
    items: allItems,
    warnings,
  };
}

async function main() {
  console.log('Building Reddit feed...');
  const feed = await buildFeed();
  const liveCount = feed.items.filter((i) => i.pub_date > new Date(Date.now() - 86400000).toISOString()).length;
  console.log(`  items: ${feed.items.length} (${liveCount} from last 24h), warnings: ${feed.warnings.length}`);

  // Don't publish an empty feed — if every sub failed, keep the last-good data
  // on the branch rather than overwriting it with nothing.
  if (feed.items.length === 0) {
    console.error('Refusing to publish an empty feed (all sources failed)');
    process.exit(1);
  }

  writeFileSync(OUT_FILE, JSON.stringify(feed));
  console.log(`Wrote ${OUT_FILE} (${feed.items.length} items) — workflow will publish to reddit-feed-data branch`);
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
