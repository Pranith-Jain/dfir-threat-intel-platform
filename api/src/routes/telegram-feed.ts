import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, notFound, internalError, conflict } from '../lib/api-error';
import { requireAdmin } from '../lib/admin-auth';
import { safeNullLog, kvBulkGetText } from '../lib/safe-catch';

const CUSTOM_CHANNELS_KV_KEY = 'tg:custom-channels:v1';

// In-flight build dedup (per-colocate: module state persists across requests
// within an isolate). Keyed by the cache-key string + bump, so concurrent
// cold reads (firehose page, feed panel, queue-consumer warm) share ONE
// fetchTelegramFeed build instead of firing three parallel t.me bursts.
const inflightBuilds = new Map<string, Promise<TelegramFeedResponse>>();

/**
 * Aggregated cybersec Telegram firehose.
 *
 * Telegram exposes a server-rendered preview of any public channel at
 * `https://telegram.me/s/<handle>`. The HTML contains the latest ~20 messages
 * with timestamps, permalinks, view counts, and text — no auth, no
 * Bot API, no MTProto. This is what tg-rss services scrape internally.
 *
 * We hand-pick the channels (high signal, stable handles, public-by-design)
 * rather than letting the user point us at arbitrary handles — that
 * keeps us out of the abuse-vector business and bounds subrequest cost.
 *
 * Cost shape: each preview HTML is ~30–130 KB. With CHANNELS.length
 * fetches at CONCURRENCY parallelism, we issue N subrequests in 4 round-trips.
 * Cached 30 min — Telegram channels post at human cadence, polling more
 * often is wasteful and risks rate-limiting from Telegram's edge.
 */

const TELEGRAM_RSS_CACHE_RAW_URL =
  'https://raw.githubusercontent.com/pranithjain/portfolio/telegram-rss-cache/telegram-rss-cache.json';

const FETCH_TIMEOUT_MS = 6_000;
// Bounded live-t.me budget. The GitHub pre-baked cache is now the PRIMARY
// source (except custom channels + occasional cache misses), so live scraping
// is only ever a targeted fill-in. Keeps a cold-cache / blocked-t.me build
// inside the free-plan 50-subrequest cap instead of the old ~210+ burst.
const LIVE_FETCH_BUDGET_PER_INVOCATION = 10;
const CACHE_TTL = 75 * 60; // 75 min — over the hourly cron interval so every-other
// tick avoids re-fetching all 34+ Telegram channels and preserves subrequest
// budget for x-claims, x-feed, and reddit feed pre-warps in the same cron.
const CONCURRENCY = 8;
/** Per-channel cap. Channel HTML preview surfaces ~20 messages — keep the
 *  full preview window. Combined with the 7d cutoff below, this lifts the
 *  page from ~176 messages → up to ~440 across 22 channels with newer
 *  ones bubbling to the top naturally. */
// Per-channel cap. Bumped 20 → 50 alongside the cross-platform "show
// last 500 items OR 7 days" upgrade. Telegram's telegram.me/s/ preview view
// surfaces ~30-50 most-recent messages — 50 captures the realistic
// upstream ceiling without an extra paginated fetch.
const MAX_MESSAGES_PER_CHANNEL = 50;
/** Drop messages older than this many days. Telegram channels post at
 *  human cadence; anything older than a week is stale by the standards
 *  of a "today's intel" surface. */
// Was 7 — too tight for channels like CyberSecurityPulse / phishingradar /
// group_ib which post a few times a week. 7-day window produced "0"
// counts that read as broken when the channel was actually fine, just
// not chatty enough. 30 days surfaces a full month's signal.
const MAX_MESSAGE_AGE_DAYS = 30;
/** Truncate per-message text. Long posts (full IR write-ups) are still followable via permalink. */
const MAX_TEXT_LEN = 800;

interface ChannelSpec {
  handle: string;
  /** Display name shown in the UI. */
  name: string;
  /** What this channel covers — surfaces as a tooltip. */
  blurb: string;
  /** Pill-colour hint so the panel can colour-code by topic. */
  topic: 'malware' | 'ransomware' | 'hacktivism' | 'osint' | 'news' | 'leaks' | 'bot-monitored';
}

/**
 * Curated channel set. Each handle is liveness-probed before inclusion —
 * we only ship channels that (a) expose t.me/s/<handle> previews and
 * (b) have posted within the last ~30 days. Last verified 2026-07-27.
 *
 * Channels we used to carry but had to drop because they went silent or
 * disabled previews (kept here as a "do not re-add without re-checking"
 * audit trail): malware_traffic (Oct'25), CyberKnow20 (Oct'23),
 * FalconFeedsio (May'24), bellingcat (Jan'24), ransomwatch (no preview),
 * DDoSecrets / IntelCrab / osintfounder / cisa_alerts / krebsonsecurity
 * (preview disabled or channel removed).
 *
 * 2026-05-12 probe round (~50 handles tested) skipped because of preview
 * disabled / channel removed / stale (>30d): cve_notify, dailycve, cves,
 * CVEnew, cve_alerts, 0daytoday, 0day_today, exploit_dev, CyberNewsfeed
 * (Dec'24), cyberonews, feed_threatintel, GossiTheDog, secblog,
 * cybersecurity_alerts, cyberalerts, threatintelligence (Mar'26, just
 * past 30d), osint_lite, osintessentials (Dec'23), osintbase (Nov'22),
 * osinternational, osint_resources, osint_dose, osinttv (recent but
 * only 4 msgs in a month), osint_unlimited, dataleak_news, leaksbase,
 * databreaches_news, breach_alerts, breachalerts, hackleak, dataleakers,
 * dataleaknet, scam_alerts, scam_radar, scamalert, antiscam, cyberscams,
 * scamcheckers (Oct'22), fraud_alerts, antifraud_uk, pwn3d_labs,
 * cvepost, secalert (Dec'23), cveofficial, cvedaily, cve_news, vulninfo,
 * cyber_security_official (2022), Pwn3d, DailyDarkWeb, cybernewsoffl,
 * darkwebnews (Feb'25), soc_radar, lookcyber, threatpost, SocRadar,
 * cybernewslive, infostealer_leaks, stealer_logs (May'24), darkfeed_io,
 * leakedsource, breachednews, dataleak_alert, leaks_news, databreachtoday.
 *
 * 2026-09-12 probe round: `breachdetect` unreachable (repeated egress 000,
 * no preview served — private or removed, do not add), `ransomwarelive`
 * 302-redirects to a join page with 0 preview messages (private or
 * preview-disabled, do not add to the preview-based firehose; ransomware.live
 * coverage already comes via the PRO API + posts.json dump).
 *
 * 2026-09-25 re-probe: `breachdetect` is REAL (27k subs, same crew as
 * CyberMonitum) but STILL serves 0 preview messages (302 → join page;
 * siblings CVEDetector/CyberMonitum served 20/20 the same minute). It
 * stays out of CHANNELS below — instead it syncs via the MTProto
 * sidecar (scripts/sync-telegram-mtproto.mjs → KV `tg:bot-posts:*`,
 * docs/telegram-mtproto-sidecar.md), which renders as `[Bot]
 * breachdetect` with no code change here.
 *
 * Carding-specific channels were INTENTIONALLY skipped. Public carding
 * channels on Telegram are almost exclusively vendor channels promoting
 * stolen-card sales, not defensive research. Surfacing them on a security
 * portfolio site would carry legal and ethical risk. Phishing / scam
 * warning channels (phishingradar below) are the closest defensive proxy.
 */
const CHANNELS: ChannelSpec[] = [
  // Malware research
  {
    handle: 'vxunderground',
    name: 'vx-underground',
    blurb: 'Malware-source archive + threat-actor commentary',
    topic: 'malware',
  },
  {
    handle: 'androidmalware',
    name: 'Android Malware',
    blurb: 'Daily Android-malware sample drops + analysis',
    topic: 'malware',
  },
  // Threat intel / CTI feeds
  { handle: 'secharvester', name: 'SecHarvester', blurb: 'High-volume threat-intel firehose', topic: 'leaks' },
  { handle: 'group_ib', name: 'Group-IB', blurb: 'Official Group-IB threat-intel channel', topic: 'osint' },
  { handle: 'ctinow', name: 'CTI Now', blurb: 'Real-time CTI aggregator — IOCs, advisories, leaks', topic: 'osint' },
  {
    handle: 'Cyber_Ti_Reports_VN',
    name: 'Cyber TI Reports',
    blurb: 'Curated CTI report digest (multi-language)',
    topic: 'osint',
  },
  {
    handle: 'defendor_eng',
    name: 'Defendor (EN)',
    blurb: 'Defensive-CTI / IR write-ups + threat-actor tracking',
    topic: 'osint',
  },
  {
    handle: 'cyberosintosint',
    name: 'Cyber OSINT',
    blurb: 'OSINT-style cyber-news firehose',
    topic: 'osint',
  },
  {
    handle: 'CTIUpdates',
    name: 'CTI Updates',
    blurb: 'Real-time CTI feed — IOCs, threat reports, advisories',
    topic: 'osint',
  },
  // CVE / vulnerability disclosure channels (verified 2026-05-12: each has
  // 40+ recent posts and a sub-day publish cadence). Classed as 'osint'
  // because they're disclosure intelligence rather than breaking news.
  // REMOVED 2026-09-21 (serving 0 preview messages — dead or
  // preview-disabled, verified live from a non-throttled probe):
  //   - `cve0day` (was: CVE / 0day disclosure firehose)
  // `CVEDetector` was on that removal list and is now BACK (re-verified live
  // 2026-10-01: 20 preview messages, sub-hour cadence). The 09-21 call was
  // correct then and stale now — it also feeds the structured CVE parser in
  // cve-tg-parser.ts, so removal here would silently starve that tier.
  // Do NOT re-add cve0day without a live t.me/s/ message check.
  { handle: 'cvenotify', name: 'CVE Notify', blurb: 'High-cadence CVE alerts (NVD-style)', topic: 'osint' },
  {
    handle: 'cvedetector',
    name: 'CVE Detector',
    blurb: 'Structured CVE alerts with publish timestamps (20 recent posts, sub-hour cadence)',
    topic: 'osint',
  },
  {
    handle: 'cvefeed',
    name: 'CVE & Vulnerability RSS',
    blurb: 'CVE / vulnerability RSS aggregator',
    topic: 'osint',
  },
  // CVE / breach community channels (verified 2026-09-12, t.me/s/ preview
  // message counts in parentheses). Classed as 'osint' — disclosure
  // intelligence rather than breaking news.
  {
    handle: 'CyberMonitum',
    name: 'Cyber Monitum',
    blurb: 'Threat-intel + cyber-sec digest (20 recent posts, sub-day cadence)',
    topic: 'osint',
  },
  {
    handle: 'DWI_CVE_Alerts',
    name: 'DWI CVE Alerts',
    blurb: 'Dark Web Informer CVE alerts (20 recent posts, sub-day cadence)',
    topic: 'osint',
  },
  // Vendor-backed CTI news (Telefónica Tech). Daily volume, English-language.
  {
    handle: 'CyberSecurityPulse',
    name: 'CyberSecurityPulse',
    blurb: 'Telefónica Tech daily CTI pulse — incidents, advisories, research',
    topic: 'news',
  },
  // Phishing / scam warnings. German-language but covers global brands.
  {
    handle: 'phishingradar',
    name: 'Phishing Radar',
    blurb: 'Phishing + scam warnings (DE) — brand-impersonation alerts',
    topic: 'news',
  },
  // Spanish-language multi-source CTI firehose. Posts "🚨 ALERTA CVE 🚨"
  // and "🚨🚨 ALERTA RANSOMWARE 🚨🚨" templates with structured fields
  // (Víctima / Grupo / País / Web / Descripción). Verified 2026-05-12: 40
  // recent posts, today's last activity. Same publisher backs a broader
  // CTI dashboard (leaks / darknet / negotiations / malware samples).
  {
    handle: 'mythreatintel',
    name: 'My Threat Intel',
    blurb: 'Spanish CTI firehose — CVE + ransomware-victim alerts',
    topic: 'osint',
  },
  // Breach / leak / ransomware feeds — both replacements verified live
  // 2026-05-23 (20 posts each in t.me/s/ preview):
  //   - `dataleak`   was a low-quality repost channel (mixed signal, drama).
  //   - `leakradar_io` went dead (0 posts in the preview view).
  // FalconFeeds and RansomLook are defensive-CTI publishers with stable
  // posting cadence and structured fields (victim / group / dates).
  {
    handle: 'falconfeedsio',
    name: 'FalconFeeds.io',
    blurb: 'Official FalconFeeds — ransomware victim tracker + breach announcements',
    topic: 'leaks',
  },
  {
    handle: 'RansomLook',
    name: 'RansomLook',
    blurb: 'Ransomware operator tracker — group claims, victims, leak-site activity',
    topic: 'leaks',
  },
  // Breach / FBI-watch feeds (verified 2026-09-12, t.me/s/ preview counts
  // in parentheses). Dark Web Informer family + DARKFEED victim-news +
  // Brut Security (FR breach/vuln news).
  {
    handle: 'FBI_Watchdog',
    name: 'FBI Watchdog',
    blurb: 'FBI Watchdog alerts by Dark Web Informer (20 recent posts)',
    topic: 'leaks',
  },
  {
    handle: 'DarkfeedNews',
    name: 'DARKFEED',
    blurb: 'DARKFEED ransomware-victim + breach news (20 recent posts)',
    topic: 'leaks',
  },
  {
    handle: 'brutsecurity',
    name: 'Brut Security',
    blurb: 'Brut Security breach/vuln news, French-language (19 recent posts)',
    topic: 'news',
  },
  // News mirrors (cyberscoop REMOVED 2026-09-21: t.me/s/ 302-redirects to a
  // join page with 0 preview messages — preview-disabled; do not re-add
  // without a live t.me/s/ message check).
  { handle: 'BleepingComputer', name: 'BleepingComputer', blurb: 'Breaking incident news', topic: 'news' },
  { handle: 'TheHackerNews', name: 'The Hacker News', blurb: 'Security news headlines', topic: 'news' },
  {
    handle: 'cyber_security_channel',
    name: 'Cyber Security Channel',
    blurb: 'High-volume security-news aggregator',
    topic: 'news',
  },
  // Bug-bounty / offensive research
  {
    handle: 'dailybountywriteup',
    name: 'Daily Bounty Writeup',
    blurb: 'Curated bug-bounty write-ups + disclosed vuln reports',
    topic: 'osint',
  },
  // Intelligence digests
  {
    handle: 'threatinteltrends',
    name: 'CTT CTI Trends',
    blurb: 'Community-driven CTI trends — threat actor tracking, campaign intel, and curated security news',
    topic: 'osint',
  },
  // International Cyber Digest (verified 2026-09-12: 11 recent posts,
  // daily cadence) — cross-source cyber-incident digest.
  {
    handle: 'IntCyberDigest',
    name: 'International Cyber Digest',
    blurb: 'International cyber-incident digest (11 recent posts, daily cadence)',
    topic: 'osint',
  },
  // Malware analysis — partner channel of CVE Notify, verified 20+ recent msgs
  {
    handle: 'malwr',
    name: 'Malware Analysis',
    blurb: 'Malware analysis reports, sample drops, and reverse-engineering write-ups',
    topic: 'malware',
  },
  // CTI watch — curated threat intelligence firehose
  {
    handle: 'ctiwatch',
    name: 'CTI Watch',
    blurb: 'Curated threat intelligence watch — IOCs, TTPs, and incident tracking',
    topic: 'osint',
  },
  // FSEC INTELS — threat intelligence firehose (IOCs, breach/leak alerts, actor tracking)
  {
    handle: 'FSECINTELES2',
    name: 'FSEC Intel',
    blurb: 'FSEC threat-intelligence firehose — IOCs, breach alerts, and actor tracking',
    topic: 'osint',
  },
];

interface ParsedMessage {
  permalink: string;
  datetime: string;
  views?: string;
  text: string;
}

export interface TelegramFeedItem {
  channel_handle: string;
  channel_name: string;
  channel_topic: ChannelSpec['topic'];
  channel_blurb: string;
  permalink: string;
  /** ISO 8601 from Telegram's <time datetime>. */
  datetime: string;
  /** Truncated, plain-text. Permalink for full content + media. */
  text: string;
  /** Telegram's display string (e.g. "3.6K", "12K"). Optional. */
  views?: string;
}

/** Fingerprint for cross-channel duplicate detection: lowercase alphanumeric
 *  fold of the first 200 chars. Two items are duplicates when they share a
 *  fingerprint (same syndicated copy) — the longer text wins (more complete).
 *  Short stubs (<30 chars after folding) never fuzzy-match: generic one-liner
 *  reactions ("🔥", "+1") from different channels about different stories
 *  must not merge. Exact permalink matches always merge regardless of text. */
export function fingerprintItemText(text: string): string | null {
  const folded = text
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, ' ')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
  return folded.length >= 30 ? folded : null;
}

/** Drop duplicate feed items: same permalink, or same text fingerprint across
 *  channels (syndicated copies). Returns the deduped list + removal count. */
export function dedupeFeedItems(items: TelegramFeedItem[]): { items: TelegramFeedItem[]; removed: number } {
  const seenPermalinks = new Set<string>();
  const seenPrints = new Map<string, number>();
  const out: TelegramFeedItem[] = [];
  let removed = 0;
  for (const item of items) {
    if (seenPermalinks.has(item.permalink)) {
      removed += 1;
      continue;
    }
    const print = fingerprintItemText(item.text);
    if (print !== null) {
      const prevIdx = seenPrints.get(print);
      if (prevIdx !== undefined) {
        // Duplicate syndicated copy — keep the longer (more complete) text.
        if (item.text.length > out[prevIdx]!.text.length) {
          seenPermalinks.delete(out[prevIdx]!.permalink);
          seenPermalinks.add(item.permalink);
          out[prevIdx] = item;
        }
        removed += 1;
        continue;
      }
      seenPrints.set(print, out.length);
    }
    seenPermalinks.add(item.permalink);
    out.push(item);
  }
  return { items: out, removed };
}

export interface ChannelQuality {
  /** 0-100. Combined score; higher = healthier signal-to-noise. */
  score: number;
  /** What we used to compute the score — exposed so the UI can show the math. */
  signals: {
    /** Share of messages within the last 30d. Stale channels drag this down. */
    recent_pct: number;
    /** Share of messages whose text duplicates another in the same window. */
    dupe_pct: number;
    /** Median text length across messages — proxy for content depth. */
    median_text_len: number;
    /** Posts per day across the message window (rolling, days-since-oldest basis). */
    posts_per_day: number;
  };
}

export interface TelegramFeedResponse {
  generated_at: string;
  channels: {
    handle: string;
    name: string;
    topic: string;
    ok: boolean;
    count: number;
    quality?: ChannelQuality;
  }[];
  items: TelegramFeedItem[];
  /** Cross-channel/permalink duplicates collapsed before sort. Optional so
   *  older cached payloads (built before dedup) still typecheck. */
  duplicates_removed?: number;
  warnings: string[];
}

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

async function fetchWithRetry(url: string): Promise<string | null> {
  // 2 attempts max, 6s each, with a short gap — 3×12s back-to-back was exactly
  // the burst Telegram's edge throttles, and with GitHub-first the live scrape
  // only runs for channels that miss the pre-baked cache, so every attempt
  // counts against the bounded LIVE_FETCH_BUDGET.
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 350));
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const ua =
        attempt === 0 ? 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0; +https://pranithjain.qzz.io)' : BROWSER_UA;
      const fetchUrl = attempt >= 1 ? `${url}${url.includes('?') ? '&' : '?'}_=${Date.now()}` : url;
      const r = await fetch(fetchUrl, {
        signal: ctrl.signal,
        headers: {
          accept: 'text/html,application/xhtml+xml',
          'accept-language': 'en-US,en;q=0.9',
          'user-agent': ua,
        },
        redirect: 'follow',
      });
      clearTimeout(timer);
      if (!r.ok) continue;
      const text = await r.text();
      if (!text.includes('tgme_widget_message_wrap')) continue;
      return text;
    } catch (_catchErr) {
      logError('fetchHtml attempt failed', _catchErr);
      clearTimeout(timer);
    }
  }
  return null;
}

export async function fetchHtml(url: string): Promise<string | null> {
  const result = await fetchWithRetry(url);
  if (!result) {
    logError('fetchHtml failed', new Error('all attempts failed for URL (telegram.me may be on hold)'));
  }
  return result;
}

const RSS_BRIDGES = [
  (handle: string) => `https://tg.i-c-a.su/rss/channel/${encodeURIComponent(handle)}`,
  (handle: string) => `https://rsshub.app/telegram/channel/${encodeURIComponent(handle)}`,
];

async function fetchRssFeed(handle: string): Promise<ParsedMessage[] | null> {
  for (const buildUrl of RSS_BRIDGES) {
    try {
      const url = buildUrl(handle);
      const r = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; pranithjain-dfir/1.0)',
          accept: 'application/rss+xml, application/xml, text/xml',
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!r.ok) continue;
      const xml = await r.text();
      if (!xml.includes('<item>')) continue;
      const msgs = parseRssToMessages(xml);
      if (msgs.length > 0) return msgs;
    } catch {
      continue;
    }
  }
  return null;
}

function parseRssToMessages(xml: string): ParsedMessage[] {
  const items: ParsedMessage[] = [];
  const blocks = xml.split('<item>').slice(1);
  for (const block of blocks) {
    const content = block.split('</item>')[0];
    if (!content) continue;
    const link = /<link>(.*?)<\/link>/.exec(content)?.[1];
    if (!link) continue;
    const pubDate = /<pubDate>(.*?)<\/pubDate>/.exec(content)?.[1];
    const description =
      /<description><!\[CDATA\[(.*?)\]\]><\/description>/.exec(content)?.[1] ||
      /<description>(.*?)<\/description>/.exec(content)?.[1];
    const title =
      /<title><!\[CDATA\[(.*?)\]\]><\/title>/.exec(content)?.[1] || /<title>(.*?)<\/title>/.exec(content)?.[1];

    let text = (description || title || '').replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '');
    text = text
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
    if (text.length > MAX_TEXT_LEN) text = text.slice(0, MAX_TEXT_LEN - 1) + '…';

    const datetime = pubDate ? new Date(pubDate).toISOString() : '';
    items.push({ permalink: link, datetime, views: undefined, text });
  }
  const cutoff = Date.now() - MAX_MESSAGE_AGE_DAYS * 86_400_000;
  return items.filter((m) => new Date(m.datetime).getTime() >= cutoff).slice(0, MAX_MESSAGES_PER_CHANNEL);
}

/**
 * Decode the tiny subset of HTML entities that appear in Telegram message
 * text. Telegram only emits these five via their preview renderer.
 */
function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

function stripHtml(s: string): string {
  // Convert <br> to newline so we don't run lines together.
  const withBreaks = s.replace(/<br\s*\/?>/gi, '\n');
  // Drop everything else.
  return decodeEntities(withBreaks.replace(/<[^>]+>/g, '')).trim();
}

export function parseChannelHtml(html: string): ParsedMessage[] {
  // Split on the wrapper boundary — each block is one message.
  // Use a sentinel to mark boundaries, then split, since JS regex lacks lookbehind in older engines.
  const SENTINEL = 'TGMSG';
  const marked = html.replace(
    /<div class="tgme_widget_message_wrap/g,
    SENTINEL + '<div class="tgme_widget_message_wrap'
  );
  const blocks = marked.split(SENTINEL).slice(1);

  const out: ParsedMessage[] = [];
  for (const block of blocks) {
    const permalink = /<a class="tgme_widget_message_date"[^>]*href="([^"]+)"/.exec(block)?.[1];
    const datetime = /datetime="([^"]+)"/.exec(block)?.[1];
    const views = /tgme_widget_message_views"[^>]*>([^<]+)/.exec(block)?.[1]?.trim();
    const textBlock = /<div[^>]*class="[^"]*tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)<\/div>/i.exec(block)?.[1];
    if (!permalink || !datetime) continue;
    let text = textBlock ? stripHtml(textBlock) : '';
    if (text.length > MAX_TEXT_LEN) text = text.slice(0, MAX_TEXT_LEN - 1) + '…';
    out.push({ permalink, datetime, views, text });
  }
  // Telegram renders oldest-first. Filter to the last MAX_MESSAGE_AGE_DAYS
  // window, then keep the newest MAX_MESSAGES_PER_CHANNEL — newest first.
  const cutoff = Date.now() - MAX_MESSAGE_AGE_DAYS * 86_400_000;
  const fresh = out.filter((m) => {
    const t = Date.parse(m.datetime);
    return Number.isFinite(t) && t >= cutoff;
  });
  // If a channel went silent for >7d we still want SOMETHING surfaced;
  // fall back to the latest few raw messages so the channel isn't dropped
  // entirely from the panel.
  const pool = fresh.length > 0 ? fresh : out;
  return pool.slice(-MAX_MESSAGES_PER_CHANNEL).reverse();
}

/**
 * Compute a 0-100 quality score for a channel from its recent messages.
 *
 * The four signals:
 *   - recent_pct  → fraction posted in last 30d (dead channels drop sharply)
 *   - dupe_pct    → fraction of msgs whose text matches another (spam/repost)
 *   - median_len  → content depth proxy; <50 chars is "title-only" noise
 *   - posts/day   → cadence sanity; both <0.05 and >25 are penalized
 *
 * Each signal feeds a sub-score in [0,1]; we average them and scale to 100.
 * The intent is decision-support — a channel scoring 35 should be sorted
 * below one scoring 80, but we don't drop it from the firehose entirely.
 */
function scoreChannel(messages: ParsedMessage[]): ChannelQuality {
  if (messages.length === 0) {
    return {
      score: 0,
      signals: { recent_pct: 0, dupe_pct: 0, median_text_len: 0, posts_per_day: 0 },
    };
  }

  const now = Date.now();
  const recentMs = 30 * 24 * 3600 * 1000;
  let recent = 0;
  const lengths: number[] = [];
  const normalized = new Map<string, number>();
  const timestamps: number[] = [];

  for (const m of messages) {
    const t = Date.parse(m.datetime);
    if (Number.isFinite(t)) {
      timestamps.push(t);
      if (now - t <= recentMs) recent += 1;
    }
    const len = (m.text ?? '').length;
    lengths.push(len);
    const key = (m.text ?? '').toLowerCase().replace(/\s+/g, ' ').trim();
    if (key) normalized.set(key, (normalized.get(key) ?? 0) + 1);
  }

  const recentPct = recent / messages.length;

  // Dupes: any text appearing >1× contributes (count - 1) to dupe count.
  let dupes = 0;
  for (const c of normalized.values()) if (c > 1) dupes += c - 1;
  const dupePct = dupes / messages.length;

  lengths.sort((a, b) => a - b);
  const medianLen = lengths[Math.floor(lengths.length / 2)] ?? 0;

  // posts/day across the message window: oldest→newest delta.
  let postsPerDay = 0;
  if (timestamps.length >= 2) {
    timestamps.sort((a, b) => a - b);
    const spanDays = Math.max(0.5, (timestamps[timestamps.length - 1]! - timestamps[0]!) / (24 * 3600 * 1000));
    postsPerDay = messages.length / spanDays;
  }

  // Sub-scores
  const sRecent = recentPct;
  const sDupe = 1 - Math.min(1, dupePct * 2); // penalize duplicates aggressively
  const sLen = Math.min(1, medianLen / 200); // 200 chars ≈ a good post body
  // Cadence: ideal 0.3 → 15 posts/day. Below 0.05 = dead; above 25 = firehose.
  let sCadence: number;
  if (postsPerDay <= 0.05) sCadence = 0;
  else if (postsPerDay >= 25) sCadence = 0.3;
  else if (postsPerDay < 0.3) sCadence = postsPerDay / 0.3;
  else if (postsPerDay <= 15) sCadence = 1;
  else sCadence = 1 - (postsPerDay - 15) / 10; // taper 15 → 25

  const score = Math.round(((sRecent + sDupe + sLen + sCadence) / 4) * 100);

  return {
    score,
    signals: {
      recent_pct: Math.round(recentPct * 100),
      dupe_pct: Math.round(dupePct * 100),
      median_text_len: medianLen,
      posts_per_day: Math.round(postsPerDay * 10) / 10,
    },
  };
}

/**
 * Bot-API update schema (subset needed for channel messages).
 * Telegram Bot API returns channel posts when the bot is admin of the channel.
 */
interface BotApiUpdate {
  update_id: number;
  channel_post?: {
    message_id: number;
    chat: { id: number; username?: string; title: string; type: string };
    date: number;
    text?: string;
    caption?: string;
    reply_to_message?: { text?: string };
    forward_from_chat?: { username?: string };
  };
}

/**
 * Poll the Telegram Bot API `getUpdates` endpoint, storing channel messages
 * in KV so `fetchTelegramFeed` can read them as a fallback when t.me is down.
 *
 * Call from the 30-min cron alongside pre-warm. Idempotent; stores at most
 * the latest 50 messages per channel.
 */
export async function pollBotUpdates(env: Env): Promise<void> {
  if (!env.TELEGRAM_BOT_TOKEN || !env.KV_CACHE) return;
  const kv = env.KV_CACHE;

  const offsetStr = await kv.get('tg:bot-offset').catch(() => null);
  const offset = offsetStr ? parseInt(offsetStr, 10) : undefined;

  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates?timeout=3${
    offset ? `&offset=${offset}` : ''
  }`;
  const r = await fetch(url, { signal: AbortSignal.timeout(15_000) }).catch((e) => {
    logError('tg-bot-poll fetch_failed', e);
    return null;
  });
  if (!r || !r.ok) {
    return;
  }

  const data = (await r.json().catch(() => null)) as { ok: boolean; result?: BotApiUpdate[] } | null;
  if (!data?.ok || !data?.result?.length) return;

  let maxId = offset ?? 0;
  const byChat = new Map<string, BotApiUpdate['channel_post'][]>();

  for (const u of data.result) {
    if (u.update_id > maxId) maxId = u.update_id + 1;
    if (!u.channel_post?.chat) continue;
    if (u.channel_post.chat.type !== 'channel') continue;
    const cid = String(u.channel_post.chat.id);
    if (!byChat.has(cid)) byChat.set(cid, []);
    byChat.get(cid)!.push(u.channel_post);
  }

  // Build handle→chat_id mapping from channels that have a username.
  // This is what lets fetchFromBotApiCache look up messages by t.me handle.
  const existingMap = await getBotChannelMap(kv);
  let mapChanged = false;
  for (const [cid, posts] of byChat) {
    const first = posts[0];
    if (first?.chat?.username) {
      const handle = first.chat.username.toLowerCase();
      if (existingMap.get(handle) !== Number(cid)) {
        existingMap.set(handle, Number(cid));
        mapChanged = true;
      }
    }
    const raw = await kv.get(`tg:bot-posts:${cid}`).catch(() => null);
    const existing: BotApiUpdate['channel_post'][] = raw ? JSON.parse(raw) : [];
    const merged = [...existing, ...posts].slice(-50);
    await kv.put(`tg:bot-posts:${cid}`, JSON.stringify(merged), { expirationTtl: 172_800 });
  }
  if (mapChanged) {
    await kv.put(BOT_CHANNEL_MAP_KEY, JSON.stringify(Object.fromEntries(existingMap)));
  }

  if (maxId > (offset ?? 0)) {
    await kv.put('tg:bot-offset', String(maxId));
  }
}

/** Poll bot updates and return a result object (for manual trigger UI). */
export async function pollBotUpdatesWithResult(env: Env): Promise<{
  ok: boolean;
  updates_processed: number;
  channels_updated: number;
  error?: string;
}> {
  if (!env.TELEGRAM_BOT_TOKEN)
    return { ok: false, updates_processed: 0, channels_updated: 0, error: 'TELEGRAM_BOT_TOKEN not set' };
  if (!env.KV_CACHE) return { ok: false, updates_processed: 0, channels_updated: 0, error: 'KV_CACHE not available' };
  const kv = env.KV_CACHE;

  const offsetStr = await kv.get('tg:bot-offset').catch(() => null);
  const offset = offsetStr ? parseInt(offsetStr, 10) : undefined;

  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates?timeout=3${offset ? `&offset=${offset}` : ''}`;
  const r = await fetch(url, { signal: AbortSignal.timeout(15_000) }).catch(() => null);
  if (!r || !r.ok)
    return { ok: false, updates_processed: 0, channels_updated: 0, error: `HTTP ${r?.status ?? 'fetch failed'}` };

  const data = (await r.json().catch(() => null)) as { ok: boolean; result?: BotApiUpdate[] } | null;
  if (!data?.ok || !data?.result?.length) return { ok: true, updates_processed: 0, channels_updated: 0 };

  let maxId = offset ?? 0;
  const byChat = new Map<string, BotApiUpdate['channel_post'][]>();
  for (const u of data.result) {
    if (u.update_id > maxId) maxId = u.update_id + 1;
    if (!u.channel_post?.chat) continue;
    if (u.channel_post.chat.type !== 'channel') continue;
    const cid = String(u.channel_post.chat.id);
    if (!byChat.has(cid)) byChat.set(cid, []);
    byChat.get(cid)!.push(u.channel_post);
  }

  const existingMap = await getBotChannelMap(kv);
  let channelsUpdated = 0;
  for (const [cid, posts] of byChat) {
    const first = posts[0];
    if (first?.chat?.username) {
      const handle = first.chat.username.toLowerCase();
      if (existingMap.get(handle) !== Number(cid)) {
        existingMap.set(handle, Number(cid));
        channelsUpdated++;
      }
    }
    const raw = await kv.get(`tg:bot-posts:${cid}`).catch(() => null);
    const existing: BotApiUpdate['channel_post'][] = raw ? JSON.parse(raw) : [];
    const merged = [...existing, ...posts].slice(-50);
    await kv.put(`tg:bot-posts:${cid}`, JSON.stringify(merged), { expirationTtl: 172_800 });
  }
  if (channelsUpdated > 0) {
    await kv.put(BOT_CHANNEL_MAP_KEY, JSON.stringify(Object.fromEntries(existingMap)));
  }
  if (maxId > (offset ?? 0)) {
    await kv.put('tg:bot-offset', String(maxId));
  }

  return { ok: true, updates_processed: data.result.length, channels_updated: channelsUpdated };
}

/** Mapping between Telegram chat IDs and known channel handles, stored in KV. */
const BOT_CHANNEL_MAP_KEY = 'tg:bot-channel-map';

/** Read the bot channel map from KV — maps t.me handles → numeric chat IDs. */
async function getBotChannelMap(kv: KVNamespace): Promise<Map<string, number>> {
  try {
    const raw = await kv.get(BOT_CHANNEL_MAP_KEY);
    if (!raw) return new Map();
    return new Map(Object.entries(JSON.parse(raw)));
  } catch {
    return new Map();
  }
}

/**
 * Try reading a channel's messages from the Bot-API KV cache.
 * Returns null if no Bot API data exists for the handle's chat ID.
 *
 * `channelMap` is passed in rather than loaded here on purpose. This function
 * runs once per channel inside the fetch loops, and KV read quota is billed
 * per key on the free plan (100k/day), so re-reading `tg:bot-channel-map`
 * inside it cost one billed read per channel per build — the same key,
 * fetched ~32x, twice over (once in each of the two bot-cache loops). The
 * callers already load the map once, so it is threaded through instead.
 */
async function fetchFromBotApiCache(
  kv: KVNamespace,
  handle: string,
  channelMap: Map<string, number>
): Promise<ParsedMessage[] | null> {
  const chatId = channelMap.get(handle) ?? channelMap.get(handle.toLowerCase());
  if (!chatId) return null;

  try {
    const raw = await kv.get(`tg:bot-posts:${chatId}`);
    if (!raw) return null;
    const posts: BotApiUpdate['channel_post'][] = JSON.parse(raw);
    if (!posts.length) return null;

    return posts
      .filter((p): p is NonNullable<BotApiUpdate['channel_post']> => p != null)
      .map((p) => ({
        permalink: `https://t.me/${handle}/${p.message_id}`,
        datetime: new Date(p.date * 1000).toISOString(),
        views: undefined,
        text: (p.text || p.caption || '').slice(0, MAX_TEXT_LEN),
      }));
  } catch {
    return null;
  }
}

/**
 * Pure-data fetcher exposed for /api/v1/snapshot. Returns the full payload
 * (no Response wrapping) so the snapshot handler can compose it directly
 * without a worker-internal HTTP call (which Cloudflare 522s on same-worker).
 */
export async function fetchTelegramFeed(kv?: KVNamespace, env?: Env): Promise<TelegramFeedResponse> {
  const warnings: string[] = [];
  const channelStatus: TelegramFeedResponse['channels'] = [];
  const allItems: TelegramFeedItem[] = [];

  // Merge hardcoded channels with user-added custom channels from KV
  const customChannels: ChannelSpec[] = [];
  if (kv) {
    try {
      const raw = await kv.get(CUSTOM_CHANNELS_KV_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Array<{ handle: string; name: string }>;
        for (const ch of parsed) {
          customChannels.push({
            handle: ch.handle,
            name: ch.name,
            blurb: `User-added channel: ${ch.handle}`,
            topic: 'osint',
          });
        }
      }
    } catch (_catchErr) {
      logError('fetchTelegramFeed failed', _catchErr);
      /* KV unavailable, skip custom channels */
    }
  }

  const queue = [...CHANNELS, ...customChannels];

  // Try GitHub RSS cache (pre-baked by GitHub Actions from t.me/s previews,
  // never blocked by Telegram's Cloudflare edge). Fetched once upfront so every
  // channel can fall back to it without issuing N individual requests. Now the
  // PRIMARY source — it's fresh (≤30-min-old rebake), cheap (1 subrequest) and
  // immune to the egress block that made the live fan-out blow the budget.
  // A hard timeout keeps a stalled GitHub fetch from blocking the whole build.
  let gitHubCache: Map<string, ParsedMessage[]> | undefined;
  try {
    const ghRes = await fetch(TELEGRAM_RSS_CACHE_RAW_URL, { signal: AbortSignal.timeout(8_000) });
    if (ghRes.ok) {
      const raw = (await ghRes.json()) as {
        items?: Array<{
          channel_handle: string;
          datetime: string;
          text: string;
          views?: string;
          permalink: string;
        }>;
      };
      if (raw?.items?.length) {
        gitHubCache = new Map();
        for (const item of raw.items) {
          const h = item.channel_handle;
          if (!gitHubCache.has(h)) gitHubCache.set(h, []);
          gitHubCache.get(h)!.push({
            permalink: item.permalink,
            datetime: item.datetime,
            text: item.text,
            views: item.views,
          });
        }
      }
    }
  } catch {
    /* GitHub cache unavailable — continue without it */
  }

  // Bounded live-scrape budget shared across the worker pool. When the GitHub
  // cache is present, only a handful of channels (custom adds, cache misses)
  // ever hit t.me directly — so the whole cold build stays well inside the
  // free-plan 50-subrequest cap. When the cache is entirely absent (workflow
  // hasn't rebaked yet) fall back to unbounded live scraping so the firehose
  // still builds at all.
  const liveBudget = gitHubCache && gitHubCache.size > 0 ? LIVE_FETCH_BUDGET_PER_INVOCATION : Number.MAX_SAFE_INTEGER;
  let liveUsed = 0;

  // Loaded ONCE for the whole build. fetchFromBotApiCache needs this map per
  // channel, but KV reads are billed per key on the free plan, so letting it
  // fetch the map itself meant re-reading the same `tg:bot-channel-map` key
  // once per channel — ~32 identical billed reads per build.
  const botChannelMap = kv ? await getBotChannelMap(kv) : new Map<string, number>();

  async function worker() {
    while (queue.length > 0) {
      const ch = queue.shift();
      if (!ch) return;
      let messages: ParsedMessage[] = [];
      const handle = encodeURIComponent(ch.handle);
      // 1. GitHub pre-baked cache first — zero extra subrequests per channel,
      //    never blocked by Telegram, and at most 30 minutes stale.
      if (gitHubCache?.has(ch.handle)) {
        messages = gitHubCache.get(ch.handle)!;
      }
      // 2. Bounded live t.me scrape — only for channels the cache can't serve.
      if (messages.length === 0 && liveUsed < liveBudget) {
        const previewUrls = [`https://t.me/s/${handle}`, `https://telegram.me/s/${handle}`];
        for (const url of previewUrls) {
          if (messages.length > 0) break;
          liveUsed += 1;
          const html = await fetchHtml(url);
          if (html) messages = parseChannelHtml(html);
        }
      }
      // 3. RSS bridge (avoids Workers IP block; both bridges are currently
      //    flaky, so this is a best-effort third resort).
      if (messages.length === 0) {
        const rss = await fetchRssFeed(ch.handle);
        if (rss && rss.length > 0) {
          messages = rss;
        }
      }
      // 4. Bot API KV cache as the last line of defence.
      if (messages.length === 0 && kv && env) {
        const botMsgs = await fetchFromBotApiCache(kv, ch.handle, botChannelMap);
        if (botMsgs) {
          messages = botMsgs;
        } else {
          warnings.push(`could not fetch t.me/s/${ch.handle} (bot-cache miss)`);
        }
      }
      if (messages.length === 0) {
        channelStatus.push({ handle: ch.handle, name: ch.name, topic: ch.topic, ok: false, count: 0 });
        continue;
      }
      const quality = scoreChannel(messages);
      let textCount = 0;
      for (const m of messages) {
        if (!m.text) continue;
        textCount += 1;
        allItems.push({
          channel_handle: ch.handle,
          channel_name: ch.name,
          channel_topic: ch.topic,
          channel_blurb: ch.blurb,
          permalink: m.permalink,
          datetime: m.datetime,
          text: m.text,
          views: m.views,
        });
      }
      channelStatus.push({
        handle: ch.handle,
        name: ch.name,
        topic: ch.topic,
        ok: true,
        count: textCount,
        quality,
      });
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  // If kv+env are available, pull in any Bot-API cached channels that are NOT
  // in the hardcoded CHANNELS list (bot-admin channels the user added manually).
  if (kv && env) {
    try {
      const map = botChannelMap;
      const knownHandles = new Set(queue.map((c) => c.handle.toLowerCase()));
      for (const [rawHandle, _chatId] of map) {
        // Case-insensitive compare: bot-map keys keep the channel's display
        // case (e.g. `FBI_Watchdog`) while the queue set is lowercased — a
        // raw compare re-added the whole channel as a `[Bot]` duplicate.
        const handle = rawHandle.toLowerCase();
        if (knownHandles.has(handle)) continue;
        const botMsgs = await fetchFromBotApiCache(kv, handle, map);
        if (!botMsgs || botMsgs.length === 0) continue;
        const quality = scoreChannel(botMsgs);
        let textCount = 0;
        for (const m of botMsgs) {
          if (!m.text) continue;
          textCount += 1;
          allItems.push({
            channel_handle: handle,
            channel_name: `[Bot] ${handle}`,
            channel_topic: 'bot-monitored',
            channel_blurb: `Bot-monitored channel: ${handle}`,
            permalink: m.permalink,
            datetime: m.datetime,
            text: m.text,
            views: undefined,
          });
        }
        channelStatus.push({
          handle,
          name: `[Bot] ${handle}`,
          topic: 'bot-monitored',
          ok: true,
          count: textCount,
          quality,
        });
      }
    } catch (_catchErr) {
      logError('fetchTelegramFeed (bot-bonus) failed', _catchErr);
    }
  }

  // De-duplicate: same permalink served twice (preview pinned-replay) or the
  // same syndicated copy cross-posted across channels. Longer text wins.
  const { items: dedupedItems, removed: duplicatesRemoved } = dedupeFeedItems(allItems);
  dedupedItems.sort((a, b) => b.datetime.localeCompare(a.datetime));

  return {
    generated_at: new Date().toISOString(),
    channels: channelStatus.sort((a, b) => a.name.localeCompare(b.name)),
    items: dedupedItems,
    duplicates_removed: duplicatesRemoved,
    warnings,
  };
}

/** Exported so /api/v1/snapshot can read the same cached payload directly. */
// Bumped v8 → v9 alongside MAX_MESSAGES_PER_CHANNEL 8→20 and the 7d filter
// so the next request abandons any cached payload built under the old caps.
export const TELEGRAM_FEED_CACHE_KEY = 'https://telegram-feed-cache.internal/v13-telegram-me';

// Bump value is read on every TG feed visit to invalidate the cache
// when custom channels change. Shadow it in caches.default with a 60s
// TTL so the KV read happens at most once/min/colo instead of per-visit.
const BUMP_SHADOW_CACHE_KEY = new Request('https://tg-bump-shadow.internal/v1');
const BUMP_SHADOW_TTL = 60;

export async function readBumpValue(env: Env): Promise<string | null> {
  const cache = (caches as unknown as { default: Cache }).default;
  try {
    const shadow = await cache.match(BUMP_SHADOW_CACHE_KEY);
    if (shadow) {
      const v = await shadow.text();
      return v || null;
    }
  } catch (_catchErr) {
    logError('readBumpValue failed', _catchErr);
    /* fall through to KV */
  }
  const fresh = env.KV_CACHE ? await safeNullLog('kv-get-tg-bump', env.KV_CACHE.get('tg:custom-channels:bump')) : null;
  // Always write a shadow — even "no bump" cached as empty string saves
  // the same read next time. Empty marker is treated as absent on read.
  try {
    await cache.put(
      BUMP_SHADOW_CACHE_KEY,
      new Response(fresh ?? '', { headers: { 'cache-control': `max-age=${BUMP_SHADOW_TTL}` } })
    );
  } catch (_catchErr) {
    logError('readBumpValue failed', _catchErr);
    /* swallow */
  }
  return fresh;
}

export async function getTelegramFeedCacheKey(env: Env): Promise<Request> {
  const bump = await readBumpValue(env);
  return new Request(`${TELEGRAM_FEED_CACHE_KEY}${bump ? `-${bump}` : ''}`);
}

export async function telegramFeedHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = await getTelegramFeedCacheKey(c.env);
  const cacheKeyStr = cacheKey.url;
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  // In-flight dedup: a cold key can be hit by the firehose page, the feed
  // panel on the same page, AND the queue-consumer warm — previously each ran
  // its own full 26-channel rebuild within seconds (a thundering herd that
  // tripped Telegram's throttling). Sharing ONE build promise collapses those
  // bursts into a single build; each caller then serializes + caches its own
  // Response (bodies are single-consumer streams, so we dedup the DATA build,
  // not the Response object).
  let build = inflightBuilds.get(cacheKeyStr);
  if (!build) {
    build = fetchTelegramFeed(c.env.KV_CACHE, c.env).finally(() => {
      inflightBuilds.delete(cacheKeyStr);
    });
    inflightBuilds.set(cacheKeyStr, build);
  }

  const body = await build;
  // Serialize once and build TWO independent Response objects — one to
  // return to the client, one to cache. Cloning the returned response
  // in `waitUntil` was failing (the cloned stream got canceled by the
  // client's read or by the runtime's per-invocation cleanup), which
  // left the cache empty and forced the next request to rebuild from
  // scratch. Two independent Responses eliminates the dependency.
  const json = JSON.stringify(body);
  const cacheHeaders = {
    'content-type': 'application/json',
    'cache-control': `public, max-age=${CACHE_TTL}`,
  };
  const cacheResponseBump = new Response(json, { headers: cacheHeaders });
  const cacheResponseBase = new Response(json, { headers: cacheHeaders });
  const clientResponse = new Response(json, { status: 200, headers: cacheHeaders });
  c.executionCtx.waitUntil(
    (async () => {
      try {
        await cache.put(cacheKey, cacheResponseBump);
      } catch (_catchErr) {
        logError('telegramFeedHandler failed', _catchErr);
        /* swallow */
      }
      try {
        await cache.put(new Request(TELEGRAM_FEED_CACHE_KEY), cacheResponseBase);
      } catch (_catchErr) {
        logError('telegramFeedHandler failed', _catchErr);
        /* swallow */
      }
    })()
  );
  return clientResponse;
}

// ─── Stateless live keyword search (no DB writes) ───────────────────────────
// GET /api/v1/tg-live-search?q=<keywords>&channels=<csv>&fresh=1
//
// Directly fetches t.me/s/<handle> previews for up to MAX_LIVE_CHANNELS
// channels, matches keyword tokens in memory, and returns hits WITHOUT
// writing to KV or D1 — unlike /tg-search and /telegram-leaks/search,
// which query the cron-populated D1 tables. The only persistence is a
// 5-minute Cache-API read-through (edge cache, not a database);
// `fresh=1` bypasses even that.
//
// Budget: 1 subrequest per channel (no GitHub/RSS/Bot fallbacks here —
// a channel that doesn't answer counts as a diagnostic, not a retry
// storm), hard-capped so a single search stays far inside the free-plan
// 50-subrequest budget.

const LIVE_SEARCH_CACHE_TTL = 300; // 5 min — fresh enough for triage, polite to t.me
const MAX_LIVE_CHANNELS = 8;
const MAX_LIVE_RESULTS = 100;
const HANDLE_RE = /^[A-Za-z0-9_]{3,64}$/;

/** Default scope: the CVE/breach batch (all preview-verified 2026-09-12). */
const LIVE_SEARCH_DEFAULTS = [
  'CVEDetector',
  'CyberMonitum',
  'DWI_CVE_Alerts',
  'FBI_Watchdog',
  'DarkfeedNews',
  'brutsecurity',
  'IntCyberDigest',
  'ctiwatch',
];

export interface TgLiveSearchHit {
  channel_handle: string;
  channel_name: string;
  permalink: string;
  datetime: string;
  views?: string;
  snippet: string;
  matched: string[];
}

export async function tgLiveSearchHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const rawQ = (c.req.query('q') ?? '').trim();
  const tokens = rawQ
    .toLowerCase()
    .split(/\s+/)
    .filter((t) => t.length >= 2);
  if (tokens.length === 0) {
    return badRequest(c, 'Provide ?q=<keywords> (at least one token ≥ 2 chars)');
  }
  if (rawQ.length > 200) {
    return badRequest(c, 'Query too long (max 200 chars)');
  }

  const rawChannels = (c.req.query('channels') ?? '').trim();
  const requested = rawChannels
    ? rawChannels
        .split(',')
        .map((h) => h.trim())
        .filter(Boolean)
    : [...LIVE_SEARCH_DEFAULTS];
  const seen = new Set<string>();
  const channels: string[] = [];
  for (const h of requested) {
    const clean = h.replace(/^@/, '');
    if (!HANDLE_RE.test(clean)) {
      return badRequest(c, `Invalid channel handle: ${h}`);
    }
    const key = clean.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      channels.push(clean);
    }
    if (channels.length >= MAX_LIVE_CHANNELS) break;
  }
  if (channels.length === 0) {
    return badRequest(c, 'Provide ?channels=<handle1,handle2> (max 8)');
  }

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(
    `https://tg-live-search.internal/v1?q=${encodeURIComponent(tokens.join(' '))}&c=${encodeURIComponent(channels.join(',').toLowerCase())}`
  );
  const fresh = c.req.query('fresh') === '1';
  if (!fresh) {
    const cached = await safeNullLog('cache-match-tg-live-search', cache.match(cacheKey));
    if (cached) return new Response(cached.body, cached);
  }

  const nameOf = (handle: string): string => {
    const known = CHANNELS.find((ch) => ch.handle.toLowerCase() === handle.toLowerCase());
    return known ? known.name : handle;
  };

  const diagnostics: Array<{ handle: string; ok: boolean; messages: number; note?: string }> = [];
  const hits: TgLiveSearchHit[] = [];

  // Sequential, not parallel: Telegram's edge throttles bursty fan-out from
  // a single egress IP (the lesson encoded in fetchWithRetry). ≤8 channels
  // × ~1–2 subrequests each stays inside the free-plan 50-subrequest budget
  // and under the throttle. No KV/D1 writes anywhere on this path.
  for (const handle of channels) {
    if (hits.length >= MAX_LIVE_RESULTS) break;
    let messages: ParsedMessage[] = [];
    try {
      const html = await fetchHtml(`https://t.me/s/${encodeURIComponent(handle)}`);
      if (html) messages = parseChannelHtml(html);
    } catch (_catchErr) {
      logError('tgLiveSearchHandler failed', _catchErr);
    }
    if (messages.length === 0) {
      diagnostics.push({ handle, ok: false, messages: 0, note: 'no preview (private/removed/rate-limited)' });
      continue;
    }
    diagnostics.push({ handle, ok: true, messages: messages.length });
    for (const m of messages) {
      const hay = m.text.toLowerCase();
      const matched = tokens.filter((t) => hay.includes(t));
      if (matched.length !== tokens.length) continue; // AND semantics
      const firstIdx = Math.min(...matched.map((t) => hay.indexOf(t)));
      const start = Math.max(0, firstIdx - 120);
      hits.push({
        channel_handle: handle,
        channel_name: nameOf(handle),
        permalink: m.permalink,
        datetime: m.datetime,
        views: m.views,
        snippet: (start > 0 ? '…' : '') + m.text.slice(start, start + 320) + (start + 320 < m.text.length ? '…' : ''),
        matched,
      });
      if (hits.length >= MAX_LIVE_RESULTS) break;
    }
  }

  hits.sort((a, b) => b.datetime.localeCompare(a.datetime));
  const body = {
    generated_at: new Date().toISOString(),
    query: tokens,
    channels: diagnostics.sort((a, b) => a.handle.localeCompare(b.handle)),
    count: hits.length,
    hits,
    storage: 'none — live t.me/s previews matched in memory (5-min edge-cache read-through unless fresh=1)',
  };
  const response = c.json(body, 200, { 'Cache-Control': `public, max-age=${LIVE_SEARCH_CACHE_TTL}` });
  if (!fresh) {
    c.executionCtx.waitUntil(
      (async () => {
        try {
          await cache.put(cacheKey, response.clone());
        } catch (_catchErr) {
          logError('tgLiveSearchHandler failed', _catchErr);
          /* swallow */
        }
      })()
    );
  }
  return response;
}

// ─── Custom channels (user-added) ────────────────────────────────────────────

interface CustomChannelEntry {
  handle: string;
  name: string;
  added_at: string;
}

export async function telegramCustomChannelsGetHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  if (!kv) return c.json({ channels: [], error: 'KV not configured' });
  try {
    const raw = await kv.get(CUSTOM_CHANNELS_KV_KEY);
    const channels: CustomChannelEntry[] = raw ? JSON.parse(raw) : [];
    return c.json({ channels }, 200, { 'cache-control': 'no-store' });
  } catch (_catchErr) {
    logError('telegramCustomChannelsGetHandler failed', _catchErr);
    return c.json({ channels: [], error: 'failed to read custom channels' }, 500);
  }
}

export async function telegramCustomChannelsPostHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;
  const kv = c.env.KV_CACHE;
  if (!kv) return internalError(c, 'KV not configured');

  const body = (await c.req.json()) as { handle?: string; name?: string };
  const handle = body.handle?.trim().replace(/^@/, '') ?? '';
  const name = (body.name?.trim() || handle) ?? '';

  if (!handle || !/^[a-zA-Z][a-zA-Z0-9_]{3,31}$/.test(handle)) {
    return badRequest(c, 'invalid handle — must be 4-32 alphanumeric chars, starting with a letter');
  }

  try {
    const raw = await kv.get(CUSTOM_CHANNELS_KV_KEY);
    const channels: CustomChannelEntry[] = raw ? JSON.parse(raw) : [];

    if (channels.some((ch) => ch.handle.toLowerCase() === handle.toLowerCase())) {
      return conflict(c, 'channel already added');
    }

    channels.push({ handle, name, added_at: new Date().toISOString() });
    await kv.put(CUSTOM_CHANNELS_KV_KEY, JSON.stringify(channels));
    // Bump the cache key so the next reader gets fresh data
    await kv.put('tg:custom-channels:bump', Date.now().toString());
    // Drop the bump-shadow so the next read picks up the new value
    // immediately instead of waiting out the 60s shadow TTL.
    try {
      await (caches as unknown as { default: Cache }).default.delete(BUMP_SHADOW_CACHE_KEY);
    } catch (_catchErr) {
      logError('telegramCustomChannelsPostHandler failed', _catchErr);
      /* swallow */
    }

    return c.json({ ok: true, channel: { handle, name } }, 201);
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return internalError(c, 'failed to save custom channel');
  }
}

export async function telegramCustomChannelsDeleteHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;
  const kv = c.env.KV_CACHE;
  if (!kv) return internalError(c, 'KV not configured');

  const handle = c.req.param('handle')?.trim().replace(/^@/, '');
  if (!handle) return badRequest(c, 'missing handle');

  try {
    const raw = await kv.get(CUSTOM_CHANNELS_KV_KEY);
    const channels: CustomChannelEntry[] = raw ? JSON.parse(raw) : [];
    const filtered = channels.filter((ch) => ch.handle.toLowerCase() !== handle.toLowerCase());
    if (filtered.length === channels.length) {
      return notFound(c, 'channel not found');
    }
    await kv.put(CUSTOM_CHANNELS_KV_KEY, JSON.stringify(filtered));
    await kv.put('tg:custom-channels:bump', Date.now().toString());
    try {
      await (caches as unknown as { default: Cache }).default.delete(BUMP_SHADOW_CACHE_KEY);
    } catch (_catchErr) {
      logError('telegramCustomChannelsDeleteHandler failed', _catchErr);
      /* swallow */
    }
    return c.json({ ok: true });
  } catch (_catchErr) {
    logError('telegramCustomChannelsDeleteHandler failed', _catchErr);
    return internalError(c, 'failed to delete custom channel');
  }
}

// ─── Bot status & manual channel registration ──────────────────────────────

/**
 * Returns the bot's username (from getMe) + a list of channels the bot
 * has cached data for (channels where it's been added as admin).
 */
export async function telegramBotStatusHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const kv = c.env.KV_CACHE;
  const token = c.env.TELEGRAM_BOT_TOKEN;
  const configured = !!token;

  let botUsername: string | null = null;
  if (token) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/getMe`);
      if (r.ok) {
        const data = (await r.json()) as { ok: boolean; result?: { username?: string } };
        botUsername = data?.result?.username ?? null;
      }
    } catch {
      /* swallow */
    }
  }

  const cachedChannels: Array<{ handle: string; chat_id: number }> = [];
  if (kv) {
    try {
      const map = await getBotChannelMap(kv);
      // One bulk read per 100 channels instead of one get per channel.
      const postValues = await kvBulkGetText(
        kv,
        [...map.values()].map((chatId) => `tg:bot-posts:${chatId}`)
      );
      for (const [handle, chatId] of map) {
        const raw = postValues.get(`tg:bot-posts:${chatId}`) ?? null;
        if (raw) {
          JSON.parse(raw);
          cachedChannels.push({ handle, chat_id: chatId });
        }
      }
    } catch {
      /* swallow */
    }
  }

  return c.json({
    configured,
    bot_username: botUsername,
    bot_token_prefix: token ? token.slice(0, 8) + '…' : null,
    cached_channels: cachedChannels.sort((a, b) => a.handle.localeCompare(b.handle)),
    cached_channel_count: cachedChannels.length,
    help:
      'To add a channel: (1) add @' +
      (botUsername ?? 'your-bot') +
      ' as admin to your Telegram channel, ' +
      '(2) wait for the next 30-min cron poll (or use POST /api/v1/admin/telegram/bot/register with {handle, chat_id}).',
  });
}

/**
 * Manually register a channel handle → chat_id mapping for Bot API monitoring.
 * Use this after adding the bot as admin to a channel so the feed knows
 * which handle to associate the chat_id with.
 */
export async function telegramBotRegisterHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const gate = requireAdmin(c);
  if ('error' in gate) return gate.error;
  const kv = c.env.KV_CACHE;
  if (!kv) return internalError(c, 'KV not configured');

  const body = (await c.req.json()) as { handle?: string; chat_id?: number };
  const handle = body.handle?.trim().replace(/^@/, '').toLowerCase();
  const chatId = body.chat_id;

  if (!handle || !chatId) {
    return badRequest(c, 'handle and chat_id are required');
  }
  if (!/^[a-zA-Z][a-zA-Z0-9_]{3,31}$/.test(handle)) {
    return badRequest(c, 'invalid handle');
  }

  try {
    const map = await getBotChannelMap(kv);
    map.set(handle, chatId);
    await kv.put(BOT_CHANNEL_MAP_KEY, JSON.stringify(Object.fromEntries(map)));
    // If no posts cached yet, we already polled — ensure we have an empty slot
    const existing = await kv.get(`tg:bot-posts:${chatId}`).catch(() => null);
    if (!existing) {
      await kv.put(`tg:bot-posts:${chatId}`, JSON.stringify([]));
    }
    return c.json({ ok: true, channel: { handle, chat_id: chatId } }, 200);
  } catch (_catchErr) {
    logError('telegramBotRegisterHandler failed', _catchErr);
    return internalError(c, 'failed to register channel');
  }
}
