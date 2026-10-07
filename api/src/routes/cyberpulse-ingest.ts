/**
 * CyberPulse — breach/leak/intel incident ingestion pipeline.
 *
 * Monitors X/Twitter (authenticated GraphQL), Telegram, Bluesky, and Mastodon
 * firehose for breach, leak, ransomware, extortion, and cybercrime posts.
 * Classifies, deduplicates, and stores structured incidents in D1.
 *
 * Cron: runs hourly via worker/scheduled.ts ( piggybacks on the `0 * * * *` tick).
 * Cost: X auth GraphQL ≈ 1 req/handle (30-min edge cache), Telegram ≈ 22 HTML fetches,
 *       Bluesky/Mastodon ≈ 15 RSS fetches. Well within the 50-subrequest free plan.
 */
import type { D1Database } from '@cloudflare/workers-types';
import {
  fetchAuthedTimeline,
  resolveAuthCookies,
  XAuthMissingError,
  XAuthInvalidError,
  XAuthRateLimitedError,
} from '../lib/twitter-auth-graphql';
import { X_ACCOUNTS, CLAIM_HANDLES_LOWER } from '../lib/x-handles';
import { fetchUserTimeline } from '../lib/twitter-graphql';
import { fetchTelegramFeed, type TelegramFeedItem } from './telegram-feed';
import { fetchXFeed, type XFeedItem } from './x-feed';
import { fetchRedditFeed, type RedditFeedItem } from './reddit-feed';
import { readXClaimsCache } from './x-claims';
import { classifySector as libClassifySector } from '../lib/sector-classifier';
import type { Env } from '../env';
import { logError } from '../lib/logger';

/**
 * Optionally pre-fetched feed data, threaded in by the caller.
 *
 * The hourly cron already fetches the Telegram feed once (worker/scheduled.ts,
 * telegram-leak-scanner) before this ingestion runs. Re-fetching the same t.me
 * channels a second time in the same tick trips t.me's per-egress-IP burst
 * throttle, so the duplicate fetch silently returns nothing and CyberPulse's
 * Telegram source found 0 items every hour. Reusing the already-fetched items
 * avoids the throttled duplicate burst entirely.
 */
export interface CyberPulsePrefetch {
  telegramItems?: TelegramFeedItem[];
  socialItems?: XFeedItem[];
  /** True when the cron already called fetchXFeed() — even if items is empty,
   *  CyberPulse should NOT re-fetch (the subrequest budget is already spent). */
  socialFetched?: boolean;
  redditItems?: RedditFeedItem[];
  /** True when the cron already called fetchRedditFeed() — same contract. */
  redditFetched?: boolean;
  /** Pre-fetched x-claims breach/ransomware data, threaded in by the cron
   *  to avoid the race between the pre-warm's deferred cache write and
   *  CyberPulse's synchronous cache read. */
  xClaimsBreach?: Array<{ text: string; source_url: string; handle: string; discovered: string }>;
  /** Pre-fetched X account posts (from gp:warm queue). When provided, the
   *  cron skips all GraphQL fetches for X accounts and uses these directly. */
  xAccountPosts?: RawPost[];
}

// ─── Types ─────────────────────────────────────────────────────────────────

export type IncidentType =
  | 'ransomware'
  | 'data_leak'
  | 'credential_leak'
  | 'extortion'
  | 'defacement'
  | 'supply_chain'
  | 'zero_day'
  | 'breach'
  | 'ddos'
  | 'hacktivism'
  | 'other';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Platform = 'x' | 'telegram' | 'bluesky' | 'mastodon' | 'reddit' | 'manual' | 'rss' | 'other';

export type Sector =
  | 'healthcare'
  | 'finance'
  | 'government'
  | 'education'
  | 'technology'
  | 'retail'
  | 'energy'
  | 'manufacturing'
  | 'telecom'
  | 'media'
  | 'transportation'
  | 'legal'
  | 'nonprofit'
  | 'other';

const SECTOR_MAP: Record<string, Sector | null> = {
  Healthcare: 'healthcare',
  Legal: 'legal',
  Education: 'education',
  Government: 'government',
  Finance: 'finance',
  Manufacturing: 'manufacturing',
  Construction: 'manufacturing',
  Engineering: 'technology',
  Technology: 'technology',
  'Retail / E-commerce': 'retail',
  Hospitality: 'retail',
  Logistics: 'transportation',
  Energy: 'energy',
  'Real Estate': 'other',
  Agriculture: 'other',
  'Media / Publishing': 'media',
  Nonprofit: 'nonprofit',
};

export interface CyberPulseIncident {
  id: string;
  incident_type: IncidentType;
  severity: Severity;
  victim_name: string | null;
  victim_domain: string | null;
  victim_sector: Sector | null;
  victim_country: string | null;
  threat_actor: string | null;
  threat_actor_aliases: string;
  title: string;
  description: string | null;
  data_types_leaked: string;
  records_count: number | null;
  data_volume: string | null;
  source_platform: Platform;
  source_url: string | null;
  source_handle: string | null;
  source_text: string | null;
  source_author: string | null;
  source_avatar: string | null;
  confidence: number;
  classification_method: string;
  discovered_at: string;
  reported_at: string | null;
  updated_at: string;
  dedup_hash: string | null;
  duplicate_of: string | null;
  tags: string;
  mitre_techniques: string;
  source_likes: number;
  source_retweets: number;
  source_replies: number;
  source_views: number;
}

export interface IngestResult {
  source: string;
  items_scanned: number;
  incidents_created: number;
  incidents_deduped: number;
  errors: string[];
  duration_ms: number;
}

// ─── Keyword patterns for classification ────────────────────────────────────

const INCIDENT_PATTERNS: Record<IncidentType, RegExp[]> = {
  ransomware: [
    /ransomware/i,
    /ransom\s*ware/i,
    /\bransom\b/i,
    /lockbit|blackcat|alphv|cl0p|\bplay\b|akira|black\s*basta|medusa|hunters|clop|qilin|basilic|bianlian|rhysida|monti|abyss|8base|cactus|cryptnet|darkangels|darkrace|donut|duck|everest|foxbiz|ice\s*fire|inc\s*ransom|killsecurity|mads|malas|malox|moneymessage|nokoyawa|noktor|omerta|pysa|ragnarlocker|ragnarok|rancsom|ransomexx|ransomhouse|ransomhub|ransomwhere|redansom|roubaix|royal|snatch|solidbit|sparta|stormous|sugar|threeam|trigona|tutanchamon|underground|unlock|vanilla|vice\s*society|vohuk|yanluowang/i,
    /leak\s*site.*(?:added|new|post)/i,
    /data\s*(?:will\s*)?(?:be\s*)?leaked/i,
    /pay\s*or\s*(?:your|we)/i,
    /double\s*extort/i,
    /(?:group|gang).*added.*(?:victim|company|org)/i,
    /new.*victim.*(?:added|listed|posted)/i,
    /leak.*(?:published|released|upload)/i,
  ],
  data_leak: [
    /data\s*leak/i,
    /leaked\s*data/i,
    /data\s*(?:dump|breach|exposed)/i,
    /\bleak(?:ed|ing|s)?\b.*\b(?:database|records?|data|info)/i,
    /(?:database|records?|data|info)\b.*\b(?:leaked|exposed|dumped)/i,
    /(?:millions?|thousands?|billions?)\s*(?:of\s*)?(?:records?|accounts?|users?)/i,
    /(?:million|billion|thousand)\s+(?:people|patients?|customers?|users?|individuals?)/i,
    /full\s*(?:dump|database)/i,
    /pastebin|ghostbin|rentry/i,
    /alleged(?:ly)?\s+(?:leaked|compromised|breached)/i,
    /(?:database|customer\s*data|user\s*data).*(?:sale|sold|offer|advertising)/i,
    /(?:claimed|claims?)\s+to\s+have\s+(?:leaked|compromised|obtained|breached)/i,
    /advertising.*(?:database|data|records?)/i,
    /sample.*(?:file|data|records?).*(?:available|posted|shared)/i,
    /(?:internal|classified|confidential).*(?:docs|files|data|documents)/i,
  ],
  credential_leak: [
    /credential/i,
    /(?:stolen|exposed|leaked|compromised)\s*(?:password|credential|login)/i,
    /infostealer|stealer\s*log/i,
    /redline|raccoon|vidar|meta\s*infostealer|lumma|risepro|stealc|rhadamanthys|danabot|formbook|agenttesla|nano\s*stealer|acr|recordbreaker|white\s*hawk|max\s*stealer|torii/i,
    /combo\s*(?:list|dump)/i,
    /email.*password.*(?:leaked|exposed|dumped)/i,
    /(?:plaintext|cleartext).*password/i,
    /hash.*(?:crack|cracked|decrypt)/i,
    /login.*(?:leak|dump|exposed)/i,
    /session.*(?:token|cookie|hijack)/i,
    /\b2fa|otp|mfa\b.*(?:bypass|leak|compromised)/i,
  ],
  extortion: [
    /extort/i,
    /(?:threat|attempt)ing?\s*to\s*(?:extort|blackmail)/i,
    /pay\s*or\s*(?:we|your)/i,
    /(?:expose|publish|release)\s*(?:your|sensitive|private)/i,
    /sextortion/i,
    /blackmail/i,
    /ransom\s*demand/i,
  ],
  defacement: [
    /defac(?:ed?|ement|ing)/i,
    /hack(?:ed?|ing)?\s*(?:website|site|page)/i,
    /website\s*(?:compromised|hacked|defaced)/i,
    /homepage.*(?:defaced|replaced|hacked)/i,
    /(?:iranian|hacker).*(?:defaced|replaced)/i,
  ],
  supply_chain: [
    /supply\s*chain/i,
    /(?:backdoor|trojan)\s*(?:in|found\s*in|discovered\s*in)/i,
    /compromised\s*(?:package|update|dependency|library)/i,
    /npm|pypi|crate|gems?\b.*\b(?:malicious|compromised)/i,
    /codecov|solarwinds|3cx|moveit|citrix|mimem/i,
    /software\s*supply\s*chain/i,
    /dependency.*(?:confusion|typo|squatting)/i,
    /malicious.*(?:package|update|patch|plugin|extension)/i,
    /(?:pipeline|ci\/cd|builder).*(?:compromised|breach|injected)/i,
  ],
  zero_day: [
    /0[\s-]?day/i,
    /zero[\s-]?day/i,
    /actively\s*exploited/i,
    /in[\s-]?the[\s-]?wild/i,
    /unpatched\s*vuln/i,
    /(?:cve|cve-\d{4}-\d{4,7})/i,
    /proof[\s-]?of[\s-]?concept.*(?:released|published|available)/i,
    /exploit.*(?:released|published|public|available)/i,
    /remote\s*code\s*execution.*(?:critical|unpatched|0[\s-]?day)/i,
  ],
  breach: [
    /(?:confirmed|suffered|experienced|hit\s*(?:by|with))\s*(?:a\s*)?breach/i,
    /data\s*breach/i,
    /security\s*breach/i,
    /unauthorized\s*access/i,
    /cyber\s*(?:attack|incident)/i,
    /network\s*(?:compromised|breach|incident)/i,
    /(?:reportedly|allegedly).*(?:victim|compromised|breached|hacked|fallen\s*victim)/i,
    /(?:victim|target)\s*of\s*(?:a\s*)?(?:data\s*)?breach/i,
    /(?:exposed|compromised)\s*(?:data\s*of|information\s*found|records?\s*of)/i,
    /\bbreach\b.*\b(?:expos|leak|impact|affect)/i,
    /\bbreach\b.*\b(?:data|records?|info)/i,
    /(?:database|server).*(?:exposed|public|open|unsecured|misconfigured)/i,
    /security\s*incident/i,
    /(?:company|org|firm).*(?:breached|hacked|compromised)/i,
  ],
  ddos: [
    /\bddos\b/i,
    /denial[\s-]of[\s-]service/i,
    /(?:taken\s*down|knocked\s*(?:offline|out))\s*(?:by|via|with)/i,
    /volumetric.*(?:attack|flood)/i,
    /layer.*(?:7|3|4).*(?:attack|flood)/i,
    /(?:amplification|reflection).*(?:attack|drdos)/i,
    /(?:syn|udp|http).*(?:flood|attack)/i,
  ],
  hacktivism: [
    /hacktivist/i,
    /(?:anonymous|ghostsec|killnet|no\s*name|ldz|mkv|siert|cyber\s*partisans|ukrainian\s*cyber|it\s*army)\s*(?:claimed|hits?|attacks?)/i,
    /(?:political|ideological)\s*(?:hack|attack)/i,
    /protest.*(?:hack|defac|attack|leak)/i,
    /op(?:eration)?\s*(?:israel|russia|ukraine|palestine|gaza|free)/i,
    /(?:expose|dox).*(?:govt|government|military|regime)/i,
  ],
  other: [
    /cyber(?:crime|security)/i,
    /threat\s*actor/i,
    /apt[\s-]?\d+/i,
    /forum.*(?:post|thread|mention|discuss)/i,
    /(?:alert|advisory|warning).*(?:threat|malware|attack)/i,
  ],
};

const SEVERITY_KEYWORDS: Record<Severity, RegExp[]> = {
  critical: [
    /critical/i,
    /emergency/i,
    /actively\s*exploited/i,
    /zero[\s-]?day/i,
    /(?:millions?|billions?)\s*(?:of\s*)?(?:records?|accounts?|users?)/i,
    /(?:hospital|power\s*grid|nuclear|military)/i,
  ],
  high: [
    /high\s*severity/i,
    /major\s*(?:breach|attack|incident)/i,
    /(?:hundreds?\s*of\s*thousands?|thousands?)\s*(?:of\s*)?(?:records?|accounts?)/i,
    /Fortune\s*500/i,
    /federal\s*agency/i,
  ],
  medium: [
    /medium\s*severity/i,
    /moderate/i,
    /(?:thousands?|tens?\s*of\s*thousands?)\s*(?:of\s*)?(?:records?|accounts?)/i,
  ],
  low: [/low\s*severity/i, /minor/i, /contained/i],
  info: [/informational/i, /advisory/i, /heads[\s-]?up/i],
};

const _SECTOR_KEYWORDS: Record<Sector, RegExp[]> = {
  healthcare: [/health(?:care|care|system|hospital|clinic)/i, /medical/i, /pharma/i, /biotech/i, /FDA/i],
  finance: [
    /bank(?:ing)?/i,
    /financial/i,
    /credit\s*union/i,
    /insurance/i,
    /fintech/i,
    /crypto(?:currency)?\s*(?:exchange|platform)/i,
  ],
  government: [
    /federal/i,
    /state\s*government/i,
    /municipal/i,
    /agency/i,
    /department\s*of/i,
    /military/i,
    /pentagon/i,
    /doD/i,
  ],
  education: [/university|college|school\s*district|education/i],
  technology: [/tech\s*company|software|SaaS|cloud|hosting|ISP|data\s*center/i],
  retail: [/retail|e[\s-]?commerce|store|shop|merchant/i],
  energy: [/energy|oil|gas|utility|power\s*grid|nuclear/i],
  manufacturing: [/manufacturing|industrial|factory/i],
  telecom: [/telecom|mobile\s*carrier|broadband/i],
  media: [/media|news|broadcast|streaming|entertainment/i],
  transportation: [/airline|railway|shipping|logistics|aviation/i],
  legal: [/law\s*firm|legal/i],
  nonprofit: [/non[\s-]?profit|NGO|foundation/i],
  other: [],
};

// ─── Known threat actors (common groups) ────────────────────────────────────

const KNOWN_ACTORS = [
  // ── Ransomware gangs ─────────────────────────────────────────────────
  'lockbit',
  'blackcat',
  'alphv',
  'cl0p',
  'clop',
  'play',
  'akira',
  'black basta',
  'blackbasta',
  'medusa',
  'hunters',
  'rhysida',
  'monti',
  'INC ransom',
  'incransom',
  'embargo',
  'redansom',
  'qilin',
  'basilic',
  'bianlian',
  'abyss',
  '8base',
  'cactus',
  'cryptnet',
  'dark angels',
  'darkangels',
  'darkrace',
  'donut',
  'everest',
  'foxbiz',
  'ice fire',
  'icefire',
  'killsecurity',
  'mads',
  'malox',
  'moneymessage',
  'nokoyawa',
  'noktor',
  'omerta',
  'pysa',
  'ragnarlocker',
  'ragnarok',
  'ransomexx',
  'ransomhouse',
  'ransomhub',
  'ransomwhere',
  'roubaix',
  'royal',
  'snatch',
  'solidbit',
  'stormous',
  'sugar',
  'threeam',
  'trigona',
  'tutanchamon',
  'underground',
  'vanilla',
  'vice society',
  'vicesociety',
  'vohuk',
  'yanluowang',
  'hive',
  'nobreks',
  'avaddon',
  'babuk',
  'blackmatter',
  'cuba',
  'darkleak',
  'dragonforce',
  'haron',
  'hello kitty',
  'hellokitty',
  'kara',
  'lorenz',
  'lv',
  'lv ransomware',
  'malas',
  'mallox',
  'midas',
  'mindware',
  'moses staff',
  'mosess staff',
  'night sky',
  'nightsky',
  'nvd',
  'onlines',
  'project relativistic',
  'prometheus',
  'prolock',
  'rancsom',
  'ranzy',
  'sabbath',
  'silent',
  'sparta',
  'spook',
  'storm-0978',
  'sun crypt',
  'suncrypt',
  'vice society',
  'vicesociety',
  // ── APT / Nation-state groups ────────────────────────────────────────
  'lazarus',
  'kimsuky',
  'apt28',
  'apt29',
  'apt33',
  'apt41',
  'cozy bear',
  'fancy bear',
  'turla',
  'darkhotel',
  'salt typhoon',
  'charcoal typhoon',
  'grizzly steppe',
  'iron tiger',
  'winnti',
  'scattered spider',
  'scatteredspider',
  'midnight blizzard',
  'storm-0558',
  'storm-0978',
  'storm-1674',
  'storm-0539',
  'starblizzard',
  'callisto group',
  'sewer typhoon',
  'volt typhoon',
  'panda typhoon',
  'flax typhoon',
  'paper typhoon',
  'stone typhoon',
  'red appolo',
  'blue noroff',
  'silk surgeon',
  'stonefly',
  'wildneutron',
  'strongpity',
  'ocean lotus',
  'patchwork',
  'sidewinder',
  'transparent tribe',
  'donot team',
  'apt-c-39',
  'apt-c-23',
  'apt-c-36',
  'tonto team',
  'dark basin',
  'elementary group',
  'metador',
  'velvet chollima',
  'dark panda',
  'menupass',
  'naikon',
  'blacken',
  'deep panda',
  'hidden cobra',
  'temple of svet12',
  'tucker',
  // ── Hacktivist / protest groups ──────────────────────────────────────
  'anonymous',
  'ghostsec',
  'ghost security',
  'killnet',
  'no name',
  'no name 057',
  'ldz',
  'mkv',
  'siert',
  'cyber partisans',
  'ukrainian cyber',
  'it army',
  'it army of ukraine',
  'anonymous sudan',
  'anonymous russia',
  'squad303',
  'dragons of ukraine',
  'cyber anarchy squad',
  'legion cyber',
  'handala',
  'anonala',
  'garuna',
  'destroyersquad',
  // ── Initial access brokers / malware operators ───────────────────────
  'revil',
  'ryuk',
  'conti',
  'darkside',
  'maze',
  'blackmatter',
  'avaddon',
  'babuk',
  'blackbasta',
  'cuba ransomware',
  'netwalker',
  'doppelpaymer',
  'egregor',
  'nefilim',
  'sodinokibi',
  'ragnarlocker',
  'lockergoga',
  'cerber',
  'david',
  'dragonforce',
];

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateId(): string {
  const ts = Date.now().toString(36);
  const rand = crypto.getRandomValues(new Uint8Array(8));
  return `cp_${ts}-${Array.from(rand)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}

function dedupHash(title: string, victim: string, platform: string): string {
  const norm = `${title}|${victim}|${platform}`.toLowerCase().replace(/[^a-z0-9]/g, '');
  // Simple hash — not cryptographic, just for dedup
  let hash = 0;
  for (let i = 0; i < norm.length; i++) {
    hash = ((hash << 5) - hash + norm.charCodeAt(i)) | 0;
  }
  return `dh_${Math.abs(hash).toString(36)}`;
}

function classifyType(text: string): { type: IncidentType; confidence: number } {
  let best: IncidentType = 'other';
  let bestScore = 0;
  for (const [type, patterns] of Object.entries(INCIDENT_PATTERNS) as [IncidentType, RegExp[]][]) {
    let score = 0;
    for (const p of patterns) {
      if (p.test(text)) score++;
    }
    if (score > bestScore) {
      bestScore = score;
      best = type;
    }
  }
  const confidence = Math.min(0.95, 0.3 + bestScore * 0.2);
  return { type: best, confidence: bestScore > 0 ? confidence : 0.2 };
}

function classifySeverity(text: string): Severity {
  for (const [sev, patterns] of Object.entries(SEVERITY_KEYWORDS) as [Severity, RegExp[]][]) {
    for (const p of patterns) {
      if (p.test(text)) return sev;
    }
  }
  return 'medium';
}

function classifySector(text: string): Sector | null {
  const libResult = libClassifySector(text, '');
  if (libResult === 'Unknown') return null;
  return SECTOR_MAP[libResult] ?? null;
}

function extractThreatActor(text: string): string | null {
  const lower = text.toLowerCase();
  for (const actor of KNOWN_ACTORS) {
    if (lower.includes(actor.toLowerCase())) return actor;
  }
  // Pattern: "Group X claims" or "attributed to Y"
  const m =
    /(?:group|gang|crew|collective|apt|threat\s*actor)\s+(?:named?\s+)?["']?([A-Z][A-Za-z0-9\s-]+?)["']?\s*(?:claims?|hits?|attacks?|responsible)/i.exec(
      text
    );
  return m?.[1]?.trim() ?? null;
}

function extractVictim(text: string): { name: string | null; domain: string | null } {
  // Pattern: "X confirmed/enuffers a breach" or "X data leaked"
  const m =
    /([A-Z][A-Za-z0-9.&\s]{2,40})\s+(?:confirmed|suffered|experienced|hit\s*(?:by|with)|data\s*(?:leak|breach)|breach|compromised|hacked|leaked|attack)/i.exec(
      text
    );
  const name = m?.[1]?.trim() ?? null;
  // Domain extraction
  const dm = /\b([a-z0-9-]+\.[a-z]{2,})\b/i.exec(text);
  return { name, domain: dm?.[1] ?? null };
}

function extractRecordsCount(text: string): number | null {
  const m = /(\d[\d,.]*)\s*(?:million|m)\s*(?:of\s*)?(?:records?|accounts?|users?)/i.exec(text);
  if (m?.[1]) return Math.round(parseFloat(m[1].replace(/,/g, '')) * 1_000_000);
  const m2 = /(\d[\d,.]*)\s*(?:thousand|k)\s*(?:of\s*)?(?:records?|accounts?|users?)/i.exec(text);
  if (m2?.[1]) return Math.round(parseFloat(m2[1].replace(/,/g, '')) * 1_000);
  const m3 = /(\d[\d,]+)\s*(?:records?|accounts?|users?)/i.exec(text);
  if (m3?.[1]) return parseInt(m3[1].replace(/,/g, ''), 10);
  return null;
}

function extractDataVolume(text: string): string | null {
  const m = /(\d[\d.]*)\s*(GB|TB|MB|PB)/i.exec(text);
  return m?.[1] && m?.[2] ? `${m[1]}${m[2].toUpperCase()}` : null;
}

function extractMitres(text: string): string[] {
  const techniques = Array.from(text.matchAll(/T\d{4}(?:\.\d{3})?/g)).map((m) => m[0]);
  return [...new Set(techniques)].slice(0, 10);
}

function extractTags(text: string): string[] {
  const tags: string[] = [];
  if (/\bransomware\b/i.test(text)) tags.push('ransomware');
  if (/\bdata\s*leak\b/i.test(text)) tags.push('data-leak');
  if (/\bbreach\b/i.test(text)) tags.push('breach');
  if (/\bphishing\b/i.test(text)) tags.push('phishing');
  if (/\bmalware\b/i.test(text)) tags.push('malware');
  if (/\bzeroday|0[\s-]?day\b/i.test(text)) tags.push('zero-day');
  if (/\bddos\b/i.test(text)) tags.push('ddos');
  if (/\bextort/i.test(text)) tags.push('extortion');
  if (/\binsider\s*threat\b/i.test(text)) tags.push('insider-threat');
  if (/\bsupply\s*chain\b/i.test(text)) tags.push('supply-chain');
  return tags;
}

function extractCountry(text: string): string | null {
  // Flag emoji prefix: "🇲🇽 Mexico - text..."
  const flagMatch = /^[\s]*[\u{1F1E6}-\u{1F1FF}]{2}\s*([A-Z][A-Za-z.\-() ]{1,40}?)\s*[-:]/u.exec(text);
  if (flagMatch?.[1]) {
    const c = flagMatch[1].trim();
    if (c.length >= 2 && c.length <= 40) return c;
  }
  // "based in X" / "operating out of X" / "headquartered in X"
  const basedMatch =
    /(?:based|operating|headquartered|located)\s+(?:in|out\s*of)\s+([A-Z][A-Za-z\s.-]{2,40})(?:\s+[,-]|\s*$)/i.exec(
      text
    );
  if (basedMatch?.[1]) {
    const c = basedMatch[1].trim().replace(/\s+/g, ' ');
    if (c.length >= 2 && c.length <= 40) return c;
  }
  // "Country: X" prefix pattern
  const countryLabelMatch = /(?:country|nation|region)\s*[:]\s*([A-Z][A-Za-z\s.-]{2,40})(?:\s|$|[.,])/i.exec(text);
  if (countryLabelMatch?.[1]) {
    const c = countryLabelMatch[1].trim();
    if (c.length >= 2 && c.length <= 40) return c;
  }
  return null;
}

const DATA_TYPES_PATTERNS: [RegExp, string][] = [
  [/\b(?:customer|client)\s*(?:data|info|records?|database|list)\b/i, 'customer-data'],
  [/\b(?:employee|staff|worker|personnel)\s*(?:data|info|records?|database|list)\b/i, 'employee-data'],
  [/\b(?:patient|medical|health)\s*(?:data|info|records?|database)\b/i, 'medical-records'],
  [/\b(?:financial|bank|credit\s*card|crypto)\s*(?:data|info|records?|account)\b/i, 'financial-data'],
  [/\b(?:payment|credit\s*card|debit\s*card|cardholder|cc|pan)\b/i, 'payment-info'],
  [/password|passwd|hash|hashcat|\bntlm\b/i, 'passwords'],
  [/email\s*(?:address|list|database)/i, 'email-addresses'],
  [/\bssn|social\s*security|national\s*(?:id|identity)\b/i, 'ssn'],
  [/\b(?:phone|telephone|mobile)\s*(?:number|list|database)\b/i, 'phone-numbers'],
  [/\b(?:address|home\s*address|physical\s*address)\b/i, 'physical-addresses'],
  [/\bdob|date\s*of\s*birth\b/i, 'date-of-birth'],
  [/\b(?:driver.?s\s*license|passport|national\s*id)\b/i, 'id-documents'],
  [/\bi?pii\b/i, 'pii'],
  [/\bsource\s*code|repository|github|gitlab\b/i, 'source-code'],
  [/\b(?:classified|confidential|internal)\s*(?:docs|documents|files)\b/i, 'classified-documents'],
  [/\bintellectual\s*property|ip|trade\s*secret|patent\b/i, 'intellectual-property'],
  [/\b(?:military|defense|intelligence|government)\s*(?:data|docs|files|records)\b/i, 'government-data'],
  [/\b(?:api|token|secret|key|credential)\s*(?:key|leak|exposed)\b/i, 'api-keys'],
  [/\bdatabase\s*(?:dump|export|backup)\b/i, 'database-dump'],
  [/\b(?:session|cookie|auth)\s*(?:token|cookie|key)\b/i, 'session-data'],
  [/\bchat|conversation|message|dm|private\s*message\b/i, 'chat-logs'],
];

function extractDataTypes(text: string): string[] {
  const found = new Set<string>();
  for (const [re, label] of DATA_TYPES_PATTERNS) {
    if (re.test(text)) found.add(label);
  }
  return [...found].slice(0, 20);
}

function verifyClassification(info: {
  incident_type: IncidentType;
  confidence: number;
  victim_name: string | null;
  victim_domain: string | null;
  threat_actor: string | null;
  records_count: number | null;
  tags: string[];
}): { adjustedConfidence: number; verified: boolean } {
  let adj = info.confidence;
  const _notes: string[] = [];

  // Ransomware without a detected threat actor or victim is less reliable
  if (info.incident_type === 'ransomware') {
    if (!info.threat_actor) adj -= 0.1;
    if (!info.victim_name) adj -= 0.05;
  }

  // Data leak without a victim is less specific
  if (info.incident_type === 'data_leak' && !info.victim_name && !info.victim_domain) {
    adj -= 0.1;
  }

  // Credential leak should mention password/email patterns
  if (info.incident_type === 'credential_leak' && !info.records_count) {
    adj -= 0.05;
  }

  // Zero-day with CVE mention is more reliable
  if (info.incident_type === 'zero_day' && info.tags.includes('zero-day')) {
    adj += 0.05;
  }

  // DDoS without explicit DDoS keyword is weak
  if (info.incident_type === 'ddos' && !info.tags.includes('ddos')) {
    adj -= 0.1;
  }

  // Breach/leak with a victim name is more credible
  if (
    (info.incident_type === 'breach' || info.incident_type === 'data_leak') &&
    info.victim_name &&
    !info.threat_actor
  ) {
    adj += 0.05;
  }

  // Supply chain without known incident name is weak
  if (info.incident_type === 'supply_chain' && !info.victim_name) {
    adj -= 0.1;
  }

  const verified = adj >= 0.25;
  return { adjustedConfidence: Math.max(0.05, Math.min(0.99, adj)), verified };
}

export interface ClassificationResult {
  incident_type: IncidentType;
  severity: Severity;
  confidence: number;
  victim_name: string | null;
  victim_domain: string | null;
  victim_sector: Sector | null;
  victim_country: string | null;
  threat_actor: string | null;
  records_count: number | null;
  data_volume: string | null;
  data_types_leaked: string[];
  tags: string[];
  mitre_techniques: string[];
  classification_verified: boolean;
}

function classifyIncident(text: string, _platform: Platform, _url: string): ClassificationResult {
  const { type, confidence } = classifyType(text);
  const severity = classifySeverity(text);
  const { name: victim_name, domain: victim_domain } = extractVictim(text);
  const victim_sector = classifySector(text);
  const victim_country = extractCountry(text);
  const threat_actor = extractThreatActor(text);
  const records_count = extractRecordsCount(text);
  const data_volume = extractDataVolume(text);
  const data_types_leaked = extractDataTypes(text);
  const tags = extractTags(text);
  const mitre_techniques = extractMitres(text);
  const { adjustedConfidence, verified } = verifyClassification({
    incident_type: type,
    confidence,
    victim_name,
    victim_domain,
    threat_actor,
    records_count,
    tags,
  });

  // Add forum tag if text mentions forums
  if (/\b(?:forum|breach\s*forum|dark\s*web|dread|exploit)\b/i.test(text)) {
    tags.push('forum-post');
  }

  return {
    incident_type: type,
    severity,
    confidence: adjustedConfidence,
    victim_name,
    victim_domain,
    victim_sector,
    victim_country,
    threat_actor,
    records_count,
    data_volume,
    data_types_leaked,
    tags,
    mitre_techniques,
    classification_verified: verified,
  };
}

// ─── Source-specific fetchers ───────────────────────────────────────────────

export interface RawPost {
  text: string;
  url: string;
  platform: Platform;
  handle: string;
  author: string;
  avatar: string | null;
  published_at: string;
  likes: number;
  retweets: number;
  replies: number;
  views: number;
}

/** Fetch recent posts from X accounts. Tries auth first, falls back to anonymous. */
export async function fetchXAccountPosts(
  env: Env,
  handles: string[],
  sinceDays: number = 1,
  prefetchedClaims?: CyberPulsePrefetch['xClaimsBreach'],
  prefetchedPosts?: RawPost[]
): Promise<RawPost[]> {
  // When prefetched posts are provided (from gp:warm queue), return them
  // directly — the queue consumer already burned the subrequest budget.
  if (prefetchedPosts) return prefetchedPosts;

  const posts: RawPost[] = [];

  // ── 1. Use pre-fetched x-claims breach data (threaded from cron) ───────
  // Avoids the race between the pre-warm's waitUntil cache write and
  // CyberPulse's synchronous cache read. Falls back to cache read if no
  // prefetched data is available.
  const claimsData =
    prefetchedClaims ??
    (await (async () => {
      try {
        const claims = await readXClaimsCache();
        return claims?.breach;
      } catch (_catchErr) {
        logError('fetchXAccountPosts failed', _catchErr);
        return undefined;
      }
    })());
  if (claimsData) {
    for (const b of claimsData) {
      posts.push({
        text: b.text,
        url: b.source_url,
        platform: 'x',
        handle: b.handle,
        author: b.handle,
        avatar: null,
        published_at: b.discovered,
        likes: 0,
        retweets: 0,
        replies: 0,
        views: 0,
      });
    }
  }

  // ── 2. Direct GraphQL fetch for handles NOT covered by x-claims ───────
  const directHandles = handles.filter((h) => !CLAIM_HANDLES_LOWER.has(h.toLowerCase()));
  if (directHandles.length === 0) return posts;

  let authed = true;
  try {
    await resolveAuthCookies(env);
  } catch (e) {
    authed = false;
    if (e instanceof XAuthMissingError) {
    } else {
    }
    // Without auth, anonymous GraphQL returns curated "best of" timelines
    // (not chronological) and is heavily rate-limited. The 20+ subrequests
    // needed for all direct handles would exhaust the free-plan budget,
    // starving Telegram/Bluesky/Reddit sources. Skip entirely — the claims
    // data above already covers the key CTI handles.
    return posts;
  }

  for (const handle of directHandles) {
    try {
      const resp = authed
        ? await fetchAuthedTimeline(env, handle, {
            count: 20,
            sinceDays: Math.max(sinceDays, 0.04),
            includeReplies: false,
          })
        : await fetchUserTimeline(env, handle, {
            count: 20,
            sinceDays: Math.max(sinceDays, 0.04),
          });
      if (resp.items.length === 0) {
      }
      for (const item of resp.items) {
        if (item.is_retweet) continue;
        posts.push({
          text: item.text,
          url: item.url,
          platform: 'x',
          handle,
          author: item.author.name,
          avatar: item.author.avatar_url ?? null,
          published_at: item.created_at,
          likes: item.favorite_count ?? 0,
          retweets: item.retweet_count ?? 0,
          replies: item.reply_count ?? 0,
          views: item.view_count ?? 0,
        });
      }
    } catch (e) {
      if (e instanceof XAuthMissingError) break;
      if (e instanceof XAuthInvalidError) {
        if (authed) {
          authed = false;
        }
        continue;
      }
      if (e instanceof XAuthRateLimitedError) {
        break;
      }
    }
  }
  return posts;
}

// ─── D1 operations ─────────────────────────────────────────────────────────

/**
 * Lazy, memoized dedup membership test against `cyberpulse_incidents`.
 *
 * Replaces a preload that read EVERY dedup_hash in a trailing 48h window into a
 * JS Set before each ingestion pass. That range walk costs roughly the row
 * count of the window plus one index probe per row (~4.8k rows_read against a
 * 36k-row table). Ingestion runs 72x/day (48 from the every-30-minutes cron plus
 * 24 from the hourly cron), so the preload alone burned ~350k rows_read/day,
 * ~6% of the 5M free-tier daily budget, before any real work happened.
 *
 * Cost is now proportional to the number of INCOMING hashes rather than to the
 * size of the table: each unseen hash costs one point lookup served by
 * idx_cp_dedup (~1 row). Nothing is re-probed within a run.
 *
 * Correctness note: idx_cp_dedup is NOT unique, so `INSERT OR IGNORE` does not
 * dedupe on this column — `claim()` is the only thing standing between a
 * re-scraped post and a duplicate incident row. It must stay correct, not
 * merely fast, so a miss still *claims* the hash: a second identical hash in
 * the same batch must resolve as already-seen, exactly as the old
 * `existingHashes.add(hash)` immediately after a miss did.
 */
class DedupProbe {
  /** Hashes known to be persisted, or reserved by this run for insertion. */
  private readonly claimed = new Set<string>();

  /**
   * @returns true if the hash is already stored (or already reserved by an
   *   earlier item in this same batch) and the caller must skip it.
   */
  async claim(db: D1Database, hash: string): Promise<boolean> {
    if (this.claimed.has(hash)) return true;

    const row = await db
      .prepare('SELECT 1 AS hit FROM cyberpulse_incidents WHERE dedup_hash = ? LIMIT 1')
      .bind(hash)
      .first<{ hit: number }>();

    // Claim on BOTH outcomes. On a hit that is memoization; on a miss it is
    // what prevents a duplicate hash later in this batch from inserting twice.
    this.claimed.add(hash);
    return row !== null;
  }
}

async function insertIncidents(db: D1Database, incidents: CyberPulseIncident[]): Promise<number> {
  if (incidents.length === 0) return 0;
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO cyberpulse_incidents (
      id, incident_type, severity, victim_name, victim_domain, victim_sector,
      victim_country, threat_actor, threat_actor_aliases, title, description,
      data_types_leaked, records_count, data_volume, source_platform, source_url,
      source_handle, source_text, source_author, source_avatar, confidence,
      classification_method, discovered_at, reported_at, updated_at, dedup_hash,
      duplicate_of, tags, mitre_techniques, source_likes, source_retweets,
      source_replies, source_views
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
  `);
  const batches = [];
  for (const inc of incidents) {
    batches.push(
      stmt.bind(
        inc.id,
        inc.incident_type,
        inc.severity,
        inc.victim_name,
        inc.victim_domain,
        inc.victim_sector,
        inc.victim_country,
        inc.threat_actor,
        inc.threat_actor_aliases,
        inc.title,
        inc.description,
        inc.data_types_leaked,
        inc.records_count,
        inc.data_volume,
        inc.source_platform,
        inc.source_url,
        inc.source_handle,
        inc.source_text,
        inc.source_author,
        inc.source_avatar,
        inc.confidence,
        inc.classification_method,
        inc.discovered_at,
        inc.reported_at,
        inc.updated_at,
        inc.dedup_hash,
        inc.duplicate_of,
        inc.tags,
        inc.mitre_techniques,
        inc.source_likes,
        inc.source_retweets,
        inc.source_replies,
        inc.source_views
      )
    );
  }
  // D1 batch — up to 50 statements per batch
  let inserted = 0;
  for (let i = 0; i < batches.length; i += 50) {
    const batch = batches.slice(i, i + 50);
    const results = await db.batch(batch);
    inserted += results.filter((r) => r.meta?.changes > 0).length;
  }
  return inserted;
}

function buildIncident(
  classification: ClassificationResult,
  post: RawPost,
  now: string,
  hash: string,
  platform: Platform
): CyberPulseIncident {
  const tags = [...classification.tags];
  if (classification.classification_verified) tags.push('verified');
  else tags.push('unverified');

  return {
    id: generateId(),
    incident_type: classification.incident_type,
    severity: classification.severity,
    victim_name: classification.victim_name,
    victim_domain: classification.victim_domain,
    victim_sector: classification.victim_sector,
    victim_country: classification.victim_country,
    threat_actor: classification.threat_actor,
    threat_actor_aliases: '[]',
    title: post.text.slice(0, 200).replace(/\n/g, ' '),
    description: post.text,
    data_types_leaked: JSON.stringify(classification.data_types_leaked),
    records_count: classification.records_count,
    data_volume: classification.data_volume,
    source_platform: platform,
    source_url: post.url,
    source_handle: post.handle,
    source_text: post.text,
    source_author: post.author,
    source_avatar: post.avatar,
    confidence: classification.confidence,
    classification_method: 'keyword',
    discovered_at: now,
    reported_at: post.published_at,
    updated_at: now,
    dedup_hash: hash,
    duplicate_of: null,
    tags: JSON.stringify(tags),
    mitre_techniques: JSON.stringify(classification.mitre_techniques),
    source_likes: post.likes,
    source_retweets: post.retweets,
    source_replies: post.replies,
    source_views: post.views,
  };
}

async function logScan(
  db: D1Database,
  source: string,
  handle: string | null,
  query: string | null,
  itemsFound: number,
  incidentsCreated: number,
  incidentsDeduped: number,
  durationMs: number,
  error: string | null
): Promise<void> {
  // Skip quiet no-op scans: 4 rows/run × 72 runs/day = 288 rows/day of
  // "scanned 0, created 0" even when every feed is cold. Errors and
  // productive scans are always logged; pure zeros carry no signal.
  if (!error && incidentsCreated === 0 && itemsFound === 0) return;
  await db
    .prepare(
      `INSERT INTO cyberpulse_scan_log (source, handle, query, scanned_at, items_found, incidents_created, incidents_deduped, duration_ms, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      source,
      handle,
      query,
      new Date().toISOString(),
      itemsFound,
      incidentsCreated,
      incidentsDeduped,
      durationMs,
      error
    )
    .run();
}

// ─── Telegram & social feed converters ──────────────────────────────────────

/** Telegram channels that report breaches/leaks/ransomware. */
const TELEGRAM_BREACH_CHANNELS = new Set([
  'falconfeedsio',
  'RansomLook',
  'secharvester',
  'ctinow',
  'ctiwatch',
  'FSECINTELES2',
  'BleepingComputer',
  'TheHackerNews',
  'cyber_security_channel',
  'mythreatintel',
  'vxunderground',
  'IntCyberDigest',
  // 2026-09-12 batch: Dark Web Informer FBI watch, DARKFEED victim-news,
  // Brut Security (FR) breach news — all verified with live previews.
  'FBI_Watchdog',
  'DarkfeedNews',
  'brutsecurity',
]);

/** Convert a Telegram feed item to a RawPost for classification. */
function telegramItemToRawPost(item: TelegramFeedItem): RawPost | null {
  // Skip channels not relevant to breach/leak tracking
  if (!TELEGRAM_BREACH_CHANNELS.has(item.channel_handle)) return null;
  // Skip very short posts (likely not incident reports)
  if (item.text.length < 40) return null;
  return {
    text: item.text,
    url: item.permalink,
    platform: 'telegram' as Platform,
    handle: item.channel_handle,
    author: item.channel_name,
    avatar: null,
    published_at: item.datetime,
    likes: 0,
    retweets: 0,
    replies: 0,
    views: parseViews(item.views),
  };
}

function parseViews(views?: string): number {
  if (!views) return 0;
  const cleaned = views.replace(/[,.\s]/g, '').toLowerCase();
  if (cleaned.endsWith('k')) return Math.round(parseFloat(cleaned) * 1000);
  if (cleaned.endsWith('m')) return Math.round(parseFloat(cleaned) * 1_000_000);
  return parseInt(cleaned, 10) || 0;
}

/** Convert a Bluesky/Mastodon feed item to a RawPost for classification. */
function xFeedItemToRawPost(item: XFeedItem): RawPost | null {
  // Skip very short posts
  if (item.text.length < 40) return null;
  return {
    text: item.text,
    url: item.link,
    platform: item.platform as Platform,
    handle: item.handle,
    author: item.handle_name,
    avatar: null,
    published_at: item.pub_date,
    likes: 0,
    retweets: 0,
    replies: 0,
    views: 0,
  };
}

/**
 * Fetch Telegram breach/leak feed. When `items` is supplied (reused from the
 * cron's earlier fetch) no new t.me request is made — see CyberPulsePrefetch.
 */
async function fetchTelegramBreachFeed(kv?: KVNamespace, items?: TelegramFeedItem[], env?: Env): Promise<RawPost[]> {
  try {
    const feedItems = items ?? (await fetchTelegramFeed(kv, env)).items;
    return feedItems.map(telegramItemToRawPost).filter((p): p is RawPost => p !== null);
  } catch (_catchErr) {
    logError('fetchTelegramBreachFeed failed', _catchErr);
    return [];
  }
}

/** Fetch Bluesky/Mastodon social feed. Reuses `items` when supplied.
 *  When `fetched` is true (cron already called fetchXFeed), accepts even
 *  an empty array — re-fetching would waste subrequest budget. */
async function fetchSocialBreachFeed(items?: XFeedItem[], fetched?: boolean): Promise<RawPost[]> {
  try {
    const feedItems = items && items.length > 0 ? items : fetched ? (items ?? []) : (await fetchXFeed()).items;
    if (feedItems.length === 0) {
    }
    return feedItems.map(xFeedItemToRawPost).filter((p): p is RawPost => p !== null);
  } catch {
    return [];
  }
}

/** Convert a Reddit feed item to a RawPost for classification. */
function redditItemToRawPost(item: RedditFeedItem): RawPost {
  return {
    text: item.text || item.title,
    url: item.link,
    platform: 'reddit' as Platform,
    handle: item.sub,
    author: item.author,
    avatar: null,
    published_at: item.pub_date,
    likes: 0,
    retweets: 0,
    replies: 0,
    views: 0,
  };
}

/** Fetch Reddit breach/leak feed. Reuses `items` when supplied.
 *  When `fetched` is true (cron already called fetchRedditFeed), accepts even
 *  an empty array — re-fetching would waste subrequest budget. */
async function fetchRedditBreachFeed(items?: RedditFeedItem[], fetched?: boolean): Promise<RawPost[]> {
  try {
    const feedItems = items && items.length > 0 ? items : fetched ? (items ?? []) : (await fetchRedditFeed()).items;
    return feedItems.map(redditItemToRawPost);
  } catch (_catchErr) {
    logError('fetchRedditBreachFeed failed', _catchErr);
    return [];
  }
}

// ─── Main ingestion pipeline ────────────────────────────────────────────────

export { X_ACCOUNTS };

/** Full ingestion pass — called by the hourly cron. */
export async function runCyberPulseIngestion(
  env: Env,
  db: D1Database,
  prefetched: CyberPulsePrefetch = {}
): Promise<IngestResult[]> {
  const results: IngestResult[] = [];
  const dedup = new DedupProbe();
  const now = new Date().toISOString();

  // ── 1. X account monitoring ──────────────────────────────────────────
  const xStart = Date.now();
  try {
    const xPosts = await fetchXAccountPosts(env, X_ACCOUNTS, 0.08, prefetched.xClaimsBreach, prefetched.xAccountPosts);
    let created = 0;
    let deduped = 0;
    const incidents: CyberPulseIncident[] = [];

    for (const post of xPosts) {
      const classification = classifyIncident(post.text, 'x', post.url);
      // X accounts are curated breach-intel sources — keep all non-retweet posts
      if (classification.confidence < 0.2 && classification.incident_type === 'other') continue;

      const hash = dedupHash(post.text.slice(0, 200), classification.victim_name ?? '', 'x');
      if (await dedup.claim(db, hash)) {
        deduped++;
        continue;
      }

      incidents.push(buildIncident(classification, post, now, hash, 'x'));
    }

    const inserted = await insertIncidents(db, incidents);
    created += inserted;
    await logScan(
      db,
      'x_accounts',
      X_ACCOUNTS.join(','),
      null,
      xPosts.length,
      created,
      deduped,
      Date.now() - xStart,
      null
    );
    results.push({
      source: 'x_accounts',
      items_scanned: xPosts.length,
      incidents_created: created,
      incidents_deduped: deduped,
      errors: [],
      duration_ms: Date.now() - xStart,
    });
  } catch (e) {
    logError('handler failed', e);
    const err = e instanceof Error ? e.message : String(e);
    await logScan(db, 'x_accounts', null, null, 0, 0, 0, Date.now() - xStart, err);
    results.push({
      source: 'x_accounts',
      items_scanned: 0,
      incidents_created: 0,
      incidents_deduped: 0,
      errors: [err],
      duration_ms: Date.now() - xStart,
    });
  }

  // ── 2. Telegram breach/leak channels ─────────────────────────────────
  const tgStart = Date.now();
  try {
    const tgPosts = await fetchTelegramBreachFeed(env.KV_CACHE, prefetched.telegramItems, env);
    let created = 0;
    let deduped = 0;
    const incidents: CyberPulseIncident[] = [];

    for (const post of tgPosts) {
      const classification = classifyIncident(post.text, 'telegram', post.url);
      if (classification.confidence < 0.3 && classification.incident_type === 'other') continue;

      const hash = dedupHash(post.text.slice(0, 200), classification.victim_name ?? '', 'telegram');
      if (await dedup.claim(db, hash)) {
        deduped++;
        continue;
      }

      incidents.push(buildIncident(classification, post, now, hash, 'telegram'));
    }

    const inserted = await insertIncidents(db, incidents);
    created += inserted;
    await logScan(
      db,
      'telegram',
      TELEGRAM_BREACH_CHANNELS.size + ' channels',
      null,
      tgPosts.length,
      created,
      deduped,
      Date.now() - tgStart,
      null
    );
    results.push({
      source: 'telegram',
      items_scanned: tgPosts.length,
      incidents_created: created,
      incidents_deduped: deduped,
      errors: [],
      duration_ms: Date.now() - tgStart,
    });
  } catch (e) {
    logError('handler failed', e);
    const err = e instanceof Error ? e.message : String(e);
    await logScan(db, 'telegram', null, null, 0, 0, 0, Date.now() - tgStart, err);
    results.push({
      source: 'telegram',
      items_scanned: 0,
      incidents_created: 0,
      incidents_deduped: 0,
      errors: [err],
      duration_ms: Date.now() - tgStart,
    });
  }

  // ── 4. Bluesky + Mastodon social feed ─────────────────────────────────
  const socialStart = Date.now();
  try {
    const socialPosts = await fetchSocialBreachFeed(prefetched.socialItems, prefetched.socialFetched);
    let created = 0;
    let deduped = 0;
    const incidents: CyberPulseIncident[] = [];

    for (const post of socialPosts) {
      const classification = classifyIncident(post.text, post.platform, post.url);
      if (classification.confidence < 0.15 && classification.incident_type === 'other') continue;

      const hash = dedupHash(post.text.slice(0, 200), classification.victim_name ?? '', post.platform);
      if (await dedup.claim(db, hash)) {
        deduped++;
        continue;
      }

      incidents.push(buildIncident(classification, post, now, hash, post.platform));
    }

    const inserted = await insertIncidents(db, incidents);
    created += inserted;
    await logScan(
      db,
      'bluesky_mastodon',
      null,
      null,
      socialPosts.length,
      created,
      deduped,
      Date.now() - socialStart,
      null
    );
    results.push({
      source: 'bluesky_mastodon',
      items_scanned: socialPosts.length,
      incidents_created: created,
      incidents_deduped: deduped,
      errors: [],
      duration_ms: Date.now() - socialStart,
    });
  } catch (e) {
    logError('handler failed', e);
    const err = e instanceof Error ? e.message : String(e);
    await logScan(db, 'bluesky_mastodon', null, null, 0, 0, 0, Date.now() - socialStart, err);
    results.push({
      source: 'bluesky_mastodon',
      items_scanned: 0,
      incidents_created: 0,
      incidents_deduped: 0,
      errors: [err],
      duration_ms: Date.now() - socialStart,
    });
  }

  // ── 5. Reddit social feed ─────────────────────────────────────────────
  const redditStart = Date.now();
  try {
    const redditPosts = await fetchRedditBreachFeed(prefetched.redditItems, prefetched.redditFetched);
    let created = 0;
    let deduped = 0;
    const incidents: CyberPulseIncident[] = [];

    for (const post of redditPosts) {
      const classification = classifyIncident(post.text, 'reddit', post.url);
      if (classification.confidence < 0.3 && classification.incident_type === 'other') continue;

      const hash = dedupHash(post.text.slice(0, 200), classification.victim_name ?? '', 'reddit');
      if (await dedup.claim(db, hash)) {
        deduped++;
        continue;
      }

      incidents.push(buildIncident(classification, post, now, hash, 'reddit'));
    }

    const inserted = await insertIncidents(db, incidents);
    created += inserted;
    await logScan(db, 'reddit', null, null, redditPosts.length, created, deduped, Date.now() - redditStart, null);
    results.push({
      source: 'reddit',
      items_scanned: redditPosts.length,
      incidents_created: created,
      incidents_deduped: deduped,
      errors: [],
      duration_ms: Date.now() - redditStart,
    });
  } catch (e) {
    logError('handler failed', e);
    const err = e instanceof Error ? e.message : String(e);
    await logScan(db, 'reddit', null, null, 0, 0, 0, Date.now() - redditStart, err);
    results.push({
      source: 'reddit',
      items_scanned: 0,
      incidents_created: 0,
      incidents_deduped: 0,
      errors: [err],
      duration_ms: Date.now() - redditStart,
    });
  }

  return results;
}
