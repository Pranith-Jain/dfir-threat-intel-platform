import { errMessage } from './err';
export type DbBriefType = 'cyber' | 'deepfake' | 'disaster' | 'maritime';

interface DbIndexEntry {
  type: DbBriefType;
  date: string;
  sizeBytes: number;
}

interface DbIndex {
  source: string;
  license: string;
  generatedAt: string;
  counts: { cyber: number; deepfake: number; disaster: number; maritime: number };
  briefs: DbIndexEntry[];
}

const BRIEF_TYPES: DbBriefType[] = ['cyber', 'deepfake', 'disaster', 'maritime'];
const BASE_URL = 'https://agentic-ai-daily-reports.netlify.app';

const KV_PREFIX_INDEX = 'db:index';
const KV_PREFIX_BODY = 'db:body';
/** 30 days — daily briefs are useful for a month, then the static
 *  manifest in public/data/daily-briefs/ has the historical copy. */
const BODY_TTL_S = 30 * 24 * 3600;
/** 7 days — the index is rewritten every sync; TTL prevents
 *  orphaned keys if the sync stops running. */
const INDEX_TTL_S = 7 * 24 * 3600;

function stripTags(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#\d+;/g, '')
    .replace(/\u2011/g, '-') // non-breaking hyphen → ASCII (CVE IDs etc.)
    .replace(/\u2013|\u2014/g, '-')
    .replace(/\u2018|\u2019/g, "'")
    .replace(/\u201c|\u201d/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Extract the body of a named section. Matches the heading variants used
 * across the reference site's brief types (the site has been redesigned
 * multiple times, so all historical variants are kept):
 *   1. <h2>Title</h2>                         (deepfake, current disaster/cyber)
 *   2. <h2>N. Title</h2>                      (maritime — numbered)
 *   3. <h2 class="sec">Title</h2>             (legacy disaster)
 *   4. <div class="section-title">Title</div>  (legacy cyber)
 */
function extractSection(html: string, heading: string): string {
  const esc = escapeRegex(heading);
  const variants: RegExp[] = [
    // <h2>Title</h2>  (bare — deepfake, current disaster/cyber)
    new RegExp(
      `<h2[^>]*>\\s*${esc}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2[^>]*>|<section class="section"|<section class="panel"|<footer|<aside|$)`,
      'i'
    ),
    // <h2>N. Title</h2>  (maritime numbered)
    new RegExp(`<h2[^>]*>\\s*\\d+\\.\\s*${esc}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2[^>]*>|<footer|<aside|$)`, 'i'),
    // <h2 class="sec">Title</h2>  (legacy disaster)
    new RegExp(`<h2 class="sec"[^>]*>\\s*${esc}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2 class="sec"|<footer|<aside|$)`, 'i'),
    // <div class="section-title">Title</div>  (legacy cyber)
    new RegExp(
      `<div class="section-title"[^>]*>\\s*${esc}[\\s\\S]*?</div>[\\s\\S]*?<div class="section-body"[^>]*>([\\s\\S]*?)(?=<section class="section"|<footer|<aside|$)`,
      'i'
    ),
  ];
  for (const re of variants) {
    const m = html.match(re);
    if (m && m[1] && m[1].trim()) return m[1]!;
  }
  // Fuzzy: match on the first word only.
  const firstWord = escapeRegex(heading.split(/\s+/)[0] ?? heading);
  const fuzzy: RegExp[] = [
    new RegExp(`<h2[^>]*>[^<]*${firstWord}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2[^>]*>|<footer|<aside|$)`, 'i'),
    new RegExp(
      `<div class="section-title"[^>]*>[^<]*${firstWord}[\\s\\S]*?</div>[\\s\\S]*?<div class="section-body"[^>]*>([\\s\\S]*?)(?=<section class="section"|<footer|$)`,
      'i'
    ),
  ];
  for (const re of fuzzy) {
    const m = html.match(re);
    if (m && m[1] && m[1].trim()) return m[1]!;
  }
  return '';
}

function extractChips(html: string): string[] {
  const chips: string[] = [];
  // Match both <span class="chip"> (old) and <span class="pill"> (new DOM)
  const re = /<span class="(?:chip|pill)"[^>]*>([\s\S]*?)<\/span>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const t = stripTags(m[1]!).trim();
    if (t) chips.push(t);
  }
  return chips;
}

function extractLinks(html: string): { url: string; label: string }[] {
  const links: { url: string; label: string }[] = [];
  const re = /<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const label = stripTags(m[2]!).trim();
    if (m[1] && !m[1].startsWith('#')) links.push({ url: m[1]!, label });
  }
  return links;
}

function extractListItems(html: string): string[] {
  const items: string[] = [];
  const re = /<li>([\s\S]*?)<\/li>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const t = stripTags(m[1]!).trim();
    if (t) items.push(t);
  }
  return items;
}

/** Split a free-text section (no chips/li) into bullet-ish items: split on
 *  line breaks, then on bullet dashes, dropping empty/decorative pieces.
 *  Used for the current-DOM "Affected Vendors" / "Affected Sectors" panels
 *  which render as plain text with <br> separators. */
function splitTextList(html: string): string[] {
  const text = stripTags(html);
  if (!text) return [];
  const pieces = text
    .split(/<br\s*\/?>|\n/)
    .flatMap((line) => line.split(/\s*[•·]\s*/))
    .map((s) => s.replace(/^[-–—]\s*/, '').trim())
    .filter((s) => s && s.length > 2);
  return [...new Set(pieces)];
}

const MONTHS: Record<string, number> = {
  january: 0,
  february: 1,
  march: 2,
  april: 3,
  may: 4,
  june: 5,
  july: 6,
  august: 7,
  september: 8,
  october: 9,
  november: 10,
  december: 11,
};

function extractDate(html: string): string {
  // Extract the report date from a DEDICATED date marker — never from the
  // first random "Month DD, YYYY" in the body, which can be a stale
  // reference to a previous day when the upstream site is mid-update.
  // Priority order, per brief type:
  //   cyber:    "Report date: 2026-08-05"            (ISO)
  //   deepfake: "Generated: Wednesday, August 05, 2026" (in .subtitle)
  //   disaster: "Generated: Wednesday, August 05, 2026" (in .badge)
  //             or "Report Date: 05 Aug 2026"          (in .pill)
  //   maritime: "Publication Date: Wednesday, August 05, 2026" (in .badge)
  //             or title "– Wednesday, August 05, 2026" (en-dash)

  // 1. ISO "Report date: 2026-08-05" (cyber)
  const iso = html.match(/Report date[^0-9]*?(\d{4}-\d{2}-\d{2})/i);
  if (iso) return iso[1]!;

  // 2. Dedicated labelled markers: "Generated:", "Publication Date:",
  //    "Report Date:", and the current cyber masthead's bare "Date:" —
  //    masthead/header fields, not body prose.
  const labelled = html.match(/(?:Generated|Publication Date|Report Date|Date)\s*:\s*([^<\n]{3,60}?)(?:<|\n|$)/i);
  if (labelled) {
    const s = stripTags(labelled[1]!).trim();
    const long = s.match(
      /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
    );
    if (long) {
      const mon = MONTHS[long[1]!.toLowerCase()];
      if (mon !== undefined) return `${long[3]!}-${String(mon + 1).padStart(2, '0')}-${long[2]!.padStart(2, '0')}`;
    }
    const short = s.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{4})/i);
    if (short) {
      const monMap: Record<string, number> = {
        jan: 0,
        feb: 1,
        mar: 2,
        apr: 3,
        may: 4,
        jun: 5,
        jul: 6,
        aug: 7,
        sep: 8,
        oct: 9,
        nov: 10,
        dec: 11,
      };
      const mon = monMap[short[2]!.toLowerCase().slice(0, 3)];
      if (mon !== undefined) return `${short[3]!}-${String(mon + 1).padStart(2, '0')}-${short[1]!.padStart(2, '0')}`;
    }
  }

  // 3. <title> with a date — handle hyphen OR en-dash (–/—) separators and
  //    both "Month DD, YYYY" and "DD Mon YYYY" formats.
  const titleDate = html.match(/<title>[^<]*?[\u2012-\u2015\-]\s*([^<]+?)<\/title>/i);
  if (titleDate) {
    const s = titleDate[1]!;
    const long = s.match(
      /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
    );
    if (long) {
      const mon = MONTHS[long[1]!.toLowerCase()];
      if (mon !== undefined) return `${long[3]!}-${String(mon + 1).padStart(2, '0')}-${long[2]!.padStart(2, '0')}`;
    }
    const short = s.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{4})/i);
    if (short) {
      const monMap: Record<string, number> = {
        jan: 0,
        feb: 1,
        mar: 2,
        apr: 3,
        may: 4,
        jun: 5,
        jul: 6,
        aug: 7,
        sep: 8,
        oct: 9,
        nov: 10,
        dec: 11,
      };
      const mon = monMap[short[2]!.toLowerCase().slice(0, 3)];
      if (mon !== undefined) return `${short[3]!}-${String(mon + 1).padStart(2, '0')}-${short[1]!.padStart(2, '0')}`;
    }
  }

  // 4. Masthead date div (legacy fallback)
  const m = html.match(/<div class="date"[^>]*>([\s\S]*?)<\/div>/i);
  if (m) return stripTags(m[1]!).trim();

  // 5. Last resort: first "Month DD, YYYY" anywhere (risky — kept so we never return empty)
  const m2 = html.match(
    /(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}/i
  );
  return m2 ? m2[0]! : '';
}

function dateFromContent(html: string): string {
  const dateStr = extractDate(html);
  if (!dateStr) return new Date().toISOString().slice(0, 10);
  // Already ISO (from the cyber "Report date" path or the labelled/title paths)
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return dateStr;
  const named = dateStr.match(
    /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
  );
  if (named) {
    const month = MONTHS[named[1]!.toLowerCase()];
    const day = Number(named[2]);
    const year = Number(named[3]);
    if (month !== undefined && day >= 1 && day <= 31)
      return `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  }
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
  return d.toISOString().slice(0, 10);
}

function extractBalancedDiv(html: string, startIdx: number): string {
  // startIdx points at a `<div ...>` opening tag. Start scanning AFTER it
  // with depth=1 (we're already inside the opening div) so the matching
  // close is the one that brings depth back to 0.
  let depth = 1;
  let i = startIdx + 4;
  while (i < html.length) {
    const nextOpen = html.indexOf('<div', i);
    const nextClose = html.indexOf('</div>', i);
    if (nextClose === -1) return html.slice(startIdx);
    if (nextOpen !== -1 && nextOpen < nextClose) {
      depth++;
      i = nextOpen + 4;
    } else {
      depth--;
      if (depth === 0) return html.slice(startIdx, nextClose + 6);
      i = nextClose + 6;
    }
  }
  return html.slice(startIdx);
}

/** Like extractBalancedDiv but for an arbitrary tag (article/section/li).
 *  startIdx points at the OPENING TAG; tagName is e.g. 'article' or 'div'. */
function extractBalancedTag(html: string, startIdx: number, tagName: string): string {
  const openRe = new RegExp(`<${tagName}[\\s>]`, 'gi');
  const closeTag = `</${tagName}>`;
  let depth = 1;
  let i = startIdx + 4;
  while (i < html.length) {
    openRe.lastIndex = i;
    const nextOpen = openRe.exec(html);
    const nextClose = html.indexOf(closeTag, i);
    if (nextClose === -1) return html.slice(startIdx);
    if (nextOpen && nextOpen.index < nextClose) {
      depth++;
      i = nextOpen.index + 4;
    } else {
      depth--;
      if (depth === 0) return html.slice(startIdx, nextClose + closeTag.length);
      i = nextClose + closeTag.length;
    }
  }
  return html.slice(startIdx);
}

/** cyber masthead: <section class="kpi-row"><div class="kpi"><h4>L</h4><div class="value">V</div><div class="sub">S</div></div>…
 *  legacy: <div class="kpi"><div class="label">L</div><div class="value">V</div><div class="trend">T</div></div> */
function extractKpisCyber(html: string): { value: string; label: string; trend?: string }[] {
  const kpis: { value: string; label: string; trend?: string }[] = [];
  const re = /<div class="kpi"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const inner = extractBalancedDiv(html, m.index);
    const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const trend =
      inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i) ||
      inner.match(/<div class="sub"[^>]*>([\s\S]*?)<\/div>/i);
    const l = h4 ? stripTags(h4[1]!).trim() : label ? stripTags(label[1]!).trim() : '';
    const v = value ? stripTags(value[1]!).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(trend ? { trend: stripTags(trend[1]!).trim() } : {}) });
  }
  return kpis;
}

/** disaster KPIs (current DOM): <div class="card kpi"><div class="label">L</div><div class="value">V</div><div class="trend">T</div></div>
 *  mid DOM: <div class="metric"> with muted/num/muted children
 *  old DOM: <div class="kpi escalate"><h4>L</h4><div class="val">V</div><div class="note">N</div></div> */
function extractKpisDisaster(html: string): { value: string; label: string; trend?: string }[] {
  const kpis: { value: string; label: string; trend?: string }[] = [];
  // Current: <div class="card kpi"> with .label/.value/.trend
  const re = /<div class="card\s+kpi"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const inner = extractBalancedDiv(html, m.index);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const trend = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i);
    const l = label ? stripTags(label[1]!).trim() : '';
    const v = value ? stripTags(value[1]!).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(trend ? { trend: stripTags(trend[1]!).trim() } : {}) });
  }
  // Mid: <div class="metric"> with muted/num/muted children
  if (kpis.length === 0) {
    const re2 = /<div class="metric"[^>]*>/gi;
    while ((m = re2.exec(html)) !== null) {
      const inner = extractBalancedDiv(html, m.index);
      const muteds = inner.match(/<div class="muted"[^>]*>([\s\S]*?)<\/div>/gi) || [];
      const num = inner.match(/<div class="num"[^>]*>([\s\S]*?)<\/div>/i);
      const label = muteds[0] ? stripTags(muteds[0]).trim() : '';
      const value = num ? stripTags(num[1]!).trim() : '';
      const note = muteds[1] ? stripTags(muteds[1]).trim() : '';
      if (label || value) kpis.push({ value, label, ...(note ? { trend: note } : {}) });
    }
  }
  // Old: <div class="kpi escalate"><h4>L</h4><div class="val">V</div>…
  if (kpis.length === 0) {
    const re3 = /<div class="kpi[^"]*"[^>]*>/gi;
    while ((m = re3.exec(html)) !== null) {
      const inner = extractBalancedDiv(html, m.index);
      const label = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
      const val = inner.match(/<div class="val"[^>]*>([\s\S]*?)<\/div>/i);
      const note = inner.match(/<div class="note"[^>]*>([\s\S]*?)<\/div>/i);
      const l = label ? stripTags(label[1]!).trim() : '';
      const v = val ? stripTags(val[1]!).trim() : '';
      if (l || v) kpis.push({ value: v, label: l, ...(note ? { trend: stripTags(note[1]!).trim() } : {}) });
    }
  }
  return kpis;
}

/** maritime KPIs (current DOM): <div class="col-3 card kpi"><div class="label">L</div><div class="value">V</div><div class="note">N</div></div>
 *  mid DOM: <div class="kpi"><span>Label</span><strong>Value</strong></div>.
 *  Old DOM used <div class="card"><div class="label">/<div class="metric">. */
function extractKpisMaritime(html: string): { value: string; label: string; trend?: string }[] {
  const kpis: { value: string; label: string; trend?: string }[] = [];
  const dash = extractSection(html, 'Maritime Threat Dashboard') || '';
  // Current: <div class="col-3 card kpi"> with .label/.value/.note
  const re = /<div class="[^"]*card\s+kpi[^"]*"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(dash)) !== null) {
    const inner = extractBalancedDiv(dash, m.index);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const note = inner.match(/<div class="note"[^>]*>([\s\S]*?)<\/div>/i);
    const l = label ? stripTags(label[1]!).trim() : '';
    const v = value ? stripTags(value[1]!).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(note ? { trend: stripTags(note[1]!).trim() } : {}) });
  }
  // Mid: <div class="kpi"><span>L</span><strong>V</strong></div>
  if (kpis.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(dash)) !== null) {
      const inner = extractBalancedDiv(dash, m.index);
      const span = inner.match(/<span[^>]*>([\s\S]*?)<\/span>/i);
      const strong = inner.match(/<strong[^>]*>([\s\S]*?)<\/strong>/i);
      const l = span ? stripTags(span[1]!).trim() : '';
      const v = strong ? stripTags(strong[1]!).trim() : '';
      if (l || v) kpis.push({ value: v, label: l });
    }
  }
  // Old DOM: <div class="card"><div class="label">/<div class="metric">
  if (kpis.length === 0) {
    const re3 = /<div class="card"[^>]*>/gi;
    while ((m = re3.exec(dash)) !== null) {
      const inner = extractBalancedDiv(dash, m.index);
      const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
      const metric = inner.match(/<div class="metric"[^>]*>([\s\S]*?)<\/div>/i);
      const l = label ? stripTags(label[1]!).trim() : '';
      let v = metric ? stripTags(metric[1]!).trim() : '';
      v = v.replace(/\s+Level\s*$/, '').trim();
      if (l || v) kpis.push({ value: v, label: l });
    }
  }
  return kpis;
}

/** cyber dashboard cards: <div class="dash-row"><div class="card"><h3>Title</h3><div>text</div>…</div></div>
 *  (current DOM) — legacy grid-of-kpi blocks also matched. */
function extractCardsCyberDash(html: string): { title: string; text: string; chips: string[] }[] {
  const dash = extractSection(html, 'Threat Dashboard') || html;
  const cards: { title: string; text: string; chips: string[] }[] = [];
  const re = /<div class="card"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(dash)) !== null) {
    const inner = extractBalancedDiv(dash, m.index);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    if (!h3) continue;
    const title = stripTags(h3[1]!).trim();
    const textDiv = inner.match(/<h3[^>]*>[\s\S]*?<\/h3>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const text = textDiv ? stripTags(textDiv[1]!).trim() : '';
    cards.push({ title, text, chips: extractChips(inner) });
  }
  if (cards.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(dash)) !== null) {
      const inner = extractBalancedDiv(dash, m.index);
      const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
      const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
      const note =
        inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i) ||
        inner.match(/<div class="note"[^>]*>([\s\S]*?)<\/div>/i);
      const title = label ? stripTags(label[1]!).trim() : '';
      const text = value ? stripTags(value[1]!).trim() : note ? stripTags(note[1]!).trim() : '';
      if (title) cards.push({ title, text, chips: extractChips(inner) });
    }
  }
  return cards;
}

/** cyber priority threats (current DOM): <div class="two-col"><div class="card"><h3>N) Title</h3><div>text</div><div class="link"><a…></a></div></div>
 *  legacy: <div class="kpi"><div class="label">N) Title</div><div class="value">Action</div>…
 *  NOTE: caller passes the already-extracted section (see parseCyberBrief). */
function extractCardsCyberPriority(
  section: string
): { title: string; action: string; sources: { url: string; label: string }[]; trend?: string }[] {
  const cards: { title: string; action: string; sources: { url: string; label: string }[]; trend?: string }[] = [];
  const re = /<div class="card"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(section)) !== null) {
    const inner = extractBalancedDiv(section, m.index);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    if (!h3) continue;
    const title = stripTags(h3[1]!).trim();
    const textDiv = inner.match(/<h3[^>]*>[\s\S]*?<\/h3>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const action = textDiv ? stripTags(textDiv[1]!).trim() : '';
    cards.push({ title, action, sources: extractLinks(inner) });
  }
  if (cards.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(section)) !== null) {
      const inner = extractBalancedDiv(section, m.index);
      const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
      const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
      const trend = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i);
      const title = label ? stripTags(label[1]!).trim() : '';
      const action = value ? stripTags(value[1]!).trim() : '';
      cards.push({
        title,
        action,
        sources: extractLinks(inner),
        ...(trend ? { trend: stripTags(trend[1]!).trim() } : {}),
      });
    }
  }
  return cards;
}

/** cyber events (current DOM): <div class="event-groups"><div class="event-col"><h3><span class="pill critical">ESCALATE</span></h3>
 *  <div class="event-list"><div class="event escalate"><strong>Title</strong><div class="meta">desc</div><div class="link"><a…></div>
 *  Severity from the event class AND the group pill. Legacy band layout kept as fallback. */
function extractEventsCyber(
  html: string
): { title: string; severity: string; text: string; chips: string[]; sources: { url: string; label: string }[] }[] {
  const events: {
    title: string;
    severity: string;
    text: string;
    chips: string[];
    sources: { url: string; label: string }[];
  }[] = [];
  const colRe = /<div class="event-col"[^>]*>/gi;
  let cm: RegExpExecArray | null;
  while ((cm = colRe.exec(html)) !== null) {
    const col = extractBalancedDiv(html, cm.index);
    const pill = col.match(/<h3[^>]*>[\s\S]*?<span class="pill\s+(?:critical|moderate|low)"[^>]*>([^<]+)<\/span>/i);
    const groupSeverity = pill ? stripTags(pill[1]!).trim().toLowerCase() : '';
    const evRe = /<div class="event\s+(escalate|monitor|ignore)"[^>]*>/gi;
    let em: RegExpExecArray | null;
    while ((em = evRe.exec(col)) !== null) {
      const classSeverity = em[1]!.toLowerCase();
      const inner = extractBalancedDiv(col, em.index);
      const strong = inner.match(/<strong[^>]*>([\s\S]*?)<\/strong>/i);
      const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
      const link = inner.match(/<div class="link"[^>]*>([\s\S]*?)<\/div>/i);
      const title = strong ? stripTags(strong[1]!).trim() : '';
      const text = meta ? stripTags(meta[1]!).trim() : '';
      const severity = classSeverity || groupSeverity || 'monitor';
      const sources = link ? extractLinks(link[1]!) : extractLinks(inner);
      events.push({ title, severity, text, chips: [], sources });
    }
  }
  if (events.length === 0) {
    const bandRe =
      /<div class="band\s+(escalate|monitor|ignore)"[^>]*>[\s\S]*?<\/div>\s*<div class="event-columns">([\s\S]*?)(?=<div class="band\s+(?:escalate|monitor|ignore)"|<div class="section"|<footer|<aside|$)/gi;
    let bm: RegExpExecArray | null;
    while ((bm = bandRe.exec(html)) !== null) {
      const severity = bm[1]!.toLowerCase();
      const columns = bm[2]!;
      const evRe = /<div class="event"[^>]*>/gi;
      let em: RegExpExecArray | null;
      while ((em = evRe.exec(columns)) !== null) {
        const inner = extractBalancedDiv(columns, em.index);
        const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
        const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
        const p = inner.match(/<p>([\s\S]*?)<\/p>/i);
        const srcs = inner.match(/<div class="srcs"[^>]*>([\s\S]*?)<\/div>/i);
        const title = h4 ? stripTags(h4[1]!).trim() : '';
        const text = p ? stripTags(p[1]!).trim() : '';
        const chips = meta ? extractChips(meta[1]!) : [];
        const sources = srcs ? extractLinks(srcs[1]!) : extractLinks(inner);
        events.push({ title, severity, text, chips, sources });
      }
    }
  }
  return events;
}

/** deepfake incidents (current DOM): <article class="incident-card"><div class="inline-badges">
 *  <span class="badge escalate">ESCALATE</span><span class="badge high">High Urgency</span></div>
 *  <h3>Title</h3><div class="meta"><span>…</span>…</div><div class="field">…</div>…</article>
 *  Legacy used <div class="incident-card"> — both matched. */
function extractIncidentsDeepfake(html: string): {
  title: string;
  badges: string[];
  fields: Record<string, string>;
  summary: string;
  sources: { url: string; label: string }[];
}[] {
  const incidents: {
    title: string;
    badges: string[];
    fields: Record<string, string>;
    summary: string;
    sources: { url: string; label: string }[];
  }[] = [];
  const re = /<(?:div|article)\s+class="incident-card"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const tagName = m[0].startsWith('<article') ? 'article' : 'div';
    const inner = extractBalancedTag(html, m.index, tagName);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const title = h3 ? stripTags(h3[1]!).trim() : '';
    const badges: string[] = [];
    const badgeRe = /<span class="(?:badge|urgency)[^"]*"[^>]*>([^<]+)<\/span>/gi;
    let bm: RegExpExecArray | null;
    while ((bm = badgeRe.exec(inner)) !== null) badges.push(stripTags(bm[1]!).trim());
    const fields: Record<string, string> = {};
    const metaInner = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
    if (metaInner) {
      const spanRe = /<span[^>]*>([^:<>]+):\s*([^<]+)<\/span>/gi;
      let sm: RegExpExecArray | null;
      while ((sm = spanRe.exec(metaInner[1]!)) !== null) fields[stripTags(sm[1]!).trim()] = stripTags(sm[2]!).trim();
    }
    const summaryP =
      inner.match(/<div class="field"[^>]*><strong>Incident Summary:[^<]*<\/strong>\s*([\s\S]*?)<\/div>/i) ||
      inner.match(/<p><strong>Incident Summary:[^<]*<\/strong>\s*([\s\S]*?)<\/p>/i);
    const summary = summaryP ? stripTags(summaryP[1]!).trim() : '';
    const sources = extractLinks(inner);
    incidents.push({ title, badges, fields, summary, sources });
  }
  return incidents;
}

/** disaster events (current DOM): grouped under <h3>ESCALATE</h3>/<h3>MONITOR</h3> headers, each
 *  <div class="card"><div class="event-head"><p class="event-title">Title</p><div class="event-meta">
 *  <span class="badge escalate">ESCALATE</span>…</div></div><div class="event-body">text</div>
 *  <div class="indicators"><span class="pill">…</span>…</div><div class="event-nums"><span class="num">…</span>…
 *  <div class="spaced small">links</div></div>
 *  Severity comes from the group header and/or the <span class="badge escalate|monitor|ignore">.
 *  Mid DOM: <div class="card"><h3>Title</h3>…<span class="status escalate|monitor">. Old DOM:
 *  <div class="event-card indicator escalate|monitor"> with <h4 class="event-title">. */
function extractEventsDisaster(
  html: string
): { title: string; severity: string; text: string; chips: string[]; sources: { url: string; label: string }[] }[] {
  const events: {
    title: string;
    severity: string;
    text: string;
    chips: string[];
    sources: { url: string; label: string }[];
  }[] = [];
  const section = extractSection(html, 'Event Cards by Decision Level') || html;
  const groupRe = /<h3[^>]*>\s*(ESCALATE|MONITOR|IGNORE)\s*<\/h3>/gi;
  const groupSpans: { severity: string; start: number }[] = [];
  let gm: RegExpExecArray | null;
  while ((gm = groupRe.exec(section)) !== null) groupSpans.push({ severity: gm[1]!.toLowerCase(), start: gm.index });
  const cards: number[] = [];
  const re = /<div class="card"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(section)) !== null) cards.push(m.index);
  for (const idx of cards) {
    const inner = extractBalancedDiv(section, idx);
    let severity = 'monitor';
    for (const g of groupSpans) if (g.start < idx) severity = g.severity;
    const titleM =
      inner.match(/<p class="event-title"[^>]*>([\s\S]*?)<\/p>/i) ||
      inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i) ||
      inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (!titleM) continue;
    const title = stripTags(titleM[1]!).trim();
    const badge =
      inner.match(/<span class="badge\s+(escalate|monitor|ignore)"[^>]*>/i) ||
      inner.match(/<span class="status\s+(escalate|monitor|ignore)"[^>]*>/i) ||
      inner.match(/<span class="badge\s+(high|critical)"[^>]*>/i);
    if (badge)
      severity =
        badge[1]!.toLowerCase() === 'high' || badge[1]!.toLowerCase() === 'critical'
          ? 'escalate'
          : badge[1]!.toLowerCase();
    const chips: string[] = [];
    const chipRe = /<span class="(?:pill|tag)"[^>]*>([\s\S]*?)<\/span>/gi;
    let tm: RegExpExecArray | null;
    while ((tm = chipRe.exec(inner)) !== null) {
      const t = stripTags(tm[1]!).trim();
      if (t) chips.push(t);
    }
    const bodyM =
      inner.match(/<div class="event-body"[^>]*>([\s\S]*?)<\/div>/i) ||
      inner.match(/<p class="event-body"[^>]*>([\s\S]*?)<\/p>/i) ||
      inner.match(/<div class="row"[^>]*>[\s\S]*?<\/div>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const text = bodyM ? stripTags(bodyM[1]!).trim() : '';
    const sources = extractLinks(inner);
    events.push({ title, severity, text, chips, sources });
  }
  return events;
}

/** maritime priority (current DOM): <div class="col-6 card priority"><div class="title">N) Title</div>
 *  <div class="meta">chips</div><div class="impact">Why it matters: …</div>…</div>
 *  mid: <div class="card priority monitor-accent"><div class="title">…</div><div class="why">…
 *  old: <div class="priority"> with <h3><span class="num">) */
function extractPriorityMaritime(
  html: string
): { title: string; action: string; items: string[]; sources: { url: string; label: string }[]; rank?: string }[] {
  const cards: {
    title: string;
    action: string;
    items: string[];
    sources: { url: string; label: string }[];
    rank?: string;
  }[] = [];
  const section = extractSection(html, 'Top Five Priority Threats') || '';
  // Match <div class="col-6 card priority"> (class list, not exact)
  const re = /<div class="[^"]*card\s+priority[^"]*"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(section)) !== null) {
    const inner = extractBalancedDiv(section, m.index);
    const titleDiv = inner.match(/<div class="title"[^>]*>([\s\S]*?)<\/div>/i);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const num = h3 ? (h3[1]!.match(/<span class="num"[^>]*>([\s\S]*?)<\/span>/i) || [])[1] : '';
    const title = titleDiv ? stripTags(titleDiv[1]!).trim() : h3 ? stripTags(h3[1]!).trim() : '';
    const impactDiv = inner.match(/<div class="impact"[^>]*>([\s\S]*?)<\/div>/i);
    const whyDiv = inner.match(/<div class="why"[^>]*>([\s\S]*?)<\/div>/i);
    const whyMatch = inner.match(/Why it matters:\s*([\s\S]*?)(?=<ul|<a|<div class="impact"|<div class="why"|$)/i);
    const action = impactDiv
      ? stripTags(impactDiv[1]!)
          .replace(/^Why it matters:\s*/i, '')
          .trim()
      : whyDiv
        ? stripTags(whyDiv[1]!)
            .replace(/^Why it matters:\s*/i, '')
            .trim()
        : whyMatch
          ? stripTags(whyMatch[1]!).trim()
          : '';
    const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
    const items = ul ? extractListItems(ul[1]!) : [];
    const sources = extractLinks(inner);
    cards.push({ title, action, items, sources, ...(num ? { rank: stripTags(num).trim() } : {}) });
  }
  return cards;
}

/** maritime events (current DOM): grouped under <h3>C:ESCALATE</h3>/<h3>B:MONITOR</h3> headers, each
 *  <div class="card event escalate|monitor|ignore"><div class="head"><span class="title">Title</span>
 *  <span class="chip red">HIGH</span>…</div><div class="details">text</div><div class="tags">chips</div>…
 *  Severity from the group header (C:ESCALATE / B:MONITOR / A:IGNORE), the card class
 *  suffix, or the THREAT LEVEL text. Legacy event-card layouts kept as fallback. */
function extractEventsMaritime(html: string): {
  title: string;
  severity: string;
  text: string;
  chips: string[];
  sources: { url: string; label: string }[];
  items?: string[];
}[] {
  const events: {
    title: string;
    severity: string;
    text: string;
    chips: string[];
    sources: { url: string; label: string }[];
    items?: string[];
  }[] = [];
  const section = extractSection(html, 'Intelligence Event Cards') || html;
  const re = /<div class="[^"]*card\s+event(?:\s+(escalate|monitor|ignore))?[^"]*"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(section)) !== null) {
    const classSeverity = m[1] ? m[1]!.toLowerCase() : null;
    const inner = extractBalancedDiv(section, m.index);
    const titleM =
      inner.match(/<span class="title"[^>]*>([\s\S]*?)<\/span>/i) ||
      inner.match(/<div class="event-title"[^>]*>([\s\S]*?)<\/div>/i) ||
      inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    const title = titleM ? stripTags(titleM[1]!).trim() : '';
    const details = [...inner.matchAll(/<div class="details"[^>]*>([\s\S]*?)<\/div>/gi)]
      .map((d) => stripTags(d[1]!).trim())
      .filter(Boolean);
    const meta =
      inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i) ||
      inner.match(/<div class="event-meta"[^>]*>([\s\S]*?)<\/div>/i);
    const kicker = inner.match(/<div class="kicker"[^>]*>([\s\S]*?)<\/div>/i);
    const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
    let severity = classSeverity || 'monitor';
    const before = section.slice(0, m.index);
    const groupM = [...before.matchAll(/<h3[^>]*>\s*([ABC]):(ESCALATE|MONITOR|IGNORE)\s*<\/h3>/gi)].pop();
    if (groupM) {
      const t = groupM[2]!.toLowerCase();
      if (t === 'escalate' || t === 'ignore') severity = t;
    }
    if (meta) {
      const lvl = meta[1]!.match(/THREAT LEVEL:\s*(\w+)/i) || meta[1]!.match(/<div class="status\s+(\w+)"[^>]*>/i);
      if (lvl && lvl[1]) {
        const t = lvl[1]!.toLowerCase();
        if (t === 'critical' || t === 'high' || t === 'escalate') severity = 'escalate';
        else if (t === 'medium' || t === 'low' || t === 'monitor') severity = 'monitor';
        else if (t === 'ignore') severity = 'ignore';
      } else if (inner.match(/<span class="chip\s+red"[^>]*>/i)) {
        severity = 'escalate';
      } else if (inner.match(/<span class="chip\s+amber"[^>]*>/i)) {
        severity = 'monitor';
      }
    }
    const text =
      details.join(' ') ||
      ((kicker ? stripTags(kicker[1]!).trim() : '') + (ul ? ' ' + stripTags(ul[1]!).trim() : '')).trim();
    const items = ul ? extractListItems(ul[1]!) : [];
    const sources = extractLinks(inner);
    events.push({ title, severity, text, chips: extractChips(inner), sources, ...(items.length ? { items } : {}) });
  }
  if (events.length === 0) {
    const re2 = /<div class="event-card(?:\s+event-(escalate|monitor|ignore))?"[^>]*>/gi;
    while ((m = re2.exec(section)) !== null) {
      const classSeverity = m[1] ? m[1]!.toLowerCase() : null;
      const inner = extractBalancedDiv(section, m.index);
      const titleM =
        inner.match(/<div class="event-title"[^>]*>([\s\S]*?)<\/div>/i) || inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
      const title = titleM ? stripTags(titleM[1]!).trim() : '';
      const meta =
        inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i) ||
        inner.match(/<div class="event-meta"[^>]*>([\s\S]*?)<\/div>/i);
      const kicker = inner.match(/<div class="kicker"[^>]*>([\s\S]*?)<\/div>/i);
      const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
      let severity = classSeverity || 'monitor';
      if (meta) {
        const lvl = meta[1]!.match(/THREAT LEVEL:\s*(\w+)/i) || meta[1]!.match(/<div class="status\s+(\w+)"[^>]*>/i);
        if (lvl) {
          const t = lvl[1]!.toLowerCase();
          if (t === 'critical' || t === 'high' || t === 'escalate') severity = 'escalate';
          else if (t === 'medium' || t === 'low' || t === 'monitor') severity = 'monitor';
          else if (t === 'ignore') severity = 'ignore';
        }
      }
      const text = (kicker ? stripTags(kicker[1]!).trim() : '') + (ul ? ' ' + stripTags(ul[1]!).trim() : '');
      const items = ul ? extractListItems(ul[1]!) : [];
      const sources = extractLinks(inner);
      events.push({ title, severity, text: text.trim(), chips: [], sources, ...(items.length ? { items } : {}) });
    }
  }
  return events;
}

function parseCyberBrief(html: string, date: string) {
  const threatLevel = (() => {
    // current DOM: kpi-row kpi with <h4>Overall OT Threat Level</h4> and
    // <div class="value"><span class="pill critical">CRITICAL</span></div>
    const kpiRow = html.match(/<section class="kpi-row"[^>]*>([\s\S]*?)<\/section>/i);
    if (kpiRow) {
      const kpis = [...kpiRow[1]!.matchAll(/<div class="kpi"[^>]*>([\s\S]*?)<\/div>/gi)];
      for (const k of kpis) {
        const h4 = k[1]!.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
        if (h4 && /overall.*threat level/i.test(h4[1]!)) {
          const pill = k[1]!.match(/<span class="pill\s+\w+"[^>]*>([^<]+)<\/span>/i);
          if (pill) return stripTags(pill[1]!).trim().toUpperCase();
        }
      }
    }
    // legacy: <span class="level-pill lvl-critical">Overall Threat Level: CRITICAL</span>
    // was <div class="level-pill"> in the older DOM
    const pill = html.match(/<(?:span|div) class="level-pill[^>]*>([\s\S]*?)<\/(?:span|div)>/i);
    return pill ? stripTags(pill[1]!).trim() : '';
  })();

  const executiveSummary = stripTags(extractSection(html, 'Executive Summary')).trim();

  // Key Findings: <div class="finding">N) Title. Summary <a>…</a></div> (new DOM)
  // or <li> bullets (old DOM). Extract both.
  const kfSection = extractSection(html, 'Key Findings');
  const kfFindingItems: string[] = [];
  const findingRe = /<div class="finding"[^>]*>([\s\S]*?)<\/div>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = findingRe.exec(kfSection)) !== null) {
    const t = stripTags(fm[1]!).trim();
    if (t) kfFindingItems.push(t);
  }
  const kfItems = kfFindingItems.length > 0 ? kfFindingItems : extractListItems(kfSection);
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80)
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    const paren = item.match(/^\s*\d+\)\s*([^.]*)\.\s*(.*)$/);
    if (paren) return { title: paren[1]!.trim(), summary: paren[2]!.trim() };
    return { title: item.slice(0, 80), summary: item };
  });

  const kpis = extractKpisCyber(html);

  const dashboardSection = extractSection(html, 'Threat Dashboard');
  const dashboardCards = extractCardsCyberDash(dashboardSection);
  const dashboardMap: Record<string, { title: string; text: string; chips: string[] }> = {};
  for (const dc of dashboardCards) dashboardMap[dc.title.toLowerCase()] = dc;

  const activelyExploited = (() => {
    // current DOM dashboard card "Active Exploitation" body is a comma/semicolon list
    const current = dashboardMap['active exploitation'];
    if (current?.text)
      return current.text
        .split(/[;,]\s*/)
        .map((s) => s.trim())
        .filter(Boolean);
    const dashCard = dashboardMap['perimeter devices under active exploit'];
    if (dashCard?.text)
      return dashCard.text
        .split(/,\s*/)
        .map((s) => s.trim())
        .filter(Boolean);
    return extractChips(extractSection(html, 'Actively Exploited Focus'));
  })();

  const vendorsSection = extractSection(html, 'Affected Vendors');
  let vendors = [...new Set(extractChips(vendorsSection))];
  if (vendors.length === 0) vendors = splitTextList(vendorsSection);
  const sectorsSection = extractSection(html, 'Affected Sectors');
  let sectors = [...new Set(extractChips(sectorsSection))];
  if (sectors.length === 0) sectors = splitTextList(sectorsSection);

  const topThreats = extractCardsCyberPriority(extractSection(html, 'Top Five Priority Threats')).map((c) => ({
    title: c.title,
    action: c.action,
    sources: c.sources,
  }));

  const threatActorsSection = extractSection(html, 'Threat Actor Activity');
  const threatActorItems = extractListItems(threatActorsSection);
  const threatActors = threatActorItems.length > 0 ? [{ category: 'Activity', items: threatActorItems }] : [];

  const cveWatchSection =
    extractSection(html, 'Vulnerability and CVE Watch') || extractSection(html, 'New/Notable OT CVEs');
  const cveWatchItems = extractListItems(cveWatchSection);
  const cveWatch = cveWatchItems.length > 0 ? [{ category: 'Vulnerability and CVE Watch', items: cveWatchItems }] : [];

  const events = extractEventsCyber(html);

  const relevance = stripTags(extractSection(html, 'OT/ICS Relevance')).trim();

  const ttpSection = extractSection(html, 'TTPs and MITRE ATT') || extractSection(html, 'TTPs');
  const ttpItems = extractListItems(ttpSection);
  const mitreIds = [...new Set(ttpItems.join(' ').match(/T\d{4}(?:\.\d{3})?/g) || [])];

  const outlook = stripTags(extractSection(html, 'Next 72')).trim();

  const allCves = [
    ...new Set(
      (html.match(/CVE[\-\u2011]\d{4}[\-\u2011]\d{4,}/gi) || []).map((c) => c.toUpperCase().replace(/[\u2011]/g, '-'))
    ),
  ];

  return {
    type: 'cyber' as const,
    date,
    threatLevel,
    executiveSummary,
    keyFindings,
    dashboard: { kpis, activelyExploited, vendors, sectors },
    topThreats,
    threatActors,
    relevance,
    cveWatch,
    events,
    ttps: { descriptions: ttpItems, mitreIds },
    outlook72h: outlook,
    relatedCves: allCves,
  };
}

function parseDeepfakeBrief(html: string, date: string) {
  const executiveSummary =
    stripTags(extractSection(html, 'Executive Overview')).trim() ||
    stripTags(extractSection(html, 'Executive Summary')).trim();

  // Risk Outlook: masthead "Risk Outlook: <span class="state state-stable">Stable</span>"
  // (current DOM) or section "Assessment: Worsening" (legacy)
  const riskMast = html.match(/Risk Outlook:\s*<span class="state[^"]*"[^>]*>([^<]+)<\/span>/i);
  let riskOutlook = riskMast ? stripTags(riskMast[1]!).trim() : '';
  if (!riskOutlook) {
    const riskSection = extractSection(html, 'Risk Outlook');
    const riskMatch = riskSection.match(/Assessment:\s*(\w+)/i) || html.match(/Assessment:\s*(\w+)/i);
    riskOutlook = riskMatch && riskMatch[1] ? riskMatch[1] : '';
  }

  const kfSection = extractSection(html, 'Key Findings');
  const kfItems = extractListItems(kfSection);
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80)
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    return { title: item.slice(0, 80), summary: item };
  });

  const incidents = extractIncidentsDeepfake(html);

  const emergingTrends = extractListItems(extractSection(html, 'Emerging Trends'));
  const geographicObservations = extractListItems(extractSection(html, 'Geographic Observations'));
  const detectionDevelopments = extractListItems(extractSection(html, 'Detection and Defensive'));

  return {
    type: 'deepfake' as const,
    date,
    riskOutlook,
    executiveSummary,
    keyFindings,
    incidents,
    emergingTrends,
    geographicObservations,
    detectionDevelopments,
  };
}

function parseDisasterBrief(html: string, date: string) {
  const executiveSummary = stripTags(extractSection(html, 'Executive Summary')).trim();

  const overallThreat = (() => {
    // current: <span class="chip level">Overall Threat Level: Severe</span>
    const chip = html.match(/<span class="chip\s+level"[^>]*>Overall Threat Level:\s*([^<]+)<\/span>/i);
    if (chip) return stripTags(chip[1]!).trim().toLowerCase();
    // <span class="lvl">Severe</span> (mid) or <span class="flag escalate">ESCALATE</span> (old)
    const lvl = html.match(/<span class="lvl"[^>]*>([^<]+)<\/span>/i);
    if (lvl) return stripTags(lvl[1]!).trim().toLowerCase();
    const flag = html.match(/<span class="flag\s+(\w+)"[^>]*>([^<]+)<\/span>/i);
    if (flag) return stripTags(flag[2]!).trim().toLowerCase();
    const kpiEsc = html.match(/<div class="kpi\s+(escalate|monitor)"[^>]*>[\s\S]*?<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (kpiEsc) return stripTags(kpiEsc[2]!).trim().toLowerCase();
    return '';
  })();

  const kpis = extractKpisDisaster(html);

  const allEvents = extractEventsDisaster(html);
  const escalateEvents = allEvents.filter((e) => e.severity === 'escalate');
  const monitorEvents = allEvents.filter((e) => e.severity === 'monitor');

  // Top Five Critical Events — current: <div class="card priority-card"><div class="event-head">
  // <p class="event-title">N) Title</p><span class="badge escalate">ESCALATE</span></div><p class="event-body">text</p>
  // mid: <div class="card priority"><div class="severity">Priority N</div><h3>Title</h3>…
  const topSection = extractSection(html, 'Top Five Critical Events');
  const topEvents: { title: string; severity: string; text: string; sources: { url: string; label: string }[] }[] = [];
  const re = /<div class="card\s+priority[^"]*"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(topSection)) !== null) {
    const inner = extractBalancedDiv(topSection, m.index);
    const titleM =
      inner.match(/<p class="event-title"[^>]*>([\s\S]*?)<\/p>/i) || inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const title = titleM ? stripTags(titleM[1]!).trim() : '';
    const bodyM =
      inner.match(/<p class="event-body"[^>]*>([\s\S]*?)<\/p>/i) ||
      inner.match(/<div class="muted"[^>]*>([\s\S]*?)<\/div>/i) ||
      inner.match(/<p>([\s\S]*?)<\/p>/i);
    const text = bodyM ? stripTags(bodyM[1]!).trim() : '';
    topEvents.push({ title, severity: 'escalate', text, sources: extractLinks(inner) });
  }
  const topEventsFinal = topEvents.length > 0 ? topEvents.slice(0, 5) : escalateEvents.slice(0, 5);

  const outlook = stripTags(extractSection(html, 'Next 72')).trim();
  const regionalTrends = extractListItems(extractSection(html, 'Regional and Hazard'));

  // Key Findings — bullets list
  const kfItems = extractListItems(extractSection(html, 'Key Findings'));
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80)
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    return { title: item.slice(0, 80), summary: item };
  });

  return {
    type: 'disaster' as const,
    date,
    overallThreat,
    executiveSummary,
    dashboard: { kpis },
    keyFindings,
    topEvents: topEventsFinal,
    escalateEvents,
    monitorEvents,
    outlook72h: outlook,
    regionalTrends,
  };
}

function parseMaritimeBrief(html: string, date: string) {
  const executiveSummary = (() => {
    // current DOM: .summary-item divs carry the summary paragraphs
    const items = extractSection(html, 'Executive Summary');
    const summaryDivs = [...(items.matchAll(/<div class="summary-item"[^>]*>([\s\S]*?)<\/div>/gi) || [])]
      .map((d) => stripTags(d[1]!).trim())
      .filter(Boolean);
    if (summaryDivs.length > 0) return summaryDivs.join(' ');
    return stripTags(items).trim();
  })();

  const tlSection = extractSection(html, 'Overall Maritime Cyber Threat Level');
  let threatLevel = 'Unknown';
  // current DOM: <span class="badge high">HIGH</span> in section 3
  const badge = tlSection.match(/<span class="badge\s+(high|moderate|low|critical)"[^>]*>([^<]+)<\/span>/i);
  if (badge) threatLevel = stripTags(badge[2]!).trim();
  // "Current Level: MODERATE." (mid) or "Assessed Threat Level: HIGH" (old)
  const tlMatch = tlSection.match(/(?:Current Level|Assessed Threat Level):\s*(\w+)/i);
  if (tlMatch) threatLevel = tlMatch[1]!;

  const kpis = extractKpisMaritime(html);

  const topThreats = extractPriorityMaritime(html).map((c) => ({
    title: c.title,
    action: c.action,
    sources: c.sources,
  }));

  const events = extractEventsMaritime(html);
  const escalateEvents = events.filter((e) => e.severity === 'escalate');
  const monitorEvents = events.filter((e) => e.severity === 'monitor');
  const topEventsFinal = escalateEvents.slice(0, 5);

  const kfItems = extractListItems(extractSection(html, 'Key Findings'));

  const cveWatchItems = extractListItems(extractSection(html, 'Vulnerability and CVE Watch'));
  const cveWatch = cveWatchItems.length > 0 ? [{ category: 'Vulnerability and CVE Watch', items: cveWatchItems }] : [];

  const ttpItems = extractListItems(extractSection(html, 'TTPs and MITRE ATT'));
  const mitreIds = [...new Set(ttpItems.join(' ').match(/T\d{4}(?:\.\d{3})?/g) || [])];

  // current DOM: <ul class="compact"> list items; legacy: chips
  const vendorsSection = extractSection(html, 'Affected Vendors');
  let vendors = [...new Set(extractChips(vendorsSection))];
  if (vendors.length === 0) vendors = extractListItems(vendorsSection);
  const sectorsSection = extractSection(html, 'Affected Maritime Sectors');
  let sectors = [...new Set(extractChips(sectorsSection))];
  if (sectors.length === 0) sectors = extractListItems(sectorsSection);

  const outlook = stripTags(extractSection(html, 'Next 72-Hour Maritime Cyber Outlook')).trim();

  const allCves = [
    ...new Set(
      (html.match(/CVE[\-\u2011]\d{4}[\-\u2011]\d{4,}/gi) || []).map((c) => c.toUpperCase().replace(/[\u2011]/g, '-'))
    ),
  ];

  return {
    type: 'maritime' as const,
    date,
    threatLevel,
    executiveSummary: executiveSummary || stripTags(html).slice(0, 2048),
    dashboard: { kpis: kpis.length > 0 ? kpis : [{ value: 'N/A', label: 'No KPI data' }], vendors, sectors },
    keyFindings: kfItems,
    topThreats,
    cveWatch,
    events,
    topEvents: topEventsFinal,
    escalateEvents,
    monitorEvents,
    ttps: { descriptions: ttpItems, mitreIds },
    outlook72h: outlook,
    relatedCves: allCves,
  };
}

interface SyncEnv {
  KV_CACHE?: KVNamespace;
}

export async function syncDailyBriefs(env: SyncEnv): Promise<{ types: string[]; errors: string[] }> {
  const types: string[] = [];
  const errors: string[] = [];

  if (!env.KV_CACHE) {
    return { types: [], errors: ['KV_CACHE not bound'] };
  }

  const parsers: Record<DbBriefType, (html: string, date: string) => unknown> = {
    cyber: parseCyberBrief,
    deepfake: parseDeepfakeBrief,
    disaster: parseDisasterBrief,
    maritime: parseMaritimeBrief,
  };

  const mergedBriefs = new Map<string, { type: DbBriefType; date: string; sizeBytes: number }>();

  // Load existing index from KV to merge with new data
  try {
    const existingIndex: DbIndex | null = await env.KV_CACHE.get(KV_PREFIX_INDEX, 'json');
    if (existingIndex?.briefs) {
      const today = new Date().toISOString().slice(0, 10);
      for (const b of existingIndex.briefs) {
        // Drop future-dated entries — they are always mislabels from a
        // prior date-parsing bug (report date read as "today"), never real.
        if (b.date > today) continue;
        mergedBriefs.set(`${b.type}:${b.date}`, b);
      }
    }
  } catch {
    // No existing data — start fresh
  }

  for (const type of BRIEF_TYPES) {
    try {
      const url = `${BASE_URL}/${type}`;
      const res = await fetch(url, {
        headers: { 'user-agent': 'pranithjain-daily-briefs-sync/1.0 (Worker; +https://pranithjain.qzz.io)' },
      });
      if (!res.ok) {
        errors.push(`${type}: fetch failed (${res.status})`);
        continue;
      }
      const html = await res.text();
      const date = dateFromContent(html);
      const parsed = parsers[type](html, date);
      const bodyStr = JSON.stringify(parsed);
      const sizeBytes = bodyStr.length;

      const existing = mergedBriefs.get(`${type}:${date}`);
      if (existing && existing.sizeBytes === sizeBytes) {
        types.push(type);
        continue;
      }

      // Write body to KV (with TTL — static manifest is the long-term archive)
      await env.KV_CACHE.put(`${KV_PREFIX_BODY}:${type}:${date}`, bodyStr, { expirationTtl: BODY_TTL_S });
      mergedBriefs.set(`${type}:${date}`, { type: type as DbBriefType, date, sizeBytes });
      types.push(type);
    } catch (err) {
      errors.push(`${type}: ${errMessage(err)}`);
    }
  }

  // Write merged index
  const allBriefs = [...mergedBriefs.values()].sort((a, b) => b.date.localeCompare(a.date));
  const counts: Record<DbBriefType, number> = { cyber: 0, deepfake: 0, disaster: 0, maritime: 0 };
  for (const b of allBriefs) counts[b.type] = (counts[b.type] || 0) + 1;
  const index: DbIndex = {
    source: 'agentic-ai-daily-reports.netlify.app',
    license: 'MIT',
    generatedAt: new Date().toISOString().slice(0, 10),
    counts,
    briefs: allBriefs,
  };
  await env.KV_CACHE.put(KV_PREFIX_INDEX, JSON.stringify(index), { expirationTtl: INDEX_TTL_S });

  return { types, errors };
}
