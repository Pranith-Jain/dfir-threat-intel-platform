#!/usr/bin/env node
/**
 * Build the Daily Briefs manifest under public/data/daily-briefs/.
 *
 * Reads HTML from ./daily-briefs-staging/ (created by
 * `node scripts/sync-daily-briefs.mjs`) and emits structured JSON:
 *   public/data/daily-briefs/index.json
 *   public/data/daily-briefs/cyber/<date>.json
 *   public/data/daily-briefs/deepfake/<date>.json
 *   public/data/daily-briefs/disaster/<date>.json
 *   public/data/daily-briefs/maritime/<date>.json
 *   public/data/daily-briefs/water/<date>.json
 *   public/data/daily-briefs/french/<date>.json
 *
 * Parses HTML using regex — no external dependencies.
 *
 * Each brief type on agentic-ai-daily-reports.netlify.app uses a DIFFERENT
 * DOM, so the section/heading/event extractors below are per-type:
 *   - cyber:    <section class="section"><div class="section-title">Title</div>…
 *              events in <div class="event escalate|monitor|ignore">…<h4>…<div class="desc">
 *   - deepfake: <h2>Title</h2> sections; incidents in <div class="incident-card card">…<h3>
 *   - disaster: <h2 class="sec">Title</h2>; events in <div class="event-card indicator escalate|monitor">
 *   - maritime: <h2>N. Title</h2> (numbered); priority <div class="priority">; events <div class="event-card">
 *
 * extractSection() matches all four heading variants so a single helper
 * works across types, then per-type extractors pull the structured pieces.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'daily-briefs-staging');
const OUT = join(ROOT, 'public', 'data', 'daily-briefs');

const BRIEF_TYPES = ['cyber', 'deepfake', 'disaster', 'maritime', 'water', 'french'];

// ─── HTML helpers ────────────────────────────────────────────────────────

function stripTags(html) {
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

function escapeRegex(s) {
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
 * The section ends at the next heading, <section>/<footer>/<aside>, or end.
 */
function extractSection(html, heading) {
  const esc = escapeRegex(heading);
  const variants = [
    // <h2>Title</h2>  (bare — deepfake, current disaster/cyber)
    new RegExp(`<h2[^>]*>\\s*${esc}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2[^>]*>|<section class="section"|<section class="panel"|<footer|<aside|$)`, 'i'),
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
    if (m && m[1] && m[1].trim()) return m[1];
  }
  // Fuzzy: match on the first word only (e.g. "TTPs and MITRE…" by "TTPs").
  const firstWord = escapeRegex(heading.split(/\s+/)[0]);
  const fuzzy = [
    new RegExp(`<h2[^>]*>[^<]*${firstWord}[\\s\\S]*?</h2>([\\s\\S]*?)(?=<h2[^>]*>|<footer|<aside|$)`, 'i'),
    new RegExp(`<div class="section-title"[^>]*>[^<]*${firstWord}[\\s\\S]*?</div>[\\s\\S]*?<div class="section-body"[^>]*>([\\s\\S]*?)(?=<section class="section"|<footer|$)`, 'i'),
  ];
  for (const re of fuzzy) {
    const m = html.match(re);
    if (m && m[1] && m[1].trim()) return m[1];
  }
  return '';
}

function extractChips(html) {
  const chips = [];
  // Match both <span class="chip"> (old) and <span class="pill"> (new DOM)
  const re = /<span class="(?:chip|pill)"[^>]*>([\s\S]*?)<\/span>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const t = stripTags(m[1]).trim();
    if (t) chips.push(t);
  }
  return chips;
}

function extractLinks(html) {
  const links = [];
  const re = /<a[^>]+href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const label = stripTags(m[2]).trim();
    if (m[1] && !m[1].startsWith('#')) links.push({ url: m[1], label });
  }
  return links;
}

function extractListItems(html) {
  const items = [];
  const re = /<li>([\s\S]*?)<\/li>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const t = stripTags(m[1]).trim();
    if (t) items.push(t);
  }
  return items;
}

/** Split a free-text section (no chips/li) into bullet-ish items: split on
 *  line breaks, then on bullet dashes, dropping empty/decorative pieces.
 *  Used for the current-DOM "Affected Vendors" / "Affected Sectors" panels
 *  which render as plain text with <br> separators. */
function splitTextList(html) {
  const text = stripTags(html);
  if (!text) return [];
  const pieces = text
    .split(/<br\s*\/?>|\n/)
    .flatMap((line) => line.split(/\s*[•·]\s*/))
    .map((s) => s.replace(/^[-–—]\s*/, '').trim())
    .filter((s) => s && s.length > 2);
  return [...new Set(pieces)];
}

const MONTHS = {
  january: 0, february: 1, march: 2, april: 3, may: 4, june: 5,
  july: 6, august: 7, september: 8, october: 9, november: 10, december: 11,
};

function extractDate(html) {
  // Extract the report date from a DEDICATED date marker — never from the
  // first random "Month DD, YYYY" in the body, which can be a stale
  // reference to a previous day (e.g. "compared to August 04, 2026") when
  // the upstream site is mid-update. Priority order, per brief type:
  //
  //   cyber:    "Date: 14 Aug 2026"                  (current masthead .sub)
  //             or "Report date: 2026-08-05"         (legacy ISO)
  //   deepfake: "Generated: Friday, August 14, 2026" (in .subhead)
  //   disaster: "Generated: Friday, August 14, 2026" (in .chip)
  //   maritime: "Report Date: Friday, August 14, 2026" (in .meta)

  // 1. ISO "Report date: 2026-08-05" (legacy cyber)
  const iso = html.match(/Report date[^0-9]*?(\d{4}-\d{2}-\d{2})/i);
  if (iso) return iso[1];

  // 2. Dedicated labelled markers: "Generated:", "Publication Date:",
  //    "Report Date:", and the current cyber masthead's bare "Date:" —
  //    these are the masthead/header fields, not body prose.
  //    Match "Day, Month DD, YYYY" OR "DD Mon YYYY".
  const labelled = html.match(
    /(?:Generated|Publication Date|Report Date|Date)\s*:\s*([^<\n]{3,60}?)(?:<|\n|$)/i
  );
  if (labelled) {
    const s = stripTags(labelled[1]).trim();
    // "Wednesday, August 05, 2026"
    const long = s.match(
      /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
    );
    if (long) return `${long[3]}-${String(MONTHS[long[1].toLowerCase()] + 1).padStart(2, '0')}-${long[2].padStart(2, '0')}`;
    // "05 Aug 2026" or "14 Aug 2026"
    const short = s.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{4})/i);
    if (short) {
      const monMap = { jan:0,feb:1,mar:2,apr:3,may:4,jun:5,jul:6,aug:7,sep:8,oct:9,nov:10,dec:11 };
      const mon = monMap[short[2].toLowerCase().slice(0,3)];
      if (mon !== undefined) return `${short[3]}-${String(mon + 1).padStart(2, '0')}-${short[1].padStart(2, '0')}`;
    }
  }

  // 3. <title> with a date — handle hyphen OR en-dash (–/—) separators and
  //    both "Month DD, YYYY" and "DD Mon YYYY" formats.
  //    e.g. "Maritime ... Brief – Wednesday, August 05, 2026"
  //         "DeepFake ... Brief — 05 Aug 2026"
  const titleDate = html.match(/<title>[^<]*?[\u2012-\u2015\-]\s*([^<]+?)<\/title>/i);
  if (titleDate) {
    const s = titleDate[1];
    const long = s.match(
      /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
    );
    if (long) return `${long[3]}-${String(MONTHS[long[1].toLowerCase()] + 1).padStart(2, '0')}-${long[2].padStart(2, '0')}`;
    const short = s.match(/(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{4})/i);
    if (short) {
      const monMap = { jan:0,feb:1,mar:2,apr:3,may:4,jun:5,jul:6,aug:7,sep:8,oct:9,nov:10,dec:11 };
      const mon = monMap[short[2].toLowerCase().slice(0,3)];
      if (mon !== undefined) return `${short[3]}-${String(mon + 1).padStart(2, '0')}-${short[1].padStart(2, '0')}`;
    }
  }

  // 4. Masthead date div (legacy fallback)
  const m = html.match(/<div class="date"[^>]*>([\s\S]*?)<\/div>/i);
  if (m) return stripTags(m[1]).trim();

  // 5. Last resort: first "Month DD, YYYY" anywhere. This is the risky fallback
  //    that previously caused stale dates — kept only so we never return empty.
  const m2 = html.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}/i);
  return m2 ? m2[0] : '';
}

function dateFromContent(html) {
  const dateStr = extractDate(html);
  if (!dateStr) return new Date().toISOString().slice(0, 10);
  // Already ISO (from the cyber "Report date" path or the labelled/title paths)
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return dateStr;
  const named = dateStr.match(
    /(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i
  );
  if (named) {
    const month = MONTHS[named[1].toLowerCase()];
    const day = Number(named[2]);
    const year = Number(named[3]);
    if (month !== undefined && day >= 1 && day <= 31) {
      return `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    }
  }
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
  return d.toISOString().slice(0, 10);
}

// ─── KPI extractors (per layout) ───────────────────────────────────────

function extractBalancedDiv(html, startIdx) {
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
function extractBalancedTag(html, startIdx, tagName) {
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
function extractKpisCyber(html) {
  const kpis = [];
  // current DOM (Nov 2026): <div class="kpi"><div class="kpi-label">L</div>
  // <div class="kpi-value">V</div></div> — no h4/.value classes.
  const reNew = /<div class="kpi"[^>]*>/gi;
  let m;
  while ((m = reNew.exec(html)) !== null) {
    const inner = extractBalancedDiv(html, m.index);
    const l = inner.match(/<div class="kpi-label"[^>]*>([\s\S]*?)<\/div>/i);
    const v = inner.match(/<div class="kpi-value"[^>]*>([\s\S]*?)<\/div>/i);
    if (!l && !v) continue;
    const label = l ? stripTags(l[1]).trim() : '';
    const value = v ? stripTags(v[1]).trim() : '';
    if (label || value) kpis.push({ value, label });
  }
  if (kpis.length > 0) return kpis;
  // previous DOM: h4 label + .value + .sub
  const re = /<div class="kpi"[^>]*>/gi;
  while ((m = re.exec(html)) !== null) {
    const inner = extractBalancedDiv(html, m.index);
    // previous DOM: h4 label + .value + .sub
    const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const trend = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i)
      || inner.match(/<div class="sub"[^>]*>([\s\S]*?)<\/div>/i);
    const l = h4 ? stripTags(h4[1]).trim() : (label ? stripTags(label[1]).trim() : '');
    const v = value ? stripTags(value[1]).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(trend ? { trend: stripTags(trend[1]).trim() } : {}) });
  }
  return kpis;
}

/** disaster KPIs (current DOM): <div class="card kpi"><div class="label">L</div><div class="value">V</div><div class="trend">T</div></div>
 *  mid DOM: <div class="metric"> with muted/num/muted children
 *  old DOM: <div class="kpi escalate"><h4>L</h4><div class="val">V</div><div class="note">N</div></div> */
function extractKpisDisaster(html) {
  const kpis = [];
  // Current: <div class="card kpi"> with .label/.value/.trend
  const re = /<div class="card\s+kpi"[^>]*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const inner = extractBalancedDiv(html, m.index);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const trend = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i);
    const l = label ? stripTags(label[1]).trim() : '';
    const v = value ? stripTags(value[1]).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(trend ? { trend: stripTags(trend[1]).trim() } : {}) });
  }
  // Mid: <div class="metric"> with muted/num/muted children
  if (kpis.length === 0) {
    const re2 = /<div class="metric"[^>]*>/gi;
    while ((m = re2.exec(html)) !== null) {
      const inner = extractBalancedDiv(html, m.index);
      const muteds = inner.match(/<div class="muted"[^>]*>([\s\S]*?)<\/div>/gi) || [];
      const num = inner.match(/<div class="num"[^>]*>([\s\S]*?)<\/div>/i);
      const label = muteds[0] ? stripTags(muteds[0]).trim() : '';
      const value = num ? stripTags(num[1]).trim() : '';
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
      const l = label ? stripTags(label[1]).trim() : '';
      const v = val ? stripTags(val[1]).trim() : '';
      if (l || v) kpis.push({ value: v, label: l, ...(note ? { trend: stripTags(note[1]).trim() } : {}) });
    }
  }
  return kpis;
}

/** maritime KPIs (current DOM): <div class="col-3 card kpi"><div class="label">L</div><div class="value">V</div><div class="note">N</div></div>
 *  mid DOM: <div class="kpi"><span>Label</span><strong>Value</strong></div>.
 *  Old DOM used <div class="card"><div class="label">/<div class="metric">. */
function extractKpisMaritime(html) {
  const kpis = [];
  const dash = extractSection(html, 'Maritime Threat Dashboard') || '';
  // Current: <div class="col-3 card kpi"> with .label/.value/.note
  const re = /<div class="[^"]*card\s+kpi[^"]*"[^>]*>/gi;
  let m;
  while ((m = re.exec(dash)) !== null) {
    const inner = extractBalancedDiv(dash, m.index);
    const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
    const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
    const note = inner.match(/<div class="note"[^>]*>([\s\S]*?)<\/div>/i);
    const l = label ? stripTags(label[1]).trim() : '';
    const v = value ? stripTags(value[1]).trim() : '';
    if (l || v) kpis.push({ value: v, label: l, ...(note ? { trend: stripTags(note[1]).trim() } : {}) });
  }
  // Mid: <div class="kpi"><span>L</span><strong>V</strong></div>
  if (kpis.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(dash)) !== null) {
      const inner = extractBalancedDiv(dash, m.index);
      const span = inner.match(/<span[^>]*>([\s\S]*?)<\/span>/i);
      const strong = inner.match(/<strong[^>]*>([\s\S]*?)<\/strong>/i);
      const l = span ? stripTags(span[1]).trim() : '';
      const v = strong ? stripTags(strong[1]).trim() : '';
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
      const l = label ? stripTags(label[1]).trim() : '';
      let v = metric ? stripTags(metric[1]).trim() : '';
      v = v.replace(/\s+Level\s*$/, '').trim();
      if (l || v) kpis.push({ value: v, label: l });
    }
  }
  return kpis;
}

// ─── Card extractors ───────────────────────────────────────────────────

/** cyber dashboard cards: <div class="dash-row"><div class="card"><h3>Title</h3><div>text</div>…</div></div>
 *  (current DOM) — legacy grid-of-kpi blocks also matched. */
function extractCardsCyberDash(html) {
  const dash = extractSection(html, 'Threat Dashboard') || html;
  const cards = [];
  // current DOM: <div class="card"><h3>Title</h3><div>text</div> or <div class="chips">…
  const re = /<div class="card"[^>]*>/gi;
  let m;
  while ((m = re.exec(dash)) !== null) {
    const inner = extractBalancedDiv(dash, m.index);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    if (!h3) continue;
    const title = stripTags(h3[1]).trim();
    // body text: first non-chips div after the h3
    const textDiv = inner.match(/<h3[^>]*>[\s\S]*?<\/h3>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const text = textDiv ? stripTags(textDiv[1]).trim() : '';
    cards.push({ title, text, chips: extractChips(inner) });
  }
  // legacy: kpi blocks in the dashboard section
  if (cards.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(dash)) !== null) {
      const inner = extractBalancedDiv(dash, m.index);
      const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
      const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
      const note = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i)
        || inner.match(/<div class="note"[^>]*>([\s\S]*?)<\/div>/i);
      const title = label ? stripTags(label[1]).trim() : '';
      const text = value ? stripTags(value[1]).trim() : (note ? stripTags(note[1]).trim() : '');
      if (title) cards.push({ title, text, chips: extractChips(inner) });
    }
  }
  return cards;
}

/** cyber priority threats (current DOM): <div class="two-col"><div class="card"><h3>N) Title</h3><div>text</div><div class="link"><a…></a></div></div>
 *  legacy: <div class="kpi"><div class="label">N) Title</div><div class="value">Action</div>…
 *  NOTE: caller passes the already-extracted section (see parseCyberBrief). */
function extractCardsCyberPriority(section) {
  const cards = [];
  // Nov 2026 DOM: .card.event with h4 title, .decision/.severity meta, p, .linkbar
  const reNew = /<div class="card\s+event"[^>]*>/gi;
  let mn;
  while ((mn = reNew.exec(section)) !== null) {
    const inner = extractBalancedDiv(section, mn.index);
    const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (!h4) continue;
    const p = inner.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const decision = inner.match(/class="decision\s+dec-(\w+)"/i);
    const linkbar = inner.match(/<div class="linkbar"[^>]*>([\s\S]*?)<\/div>/i);
    cards.push({
      title: stripTags(h4[1]).trim(),
      action: p ? stripTags(p[1]).trim() : '',
      sources: extractLinks(linkbar ? linkbar[1] : inner),
      ...(decision ? { severity: decision[1].toLowerCase() } : {}),
    });
  }
  if (cards.length > 0) return cards;
  // current DOM: .card with h3 title + text + .link
  const re = /<div class="card"[^>]*>/gi;
  let m;
  while ((m = re.exec(section)) !== null) {
    const inner = extractBalancedDiv(section, m.index);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    if (!h3) continue;
    const title = stripTags(h3[1]).trim();
    const textDiv = inner.match(/<h3[^>]*>[\s\S]*?<\/h3>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const action = textDiv ? stripTags(textDiv[1]).trim() : '';
    cards.push({ title, action, sources: extractLinks(inner) });
  }
  // legacy: kpi blocks
  if (cards.length === 0) {
    const re2 = /<div class="kpi"[^>]*>/gi;
    while ((m = re2.exec(section)) !== null) {
      const inner = extractBalancedDiv(section, m.index);
      const label = inner.match(/<div class="label"[^>]*>([\s\S]*?)<\/div>/i);
      const value = inner.match(/<div class="value"[^>]*>([\s\S]*?)<\/div>/i);
      const trend = inner.match(/<div class="trend"[^>]*>([\s\S]*?)<\/div>/i);
      const title = label ? stripTags(label[1]).trim() : '';
      const action = value ? stripTags(value[1]).trim() : '';
      cards.push({ title, action, sources: extractLinks(inner), ...(trend ? { trend: stripTags(trend[1]).trim() } : {}) });
    }
  }
  return cards;
}

/** cyber events (current DOM): <div class="event-groups"><div class="event-col"><h3><span class="pill critical">ESCALATE</span></h3>
 *  <div class="event-list"><div class="event escalate"><strong>Title</strong><div class="meta">desc</div><div class="link"><a…></div>
 *  Severity from the event class AND the group pill. Legacy band layout kept as fallback. */
function extractEventsCyber(html) {
  const events = [];
  // Nov 2026 DOM: <div class="card event"><h4>1) Title</h4>
  // <div class="meta"><span class="decision dec-escalate">ESCALATE</span>
  // <span class="severity sev-critical">CRITICAL</span></div><p>text</p>
  // <div class="linkbar"><a class="source-link" …></a></div></div>
  // Groups are <h3>ESCALATE|MONITOR|IGNORE</h3> under "Actively Exploited Focus…".
  const focus = extractSection(html, 'Actively Exploited Focus') || html;
  const groupRe = /<h3[^>]*>\s*(ESCALATE|MONITOR|IGNORE)\s*<\/h3>/gi;
  const groups = [];
  let gg;
  while ((gg = groupRe.exec(focus)) !== null) groups.push({ severity: gg[1].toLowerCase(), at: gg.index });
  const cardRe = /<div class="card\s+event"[^>]*>/gi;
  let cm2;
  while ((cm2 = cardRe.exec(focus)) !== null) {
    const inner = extractBalancedDiv(focus, cm2.index);
    const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (!h4) continue;
    const decision = inner.match(/class="decision\s+dec-(escalate|monitor|ignore)"/i);
    const sev = inner.match(/class="severity\s+sev-(\w+)"/i);
    let severity = decision ? decision[1].toLowerCase() : 'monitor';
    for (const g of groups) if (g.at < cm2.index) severity = g.severity;
    const p = inner.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const linkbar = inner.match(/<div class="linkbar"[^>]*>([\s\S]*?)<\/div>/i);
    events.push({
      title: stripTags(h4[1]).trim(),
      severity,
      text: p ? stripTags(p[1]).trim() : '',
      chips: sev ? [`severity: ${sev[1]}`] : [],
      sources: extractLinks(linkbar ? linkbar[1] : inner),
    });
  }
  if (events.length > 0) return events;
  // current DOM: .event-groups > .event-col > h3 (pill) + .event-list > .event <severity>
  const colRe = /<div class="event-col"[^>]*>/gi;
  let cm;
  while ((cm = colRe.exec(html)) !== null) {
    const colStart = cm.index;
    const col = extractBalancedDiv(html, colStart);
    const pill = col.match(/<h3[^>]*>[\s\S]*?<span class="pill\s+(?:critical|moderate|low)"[^>]*>([^<]+)<\/span>/i);
    const groupSeverity = pill ? stripTags(pill[1]).trim().toLowerCase() : '';
    const evRe = /<div class="event\s+(escalate|monitor|ignore)"[^>]*>/gi;
    let em;
    while ((em = evRe.exec(col)) !== null) {
      const classSeverity = em[1].toLowerCase();
      const inner = extractBalancedDiv(col, em.index);
      const strong = inner.match(/<strong[^>]*>([\s\S]*?)<\/strong>/i);
      const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
      const link = inner.match(/<div class="link"[^>]*>([\s\S]*?)<\/div>/i);
      const title = strong ? stripTags(strong[1]).trim() : '';
      const text = meta ? stripTags(meta[1]).trim() : '';
      const severity = classSeverity || groupSeverity || 'monitor';
      const sources = link ? extractLinks(link[1]) : extractLinks(inner);
      events.push({ title, severity, text, chips: [], sources });
    }
  }
  // legacy: .band escalate|monitor|ignore + .event-columns + .event
  if (events.length === 0) {
    const bandRe = /<div class="band\s+(escalate|monitor|ignore)"[^>]*>[\s\S]*?<\/div>\s*<div class="event-columns">([\s\S]*?)(?=<div class="band\s+(?:escalate|monitor|ignore)"|<div class="section"|<footer|<aside|$)/gi;
    let bm;
    while ((bm = bandRe.exec(html)) !== null) {
      const severity = bm[1].toLowerCase();
      const columns = bm[2];
      const evRe = /<div class="event"[^>]*>/gi;
      let em;
      while ((em = evRe.exec(columns)) !== null) {
        const inner = extractBalancedDiv(columns, em.index);
        const h4 = inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
        const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
        const p = inner.match(/<p>([\s\S]*?)<\/p>/i);
        const srcs = inner.match(/<div class="srcs"[^>]*>([\s\S]*?)<\/div>/i);
        const title = h4 ? stripTags(h4[1]).trim() : '';
        const text = p ? stripTags(p[1]).trim() : '';
        const chips = meta ? extractChips(meta[1]) : [];
        const sources = srcs ? extractLinks(srcs[1]) : extractLinks(inner);
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
function extractIncidentsDeepfake(html) {
  const incidents = [];
  // Nov 2026 DOM: <section><h2>Priority Incidents</h2><h3>Title</h3>
  // <p>summary with <a> sources</p><h3>Next title</h3>…</section>
  // (no .incident-card wrappers anymore)
  const priority = extractSection(html, 'Priority Incidents');
  if (priority) {
    const h3Re = /<h3[^>]*>([\s\S]*?)<\/h3>/gi;
    const heads = [...priority.matchAll(h3Re)];
    for (let i = 0; i < heads.length; i++) {
      const title = stripTags(heads[i][1]).trim();
      if (!title) continue;
      const start = heads[i].index + heads[i][0].length;
      const end = i + 1 < heads.length ? heads[i + 1].index : priority.length;
      const body = priority.slice(start, end);
      const p = body.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
      incidents.push({
        title,
        badges: [],
        fields: {},
        summary: stripTags(p ? p[1] : body).trim(),
        sources: extractLinks(body),
      });
    }
  }
  if (incidents.length > 0) return incidents;
  const re = /<(?:div|article)\s+class="incident-card"[^>]*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const inner = extractBalancedTag(html, m.index, m[0].startsWith('<article') ? 'article' : 'div');
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const title = h3 ? stripTags(h3[1]).trim() : '';
    // Badges: <span class="badge escalate">ESCALATE</span> <span class="badge high">High Urgency</span>
    const badges = [];
    const badgeRe = /<span class="(?:badge|urgency)[^"]*"[^>]*>([^<]+)<\/span>/gi;
    let bm;
    while ((bm = badgeRe.exec(inner)) !== null) badges.push(stripTags(bm[1]).trim());
    // Fields: <span>Key: Value</span> inside <div class="meta">
    const fields = {};
    const metaInner = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i);
    if (metaInner) {
      // <span>Publication date: 2026-08-04</span>  (no class)
      const spanRe = /<span[^>]*>([^:<>]+):\s*([^<]+)<\/span>/gi;
      let sm;
      while ((sm = spanRe.exec(metaInner[1])) !== null) {
        fields[stripTags(sm[1]).trim()] = stripTags(sm[2]).trim();
      }
    }
    // Summary: <div class="field"><strong>Incident Summary:</strong> …</div>
    const summaryP = inner.match(/<div class="field"[^>]*><strong>Incident Summary:[^<]*<\/strong>\s*([\s\S]*?)<\/div>/i)
      || inner.match(/<p><strong>Incident Summary:[^<]*<\/strong>\s*([\s\S]*?)<\/p>/i);
    const summary = summaryP ? stripTags(summaryP[1]).trim() : '';
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
function extractEventsDisaster(html) {
  const events = [];
  // Nov 2026 DOM: <div class="event"><div class="head">
  // <div class="title">Title</div><span class="badge b-escalate">ESCALATE</span></div>
  // <div class="meta-row"><span class="tag">…</span></div>
  // <div class="desc">text</div><div class="links"><a …></a></div></div>
  const sectionNew = extractSection(html, 'Event Cards by Decision Level') || html;
  const evReNew = /<div class="event"[^>]*>/gi;
  let en;
  while ((en = evReNew.exec(sectionNew)) !== null) {
    const inner = extractBalancedDiv(sectionNew, en.index);
    const titleM = inner.match(/<div class="title"[^>]*>([\s\S]*?)<\/div>/i);
    if (!titleM) continue;
    const badge = inner.match(/class="badge\s+b-(escalate|monitor|ignore)"/i);
    const metaRow = inner.match(/<div class="meta-row"[^>]*>([\s\S]*?)<\/div>/i);
    const desc = inner.match(/<div class="desc"[^>]*>([\s\S]*?)<\/div>/i);
    const links = inner.match(/<div class="links"[^>]*>([\s\S]*?)<\/div>/i);
    events.push({
      title: stripTags(titleM[1]).trim(),
      severity: badge ? badge[1].toLowerCase() : 'monitor',
      text: desc ? stripTags(desc[1]).trim() : '',
      chips: metaRow ? (metaRow[1].match(/<span class="tag"[^>]*>([\s\S]*?)<\/span>/gi) || []).map((t) => stripTags(t).trim()) : [],
      sources: extractLinks(links ? links[1] : inner),
    });
  }
  if (events.length > 0) return events;
  const section = extractSection(html, 'Event Cards by Decision Level') || html;
  // Current: walk group headers to know severity, then .card with .event-head
  const groupRe = /<h3[^>]*>\s*(ESCALATE|MONITOR|IGNORE)\s*<\/h3>/gi;
  let gm;
  let currentSeverity = 'monitor';
  let searchFrom = 0;
  const groupSpans = [];
  while ((gm = groupRe.exec(section)) !== null) {
    groupSpans.push({ severity: gm[1].toLowerCase(), start: gm.index });
  }
  const cards = [];
  const re = /<div class="card"[^>]*>/gi;
  let m;
  while ((m = re.exec(section)) !== null) {
    cards.push(m.index);
  }
  for (const idx of cards) {
    const inner = extractBalancedDiv(section, idx);
    // Which group is this card under? (last group header before the card)
    let severity = 'monitor';
    for (const g of groupSpans) {
      if (g.start < idx) severity = g.severity;
    }
    // event-head / event-title (current) or h3 title (mid) or h4.event-title (old)
    const titleM =
      inner.match(/<p class="event-title"[^>]*>([\s\S]*?)<\/p>/i)
      || inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i)
      || inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (!titleM) continue;
    const title = stripTags(titleM[1]).trim();
    // Severity override from badge/status inside the card
    const badge = inner.match(/<span class="badge\s+(escalate|monitor|ignore)"[^>]*>/i)
      || inner.match(/<span class="status\s+(escalate|monitor|ignore)"[^>]*>/i)
      || inner.match(/<span class="badge\s+(high|critical)"[^>]*>/i);
    if (badge) severity = badge[1].toLowerCase() === 'high' || badge[1].toLowerCase() === 'critical' ? 'escalate' : badge[1].toLowerCase();
    // Chips: <span class="pill"> (current indicators) or <span class="tag"> (mid)
    const chips = [];
    const chipRe = /<span class="(?:pill|tag)"[^>]*>([\s\S]*?)<\/span>/gi;
    let tm;
    while ((tm = chipRe.exec(inner)) !== null) {
      const t = stripTags(tm[1]).trim();
      if (t) chips.push(t);
    }
    // Body text: .event-body (current) or bare <div> after the row (mid)
    const bodyM = inner.match(/<div class="event-body"[^>]*>([\s\S]*?)<\/div>/i)
      || inner.match(/<p class="event-body"[^>]*>([\s\S]*?)<\/p>/i)
      || inner.match(/<div class="row"[^>]*>[\s\S]*?<\/div>\s*<div[^>]*>([\s\S]*?)<\/div>/i);
    const text = bodyM ? stripTags(bodyM[1]).trim() : '';
    const sources = extractLinks(inner);
    events.push({ title, severity, text, chips, sources });
  }
  return events;
}

/** maritime priority (current DOM): <div class="col-6 card priority"><div class="title">N) Title</div>
 *  <div class="meta">chips</div><div class="impact">Why it matters: …</div>…</div>
 *  mid: <div class="card priority monitor-accent"><div class="title">…</div><div class="why">…
 *  old: <div class="priority"> with <h3><span class="num">) */
function extractPriorityMaritime(html) {
  const cards = [];
  const section = extractSection(html, 'Top Five Priority Threats') || '';
  const re = /<div class="[^"]*card\s+priority[^"]*"[^>]*>/gi;
  let m;
  while ((m = re.exec(section)) !== null) {
    const inner = extractBalancedDiv(section, m.index);
    // Title: <div class="title">N) Title</div> (current/mid) or <h3>…</h3> (old)
    const titleDiv = inner.match(/<div class="title"[^>]*>([\s\S]*?)<\/div>/i);
    const h3 = inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const num = h3 ? (h3[1].match(/<span class="num"[^>]*>([\s\S]*?)<\/span>/i) || [])[1] : '';
    const title = titleDiv ? stripTags(titleDiv[1]).trim() : (h3 ? stripTags(h3[1]).trim() : '');
    // "Why it matters: …" in <div class="impact"> (current) or <div class="why"> (mid) or before <ul> (old)
    const impactDiv = inner.match(/<div class="impact"[^>]*>([\s\S]*?)<\/div>/i);
    const whyDiv = inner.match(/<div class="why"[^>]*>([\s\S]*?)<\/div>/i);
    const whyMatch = inner.match(/Why it matters:\s*([\s\S]*?)(?=<ul|<a|<div class="impact"|<div class="why"|$)/i);
    const action = impactDiv
      ? stripTags(impactDiv[1]).replace(/^Why it matters:\s*/i, '').trim()
      : whyDiv
        ? stripTags(whyDiv[1]).replace(/^Why it matters:\s*/i, '').trim()
        : (whyMatch ? stripTags(whyMatch[1]).trim() : '');
    const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
    const items = ul ? extractListItems(ul[1]) : [];
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
function extractEventsMaritime(html) {
  const events = [];
  // Nov 2026 DOM: <div class="event-group"><h3><span class="badge esc">C:ESCALATE</span></h3>
  // <div class="event-card"><div class="event-top"><span class="event-title">Title</span></div>
  // <div class="event-meta"><span class="badge level-critical">Threat Level: CRITICAL</span>…</div>
  // <ul class="compact"><li>Summary: …</li>…</ul></div></div>
  const sectionNew = extractSection(html, 'Intelligence Event Cards') || html;
  const groupReNew = /<div class="event-group"[^>]*>/gi;
  let gn;
  while ((gn = groupReNew.exec(sectionNew)) !== null) {
    const group = extractBalancedDiv(sectionNew, gn.index);
    const g = group.match(/class="badge\s+\w+"[^>]*>\s*[ABC]:(ESCALATE|MONITOR|IGNORE)/i);
    const groupSeverity = g ? g[1].toLowerCase() : 'monitor';
    const cardRe = /<div class="event-card"[^>]*>/gi;
    let cn;
    while ((cn = cardRe.exec(group)) !== null) {
      const inner = extractBalancedDiv(group, cn.index);
      const titleM = inner.match(/<span class="event-title"[^>]*>([\s\S]*?)<\/span>/i);
      if (!titleM) continue;
      const lvl = inner.match(/class="badge\s+level-(critical|high|moderate|medium|low)"/i);
      let severity = groupSeverity;
      if (lvl) {
        const t = lvl[1].toLowerCase();
        severity = ['critical', 'high', 'escalate'].includes(t) ? 'escalate' : ['medium', 'low', 'moderate'].includes(t) ? 'monitor' : severity;
      }
      const ul = inner.match(/<ul class="compact"[^>]*>([\s\S]*?)<\/ul>/i);
      const items = ul ? extractListItems(ul[1]) : [];
      const text = items.join(' ');
      events.push({
        title: stripTags(titleM[1]).trim(),
        severity,
        text,
        chips: (inner.match(/<span class="badge[^"]*"[^>]*>([\s\S]*?)<\/span>/gi) || []).map((b) => stripTags(b).trim()).filter(Boolean),
        sources: extractLinks(inner),
        ...(items.length ? { items } : {}),
      });
    }
  }
  if (events.length > 0) return events;
  const section = extractSection(html, 'Intelligence Event Cards') || html;
  // current DOM: .card.event with severity class
  const re = /<div class="[^"]*card\s+event(?:\s+(escalate|monitor|ignore))?[^"]*"[^>]*>/gi;
  let m;
  while ((m = re.exec(section)) !== null) {
    const classSeverity = m[1] ? m[1].toLowerCase() : null;
    const inner = extractBalancedDiv(section, m.index);
    // Title: <span class="title">…</span> (current) or .event-title/h4 (legacy)
    const titleM = inner.match(/<span class="title"[^>]*>([\s\S]*?)<\/span>/i)
      || inner.match(/<div class="event-title"[^>]*>([\s\S]*?)<\/div>/i)
      || inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
    const title = titleM ? stripTags(titleM[1]).trim() : '';
    // Body: .details divs (current), .meta/.kicker + ul (legacy)
    const details = [...inner.matchAll(/<div class="details"[^>]*>([\s\S]*?)<\/div>/gi)].map((d) => stripTags(d[1]).trim()).filter(Boolean);
    const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i)
      || inner.match(/<div class="event-meta"[^>]*>([\s\S]*?)<\/div>/i);
    const kicker = inner.match(/<div class="kicker"[^>]*>([\s\S]*?)<\/div>/i);
    const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
    let severity = classSeverity || 'monitor';
    // Group header severity: look at the closest preceding <h3>C:ESCALATE|B:MONITOR|A:IGNORE>
    const before = section.slice(0, m.index);
    const groupM = [...before.matchAll(/<h3[^>]*>\s*([ABC]):(ESCALATE|MONITOR|IGNORE)\s*<\/h3>/gi)].pop();
    if (groupM) {
      const t = groupM[2].toLowerCase();
      if (t === 'escalate' || t === 'ignore') severity = t;
    }
    if (meta) {
      const lvl = meta[1].match(/THREAT LEVEL:\s*(\w+)/i)
        || meta[1].match(/<div class="status\s+(\w+)"[^>]*>/i)
        || inner.match(/<span class="chip\s+red"[^>]*>/i);
      if (lvl && lvl[1]) {
        const t = lvl[1].toLowerCase();
        if (t === 'critical' || t === 'high' || t === 'escalate') severity = 'escalate';
        else if (t === 'medium' || t === 'low' || t === 'monitor') severity = 'monitor';
        else if (t === 'ignore') severity = 'ignore';
      } else if (inner.match(/<span class="chip\s+red"[^>]*>/i)) {
        severity = 'escalate';
      } else if (inner.match(/<span class="chip\s+amber"[^>]*>/i)) {
        severity = 'monitor';
      }
    }
    const text = details.join(' ') || ((kicker ? stripTags(kicker[1]).trim() : '') + (ul ? ' ' + stripTags(ul[1]).trim() : '')).trim();
    const items = ul ? extractListItems(ul[1]) : [];
    const sources = extractLinks(inner);
    events.push({ title, severity, text, chips: extractChips(inner), sources, ...(items.length ? { items } : {}) });
  }
  // legacy: .event-card with severity suffix
  if (events.length === 0) {
    const re2 = /<div class="event-card(?:\s+event-(escalate|monitor|ignore))?"[^>]*>/gi;
    while ((m = re2.exec(section)) !== null) {
      const classSeverity = m[1] ? m[1].toLowerCase() : null;
      const inner = extractBalancedDiv(section, m.index);
      const titleM = inner.match(/<div class="event-title"[^>]*>([\s\S]*?)<\/div>/i)
        || inner.match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
      const title = titleM ? stripTags(titleM[1]).trim() : '';
      const meta = inner.match(/<div class="meta"[^>]*>([\s\S]*?)<\/div>/i)
        || inner.match(/<div class="event-meta"[^>]*>([\s\S]*?)<\/div>/i);
      const kicker = inner.match(/<div class="kicker"[^>]*>([\s\S]*?)<\/div>/i);
      const ul = inner.match(/<ul[^>]*>([\s\S]*?)<\/ul>/i);
      let severity = classSeverity || 'monitor';
      if (meta) {
        const lvl = meta[1].match(/THREAT LEVEL:\s*(\w+)/i) || meta[1].match(/<div class="status\s+(\w+)"[^>]*>/i);
        if (lvl) {
          const t = lvl[1].toLowerCase();
          if (t === 'critical' || t === 'high' || t === 'escalate') severity = 'escalate';
          else if (t === 'medium' || t === 'low' || t === 'monitor') severity = 'monitor';
          else if (t === 'ignore') severity = 'ignore';
        }
      }
      const text = (kicker ? stripTags(kicker[1]).trim() : '') + (ul ? ' ' + stripTags(ul[1]).trim() : '');
      const items = ul ? extractListItems(ul[1]) : [];
      const sources = extractLinks(inner);
      events.push({ title, severity, text: text.trim(), chips: [], sources, ...(items.length ? { items } : {}) });
    }
  }
  return events;
}

// ─── Per-type parsers ──────────────────────────────────────────────────

function parseCyberBrief(html, date) {
  const threatLevel = (() => {
    // current DOM: kpi-row kpi with <h4>Overall OT Threat Level</h4> and
    // <div class="value"><span class="pill critical">CRITICAL</span></div>
    const kpiRow = html.match(/<section class="kpi-row"[^>]*>([\s\S]*?)<\/section>/i);
    if (kpiRow) {
      const kpis = [...kpiRow[1].matchAll(/<div class="kpi"[^>]*>([\s\S]*?)<\/div>/gi)];
      for (const k of kpis) {
        const h4 = k[1].match(/<h4[^>]*>([\s\S]*?)<\/h4>/i);
        if (h4 && /overall.*threat level/i.test(h4[1])) {
          const pill = k[1].match(/<span class="pill\s+\w+"[^>]*>([^<]+)<\/span>/i);
          if (pill) return stripTags(pill[1]).trim().toUpperCase();
        }
      }
    }
    // legacy: <span class="level-pill lvl-critical">Overall Threat Level: CRITICAL</span>
    // was <div class="level-pill"> in the older DOM
    const pill = html.match(/<(?:span|div) class="level-pill[^>]*>([\s\S]*?)<\/(?:span|div)>/i);
    return pill ? stripTags(pill[1]).trim() : '';
  })();

  const executiveSummary = stripTags(extractSection(html, 'Executive Summary')).trim();

  // Key Findings: <div class="finding">N) Title. Summary <a>…</a></div> (new DOM)
  // or <li> bullets (old DOM). Extract both.
  const kfSection = extractSection(html, 'Key Findings');
  const kfFindingItems = [];
  const findingRe = /<div class="finding"[^>]*>([\s\S]*?)<\/div>/gi;
  let fm;
  while ((fm = findingRe.exec(kfSection)) !== null) {
    const t = stripTags(fm[1]).trim();
    if (t) kfFindingItems.push(t);
  }
  const kfItems = kfFindingItems.length > 0 ? kfFindingItems : extractListItems(kfSection);
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80) {
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    }
    // "N) Title. Summary" — split on first ". " or ") "
    const paren = item.match(/^\s*\d+\)\s*([^.]*)\.\s*(.*)$/);
    if (paren) return { title: paren[1].trim(), summary: paren[2].trim() };
    return { title: item.slice(0, 80), summary: item };
  });

  const kpis = extractKpisCyber(html);

  // Threat Dashboard: dash-cards with h3 + text (current) or h4/kpi (legacy)
  const dashboardSection = extractSection(html, 'Threat Dashboard');
  const dashboardCards = extractCardsCyberDash(dashboardSection);
  const dashboardMap = {};
  for (const dc of dashboardCards) {
    const key = dc.title.toLowerCase();
    dashboardMap[key] = dc;
  }
  // Actively Exploited — current DOM dashboard card "Active Exploitation"
  // whose body is a comma/semicolon list; legacy card
  // "Perimeter Devices Under Active Exploit" (.note comma list); legacy
  // "Actively Exploited Focus" section bullets.
  const activelyExploited = (() => {
    const current = dashboardMap['active exploitation'];
    if (current?.text) {
      return current.text.split(/[;,]\s*/).map((s) => s.trim()).filter(Boolean);
    }
    const dashCard = dashboardMap['perimeter devices under active exploit'];
    if (dashCard?.text) {
      return dashCard.text.split(/,\s*/).map((s) => s.trim()).filter(Boolean);
    }
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

  // Threat Actor Activity — bullets under section
  const threatActorsSection = extractSection(html, 'Threat Actor Activity');
  const threatActorItems = extractListItems(threatActorsSection);
  const threatActors = threatActorItems.length > 0 ? [{ category: 'Activity', items: threatActorItems }] : [];

  // OT/ICS Relevance Assessment (current DOM) — free text after the bullets
  const relevanceSection = extractSection(html, 'OT/ICS Relevance');
  const relevance = stripTags(relevanceSection).trim();

  // CVE Watch — current DOM "Vulnerability and CVE Watch" bullets;
  // legacy "New/Notable OT CVEs and Issues" section bullets.
  const cveWatchSection = extractSection(html, 'Vulnerability and CVE Watch') || extractSection(html, 'New/Notable OT CVEs');
  const cveWatchItems = extractListItems(cveWatchSection);
  const cveWatch = cveWatchItems.length > 0 ? [{ category: 'Vulnerability and CVE Watch', items: cveWatchItems }] : [];

  const events = extractEventsCyber(html);

  const ttpSection = extractSection(html, 'TTPs and MITRE ATT') || extractSection(html, 'TTPs');
  const ttpItems = extractListItems(ttpSection);
  const mitreIds = [...new Set(ttpItems.join(' ').match(/T\d{4}(?:\.\d{3})?/g) || [])];

  const outlookSection = extractSection(html, 'Next 72');
  const outlook = stripTags(outlookSection).trim();

  const allCves = [...new Set(
    (html.match(/CVE[\-\u2011]\d{4}[\-\u2011]\d{4,}/gi) || [])
      .map((c) => c.toUpperCase().replace(/[\u2011]/g, '-'))
  )];

  return {
    type: 'cyber',
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

function parseDeepfakeBrief(html, date) {
  const executiveSummary =
    stripTags(extractSection(html, 'Executive Overview')).trim() ||
    stripTags(extractSection(html, 'Executive Summary')).trim();

  // Risk Outlook: masthead "Risk Outlook: <span class="state state-stable">Stable</span>"
  // (current DOM) or section "Assessment: Worsening" (legacy)
  const riskMast = html.match(/Risk Outlook:\s*<span class="state[^"]*"[^>]*>([^<]+)<\/span>/i);
  let riskOutlook = riskMast ? stripTags(riskMast[1]).trim() : '';
  if (!riskOutlook) {
    const riskSection = extractSection(html, 'Risk Outlook');
    const riskMatch = riskSection.match(/Assessment:\s*(\w+)/i) || html.match(/Assessment:\s*(\w+)/i);
    riskOutlook = riskMatch ? riskMatch[1] : '';
  }

  const kfSection = extractSection(html, 'Key Findings');
  const kfItems = extractListItems(kfSection);
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80) {
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    }
    return { title: item.slice(0, 80), summary: item };
  });

  const incidents = extractIncidentsDeepfake(html);

  const emergingTrends = extractListItems(extractSection(html, 'Emerging Trends'));
  const geographicObservations = extractListItems(extractSection(html, 'Geographic Observations'));
  const detectionDevelopments = extractListItems(extractSection(html, 'Detection and Defensive'));

  return {
    type: 'deepfake',
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

function parseDisasterBrief(html, date) {
  const executiveSummary = stripTags(extractSection(html, 'Executive Summary')).trim();

  const overallThreat = (() => {
    // current: <span class="chip level">Overall Threat Level: Severe</span>
    const chip = html.match(/<span class="chip\s+level"[^>]*>Overall Threat Level:\s*([^<]+)<\/span>/i);
    if (chip) return stripTags(chip[1]).trim().toLowerCase();
    // <span class="lvl">Severe</span> (mid) or <span class="flag escalate">ESCALATE</span> (old)
    const lvl = html.match(/<span class="lvl"[^>]*>([^<]+)<\/span>/i);
    if (lvl) return stripTags(lvl[1]).trim().toLowerCase();
    const flag = html.match(/<span class="flag\s+(\w+)"[^>]*>([^<]+)<\/span>/i);
    if (flag) return stripTags(flag[2]).trim().toLowerCase();
    const kpiEsc = html.match(/<div class="kpi\s+(escalate|monitor)"[^>]*>[\s\S]*?<h4[^>]*>([\s\S]*?)<\/h4>/i);
    if (kpiEsc) return stripTags(kpiEsc[2]).trim().toLowerCase();
    return '';
  })();

  const kpis = extractKpisDisaster(html);

  const allEvents = extractEventsDisaster(html);
  const escalateEvents = allEvents.filter((e) => e.severity === 'escalate');
  const monitorEvents = allEvents.filter((e) => e.severity === 'monitor');

  // Top Five Critical Events — <div class="card priority-card"><div class="event-head">
  // <p class="event-title">N) Title</p><span class="badge escalate">ESCALATE</span></div><p class="event-body">text</p>
  // (current); mid: <div class="card priority"><div class="severity">Priority N</div><h3>Title</h3>…
  const topSection = extractSection(html, 'Top Five Critical Events');
  const topEvents = [];
  const re = /<div class="card\s+priority[^"]*"[^>]*>/gi;
  let m;
  while ((m = re.exec(topSection)) !== null) {
    const inner = extractBalancedDiv(topSection, m.index);
    const titleM =
      inner.match(/<p class="event-title"[^>]*>([\s\S]*?)<\/p>/i)
      || inner.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const title = titleM ? stripTags(titleM[1]).trim() : '';
    // Body text: <p class="event-body">…</p> (current) or <div class="muted">…</div>/<p>…</p> (mid/old)
    const bodyM = inner.match(/<p class="event-body"[^>]*>([\s\S]*?)<\/p>/i)
      || inner.match(/<div class="muted"[^>]*>([\s\S]*?)<\/div>/i)
      || inner.match(/<p>([\s\S]*?)<\/p>/i);
    const text = bodyM ? stripTags(bodyM[1]).trim() : '';
    topEvents.push({ title, severity: 'escalate', text, sources: extractLinks(inner) });
  }
  // Fallback: if priority cards not found, use first 5 escalate events
  const topEventsFinal = topEvents.length > 0 ? topEvents.slice(0, 5) : escalateEvents.slice(0, 5);

  const outlookSection = extractSection(html, 'Next 72');
  const outlook = stripTags(outlookSection).trim();

  const regionalTrends = extractListItems(extractSection(html, 'Regional and Hazard'));

  // Key Findings — bullets list
  const kfItems = extractListItems(extractSection(html, 'Key Findings'));
  const keyFindings = kfItems.map((item) => {
    const colonIdx = item.indexOf(':');
    if (colonIdx > 0 && colonIdx < 80) {
      return { title: item.slice(0, colonIdx).trim(), summary: item.slice(colonIdx + 1).trim() };
    }
    return { title: item.slice(0, 80), summary: item };
  });

  return {
    type: 'disaster',
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

function parseMaritimeBrief(html, date) {
  const executiveSummary = (() => {
    // current DOM: .summary-item divs carry the summary paragraphs
    const items = extractSection(html, 'Executive Summary');
    const summaryDivs = [...(items.matchAll(/<div class="summary-item"[^>]*>([\s\S]*?)<\/div>/gi) || [])]
      .map((d) => stripTags(d[1]).trim())
      .filter(Boolean);
    if (summaryDivs.length > 0) return summaryDivs.join(' ');
    return stripTags(items).trim();
  })();

  // Threat level (current DOM): <span class="badge high">HIGH</span> in section 3;
  // "Current Level: MODERATE." (mid) or "Assessed Threat Level: HIGH" (old)
  const tlSection = extractSection(html, 'Overall Maritime Cyber Threat Level');
  let threatLevel = 'Unknown';
  const badge = tlSection.match(/<span class="badge\s+(high|moderate|low|critical)"[^>]*>([^<]+)<\/span>/i);
  if (badge) threatLevel = stripTags(badge[2]).trim();
  const tlMatch = tlSection.match(/(?:Current Level|Assessed Threat Level):\s*(\w+)/i);
  if (tlMatch) threatLevel = tlMatch[1];

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

  // Key Findings — section 5 bullets
  const kfItems = extractListItems(extractSection(html, 'Key Findings'));
  const keyFindings = kfItems;

  // CVE Watch — section 17
  const cveWatchItems = extractListItems(extractSection(html, 'Vulnerability and CVE Watch'));
  const cveWatch = cveWatchItems.length > 0 ? [{ category: 'Vulnerability and CVE Watch', items: cveWatchItems }] : [];

  // TTPs — section 20
  const ttpItems = extractListItems(extractSection(html, 'TTPs and MITRE ATT'));
  const mitreIds = [...new Set(ttpItems.join(' ').match(/T\d{4}(?:\.\d{3})?/g) || [])];

  // Affected Vendors / Sectors (current DOM: <ul class="compact"> list items;
  // legacy: chips)
  const vendorsSection = extractSection(html, 'Affected Vendors');
  let vendors = [...new Set(extractChips(vendorsSection))];
  if (vendors.length === 0) vendors = extractListItems(vendorsSection);
  const sectorsSection = extractSection(html, 'Affected Maritime Sectors');
  let sectors = [...new Set(extractChips(sectorsSection))];
  if (sectors.length === 0) sectors = extractListItems(sectorsSection);

  const outlook = stripTags(extractSection(html, 'Next 72-Hour Maritime Cyber Outlook')).trim();

  const allCves = [...new Set(
    (html.match(/CVE[\-\u2011]\d{4}[\-\u2011]\d{4,}/gi) || [])
      .map((c) => c.toUpperCase().replace(/[\u2011]/g, '-'))
  )];

  return {
    type: 'maritime',
    date,
    threatLevel,
    executiveSummary: executiveSummary || stripTags(html).slice(0, 2048),
    dashboard: { kpis: kpis.length > 0 ? kpis : [{ value: 'N/A', label: 'No KPI data' }], vendors, sectors },
    keyFindings,
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

// ─── Investigative-assessment parser (water / french) ──────────────────
// Unlike the four daily briefs, /water and /french are month-scoped
// open-source investigative assessments. Their DOM: numbered h2/h3 section
// headings with card grids (h3/h5 title, .badge fact/assessment/high/…,
// <p> body, .src sources). Preserve every section, not just a few fields.

function splitAssessmentSections(html) {
  const re = /<h([23])[^>]*>\s*\d+\.\s*([\s\S]*?)<\/h\1>/gi;
  const heads = [...html.matchAll(re)];
  return heads.map((h, i) => ({
    heading: stripTags(h[2]).replace(/^\d+\.\s*/, '').trim(),
    body: html.slice(h.index + h[0].length, i + 1 < heads.length ? heads[i + 1].index : html.length),
  }));
}

function assessmentCards(body) {
  const cards = [];
  const re = /<div class="[^"]*card[^"]*"[^>]*>/gi;
  let m;
  while ((m = re.exec(body)) !== null) {
    const inner = extractBalancedDiv(body, m.index);
    const h = inner.match(/<h[35][^>]*>([\s\S]*?)<\/h[35]>/i);
    if (!h) continue;
    const badges = [...inner.matchAll(/<span class="badge[^"]*"[^>]*>([\s\S]*?)<\/span>/gi)].map((b) => stripTags(b[1]).trim()).filter(Boolean);
    const paras = [...inner.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi)].map((p) => stripTags(p[1]).trim()).filter(Boolean);
    const list = extractListItems(inner);
    cards.push({
      title: stripTags(h[1]).trim(),
      badges,
      text: paras.join(' ') || list.join(' '),
      sources: extractLinks(inner),
    });
  }
  return cards;
}

function assessmentDate(html, fallback) {
  const labelled = html.match(/(?:Report date|Published|Generated)\s*:\s*([^<\n]{3,60})/i);
  if (labelled) {
    const s = stripTags(labelled[1]);
    const long = s.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})/i);
    if (long) return `${long[3]}-${String(MONTHS[long[1].toLowerCase()] + 1).padStart(2, '0')}-${long[2].padStart(2, '0')}`;
  }
  // Title often ends with a month + year ("… — November 2026") — month precision.
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] ?? '';
  const monthYear = title.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i);
  if (monthYear) return `${monthYear[2]}-${String(MONTHS[monthYear[1].toLowerCase()] + 1).padStart(2, '0')}-01`;
  return fallback;
}

function parseAssessmentBrief(html, date, type) {
  const sections = splitAssessmentSections(html);
  const pick = (re) => sections.filter((s) => re.test(s.heading));
  const sectionText = (list) => list.map((s) => stripTags(s.body).trim()).filter(Boolean).join(' ');
  const sectionCards = (list) => list.flatMap((s) => assessmentCards(s.body));
  const title = stripTags((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i) || [])[1] ?? '').trim();
  const allCves = [...new Set(
    (html.match(/CVE[\-\u2011]\d{4}[\-\u2011]\d{4,}/gi) || []).map((c) => c.toUpperCase().replace(/\u2011/g, '-'))
  )];
  return {
    type,
    date: assessmentDate(html, date),
    title,
    executiveAssessment: sectionText(pick(/executive assessment/i)),
    keyFindings: sectionCards(pick(/key findings/i)),
    timeline: sectionText(pick(/timeline/i)),
    affectedSystems: sectionCards(pick(/affected systems/i)),
    methodology: sectionText(pick(/attack methodology/i)),
    impact: sectionText(pick(/operational impact|impact assessment/i)),
    correlation: sectionText(pick(/correlation/i)),
    attribution: sectionText(pick(/attribution/i)),
    recommendations: sectionText(pick(/recommendation|mitigation|defensive/i)),
    sections: sections.map((s) => ({ heading: s.heading, text: stripTags(s.body).trim(), cards: assessmentCards(s.body) })),
    sources: extractLinks(html),
    relatedCves: allCves,
  };
}

// ─── Main ──────────────────────────────────────────────────────────────

if (!existsSync(STAGING)) {
  console.error(`✘ Staging folder missing: ${STAGING}`);
  console.error('  Run: node scripts/sync-daily-briefs.mjs first.');
  process.exit(1);
}

for (const t of BRIEF_TYPES) mkdirSync(join(OUT, t), { recursive: true });

// Load existing index to merge with new data (preserve historical briefs)
let existingIndex = { briefs: [] };
const indexPath = join(OUT, 'index.json');
if (existsSync(indexPath)) {
  try { existingIndex = JSON.parse(readFileSync(indexPath, 'utf8')); } catch { /* ignore corrupt index */ }
}
const existingBriefs = new Map((existingIndex.briefs ?? []).map((b) => [`${b.type}:${b.date}`, b]));
const mergedBriefs = new Map(existingBriefs);
const briefCounts = { cyber: 0, deepfake: 0, disaster: 0, maritime: 0, water: 0, french: 0 };

const parsers = {
  cyber: parseCyberBrief,
  deepfake: parseDeepfakeBrief,
  disaster: parseDisasterBrief,
  maritime: parseMaritimeBrief,
  water: (html, date) => parseAssessmentBrief(html, date, 'water'),
  french: (html, date) => parseAssessmentBrief(html, date, 'french'),
};

for (const type of BRIEF_TYPES) {
  const htmlPath = join(STAGING, `${type}.html`);
  if (!existsSync(htmlPath)) {
    console.warn(`  ⚠ ${type}.html not found — skipping`);
    continue;
  }
  const html = readFileSync(htmlPath, 'utf8');
  const date = dateFromContent(html);
  const parsed = parsers[type](html, date);
  const outPath = join(OUT, type, `${date}.json`);
  const newSize = JSON.stringify(parsed).length;

  const existing = mergedBriefs.get(`${type}:${date}`);
  if (existing && existing.sizeBytes === newSize) {
    console.log(`  ─ ${type} ${date} (unchanged, ${newSize} bytes)`);
    briefCounts[type]++;
    continue;
  }

  writeFileSync(outPath, JSON.stringify(parsed, null, 2));
  mergedBriefs.set(`${type}:${date}`, { type, date, sizeBytes: newSize });
  briefCounts[type]++;
  console.log(`  ✔ ${type} ${date} (${newSize} bytes)`);
}

// Prune index entries whose body file no longer exists (e.g. stale
// entries from a broken parser that were deleted). Keeps the index
// honest so the UI doesn't list dates that 404 on fetch.
const allBriefs = [...mergedBriefs.values()]
  .filter((b) => existsSync(join(OUT, b.type, `${b.date}.json`)))
  .sort((a, b) => b.date.localeCompare(a.date));
const counts = { cyber: 0, deepfake: 0, disaster: 0, maritime: 0, water: 0, french: 0 };
for (const b of allBriefs) counts[b.type] = (counts[b.type] || 0) + 1;
const index = {
  source: 'agentic-ai-daily-reports.netlify.app',
  license: 'MIT',
  generatedAt: new Date().toISOString().slice(0, 10),
  counts,
  briefs: allBriefs,
};
writeFileSync(join(OUT, 'index.json'), JSON.stringify(index, null, 2));

console.log('\n✔ Built:');
for (const t of BRIEF_TYPES) {
  console.log(`    ${briefCounts[t]} ${t} brief(s) new/updated`);
}
console.log(`    ${allBriefs.length} total briefs in index`);
console.log(`    1 index (public/data/daily-briefs/index.json)`);
