#!/usr/bin/env node
/**
 * Sync the LeakScope breach/dark-forum leak index.
 *
 * LeakScope (github.com/Ivancastl/LeakScope) is a Flask app that indexes
 * threads published on breach and dark forums, showing **metadata only** —
 * title, author, dates, view and reply counts — with every URL column
 * stripped before display. That metadata-only property is the reason it is
 * safe to replicate here: the dataset says *what was exposed and by whom*,
 * never *where the dump is*.
 *
 * The upstream CSVs carry a `url`-shaped column that the original app
 * filters out at read time. This sync strips it at write time instead, so
 * the URL never enters the staging area and cannot leak into a build
 * artifact.
 *
 * Sources (public GitHub, no auth):
 *   data/databases_progreso.csv  — dark-forum database/thread index (8.4k rows)
 *   data/db_leaks_progreso.csv   — breach leak index (3.4k rows)
 *
 * Run by:
 *   1. GitHub Action (.github/workflows/threat-intel-sync.yml)
 *   2. Manual: `node scripts/sync-leakscope.mjs`
 *
 * After sync, run `node scripts/build-leakscope.mjs`.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging');
const OUT = join(STAGING, 'leakscope');
const UA = 'pranithjain-threat-intel-sync/1.0 (+https://pranithjain.qzz.io)';

export const LEAKSCOPE = {
  source: 'LeakScope',
  sourceUrl: 'https://github.com/Ivancastl/LeakScope',
  description:
    'Breach and dark-forum leak thread index — metadata only (title, author, dates, engagement counts). No URLs and no leaked data.',
  license: 'MIT (metadata index only)',
  files: {
    darkforum: {
      url: 'https://raw.githubusercontent.com/Ivancastl/LeakScope/main/data/databases_progreso.csv',
      rows: 'databases_progreso.csv',
    },
    breach: {
      url: 'https://raw.githubusercontent.com/Ivancastl/LeakScope/main/data/db_leaks_progreso.csv',
      rows: 'db_leaks_progreso.csv',
    },
  },
};

/** Columns the upstream app drops before rendering. */
const URL_LIKE = /url|link|href/i;

/** Row cap — the upstream CSVs are ~12k rows; this is a runaway guard. */
const MAX_ROWS = 200_000;
const FETCH_TIMEOUT_MS = 30_000;

/**
 * Parse the upstream date formats.
 *
 * Three shapes appear across the two CSVs:
 *   `2026-09-28T11:19:33-0600` — ISO with a numeric offset
 *   `22-03-26, 05:56 PM`        — day-month-year with a 12-hour clock
 *   `2026-09-28 19:03:49`       — naive local timestamp
 *
 * The middle one is ambiguous (is `03-04-26` March 4th or April 3rd?), and
 * the upstream app resolves it as **day-month-year**, which is the European
 * convention the source data uses. Getting this wrong would silently shift
 * every thread by months, so it is pinned here rather than guessed.
 */
export function parseUpstreamDate(value) {
  if (!value) return null;
  const raw = String(value).trim();

  // ISO 8601, with or without a numeric offset.
  const iso = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(raw);
  if (iso) {
    const [, y, mo, d, h, mi, s, off] = iso;
    const offset = !off ? 'Z' : off === 'Z' ? 'Z' : off.includes(':') ? off : `${off.slice(0, 3)}:${off.slice(3)}`;
    const d2 = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}${offset}`);
    return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
  }

  // `22-03-26, 05:56 PM` — day-month-year, 12-hour clock.
  const dmy = /^(\d{2})-(\d{2})-(\d{2}),\s*(\d{2}):(\d{2})\s*(AM|PM)$/i.exec(raw);
  if (dmy) {
    const [, d, mo, y, h, mi, meridiem] = dmy;
    let hour = Number(h) % 12;
    if (meridiem.toUpperCase() === 'PM') hour += 12;
    const d2 = new Date(Date.UTC(2000 + Number(y), Number(mo) - 1, Number(d), hour, Number(mi)));
    return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
  }

  // `2026-09-28 19:03:49` — naive; treated as UTC so the value is stable
  // regardless of where the build runs.
  const naive = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(raw);
  if (naive) {
    const [, y, mo, d, h, mi, s] = naive;
    const d2 = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s ?? 0)));
    return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
  }

  // Bare `22-03-26`.
  const dmyShort = /^(\d{2})-(\d{2})-(\d{2})$/.exec(raw);
  if (dmyShort) {
    const [, d, mo, y] = dmyShort;
    const d2 = new Date(Date.UTC(2000 + Number(y), Number(mo) - 1, Number(d)));
    return Number.isNaN(d2.getTime()) ? null : d2.toISOString();
  }

  return null;
}

/** Split one CSV line, honouring quoted fields and "" escapes. */
export function parseCsvLine(line) {
  const out = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += ch;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ',') {
      out.push(field);
      field = '';
    } else if (ch !== '\r') field += ch;
  }
  out.push(field);
  return out;
}

/** Parse a whole CSV into records. */
export function parseCsv(text) {
  const records = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    records.push(parseCsvLine(line));
  }
  if (records.length === 0) return [];
  const header = records[0].map((h) => h.replace(/^﻿/, '').trim());
  return records.slice(1).map((r) => {
    const obj = {};
    header.forEach((h, i) => {
      obj[h] = (r[i] ?? '').trim();
    });
    return obj;
  });
}

function toInt(value) {
  const n = Number.parseInt(String(value ?? '').replace(/[^0-9-]/g, ''), 10);
  return Number.isFinite(n) ? n : 0;
}

async function fetchText(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: 'text/csv,*/*' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function syncSource(kind) {
  const spec = LEAKSCOPE.files[kind];
  const text = await fetchText(spec.url);
  const rows = parseCsv(text).slice(0, MAX_ROWS);

  // Strip every URL-shaped column up front. The upstream app filters these
  // at render time; doing it here means they never reach the staging file.
  const columns = Object.keys(rows[0] ?? {});
  const kept = columns.filter((c) => !URL_LIKE.test(c));

  const entries = rows.map((row) => {
    const out = { source: kind };
    for (const col of kept) {
      const raw = row[col] ?? '';
      switch (col) {
        case 'tid':
          out.tid = raw;
          break;
        case 'prefijo':
          out.prefix = raw || null;
          break;
        case 'titulo':
          out.title = raw;
          break;
        case 'autor':
          out.author = raw;
          break;
        case 'fecha_publicacion': {
          const iso = parseUpstreamDate(raw);
          out.published_at = iso;
          // Keep the raw string only when it could not be parsed — that is
          // the one case where it carries information the ISO value does not.
          // Emitting it unconditionally doubles the artifact for no gain.
          if (!iso && raw) out.published_raw = raw;
          break;
        }
        case 'respuestas':
          out.replies = toInt(raw);
          break;
        case 'vistas':
          out.views = toInt(raw);
          break;
        case 'paginas':
          out.pages = toInt(raw);
          break;
        case 'adjuntos':
          out.attachments = toInt(raw);
          break;
        case 'ultimo_post_fecha': {
          const iso = parseUpstreamDate(raw);
          out.last_post_at = iso;
          if (!iso && raw) out.last_post_raw = raw;
          break;
        }
        case 'ultimo_post_usuario':
          out.last_post_by = raw;
          break;
        case 'estado':
          out.status = raw;
          break;
        case 'pagina_listado':
          // A scraper artifact (which listing page the thread appeared on).
          // Carries no analyst value and only adds weight to the index.
          break;
        case 'capturado':
          out.captured_at = parseUpstreamDate(raw);
          break;
        default:
          out[col] = raw;
      }
    }
    return out;
  });

  writeFileSync(join(OUT, `${spec.rows}`), JSON.stringify({ kind, entries }));
  console.log(`  ✓ ${kind}: ${entries.length} rows`);
  return entries.length;
}

async function main() {
  if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
  console.log('• LeakScope');

  let total = 0;
  for (const kind of Object.keys(LEAKSCOPE.files)) {
    try {
      total += await syncSource(kind);
    } catch (err) {
      console.error(`  ✗ ${kind}: ${err.message ?? err}`);
      process.exitCode = 1;
    }
  }

  writeFileSync(
    join(OUT, 'source.json'),
    JSON.stringify(
      {
        ...LEAKSCOPE,
        synced_at: new Date().toISOString(),
        total_rows: total,
      },
      null,
      2
    )
  );
  console.log(`  → ${OUT} (${total} rows)\n`);
}

main().catch((err) => {
  console.error(`  ✗ ${err.message ?? err}`);
  process.exit(1);
});
