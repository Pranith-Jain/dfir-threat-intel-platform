#!/usr/bin/env node
/**
 * Mirror VulnSocial's public CVE decision data as a structured reference.
 *
 * REA verified https://vulnsocial.com/cve/<id> is server-rendered: the exact
 * triage object lives in the Next.js RSC flight stream as
 * `{"variant":"inline","cveId":...,"directive":...,"pocUrls":[...]}`. We parse
 * that stream as DATA (never execute it) with a balanced-brace scanner.
 *
 * robots.txt content signals: ai-train=no, search=yes, ai-input=yes. We do not
 * train on this content and mirror only factual fields + links, no CSS/code.
 *
 * Output: public/data/vulnsocial/index.json + cves/<id>.json
 * Run:    node scripts/sync-vulnsocial.mjs [--source-dir <dir>] [--limit N]
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeJsonIfChanged } from './lib/write-if-changed.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = join(ROOT, 'public', 'data', 'vulnsocial');
const SITE = 'https://vulnsocial.com';
const UA = 'Mozilla/5.0 (compatible; pranithjain-sync/1.0; +https://pranithjain.qzz.io)';
const DEFAULT_LIMIT = 40;

/** Join the RSC flight strings embedded in a server-rendered page. */
export function flightText(html) {
  const chunks = [];
  const re = /self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)/g;
  for (const m of String(html ?? '').matchAll(re)) {
    try { chunks.push(JSON.parse(m[1])); } catch { /* skip malformed chunk */ }
  }
  return chunks.join('');
}

/** Extract a balanced JSON object starting at `start` (respecting strings). */
export function balancedObject(text, start) {
  if (text[start] !== '{') return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        try { return JSON.parse(text.slice(start, i + 1)); } catch { return null; }
      }
    }
  }
  return null;
}

/** Parse the compact decision object for one CVE from its page HTML. */
export function parseCvePage(html, cveId) {
  const flight = flightText(html);
  const marker = `"cveId":"${cveId}"`;
  const at = flight.indexOf(marker);
  if (at < 0) return null;
  const brace = flight.lastIndexOf('{', at);
  const decision = balancedObject(flight, brace);
  if (!decision?.directive) return null;

  // Plain-English brief: "Severity: … Impact: …" is rendered in the flight
  // stream as a string child. Prefer it over the raw NVD description.
  const briefAt = flight.indexOf('"Severity:');
  let plain = null;
  if (briefAt >= 0) {
    const end = flight.indexOf('"', briefAt + 1);
    if (end > briefAt) {
      try { plain = JSON.parse(`"${flight.slice(briefAt + 1, end)}"`); } catch { plain = null; }
    }
  }

  return {
    id: cveId,
    shareUrl: decision.shareUrl ?? `${SITE}/cve/${cveId}`,
    plainEnglish: plain,
    vendors: decision.summary?.vendors ?? [],
    products: decision.summary?.products ?? [],
    versions: decision.summary?.versions ?? [],
    totalMentions: decision.totalMentions ?? 0,
    totalDays: decision.totalDays ?? 0,
    topClassification: decision.topClassification ?? null,
    cvssScore: decision.cvssScore ?? null,
    cvssSeverity: decision.cvssSeverity ?? null,
    cvssSource: decision.cvssSource ?? null,
    inKev: Boolean(decision.inCisaKev),
    kevDueDate: decision.kevDueDate ?? null,
    activeExploitation: Boolean(decision.hasActiveExploitation),
    exploitCode: Boolean(decision.hasExploitCode),
    poc: Boolean(decision.hasPoc),
    patch: Boolean(decision.hasPatch),
    sla: decision.slaWindow ?? null,
    urgency: decision.urgencyLabel ?? null,
    directive: String(decision.directive).slice(0, 1200),
    pocUrls: (decision.pocUrls ?? []).slice(0, 40).map((u) => String(u).slice(0, 1000)),
    patchUrls: (decision.patchUrls ?? []).slice(0, 40).map((u) => String(u).slice(0, 1000)),
    fetchedAt: new Date().toISOString(),
  };
}

/** CVE ids published on the radar homepage's RSC payload. */
export function parseHomeIds(html) {
  const flight = flightText(html);
  return [...new Set([...flight.matchAll(/CVE-\d{4}-\d{4,7}/g)].map((m) => m[0]))].slice(0, 60);
}

async function main() {
  const srcArg = process.argv.indexOf('--source-dir');
  const limitArg = process.argv.indexOf('--limit');
  const limit = limitArg > 0 ? Math.max(1, Math.min(Number(process.argv[limitArg + 1]) || DEFAULT_LIMIT, 100)) : DEFAULT_LIMIT;
  const fetchText = async (url) => {
    const res = await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(45_000) });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res.text();
  };

  let ids;
  if (srcArg > 0) {
    const dir = process.argv[srcArg + 1];
    ids = readFileSync(join(dir, 'ids.txt'), 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  } else {
    ids = parseHomeIds(await fetchText(`${SITE}/`));
  }
  if (!ids.length) throw new Error('no CVE ids discovered — upstream layout changed');

  const bodies = [];
  for (const id of ids.slice(0, limit)) {
    try {
      const html = srcArg > 0
        ? readFileSync(join(process.argv[srcArg + 1], `${id}.html`), 'utf8')
        : await fetchText(`${SITE}/cve/${id}`);
      const body = parseCvePage(html, id);
      if (body) bodies.push(body);
      if (srcArg < 0) await new Promise((r) => setTimeout(r, 400));
    } catch (e) {
      console.warn(`  ! ${id}: ${e.message}`);
    }
  }
  if (!bodies.length) throw new Error('no CVE decision objects parsed');

  rmSync(join(OUT, 'cves'), { recursive: true, force: true });
  mkdirSync(join(OUT, 'cves'), { recursive: true });
  for (const b of bodies) writeJsonIfChanged(join(OUT, 'cves', `${b.id}.json`), b);
  writeJsonIfChanged(join(OUT, 'index.json'), {
    generatedAt: new Date().toISOString(),
    source: 'VulnSocial',
    sourceUrl: SITE,
    note: 'Factual triage metadata parsed from public server-rendered pages. No upstream code, CSS or prose bodies vendored. Content signals: ai-train=no, search=yes, ai-input=yes.',
    counts: { cves: bodies.length, withPlainEnglish: bodies.filter((b) => b.plainEnglish).length },
    cves: bodies.map((b) => ({
      id: b.id, urgency: b.urgency, sla: b.sla, cvssScore: b.cvssScore, cvssSeverity: b.cvssSeverity,
      kev: b.inKev, exploitation: b.activeExploitation, poc: b.poc, patch: b.patch,
      mentions: b.totalMentions, directive: b.directive.slice(0, 160), url: b.shareUrl,
    })),
  });
  console.log(`  ✓ VulnSocial: ${bodies.length} CVE decision records → ${OUT}\n`);
}

const invoked = process.argv[1] && pathToFileURL(process.argv[1]).href === pathToFileURL(fileURLToPath(import.meta.url)).href;
if (invoked) main().catch((e) => { console.error(`vulnsocial sync failed: ${e.message}`); process.exit(1); });
