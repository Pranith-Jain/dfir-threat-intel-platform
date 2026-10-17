#!/usr/bin/env node
/**
 * Build the OffSeq Threat Radar manifest under
 * public/data/threat-intel/offseq/.
 *
 * Reads staging in ./threat-intel-staging/offseq/ (created by
 * `node scripts/sync-offseq.mjs`) and emits:
 *   index.json                  (slim — source meta, counts, slim entries, overview, tags)
 *   threats/<slug>.json         (one per threat, full slim body)
 *
 * The manifest is read at runtime by worker/lib/threat-intel-manifest.ts
 * through env.ASSETS — no D1, no KV, no public fetch.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'offseq');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'offseq');

function hashString(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, '0');
}

function safeFilename(slug) {
  return String(slug).replace(/\//g, '__').replace(/[^A-Za-z0-9._-]/g, '_');
}

function threatSlug(t) {
  const base = safeFilename(String(t.slug || t.externalId || t.title || 'threat')).slice(0, 80) || 'threat';
  const suffix = hashString(`${t.externalId || ''}|${t.slug || ''}|${t.title || ''}`).slice(0, 6);
  return `${base}-${suffix}`;
}

function extractCveIds(t) {
  const out = new Set();
  const scan = (s) => {
    const direct = String(s).match(/CVE-\d{4}-\d+/gi);
    if (direct) for (const x of direct) out.add(x.toUpperCase());
    const tagged = String(s).match(/cve[-_](\d{4})[-_](\d+)/gi);
    if (tagged) for (const x of tagged) {
      const m = x.match(/cve[-_](\d{4})[-_](\d+)/i);
      if (m) out.add(`CVE-${m[1]}-${m[2]}`);
    }
  };
  if (t.cveId) scan(t.cveId);
  if (Array.isArray(t.tags)) for (const x of t.tags) scan(x);
  if (t.title) scan(t.title);
  if (t.description) scan(t.description);
  return [...out];
}

function toSlim(t, slug) {
  return {
    slug,
    externalId: t.externalId ?? null,
    source: t.source ?? null,
    type: t.type ?? null,
    title: t.title ?? null,
    severity: typeof t.severity === 'string' ? t.severity.toLowerCase() : null,
    cvssScore: typeof t.cvssScore === 'number' ? t.cvssScore : null,
    publishedDate: t.publishedDate ?? null,
    cveId: t.cveId ?? null,
    cveIds: extractCveIds(t),
    exploited: t.mirageIntel?.exploited === true || t.knownExploitsInWild === true,
    knownExploitsInWild: t.knownExploitsInWild === true,
    tags: Array.isArray(t.tags) ? t.tags.slice(0, 8) : [],
    url: slug ? `https://radar.offseq.com/threats/${slug}` : null,
    sizeBytes: 0,
  };
}

function toBody(t, slug) {
  const mirage = t.mirageIntel && typeof t.mirageIntel === 'object' ? t.mirageIntel : null;
  const enrichment = t.enrichment && typeof t.enrichment === 'object' ? t.enrichment : null;
  const body = {
    slug,
    externalId: t.externalId ?? null,
    source: t.source ?? null,
    type: t.type ?? null,
    title: t.title ?? null,
    description: t.description ?? null,
    severity: typeof t.severity === 'string' ? t.severity.toLowerCase() : null,
    cvssScore: typeof t.cvssScore === 'number' ? t.cvssScore : null,
    cvssVector: t.cvssVector ?? null,
    publishedDate: t.publishedDate ?? null,
    cveId: t.cveId ?? null,
    cveIds: extractCveIds(t),
    tags: Array.isArray(t.tags) ? t.tags : [],
    knownExploitsInWild: t.knownExploitsInWild === true,
    exploited: (mirage && mirage.exploited === true) || t.knownExploitsInWild === true,
    mirageCountries: Array.isArray(mirage?.countries) ? mirage.countries : [],
    patchAvailable: t.patchAvailable === true,
    knownThreatActors: Array.isArray(t.knownThreatActors) ? t.knownThreatActors : [],
    affectedCountries: Array.isArray(t.affectedCountries) ? t.affectedCountries : [],
    references: Array.isArray(t.references) ? t.references.slice(0, 20) : [],
    url: slug ? `https://radar.offseq.com/threats/${slug}` : null,
    aiSummary: (enrichment && typeof enrichment.aiGeneratedSummary === 'string') ? enrichment.aiGeneratedSummary : (typeof enrichment?.summary === 'string' ? enrichment.summary : null),
    aiImpact: (enrichment && typeof enrichment.aiGeneratedImpact === 'string') ? enrichment.aiGeneratedImpact : null,
  };
  body.sizeBytes = Buffer.byteLength(JSON.stringify(body), 'utf8');
  // backfill sizeBytes into slim not needed (computed in build)
  return body;
}

function readStaging() {
  const p = join(STAGING, 'offseq.json');
  if (!existsSync(p)) {
    console.error(`  ⚠ no staging file at ${p} — run \`node scripts/sync-offseq.mjs\` first`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(p, 'utf8'));
}

function main() {
  console.log('OffSeq build — writing into', OUT);
  const staged = readStaging();
  const threats = Array.isArray(staged.threats) ? staged.threats : [];
  if (threats.length === 0) {
    console.error('  ✘ staging has zero threats — aborting');
    process.exit(1);
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'threats'), { recursive: true });

  const slim = [];
  const byType = {};
  const bySeverity = {};
  let exploited = 0;
  for (const t of threats) {
    const slug = threatSlug(t);
    const body = toBody(t, slug);
    const s = toSlim(t, slug);
    s.sizeBytes = body.sizeBytes;
    writeFileSync(join(OUT, 'threats', `${safeFilename(slug)}.json`), JSON.stringify(body));
    slim.push(s);
    const ty = t.type || 'unknown';
    byType[ty] = (byType[ty] ?? 0) + 1;
    const sev = (typeof t.severity === 'string' ? t.severity.toLowerCase() : 'unknown');
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    if (body.exploited) exploited += 1;
  }

  // top tags
  const tagCounts = {};
  for (const t of threats) {
    if (Array.isArray(t.tags)) for (const tag of t.tags) tagCounts[tag] = (tagCounts[tag] ?? 0) + 1;
  }
  const topTags = Object.entries(tagCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 60)
    .map(([name, count]) => ({ name, count }));

  const index = {
    source: staged.source,
    sourceUrl: staged.sourceUrl,
    description: staged.description,
    license: staged.license,
    syncedAt: staged.syncedAt,
    days: staged.days,
    overview: staged.overview ?? null,
    counts: {
      threats: threats.length,
      exploited,
      byType,
      bySeverity,
    },
    tags: topTags,
    threats: slim,
  };
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  console.log(`    ✔ index.json (${threats.length} threats, ${exploited} exploited)`);
  for (const [ty, n] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
    console.log(`      ${ty.padEnd(16)} ${String(n).padStart(3)}`);
  }
}

main();
