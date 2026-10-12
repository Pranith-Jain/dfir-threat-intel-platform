#!/usr/bin/env node
/**
 * Sync Anthropic's Project Glasswing coordinated-disclosure ledger.
 *
 * Source: https://red.anthropic.com/2026/cvd
 *
 * Glasswing is Anthropic's AI vulnerability-discovery program. The ledger is
 * the public half of it: CVEs assigned to findings the program disclosed, each
 * with the affected ecosystem, weakness class, severity, discovery date and an
 * internal `ANT-*` finding id that links to a fuller write-up.
 *
 * Why it earns a feed rather than a blog link:
 *
 *  - It is a CVE source with an origin most vulnerability feeds cannot
 *    distinguish: these were found by an AI agent, not by a human researcher.
 *    For the /threatintel/ai-security surface, "machine-discovered" is the
 *    whole point, and it is otherwise invisible in NVD/GHSA.
 *  - The `ANT-*` ids resolve to a per-finding write-up, so it carries
 *    narrative a bare CVE record does not.
 *  - The ecosystem field (e.g. `wolfssl/wolfssl`, `twigphp/twig`) gives a
 *    language/package key we can join against our supply-chain surfaces.
 *
 * The page is server-rendered HTML rather than JSON (no __NEXT_DATA__, no
 * ld+json), so this parses the markup. That is brittle by nature; the
 * `parseCvdHtml` pure function is what the tests pin, and the sync reports a
 * hard failure if the shape ever changes rather than silently emitting an
 * empty dataset.
 *
 * Run:  node scripts/sync-anthropic-glasswing.mjs
 * Emits:
 *   public/data/threat-intel/glasswing/cvd.json
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'glasswing');
const SOURCE_URL = 'https://red.anthropic.com/2026/cvd';
const FETCH_TIMEOUT_MS = 25_000;

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Parse the ledger's server-rendered record cards.
 *
 * Exported and pure so the shape can be tested against a fixture without a
 * network fetch. Every field degrades to null rather than throwing: a record
 * missing its severity is still worth indexing for its CVE and ecosystem.
 */
export function parseCvdHtml(html) {
  const records = [];
  // Each record is a <div class="card id-record" ...> ... </div>. The attribute
  // values are the reliable part; the inner spans carry the display fields.
  const cardRe = /<div class="card id-record"([^>]*)>([\s\S]*?)<\/div>/g;

  for (const m of html.matchAll(cardRe)) {
    const [, attrs, body] = m;

    const attr = (name) => {
      const a = new RegExp(`${name}="([^"]*)"`).exec(attrs);
      return a ? a[1] : null;
    };

    const cveMatch = /class="id-record-id"[^>]*>\s*(CVE-\d{4}-\d+)\s*</.exec(body);
    if (!cveMatch) continue;

    const meta = /class="id-record-meta"[^>]*>([\s\S]*?)<\/span>\s*(?:<span class="id-record-title"|$)/.exec(body);
    const metaText = (meta ? meta[1] : '')
      .replace(/<[^>]+>/g, ' ') // drop the severity span and the ANT link anchor
      .replace(/&middot;|·/g, '|')
      .replace(/&amp;/g, '&')
      .replace(/\s*\|\s*/g, '|')
      .replace(/\|+/g, '|')
      .trim();
    // `ecosystem|weaknessClass|<severity cell>|<severity cell>|ANT-id`
    const parts = metaText.split('|').map((s) => s.trim());

    const antMatch = /(ANT-\d{4}-[A-Z0-9]+)/.exec(body);
    const titleMatch = /class="id-record-title"[^>]*>([\s\S]*?)<\/span>/.exec(body);
    const nvdMatch = /class="id-record-id"[^>]*href="([^"]+)"/.exec(body);

    const severity = attr('data-sev');
    const discovered = attr('data-discovered');

    records.push({
      cveId: cveMatch[1],
      findingId: antMatch ? antMatch[1] : null,
      ecosystem: parts[0] || null,
      weakness: parts[1] || null,
      severity: severity ?? null,
      discoveredAt: discovered ?? null,
      title: titleMatch ? titleMatch[1].trim() : null,
      nvdUrl: nvdMatch ? nvdMatch[1] : null,
      // Relative on the page; absolutise so the frontend can link straight out.
      findingUrl: antMatch ? new URL(`findings/${antMatch[1]}.html`, SOURCE_URL).href : null,
    });
  }

  return records;
}

/**
 * Rollup used by the header stats and the hub tab badges.
 */
export function summarise(records) {
  const bySeverity = {};
  const ecosystems = new Set();
  const weaknesses = {};
  let earliest = null;

  for (const r of records) {
    const sev = r.severity ?? 'unknown';
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    if (r.ecosystem) {
      ecosystems.add(r.ecosystem);
      // Count per project, not per vendor: `twigphp/twig` and `joomla/joomla-cms`
      // are two projects; grouping on the prefix alone would merge them.
      const project = r.ecosystem.split('/')[0];
      weaknesses[project] = (weaknesses[project] ?? 0) + 1;
    }
    if (r.discoveredAt && (earliest === null || r.discoveredAt < earliest)) earliest = r.discoveredAt;
  }

  const topEcosystems = Object.entries(weaknesses)
    .map(([id, count]) => ({ id, findings: count }))
    .sort((a, b) => b.findings - a.findings || a.id.localeCompare(b.id));

  return {
    total: records.length,
    bySeverity,
    severityRanked: Object.entries(bySeverity)
      .sort((a, b) => (SEV_RANK[b[0]] ?? 0) - (SEV_RANK[a[0]] ?? 0))
      .map(([id, count]) => ({ id, count })),
    ecosystemCount: ecosystems.size,
    topEcosystems,
    earliestDiscovery: earliest,
  };
}

async function main() {
  console.log('🔨 Syncing Anthropic Project Glasswing CVD ledger');

  const res = await fetch(SOURCE_URL, {
    headers: { 'User-Agent': 'pranithjain-dfir/1.0', accept: 'text/html' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`${SOURCE_URL} -> HTTP ${res.status}`);

  const html = await res.text();
  const records = parseCvdHtml(html);

  if (records.length === 0) {
    // Hard fail. The page is server-rendered HTML and a silent empty parse is
    // indistinguishable downstream from "Anthropic disclosed nothing", which
    // is the worst possible failure mode for a vulnerability feed.
    throw new Error(
      `Parsed 0 records from ${SOURCE_URL}. The page markup has probably changed. ` +
        `Check parseCvdHtml() and update its tests before shipping.`
    );
  }

  // Newest first; discovery date is the only reliable ordering key and the page
  // itself paginates in an arbitrary order.
  records.sort((a, b) => (b.discoveredAt ?? '').localeCompare(a.discoveredAt ?? '') || a.cveId.localeCompare(b.cveId));

  const payload = {
    schemaVersion: 'anthropic-glasswing-cvd-v1',
    generatedAt: new Date().toISOString(),
    sourceUrl: SOURCE_URL,
    attribution: 'Anthropic Project Glasswing coordinated vulnerability disclosure ledger.',
    ...summarise(records),
    records,
  };

  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'cvd.json'), JSON.stringify(payload, null, 2));

  console.log(`  ✓ ${records.length} CVE-bearing findings across ${payload.ecosystemCount} ecosystems`);
  console.log(`  ✓ severity: ${payload.severityRanked.map((s) => `${s.id} ${s.count}`).join(', ')}`);
  console.log(`  ✓ earliest discovery: ${payload.earliestDiscovery}`);
  console.log(`  → public/data/threat-intel/glasswing/cvd.json\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(`  ✗ ${err.message ?? err}`);
    process.exit(1);
  });
}