#!/usr/bin/env node
/**
 * format-feed-audit.mjs — render `audit-feed-health.mjs --json` as plain text.
 *
 * Split out of the workflow so the summary format lives next to the audit logic
 * and can be run locally:
 *
 *   node scripts/audit-feed-health.mjs --json > /tmp/a.json
 *   node scripts/format-feed-audit.mjs /tmp/a.json
 *
 * Usage: format-feed-audit.mjs <in.json> [out.txt]
 *
 * Prints to stdout when no output path is given, so it doubles as a local
 * formatter. Never exits non-zero — the audit's own exit code is the signal,
 * and this script must still produce a report when that code is 1.
 */

import { readFileSync, writeFileSync } from 'node:fs';

const [, , inPath, outPath] = process.argv;

if (!inPath) {
  console.error('usage: format-feed-audit.mjs <in.json> [out.txt]');
  process.exit(2);
}

let report;
try {
  report = JSON.parse(readFileSync(inPath, 'utf8'));
} catch (e) {
  console.error(`could not read audit JSON at ${inPath}: ${e instanceof Error ? e.message : e}`);
  process.exit(2);
}

const s = report.summary ?? {};
const rows = Array.isArray(report.registered) ? report.registered : [];
const retired = Array.isArray(report.retired) ? report.retired : [];

const lines = [];
lines.push(`Feed health audit — ${report.audited_at ?? 'unknown time'}`);
lines.push('');
lines.push(`registered:  ${s.registered ?? rows.length}`);
lines.push(`healthy:      ${s.healthy ?? '?'}`);
lines.push(`unhealthy:    ${s.unhealthy ?? '?'}`);
lines.push(`skipped:      ${s.skipped ?? 0} (key-gated / not a plain GET)`);
lines.push(`on fallback:  ${s.on_fallback ?? 0}`);
lines.push('');

const bad = rows.filter((f) => !f.ok && !f.skipped);
// Only compare against `auditRows` when the PRIMARY answered — it records the
// primary's size, so a fallback's row count is not comparable. Feeds currently on
// a fallback are reported separately below instead.
const warn = rows.filter(
  (f) => f.ok && f.via === 'primary' && f.auditRows !== undefined && f.rows > 0 && f.rows < f.auditRows * 0.25
);
const onFallback = rows.filter((f) => f.ok && f.via === 'fallback');

if (bad.length === 0) {
  lines.push('All registered feeds healthy.');
} else {
  lines.push(`UNHEALTHY (${bad.length}) — dead, stubbed, or returning HTML:`);
  for (const f of bad) lines.push(`  x ${f.id} — ${f.note ?? `HTTP ${f.status ?? 'ERR'}`}`);
}

if (onFallback.length) {
  lines.push('');
  lines.push(`ON FALLBACK (${onFallback.length}) — primary did not answer; serving data but the upstream is degraded:`);
  for (const f of onFallback) lines.push(`  ~ ${f.id} — primary: ${f.primaryNote ?? 'failed'}`);
}

if (warn.length) {
  lines.push('');
  lines.push(`ROW-COUNT COLLAPSE (${warn.length}) — over 4x smaller than the recorded auditRows:`);
  for (const f of warn) lines.push(`  ! ${f.id} — ${f.auditRows} -> ${f.rows} rows`);
}

if (retired.length) {
  const recovered = retired.filter((r) => r.recovered);
  lines.push('');
  lines.push(`Retired feeds: ${retired.length - recovered.length}/${retired.length} still offline as expected.`);
  for (const r of recovered) lines.push(`  ? RECOVERED — ${r.url} may be re-adoptable`);
}

const out = lines.join('\n') + '\n';
if (outPath) writeFileSync(outPath, out);
process.stdout.write(out);
