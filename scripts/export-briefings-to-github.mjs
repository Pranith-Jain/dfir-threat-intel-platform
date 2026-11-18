#!/usr/bin/env node
/**
 * Export threat briefings from D1 to markdown files for GitHub publishing.
 *
 * Usage: node scripts/export-briefings-to-github.mjs [--refresh-days 3]
 *
 * Reads briefings from the pranithjain-briefings D1 database via wrangler,
 * renders each as structured markdown, and writes to briefings/ in this repo.
 * The GitHub Action then commits them and pushes to main on this repo, and
 * mirrors the same folder to Pranith-Jain/daily-threat-brief.
 *
 * Every brief is kept forever on GitHub. Files older than `--refresh-days`
 * (default 3) that already exist on disk are skipped — that keeps the daily
 * run cheap without ever deleting a historical brief. The website still
 * applies a separate 30-day limit to its *listing* only.
 */
import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const OUT_DIR = join(process.cwd(), 'briefings');
const REFRESH_DAYS = parseInt(
  process.argv.find((_, i, a) => a[i - 1] === '--refresh-days') ?? '3',
  10
);

function d1Query(sql) {
  let raw;
  try {
    raw = execSync(
      `npx wrangler d1 execute pranithjain-briefings --remote --json --command "${sql.replace(/"/g, '\\"')}"`,
      { encoding: 'utf8', timeout: 60_000, maxBuffer: 50 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }
    );
  } catch (err) {
    // Surface the real wrangler/D1 error instead of a generic execSync failure.
    // Common causes: missing/invalid CLOUDFLARE_API_TOKEN, wrong account, DB
    // not bound, or a SQL syntax error. Without this, CI fails with a cryptic
    // "Command failed" and the briefings/ folder silently stops updating.
    const stderr = err.stderr?.toString?.() ?? '';
    const stdout = err.stdout?.toString?.() ?? '';
    const detail = (stderr || stdout || err.message).slice(0, 500);
    throw new Error(
      `wrangler d1 execute failed (exit ${err.status ?? '?'}): ${detail}\n` +
      `Hint: ensure CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID are set and ` +
      `the token has D1 read access on account 6a7461d701e2e1c989e05137b0255405.`
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`wrangler returned non-JSON output (first 300 chars): ${raw.slice(0, 300)}`);
  }
  const results = parsed?.[0]?.results ?? parsed?.results ?? [];
  return results;
}

function sevEmoji(s) {
  const m = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', unknown: '⚪' };
  return m[s] ?? '⚪';
}

function esc(v) {
  return (v ?? '').replace(/\|/g, '\\|');
}

function renderBriefing(b) {
  const lines = [];
  lines.push(`# ${b.title}`);
  lines.push('');
  lines.push(`> **${b.type}** · ${b.date_range} · Generated ${b.generated_at?.slice(0, 16).replace('T', ' ')} UTC`);
  lines.push('');

  if (b.degraded) {
    lines.push('> ⚠️ **DEGRADED**: Some sources were unreachable at build time. Findings may be incomplete.');
    lines.push('');
  }

  if (b.executive_summary) {
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(b.executive_summary);
    lines.push('');
  }

  if (b.stats) {
    const s = b.stats;
    lines.push('## Stats');
    lines.push('');
    lines.push(`| Metric | Count |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Findings | ${s.findings} |`);
    lines.push(`| CVEs | ${s.cves} |`);
    lines.push(`| KEVs | ${s.kevs} |`);
    lines.push(`| IOCs | ${s.iocs} |`);
    lines.push(`| Critical | ${s.critical} |`);
    lines.push(`| High | ${s.high} |`);
    if (s.ransomware_victims > 0) lines.push(`| Ransomware victims | ${s.ransomware_victims} |`);
    lines.push('');
  }

  for (const section of b.sections ?? []) {
    lines.push(`## ${section.title} (${section.count})`);
    lines.push('');
    if (section.blurb) {
      lines.push(`_${section.blurb}_`);
      lines.push('');
    }
    if (section.findings?.length > 0) {
      lines.push('| Severity | Finding | MITRE | Description | Enrichment |');
      lines.push('|----------|---------|-------|-------------|------------|');
      for (const f of section.findings.slice(0, 50)) {
        const techs = f.mitre_techniques?.length > 0 ? f.mitre_techniques.map((t) => `\`${t}\``).join(', ') : '—';
        const cveId = /^CVE-\d{4}-\d+$/i.test(f.id ?? '') ? f.id.toUpperCase() : null;
        const enrich = cveId
          ? `[RDI](https://rdintel.com/cve/${cveId}) · [HB](https://hexbrainai.com/cve/${cveId})`
          : '—';
        lines.push(
          `| ${sevEmoji(f.severity)} ${f.severity} | ${esc(f.title)} | ${techs} | ${esc((f.description ?? '').slice(0, 120))} | ${enrich} |`
        );
      }
      if (section.findings.length > 50) lines.push(`| | _+${section.findings.length - 50} more…_ | | | |`);
      lines.push('');
    }
  }

  if (b.ioc_dump?.content) {
    lines.push('## IOC Dump');
    lines.push('');
    lines.push(`\`${b.ioc_dump.count}\` indicators (${b.ioc_dump.rawTotal} observed total${b.ioc_dump.truncated ? ', truncated for storage' : ''}):`);
    lines.push('');
    lines.push('```');
    lines.push(b.ioc_dump.content.slice(0, 5000));
    if (b.ioc_dump.content.length > 5000) lines.push(`... (+${b.ioc_dump.content.length - 5000} chars truncated)`);
    lines.push('```');
    lines.push('');
  }

  if (b.sources?.length > 0) {
    lines.push('---');
    lines.push(`Sources: ${b.sources.join(', ')}`);
  }
  if (b.mitre_techniques?.length > 0) {
    lines.push(`MITRE ATT&CK: ${b.mitre_techniques.join(', ')}`);
  }
  lines.push('');
  lines.push(`---`);
  lines.push(`*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/${b.slug})*`);

  return lines.join('\n');
}

// ── Main ──────────────────────────────────────────────────────────────────
console.log(`Exporting all briefings from D1 (refreshing last ${REFRESH_DAYS} days)…`);

// No date cutoff and no LIMIT: GitHub is the permanent archive of every brief.
const slugs = d1Query('SELECT slug, date FROM briefings ORDER BY date DESC, slug DESC');

if (slugs.length === 0) {
  // Exit NON-zero so CI fails loudly instead of silently publishing an empty
  // briefings/ folder. An empty result almost always means the D1 query is
  // broken or the briefing cron stopped — both need a human to notice.
  console.error('::error::No briefings found in D1. Aborting (the briefing cron may have stopped).');
  process.exit(1);
}

mkdirSync(OUT_DIR, { recursive: true });

const refreshCutoff = new Date(Date.now() - REFRESH_DAYS * 86_400_000).toISOString().slice(0, 10);
let written = 0;
let reused = 0;
for (const { slug, date } of slugs) {
  if (typeof slug !== 'string' || !slug) continue;
  const filename = `${slug}.md`;
  const path = join(OUT_DIR, filename);
  // Historical files are immutable once exported; only regenerate the last
  // few days so same-slug rebuilds (or a renderer fix) still land.
  if (existsSync(path) && (typeof date !== 'string' || date < refreshCutoff)) {
    reused++;
    continue;
  }
  try {
    const rows = d1Query(`SELECT body FROM briefings WHERE slug = '${slug.replace(/'/g, "''")}' LIMIT 1`);
    if (!rows[0]?.body) continue;
    const b = JSON.parse(rows[0].body);
    const md = renderBriefing(b);
    writeFileSync(path, md, 'utf8');
    written++;
    console.log(`  ✓ ${filename} (${(md.length / 1024).toFixed(1)} KB)`);
  } catch (e) {
    console.error(`  ✗ ${slug}: ${e.message?.slice(0, 100)}`);
  }
}
console.log(`  · ${reused} historical files already on disk (kept as-is)`);

// Write a README index
const files = readdirSync(OUT_DIR).filter((f) => f.endsWith('.md') && f !== 'README.md').sort().reverse();
const indexLines = [
  '# Daily Threat Briefings',
  '',
  'Automated CTI briefings from [PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings).',
  '',
  `> Last synced: ${new Date().toISOString().slice(0, 10)} · ${files.length} briefings archived (permanent on GitHub; website lists the last 30 days)`,
  '',
  '## Briefings',
  '',
];
for (const f of files) {
  const slug = f.replace('.md', '');
  indexLines.push(`- [${slug}](./${f})`);
}
indexLines.push('');
indexLines.push('---');
indexLines.push(
  'Generated by [export-briefings-to-github.mjs](https://github.com/Pranith-Jain/dfir-threat-intel-platform/blob/main/scripts/export-briefings-to-github.mjs)',
);
writeFileSync(join(OUT_DIR, 'README.md'), indexLines.join('\n'), 'utf8');

console.log(`\n✔ Exported ${written} briefings to ${OUT_DIR}/`);
