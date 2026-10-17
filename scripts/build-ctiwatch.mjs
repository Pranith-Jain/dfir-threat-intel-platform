#!/usr/bin/env node
/**
 * Build the CTIWatch manifest under public/data/threat-intel/ctiwatch/.
 *
 * Reads staging in ./threat-intel-staging/ctiwatch/ (created by
 * `node scripts/sync-ctiwatch.mjs`) and emits:
 *   index.json                          (slim — stats, counts, slim entries for all collections)
 *   vulnerabilities/<CVE-ID>.json        (one per CVE, full body)
 *   victims/<id>.json                   (one per victim, full body)
 *
 * IOCs, threat actors and campaigns are served from index.json (their slim
 * entries are complete enough); vulnerabilities and victims get per-record
 * bodies for the detail view.
 *
 * The manifest is read at runtime by worker/lib/threat-intel-manifest.ts
 * through env.ASSETS — no D1, no KV, no public fetch.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const STAGING = join(ROOT, 'threat-intel-staging', 'ctiwatch');
const OUT = join(ROOT, 'public', 'data', 'threat-intel', 'ctiwatch');

function safeFilename(slug) {
  return String(slug).replace(/\//g, '__').replace(/[^A-Za-z0-9._-]/g, '_');
}
function hashString(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, '0');
}

function readStaging() {
  const p = join(STAGING, 'ctiwatch.json');
  if (!existsSync(p)) {
    console.error(`  ⚠ no staging file at ${p} — run \`node scripts/sync-ctiwatch.mjs\` first`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(p, 'utf8'));
}

function slimIoc(i) {
  return {
    id: i.id ?? null,
    type: i.type ?? null,
    value: i.value ?? null,
    confidence_score: typeof i.confidence_score === 'number' ? i.confidence_score : (typeof i.confidence_score === 'string' ? Number(i.confidence_score) : null),
    is_active: i.is_active === true,
    first_seen: i.first_seen ?? null,
    last_seen: i.last_seen ?? null,
    tags: Array.isArray(i.tags) ? i.tags.slice(0, 8) : [],
    context: typeof i.context === 'string' ? i.context.slice(0, 200) : null,
    source_name: (i.source && typeof i.source === 'object') ? (i.source.name ?? null) : (typeof i.source_name === 'string' ? i.source_name : null),
    threat_actor: (i.threat_actor && typeof i.threat_actor === 'object') ? (i.threat_actor.name ?? null) : null,
  };
}

function slimVuln(v) {
  return {
    cve_id: v.cve_id ?? v.cveId ?? null,
    title: v.title ?? null,
    severity: typeof v.severity === 'string' ? v.severity.toUpperCase() : null,
    cvss_score: v.cvss_score ?? v.cvssScore ?? null,
    cvss_vector: v.cvss_vector ?? v.cvssVector ?? null,
    is_kev: v.is_kev === true || v.isInKev === true,
    exploit_status: v.exploit_status ?? null,
    published_date: v.published_date ?? v.publishedDate ?? null,
    cwe: Array.isArray(v.cwe) ? v.cwe : (Array.isArray(v.cwes) ? v.cwes : []),
    vendor: v.vendor ?? null,
    product: v.product ?? null,
    priority_score: v.priority_score ?? null,
    epss: v.epss ?? null,
    tags: Array.isArray(v.tags) ? v.tags.slice(0, 8) : [],
  };
}

function vulnBody(v) {
  const b = { ...slimVuln(v) };
  b.description = v.description ?? null;
  b.references = Array.isArray(v.references) ? v.references.slice(0, 20) : (Array.isArray(v.reference) ? v.reference.slice(0, 20) : []);
  b.affected_products = Array.isArray(v.affected_products) ? v.affected_products : (Array.isArray(v.affectedProducts) ? v.affectedProducts : []);
  b.sizeBytes = Buffer.byteLength(JSON.stringify(b), 'utf8');
  return b;
}

function slimVictim(v) {
  return {
    id: v.id ?? null,
    name: v.name ?? v.victim ?? null,
    group: v.group ?? v.threat_actor ?? v.actor ?? null,
    country: v.country ?? null,
    sector: v.sector ?? null,
    attack_date: v.attack_date ?? v.attackDate ?? v.date ?? null,
    website: v.website ?? v.url ?? null,
    source: v.source ?? null,
  };
}

function victimBody(v) {
  const b = { ...slimVictim(v) };
  b.description = v.description ?? null;
  b.sizeBytes = Buffer.byteLength(JSON.stringify(b), 'utf8');
  return b;
}

function slimActor(a) {
  return {
    id: a.id ?? null,
    name: a.name ?? null,
    country: a.country ?? null,
    aliases: Array.isArray(a.aliases) ? a.aliases : [],
    motivation: a.motivation ?? null,
    sophistication: a.sophistication ?? null,
    source: a.source ?? null,
    active: a.is_active !== false,
    description: typeof a.description === 'string' ? a.description.slice(0, 300) : null,
  };
}

function slimCampaign(c) {
  return {
    id: c.id ?? null,
    name: c.name ?? null,
    type: c.type ?? null,
    impact: c.impact ?? null,
    is_active: c.is_active === true || c.active === true,
    started: c.started ?? c.start_date ?? c.created_at ?? null,
    description: typeof c.description === 'string' ? c.description.slice(0, 300) : null,
  };
}

function main() {
  console.log('CTIWatch build — writing into', OUT);
  const staged = readStaging();
  const iocs = Array.isArray(staged.iocs) ? staged.iocs : [];
  const vulns = Array.isArray(staged.vulnerabilities) ? staged.vulnerabilities : [];
  const kev = Array.isArray(staged.kev) ? staged.kev : [];
  const actors = Array.isArray(staged.actors) ? staged.actors : [];
  const victims = Array.isArray(staged.victims) ? staged.victims : [];
  const campaigns = Array.isArray(staged.campaigns) ? staged.campaigns : [];
  if (iocs.length === 0 && vulns.length === 0 && victims.length === 0) {
    console.error('  ✘ staging empty — aborting');
    process.exit(1);
  }

  if (existsSync(OUT)) rmSync(OUT, { recursive: true });
  mkdirSync(join(OUT, 'vulnerabilities'), { recursive: true });
  mkdirSync(join(OUT, 'victims'), { recursive: true });

  // vulnerabilities per-record
  for (const v of vulns) {
    const cve = v.cve_id ?? v.cveId;
    if (!cve) continue;
    const body = vulnBody(v);
    writeFileSync(join(OUT, 'vulnerabilities', `${safeFilename(cve)}.json`), JSON.stringify(body));
  }
  // kev per-record (only if not already written by vulns)
  for (const v of kev) {
    const cve = v.cve_id ?? v.cveId;
    if (!cve) continue;
    const p = join(OUT, 'vulnerabilities', `${safeFilename(cve)}.json`);
    if (!existsSync(p)) {
      const body = vulnBody(v);
      writeFileSync(p, JSON.stringify(body));
    }
  }
  // victims per-record
  for (const v of victims) {
    const id = v.id;
    if (!id) continue;
    const body = victimBody(v);
    writeFileSync(join(OUT, 'victims', `${safeFilename(id)}.json`), JSON.stringify(body));
  }

  const index = {
    source: staged.source,
    sourceUrl: staged.sourceUrl,
    description: staged.description,
    license: staged.license,
    syncedAt: staged.syncedAt,
    stats: staged.stats ?? null,
    victimStats: staged.victimStats ?? null,
    counts: {
      iocs: iocs.length,
      vulnerabilities: vulns.length,
      kev: kev.length,
      actors: actors.length,
      victims: victims.length,
      campaigns: campaigns.length,
    },
    iocs: iocs.map(slimIoc),
    vulnerabilities: vulns.map(slimVuln),
    kev: kev.map(slimVuln),
    actors: actors.map(slimActor),
    victims: victims.map(slimVictim),
    campaigns: campaigns.map(slimCampaign),
  };
  writeFileSync(join(OUT, 'index.json'), JSON.stringify(index));

  console.log(`    ✔ index.json (iocs ${iocs.length}, vulns ${vulns.length}, kev ${kev.length}, actors ${actors.length}, victims ${victims.length}, campaigns ${campaigns.length})`);
}

main();
