/**
 * Dossier assembly: take the researched material (CVEs, pages, platform
 * signal) plus the raw candidate evidence and produce the single structured
 * object the writer prompt reads.
 *
 * Kept separate from `index.ts` so the shaping logic is pure and testable
 * without any fetching — the mining + gap-inference is all here.
 */

import type { CaseStudyType } from '../types';
import type { CveFacts, PlatformFacts } from './enrich';
import type { ExtractedPage } from './extract';
import { scrubString } from '../generation/scrub-prompt';
import type { ResearchDossier } from './dossier';

export interface BuildDossierInput {
  type: CaseStudyType;
  title: string;
  rationale?: string;
  evidence: Record<string, unknown>;
  cves: CveFacts[];
  pages: ExtractedPage[];
  platform: PlatformFacts;
  unread: Array<{ url: string; reason: string }>;
  now: Date;
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

function strings(v: unknown, limit = 40): string[] {
  if (Array.isArray(v)) {
    return v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).slice(0, limit);
  }
  return typeof v === 'string' && v.trim().length > 0 ? [v.trim()] : [];
}

function isReservedIp(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a = -1, b = -1, c = -1] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && (b === 51 || b === 18 || b === 19)) return true;
  if (a === 203 && b === 0) return true;
  if (a >= 224) return true;
  return false;
}

function isDocDomain(d: string): boolean {
  const s = d.toLowerCase();
  return (
    s === 'localhost' ||
    /\.(test|local|invalid|example|localhost)$/.test(s) ||
    /^(example|test|placeholder|sample|dummy|foobar|fake)\./.test(s) ||
    /^(www\.)?(example|test)\.(com|net|org)$/.test(s)
  );
}

function mineIndicators(evidence: Record<string, unknown>): ResearchDossier['indicators'] {
  const out: ResearchDossier['indicators'] = [];
  const explicit = (evidence.iocs ?? {}) as Record<string, unknown>;
  const add = (type: string, all: string[]) => {
    const clean = [...new Set(all.map((v) => v.trim()).filter(Boolean))];
    if (clean.length === 0) return;
    out.push({ type, values: clean.slice(0, 12), total: clean.length });
  };

  for (const key of ['domains', 'ipv4s', 'ips', 'urls', 'hashes', 'sha256', 'emails']) {
    if (explicit[key] !== undefined) add(key, strings(explicit[key], 60));
  }

  const blob = JSON.stringify(evidence).slice(0, 20000);
  add(
    'ipv4',
    (blob.match(IPV4_RE) ?? []).filter((ip) => !isReservedIp(ip))
  );
  add('sha256', blob.match(SHA256_RE) ?? []);

  const sourceHosts = new Set<string>();
  for (const u of blob.match(/https?:\/\/([^/\s"'\\)]+)/gi) ?? []) {
    const h = /https?:\/\/([^/\s"'\\)]+)/i.exec(u)?.[1];
    if (h) sourceHosts.add(h.toLowerCase().replace(/^www\./, ''));
  }
  add(
    'domain',
    (blob.match(DOMAIN_RE) ?? [])
      .filter((d) => !isDocDomain(d))
      .filter((d) => !sourceHosts.has(d.toLowerCase().replace(/^www\./, '')))
  );
  return out;
}

function mineEntities(evidence: Record<string, unknown>, cves: CveFacts[]): ResearchDossier['entities'] {
  const vendors = new Set<string>();
  const products = new Set<string>();
  const actors = new Set<string>();
  const techniques = new Set<string>();
  for (const v of strings(evidence.vendor, 20)) vendors.add(v);
  for (const v of strings(evidence.vendors, 20)) vendors.add(v);
  for (const p of strings(evidence.product, 20)) products.add(p);
  for (const p of strings(evidence.products, 20)) products.add(p);
  for (const p of strings(evidence.family, 20)) products.add(p);
  for (const a of strings(evidence.group, 20)) actors.add(a);
  for (const a of strings(evidence.actor, 20)) actors.add(a);
  for (const a of strings(evidence.actors, 20)) actors.add(a);
  const blob = JSON.stringify(evidence).slice(0, 20000);
  for (const t of blob.match(ATTACK_RE) ?? []) techniques.add(t);
  for (const a of strings(evidence.mitre_techniques, 20)) techniques.add(a);

  for (const c of cves) {
    for (const label of c.products) {
      const [vendor, ...rest] = label.split(' ');
      if (vendor && rest.length > 0) {
        vendors.add(vendor);
        products.add(rest.join(' '));
      } else if (label) products.add(label);
    }
  }

  const clean = (s: Set<string>) =>
    [...s]
      .map((x) => x.trim())
      .filter((x) => x.length > 1 && x.length < 80)
      .slice(0, 15);
  return { vendors: clean(vendors), products: clean(products), actors: clean(actors), techniques: clean(techniques) };
}

function buildTimeline(cves: CveFacts[], pages: ExtractedPage[]): ResearchDossier['timeline'] {
  const events: Array<{ date: string; event: string }> = [];
  const push = (date: string | undefined, event: string) => {
    if (date && /^\d{4}-\d{2}/.test(date)) events.push({ date: date.slice(0, 10), event });
  };
  for (const c of cves) {
    push(c.published, `${c.id} published with a ${c.cvss?.severity ?? 'scored'} ${c.cvss?.base_score ?? '?'} rating`);
    if (c.kev?.in_kev) {
      push(c.kev.date_added, `CISA added ${c.id} to the Known Exploited Vulnerabilities catalog`);
      push(c.kev.due_date, `Federal remediation deadline for ${c.id} under BOD 22-01`);
      if (c.kev.known_ransomware) push(c.kev.date_added, `${c.id} is flagged as used in a known ransomware campaign`);
    }
    if (c.pocCount && c.pocCount > 0)
      push(c.lastModified, `${c.pocCount} public exploit/PoC reference(s) recorded for ${c.id}`);
  }
  for (const p of pages) {
    if (p.ok && p.publishedAt) push(p.publishedAt, `${p.publisher} published "${p.title.slice(0, 120)}"`);
  }
  const seen = new Set<string>();
  return events
    .sort((a, b) => b.date.localeCompare(a.date))
    .filter((e) => {
      const k = `${e.date}|${e.event}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .slice(0, 12);
}

function buildGaps(
  type: CaseStudyType,
  cves: CveFacts[],
  pages: ExtractedPage[],
  platform: PlatformFacts,
  unread: Array<{ url: string; reason: string }>
): string[] {
  const gaps: string[] = [];
  if (pages.length === 0) {
    const reason =
      unread.length > 0
        ? `None of the ${unread.length} cited source pages could be read (${unread
            .slice(0, 3)
            .map((u) => `${u.url} — ${u.reason}`)
            .join('; ')}).`
        : 'No source URL was available to read.';
    gaps.push(`${reason} Write only what the candidate evidence states, and never assert details it does not contain.`);
  }
  if (cves.length > 0 && cves.every((c) => !c.kev?.in_kev)) {
    gaps.push(
      'None of these CVEs is in the CISA KEV catalog: there is no confirmed in-the-wild exploitation and no federal deadline to cite.'
    );
  }
  const noVector = cves.filter((c) => !c.cvss?.vector);
  if (noVector.length)
    gaps.push(
      `${noVector.map((c) => c.id).join(', ')} ${noVector.length === 1 ? 'has' : 'have'} no published CVSS vector. Do not reconstruct one.`
    );
  const noPoc = cves.filter((c) => !c.pocCount);
  if (noPoc.length)
    gaps.push(
      `No public exploit or proof-of-concept was found for ${noPoc.map((c) => c.id).join(', ')}. Do not assert weaponisation.`
    );
  if (platform.actors.length === 0)
    gaps.push('No tracked actor is associated with this topic. Leave attribution open rather than guessing a group.');
  if (platform.darkweb.length === 0) gaps.push('Nothing in the darkweb monitor references this topic.');
  if (type === 'vulnfaq' || type === 'cve' || type === 'exploit') {
    gaps.push(
      'Exploit mechanics, root cause, and the vulnerable code path are not established. Describe them only as far as the sources support, and say plainly where a source is general.'
    );
  }
  return gaps.slice(0, 8);
}

/** Pure assembly. No I/O. */
export function buildDossier(input: BuildDossierInput): ResearchDossier {
  const { type, title, rationale, evidence, cves, pages, platform, unread } = input;
  const subject =
    rationale && rationale.trim() && rationale !== title
      ? `${scrubString(title)} — ${scrubString(rationale)}`
      : scrubString(title);

  return {
    subject,
    cves,
    pages,
    platform,
    timeline: buildTimeline(cves, pages),
    indicators: mineIndicators(evidence),
    entities: mineEntities(evidence, cves),
    gaps: buildGaps(type, cves, pages, platform, unread),
    unread,
    meta: {
      pagesFetched: pages.length + unread.length,
      pagesRead: pages.filter((p) => p.ok).length,
      cvesEnriched: cves.length,
      tookMs: 0,
    },
  };
}
