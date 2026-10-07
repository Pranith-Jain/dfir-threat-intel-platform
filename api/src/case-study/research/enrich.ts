/**
 * Fact enrichment for the research stage.
 *
 * Two jobs:
 *
 *  1. Turn a bare CVE id into the concrete numbers a vulnerability write-up
 *     is made of — CVSS vector, CWE, affected and fixed versions, KEV dates,
 *     EPSS, whether a public PoC exists, SSVC exploitation verdict. All of
 *     this already exists behind `lookupCve`, so reuse it rather than
 *     re-querying NVD.
 *
 *  2. Pull the platform's OWN aggregated intel for a topic — writeups,
 *     actor claims, darkweb monitor hits, trending CVEs — so the writer
 *     works from the same corpus the rest of the site is built on instead of
 *     the public web alone.
 *
 * Everything degrades to `null` / `[]` on failure. A research pass that
 * enriches nothing is still useful: the extracted source text alone is a big
 * improvement on writing from a title.
 */

import { lookupCve, type CveLookupResult } from '../../lib/cve-lookup';
import { selfFetchJson } from '../../lib/self-fetch';

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
/** Bounded so one post can never blow the subrequest budget. */
const MAX_CVES = 4;

/** Distinct CVE ids mentioned anywhere in the candidate's evidence + title. */
export function findCveIds(type: unknown, title: string, evidence: Record<string, unknown>): string[] {
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(v.trim())) out.push(v.trim().toUpperCase());
  };
  push(evidence.cveId);
  push(evidence.cve_id);
  push(evidence.cve);
  if (Array.isArray(evidence.cveIds)) evidence.cveIds.forEach(push);
  if (Array.isArray(evidence.cves)) evidence.cves.forEach(push);

  // Briefings nest CVEs inside section findings.
  if (Array.isArray(evidence.sections)) {
    for (const s of evidence.sections) {
      const findings = (s as Record<string, unknown> | null)?.findings;
      if (!Array.isArray(findings)) continue;
      for (const f of findings) {
        const id = (f as Record<string, unknown> | null)?.id;
        if (typeof id === 'string' && /^CVE-\d{4}-\d{4,7}$/i.test(id)) out.push(id.toUpperCase());
      }
    }
  }

  const blob = `${title}\n${JSON.stringify(evidence).slice(0, 8000)}`;
  for (const m of blob.match(CVE_RE) ?? []) out.push(m.toUpperCase());

  return [...new Set(out)].slice(0, MAX_CVES);
}

// ── CPE → affected/fixed version ranges ──────────────────────────────────

/**
 * A single "product is affected from X up to but not including Y" row —
 * exactly the shape of the affected-versions table in a good vulnerability
 * FAQ. `fixed` is null when the record only gives a lower bound, which is
 * itself worth knowing (it usually means "all current releases").
 */
export interface VersionRange {
  vendor: string;
  product: string;
  /** The version in the CPE, or '*' when the record names no specific one. */
  version: string;
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

/**
 * Parse CPE 2.3 criteria + its version-range siblings out of an NVD
 * `cpeMatch` entry.
 *
 * `cpe:2.3:a:citrix:netscaler_gateway:14.1:*:*:*:*:*:*:*` splits as
 * [cpe, 2.3, part, vendor, product, version, ...]. Range bounds live on the
 * match object rather than in the criteria string.
 */
export function parseVersionRange(
  criteria: string,
  bounds: {
    versionStartIncluding?: string;
    versionStartExcluding?: string;
    versionEndIncluding?: string;
    versionEndExcluding?: string;
  } = {}
): VersionRange | null {
  const parts = criteria.split(':');
  if (parts.length < 6 || parts[0] !== 'cpe') return null;
  const vendor = (parts[3] ?? '').replace(/_/g, ' ');
  const product = (parts[4] ?? '').replace(/_/g, ' ');
  if (!vendor && !product) return null;
  return {
    vendor,
    product,
    version: parts[5] === '*' ? '' : (parts[5] ?? ''),
    startIncluding: bounds.versionStartIncluding,
    startExcluding: bounds.versionStartExcluding,
    endIncluding: bounds.versionEndIncluding,
    endExcluding: bounds.versionEndExcluding,
  };
}

/**
 * Flatten `lookupCve`'s `affected_products` (a list of CPE criteria strings)
 * into vendor/product pairs. We lose the range bounds this way, but the
 * affected-version detail comes from the extracted advisory text, which
 * states it in prose ("before 14.1-73.41"). Guessing bounds from a wildcard
 * CPE would be worse than not claiming them.
 */
export function productLabels(cpeCriteria: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const c of cpeCriteria) {
    const m = /^cpe:2\.3:[aoh]:([^:]+):([^:]+):/.exec(c);
    if (!m) continue;
    const vendor = (m[1] ?? '').replace(/_/g, ' ').trim();
    const product = (m[2] ?? '').replace(/_/g, ' ').trim();
    if (!vendor && !product) continue;
    const label = vendor && product ? `${vendor} ${product}` : vendor || product;
    const key = label.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(label);
  }
  return out.slice(0, 8);
}

// ── Per-CVE enrichment ───────────────────────────────────────────────────

/** Flattened, prompt-ready view of one CVE. */
export interface CveFacts {
  id: string;
  description: string;
  published?: string;
  lastModified?: string;
  cvss?: { version: string; base_score: number; severity: string; vector: string };
  cwe: string[];
  products: string[];
  kev?: {
    in_kev: boolean;
    date_added?: string;
    vulnerability_name?: string;
    required_action?: string;
    due_date?: string;
    known_ransomware?: boolean;
  };
  epss?: { score: number; percentile: number };
  pocCount?: number;
  ssvc?: Record<string, string | undefined>;
  references: string[];
}

function toCveFacts(id: string, r: CveLookupResult): CveFacts {
  return {
    id: r.cve_id ?? id,
    description: (r.description ?? '').trim(),
    published: r.published,
    lastModified: r.last_modified,
    // Spelled out rather than spread so the version widens from the literal
    // union ('3.1' | '3.0' | '2.0') to plain string.
    cvss: r.cvss
      ? {
          version: r.cvss.version,
          base_score: r.cvss.base_score,
          severity: r.cvss.severity,
          vector: r.cvss.vector,
        }
      : undefined,
    cwe: r.cwe ?? [],
    products: productLabels(r.affected_products ?? r.products ?? []),
    kev: r.kev,
    epss: r.epss ? { score: r.epss.score, percentile: r.epss.percentile } : undefined,
    pocCount: r.poc?.count,
    ssvc: r.ssvc,
    references: (r.references ?? [])
      .map((x) => x.url)
      .filter(Boolean)
      .slice(0, 12),
  };
}

/** Look up every CVE in the candidate. Failures are dropped silently. */
export async function enrichCves(cveIds: string[]): Promise<CveFacts[]> {
  if (cveIds.length === 0) return [];
  const results = await Promise.all(
    cveIds.map(async (id) => {
      try {
        const res = await lookupCve(id);
        return res.ok ? toCveFacts(id, res.data) : null;
      } catch {
        return null;
      }
    })
  );
  return results.filter((x): x is CveFacts => x !== null);
}

// ── Platform-wide enrichment (the platform's own corpus) ─────────────────

export interface PlatformFacts {
  /** Public research writeups published on the platform about this topic. */
  writeups: Array<{ title: string; url?: string; summary?: string }>;
  /** Related CVEs the platform already tracks, with a score. */
  relatedCves: Array<{ id: string; score?: number | null; severity?: string }>;
  /** CVEs currently trending on social (cvemon / intruder.io). */
  trendingCves: Array<{ id: string; rank: number; hypeScore: number }>;
  /** Tracked actors or campaigns matching the topic. */
  actors: Array<{ name: string; slug?: string; mitre?: string | null }>;
  /** Darkweb monitor hits mentioning the topic. */
  darkweb: Array<{ source?: string; title?: string; url?: string; date?: string }>;
}

/** Minimal shape of the SELF service binding — matches `self-fetch.ts`. */
type SelfFetcher = {
  fetch: (req: RequestInfo, init?: RequestInit) => Promise<Response>;
};

type Fetcher = SelfFetcher | undefined;

function asArray(v: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(v)) return v.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object');
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    for (const k of ['items', 'results', 'data', 'posts', 'cves', 'writeups', 'hits', 'claims']) {
      if (Array.isArray(o[k])) return asArray(o[k]);
    }
  }
  return [];
}

/**
 * Ask the platform's own API surfaces for material on this topic.
 *
 * Every call is independent and optional; a 404 or an unbound SELF binding
 * simply contributes nothing. The keyword is the candidate title slugified
 * down to the distinctive part, so a "vendor product zero-day FAQ" title
 * `netscaler`.
 */
export async function enrichFromPlatform(
  self: Fetcher,
  env: { INTERNAL_TOKEN_SECRET?: string },
  keyword: string
): Promise<PlatformFacts> {
  const empty: PlatformFacts = { writeups: [], relatedCves: [], trendingCves: [], actors: [], darkweb: [] };
  if (!self || !env.INTERNAL_TOKEN_SECRET || !keyword) return empty;
  const fetcher: SelfFetcher = self;

  const q = encodeURIComponent(keyword);
  const paths = [
    `/api/v1/writeups?limit=5&q=${q}`,
    `/api/v1/cve-recent?limit=60`,
    `/api/v1/cve-trends?limit=10`,
    `/api/v1/actors?limit=5&q=${q}`,
    `/api/v1/darkweb-monitor?limit=5&q=${q}`,
  ];

  const settled = await Promise.all(paths.map((p) => selfFetchJson<unknown>(fetcher, p, env)));
  const byPath = new Map(paths.map((p, i) => [p, settled[i]]));

  // Writeups: already keyword-filtered upstream.
  empty.writeups = asArray(byPath.get(paths[0] ?? ''))
    .slice(0, 5)
    .map((w) => ({
      title: String(w.title ?? '').slice(0, 200),
      url:
        typeof w.url === 'string' ? w.url : typeof w.slug === 'string' ? `/threatintel/writeups/${w.slug}` : undefined,
      summary: typeof w.summary === 'string' ? w.summary.slice(0, 300) : undefined,
    }))
    .filter((w) => w.title);

  // Trending CVEs: the freshest hype signal available, used as a "this is
  // what people are actually reading about" cross-check.
  empty.trendingCves = asArray(byPath.get(paths[2] ?? ''))
    .slice(0, 10)
    .map((c) => ({
      id: String(c.id ?? c.cve_id ?? ''),
      rank: Number(c.rank ?? 0),
      hypeScore: Number(c.hype_score ?? c.hypeScore ?? 0),
    }))
    .filter((c) => /^CVE-\d{4}-\d{4,7}$/.test(c.id))
    .sort((a, b) => b.hypeScore - a.hypeScore);

  // cve-recent is a full recent dump — take the highest-severity slice as
  // "what else is live right now", which gives the writer a sense of scale.
  empty.relatedCves = asArray(byPath.get(paths[1] ?? ''))
    .map((c) => ({
      id: String(c.id ?? c.cve_id ?? ''),
      score: typeof c.score === 'number' ? c.score : null,
      severity: typeof c.severity === 'string' ? c.severity : undefined,
    }))
    .filter((c) => /^CVE-\d{4}-\d{4,7}$/.test(c.id))
    .slice(0, 8);

  empty.actors = asArray(byPath.get(paths[3] ?? ''))
    .slice(0, 5)
    .map((a) => ({
      name: String(a.name ?? a.actor ?? ''),
      slug: typeof a.slug === 'string' ? a.slug : undefined,
      mitre: typeof a.mitre_id === 'string' ? a.mitre_id : null,
    }))
    .filter((a) => a.name);

  empty.darkweb = asArray(byPath.get(paths[4] ?? ''))
    .slice(0, 5)
    .map((d) => ({
      source: typeof d.source === 'string' ? d.source : typeof d.source_name === 'string' ? d.source_name : undefined,
      title:
        typeof d.title === 'string'
          ? d.title.slice(0, 200)
          : typeof d.name === 'string'
            ? d.name.slice(0, 200)
            : undefined,
      url: typeof d.url === 'string' ? d.url : undefined,
      date: typeof d.date === 'string' ? d.date : typeof d.detected_at === 'string' ? d.detected_at : undefined,
    }))
    .filter((d) => d.title || d.source);

  return empty;
}

/**
 * Reduce a candidate title to the distinctive token worth querying on:
 * drop CVE ids and generic security words, keep the vendor / product / actor.
 *
 * Deliberately returns only a generic noun or two. A title of
 * "Citrix NetScaler zero-day FAQ" should query as `citrix netscaler`, not as
 * the full sentence — the platform's own endpoints do keyword matching, and a
 * long query string matches nothing.
 */
export function topicKeyword(title: string): string {
  const cleaned = title
    .toLowerCase()
    .replace(/cve-\d{4}-\d{4,7}/g, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(
      /\b(zero|day|days|vulnerability|vulnerabilities|vuln|critical|high|severe|exploit|exploited|exploitation|attack|attacker|threat|malware|ransomware|breach|patched|patch|update|updated|advisory|alert|report|analysis|breaking|latest|new|disclosure|faq|guide|explained|everything|you|need|know|about|guide|why|what|when|how|does|is|are|the|a|an|and|or|of|for|to|in|on|with|from|at|by)\b/g,
      ' '
    )
    .replace(/\s+/g, ' ')
    .trim();
  const words = cleaned.split(' ').filter((w) => w.length >= 3);
  return words.slice(0, 3).join(' ');
}
