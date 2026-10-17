import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { githubHeaders } from '../lib/github-api';
import { badRequest } from '../lib/api-error';
import { cachedJson } from '../lib/route-cache';

import { safeNullLog } from '../lib/safe-catch';
import { findActorsInText } from '../lib/cve-heuristic-mapping';
import { ACTOR_ALIASES } from '../data/threat-actor-aliases';
import { mitreGroupRef } from '../lib/ransomware-mitre-groups';

const MALPEDIA_BASE = 'https://malpedia.caad.fkie.fraunhofer.de';

interface MaltrailMatch {
  filename: string;
  displayName: string;
  size: number;
}

interface MalpediaMatch {
  type: 'family' | 'actor';
  name: string;
  commonName?: string;
  description?: string;
  url?: string;
}

interface OtxPulse {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  created?: string;
  author?: string;
  reference_count?: number;
  ioc_count?: number;
}

interface EnrichmentResult {
  malpedia: MalpediaMatch[];
  maltrail: MaltrailMatch[];
  otx: OtxPulse[];
  /** CVE IDs publicly attributed to this actor — curated, narrow scope. */
  linked_cves: string[];
}

function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function tokenMatch(query: string, target: string): boolean {
  const qTokens = normalize(query).split(/\s+/).filter(Boolean);
  const tNorm = normalize(target);
  const tTokens = tNorm.split(/\s+/).filter(Boolean);
  return qTokens.length > 0 && qTokens.some((qt) => tTokens.some((tt) => tt.includes(qt) || qt.includes(tt)));
}

function fuzzyMatch(terms: string[], target: string): boolean {
  return terms.some((t) => tokenMatch(t, target));
}

function parseActorFromFilename(name: string): string {
  const base = name.replace(/\.txt$/i, '');
  const parts = base.split(/[_\s]+/);
  return parts
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase())
    .join(' ')
    .trim();
}

export async function actorEnrichHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const name = c.req.query('name');
  if (!name || !name.trim()) {
    return badRequest(c, 'missing query param name');
  }

  const aliasesRaw = c.req.query('aliases') ?? '';
  const softwareRaw = c.req.query('software') ?? '';
  const cacheKey = `actor-enrich:${name.trim().toLowerCase()}:${aliasesRaw}:${softwareRaw}`;

  return cachedJson(c, cacheKey, 3600, async () => {
    const queryTerms = [
      name.trim(),
      ...aliasesRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      ...softwareRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ];

    // Extract CVE IDs from OTX pulse tags/descriptions and Malpedia descriptions
    const slugify = (s: string) =>
      s
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
    const slugCandidates = new Set<string>();
    for (const t of queryTerms) {
      if (!t) continue;
      slugCandidates.add(slugify(t));
      // Hokage uses bare-token slugs too (e.g. "apt28" rather than "apt-28").
      slugCandidates.add(t.trim().toLowerCase().replace(/\s+/g, ''));
    }
    const result: EnrichmentResult = {
      malpedia: [],
      maltrail: [],
      otx: [],
      linked_cves: [],
    };

    try {
      // All three upstreams run in parallel — Malpedia, Maltrail, OTX.
      // Each has its own 15s timeout so a slow upstream doesn't block the others.
      const safeJson = async (url: string): Promise<unknown> => {
        try {
          const r = await fetch(url, {
            headers: { Accept: 'application/json' },
            signal: AbortSignal.timeout(15_000),
          });
          return r.ok ? await r.json() : [];
        } catch (_catchErr) {
          logError('handler failed', _catchErr);
          return [];
        }
      };

      const [malpediaData, maltrailListRes, otxRes] = await Promise.all([
        // Malpedia families + actors (parallel within Malpedia)
        Promise.all([
          safeJson(`${MALPEDIA_BASE}/api/get/families`) as Promise<unknown[]>,
          safeJson(`${MALPEDIA_BASE}/api/get/actors`) as Promise<unknown[]>,
        ]).then(([f, a]) => ({ families: f, actors: a })),
        // Maltrail
        safeNullLog(
          'fetch-maltrail',
          fetch(`https://api.github.com/repos/stamparm/maltrail/contents/trails/static/malware`, {
            headers: githubHeaders(c.env, { accept: 'application/vnd.github.v3+json' }),
            signal: AbortSignal.timeout(15_000),
          })
        ),
        // OTX
        c.env.OTX_API_KEY
          ? safeNullLog(
              'fetch-otx',
              fetch(`https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(name.trim())}`, {
                headers: { 'X-OTX-API-KEY': c.env.OTX_API_KEY },
                signal: AbortSignal.timeout(15_000),
              })
            )
          : Promise.resolve(null),
      ]);

      const { families, actors } = malpediaData;

      if (Array.isArray(families)) {
        for (const f of families) {
          if (typeof f !== 'object' || f === null) continue;
          const rec = f as Record<string, unknown>;
          const familyName = String(rec.family_name ?? rec.common_name ?? '');
          if (fuzzyMatch(queryTerms, familyName)) {
            result.malpedia.push({
              type: 'family',
              name: familyName,
              commonName: String(rec.common_name ?? ''),
              description: String(rec.description ?? ''),
            });
          }
        }
      }

      if (Array.isArray(actors)) {
        for (const a of actors) {
          if (typeof a !== 'object' || a === null) continue;
          const rec = a as Record<string, unknown>;
          const actorName = String(rec.actor_name ?? '');
          if (fuzzyMatch(queryTerms, actorName)) {
            result.malpedia.push({
              type: 'actor',
              name: actorName,
              description: String(rec.description ?? ''),
            });
          }
        }
      }

      // --- Maltrail: match trail files against query terms ---
      if (maltrailListRes?.ok) {
        const files = (await maltrailListRes.json()) as Array<{
          name: string;
          path: string;
          size: number;
          type: string;
        }>;
        const trailFiles = (Array.isArray(files) ? files : []).filter(
          (f) => f.type === 'file' && f.name.endsWith('.txt')
        );

        for (const f of trailFiles) {
          const displayName = parseActorFromFilename(f.name);
          if (fuzzyMatch(queryTerms, displayName) || fuzzyMatch(queryTerms, f.name)) {
            result.maltrail.push({
              filename: f.name,
              displayName,
              size: f.size,
            });
          }
        }
      }

      // --- OTX: search pulses ---
      if (otxRes?.ok) {
        const otxJson = (await otxRes.json()) as {
          results?: Array<{
            id?: string;
            name?: string;
            description?: string;
            tags?: string[];
            created?: string;
            author?: string;
            reference_count?: number;
            ioc_count?: number;
          }>;
          count?: number;
        };

        if (Array.isArray(otxJson.results)) {
          result.otx = otxJson.results.slice(0, 10).map((p) => ({
            id: p.id ?? '',
            name: p.name ?? '',
            description: p.description ?? '',
            tags: p.tags ?? [],
            created: p.created ?? '',
            author: p.author ?? '',
          }));
        }
      }
    } catch (err) {
      logError('actor-enrich error:', err);
    }

    // ── Local alias fallback ────────────────────────────────────────────────
    // If external APIs returned nothing, fall back to the curated alias index.
    // This covers well-known actors (including ransomware groups like Qilin)
    // even when Malpedia/OTX/Maltrail have no match.
    const queryLower = name.trim().toLowerCase();
    const slugCand = slugify(queryLower);
    if (result.malpedia.length === 0 && result.maltrail.length === 0 && result.otx.length === 0) {
      const localMatch = ACTOR_ALIASES.find(
        (a) =>
          a.slug === slugCand ||
          a.canonical.toLowerCase() === queryLower ||
          a.aliases.some((al) => al.toLowerCase() === queryLower)
      );
      if (localMatch) {
        const mitre = localMatch.mitreId ? (mitreGroupRef(localMatch.mitreId) ?? mitreGroupRef(localMatch.slug)) : null;
        const parts: string[] = [`Canonical: ${localMatch.canonical}`];
        if (localMatch.aliases.length > 0) parts.push(`Aliases: ${localMatch.aliases.join(', ')}`);
        if (mitre) {
          parts.push(`MITRE ID: ${mitre.id}`);
          parts.push(`MITRE Name: ${mitre.name}`);
          parts.push(`MITRE URL: ${mitre.url}`);
        } else if (localMatch.mitreId) {
          parts.push(`MITRE ID: ${localMatch.mitreId}`);
        }
        result.malpedia.push({
          type: 'actor',
          name: localMatch.canonical,
          description: parts.join('; '),
        });
      }
    }

    // Extract CVE IDs from OTX pulse tags/descriptions and Malpedia descriptions
    const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
    const cveSet = new Set<string>();
    for (const pulse of result.otx) {
      for (const tag of pulse.tags ?? []) {
        for (const m of tag.matchAll(CVE_RE)) cveSet.add(m[0].toUpperCase());
      }
      for (const m of (pulse.description ?? '').matchAll(CVE_RE)) cveSet.add(m[0].toUpperCase());
    }
    for (const m of result.malpedia) {
      for (const m2 of (m.description ?? '').matchAll(CVE_RE)) cveSet.add(m2[0].toUpperCase());
    }
    // Heuristic scan: find CVE mentions in OTX pulse names + descriptions
    for (const pulse of result.otx) {
      const text = [pulse.name, pulse.description].filter(Boolean).join(' ');
      if (!text) continue;
      const actors = findActorsInText(text);
      if (actors.length > 0) {
        // If this pulse mentions the queried actor, extract any CVE IDs
        for (const m of text.matchAll(CVE_RE)) cveSet.add(m[0].toUpperCase());
      }
    }
    result.linked_cves = [...cveSet].sort((a, b) => b.localeCompare(a));

    return { ok: true, ...result };
  });
}
