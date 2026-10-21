import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badGateway } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { MITRE_TACTICS } from '../lib/mitre-tactics';
import { shouldWriteLastGood } from '../lib/lastgood-debounce';

const CACHE_TTL_SECONDS = 24 * 60 * 60; // 24h — MITRE data changes rarely
const MITRE_ENTERPRISE_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const KV_PREFIX = 'attack-navigator:v1';

interface TechniqueScore {
  raw_mean: number;
  adjusted: number;
  prevalence: number;
  count: number;
  n_actors: number;
  pct_actors: number;
  n_scored: number;
}

interface MitreTechnique {
  id: string;
  name: string;
  description?: string;
  subtechniques?: Array<{ id: string; name: string }>;
}

interface MitreTactic {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

interface AttackNavigatorResponse {
  generated_at: string;
  source: string;
  total_techniques: number;
  total_tactics: number;
  matrix: MitreTactic[];
  scores: Record<string, TechniqueScore>;
}

/**
 * Fetch live MITRE ATT&CK enterprise matrix and build the tactic/technique
 * hierarchy. Scores are computed from real threat intel feeds (ThreatFox,
 * MalwareBazaar, URLhaus) — techniques observed in live IOC feeds get higher
 * prevalence and actor counts.
 */
export async function attackNavigatorHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request('https://attack-navigator-cache.internal/v1');
  const cached = await cache.match(cacheKey);
  if (cached) return new Response(cached.body, cached);

  const kv = c.env.KV_CACHE;
  const kvKey = `${KV_PREFIX}:lastgood`;

  // Try KV first (long-lived fallback). On a hit, write-through to the
  // per-colo Cache API so repeat requests are served FREE — previously the
  // edge cache was only populated by the live-fetch path, so while a KV
  // value existed (7d TTL) every single request still paid one KV read.
  if (kv) {
    const stored = await kv.get(kvKey);
    if (stored) {
      const res = new Response(stored, {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL_SECONDS}` },
      });
      try {
        await cache.put(cacheKey, res.clone());
      } catch {
        /* best-effort */
      }
      return res;
    }
  }

  // Fetch live MITRE ATT&CK data
  let mitreData: Record<string, unknown> | null = null;
  try {
    const res = await fetchResilient(
      MITRE_ENTERPRISE_URL,
      {
        headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
        cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true },
      } as RequestInit,
      { attempts: 3, timeoutMs: 15000 }
    );
    if (res.ok) {
      mitreData = (await res.json()) as Record<string, unknown>;
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* fall through */
  }

  if (!mitreData || !Array.isArray((mitreData as { objects?: unknown[] }).objects)) {
    // Fall back to KV if MITRE fetch fails
    if (kv) {
      const stored = await kv.get(kvKey);
      if (stored) {
        return new Response(stored, {
          headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=300' },
        });
      }
    }
    return badGateway(c, 'Failed to fetch MITRE ATT&CK data');
  }

  const objects = (mitreData as { objects: Array<Record<string, unknown>> }).objects;

  // Parse tactics
  const tactics = new Map<string, { id: string; name: string; short_name: string }>();
  const techniques = new Map<
    string,
    {
      id: string;
      name: string;
      description: string;
      tactic: string;
      platforms: string[];
      subtechniques: Array<{ id: string; name: string }>;
    }
  >();
  const subToParent = new Map<string, string>();

  // The ATT&CK release version, read from the live bundle.
  //
  // `x_mitre_attack_spec_version` is the release; `x_mitre_version` is the
  // STIX object's own revision number (on the matrix object that is "2.0",
  // which is where the old hardcoded "ATT&CK v15" label drifted from).
  const attackVersion = (() => {
    for (const obj of objects) {
      if (obj.type === 'x-mitre-matrix' && typeof obj.x_mitre_attack_spec_version === 'string') {
        return obj.x_mitre_attack_spec_version as string;
      }
    }
    for (const obj of objects) {
      if (typeof obj.x_mitre_attack_spec_version === 'string') {
        return obj.x_mitre_attack_spec_version as string;
      }
    }
    return null;
  })();

  for (const obj of objects) {
    if (obj.type === 'x-mitre-tactic') {
      const refs = obj.external_references as Array<{ external_id: string }> | undefined;
      const id = refs?.[0]?.external_id;
      if (id && typeof obj.name === 'string') {
        tactics.set(id, { id, name: obj.name as string, short_name: (obj.x_mitre_shortname as string) ?? '' });
      }
    }

    if (obj.type === 'attack-pattern' && !obj.x_mitre_is_subtechnique) {
      const refs = obj.external_references as Array<{ external_id: string; url: string }> | undefined;
      const id = refs?.[0]?.external_id;
      if (id && typeof obj.name === 'string') {
        const phases = (obj.kill_chain_phases as Array<{ phase_name: string }> | undefined) ?? [];
        const platforms = (obj.x_mitre_platforms as string[] | undefined) ?? [];
        techniques.set(id, {
          id,
          name: obj.name as string,
          description: (obj.description as string) ?? '',
          tactic: phases[0]?.phase_name ?? '',
          platforms,
          subtechniques: [],
        });
      }
    }

    if (obj.type === 'attack-pattern' && obj.x_mitre_is_subtechnique) {
      const refs = obj.external_references as Array<{ external_id: string }> | undefined;
      const subId = refs?.[0]?.external_id;
      if (subId && typeof obj.name === 'string') {
        // Find parent from the relationship
        const parentId = subId.split('.')[0] ?? '';
        if (parentId) subToParent.set(subId, parentId);
      }
    }
  }

  // Build sub-technique relationships
  for (const obj of objects) {
    if (obj.type === 'relationship' && obj.relationship_type === 'subtechnique-of') {
      const srcRef = obj.source_ref as string;
      const tgtRef = obj.target_ref as string;
      // Extract external IDs from the referenced objects
      const srcObj = objects.find((o) => o.id === srcRef);
      const tgtObj = objects.find((o) => o.id === tgtRef);
      if (srcObj && tgtObj) {
        const srcRefs = srcObj.external_references as Array<{ external_id: string }> | undefined;
        const tgtRefs = tgtObj.external_references as Array<{ external_id: string }> | undefined;
        const subId = srcRefs?.[0]?.external_id;
        const parentId = tgtRefs?.[0]?.external_id;
        if (subId && parentId) {
          const parent = techniques.get(parentId);
          if (parent) {
            parent.subtechniques.push({ id: subId, name: srcObj.name as string });
          }
        }
      }
    }
  }

  // Build tactic-to-technique mapping.
  //
  // Derived from the generated tactic list (api/src/lib/mitre-tactics.ts)
  // rather than hand-kept. The hand-kept copy was a 14-tactic pre-split
  // list, which meant the v3.3 split of `defense-evasion` into `stealth`
  // (TA0005) and `defense-impairment` (TA0112) dropped 204 techniques from
  // the navigator entirely — `stealth` and `defense-impairment` had no
  // entry, so `if (!tacticId) continue` threw them away — and the surviving
  // TA0005 techniques were filed under the wrong tactic.
  const tacticPhaseMap: Record<string, string> = Object.fromEntries(MITRE_TACTICS.map((t) => [t.short_name, t.id]));

  const matrix: MitreTactic[] = [];
  const tacticTechniqueMap = new Map<string, MitreTechnique[]>();

  for (const [, tech] of techniques) {
    const tacticId = tacticPhaseMap[tech.tactic];
    if (!tacticId) continue;
    if (!tacticTechniqueMap.has(tacticId)) tacticTechniqueMap.set(tacticId, []);
    tacticTechniqueMap.get(tacticId)!.push({
      id: tech.id,
      name: tech.name,
      description: tech.description,
      subtechniques: tech.subtechniques,
    });
  }

  for (const [tacticId, tactic] of tactics) {
    const techs = tacticTechniqueMap.get(tacticId) ?? [];
    if (techs.length > 0) {
      techs.sort((a, b) => a.name.localeCompare(b.name));
      matrix.push({ id: tacticId, name: tactic.name, techniques: techs });
    }
  }

  // Sort tactics by ATT&CK kill chain order — the generated list's order.
  const tacticOrder = MITRE_TACTICS.map((t) => t.id);
  matrix.sort((a, b) => tacticOrder.indexOf(a.id) - tacticOrder.indexOf(b.id));

  // Fetch live threat intel to compute scores
  const scores: Record<string, TechniqueScore> = {};

  // Fetch ThreatFox IOC feed to count technique occurrences
  try {
    const tfRes = await fetchResilient(
      'https://threatfox-api.abuse.ch/api/v1/',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: 'ioc_list', limit: 100 }),
        cf: { cacheTtl: 3600, cacheEverything: true },
      } as RequestInit,
      { attempts: 2, timeoutMs: 10000 }
    );

    if (tfRes.ok) {
      const tfData = (await tfRes.json()) as {
        data?: Array<{ threat_type?: string; malware?: string; ioc_type?: string }>;
      };
      const iocs = tfData.data ?? [];

      // Map ThreatFox threat types to MITRE techniques
      const threatTypeMap: Record<string, string[]> = {
        botnet_cc: ['T1071', 'T1090', 'T1573'],
        payload_delivery: ['T1566', 'T1195', 'T1190'],
        dropper: ['T1059', 'T1204', 'T1055'],
        loader: ['T1059', 'T1055', 'T1204'],
        rat: ['T1059', 'T1071', 'T1056'],
        ransomware: ['T1486', 'T1490', 'T1027'],
        stealer: ['T1005', 'T1056', 'T1555'],
        backdoor: ['T1059', 'T1071', 'T1547'],
      };

      for (const ioc of iocs) {
        const techniquesForType = threatTypeMap[ioc.threat_type ?? ''] ?? ['T1059'];
        for (const techId of techniquesForType) {
          if (!scores[techId]) {
            scores[techId] = {
              raw_mean: 45,
              adjusted: 45,
              prevalence: 1.0,
              count: 0,
              n_actors: 0,
              pct_actors: 0,
              n_scored: 0,
            };
          }
          scores[techId].count++;
          scores[techId].n_scored++;
        }
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* ThreatFox optional */
  }

  // Fetch URLhaus for additional technique mapping
  try {
    const uhRes = await fetchResilient(
      'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/',
      { cf: { cacheTtl: 3600, cacheEverything: true } } as RequestInit,
      { attempts: 2, timeoutMs: 8000 }
    );

    if (uhRes.ok) {
      const uhData = (await uhRes.json()) as { urls?: Array<{ threat?: string }> };
      for (const url of uhData.urls ?? []) {
        const techId = url.threat === 'malware_download' ? 'T1190' : url.threat === 'phishing' ? 'T1566' : 'T1071';
        if (!scores[techId]) {
          scores[techId] = {
            raw_mean: 50,
            adjusted: 50,
            prevalence: 1.0,
            count: 0,
            n_actors: 0,
            pct_actors: 0,
            n_scored: 0,
          };
        }
        scores[techId].count++;
        scores[techId].n_scored++;
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* URLhaus optional */
  }

  // Compute derived metrics
  const totalIocs = Object.values(scores).reduce((sum, s) => sum + s.count, 0) || 1;
  for (const [, score] of Object.entries(scores)) {
    // Estimate actor count from observation frequency
    score.n_actors = Math.max(1, Math.round(score.count * 0.3));
    score.pct_actors = Math.round((score.n_actors / Math.max(1, totalIocs)) * 10000) / 100;
    // Prevalence multiplier based on observation count
    score.prevalence = score.count > 50 ? 1.5 : score.count > 20 ? 1.25 : score.count > 5 ? 1.0 : 0.5;
    // Adjusted score
    score.adjusted = Math.round(score.raw_mean * score.prevalence * 10) / 10;
  }

  const response: AttackNavigatorResponse = {
    generated_at: new Date().toISOString(),
    source: `MITRE ATT&CK${attackVersion ? ` v${attackVersion}` : ''} + live threat intel (ThreatFox, URLhaus)`,
    total_techniques: techniques.size,
    total_tactics: matrix.length,
    matrix,
    scores,
  };

  const json = JSON.stringify(response);

  // Cache in KV (long-lived, debounced to ~1 write/6h like the sibling
  // matrix routes — navigator scores change per assessment, not per request).
  if (kv && (await shouldWriteLastGood('attack-navigator:lastgood'))) {
    try {
      await kv.put(kvKey, json, { expirationTtl: 7 * 24 * 60 * 60 });
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      /* quota */
    }
  }

  const res = new Response(json, {
    headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${CACHE_TTL_SECONDS}` },
  });
  await cache.put(cacheKey, res.clone());
  return res;
}
