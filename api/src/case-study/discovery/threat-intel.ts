/**
 * Threat-intel corpus discovery runners.
 *
 * The platform already replicates several high-signal CTI corpora into
 * `public/data/threat-intel/` every day. Those surfaces were only reachable
 * from the UI and MCP server; discovery never read them, so a quiet RSS day
 * produced a CVE-only queue. These runners turn the same data into content
 * candidates:
 *
 *   - ThreatCluster story clusters  → /api/v1/threat-intel/threatcluster/clusters
 *   - Living Threat incident index  → /api/v1/threat-intel/living-threat/incidents
 *   - Incident Desk briefs          → /api/v1/threat-intel/incident-desk
 *
 * Each one reads the EXACT response shape its route returns (verified against
 * `threat-intel-edge-tools.ts` and `worker/lib/threat-intel-manifest.ts`).
 * A transport or shape failure throws so the orchestrator records it in
 * `runnerStats`; it must NOT silently return [] and look like a quiet feed,
 * because that is how a whole topic disappears from the daily mix with no
 * error anywhere.
 *
 * All data is fetched through the caller's authenticated `apiFetch` (SELF
 * binding), so no public API key is involved. The source `url` is always the
 * upstream article/cluster link, which gives the writer a real reference and
 * lets the cross-runner URL dedup collapse overlaps with the RSS runners.
 */

import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, severityFromText, noveltyScore, finalScoreWithTrending } from '../scoring';

export interface ThreatIntelDiscoveryDeps {
  apiFetch: (path: string) => Promise<unknown>;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

const DAY_MS = 24 * 3600 * 1000;
/** How far back a story may be and still count as fresh discovery material. */
const STORY_WINDOW_MS = 7 * DAY_MS;

/**
 * Cyber relevance filter for ThreatCluster headlines.
 *
 * The cluster feed deliberately mixes cyber with geopolitical/kinetic news
 * ("Russian Drone Attacks in Kherson", "Ukrainian Strikes ..."). Publishing
 * those as threat-intel case studies would be off-topic, so require an
 * explicit security term. "attack" alone is deliberately NOT enough — it is
 * the word that let kinetic-news clusters through.
 */
const CYBER_RELEVANCE_RE =
  /\b(cyber(?:attack|security|espionage)?|espionage|malware|ransomware|breach|data[ -]leak|vulnerab\w*|zero-?day|0-day|exploit\w*|hacker\w*|phishing|infostealer|stealer|botnet|spyware|trojan|backdoor|rats?|ddos|apt\d*|threat[ -]actor|intrusion|compromise\w*|security[ -](?:flaw|patch|bug)|cve-\d{4}-\d+|credential\w*|supply[ -]chain|deepfake|fraud|scam|cisa|mitre|att&ck)\b|\b(?:storm|unc|fin|tgr|kta|utg)[- ]\d{2,4}\b/i;

function isCyberRelevant(text: string): boolean {
  return CYBER_RELEVANCE_RE.test(text);
}

function withinWindow(iso: string | null | undefined, now: Date): boolean {
  if (!iso) return false;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return false;
  const age = now.getTime() - t;
  // Reject stale rows and rows timestamped absurdly far in the future (a bad
  // upstream clock should not make a story "maximally fresh" forever).
  return age <= STORY_WINDOW_MS && age >= -6 * 3600 * 1000;
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string' && s.trim().length > 0) : [];
}

function numberOrNull(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

// ── ThreatCluster story clusters ───────────────────────────────────────

interface TcClusterRow {
  slug?: string;
  title?: string;
  pubDate?: string | null;
  sourceCount?: number | null;
}

/**
 * Multi-source story clusters. A cluster is already the "what actually
 * moved" rollup — the same event seen by N outlets — so sourceCount is both
 * the impact proxy and the trending signal. Each cluster carries a canonical
 * threatcluster.io permalink, not a raw article URL, which is stable even
 * when the underlying outlets rotate.
 */
export async function discoverThreatClusters(deps: ThreatIntelDiscoveryDeps): Promise<Candidate[]> {
  const data = (await deps.apiFetch('/api/v1/threat-intel/threatcluster/clusters?limit=100')) as {
    clusters?: TcClusterRow[];
  } | null;
  if (!data || typeof data !== 'object' || !Array.isArray(data.clusters)) {
    throw new Error('threat-intel/threatcluster returned no clusters array');
  }
  const rows = data.clusters;

  const candidates: Candidate[] = [];
  for (const row of rows) {
    const title = row.title?.trim();
    const slug = row.slug?.trim();
    if (!title || !slug || !withinWindow(row.pubDate, deps.now)) continue;
    if (!isCyberRelevant(title)) continue;

    const sourceCount = Math.max(1, row.sourceCount ?? 1);
    const url = `https://threatcluster.io/cluster/${encodeURIComponent(slug)}`;
    const key = topicKey('tc-cluster', slug);
    const dedup = await deps.getDedup(key);

    const score = finalScoreWithTrending({
      recency: recencyScore(row.pubDate!, deps.now),
      severity: Math.max(severityFromText(title), severityScore({ mentions: sourceCount })),
      novelty: noveltyScore(dedup, deps.now),
      sourceWeight: 0.9,
      trending: Math.min(1, sourceCount / 5),
    });
    if (score < 0.45) continue;

    candidates.push({
      key,
      type: 'intel',
      title,
      rationale: `${sourceCount} independent source${sourceCount === 1 ? '' : 's'} clustered · published ${row.pubDate} · threatcluster.io`,
      score,
      evidence: {
        url,
        urls: [url],
        titles: [title],
        sourceCount,
        pubDate: row.pubDate,
        clusterSlug: slug,
        source: 'threat-intel/threatcluster',
      },
      discoveredAt: deps.now.toISOString(),
      status: 'pending',
    });
  }
  return candidates;
}

// ── Living Threat incident index ───────────────────────────────────────

interface LivingThreatRow {
  slug?: string;
  title?: string;
  timestamp?: string | null;
  source?: string;
  severity?: string;
  priorityScore?: number | null;
  relevanceScore?: number | null;
  tactics?: string[];
  techniques?: string[];
  actors?: string[];
  techniqueCount?: number;
  cves?: number;
  tools?: number;
}

/**
 * Incident-level analyses with ATT&CK mapping. Unlike the RSS runners, these
 * rows already carry a triage priority (0-100), tactic/technique coverage,
 * actor attribution and a resolved source URL. Requiring priority >= 60 keeps
 * the queue to the incidents the upstream pipeline judged worth attention,
 * and the technique count feeds the trending term so a well-mapped incident
 * outranks a one-liner at the same severity.
 */
export async function discoverLivingThreatIncidents(deps: ThreatIntelDiscoveryDeps): Promise<Candidate[]> {
  const data = (await deps.apiFetch('/api/v1/threat-intel/living-threat/incidents?min_priority=60&limit=100')) as {
    incidents?: LivingThreatRow[];
  } | null;
  if (!data || typeof data !== 'object' || !Array.isArray(data.incidents)) {
    throw new Error('threat-intel/living-threat returned no incidents array');
  }
  const rows = data.incidents;

  const candidates: Candidate[] = [];
  for (const row of rows) {
    const title = row.title?.trim();
    const slug = row.slug?.trim();
    const url = row.source?.trim();
    if (!title || !slug || !url || !/^https?:\/\//.test(url)) continue;
    if (!withinWindow(row.timestamp, deps.now)) continue;

    const priority = numberOrNull(row.priorityScore) ?? 0;
    if (priority < 60) continue;

    const techniques = stringList(row.techniques);
    const tactics = stringList(row.tactics);
    const actors = stringList(row.actors);
    const key = topicKey('living-threat', slug);
    const dedup = await deps.getDedup(key);

    const score = finalScoreWithTrending({
      recency: recencyScore(row.timestamp!, deps.now),
      // The upstream priority already blends severity and exploitation
      // status; the title floor catches a reputable but oddly-scored row.
      severity: Math.max(severityFromText(title), Math.min(1, priority / 100)),
      novelty: noveltyScore(dedup, deps.now),
      sourceWeight: 0.9,
      trending: Math.min(1, (row.techniqueCount ?? techniques.length) / 8),
    });
    if (score < 0.5) continue;

    const mapping = [
      techniques.length ? `${techniques.length} ATT&CK technique${techniques.length === 1 ? '' : 's'}` : '',
      tactics.length ? `${tactics.slice(0, 3).join(', ')}` : '',
      actors.length ? `actor: ${actors.slice(0, 2).join(', ')}` : '',
    ]
      .filter(Boolean)
      .join(' · ');

    candidates.push({
      key,
      type: 'analysis',
      title,
      rationale: `${row.severity ?? 'Unrated'} · priority ${priority}/100${mapping ? ` · ${mapping}` : ''} · ${row.timestamp}`,
      score,
      evidence: {
        url,
        sourceUrl: url,
        sourceTitle: title,
        timestamp: row.timestamp,
        severity: row.severity,
        priorityScore: priority,
        relevanceScore: numberOrNull(row.relevanceScore),
        tactics,
        techniques,
        actors,
        cveCount: numberOrNull(row.cves),
        toolCount: numberOrNull(row.tools),
        incidentSlug: slug,
        source: 'threat-intel/living-threat',
      },
      discoveredAt: deps.now.toISOString(),
      status: 'pending',
    });
  }
  return candidates;
}

// ── Incident Desk briefs ───────────────────────────────────────────────

interface IncidentDeskRow {
  title?: string | null;
  link?: string | null;
  guid?: string | null;
  published?: string | null;
  description?: string | null;
  slug?: string;
}

/**
 * Incident Desk is an identity/security incident feed with full writeups.
 * It is narrower than the RSS runners but gives the queue a regular
 * identity-and-access angle (token theft, SSO compromise, vendor
 * credentials) that the broad feeds rarely lead with.
 */
export async function discoverIncidentDesk(deps: ThreatIntelDiscoveryDeps): Promise<Candidate[]> {
  const data = (await deps.apiFetch('/api/v1/threat-intel/incident-desk?limit=50')) as {
    briefs?: IncidentDeskRow[];
  } | null;
  if (!data || typeof data !== 'object' || !Array.isArray(data.briefs)) {
    throw new Error('threat-intel/incident-desk returned no briefs array');
  }
  const rows = data.briefs;

  const candidates: Candidate[] = [];
  for (const row of rows) {
    const title = row.title?.trim();
    const url = row.link?.trim();
    if (!title || !url || !/^https?:\/\//.test(url) || !withinWindow(row.published, deps.now)) continue;

    const seed = row.slug?.trim() || row.guid?.trim() || url;
    const key = topicKey('incident-desk', seed);
    const dedup = await deps.getDedup(key);
    const description = row.description?.trim() ?? '';

    const score = finalScoreWithTrending({
      recency: recencyScore(row.published!, deps.now),
      severity: severityFromText(`${title} ${description}`),
      novelty: noveltyScore(dedup, deps.now),
      sourceWeight: 0.85,
      // A brief that explains the incident in its own feed description is
      // more useful than a headline-only item at the same recency.
      trending: Math.min(1, description.length / 400),
    });
    if (score < 0.45) continue;

    candidates.push({
      key,
      type: 'analysis',
      title,
      rationale: `Incident Desk brief${description ? ` — ${description.slice(0, 180)}` : ''} · ${row.published}`,
      score,
      evidence: {
        url,
        sourceUrl: url,
        sourceTitle: title,
        published: row.published,
        description: description.slice(0, 800),
        briefSlug: row.slug,
        source: 'threat-intel/incident-desk',
      },
      discoveredAt: deps.now.toISOString(),
      status: 'pending',
    });
  }
  return candidates;
}
