import type { Context } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import type { LiveIoc } from './live-iocs';
import { fetchTelegramFeed } from './telegram-feed';
import { fetchRansomwareRecent } from './ransomware-recent';
import {
  ingestMultipleFeedItems,
  ingestEntitiesNoEnsure,
  extractIOCs,
  sourceConfidence,
  type FeedIngestItem,
  type ExtractedEntity,
  type IngestResult,
} from '../lib/graph-ingest';
import { ensureGraphTables, upsertNode, type NodeType } from './threat-graph';
import { abuseChFeedRequestForEnv } from '../lib/abusech';
import { buildSummary } from '../lib/ioc-feed-parsers';

type SourceName = 'ioc' | 'phishing' | 'telegram' | 'ransomware' | 'all';

/** Upsert nodes for a list of entities WITHOUT creating edges between them. */
async function upsertNodesOnly(
  db: D1Database,
  entities: ExtractedEntity[],
  source: string,
  evidence: { description: string; timestamp: string }
): Promise<IngestResult> {
  const result: IngestResult = { nodes_upserted: 0, edges_created: 0, errors: [] };
  const src = sourceConfidence(source);
  for (const ent of entities) {
    try {
      await upsertNode(db, {
        type: ent.type,
        value: ent.value,
        properties: { label: ent.label, source },
        first_seen: evidence.timestamp,
        confidence: Math.round((ent.confidence * src.reliability) / 100),
        sources: [src.source_name],
      });
      result.nodes_upserted++;
    } catch (e) {
      logError('upsertNodesOnly failed', e);
      result.errors.push(`node(${ent.type}:${ent.value}): ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return result;
}

async function ingestBulkIocs(db: D1Database, items: LiveIoc[], maxItems: number): Promise<IngestResult> {
  const entities: ExtractedEntity[] = [];
  const seen = new Set<string>();

  for (const ioc of items.slice(0, maxItems)) {
    let nodeType: NodeType = 'domain';
    if (ioc.kind === 'ip') nodeType = 'ip';
    else if (ioc.kind === 'domain') nodeType = 'domain';
    else if (ioc.kind === 'hash') nodeType = 'hash';
    else if (ioc.kind === 'url') nodeType = 'url';
    else continue;

    const key = `${nodeType}:${ioc.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    entities.push({ type: nodeType, value: ioc.value, label: ioc.value, confidence: 90 });
  }

  if (!entities.length) return { nodes_upserted: 0, edges_created: 0, errors: [] };
  return upsertNodesOnly(db, entities.slice(0, 18), 'threatfox', {
    description: 'ThreatFox IOC feed',
    timestamp: new Date().toISOString(),
  });
}

// ── Direct IOC source fetchers (bypasses the aggregated live-iocs handler) ──

function parseThreatfoxCsv(csv: string): LiveIoc[] {
  // The authenticated ThreatFox path returns the JSON `get_iocs` shape, the
  // no-key fallback the retired CSV — buildSummary sniffs and normalises both
  // (shared parser = one mapping table to keep in sync, not three).
  return buildSummary('threatfox', csv).entries.map((e) => {
    const type = e.type;
    const kind: 'ip' | 'domain' | 'hash' | 'url' =
      type === 'ipv4' ? 'ip' : type === 'domain' ? 'domain' : type === 'url' ? 'url' : 'hash';
    return {
      value: e.value,
      kind,
      source: 'threatfox' as const,
      context: e.context,
      observed_at: e.timestamp ?? new Date().toISOString(),
    };
  });
}

async function ingestLiveIocs(db: D1Database, env?: Env): Promise<IngestResult> {
  try {
    // The anonymous ThreatFox CSV export upstream retired on 2026-10-21
    // (HTTP 410) — fetch through the shared authenticated helper instead.
    const req = abuseChFeedRequestForEnv(env, 'threatfox', { days: 7 });
    const res = await fetch(req.url, {
      ...req.init,
      headers: {
        'user-agent': 'pranithjain-graph-ingest/1.0',
        accept: '*/*',
        ...((req.init.headers as Record<string, string>) ?? {}),
      },
      // threatfox sometimes stalls; 20s ceiling so a hung cron subrequest
      // doesn't pin the Worker past the CPU limit.
      signal: AbortSignal.timeout(20_000),
    } as RequestInit);
    if (!res.ok) return { nodes_upserted: 0, edges_created: 0, errors: [`live-iocs: threatfox HTTP ${res.status}`] };
    const body = await res.text();
    const items = parseThreatfoxCsv(body);
    if (!items.length) return { nodes_upserted: 0, edges_created: 0, errors: ['live-iocs: no data'] };

    // Limit to 18 per batch to stay within 50-subrequest limit:
    // ensureGraphTables(6) + upsertNode(18 * 2) = 42, fits with margin.
    return ingestBulkIocs(db, items, 18);
  } catch (e) {
    logError('ingestLiveIocs failed', e);
    return {
      nodes_upserted: 0,
      edges_created: 0,
      errors: [`live-iocs: ${e instanceof Error ? e.message : String(e)}`],
    };
  }
}

async function ingestPhishingUrls(db: D1Database): Promise<IngestResult> {
  try {
    const res = await fetch('https://openphish.com/feed.txt', {
      headers: { 'user-agent': 'pranithjain-graph-ingest/1.0', accept: 'text/plain' },
      // openphish CDN is fast but flaky; 15s ceiling.
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { nodes_upserted: 0, edges_created: 0, errors: [`phishing: openphish HTTP ${res.status}`] };
    const text = await res.text();
    const urls = text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    if (!urls.length) return { nodes_upserted: 0, edges_created: 0, errors: ['phishing: no data'] };

    const entities: ExtractedEntity[] = [];
    const seen = new Set<string>();
    for (const url of urls.slice(0, 20)) {
      const key = `url:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entities.push({ type: 'url', value: url, label: url, confidence: 85 });
    }
    if (!entities.length) return { nodes_upserted: 0, edges_created: 0, errors: ['phishing: no entities'] };

    return upsertNodesOnly(db, entities, 'phishing', {
      description: 'Phishing URLs from OpenPhish/PhishTank',
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    logError('ingestPhishingUrls failed', e);
    return { nodes_upserted: 0, edges_created: 0, errors: [`phishing: ${e instanceof Error ? e.message : String(e)}`] };
  }
}

async function ingestTelegram(db: D1Database, maxItems: number = 30): Promise<IngestResult> {
  try {
    const feed = await fetchTelegramFeed();
    if (!feed?.items?.length) {
      return { nodes_upserted: 0, edges_created: 0, errors: [] };
    }
    const items: FeedIngestItem[] = feed.items.slice(0, maxItems).map((it) => ({
      title: it.text.slice(0, 80),
      description: it.text,
      link: it.permalink,
      pubDate: it.datetime,
      source: it.channel_name,
      source_url: it.permalink,
    }));
    return ingestMultipleFeedItems(db, items, 'Telegram', maxItems);
  } catch (e) {
    logError('ingestTelegram failed', e);
    return { nodes_upserted: 0, edges_created: 0, errors: [`telegram: ${e instanceof Error ? e.message : String(e)}`] };
  }
}

async function ingestRansomware(db: D1Database, env?: Env): Promise<IngestResult> {
  try {
    const { body, upstreamOk } = await fetchRansomwareRecent(env);
    if (!upstreamOk || !body?.victims?.length) {
      return { nodes_upserted: 0, edges_created: 0, errors: upstreamOk ? [] : ['ransomware upstream unreachable'] };
    }
    const aggregated: IngestResult = { nodes_upserted: 0, edges_created: 0, errors: [] };
    for (const victim of body.victims.slice(0, 5)) {
      const text = [victim.victim, victim.description, victim.group].filter(Boolean).join(' ');
      const entities = extractIOCs(text);
      if (!entities.length) continue;
      const r = await ingestEntitiesNoEnsure(db, entities, 'ransomware', {
        description: `Ransomware victim: ${victim.victim}`,
        timestamp: victim.discovered || new Date().toISOString(),
      });
      aggregated.nodes_upserted += r.nodes_upserted;
      aggregated.edges_created += r.edges_created;
      aggregated.errors.push(...r.errors);
    }
    return aggregated;
  } catch (e) {
    logError('ingestRansomware failed', e);
    return {
      nodes_upserted: 0,
      edges_created: 0,
      errors: [`ransomware: ${e instanceof Error ? e.message : String(e)}`],
    };
  }
}

export async function runGraphIngest(
  db: D1Database,
  source: SourceName = 'all',
  env?: Env
): Promise<Record<string, IngestResult>> {
  // Ensure tables once so downstream calls can skip table checks.
  await ensureGraphTables(db);

  const results: Record<string, IngestResult> = {};

  if (source === 'all' || source === 'ioc') {
    results['ioc'] = await ingestLiveIocs(db, env);
  }
  if (source === 'all' || source === 'phishing') {
    results['phishing'] = await ingestPhishingUrls(db);
  }
  if (source === 'all' || source === 'telegram') {
    results['telegram'] = await ingestTelegram(db, 5);
  }
  if (source === 'all' || source === 'ransomware') {
    results['ransomware'] = await ingestRansomware(db, env);
  }

  return results;
}

export async function graphIngestManualHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'Database not configured');

  const source = (c.req.query('source') ?? 'all') as SourceName;
  const validSources: SourceName[] = ['all', 'ioc', 'phishing', 'telegram', 'ransomware'];
  if (!validSources.includes(source)) {
    return badRequest(c, `invalid source. valid: ${validSources.join(', ')}`);
  }

  const startMs = Date.now();
  let results: Record<string, IngestResult>;
  try {
    results = await runGraphIngest(db, source, c.env);
  } catch (e) {
    logError('graphIngestManualHandler failed', e);
    return c.json(
      {
        ok: false,
        source,
        duration_ms: Date.now() - startMs,
        error: e instanceof Error ? e.message : String(e),
      },
      500
    );
  }
  const totalNodes = Object.values(results).reduce((s, r) => s + r.nodes_upserted, 0);
  const totalEdges = Object.values(results).reduce((s, r) => s + r.edges_created, 0);
  const totalErrors = Object.values(results).reduce((s, r) => s + r.errors.length, 0);

  return c.json({
    ok: true,
    source,
    duration_ms: Date.now() - startMs,
    total: { nodes_upserted: totalNodes, edges_created: totalEdges, errors: totalErrors },
    per_source: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [
        k,
        { nodes_upserted: v.nodes_upserted, edges_created: v.edges_created, errors: v.errors },
      ])
    ),
  });
}
