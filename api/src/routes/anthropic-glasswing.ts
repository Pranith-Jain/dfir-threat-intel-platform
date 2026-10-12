/**
 * Anthropic Project Glasswing — coordinated vulnerability disclosure ledger.
 *
 * A CVE source whose distinguishing property is provenance: these findings were
 * discovered by an AI agent under Anthropic's Glasswing programme, not by a
 * human researcher. NVD and GHSA both carry the CVEs, but neither distinguishes
 * that origin, so for the AI-security surfaces the distinction is invisible
 * without this source.
 *
 * Each record also carries an ecosystem (`torvalds/linux`, `twigphp/twig`) and a
 * weakness class (`use-after-free`, `code-injection`), which gives a
 * join key against our supply-chain and CVE surfaces that a bare CVE id does not.
 *
 * Data is replicated at build time by scripts/sync-anthropic-glasswing.mjs and
 * served from static assets, so there is no per-request upstream fetch.
 *
 *   GET /api/v1/glasswing             — hub meta + severity/ecosystem rollups
 *   GET /api/v1/glasswing/findings    — finding rows (?severity, ?ecosystem, ?weakness, ?q, ?limit)
 *   GET /api/v1/glasswing/findings/:id — one finding by CVE id or ANT id
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { notFound } from '../lib/api-error';
import { findUnknownParams, unknownParamHeaders } from '../lib/filter-catalog';

const DATA_PATH = '/data/threat-intel/glasswing/cvd.json';

interface Finding {
  cveId: string;
  findingId: string | null;
  ecosystem: string | null;
  weakness: string | null;
  severity: string | null;
  discoveredAt: string | null;
  title: string | null;
  nvdUrl: string | null;
  findingUrl: string | null;
}

interface Ledger {
  schemaVersion: string;
  generatedAt: string;
  sourceUrl: string;
  attribution: string;
  total: number;
  bySeverity: Record<string, number>;
  severityRanked: Array<{ id: string; count: number }>;
  ecosystemCount: number;
  topEcosystems: Array<{ id: string; findings: number }>;
  earliestDiscovery: string | null;
  records: Finding[];
}

/**
 * Isolate-level cache. The ledger is a build artifact: it does not change
 * until the next deploy, so there is no TTL to honour and nothing to
 * invalidate. 94 records is small enough to keep resident.
 */
let ledgerPromise: Promise<Ledger | null> | null = null;

async function loadLedger(env: Env): Promise<Ledger | null> {
  if (!env.ASSETS) return null;
  ledgerPromise ??= env.ASSETS.fetch(new Request(`https://glasswing.internal${DATA_PATH}`))
    .then(async (res) => {
      if (!res.ok) return null;
      const json = (await res.json()) as Ledger;
      // Shape check: a replica that silently changed keys should read as
      // "unavailable", not as "the ledger is empty".
      return Array.isArray(json.records) ? json : null;
    })
    .catch(() => null);
  return ledgerPromise;
}

export const glasswingRouter = new Hono<{ Bindings: Env }>();

const IMMUTABLE = { 'Cache-Control': 'public, max-age=300, s-maxage=3600, stale-while-revalidate=86400' };

glasswingRouter.get('/glasswing', async (c) => {
  const ledger = await loadLedger(c.env);
  if (!ledger) {
    return c.json(
      {
        error: 'Glasswing ledger unavailable',
        message: `public${DATA_PATH} not found. Run: node scripts/sync-anthropic-glasswing.mjs`,
      },
      503,
      { 'Cache-Control': 'no-store' }
    );
  }
  const { records: _records, ...meta } = ledger;
  return c.json({ ...meta, schemaVersion: ledger.schemaVersion }, { headers: IMMUTABLE });
});

glasswingRouter.get('/glasswing/findings', async (c) => {
  const ledger = await loadLedger(c.env);
  if (!ledger) {
    return c.json({ error: 'Glasswing ledger unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const severity = c.req.query('severity')?.trim().toLowerCase();
  const ecosystem = c.req.query('ecosystem')?.trim().toLowerCase();
  const weakness = c.req.query('weakness')?.trim().toLowerCase();
  const q = c.req.query('q')?.trim().toLowerCase();
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 100), 1), 500);

  const unknownParams = findUnknownParams('GET', '/api/v1/glasswing/findings', Object.keys(c.req.queries()));

  let rows = ledger.records;
  if (severity) rows = rows.filter((r) => (r.severity ?? '').toLowerCase() === severity);
  // Match on the project half of `owner/repo` as a prefix-free contains, so
  // `linux` finds `torvalds/linux` without also matching `linuxfoundation/x`.
  if (ecosystem) rows = rows.filter((r) => (r.ecosystem ?? '').toLowerCase().includes(ecosystem));
  if (weakness) rows = rows.filter((r) => (r.weakness ?? '').toLowerCase().includes(weakness));
  if (q) {
    rows = rows.filter(
      (r) =>
        (r.cveId ?? '').toLowerCase().includes(q) ||
        (r.findingId ?? '').toLowerCase().includes(q) ||
        (r.title ?? '').toLowerCase().includes(q)
    );
  }

  return c.json(
    {
      schemaVersion: ledger.schemaVersion,
      generatedAt: ledger.generatedAt,
      ...(unknownParams.length > 0 ? { unknownParams } : {}),
      total: rows.length,
      filters: { severity: severity ?? null, ecosystem: ecosystem ?? null, weakness: weakness ?? null, q: q ?? null },
      findings: rows.slice(0, limit),
    },
    { headers: { ...IMMUTABLE, ...unknownParamHeaders(unknownParams, '/api/v1/glasswing/findings') } }
  );
});

glasswingRouter.get('/glasswing/findings/:id', async (c) => {
  const ledger = await loadLedger(c.env);
  if (!ledger) {
    return c.json({ error: 'Glasswing ledger unavailable' }, 503, { 'Cache-Control': 'no-store' });
  }

  const raw = (c.req.param('id') ?? '').trim();
  // Accept CVE-2026-4747, 2026-4747 and ANT-2026-87DJGDRB alike.
  const upper = raw.toUpperCase();
  const normalised = upper.replace(/^CVE-/, '').replace(/^CVE/, '');
  const finding = ledger.records.find(
    (r) =>
      r.cveId.toUpperCase() === upper ||
      (r.findingId ?? '').toUpperCase() === upper ||
      r.cveId.toUpperCase() === `CVE-${normalised}`
  );

  if (!finding) {
    return notFound(c, `"${raw}" is not in the Glasswing ledger. Not every disclosed finding has an assigned CVE yet.`);
  }
  return c.json(
    { schemaVersion: ledger.schemaVersion, generatedAt: ledger.generatedAt, finding },
    { headers: IMMUTABLE }
  );
});

export default glasswingRouter;
