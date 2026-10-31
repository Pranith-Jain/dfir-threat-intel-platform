/**
 * C2 & infrastructure hunting playbook REST surface
 * (ported from fareedfauzi/MANTIS's curated catalog, served from the
 * static ASSETS manifest — read-only, no upstream hits):
 *   GET /c2-playbooks/               — counts, engines, categories, top families, fingerprints
 *   GET /c2-playbooks/entries        — filtered playbook list (q, engine, family, category, limit, offset)
 *   GET /c2-playbooks/fingerprint/:hash — favicon MMH3 / JARM / SHA-256 family lookup
 *   GET /c2-playbooks/stats          — cache + manifest stats
 */
import { Hono } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { internalError, notFound, badRequest } from '../lib/api-error';

function loadMod() {
  return import('../lib/c2-playbooks-manifest');
}

export const c2PlaybooksRouter = new Hono<{ Bindings: Env }>();

c2PlaybooksRouter.get('/c2-playbooks/', async (c) => {
  try {
    const mod = await loadMod();
    const idx = await mod.loadC2PlaybooksIndex(c.env.ASSETS);
    return c.json({
      source: idx.source,
      license: idx.license,
      portedFrom: idx.portedFrom,
      builtAt: idx.builtAt,
      counts: idx.counts,
      engines: idx.engines,
      categories: idx.categories,
      topFamilies: idx.topFamilies,
      fingerprints: {
        faviconHashes: idx.faviconHashes.length,
        jarmHashes: idx.jarmHashes.length,
      },
    });
  } catch (e) {
    logError('c2-playbooks index failed', e);
    return internalError(c, `c2_playbooks_index_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

c2PlaybooksRouter.get('/c2-playbooks/entries', async (c) => {
  try {
    const mod = await loadMod();
    const engine = c.req.query('engine') || undefined;
    const sections =
      engine && engine.toLowerCase() !== 'all'
        ? [await mod.getC2EngineSection(c.env.ASSETS, engine)].filter(Boolean)
        : await mod.loadAllEngineSections(c.env.ASSETS);
    const sections_ = sections as NonNullable<(typeof sections)[number]>[];
    if (engine && sections_.length === 0) {
      return notFound(c, `c2_playbooks_engine_not_found: ${engine}`);
    }
    if (!engine && sections_.length === 0) return internalError(c, 'c2_playbooks_manifest_empty');
    const result = mod.filterPlaybooks(sections_, {
      q: c.req.query('q') || undefined,
      engine,
      family: c.req.query('family') || undefined,
      category: c.req.query('category') || undefined,
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 100,
      offset: c.req.query('offset') ? Number(c.req.query('offset')) : 0,
    });
    return c.json(result);
  } catch (e) {
    logError('c2-playbooks entries failed', e);
    return internalError(c, `c2_playbooks_entries_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

c2PlaybooksRouter.get('/c2-playbooks/fingerprint/:hash', async (c) => {
  const hash = c.req.param('hash').trim();
  // Favicon MMH3 are signed 32-bit ints; JARM is 62 hex; payload SHA is 64 hex.
  if (!/^-?\d{1,10}$/.test(hash) && !/^[a-f\d]{62,64}$/i.test(hash)) {
    return badRequest(c, 'invalid fingerprint (expect MMH3 int, JARM 62 hex, or SHA-256 64 hex)');
  }
  try {
    const mod = await loadMod();
    const idx = await mod.loadC2PlaybooksIndex(c.env.ASSETS);
    const fp = mod.lookupFingerprint(idx, hash);
    if (fp) return c.json(fp);
    if (/^[a-f\d]{64}$/i.test(hash)) {
      const hits = mod.lookupSha256(await mod.loadAllEngineSections(c.env.ASSETS), hash);
      if (hits.length) {
        return c.json({
          kind: 'sha256',
          value: hash.toLowerCase(),
          families: [...new Set(hits.map((h) => h.family))],
          entries: hits.slice(0, 10),
        });
      }
    }
    return notFound(c, `fingerprint_not_in_catalog: ${hash}`);
  } catch (e) {
    logError('c2-playbooks fingerprint failed', e);
    return internalError(c, `c2_playbooks_fingerprint_failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

c2PlaybooksRouter.get('/c2-playbooks/stats', async (c) => {
  try {
    const mod = await loadMod();
    await mod.loadC2PlaybooksIndex(c.env.ASSETS).catch(() => null);
    return c.json({ ok: true, cache: mod.c2PlaybooksCacheStats() });
  } catch (e) {
    return c.json({ ok: false, error: String(e) });
  }
});
