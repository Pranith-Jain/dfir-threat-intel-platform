import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { createCveController } from '../controllers';
import { createKvCveRepository } from '../infrastructure/persistence/kv-cve-repository';
import { vulncheckCve } from '../lib/vulncheck';
import { hexbrainCveCached } from '../lib/hexbrain';
import { computeSsvcV } from '../lib/ssvc-v';
import { normaliseCveId } from '../lib/cve-id';

export async function cveSearchHandler(c: Context<{ Bindings: Env }>) {
  const repo = createKvCveRepository(c.env.KV_CACHE);
  const controller = createCveController(repo);
  const res = await controller.search(c);

  // Enrich with VulnCheck real-world exploitation intel (initial-access index)
  // when a token is configured and the base lookup succeeded.
  const token = c.env.VULNCHECK_API_TOKEN;
  // Normalise before use: VulnCheck keys on the canonical id, so an
  // abbreviated `?id=2025-1974` would otherwise enrich nothing while still
  // returning a base record, leaving the caller to assume enrichment ran.
  const id = normaliseCveId(c.req.query('id'));
  if (res.status === 200 && id) {
    let data: Record<string, unknown> | null = null;
    try {
      data = (await res.json()) as Record<string, unknown>;

      // Run the two upstream enrichments in parallel. Both swallow their own
      // errors, so a slow VulnCheck response no longer adds its 6s timeout to
      // HexBrain's 8s and pushes the whole lookup past the detail page's
      // client-side deadline (which would hide even the base CVE record).
      const enrichments = await Promise.all([
        token ? vulncheckCve(token, id, AbortSignal.timeout(6000)) : Promise.resolve(null),
        c.env.HEXBRAIN_API_KEY
          ? hexbrainCveCached(c.env.KV_CACHE, (p) => c.executionCtx.waitUntil(p), c.env.HEXBRAIN_API_KEY, id)
          : Promise.resolve(null),
      ]);
      // VulnCheck enrichment
      const vc = enrichments[0];
      if (vc && 'ok' in vc) data.vulncheck = vc.ok;

      // HexBrain enrichment (30-day exploitation likelihood, public PoC corpus,
      // nuclei detection check). Cache-first in KV: the free key allows 200
      // calls/day, so each unique CVE is fetched at most once per day across
      // all colos. Silently absent when the key is unset or upstream fails.
      const hb = enrichments[1];
      if (hb) data.hexbrain = hb;

      // SSVC-V decision engine enrichment
      const d = data as Record<string, Record<string, unknown> | boolean | string | null>;
      const cvssScore = (d?.cvss as { score?: number } | undefined)?.score ?? null;
      const epssScore = (d?.epss as { score?: number } | undefined)?.score ?? null;
      const kev = d?.kev === true;
      const ransomwareUse = d?.ransomware_use === 'Known' || d?.ransomware_use === 'Suspected';
      const exploitStatus = (d?.exploit_status as string | null) ?? null;

      const ssvc = computeSsvcV({
        cvssScore,
        epssScore,
        cisaKev: kev,
        ransomwareUse,
        exploitStatus:
          exploitStatus === 'in-the-wild'
            ? 'active'
            : exploitStatus === 'weaponized' || exploitStatus === 'poc-public'
              ? 'poc'
              : null,
      });
      data.ssvc = ssvc;

      return c.json(data, 200, { 'Cache-Control': 'public, max-age=1800, s-maxage=3600' });
    } catch (_catchErr) {
      logError('handler failed', _catchErr);
      if (data) return c.json(data, 200, { 'Cache-Control': 'public, max-age=1800, s-maxage=3600' });
    }
  }
  return res;
}
