import { describe, it, expect } from 'vitest';
import {
  putCandidate,
  getCandidate,
  listCandidates,
  listAllCandidates,
  deleteCandidate,
  countAllCandidates,
} from '../../../src/case-study/storage/candidates';
import type { Candidate } from '../../../src/case-study/types';

function mockKV() {
  const store = new Map<string, { value: string; expiresAt?: number }>();
  return {
    store,
    async get(key: string, _type?: 'json') {
      const e = store.get(key);
      if (!e) return null;
      if (e.expiresAt && Date.now() > e.expiresAt) {
        store.delete(key);
        return null;
      }
      return _type === 'json' ? JSON.parse(e.value) : e.value;
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }) {
      store.set(key, {
        value,
        expiresAt: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined,
      });
    },
    async delete(key: string) {
      store.delete(key);
    },
    async list(opts: { prefix: string }) {
      const keys = Array.from(store.keys())
        .filter((k) => k.startsWith(opts.prefix))
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: '' };
    },
  };
}

const sampleCandidate: Candidate = {
  key: 'cve-2026-1234',
  type: 'cve',
  title: 'Test CVE',
  rationale: 'in KEV',
  score: 0.9,
  evidence: { cve: 'CVE-2026-1234' },
  discoveredAt: '2026-05-14T06:00:00Z',
  status: 'pending',
};

describe('candidates storage', () => {
  it('round-trips a candidate', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    const fetched = await getCandidate(kv, 'cve', 'cve-2026-1234');
    expect(fetched).toEqual(sampleCandidate);
  });

  it('writes blob with a 30-day expiration', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    const entry = kv.store.get('candidates:cve:all');
    // Blobs carry a 30-day TTL so stale candidates age out of KV.
    expect(entry?.expiresAt).toBeDefined();
    const ttlSeconds = ((entry!.expiresAt as number) - Date.now()) / 1000;
    expect(ttlSeconds).toBeGreaterThan(29 * 24 * 3600);
    expect(ttlSeconds).toBeLessThanOrEqual(30 * 24 * 3600 + 1);
  });

  it('listCandidates returns candidates of a type', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    await putCandidate(kv, { ...sampleCandidate, key: 'cve-2026-5678' });
    await putCandidate(kv, { ...sampleCandidate, key: 'actor-fin7', type: 'actor' });
    const cves = await listCandidates(kv, 'cve');
    expect(cves).toHaveLength(2);
    const actors = await listCandidates(kv, 'actor');
    expect(actors).toHaveLength(1);
  });

  it('listAllCandidates returns every type in one pass', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    await putCandidate(kv, { ...sampleCandidate, key: 'cve-2026-5678' });
    await putCandidate(kv, { ...sampleCandidate, key: 'actor-fin7', type: 'actor' });
    await putCandidate(kv, { ...sampleCandidate, key: 'darkweb-broker-listing', type: 'darkweb' });
    const all = await listAllCandidates(kv);
    expect(all).toHaveLength(4);
    expect(new Set(all.map((c) => c.type))).toEqual(new Set(['cve', 'actor', 'darkweb']));
  });

  it('countAllCandidates returns total count', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    await putCandidate(kv, { ...sampleCandidate, key: 'actor-fin7', type: 'actor' });
    expect(await countAllCandidates(kv)).toBe(2);
  });

  it('deleteCandidate removes the entry', async () => {
    const kv = mockKV() as any;
    await putCandidate(kv, sampleCandidate);
    await deleteCandidate(kv, 'cve', 'cve-2026-1234');
    expect(await getCandidate(kv, 'cve', 'cve-2026-1234')).toBeNull();
  });
});
