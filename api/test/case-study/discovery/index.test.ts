import { describe, it, expect } from 'vitest';
import { runDiscovery } from '../../../src/case-study/discovery/index';
import type { Candidate } from '../../../src/case-study/types';

const sampleC = (key: string, type: any, score: number): Candidate => ({
  key,
  type,
  title: key,
  rationale: '',
  score,
  evidence: {},
  discoveredAt: '2026-05-14T06:00:00Z',
  status: 'pending',
});

describe('runDiscovery', () => {
  it('selects per-topic so every topic is represented (no global starvation)', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        // actor scores highest — under the old global top-5 it crowded
        // every other topic out. Per-topic selection must keep all four.
        cve: async () => [sampleC('cve-1', 'cve', 0.5), sampleC('cve-2', 'cve', 0.45)],
        actor: async () => [sampleC('actor-1', 'actor', 0.99), sampleC('actor-2', 'actor', 0.98)],
        malware: async () => [sampleC('mal-1', 'malware', 0.4)],
        ransom: async () => [sampleC('ran-1', 'ransom', 0.3)],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
    };
    const result = await runDiscovery(env as any);
    const topics = new Set(writes.map((w) => w.type));
    expect(topics).toEqual(new Set(['cve', 'actor', 'malware', 'ransom']));
    expect(result.byTopic).toEqual({ cve: 2, actor: 2, malware: 1, ransom: 1 });
    expect(result.kept).toBe(6);
  });

  it('caps each topic at perTopic', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        cve: async () => [
          sampleC('c1', 'cve', 0.9),
          sampleC('c2', 'cve', 0.8),
          sampleC('c3', 'cve', 0.7),
          sampleC('c4', 'cve', 0.6),
        ],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      perTopic: 2,
    };
    const result = await runDiscovery(env as any);
    expect(result.byTopic.cve).toBe(2);
    expect(writes.map((w) => w.key).sort()).toEqual(['c1', 'c2']);
  });

  it('applies an optional overall cap after per-topic selection', async () => {
    const env = {
      runners: {
        cve: async () => [sampleC('cve-1', 'cve', 0.9)],
        actor: async () => [sampleC('actor-1', 'actor', 0.8)],
        malware: async () => [sampleC('mal-1', 'malware', 0.7)],
        ransom: async () => [sampleC('ran-1', 'ransom', 0.6)],
      },
      putCandidate: async () => {},
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      limit: 2,
    };
    const result = await runDiscovery(env as any);
    expect(result.kept).toBe(2);
    expect(result.ids).toEqual(['cve-1', 'actor-1']);
  });

  it('one failing runner does not block the others', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        cve: async () => {
          throw new Error('cve upstream down');
        },
        actor: async () => [sampleC('actor-1', 'actor', 0.8)],
        malware: async () => [sampleC('mal-1', 'malware', 0.7)],
        ransom: async () => [sampleC('ran-1', 'ransom', 0.6)],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
    };
    const result = await runDiscovery(env as any);
    expect(result.byTopic.cve).toBe(0);
    expect(new Set(writes.map((w) => w.type))).toEqual(new Set(['actor', 'malware', 'ransom']));
  });

  it('drops candidates from a barred source and counts them', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        exploit: async () => [
          {
            ...sampleC('cve-x', 'exploit', 0.9),
            evidence: { url: 'https://exploitgrid.net/exploits/EGE-GH-abc' },
          },
          sampleC('dbugs-y', 'exploit', 0.5),
        ],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
    };
    const result = await runDiscovery(env as any);
    expect(result.blocked).toBe(1);
    expect(writes.map((w) => w.key)).toEqual(['dbugs-y']);
  });

  it('does not re-offer suppressed candidates when the day is already full', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        cve: async () => [sampleC('c1', 'cve', 0.9), sampleC('c2', 'cve', 0.8)],
        actor: async () => [sampleC('a1', 'actor', 0.7)],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      minKept: 2,
      isSuppressed: () => false,
      admitSuppressed: () => true,
    };
    const result = await runDiscovery(env as any);
    expect(result.kept).toBe(3);
    // Nothing was suppressed, so the floor had nothing to top up from.
    expect(result.filledFromSuppressed).toBe(0);
  });

  it('passes the candidate to the suppression gate so gates can read evidence', async () => {
    // A candidate-level gate (e.g. "the KEV job owns fresh additions") needs the
    // candidate, not just its key. Regression guard: the gate used to receive
    // only the key, which made that class of rule unimplementable.
    const seenEvidence: unknown[] = [];
    const env = {
      runners: {
        cve: async () => [
          { ...sampleC('kev-1', 'cve', 0.9), evidence: { kev: true, kevAddedAt: '2026-05-14T00:00:00Z' } },
        ],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async () => {},
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      isSuppressed: (_key: string, cand: Candidate) => {
        seenEvidence.push(cand.evidence);
        return true;
      },
    };
    const result = await runDiscovery(env as any);
    expect(seenEvidence[0]).toEqual({ kev: true, kevAddedAt: '2026-05-14T00:00:00Z' });
    expect(result.kept).toBe(0);
    expect(result.suppressed).toBe(1);
  });

  it('fills the daily floor from suppressed candidates the policy admits', async () => {
    const writes: Candidate[] = [];
    const suppressedKeys = new Set(['s1', 's2']);
    const env = {
      runners: {
        // One fresh candidate; everything else the runners found is suppressed
        // by the anti-repetition gate — this is the 2-3-items-a-day shape the
        // floor exists to fix.
        cve: async () => [sampleC('f1', 'cve', 0.9), sampleC('s1', 'cve', 0.8), sampleC('s2', 'cve', 0.7)],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      minKept: 3,
      isSuppressed: (k: string) => suppressedKeys.has(k),
      admitSuppressed: () => true,
    };
    const result = await runDiscovery(env as any);
    expect(result.kept).toBe(3);
    expect(result.filledFromSuppressed).toBe(2);
    expect(writes.map((w) => w.key).sort()).toEqual(['f1', 's1', 's2']);
  });

  it('leaves the day short rather than admitting a candidate the policy rejects', async () => {
    const env = {
      runners: {
        cve: async () => [sampleC('f1', 'cve', 0.9), sampleC('s1', 'cve', 0.8)],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async () => {},
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      minKept: 6,
      isSuppressed: (k: string) => k === 's1',
      // e.g. already published — never re-offered, even to hit the floor.
      admitSuppressed: () => false,
    };
    const result = await runDiscovery(env as any);
    expect(result.kept).toBe(1);
    expect(result.filledFromSuppressed).toBe(0);
  });

  it('uses an injected selectPerTopic when provided', async () => {
    const writes: Candidate[] = [];
    const env = {
      runners: {
        cve: async () => [sampleC('c1', 'cve', 0.9), sampleC('c2', 'cve', 0.8), sampleC('c3', 'cve', 0.7)],
        actor: async () => [],
        malware: async () => [],
        ransom: async () => [],
      },
      putCandidate: async (c: Candidate) => {
        writes.push(c);
      },
      commitDedup: async () => {},
      now: new Date('2026-05-14T06:00:00Z'),
      perTopic: 2,
      // Selector that takes the LOWEST scored instead of the default top-k,
      // proving the seam is honored (not the built-in sort).
      selectPerTopic: (cands: Candidate[], k: number) => [...cands].sort((a, b) => a.score - b.score).slice(0, k),
    };
    const result = await runDiscovery(env as any);
    expect(result.byTopic.cve).toBe(2);
    expect(writes.map((w) => w.key).sort()).toEqual(['c2', 'c3']);
  });
});
