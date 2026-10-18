import { describe, it, expect } from 'vitest';
import {
  discoverFromTelegramLeaks,
  discoverFromTrendingIocs,
  discoverFromThreatPulse,
} from '../../../src/case-study/discovery/platform-data';
import type { DedupRecord } from '../../../src/case-study/types';

/**
 * Field-shape regression tests.
 *
 * These three runners were dead in production for a stretch because they read
 * field names the platform endpoints never returned (`recent_leaks`,
 * `ioc.count`, `data.actors`). Nothing failed loudly — the runners just
 * returned [] on every run, which is indistinguishable from a quiet day.
 *
 * The fixtures below are literal copies of the real endpoint response shapes
 * (telegram-leaks/search, ioc-lifecycle/trending, threat-pulse). If a route
 * shape drifts again, these tests fail instead of the discovery mix silently
 * dropping a topic.
 */

const NOW = new Date('2026-10-17T12:00:00Z');
const noDedup = async (): Promise<DedupRecord | null> => null;

describe('discoverFromTelegramLeaks', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('reads entries from the search endpoint (domains_found is a JSON string)', async () => {
    const out = await discoverFromTelegramLeaks(
      deps({
        entries: [
          {
            id: 1,
            channel_handle: 'leakzone',
            leak_type: 'combolist',
            credential_count: 250_000,
            domains_found: '["example.com","example.org"]',
            severity: 'high',
            discovered_at: '2026-10-17T08:00:00Z',
          },
          {
            id: 2,
            channel_handle: 'leakzone',
            leak_type: 'stealerlogs',
            credential_count: 50_000,
            domains_found: ['example.net'],
            severity: 'medium',
            discovered_at: '2026-10-17T09:00:00Z',
          },
        ],
      })
    );

    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('breach');
    expect(out[0]?.key).toContain('telegram-leak');
    expect(out[0]?.evidence).toMatchObject({
      channel: 'leakzone',
      leakCount: 2,
      totalCredentials: 300_000,
    });
    expect(out[0]?.evidence.domains).toEqual(['example.com', 'example.org', 'example.net']);
    expect(Number.isFinite(out[0]?.score)).toBe(true);
  });

  it('ignores a channel with a single leak and entries older than 24h', async () => {
    const out = await discoverFromTelegramLeaks(
      deps({
        entries: [
          { channel_handle: 'single', credential_count: 1000, discovered_at: '2026-10-17T08:00:00Z' },
          { channel_handle: 'stale', credential_count: 10, discovered_at: '2026-10-14T08:00:00Z' },
          { channel_handle: 'stale', credential_count: 10, discovered_at: '2026-10-14T09:00:00Z' },
        ],
      })
    );
    expect(out).toEqual([]);
  });

  it('returns [] when the response has no entries array', async () => {
    const out = await discoverFromTelegramLeaks(deps({ total_entries: 5, top_domains: [] }));
    expect(out).toEqual([]);
  });
});

describe('discoverFromTrendingIocs', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('reads observation_count / indicator_type / sources_seen from the lifecycle rows', async () => {
    const out = await discoverFromTrendingIocs(
      deps({
        trending: [
          {
            indicator: '203.0.113.10',
            indicator_type: 'ipv4',
            last_seen: '2026-10-17T11:00:00Z',
            observation_count: 42,
            sources_seen: ['feodo', 'urlhaus'],
          },
        ],
        count: 1,
      })
    );

    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('intel');
    expect(out[0]?.title).toContain('203.0.113.10');
    expect(out[0]?.title).not.toContain('undefined');
    expect(out[0]?.rationale).toContain('2 sources');
    expect(Number.isFinite(out[0]?.score)).toBe(true);
  });

  it('produces no NaN scores even when every optional field is missing', async () => {
    const out = await discoverFromTrendingIocs(deps({ trending: [{ indicator: 'example.com' }] }));
    // Defaults to zero observations → below the activity threshold → dropped.
    expect(out).toEqual([]);
  });

  it('tolerates a JSON-string sources_seen (D1 raw row)', async () => {
    const out = await discoverFromTrendingIocs(
      deps({
        trending: [
          {
            indicator: 'evil.example.org',
            indicator_type: 'domain',
            last_seen: '2026-10-17T11:00:00Z',
            observation_count: 30,
            sources_seen: '["one","two"]',
          },
        ],
      })
    );
    expect(out).toHaveLength(1);
    expect(out[0]?.evidence.sources).toEqual(['one', 'two']);
  });
});

describe('discoverFromThreatPulse', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('reads the entities[] envelope and surfaces actor + malware kinds only', async () => {
    const out = await discoverFromThreatPulse(
      deps({
        generated_at: '2026-10-17T10:00:00Z',
        entities: [
          { label: 'syntheticbear', kind: 'actor', source_count: 6, sources: ['bleepingcomputer', 'reddit', 'x'] },
          { label: 'exampleloader', kind: 'malware', source_count: 4, sources: ['urlhaus'] },
          { label: 'CVE-2099-0100', kind: 'cve', source_count: 9, sources: ['nvd'] },
          { label: 'T1190', kind: 'technique', source_count: 5, sources: ['attack'] },
          { label: 'noise', kind: 'actor', source_count: 1, sources: ['x'] },
        ],
      })
    );

    expect(out.map((c) => c.type).sort()).toEqual(['actor', 'malware']);
    expect(out.map((c) => c.evidence.entity).sort()).toEqual(['exampleloader', 'syntheticbear']);
    expect(Number.isFinite(out[0]?.score)).toBe(true);
  });

  it('returns [] when the snapshot is older than 48h', async () => {
    const out = await discoverFromThreatPulse(
      deps({
        generated_at: '2026-10-10T10:00:00Z',
        entities: [{ label: 'syntheticbear', kind: 'actor', source_count: 9, sources: ['x'] }],
      })
    );
    expect(out).toEqual([]);
  });

  it('returns [] for the legacy { actors, malware } shape the route never produced', async () => {
    const out = await discoverFromThreatPulse(
      deps({
        actors: [{ entity: 'syntheticbear', mentions: 9, sources: ['x'], latest: '2026-10-17T10:00:00Z' }],
      })
    );
    expect(out).toEqual([]);
  });
});
