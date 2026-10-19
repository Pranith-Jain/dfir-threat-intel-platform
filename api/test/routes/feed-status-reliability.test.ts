import { describe, it, expect } from 'vitest';
import { aggregateReliability, PROBE_SOURCES, PROBES, ALL_PROBES } from '../../src/routes/feed-status';
import { SOURCE_RELIABILITY_REGISTRY } from '../../src/lib/confidence';

describe('aggregateReliability', () => {
  it('returns undefined for empty sourceIds', () => {
    expect(aggregateReliability(undefined)).toBeUndefined();
    expect(aggregateReliability([])).toBeUndefined();
  });

  it('skips unknown source IDs without throwing', () => {
    expect(aggregateReliability(['not-a-real-source'])).toBeUndefined();
  });

  it('returns A for a single A-grade source', () => {
    expect(aggregateReliability(['cisa-kev'])).toBe('A');
  });

  it('returns the highest letter when sources are mixed (best-evidence-wins)', () => {
    // cisa-kev (A) + reddit (D) → A
    expect(aggregateReliability(['cisa-kev', 'reddit'])).toBe('A');
    // ransomlook (B) + hudson-rock (C) → B
    expect(aggregateReliability(['ransomlook', 'hudson-rock'])).toBe('B');
  });

  it('ignores unknown IDs in a mixed list and returns the strongest known', () => {
    expect(aggregateReliability(['bogus-1', 'nvd', 'bogus-2'])).toBe('A');
  });

  it('matches the cve-recent probe mapping (NVD + CISA KEV → A)', () => {
    expect(aggregateReliability(PROBE_SOURCES['cve-recent'])).toBe('A');
  });

  it('matches the cve-exploits probe mapping (ExploitGrid → C)', () => {
    expect(aggregateReliability(PROBE_SOURCES['cve-exploits'])).toBe('C');
  });

  it('matches the live-iocs probe mapping (abuse.ch × 3 → A)', () => {
    expect(aggregateReliability(PROBE_SOURCES['live-iocs'])).toBe('A');
  });

  it('matches the x-feed probe mapping (x-twitter D + bluesky D → D)', () => {
    expect(aggregateReliability(PROBE_SOURCES['x-feed'])).toBe('D');
  });

  it('matches the stealer-forum-intel probe mapping (hudson-rock → C)', () => {
    expect(aggregateReliability(PROBE_SOURCES['stealer-forum-intel'])).toBe('C');
  });
});

describe('PROBE_SOURCES coverage', () => {
  it('every probe that relies on aggregation has sourceIds pointing to registered sources', () => {
    // Probe IDs that have sourceIds but no explicit reliability. All source
    // IDs must resolve in the registry, otherwise the probe reports no
    // reliability letter at all (silent regression — the original bug).
    const probesNeedingAgg = (ALL_PROBES as Array<{ id: string; sourceIds?: string[]; reliability?: string }>).filter(
      (p) => !p.reliability && p.sourceIds && p.sourceIds.length > 0
    );
    expect(probesNeedingAgg.length).toBeGreaterThan(0);
    for (const p of probesNeedingAgg) {
      for (const sid of p.sourceIds!) {
        expect(SOURCE_RELIABILITY_REGISTRY, `probe "${p.id}" references unregistered source "${sid}"`).toHaveProperty(
          sid
        );
      }
      const agg = aggregateReliability(p.sourceIds);
      expect(agg, `probe "${p.id}" should derive a reliability letter from its sourceIds`).toBeDefined();
    }
  });

  it('every probe that has a hardcoded reliability explains its source-set in the constant', () => {
    // Sanity: any probe with `reliability` but no `sourceIds` is composite/
    // inferred. Every aggregated probe should be in PROBE_SOURCES so we can
    // audit the mapping in one place.
    const idsInProbes = new Set<string>(PROBES.map((p) => p.id));
    for (const id of Object.keys(PROBE_SOURCES)) {
      expect(idsInProbes, `PROBE_SOURCES["${id}"] has no matching PROBES entry`).toContain(id);
    }
  });
});
