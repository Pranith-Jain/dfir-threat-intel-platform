import { describe, it, expect } from 'vitest';
import {
  engagementScore,
  computeTypePerformance,
  type MetricsRecord,
} from '../../../src/case-study/analytics/analytics';

const rec = (over: Partial<MetricsRecord>): MetricsRecord => ({
  slug: over.slug ?? 's',
  platform: over.platform ?? 'twitter',
  type: over.type ?? 'cve',
  metrics: over.metrics ?? {},
  fetchedAt: '2026-06-25T00:00:00Z',
  ...over,
});

describe('engagementScore', () => {
  it('weights replies > reposts > likes', () => {
    const likes = engagementScore({ likes: 10 });
    const reposts = engagementScore({ reposts: 10 });
    const replies = engagementScore({ replies: 10 });
    expect(reposts).toBeGreaterThan(likes);
    expect(replies).toBeGreaterThan(reposts);
  });

  it('treats missing fields as zero', () => {
    expect(engagementScore({})).toBe(0);
  });
});

describe('computeTypePerformance', () => {
  it('groups by content type, averages engagement, sorts best-first', () => {
    const records = [
      rec({ slug: 'a', type: 'cve', metrics: { likes: 100, replies: 10 } }),
      rec({ slug: 'b', type: 'cve', metrics: { likes: 0 } }),
      rec({ slug: 'c', type: 'darkweb', metrics: { likes: 500, reposts: 50 } }),
    ];
    const out = computeTypePerformance(records);
    // ransom (1 post, high) should rank above cve (avg of 2 posts)
    expect(out[0]!.type).toBe('darkweb');
    const cve = out.find((o) => o.type === 'cve')!;
    expect(cve.posts).toBe(2);
    expect(cve.avgEngagement).toBeCloseTo(engagementScore({ likes: 100, replies: 10 }) / 2, 5);
  });

  it('sums impressions per type', () => {
    const out = computeTypePerformance([
      rec({ type: 'cve', metrics: { impressions: 1000 } }),
      rec({ slug: 'b', type: 'cve', metrics: { impressions: 500 } }),
    ]);
    expect(out[0]!.totalImpressions).toBe(1500);
  });

  it('returns [] for no records', () => {
    expect(computeTypePerformance([])).toEqual([]);
  });
});
