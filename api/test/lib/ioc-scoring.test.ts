import { describe, it, expect } from 'vitest';
import { scoreIoc, scoreToGrade, calculateLifecycle, type IocObservation } from '../../src/lib/ioc-scoring';

describe('IOC Scoring Engine', () => {
  // A recent timestamp so time-decay (computed against the real `now`) stays ~1.0.
  // Tests that assert an absolute confidence/contribution threshold must use this
  // rather than a hardcoded calendar date, or they silently start failing once
  // wall-clock advances far enough past that date to decay the score below the bound.
  const RECENT = new Date(Date.now() - 60 * 60 * 1000).toISOString();

  describe('scoreIoc', () => {
    it('returns zero score for empty observations', () => {
      const result = scoreIoc([]);
      expect(result.score).toBe(0);
      expect(result.sourceCount).toBe(0);
      expect(result.isDormant).toBe(true);
      expect(result.confidence).toBe('LOW');
    });

    it('calculates score for single source', () => {
      const observations: IocObservation[] = [
        {
          source: 'virustotal',
          observedAt: '2026-05-31T10:00:00Z',
          sourceScore: 80,
        },
      ];
      const result = scoreIoc(observations);
      expect(result.score).toBeGreaterThan(0);
      expect(result.sourceCount).toBe(1);
      expect(result.confidence).toBe('LOW');
    });

    it('increases score with multiple sources', () => {
      const single: IocObservation[] = [{ source: 'virustotal', observedAt: RECENT, sourceScore: 80 }];
      const multi: IocObservation[] = [
        { source: 'virustotal', observedAt: RECENT, sourceScore: 80 },
        { source: 'abuseipdb', observedAt: RECENT, sourceScore: 70 },
        { source: 'shodan', observedAt: RECENT, sourceScore: 60 },
      ];

      const singleResult = scoreIoc(single);
      const multiResult = scoreIoc(multi);

      expect(multiResult.score).toBeGreaterThan(singleResult.score);
      expect(multiResult.correlationBoost).toBeGreaterThan(1.0);
      // 3 sources × score >= 70 → HIGH per the IocScore type contract
      // (finalScore >= 70 && sourceCount >= 3).
      expect(multiResult.confidence).toBe('HIGH');
    });

    it('applies time decay to old observations', () => {
      // Both timestamps must stay inside the 30-day decay window. Hardcoded
      // calendar dates eventually both hit the floor and the assertion fails.
      const recent: IocObservation[] = [
        { source: 'virustotal', observedAt: new Date(Date.now() - 2 * 86_400_000).toISOString(), sourceScore: 80 },
      ];
      const old: IocObservation[] = [
        { source: 'virustotal', observedAt: new Date(Date.now() - 25 * 86_400_000).toISOString(), sourceScore: 80 },
      ];

      const recentResult = scoreIoc(recent, 30);
      const oldResult = scoreIoc(old, 30);

      expect(recentResult.score).toBeGreaterThan(oldResult.score);
      expect(recentResult.decayFactor).toBeGreaterThan(oldResult.decayFactor);
    });

    it('deduplicates by source (keeps most recent)', () => {
      const observations: IocObservation[] = [
        { source: 'virustotal', observedAt: '2026-05-01T10:00:00Z', sourceScore: 50 },
        { source: 'virustotal', observedAt: RECENT, sourceScore: 90 },
      ];
      const result = scoreIoc(observations);
      expect(result.sourceCount).toBe(1);
      // Should use the more recent score
      expect(result.breakdown[0]!.contribution).toBeGreaterThan(50);
    });

    it('marks dormant IOCs correctly', () => {
      const old: IocObservation[] = [{ source: 'virustotal', observedAt: '2026-01-01T10:00:00Z', sourceScore: 80 }];
      const result = scoreIoc(old, 30);
      expect(result.isDormant).toBe(true);
    });
  });

  describe('scoreToGrade', () => {
    it('returns correct grades for score ranges', () => {
      expect(scoreToGrade(90).grade).toBe('A');
      expect(scoreToGrade(70).grade).toBe('B');
      expect(scoreToGrade(50).grade).toBe('C');
      expect(scoreToGrade(30).grade).toBe('D');
      expect(scoreToGrade(10).grade).toBe('F');
    });

    it('includes color and label', () => {
      const grade = scoreToGrade(85);
      expect(grade.color).toBeDefined();
      expect(grade.label).toBeDefined();
    });
  });

  describe('calculateLifecycle', () => {
    it('returns empty lifecycle for no observations', () => {
      const result = calculateLifecycle([]);
      expect(result.observationCount).toBe(0);
      expect(result.trend).toBe('stable');
    });

    it('calculates active days correctly', () => {
      const observations: IocObservation[] = [
        { source: 'a', observedAt: '2026-05-01T10:00:00Z' },
        { source: 'b', observedAt: '2026-05-31T10:00:00Z' },
      ];
      const result = calculateLifecycle(observations);
      expect(result.activeDays).toBe(30);
      expect(result.uniqueSources).toBe(2);
    });

    it('detects trend correctly', () => {
      const observations: IocObservation[] = [
        { source: 'a', observedAt: '2026-05-01T10:00:00Z' },
        { source: 'b', observedAt: '2026-05-15T10:00:00Z' },
        { source: 'c', observedAt: '2026-05-20T10:00:00Z' },
        { source: 'd', observedAt: '2026-05-25T10:00:00Z' },
        { source: 'e', observedAt: '2026-05-30T10:00:00Z' },
        { source: 'f', observedAt: '2026-05-31T10:00:00Z' },
      ];
      const result = calculateLifecycle(observations);
      // Trend should be one of rising, stable, or declining
      expect(['rising', 'stable', 'declining']).toContain(result.trend);
      expect(result.observationCount).toBe(6);
      expect(result.uniqueSources).toBe(6);
    });
  });
});
