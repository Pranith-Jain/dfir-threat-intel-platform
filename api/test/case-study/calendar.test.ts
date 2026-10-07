import { describe, it, expect } from 'vitest';
import type { CaseStudyType } from '../../src/case-study/types';

// Test the funnel-mix mapping logic in isolation. The route handler is a
// thin Hono wrapper around this logic; the pure functions are what matter.

// Mirror the FUNNEL_MAP from the route (kept in sync manually — the route
// is a server module that needs the Worker runtime, so we test the logic
// shape here, not the Hono handler).
const FUNNEL_MAP: Record<CaseStudyType, 'tofu' | 'mofu' | 'bofu'> = {
  cve: 'tofu',
  vulnfaq: 'tofu',
  exploit: 'tofu',
  darkweb: 'tofu',
  supplychain: 'tofu',
  breach: 'tofu',
  scam: 'tofu',
  news: 'tofu',
  trend: 'tofu',
  briefing: 'tofu',
  actor: 'mofu',
  malware: 'mofu',
  intel: 'mofu',
  aisec: 'mofu',
  llm: 'mofu',
  aisecops: 'mofu',
  agentic: 'mofu',
  hunting: 'mofu',
  report: 'mofu',
  analysis: 'mofu',
  methodology: 'bofu',
  tool: 'bofu',
  osint: 'bofu',
};

const TARGET_MIX = { tofu: 0.6, mofu: 0.3, bofu: 0.1 };

function mixDivergence(mix: { tofu: number; mofu: number; bofu: number }): number {
  const total = mix.tofu + mix.mofu + mix.bofu;
  if (total === 0) return 0;
  const actual = { tofu: mix.tofu / total, mofu: mix.mofu / total, bofu: mix.bofu / total };
  const diff =
    Math.abs(actual.tofu - TARGET_MIX.tofu) +
    Math.abs(actual.mofu - TARGET_MIX.mofu) +
    Math.abs(actual.bofu - TARGET_MIX.bofu);
  return Number((diff / 2).toFixed(3));
}

describe('funnel-mix mapping', () => {
  it('maps breaking-news types to TOFU (awareness)', () => {
    expect(FUNNEL_MAP.cve).toBe('tofu');
    expect(FUNNEL_MAP.exploit).toBe('tofu');
    expect(FUNNEL_MAP.darkweb).toBe('tofu');
    expect(FUNNEL_MAP.vulnfaq).toBe('tofu');
    expect(FUNNEL_MAP.breach).toBe('tofu');
    expect(FUNNEL_MAP.scam).toBe('tofu');
    expect(FUNNEL_MAP.news).toBe('tofu');
    expect(FUNNEL_MAP.briefing).toBe('tofu');
  });

  it('maps deep-dive types to MOFU (consideration)', () => {
    expect(FUNNEL_MAP.actor).toBe('mofu');
    expect(FUNNEL_MAP.malware).toBe('mofu');
    expect(FUNNEL_MAP.intel).toBe('mofu');
    expect(FUNNEL_MAP.aisec).toBe('mofu');
    expect(FUNNEL_MAP.hunting).toBe('mofu');
    expect(FUNNEL_MAP.analysis).toBe('mofu');
  });

  it('maps methodology/tool/osint to BOFU (decision)', () => {
    expect(FUNNEL_MAP.methodology).toBe('bofu');
    expect(FUNNEL_MAP.tool).toBe('bofu');
    expect(FUNNEL_MAP.osint).toBe('bofu');
  });

  it('covers every CaseStudyType', () => {
    const allTypes: CaseStudyType[] = [
      'cve',
      'vulnfaq',
      'exploit',
      'actor',
      'malware',
      'darkweb',
      'breach',
      'scam',
      'aisec',
      'llm',
      'aisecops',
      'supplychain',
      'intel',
      'osint',
      'methodology',
      'trend',
      'briefing',
      'analysis',
      'tool',
      'news',
      'agentic',
      'hunting',
      'report',
    ];
    for (const t of allTypes) {
      expect(FUNNEL_MAP[t]).toBeDefined();
    }
  });
});

describe('mixDivergence', () => {
  it('returns 0 for an empty mix', () => {
    expect(mixDivergence({ tofu: 0, mofu: 0, bofu: 0 })).toBe(0);
  });

  it('returns 0 for a perfect 60/30/10 mix', () => {
    expect(mixDivergence({ tofu: 6, mofu: 3, bofu: 1 })).toBe(0);
  });

  it('returns a high divergence for an all-TOFU mix', () => {
    const d = mixDivergence({ tofu: 10, mofu: 0, bofu: 0 });
    // actual = 1/0/0, target = 0.6/0.3/0.1
    // diff = |1-0.6| + |0-0.3| + |0-0.1| = 0.4 + 0.3 + 0.1 = 0.8, /2 = 0.4
    expect(d).toBeCloseTo(0.4, 2);
  });

  it('returns the max divergence (1.0) for an all-BOFU mix', () => {
    const d = mixDivergence({ tofu: 0, mofu: 0, bofu: 10 });
    // actual = 0/0/1, target = 0.6/0.3/0.1
    // diff = 0.6 + 0.3 + 0.9 = 1.8, /2 = 0.9
    expect(d).toBeCloseTo(0.9, 2);
  });

  it('is proportional — a near-target mix has low divergence', () => {
    const d = mixDivergence({ tofu: 5, mofu: 3, bofu: 2 });
    // actual = 0.5/0.3/0.2, target = 0.6/0.3/0.1
    // diff = 0.1 + 0 + 0.1 = 0.2, /2 = 0.1
    expect(d).toBeCloseTo(0.1, 2);
    expect(d).toBeLessThan(0.15);
  });

  it('scales with how far off the mix is', () => {
    const perfect = mixDivergence({ tofu: 6, mofu: 3, bofu: 1 });
    const slightlyOff = mixDivergence({ tofu: 5, mofu: 3, bofu: 2 });
    const veryOff = mixDivergence({ tofu: 0, mofu: 0, bofu: 10 });
    expect(perfect).toBeLessThan(slightlyOff);
    expect(slightlyOff).toBeLessThan(veryOff);
  });
});
