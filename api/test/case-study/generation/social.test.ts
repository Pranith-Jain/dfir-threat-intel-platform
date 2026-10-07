import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Post } from '../../../src/case-study/types';

beforeEach(() => {
  vi.clearAllMocks();
});

vi.mock('../../../src/case-study/generation/ai-client', async () => {
  const actual = await vi.importActual('../../../src/case-study/generation/ai-client');
  return {
    ...(actual as Record<string, unknown>),
    runCompletion: vi.fn(async (_ai: unknown, input: { system: string; user: string }) => {
      return { text: input.user, modelUsed: 'mock' };
    }),
  };
});

/**
 * NOTE ON FIXTURE IDS. Every CVE id, vendor and post slug below is a
 * synthetic placeholder. Tests that name real CVEs go stale as those records
 * get amended and KEV-listed, and a failure then looks like a code bug when
 * it is a fixture-rot bug. The prompts under test care about structure
 * ("is the link in a FIRST COMMENT line", "does the system prompt carry the
 * grounding contract"), never about the specific vulnerability.
 */
const SYNTHETIC_CVE = 'CVE-2099-0001';

const mockPost: Post = {
  slug: 'cve-synthetic-fixture-auth-bypass',
  type: 'vulnfaq',
  title: `${SYNTHETIC_CVE} synthetic vendor auth bypass`,
  excerpt: 'A synthetic fixture post.',
  publishedAt: '2026-05-16T00:00:00.000Z',
  candidateId: `cve-${SYNTHETIC_CVE}`,
  body: `# Summary\n${SYNTHETIC_CVE} affects a synthetic vendor appliance and was exploited before a fix shipped.`,
  hero: '<svg></svg>',
  iocs: [],
  tags: ['vulnfaq', 'synthetic'],
  sources: [{ url: `https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}`, title: 'NVD' }],
};

const lastUserPrompt = async (): Promise<string> => {
  const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
  const calls = (runCompletion as any).mock.calls;
  return calls[calls.length - 1][1].user as string;
};

const lastSystemPrompt = async (): Promise<string> => {
  const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
  const calls = (runCompletion as any).mock.calls;
  return calls[calls.length - 1][1].system as string;
};

describe('LinkedIn prompt', () => {
  it('puts the canonical article URL on the FIRST COMMENT line, not in the body', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toContain(`FIRST COMMENT: https://pranithjain.qzz.io/blog/${mockPost.slug}`);
    expect(user).toMatch(/no link in the body/i);
  });

  it('states the hard character limit and leaves length to the material', async () => {
    // The old prompt mandated a 1300-2000 char target, which made the model
    // pad or truncate to hit a number. Now the only hard rule is the limit.
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toContain('3000');
    expect(user).toMatch(/length follows/i);
    expect(user).not.toMatch(/1300-2000/);
  });

  it('requires the fold to carry a complete point rather than a teaser', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toMatch(/see more/i);
    expect(user).toMatch(/complete,? standalone point|complete point/i);
  });

  it('caps hashtags and prefers specific ones', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toMatch(/0 to 3 hashtags/i);
    expect(user).toMatch(/specific to this case/i);
  });

  it('requires every specific claim to come from the dossier', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toMatch(/comes from the\s*\n?\s*dossier|from the dossier/i);
  });
});

describe('Twitter prompt', () => {
  it('lets the model choose thread-vs-single from the material', async () => {
    // The old prompt mandated "6 tweets exactly". Now the shape follows the
    // content, which is what stops every thread having the same skeleton.
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    await generateTwitterContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toMatch(/pick the shape that fits/i);
    expect(user).not.toContain('6 tweets exactly');
  });

  it('puts the canonical article URL on the FIRST REPLY line', async () => {
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    await generateTwitterContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toContain(`FIRST REPLY: https://pranithjain.qzz.io/blog/${mockPost.slug}`);
  });

  it('states the per-post character limit and caps hashtags at one', async () => {
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    await generateTwitterContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toContain('280');
    expect(user).toMatch(/at most one hashtag/i);
  });

  it('asks for the reusable data in the middle of a thread', async () => {
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    await generateTwitterContent(mockPost, {} as never, new Date());
    const user = await lastUserPrompt();
    expect(user).toMatch(/reusable data/i);
  });
});

describe('system prompt — grounding contract', () => {
  it('states that the dossier is the only source of facts', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const sys = await lastSystemPrompt();
    expect(sys).toContain('RESEARCH DOSSIER');
    expect(sys).toMatch(/only source of facts/i);
  });

  it('tells the model to name gaps rather than fill them', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const sys = await lastSystemPrompt();
    expect(sys).toMatch(/NOT ESTABLISHED/i);
    expect(sys).toMatch(/never fill/i);
  });

  it('requires answer-first structure', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const sys = await lastSystemPrompt();
    expect(sys).toMatch(/answer the reader/i);
  });

  it('forbids describing the piece instead of writing it', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const sys = await lastSystemPrompt();
    expect(sys).toMatch(/in this article|let's dive in/i);
    expect(sys).toMatch(/do not describe/i);
  });

  it('no longer carries the removed banned-phrase and framework rulesets', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    await generateLinkedinContent(mockPost, {} as never, new Date());
    const sys = await lastSystemPrompt();
    // These were the prescriptive blocks that made every post the same shape.
    expect(sys).not.toContain('#COPYWRITING RULES');
    expect(sys).not.toContain('#FRAMEWORKS');
    expect(sys).not.toContain('#SAVE MAGNETS');
    expect(sys).not.toContain('PAS (Problem-Agitate-Solution)');
  });
});

describe('generateSocialContent', () => {
  it('produces both twitter and linkedin', async () => {
    const { generateSocialContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({ text: 'content', modelUsed: 'mock' }));
    const res = await generateSocialContent(mockPost, {} as never, new Date());
    expect(res.slug).toBe(mockPost.slug);
    expect(res.twitter).toBe('content');
    expect(res.linkedin).toBe('content');
    expect(res.generatedAt).toBeTruthy();
  });

  it('records factual per-platform checks, not a quality score', async () => {
    const { generateSocialContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({ text: 'A short but valid post.', modelUsed: 'mock' }));
    const res = await generateSocialContent(mockPost, {} as never, new Date());
    expect(res._validation?.twitter_check).toBeDefined();
    expect(res._validation?.linkedin_check).toBeDefined();
    // The score and slop_count fields are gone.
    expect(res._validation?.twitter_check).not.toHaveProperty('score');
    expect(res._validation?.twitter_check).not.toHaveProperty('slop_count');
    // And so is the cross-platform readiness verdict.
    expect(res._validation).not.toHaveProperty('readiness');
  });

  it('calls the model once per platform — no retry-on-score loop', async () => {
    // The old loop regenerated anything scoring under 60, feeding the model
    // its own validation complaints. That reliably produced keyword-stuffed
    // copy that passed the score.
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockClear();
    (runCompletion as any).mockImplementation(async () => ({ text: 'Tiny.', modelUsed: 'mock' }));
    await generateLinkedinContent(mockPost, {} as never, new Date());
    expect((runCompletion as any).mock.calls.length).toBe(1);
  });

  it('does not flag a post for using an ordinary English word', async () => {
    // The concrete-specifics scorer counted hits against a hardcoded list of
    // ~60 vendor and actor names, so a sharp post about an unfamiliar product
    // scored as "too generic" while a name-stuffed post scored perfectly.
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({
      text: 'A supply-chain note about a build pipeline, with no named vendor at all, but a genuinely useful method.',
      modelUsed: 'mock',
    }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res._validation?.check).toBeDefined();
    expect(res._validation?.check).not.toHaveProperty('issues');
  });

  it('flags an over-limit post so the caller knows it will be truncated', async () => {
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({
      text: 'x'.repeat(400),
      modelUsed: 'mock',
    }));
    const res = await generateTwitterContent(mockPost, {} as never, new Date());
    expect(res._validation?.check?.over_limit).toBe(true);
  });
});

describe('whitespace tidy', () => {
  it('collapses 3+ blank lines to one and strips trailing spaces', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({
      text: 'Hook line.   \n\n\n\nSecond para.\n\n\n- bullet  ',
      modelUsed: 'mock',
    }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res.linkedin).not.toMatch(/\n{3,}/);
    expect(res.linkedin).not.toMatch(/[ \t]\n/);
    expect(res.linkedin).not.toMatch(/[ \t]$/);
    expect(res.linkedin).toContain('Hook line.\nSecond para.');
    expect(res.linkedin).toContain('\n\n- bullet');
  });

  it('leaves punctuation alone', async () => {
    // The old blanket dash/semicolon replacement mangled numeric ranges and
    // table rows. Tidy is now whitespace only.
    const { generateTwitterContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({
      text: 'Affects versions 13.1-64.22 and 14.1-73.41 — the fixed build is 14.1-73.42.',
      modelUsed: 'mock',
    }));
    const res = await generateTwitterContent(mockPost, {} as never, new Date());
    expect(res.twitter).toContain('13.1-64.22');
    expect(res.twitter).toContain('14.1-73.41');
  });
});

describe('LinkedIn sparse-merge tidy', () => {
  it('joins consecutive short single-line paragraphs and keeps blank lines before lists and special blocks', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockImplementation(async () => ({
      text: [
        'First short line.',
        '',
        'Second short line.',
        '',
        'Third short line.',
        '',
        '- bullet 1',
        '- bullet 2',
        '',
        '#DFIR #ThreatIntel',
        '',
        'FIRST COMMENT: https://pranithjain.qzz.io/blog/x',
      ].join('\n'),
      modelUsed: 'mock',
    }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res.linkedin).toContain('First short line.\nSecond short line.\nThird short line.');
    expect(res.linkedin).not.toContain('First short line.\n\nSecond short line.');
    expect(res.linkedin).toContain('\n\n- bullet 1');
    expect(res.linkedin).toContain('\n\n#DFIR #ThreatIntel');
    expect(res.linkedin).toContain('\n\nFIRST COMMENT:');
  });

  it('keeps a long single-line paragraph as its own block', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    const long = 'x'.repeat(200);
    (runCompletion as any).mockImplementation(async () => ({
      text: `Short one.\n\n${long}\n\nShort two.`,
      modelUsed: 'mock',
    }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res.linkedin).toContain(`Short one.\n\n${long}\n\nShort two.`);
  });
});

describe('"You"-hook handling', () => {
  // The old pipeline deleted the first sentence of any hook opening on the
  // reader, which removed the hook. A soft opening is now left alone: it is
  // a style choice, and the human reviewing the draft can judge it.
  it('leaves a reader-addressed opening intact', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    const body = [
      "You're seeing more edge exploitation in your logs this week.",
      'The driver is an authentication bypass in a widely deployed VPN product.',
      '',
      'If your retainer treats every note as a fresh compromise, what does it actually hand off?',
    ].join('\n');
    (runCompletion as any).mockImplementation(async () => ({ text: body, modelUsed: 'mock' }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res.linkedin).toContain("You're seeing more edge exploitation");
    expect(res.linkedin).toContain('authentication bypass');
  });

  it('leaves a subject-led opening intact', async () => {
    const { generateLinkedinContent } = await import('../../../src/case-study/generation/social');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    const body = [
      'Edge exploitation spiked across three sectors this week.',
      'The driver is an authentication bypass in a widely deployed VPN product.',
    ].join('\n');
    (runCompletion as any).mockImplementation(async () => ({ text: body, modelUsed: 'mock' }));
    const res = await generateLinkedinContent(mockPost, {} as never, new Date());
    expect(res.linkedin).toContain('Edge exploitation spiked');
  });
});
