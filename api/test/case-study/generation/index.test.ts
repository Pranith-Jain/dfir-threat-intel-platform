import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Candidate } from '../../../src/case-study/types';
import type { LinkStatus } from '../../../src/lib/verify-url';

beforeEach(() => {
  vi.clearAllMocks();
});

vi.mock('../../../src/case-study/generation/ai-client', async () => {
  const actual = await vi.importActual('../../../src/case-study/generation/ai-client');
  return {
    ...(actual as Record<string, unknown>),
    runCompletion: vi.fn(),
  };
});

/**
 * The research stage performs real network calls (NVD/KEV/EPSS via
 * `lookupCve`, plus page fetches). Stub it so the generation path stays
 * hermetic — the research module has its own unit tests.
 */
vi.mock('../../../src/case-study/research', async () => {
  const actual = await vi.importActual<typeof import('../../../src/case-study/research')>(
    '../../../src/case-study/research'
  );
  return {
    ...(actual as unknown as Record<string, unknown>),
    researchCandidate: vi.fn(async ({ candidate }: { candidate: Candidate }) => {
      const { buildDossier } = await vi.importActual<typeof import('../../../src/case-study/research/build')>(
        '../../../src/case-study/research/build'
      );
      return buildDossier({
        type: candidate.type,
        title: candidate.title,
        rationale: candidate.rationale,
        evidence: candidate.evidence,
        cves: [],
        pages: [
          {
            url: 'https://blog.talosintelligence.com/vuln/synthetic-fixture',
            ok: true,
            status: 200,
            title: 'Synthetic vendor patches an authentication bypass',
            publisher: 'blog.talosintelligence.com',
            publishedAt: '2026-08-06',
            text: 'The vendor shipped a fix.',
          },
        ],
        platform: { writeups: [], relatedCves: [], trendingCves: [], actors: [], darkweb: [] },
        unread: [],
        now: new Date(),
      });
    }),
  };
});

// Hermetic reference verifier: treat every URL as resolving so unit tests
// never issue real HEAD requests. Tests that exercise pruning pass a stub.
const allOk = async (urls: string[]) => new Map<string, LinkStatus>(urls.map((u) => [u, 'ok']));

/** Synthetic, well-formed, non-existent. Keeps fixtures from rotting. */
const SYNTHETIC_CVE = 'CVE-2099-0001';

const candidate: Candidate = {
  key: `cve-${SYNTHETIC_CVE}`,
  type: 'cve',
  title: `${SYNTHETIC_CVE} — synthetic vendor auth bypass`,
  rationale: 'Listed in CISA KEV',
  score: 0.9,
  evidence: { cveId: SYNTHETIC_CVE, vendor: 'ExampleCorp', product: 'EdgeGateway' },
  discoveredAt: '2026-05-14T06:00:00Z',
  status: 'approved',
};

const goodMd = [
  'An authentication bypass on an internet-facing management plane is close to a worst case.',
  '## Summary',
  `${SYNTHETIC_CVE} lets an unauthenticated attacker reach the management plane as a privileged user. KEV placement means exploitation is observed, not theoretical.`,
  '## Affected products',
  'EdgeGateway builds before 7.4.5 on the affected branch are in scope. The fixed build closes the bypass cleanly.',
  '## How it works',
  'The authentication decision can be skipped by a crafted management request, so the access check never runs.',
  '## Detection and mitigation',
  'Apply 7.4.5 on the KEV due-date schedule and remove the management interface from the public internet first.',
  '## References',
  '- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)',
  `- [NVD record](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE})`,
].join('\n\n');

describe('generatePost', () => {
  it('produces a complete Post for an approved candidate', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date('2026-05-19T15:05:00Z'),
      verifyRefs: allOk,
    });
    // slug = candidate.key + slugified title
    expect(post.slug.startsWith(`cve-${SYNTHETIC_CVE}`)).toBe(true);
    expect(post.type).toBe('cve');
    expect(post.publishedAt).toBe('2026-05-19T15:05:00.000Z');
    expect(post.body).toContain('## Summary');
    expect(post.hero).toContain('<svg');
    expect(post.excerpt.length).toBeGreaterThan(0);
    expect(post.candidateId).toBe(`cve-${SYNTHETIC_CVE}`);
  });

  it('runs the research stage before the writer', async () => {
    // The pipeline order is the point of the rewrite: research first, then
    // write. Previously the first LLM call was a "fact extract" pass over raw
    // JSON, which is where invented details entered.
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { researchCandidate } = await import('../../../src/case-study/research');
    const { generatePost } = await import('../../../src/case-study/generation/index');

    (researchCandidate as any).mockClear();
    await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date(),
      verifyRefs: allOk,
    });
    expect(researchCandidate).toHaveBeenCalledTimes(1);
    // One LLM call total: the writer. The pre-generation fact-extract pass
    // and the QA-triggered repair pass are both gone.
    expect(runCompletion).toHaveBeenCalledTimes(1);
  });

  it('feeds the writer a prompt containing the research dossier', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    await generatePost({ candidate, ai: { run: vi.fn() } as never, now: new Date(), verifyRefs: allOk });

    // runCompletion(ai, { system, user }, opts)
    const call = (runCompletion as any).mock.calls[0] as unknown[];
    const prompt = call[1] as { system: string; user: string };
    expect(prompt.user).toContain('<research_dossier>');
    expect(prompt.system).toMatch(/only source of facts/i);
  });

  it('throws when the output has no section headings', async () => {
    // The one structural failure that still blocks a publish.
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: 'Garbage with no sections.', modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    await expect(generatePost({ candidate, ai: { run: vi.fn() } as never, now: new Date() })).rejects.toThrow(
      /generation failed/i
    );
  });

  it('publishes a short-but-structured draft without a QA gate', async () => {
    // The removed QA gate failed anything under 160 words, which pushed the
    // model to pad. A terse factual answer now publishes.
    const terse = ['## Answer', 'Two actively exploited RCEs. The vendor fixed both on September 27.'].join('\n\n');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: terse, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date(),
      verifyRefs: allOk,
    });
    expect(post.body).toContain('## Answer');
  });

  it('reports factual counters in `audit` rather than a quality score', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date(),
      verifyRefs: allOk,
    });
    expect(post.audit).toBeDefined();
    expect(typeof post.audit?.words).toBe('number');
    expect(post.audit?.sections).toBeGreaterThan(1);
    // `quality` and `qa` are gone.
    expect(post).not.toHaveProperty('quality');
    expect(post).not.toHaveProperty('qa');
  });

  it('surfaces a CVE absent from the dossier as a warning, not a failure', async () => {
    const withStrayCve = goodMd + `\n\n## Context\n\nFor comparison, CVE-2099-9999 was a different bug entirely.`;
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: withStrayCve, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date(),
      verifyRefs: allOk,
    });
    expect(post.body).toContain('CVE-2099-9999');
    expect(post.audit?.warnings.join(' ')).toMatch(/not in the research dossier/i);
  });

  it('attaches an AI hero image + injects a body image when aiImages is enabled', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const ai = {
      run: vi.fn(async (model: string) => {
        if (typeof model === 'string' && model.includes('flux')) return { image: btoa('IMG') };
        return { response: goodMd };
      }),
    };
    const puts: Array<{ name: string; bytes: Uint8Array }> = [];
    const post = await generatePost({
      candidate,
      ai: ai as never,
      now: new Date('2026-05-19T15:05:00Z'),
      verifyRefs: allOk,
      aiImages: {
        enabled: true,
        put: async (_slug: string, name: string, bytes: Uint8Array) => {
          puts.push({ name, bytes });
        },
      },
    });
    expect(post.heroImageUrl).toBe(`/api/v1/blog-image/${post.slug}/hero`);
    expect(post.body).toContain(`/api/v1/blog-image/${post.slug}/body1`);
    expect(puts.map((p) => p.name).sort()).toEqual(['body1', 'hero']);
  });

  it('falls back to the SVG hero when image generation fails', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const ai = {
      run: vi.fn(async (model: string) => {
        if (typeof model === 'string' && model.includes('flux')) throw new Error('AI image down');
        return { response: goodMd };
      }),
    };
    const post = await generatePost({
      candidate,
      ai: ai as never,
      now: new Date('2026-05-19T15:05:00Z'),
      verifyRefs: allOk,
      aiImages: { enabled: true, put: async () => {} },
    });
    expect(post.heroImageUrl).toBeUndefined();
    expect(post.hero).toContain('<svg');
  });

  it('prunes a confirmed-broken reference URL from the published post body', async () => {
    const withBrokenRef = [
      goodMd,
      '- [Fabricated writeup](https://www.bleepingcomputer.com/news/security/this-slug-does-not-exist/)',
    ].join('\n');
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: withBrokenRef, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date('2026-05-19T15:05:00Z'),
      verifyRefs: async (urls) =>
        new Map(urls.map((u) => [u, u.includes('this-slug-does-not-exist') ? 'broken' : 'ok'] as const)),
    });
    expect(post.body).not.toContain('this-slug-does-not-exist');
    expect(post.body).toContain('## Summary');
  });

  it('records the link-verification outcome for the admin', async () => {
    const { runCompletion } = await import('../../../src/case-study/generation/ai-client');
    (runCompletion as any).mockResolvedValue({ text: goodMd, modelUsed: 'mock' });
    const { generatePost } = await import('../../../src/case-study/generation/index');
    const post = await generatePost({
      candidate,
      ai: { run: vi.fn() } as never,
      now: new Date(),
      verifyRefs: allOk,
    });
    expect(post.linkVerification?.checked).toBeGreaterThan(0);
    expect(post.linkVerification?.broken).toBe(0);
  });
});
