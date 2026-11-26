import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { registerAdminRoutes } from '../../src/routes/case-study-admin';

/**
 * End-to-end contract for the admin "Generate" tab.
 *
 * Pins three regressions together: pasted URLs/CVE ids must reach the research
 * stage, notes must appear once in the blog path, and one research pass must
 * be shared by every requested format with its measurements in the response.
 */

const seen: {
  research: any[];
  generate: any[];
  social: any[];
  dossier: any[];
} = { research: [], generate: [], social: [], dossier: [] };

vi.mock('../../src/lib/ai-binding', () => ({ getAi: vi.fn(() => ({ run: vi.fn() })) }));

vi.mock('../../src/case-study/research', async () => {
  const actual = await vi.importActual<typeof import('../../src/case-study/research')>('../../src/case-study/research');
  return {
    ...actual,
    researchCandidate: vi.fn(async (deps: any) => {
      seen.research.push(deps);
      const { buildDossier } = await vi.importActual<typeof import('../../src/case-study/research/build')>(
        '../../src/case-study/research/build'
      );
      const dossier = buildDossier({
        type: deps.candidate.type,
        title: deps.candidate.title,
        rationale: deps.candidate.rationale,
        evidence: deps.candidate.evidence ?? {},
        cves: [],
        pages: [],
        platform: { writeups: [], relatedCves: [], trendingCves: [], actors: [], victimClaims: [] },
        unread: [],
        now: deps.now,
      });
      seen.dossier.push(dossier);
      return dossier;
    }),
  };
});

vi.mock('../../src/case-study/generation', async () => {
  const actual = await vi.importActual<typeof import('../../src/case-study/generation')>(
    '../../src/case-study/generation'
  );
  return {
    ...actual,
    generatePost: vi.fn(async (deps: any) => {
      seen.generate.push(deps);
      return {
        slug: 'custom-examplecorp-gateway-flaw',
        title: deps.candidate.title,
        body: 'A'.repeat(600),
        type: deps.candidate.type,
        publishedAt: deps.now.toISOString(),
        candidateId: deps.candidate.key,
        hero: '<svg/>',
        iocs: [],
        tags: [deps.candidate.type],
        sources: [],
        evidence: deps.candidate.evidence,
        // Production generatePost snapshots the dossier it was given; mirror
        // that so both surfaces report the same research measurements.
        researchMeta: deps.dossier?.meta,
      };
    }),
  };
});

vi.mock('../../src/case-study/generation/social', async () => {
  const actual = await vi.importActual<typeof import('../../src/case-study/generation/social')>(
    '../../src/case-study/generation/social'
  );
  return {
    ...actual,
    generateLinkedinFromNotes: vi.fn(async (src: any) => {
      seen.social.push(src);
      return { linkedin: 'L'.repeat(500), generatedAt: '' };
    }),
    generateTwitterFromNotes: vi.fn(async (src: any) => {
      seen.social.push(src);
      return { twitter: 'T'.repeat(200), generatedAt: '' };
    }),
  };
});

vi.mock('../../src/case-study/storage/drafts', async () => {
  const actual = await vi.importActual<typeof import('../../src/case-study/storage/drafts')>(
    '../../src/case-study/storage/drafts'
  );
  return { ...actual, putDraft: vi.fn(async () => {}) };
});

function app() {
  const a = new Hono<any>();
  registerAdminRoutes(a);
  return a;
}

function env() {
  return {
    CASE_STUDIES: {
      get: async () => null,
      put: async () => {},
      delete: async () => {},
      list: async () => ({ keys: [], list_complete: true, cursor: '' }),
    },
    ADMIN_TOKEN: 'sekret',
    INTERNAL_TOKEN_SECRET: 'test-secret',
  } as any;
}

beforeEach(() => {
  vi.clearAllMocks();
  seen.research.length = 0;
  seen.generate.length = 0;
  seen.social.length = 0;
  seen.dossier.length = 0;
});

describe('POST /api/v1/admin/generate', () => {
  it('routes pasted sources into research and shares one dossier with every format', async () => {
    const res = await app().request(
      '/api/v1/admin/generate',
      {
        method: 'POST',
        headers: { 'X-Admin-Token': 'sekret', 'content-type': 'application/json' },
        body: JSON.stringify({
          topic: 'Examplecorp gateway flaw',
          content: 'CVE-2099-0001 — read https://example.test/advisory for the vendor note.',
          notes: 'Emphasise patching.',
          audience: 'SOC analysts',
          tone: 'professional',
          type: 'analysis',
          formats: ['blog', 'linkedin', 'twitter'],
          dry_run: true,
        }),
      },
      env()
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.errors).toBeUndefined();

    // Pasted inputs became research evidence, not just prompt prose.
    expect(seen.research).toHaveLength(1);
    const candidate = seen.research[0].candidate;
    expect(candidate.evidence.urls).toEqual(['https://example.test/advisory']);
    expect(candidate.evidence.cveIds).toEqual(['CVE-2099-0001']);
    expect(candidate.evidence.userContent).toContain('SOC analysts');
    // Notes go to the writer via `deps.notes`, not duplicated in the dossier.
    expect(candidate.evidence.userContent).not.toContain('<admin_notes>');

    // One research pass, shared verbatim with the blog and both social calls.
    expect(seen.generate).toHaveLength(1);
    expect(seen.generate[0].dossier).toBe(seen.dossier[0]);
    expect(seen.generate[0].notes).toBe('Emphasise patching.');
    expect(seen.social).toHaveLength(2);
    expect(seen.social.every((s) => s.dossier === seen.dossier[0])).toBe(true);
    // Social still receives the notes in its own body.
    expect(seen.social[0].body).toContain('<admin_notes>');

    // Measurements are visible for every format, not only the blog, and
    // all three report the same research pass.
    const meta = seen.dossier[0].meta;
    expect(body.result.blog.research).toEqual(meta);
    expect(body.result.linkedin.research).toEqual(meta);
    expect(body.result.twitter.research).toEqual(meta);
  });
});
