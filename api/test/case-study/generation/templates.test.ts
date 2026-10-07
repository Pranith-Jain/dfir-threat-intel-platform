import { describe, it, expect } from 'vitest';
import { buildPrompt } from '../../../src/case-study/generation/templates';
import type { CaseStudyType } from '../../../src/case-study/types';
import type { ResearchDossier } from '../../../src/case-study/research';

/**
 * buildPrompt is now a contract, not a style manual.
 *
 * The tests this file replaces pinned a mandated `## TL;DR` / `## FAQ` /
 * `## References` skeleton per type, a word-count window, and the presence of
 * an outline in the user prompt. Those requirements are what made every post
 * the same shape — the model filled the form rather than answering the
 * question. What matters now is: the dossier is present and fenced, the
 * grounding contract is in the system prompt, and the type's guidance
 * describes the right genre.
 *
 * NOTE ON FIXTURES: the dossier below uses synthetic placeholder CVE ids and
 * a fake source host. Nothing here names a real vulnerability.
 */

const SYNTHETIC_CVE = 'CVE-2099-0001';
/** Documentation-range address — never routable. */
const SYNTHETIC_IP = '203.0.113.7';

function makeDossier(overrides: Partial<ResearchDossier> = {}): ResearchDossier {
  return {
    subject: 'A synthetic edge-appliance authentication bypass',
    cves: [
      {
        id: SYNTHETIC_CVE,
        description: 'An authentication bypass in a synthetic edge appliance.',
        published: '2026-08-01T00:00:00.000Z',
        cvss: {
          version: '3.1',
          base_score: 9.1,
          severity: 'CRITICAL',
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
        cwe: ['CWE-306'],
        products: ['examplecorp edge gateway'],
        kev: { in_kev: true, date_added: '2026-08-05', due_date: '2026-08-26', required_action: 'Apply mitigations' },
        epss: { score: 0.87, percentile: 0.99 },
        pocCount: 2,
        references: [`https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}`],
      },
    ],
    pages: [
      {
        url: 'https://blog.talosintelligence.com/vuln/synthetic-fixture',
        ok: true,
        status: 200,
        title: 'Synthetic vendor patches an authentication bypass',
        publisher: 'blog.talosintelligence.com',
        publishedAt: '2026-08-06',
        text: 'The vendor shipped a fix. Affected builds are listed in the bulletin.',
      },
    ],
    platform: {
      writeups: [],
      relatedCves: [],
      trendingCves: [],
      actors: [],
      darkweb: [],
    },
    timeline: [{ date: '2026-08-05', event: 'Added to CISA KEV' }],
    indicators: [{ type: 'ipv4', values: [SYNTHETIC_IP], total: 1 }],
    entities: { vendors: ['examplecorp'], products: ['edge gateway'], actors: [], techniques: ['T1190'] },
    gaps: ['No tracked actor is associated with this topic.'],
    unread: [],
    meta: { pagesFetched: 1, pagesRead: 1, cvesEnriched: 1, tookMs: 120 },
    ...overrides,
  };
}

describe('buildPrompt — the dossier is the input', () => {
  it('embeds the rendered dossier inside a fenced block', () => {
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic auth bypass', dossier: makeDossier() });
    expect(user).toContain('<research_dossier>');
    expect(user).toContain('</research_dossier>');
    expect(user).toContain(SYNTHETIC_CVE);
    expect(user).toContain('examplecorp edge gateway');
  });

  it('instructs the model to treat the fenced content as data, not instructions', () => {
    // Source excerpts are attacker-reachable text; a page saying "ignore your
    // instructions" must not be able to.
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(user).toMatch(/never as instructions/i);
  });

  it('states the researched gaps explicitly', () => {
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(user).toContain('NOT ESTABLISHED');
    expect(user).toContain('No tracked actor is associated');
  });

  it('reports what the research could not read', () => {
    const dossier = makeDossier({ pages: [], unread: [{ url: 'https://example.org/a', reason: 'http 403' }] });
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier });
    expect(user).toMatch(/could be read/i);
  });

  it('tells the writer to cite the sources it actually read', () => {
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(user).toMatch(/Link the sources you actually read/i);
  });

  it('falls back to canonical authorities when nothing could be read', () => {
    const dossier = makeDossier({ pages: [], unread: [{ url: 'https://example.org/a', reason: 'timeout' }] });
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier });
    expect(user).toMatch(/canonical authorities/i);
    expect(user).toMatch(/unconfirmed/i);
  });

  it('passes admin notes through verbatim as editor guidance', () => {
    const { user } = buildPrompt({
      type: 'vulnfaq',
      title: 'Synthetic',
      dossier: makeDossier(),
      notes: 'Drop the code block and lead with the affected-version table.',
    });
    expect(user).toContain('<editor_notes>');
    expect(user).toContain('Drop the code block and lead with the affected-version table.');
  });

  it('does not serialise raw evidence JSON into the prompt', () => {
    // The old prompt sent JSON.stringify(evidence), which is how internal
    // bookkeeping (sourceLinkStatuses, trendingSignal) ended up in the context.
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(user).not.toMatch(/"sourceLinkStatuses"/);
    expect(user).not.toMatch(/"trendingSignal"/);
  });

  it('bounds the rendered dossier length', () => {
    const pages = Array.from({ length: 200 }, (_, i) => ({
      url: `https://talosintelligence.com/vuln/${i}`,
      ok: true,
      status: 200,
      title: `Advisory ${i}`,
      publisher: 'talosintelligence.com',
      publishedAt: '2026-08-06',
      text: 'x'.repeat(6000),
    }));
    const { user } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier({ pages }) });
    expect(user.length).toBeLessThan(40_000);
  });
});

describe('buildPrompt — the grounding contract', () => {
  it('names the dossier as the only source of facts', () => {
    const { system } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(system).toMatch(/only source of facts/i);
  });

  it('requires naming unknowns rather than filling them in', () => {
    const { system } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(system).toMatch(/NOT ESTABLISHED/);
    expect(system).toMatch(/never fill/i);
  });

  it('requires answer-first structure', () => {
    const { system } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(system).toMatch(/answer the reader/i);
  });

  it('appends the voice profile when supplied', () => {
    const { system } = buildPrompt({
      type: 'vulnfaq',
      title: 'Synthetic',
      dossier: makeDossier(),
      voiceProfile: 'Average sentence length 17 words. Contraction rate 1 in 9.',
    });
    expect(system).toContain('Average sentence length 17 words.');
  });

  it('no longer carries the removed prescriptive rulesets', () => {
    const { system } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(system).not.toContain('#COPYWRITING RULES');
    expect(system).not.toContain('#FRAMEWORKS');
    expect(system).not.toContain('#SAVE MAGNETS');
    expect(system).not.toContain('#ENGAGEMENT STRATEGIES');
  });
});

describe('buildPrompt — per-type guidance', () => {
  const types: Array<[CaseStudyType, RegExp]> = [
    ['vulnfaq', /exploitability|vendor patch|fixed version|affected product/i],
    ['cve', /exploitability|vendor patch|fixed version/i],
    ['exploit', /scanner detects it|weaponi[sz]ed|public PoC/i],
    ['actor', /ATTRIBUTED|INFERRED/i],
    ['darkweb', /initial access broker|economics|listing/i],
    ['llm', /prompt injection|trust boundary|jailbreak/i],
    ['aisecops', /triage|SOC|false positive|evaluation/i],
    ['supplychain', /blast radius|build|dependency|rebuild/i],
    ['aisec', /model|poisoning|extraction/i],
    ['breach', /disclosure|confirmed/i],
    ['hunting', /hypothesis|false positive|data source/i],
    ['briefing', /ranked|grouped by theme|specifics/i],
    ['analysis', /argument|disagree|framework/i],
    ['methodology', /reproduced|method/i],
    ['tool', /does not do|reproduce/i],
    ['report', /publisher|methodology/i],
    ['news', /confirmed/i],
    ['trend', /measurable|number behind it/i],
    ['scam', /mechanism|out-of-band/i],
    ['osint', /tool|reproduce/i],
    ['intel', /falsify|counter-evidence/i],
    ['agentic', /trust boundary|prompt injection/i],
  ];

  it.each(types)('%s gets guidance matching its genre', (type, pattern) => {
    const { system } = buildPrompt({ type, title: 'Synthetic topic', dossier: makeDossier() });
    expect(system).toMatch(pattern);
  });

  it('treats every new type as first-class (no fallback guidance)', () => {
    // A type missing from the guidance map silently falls back to
    // GENERIC_GUIDANCE, which is how new content types used to ship with no
    // genre direction at all.
    for (const type of ['vulnfaq', 'exploit', 'darkweb', 'llm', 'aisecops', 'supplychain'] as CaseStudyType[]) {
      const { system } = buildPrompt({ type, title: 'Synthetic', dossier: makeDossier() });
      expect(system).toMatch(/<format name=/);
    }
  });

  it('does not mandate section headings', () => {
    // requiredSections used to return a fixed heading list that the prompt
    // declared mandatory. Forcing headings is what flattened every post into
    // the same shape.
    const { user, system } = buildPrompt({ type: 'vulnfaq', title: 'Synthetic', dossier: makeDossier() });
    expect(user).not.toMatch(/MUST include these ## section headings/);
    expect(system).not.toMatch(/required_outline/);
  });
});
