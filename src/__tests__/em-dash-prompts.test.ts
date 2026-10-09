import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { countConnectorEmDashes, NO_EM_DASH_RULE } from '../../api/src/lib/prose-style';

/**
 * Prompt hygiene for generated prose.
 *
 * The case-study prompts used to contain ~45 connector em dashes in their own
 * prose and worked examples while simultaneously telling the model not to use
 * them. Models imitate the examples, so the instruction was self-contradicting
 * and the post-processor had to repair the output on every publish.
 *
 * This lives in the root (Node) suite rather than the API suite because it
 * reads source files, which the `@cloudflare/vitest-pool-workers` sandbox does
 * not permit.
 *
 * The citation-format specifiers are the deliberate exception: they describe
 * the shape of generated output (`- [Source](url) - description`) and must keep
 * their dash.
 */

const GEN_DIR = resolve(process.cwd(), 'api/src/case-study/generation');
/**
 * `hook-variants.ts` was removed by the case-study pipeline rework
 * (896f5a745) — its hooks now live in `copywriting.ts`. Leaving it listed here
 * made this test fail on a missing file instead of on real prompt hygiene.
 */
const PROMPT_FILES = ['copywriting.ts', 'templates.ts', 'index.ts'] as const;

const readGen = (file: string) => readFileSync(resolve(GEN_DIR, file), 'utf8');

/**
 * Only template-literal lines, so JSDoc and `//` comments are ignored.
 *
 * The surrounding backticks and `+` continuation markers are stripped before
 * checking: they are TypeScript syntax, not prompt content, and leaving them
 * on defeats the structural guards (`    * NVD - only if ...` is a citation
 * list item; with a backtick in front it no longer parses as a list item).
 */
const promptLines = (file: string) =>
  readGen(file)
    .split('\n')
    .filter((l) => l.trim().startsWith('`'))
    .map((l) =>
      l
        .trim()
        .replace(/^`+/, '')
        .replace(/`\s*\+\s*$/, '')
        .replace(/`\s*;?\s*$/, '')
    );

describe('case-study prompts do not teach the em-dash habit', () => {
  it('splices the shared rule into the assembled system prompt', () => {
    expect(readGen('templates.ts')).toContain('NO_EM_DASH_RULE');
  });

  for (const file of PROMPT_FILES) {
    it(`${file} has no connector em dash in prompt prose`, () => {
      const offenders = promptLines(file).filter((l) => countConnectorEmDashes(l) > 0);
      expect(offenders, `${file} still teaches em-dash connectors:\n    ${offenders.join('\n    ')}`).toEqual([]);
    });
  }

  it('keeps the citation-format dashes the generated output depends on', () => {
    const source = readGen('templates.ts');
    // The bullet shape's "label — description" dash is a definition pair, which
    // NO_EM_DASH_RULE explicitly permits. It is load-bearing: post-process reads
    // the description off the far side of that dash.
    expect(source).toContain('— one-line description of what the source establishes');
    expect(source).toMatch(/NVD and CISA KEV entries are worth citing only when/);
  });

  /**
   * `stripUnknownRefHosts` only runs when the body carries a `##`-level
   * References-style heading. The rework stopped mandating section headings,
   * which silently skipped the citation allowlist — so the prompt has to name
   * the shape the validator keys on.
   */
  it('names the references heading the citation allowlist keys on', () => {
    expect(readGen('templates.ts')).toMatch(/^## References$/m);
  });
});

describe('prose prompts outside case studies carry the rule', () => {
  const WIRED = [
    'api/src/lib/ai-summary.ts',
    'api/src/routes/research-digest.ts',
    'api/src/routes/ti-ai-analysis.ts',
    'api/src/case-study/generation/templates.ts',
  ] as const;

  for (const file of WIRED) {
    it(`${file} references the shared rule`, () => {
      const src = readFileSync(resolve(process.cwd(), file), 'utf8');
      expect(src.includes('NO_EM_DASH_RULE'), file).toBe(true);
    });
  }

  it('every prose surface also strips on the way out', () => {
    for (const file of [
      'api/src/lib/ai-summary.ts',
      'api/src/routes/research-digest.ts',
      'api/src/routes/ti-ai-analysis.ts',
      'api/src/case-study/generation/post-process.ts',
    ]) {
      const src = readFileSync(resolve(process.cwd(), file), 'utf8');
      expect(src, `${file} injects but does not strip`).toContain('stripConnectorEmDashes');
    }
  });

  it('keeps the blanket dash-to-comma codemod out of the codebase', () => {
    // The old case-study regex rewrote a table cell's missing-value glyph into
    // ", ", which PRODUCT.md calls out as corruption. Nothing should reintroduce
    // a blanket em/en-dash -> ", " replacement.
    for (const file of [
      'api/src/case-study/generation/post-process.ts',
      'api/src/lib/ai-summary.ts',
      'api/src/lib/prose-style.ts',
    ]) {
      const src = readFileSync(resolve(process.cwd(), file), 'utf8');
      expect(src, `${file} reintroduced a blanket dash replace`).not.toMatch(
        /\[[^\]]*[\u2014\u2013][^\]]*\]\s*,\s*['"]\s*,\s*['"]/
      );
    }
  });
});

describe('NO_EM_DASH_RULE content', () => {
  it('states the prohibition and the exceptions', () => {
    expect(NO_EM_DASH_RULE).toMatch(/do not use em dashes/i);
    expect(NO_EM_DASH_RULE).toMatch(/sentence connector/i);
    expect(NO_EM_DASH_RULE).toMatch(/table/i);
    expect(NO_EM_DASH_RULE).toMatch(/range/i);
  });
});
