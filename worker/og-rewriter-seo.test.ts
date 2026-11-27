/** Regression tests for the live SEO metadata fixes. */
import { describe, it, expect } from 'vitest';
import { injectSeoContent, normalizeCanonicals, rewriteHtml } from './og-rewriter';

const TWO_CANONICALS = `<html><head>
  <link rel="canonical" href="https://pranithjain.qzz.io/dfir" />
  </head><body><div id="root">
  <link rel="canonical" href="https://pranithjain.qzz.io/dfir"/>
  </div></body></html>`;

describe('canonical normalisation', () => {
  it('collapses two conflicting canonicals to the resolved one', () => {
    const out = normalizeCanonicals(TWO_CANONICALS, 'https://crucible.pranithjain.qzz.io/dfir');
    expect(out.match(/rel="canonical"/g)).toHaveLength(1);
    expect(out).toContain('href="https://crucible.pranithjain.qzz.io/dfir"');
    expect(out).not.toContain('href="https://pranithjain.qzz.io/dfir"');
  });

  it('injects a canonical when the page has none', () => {
    const out = normalizeCanonicals('<html><head><title>x</title></head><body></body></html>', 'https://site.test/x');
    expect(out.match(/rel="canonical"/g)).toHaveLength(1);
    expect(out).toContain('<link rel="canonical" href="https://site.test/x" /></head>');
  });

  it('rewriteHtml leaves exactly one canonical on a prerendered shell', () => {
    const out = rewriteHtml(TWO_CANONICALS, null, 'https://crucible.pranithjain.qzz.io/dfir');
    expect(out.match(/rel="canonical"/g)).toHaveLength(1);
  });
});

describe('thin-content SEO fallback', () => {
  it('does not add a second h1 to pages whose app renders its own', () => {
    const thin = '<main id="main-content"><div class="animate-fade-in-up">Loading…</div></main>';
    const out = injectSeoContent(thin, '/dfir');
    expect(out).toContain('seo-prerender');
    expect(out).not.toContain('<h1>');
    expect(out).toContain('<p class="font-semibold text-heading">');
  });

  it('leaves the home page and substantial SSR content untouched', () => {
    const rich = `<main id="main-content">${'x'.repeat(300)}</main>`;
    expect(injectSeoContent(rich, '/dfir')).toBe(rich);
    expect(injectSeoContent(rich, '/')).toBe(rich);
  });
});
