import { describe, it, expect } from 'vitest';
import { extractPage } from '../../../src/case-study/research/extract';

/**
 * HTML → readable text extraction.
 *
 * The point of this stage is that the writer sees what a source actually
 * says, so these tests pin the behaviours that make that true: page chrome is
 * dropped, the article survives, and metadata is captured for attribution.
 *
 * `HTMLRewriter` is a Workers global. Under the vitest-pool-workers runtime it
 * is available, so these run against the real parser rather than a stub.
 */

/** Minimal page with realistic chrome around a short article. */
const ARTICLE_HTML = `<!doctype html>
<html>
<head>
  <title>Vendor patches authentication bypass | Example Corp</title>
  <meta property="og:title" content="Vendor patches authentication bypass in edge gateway" />
  <meta property="article:published_time" content="2026-08-06T09:30:00Z" />
  <style>.x{color:red}</style>
  <script>window.tracking = true;</script>
</head>
<body>
  <nav class="masthead"><a href="/">Home</a><a href="/blog">Blog</a></nav>
  <article>
    <h1>Vendor patches authentication bypass</h1>
    <p>The vendor shipped a fix for an authentication bypass affecting builds before 7.4.5.</p>
    <p>CISA added the CVE to the Known Exploited Vulnerabilities catalog the same day.</p>
    <h2>Affected builds</h2>
    <ul><li>EdgeGateway before 7.4.5</li><li>EdgeGateway LTS before 7.2.9</li></ul>
  </article>
  <aside class="related"><h3>Related</h3><a href="/x">Other post</a></aside>
  <div class="newsletter-signup">Subscribe to our newsletter</div>
  <footer>Copyright 2026</footer>
</body>
</html>`;

function fakeFetch(body: string, status = 200, contentType = 'text/html; charset=utf-8') {
  return (async () =>
    new Response(body, { status, headers: { 'content-type': contentType } })) as unknown as typeof globalThis.fetch;
}

describe('extractPage — article content', () => {
  it('captures title, publisher and publication date', async () => {
    const page = await extractPage('https://vendor.example.com/advisory/1', fakeFetch(ARTICLE_HTML));
    expect(page.ok).toBe(true);
    // og:title wins over <title>.
    expect(page.title).toBe('Vendor patches authentication bypass in edge gateway');
    expect(page.publisher).toBe('vendor.example.com');
    expect(page.publishedAt).toBe('2026-08-06');
  });

  it('keeps the article paragraphs and heading text', async () => {
    const page = await extractPage('https://vendor.example.com/advisory/1', fakeFetch(ARTICLE_HTML));
    expect(page.text).toContain('shipped a fix for an authentication bypass');
    expect(page.text).toContain('Known Exploited Vulnerabilities catalog');
    expect(page.text).toContain('EdgeGateway before 7.4.5');
  });

  it('drops nav, aside, newsletter and footer chrome', async () => {
    const page = await extractPage('https://vendor.example.com/advisory/1', fakeFetch(ARTICLE_HTML));
    expect(page.text).not.toContain('Subscribe to our newsletter');
    expect(page.text).not.toContain('Other post');
    expect(page.text).not.toContain('Copyright 2026');
    expect(page.text).not.toContain('window.tracking');
  });

  it('returns the title from <title> when og:title is absent', async () => {
    const html = `<html><head><title>Plain title here</title></head><body><article><p>${'Body text. '.repeat(40)}</p></article></body></html>`;
    const page = await extractPage('https://vendor.example.com/a', fakeFetch(html));
    expect(page.title).toBe('Plain title here');
  });

  it('falls back to the first h1 when no title tag exists', async () => {
    const html = `<html><body><article><h1>Heading is the only title</h1><p>${'Body text. '.repeat(40)}</p></article></body></html>`;
    const page = await extractPage('https://vendor.example.com/a', fakeFetch(html));
    expect(page.title).toBe('Heading is the only title');
  });
});

describe('extractPage — failure modes are non-fatal', () => {
  it('reports a 404 rather than throwing', async () => {
    const page = await extractPage('https://vendor.example.com/gone', fakeFetch('Not found', 404, 'text/plain'));
    expect(page.ok).toBe(false);
    expect(page.error).toContain('404');
    expect(page.text).toBe('');
  });

  it('reports a script-rendered shell as unreadable', async () => {
    // A page that yields no title and almost no text is one the writer never
    // actually read. Reporting ok would let it be cited anyway.
    const html = `<html><head><script>render()</script></head><body><div id="app"></div></body></html>`;
    const page = await extractPage('https://spa.example.com/a', fakeFetch(html));
    expect(page.ok).toBe(false);
    expect(page.error).toMatch(/no readable content/i);
  });

  it('rejects a non-http url without fetching', async () => {
    let called = false;
    const page = await extractPage('ftp://vendor.example.com/a', (async () => {
      called = true;
      return new Response('');
    }) as unknown as typeof globalThis.fetch);
    expect(page.ok).toBe(false);
    expect(page.error).toMatch(/not an http/i);
    expect(called).toBe(false);
  });

  it('survives a network throw', async () => {
    const page = await extractPage('https://vendor.example.com/a', (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof globalThis.fetch);
    expect(page.ok).toBe(false);
    expect(page.error).toContain('ECONNREFUSED');
  });

  it('rejects an unsupported content type', async () => {
    const page = await extractPage('https://vendor.example.com/a.pdf', fakeFetch('%PDF-1.4', 200, 'application/pdf'));
    expect(page.ok).toBe(false);
    expect(page.error).toMatch(/unsupported content-type/i);
  });

  it('handles a plain-text body', async () => {
    const page = await extractPage(
      'https://vendor.example.com/notes.txt',
      fakeFetch('Affected builds before 7.4.5.', 200, 'text/plain')
    );
    expect(page.ok).toBe(true);
    expect(page.text).toContain('7.4.5');
  });
});

describe('extractPage — bounds', () => {
  it('caps the extracted text length', async () => {
    const huge = `<html><head><title>Huge</title></head><body><article>${'A very long sentence. '.repeat(20000)}</article></body></html>`;
    const page = await extractPage('https://vendor.example.com/a', fakeFetch(huge));
    expect(page.text.length).toBeLessThanOrEqual(6000);
  });
});
