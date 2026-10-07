import { describe, it, expect } from 'vitest';
import { renderMarkdown } from '../dfir/report-view-helpers';

/**
 * `renderMarkdown` is a hand-rolled markdown pipeline whose output is written
 * straight into `dangerouslySetInnerHTML` (ReportView, Cairn, Denali). Its
 * input is LLM agent output that quotes untrusted third-party text — leak-site
 * titles, Telegram captions, CVE descriptions — so it is attacker-influenced.
 *
 * These tests assert on the PARSED DOM rather than on substrings: a payload
 * only matters if the browser actually builds an element out of it, and the
 * closing `>` for a stripped tag can come from a wrapper the pipeline itself
 * emits.
 */
const parse = (html: string): Document => new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html');

describe('renderMarkdown XSS hardening', () => {
  it('never builds an element from an unclosed tag in prose', () => {
    // The closing `>` is supplied by the <p> wrapper the pipeline emits, so
    // stripHtmlTags' "remove well-formed tags" pass cannot see it.
    const html = renderMarkdown('Victim listed on a leak site: foo <img src=x onerror=alert(1)');
    const doc = parse(html);

    expect(doc.querySelectorAll('img')).toHaveLength(0);
    expect(doc.querySelector('[onerror]')).toBeNull();
    expect(html).not.toMatch(/<img/i);
  });

  it('never builds an element from an unclosed tag inside a bullet', () => {
    // Same payload, but the <li> wrapper closes it — the exact path that made
    // tag-stripping alone insufficient.
    const html = renderMarkdown('- leak title <svg onload=alert(1)');
    const doc = parse(html);

    expect(doc.querySelectorAll('li')).toHaveLength(1);
    expect(doc.querySelectorAll('svg')).toHaveLength(0);
    expect(doc.querySelector('[onload]')).toBeNull();
  });

  it('never builds an element from an unclosed tag inside a table cell', () => {
    const html = renderMarkdown('| Type | Value |\n| --- | --- |\n| domain | x <img src=x onerror=alert(1) |');
    const doc = parse(html);

    expect(doc.querySelectorAll('img')).toHaveLength(0);
    expect(doc.querySelector('[onerror]')).toBeNull();
  });

  it('neutralises well-formed script tags', () => {
    const html = renderMarkdown('<script>alert(1)</script>harmless');
    const doc = parse(html);

    expect(doc.querySelectorAll('script')).toHaveLength(0);
    expect(doc.body.textContent).not.toContain('alert(1)');
  });

  it('escapes rather than drops angle brackets, so payloads render as text', () => {
    const html = renderMarkdown('if a < b and b > c then');
    expect(html).toContain('&lt;');
    expect(html).toContain('&gt;');
    expect(parse(html).body.textContent).toContain('if a < b and b > c then');
  });

  it('still renders markdown to HTML', () => {
    const html = renderMarkdown('## Heading\n\nSome **bold** text.\n\n- one\n- two\n\n### For CTI\n- intel');
    const doc = parse(html);

    expect(doc.querySelectorAll('h2')).toHaveLength(1);
    expect(doc.querySelector('h2')?.textContent).toBe('Heading');
    expect(doc.querySelectorAll('strong')).toHaveLength(1);
    expect(doc.querySelectorAll('li')).toHaveLength(3);
    expect(doc.querySelector('[data-stakeholder="cti"]')).not.toBeNull();
  });

  it('renders fenced code blocks without double-escaping', () => {
    const html = renderMarkdown('```bash\ncurl -d "x & y" if a < b\n```');
    const doc = parse(html);

    const pre = doc.querySelector('pre');
    expect(pre).not.toBeNull();
    // Exactly one level of escaping: the DOM text is the original source.
    expect(pre!.querySelector('code')!.textContent).toBe('curl -d "x & y" if a < b');
    // And the raw output carries no stray entities that would double-decode.
    expect(html).toContain('&lt;');
    expect(html).not.toContain('&amp;lt;');
    expect(html).not.toContain('&amp;amp;');
  });

  it('keeps comparisons in prose instead of deleting them as if they were tags', () => {
    // Regression: the old strip pass matched any `<...>`, so `a < b and b > c`
    // lost everything between the brackets.
    const html = renderMarkdown('patch if a < b and b > c');
    expect(parse(html).body.textContent).toContain('patch if a < b and b > c');
  });
});
