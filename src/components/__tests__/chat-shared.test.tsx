import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../threatintel/ChatShared';

describe('ChatShared.renderMarkdown', () => {
  it('emits well-formed code blocks with a closed data-language attribute', () => {
    const html = renderMarkdown('```js\nconst x = 1;\n```');
    expect(html).toContain('<pre ');
    expect(html).toContain('data-language="js"');
    expect(html).toContain('<code ');
    // The old template had a stray quote before ${langAttr}, which left
    // data-language unclosed and swallowed the opening <code> tag.
    expect(html).not.toMatch(/my-2 "\s+data-language/);
    expect(html).toMatch(/data-language="[^"]*"><code /);
  });

  it('still emits a valid code block when no language is given', () => {
    const html = renderMarkdown('```\nplain\n```');
    expect(html).toMatch(/<pre class="[^"]*"><code /);
    expect(html).not.toContain('data-language');
  });
});
