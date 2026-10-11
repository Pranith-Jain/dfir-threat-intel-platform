import { describe, it, expect } from 'vitest';
import { generateOgSvg } from '../../worker/og-image';
import { matchOgImagePath, matchOgPagePath, pageCardUrl } from '../../worker/og-path';
import { resolveOg, ogMetaForPath } from '../../worker/og-rewriter';

/**
 * Pins the OG-image card pipeline:
 *  - generateOgSvg must emit WELL-FORMED SVG (resvg's parser is strict; the
 *    old title markup rendered line-0 twice and broke rasterisation).
 *  - briefing stats are computed from sections/tags, not stored.
 *  - the route path matcher and the meta-rewriter wire the dynamic image URL.
 */

describe('generateOgSvg', () => {
  it('emits balanced <text>/<tspan> tags (no stray tspan outside text)', () => {
    const svg = generateOgSvg({
      title: 'A fairly long briefing title that wraps onto multiple lines for sure',
      subtitle: 'Subtitle here',
      type: 'briefing',
      date: '2026-06-12',
      stats: { findings: 14, cves: 6, critical: 3, high: 5 },
    });
    expect(svg.startsWith('<svg')).toBe(true);
    // Every <tspan> opens and closes, and there are as many </text> as <text.
    const openText = (svg.match(/<text\b/g) ?? []).length;
    const closeText = (svg.match(/<\/text>/g) ?? []).length;
    expect(openText).toBe(closeText);
    const openTspan = (svg.match(/<tspan\b/g) ?? []).length;
    const closeTspan = (svg.match(/<\/tspan>/g) ?? []).length;
    expect(openTspan).toBe(closeTspan);
    expect(openTspan).toBeGreaterThan(0);
  });

  it('renders the stats strip for briefings with stats', () => {
    const svg = generateOgSvg({
      title: 'T',
      subtitle: 'S',
      type: 'briefing',
      stats: { findings: 14, cves: 6, critical: 3, high: 5 },
    });
    expect(svg).toContain('>14<');
    expect(svg).toContain('FINDINGS');
    expect(svg).toContain('CRITICAL');
  });

  it('prioritises IOCs / KEVs / ransomware victims over the findings count in the stats strip', () => {
    const svg = generateOgSvg({
      title: 'T',
      subtitle: 'S',
      type: 'briefing',
      stats: { findings: 40, cves: 12, critical: 2, high: 9, iocs: 1482, kevs: 4, ransomware: 8 },
    });
    expect(svg).toContain('CRITICAL');
    expect(svg).toContain('VICTIMS');
    expect(svg).toContain('IOCs');
    expect(svg).toContain('KEVs');
    expect(svg).not.toContain('FINDINGS');
    expect(svg).toContain('>1,482<');
  });

  it('falls back to tag chips for blogs (no stats strip)', () => {
    const svg = generateOgSvg({ title: 'T', subtitle: 'S', type: 'blog', tags: ['detection', 'workers'] });
    expect(svg).toContain('detection');
    expect(svg).not.toContain('FINDINGS');
  });

  it('escapes XML-special characters in the title', () => {
    const svg = generateOgSvg({ title: 'A & B <script>', subtitle: '', type: 'blog' });
    expect(svg).toContain('A &amp; B &lt;script&gt;');
    expect(svg).not.toContain('<script>');
  });

  it('renders a page card with section-aware badge + product overrides', () => {
    const svg = generateOgSvg({
      title: 'CVE Check',
      subtitle: 'A free DFIR tool on pranithjain.qzz.io.',
      type: 'page',
      badge: 'DFIR TOOLKIT',
      product: 'PANOPTICON',
    });
    expect(svg).toContain('DFIR TOOLKIT');
    expect(svg).toContain('PANOPTICON');
    expect(svg).toContain('CVE Check');
  });
});

describe('matchOgImagePath', () => {
  it.each([
    ['/api/v1/og-image/briefing/daily-2026-06-12.png', { type: 'briefing', slug: 'daily-2026-06-12' }],
    ['/api/v1/og-image/blog/my-post.png', { type: 'blog', slug: 'my-post' }],
  ])('matches %s', (path, expected) => {
    expect(matchOgImagePath(path)).toEqual(expected);
  });

  it.each([
    '/api/v1/og-image/briefing/foo.svg', // wrong extension
    '/api/v1/og-image/unknown/foo.png', // unknown type
    '/api/v1/og-image/briefing/../etc.png', // path traversal chars
    '/api/v1/og-image/blog/.png', // empty slug
  ])('rejects %s', (path) => {
    expect(matchOgImagePath(path)).toBeNull();
  });
});

describe('matchOgPagePath', () => {
  it('decodes the route path from the slash-free dot form', () => {
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page/dfir.cve.png'))).toBe('/dfir/cve');
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page/about.png'))).toBe('/about');
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page/threatintel.correlation.png'))).toBe(
      '/threatintel/correlation'
    );
  });

  it('still accepts the percent-encoded path form (intermediate deploys)', () => {
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page/%2Fdfir%2Fcve.png'))).toBe('/dfir/cve');
  });

  it('still accepts the legacy ?p= form', () => {
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page.png?p=%2Fdfir%2Fcve'))).toBe('/dfir/cve');
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page.png?p=%2Fabout'))).toBe('/about');
  });

  it.each([
    'https://x/api/v1/og-image/page.png', // legacy endpoint without ?p=
    'https://x/api/v1/og-image/page.png?p=dfir', // not site-relative
    'https://x/api/v1/og-image/briefing/foo.png?p=%2Fdfir', // wrong pathname
    'https://x/api/v1/og-image/page/.png', // no segments
    'https://x/api/v1/og-image/page/dfir%40cve.png', // percent-encoded non-slash chars are not dot-encoded
  ])('rejects %s', (u) => {
    expect(matchOgPagePath(new URL(u))).toBeNull();
  });
});

describe('pageCardUrl', () => {
  it('round-trips a route path through the page-card URL', () => {
    const url = new URL(`https://x${pageCardUrl('/threatintel/feeds/threatfeeds')}`);
    expect(matchOgPagePath(url)).toBe('/threatintel/feeds/threatfeeds');
  });

  it('emits the versioned /og-image/v<build>/ prefix and round-trips it', () => {
    const u = pageCardUrl('/dfir/cve');
    expect(u).toMatch(/^\/og-image\/v[a-z0-9]+\/page\/dfir\.cve\.png$/);
    // No query strings, no %2F — both are fatal to X's image parser.
    expect(u).not.toContain('?');
    expect(u).not.toContain('%2F');
    // Round-trips through the handler's path matcher.
    expect(matchOgPagePath(new URL(`https://x${u}`))).toBe('/dfir/cve');
    // Legacy /api/v1/og-image/page/... form still resolves for old meta.
    expect(matchOgPagePath(new URL('https://x/api/v1/og-image/page/dfir.cve.png'))).toBe('/dfir/cve');
  });
});

describe('ogMetaForPath', () => {
  it('derives a unique title + section branding for a deep tool page', () => {
    const meta = ogMetaForPath('/dfir/cve');
    expect(meta?.title).toContain('CVE');
    expect(meta?.badge).toBe('DFIR TOOLKIT');
    expect(meta?.product).toBe('CRUCIBLE');
  });

  it('brands threat-intel pages as PANOPTICON', () => {
    expect(ogMetaForPath('/threatintel/telegram')?.product).toBe('PANOPTICON');
    expect(ogMetaForPath('/threatintel/telegram')?.badge).toBe('THREAT INTEL');
  });

  it('returns null for the home page (keeps the static home card)', () => {
    expect(ogMetaForPath('/')).toBeNull();
  });
});

describe('resolveOg dynamic image wiring', () => {
  it('points a blog page at its dynamic card', async () => {
    const env = { CASE_STUDIES: { get: async () => ({ title: 'Post', excerpt: 'x' }) } };
    const og = await resolveOg(new URL('https://pranithjain.qzz.io/blog/my-post'), env as never);
    expect(og?.image).toBe('/api/v1/og-image/blog/my-post.png');
  });

  it('points a briefing page at its dynamic card (image even on a D1 miss)', async () => {
    const env = { BRIEFINGS_DB: undefined };
    const og = await resolveOg(
      new URL('https://pranithjain.qzz.io/threatintel/briefings/daily-2026-06-12'),
      env as never
    );
    expect(og?.image).toBe('/api/v1/og-image/briefing/daily-2026-06-12.png');
  });

  it('gives a deep tool page its OWN unique page card (not the section card)', async () => {
    const og = await resolveOg(new URL('https://pranithjain.qzz.io/dfir/cve'), {} as never);
    // Versioned KV-backed card: /og-image/v<BUILD>/page/<dot>.png.
    expect(og?.image).toMatch(/^\/og-image\/v[a-z0-9]+\/page\/dfir\.cve\.png$/);
    expect(og?.title).toContain('CVE');
  });

  it('gives two sibling pages DIFFERENT cards', async () => {
    const a = await resolveOg(new URL('https://pranithjain.qzz.io/dfir/cve'), {} as never);
    const b = await resolveOg(new URL('https://pranithjain.qzz.io/dfir/domain-investigator'), {} as never);
    expect(a?.image).not.toBe(b?.image);
  });

  it('keeps the static branded card for a surface route (/dfir)', async () => {
    const og = await resolveOg(new URL('https://pranithjain.qzz.io/dfir'), {} as never);
    expect(og?.image).toContain('/og-dfir.png');
  });

  it('returns null for the home page (keeps index.html home card)', async () => {
    expect(await resolveOg(new URL('https://pranithjain.qzz.io/'), {} as never)).toBeNull();
  });
});
