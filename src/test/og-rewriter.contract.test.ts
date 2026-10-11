import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { injectOgMeta, OG_OVERRIDES } from '../../worker/og-rewriter';

// Contract test against the REAL index.html so it can never silently drift:
// the per-route metadata the worker serves is the only thing differentiating
// social/SEO cards across routes (head tags are NOT managed in React). These
// assertions pin the bugs the audit found in worker/og-rewriter.ts:
//   1. <meta name="description"> is multi-line in index.html, so the single-line
//      rewrite regex never matched -> 317-char home description on every route.
//   2. twitter:* tags must use name= (the X/Twitter card spec). They were
//      property=, which X's parser doesn't reliably read — per-page cards
//      rendered on LinkedIn (reads og:*) but not on X. index.html AND the
//      worker regexes now both use name=.
//   3. /, /dfir, /copilot had no override -> 97-char home <title> verbatim.
const indexHtml = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8');

/** Serve a path through the worker's OG rewriter (no nonce -> no caches access). */
async function serve(path: string, env: any = {}): Promise<string> {
  const res = new Response(indexHtml, { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  const url = new URL(`https://pranithjain.qzz.io${path}`);
  const out = await injectOgMeta(res, url, env, { waitUntil() {} } as any);
  return out.text();
}

/** Minimal CASE_STUDIES KV stub: get(key) -> the canned record (or null). */
function blogEnv(data: Record<string, unknown>) {
  return { CASE_STUDIES: { get: async (k: string) => data[k] ?? null } };
}
const POST = {
  slug: 'unit-post',
  title: 'Unit Test Post',
  excerpt: 'A short excerpt for the post.',
  publishedAt: '2026-01-01T00:00:00.000Z',
  tags: ['cve', 'ransomware'],
};
const INDEX = [
  POST,
  {
    slug: 'second-post',
    title: 'Second Post',
    excerpt: 'Another one.',
    publishedAt: '2026-01-02T00:00:00.000Z',
    tags: [],
  },
];

const ENTITIES: Record<string, string> = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" };
const decode = (s: string): string => s.replace(/&(amp|lt|gt|quot|#39);/g, (m) => ENTITIES[m] ?? m);

/** Tolerant of multi-line tags + attribute order. Returns decoded display text. */
function metaByName(html: string, name: string): string | null {
  const m =
    new RegExp(`<meta\\s+name="${name}"\\s+content="([^"]*)"`, 'is').exec(html) ??
    new RegExp(`<meta\\s+content="([^"]*)"\\s+name="${name}"`, 'is').exec(html);
  return m ? decode(m[1]!) : null;
}
function metaByProperty(html: string, prop: string): string | null {
  const m = new RegExp(`<meta\\s+property="${prop}"\\s+content="([^"]*)"`, 'is').exec(html);
  return m ? decode(m[1]!) : null;
}
function titleOf(html: string): string | null {
  const m = /<title>([^<]*)<\/title>/i.exec(html);
  return m ? decode(m[1]!) : null;
}

describe('og-rewriter per-route metadata (contract vs real index.html)', () => {
  it('serves a DIFFERENT <meta name="description"> per route (the multi-line rewrite must fire)', async () => {
    const home = metaByName(await serve('/'), 'description');
    const about = metaByName(await serve('/about'), 'description');
    expect(home).toBeTruthy();
    expect(about).toBeTruthy();
    expect(about).not.toBe(home);
  });

  it('rewrites twitter:title and twitter:description per route (name= attribute)', async () => {
    const html = await serve('/about');
    expect(metaByName(html, 'twitter:title')).toContain('About');
    // home twitter:description phrase must be gone once the override applies
    expect(metaByName(html, 'twitter:description') ?? '').not.toContain('1,300+ domains secured');
  });

  it('rewrites twitter:url to the requested path on every route', async () => {
    expect(metaByName(await serve('/about'), 'twitter:url')).toBe('https://pranithjain.qzz.io/about');
    expect(metaByName(await serve('/dfir'), 'twitter:url')).toBe('https://pranithjain.qzz.io/dfir');
  });

  it('rewrites twitter:image + og:image per route when an override declares an image', async () => {
    const html = await serve('/dfir');
    expect(metaByName(html, 'twitter:image')).toContain('/og-dfir.png');
    expect(metaByProperty(html, 'og:image')).toContain('/og-dfir.png');
  });

  it('rewrites og:image:alt + twitter:image:alt per route when an override declares an image', async () => {
    const html = await serve('/dfir');
    // The alt text must match the page-specific card, not the generic homepage alt
    const alt = metaByProperty(html, 'og:image:alt');
    expect(alt).toBeTruthy();
    expect(alt).not.toContain('PANOPTICON'); // must not be the homepage alt
    expect(alt).toContain('CRUCIBLE');
    const twitterAlt = metaByName(html, 'twitter:image:alt');
    expect(twitterAlt).toBeTruthy();
    expect(twitterAlt).not.toContain('PANOPTICON');
  });

  it('rewrites og:image:alt for deep pages with dynamic page cards', async () => {
    const html = await serve('/dfir/cve');
    const alt = metaByProperty(html, 'og:image:alt');
    expect(alt).toBeTruthy();
    expect(alt).not.toContain('PANOPTICON'); // must not be the generic homepage alt
    const twitterAlt = metaByName(html, 'twitter:image:alt');
    expect(twitterAlt).toBeTruthy();
  });

  it('gives a deep page a UNIQUE generated page card (og:image + twitter:image)', async () => {
    const html = await serve('/dfir/cve');
    // Versioned dynamic card: /og-image/v<build>/page/<dot>.png (emitted by
    // pageCardUrl()), pre-rendered at build time and served from Workers KV.
    expect(metaByProperty(html, 'og:image')).toMatch(/\/og-image\/v[a-z0-9]+\/page\/dfir\.cve\.png$/);
    expect(metaByName(html, 'twitter:image')).toMatch(/\/og-image\/v[a-z0-9]+\/page\/dfir\.cve\.png$/);
    // X-compat contract: the card image URL must contain no query string and
    // no percent-encoded separators — X's parser drops query-string images
    // and corrupts %2F on re-fetch, in both cases rendering chip-without-image.
    expect(metaByProperty(html, 'og:image')).not.toContain('?');
    expect(metaByProperty(html, 'og:image')).not.toContain('%2F');
    // and it differs from the section landing card
    expect(metaByProperty(html, 'og:image')).not.toContain('/og-dfir.png');
  });

  it('gives /dfir and /copilot unique, <=60-char titles (not the 97-char home default)', async () => {
    const dfir = titleOf(await serve('/dfir'));
    const copilot = titleOf(await serve('/copilot'));
    expect(dfir).toContain('DFIR');
    expect(dfir).not.toContain('Security Analyst & Detection Engineer | DFIR Toolkit');
    expect((dfir ?? '').length).toBeLessThanOrEqual(60);
    expect(copilot).toContain('Copilot');
    expect((copilot ?? '').length).toBeLessThanOrEqual(60);
  });

  it('home <title> <=60 chars and <meta name="description"> <=160 chars', async () => {
    const html = await serve('/');
    expect((titleOf(html) ?? '').length).toBeLessThanOrEqual(60);
    expect((metaByName(html, 'description') ?? '').length).toBeLessThanOrEqual(160);
  });

  it('still corrects og:url + canonical per route (no regression)', async () => {
    const html = await serve('/projects');
    expect(metaByProperty(html, 'og:url')).toBe('https://pranithjain.qzz.io/projects');
    expect(/<link rel="canonical" href="https:\/\/pranithjain\.qzz\.io\/projects"/i.test(html)).toBe(true);
  });

  it('every OG_OVERRIDES title is <=60 chars (Google truncates beyond ~60)', () => {
    for (const [route, ov] of Object.entries(OG_OVERRIDES)) {
      expect(ov.title.length, `${route} title is ${ov.title.length} chars`).toBeLessThanOrEqual(60);
    }
  });

  it('every OG_OVERRIDES description is <=160 chars (snippet truncation limit)', () => {
    for (const [route, ov] of Object.entries(OG_OVERRIDES)) {
      expect(ov.description.length, `${route} description is ${ov.description.length} chars`).toBeLessThanOrEqual(160);
    }
  });
});

describe('blog structured data (worker-injected JSON-LD)', () => {
  it('injects BlogPosting JSON-LD into /blog/<slug> from KV', async () => {
    const html = await serve('/blog/unit-post', blogEnv({ 'posts:unit-post': POST }));
    expect(html).toContain('application/ld+json');
    expect(html).toContain('"@type":"BlogPosting"');
    expect(html).toContain('"headline":"Unit Test Post"');
    expect(html).toContain('https://pranithjain.qzz.io/blog/unit-post');
  });

  it('injects Blog JSON-LD with the post list into /blog from KV', async () => {
    const html = await serve('/blog', blogEnv({ 'posts:index': INDEX }));
    expect(html).toContain('"@type":"Blog"');
    expect(html).toContain('Unit Test Post');
    expect(html).toContain('Second Post');
  });

  it('does not inject blog JSON-LD on non-blog routes', async () => {
    const html = await serve('/about', blogEnv({}));
    expect(html).not.toContain('"@type":"BlogPosting"');
    expect(html).not.toContain('"@type":"Blog"');
  });

  it('is resilient when KV has no data (no crash, no script)', async () => {
    expect(await serve('/blog', blogEnv({}))).not.toContain('"@type":"Blog"');
    expect(await serve('/blog/missing', blogEnv({}))).not.toContain('"@type":"BlogPosting"');
  });
});

describe('credential/login surfaces served noindex (Safe Browsing mitigation)', () => {
  for (const p of [
    '/dfir/breach',
    '/dfir/phishing',
    '/threatintel/telegram-leaks/channels',
    '/threatintel/misp-browser',
    '/admin',
  ]) {
    it(`serves ${p} with a noindex robots meta`, async () => {
      expect(await serve(p)).toMatch(/<meta\s+name="robots"\s+content="noindex/i);
    });
  }
  it('leaves ordinary routes index,follow', async () => {
    expect(await serve('/about')).toMatch(/<meta\s+name="robots"\s+content="index, follow/i);
  });
});

describe('prerendered #root duplicate-meta stripping', () => {
  /**
   * React Helmet injects OG/Twitter meta tags into the prerendered app HTML
   * inside #root. These are stale build-time copies (wrong URL/title, no
   * twitter:image) that duplicate the <head> tags the worker rewrites. X's
   * crawler picks up the duplicates and shows no card; LinkedIn reads <head>
   * only. The worker must strip the #root copies so only the authoritative
   * <head> tags remain.
   */
  async function servePrerendered(path: string, env: any = {}): Promise<string> {
    // Simulate a prerendered shell: app HTML (with Helmet meta tags) inside #root.
    const prerenderedShell = indexHtml.replace(
      '<div id="root"></div>',
      '<div id="root"><title>Blog · Pranith Jain · Security Portfolio</title>' +
        '<meta property="og:title" content="Blog · Pranith Jain · Security Portfolio"/>' +
        '<meta property="og:url" content="https://pranithjain.qzz.io/blog"/>' +
        '<meta property="og:type" content="profile"/>' +
        '<meta name="twitter:card" content="summary_large_image"/>' +
        '<meta name="twitter:title" content="Blog · Pranith Jain · Security Portfolio"/>' +
        '<meta name="twitter:site" content="@pranithjain"/>' +
        '<link rel="canonical" href="https://pranithjain.qzz.io/blog"/>' +
        '<div>app content</div></div>'
    );
    const res = new Response(prerenderedShell, { headers: { 'content-type': 'text/html;charset=UTF-8' } });
    const url = new URL(`https://pranithjain.qzz.io${path}`);
    const out = await injectOgMeta(res, url, env, { waitUntil() {} } as any);
    return out.text();
  }

  it('strips duplicate og:*/twitter:* meta tags from inside #root', async () => {
    const html = await servePrerendered('/dfir', {});
    const rootStart = html.indexOf('<div id="root"');
    const rootHtml = html.slice(rootStart);
    // No OG/Twitter meta tags should survive inside #root.
    expect(rootHtml).not.toMatch(/<meta\s+property="og:/);
    expect(rootHtml).not.toMatch(/<meta\s+name="twitter:/);
    // The <head> tags must still be present.
    const head = html.slice(0, rootStart);
    expect(head).toMatch(/<meta\s+property="og:title"/);
    expect(head).toMatch(/<meta\s+name="twitter:card"/);
  });

  it('strips the duplicate <title> from inside #root', async () => {
    const html = await servePrerendered('/dfir', {});
    const rootStart = html.indexOf('<div id="root"');
    const rootHtml = html.slice(rootStart);
    expect(rootHtml).not.toMatch(/<title>[^<]*<\/title>/);
  });

  it('preserves the canonical <link> in <head> (only strips #root copy)', async () => {
    const html = await servePrerendered('/dfir', {});
    const rootStart = html.indexOf('<div id="root"');
    const head = html.slice(0, rootStart);
    // <head> canonical must survive.
    expect(head).toMatch(/<link\s+rel="canonical"/);
  });
});

// Each tools host is authoritative for its own path prefix and only for it.
// Without this every host self-canonicalises and Google splits the ranking of
// one page across three origins — with it, `/dfir` has exactly one owner.
// The inverse failure (a canonical pointing at a host with no DNS record) is
// why only prefixes whose hostname actually resolves may appear in the map.
const TOOLS_HOSTS =
  '/dfir=crucible.pranithjain.qzz.io,/threatintel=panopticon.pranithjain.qzz.io,/radar=scout.pranithjain.qzz.io';

const canonicalOf = (html: string): string | null => {
  const m = /<link\s+rel="canonical"\s+href="([^"]*)"/i.exec(html);
  return m ? decode(m[1]!) : null;
};

describe('canonical ownership across the several front doors', () => {
  it('routes each app prefix to its own host', async () => {
    expect(canonicalOf(await serve('/dfir', { TOOLS_HOSTS }))).toBe('https://crucible.pranithjain.qzz.io/dfir');
    expect(canonicalOf(await serve('/threatintel', { TOOLS_HOSTS }))).toBe(
      'https://panopticon.pranithjain.qzz.io/threatintel'
    );
    expect(canonicalOf(await serve('/radar', { TOOLS_HOSTS }))).toBe('https://scout.pranithjain.qzz.io/radar');
  });

  it('keeps portfolio routes on the apex', async () => {
    expect(canonicalOf(await serve('/projects', { TOOLS_HOSTS }))).toBe('https://pranithjain.qzz.io/projects');
    expect(canonicalOf(await serve('/', { TOOLS_HOSTS }))).toBe('https://pranithjain.qzz.io/');
  });

  it('leaves an unconfigured app prefix on the apex', async () => {
    // /argus has no hostname yet — the fallback must stay on a host that resolves.
    expect(canonicalOf(await serve('/argus', { TOOLS_HOSTS }))).toBe('https://pranithjain.qzz.io/argus');
  });

  it('canonicalises a redirect-only route to the TARGET owner', async () => {
    // /copilot redirects to /threatintel/... → panopticon, not crucible/apex.
    expect(canonicalOf(await serve('/copilot', { TOOLS_HOSTS }))).toBe(
      'https://panopticon.pranithjain.qzz.io/threatintel/tools/copilot'
    );
    // /agent redirects to /dfir/agent-suite → crucible.
    expect(canonicalOf(await serve('/agent', { TOOLS_HOSTS }))).toBe(
      'https://crucible.pranithjain.qzz.io/dfir/agent-suite'
    );
  });

  it('falls back to the apex when TOOLS_HOSTS is unset or blank', async () => {
    for (const raw of [undefined, '', '   ']) {
      expect(canonicalOf(await serve('/dfir', { TOOLS_HOSTS: raw }))).toBe('https://pranithjain.qzz.io/dfir');
      expect(canonicalOf(await serve('/threatintel', { TOOLS_HOSTS: raw }))).toBe(
        'https://pranithjain.qzz.io/threatintel'
      );
    }
  });

  it('still corrects og:url to match the canonical', async () => {
    const html = await serve('/dfir', { TOOLS_HOSTS });
    expect(metaByProperty(html, 'og:url')).toBe('https://crucible.pranithjain.qzz.io/dfir');
  });
});
