/**
 * Turn a real web page into the small amount of text a writer actually needs.
 *
 * The generator used to receive a title and a URL and nothing else, so the
 * model either wrote from memory (and got details wrong) or wrote vaguely to
 * avoid being wrong. Reading the source page is the difference between a
 * post that cites a vendor bulletin it never opened and one that quotes the
 * affected-version table from it.
 *
 * EXTRACTION STRATEGY — two passes, in this order, because the one-pass
 * streaming form does not work:
 *
 *   1. HTMLRewriter removes chrome subtrees (nav, share widgets, related
 *      rails, cookie banners, scripts) from the markup, and we read the
 *      cleaned HTML back as a string.
 *   2. A plain string pass over that cleaned HTML produces the readable text.
 *
 * The obvious alternative — register a handler on the chrome selector whose
 * `text` callback does not fire, alongside a catch-all `*` handler — does
 * NOT drop the subtree. Verified against the runtime: a catch-all text
 * handler still receives the descendants, because HTMLRewriter dispatches
 * per element and the removed element's children are separate events.
 * `el.remove()` inside a catch-all-bearing rewriter has the same problem.
 * Separating the two passes is what actually works, and it has the side
 * benefit of making pass 2 a cheap linear scan over already-clean markup.
 */

const DROP_SELECTOR =
  'script,style,noscript,template,iframe,svg,form,button,select,textarea,' +
  'nav,header,footer,aside,[role="navigation"],[role="banner"],[role="complementary"],' +
  '[aria-hidden="true"],.cookie,.cookies,.newsletter,.newsletter-signup,.signup,' +
  '.subscribe,.advertisement,.advert,.ad-slot,.promo,.related,.recommended,' +
  '.share,.social-share,.share-buttons,.comments,.comment-list,#comments,' +
  '.breadcrumb,.breadcrumbs,.sidebar,.side-bar,.masthead,.site-header';

/** Tags whose boundaries become newlines so extracted text keeps its shape. */
const BLOCK_TAGS = new Set([
  'P',
  'DIV',
  'SECTION',
  'ARTICLE',
  'MAIN',
  'LI',
  'UL',
  'OL',
  'BR',
  'H1',
  'H2',
  'H3',
  'H4',
  'H5',
  'H6',
  'TR',
  'TABLE',
  'TD',
  'TH',
  'BLOCKQUOTE',
  'PRE',
  'FIGURE',
]);

/** Lines that read like navigation or legal chrome even inside <article>. */
const NOISE_TEXT = [
  /^(share|tweet|advertisement|sign up|subscribe|newsletter|cookie|accept all|read more|related|related articles|comments?|leave a comment|previous|next|menu|search|home)\b/i,
  /^\s*(all rights reserved|copyright ©?|terms of (use|service)|privacy policy)\b/i,
];

/** Max characters of body text kept per page. */
const TEXT_CAP = 6000;
/** Cap on the number of pages fetched in one research pass. */
export const MAX_PAGES = 6;
const PAGE_TIMEOUT_MS = 8000;

export interface ExtractedPage {
  url: string;
  ok: boolean;
  status: number;
  /** Human title — og:title, then <title>, then the first <h1>. */
  title: string;
  /** Host, used as the citation label. */
  publisher: string;
  /** ISO date when the page exposed one, else ''. */
  publishedAt: string;
  /** Readable body text, whitespace-normalised, capped at TEXT_CAP. */
  text: string;
  /** Set when the page could not be read. Never fatal. */
  error?: string;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

const SIMPLE_ENTITIES: Array<[RegExp, string]> = [
  [/&nbsp;/gi, ' '],
  [/&amp;/gi, '&'],
  [/&lt;/gi, '<'],
  [/&gt;/gi, '>'],
  [/&quot;/gi, '"'],
  [/&#0?39;|&apos;/gi, "'"],
  [/&#8217;|&rsquo;/gi, "'"],
  [/&#8216;|&lsquo;/gi, "'"],
  [/&#8220;|&ldquo;/gi, '"'],
  [/&#8221;|&rdquo;/gi, '"'],
  [/&#8230;|&hellip;/gi, '...'],
  [/&mdash;/gi, ' - '],
  [/&ndash;/gi, '-'],
];

function decodeEntities(s: string): string {
  let out = s;
  for (const [re, rep] of SIMPLE_ENTITIES) out = out.replace(re, rep);
  // Numeric entities, e.g. &#8217; — covered above for the common cases, but
  // a generic pass catches the long tail like &#228;.
  out = out.replace(/&#(\d+);/g, (_m: string, code: string) => String.fromCodePoint(Number(code)));
  return out;
}

/** Collapse whitespace without destroying paragraph boundaries. */
function tidy(raw: string): string {
  return raw
    .split('\n')
    .map((l) => l.replace(/[ \t ]+/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Drop lines that read like navigation or legal chrome. */
function dropNoiseLines(text: string): string {
  return text
    .split('\n')
    .filter((line) => {
      if (line.length < 3) return false;
      return !NOISE_TEXT.some((re) => re.test(line));
    })
    .join('\n');
}

/** First capture group of `re` against `html`, entity-decoded and trimmed. */
function firstMatch(html: string, re: RegExp): string {
  return decodeEntities(html.match(re)?.[1] ?? '').trim();
}

/** Accepts ISO-8601 and RFC-2822 shapes; returns YYYY-MM-DD or ''. */
function normalizeDate(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || /^\d{4}$/.test(trimmed)) return '';
  const t = Date.parse(trimmed);
  return Number.isNaN(t) ? '' : new Date(t).toISOString().slice(0, 10);
}

/**
 * Pull metadata out of the cleaned HTML.
 *
 * og:title / twitter:title win over <title> because publishers set them to
 * the headline rather than "Headline | Site Name".
 */
function readMeta(html: string): { title: string; publishedAt: string } {
  const metaTag = (prop: string) => {
    // Attribute order varies, so match the tag then look inside it.
    const tag = html.match(new RegExp(`<meta[^>]*${prop}[^>]*>`, 'i'))?.[0] ?? '';
    return firstMatch(tag, /content="([^"]*)"/i) || firstMatch(tag, /content='([^']*)'/i);
  };

  const title =
    metaTag('property="og:title"') ||
    metaTag('property="og:title') ||
    metaTag('name="twitter:title"') ||
    firstMatch(html, /<title[^>]*>([\s\S]*?)<\/title>/i) ||
    firstMatch(html, /<h1[^>]*>([\s\S]*?)<\/h1>/i);

  const rawDate =
    metaTag('property="article:published_time"') ||
    metaTag('property="og:published_time"') ||
    metaTag('name="date"') ||
    metaTag('name="pubdate"') ||
    metaTag('name="dc.date"') ||
    firstMatch(html, /<time[^>]*datetime="([^"]*)"/i);

  return { title: title.slice(0, 300), publishedAt: normalizeDate(rawDate) };
}

/**
 * Pass 1: remove chrome subtrees from the markup.
 *
 * Uses `el.remove()`, which drops the element and its contents from the
 * output document. This must be a rewriter with no competing catch-all text
 * handler — see the strategy note at the top of the file.
 */
async function stripChrome(html: string): Promise<string> {
  try {
    return await new HTMLRewriter()
      .on(DROP_SELECTOR, {
        element: (el) => {
          el.remove();
        },
      })
      .transform(new Response(html, { headers: { 'content-type': 'text/html' } }))
      .text();
  } catch {
    // A malformed document still yields usable text; fall through.
    return html;
  }
}

/**
 * Pass 2: cleaned HTML → readable text.
 *
 * Block tags become newlines so paragraph and list structure survives, which
 * matters because a version table extracted as one run-on line is unusable to
 * the writer.
 */
function htmlToText(html: string): string {
  const withBreaks = html
    // Drop the remaining non-content elements' *tags* (bodies already gone).
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|template|svg|iframe)\b[\s\S]*?<\/\1>/gi, ' ');

  let out = '';
  let lastIndex = 0;
  const tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(withBreaks)) !== null) {
    const [full, closing, rawName] = m;
    out += withBreaks.slice(lastIndex, m.index);
    lastIndex = m.index + full.length;

    const name = (rawName ?? '').toUpperCase();
    if (closing) {
      if (BLOCK_TAGS.has(name)) out += '\n';
    } else if (BLOCK_TAGS.has(name)) {
      out += '\n';
    }
    // <br> is void: never look for a closing tag.
  }
  out += withBreaks.slice(lastIndex);

  return tidy(dropNoiseLines(tidy(decodeEntities(out.replace(/<[^>]*>/g, ' ')))));
}

/**
 * Read one URL and return its metadata + readable text.
 *
 * Never throws. A blocked WAF, a timeout, a JS-only page and a 404 all come
 * back as `ok: false` with a reason, and the caller treats them as "this
 * source told us nothing" rather than failing the run — the dossier is still
 * useful from the enrichment APIs alone.
 */
export async function extractPage(
  url: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch
): Promise<ExtractedPage> {
  const base: ExtractedPage = {
    url,
    ok: false,
    status: 0,
    title: '',
    publisher: hostOf(url),
    publishedAt: '',
    text: '',
  };
  if (!/^https?:\/\//i.test(url)) return { ...base, error: 'not an http(s) url' };

  try {
    const res = await fetchFn(url, {
      redirect: 'follow',
      headers: {
        // Some publishers serve a stripped page to unknown agents; a browser
        // UA gets us the article body rather than a consent interstitial.
        'user-agent': 'Mozilla/5.0 (compatible; threatintel-research/1.0; +https://pranithjain.qzz.io/about)',
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en',
      },
      signal: AbortSignal.timeout(PAGE_TIMEOUT_MS),
    });

    const status = res.status;
    if (!res.ok) return { ...base, status, error: `http ${status}` };

    const contentType = (res.headers.get('content-type') ?? '').toLowerCase();
    if (contentType.includes('application/json')) {
      const text = await res.text();
      return { ...base, ok: true, status, text: tidy(text.slice(0, TEXT_CAP)) };
    }
    if (contentType.includes('text/plain')) {
      const text = await res.text();
      return { ...base, ok: true, status, text: tidy(text.slice(0, TEXT_CAP)) };
    }
    if (!contentType.includes('html') && !contentType.includes('xml')) {
      return { ...base, status, error: `unsupported content-type: ${contentType || 'unknown'}` };
    }

    const html = await res.text();
    const cleaned = await stripChrome(html);
    const meta = readMeta(cleaned);
    const text = htmlToText(cleaned).slice(0, TEXT_CAP);

    // A page that yields neither a title nor text is a shell (JS-rendered or
    // bot-walled). Reporting ok here would let the caller cite a page the
    // writer never actually read.
    if (!meta.title && text.length < 200) {
      return { ...base, status, error: 'no readable content (script-rendered or bot-walled)' };
    }

    return {
      url,
      ok: true,
      status,
      title: meta.title,
      publisher: hostOf(url),
      publishedAt: meta.publishedAt,
      text,
    };
  } catch (err) {
    return { ...base, error: err instanceof Error ? err.message.slice(0, 120) : String(err).slice(0, 120) };
  }
}
