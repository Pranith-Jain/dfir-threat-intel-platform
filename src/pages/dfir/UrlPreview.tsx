import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link, useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Eye, ExternalLink, AlertTriangle } from 'lucide-react';
interface OgData {
  title?: string;
  description?: string;
  image?: string;
  site_name?: string;
  type?: string;
}

interface TwitterData {
  title?: string;
  description?: string;
  image?: string;
  card?: string;
}

interface UrlPreviewResult {
  url: string;
  final_url: string;
  status: number;
  content_type?: string;
  title?: string;
  description?: string;
  og?: OgData;
  twitter?: TwitterData;
  canonical?: string;
  lang?: string;
  charset?: string;
  favicon?: string;
  feeds?: { title?: string; url: string; type: string }[];
  meta?: {
    author?: string;
    generator?: string;
    robots?: string;
    keywords?: string;
    theme_color?: string;
    viewport?: string;
  };
  urlscan?: {
    result: string;
    screenshot?: string;
    scanned_at?: string;
    page?: { ip?: string; server?: string; country?: string; domain?: string };
  };
  bytes_read: number;
  redirect_blocked?: { location: string };
}

function hasOgData(og?: OgData): boolean {
  return !!og && Object.values(og).some(Boolean);
}

function hasTwitterData(tw?: TwitterData): boolean {
  return !!tw && Object.values(tw).some(Boolean);
}

function StatusBadge({ status }: { status: number }) {
  const isOk = status >= 200 && status < 300;
  const isRedirect = status >= 300 && status < 400;
  const isError = status >= 400;
  return (
    <span
      className={[
        'inline-flex items-center px-2 py-0.5 rounded font-mono text-xs font-bold border',
        isOk &&
          'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-700',
        isRedirect &&
          'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-700',
        isError &&
          'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-900/30 dark:text-rose-300 dark:border-rose-700',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      HTTP {status}
    </span>
  );
}

export default function UrlPreview(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialUrl = searchParams.get('url') ?? searchParams.get('q') ?? '';
  const [input, setInput] = useState(initialUrl);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<UrlPreviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const autoFetched = useRef(false);

  const isValidUrl = (() => {
    try {
      const p = new URL(input.trim());
      return p.protocol === 'http:' || p.protocol === 'https:';
    } catch (_catchErr) {
      console.error('UrlPreview failed:', errMessage(_catchErr));
      return false;
    }
  })();

  const canSubmit = isValidUrl && !loading;

  const runPreview = async (q: string) => {
    const target = q.trim();
    try {
      const p = new URL(target);
      if (p.protocol !== 'http:' && p.protocol !== 'https:') return;
    } catch (_catchErr) {
      console.error('UrlPreview failed:', errMessage(_catchErr));
      return;
    }
    setLoading(true);
    setResult(null);
    setError(null);
    setSearchParams({ url: target }, { replace: true });
    try {
      const r = await fetch(`/api/v1/url-preview?url=${encodeURIComponent(target)}`);
      const body = (await r.json()) as UrlPreviewResult & { error?: string };
      if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
      setResult(body);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'preview failed'));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    void runPreview(input);
  };

  useEffect(() => {
    if (autoFetched.current) return;
    if (initialUrl) {
      autoFetched.current = true;
      void runPreview(initialUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">URL Preview</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Fetch metadata from a URL server-side. Get title, meta description, Open Graph, and Twitter Card tags. No
          JavaScript execution, no rendering.
        </p>
      </div>

      {/* Security note */}
      <div className="flex gap-3 p-4 mb-8 rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10 text-sm font-mono text-amber-800 dark:text-amber-300">
        <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-bold">Privacy &amp; Security:</span> URLs resolving to private/loopback IPs are refused.
          Redirects are NOT followed. Body capped at 128KB. Only{' '}
          <code className="bg-amber-100 dark:bg-amber-900/30 px-1 rounded">&lt;head&gt;</code> metadata is parsed, while
          the page is not rendered.
        </div>
      </div>

      <form onSubmit={onSubmit} className="mb-10">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="url"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="https://www.cisa.gov/"
              className="w-full bg-input-200 border border-line-input rounded-control px-4 py-3 text-tool text-heading placeholder:text-muted focus:outline-none focus:border-accent-text transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={!canSubmit}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-control disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <Eye size={16} className="inline mr-2" />
            Preview
          </button>
        </div>
        {input && !isValidUrl && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">
            Enter a valid http:// or https:// URL
          </p>
        )}
      </form>

      {loading && <p className="font-mono text-muted">Fetching metadata…</p>}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-5">
          {/* Header */}
          <section className="surface-card p-6">
            <div className="flex flex-wrap items-center gap-3 mb-3">
              <StatusBadge status={result.status} />
              {result.content_type && (
                <span className="font-mono text-xs text-muted">{result.content_type.split(';')[0]}</span>
              )}
              <span className="font-mono text-xs text-muted">{(result.bytes_read / 1024).toFixed(1)} KB read</span>
            </div>
            <a
              href={sanitizeUrl(result.final_url)}
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline font-mono text-sm break-all flex items-center gap-1 transition-colors"
            >
              {result.final_url}
              <ExternalLink size={12} className="flex-shrink-0" />
            </a>
            {/* Per-final-URL pivots - let the analyst go directly to the host
                inspector / cert-search / IOC reputation rather than copy-pasting. */}
            {(() => {
              try {
                const host = new URL(result.final_url).hostname;
                return (
                  <div className="flex flex-wrap gap-2 mt-3 text-micro font-mono">
                    <Link
                      to={`/dfir/ioc-check?indicator=${encodeURIComponent(result.final_url)}`}
                      className="px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/5 text-rose-700 dark:text-rose-300 hover:bg-rose-500/10"
                    >
                      → IOC check
                    </Link>
                    <Link
                      to={`/dfir/domain?domain=${encodeURIComponent(host)}`}
                      className="px-1.5 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/5 text-sky-700 dark:text-sky-300 hover:bg-cyan-500/10"
                    >
                      → {host}
                    </Link>
                    <Link
                      to={`/dfir/cert-search?domain=${encodeURIComponent(host)}`}
                      className="px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/5 text-violet-700 dark:text-violet-300 hover:bg-violet-500/10"
                    >
                      → certs
                    </Link>
                    <Link
                      to={`/dfir/wayback?url=${encodeURIComponent(result.final_url)}`}
                      className="px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-300 hover:bg-amber-500/10"
                    >
                      → wayback
                    </Link>
                  </div>
                );
              } catch (_catchErr) {
                logCatch(_catchErr);
                return null;
              }
            })()}
          </section>

          {/* Redirect blocked */}
          {result.redirect_blocked && (
            <section className="rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10 p-6">
              <h3 className="font-display font-semibold text-lg mb-2 text-amber-800 dark:text-amber-300">
                Redirect Blocked
              </h3>
              <p className="text-sm font-mono text-amber-700 dark:text-amber-400">
                The redirect target was blocked by the SSRF guard - it resolves to a private or reserved IP.
              </p>
              {result.redirect_blocked.location && (
                <div className="mt-2 text-sm font-mono text-muted">
                  Location: <span className="text-heading">{result.redirect_blocked.location}</span>
                </div>
              )}
            </section>
          )}

          {/* Page title */}
          {result.title && (
            <section className="surface-card p-6">
              <div className="text-xs uppercase tracking-wider text-muted font-mono mb-1">Page Title</div>
              <p className="text-heading font-semibold">{result.title}</p>
            </section>
          )}

          {/* Meta description */}
          {result.description && (
            <section className="surface-card p-6">
              <div className="text-xs uppercase tracking-wider text-muted font-mono mb-1">Meta Description</div>
              <p className="text-body text-sm">{result.description}</p>
            </section>
          )}

          {/* Site basics: favicon, lang, charset, feeds */}
          {(result.favicon || result.lang || result.charset || (result.feeds && result.feeds.length > 0)) && (
            <section className="surface-card p-6">
              <div className="text-xs uppercase tracking-wider text-muted font-mono mb-3">Site</div>
              <div className="flex flex-wrap items-center gap-3 text-sm font-mono">
                {result.favicon && (
                  <span className="inline-flex items-center gap-2">
                    <img
                      loading="lazy"
                      src={result.favicon}
                      alt="favicon"
                      className="h-5 w-5 rounded"
                      onError={(e) => {
                        (e.currentTarget as HTMLImageElement).style.display = 'none';
                      }}
                    />
                    <a
                      href={sanitizeUrl(result.favicon)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                    >
                      favicon
                    </a>
                  </span>
                )}
                {result.lang && (
                  <span className="px-2 py-0.5 rounded border border-line-2 text-body">lang: {result.lang}</span>
                )}
                {result.charset && (
                  <span className="px-2 py-0.5 rounded border border-line-2 text-body">charset: {result.charset}</span>
                )}
              </div>
              {result.feeds && result.feeds.length > 0 && (
                <div className="mt-4">
                  <div className="text-xs text-muted mb-1 font-mono">Feeds</div>
                  <ul className="space-y-1 text-sm font-mono">
                    {result.feeds.map((f) => (
                      <li key={f.url}>
                        <a
                          href={sanitizeUrl(f.url) || undefined}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-brand-600 dark:text-brand-400 hover:underline break-all transition-colors"
                        >
                          {f.title || f.type} <ExternalLink size={10} className="inline" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}

          {/* urlscan.io - most recent existing public scan */}
          {result.urlscan && (
            <section className="surface-card p-6">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-display font-semibold text-lg">urlscan.io</h3>
                <a
                  href={sanitizeUrl(result.urlscan.result)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                >
                  open scan <ExternalLink size={12} />
                </a>
              </div>
              {result.urlscan.screenshot && (
                <a href={sanitizeUrl(result.urlscan.result)} target="_blank" rel="noopener noreferrer">
                  <img
                    loading="lazy"
                    src={result.urlscan.screenshot}
                    alt="urlscan screenshot"
                    className="max-w-full max-h-72 rounded-xl border border-line-1 object-contain"
                    onError={(e) => {
                      (e.currentTarget as HTMLImageElement).style.display = 'none';
                    }}
                  />
                </a>
              )}
              <div className="mt-3 grid sm:grid-cols-2 gap-2 font-mono text-sm">
                {result.urlscan.scanned_at && (
                  <div>
                    <span className="text-xs text-muted">scanned</span>{' '}
                    <span className="text-heading">{new Date(result.urlscan.scanned_at).toLocaleString()}</span>
                  </div>
                )}
                {result.urlscan.page?.ip && (
                  <div>
                    <span className="text-xs text-muted">IP</span>{' '}
                    <span className="text-heading">{result.urlscan.page.ip}</span>
                  </div>
                )}
                {result.urlscan.page?.server && (
                  <div>
                    <span className="text-xs text-muted">server</span>{' '}
                    <span className="text-heading">{result.urlscan.page.server}</span>
                  </div>
                )}
                {result.urlscan.page?.country && (
                  <div>
                    <span className="text-xs text-muted">country</span>{' '}
                    <span className="text-heading">{result.urlscan.page.country}</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Other meta */}
          {result.meta && Object.values(result.meta).some(Boolean) && (
            <section className="surface-card p-6">
              <div className="text-xs uppercase tracking-wider text-muted font-mono mb-3">Other Meta</div>
              <div className="grid sm:grid-cols-2 gap-3 font-mono text-sm">
                {(
                  [
                    ['author', result.meta.author],
                    ['generator', result.meta.generator],
                    ['robots', result.meta.robots],
                    ['keywords', result.meta.keywords],
                    ['theme-color', result.meta.theme_color],
                    ['viewport', result.meta.viewport],
                  ] as const
                )
                  .filter(([, v]) => Boolean(v))
                  .map(([k, v]) => (
                    <div key={k}>
                      <div className="text-xs text-muted mb-1">{k}</div>
                      <div className="text-heading break-words">{v}</div>
                    </div>
                  ))}
              </div>
            </section>
          )}

          {/* Canonical */}
          {result.canonical && (
            <section className="surface-card p-6">
              <div className="text-xs uppercase tracking-wider text-muted font-mono mb-1">Canonical URL</div>
              <a
                href={sanitizeUrl(result.canonical)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-brand-600 dark:text-brand-400 hover:underline font-mono text-sm break-all transition-colors"
              >
                {result.canonical}
              </a>
            </section>
          )}

          {/* Open Graph */}
          {hasOgData(result.og) && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-4">Open Graph</h3>
              {result.og?.image && (
                <div className="mb-4">
                  <div className="text-xs uppercase tracking-wider text-muted font-mono mb-2">Image</div>
                  <img
                    loading="lazy"
                    src={result.og.image}
                    alt="og:image"
                    className="max-w-full max-h-48 rounded-xl border border-line-1 object-contain"
                    onError={(e) => {
                      (e.currentTarget as HTMLImageElement).style.display = 'none';
                    }}
                  />
                  <p className="mt-1 text-mini font-mono text-muted">
                    Note: image loaded from the queried site, so referer may be visible to that server.
                  </p>
                </div>
              )}
              <div className="grid sm:grid-cols-2 gap-4 font-mono text-sm">
                {result.og?.title && (
                  <div>
                    <div className="text-xs text-muted mb-1">og:title</div>
                    <div className="text-heading">{result.og.title}</div>
                  </div>
                )}
                {result.og?.description && (
                  <div>
                    <div className="text-xs text-muted mb-1">og:description</div>
                    <div className="text-heading">{result.og.description}</div>
                  </div>
                )}
                {result.og?.site_name && (
                  <div>
                    <div className="text-xs text-muted mb-1">og:site_name</div>
                    <div className="text-heading">{result.og.site_name}</div>
                  </div>
                )}
                {result.og?.type && (
                  <div>
                    <div className="text-xs text-muted mb-1">og:type</div>
                    <div className="text-heading">{result.og.type}</div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Twitter Card */}
          {hasTwitterData(result.twitter) && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-4">Twitter Card</h3>
              {result.twitter?.image && (
                <div className="mb-4">
                  <div className="text-xs uppercase tracking-wider text-muted font-mono mb-2">Image</div>
                  <img
                    loading="lazy"
                    src={result.twitter.image}
                    alt="Twitter card preview"
                    className="max-w-full max-h-48 rounded-xl border border-line-1 object-contain"
                    onError={(e) => {
                      (e.currentTarget as HTMLImageElement).style.display = 'none';
                    }}
                  />
                </div>
              )}
              <div className="grid sm:grid-cols-2 gap-4 font-mono text-sm">
                {result.twitter?.card && (
                  <div>
                    <div className="text-xs text-muted mb-1">twitter:card</div>
                    <div className="text-heading">{result.twitter.card}</div>
                  </div>
                )}
                {result.twitter?.title && (
                  <div>
                    <div className="text-xs text-muted mb-1">twitter:title</div>
                    <div className="text-heading">{result.twitter.title}</div>
                  </div>
                )}
                {result.twitter?.description && (
                  <div>
                    <div className="text-xs text-muted mb-1">twitter:description</div>
                    <div className="text-heading">{result.twitter.description}</div>
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
