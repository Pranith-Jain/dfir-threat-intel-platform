import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { useSearchParams } from 'react-router-dom';
import { Search, ExternalLink, Loader2, Copy } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

/**
 * /dfir/google-dorks - SerpAPI-backed Google search with dork-operator hints.
 *
 * The page is a thin shell around /api/v1/google-dorks?q=… : type a query
 * (with operators like `site:`, `inurl:`, `intitle:`, `filetype:`), see the
 * organic results inline, click through to the source. Results are
 * edge-cached for an hour to keep SerpAPI quota usage sane.
 *
 * Nothing on the page leaves the browser except the search query - and the
 * server-side route strips HTML-y chars before forwarding to SerpAPI.
 */

interface DorkResult {
  title: string;
  link: string;
  displayedLink: string;
  snippet: string;
  date?: string;
  position?: number;
}

interface DorkResponse {
  query: string;
  total: number;
  results: DorkResult[];
}

interface ErrorResponse {
  error: string;
  message?: string;
  hint?: string;
  detail?: string;
}

const PRESETS: { label: string; query: string; hint: string }[] = [
  {
    label: 'Exposed .env files',
    query: 'intitle:"index of" .env',
    hint: 'Misconfigured directory listings containing dotenv files',
  },
  {
    label: 'Pastebin password leaks',
    query: 'site:pastebin.com (password OR passwd) -site:pastebin.com/u',
    hint: 'Public pastes containing credentials',
  },
  {
    label: 'SQL backup dumps',
    query: 'filetype:sql intext:INSERT INTO',
    hint: 'Indexed SQL dump files',
  },
  {
    label: 'GitHub leaks for a domain',
    query: 'site:github.com "@example.com" password',
    hint: 'Replace example.com with the target',
  },
  {
    label: 'Internal docs (Confluence)',
    query: 'site:atlassian.net OR site:confluence inurl:display',
    hint: 'Publicly indexed Confluence pages',
  },
  {
    label: 'Open S3 buckets',
    query: 'site:s3.amazonaws.com inurl:bucket',
    hint: 'Publicly listable S3 prefixes',
  },
];

type Status = 'idle' | 'loading' | 'ready' | 'error';

export default function GoogleDorks(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') ?? '';
  const [query, setQuery] = useState(initialQuery);
  const [num, setNum] = useState(20);
  const [status, setStatus] = useState<Status>('idle');
  const [data, setData] = useState<DorkResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Sync the query into the URL - share-friendly, back-button friendly.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (query.trim()) out.set('q', query.trim());
        else out.delete('q');
        return out;
      },
      { replace: true }
    );
  }, [query, setSearchParams]);

  // Auto-run on initial mount when the URL carried a `?q=` - supports
  // shareable dork links.
  useEffect(() => {
    if (initialQuery.trim()) void runSearch(initialQuery, num);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reset copied-badge after a tick.
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(null), 1200);
    return () => clearTimeout(t);
  }, [copied]);

  async function runSearch(q: string, n: number): Promise<void> {
    const trimmed = q.trim();
    if (!trimmed) return;
    setStatus('loading');
    setError(null);
    try {
      const url = `/api/v1/google-dorks?q=${encodeURIComponent(trimmed)}&num=${encodeURIComponent(String(n))}`;
      const res = await fetch(url);
      if (!res.ok) {
        const err = (await res.json().catch(() => ({}))) as ErrorResponse;
        const msg = err.message || err.detail || err.error || `HTTP ${res.status}`;
        if (res.status === 503 && err.error === 'serpapi_not_configured') {
          setError('Google-Dorks needs a SerpAPI key. Ask the admin to set the SERPAPI_API_KEY worker secret.');
        } else if (res.status === 429) {
          setError('SerpAPI rate limit / monthly quota exhausted. Try again later.');
        } else {
          setError(msg);
        }
        setStatus('error');
        setData(null);
        return;
      }
      const json = (await res.json()) as DorkResponse;
      setData(json);
      setStatus('ready');
    } catch (e) {
      console.error('runSearch failed:', errMessage(e));
      setError(errMessage(e));
      setStatus('error');
      setData(null);
    }
  }

  function onSubmit(e: React.FormEvent): void {
    e.preventDefault();
    void runSearch(query, num);
  }

  async function copyLink(link: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(link);
      setCopied(link);
    } catch (_catchErr) {
      console.error('copyLink failed:', errMessage(_catchErr));
      /* clipboard blocked; skip */
    }
  }

  const totalLabel = useMemo(() => {
    if (!data) return '';
    return data.total > 0 ? `${data.total.toLocaleString()} results` : 'no results';
  }, [data]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Search size={28} />}
      title="Google Dorks"
      description="Programmatic Google search with dork-operator hints - useful for surfacing exposed config files, public credential leaks, indexed admin panels, and similar OSINT leads. Backed by SerpAPI; results are edge-cached for an hour to keep the free tier from burning out."
    >
      <form onSubmit={onSubmit} className="mb-6">
        <label htmlFor="dork-q" className="sr-only">
          Google search query
        </label>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
            <input
              id="dork-q"
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='site:pastebin.com "password"  ·  intitle:"index of" .env  ·  filetype:sql intext:INSERT'
              className="w-full pl-10 pr-3 py-2.5 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
          </div>
          <select
            value={num}
            onChange={(e) => setNum(Number.parseInt(e.target.value, 10))}
            className="px-3 py-2.5 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm"
            aria-label="Results per page"
          >
            {[10, 20, 30, 50].map((n) => (
              <option key={n} value={n}>
                {n} results
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={status === 'loading' || !query.trim()}
            className="px-4 py-2.5 rounded-xl bg-brand-600 text-on-fill font-medium text-sm hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-2 transition-colors"
          >
            {status === 'loading' ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Search
          </button>
        </div>
      </form>

      <div className="mb-6">
        <p className="text-mini font-mono uppercase tracking-wider text-muted mb-2">Quick-start presets</p>
        <div className="flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => {
                setQuery(p.query);
                void runSearch(p.query, num);
              }}
              title={p.hint}
              className="text-mini font-mono px-2 py-1 rounded border border-line-1 bg-surface-200 text-body hover:bg-surface-300 dark:hover:bg-surface-300"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="mb-6 rounded-xl border border-rose-300/60 bg-rose-50/40 p-4 text-sm text-rose-700 dark:border-rose-700/50 dark:bg-rose-950/30 dark:text-rose-300">
          {error}
        </div>
      )}

      {data && status === 'ready' && (
        <section>
          <p className="text-xs font-mono text-muted mb-4">
            {totalLabel}
            {data.query && (
              <>
                {' · '}query: <span className="text-body">{data.query}</span>
              </>
            )}
          </p>
          <ol className="space-y-4">
            {data.results.map((r) => (
              <li key={`${r.position ?? r.link}|${r.link}`} className="list-none">
                <div className="flex items-start gap-2">
                  <div className="flex-1 min-w-0">
                    <a
                      href={sanitizeUrl(r.link) || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 font-medium text-heading hover:text-brand-600 dark:hover:text-brand-400 break-words transition-colors"
                    >
                      {r.title || r.displayedLink || r.link}
                      <ExternalLink size={12} className="opacity-60 shrink-0" />
                    </a>
                    {r.displayedLink && (
                      <p className="text-mini font-mono text-emerald-700 dark:text-emerald-400 mt-0.5 break-all">
                        {r.displayedLink}
                      </p>
                    )}
                    {r.snippet && (
                      <p className="text-sm text-muted mt-1.5">
                        {r.date && <span className="text-muted">{r.date} · </span>}
                        {r.snippet}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => void copyLink(r.link)}
                    className="shrink-0 p-1.5 rounded text-muted hover:text-body dark:hover:text-inverted hover:bg-surface-300 dark:hover:bg-surface-300"
                    title="Copy link"
                    aria-label="Copy link"
                  >
                    <Copy size={13} />
                  </button>
                </div>
                {copied === r.link && (
                  <span className="ml-auto inline-block mt-1 text-micro font-mono text-emerald-600 dark:text-emerald-400">
                    copied
                  </span>
                )}
              </li>
            ))}
          </ol>
          {data.results.length === 0 && (
            <p className="text-sm text-muted">No organic results. Try widening the query or removing operators.</p>
          )}
        </section>
      )}
    </DataPageLayout>
  );
}
