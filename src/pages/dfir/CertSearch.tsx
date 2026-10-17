import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useRef, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link, useSearchParams } from 'react-router-dom';
import { ShieldAlert, Search, Loader2, ExternalLink, AlertTriangle, ScrollText, Globe2, Filter } from 'lucide-react';
import { CopyChip } from '../../components/dfir/CopyButton';

interface CertSearchResponse {
  domain: string;
  include_subdomains: boolean;
  total: number;
  unique_names: string[];
  issuers: Array<{ name: string; count: number }>;
  recent: Array<{
    id: string;
    dns_names: string[];
    issuer: string;
    not_before?: string;
    not_after?: string;
    revoked: boolean;
  }>;
  source: string;
  source_url: string;
  generated_at: string;
}

const SAMPLES: { label: string; domain: string }[] = [
  { label: 'anthropic.com', domain: 'anthropic.com' },
  { label: 'cloudflare.com', domain: 'cloudflare.com' },
  { label: 'github.com', domain: 'github.com' },
];

export default function CertSearch(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = searchParams.get('domain') ?? searchParams.get('q') ?? '';
  const [domain, setDomain] = useState(initial);
  const [includeSubs, setIncludeSubs] = useState(searchParams.get('include_subdomains') !== '0');
  const [data, setData] = useState<CertSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const autoFetched = useRef(false);

  const lookup = async (override?: string) => {
    const q = (override ?? domain).trim().toLowerCase();
    if (!q) return;
    if (override) setDomain(override);
    setLoading(true);
    setError(null);
    setData(null);
    setSearchParams({ domain: q, ...(includeSubs ? {} : { include_subdomains: '0' }) }, { replace: false });
    try {
      const url = `/api/v1/cert-search?domain=${encodeURIComponent(q)}&include_subdomains=${includeSubs ? '1' : '0'}`;
      const res = await fetch(url);
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const parsed = JSON.parse(body) as { error?: string };
          msg = parsed.error ?? msg;
        } catch (_catchErr) {
          console.error('CertSearch failed:', errMessage(_catchErr));
          /* use default */
        }
        throw new Error(msg);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setData((await res.json()) as CertSearchResponse);
    } catch (e) {
      logCatch(e);
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (autoFetched.current) return;
    if (initial) {
      autoFetched.current = true;
      void lookup(initial);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredNames = useMemo(() => {
    if (!data) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data.unique_names;
    return data.unique_names.filter((n) => n.includes(q));
  }, [data, filter]);

  const allNamesBlob = useMemo(() => filteredNames.join('\n'), [filteredNames]);

  return (
    <div className="max-w-6xl">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <ShieldAlert size={28} className="text-brand-600 dark:text-brand-400" /> Certificate Search
        </h1>
        <p className="text-muted mb-2 max-w-3xl leading-relaxed">
          Enumerate certificates issued for a domain. Fast subdomain discovery via Certificate Transparency logs. Free,
          no key, powered by{' '}
          <a
            href="https://sslmate.com/certspotter/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            SSLMate Cert Spotter
          </a>
          . Cached 6h at the edge.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Pairs with{' '}
          <Link to="/dfir/domain-investigator" className="text-brand-600 dark:text-brand-400 hover:underline">
            Domain Inspector
          </Link>{' '}
          (zone records) and{' '}
          <Link to="/dfir/domain-investigator" className="text-brand-600 dark:text-brand-400 hover:underline">
            Exposure Scan
          </Link>{' '}
          (open ports). CT logs are append-only; once an issuance is logged it never disappears.
        </p>
      </div>

      {/* Lookup form */}
      <section className="surface-card p-4 mb-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void lookup();
          }}
        >
          <div className="flex flex-wrap gap-2">
            <div className="relative flex-1 min-w-[260px]">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <label className="self-center text-meta font-mono text-muted cursor-pointer inline-flex items-center gap-1.5">
              <input type="checkbox" checked={includeSubs} onChange={(e) => setIncludeSubs(e.target.checked)} />
              include subdomains
            </label>
            <button
              type="submit"
              disabled={loading || !domain.trim()}
              className="px-4 py-2 rounded bg-brand-600 hover:bg-brand-700 dark:bg-brand-500 dark:hover:bg-brand-400 text-on-fill font-mono text-sm disabled:opacity-50 inline-flex items-center gap-2 transition-colors"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
              {loading ? 'searching…' : 'search'}
            </button>
          </div>
        </form>

        <div className="flex flex-wrap gap-2 mt-3 items-center">
          <span className="text-micro font-mono text-muted mr-1">samples:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.domain}
              type="button"
              onClick={() => void lookup(s.domain)}
              className="text-mini font-mono px-3 py-2 sm:px-2 sm:py-0.5 min-h-[44px] sm:min-h-0 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center"
            >
              {s.label}
            </button>
          ))}
        </div>
      </section>

      {error && (
        <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4 inline-flex items-center gap-2">
          <AlertTriangle size={14} /> {error}
        </p>
      )}

      {data && (
        <>
          {/* Summary */}
          <section className="surface-card p-4 mb-6">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">Summary</h2>
            <div className="grid sm:grid-cols-3 gap-4">
              <div>
                <div className="text-2xl font-bold text-heading">{data.total}</div>
                <div className="text-mini font-mono text-muted">total issuances</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-heading">{data.unique_names.length}</div>
                <div className="text-mini font-mono text-muted">unique DNS names</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-heading">{data.issuers.length}</div>
                <div className="text-mini font-mono text-muted">distinct issuers</div>
              </div>
            </div>
            {data.issuers.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-1.5">
                {data.issuers.slice(0, 8).map((i, ii) => (
                  <span
                    key={`${i.name}-${ii}`}
                    className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300"
                  >
                    {i.name} · {i.count}
                  </span>
                ))}
              </div>
            )}
          </section>

          {/* Unique DNS names */}
          <section className="surface-card p-4 mb-6">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono inline-flex items-center gap-2">
                <Globe2 size={12} /> Unique DNS names
                {filter && (
                  <span className="text-muted">
                    ({filteredNames.length} of {data.unique_names.length})
                  </span>
                )}
              </h2>
              <CopyChip value={allNamesBlob} label={`copy ${filteredNames.length}`} />
            </div>
            <div className="relative mb-3">
              <Filter size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="search"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="filter (e.g. api, dev, staging)"
                className="w-full pl-7 pr-3 py-1.5 bg-surface-200 border border-line-1 rounded font-mono text-mini focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              />
            </div>
            <ul className="font-mono text-meta text-body space-y-1 max-h-80 overflow-auto break-all">
              {filteredNames.map((n, ni) => (
                <li key={`${n}-${ni}`} className="border-b border-line-1 pb-1 last:border-0 flex items-baseline gap-2">
                  <span className="flex-1">{n}</span>
                  <Link
                    to={`/dfir/domain?domain=${encodeURIComponent(n.replace(/^\*\./, ''))}`}
                    className="text-micro text-brand-600 dark:text-brand-400 hover:underline shrink-0"
                  >
                    inspect
                  </Link>
                  <Link
                    to={`/dfir/subdomain-takeover?domain=${encodeURIComponent(n.replace(/^\*\./, ''))}`}
                    className="text-micro text-brand-600 dark:text-brand-400 hover:underline shrink-0"
                  >
                    takeover
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          {/* Recent issuances */}
          <section className="surface-card p-4 mb-6">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
              <ScrollText size={12} /> Recent issuances ({data.recent.length})
            </h2>
            <ul className="space-y-2">
              {data.recent.map((it, ri) => (
                <li
                  key={`${it.id ?? 'cert'}-${ri}`}
                  className={`rounded border p-2 ${
                    it.revoked ? 'border-rose-500/40 bg-rose-500/5' : 'border-line-1 bg-slate-50 dark:bg-input-200'
                  }`}
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2 mb-1">
                    <span className="text-mini font-mono text-brand-700 dark:text-brand-300">{it.issuer}</span>
                    <span className="text-micro font-mono text-muted">
                      {it.not_before?.slice(0, 10)} → {it.not_after?.slice(0, 10)}
                      {it.revoked && (
                        <span className="ml-2 px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40">
                          revoked
                        </span>
                      )}
                    </span>
                  </div>
                  <div className="text-mini font-mono text-body flex flex-wrap gap-x-3 gap-y-0.5 break-all">
                    {it.dns_names.map((n, di) => (
                      <span key={`${n}-${di}`}>{n}</span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </section>

          <p className="text-micro font-mono text-muted">
            Source:{' '}
            <a
              href={sanitizeUrl(data.source_url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:underline inline-flex items-center gap-1 transition-colors"
            >
              {data.source} <ExternalLink size={9} />
            </a>{' '}
            · resolved {new Date(data.generated_at).toLocaleTimeString()}
          </p>
        </>
      )}
    </div>
  );
}
