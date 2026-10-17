import { useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { CheckCircle2, ExternalLink, Loader2, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * Destroylist — phishing & scam domain blacklist explorer
 * (github.com/phishdestroy/destroylist, MIT).
 *
 * Reads the replicated manifest through the platform API:
 *   GET /api/v1/threat-intel/destroylist            → index + counts
 *   GET /api/v1/threat-intel/destroylist/check      → single-domain membership
 *   GET /api/v1/threat-intel/destroylist/search     → root-domain substring search
 */

interface DestroylistIndex {
  source: string;
  license: string;
  syncedAt: string;
  bucketCount: number;
  counts: {
    primary: number;
    primaryRoots: number;
    community: number | null;
    primaryActive: number | null;
  };
  feeds?: Record<string, string>;
}

interface CheckResult {
  domain: string;
  listed: boolean;
  matched: string | null;
  verdict: 'malicious' | 'clean';
  syncedAt?: string;
}

interface SearchResult {
  query: string;
  total: number;
  truncated: boolean;
  roots: string[];
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

function fmt(n: number | null | undefined): string {
  return typeof n === 'number' ? n.toLocaleString() : '—';
}

export default function Destroylist(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<DestroylistIndex>({
    url: '/api/v1/threat-intel/destroylist',
    ttl: 300_000,
  });

  const [checkDomain, setCheckDomain] = useState('');
  const [checkResult, setCheckResult] = useState<CheckResult | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [searchQ, setSearchQ] = useState('');
  const [searchResult, setSearchResult] = useState<SearchResult | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);

  async function runCheck() {
    if (!checkDomain.trim()) return;
    setChecking(true);
    setCheckResult(null);
    setCheckError(null);
    try {
      const res = await fetch(
        `/api/v1/threat-intel/destroylist/check?domain=${encodeURIComponent(checkDomain.trim())}`,
        {
          signal: AbortSignal.timeout(15_000),
        }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCheckResult((await res.json()) as CheckResult);
    } catch (e) {
      setCheckError(errMessage(e));
    } finally {
      setChecking(false);
    }
  }

  async function runSearch() {
    if (searchQ.trim().length < 3) return;
    setSearching(true);
    setSearchResult(null);
    setSearchError(null);
    try {
      const res = await fetch(
        `/api/v1/threat-intel/destroylist/search?q=${encodeURIComponent(searchQ.trim())}&limit=100`,
        {
          signal: AbortSignal.timeout(15_000),
        }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setSearchResult((await res.json()) as SearchResult);
    } catch (e) {
      setSearchError(errMessage(e));
    } finally {
      setSearching(false);
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="Destroylist"
      description="Phishing & scam domain blacklist (phishdestroy/destroylist, MIT) — curated primary feed replicated locally plus a 13+ source community aggregate via the live API. Domain membership checks run against the local manifest with zero external egress."
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      {/* Stats band */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        {[
          ['Primary domains', fmt(data?.counts.primary)],
          ['DNS-active', fmt(data?.counts.primaryActive)],
          ['Community aggregate', fmt(data?.counts.community)],
          ['Root domains', fmt(data?.counts.primaryRoots)],
        ].map(([label, value]) => (
          <div key={label} className="surface-card p-4 text-center">
            <div className="text-2xl font-display font-bold text-heading tabular-nums">{value}</div>
            <div className="text-micro font-mono uppercase tracking-wider text-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Domain check */}
      <section className="surface-card p-5 mb-6">
        <h2 className="text-lg font-bold text-heading mb-3">Check a domain</h2>
        <div className="flex gap-2">
          <input
            value={checkDomain}
            onChange={(e) => setCheckDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runCheck()}
            placeholder="domain or URL — e.g. evil.example.com"
            className={inputCls}
            aria-label="Domain to check against destroylist"
          />
          <button
            onClick={() => void runCheck()}
            disabled={checking || !checkDomain.trim()}
            className="px-4 py-2 bg-brand-600 text-on-fill rounded-xl text-sm font-medium hover:bg-brand-500 disabled:opacity-50 whitespace-nowrap inline-flex items-center gap-2"
          >
            {checking ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Check
          </button>
        </div>
        {checkError && (
          <p role="alert" className="mt-3 text-sm text-rose-600 dark:text-rose-400">
            Check failed: {checkError}
          </p>
        )}
        {checkResult && (
          <div
            role="status"
            className={`mt-4 p-4 rounded-xl border ${
              checkResult.listed
                ? 'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30'
                : 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/30'
            }`}
          >
            <div className="flex items-center gap-2">
              {checkResult.listed ? (
                <ShieldAlert size={18} className="text-rose-600 dark:text-rose-400" />
              ) : (
                <ShieldCheck size={18} className="text-emerald-600 dark:text-emerald-400" />
              )}
              <span
                className={`font-semibold text-sm ${
                  checkResult.listed ? 'text-rose-700 dark:text-rose-300' : 'text-emerald-700 dark:text-emerald-300'
                }`}
              >
                {checkResult.listed ? 'Listed — malicious' : 'Not listed'}
                {checkResult.matched ? ` (matched: ${checkResult.matched})` : ''}
              </span>
            </div>
          </div>
        )}
      </section>

      {/* Root-domain search */}
      <section className="surface-card p-5 mb-6">
        <h2 className="text-lg font-bold text-heading mb-3">Search root domains</h2>
        <div className="flex gap-2">
          <input
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runSearch()}
            placeholder="substring in root domain (min 3 chars)"
            className={inputCls}
            aria-label="Search destroylist root domains"
          />
          <button
            onClick={() => void runSearch()}
            disabled={searching || searchQ.trim().length < 3}
            className="px-4 py-2 border border-line-1 rounded-xl text-sm font-medium hover:bg-surface-200 dark:hover:bg-surface-300 disabled:opacity-50 whitespace-nowrap"
          >
            Search
          </button>
        </div>
        {searchError && (
          <p role="alert" className="mt-3 text-sm text-rose-600 dark:text-rose-400">
            Search failed: {searchError}
          </p>
        )}
        {searchResult && searchResult.roots.length > 0 && (
          <ul className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5 max-h-80 overflow-y-auto">
            {searchResult.roots.map((d) => (
              <li key={d} className="inline-flex items-center gap-1.5 text-sm font-mono text-body">
                <CheckCircle2 size={12} className="text-rose-500 shrink-0" aria-hidden="true" />
                <span className="truncate">{d}</span>
              </li>
            ))}
          </ul>
        )}
        {searchResult && searchResult.roots.length === 0 && (
          <p className="mt-4 text-sm text-muted">No root domains match “{searchResult.query}”.</p>
        )}
      </section>

      {/* Feed info footer */}
      <footer className="pt-6 border-t border-line-1 text-sm text-muted">
        <p>
          Primary feed synced <strong>{data ? relativeAgo(data.syncedAt) : '—'}</strong> · MIT license ·{' '}
          <a
            href="https://github.com/phishdestroy/destroylist"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
          >
            upstream repo <ExternalLink size={12} />
          </a>{' '}
          ·{' '}
          <a
            href="/api/v1/threat-intel/destroylist/roots.txt"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
          >
            roots.txt for Pi-hole / AdGuard <ExternalLink size={12} />
          </a>
        </p>
        <p className="mt-2 flex items-start gap-1.5">
          <ShieldAlert size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          Domain NOT listed ≠ safe — scammers cloak phishing pages from scanners. Use the full primary list for complete
          protection.
        </p>
      </footer>
    </DataPageLayout>
  );
}
