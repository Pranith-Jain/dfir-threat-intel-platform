import { useMemo, useState } from 'react';
import { Download, ExternalLink, Filter, Fish, Globe, RefreshCw, Search, Shield, Tag } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

interface PhishingUrl {
  url: string;
  source: 'openphish' | 'phishtank';
  first_seen?: string;
  target?: string;
  verified?: boolean;
}

interface PhishingResponse {
  generated_at: string;
  sources: Array<{ id: string; ok: boolean; count: number; stale?: boolean }>;
  total: number;
  urls: PhishingUrl[];
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch (_catchErr) {
    console.error('extractDomain failed:', errMessage(_catchErr));
    return url.slice(0, 40);
  }
}

function extractTLD(url: string): string {
  const host = extractDomain(url);
  const parts = host.split('.');
  return parts.length > 1 ? parts[parts.length - 1]! : '';
}

const RISKY_TLDS = new Set([
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'xyz',
  'top',
  'buzz',
  'icu',
  'club',
  'online',
  'site',
  'work',
  'click',
  'link',
  'fun',
  'monster',
  'surf',
]);

export default function PhishFeed(): JSX.Element {
  const [query, setQuery] = useState('');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'openphish' | 'phishtank'>('all');
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [sortKey, setSortKey] = useState<'domain' | 'first_seen' | 'source'>('first_seen');
  const [exportFormat, setExportFormat] = useState<'txt' | 'hosts' | 'adblock'>('txt');

  const { data, loading, error, refetch } = useDataFetch<PhishingResponse>({
    url: '/api/v1/phishing-urls',
    ttl: 300_000,
    staleWhileRevalidate: true,
  });

  const filtered = useMemo(() => {
    if (!data) return [];
    let items = data.urls;

    if (sourceFilter !== 'all') {
      items = items.filter((u) => u.source === sourceFilter);
    }
    if (verifiedOnly) {
      items = items.filter((u) => u.verified !== false);
    }
    if (query.trim()) {
      const q = query.trim().toLowerCase();
      items = items.filter(
        (u) =>
          u.url.toLowerCase().includes(q) ||
          extractDomain(u.url).toLowerCase().includes(q) ||
          (u.target?.toLowerCase().includes(q) ?? false)
      );
    }

    items.sort((a, b) => {
      if (sortKey === 'domain') return extractDomain(a.url).localeCompare(extractDomain(b.url));
      if (sortKey === 'source') return a.source.localeCompare(b.source);
      return (b.first_seen ?? '').localeCompare(a.first_seen ?? '');
    });

    return items;
  }, [data, query, sourceFilter, verifiedOnly, sortKey]);

  const stats = useMemo(() => {
    if (!data) return { total: 0, openphish: 0, phishtank: 0, riskyTld: 0 };
    const urls = data.urls;
    return {
      total: urls.length,
      openphish: urls.filter((u) => u.source === 'openphish').length,
      phishtank: urls.filter((u) => u.source === 'phishtank').length,
      riskyTld: urls.filter((u) => RISKY_TLDS.has(extractTLD(u.url))).length,
    };
  }, [data]);

  const exportList = useMemo(() => {
    if (exportFormat === 'hosts') {
      return filtered.map((u) => `0.0.0.0 ${extractDomain(u.url)}`).join('\n');
    }
    if (exportFormat === 'adblock') {
      return filtered.map((u) => `||${extractDomain(u.url)}^`).join('\n');
    }
    return filtered.map((u) => u.url).join('\n');
  }, [filtered, exportFormat]);

  const doExport = () => {
    const ext = exportFormat === 'hosts' ? 'hosts' : exportFormat === 'adblock' ? 'txt' : 'txt';
    const mime = 'text/plain';
    const blob = new Blob([exportList], { type: mime });
    downloadBlob(blob, `phish-feed-${new Date().toISOString().slice(0, 10)}.${ext}`);
  };

  const targetBreakdown = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    for (const u of data.urls) {
      if (u.target) counts.set(u.target, (counts.get(u.target) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  }, [data]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Fish className="w-7 h-7" />}
      title="Phish Feed"
      description="Live phishing URLs from OpenPhish with built-in brand detection. PhishTank enrichment is optional (requires API key). Export as plain list, hosts file, or AdBlock rules."
      maxWidthClass="max-w-6xl"
    >
      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
        {[
          { label: 'Total URLs', value: stats.total, icon: Globe, cls: 'text-slate-500' },
          { label: 'OpenPhish', value: stats.openphish, icon: Shield, cls: 'text-rose-600 dark:text-rose-400' },
          { label: 'PhishTank', value: stats.phishtank, icon: Tag, cls: 'text-sky-600 dark:text-sky-400' },
          { label: 'Risky TLDs', value: stats.riskyTld, icon: Filter, cls: 'text-amber-600 dark:text-amber-400' },
        ].map(({ label, value, icon: Icon, cls }) => (
          <div key={label} className="surface-card/50 shadow-e1 p-2.5">
            <div className={`flex items-center gap-1.5 text-mini uppercase tracking-wider mb-0.5 ${cls}`}>
              <Icon className="w-3 h-3" /> {label}
            </div>
            <div className="text-lg font-bold text-heading">{value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            type="text"
            placeholder="Search URL, domain, or target brand…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
          />
        </div>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as 'all' | 'openphish' | 'phishtank')}
          className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
        >
          <option value="all">All sources</option>
          <option value="openphish">OpenPhish</option>
          <option value="phishtank">PhishTank</option>
        </select>
        <button
          type="button"
          onClick={() => setVerifiedOnly(!verifiedOnly)}
          className={`px-3 py-2 rounded-xl border text-xs font-medium flex items-center gap-1.5 transition ${
            verifiedOnly
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
              : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'
          }`}
        >
          <Shield className="w-3.5 h-3.5" /> Verified only
        </button>
        <button
          type="button"
          onClick={() => refetch()}
          className="px-3 py-2 rounded-xl border border-line-2 text-muted hover:border-line-3 dark:hover:border-slate-600 text-sm flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Sort + Export */}
      <div className="flex items-center gap-3 mb-4">
        <span className="text-xs text-muted font-mono">sort:</span>
        {(['first_seen', 'domain', 'source'] as const).map((k) => (
          <button
            type="button"
            key={k}
            onClick={() => setSortKey(k)}
            className={`px-2 py-1 rounded text-xs font-mono border transition ${
              sortKey === k
                ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'
            }`}
          >
            {k === 'first_seen' ? 'newest' : k}
          </button>
        ))}
        <div className="flex-1" />
        <select
          value={exportFormat}
          onChange={(e) => setExportFormat(e.target.value as 'txt' | 'hosts' | 'adblock')}
          className="px-2 py-1 rounded text-xs font-mono border border-line-2 bg-surface-100 text-body focus:outline-none focus:border-rose-500"
        >
          <option value="txt">Plain list (.txt)</option>
          <option value="hosts">Hosts file</option>
          <option value="adblock">AdBlock / uBO</option>
        </select>
        <button
          type="button"
          onClick={doExport}
          className="px-3 py-1.5 rounded-xl border border-line-2 text-muted hover:border-line-3 dark:hover:border-slate-600 text-xs flex items-center gap-1.5 transition-colors"
        >
          <Download className="w-3.5 h-3.5" /> Export ({filtered.length})
        </button>
      </div>

      {/* Results */}
      {data && (
        <div className="flex items-center justify-between text-xs text-muted mb-3 font-mono">
          <span>
            {filtered.length} of {data.total} URLs
          </span>
          <span>updated {relativeAgo(data.generated_at)}</span>
        </div>
      )}

      <DataState loading={loading} error={error} empty={filtered.length === 0} onRetry={refetch} rows={8}>
        <div className="space-y-1">
          {filtered.slice(0, 200).map((u, i) => {
            const domain = extractDomain(u.url);
            const tld = extractTLD(u.url);
            const risky = RISKY_TLDS.has(tld);
            return (
              <div
                key={`${domain}-${i}`}
                className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-mono ${
                  risky
                    ? 'border-amber-300/50 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-900/5'
                    : 'border-line-1 bg-white dark:bg-surface-200/30'
                } hover:bg-surface-200 dark:hover:bg-surface-200/40 transition`}
              >
                <a
                  href={sanitizeUrl(u.url)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-0 truncate text-body hover:text-rose-600 dark:hover:text-rose-400 flex items-center gap-1 transition-colors"
                >
                  {u.url} <ExternalLink className="w-3 h-3 shrink-0" />
                </a>
                {u.target && (
                  <span className="px-1.5 py-0.5 text-micro rounded border border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300 shrink-0">
                    {u.target}
                  </span>
                )}
                {u.verified && (
                  <span className="px-1.5 py-0.5 text-micro rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 shrink-0">
                    verified
                  </span>
                )}
                {risky && (
                  <span className="px-1.5 py-0.5 text-micro rounded border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300 shrink-0">
                    .{tld}
                  </span>
                )}
                <span
                  className={`px-1.5 py-0.5 text-micro rounded border shrink-0 ${
                    u.source === 'openphish'
                      ? 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                      : 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                  }`}
                >
                  {u.source}
                </span>
                {u.first_seen && <span className="text-muted shrink-0">{relativeAgo(u.first_seen)}</span>}
              </div>
            );
          })}
          {filtered.length > 200 && (
            <div className="text-center py-3 text-xs text-muted font-mono">
              Showing 200 of {filtered.length} - use export to download all
            </div>
          )}
        </div>
      </DataState>

      {/* Target brand breakdown */}
      {targetBreakdown.length > 0 && (
        <div className="mt-8 surface-card/50 p-4">
          <h3 className="text-sm font-semibold text-heading mb-3">Targeted Brands (PhishTank)</h3>
          <div className="space-y-1.5">
            {targetBreakdown.map(([brand, count]) => (
              <button
                type="button"
                key={brand}
                onClick={() => setQuery(brand === query ? '' : brand)}
                className={`w-full flex items-center gap-2 text-xs px-2 py-1 rounded transition ${
                  query === brand
                    ? 'bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300'
                    : 'hover:bg-slate-50 dark:hover:bg-surface-300/50 text-muted'
                }`}
              >
                <span className="font-mono truncate flex-1 text-left">{brand}</span>
                <span className="font-mono text-muted">{count}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
        Sources: OpenPhish + PhishTank (optional) · Built-in brand detection for target attribution · Cached 1h
        server-side
      </div>
    </DataPageLayout>
  );
}
