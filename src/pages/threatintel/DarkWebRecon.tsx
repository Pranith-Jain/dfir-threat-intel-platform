import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Globe, Search, Scan, Bitcoin, Network, ExternalLink, Loader2 } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { fetchJson } from '../../lib/fetch-helpers';

type ToolTab = 'onion-search' | 'onion-lookup' | 'btc-check' | 'exit-check';

interface AhmiaResult {
  title: string;
  url: string;
  description: string;
}

interface OnionLookupResult {
  address: string;
  first_seen: string | null;
  last_seen: string | null;
  status: string | null;
  tags: string[];
  ports: number[];
  title: string | null;
  bitcoin_addresses: string[];
}

interface TorExitCheckResult {
  isTorExit: boolean;
  ip: string;
}

interface ChainAbuseReport {
  id: string;
  address: string;
  category: string;
  description: string;
  createdAt: string;
  scamType: string;
}

interface ChainAbuseResult {
  address: string;
  reports: ChainAbuseReport[];
  count: number;
  /** 'unknown' means the lookup did not complete — not an absence of reports. */
  verdict?: 'clean' | 'flagged' | 'unknown';
  unavailable?: boolean;
  note?: string;
}

const TABS: Array<{
  id: ToolTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  placeholder: string;
}> = [
  {
    id: 'onion-search',
    label: 'Onion Search',
    icon: Search,
    placeholder: 'Search .onion sites, e.g. breach, marketplace',
  },
  {
    id: 'onion-lookup',
    label: 'Onion Lookup',
    icon: Scan,
    placeholder: '.onion address, e.g. facebookwkhpilnemxj7.onion',
  },
  {
    id: 'btc-check',
    label: 'BTC Abuse',
    icon: Bitcoin,
    placeholder: 'Bitcoin address, e.g. 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
  },
  { id: 'exit-check', label: 'Tor Exit', icon: Network, placeholder: 'IP address to check, e.g. 185.220.101.1' },
];

export default function DarkWebRecon(): JSX.Element {
  const [tab, setTab] = useState<ToolTab>('onion-search');
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<unknown>(null);

  async function handleSearch() {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setData(null);

    try {
      const q = input.trim();

      switch (tab) {
        case 'onion-search': {
          const r = await fetchJson<{ query: string; count: number; results: AhmiaResult[] }>(
            `/api/v1/darknet/tor-search-onion?q=${encodeURIComponent(q)}&limit=30`
          );
          setData(r);
          break;
        }
        case 'onion-lookup': {
          const r = await fetchJson<OnionLookupResult>(`/api/v1/darknet/onion-lookup?address=${encodeURIComponent(q)}`);
          setData(r);
          break;
        }
        case 'btc-check': {
          const r = await fetchJson<ChainAbuseResult>(
            `/api/v1/darknet/btc-abuse-check?address=${encodeURIComponent(q)}`
          );
          setData(r);
          break;
        }
        case 'exit-check': {
          const r = await fetchJson<TorExitCheckResult>(`/api/v1/darknet/tor-exit-check?ip=${encodeURIComponent(q)}`);
          setData(r);
          break;
        }
      }
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }

  const activeTab = TABS.find((t) => t.id === tab)!;

  function renderResults(): JSX.Element | null {
    if (!data) return null;
    switch (tab) {
      case 'onion-search':
        return <OnionSearchResults data={data as { query: string; count: number; results: AhmiaResult[] }} />;
      case 'onion-lookup':
        return <OnionLookupResults data={data as OnionLookupResult} />;
      case 'btc-check':
        return <BtcAbuseResults data={data as ChainAbuseResult} />;
      case 'exit-check':
        return <TorExitResults data={data as TorExitCheckResult} />;
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Globe className="h-6 w-6" />}
      title="Dark Web Recon"
      description="Search .onion sites, look up hidden service metadata, check BTC addresses for abuse, and scan Tor exit nodes."
      headerExtra={
        <div className="flex flex-wrap gap-1.5">
          {TABS.map((t) => (
            <button
              type="button"
              key={t.id}
              onClick={() => {
                setTab(t.id);
                setData(null);
                setError(null);
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-sm font-medium transition-colors ${
                tab === t.id
                  ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 ring-1 ring-rose-500/40'
                  : 'text-muted hover:text-slate-800 dark:hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          ))}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={handleSearch}
    >
      <div className="space-y-4">
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder={activeTab.placeholder}
            className="flex-1 [background:rgb(var(--surface-200)/0.6)] border border-line-2 rounded-xl px-4 py-2.5 text-heading placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-rose-500/50 focus:border-transparent text-sm"
          />
          <button
            type="button"
            onClick={handleSearch}
            disabled={loading || !input.trim()}
            className="flex items-center gap-2 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 disabled:text-muted rounded-xl text-sm font-medium text-on-fill transition-colors"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>

        {data === null && !loading && !error ? (
          <div className="rounded-xl border border-dashed border-line-2 p-10 text-center" role="status">
            <p className="text-sm text-muted">Enter a query above to search dark web intelligence sources.</p>
          </div>
        ) : (
          renderResults()
        )}
      </div>
    </DataPageLayout>
  );
}

function OnionSearchResults({ data }: { data: { query: string; count: number; results: AhmiaResult[] } }) {
  return (
    <div className="space-y-2">
      <p className="text-sm text-muted">
        {data.count} result{data.count !== 1 ? 's' : ''} for "{data.query}"
      </p>
      {data.results.length === 0 ? (
        <p className="text-sm text-muted">No results found.</p>
      ) : (
        data.results.map((r, i) => (
          <div
            key={i}
            className="[background:rgb(var(--surface-200)/0.4)] border border-line-1 rounded-xl p-3 hover:border-line-2 transition-colors"
          >
            <a
              href={r.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:text-rose-700 dark:hover:text-rose-300 font-medium text-sm flex items-center gap-1 transition-colors"
            >
              {r.title || 'Untitled'}
              <ExternalLink className="w-3 h-3 flex-shrink-0" />
            </a>
            {r.description && <p className="text-muted text-xs mt-1 line-clamp-2">{r.description}</p>}
            <p className="text-muted text-xs mt-1 truncate">{r.url}</p>
          </div>
        ))
      )}
    </div>
  );
}

function OnionLookupResults({ data }: { data: OnionLookupResult }) {
  return (
    <div className="[background:rgb(var(--surface-200)/0.4)] border border-line-1 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2">
        <span
          className={`px-2 py-0.5 rounded text-xs font-medium ${
            data.status === 'online'
              ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
              : data.status === 'offline'
                ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300'
                : '[background:rgb(var(--hover-100))] text-muted'
          }`}
        >
          {data.status ?? 'unknown'}
        </span>
        <span className="text-sm text-heading font-mono">{data.address}</span>
      </div>

      {(data.first_seen || data.last_seen) && (
        <div className="grid grid-cols-2 gap-3 text-xs">
          {data.first_seen && (
            <div>
              <span className="text-muted">First seen</span>
              <p className="text-body mt-0.5">{data.first_seen}</p>
            </div>
          )}
          {data.last_seen && (
            <div>
              <span className="text-muted">Last seen</span>
              <p className="text-body mt-0.5">{data.last_seen}</p>
            </div>
          )}
        </div>
      )}

      {data.title && (
        <div>
          <span className="text-xs text-muted">Title</span>
          <p className="text-sm text-heading mt-0.5">{data.title}</p>
        </div>
      )}

      {data.tags.length > 0 && (
        <div>
          <span className="text-xs text-muted">Tags</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {data.tags.map((t, i) => (
              <span key={i} className="px-2 py-0.5 [background:rgb(var(--hover-100))] rounded text-xs text-body">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.ports.length > 0 && (
        <div>
          <span className="text-xs text-muted">Open ports</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {data.ports.map((p) => (
              <span key={p} className="px-2 py-0.5 [background:rgb(var(--hover-100))] rounded text-xs text-body">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.bitcoin_addresses.length > 0 && (
        <div>
          <span className="text-xs text-muted">Associated BTC addresses</span>
          {data.bitcoin_addresses.map((addr) => (
            <p key={addr} className="text-xs text-amber-700 dark:text-amber-400 font-mono mt-0.5">
              {addr}
            </p>
          ))}
        </div>
      )}

      {!data.first_seen && !data.last_seen && data.tags.length === 0 && data.ports.length === 0 && !data.title && (
        <p className="text-sm text-muted">No metadata available for this address.</p>
      )}
    </div>
  );
}

function BtcAbuseResults({ data }: { data: ChainAbuseResult }) {
  // `verdict` is authoritative, but payloads served from a cache written
  // before the field existed won't carry it — fall back to the old count
  // heuristic rather than treating a verdict-less response as clean.
  const verdict: 'clean' | 'flagged' | 'unknown' =
    data.verdict ?? (data.unavailable ? 'unknown' : data.count > 0 ? 'flagged' : 'clean');

  if (verdict === 'unknown') {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-300">Unavailable</span>
          <span className="text-xs text-muted font-mono">{data.address}</span>
        </div>
        <p className="text-sm text-muted">{data.note ?? 'BTC abuse lookup is temporarily unavailable.'}</p>
        <p className="text-xs text-muted">
          Result unknown — this address has <em>not</em> been cleared.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span
          className={`px-2 py-0.5 rounded text-xs font-medium ${
            verdict === 'flagged'
              ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300'
              : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          }`}
        >
          {verdict === 'flagged' ? `${data.count} report${data.count !== 1 ? 's' : ''}` : 'No reports'}
        </span>
        <span className="text-xs text-muted font-mono">{data.address}</span>
      </div>

      {data.reports.length > 0 && (
        <div className="space-y-2 mt-2">
          {data.reports.map((r) => (
            <div key={r.id} className="[background:rgb(var(--surface-200)/0.4)] border border-line-1 rounded-xl p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20">
                  {r.category}
                </span>
                {r.scamType && <span className="text-xs text-muted">{r.scamType}</span>}
              </div>
              <p className="text-sm text-body">{r.description}</p>
              <p className="text-xs text-muted mt-1">{new Date(r.createdAt).toLocaleDateString()}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TorExitResults({ data }: { data: TorExitCheckResult }) {
  return (
    <div className="[background:rgb(var(--surface-200)/0.4)] border border-line-1 rounded-xl p-4">
      <div className="flex items-center gap-3">
        <span
          className={`px-3 py-1 rounded-xl text-sm font-medium ${
            data.isTorExit
              ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300 ring-1 ring-rose-500/30'
              : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 ring-1 ring-emerald-500/30'
          }`}
        >
          {data.isTorExit ? 'TOR EXIT NODE' : 'NOT A TOR EXIT NODE'}
        </span>
        <span className="text-sm text-body font-mono">{data.ip}</span>
      </div>
    </div>
  );
}
