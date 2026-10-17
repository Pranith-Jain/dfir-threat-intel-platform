import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useRef, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import {
  KeyRound,
  Search,
  Globe,
  User,
  MapPin,
  Bug,
  RefreshCw,
  Copy,
  Check,
  ExternalLink,
  Shield,
  Clock,
  Building2,
} from 'lucide-react';

type TabId = 'email' | 'domain' | 'username' | 'ip' | 'overview' | 'infection';

const TABS: Array<{ id: TabId; label: string; icon: typeof KeyRound; placeholder: string; description: string }> = [
  {
    id: 'email',
    label: 'Email',
    icon: Search,
    placeholder: '[email protected]',
    description: 'Search compromised credentials by email address.',
  },
  {
    id: 'domain',
    label: 'Domain',
    icon: Globe,
    placeholder: 'example.com',
    description: 'Search domain-wide infostealer compromises.',
  },
  {
    id: 'username',
    label: 'Username',
    icon: User,
    placeholder: 'johndoe',
    description: 'Search compromised credentials by username.',
  },
  {
    id: 'ip',
    label: 'IP / CIDR',
    icon: MapPin,
    placeholder: '192.168.1.1',
    description: 'Search compromises by IP address or CIDR range.',
  },
  {
    id: 'overview',
    label: 'Domain Overview',
    icon: Building2,
    placeholder: 'example.com',
    description: 'Domain compromise statistics and risk posture.',
  },
  {
    id: 'infection',
    label: 'Infection Analysis',
    icon: Bug,
    placeholder: '[IN]175.101.37.65',
    description: 'AI-powered infection source tracing (stealer ID).',
  },
];

interface StealerEntry {
  stealer_id: string;
  stealer_family: string;
  date_compromised: string;
  date_uploaded: string;
  ip: string;
  computer_name: string;
  operating_system: string;
  employee_at?: string[];
  client_at?: string[];
  credentials: Array<{ url: string; domain: string; username: string; type: string }>;
}

interface SearchResult {
  api_version: string;
  found: boolean;
  total_infections: number;
  total_credentials?: number;
  has_more?: boolean;
  results: StealerEntry[];
  generated_at: string;
  error?: string;
}

interface DomainOverviewResult {
  domain: string;
  overview: {
    compromised_employees: number;
    compromised_users: number;
    last_employee_compromised?: string;
    last_user_compromised?: string;
  } | null;
  generated_at: string;
  error?: string;
}

interface InfectionResult {
  stealer: string;
  analysis: {
    likely_infection_url: string;
    infection_confidence: number;
    infection_reasoning: string;
    infection_flow: Array<{ timestamp: string; url: string; notes: string }>;
    analyst_summary: string;
  };
  generated_at: string;
  error?: string;
}

function fmtDate(s: string): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch (_catchErr) {
    console.error('fmtDate failed:', errMessage(_catchErr));
    return s;
  }
}

function fmtDateTime(s: string): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch (_catchErr) {
    console.error('fmtDateTime failed:', errMessage(_catchErr));
    return s;
  }
}

const TYPE_COLORS: Record<string, string> = {
  employee: 'bg-brand-500/10 text-brand-700 dark:text-brand-300 border-brand-500/30',
  user: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
  third_party: 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30',
  client: 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30',
};

export default function InfostealerIntel(): JSX.Element {
  const [tab, setTab] = useState<TabId>('email');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const mountedRef = useRef(true);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [searchResult, setSearchResult] = useState<SearchResult | null>(null);
  const [overviewResult, setOverviewResult] = useState<DomainOverviewResult | null>(null);
  const [infectionResult, setInfectionResult] = useState<InfectionResult | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (copyTimer.current) clearTimeout(copyTimer.current);
    };
  }, []);

  const reset = useCallback(() => {
    setSearchResult(null);
    setOverviewResult(null);
    setInfectionResult(null);
    setError(null);
  }, []);

  const handleTab = useCallback(
    (t: TabId) => {
      setTab(t);
      setQuery('');
      reset();
    },
    [reset]
  );

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    reset();
    try {
      let url = '';
      if (tab === 'email') url = `/api/v1/breach/hudsonrock?email=${encodeURIComponent(query.trim())}`;
      else if (tab === 'domain') url = `/api/v1/breach/hudsonrock/domain?domain=${encodeURIComponent(query.trim())}`;
      else if (tab === 'username') url = `/api/v1/hudsonrock/username?username=${encodeURIComponent(query.trim())}`;
      else if (tab === 'ip') url = `/api/v1/hudsonrock/ip?ip=${encodeURIComponent(query.trim())}`;
      else if (tab === 'overview')
        url = `/api/v1/hudsonrock/domain-overview?domain=${encodeURIComponent(query.trim())}`;
      else if (tab === 'infection')
        url = `/api/v1/hudsonrock/infection-analysis?stealer=${encodeURIComponent(query.trim())}`;
      const res = await fetch(url);
      if (!mountedRef.current) return;
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(body || `HTTP ${res.status}`);
      }
      const data = await res.json();
      if (!mountedRef.current) return;
      if (tab === 'overview') setOverviewResult(data as DomainOverviewResult);
      else if (tab === 'infection') setInfectionResult(data as InfectionResult);
      else setSearchResult(data as SearchResult);
    } catch (e) {
      logCatch(e);
      if (!mountedRef.current) return;
      setError((e as Error).message);
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [tab, query, reset]);

  const handleCopyJson = useCallback(() => {
    const data = tab === 'overview' ? overviewResult : tab === 'infection' ? infectionResult : searchResult;
    if (!data) return;
    navigator.clipboard.writeText(JSON.stringify(data, null, 2)).catch(() => {});
    setCopied(true);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 2000);
  }, [tab, overviewResult, infectionResult, searchResult]);

  const currentTab = TABS.find((t) => t.id === tab)!;
  const TabIcon = currentTab.icon;

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<KeyRound size={28} />}
      title="Infostealer Intelligence"
      description="Search compromised credentials, domain exposure, and infection analysis from 30M+ infostealer-infected machines. Powered by Hudson Rock Cavalier API."
    >
      {/* Tabs */}
      <div className="flex flex-wrap gap-1.5 mb-6">
        {TABS.map((t) => {
          const TIcon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => handleTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-sm font-medium transition-colors ${
                tab === t.id
                  ? 'bg-brand-600/10 text-brand-600 dark:text-brand-400 border border-brand-600/30'
                  : 'border border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <TIcon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Input + search */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <TabIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder={currentTab.placeholder}
              className="w-full pl-10 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400 font-mono"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={loading || !query.trim()}
            className="px-4 py-2.5 bg-brand-600 text-on-fill font-medium rounded-xl text-sm hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
          {(searchResult || overviewResult || infectionResult) && (
            <button
              onClick={handleCopyJson}
              className="px-3 py-2.5 border border-line-1 rounded-xl text-sm text-muted hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
            </button>
          )}
        </div>
        <p className="text-xs text-muted mt-2">{currentTab.description}</p>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 p-4 text-sm text-rose-700 dark:text-rose-300 mb-6">
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-16 text-muted">
          <RefreshCw className="w-5 h-5 animate-spin mr-2" />
          Querying Hudson Rock…
        </div>
      )}

      {/* ── Search results (email / domain / username / ip) ──────────── */}
      {!loading && searchResult && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-4 text-sm text-muted">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl border border-line-1 font-mono text-xs">
              v3
            </span>
            <span>
              Infections: <strong className="text-heading">{searchResult.total_infections}</strong>
            </span>
            {searchResult.total_credentials != null && (
              <span>
                Credentials: <strong className="text-heading">{searchResult.total_credentials}</strong>
              </span>
            )}
            {searchResult.has_more && (
              <span className="text-amber-600 dark:text-amber-400">More results available</span>
            )}
          </div>

          {!searchResult.found && (
            <div className="surface-card/40 shadow-e1 p-8 text-center text-muted">
              No infostealer compromises found.
            </div>
          )}

          {(searchResult.results ?? []).map((entry, i) => (
            <div key={i} className="surface-card/40 shadow-e1 overflow-hidden">
              <div className="px-4 py-3 border-b border-line-1 flex flex-wrap items-center gap-2.5 text-sm">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/20">
                  {entry.stealer_family}
                </span>
                <span className="text-muted">·</span>
                <span className="text-muted">{fmtDate(entry.date_compromised)}</span>
                <span className="text-muted">·</span>
                <span className="font-mono text-xs text-muted">{entry.ip}</span>
                <span className="text-muted">·</span>
                <span className="text-muted">{entry.computer_name}</span>
                <span className="text-muted">·</span>
                <span className="text-xs text-muted">{entry.operating_system}</span>
                {entry.employee_at?.length ? (
                  <>
                    <span className="text-muted">·</span>
                    <span className="inline-flex items-center gap-1 text-xs text-brand-600 dark:text-brand-400">
                      <Building2 className="w-3 h-3" />
                      {entry.employee_at.join(', ')}
                    </span>
                  </>
                ) : null}
              </div>
              <div className="divide-y divide-line-1 dark:divide-slate-800/50">
                {(entry.credentials ?? []).map((cred, j) => (
                  <div key={j} className="px-4 py-2 flex flex-wrap items-center gap-2.5 text-xs">
                    <span
                      className={`inline-block px-2 py-0.5 rounded-full border text-xs ${TYPE_COLORS[cred.type] ?? 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-surface-300 dark:text-muted dark:border-line-1'}`}
                    >
                      {cred.type}
                    </span>
                    <span className="font-mono text-body truncate max-w-[300px]" title={cred.url}>
                      {cred.url}
                    </span>
                    <span className="text-muted">·</span>
                    <span className="text-muted">{cred.domain}</span>
                    <span className="text-muted">·</span>
                    <span className="font-mono text-muted">{cred.username}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Domain Overview ──────────────────────────────────────────── */}
      {!loading && overviewResult && (
        <div className="space-y-4">
          {overviewResult.error ? (
            <div className="rounded-xl border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 p-4 text-sm text-rose-700 dark:text-rose-300">
              {overviewResult.error}
            </div>
          ) : overviewResult.overview ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <OverviewCard
                label="Compromised Employees"
                value={overviewResult.overview.compromised_employees}
                accent="text-brand-600 dark:text-brand-400"
              />
              <OverviewCard
                label="Compromised Users"
                value={overviewResult.overview.compromised_users}
                accent="text-emerald-600 dark:text-emerald-400"
              />
              <OverviewCard
                label="Last Employee Compromised"
                value={fmtDate(overviewResult.overview.last_employee_compromised ?? '')}
                accent="text-amber-600 dark:text-amber-400"
              />
              <OverviewCard
                label="Last User Compromised"
                value={fmtDate(overviewResult.overview.last_user_compromised ?? '')}
                accent="text-purple-600 dark:text-purple-400"
              />
            </div>
          ) : (
            <div className="surface-card/40 shadow-e1 p-8 text-center text-muted">
              No overview data available for this domain.
            </div>
          )}
        </div>
      )}

      {/* ── Infection Analysis ───────────────────────────────────────── */}
      {!loading && infectionResult && (
        <div className="space-y-4">
          {infectionResult.error ? (
            <div className="rounded-xl border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 p-4 text-sm text-rose-700 dark:text-rose-300">
              {infectionResult.error}
            </div>
          ) : infectionResult.analysis ? (
            <div className="space-y-4">
              <div className="surface-card/40 shadow-e1 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <Shield className="w-5 h-5 text-brand-600 dark:text-brand-400" />
                  <span className="font-medium">Infection Confidence</span>
                  <span
                    className={`text-lg font-bold ${infectionResult.analysis.infection_confidence >= 0.7 ? 'text-emerald-600 dark:text-emerald-400' : infectionResult.analysis.infection_confidence >= 0.4 ? 'text-amber-600 dark:text-amber-400' : 'text-rose-600 dark:text-rose-400'}`}
                  >
                    {(infectionResult.analysis.infection_confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="text-sm text-body mb-2">{infectionResult.analysis.analyst_summary}</p>
                <p className="text-xs text-muted">
                  Likely source:{' '}
                  <a
                    href={infectionResult.analysis.likely_infection_url}
                    target="_blank"
                    rel="noopener"
                    className="text-brand-600 dark:text-brand-400 hover:underline break-all inline-flex items-center gap-1 transition-colors"
                  >
                    {infectionResult.analysis.likely_infection_url} <ExternalLink className="w-3 h-3" />
                  </a>
                </p>
              </div>

              <div className="surface-card/40 shadow-e1 p-5">
                <h3 className="font-medium mb-3 flex items-center gap-2 text-sm">
                  <Clock className="w-4 h-4 text-muted" /> Infection Flow
                </h3>
                <div className="space-y-3">
                  {(infectionResult.analysis.infection_flow ?? []).map((step, i) => (
                    <div key={i} className="flex gap-3 text-sm">
                      <div className="flex flex-col items-center">
                        <div className="w-2 h-2 rounded-full bg-brand-600 dark:bg-brand-400 shrink-0 mt-1.5" />
                        {i < infectionResult.analysis.infection_flow.length - 1 && (
                          <div className="w-px flex-1 bg-track" />
                        )}
                      </div>
                      <div className="pb-3">
                        <div className="text-xs text-muted mb-0.5">{fmtDateTime(step.timestamp)}</div>
                        <div className="font-mono text-xs text-brand-600 dark:text-brand-400 break-all">{step.url}</div>
                        <div className="text-muted text-xs mt-0.5">{step.notes}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="surface-card/40 shadow-e1 p-8 text-center text-muted">
              No infection analysis available for this stealer.
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="mt-8 pt-4 border-t border-line-1 text-xs text-muted flex items-center gap-2">
        <KeyRound className="w-3 h-3" />
        Powered by Hudson Rock Cavalier API
        <span className="mx-1">·</span>
        <a
          href="https://docs.hudsonrock.com/"
          target="_blank"
          rel="noopener"
          className="hover:text-muted dark:hover:text-inverted inline-flex items-center gap-1 transition-colors"
        >
          Docs <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </DataPageLayout>
  );
}

function OverviewCard({ label, value, accent }: { label: string; value: string | number; accent: string }) {
  return (
    <div className="surface-card/40 shadow-e1 p-4">
      <div className="text-xs text-muted mb-1">{label}</div>
      <div className={`text-2xl font-bold ${accent}`}>{value}</div>
    </div>
  );
}
