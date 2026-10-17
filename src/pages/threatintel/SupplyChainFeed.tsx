import { useCallback, useEffect, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { fetchJsonCached } from '../../lib/api-client';
import { errMessage } from '../../lib/log';
import {
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  HelpCircle,
  Loader2,
  Package,
  RefreshCw,
  Search,
  Shield,
  ShieldOff,
} from 'lucide-react';

// ── Types ───────────────────────────────────────────────────────────────

interface FeedEntry {
  name: string;
  ecosystem: string;
  ossf_url: string;
}

interface FeedResponse {
  schema_version: string;
  command: string;
  data: {
    total: number;
    ecosystem_filter: string | null;
    entries: FeedEntry[];
    ecosystem_breakdown: Record<string, number>;
    source: string;
    source_url: string;
  };
  timestamp: string;
  upstream_error?: string;
  stale?: boolean;
}

interface CheckResult {
  ref: string;
  purl: string;
  verdict: 'clean' | 'malicious' | 'vulnerable' | 'unknown';
  confidence: 'high' | 'medium' | 'low';
  ids: string[];
  package_ecosystem: string;
  package_name: string;
  registry_url: string;
  advisories: Array<{ id: string; summary: string; source: string }>;
}

interface CheckResponse {
  schema_version: string;
  command: string;
  data: CheckResult;
  timestamp: string;
}

// ── Constants ───────────────────────────────────────────────────────────

const ECOSYSTEMS = [
  { id: 'npm', label: 'npm', color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300', icon: 'N' },
  {
    id: 'pypi',
    label: 'PyPI',
    color: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300',
    icon: 'Py',
  },
  { id: 'go', label: 'Go', color: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300', icon: 'Go' },
  {
    id: 'maven',
    label: 'Maven',
    color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    icon: 'Mv',
  },
  {
    id: 'rubygems',
    label: 'RubyGems',
    color: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
    icon: 'Rb',
  },
  {
    id: 'crates.io',
    label: 'Cargo',
    color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    icon: 'Cr',
  },
];

const VERDICT_META: Record<string, { icon: typeof Shield; color: string; bg: string; label: string }> = {
  malicious: {
    icon: ShieldOff,
    color: 'text-rose-700 dark:text-rose-300',
    bg: 'border-rose-500/30 bg-rose-500/10',
    label: 'MALICIOUS',
  },
  clean: {
    icon: CheckCircle,
    color: 'text-emerald-700 dark:text-emerald-300',
    bg: 'border-emerald-500/30 bg-emerald-500/10',
    label: 'CLEAN',
  },
  vulnerable: {
    icon: AlertTriangle,
    color: 'text-amber-700 dark:text-amber-300',
    bg: 'border-amber-500/30 bg-amber-500/10',
    label: 'VULNERABLE',
  },
  unknown: {
    icon: HelpCircle,
    color: 'text-muted',
    bg: 'border-slate-400/30 bg-slate-400/10',
    label: 'UNKNOWN',
  },
};

// ── Main component ──────────────────────────────────────────────────────

export default function SupplyChainFeed(): JSX.Element {
  const [feed, setFeed] = useState<FeedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [ecoFilter, setEcoFilter] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const [checkInput, setCheckInput] = useState('');
  const [checkResult, setCheckResult] = useState<CheckResponse | null>(null);
  const [checkLoading, setCheckLoading] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);

  const fetchFeed = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ limit: '200' });
      if (ecoFilter) params.set('ecosystem', ecoFilter);
      setFeed(await fetchJsonCached<FeedResponse>(`/api/v1/depx/feed?${params}`, 30_000));
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [ecoFilter]);

  useEffect(() => {
    void fetchFeed();
  }, [fetchFeed]);

  const handleCheck = useCallback(async () => {
    const input = checkInput.trim();
    if (!input) return;
    setCheckLoading(true);
    setCheckError(null);
    setCheckResult(null);
    try {
      const params = input.includes(':')
        ? new URLSearchParams({ ref: input })
        : new URLSearchParams({ ecosystem: 'npm', package: input });
      setCheckResult(await fetchJsonCached<CheckResponse>(`/api/v1/depx/feed/check?${params}`, 15_000));
    } catch (e) {
      setCheckError(errMessage(e));
    } finally {
      setCheckLoading(false);
    }
  }, [checkInput]);

  const ecoBreakdown = feed?.data.ecosystem_breakdown ?? {};
  const totalFeed = feed?.data.total ?? 0;
  const maxEcoCount = Math.max(...Object.values(ecoBreakdown), 1);

  const filteredEntries = (feed?.data.entries ?? []).filter(
    (e) => !searchQuery || e.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <DataPageLayout
      title="Supply-Chain Feed"
      description="Malicious package intelligence from the OpenSSF Malicious Packages database"
      icon={<Package size={20} />}
      accentClass="text-rose-500"
      backTo="/threatintel"
    >
      {/* ── Package check ───────────────────────────────────────────── */}
      <div className="rounded-xl border border-line-1 bg-surface-100 p-4 mb-6">
        <h3 className="text-sm font-semibold text-body mb-3">Check a Package</h3>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={checkInput}
              onChange={(e) => setCheckInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
              placeholder="npm:lodash or pypi:requests"
              className="h-10 w-full rounded-xl border border-line-1 bg-surface-100 pl-9 pr-3 text-sm dark:text-white"
              disabled={checkLoading}
            />
          </div>
          <button
            type="button"
            onClick={handleCheck}
            disabled={checkLoading || !checkInput.trim()}
            className="flex h-10 items-center gap-1.5 rounded-xl bg-rose-600 px-4 text-sm font-medium text-on-fill hover:bg-rose-700 disabled:opacity-40 transition-colors"
          >
            {checkLoading ? <Loader2 size={14} className="animate-spin" /> : <Shield size={14} />}
            Check
          </button>
        </div>
        {checkError && <p className="mt-2 text-xs text-rose-600 dark:text-rose-400">{checkError}</p>}
        {checkResult && <VerdictCard result={checkResult.data} />}
      </div>

      {/* ── Stats + Filters row ─────────────────────────────────────── */}
      <div className="flex flex-wrap items-start gap-4 mb-6">
        {/* Stats */}
        <div className="flex gap-3">
          <StatPill label="Total" value={String(totalFeed)} color="text-brand-600 dark:text-brand-400" />
          {Object.entries(ecoBreakdown)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 4)
            .map(([eco, count]) => {
              const meta = ECOSYSTEMS.find((e) => e.id === eco);
              return <StatPill key={eco} label={meta?.label ?? eco} value={String(count)} color="text-muted" />;
            })}
        </div>

        {/* Ecosystem filter */}
        <div className="flex flex-wrap gap-1.5 ml-auto">
          <button
            type="button"
            onClick={() => setEcoFilter(null)}
            className={`rounded-full px-2.5 py-1 text-mini font-mono transition-colors ${
              !ecoFilter
                ? 'bg-rose-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-surface-300 dark:text-muted'
            }`}
          >
            All
          </button>
          {ECOSYSTEMS.map((eco) => (
            <button
              type="button"
              key={eco.id}
              onClick={() => setEcoFilter(eco.id)}
              className={`rounded-full px-2.5 py-1 text-mini font-mono transition-colors ${
                ecoFilter === eco.id ? 'bg-rose-600 text-white' : eco.color
              }`}
            >
              {eco.label}
            </button>
          ))}
          <button
            type="button"
            onClick={fetchFeed}
            className="flex items-center gap-1 rounded-full px-2 py-1 text-mini text-muted hover:text-rose-600 transition-colors"
            aria-label="Refresh"
          >
            <RefreshCw size={11} />
          </button>
        </div>
      </div>

      {/* ── Search bar ──────────────────────────────────────────────── */}
      <div className="relative mb-4">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter packages…"
          className="h-9 w-full rounded-xl border border-line-1 bg-surface-100 pl-9 pr-3 text-sm dark:text-white"
        />
      </div>

      {/* ── Feed entries ────────────────────────────────────────────── */}
      {loading && (
        <div className="flex items-center justify-center py-16">
          <Loader2 size={24} className="animate-spin text-rose-500" />
          <span className="ml-3 font-mono text-sm text-muted">Loading feed…</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-300 bg-rose-50/50 p-4 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300">
          <AlertTriangle size={14} className="mr-1 inline" /> {error}
        </div>
      )}

      {!loading && !error && feed && (
        <>
          <div className="text-xs font-mono text-muted mb-3">
            {filteredEntries.length} packages {ecoFilter ? `in ${ecoFilter}` : 'across all ecosystems'}
          </div>
          {filteredEntries.length > 0 && (
            <>
              <PostAnalysisButton
                title="Malicious Package Feed Digest"
                description="AI-powered threat analysis of the current feed."
                source="supplychainfeed"
              />
              <AiSummaryCard
                surface="Malicious Package Feed"
                items={filteredEntries.slice(0, 30).map((e) => ({
                  title: e.name,
                  body: `ecosystem: ${e.ecosystem}`,
                  source: 'ossf',
                }))}
                requireAdmin={false}
              />
            </>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {filteredEntries.length === 0 && (
              <div className="col-span-full py-12 text-center text-sm text-muted">No packages match your filter.</div>
            )}
            {filteredEntries.map((entry) => (
              <PackageCard key={`${entry.ecosystem}-${entry.name}`} entry={entry} />
            ))}
          </div>
        </>
      )}

      {!loading && feed?.stale && (
        <p className="mt-4 text-center text-mini font-mono text-amber-600 dark:text-amber-400">
          Showing cached data (upstream temporarily unavailable)
        </p>
      )}

      {/* ── Ecosystem breakdown ─────────────────────────────────────── */}
      {!loading && Object.keys(ecoBreakdown).length > 0 && (
        <div className="mt-8 rounded-xl border border-line-1 bg-surface-100 p-4">
          <h3 className="text-sm font-semibold text-body mb-3">Ecosystem Breakdown</h3>
          <div className="space-y-2">
            {Object.entries(ecoBreakdown)
              .sort((a, b) => b[1] - a[1])
              .map(([eco, count]) => {
                const meta = ECOSYSTEMS.find((e) => e.id === eco);
                const pct = (count / maxEcoCount) * 100;
                return (
                  <div key={eco} className="flex items-center gap-3">
                    <span
                      className={`w-14 rounded px-1.5 py-0.5 text-micro font-mono text-center ${meta?.color ?? 'bg-slate-100 text-slate-600'}`}
                    >
                      {meta?.icon ?? eco.slice(0, 2)}
                    </span>
                    <div className="flex-1 h-2 overflow-hidden rounded-full bg-surface-300">
                      <div className="h-full rounded-full bg-rose-500 transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-16 text-right text-xs font-mono text-muted">{count.toLocaleString()}</span>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* ── Source ──────────────────────────────────────────────────── */}
      <div className="mt-6 text-center">
        <a
          href="https://github.com/ossf/malicious-packages"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs font-mono text-muted hover:text-rose-600 transition-colors"
        >
          <ExternalLink size={11} />
          Source: OpenSSF Malicious Packages
        </a>
      </div>
    </DataPageLayout>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────

function StatPill({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex items-center gap-1.5 rounded-xl border border-line-1 bg-surface-100 px-2.5 py-1.5">
      <span className={`text-sm font-bold ${color}`}>{value}</span>
      <span className="text-micro font-medium text-muted">{label}</span>
    </div>
  );
}

function PackageCard({ entry }: { entry: FeedEntry }) {
  const meta = ECOSYSTEMS.find((e) => e.id === entry.ecosystem);
  return (
    <a
      href={entry.ossf_url}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex items-center gap-2 rounded-xl border border-slate-150 bg-surface-100 px-3 py-2 transition-all hover:border-rose-300/50 hover:shadow-sm dark:border-line-1 dark:hover:border-rose-500/30"
    >
      <ShieldOff size={12} className="text-rose-400 shrink-0 group-hover:text-rose-500" />
      <span className="font-mono text-xs font-medium text-heading truncate flex-1">{entry.name}</span>
      <span
        className={`shrink-0 rounded px-1.5 py-0.5 text-micro font-mono ${meta?.color ?? 'bg-slate-100 text-slate-600'}`}
      >
        {meta?.icon ?? entry.ecosystem.slice(0, 2)}
      </span>
      <ExternalLink size={10} className="shrink-0 text-inverted group-hover:text-rose-500" />
    </a>
  );
}

function VerdictCard({ result }: { result: CheckResult }) {
  const meta = VERDICT_META[result.verdict] ?? VERDICT_META.unknown!;
  const Icon = meta.icon;
  return (
    <div className={`mt-3 rounded-xl border p-3 ${meta.bg}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon size={16} className={meta.color} />
        <span className={`text-sm font-bold ${meta.color}`}>{meta.label}</span>
        <span className="text-mini font-mono text-muted">{result.ref}</span>
        <span className="ml-auto rounded bg-track px-1.5 py-0.5 text-micro font-mono text-muted">
          {result.confidence} confidence
        </span>
      </div>
      {result.advisories.length > 0 && (
        <div className="space-y-1">
          {result.advisories.slice(0, 5).map((adv) => (
            <div key={adv.id} className="flex items-center gap-2 text-xs">
              <span className="font-mono text-muted">{adv.id}</span>
              <span className="text-muted truncate">{adv.summary}</span>
            </div>
          ))}
        </div>
      )}
      {result.registry_url && (
        <a
          href={result.registry_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-2 inline-flex items-center gap-1 text-mini font-mono text-rose-600 hover:text-rose-700 transition-colors"
        >
          <ExternalLink size={10} />
          View on registry
        </a>
      )}
    </div>
  );
}
