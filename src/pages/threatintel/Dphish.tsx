import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  FileText,
  Fingerprint,
  Link2,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Tag,
} from 'lucide-react';

interface DphishIndexEntry {
  slug: string;
  stixId: string | null;
  value: string | null;
  category: string;
  mainObservableType: string | null;
  active: boolean;
  revoked: boolean;
  confidence: number | null;
  score: number | null;
  created: string | null;
  modified: string | null;
  validUntil: string | null;
  description: string | null;
  sizeBytes: number;
}

interface DphishIndex {
  source: string;
  sourceUrl: string;
  collectionId: string;
  collectionUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  counts: {
    indicators: number;
    active: number;
    revoked: number;
    byCategory: Record<string, number>;
  };
  indicators: DphishIndexEntry[];
}

interface DphishIndicatorBody extends DphishIndexEntry {
  name: string | null;
  observableValues: { type: string; value: string }[];
  pattern: string | null;
  patternType: string | null;
  validFrom: string | null;
  labels: string[];
  indicatorTypes: string[];
  detection: boolean | null;
}

const CATEGORY_META: Record<string, { label: string; pill: string }> = {
  domain: {
    label: 'Domain',
    pill: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  },
  ipv4: {
    label: 'IPv4',
    pill: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  },
  ipv6: {
    label: 'IPv6',
    pill: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  },
  url: {
    label: 'URL',
    pill: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  phone: {
    label: 'Phone',
    pill: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
  file: {
    label: 'File',
    pill: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  email: {
    label: 'Email',
    pill: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300',
  },
  other: {
    label: 'Other',
    pill: 'border-slate-300 dark:border-line-1 text-slate-500',
  },
};

function ActiveBadge({ active }: { active: boolean }) {
  if (active) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> ACTIVE
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> REVOKED
    </span>
  );
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function IndicatorCard({ entry }: { entry: DphishIndexEntry }) {
  const [expanded, setExpanded] = useState(false);
  const [body, setBody] = useState<DphishIndicatorBody | null>(null);
  const [loading, setLoading] = useState(false);
  const meta = CATEGORY_META[entry.category] ?? {
    label: entry.category,
    pill: 'border-slate-300 dark:border-line-1 text-slate-500',
  };
  const metaPill = meta.pill;

  const toggle = async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && !body) {
      setLoading(true);
      try {
        const res = await fetch(`/api/v1/threat-intel/dphish/indicators/${encodeURIComponent(entry.slug)}`);
        if (res.ok) setBody((await res.json()) as DphishIndicatorBody);
      } catch {
        // body stays null — collapse shows nothing extra
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 overflow-hidden">
      <button
        onClick={toggle}
        className="w-full text-left p-3.5 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors"
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`px-1.5 py-0.5 text-micro font-mono rounded border ${metaPill}`}>{meta.label}</span>
              <ActiveBadge active={entry.active} />
              {entry.confidence != null && (
                <span className="text-micro font-mono text-muted">conf {entry.confidence}%</span>
              )}
              {entry.score != null && <span className="text-micro font-mono text-muted">score {entry.score}</span>}
            </div>
            <div className="mt-1.5 font-mono text-sm text-heading break-all">{entry.value ?? entry.slug}</div>
            {entry.description && <div className="mt-1 text-mini text-muted line-clamp-2">{entry.description}</div>}
            <div className="mt-1.5 flex items-center gap-3 text-micro text-muted font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-2.5 h-2.5" />
                {fmtDate(entry.created)}
              </span>
              {entry.validUntil && (
                <span className="flex items-center gap-1">
                  <Shield className="w-2.5 h-2.5" />
                  until {fmtDate(entry.validUntil)}
                </span>
              )}
            </div>
          </div>
          <div className="shrink-0 text-muted mt-0.5">
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-line-1 p-3.5 bg-surface-200/60 dark:bg-surface-100/40 space-y-2.5">
          {loading ? (
            <div className="flex items-center gap-2 text-xs text-muted font-mono">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> loading full STIX body…
            </div>
          ) : body ? (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-mini font-mono">
                <Detail label="STIX ID" value={body.stixId ?? '—'} mono />
                <Detail label="Pattern type" value={body.patternType ?? '—'} mono />
                <Detail label="Main observable" value={body.mainObservableType ?? '—'} mono />
                <Detail label="Created" value={body.created ?? '—'} />
                <Detail label="Modified" value={body.modified ?? '—'} />
                <Detail label="Valid from" value={body.validFrom ?? '—'} />
              </div>
              {body.observableValues.length > 0 && (
                <div className="flex items-start gap-2 text-mini font-mono">
                  <Fingerprint className="w-3.5 h-3.5 text-muted mt-0.5 shrink-0" />
                  <div className="space-y-0.5">
                    {body.observableValues.map((ov, i) => (
                      <div key={i} className="text-body break-all">
                        <span className="text-muted">{ov.type}: </span>
                        {ov.value}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {body.labels.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono">
                  <Tag className="w-3 h-3 text-muted" />
                  {body.labels.map((l) => (
                    <span key={l} className="px-1.5 py-0.5 rounded border border-line-2 text-muted">
                      {l}
                    </span>
                  ))}
                </div>
              )}
              <PostAnalysisButton
                title={entry.value ?? entry.slug}
                description={`${body.description ?? ''}\n\nSTIX pattern: ${body.pattern ?? 'n/a'}`}
                source="dphish"
                compact
              />
              {body.pattern && (
                <div>
                  <div className="flex items-center gap-1.5 text-micro text-muted font-mono mb-1">
                    <FileText className="w-3 h-3" /> STIX PATTERN
                  </div>
                  <pre className="text-mini font-mono text-body whitespace-pre-wrap break-all bg-surface-100 border border-line-1 rounded-lg p-2.5 max-h-64 overflow-auto">
                    {body.pattern}
                  </pre>
                </div>
              )}
              {body.indicatorTypes.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono text-muted">
                  <AlertTriangle className="w-3 h-3" />
                  {body.indicatorTypes.join(', ')}
                </div>
              )}
            </>
          ) : (
            <div className="text-xs text-muted font-mono">body unavailable</div>
          )}
        </div>
      )}
    </div>
  );
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-micro text-muted uppercase tracking-wider">{label}</div>
      <div className={`text-mini text-body break-all ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  );
}

export default function Dphish(): JSX.Element {
  const [data, setData] = useState<DphishIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState<string>('all');
  const [activeOnly, setActiveOnly] = useState(false);
  const [query, setQuery] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/dphish');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData((await res.json()) as DphishIndex);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    if (!data) return [];
    const needle = query.toLowerCase().trim();
    return data.indicators.filter((i) => {
      if (category !== 'all' && i.category !== category) return false;
      if (activeOnly && !i.active) return false;
      if (needle) {
        const hay = `${i.value ?? ''} ${i.slug} ${i.mainObservableType ?? ''} ${i.description ?? ''}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [data, category, activeOnly, query]);

  const categoryCounts = useMemo(() => {
    if (!data) return new Map<string, number>();
    const m = new Map<string, number>();
    for (const i of data.indicators) m.set(i.category, (m.get(i.category) ?? 0) + 1);
    return m;
  }, [data]);

  return (
    <DataPageLayout
      backTo="/threatintel/feeds"
      backLabel="Threat Feeds"
      icon={<Link2 size={28} />}
      title="dPhish Phishing Feed"
      description={
        <>
          Public phishing threat-intel feed from{' '}
          <a
            href="https://dphish.com/feeds/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            dphish.com
          </a>{' '}
          — malicious domains, phishing URLs, sender IPs, phone numbers, and attachment rules via TAXII 2.1 / STIX 2.1.
        </>
      }
      headerExtra={
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }
      loading={loading && !data}
      error={error}
      onRetry={load}
    >
      {data && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
            {[
              { label: 'Indicators', value: data.counts.indicators, cls: 'text-slate-500' },
              { label: 'Active', value: data.counts.active, cls: 'text-emerald-600 dark:text-emerald-400' },
              { label: 'Revoked', value: data.counts.revoked, cls: 'text-slate-500' },
              { label: 'Categories', value: Object.keys(data.counts.byCategory).length, cls: 'text-slate-500' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                type="text"
                placeholder="Search value, observable type, or description…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>
            <button
              onClick={() => setActiveOnly((v) => !v)}
              className={`px-3 py-2 rounded-xl text-sm font-mono border flex items-center gap-1.5 transition ${
                activeOnly
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                  : 'border-line-1 text-slate-500 hover:border-emerald-500/30'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Active only
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            <span className="text-xs text-muted mr-1 font-mono">category:</span>
            <button
              onClick={() => setCategory('all')}
              className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                category === 'all'
                  ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                  : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
              }`}
            >
              All <span className="opacity-60">{data.indicators.length}</span>
            </button>
            {Object.entries(CATEGORY_META)
              .filter(([id]) => categoryCounts.has(id))
              .map(([id, meta]) => {
                const active = category === id;
                return (
                  <button
                    key={id}
                    onClick={() => setCategory(id)}
                    className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                      active ? meta.pill : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'
                    }`}
                  >
                    {meta.label} <span className="opacity-60">{categoryCounts.get(id) ?? 0}</span>
                  </button>
                );
              })}
            {(category !== 'all' || activeOnly || query) && (
              <button
                onClick={() => {
                  setCategory('all');
                  setActiveOnly(false);
                  setQuery('');
                }}
                className="text-xs text-rose-600 dark:text-rose-400 hover:underline ml-2"
              >
                clear
              </button>
            )}
          </div>

          <div className="flex items-center justify-between mb-3 text-xs text-muted font-mono">
            <span>
              Showing {filtered.length} of {data.indicators.length} indicators
            </span>
            {data.syncedAt && (
              <span>
                synced {new Date(data.syncedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
              </span>
            )}
          </div>

          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted font-mono text-sm">No indicators match your filters</div>
          ) : (
            <>
              {/* Top-level AI threat analysis for the filtered dPhish indicators */}
              <div className="mb-4">
                <PostAnalysisButton
                  title={`dPhish Digest \u2014 ${filtered.length} phishing indicators${category !== 'all' ? ` (${category})` : ''}${activeOnly ? ' (active only)' : ''}`}
                  description={filtered
                    .slice(0, 20)
                    .map(
                      (e) => `${e.value ?? e.slug} (${e.category ?? 'unknown'}): ${(e.description ?? '').slice(0, 120)}`
                    )
                    .join('\n')}
                  source="dphish.com"
                />
              </div>

              <AiSummaryCard
                surface="dPhish Phishing Feed"
                items={filtered.slice(0, 30).map((entry) => ({
                  title: entry.value ?? entry.slug,
                  body: entry.description ?? '',
                  source: 'dphish',
                }))}
                requireAdmin={false}
              />
              <div className="space-y-2">
                {filtered.map((entry) => (
                  <IndicatorCard key={entry.slug} entry={entry} />
                ))}
              </div>
            </>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: dphish.com · TAXII 2.1 collection {data.collectionId} · {data.counts.active} active of{' '}
            {data.counts.indicators} indicators
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
