import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Clock,
  FileText,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Tag,
} from 'lucide-react';

interface OffseqIndexEntry {
  slug: string;
  externalId: string | null;
  source: string | null;
  type: string | null;
  title: string | null;
  severity: string | null;
  cvssScore: number | null;
  publishedDate: string | null;
  cveId: string | null;
  cveIds: string[];
  exploited: boolean;
  knownExploitsInWild: boolean;
  tags: string[];
  url: string | null;
  sizeBytes: number;
}
interface OffseqIndex {
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  days: number;
  overview: {
    total?: number;
    newThreats24h?: number;
    enrichedCount?: number;
    severityCounts?: { critical?: number; high?: number; medium?: number; low?: number };
  } | null;
  counts: { threats: number; exploited: number; byType: Record<string, number>; bySeverity: Record<string, number> };
  tags: { name: string; count: number }[];
  threats: OffseqIndexEntry[];
}
interface OffseqThreatBody extends OffseqIndexEntry {
  description: string | null;
  cvssVector: string | null;
  mirageCountries: string[];
  patchAvailable: boolean;
  knownThreatActors: string[];
  affectedCountries: string[];
  references: string[];
  aiSummary: string | null;
  aiImpact: string | null;
}
const SEVERITY_PILL: Record<string, string> = {
  critical: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  high: 'border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-slate-300 dark:border-line-1 text-slate-500',
};
function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
function ThreatCard({ entry }: { entry: OffseqIndexEntry }) {
  const [expanded, setExpanded] = useState(false);
  const [body, setBody] = useState<OffseqThreatBody | null>(null);
  const [loading, setLoading] = useState(false);
  const pill = SEVERITY_PILL[entry.severity ?? ''] ?? 'border-slate-300 dark:border-line-1 text-slate-500';
  const toggle = async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && !body) {
      setLoading(true);
      try {
        const res = await fetch(`/api/v1/threat-intel/offseq/threats/${encodeURIComponent(entry.slug)}`);
        if (res.ok) setBody((await res.json()) as OffseqThreatBody);
      } catch {
        /* */
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
              {entry.severity && (
                <span className={`px-1.5 py-0.5 text-micro font-mono rounded border ${pill}`}>
                  {entry.severity.toUpperCase()}
                </span>
              )}
              {entry.type && (
                <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                  {entry.type}
                </span>
              )}
              {entry.exploited && (
                <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                  IN THE WILD
                </span>
              )}
              {entry.cvssScore != null && (
                <span className="text-micro font-mono text-muted">CVSS {entry.cvssScore}</span>
              )}
            </div>
            <div className="mt-1.5 text-sm text-heading line-clamp-2">{entry.title ?? entry.slug}</div>
            {entry.cveIds.length > 0 && (
              <div className="mt-1 text-micro font-mono text-muted">{entry.cveIds.slice(0, 3).join(', ')}</div>
            )}
            <div className="mt-1.5 flex items-center gap-3 text-micro text-muted font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-2.5 h-2.5" />
                {fmtDate(entry.publishedDate)}
              </span>
              {entry.source && <span>{entry.source}</span>}
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
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> loading body…
            </div>
          ) : body ? (
            <>
              {body.aiSummary && <div className="text-sm text-body leading-relaxed">{body.aiSummary}</div>}
              {body.aiImpact && (
                <div className="text-xs text-muted leading-relaxed">
                  <span className="font-mono text-micro uppercase tracking-wider">Impact: </span>
                  {body.aiImpact}
                </div>
              )}
              {body.description && !body.aiSummary && (
                <div className="text-sm text-body leading-relaxed line-clamp-6">{body.description}</div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-mini font-mono">
                <Detail label="CVE" value={body.cveIds.join(', ') || body.cveId || '—'} mono />
                <Detail label="CVSS vector" value={body.cvssVector ?? '—'} mono />
                <Detail label="Patch" value={body.patchAvailable ? 'available' : 'unknown'} />
                <Detail label="Source" value={body.source ?? '—'} />
                <Detail label="Published" value={body.publishedDate ?? '—'} />
                <Detail label="Exploited" value={body.exploited ? 'yes (Mirage)' : 'no'} />
              </div>
              {body.mirageCountries.length > 0 && (
                <div className="text-mini font-mono text-muted">
                  Mirage countries: {body.mirageCountries.join(', ')}
                </div>
              )}
              {body.knownThreatActors.length > 0 && (
                <div className="text-mini font-mono text-muted">Actors: {body.knownThreatActors.join(', ')}</div>
              )}
              {body.tags.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono">
                  <Tag className="w-3 h-3 text-muted" />
                  {body.tags.slice(0, 12).map((t) => (
                    <span key={t} className="px-1.5 py-0.5 rounded border border-line-2 text-muted">
                      {t}
                    </span>
                  ))}
                </div>
              )}
              {body.references.length > 0 && (
                <div className="text-mini font-mono text-muted">
                  <FileText className="inline w-3 h-3 mr-1" />
                  {body.references.length} reference{body.references.length === 1 ? '' : 's'}
                </div>
              )}
              <PostAnalysisButton
                title={entry.title ?? entry.slug}
                description={(body.aiSummary ?? body.description ?? '').slice(0, 400)}
                source="radar.offseq.com"
                compact
              />
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
export default function Offseq(): JSX.Element {
  const [data, setData] = useState<OffseqIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('all');
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [query, setQuery] = useState('');
  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/offseq');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData((await res.json()) as OffseqIndex);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);
  const types = useMemo(() => (data ? Object.keys(data.counts.byType).sort() : []), [data]);
  const filtered = useMemo(() => {
    if (!data) return [];
    const needle = query.toLowerCase().trim();
    return data.threats.filter((t) => {
      if (type !== 'all' && t.type !== type) return false;
      if (severity !== 'all' && t.severity !== severity) return false;
      if (exploitedOnly && !t.exploited) return false;
      if (needle) {
        const hay = `${t.title ?? ''} ${t.slug} ${t.cveIds.join(' ')} ${t.tags.join(' ')}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [data, type, severity, exploitedOnly, query]);
  return (
    <DataPageLayout
      backTo="/threatintel/feeds"
      backLabel="Threat Feeds"
      icon={<AlertTriangle size={28} />}
      title="OffSeq Threat Radar"
      description={
        <>
          <a
            href="https://radar.offseq.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sky-600 dark:text-sky-400 hover:underline transition-colors"
          >
            radar.offseq.com
          </a>{' '}
          — ~40 upstream sources, AI-enriched summaries, KEV correlation and Mirage honeypot exploitation telemetry.
        </>
      }
      headerExtra={
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-sky-500/30 hover:text-sky-600 dark:hover:text-sky-400 transition-colors disabled:opacity-50"
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
              { label: 'Threats', value: data.counts.threats, cls: 'text-slate-500' },
              { label: 'Exploited', value: data.counts.exploited, cls: 'text-rose-600 dark:text-rose-400' },
              {
                label: 'Critical',
                value: data.counts.bySeverity.critical ?? 0,
                cls: 'text-rose-600 dark:text-rose-400',
              },
              { label: 'High', value: data.counts.bySeverity.high ?? 0, cls: 'text-orange-600 dark:text-orange-400' },
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
                placeholder="Search title, CVE id, or tags…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-sky-500"
              />
            </div>
            <button
              onClick={() => setExploitedOnly((v) => !v)}
              className={`px-3 py-2 rounded-xl text-sm font-mono border flex items-center gap-1.5 transition ${exploitedOnly ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-line-1 text-slate-500 hover:border-rose-500/30'}`}
            >
              <Shield className="w-3.5 h-3.5" />
              Exploited only
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            <span className="text-xs text-muted mr-1 font-mono">type:</span>
            <button
              onClick={() => setType('all')}
              className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${type === 'all' ? 'border-sky-500/60 bg-sky-500/10 text-sky-600 dark:text-sky-400' : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-sky-500/30'}`}
            >
              All <span className="opacity-60">{data.threats.length}</span>
            </button>
            {types.map((t) => (
              <button
                key={t}
                onClick={() => setType(t)}
                className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${type === t ? 'border-sky-500/60 bg-sky-500/10 text-sky-600 dark:text-sky-400' : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'}`}
              >
                {t} <span className="opacity-60">{data.counts.byType[t] ?? 0}</span>
              </button>
            ))}
            {(type !== 'all' || severity !== 'all' || exploitedOnly || query) && (
              <button
                onClick={() => {
                  setType('all');
                  setSeverity('all');
                  setExploitedOnly(false);
                  setQuery('');
                }}
                className="text-xs text-sky-600 dark:text-sky-400 hover:underline ml-2"
              >
                clear
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            <span className="text-xs text-muted mr-1 font-mono">severity:</span>
            {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
              <button
                key={s}
                onClick={() => setSeverity(s)}
                className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${severity === s ? 'border-sky-500/60 bg-sky-500/10 text-sky-600 dark:text-sky-400' : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'}`}
              >
                {s}
              </button>
            ))}
          </div>
          <div className="flex items-center justify-between mb-3 text-xs text-muted font-mono">
            <span>
              Showing {filtered.length} of {data.threats.length} threats
            </span>
            {data.syncedAt && (
              <span>
                synced {new Date(data.syncedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
              </span>
            )}
          </div>
          <AiSummaryCard
            surface="OffSeq Threat Radar"
            items={filtered
              .slice(0, 30)
              .map((e) => ({ title: e.title ?? e.slug, body: e.tags.join(', '), source: 'offseq' }))}
            requireAdmin={false}
          />
          <div className="space-y-2">
            {filtered.map((entry) => (
              <ThreatCard key={entry.slug} entry={entry} />
            ))}
          </div>
          {filtered.length === 0 && (
            <div className="text-center py-12 text-muted font-mono text-sm">No threats match your filters</div>
          )}
          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: radar.offseq.com · {data.counts.threats} threats · {data.counts.exploited} with observed
            exploitation
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
