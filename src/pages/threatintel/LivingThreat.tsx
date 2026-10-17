import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  Fingerprint,
  Flame,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Tag,
  Target,
  Wrench,
} from 'lucide-react';

interface LtIndexEntry {
  slug: string;
  shard: number;
  sequence: number | null;
  title: string;
  timestamp: string | null;
  source: string;
  severity: string;
  priorityScore: number | null;
  relevanceScore: number | null;
  tactics: string[];
  techniques: string[];
  actors: string[];
  techniqueCount: number;
  cves: number;
  tools: number;
  sizeBytes: number;
}

interface LtIndex {
  source: string;
  sourceUrl: string;
  repoUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  counts: {
    incidents: number;
    bySeverity: Record<string, number>;
    byTactic: Record<string, number>;
    uniqueCves: number;
    uniqueTechniques: number;
  };
  topTechniques: { id: string; count: number }[];
  topActors: { name: string; count: number }[];
  topTools: { name: string; count: number }[];
}

interface LtIncidentBody {
  slug: string;
  Title: string | null;
  Timestamp: string | null;
  Severity: string | null;
  source: string | null;
  CVEs: string[];
  Threat_Actors: string[];
  Tools: string[];
  Analyses: {
    Stage: string;
    Description: string;
    Detection: string;
    Remediation: string;
    Tactics: { tactic_id: string; tactic_name: string }[];
    Technique_Details: { technique_id: string; technique_name: string; technique_description: string }[];
  }[];
  priority_score?: number | null;
  relevance_score?: number | null;
  operational_tags?: string[];
  doc_summary?: string | null;
  diamond_model_summary?: string | null;
  kill_chain_summary?: string | null;
  Detection_Rules_And_Indicators?: string[];
  Post_Incident_Recommendations?: string[];
  Pyramid_Of_Pain?: string[];
}

const SEVERITY_PILL: Record<string, string> = {
  Critical: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  High: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  Moderate: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  Low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function Pill({ text }: { text: string }) {
  const pill = SEVERITY_PILL[text] ?? 'border-slate-300 dark:border-line-1 text-slate-500';
  return <span className={`px-1.5 py-0.5 text-micro font-mono rounded border ${pill}`}>{text}</span>;
}

function IncidentCard({ entry }: { entry: LtIndexEntry }) {
  const [expanded, setExpanded] = useState(false);
  const [body, setBody] = useState<LtIncidentBody | null>(null);
  const [loading, setLoading] = useState(false);

  const toggle = async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && !body) {
      setLoading(true);
      try {
        const res = await fetch(`/api/v1/threat-intel/living-threat/incidents/${encodeURIComponent(entry.slug)}`);
        if (res.ok) setBody((await res.json()) as LtIncidentBody);
      } catch {
        // body stays null — collapse shows nothing extra
      } finally {
        setLoading(false);
      }
    }
  };

  const shownAnalyses = useMemo(
    () => (body?.Analyses ?? []).filter((a) => a.Description && a.Description !== 'No significant activity detected'),
    [body]
  );

  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 overflow-hidden">
      <button
        onClick={toggle}
        className="w-full text-left p-3.5 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors"
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <Pill text={entry.severity} />
              {entry.priorityScore != null && (
                <span className="text-micro font-mono text-muted">priority {entry.priorityScore}</span>
              )}
              {entry.relevanceScore != null && (
                <span className="text-micro font-mono text-muted">relevance {entry.relevanceScore}</span>
              )}
              <span className="text-micro font-mono text-muted">
                {entry.techniqueCount} techniques · {entry.cves} CVEs
              </span>
            </div>
            <div className="mt-1.5 text-sm font-medium text-heading leading-snug">{entry.title}</div>
            {entry.actors.length > 0 && (
              <div className="mt-1 flex items-center gap-1.5 flex-wrap">
                {entry.actors.slice(0, 4).map((a) => (
                  <span
                    key={a}
                    className="px-1.5 py-0.5 text-micro font-mono rounded border border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300"
                  >
                    {a}
                  </span>
                ))}
              </div>
            )}
            <div className="mt-1.5 flex items-center gap-3 text-micro text-muted font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-2.5 h-2.5" /> {fmtDate(entry.timestamp)}
              </span>
              {entry.source && <span className="truncate max-w-[45ch]">{hostOf(entry.source)}</span>}
              {entry.tactics.length > 0 && <span className="truncate max-w-[40ch]">{entry.tactics.join(' → ')}</span>}
            </div>
          </div>
          <div className="shrink-0 text-muted mt-0.5">
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-line-1 p-3.5 bg-surface-200/60 dark:bg-surface-100/40 space-y-3">
          {loading ? (
            <div className="flex items-center gap-2 text-xs text-muted font-mono">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> loading incident body…
            </div>
          ) : body ? (
            <>
              {body.doc_summary && <div className="text-mini text-body leading-relaxed">{body.doc_summary}</div>}
              <PostAnalysisButton
                title={entry.title}
                description={`${body.doc_summary ?? ''}\n\nKill chain: ${body.kill_chain_summary ?? 'n/a'}\nDiamond model: ${body.diamond_model_summary ?? 'n/a'}\nCVEs: ${body.CVEs.join(', ') || 'none'}\nTools: ${body.Tools.join(', ') || 'none'}`}
                source={entry.source || 'living-threat'}
                compact
              />
              {body.operational_tags && body.operational_tags.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono text-muted">
                  <Tag className="w-3 h-3" />
                  {body.operational_tags.join(', ')}
                </div>
              )}
              {shownAnalyses.length > 0 && (
                <div className="space-y-2">
                  {shownAnalyses.map((a) => (
                    <div key={a.Stage} className="rounded-lg border border-line-1 bg-surface-100 p-2.5">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-1.5 text-micro font-mono text-muted uppercase tracking-wider">
                          <Target className="w-3 h-3" /> {a.Stage}
                        </div>
                        <div className="flex items-center gap-1 flex-wrap">
                          {(a.Technique_Details ?? []).map((t) => (
                            <a
                              key={t.technique_id}
                              href={`https://attack.mitre.org/techniques/${t.technique_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20"
                            >
                              {t.technique_id}
                            </a>
                          ))}
                        </div>
                      </div>
                      <div className="mt-1.5 text-mini text-body">{a.Description}</div>
                      {a.Detection && (
                        <div className="mt-1.5 text-mini text-muted">
                          <span className="font-mono text-sky-600 dark:text-sky-400">Detection: </span>
                          {a.Detection}
                        </div>
                      )}
                      {a.Remediation && (
                        <div className="mt-1 text-mini text-muted">
                          <span className="font-mono text-emerald-600 dark:text-emerald-400">Remediation: </span>
                          {a.Remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {body.CVEs.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono">
                  <AlertTriangle className="w-3 h-3 text-amber-500" />
                  {body.CVEs.map((c) => (
                    <span
                      key={c}
                      className="px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              )}
              {body.Tools.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono">
                  <Wrench className="w-3 h-3 text-muted" />
                  {body.Tools.join(', ')}
                </div>
              )}
              {body.kill_chain_summary && (
                <div className="flex items-start gap-2 text-mini font-mono">
                  <Flame className="w-3.5 h-3.5 text-muted mt-0.5 shrink-0" />
                  <div className="text-body">{body.kill_chain_summary}</div>
                </div>
              )}
              {body.diamond_model_summary && (
                <div className="flex items-start gap-2 text-mini font-mono text-muted">
                  <Fingerprint className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <div>{body.diamond_model_summary}</div>
                </div>
              )}
              {body.Detection_Rules_And_Indicators && body.Detection_Rules_And_Indicators.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-micro text-muted font-mono mb-1">
                    <FileText className="w-3 h-3" /> DETECTION RULES &amp; INDICATORS
                  </div>
                  <ul className="space-y-1 list-disc list-inside text-mini text-body">
                    {body.Detection_Rules_And_Indicators.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                </div>
              )}
              {body.Post_Incident_Recommendations && body.Post_Incident_Recommendations.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-micro text-muted font-mono mb-1">
                    <Shield className="w-3 h-3" /> POST-INCIDENT RECOMMENDATIONS
                  </div>
                  <ul className="space-y-1 list-disc list-inside text-mini text-body">
                    {body.Post_Incident_Recommendations.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                </div>
              )}
              {body.Pyramid_Of_Pain && body.Pyramid_Of_Pain.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap text-mini font-mono text-muted">
                  <Tag className="w-3 h-3" /> Pyramid of Pain: {body.Pyramid_Of_Pain.join(', ')}
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

/** Safe hostname extraction — feed `source` values are scraped third-party
 *  strings; a relative/garbage URL must not throw during render (one bad row
 *  used to blank the whole page via the top-level ErrorBoundary). */
function hostOf(u: string): string {
  try {
    return new URL(u).hostname;
  } catch {
    return u;
  }
}

export default function LivingThreat(): JSX.Element {
  const [data, setData] = useState<LtIndex | null>(null);
  const [incidents, setIncidents] = useState<LtIndexEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [listLoading, setListLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tactic, setTactic] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('all');
  const [technique, setTechnique] = useState<string>('');
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(100);
  const debounceRef = useRef<number | null>(null);

  const loadIndex = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/living-threat');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData((await res.json()) as LtIndex);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    setListLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (tactic !== 'all') params.set('tactic', tactic);
      if (severity !== 'all') params.set('severity', severity);
      if (technique.trim()) params.set('technique', technique.trim());
      if (query.trim()) params.set('q', query.trim());
      const res = await fetch(`/api/v1/threat-intel/living-threat/incidents?${params.toString()}`);
      if (res.ok) {
        const body = (await res.json()) as { incidents: LtIndexEntry[] };
        setIncidents(body.incidents);
      }
    } catch {
      // keep previous list on transient errors
    } finally {
      setListLoading(false);
    }
  }, [tactic, severity, technique, query, limit]);

  useEffect(() => {
    loadIndex();
  }, [loadIndex]);

  useEffect(() => {
    if (debounceRef.current) window.clearTimeout(debounceRef.current);
    debounceRef.current = window.setTimeout(() => {
      void loadIncidents();
    }, 250);
    return () => {
      if (debounceRef.current) window.clearTimeout(debounceRef.current);
    };
  }, [loadIncidents]);

  const tactics = useMemo(() => (data ? Object.entries(data.counts.byTactic).sort((a, b) => b[1] - a[1]) : []), [data]);

  return (
    <DataPageLayout
      backTo="/threatintel/feeds"
      backLabel="Threat Feeds"
      icon={<Target size={28} />}
      title="Living Threat Repository"
      description={
        <>
          Real-world incidents continuously mapped to MITRE ATT&CK tactics and techniques from{' '}
          <a
            href="https://living-threat.rabitanoor.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            living-threat.rabitanoor.com
          </a>{' '}
          (MIT,{' '}
          <a
            href="https://github.com/HudKSD/Living-Threat"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            HudKSD/Living-Threat
          </a>
          ) — per-kill-chain-stage ATT&CK mappings with detection + remediation notes, CVEs, actors and hunting
          guidance. Newest 5,000 of ~21k incidents.
        </>
      }
      headerExtra={
        <button
          onClick={() => {
            void loadIndex();
            void loadIncidents();
          }}
          disabled={loading || listLoading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading || listLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }
      loading={loading && !data}
      error={error}
      onRetry={loadIndex}
    >
      {data && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-5">
            {[
              { label: 'Incidents', value: data.counts.incidents, cls: 'text-slate-500' },
              { label: 'Techniques', value: data.counts.uniqueTechniques, cls: 'text-rose-600 dark:text-rose-400' },
              { label: 'CVEs', value: data.counts.uniqueCves, cls: 'text-amber-600 dark:text-amber-400' },
              { label: 'Actors', value: data.topActors.length, cls: 'text-violet-600 dark:text-violet-400' },
              { label: 'Synced', value: fmtDate(data.syncedAt), cls: 'text-slate-500' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-col lg:flex-row gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                type="text"
                placeholder="Search title, source, actor, or technique…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>
            <select
              value={tactic}
              onChange={(e) => setTactic(e.target.value)}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-body focus:outline-none focus:border-rose-500"
            >
              <option value="all">All tactics</option>
              {tactics.map(([t, n]) => (
                <option key={t} value={t}>
                  {t} ({n})
                </option>
              ))}
            </select>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-body focus:outline-none focus:border-rose-500"
            >
              <option value="all">All severities</option>
              {Object.entries(data.counts.bySeverity)
                .sort((a, b) => b[1] - a[1])
                .map(([s, n]) => (
                  <option key={s} value={s}>
                    {s} ({n})
                  </option>
                ))}
            </select>
            <input
              type="text"
              placeholder="Technique ID (T1190)…"
              value={technique}
              onChange={(e) => setTechnique(e.target.value)}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm font-mono text-heading placeholder:text-muted focus:outline-none focus:border-rose-500 w-full lg:w-44"
            />
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-body focus:outline-none focus:border-rose-500"
            >
              {[50, 100, 250, 500].map((n) => (
                <option key={n} value={n}>
                  {n} rows
                </option>
              ))}
            </select>
          </div>

          {tactics.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap mb-4">
              {tactics.map(([t, n]) => (
                <button
                  key={t}
                  onClick={() => setTactic(tactic === t ? 'all' : t)}
                  className={`px-2 py-1 rounded-lg text-micro font-mono border transition ${
                    tactic === t
                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                      : 'border-line-1 text-slate-500 hover:border-rose-500/30'
                  }`}
                >
                  {t} · {n}
                </button>
              ))}
            </div>
          )}

          <div className="flex items-center justify-between mb-2">
            <div className="text-mini font-mono text-muted">
              {listLoading ? 'loading…' : `${incidents.length} incidents`}
            </div>
          </div>

          {/* Top-level AI threat analysis for the filtered incidents */}
          {incidents.length > 0 && (
            <div className="mb-4">
              <PostAnalysisButton
                title={`Living Threat Digest \u2014 ${incidents.length} incidents`}
                description={incidents
                  .slice(0, 20)
                  .map(
                    (e) =>
                      `${e.title} (${e.severity}): actors ${e.actors.join(', ') || 'none'} · tactics ${e.tactics.join(' \u2192 ') || 'none'}`
                  )
                  .join('\n')}
                source="living-threat.rabitanoor.com"
              />
            </div>
          )}

          <div className="space-y-2">
            {incidents.length > 0 && (
              <AiSummaryCard
                surface="Living Threat Repository"
                items={incidents.slice(0, 30).map((e) => ({
                  title: e.title,
                  body: `severity: ${e.severity} · actors: ${e.actors.join(', ') || 'none'} · tactics: ${e.tactics.join(' → ') || 'none'}`,
                  source: e.source ? hostOf(e.source) : 'living-threat',
                }))}
                requireAdmin={false}
              />
            )}
            {incidents.map((e) => (
              <IncidentCard key={e.slug} entry={e} />
            ))}
            {!listLoading && incidents.length === 0 && (
              <div className="text-sm text-muted font-mono py-8 text-center border border-dashed border-line-1 rounded-xl">
                No incidents match the current filters.
              </div>
            )}
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
