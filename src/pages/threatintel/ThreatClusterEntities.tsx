import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';
import {
  Activity,
  AlertTriangle,
  Bug,
  Check,
  Copy,
  Hash,
  Link as LinkIcon,
  Network,
  Search,
  Shield,
  Skull,
  Tag,
  Users,
} from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Types (mirror the API JSON)                                        */
/* ------------------------------------------------------------------ */

type TcEntityType = 'actor' | 'group' | 'malware' | 'cve' | 'sector';

interface TcEntityIndexEntry {
  type: TcEntityType;
  slug: string;
  name: string;
  aliases: string[];
  mentionCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
}

interface TcEntityListResponse {
  builtAt: string;
  counts: Record<TcEntityType, number>;
  total: number;
  returned: number;
  entities: TcEntityIndexEntry[];
}

interface TcEntityRelated {
  type: TcEntityType;
  slug: string;
  name: string;
  weight: number;
}

interface TcEntityActivity {
  recordType: 'cluster' | 'vulnerability' | 'exploit' | 'victim' | 'mispEvent';
  slug: string;
  title: string;
  pubDate: string | null;
}

interface TcEntityBody extends TcEntityIndexEntry {
  sources: string[];
  summary: string;
  frequency: { date: string; count: number }[];
  recentActivity: TcEntityActivity[];
  relatedEntities: TcEntityRelated[];
  mitreTechniques: string[];
  victims?: { id: string; victim: string; sector: string | null; country: string | null; pubDate: string | null }[];
}

/* ------------------------------------------------------------------ */
/*  Meta                                                               */
/* ------------------------------------------------------------------ */

const TYPE_META: Record<TcEntityType, { label: string; icon: typeof Skull; cls: string }> = {
  actor: { label: 'Actor', icon: Skull, cls: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' },
  group: {
    label: 'Group',
    icon: Users,
    cls: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  },
  malware: {
    label: 'Malware',
    icon: Bug,
    cls: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  },
  cve: {
    label: 'CVE',
    icon: AlertTriangle,
    cls: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  sector: { label: 'Sector', icon: Tag, cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300' },
};

const ACTIVITY_META: Record<TcEntityBody['recentActivity'][number]['recordType'], { label: string; cls: string }> = {
  cluster: { label: 'cluster', cls: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300' },
  vulnerability: { label: 'vuln', cls: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300' },
  exploit: { label: 'exploit', cls: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300' },
  victim: { label: 'victim', cls: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300' },
  mispEvent: { label: 'misp', cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' },
};

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border ${cls}`}>
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Page                                                               */
/* ------------------------------------------------------------------ */

export default function ThreatClusterEntities() {
  const [idx, setIdx] = useState<TcEntityListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<TcEntityType | 'all'>('all');
  const [minMentions, setMinMentions] = useState(1);
  const [sel, setSel] = useState<{ type: TcEntityType; slug: string } | null>(null);
  const [detail, setDetail] = useState<TcEntityBody | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/threat-intel/threatcluster/entities?limit=1000');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setIdx(j);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!sel) return;
    let cancelled = false;
    setDetailLoading(true);
    fetch(`/api/v1/threat-intel/threatcluster/entities/${sel.type}/${encodeURIComponent(sel.slug)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (!cancelled) setDetail(j as TcEntityBody | null);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [sel]);

  const all = useMemo<TcEntityIndexEntry[]>(() => {
    if (!idx) return [];
    return [...idx.entities].sort((a, b) => b.mentionCount - a.mentionCount || a.name.localeCompare(b.name));
  }, [idx]);

  const filtered = useMemo(() => {
    const n = query.toLowerCase().trim();
    return all.filter((e) => {
      if (typeFilter !== 'all' && e.type !== typeFilter) return false;
      if (e.mentionCount < minMentions) return false;
      if (n) {
        const hay = `${e.name} ${e.aliases.join(' ')} ${e.slug}`.toLowerCase();
        if (!hay.includes(n)) return false;
      }
      return true;
    });
  }, [all, query, typeFilter, minMentions]);

  async function copySummary(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied('s');
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel/feeds/threatcluster"
      backLabel="ThreatCluster Feeds"
      icon={<Network size={28} />}
      title="ThreatCluster Entity Intelligence"
      description={
        <>
          Derived entity profiles from ThreatCluster data — threat actors (MISP galaxy attribution), ransomware groups
          and the sectors they hit, malware families, and CVEs. Extracted deterministically at build time from in-repo
          signals; no LLM in the loop.
        </>
      }
      loading={loading && !idx}
      error={error}
      onRetry={load}
    >
      {idx && (
        <div className="grid gap-4 lg:grid-cols-[380px_1fr] items-start">
          {/* ── Explorer ─────────────────────────────────────────── */}
          <div className="lg:sticky lg:top-4 space-y-3">
            <div className="surface-card/50 shadow-e1 p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="text-mini uppercase tracking-wider text-muted">Entity count</div>
                <div className="text-xs font-mono text-muted">{idx.builtAt ? `built ${fmtDate(idx.builtAt)}` : ''}</div>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {(['actor', 'group', 'malware', 'cve', 'sector'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(typeFilter === t ? 'all' : t)}
                    className={`rounded-lg border p-2 text-left transition-colors ${
                      (typeFilter === 'all' ? false : typeFilter === t)
                        ? 'border-rose-500/50 bg-rose-500/10'
                        : 'border-line-1 hover:border-rose-500/40'
                    }`}
                    title={`${TYPE_META[t].label}s`}
                  >
                    <div className="text-sm font-bold text-heading">{idx.counts[t]}</div>
                    <div className="text-micro uppercase tracking-wider text-muted">{TYPE_META[t].label}s</div>
                  </button>
                ))}
              </div>

              <div className="relative flex-1 mt-3">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search name or alias…"
                  className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="flex items-center gap-2 mt-3">
                <span className="text-mini text-muted shrink-0">Min mentions</span>
                {[1, 2, 5, 10].map((m) => (
                  <button
                    key={m}
                    onClick={() => setMinMentions(m)}
                    className={`px-2 py-0.5 rounded-lg text-micro font-mono border transition-colors ${
                      minMentions === m
                        ? 'border-rose-500/50 bg-rose-500/10 text-rose-600 dark:text-rose-300'
                        : 'border-line-1 text-slate-500'
                    }`}
                  >
                    {m}
                  </button>
                ))}
              </div>

              <div className="text-xs text-muted font-mono mt-3">
                Showing {filtered.length} of {all.length} entities
              </div>
            </div>

            <div className="max-h-[60vh] overflow-y-auto rounded-xl border border-line-1 divide-y divide-line-1 bg-surface-100/50">
              {/* Top-level AI threat analysis for the filtered entities */}
              {filtered.length > 0 && (
                <div className="p-2 border-b border-line-1">
                  <PostAnalysisButton
                    title={`ThreatCluster Entity Digest \u2014 ${filtered.length} entities`}
                    description={filtered
                      .slice(0, 20)
                      .map(
                        (e) =>
                          `${e.name} (${TYPE_META[e.type].label}): ${e.mentionCount} mentions${e.aliases.length > 0 ? `, aliases: ${e.aliases.join(', ')}` : ''}`
                      )
                      .join('\n')}
                    source="threatcluster.io"
                  />
                </div>
              )}

              {filtered.length > 0 && (
                <div className="p-2 border-b border-line-1">
                  <AiSummaryCard
                    surface="ThreatCluster Entities"
                    items={filtered.slice(0, 30).map((e) => ({
                      title: e.name,
                      body: `${TYPE_META[e.type].label} · ${e.mentionCount} mentions${e.aliases.length > 0 ? ` · ${e.aliases.join(', ')}` : ''}`,
                      source: 'threatcluster.io',
                    }))}
                    requireAdmin={false}
                  />
                </div>
              )}
              {filtered.map((e) => {
                const meta = TYPE_META[e.type];
                const Icon = meta.icon;
                const active = sel?.type === e.type && sel?.slug === e.slug;
                return (
                  <button
                    key={`${e.type}/${e.slug}`}
                    onClick={() => setSel({ type: e.type, slug: e.slug })}
                    className={`w-full text-left p-3 transition-colors ${
                      active ? 'bg-rose-500/10' : 'hover:bg-slate-50 dark:hover:bg-white/5'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <Icon className="w-3.5 h-3.5 text-muted shrink-0" />
                        <span className="text-sm font-semibold text-heading truncate">{e.name}</span>
                      </div>
                      <Badge cls={meta.cls}>{e.mentionCount}</Badge>
                    </div>
                    <div className="flex items-center gap-1.5 mt-1">
                      {e.aliases.slice(0, 2).map((a) => (
                        <span key={a} className="text-micro font-mono text-muted truncate">
                          {a}
                        </span>
                      ))}
                      <span className="text-micro font-mono text-muted ml-auto">{e.type}</span>
                    </div>
                  </button>
                );
              })}
              {filtered.length === 0 && (
                <div className="p-4 text-sm text-muted text-center">No entities match this filter.</div>
              )}
            </div>
          </div>

          {/* ── Detail ────────────────────────────────────────────── */}
          <div className="surface-card/50 shadow-e1 p-4 min-h-[300px]">
            {!sel && (
              <div className="h-full flex flex-col items-center justify-center py-16 text-muted">
                <Network className="w-8 h-8 mb-2 opacity-60" />
                <p className="text-sm">Select an entity to view its profile, frequency, and relationship graph.</p>
              </div>
            )}
            {sel && detailLoading && <p className="text-sm text-muted font-mono p-6">loading profile…</p>}
            {sel && !detailLoading && !detail && (
              <p className="text-sm text-muted p-6">
                Profile unavailable for {sel.type}/{sel.slug}.
              </p>
            )}
            {sel && detail && (
              <EntityProfile body={detail} onSelect={setSel} onCopy={copySummary} copied={copied === 's'} />
            )}
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}

/* ------------------------------------------------------------------ */
/*  Profile                                                            */
/* ------------------------------------------------------------------ */

function EntityProfile({
  body,
  onSelect,
  onCopy,
  copied,
}: {
  body: TcEntityBody;
  onSelect: (s: { type: TcEntityType; slug: string }) => void;
  onCopy: (t: string) => void;
  copied: boolean;
}) {
  const meta = TYPE_META[body.type];
  const Icon = meta.icon;
  const maxFreq = Math.max(1, ...body.frequency.map((f) => f.count));
  const freqWindow = body.frequency.slice(-14);

  return (
    <div className="space-y-4">
      <PostAnalysisButton
        title={body.name}
        description={`${body.summary}\n\naliases: ${body.aliases.join(', ') || 'none'}\nMITRE: ${body.mitreTechniques.join(', ') || 'none'}\nrelated: ${body.relatedEntities.map((r) => `${r.name} (w${r.weight})`).join(', ') || 'none'}\nrecent: ${
          body.recentActivity
            .slice(0, 6)
            .map((a) => a.title)
            .join(' · ') || 'none'
        }`}
        source={body.sources[0] || 'threatcluster.io'}
        compact
      />
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <Icon className="w-5 h-5 text-muted shrink-0" />
          <div className="min-w-0">
            <h2 className="text-lg font-bold text-heading truncate">{body.name}</h2>
            <div className="flex flex-wrap items-center gap-1.5 mt-1">
              <Badge cls={meta.cls}>{meta.label}</Badge>
              {body.aliases.slice(0, 4).map((a) => (
                <Badge key={a} cls="border-slate-300 dark:border-line-1 text-slate-500">
                  {a}
                </Badge>
              ))}
            </div>
          </div>
        </div>
        <div className="text-right shrink-0">
          <button
            onClick={() => onCopy(body.summary)}
            className="inline-flex items-center gap-1 text-micro font-mono text-muted hover:text-rose-600"
            title="Copy summary"
          >
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            {copied ? 'copied' : 'copy'}
          </button>
          <div className="text-xl font-bold text-heading mt-1">{body.mentionCount}</div>
          <div className="text-micro uppercase tracking-wider text-muted">mentions</div>
        </div>
      </div>

      <p className="text-xs text-body leading-relaxed">{body.summary}</p>

      <div className="flex flex-wrap items-center gap-1.5">
        {body.sources.map((s) => (
          <Badge key={s} cls="border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
            <LinkIcon className="w-2.5 h-2.5" />
            {s}
          </Badge>
        ))}
        <span className="text-micro font-mono text-muted">
          first {fmtDate(body.firstSeen)} · last {fmtDate(body.lastSeen)}
        </span>
      </div>

      {/* Frequency chart */}
      {freqWindow.length > 0 && (
        <div>
          <div className="text-mini uppercase tracking-wider text-muted mb-2 flex items-center gap-1">
            <Activity className="w-3 h-3" /> Mentions per day (last {freqWindow.length})
          </div>
          <div className="flex items-end gap-1 h-20">
            {freqWindow.map((f) => (
              <div key={f.date} className="flex-1 flex flex-col items-center gap-1" title={`${f.date}: ${f.count}`}>
                <div
                  className="w-full rounded-t bg-gradient-to-t from-rose-600/60 to-rose-400/80"
                  style={{ height: `${Math.max(2, Math.round((f.count / maxFreq) * 56))}px` }}
                />
                <span className="text-micro font-mono text-muted">{f.date.slice(5)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Related entities */}
      {body.relatedEntities.length > 0 && (
        <div>
          <div className="text-mini uppercase tracking-wider text-muted mb-2 flex items-center gap-1">
            <Network className="w-3 h-3" /> Relationship graph · co-occurrence
          </div>
          <div className="flex flex-wrap gap-1.5">
            {body.relatedEntities.map((r) => {
              const rm = TYPE_META[r.type];
              return (
                <button
                  key={`${r.type}/${r.slug}`}
                  onClick={() => onSelect({ type: r.type, slug: r.slug })}
                  className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg border text-micro font-mono transition-colors ${rm.cls} hover:brightness-110`}
                  title={`${r.weight} co-occurring record(s)`}
                >
                  <Hash className="w-2.5 h-2.5" />
                  {r.name}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Victims (groups) */}
      {body.victims && body.victims.length > 0 && (
        <div>
          <div className="text-mini uppercase tracking-wider text-muted mb-2 flex items-center gap-1">
            <Users className="w-3 h-3" /> Leak-site victims · {body.victims.length}
          </div>
          <div className="overflow-x-auto rounded-lg border border-line-1">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-surface-200 dark:bg-surface-100/5 text-muted uppercase tracking-wider text-micro">
                  <th className="text-left px-3 py-2">Victim</th>
                  <th className="text-left px-3 py-2">Sector</th>
                  <th className="text-left px-3 py-2">Country</th>
                  <th className="text-left px-3 py-2">Posted</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-1">
                {body.victims.slice(0, 20).map((v) => (
                  <tr key={v.id}>
                    <td className="px-3 py-2 font-medium text-heading">{v.victim}</td>
                    <td className="px-3 py-2 text-muted">{v.sector ?? '—'}</td>
                    <td className="px-3 py-2 text-muted">{v.country ?? '—'}</td>
                    <td className="px-3 py-2 text-muted font-mono">{fmtDate(v.pubDate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MITRE */}
      {body.mitreTechniques.length > 0 && (
        <div>
          <div className="text-mini uppercase tracking-wider text-muted mb-2 flex items-center gap-1">
            <Shield className="w-3 h-3" /> MITRE techniques
          </div>
          <div className="flex flex-wrap gap-1.5">
            {body.mitreTechniques.map((t) => (
              <Badge key={t} cls="border-slate-300 dark:border-line-1 text-slate-500">
                {t}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Recent activity */}
      {body.recentActivity.length > 0 && (
        <div>
          <div className="text-mini uppercase tracking-wider text-muted mb-2 flex items-center gap-1">
            <Activity className="w-3 h-3" /> Recent activity
          </div>
          <div className="space-y-1.5">
            {body.recentActivity.map((a) => {
              const am = ACTIVITY_META[a.recordType];
              return (
                <div key={`${a.recordType}/${a.slug}`} className="flex items-center gap-2 text-xs">
                  <Badge cls={am.cls}>{am.label}</Badge>
                  <span className="text-heading truncate min-w-0">{a.title}</span>
                  <span className="text-micro font-mono text-muted ml-auto shrink-0">{fmtDate(a.pubDate)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
