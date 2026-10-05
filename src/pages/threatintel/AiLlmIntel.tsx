import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ExternalLink, RefreshCw, Bot, Shield, BrainCircuit, FileText, Activity, AlertTriangle } from 'lucide-react';

/**
 * AI / LLM Threat Intelligence.
 *
 * The campaign layer for LLM-specific abuse — distinct from
 * `AiHoneypotObservatory`, which is the raw observed-telemetry view of
 * ai-honeypots.com. This page is the narrative: which campaigns are active,
 * what techniques they use, what analysts have written about them, and how the
 * volume is trending.
 *
 * It complements rather than duplicates the Live IOC stream, which carries the
 * same indicators as rows in a tweet-style feed. The stream answers "what
 * address"; this answers "what campaign is it part of and what do I do".
 *
 * Data comes from `/api/v1/ai-llm-intel`, a per-colo Cache API slice warmed by
 * the hourly queue — so this page never fans out to third-party upstreams, and
 * an upstream outage shows as a `degraded` banner rather than a blank page.
 */

const API_URL = '/api/v1/ai-llm-intel';
const UPSTREAM_URL = 'https://llm-threatintel.com';

interface AiLlmActor {
  id: string;
  names: string[];
  type: string;
  first_seen?: string;
  status?: string;
  distribution?: string[];
  ttps?: string[];
  description?: string;
}

interface AiLlmPost {
  id: string;
  title: string;
  date: string;
  author?: string;
  tags: string[];
  tlp?: string;
  excerpt?: string;
  url: string;
}

interface AiLlmTrend {
  key: string;
  dimension: string;
  count: number;
  latest?: string;
}

interface AiLlmActorClass {
  category: string;
  description?: string;
  count: number;
  indicators: number;
}

interface AiLlmIntelResponse {
  generated_at: string;
  last_updated?: string;
  sources: Array<{ id: string; label: string; ok: boolean; count: number; error?: string }>;
  actors: AiLlmActor[];
  posts: AiLlmPost[];
  blog: AiLlmPost[];
  honeypot_actor_classes: AiLlmActorClass[];
  trends: AiLlmTrend[];
  stats: {
    iocs: number;
    actors: number;
    posts: number;
    blog: number;
    honeypot_indicators: number;
    campaigns: number;
    tags: number;
  };
  degraded?: boolean;
}

const TREND_DIMENSIONS: Array<{ id: string; label: string }> = [
  { id: 'ttp', label: 'ATT&CK techniques' },
  { id: 'tag', label: 'Write-up tags' },
  { id: 'honeypot_category', label: 'Honeypot actor classes' },
  { id: 'actor_type', label: 'Campaign types' },
];

function relativeTime(dateStr?: string): string {
  if (!dateStr) return '';
  const parsed = Date.parse(dateStr);
  if (!Number.isFinite(parsed)) return '';
  const mins = Math.floor((Date.now() - parsed) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return dateStr.slice(0, 10);
}

/** Technique ids matching credential/execution impact — the ones that matter. */
const HIGH_IMPACT_TTP = /T1059|T1552|T1204|T1190|T1055|T1548/;
const HIGH_IMPACT_TAG = /clickfix|phishing|injection|mcp|exfiltrat|malware|rat|stealer|ransomware/;

export default function AiLlmIntel() {
  const [data, setData] = useState<AiLlmIntelResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [trendDimension, setTrendDimension] = useState('ttp');
  const abortRef = useRef<AbortController | null>(null);

  const fetchIntel = useCallback(async () => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(API_URL, { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(20_000)]) });
      if (!res.ok) throw new Error(`Feed returned ${res.status}`);
      const payload = (await res.json()) as AiLlmIntelResponse;
      if (ctrl.signal.aborted) return;
      setData(payload);
    } catch (e) {
      if (ctrl.signal.aborted) return;
      setError(e instanceof Error ? e.message : 'Failed to load AI/LLM intelligence');
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntel();
    return () => abortRef.current?.abort();
  }, [fetchIntel, refreshKey]);

  const narrative = useMemo(() => {
    const seen = new Set<string>();
    return [...(data?.posts ?? []), ...(data?.blog ?? [])]
      .filter((p) => (seen.has(p.id) ? false : (seen.add(p.id), true)))
      .sort((a, b) => b.date.localeCompare(a.date));
  }, [data]);

  const trends = useMemo(
    () => (data?.trends ?? []).filter((t) => t.dimension === trendDimension),
    [data, trendDimension]
  );
  const maxTrend = trends[0]?.count ?? 1;
  const failedSources = (data?.sources ?? []).filter((s) => !s.ok);

  return (
    <DataPageLayout
      backTo="/threatintel/infra"
      title="AI / LLM Threat Intelligence"
      description="Campaigns, techniques, and analyst reporting on LLM-specific abuse — ClickFix lures, malicious MCP servers, prompt injection, relay-pool abuse."
      icon={<BrainCircuit size={28} />}
    >
      {/* Status banner — a partial upstream outage must be visible, not inferred
          from a silently-short list. */}
      {data?.degraded && (
        <div className="mb-4 flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-300">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <div>
            <span className="font-medium">Partial data.</span> {failedSources.length} of {data.sources.length} upstream
            feeds did not respond this refresh ({failedSources.map((s) => s.label).join(', ')}). Everything shown below
            came from the feeds that did.
          </div>
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Campaigns" value={data?.stats.campaigns ?? 0} icon={<BrainCircuit size={16} />} />
        <StatCard label="Tracked actors" value={data?.stats.actors ?? 0} icon={<Shield size={16} />} />
        <StatCard label="Indicators" value={data?.stats.iocs ?? 0} icon={<Activity size={16} />} />
        <StatCard label="Write-ups" value={narrative.length} icon={<FileText size={16} />} />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-line-1 bg-surface-100/50 p-3">
        <span className="text-xs text-muted">
          Upstream:{' '}
          <a
            href={UPSTREAM_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 transition-colors hover:underline dark:text-brand-400"
          >
            llm-threatintel.com
          </a>
          {data?.last_updated && <span className="ml-2">Updated {relativeTime(data.last_updated)}</span>}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <a
            href="/threatintel/iocs/live"
            className="btn-outline flex items-center gap-1 text-xs"
            title="The same indicators in the live IOC stream"
          >
            <Bot size={13} /> Live IOC stream
          </a>
          <button
            onClick={() => setRefreshKey((k) => k + 1)}
            className="btn-outline flex items-center gap-1 text-xs"
            disabled={loading}
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-400">
          {error}
        </div>
      )}

      {loading && !data && <div className="p-8 text-center text-sm text-muted">Loading AI/LLM intelligence…</div>}

      {data && (
        <div className="space-y-8">
          {/* ── Trends ─────────────────────────────────────────────────── */}
          <section>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold tracking-wide text-heading uppercase">Trends</h2>
              <div className="ml-auto flex flex-wrap gap-1">
                {TREND_DIMENSIONS.map((d) => (
                  <button
                    key={d.id}
                    onClick={() => setTrendDimension(d.id)}
                    className={`rounded-full px-2.5 py-1 font-mono text-xs transition-colors ${
                      trendDimension === d.id
                        ? 'bg-brand-500/15 text-brand-700 dark:text-brand-300'
                        : 'bg-surface-200 text-muted hover:text-slate-800 dark:hover:text-slate-200'
                    }`}
                  >
                    {d.label}
                  </button>
                ))}
              </div>
            </div>
            {trends.length === 0 ? (
              <p className="text-sm text-muted">No trend data in this refresh.</p>
            ) : (
              <div className="surface-card divide-y divide-line-1">
                {trends.slice(0, 12).map((t) => (
                  <div key={`${t.dimension}-${t.key}`} className="flex items-center gap-3 px-3 py-2">
                    <span className="w-2/5 truncate font-mono text-xs" title={t.key}>
                      {t.key}
                    </span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-200">
                      <div
                        className="h-full rounded-full bg-brand-500/70"
                        // Relative to the top entry, not the absolute max, so the
                        // chart shape stays readable when counts are small.
                        style={{ width: `${Math.max(4, Math.round((t.count / maxTrend) * 100))}%` }}
                      />
                    </div>
                    <span className="w-8 text-right font-mono text-xs text-muted">{t.count}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* ── Honeypot actor classes ─────────────────────────────────── */}
          {data.honeypot_actor_classes.length > 0 && (
            <section>
              <h2 className="mb-3 text-sm font-semibold tracking-wide text-heading uppercase">
                Observed actor classes
              </h2>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {data.honeypot_actor_classes.slice(0, 9).map((c) => (
                  <div key={c.category} className="surface-card p-3">
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="font-mono text-xs font-medium">{c.category}</span>
                      <span className="text-xs text-muted">{c.count}</span>
                    </div>
                    {c.description && <p className="mt-1 text-xs text-muted">{c.description}</p>}
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ── Campaigns / actors ────────────────────────────────────── */}
          <section>
            <h2 className="mb-3 text-sm font-semibold tracking-wide text-heading uppercase">Campaigns &amp; actors</h2>
            {data.actors.length === 0 ? (
              <p className="text-sm text-muted">No tracked campaigns in this refresh.</p>
            ) : (
              <div className="space-y-2">
                {data.actors.slice(0, 20).map((a) => {
                  const highImpact = (a.ttps ?? []).some((t) => HIGH_IMPACT_TTP.test(t));
                  return (
                    <article key={a.id} className="surface-card p-3">
                      <div className="flex flex-wrap items-baseline gap-2">
                        <h3 className="text-sm font-semibold text-heading">{a.names[0] || a.id}</h3>
                        {highImpact && (
                          <span className="rounded-full bg-red-500/15 px-2 py-0.5 font-mono text-[10px] text-red-700 dark:text-red-400">
                            active technique
                          </span>
                        )}
                        <span className="font-mono text-[10px] text-muted">{a.type}</span>
                        {a.first_seen && (
                          <span className="ml-auto font-mono text-[10px] text-muted">first seen {a.first_seen}</span>
                        )}
                      </div>
                      {a.description && (
                        <p className="mt-1.5 line-clamp-3 text-xs leading-relaxed text-muted">{a.description}</p>
                      )}
                      {(a.ttps?.length || a.distribution?.length) && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {a.ttps?.slice(0, 6).map((t) => (
                            <span
                              key={t}
                              className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                                HIGH_IMPACT_TTP.test(t)
                                  ? 'bg-red-500/10 text-red-700 dark:text-red-400'
                                  : 'bg-surface-200 text-muted'
                              }`}
                            >
                              {t}
                            </span>
                          ))}
                          {a.distribution?.slice(0, 3).map((d) => (
                            <span
                              key={d}
                              className="rounded bg-brand-500/10 px-1.5 py-0.5 font-mono text-[10px] text-brand-700 dark:text-brand-400"
                            >
                              {d}
                            </span>
                          ))}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          {/* ── Write-ups + blog ──────────────────────────────────────── */}
          <section>
            <h2 className="mb-3 text-sm font-semibold tracking-wide text-heading uppercase">
              Analysis &amp; reporting
            </h2>
            {narrative.length === 0 ? (
              <p className="text-sm text-muted">No write-ups in this refresh.</p>
            ) : (
              <div className="space-y-2">
                {narrative.slice(0, 20).map((p) => (
                  <article key={p.id} className="surface-card p-3">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <h3 className="text-sm font-semibold text-heading">
                        <a
                          href={p.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 hover:underline"
                        >
                          {p.title}
                          <ExternalLink size={12} className="shrink-0 text-muted" />
                        </a>
                      </h3>
                      <span className="ml-auto font-mono text-[10px] text-muted">{p.date}</span>
                    </div>
                    {p.excerpt && <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">{p.excerpt}</p>}
                    {p.tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {p.tags.slice(0, 8).map((t) => (
                          <span
                            key={t}
                            className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                              HIGH_IMPACT_TAG.test(t)
                                ? 'bg-amber-500/15 text-amber-700 dark:text-amber-400'
                                : 'bg-surface-200 text-muted'
                            }`}
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </DataPageLayout>
  );
}

function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="surface-card flex items-center gap-3 p-3">
      <span className="text-brand-500">{icon}</span>
      <div>
        <div className="text-xl font-bold text-heading">{value.toLocaleString()}</div>
        <div className="text-micro font-mono tracking-wider text-muted uppercase">{label}</div>
      </div>
    </div>
  );
}
