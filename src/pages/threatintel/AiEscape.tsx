import { useCallback, useEffect, useMemo, useState } from 'react';
import { errMessage, logCatch } from '../../lib/log';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { sanitizeUrl } from '../../lib/sanitize-url';
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  GitPullRequest,
  Search,
  ShieldAlert,
} from 'lucide-react';

type Klass = 'containment-breach' | 'agent-hijack' | 'supply-chain' | 'tool-misuse' | 'injection';

interface Slim {
  id: string;
  title: string;
  klass: Klass;
  sev: 'critical' | 'severe' | 'notable' | 'contained';
  tier: string;
  cbs: number;
  occurred: string;
  disclosed: string;
  dwell: number | null;
  autonomous: boolean;
  developer: string;
  purpose: string;
  failed: string[];
}

interface IndexDoc {
  registry: string;
  version: string;
  compiled: string;
  builtAt: string;
  cbsScale: string;
  stats: {
    entries: number;
    tierA: number;
    evalEnvBreaches: number;
    autonomous: number;
    medianDwellDays: number | null;
    dwellRange: [number, number] | null;
    mostAbsentGuardrail: { id: string; entries: number } | null;
    lastDisclosedAt: string | null;
    lastDisclosedId: string | null;
  };
  guardrailCounts: Record<string, number>;
  incidents: Slim[];
}

interface Docket extends Slim {
  actor: string;
  systems: string;
  targets: string;
  summary: string;
  disputed: string | null;
  chain: Record<string, string | null>;
  sources: { label: string; url: string }[];
}

interface Guardrail {
  id: string;
  title: string;
  def: string;
}

interface Tracker {
  name: string;
  url: string;
  kind: string;
  holds: string;
  checked: string;
}

const KLASS_LABEL: Record<Klass, string> = {
  'containment-breach': 'Containment breach',
  'agent-hijack': 'Agent hijack',
  'supply-chain': 'Supply chain',
  'tool-misuse': 'Tool misuse',
  injection: 'Injection',
};

const SEV_PILL: Record<string, string> = {
  critical: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  severe: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  notable: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  contained: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

const CHAIN_STAGES = ['PRESSURE', 'PROBE', 'BREACH', 'CHANNEL', 'ESCALATE', 'PROPAGATE', 'HALT'];

function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

function DocketView({ id }: { id: string }) {
  const [body, setBody] = useState<Docket | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`/api/v1/ai-escape/incidents/${encodeURIComponent(id)}`);
        if (r.ok && !cancelled) setBody((await r.json()) as Docket);
      } catch {
        /* non-fatal */
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (loading) return <p className="text-mini font-mono text-muted mt-2">loading docket…</p>;
  if (!body) return <p className="text-mini font-mono text-muted mt-2">docket unavailable</p>;

  return (
    <div className="mt-3 pt-3 border-t border-line-1 space-y-3">
      <p className="text-sm text-body leading-relaxed">{body.summary}</p>
      <div className="grid sm:grid-cols-2 gap-2 text-xs">
        <div>
          <span className="font-mono text-muted">actor: </span>
          <span className="text-body">{body.actor}</span>
        </div>
        <div>
          <span className="font-mono text-muted">systems: </span>
          <span className="text-body">{body.systems}</span>
        </div>
        <div>
          <span className="font-mono text-muted">targets: </span>
          <span className="text-body">{body.targets}</span>
        </div>
        <div>
          <span className="font-mono text-muted">deployed to do: </span>
          <span className="text-body">{body.purpose}</span>
        </div>
      </div>
      <div>
        <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">Containment chain</div>
        <ol className="space-y-1">
          {CHAIN_STAGES.map((stage) => (
            <li key={stage} className="flex gap-2 text-xs">
              <span className="font-mono text-rose-600 dark:text-rose-400 w-24 shrink-0">{stage}</span>
              <span className={body.chain[stage] ? 'text-body' : 'text-slate-400 font-mono'}>
                {body.chain[stage] ?? '—'}
              </span>
            </li>
          ))}
        </ol>
      </div>
      {body.failed.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini font-mono text-muted mr-1">absent guardrails:</span>
          {body.failed.map((g) => (
            <span
              key={g}
              className="px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
            >
              {g}
            </span>
          ))}
        </div>
      )}
      {body.disputed && (
        <p className="text-xs text-amber-700 dark:text-amber-300 leading-relaxed">
          <span className="font-mono">disputed: </span>
          {body.disputed}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {body.sources.map((s) => (
          <a
            key={s.url}
            href={sanitizeUrl(s.url) ?? undefined}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-0.5 text-xs text-sky-600 dark:text-sky-400 hover:underline"
          >
            {s.label} <ExternalLink className="w-2.5 h-2.5" />
          </a>
        ))}
      </div>
      <PostAnalysisButton
        title={`${body.id} — ${body.title}`}
        description={`${body.summary}\n\nFailed guardrails: ${body.failed.join(', ') || 'none named'}\nActor: ${body.actor}\nSystems: ${body.systems}`}
        source={body.sources[0]?.url ?? 'ai-escape registry'}
        compact
      />
    </div>
  );
}

export default function AiEscape(): JSX.Element {
  const [idx, setIdx] = useState<IndexDoc | null>(null);
  const [guardrails, setGuardrails] = useState<Guardrail[]>([]);
  const [trackers, setTrackers] = useState<Tracker[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [klass, setKlass] = useState<'all' | Klass>('all');
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [iRes, gRes, tRes] = await Promise.all([
        fetch('/api/v1/ai-escape/'),
        fetch('/api/v1/ai-escape/guardrails'),
        fetch('/api/v1/ai-escape/trackers'),
      ]);
      if (!iRes.ok) throw new Error(`index HTTP ${iRes.status}`);
      const full = (await (await fetch('/api/v1/ai-escape/incidents?limit=100')).json()) as { incidents: Slim[] };
      const base = (await iRes.json()) as IndexDoc;
      base.incidents = full.incidents ?? [];
      setIdx(base);
      if (gRes.ok) setGuardrails(((await gRes.json()) as { guardrails: Guardrail[] }).guardrails ?? []);
      if (tRes.ok) setTrackers(((await tRes.json()) as { trackers: Tracker[] }).trackers ?? []);
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
    if (!idx) return [];
    const needle = query.toLowerCase().trim();
    return idx.incidents.filter((e) => {
      if (klass !== 'all' && e.klass !== klass) return false;
      if (needle && !`${e.id} ${e.title} ${e.developer} ${e.purpose}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [idx, klass, query]);

  const guardMax = useMemo(() => Math.max(1, ...Object.values(idx?.guardrailCounts ?? { _: 1 })), [idx]);
  const sinceDays = daysSince(idx?.stats.lastDisclosedAt ?? null);

  // Community report queue (server-side, reviewed before publish).
  const [queue, setQueue] = useState<
    { id: string; title: string; klass: string; occurred: string | null; status: string; created_at: string }[]
  >([]);
  const [queueLoading, setQueueLoading] = useState(false);
  const [form, setForm] = useState({
    title: '',
    klass: 'containment-breach',
    occurred: '',
    purpose: '',
    systems: '',
    summary: '',
    sources: '',
    handle: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState<string | null>(null);

  const loadQueue = useCallback(async () => {
    setQueueLoading(true);
    try {
      const r = await fetch('/api/v1/ai-escape/reports?status=pending&limit=50');
      if (r.ok) {
        const j = (await r.json()) as { reports: typeof queue };
        setQueue(j.reports ?? []);
      }
    } catch (e) {
      logCatch(e);
    } finally {
      setQueueLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  const submitReport = useCallback(async () => {
    setSubmitting(true);
    setSubmitMsg(null);
    try {
      const r = await fetch('/api/v1/ai-escape/reports', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          title: form.title.trim(),
          klass: form.klass,
          occurred: form.occurred || undefined,
          purpose: form.purpose.trim() || undefined,
          systems: form.systems.trim() || undefined,
          summary: form.summary.trim(),
          sources: form.sources.trim(),
          handle: form.handle.trim() || undefined,
        }),
      });
      const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string; message?: string };
      if (!r.ok || !j.ok) throw new Error(j.message ?? j.error ?? `HTTP ${r.status}`);
      setSubmitMsg('Received — queued for review. Nothing reaches the registry unreviewed.');
      setForm({
        title: '',
        klass: 'containment-breach',
        occurred: '',
        purpose: '',
        systems: '',
        summary: '',
        sources: '',
        handle: '',
      });
      void loadQueue();
    } catch (e) {
      logCatch(e);
      setSubmitMsg(`Submit failed: ${errMessage(e)}`);
    } finally {
      setSubmitting(false);
    }
  }, [form, loadQueue]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<Bot size={28} />}
      title="AI Escape Watch"
      description={
        <>
          A registry of AI agent containment failures — indexed by the control that failed, not the harm. Each entry
          carries the agent&apos;s assigned task, the seven-stage containment chain, the absent guardrails, and sources;
          disputed figures are flagged, never averaged. Seed corpus v0.1; new entries land via reviewed PRs to{' '}
          <span className="font-mono">threat-intel-staging/ai-escape/seed.json</span>.
        </>
      }
      loading={loading && !idx}
      error={error}
      onRetry={load}
    >
      {idx && (
        <>
          {/* Clock + stats */}
          <div className="surface-card p-4 mb-4 flex flex-wrap items-center gap-x-8 gap-y-3">
            <div>
              <div className="text-micro font-mono uppercase tracking-wider text-muted">
                Since last disclosed escape
              </div>
              <div className="text-2xl font-bold text-heading font-mono">
                {sinceDays ?? '—'}
                <span className="text-sm font-normal text-muted"> days</span>
              </div>
              <div className="text-mini font-mono text-muted">
                {idx.stats.lastDisclosedId ?? ''} · {fmtDate(idx.stats.lastDisclosedAt)}
              </div>
            </div>
            {[
              { label: 'Entries', value: idx.stats.entries },
              { label: 'Tier A', value: idx.stats.tierA },
              { label: 'Eval-env breaches', value: idx.stats.evalEnvBreaches },
              { label: 'Autonomous', value: idx.stats.autonomous },
              {
                label: 'Median dwell',
                value: idx.stats.medianDwellDays != null ? `${idx.stats.medianDwellDays}d` : '—',
              },
            ].map(({ label, value }) => (
              <div key={label}>
                <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
                <div className="text-xl font-bold text-heading">{value}</div>
              </div>
            ))}
            {idx.stats.mostAbsentGuardrail && (
              <div>
                <div className="text-micro font-mono uppercase tracking-wider text-muted">Most-absent guardrail</div>
                <div className="text-xl font-bold text-rose-600 dark:text-rose-400 font-mono">
                  {idx.stats.mostAbsentGuardrail.id}
                </div>
                <div className="text-mini font-mono text-muted">{idx.stats.mostAbsentGuardrail.entries} entries</div>
              </div>
            )}
          </div>

          <AiSummaryCard
            surface="AI Escape Watch"
            items={filtered.slice(0, 15).map((e) => ({
              title: `${e.id} — ${e.title}`,
              body: `${KLASS_LABEL[e.klass]} · ${e.sev} · CBS ${e.cbs} · failed: ${e.failed.join(', ') || 'none named'}`,
              source: 'ai-escape registry',
            }))}
            requireAdmin={false}
          />

          {/* Registry */}
          <div className="flex flex-col sm:flex-row gap-3 my-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                type="text"
                placeholder="Search incidents, developers, tasks…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            {(['all', 'containment-breach', 'agent-hijack', 'supply-chain', 'tool-misuse', 'injection'] as const).map(
              (k) => (
                <button
                  key={k}
                  onClick={() => setKlass(k)}
                  className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                    klass === k
                      ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                      : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
                  }`}
                >
                  {k === 'all' ? 'All' : KLASS_LABEL[k]}
                </button>
              )
            )}
            <span className="ml-auto text-xs font-mono text-muted">
              {filtered.length} / {idx.stats.entries}
            </span>
          </div>

          <div className="grid gap-2 mb-8">
            {filtered.map((e) => {
              const open = openId === e.id;
              return (
                <div key={e.id} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
                  <button
                    type="button"
                    onClick={() => setOpenId(open ? null : e.id)}
                    className="w-full text-left"
                    aria-expanded={open}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-micro font-mono text-muted">{e.id}</span>
                          <span className={`px-1.5 py-0.5 text-micro font-mono rounded border ${SEV_PILL[e.sev]}`}>
                            {e.sev}
                          </span>
                          <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                            tier {e.tier}
                          </span>
                          <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
                            {KLASS_LABEL[e.klass]}
                          </span>
                          {e.autonomous && (
                            <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-violet-500/10 text-violet-700 dark:text-violet-300 border border-violet-500/30">
                              autonomous
                            </span>
                          )}
                        </div>
                        <h3 className="text-sm font-bold text-heading mt-1 leading-snug">{e.title}</h3>
                        <p className="text-xs text-muted mt-0.5">
                          Deployed to do: <span className="text-body">{e.purpose}</span>
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span
                          className="text-sm font-mono font-bold text-heading"
                          title="Containment Breach Score (v0.1 draft)"
                        >
                          {e.cbs.toFixed(1)}
                        </span>
                        {open ? (
                          <ChevronUp className="w-3.5 h-3.5 text-muted" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5 text-muted" />
                        )}
                      </div>
                    </div>
                    <p className="text-mini font-mono text-muted mt-1">
                      {e.occurred} → disclosed {e.disclosed} · {e.developer}
                      {e.dwell != null && ` · dwell ${e.dwell}d`}
                    </p>
                  </button>
                  {open && <DocketView id={e.id} />}
                </div>
              );
            })}
          </div>

          {/* Guardrails */}
          <h2 className="flex items-center gap-2 text-lg font-bold text-heading mb-1">
            <ShieldAlert className="w-4 h-4 text-rose-500" /> Which guardrail was missing
          </h2>
          <p className="text-xs text-muted mb-3">
            Entries name more than one control, so counts sum above {idx.stats.entries}.
          </p>
          <div className="space-y-1.5 mb-8">
            {guardrails.map((g) => {
              const count = idx.guardrailCounts[g.id] ?? 0;
              return (
                <div key={g.id} className="flex items-center gap-3">
                  <span className="font-mono text-xs text-heading w-28 shrink-0">{g.id}</span>
                  <div className="flex-1 h-2.5 rounded-full bg-surface-300 dark:bg-surface-100/5 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-rose-500"
                      style={{ width: `${Math.round((count / guardMax) * 100)}%` }}
                    />
                  </div>
                  <span className="font-mono text-xs text-muted w-8 text-right shrink-0">{count}</span>
                  <span className="hidden md:block text-xs text-muted flex-[2] truncate" title={g.def}>
                    {g.title}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Provenance */}
          <h2 className="text-lg font-bold text-heading mb-1">Who holds the evidence</h2>
          <p className="text-xs text-muted mb-3">A registry is only as good as the record behind it.</p>
          <div className="overflow-x-auto rounded-xl border border-line-1 mb-8">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-line-1 text-left">
                  <th className="px-3 py-2 font-semibold text-muted">Tracker</th>
                  <th className="px-3 py-2 font-semibold text-muted">Kind</th>
                  <th className="px-3 py-2 font-semibold text-muted">Holds</th>
                  <th className="px-3 py-2 font-semibold text-muted">Checked</th>
                </tr>
              </thead>
              <tbody>
                {trackers.map((t) => (
                  <tr key={t.name} className="border-b border-line-1 last:border-0">
                    <td className="px-3 py-2">
                      <a
                        href={sanitizeUrl(t.url) ?? undefined}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="text-sky-600 dark:text-sky-400 hover:underline font-medium"
                      >
                        {t.name}
                      </a>
                    </td>
                    <td className="px-3 py-2 font-mono text-muted">{t.kind}</td>
                    <td className="px-3 py-2 text-body">{t.holds}</td>
                    <td className="px-3 py-2 font-mono text-muted whitespace-nowrap">{t.checked}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Report + public review queue */}
          <div className="surface-card p-4">
            <h2 className="flex items-center gap-2 text-lg font-bold text-heading mb-1">
              <AlertTriangle className="w-4 h-4 text-amber-500" /> Report an incident
            </h2>
            <p className="text-xs text-muted mb-3">
              Two fields required (what happened + account), sources mandatory. Nothing reaches the registry unreviewed
              — the queue below is visible to every reader.
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              <label className="block sm:col-span-2">
                <span className="text-micro font-mono text-muted">What happened *</span>
                <input
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  maxLength={140}
                  placeholder="Agent bypassed egress allowlist via internal package proxy"
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block">
                <span className="text-micro font-mono text-muted">Class</span>
                <select
                  value={form.klass}
                  onChange={(e) => setForm({ ...form, klass: e.target.value })}
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                >
                  <option value="containment-breach">Containment breach</option>
                  <option value="agent-hijack">Agent hijack</option>
                  <option value="supply-chain">Supply chain</option>
                  <option value="tool-misuse">Tool misuse</option>
                  <option value="injection">Injection</option>
                </select>
              </label>
              <label className="block">
                <span className="text-micro font-mono text-muted">Date observed</span>
                <input
                  type="date"
                  value={form.occurred}
                  onChange={(e) => setForm({ ...form, occurred: e.target.value })}
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block sm:col-span-2">
                <span className="text-micro font-mono text-muted">What was the agent deployed to do</span>
                <input
                  value={form.purpose}
                  onChange={(e) => setForm({ ...form, purpose: e.target.value })}
                  maxLength={140}
                  placeholder="Automated code review in CI · capability evaluation · customer support"
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block">
                <span className="text-micro font-mono text-muted">Systems involved</span>
                <input
                  value={form.systems}
                  onChange={(e) => setForm({ ...form, systems: e.target.value })}
                  maxLength={140}
                  placeholder="Model, framework, affected platform"
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block">
                <span className="text-micro font-mono text-muted">Attribution (optional)</span>
                <input
                  value={form.handle}
                  onChange={(e) => setForm({ ...form, handle: e.target.value })}
                  maxLength={60}
                  placeholder="Name or handle"
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block sm:col-span-2">
                <span className="text-micro font-mono text-muted">
                  Account *{' '}
                  <span className="text-muted">
                    — mechanism over narrative: which control was supposed to catch this?
                  </span>
                </span>
                <textarea
                  value={form.summary}
                  onChange={(e) => setForm({ ...form, summary: e.target.value })}
                  maxLength={1600}
                  rows={4}
                  placeholder="What the agent was doing, what boundary it crossed, how it was noticed, what stopped it."
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm focus:outline-none focus:border-rose-500"
                />
              </label>
              <label className="block sm:col-span-2">
                <span className="text-micro font-mono text-muted">
                  Sources * — comma-separated URLs; a report without a source will not clear review
                </span>
                <input
                  value={form.sources}
                  onChange={(e) => setForm({ ...form, sources: e.target.value })}
                  maxLength={600}
                  placeholder="https://…, https://…"
                  className="mt-1 w-full px-3 py-2 rounded-xl border border-line-1 bg-surface-100 text-sm font-mono focus:outline-none focus:border-rose-500"
                />
              </label>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <button
                type="button"
                onClick={() => void submitReport()}
                disabled={submitting}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-mono bg-rose-600 dark:bg-rose-500 text-on-fill hover:bg-rose-700 dark:hover:bg-rose-400 transition-colors disabled:opacity-40"
              >
                <GitPullRequest className="w-3.5 h-3.5" /> {submitting ? 'Submitting…' : 'Submit for review'}
              </button>
              {submitMsg && <p className="text-xs font-mono text-muted">{submitMsg}</p>}
            </div>

            <div className="mt-5">
              <h3 className="text-sm font-bold text-heading mb-2">
                Under review{' '}
                <span className="font-mono text-xs text-muted">
                  {queueLoading ? 'loading…' : `${queue.length} pending`}
                </span>
              </h3>
              {queue.length === 0 && !queueLoading ? (
                <p className="text-xs font-mono text-muted">Queue empty — be the first to report.</p>
              ) : (
                <ul className="space-y-2">
                  {queue.map((rep) => (
                    <li key={rep.id} className="rounded-xl border border-line-1 p-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold text-heading">{rep.title}</span>
                        <span className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 text-muted">
                          {rep.klass}
                        </span>
                      </div>
                      <p className="text-micro font-mono text-muted mt-1">
                        {rep.occurred ?? 'date unknown'} · submitted {fmtDate(rep.created_at)}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
