import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Download, FileText, RefreshCw, Search, ShieldCheck } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';

/**
 * Agent report archive.
 *
 * Reports are persisted as `report_json` in D1 `agent_sessions` by the
 * InvestigatorAgent DO. This tab turns those rows into a browsable archive:
 * pick a finished session, read the sanitised report and its QA / self-eval /
 * cost / data-gap metadata, and download a Markdown copy. All calls are the
 * existing admin-gated agent endpoints, same-origin from the browser.
 */

/** Applied at the render sink, so the HTML injection guard can see the sanitiser. */
const REPORT_SANITIZE_OPTIONS = {
  ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|#|\/):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  ADD_ATTR: ['title'],
};

interface SessionRow {
  id: string;
  query: string;
  query_type: string;
  status: 'running' | 'done' | 'error' | string;
  total_steps: number;
  model_used: string | null;
  created_at: string;
  updated_at: string;
}

interface DataGap {
  tool: string;
  error: string;
  cause: string;
  missedCapability: string;
}

interface AgentState {
  id: string;
  query: string;
  status: string;
  report?: string;
  qa?: { qualityScore: number; flaggedClaims: string[]; missingFacts: string[] };
  selfEval?: Record<string, unknown>;
  cost?: { usd: number; tokens: number; llmCalls: number };
  reportVersioning?: { versions: Array<{ version: number; qualityScore: number; reason: string }> };
  dataGaps?: DataGap[];
  sources?: Array<{ name: string; items: number }>;
  error?: string | null;
}

function statusTone(status: string): string {
  switch (status) {
    case 'done':
      return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300';
    case 'error':
      return 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300';
    default:
      return 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300';
  }
}

function safeNumber(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : '-';
}

export default function AgentReports(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<{ sessions: SessionRow[] }>({
    url: '/api/v1/agent/sessions?limit=50',
    ttl: 30_000,
  });
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [state, setState] = useState<AgentState | null>(null);
  const [stateLoading, setStateLoading] = useState(false);
  const [stateError, setStateError] = useState<string | null>(null);
  const [reportHtml, setReportHtml] = useState('');
  const sanitizeRef = useRef<((html: string) => string) | null>(null);
  const sanitizeHtml = (html: string): string => (sanitizeRef.current ? sanitizeRef.current(html) : '');

  const sessions = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.sessions ?? []).filter(
      (s) => !q || s.query.toLowerCase().includes(q) || s.model_used?.toLowerCase().includes(q)
    );
  }, [data, query]);

  const open = useCallback(async (id: string) => {
    setSelected(id);
    setState(null);
    setReportHtml('');
    setStateError(null);
    setStateLoading(true);
    try {
      const res = await fetch(`/api/v1/agent/${encodeURIComponent(id)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const next = (await res.json()) as AgentState;
      setState(next);
      if (next.report) {
        const [{ marked }, { default: DOMPurify }] = await Promise.all([
          import('marked'),
          import('isomorphic-dompurify'),
        ]);
        // Store the unrendered HTML plus the sanitiser; sanitisation happens at
        // the render sink so every path through this component is covered.
        sanitizeRef.current = (html: string) => DOMPurify.sanitize(html, REPORT_SANITIZE_OPTIONS);
        setReportHtml((await marked.parse(next.report)) as string);
      }
    } catch (err) {
      setStateError(err instanceof Error ? err.message : String(err));
    } finally {
      setStateLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!selected && sessions.length > 0 && sessions[0]) {
      void open(sessions[0].id);
    }
  }, [sessions, selected, open]);

  const downloadMarkdown = () => {
    if (!state) return;
    const lines = [
      `# Investigation report — ${state.query}`,
      '',
      `_Session ${state.id} · generated ${new Date().toISOString()}_`,
      '',
      state.report ?? '_No report text available._',
      '',
      '## Assessment metadata',
      `- Quality score: ${safeNumber(state.qa?.qualityScore)}`,
      `- Model: ${selectedSession?.model_used ?? '-'}`,
      `- Cost: ${safeNumber(state.cost?.usd)} USD / ${safeNumber(state.cost?.tokens)} tokens / ${safeNumber(state.cost?.llmCalls)} LLM calls`,
      state.reportVersioning?.versions?.length
        ? `- Versions: ${state.reportVersioning.versions.map((v) => `v${v.version} (${safeNumber(v.qualityScore)})`).join(', ')}`
        : '',
      '',
      '## Data gaps',
      ...(state.dataGaps?.length
        ? state.dataGaps.map((g) => `- **${g.tool}** (${g.cause}): ${g.error} — missed ${g.missedCapability}`)
        : ['- None recorded']),
      '',
    ];
    const blob = new Blob([lines.filter(Boolean).join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agent-report-${state.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedSession = data?.sessions.find((s) => s.id === selected);
  const doneCount = (data?.sessions ?? []).filter((s) => s.status === 'done').length;
  const failedCount = (data?.sessions ?? []).filter((s) => s.status === 'error').length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold text-heading">
            <FileText size={18} /> Report archive
          </h2>
          <p className="mt-1 text-[11px] text-muted">
            {data ? `${data.sessions.length} sessions · ${doneCount} completed · ${failedCount} failed` : 'Loading…'} ·
            reports persist in D1 and survive worker restarts
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refetch()}
          className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 text-[11px] text-muted hover:text-heading"
        >
          <RefreshCw size={11} /> refresh
        </button>
      </div>

      {loading && !data && <p className="py-10 text-center text-sm text-muted">Loading agent sessions…</p>}
      {error && !data && (
        <p className="py-10 text-center text-sm text-rose-600 dark:text-rose-400">
          Agent sessions unavailable: {error}
        </p>
      )}

      {data && (
        <div className="grid gap-4 lg:grid-cols-[minmax(260px,1fr)_minmax(0,2fr)]">
          <section className="space-y-2">
            <label className="relative block">
              <span className="sr-only">Search reports</span>
              <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Query or model…"
                className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-brand-500 focus:outline-none"
              />
            </label>
            <ul className="max-h-[620px] space-y-1.5 overflow-y-auto pr-1">
              {sessions.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    onClick={() => void open(s.id)}
                    className={`w-full rounded-lg border p-2.5 text-left transition-colors ${
                      selected === s.id ? 'border-rose-500/50 bg-rose-500/5' : 'border-line-1 hover:border-rose-500/30'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${statusTone(s.status)}`}
                      >
                        {s.status}
                      </span>
                      <span className="font-mono text-[10px] text-muted">{relativeAgo(s.created_at)}</span>
                    </div>
                    <p className="mt-1 line-clamp-2 text-xs font-semibold text-heading">{s.query}</p>
                    <div className="mt-1 flex items-center gap-2 font-mono text-[10px] text-muted">
                      <span>{s.total_steps} steps</span>
                      {s.model_used && <span className="truncate">{s.model_used}</span>}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
            {sessions.length === 0 && <p className="text-center text-sm text-muted">No sessions match that search.</p>}
          </section>

          <section className="surface-card rounded-xl border border-line-1 p-4">
            {!selected && <p className="py-10 text-center text-sm text-muted">Select a session to read its report.</p>}
            {stateLoading && <p className="py-10 text-center text-sm text-muted">Loading report…</p>}
            {stateError && (
              <p className="py-10 text-center text-sm text-rose-600 dark:text-rose-400">
                Report load failed: {stateError}
              </p>
            )}
            {state && !stateLoading && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-heading">{state.query}</h3>
                    <p className="mt-0.5 font-mono text-[10px] text-muted">
                      {selectedSession?.id} · {selectedSession?.created_at}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={downloadMarkdown}
                    className="inline-flex items-center gap-1 rounded border border-line-1 px-2.5 py-1.5 font-mono text-[11px] text-muted hover:border-rose-500/40 hover:text-heading"
                  >
                    <Download size={11} /> Markdown
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    { label: 'Quality', value: safeNumber(state.qa?.qualityScore) },
                    { label: 'Cost (USD)', value: safeNumber(state.cost?.usd) },
                    { label: 'Tokens', value: safeNumber(state.cost?.tokens) },
                    { label: 'LLM calls', value: safeNumber(state.cost?.llmCalls) },
                  ].map((s) => (
                    <div key={s.label} className="rounded-lg border border-line-1 bg-surface-100 px-2.5 py-2">
                      <div className="text-[10px] uppercase tracking-wide text-muted">{s.label}</div>
                      <div className="font-mono text-sm text-heading">{s.value}</div>
                    </div>
                  ))}
                </div>

                {state.qa && (state.qa.flaggedClaims.length > 0 || state.qa.missingFacts.length > 0) && (
                  <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-[11px]">
                    <p className="flex items-center gap-1 font-semibold text-heading">
                      <ShieldCheck size={13} /> QA notes
                    </p>
                    {state.qa.flaggedClaims.length > 0 && (
                      <p className="mt-1 text-muted">Flagged: {state.qa.flaggedClaims.join(' · ')}</p>
                    )}
                    {state.qa.missingFacts.length > 0 && (
                      <p className="mt-1 text-muted">Missing: {state.qa.missingFacts.join(' · ')}</p>
                    )}
                  </div>
                )}

                {state.dataGaps && state.dataGaps.length > 0 && (
                  <div className="rounded-lg border border-line-1 p-3 text-[11px]">
                    <p className="font-semibold text-heading">Data gaps ({state.dataGaps.length})</p>
                    <ul className="mt-1 space-y-0.5 text-muted">
                      {state.dataGaps.map((g, i) => (
                        <li key={`${g.tool}-${i}`}>
                          <span className="font-mono text-body">{g.tool}</span> ({g.cause}) — {g.missedCapability}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {state.sources && state.sources.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {state.sources.map((s) => (
                      <span
                        key={s.name}
                        className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 font-mono text-[10px] text-muted"
                      >
                        {s.name} · {s.items}
                      </span>
                    ))}
                  </div>
                )}

                <div
                  className="prose prose-sm max-w-none text-body dark:prose-invert"
                  dangerouslySetInnerHTML={{ __html: sanitizeHtml(reportHtml) }}
                />
                {!state.report && <p className="text-sm text-muted">No report text is stored for this session.</p>}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
