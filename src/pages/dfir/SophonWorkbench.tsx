/**
 * Sophon-style authorized security-testing workbench.
 *
 * A real DFIR agent run (Main → Planner → Worker → review → report) with an
 * explicit mission scope and evidence-backed findings. The workflow concept
 * comes from github.com/i11us0ry/Sophon; that repository has no reuse licence,
 * so no upstream prose, prompts, roles or code are vendored here. This page
 * and the agent logic are original and run on the platform's own DO.
 */
import { useCallback, useEffect, useMemo, useState, type JSX } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Loader2,
  Play,
  ShieldCheck,
  Target,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { Tabs } from '../../components/ui/Tabs';
import { InvestigationTrace } from '../../components/threatintel/InvestigationTrace';
import { DataGapsPanel, type ToolFailure } from '../../components/threatintel/DataGapsPanel';
import { ReportView, type ReportActionCard } from '../../components/dfir/ReportView';
import { api, ApiError } from '../../lib/api-client';
import { adminAuthHeaders } from '../../lib/admin-token';
import { useWebSocket } from '../../hooks/useWebSocket';
import { errMessage } from '../../lib/log';

interface Profile {
  id: string;
  label: string;
  description: string;
  queryType: string;
  specialists: string[];
  maxSteps: number;
}

interface ProfileResponse {
  profiles: Profile[];
  workflow: string[];
  note: string;
  source: string;
}

interface WorkStep {
  stepNumber: number;
  plan?: string;
  status?: string;
  toolCalls?: Array<{ tool: string; args: Record<string, unknown>; reasoning?: string }>;
  results?: Array<{ tool: string; status: string; durationMs?: number; error?: string }>;
  observation?: string;
  completedAt?: string;
  observerFindings?: {
    iocs?: unknown[];
    actors?: unknown[];
    cves?: unknown[];
    keyFacts?: string[];
    gaps?: string[];
    confidence?: string;
  };
}

interface WorkState {
  id: string;
  status: 'running' | 'done' | 'error';
  steps: WorkStep[];
  currentStep: number;
  maxSteps: number;
  report: string | null;
  modelUsed: string | null;
  error: string | null;
  actionCard?: ReportActionCard;
  reportVersioning?: {
    versions: Array<{ version: number; qualityScore: number; modelUsed: string; reason: string }>;
    diff?: {
      fromVersion: number;
      toVersion: number;
      fromScore: number;
      toScore: number;
      additions: number;
      deletions: number;
    };
  };
  dataGaps?: ToolFailure[];
  sources?: Array<{ name: string; items: number }>;
  sophon?: { profileId: string; scope: string; parsedTargets: number; blockedCalls: number };
}

type WsMessage =
  | { type: 'connected' }
  | { type: 'step'; step: WorkStep }
  | { type: 'token'; token: string }
  | { type: 'done'; report?: string; modelUsed?: string; actionCard?: ReportActionCard }
  | { type: 'error'; error: string };

const WORKFLOW = [
  { id: 'main', label: 'Main', desc: 'Confirm scope, dispatch work' },
  { id: 'planner', label: 'Planner', desc: 'Form one testable hypothesis' },
  { id: 'worker', label: 'Worker', desc: 'Execute, collect evidence' },
  { id: 'review', label: 'Review', desc: 'Challenge the conclusion' },
  { id: 'report', label: 'Report', desc: 'Findings, evidence, gaps' },
];

export default function SophonWorkbench(): JSX.Element {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [meta, setMeta] = useState<ProfileResponse | null>(null);
  const [profileId, setProfileId] = useState('web-pentest');
  const [query, setQuery] = useState('');
  const [scope, setScope] = useState('');
  const [activeId, setActiveId] = useState<string | null>(null);
  const [state, setState] = useState<WorkState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [tab, setTab] = useState('setup');

  useEffect(() => {
    api
      .get<ProfileResponse>('/api/v1/agent/sophon/profiles', { headers: adminAuthHeaders() })
      .then((r) => {
        setMeta(r);
        setProfiles(r.profiles);
      })
      .catch((e) => setError(errMessage(e)));
  }, []);

  const poll = useCallback(async () => {
    if (!activeId) return;
    try {
      const next = await api.get<WorkState>(`/api/v1/agent/${encodeURIComponent(activeId)}`, {
        headers: adminAuthHeaders(),
      });
      setState(next);
      if (next.status === 'done' || next.status === 'error') setStarting(false);
    } catch (e) {
      if (!(e instanceof ApiError)) setError(errMessage(e));
    }
  }, [activeId]);

  useEffect(() => {
    if (!activeId || !starting) return;
    const timer = window.setInterval(() => void poll(), 2000);
    return () => window.clearInterval(timer);
  }, [activeId, starting, poll]);

  const wsUrl = useMemo(() => {
    if (!activeId) return null;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/api/v1/ws/agent/${encodeURIComponent(activeId)}`;
  }, [activeId]);

  useWebSocket<WsMessage>(wsUrl, {
    onMessage: (msg) => {
      if (msg.type === 'step') {
        setState((prev) =>
          prev
            ? {
                ...prev,
                steps: [...prev.steps.filter((s) => s.stepNumber !== msg.step.stepNumber), msg.step],
                currentStep: msg.step.stepNumber,
              }
            : prev
        );
      } else if (msg.type === 'done') {
        setStarting(false);
        void poll();
      } else if (msg.type === 'error') {
        setError(msg.error);
        setStarting(false);
        void poll();
      }
    },
    reconnect: true,
    maxReconnectAttempts: 5,
  });

  const start = useCallback(async () => {
    if (!query.trim() || !scope.trim()) return;
    setStarting(true);
    setError(null);
    setState(null);
    setTab('trace');
    try {
      const res = await api.post<{ id: string; profile: string; status: string }>(
        '/api/v1/agent/sophon',
        { query: query.trim(), profile: profileId, missionScope: scope.trim() },
        { headers: adminAuthHeaders() }
      );
      setActiveId(res.id);
    } catch (e) {
      setStarting(false);
      setError(
        e instanceof ApiError
          ? `${e.message}${e.status === 400 ? ' — add a domain, IP, CIDR or wildcard target to the scope.' : ''}`
          : errMessage(e)
      );
    }
  }, [query, scope, profileId]);

  const selected = profiles.find((p) => p.id === profileId);
  const steps = useMemo(() => state?.steps ?? [], [state?.steps]);
  const okSteps = steps.filter((s) => s.status === 'done').length;
  const evidence = useMemo(() => steps.flatMap((s) => s.observerFindings?.keyFacts ?? []).slice(-12), [steps]);
  const dataGaps = (state?.dataGaps ?? []) as ToolFailure[];

  const exportReport = () => {
    if (!state?.report) return;
    const blob = new Blob(
      [
        `# Sophon workbench — ${selected?.label ?? profileId}\n\nScope: ${state.sophon?.scope ?? scope}\n\n${state.report}`,
      ],
      {
        type: 'text/markdown',
      }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sophon-${(activeId ?? 'run').slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <DataPageLayout
      backTo="/dfir/agent-suite"
      backLabel="Agent suite"
      icon={<ShieldCheck size={28} />}
      title="Sophon Workbench"
      description="Authorized security testing with a mission scope, evidence-backed findings and a Main → Planner → Worker → review workflow."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="Sophon Workbench — authorized security agent"
        description="A scoped, evidence-driven DFIR agent run with task profiles, mission policy and adversarial review."
        section="DFIR"
        canonicalPath="/dfir/sophon"
      />

      <div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-mini leading-relaxed text-amber-800 dark:text-amber-200">
        <div className="flex items-center gap-2 font-semibold">
          <AlertTriangle size={14} /> Authorization boundary
        </div>
        Only assess systems you own or are explicitly authorized to test. The mission scope below is enforced
        deterministically: tool calls naming an out-of-scope host are blocked before execution. No exploitation,
        credential use or destructive requests are performed.
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-mini text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      <Tabs
        tabs={[
          { id: 'setup', label: 'Setup' },
          { id: 'trace', label: `Trace${steps.length ? ` (${steps.length})` : ''}`, disabled: !activeId },
          { id: 'report', label: 'Report', disabled: !state?.report },
        ]}
        active={tab}
        onChange={setTab}
        variant="underline"
      >
        {(active) =>
          active === 'setup' ? (
            <div className="grid gap-5 py-4 lg:grid-cols-[320px_1fr]">
              <section>
                <h2 className="mb-2 text-mini font-mono uppercase tracking-wider text-muted">Task profile</h2>
                <p className="mb-3 text-micro text-muted">
                  A profile supplies method guidance only — it does not change agent identity, tools or permissions.
                </p>
                <div className="space-y-2">
                  {profiles.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setProfileId(p.id)}
                      aria-pressed={profileId === p.id}
                      className={`w-full rounded-lg border px-3 py-2 text-left transition-colors ${
                        profileId === p.id
                          ? 'border-sky-500/50 bg-sky-500/10'
                          : 'border-line-1 bg-surface-100/60 hover:border-sky-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-semibold text-heading">{p.label}</span>
                        <span className="font-mono text-micro text-muted">{p.maxSteps} steps</span>
                      </div>
                      <p className="mt-0.5 text-mini text-muted">{p.description}</p>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {p.specialists.slice(0, 3).map((s) => (
                          <span
                            key={s}
                            className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              </section>

              <section className="space-y-4">
                <div>
                  <label
                    htmlFor="sophon-scope"
                    className="mb-1 flex items-center gap-1.5 text-mini font-semibold text-heading"
                  >
                    <Target size={13} className="text-rose-500" /> Authorized scope
                  </label>
                  <textarea
                    id="sophon-scope"
                    value={scope}
                    onChange={(e) => setScope(e.target.value)}
                    rows={3}
                    placeholder="example.com, *.corp.example, 10.0.0.0/8, CVE-2026-1234"
                    className="w-full rounded-lg border border-line-1 bg-surface-100 px-3 py-2 font-mono text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
                  />
                  <p className="mt-1 text-micro text-muted">
                    Domains cover subdomains; CIDRs cover their addresses. At least one target is required.
                  </p>
                </div>
                <div>
                  <label htmlFor="sophon-query" className="mb-1 block text-mini font-semibold text-heading">
                    Assessment goal
                  </label>
                  <textarea
                    id="sophon-query"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    rows={4}
                    maxLength={2000}
                    placeholder="What should the workbench assess within that scope?"
                    className="w-full rounded-lg border border-line-1 bg-surface-100 px-3 py-2 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
                  />
                </div>

                <button
                  type="button"
                  onClick={() => void start()}
                  disabled={starting || !query.trim() || !scope.trim()}
                  className="inline-flex items-center gap-2 rounded-lg border border-sky-500/50 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-700 transition-colors hover:bg-sky-500/20 disabled:opacity-40 dark:text-sky-300"
                >
                  {starting ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
                  {starting ? 'Running…' : 'Start assessment'}
                </button>

                <div>
                  <h2 className="mb-2 text-mini font-mono uppercase tracking-wider text-muted">Workflow</h2>
                  <ol className="flex flex-wrap items-center gap-1.5">
                    {WORKFLOW.map((w, i) => (
                      <li key={w.id} className="flex items-center gap-1.5">
                        <span
                          className="rounded-full border border-line-1 bg-surface-100 px-2.5 py-1 text-mini text-body"
                          title={w.desc}
                        >
                          {w.label}
                        </span>
                        {i < WORKFLOW.length - 1 && <ArrowRight size={11} className="text-muted" />}
                      </li>
                    ))}
                  </ol>
                  {meta?.note && <p className="mt-2 text-micro text-muted">{meta.note}</p>}
                </div>
              </section>
            </div>
          ) : active === 'trace' ? (
            <div className="space-y-4 py-4">
              <div className="flex flex-wrap items-center gap-3 text-mini text-muted">
                <span>
                  status <span className="font-mono text-fg">{state?.status ?? 'starting'}</span>
                </span>
                <span>
                  step{' '}
                  <span className="font-mono text-fg">
                    {state?.currentStep ?? 0}/{state?.maxSteps ?? selected?.maxSteps ?? 6}
                  </span>
                </span>
                <span>
                  ok <span className="font-mono text-fg">{okSteps}</span>
                </span>
                {state?.sophon?.blockedCalls ? (
                  <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
                    <ShieldCheck size={12} /> {state.sophon.blockedCalls} out-of-scope call(s) blocked
                  </span>
                ) : null}
                {state?.modelUsed && <span className="font-mono">via {state.modelUsed}</span>}
              </div>
              {starting && state?.status === 'running' && (
                <div className="h-1 overflow-hidden rounded-full bg-surface-200">
                  <div
                    className="h-full bg-sky-500 transition-all"
                    style={{ width: `${Math.min(100, ((state.currentStep + 1) / (state.maxSteps || 6)) * 100)}%` }}
                  />
                </div>
              )}
              <InvestigationTrace steps={steps} />
              {evidence.length > 0 && (
                <div className="rounded-lg border border-line-1 bg-surface-100/70 p-3">
                  <h3 className="flex items-center gap-1.5 text-mini font-semibold text-heading">
                    <ClipboardCheck size={13} className="text-emerald-500" /> Evidence observed
                  </h3>
                  <ul className="mt-2 space-y-1 text-mini text-body">
                    {evidence.map((e, i) => (
                      <li key={i} className="flex gap-2">
                        <CheckCircle2 size={12} className="mt-0.5 shrink-0 text-emerald-500" />
                        <span>{e}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {dataGaps.length > 0 && <DataGapsPanel dataGaps={dataGaps} />}
              {state?.sources && state.sources.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {state.sources.map((s) => (
                    <span
                      key={s.name}
                      className="rounded-full border border-line-1 px-2 py-0.5 font-mono text-micro text-muted"
                    >
                      {s.name} · {s.items}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="py-4">
              {state?.report ? (
                <>
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <p className="text-mini text-muted">
                      Scope: <span className="font-mono text-fg">{state.sophon?.scope ?? scope}</span>
                    </p>
                    <button
                      type="button"
                      onClick={exportReport}
                      className="rounded-lg border border-line-1 px-3 py-1.5 text-mini text-body hover:border-sky-500/40"
                    >
                      Export markdown
                    </button>
                  </div>
                  <ReportView
                    report={state.report}
                    actionCard={state.actionCard}
                    reportVersioning={state.reportVersioning}
                    query={query}
                  />
                </>
              ) : (
                <p className="rounded-lg border border-line-1 bg-surface-100/60 p-6 text-center text-mini text-muted">
                  No report yet.
                </p>
              )}
            </div>
          )
        }
      </Tabs>

      <footer className="mt-6 border-t border-line-1 pt-3 text-micro text-muted">
        Workflow concept from Sophon (no reuse licence — no upstream content vendored). Runs on this platform's
        investigator agent with its existing cost, rate-limit and review guardrails.{' '}
        <Link to="/dfir/agent-suite" className="text-sky-600 hover:underline dark:text-sky-400">
          Agent suite
        </Link>
      </footer>
    </DataPageLayout>
  );
}
