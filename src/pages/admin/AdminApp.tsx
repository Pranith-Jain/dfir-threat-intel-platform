import { useEffect, useState } from 'react';
import { getJson, postJson, probeAuth } from './adminApi';
import { readAdminToken, clearAdminToken } from '../../lib/admin-token';
import AdminLogin from './AdminLogin';
import PendingTab from './PendingTab';
import ApprovedTab from './ApprovedTab';
import ScheduleTab from './ScheduleTab';
import DraftsTab from './DraftsTab';
import PublishedTab from './PublishedTab';
import FailedTab from './FailedTab';
import HealthTab from './HealthTab';
import GenerateTab from './GenerateTab';
import IntelBundleTab from './IntelBundleTab';
import ApiKeysTab from './ApiKeysTab';
import XCookiesTab from './XCookiesTab';
import RetentionTab from './RetentionTab';
import BriefingsTab from './BriefingsTab';
import AnalyticsTab from './AnalyticsTab';
import CalendarTab from './CalendarTab';
import LinkAuditTab from './LinkAuditTab';
import { errMessage } from '../../lib/log';

type TabKey =
  | 'pending'
  | 'approved'
  | 'schedule'
  | 'drafts'
  | 'published'
  | 'failed'
  | 'health'
  | 'manual'
  | 'intel'
  | 'apikeys'
  | 'xcookies'
  | 'briefings'
  | 'retention'
  | 'analytics'
  | 'calendar'
  | 'linkaudit';

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: 'pending', label: 'Pending' },
  { key: 'approved', label: 'Queue' },
  { key: 'schedule', label: 'Schedule' },
  { key: 'drafts', label: 'Drafts' },
  { key: 'published', label: 'Published' },
  { key: 'manual', label: 'Generate' },
  { key: 'failed', label: 'Failed' },
  { key: 'health', label: 'Health' },
  { key: 'intel', label: 'Intel bundle' },
  { key: 'apikeys', label: 'API Keys' },
  { key: 'xcookies', label: 'X Cookies' },
  { key: 'briefings', label: 'Briefings' },
  { key: 'retention', label: 'Retention' },
  { key: 'analytics', label: 'Analytics' },
  { key: 'calendar', label: 'Calendar' },
  { key: 'linkaudit', label: 'Link audit' },
];

const STAGES: Array<{ stage: 'discovery' | 'planner' | 'publisher'; label: string; hint: string }> = [
  {
    stage: 'discovery',
    label: 'Run discovery',
    hint: 'Populate the pending queue now (normally daily cron at 00:05 UTC)',
  },
  {
    stage: 'planner',
    label: 'Run planner',
    hint: 'Schedule approved candidates now (runs daily, chained after discovery)',
  },
  { stage: 'publisher', label: 'Publish now', hint: 'Generate + publish the next due slot (normally hourly cron)' },
];

function summariseRunResult(stage: string, result: unknown): string {
  if (!result || typeof result !== 'object') return `${stage}: done`;
  const r = result as Record<string, unknown>;
  if (typeof r.slug === 'string') return `${stage}: published /blog/${r.slug}`;
  if (typeof r.scheduled === 'number') return `${stage}: scheduled ${r.scheduled} slot(s)`;
  if (typeof r.discovered === 'number') return `${stage}: discovered ${r.discovered} candidate(s)`;
  if (typeof r.published === 'number') return `${stage}: published ${r.published}`;
  if (typeof r.count === 'number') return `${stage}: ${r.count}`;
  return `${stage}: ${JSON.stringify(result).slice(0, 160)}`;
}

function PipelineBar() {
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function run(stage: string) {
    setBusy(stage);
    setMsg(null);
    try {
      const r = await postJson<{ ok?: boolean; stage?: string; result?: unknown; error?: string }>(`/run/${stage}`);
      setMsg(r.error ? `${stage}: ${r.error}` : summariseRunResult(stage, r.result));
    } catch (e) {
      console.error('run failed:', errMessage(e));
      setMsg(`${stage}: ${errMessage(e)}`);
    } finally {
      setBusy(null);
    }
  }

  async function runAll() {
    setBusy('all');
    setMsg(null);
    const parts: string[] = [];
    try {
      const d = await postJson<{ ok?: boolean; result?: unknown; error?: string }>(`/run/discovery`);
      parts.push(summariseRunResult('discovery', d.result));
      const p = await postJson<{ ok?: boolean; result?: unknown; error?: string }>(`/run/planner`);
      parts.push(summariseRunResult('planner', p.result));
      const u = await postJson<{ ok?: boolean; result?: unknown; error?: string }>(`/run/publisher`);
      parts.push(summariseRunResult('publisher', u.result));
      setMsg(parts.join(' · '));
    } catch (e) {
      console.error('runAll failed:', errMessage(e));
      setMsg(`${parts.join(' · ')}${parts.length ? ' · ' : ''}${errMessage(e)}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="mb-6 rounded-xl border border-line-2 bg-surface-200/50 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-mono uppercase tracking-wider text-muted mr-2">Pipeline</span>
        {STAGES.map((s) => (
          <button
            key={s.stage}
            onClick={() => run(s.stage)}
            disabled={busy !== null}
            title={s.hint}
            className="px-3 py-1.5 border border-line-2 rounded text-sm text-body hover:bg-surface-300 dark:hover:bg-surface-300 hover:text-heading dark:hover:text-white disabled:opacity-50 transition-colors"
          >
            {busy === s.stage ? `${s.label}…` : s.label}
          </button>
        ))}
        <button
          onClick={() => void runAll()}
          disabled={busy !== null}
          title="Discover → Plan → Publish in sequence"
          className="px-3 py-1.5 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 rounded text-sm hover:bg-emerald-50 dark:hover:bg-emerald-500/10 disabled:opacity-50 transition-colors"
        >
          {busy === 'all' ? 'Running…' : 'Run full pipeline'}
        </button>
      </div>
      {msg && <p className="mt-3 text-xs font-mono text-muted break-all">{msg}</p>}
    </div>
  );
}

export default function AdminApp() {
  const [authStatus, setAuthStatus] = useState<'probing' | 'unauthed' | 'authed'>('probing');
  const [active, setActive] = useState<TabKey>('pending');
  const [inferenceStats, setInferenceStats] = useState<{
    calls: number;
    totalTokens: number;
    estimatedCostCents: number;
    overCap: boolean;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!readAdminToken()) {
        if (!cancelled) setAuthStatus('unauthed');
        return;
      }
      const ok = await probeAuth();
      if (cancelled) return;
      if (ok) setAuthStatus('authed');
      else {
        clearAdminToken();
        setAuthStatus('unauthed');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch inference cost stats on auth (best-effort)
  useEffect(() => {
    if (authStatus !== 'authed') return;
    getJson<{ calls: number; totalTokens: number; estimatedCostCents: number; overCap: boolean }>('/inference-stats')
      .then((data) => {
        if (
          data &&
          typeof data.calls === 'number' &&
          typeof data.totalTokens === 'number' &&
          typeof data.estimatedCostCents === 'number'
        ) {
          setInferenceStats(data);
        }
      })
      .catch(() => {});
  }, [authStatus]);

  function logout() {
    clearAdminToken();
    window.location.reload();
  }

  if (authStatus === 'probing') {
    return (
      <div className="max-w-6xl mx-auto px-6 py-8">
        <p className="text-sm font-mono text-muted">Checking admin session…</p>
      </div>
    );
  }
  if (authStatus === 'unauthed') {
    return <AdminLogin onLogin={() => setAuthStatus('authed')} />;
  }

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-display font-bold text-heading">Case Study Admin</h1>
          <p className="text-xs font-mono text-muted mt-0.5">Pipeline management and content admin</p>
        </div>
        <div className="flex items-center gap-3">
          {inferenceStats && (
            <span
              className={`px-2 py-1 rounded text-micro font-mono border ${
                inferenceStats.overCap
                  ? 'bg-rose-50 dark:bg-rose-900/30 text-rose-600 dark:text-rose-300 border-rose-200 dark:border-rose-700/50'
                  : 'bg-slate-50 dark:bg-surface-200 text-muted border-line-1'
              }`}
              title={`${inferenceStats.calls ?? 0} calls · ${(inferenceStats.totalTokens ?? 0).toLocaleString()} tokens`}
            >
              ${(inferenceStats.estimatedCostCents ?? 0).toFixed(2)} this month
            </span>
          )}
          <a
            href="/admin/analytics"
            className="px-3 py-1.5 border border-line-2 rounded text-sm text-muted hover:bg-surface-300 dark:hover:bg-surface-300 hover:text-heading dark:hover:text-white transition-colors"
          >
            Analytics
          </a>
          <button
            onClick={logout}
            className="px-3 py-1.5 border border-line-2 rounded text-sm text-muted hover:bg-surface-300 dark:hover:bg-surface-300 hover:text-heading dark:hover:text-white transition-colors"
          >
            Logout
          </button>
        </div>
      </div>

      <PipelineBar />

      {/* Tabs */}
      <nav className="flex flex-wrap gap-1 border-b border-line-2 mb-6">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setActive(t.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              active === t.key
                ? 'border-b-2 border-brand-500 -mb-px text-slate-900 dark:text-white'
                : 'text-muted hover:text-slate-900 dark:hover:text-slate-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {/* Content */}
      <section className="bg-surface-100 border border-line-2 rounded-xl p-4">
        {active === 'pending' && <PendingTab />}
        {active === 'approved' && <ApprovedTab />}
        {active === 'schedule' && <ScheduleTab />}
        {active === 'drafts' && <DraftsTab />}
        {active === 'published' && <PublishedTab />}
        {active === 'failed' && <FailedTab />}
        {active === 'health' && <HealthTab />}
        {active === 'manual' && <GenerateTab />}
        {active === 'intel' && <IntelBundleTab />}
        {active === 'apikeys' && <ApiKeysTab />}
        {active === 'xcookies' && <XCookiesTab />}
        {active === 'briefings' && <BriefingsTab />}
        {active === 'retention' && <RetentionTab />}
        {active === 'analytics' && <AnalyticsTab />}
        {active === 'calendar' && <CalendarTab />}
        {active === 'linkaudit' && <LinkAuditTab />}
      </section>
    </div>
  );
}
