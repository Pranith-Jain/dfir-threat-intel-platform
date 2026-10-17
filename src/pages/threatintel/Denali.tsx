import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { renderMarkdown } from '../../components/dfir/report-view-helpers';
import { ExternalLink, Loader2, ScanSearch, Search, ShieldCheck } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * Denali — evidence-led, provider-neutral AI security (transilienceai, Apache-2.0).
 *
 * Deterministic issue/detection rules with exact UIDs and thresholds, a
 * 16-kind asset taxonomy with explicit coverage states, and the architecture
 * ADR knowledge base. No finding without sufficient independent evidence —
 * unknown scope stays visible, never "safe".
 *
 * Reads the replicated manifest through the platform API:
 *   GET  /api/v1/denali/                    → index
 *   GET  /api/v1/denali/rules/:uid          → full rule semantics
 *   GET  /api/v1/denali/taxonomy            → asset/coverage/severity enums
 *   GET  /api/v1/denali/docs/:slug          → verbatim ADR body
 *   POST /api/v1/denali/evaluate/activity   → stateless sliding-window checks
 */

interface RuleSlim {
  uid: string;
  kind: string;
  title: string;
  description: string;
}

interface RuleBody extends RuleSlim {
  engine: string;
  inputs: Record<string, unknown>;
  thresholds: Record<string, unknown>;
  grouping?: string;
  evidenceSemantics: string;
  engineUrl: string;
}

interface DenaliIndex {
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  tagline: string;
  edgeNote: string;
  counts: { rules: number; issueRules: number; runtimeRules: number; assetKinds: number; docs: number };
  rules: RuleSlim[];
}

interface Taxonomy {
  counts: { assetKinds: number; coverageStates: number; severities: number; relationshipKinds: number };
  assetKinds: Array<{ id: string; category: string }>;
  coverageStates: Array<{ id: string; meaning: string }>;
  findingSeverities: string[];
  relationshipKinds: Array<{ id: string; category: string }>;
  evidencePrinciples: string[];
}

interface DocSlim {
  slug: string;
  kind: 'adr' | 'guide';
  title: string;
  summary: string;
}

interface EvalResult {
  activitiesEvaluated: number;
  findingCount: number;
  failedSignins: {
    candidates: Array<{ actorUid: string; appId: string; failures: number; windowStart: string; windowEnd: string }>;
    incomplete: number;
  };
  highImpactConsents: { count: number; items: Array<{ operation?: string; scopes: string[] }> };
  riskySequences: {
    candidates: Array<{ session: string; retrievalAt: string; mutationAt: string; gapSeconds: number }>;
  };
  evidenceNote: string;
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

const KIND_STYLES: Record<string, string> = {
  issue:
    'text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800',
  runtime_detection:
    'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
};

const EXAMPLE_ACTIVITIES = `[
  {"category": "ai_app_sign_in", "outcome": "failure", "occurredAt": "2026-09-20T10:00:00Z", "actorUid": "alice@example.com", "appId": "ai-app-1"},
  {"category": "ai_app_sign_in", "outcome": "failure", "occurredAt": "2026-09-20T11:00:00Z", "actorUid": "alice@example.com", "appId": "ai-app-1"},
  {"category": "ai_app_sign_in", "outcome": "failure", "occurredAt": "2026-09-20T12:00:00Z", "actorUid": "alice@example.com", "appId": "ai-app-1"},
  {"category": "admin_change", "outcome": "success", "occurredAt": "2026-09-20T13:00:00Z", "operation": "Consent to application", "scopes": ["Mail.ReadWrite"]}
]`;

type Tab = 'rules' | 'taxonomy' | 'docs' | 'evaluate';

export default function Denali(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<DenaliIndex>({ url: '/api/v1/denali/', ttl: 300_000 });
  const { data: tax } = useDataFetch<Taxonomy>({ url: '/api/v1/denali/taxonomy', ttl: 300_000 });
  const { data: docsData } = useDataFetch<{ docs: DocSlim[] }>({ url: '/api/v1/denali/docs', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('rules');
  const [kind, setKind] = useState('');
  const [q, setQ] = useState('');
  const [ruleBody, setRuleBody] = useState<RuleBody | null>(null);
  const [ruleLoading, setRuleLoading] = useState(false);
  const [docBody, setDocBody] = useState<{ meta: DocSlim; body: string } | null>(null);
  const [docLoading, setDocLoading] = useState(false);
  const [activitiesText, setActivitiesText] = useState(EXAMPLE_ACTIVITIES);
  const [evalResult, setEvalResult] = useState<EvalResult | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);

  const rules = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.rules ?? []).filter((r) => {
      if (kind && r.kind !== kind) return false;
      if (needle && `${r.uid} ${r.title} ${r.description}`.toLowerCase().includes(needle) === false) return false;
      return true;
    });
  }, [data, kind, q]);

  const docs = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (docsData?.docs ?? []).filter((d) => {
      if (needle && `${d.slug} ${d.title} ${d.summary}`.toLowerCase().includes(needle) === false) return false;
      return true;
    });
  }, [docsData, q]);

  async function openRule(uid: string) {
    setRuleLoading(true);
    try {
      setRuleBody(await api.get<RuleBody>(`/api/v1/denali/rules/${encodeURIComponent(uid)}`));
    } catch {
      setRuleBody(null);
    } finally {
      setRuleLoading(false);
    }
  }

  async function openDoc(slug: string) {
    setDocLoading(true);
    try {
      setDocBody(await api.get<{ meta: DocSlim; body: string }>(`/api/v1/denali/docs/${encodeURIComponent(slug)}`));
    } catch {
      setDocBody(null);
    } finally {
      setDocLoading(false);
    }
  }

  async function runEvaluate() {
    setEvaluating(true);
    setEvalResult(null);
    setEvalError(null);
    try {
      const activities = JSON.parse(activitiesText) as unknown;
      setEvalResult(await api.post<EvalResult>('/api/v1/denali/evaluate/activity', { activities }));
    } catch (e) {
      setEvalError(errMessage(e, 'Evaluation failed'));
    } finally {
      setEvaluating(false);
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'rules', label: `Rules (${data?.counts.rules ?? '…'})` },
    { id: 'taxonomy', label: 'Taxonomy' },
    { id: 'docs', label: `Docs (${data?.counts.docs ?? '…'})` },
    { id: 'evaluate', label: 'Evaluate' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldCheck size={28} />}
      title="Denali"
      description="Evidence-led, provider-neutral AI security (transilienceai, Apache-2.0) — inventory, posture, attack paths, and runtime context with observed facts kept separate from inferences. No finding without sufficient independent evidence."
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-white border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {(tab === 'rules' || tab === 'docs') && (
        <div className="flex flex-col sm:flex-row gap-2 mb-4">
          {tab === 'rules' && (
            <select value={kind} onChange={(e) => setKind(e.target.value)} className={`${inputCls} sm:w-48`}>
              <option value="">Issues + detections</option>
              <option value="issue">Issues</option>
              <option value="runtime_detection">Runtime detections</option>
            </select>
          )}
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={tab === 'rules' ? 'Search rules…' : 'Search ADRs…'}
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>
      )}

      {tab === 'rules' && (
        <div className="grid gap-2">
          {rules.map((r) => (
            <button
              key={r.uid}
              onClick={() => openRule(r.uid)}
              className="surface-card text-left p-3 hover:border-brand-400 transition-colors"
            >
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${KIND_STYLES[r.kind] ?? ''}`}>
                  {r.kind === 'issue' ? 'ISSUE' : 'RUNTIME'}
                </span>
                <span className="font-semibold text-sm text-heading">{r.title}</span>
              </div>
              <p className="text-sm text-body mt-1">{r.description}</p>
              <p className="font-mono text-xs text-muted mt-1">{r.uid}</p>
            </button>
          ))}
          {rules.length === 0 && !loading && <p className="text-sm text-muted">No rules match.</p>}
        </div>
      )}

      {tab === 'taxonomy' && tax && (
        <div className="grid gap-2">
          <div className="surface-card p-3">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">
              Asset kinds ({tax.counts.assetKinds})
            </p>
            <div className="flex flex-wrap gap-1.5">
              {tax.assetKinds.map((k) => (
                <span key={k.id} className="font-mono text-xs px-2 py-0.5 rounded border border-line-1 text-body">
                  {k.id}
                </span>
              ))}
            </div>
          </div>
          <div className="surface-card p-3">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Coverage states</p>
            {tax.coverageStates.map((s) => (
              <p key={s.id} className="text-sm text-body">
                <span className="font-mono text-xs text-brand-600 dark:text-brand-400">{s.id}</span> — {s.meaning}
              </p>
            ))}
            <p className="text-sm text-body mt-1">
              Severities: <span className="font-mono text-xs">{tax.findingSeverities.join(', ')}</span>
            </p>
          </div>
          <div className="surface-card p-3">
            <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Evidence principles</p>
            <ul className="list-disc ml-5 space-y-1">
              {tax.evidencePrinciples.map((p, i) => (
                <li key={i} className="text-sm text-body">
                  {p}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {tab === 'docs' && (
        <div className="grid gap-2">
          {docs.map((d) => (
            <button
              key={d.slug}
              onClick={() => openDoc(d.slug)}
              className="surface-card text-left p-3 hover:border-brand-400 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-bold px-2 py-0.5 rounded border border-line-1 text-muted uppercase">
                  {d.kind}
                </span>
                <span className="font-semibold text-sm text-heading">{d.title}</span>
              </div>
              <p className="text-sm text-body mt-1 line-clamp-2">{d.summary}</p>
            </button>
          ))}
          {docs.length === 0 && <p className="text-sm text-muted">No docs match.</p>}
        </div>
      )}

      {tab === 'evaluate' && (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Paste runtime activity JSON — the stateless Denali checks run on the edge: repeated failed AI sign-ins
            (≥3/24h), high-impact consent grants, retrieval→mutation sequences (5 min). Sequence and identity only,
            never intent.
          </p>
          <textarea
            value={activitiesText}
            onChange={(e) => setActivitiesText(e.target.value)}
            rows={12}
            spellCheck={false}
            className={`${inputCls} font-mono text-xs`}
          />
          <button
            onClick={runEvaluate}
            disabled={evaluating}
            className="px-4 py-2 rounded-xl bg-brand-600 text-on-fill text-sm font-medium disabled:opacity-50 flex items-center gap-2"
          >
            {evaluating ? <Loader2 size={15} className="animate-spin" /> : <ScanSearch size={15} />}
            Evaluate activity
          </button>
          {evalError && <p className="text-sm text-rose-600">{evalError}</p>}
          {evalResult && (
            <div className="space-y-2">
              <p className="text-sm text-heading font-medium">
                {evalResult.findingCount === 0
                  ? 'No findings'
                  : `${evalResult.findingCount} finding${evalResult.findingCount === 1 ? '' : 's'}`}{' '}
                ({evalResult.activitiesEvaluated} activities)
              </p>
              {evalResult.failedSignins.candidates.map((c, i) => (
                <div key={i} className="surface-card p-3 border-l-4 border-l-rose-500">
                  <p className="text-sm text-heading font-medium">Repeated failed sign-ins × {c.failures}</p>
                  <p className="font-mono text-xs text-muted">
                    {c.actorUid} → {c.appId}
                  </p>
                  <p className="text-xs text-muted">
                    {c.windowStart} … {c.windowEnd}
                  </p>
                </div>
              ))}
              {evalResult.highImpactConsents.count > 0 && (
                <div className="surface-card p-3 border-l-4 border-l-amber-500">
                  <p className="text-sm text-heading font-medium">
                    High-impact consent × {evalResult.highImpactConsents.count}
                  </p>
                  {evalResult.highImpactConsents.items.map((it, i) => (
                    <p key={i} className="font-mono text-xs text-muted">
                      {it.operation} — {it.scopes.join(', ')}
                    </p>
                  ))}
                </div>
              )}
              {evalResult.riskySequences.candidates.map((c, i) => (
                <div key={i} className="surface-card p-3 border-l-4 border-l-amber-500">
                  <p className="text-sm text-heading font-medium">Retrieval → mutation in {c.gapSeconds}s</p>
                  <p className="font-mono text-xs text-muted">session {c.session}</p>
                </div>
              ))}
              <p className="text-xs text-muted italic">{evalResult.evidenceNote}</p>
            </div>
          )}
        </div>
      )}

      <Modal
        open={ruleLoading || ruleBody !== null}
        onClose={() => {
          setRuleBody(null);
        }}
        title={ruleBody?.uid ?? 'Loading rule…'}
        size="lg"
      >
        {ruleBody && (
          <div className="space-y-4 max-h-[70vh] overflow-y-auto">
            <div>
              <p className="font-semibold text-heading">{ruleBody.title}</p>
              <p className="text-sm text-body mt-1">{ruleBody.description}</p>
            </div>
            <div className="border-l-2 border-amber-500 pl-4 py-2 bg-amber-50 dark:bg-amber-950/20 rounded-r-lg">
              <div className="text-xs font-semibold text-amber-600 dark:text-amber-400 uppercase tracking-wider mb-1">
                Evidence bounds
              </div>
              <p className="text-sm text-body">{ruleBody.evidenceSemantics}</p>
            </div>
            <div>
              <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-1">Thresholds & inputs</div>
              <pre className="font-mono text-xs text-body bg-surface-200 border border-line-1 rounded px-3 py-2 overflow-x-auto">
                {JSON.stringify(
                  { inputs: ruleBody.inputs, thresholds: ruleBody.thresholds, grouping: ruleBody.grouping },
                  null,
                  2
                )}
              </pre>
            </div>
            <a
              href={ruleBody.engineUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-brand-600 dark:text-brand-400"
            >
              Upstream engine <ExternalLink size={12} />
            </a>
          </div>
        )}
      </Modal>

      <Modal
        open={docLoading || docBody !== null}
        onClose={() => {
          setDocBody(null);
        }}
        title={docBody?.meta.title ?? 'Loading doc…'}
        size="lg"
      >
        {docBody && (
          <div className="max-h-[70vh] overflow-y-auto">
            <div
              className="prose dark:prose-invert prose-sm max-w-none"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(docBody.body) }}
            />
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
