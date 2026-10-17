import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { KeyRound, ChevronDown, ChevronRight, Plus, Trash2, RotateCcw, Download, ExternalLink } from 'lucide-react';
import {
  NHI_TOP_10,
  NHI_TYPES,
  emptyEntry,
  entryRisk,
  type CoverageStatus,
  type NhiEntry,
  type NhiTopId,
  type NhiType,
} from '../../data/nhi';
import { SEVERITY_TONE, SEVERITY_BAR } from '../../components/severity';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

/** Risk grade from entryRisk(). `safe` keeps its own all-clear green; the
 *  four risk tiers map onto the canonical severity ramp. */
type RiskGrade = ReturnType<typeof entryRisk>['grade'];

const SAFE_TONE = 'border-emerald-500/30 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300';

const gradeTone = (g: RiskGrade): string => (g === 'safe' ? SAFE_TONE : SEVERITY_TONE[g]);
const gradeBar = (g: RiskGrade): string => (g === 'safe' ? 'bg-emerald-500' : SEVERITY_BAR[g]);

const STORAGE_KEY = 'dfir.nhi.inventory.v1';

const STATUS_CYCLE: Record<CoverageStatus, CoverageStatus> = {
  unset: 'covered',
  covered: 'partial',
  partial: 'gap',
  gap: 'na',
  na: 'unset',
};

const STATUS_STYLES: Record<CoverageStatus, { label: string; cls: string }> = {
  unset: {
    label: '- unset',
    cls: 'border-slate-300 dark:border-line-1 text-slate-500',
  },
  covered: {
    label: 'covered',
    cls: 'border-emerald-400/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
  partial: {
    label: '~ partial',
    cls: 'border-amber-400/60 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  gap: {
    label: 'gap',
    cls: 'border-rose-400/60 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  na: {
    label: 'n/a',
    cls: 'border-slate-300 dark:border-line-1 text-muted',
  },
};

function loadInventory(): NhiEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as NhiEntry[];
  } catch (_catchErr) {
    console.error('loadInventory failed:', errMessage(_catchErr));
    return [];
  }
}

function buildMarkdown(items: NhiEntry[]): string {
  const lines: string[] = ['# Non-Human Identity Inventory', ''];
  if (items.length === 0) {
    lines.push('_(no entries)_');
    return lines.join('\n');
  }
  for (const e of items) {
    const r = entryRisk(e);
    lines.push(`## ${e.name || '(unnamed)'} - ${r.grade.toUpperCase()} (${r.score}/100)`);
    lines.push('');
    lines.push(`- **Type:** ${e.type}`);
    if (e.owner) lines.push(`- **Owner:** ${e.owner}`);
    if (e.scope) lines.push(`- **Scope:** ${e.scope}`);
    if (e.lastRotated) lines.push(`- **Last rotated:** ${e.lastRotated}`);
    if (e.rotationDays) lines.push(`- **Rotation cadence:** ${e.rotationDays} days`);
    lines.push(`- **Monitored:** ${e.monitored ? 'yes' : 'no'}`);
    if (e.storage) lines.push(`- **Storage:** ${e.storage}`);
    if (e.notes) lines.push(`- **Notes:** ${e.notes}`);
    lines.push('');
    lines.push('### OWASP NHI Top 10 coverage');
    lines.push('');
    for (const item of NHI_TOP_10) {
      const s = e.status[item.id] ?? 'unset';
      lines.push(`- ${item.id} ${item.title}: **${s}**`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export default function Nhi(): JSX.Element {
  const [tab, setTab] = useState<'top10' | 'inventory'>('inventory');
  const [items, setItems] = useState<NhiEntry[]>([]);
  const [expandedTop10, setExpandedTop10] = useState<Set<string>>(new Set());
  const [expandedItem, setExpandedItem] = useState<string | null>(null);

  useEffect(() => {
    setItems(loadInventory());
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
    } catch (_catchErr) {
      console.error('Nhi failed:', errMessage(_catchErr));
      /* quota - non-fatal */
    }
  }, [items]);

  const update = (id: string, patch: Partial<NhiEntry>) =>
    setItems((xs) => xs.map((x) => (x.id === id ? { ...x, ...patch } : x)));

  const cycleStatus = (id: string, top: NhiTopId) =>
    setItems((xs) =>
      xs.map((x) =>
        x.id === id ? { ...x, status: { ...x.status, [top]: STATUS_CYCLE[x.status[top] ?? 'unset'] } } : x
      )
    );

  const remove = (id: string) => setItems((xs) => xs.filter((x) => x.id !== id));
  const add = () => {
    const e = emptyEntry();
    setItems((xs) => [...xs, e]);
    setExpandedItem(e.id);
  };

  const reset = () => {
    if (typeof window !== 'undefined' && confirm('Clear all NHI entries? This cannot be undone.')) {
      setItems([]);
    }
  };

  const exportMd = () => {
    const blob = new Blob([buildMarkdown(items)], { type: 'text/markdown' });
    downloadBlob(blob, 'nhi-inventory.md');
  };

  const aggregate = useMemo(() => {
    const counts = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const e of items) counts[entryRisk(e).grade]++;
    const total = items.length;
    const worst = (['critical', 'high', 'medium', 'low', 'safe'] as const).find((g) => counts[g] > 0) ?? 'safe';
    return { counts, total, worst };
  }, [items]);

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <KeyRound size={28} className="text-brand-600 dark:text-brand-400" /> NHI Inventory &amp; OWASP Top 10
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          Non-Human Identity inventory templater. Add the NHIs in your environment (service accounts, OAuth apps,
          machine certs, MCP tokens, …), then assess each one against the OWASP NHI Top 10 (2025). Coverage stats and
          markdown export. All data stays in your browser.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Pairs with the{' '}
          <Link to="/dfir/mcp-audit" className="text-brand-600 dark:text-brand-400 hover:underline">
            MCP &amp; Claude Code Auditor
          </Link>{' '}
          (which finds the NHIs hiding in your AI tooling) and the{' '}
          <Link to="/dfir/owasp" className="text-brand-600 dark:text-brand-400 hover:underline">
            OWASP Top 10
          </Link>{' '}
          (Web / API / LLM).
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setTab('inventory')}
          className={`text-sm font-mono px-3 py-1.5 rounded border transition-colors ${
            tab === 'inventory'
              ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
              : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
          }`}
        >
          Inventory ({items.length})
        </button>
        <button
          onClick={() => setTab('top10')}
          className={`text-sm font-mono px-3 py-1.5 rounded border transition-colors ${
            tab === 'top10'
              ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
              : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
          }`}
        >
          OWASP NHI Top 10
        </button>
      </div>

      {tab === 'top10' ? (
        <section className="space-y-2">
          {NHI_TOP_10.map((item) => {
            const expanded = expandedTop10.has(item.id);
            return (
              <div key={item.id}>
                <button
                  onClick={() => {
                    setExpandedTop10((prev) => {
                      const next = new Set(prev);
                      next.has(item.id) ? next.delete(item.id) : next.add(item.id);
                      return next;
                    });
                  }}
                  className="w-full flex items-center gap-3 text-left surface-card hover:border-brand-500/40 hover:bg-surface-200 dark:hover:bg-surface-300/60 px-4 py-3 transition-colors"
                  aria-expanded={expanded}
                >
                  <span className="flex-none w-12 font-mono text-mini text-brand-600 dark:text-brand-400 font-bold">
                    {item.id}
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block font-display font-semibold text-heading">{item.title}</span>
                    <span className="block text-xs font-mono text-muted truncate">
                      {item.summary.slice(0, 110)}
                      {item.summary.length > 110 && '…'}
                    </span>
                  </span>
                  {expanded ? (
                    <ChevronDown size={16} className="flex-none text-muted" />
                  ) : (
                    <ChevronRight size={16} className="flex-none text-muted" />
                  )}
                </button>
                {expanded && (
                  <div className="animate-fade-in-up overflow-hidden">
                    <div className="rounded-xl border border-line-1 bg-surface-200/50 mt-2 p-4 space-y-3">
                      <p className="text-sm font-mono text-body leading-relaxed">{item.summary}</p>
                      <div className="rounded border border-line-1 bg-surface-100 p-3">
                        <h4 className="text-micro font-mono uppercase tracking-[0.2em] text-rose-600 dark:text-rose-400 mb-1">
                          Attack
                        </h4>
                        <p className="text-xs font-mono text-body leading-relaxed">{item.attack}</p>
                      </div>
                      <div className="rounded border border-line-1 bg-surface-100 p-3">
                        <h4 className="text-micro font-mono uppercase tracking-[0.2em] text-emerald-600 dark:text-emerald-400 mb-1">
                          Mitigation
                        </h4>
                        <p className="text-xs font-mono text-body leading-relaxed">{item.mitigation}</p>
                      </div>
                      {item.attCK && item.attCK.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-micro font-mono uppercase tracking-[0.2em] text-muted">
                            ATT&amp;CK:
                          </span>
                          {item.attCK.map((id) => (
                            <Link
                              key={id}
                              to={`/threatintel/mitre?id=${encodeURIComponent(id)}`}
                              className="text-micro font-mono px-1.5 py-0.5 rounded border border-brand-500/30 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:border-brand-500/60"
                            >
                              {id}
                            </Link>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </section>
      ) : (
        <>
          {/* Aggregate */}
          {items.length > 0 && (
            <section className="surface-card p-4 mb-6">
              <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">
                  Inventory risk distribution
                </h2>
                <span
                  className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${gradeTone(aggregate.worst)}`}
                >
                  worst: {aggregate.worst}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                {(['critical', 'high', 'medium', 'low', 'safe'] as const).map((g) => (
                  <div
                    key={g}
                    className={`rounded border px-2 py-1.5 text-center font-mono ${gradeTone(g)} ${
                      aggregate.counts[g] === 0 ? 'opacity-40' : ''
                    }`}
                  >
                    <div className="text-lg font-bold">{aggregate.counts[g]}</div>
                    <div className="text-micro uppercase tracking-wider">{g}</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Action bar */}
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <button
              onClick={add}
              className="text-sm font-mono px-3 py-1.5 rounded border border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300 hover:border-brand-500 inline-flex items-center gap-1.5 transition-colors"
            >
              <Plus size={14} /> Add NHI
            </button>
            <button
              onClick={exportMd}
              disabled={items.length === 0}
              className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-brand-500/40 disabled:opacity-50 inline-flex items-center gap-1.5 transition-colors"
            >
              <Download size={13} /> Export markdown
            </button>
            <button
              onClick={reset}
              disabled={items.length === 0}
              className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 disabled:opacity-50 inline-flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw size={13} /> Reset all
            </button>
          </div>

          {/* List */}
          {items.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line-2 p-8 text-center text-sm font-mono text-muted">
              No NHIs yet. Click <strong>Add NHI</strong> to start an inventory. Everything stays in your browser.
            </div>
          ) : (
            <ul className="space-y-3">
              {items.map((e) => {
                const risk = entryRisk(e);
                const isOpen = expandedItem === e.id;
                return (
                  <li key={e.id} className="surface-card">
                    {/* Row header */}
                    <button
                      onClick={() => setExpandedItem(isOpen ? null : e.id)}
                      className="w-full flex items-center gap-3 text-left px-4 py-3 hover:bg-surface-200 dark:hover:bg-surface-300/40"
                      aria-expanded={isOpen}
                    >
                      <span className="flex-1 min-w-0">
                        <span className="block font-display font-semibold text-heading truncate">
                          {e.name || '(unnamed)'}
                        </span>
                        <span className="block text-xs font-mono text-muted truncate">
                          {e.type} · {e.owner || 'no owner'}
                          {e.scope ? ` · ${e.scope}` : ''}
                        </span>
                      </span>
                      <span
                        className={`flex-none text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${gradeTone(risk.grade)}`}
                      >
                        {risk.grade} · {risk.score}
                      </span>
                      {isOpen ? (
                        <ChevronDown size={16} className="flex-none text-muted" />
                      ) : (
                        <ChevronRight size={16} className="flex-none text-muted" />
                      )}
                    </button>

                    {/* Risk bar */}
                    <div className="px-4 pb-3">
                      <div className="h-1 rounded bg-track overflow-hidden">
                        <div
                          className={`h-full transition-all ${gradeBar(risk.grade)}`}
                          style={{ width: `${Math.max(2, risk.score)}%` }}
                        />
                      </div>
                    </div>

                    {isOpen && (
                      <div className="border-t border-line-1 px-4 py-3 space-y-4">
                        {/* Fields */}
                        <div className="grid gap-3 sm:grid-cols-2">
                          <Field label="Name">
                            <input
                              type="text"
                              value={e.name}
                              onChange={(ev) => update(e.id, { name: ev.target.value })}
                              placeholder="prod-deploy-bot"
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Type">
                            <select
                              value={e.type}
                              onChange={(ev) => update(e.id, { type: ev.target.value as NhiType })}
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            >
                              {NHI_TYPES.map((t) => (
                                <option key={t.id} value={t.id}>
                                  {t.label}
                                </option>
                              ))}
                            </select>
                          </Field>
                          <Field label="Owner (a real human)">
                            <input
                              type="text"
                              value={e.owner}
                              onChange={(ev) => update(e.id, { owner: ev.target.value })}
                              placeholder="alice@team - name + escalation path"
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Scope / permissions">
                            <input
                              type="text"
                              value={e.scope}
                              onChange={(ev) => update(e.id, { scope: ev.target.value })}
                              placeholder="repo:write, deploy:prod"
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Last rotated (YYYY-MM-DD)">
                            <input
                              type="date"
                              value={e.lastRotated}
                              onChange={(ev) => update(e.id, { lastRotated: ev.target.value })}
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Rotation cadence (days, 0 = never)">
                            <input
                              type="number"
                              min={0}
                              value={e.rotationDays}
                              onChange={(ev) => update(e.id, { rotationDays: Number(ev.target.value) || 0 })}
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Storage">
                            <input
                              type="text"
                              value={e.storage}
                              onChange={(ev) => update(e.id, { storage: ev.target.value })}
                              placeholder="AWS Secrets Manager - secret/prod/deploy"
                              className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                            />
                          </Field>
                          <Field label="Monitored?">
                            <label className="inline-flex items-center gap-2 text-xs font-mono">
                              <input
                                type="checkbox"
                                checked={e.monitored}
                                onChange={(ev) => update(e.id, { monitored: ev.target.checked })}
                              />
                              <span>Logged + alertable on use</span>
                            </label>
                          </Field>
                        </div>
                        <Field label="Notes">
                          <textarea
                            value={e.notes}
                            onChange={(ev) => update(e.id, { notes: ev.target.value })}
                            rows={2}
                            placeholder="Free text - incident history, special handling, related tickets…"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>

                        {/* Coverage */}
                        <div>
                          <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-2">
                            OWASP NHI Top 10 coverage
                          </h3>
                          <p className="text-mini font-mono text-muted mb-2">
                            Click each row to cycle: unset → covered → partial → gap → n/a → unset.
                          </p>
                          <div className="grid gap-1.5">
                            {NHI_TOP_10.map((it) => {
                              const s: CoverageStatus = e.status[it.id] ?? 'unset';
                              return (
                                <button
                                  key={it.id}
                                  onClick={() => cycleStatus(e.id, it.id)}
                                  className={`flex items-center gap-3 text-left rounded border px-2 py-1.5 text-xs font-mono ${STATUS_STYLES[s].cls}`}
                                >
                                  <span className="flex-none w-12 font-bold">{it.id}</span>
                                  <span className="flex-1 truncate text-body">{it.title}</span>
                                  <span className="flex-none">{STATUS_STYLES[s].label}</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>

                        <div className="flex justify-end pt-2">
                          <button
                            onClick={() => remove(e.id)}
                            className="text-xs font-mono px-2 py-1 rounded border border-rose-300 dark:border-rose-900/40 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 inline-flex items-center gap-1"
                          >
                            <Trash2 size={11} /> Delete
                          </button>
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}

      <section className="mt-8 surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">References</h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          <li>
            <a
              href="https://owasp.org/www-project-non-human-identities-top-10/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              OWASP Non-Human Identities Top 10 (2025)
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://spiffe.io/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              SPIFFE - workload identity standard
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }): JSX.Element {
  return (
    <label className="block">
      <span className="text-micro font-mono uppercase tracking-[0.2em] text-muted mb-1 block">{label}</span>
      {children}
    </label>
  );
}
