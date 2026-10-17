import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { FolderTree, Plus, Trash2, RotateCcw, Download, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import {
  TIERS,
  TIER_LABELS,
  TIER_STYLES,
  DATASET_TYPES,
  STORAGE_KEY,
  emptyState,
  emptyDataset,
  loadState,
  distributionByTier,
  buildMarkdown,
  type ClassificationState,
  type Dataset,
  type DatasetType,
  type Tier,
  type TierPolicy,
} from '../../data/data-classification';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

export default function DataClassification(): JSX.Element {
  const [state, setState] = useState<ClassificationState>(emptyState);
  const [tab, setTab] = useState<'policies' | 'inventory' | 'matrix'>('policies');
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setState(loadState());
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (_catchErr) {
      console.error('DataClassification failed:', errMessage(_catchErr));
      /* quota */
    }
  }, [state]);

  const updatePolicy = (tier: Tier, patch: Partial<TierPolicy>) =>
    setState((s) => ({
      ...s,
      policies: { ...s.policies, [tier]: { ...s.policies[tier], ...patch } },
    }));

  const addDataset = () => {
    const d = emptyDataset();
    setState((s) => ({ ...s, datasets: [...s.datasets, d] }));
    setExpanded(d.id);
    setTab('inventory');
  };

  const updateDataset = (id: string, patch: Partial<Dataset>) =>
    setState((s) => ({
      ...s,
      datasets: s.datasets.map((d) => (d.id === id ? { ...d, ...patch } : d)),
    }));

  const removeDataset = (id: string) => setState((s) => ({ ...s, datasets: s.datasets.filter((d) => d.id !== id) }));

  const reset = () => {
    if (
      typeof window !== 'undefined' &&
      confirm('Reset everything? Tier policies will return to defaults and inventory will be cleared.')
    ) {
      setState(emptyState());
    }
  };

  const exportMd = () => {
    const blob = new Blob([buildMarkdown(state)], { type: 'text/markdown' });
    downloadBlob(blob, 'data-classification.md');
  };

  const dist = useMemo(() => distributionByTier(state), [state]);
  const total = state.datasets.length;

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<FolderTree size={28} />}
      title="Data Classification & Handling"
      description="Define your tier policies (Public / Internal / Confidential / Restricted), inventory the datasets that exist in your environment, and assign each one to a tier. The matrix view renders the cross-product as a handling reference. localStorage; everything stays in your browser."
      headerExtra={
        <p className="text-xs text-muted font-mono">
          Pairs with{' '}
          <Link to="/dfir/dlp-scan" className="text-brand-600 dark:text-brand-400 hover:underline">
            Sensitive Data Detector
          </Link>{' '}
          (find PII / secrets in content) and the{' '}
          <Link to="/dfir/grc" className="text-brand-600 dark:text-brand-400 hover:underline">
            GRC hub
          </Link>{' '}
          (NIST PR.DS / ISO 27001 A.5.12 / ISO 42001 A.7).
        </p>
      }
      maxWidthClass="max-w-6xl"
    >
      {/* Distribution */}
      <section className="grid gap-2 sm:grid-cols-4 mb-6">
        {TIERS.map((t) => (
          <div key={t} className={`rounded border px-3 py-2 ${TIER_STYLES[t]}`}>
            <div className="text-xs font-mono uppercase tracking-wider opacity-80">{TIER_LABELS[t]}</div>
            <div className="text-2xl font-display font-bold">{dist[t]}</div>
            <div className="text-micro font-mono opacity-70">
              {total === 0 ? '-' : `${Math.round((dist[t] / total) * 100)}%`}
            </div>
          </div>
        ))}
      </section>

      {/* Tabs + actions */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div className="flex gap-2">
          <TabBtn active={tab === 'policies'} onClick={() => setTab('policies')}>
            Tier policies
          </TabBtn>
          <TabBtn active={tab === 'inventory'} onClick={() => setTab('inventory')}>
            Inventory ({total})
          </TabBtn>
          <TabBtn active={tab === 'matrix'} onClick={() => setTab('matrix')}>
            Matrix
          </TabBtn>
        </div>
        <div className="flex gap-2">
          <button
            onClick={addDataset}
            className="text-sm font-mono px-3 py-1.5 rounded border border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300 hover:border-brand-500 inline-flex items-center gap-1.5 transition-colors"
          >
            <Plus size={13} /> Add dataset
          </button>
          <button
            onClick={exportMd}
            className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1.5 transition-colors"
          >
            <Download size={13} /> Export markdown
          </button>
          <button
            onClick={reset}
            className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw size={13} /> Reset
          </button>
        </div>
      </div>

      {/* ── Tier Policies ── */}
      {tab === 'policies' && (
        <div className="space-y-3">
          {TIERS.map((t) => {
            const p = state.policies[t];
            return (
              <div key={t} className="surface-card p-4">
                <div className="flex flex-wrap items-baseline gap-2 mb-2">
                  <span
                    className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${TIER_STYLES[t]}`}
                  >
                    {TIER_LABELS[t]}
                  </span>
                  <h3 className="font-display font-semibold text-heading">{p.description}</h3>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Field label="Access policy">
                    <textarea
                      value={p.access}
                      onChange={(e) => updatePolicy(t, { access: e.target.value })}
                      rows={2}
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    />
                  </Field>
                  <Field label="Examples (comma-separated)">
                    <input
                      type="text"
                      value={p.examples.join(', ')}
                      onChange={(e) =>
                        updatePolicy(t, {
                          examples: e.target.value
                            .split(',')
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    />
                  </Field>
                  <Field label="Encryption at rest">
                    <select
                      value={p.encryptionAtRest}
                      onChange={(e) =>
                        updatePolicy(t, { encryptionAtRest: e.target.value as TierPolicy['encryptionAtRest'] })
                      }
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="optional">optional</option>
                      <option value="required">required</option>
                      <option value="required-customer-key">required (customer-managed key)</option>
                    </select>
                  </Field>
                  <Field label="Encryption in transit">
                    <select
                      value={p.encryptionInTransit}
                      onChange={(e) =>
                        updatePolicy(t, { encryptionInTransit: e.target.value as TierPolicy['encryptionInTransit'] })
                      }
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="optional">optional</option>
                      <option value="required">required</option>
                    </select>
                  </Field>
                  <Field label="Retention (months, or 'indefinite')">
                    <input
                      type="text"
                      value={String(p.retentionMonths)}
                      onChange={(e) => {
                        const v = e.target.value.trim();
                        updatePolicy(t, { retentionMonths: v === 'indefinite' ? 'indefinite' : Number(v) || 0 });
                      }}
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    />
                  </Field>
                  <Field label="External sharing">
                    <select
                      value={p.externalSharing}
                      onChange={(e) =>
                        updatePolicy(t, { externalSharing: e.target.value as TierPolicy['externalSharing'] })
                      }
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="allowed">allowed</option>
                      <option value="allowed-with-approval">allowed-with-approval</option>
                      <option value="denied">denied</option>
                    </select>
                  </Field>
                  <Field label="Audit logging">
                    <select
                      value={p.auditLogging}
                      onChange={(e) => updatePolicy(t, { auditLogging: e.target.value as TierPolicy['auditLogging'] })}
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="recommended">recommended</option>
                      <option value="required">required</option>
                    </select>
                  </Field>
                  <Field label="Geo restriction">
                    <select
                      value={p.geoRestriction}
                      onChange={(e) =>
                        updatePolicy(t, { geoRestriction: e.target.value as TierPolicy['geoRestriction'] })
                      }
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="none">none</option>
                      <option value="region-locked">region-locked</option>
                    </select>
                  </Field>
                  <Field label="DLP enforcement">
                    <select
                      value={p.dlp}
                      onChange={(e) => updatePolicy(t, { dlp: e.target.value as TierPolicy['dlp'] })}
                      className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                    >
                      <option value="monitor-only">monitor-only</option>
                      <option value="warn-and-allow">warn-and-allow</option>
                      <option value="block">block</option>
                    </select>
                  </Field>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Inventory ── */}
      {tab === 'inventory' && (
        <div className="space-y-3">
          {state.datasets.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line-2 p-8 text-center text-sm font-mono text-muted">
              No datasets yet. Click <strong>Add dataset</strong> to start an inventory.
            </div>
          ) : (
            state.datasets.map((d) => {
              const isOpen = expanded === d.id;
              return (
                <div key={d.id} className="surface-card">
                  <button
                    onClick={() => setExpanded(isOpen ? null : d.id)}
                    className="w-full flex items-center gap-3 text-left px-4 py-3 hover:bg-surface-200 dark:hover:bg-surface-300/40"
                  >
                    <span className="flex-1 min-w-0">
                      <span className="block font-display font-semibold text-heading truncate">
                        {d.name || '(unnamed)'}
                      </span>
                      <span className="block text-xs font-mono text-muted truncate">
                        {d.type} · {d.owner || 'no owner'}
                        {d.storage ? ` · ${d.storage}` : ''}
                      </span>
                    </span>
                    <span
                      className={`flex-none text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${TIER_STYLES[d.tier]}`}
                    >
                      {TIER_LABELS[d.tier]}
                    </span>
                    {isOpen ? (
                      <ChevronDown size={16} className="flex-none text-muted" />
                    ) : (
                      <ChevronRight size={16} className="flex-none text-muted" />
                    )}
                  </button>
                  {isOpen && (
                    <div className="border-t border-line-1 px-4 py-3 space-y-3">
                      <div className="grid gap-3 sm:grid-cols-2">
                        <Field label="Name">
                          <input
                            type="text"
                            value={d.name}
                            onChange={(e) => updateDataset(d.id, { name: e.target.value })}
                            placeholder="prod-customers-db"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                        <Field label="Type">
                          <select
                            value={d.type}
                            onChange={(e) => updateDataset(d.id, { type: e.target.value as DatasetType })}
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          >
                            {DATASET_TYPES.map((t) => (
                              <option key={t.id} value={t.id}>
                                {t.label}
                              </option>
                            ))}
                          </select>
                        </Field>
                        <Field label="Classification tier">
                          <div className="flex flex-wrap gap-1.5">
                            {TIERS.map((t) => (
                              <button
                                key={t}
                                onClick={() => updateDataset(d.id, { tier: t })}
                                className={`text-xs font-mono px-2 py-1 rounded border ${
                                  d.tier === t
                                    ? TIER_STYLES[t]
                                    : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
                                }`}
                              >
                                {TIER_LABELS[t]}
                              </button>
                            ))}
                          </div>
                        </Field>
                        <Field label="Owner (a real human)">
                          <input
                            type="text"
                            value={d.owner}
                            onChange={(e) => updateDataset(d.id, { owner: e.target.value })}
                            placeholder="alice@team - name + escalation"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                        <Field label="Storage location">
                          <input
                            type="text"
                            value={d.storage}
                            onChange={(e) => updateDataset(d.id, { storage: e.target.value })}
                            placeholder="aws/eu-west-1/rds/prod-customers"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                        <Field label="Region / data residency">
                          <input
                            type="text"
                            value={d.region}
                            onChange={(e) => updateDataset(d.id, { region: e.target.value })}
                            placeholder="EU only"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                        <Field label="Volume">
                          <input
                            type="text"
                            value={d.volume}
                            onChange={(e) => updateDataset(d.id, { volume: e.target.value })}
                            placeholder="~120 GB · 4M rows"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                        <Field label="Contents">
                          <input
                            type="text"
                            value={d.contents}
                            onChange={(e) => updateDataset(d.id, { contents: e.target.value })}
                            placeholder="customer profiles · billing addresses · phone numbers"
                            className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                          />
                        </Field>
                      </div>
                      <Field label="Notes">
                        <textarea
                          value={d.notes}
                          onChange={(e) => updateDataset(d.id, { notes: e.target.value })}
                          rows={2}
                          className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs"
                        />
                      </Field>
                      <div className="flex justify-end">
                        <button
                          onClick={() => removeDataset(d.id)}
                          className="text-xs font-mono px-2 py-1 rounded border border-rose-300 dark:border-rose-900/40 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 inline-flex items-center gap-1"
                        >
                          <Trash2 size={11} /> Delete
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Matrix ── */}
      {tab === 'matrix' && (
        <div className="overflow-x-auto surface-card">
          <table className="w-full text-xs font-mono">
            <thead className="bg-surface-200 text-left">
              <tr>
                <th scope="col" className="px-3 py-2 text-micro uppercase tracking-wider text-muted">
                  Handling rule
                </th>
                {TIERS.map((t) => (
                  <th
                    key={t}
                    scope="col"
                    className={`px-3 py-2 text-micro uppercase tracking-wider border-l border-line-1 ${TIER_STYLES[t]}`}
                  >
                    {TIER_LABELS[t]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(
                [
                  ['Encryption at rest', 'encryptionAtRest'],
                  ['Encryption in transit', 'encryptionInTransit'],
                  ['Access', 'access'],
                  ['Retention (months)', 'retentionMonths'],
                  ['External sharing', 'externalSharing'],
                  ['Audit logging', 'auditLogging'],
                  ['Geographic restriction', 'geoRestriction'],
                  ['DLP enforcement', 'dlp'],
                ] as Array<[string, keyof TierPolicy]>
              ).map(([label, key]) => (
                <tr key={key} className="border-t border-line-1">
                  <td className="px-3 py-2 text-body font-bold">{label}</td>
                  {TIERS.map((t) => (
                    <td key={t} className="px-3 py-2 border-l border-line-1 text-body align-top">
                      {String(state.policies[t][key])}
                    </td>
                  ))}
                </tr>
              ))}
              <tr className="border-t border-line-1">
                <td className="px-3 py-2 text-body font-bold">Datasets in tier</td>
                {TIERS.map((t) => (
                  <td key={t} className="px-3 py-2 border-l border-line-1 text-body align-top">
                    {dist[t]}
                  </td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      )}

      <section className="mt-8 surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">References</h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          <li>
            <a
              href="https://csrc.nist.gov/glossary/term/data_classification"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              NIST glossary - Data Classification
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <Link
              to="/threatintel/wiki/data-classification"
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              Wiki - Data classification primer
            </Link>
          </li>
          <li>
            <Link
              to="/threatintel/wiki/dlp-architectures"
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              Wiki - DLP architectures
            </Link>
          </li>
        </ul>
      </section>
    </DataPageLayout>
  );
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <button
      onClick={onClick}
      className={`text-sm font-mono px-3 py-1.5 rounded border transition-colors ${
        active
          ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
          : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
      }`}
    >
      {children}
    </button>
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
