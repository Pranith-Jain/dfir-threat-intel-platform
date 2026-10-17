import { useState } from 'react';
import { api } from '../lib/api-client';
import { DataPageLayout } from '../components/DataPageLayout';
import { Button } from '../components/ui/Button';
import { Spinner } from '../components/ui/Spinner';
import { Bot, Search, AlertTriangle, Download, ChevronDown, ChevronRight } from 'lucide-react';
import { downloadBlob } from '../lib/download';
import { errMessage } from '../lib/log';

interface TierReason {
  rule: string;
  floor: number;
  rationale: string;
}

interface Finding {
  nhi_id: string;
  nhi_name: string;
  owasp_id: string;
  owasp_title: string;
  severity: string;
  evidence: string;
  remediation: string;
}

interface IdentityReport {
  id: string;
  name: string;
  type: string;
  tier: number;
  tier_label: string;
  risk_score: number;
  reasons: TierReason[];
  findings: Finding[];
}

interface ScanReport {
  summary: {
    total_identities: number;
    findings: number;
    orphaned: number;
    long_lived_secrets: number;
    tier_counts: Record<string, number>;
    type_counts: Record<string, number>;
    owasp_counts: Record<string, number>;
  };
  identities: IdentityReport[];
}

/** Mirrors examples/sample-inventory.json from github.com/rpmsft9/nhi-scan. */
const SAMPLE_INVENTORY = [
  {
    id: 'svc-payments-prod',
    name: 'payments-batch-runner',
    type: 'service_account',
    owner: 'payments-platform@bank.example',
    environment: 'prod',
    privilege: 'admin',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 410,
    last_used_days: 1,
    exposure: 'internal',
    scopes: ['payments:*'],
  },
  {
    id: 'key-legacy-etl',
    name: 'legacy-etl-api-key',
    type: 'api_key',
    owner: null,
    environment: 'prod',
    privilege: 'privileged',
    credential: 'api_key',
    secret_storage: 'plaintext',
    last_rotated_days: null,
    last_used_days: 220,
    exposure: 'internet',
    scopes: ['data:read', 'data:write'],
  },
  {
    id: 'agent-collections',
    name: 'collections-ai-agent',
    type: 'ai_agent',
    owner: 'cx-automation@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'env',
    last_rotated_days: 30,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['accounts:read', 'accounts:update', 'ledger:*'],
    autonomous: true,
  },
  {
    id: 'sp-analytics-vendor',
    name: 'analytics-vendor-connector',
    type: 'service_principal',
    owner: 'data-eng@bank.example',
    environment: 'prod',
    privilege: 'scoped',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 45,
    last_used_days: 3,
    exposure: 'external_partner',
    scopes: ['reports:read'],
    third_party: true,
  },
  {
    id: 'ci-deploy-token',
    name: 'github-actions-deployer',
    type: 'ci_cd_token',
    owner: 'devsecops@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 15,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['deploy:prod', 'deploy:nonprod'],
    shared_across_env: true,
    used_by: ['web-app', 'batch', 'mobile-bff'],
  },
  {
    id: 'wl-fraud-scoring',
    name: 'fraud-scoring-workload',
    type: 'workload_identity',
    owner: 'fraud-ml@bank.example',
    environment: 'prod',
    privilege: 'scoped',
    credential: 'federated',
    secret_storage: 'none',
    last_rotated_days: null,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['features:read'],
  },
  {
    id: 'pat-oncall-shared',
    name: 'oncall-shared-pat',
    type: 'pat',
    owner: 'sre@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'env',
    last_rotated_days: 200,
    last_used_days: 2,
    exposure: 'internal',
    scopes: ['repo', 'admin:org'],
    human_used: true,
  },
  {
    id: 'hook-sandbox-test',
    name: 'sandbox-webhook',
    type: 'webhook',
    owner: 'qa@bank.example',
    environment: 'sandbox',
    privilege: 'read_only',
    credential: 'short_lived_token',
    secret_storage: 'none',
    last_rotated_days: 5,
    last_used_days: 400,
    exposure: 'internal',
    scopes: ['events:read'],
  },
];

const TIER_STYLE: Record<number, string> = {
  1: 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  2: 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  3: 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  4: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  high: 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  info: 'border-slate-300 dark:border-line-1 text-muted',
};

function downloadFile(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  downloadBlob(blob, filename);
}

export default function NhiScan() {
  const [inventoryText, setInventoryText] = useState(() => JSON.stringify(SAMPLE_INVENTORY, null, 2));
  const [result, setResult] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [mdLoading, setMdLoading] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const runScan = async (format: 'json' | 'markdown' = 'json') => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(inventoryText);
    } catch (e) {
      setError(`Inventory is not valid JSON: ${errMessage(e)}`);
      return null;
    }
    setLoading(true);
    setError(null);
    setMarkdown(null);
    try {
      const res = await api.post<ScanReport | { format: string; markdown: string }>('/api/v1/nhi/scan', {
        inventory: parsed,
        format,
      });
      if (format === 'markdown' && res && typeof res === 'object' && 'markdown' in res) {
        setMarkdown((res as { markdown: string }).markdown);
      } else {
        setResult(res as ScanReport);
      }
      return res;
    } catch (err) {
      const msg = errMessage(err);
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    void runScan('json');
  };

  const handleDownloadMd = async () => {
    if (markdown) {
      downloadFile('nhi-risk-report.md', markdown, 'text/markdown');
      return;
    }
    setMdLoading(true);
    const res = await runScan('markdown');
    setMdLoading(false);
    if (res && typeof res === 'object' && 'markdown' in res) {
      downloadFile('nhi-risk-report.md', (res as { markdown: string }).markdown, 'text/markdown');
    }
  };

  const handleDownloadJson = () => {
    if (!result) return;
    downloadFile('nhi-risk-report.json', JSON.stringify(result, null, 2), 'application/json');
  };

  const toggleIdentity = (id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const summary = result?.summary;

  return (
    <DataPageLayout
      backTo="/dfir"
      backLabel="DFIR"
      icon={<Bot />}
      title="NHI Scanner — Non-Human Identity Risk"
      description={
        <span>
          Inventory and risk-tier your non-human &amp; agent identities (service accounts, API keys, OAuth apps, service
          principals, workload identities, CI/CD tokens, PATs, webhooks, secrets, AI agents) against the{' '}
          <a
            href="https://owasp.org/www-project-non-human-identities-top-10/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            OWASP NHI Top 10
          </a>
          . Deterministic floor-tier rules engine — the same inventory always produces the same tiers and findings, with
          a least-privilege remediation for every finding. No LLM is in the verdict path. Port of{' '}
          <a
            href="https://github.com/rpmsft9/nhi-scan"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            nhi-scan
          </a>{' '}
          (MIT).
        </span>
      }
    >
      <div className="space-y-6 max-w-4xl mx-auto">
        <section className="surface-card p-4">
          <form onSubmit={handleScan}>
            <div className="flex items-center justify-between mb-2">
              <label className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted">
                NHI Inventory (JSON)
              </label>
              <div className="flex gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setInventoryText(JSON.stringify(SAMPLE_INVENTORY, null, 2));
                    setResult(null);
                    setError(null);
                  }}
                  className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
                >
                  load sample
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInventoryText(
                      JSON.stringify(
                        [
                          { id: 'svc-REPLACE-ME', name: 'human-readable-name' },
                          {
                            id: 'svc-payments-prod',
                            name: 'payments-batch-runner',
                            type: 'service_account',
                            owner: 'team-or-person@example.com',
                            environment: 'prod',
                            privilege: 'privileged',
                            credential: 'static_secret',
                            secret_storage: 'vault',
                            last_rotated_days: 120,
                            last_used_days: 2,
                            exposure: 'internal',
                            scopes: ['payments:read', 'payments:write'],
                          },
                        ],
                        null,
                        2
                      )
                    );
                    setResult(null);
                    setError(null);
                  }}
                  className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
                >
                  load template
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInventoryText('');
                    setResult(null);
                    setError(null);
                  }}
                  className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
                >
                  clear
                </button>
              </div>
            </div>
            <textarea
              value={inventoryText}
              onChange={(e) => setInventoryText(e.target.value)}
              rows={12}
              spellCheck={false}
              placeholder='A JSON array of NHI records, or {"identities": [...]}. Only id and name are required per record — type, privilege, credential, secret_storage, last_rotated_days, last_used_days, exposure, scopes, autonomous, third_party, human_used, shared_across_env, used_by all fall back to safe defaults.'
              className="w-full p-3 bg-surface-200 border border-line-1 rounded font-mono text-xs leading-relaxed focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
            <div className="flex items-center justify-between mt-3">
              <p className="text-mini text-muted">
                Runs entirely locally &amp; deterministically — your inventory is never stored.
              </p>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  loading={mdLoading}
                  disabled={loading || !inventoryText.trim()}
                  onClick={() => void handleDownloadMd()}
                  icon={<Download size={14} />}
                >
                  markdown report
                </Button>
                <Button
                  type="submit"
                  variant="primary-brand"
                  size="sm"
                  loading={loading}
                  disabled={!inventoryText.trim()}
                  icon={<Search size={14} />}
                >
                  {loading ? 'scanning…' : 'scan inventory'}
                </Button>
              </div>
            </div>
          </form>
        </section>

        {loading && (
          <div className="flex items-center justify-center py-12 text-muted">
            <Spinner size="md" className="mr-3" />
            Assessing identities…
          </div>
        )}

        {error && !loading && (
          <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 flex items-center gap-3">
            <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
            <p className="text-sm font-mono text-rose-700 dark:text-rose-300">{error}</p>
          </div>
        )}

        {result && summary && !loading && (
          <div className="space-y-4">
            {/* Summary */}
            <section className="surface-card p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted">Summary</h2>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={handleDownloadJson}
                    icon={<Download size={14} />}
                  >
                    JSON
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => void handleDownloadMd()}
                    icon={<Download size={14} />}
                  >
                    Markdown
                  </Button>
                </div>
              </div>
              <div className="flex flex-wrap gap-6">
                <div>
                  <div className="text-2xl font-bold text-heading">{summary.total_identities}</div>
                  <div className="text-mini font-mono text-muted">identities</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-heading">{summary.findings}</div>
                  <div className="text-mini font-mono text-muted">findings</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-heading">{summary.orphaned}</div>
                  <div className="text-mini font-mono text-muted">orphaned</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-heading">{summary.long_lived_secrets}</div>
                  <div className="text-mini font-mono text-muted">long-lived secrets</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {[1, 2, 3, 4].map((t) => (
                  <span
                    key={t}
                    className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${TIER_STYLE[t] ?? ''}`}
                  >
                    tier {t} · {summary.tier_counts[`TIER_${t}`] ?? 0}
                  </span>
                ))}
              </div>
            </section>

            {/* OWASP counts */}
            {Object.keys(summary.owasp_counts).length > 0 && (
              <section className="surface-card p-4">
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted mb-3">
                  OWASP NHI Top 10 findings
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(summary.owasp_counts).map(([code, count]) => (
                    <div
                      key={code}
                      className="flex items-center justify-between text-sm py-1 border-b border-line-1 last:border-0"
                    >
                      <span className="font-mono text-heading">
                        {code}
                        <span className="text-muted ml-2 text-mini">{OWASP_TITLES[code] ?? ''}</span>
                      </span>
                      <span className="font-mono text-muted">{count}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Identities by risk */}
            <section className="space-y-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted">Identities by risk</h2>
              {result.identities.map((idn) => {
                const isOpen = expanded[idn.id] ?? false;
                return (
                  <div key={idn.id} className="surface-card p-4">
                    <button
                      type="button"
                      onClick={() => toggleIdentity(idn.id)}
                      className="w-full text-left flex items-start justify-between gap-3"
                    >
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${TIER_STYLE[idn.tier] ?? ''}`}
                          >
                            tier {idn.tier} · {idn.tier_label}
                          </span>
                          <span className="text-sm font-semibold text-heading">{idn.name}</span>
                          <span className="text-mini font-mono text-muted">({idn.type})</span>
                        </div>
                        <p className="text-mini font-mono text-muted mt-1">
                          score {idn.risk_score} · findings {idn.findings.length}
                        </p>
                        <p className="text-xs text-muted mt-1">Why this tier: {idn.reasons[0]?.rationale}</p>
                      </div>
                      {isOpen ? (
                        <ChevronDown size={16} className="text-muted flex-shrink-0 mt-1" />
                      ) : (
                        <ChevronRight size={16} className="text-muted flex-shrink-0 mt-1" />
                      )}
                    </button>

                    {isOpen && (
                      <div className="mt-3 border-t border-line-1 pt-3">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-mini font-mono text-muted mb-3">
                          <div>
                            <span className="block text-micro uppercase tracking-wider text-muted">matched rules</span>
                            <span className="text-heading">{idn.reasons.length}</span>
                          </div>
                          <div>
                            <span className="block text-micro uppercase tracking-wider text-muted">top rule</span>
                            <span className="text-heading">{idn.reasons[0]?.rule}</span>
                          </div>
                          <div>
                            <span className="block text-micro uppercase tracking-wider text-muted">OWASP findings</span>
                            <span className="text-heading">{idn.findings.length}</span>
                          </div>
                          <div>
                            <span className="block text-micro uppercase tracking-wider text-muted">risk score</span>
                            <span className="text-heading">{idn.risk_score}</span>
                          </div>
                        </div>

                        {idn.findings.length > 0 && (
                          <div className="space-y-2">
                            {idn.findings.map((f, i) => (
                              <div key={`${f.owasp_id}-${i}`} className="rounded-lg border border-line-1 p-3">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span
                                    className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.info}`}
                                  >
                                    {f.severity}
                                  </span>
                                  <span className="text-xs font-mono font-semibold text-heading">
                                    {f.owasp_id} {f.owasp_title}
                                  </span>
                                </div>
                                <p className="text-xs font-mono text-muted mt-1.5">{f.evidence}</p>
                                <p className="text-xs text-body mt-1">→ {f.remediation}</p>
                              </div>
                            ))}
                          </div>
                        )}
                        {idn.findings.length === 0 && (
                          <p className="text-xs text-emerald-600 dark:text-emerald-400 font-mono">no OWASP findings</p>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </section>
          </div>
        )}

        {markdown && !loading && (
          <section className="surface-card p-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.16em] text-muted">Markdown Report</h2>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void handleDownloadMd()}
                icon={<Download size={14} />}
              >
                download
              </Button>
            </div>
            <pre className="text-xs font-mono leading-relaxed whitespace-pre-wrap text-heading max-h-96 overflow-y-auto">
              {markdown}
            </pre>
          </section>
        )}

        <div className="text-center pt-6 pb-2 text-xs text-muted border-t border-line-1">
          Port of{' '}
          <a
            href="https://github.com/rpmsft9/nhi-scan"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            nhi-scan
          </a>{' '}
          (MIT) — mapped to the{' '}
          <a
            href="https://owasp.org/www-project-non-human-identities-top-10/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            OWASP NHI Top 10
          </a>
          . Deterministic, local, explainable — no LLM in the verdict path.
        </div>
      </div>
    </DataPageLayout>
  );
}

const OWASP_TITLES: Record<string, string> = {
  'NHI1:2025': 'Improper Offboarding',
  'NHI2:2025': 'Secret Leakage',
  'NHI3:2025': 'Vulnerable Third-Party NHI',
  'NHI4:2025': 'Insecure Authentication',
  'NHI5:2025': 'Overprivileged NHI',
  'NHI6:2025': 'Insecure Cloud Deployment Configurations',
  'NHI7:2025': 'Long-Lived Secrets',
  'NHI8:2025': 'Environment Isolation',
  'NHI9:2025': 'NHI Reuse',
  'NHI10:2025': 'Human Use of NHI',
};
