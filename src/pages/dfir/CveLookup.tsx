import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { SkeletonCard } from '../../components/ui/Skeleton';
import { sanitizeAiHtml } from '../../lib/sanitize-html';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { BookText, Bug, ExternalLink, FileCode, Gauge, Loader2, Copy, Check, ChevronDown } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';
import { Input } from '../../components/ui/Input';
import { prioritise, TIER_LABELS, TIER_STYLES, TIER_BARS } from '../../lib/dfir/cve-priority';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { SEVERITY_TONE, type Severity } from '../../components/severity';

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

interface CvssData {
  version: '3.1' | '3.0' | '2.0';
  base_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  vector: string;
}

interface KevData {
  in_kev: boolean;
  date_added?: string;
  vulnerability_name?: string;
  required_action?: string;
  due_date?: string;
  /** True when CISA flags it as used in known ransomware campaigns. */
  known_ransomware?: boolean;
}

interface EpssData {
  score: number;
  percentile: number;
  date: string;
}

interface ActorLink {
  slug: string;
  confidence: number;
  sources: string[];
}

interface CveLookupResult {
  cve_id: string;
  published?: string;
  last_modified?: string;
  description?: string;
  cvss?: CvssData;
  cwe?: string[];
  references?: Array<{ url: string; tags?: string[] }>;
  affected_products?: string[];
  kev: KevData;
  epss?: EpssData;
  actors?: string[];
  actor_links?: ActorLink[];
  vulncheck?: { cve: string; exploited: boolean; records: number; reported: string[] };
}

const ACTOR_LINK_SOURCE_LABEL: Record<string, string> = {
  cisa_kev: 'CISA KEV text',
  nvd: 'NVD description',
  otx: 'OTX pulse',
  feed: 'feed mention',
};

// NVD/CVSS severity strings are uppercase ('CRITICAL'|'HIGH'|'MEDIUM'|'LOW');
// map them onto the canonical Severity union for SEVERITY_TONE lookup.
function toSeverity(s?: string): Severity {
  switch (s?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    default:
      return 'low';
  }
}

export default function CveLookup(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = (searchParams.get('cve') ?? searchParams.get('id') ?? searchParams.get('q') ?? '').toUpperCase();
  const [input, setInput] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CveLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refTagFilter, setRefTagFilter] = useState<Set<string>>(new Set());
  const autoFetched = useRef(false);

  const [explainText, setExplainText] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [ruleText, setRuleText] = useState<string | null>(null);
  const [ruleName, setRuleName] = useState<string | null>(null);
  const [ruleLoading, setRuleLoading] = useState(false);
  const [ruleFormat, setRuleFormat] = useState<'kql' | 'sigma' | 'yara'>('kql');
  const [copied, setCopied] = useState<'explain' | 'rule' | null>(null);

  const explainCve = async () => {
    if (!result) return;
    setExplainLoading(true);
    setExplainText(null);
    try {
      const res = await fetch('/api/v1/copilot/investigate', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: result.cve_id }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as { narrative: string };
      const safe = await sanitizeAiHtml(data.narrative);
      setExplainText(safe);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    } finally {
      setExplainLoading(false);
    }
  };

  const generateRule = async () => {
    if (!result) return;
    setRuleLoading(true);
    setRuleText(null);
    setRuleName(null);
    try {
      const res = await fetch('/api/v1/ioc/rule', {
        method: 'POST',
        signal: AbortSignal.timeout(30_000),
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ indicator: result.cve_id, format: ruleFormat }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as { rule_name: string; rule_text: string };
      setRuleName(data.rule_name);
      setRuleText(data.rule_text);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    } finally {
      setRuleLoading(false);
    }
  };

  const valid = CVE_RE.test(input.trim());
  const canSubmit = valid && !loading;

  const runLookup = async (q: string) => {
    const id = q.trim().toUpperCase();
    if (!CVE_RE.test(id)) return;
    setLoading(true);
    setResult(null);
    setError(null);
    setSearchParams({ cve: id }, { replace: true });
    try {
      const r = await fetch(`/api/v1/cve/search?id=${encodeURIComponent(id)}`);
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        let msg = `HTTP ${r.status}`;
        try {
          const parsed = JSON.parse(body) as { message?: string };
          msg = parsed.message ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* use default */
        }
        throw new Error(msg);
      }
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult((await r.json()) as CveLookupResult);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'lookup failed'));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    void runLookup(input);
  };

  useEffect(() => {
    if (autoFetched.current) return;
    if (initialQuery && CVE_RE.test(initialQuery)) {
      autoFetched.current = true;
      void runLookup(initialQuery);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Bug size={28} />}
      title="CVE Lookup"
      description="Query NVD for CVE details. Get CVSS score, EPSS exploit likelihood, CISA KEV status, and references."
      maxWidthClass="max-w-4xl"
    >
      <form onSubmit={onSubmit} className="mb-10">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="CVE-2021-44228"
              aria-label="CVE ID to look up"
              className="focus-visible:ring-2 focus-visible:ring-brand-500/40"
            />
          </div>
          <button
            type="submit"
            disabled={!canSubmit}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <BookText size={16} className="inline mr-2" />
            Lookup
          </button>
        </div>
        {input && !valid && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">
            Enter a valid CVE ID (e.g. CVE-2024-12345)
          </p>
        )}
      </form>
      {/* New: link to enhanced threatintel.dk-style CVE detail page */}
      <div className="mb-6 rounded-xl border border-sky-200 dark:border-sky-800 bg-sky-50/60 dark:bg-sky-900/20 p-3 flex items-center justify-between">
        <span className="text-xs font-mono text-sky-700 dark:text-sky-300">
          New: Enhanced CVE detail with Risk, Exploitability, Timeline & STIX export (threatintel.dk style)
        </span>
        <Link
          to={
            input && CVE_RE.test(input.trim())
              ? `/threatintel/cve/${encodeURIComponent(input.trim().toUpperCase())}`
              : '/threatintel/live-feed'
          }
          className="text-xs font-mono font-bold text-sky-700 dark:text-sky-300 hover:underline inline-flex items-center gap-1"
        >
          Open detail <ExternalLink size={12} />
        </Link>
      </div>

      {loading && (
        <div className="space-y-4" role="status" aria-label="Querying NVD">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      )}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          {/* Header */}
          <section className="surface-card p-6">
            <div className="flex flex-wrap items-start gap-3 mb-3">
              <h2 className="font-display font-bold text-2xl font-mono">{result.cve_id}</h2>
              {result.kev.in_kev && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-300 border border-rose-300 dark:border-rose-700">
                  CISA KEV
                </span>
              )}
              {result.kev.in_kev && result.kev.known_ransomware && (
                <span
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-300 border border-amber-400 dark:border-amber-700"
                  title="CISA has tied this CVE to a known ransomware campaign - top remediation priority"
                >
                  Ransomware
                </span>
              )}
              {result.vulncheck?.exploited && (
                <span
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-fuchsia-100 text-fuchsia-900 dark:bg-fuchsia-900/40 dark:text-fuchsia-300 border border-fuchsia-400 dark:border-fuchsia-700"
                  title={`VulnCheck reports real-world exploitation / initial-access intel (${result.vulncheck.records} record(s))${result.vulncheck.reported.length ? ` · ${result.vulncheck.reported.join(', ')}` : ''}`}
                >
                  VulnCheck: Exploited
                </span>
              )}
              {result.cvss && (
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider border ${SEVERITY_TONE[toSeverity(result.cvss.severity)]}`}
                >
                  {result.cvss.severity} {result.cvss.base_score}
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-4 font-mono text-xs text-muted">
              {result.published && (
                <span>
                  Published: <span className="text-body">{result.published.slice(0, 10)}</span>
                </span>
              )}
              {result.last_modified && (
                <span>
                  Modified: <span className="text-body">{result.last_modified.slice(0, 10)}</span>
                </span>
              )}
            </div>
          </section>

          {/* Patch priority - combined CVSS + EPSS + KEV */}
          {(() => {
            if (!result.cvss && !result.epss && !result.kev) return null;
            const p = prioritise({ cvss: result.cvss, epss: result.epss, kev: result.kev });
            const total = p.contributions.cvss + p.contributions.epss + p.contributions.kev;
            return (
              <section className="surface-card p-6">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                  <h3 className="font-display font-semibold text-lg inline-flex items-center gap-2">
                    <Gauge size={18} className="text-brand-600 dark:text-brand-400" /> Patch priority
                  </h3>
                  <span
                    className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${TIER_STYLES[p.tier]}`}
                  >
                    {TIER_LABELS[p.tier]} · {p.score}/100
                  </span>
                </div>

                <div className="h-2 rounded bg-track overflow-hidden mb-3">
                  <div
                    className={`h-full transition-all ${TIER_BARS[p.tier]}`}
                    style={{ width: `${Math.max(2, p.score)}%` }}
                  />
                </div>

                <p className="text-sm font-mono text-muted mb-4">
                  Combined signal across CVSS severity, EPSS exploit probability, and CISA KEV listing. SLA suggestion:{' '}
                  <strong className="text-heading">{p.sla}</strong>.
                </p>

                {/* Per-signal contribution bar */}
                {total > 0 && (
                  <div className="mb-4">
                    <div className="flex h-3 rounded overflow-hidden border border-line-1">
                      {p.contributions.cvss > 0 && (
                        <div
                          className="bg-amber-500"
                          style={{ width: `${(p.contributions.cvss / 100) * 100}%` }}
                          title={`CVSS contribution: ${p.contributions.cvss}`}
                        />
                      )}
                      {p.contributions.epss > 0 && (
                        <div
                          className="bg-orange-500"
                          style={{ width: `${(p.contributions.epss / 100) * 100}%` }}
                          title={`EPSS contribution: ${p.contributions.epss}`}
                        />
                      )}
                      {p.contributions.kev > 0 && (
                        <div
                          className="bg-rose-500"
                          style={{ width: `${(p.contributions.kev / 100) * 100}%` }}
                          title={`KEV contribution: ${p.contributions.kev}`}
                        />
                      )}
                      <div className="bg-slate-300 dark:bg-surface-300" style={{ flex: 1 }} />
                    </div>
                    <div className="flex flex-wrap gap-3 mt-1.5 text-micro font-mono text-muted">
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2 h-2 bg-amber-500 rounded" /> CVSS · {p.contributions.cvss}
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2 h-2 bg-orange-500 rounded" /> EPSS · {p.contributions.epss}
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2 h-2 bg-rose-500 rounded" /> KEV · {p.contributions.kev}
                      </span>
                    </div>
                  </div>
                )}

                <ul className="space-y-1 text-sm font-mono text-body">
                  {p.rationale.map((r, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-muted select-none">›</span>
                      <span
                        dangerouslySetInnerHTML={{
                          __html: r
                            // Escape any HTML in the upstream rationale string
                            // before pattern-replacing the markdown bold.
                            // KEV due-dates and similar fields flow in from
                            // CISA/NVD upstream and shouldn't be trusted as
                            // pre-escaped HTML.
                            .replace(/&/g, '&amp;')
                            .replace(/</g, '&lt;')
                            .replace(/>/g, '&gt;')
                            .replace(/"/g, '&quot;')
                            .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-heading">$1</strong>'),
                        }}
                      />
                    </li>
                  ))}
                </ul>

                <div className="mt-4 flex">
                  <CopyButton
                    value={`${result.cve_id} - ${TIER_LABELS[p.tier]} (${p.score}/100, ${p.sla}).\n${p.rationale.map((r) => '- ' + r.replace(/\*\*/g, '')).join('\n')}`}
                  />
                  <span className="ml-2 self-center text-mini font-mono text-muted">Copy ticket-ready rationale</span>
                </div>
              </section>
            );
          })()}

          {/* AI Actions */}
          <section className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={explainCve}
              disabled={explainLoading}
              className="inline-flex items-center gap-1.5 px-4 py-2 surface-card/40 shadow-e1 text-sm font-medium text-body hover:border-brand-500/40 transition-colors disabled:opacity-50"
            >
              {explainLoading ? <Loader2 size={14} className="animate-spin" /> : <ChevronDown size={14} />}
              AI explain
            </button>

            <div className="flex items-center gap-1.5">
              {(['kql', 'sigma', 'yara'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setRuleFormat(f)}
                  className={`px-3 py-2 rounded-xl text-xs font-mono border transition-colors ${
                    ruleFormat === f
                      ? 'border-brand-500/60 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                      : 'border-line-1 text-muted hover:border-slate-300 dark:hover:border-line-1'
                  }`}
                >
                  {f.toUpperCase()}
                </button>
              ))}
              <button
                type="button"
                onClick={generateRule}
                disabled={ruleLoading}
                className="inline-flex items-center gap-1.5 px-4 py-2 surface-card/40 shadow-e1 text-sm font-medium text-body hover:border-brand-500/40 transition-colors disabled:opacity-50"
              >
                {ruleLoading ? <Loader2 size={14} className="animate-spin" /> : <FileCode size={14} />}
                Generate rule
              </button>
            </div>
          </section>

          {explainText && (
            <section className="surface-card p-4 animate-fade-in-up">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-muted">AI Analysis</h3>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(explainText);
                    setCopied('explain');
                    setTimeout(() => setCopied(null), 2000);
                  }}
                  className="text-xs font-mono text-muted hover:text-muted dark:hover:text-inverted"
                >
                  {copied === 'explain' ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                </button>
              </div>
              <div className="text-sm text-body leading-relaxed prose prose-sm dark:prose-invert max-w-none">
                <div dangerouslySetInnerHTML={{ __html: explainText }} />
              </div>
            </section>
          )}

          {ruleText && (
            <section className="surface-card animate-fade-in-up">
              <div className="flex items-center justify-between p-3 border-b border-line-1">
                <div className="flex items-center gap-2">
                  <FileCode size={14} className="text-brand-600 dark:text-brand-400" />
                  <span className="text-sm font-mono font-semibold text-body">{ruleName}</span>
                  <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                    {ruleFormat.toUpperCase()}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(ruleText);
                    setCopied('rule');
                    setTimeout(() => setCopied(null), 2000);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono text-muted hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                >
                  {copied === 'rule' ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                  {copied === 'rule' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="p-4 overflow-x-auto text-xs font-mono text-heading leading-relaxed whitespace-pre max-h-96 overflow-y-auto">
                {ruleText}
              </pre>
            </section>
          )}

          {/* Description */}
          {result.description && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">Description</h3>
              <p className="text-body leading-relaxed">{result.description}</p>
            </section>
          )}

          {/* CVSS */}
          {result.cvss && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-4">CVSS {result.cvss.version}</h3>
              <div className="flex items-center gap-6">
                <div className="text-center">
                  <div className="text-3xl sm:text-4xl font-display font-bold">{result.cvss.base_score}</div>
                  <div className="text-xs font-mono text-muted">/ 10</div>
                </div>
                <div>
                  <span
                    className={`inline-block px-3 py-1 rounded-full text-sm font-bold border ${SEVERITY_TONE[toSeverity(result.cvss.severity)]}`}
                  >
                    {result.cvss.severity}
                  </span>
                  <div className="flex items-center mt-2 font-mono text-xs text-muted break-all">
                    <span>{result.cvss.vector}</span>
                    <CopyButton value={result.cvss.vector} />
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* EPSS */}
          {result.epss && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">EPSS, Exploit Prediction</h3>
              <div className="flex gap-8 font-mono">
                <div>
                  <div className="text-2xl font-bold">{(result.epss.score * 100).toFixed(2)}%</div>
                  <div className="text-xs text-muted">exploit probability</div>
                </div>
                <div>
                  <div className="text-2xl font-bold">{(result.epss.percentile * 100).toFixed(1)}th</div>
                  <div className="text-xs text-muted">percentile</div>
                </div>
                <div>
                  <div className="text-sm text-muted">{result.epss.date}</div>
                  <div className="text-xs text-muted">data date</div>
                </div>
              </div>
            </section>
          )}

          {/* KEV Details */}
          {result.kev.in_kev && (
            <section
              className={`rounded-xl border p-6 ${
                result.kev.known_ransomware
                  ? 'border-amber-400 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/15'
                  : 'border-rose-200 dark:border-rose-900/40 bg-rose-50 dark:bg-rose-900/10'
              }`}
            >
              <h3
                className={`font-display font-semibold text-lg mb-3 ${
                  result.kev.known_ransomware
                    ? 'text-amber-900 dark:text-amber-300'
                    : 'text-rose-800 dark:text-rose-300'
                }`}
              >
                CISA KEV - Known Exploited
                {result.kev.known_ransomware && (
                  <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-amber-200 dark:bg-amber-800/40 text-amber-900 dark:text-amber-200 border border-amber-400 dark:border-amber-700">
                    Ransomware
                  </span>
                )}
              </h3>
              {result.kev.known_ransomware && (
                <p className="text-xs font-mono text-amber-900 dark:text-amber-300 mb-3 leading-relaxed">
                  CISA has linked this CVE to known ransomware campaigns. Treat as top-of-queue remediation - patch
                  immediately and hunt for active exploitation indicators in your environment.
                </p>
              )}
              <div className="grid sm:grid-cols-3 gap-4 font-mono text-sm">
                {result.kev.date_added && (
                  <div>
                    <div className="text-xs text-muted mb-1">Date Added</div>
                    <div className="text-heading">{result.kev.date_added}</div>
                  </div>
                )}
                {result.kev.due_date && (
                  <div>
                    <div className="text-xs text-muted mb-1">Due Date</div>
                    <div className="text-heading">{result.kev.due_date}</div>
                  </div>
                )}
                {result.kev.required_action && (
                  <div className="sm:col-span-3">
                    <div className="text-xs text-muted mb-1">Required Action</div>
                    <div className="text-heading">{result.kev.required_action}</div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Actor attribution panel - surfaces evidence-scored CVE→actor links */}
          {result.actor_links && result.actor_links.length > 0 && (
            <section className="rounded-xl border border-violet-200 dark:border-violet-900/40 bg-violet-50/40 dark:bg-violet-900/10 p-6">
              <h3 className="font-display font-semibold text-lg mb-3 text-violet-900 dark:text-violet-300">
                Threat-actor attribution
              </h3>
              <p className="text-mini font-mono text-violet-800/70 dark:text-violet-300/70 mb-3 leading-relaxed">
                Multi-signal CVE → actor evidence chain. Curated mapping (confidence 100) is anchored to public CISA /
                vendor PSIRT attribution; heuristic signals (NVD description, CISA KEV text, OTX pulse) add independent
                corroboration with their own confidence weight. Sources are listed so analysts can pressure-test
                attribution rather than trust it blindly.
              </p>
              <ul className="space-y-2">
                {[...result.actor_links]
                  .sort((a, b) => b.confidence - a.confidence)
                  .map((link) => {
                    const conf = link.confidence;
                    const tier = conf >= 90 ? 'high' : conf >= 60 ? 'medium' : 'low';
                    // Attribution CONFIDENCE is a trust scale, NOT severity - high
                    // confidence reads as good (emerald), not a warning. Do not route
                    // this through SEVERITY_TONE (where high = orange).
                    const tierColor =
                      conf >= 90
                        ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                        : conf >= 60
                          ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                          : 'border-slate-400/40 bg-slate-400/10 text-muted';
                    return (
                      <li
                        key={link.slug}
                        className="rounded-xl border border-line-1 bg-surface-100/80 dark:bg-surface-200/60 p-3"
                      >
                        <div className="flex items-start justify-between gap-2 mb-1.5 flex-wrap">
                          <Link
                            to={`/threatintel/actors/${encodeURIComponent(link.slug)}`}
                            className="font-mono font-semibold text-sm text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1"
                          >
                            {link.slug}
                            <ExternalLink size={10} />
                          </Link>
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`text-micro font-mono px-1.5 py-0.5 rounded border ${tierColor}`}
                              title={`confidence score ${conf}/100`}
                            >
                              {tier} · {conf}
                            </span>
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 text-micro font-mono">
                          <span className="text-muted">evidence:</span>
                          {link.sources.map((s) => (
                            <span
                              key={s}
                              className="rounded border border-line-2 bg-surface-200 px-1.5 py-0.5 text-body"
                              title={`Attribution sourced from ${ACTOR_LINK_SOURCE_LABEL[s] ?? s}`}
                            >
                              {ACTOR_LINK_SOURCE_LABEL[s] ?? s}
                            </span>
                          ))}
                        </div>
                      </li>
                    );
                  })}
              </ul>
              <details className="mt-3">
                <summary className="cursor-pointer text-micro font-mono text-violet-700/70 dark:text-violet-300/60 hover:text-violet-900 dark:hover:text-violet-200">
                  Confidence scale
                </summary>
                <ul className="mt-2 text-micro font-mono text-violet-800/70 dark:text-violet-300/70 leading-relaxed space-y-0.5 list-disc list-inside">
                  <li>
                    <b>100 - curated:</b> human-vetted attribution from CISA advisory, vendor PSIRT, or IR report.
                  </li>
                  <li>
                    <b>70 - OTX:</b> AlienVault pulse tagged both the actor and the CVE.
                  </li>
                  <li>
                    <b>65 - NVD:</b> NVD description text names a known actor.
                  </li>
                  <li>
                    <b>60 - CISA KEV:</b> KEV vulnerability name / required-action text mentions an actor.
                  </li>
                  <li>
                    <b>35 - feed:</b> news/blog feed item mentioned both the actor and the CVE.
                  </li>
                </ul>
              </details>
            </section>
          )}

          {/* CWEs */}
          {result.cwe && result.cwe.length > 0 && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">Weaknesses (CWE)</h3>
              <div className="flex flex-wrap gap-2">
                {result.cwe.map((id) => {
                  const num = id.replace('CWE-', '');
                  return (
                    <a
                      key={id}
                      href={`https://cwe.mitre.org/data/definitions/${num}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2 py-1 rounded border border-line-1 text-xs font-mono text-brand-600 dark:text-brand-400 hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                    >
                      {id}
                      <ExternalLink size={10} />
                    </a>
                  );
                })}
              </div>
            </section>
          )}

          {/* Affected Products */}
          {result.affected_products && result.affected_products.length > 0 && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">Affected Products</h3>
              <ul className="space-y-1">
                {result.affected_products.map((cpe) => (
                  <li key={cpe} className="font-mono text-xs text-muted break-all">
                    {cpe}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* References - filterable by tag (Vendor Advisory / Exploit / Patch / Mitigation / Third Party Advisory). */}
          {result.references &&
            result.references.length > 0 &&
            (() => {
              const allTags = new Set<string>();
              for (const r of result.references) for (const t of r.tags ?? []) allTags.add(t);
              const tagList = [...allTags].sort();
              const filtered = result.references.filter((r) => {
                if (refTagFilter.size === 0) return true;
                return (r.tags ?? []).some((t) => refTagFilter.has(t));
              });
              const toggleTag = (t: string) =>
                setRefTagFilter((prev) => {
                  const next = new Set(prev);
                  if (next.has(t)) next.delete(t);
                  else next.add(t);
                  return next;
                });
              return (
                <section className="surface-card p-6">
                  <div className="flex items-baseline justify-between gap-2 mb-3">
                    <h3 className="font-display font-semibold text-lg">
                      References{' '}
                      <span className="text-muted text-sm font-normal">
                        ({filtered.length} of {result.references.length})
                      </span>
                    </h3>
                    {refTagFilter.size > 0 && (
                      <button
                        type="button"
                        onClick={() => setRefTagFilter(new Set())}
                        className="text-mini font-mono text-brand-600 dark:text-brand-400 hover:underline"
                      >
                        clear filter
                      </button>
                    )}
                  </div>
                  {tagList.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mb-3">
                      <span className="text-mini font-mono text-muted mr-1 self-center">filter by tag:</span>
                      {tagList.map((t) => {
                        const active = refTagFilter.has(t);
                        return (
                          <button
                            key={t}
                            type="button"
                            onClick={() => toggleTag(t)}
                            className={`text-micro font-mono px-2 py-0.5 rounded border ${
                              active
                                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                                : 'border-slate-300 dark:border-line-1 text-slate-500'
                            }`}
                          >
                            {t}
                          </button>
                        );
                      })}
                    </div>
                  )}
                  <ul className="space-y-2">
                    {filtered.map(({ url, tags }) => (
                      <li key={url} className="flex items-start gap-2">
                        <a
                          href={sanitizeUrl(url) || undefined}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-brand-600 dark:text-brand-400 hover:underline break-all font-mono flex items-center gap-1 transition-colors"
                        >
                          {url}
                          <ExternalLink size={11} className="shrink-0" />
                        </a>
                        {tags && tags.length > 0 && (
                          <span className="text-xs font-mono text-muted shrink-0">[{tags.join(', ')}]</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              );
            })()}
        </div>
      )}
      <RelatedWikiArticles />
    </DataPageLayout>
  );
}
