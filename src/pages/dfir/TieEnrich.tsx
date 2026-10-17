import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef, useCallback, useEffect } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ReportView, type ReportActionCard } from '../../components/dfir/ReportView';
import { Shield, Search, Globe, Link, FileDigit, AlertTriangle, Download, Loader2, Terminal } from 'lucide-react';
import { downloadBlob } from '../../lib/download';

type IocType = 'ip' | 'hash' | 'domain' | 'url';

interface GeoData {
  country?: string;
  city?: string;
  org?: string;
  asn?: string;
  is_vpn?: boolean;
  [key: string]: unknown;
}

interface EnrichResult {
  ioc: string;
  iocType: IocType;
  reputation?: Record<string, unknown>;
  geo?: GeoData;
  phantomcandle?: Record<string, unknown>;
  domainIntel?: Record<string, unknown>;
  phishingAnalysis?: Record<string, unknown>;
  malpedia?: Record<string, unknown>;
  mitre?: Record<string, unknown>;
  diagnostics: Array<{ provider: string; status: string; ms: number; error?: string }>;
  report?: string;
  status?: string;
  modelUsed?: string;
  qa?: { qualityScore: number; flaggedClaims: string[]; missingFacts: string[] };
  actionCard?: ReportActionCard;
  steps?: Array<{ stepNumber: number; plan: string; status: string; observation?: string }>;
}

function JsonBlock({ label, data }: { label: string; data: unknown }) {
  if (!data) return null;
  return (
    <details className="group">
      <summary className="cursor-pointer text-sm font-medium text-cyan-700 dark:text-cyan-400 hover:text-cyan-600">
        {label} <span className="text-xs opacity-50">(click to expand)</span>
      </summary>
      <pre className="mt-1 max-h-96 overflow-auto rounded border border-line-1 bg-surface-200 p-3 text-xs">
        {JSON.stringify(data, null, 2)}
      </pre>
    </details>
  );
}

function DiagnosticBadge({ d }: { d: { provider: string; status: string; ms: number; error?: string } }) {
  const color =
    d.status === 'ok'
      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-300'
      : d.status === 'skipped'
        ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300'
        : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${color}`}
      title={d.error}
    >
      {d.provider}
      <span className="opacity-60">{d.ms}ms</span>
    </span>
  );
}

function downloadFile(name: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  downloadBlob(blob, name);
}

const IOC_LABELS: Record<IocType, string> = { ip: 'IP Address', hash: 'File Hash', domain: 'Domain', url: 'URL' };
const IOC_ICONS: Record<IocType, typeof Search> = { ip: Globe, hash: FileDigit, domain: Link, url: AlertTriangle };

export default function TieEnrich() {
  const [ioc, setIoc] = useState('');
  const [iocType, setIocType] = useState<IocType>('ip');
  const [deep, setDeep] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EnrichResult | null>(null);
  const [error, setError] = useState('');

  const submitRef = useRef<AbortController | null>(null);
  const evtSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    return () => {
      evtSourceRef.current?.close();
      evtSourceRef.current = null;
    };
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!ioc.trim()) return;
      submitRef.current?.abort();
      const ctrl = new AbortController();
      submitRef.current = ctrl;
      setLoading(true);
      setError('');
      setResult(null);

      try {
        const res = await fetch('/api/v1/tie/enrich', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ ioc: ioc.trim(), ioc_type: iocType, deep }),
          signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30_000)]),
        });
        if (ctrl.signal.aborted) return;
        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: 'Unknown error' }));
          throw new Error(err.error || `HTTP ${res.status}`);
        }
        const data = await res.json();

        if (deep && data.id) {
          setResult({ ioc: ioc.trim(), iocType, status: 'running', diagnostics: [] });
          evtSourceRef.current?.close();
          const evtSource = new EventSource(`/api/v1/tie/enrich/${data.id}/stream`);
          evtSourceRef.current = evtSource;
          evtSource.onmessage = (ev) => {
            try {
              const msg = JSON.parse(ev.data);
              if (msg.type === 'done') {
                setResult({
                  ioc: ioc.trim(),
                  iocType,
                  status: 'done',
                  report: msg.report,
                  modelUsed: msg.modelUsed,
                  qa: msg.qa,
                  actionCard: msg.actionCard,
                  diagnostics: [],
                });
                evtSource.close();
              } else if (msg.type === 'error') {
                setError(msg.error);
                evtSource.close();
              }
            } catch (_catchErr) {
              logCatch(_catchErr);
            }
          };
          evtSource.onerror = () => {
            setError('Stream connection lost');
            evtSource.close();
          };
          setLoading(false);
          return;
        }

        setResult(data);
      } catch (err) {
        logCatch(err);
        if (ctrl.signal.aborted) return;
        setError(errMessage(err));
      } finally {
        if (!ctrl.signal.aborted) setLoading(false);
      }
    },
    [ioc, iocType, deep]
  );

  const handleDownload = useCallback(
    (format: 'md' | 'stix') => {
      if (!result?.report) return;
      if (format === 'md') {
        downloadFile(`enrich-${result.ioc.slice(0, 20)}.md`, result.report, 'text/markdown');
      } else {
        const stix = {
          type: 'bundle',
          id: `bundle--${crypto.randomUUID()}`,
          spec_version: '2.1',
          objects: [
            {
              type: 'report',
              id: `report--${crypto.randomUUID()}`,
              name: `Enrichment: ${result.ioc}`,
              created: new Date().toISOString(),
              object_refs: [],
            },
          ],
        };
        downloadFile(`enrich-${result.ioc.slice(0, 20)}.stix.json`, JSON.stringify(stix, null, 2), 'application/json');
      }
    },
    [result]
  );

  const Icon = IOC_ICONS[iocType];

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Shield size={28} />}
      title="Threat Intel Enrichment Agent"
      description="Enrich any IOC using 30+ providers. Fast mode for quick checks, deep autonomous mode for full investigation with structured report."
      maxWidthClass="max-w-4xl"
    >
      <form onSubmit={handleSubmit} className="mb-6 space-y-4">
        <div className="flex flex-wrap gap-3">
          <select
            value={iocType}
            onChange={(e) => setIocType(e.target.value as IocType)}
            className="rounded-xl border border-line-2 bg-surface-100 px-3 py-2 text-sm"
          >
            {(['ip', 'hash', 'domain', 'url'] as IocType[]).map((t) => (
              <option key={t} value={t}>
                {IOC_LABELS[t]}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={ioc}
            onChange={(e) => setIoc(e.target.value)}
            placeholder={
              iocType === 'ip'
                ? '8.8.8.8'
                : iocType === 'hash'
                  ? 'sha256 hash...'
                  : iocType === 'domain'
                    ? 'example.com'
                    : 'https://...'
            }
            className="flex-1 min-w-[200px] rounded-xl border border-line-2 bg-surface-100 px-3 py-2 text-sm"
          />
          <button
            type="submit"
            disabled={loading || !ioc.trim()}
            className="flex items-center gap-2 rounded-xl bg-cyan-600 px-4 py-2 text-sm font-medium text-on-fill hover:bg-cyan-700 disabled:opacity-50 transition-colors"
          >
            <Search size={16} />
            {loading ? 'Enriching...' : deep ? 'Deep Enrich' : 'Enrich'}
          </button>
        </div>
        <label className="flex items-center gap-2 text-xs text-muted">
          <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} className="rounded" />
          Deep analysis (autonomous investigator - runs 3-5 steps, generates structured report with QA verification)
        </label>
      </form>

      {loading && !deep && (
        <div className="flex items-center gap-3 rounded-xl border border-line-1 bg-surface-200 p-4">
          <Loader2 size={16} className="animate-spin text-cyan-600" />
          <span className="text-sm text-muted">Running enrichment across providers...</span>
        </div>
      )}

      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-400">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Deep analysis: structured report with ReportView */}
      {result && result.status === 'done' && result.report && (
        <section className="surface-card p-6 mb-6 animate-fade-in-up">
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            <Shield size={16} className="text-emerald-600" />
            <h2 className="text-lg font-display font-bold">Investigation Report</h2>
            {result.modelUsed && (
              <span className="text-micro font-mono px-2 py-0.5 rounded border border-line-1 text-muted">
                {result.modelUsed}
              </span>
            )}
            {result.qa && (
              <span
                className={`text-micro font-mono px-2 py-0.5 rounded border ${
                  result.qa.qualityScore >= 80
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600'
                    : result.qa.qualityScore >= 60
                      ? 'border-amber-500/40 bg-amber-500/10 text-amber-600'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-600'
                }`}
              >
                QA: {result.qa.qualityScore}/100
              </span>
            )}
            <div className="ml-auto flex gap-2">
              <button
                onClick={() => handleDownload('md')}
                className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded border border-line-1 hover:border-cyan-500/40 text-muted"
              >
                <Download size={12} /> .md
              </button>
              <button
                onClick={() => handleDownload('stix')}
                className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded border border-emerald-500/40 bg-emerald-500/5 hover:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
              >
                <Download size={12} /> STIX 2.1
              </button>
            </div>
          </div>

          {/* QA Details */}
          {result.qa && (result.qa.flaggedClaims.length > 0 || result.qa.missingFacts.length > 0) && (
            <details className="mb-4 rounded border border-amber-500/30 bg-amber-500/5 p-3">
              <summary className="text-xs font-mono font-bold text-amber-700 dark:text-amber-300 cursor-pointer">
                QA Notes ({result.qa.flaggedClaims.length} flagged, {result.qa.missingFacts.length} added)
              </summary>
              {result.qa.flaggedClaims.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {result.qa.flaggedClaims.map((c, i) => (
                    <li key={i} className="text-micro font-mono text-amber-700 dark:text-amber-300">
                      • {c}
                    </li>
                  ))}
                </ul>
              )}
              {result.qa.missingFacts.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {result.qa.missingFacts.map((f, i) => (
                    <li key={i} className="text-micro font-mono text-amber-700 dark:text-amber-300">
                      + {f}
                    </li>
                  ))}
                </ul>
              )}
            </details>
          )}

          <ReportView report={result.report} actionCard={result.actionCard} query={result.ioc} />
        </section>
      )}

      {/* Deep analysis: running */}
      {result && result.status === 'running' && (
        <div className="rounded-xl border border-cyan-200 bg-cyan-50 p-4 dark:border-cyan-800 dark:bg-cyan-900/20">
          <div className="flex items-center gap-2 text-sm text-cyan-700 dark:text-cyan-300">
            <Loader2 size={16} className="animate-spin" />
            Investigation in progress...
          </div>
          {result.steps && result.steps.length > 0 && (
            <div className="mt-3 space-y-1">
              {result.steps.map((s) => (
                <div key={s.stepNumber} className="flex items-center gap-2 text-xs font-mono text-muted">
                  <Terminal size={12} />
                  <span className={s.status === 'done' ? 'text-emerald-600' : 'text-cyan-600'}>
                    Step {s.stepNumber}
                  </span>
                  <span className="truncate">{s.plan?.slice(0, 60)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Fast enrichment: structured results */}
      {result && !result.report && result.status !== 'running' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Icon size={20} className="text-cyan-600" />
            <span className="font-mono text-sm text-heading">{result.ioc}</span>
            <span className="text-xs text-muted">{IOC_LABELS[result.iocType]}</span>
          </div>

          {result.diagnostics.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {result.diagnostics.map((d, i) => (
                <DiagnosticBadge key={i} d={d} />
              ))}
            </div>
          )}

          {result.geo && (
            <div className="grid grid-cols-2 gap-2 rounded-xl border border-line-1 bg-surface-200/50 p-3 text-sm">
              {result.geo.country && (
                <div>
                  <span className="font-medium">Country:</span> {result.geo.country}
                </div>
              )}
              {result.geo.city && (
                <div>
                  <span className="font-medium">City:</span> {result.geo.city}
                </div>
              )}
              {result.geo.org && (
                <div className="col-span-2">
                  <span className="font-medium">Org:</span> {result.geo.org}
                </div>
              )}
              {result.geo.asn && (
                <div>
                  <span className="font-medium">ASN:</span> {result.geo.asn}
                </div>
              )}
              {result.geo.is_vpn !== undefined && (
                <div>
                  <span className="font-medium">VPN/Proxy:</span> {String(result.geo.is_vpn)}
                </div>
              )}
            </div>
          )}

          {result.phantomcandle ? <JsonBlock label="PhantomCandle Attribution" data={result.phantomcandle} /> : null}
          {result.domainIntel ? <JsonBlock label="Domain Intelligence" data={result.domainIntel} /> : null}
          {result.phishingAnalysis ? <JsonBlock label="Phishing URL Analysis" data={result.phishingAnalysis} /> : null}
          {result.malpedia ? <JsonBlock label="Malpedia Lookup" data={result.malpedia} /> : null}
          {result.reputation ? <JsonBlock label="IOC Reputation (30+ providers)" data={result.reputation} /> : null}
          {result.mitre ? <JsonBlock label="MITRE ATT&CK Mapping" data={result.mitre} /> : null}
        </div>
      )}
    </DataPageLayout>
  );
}
