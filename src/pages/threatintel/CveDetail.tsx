import { useEffect, useState } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Copy, Check, ExternalLink, AlertTriangle, Shield, Search, Download, Bug } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * SSVC-V decision, computed server-side from KEV / EPSS / CVSS / exploit
 * status (`api/src/lib/ssvc-v.ts`). This is the "is it actually being
 * exploited" axis, kept deliberately separate from severity — a low-CVSS CVE
 * with active exploitation is a different problem from a critical CVE nobody
 * is touching.
 */
interface SsvcVerdict {
  decision: 'act' | 'prioritise' | 'track' | 'watch';
  exploitation: 'none' | 'poc' | 'active';
  automatable: 'yes' | 'no';
  exposure: 'small' | 'controlled' | 'open' | 'none';
  missionImpact: 'degraded' | 'crippled' | 'failure';
  rationale: string;
}

interface CveDetailData {
  cve_id: string;
  description: string;
  published?: string;
  last_modified?: string;
  severity?: string;
  cvss?: { base_score: number; severity: string; vector?: string };
  cwe?: string[];
  references?: string[];
  affected_products?: string[];
  products?: string[];
  kev?: { in_kev: boolean; date_added?: string; due_date?: string; required_action?: string };
  epss?: { score: number; percentile: number };
  /** Public proof-of-concept repositories (poc-in-github). */
  poc?: { count: number; urls: string[] };
  /** GitHub Security Advisory, when one exists for this CVE. */
  ghsa?: { id: string; severity?: string; url: string };
  /** Exploitation verdict. Absent only if the server could not compute it. */
  ssvc?: SsvcVerdict;
  /** CVE-ID of a related MITRE ATT&CK technique, only when NVD asserts one. */
  mitre?: Array<{ id: string; name: string; tactic?: string }>;
  iocs?: Array<{ type: string; value: string }>;
}

export default function CveDetail(): JSX.Element {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const cveId = id || searchParams.get('id') || searchParams.get('cve') || '';
  const [data, setData] = useState<CveDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (!cveId) {
      setLoading(false);
      setError('No CVE ID provided');
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/v1/cve/search?id=${encodeURIComponent(cveId)}`, {
          signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (cancelled) return;
        const raw = json?.result || json || {};
        // Map only what the server actually returned. Nothing here is
        // defaulted to a plausible-looking value: this page previously
        // synthesised a Sigma rule name, a T1190 MITRE mapping, a fake
        // timeline and a hit count for every CVE missing that data, which on a
        // threat-intel surface is misinformation an analyst can act on.
        // Absent data renders as absent.
        const mapped: CveDetailData = {
          cve_id: raw.cve_id || raw.cveId || cveId.toUpperCase(),
          description: raw.description || '',
          published: raw.published || raw.publishedAt,
          last_modified: raw.last_modified,
          severity: raw?.cvss?.severity || raw.severity,
          cvss: raw.cvss,
          cwe: raw.cwe || [],
          references: raw.references || [],
          affected_products: raw.affected_products || raw.affectedProducts || [],
          products: raw.products || [],
          kev: raw.kev,
          epss: raw.epss,
          poc: raw.poc,
          ghsa: raw.ghsa,
          ssvc: raw.ssvc,
          mitre: raw.mitre,
          iocs: raw.iocs,
        };
        setData(mapped);
      } catch (e) {
        if (cancelled) return;
        setError(errMessage(e, 'Failed to load CVE'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [cveId]);

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 1500);
  };

  if (loading) {
    return (
      <DataPageLayout
        backTo="/threatintel/cves/cves"
        icon={<Bug size={28} />}
        title={cveId || 'CVE Detail'}
        description="Loading CVE detail..."
        maxWidthClass="max-w-7xl"
      >
        <div className="animate-pulse space-y-4">
          <div className="h-24 rounded-xl bg-surface-300" />
          <div className="h-64 rounded-xl bg-surface-300" />
        </div>
      </DataPageLayout>
    );
  }

  if (!data) {
    return (
      <DataPageLayout
        backTo="/threatintel/cves/cves"
        icon={<Bug size={28} />}
        title="CVE not found"
        description="The requested CVE could not be loaded."
        maxWidthClass="max-w-7xl"
        error={error || 'Not found'}
      >
        <div className="p-10 text-center">
          <AlertTriangle size={32} className="mx-auto text-amber-500 mb-3" />
          <div className="font-bold text-heading">CVE not found</div>
          <p className="text-sm text-muted mt-1">{error}</p>
        </div>
      </DataPageLayout>
    );
  }

  return (
    <DataPageLayout
      backTo="/threatintel/cves/cves"
      icon={<Bug size={28} />}
      title={`${data.cve_id} — ${data.description.slice(0, 80)}...`}
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-sky-700 dark:text-sky-300">
            Severity: {data.severity}
          </span>
          <span className="px-2 py-1 rounded bg-surface-100 dark:bg-surface-200 border border-slate-700 text-xs font-mono text-muted">
            {data.epss ? `EPSS ${(data.epss.score * 100).toFixed(1)}%` : 'EPSS n/a'}
          </span>
          {data.ssvc && (
            <span
              className={`px-2 py-1 rounded text-xs font-mono font-bold ${
                data.ssvc.exploitation === 'active'
                  ? 'bg-rose-500 text-on-fill'
                  : data.ssvc.exploitation === 'poc'
                    ? 'bg-amber-500 text-on-fill'
                    : 'bg-surface-300 border border-line-1 text-muted'
              }`}
              title={data.ssvc.rationale}
            >
              Exploitation: {data.ssvc.exploitation}
            </span>
          )}
          {data.kev?.in_kev && (
            <span className="px-2 py-1 rounded bg-rose-500 text-on-fill text-xs font-mono font-bold">CISA KEV</span>
          )}
        </span>
      }
      maxWidthClass="max-w-7xl"
      headerExtra={
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => copy(data.cve_id)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-line-1 bg-surface-100 text-xs font-mono hover:bg-surface-200"
          >
            {copied === data.cve_id ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />} Copy ID
          </button>
          <Link
            to={`/dfir/cve?cve=${encodeURIComponent(data.cve_id)}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-100 text-white dark:text-heading text-xs font-mono"
          >
            <Search size={12} /> Open in DFIR CVE
          </Link>
          <button
            onClick={() => window.open(`/api/v1/live-feed/export?id=${data.cve_id}&format=stix`, '_blank')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-line-1 bg-surface-100 text-xs font-mono"
          >
            <Download size={12} /> STIX 2.1
          </button>
        </div>
      }
    >
      <div className="grid grid-cols-1 xl:grid-cols-[1.15fr_0.85fr] gap-6">
        <div className="space-y-4">
          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-sky-600 dark:text-sky-400 mb-2">DESCRIPTION</div>
            <p className="text-sm leading-relaxed text-body">{data.description}</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-orange-600 mb-2">RISK ASSESSMENT</div>
              {data.cvss ? (
                <div className="p-2 rounded bg-surface-200 border border-line-1 font-mono text-xs">
                  CVSS {data.cvss.base_score} ({data.cvss.severity}) {data.cvss.vector && `· ${data.cvss.vector}`}
                </div>
              ) : (
                <p className="text-xs text-muted">No CVSS vector from NVD.</p>
              )}
              {data.epss && (
                <div className="mt-2 text-xs font-mono text-muted">
                  EPSS {Math.round(data.epss.score * 100)}% · percentile {data.epss.percentile}
                </div>
              )}
              {data.last_modified && (
                <div className="mt-2 text-xs font-mono text-muted">Last modified {data.last_modified}</div>
              )}
            </div>
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-sky-600 mb-2">EXPLOITATION</div>
              {data.ssvc ? (
                <>
                  <p className="text-xs leading-relaxed text-body">{data.ssvc.rationale}</p>
                  <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs font-mono">
                    <dt className="text-muted">Decision</dt>
                    <dd className="font-bold uppercase">{data.ssvc.decision}</dd>
                    <dt className="text-muted">Exploitation</dt>
                    <dd className="font-bold uppercase">{data.ssvc.exploitation}</dd>
                    <dt className="text-muted">Automatable</dt>
                    <dd className="uppercase">{data.ssvc.automatable}</dd>
                    <dt className="text-muted">Impact</dt>
                    <dd className="uppercase">{data.ssvc.missionImpact}</dd>
                  </dl>
                </>
              ) : (
                <p className="text-xs text-muted">No exploitation verdict computed.</p>
              )}
              {data.poc && (
                <div className="mt-2 text-xs text-amber-700 dark:text-amber-300">
                  {data.poc.count} public PoC {data.poc.count === 1 ? 'repository' : 'repositories'}
                  {data.poc.urls?.length > 0 && (
                    <a
                      href={data.poc.urls[0]}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-1 underline inline-flex items-center gap-0.5"
                    >
                      view <ExternalLink size={10} />
                    </a>
                  )}
                </div>
              )}
              {data.ghsa && (
                <a
                  href={data.ghsa.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-1 block text-xs text-sky-700 dark:text-sky-300 underline inline-flex items-center gap-1"
                >
                  {data.ghsa.id}
                  {data.ghsa.severity && ` · ${data.ghsa.severity}`} <ExternalLink size={10} />
                </a>
              )}
              {data.kev?.in_kev && (
                <div className="mt-2 text-xs font-bold text-rose-600">
                  Known exploited — CISA KEV {data.kev.date_added || ''}
                </div>
              )}
            </div>
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-2">AFFECTED PRODUCTS</div>
            <div className="flex flex-wrap gap-1.5">
              {(data.affected_products && data.affected_products.length ? data.affected_products : ['Unknown'])
                .slice(0, 12)
                .map((p) => (
                  <span
                    key={p}
                    className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted"
                  >
                    {p}
                  </span>
                ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-emerald-600 mb-2">REMEDIATION</div>
              {data.kev?.required_action ? (
                <p className="text-xs leading-relaxed text-body">{data.kev.required_action}</p>
              ) : (
                <p className="text-xs leading-relaxed text-muted">
                  No vendor remediation text in our sources. Follow the NVD references below, or check the linked
                  advisory for the affected product&apos;s fix.
                </p>
              )}
              {data.kev?.due_date && (
                <p className="mt-2 text-xs font-mono text-rose-600">BOD due {data.kev.due_date}</p>
              )}
            </div>
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-amber-600 mb-2">DETECTION</div>
              {/* No CVE-linked signature corpus yet. This panel previously
                  rendered a Sigma rule name built from the CVE ID, which does
                  not exist anywhere — it read like a real rule a responder
                  could deploy. Stating the gap is more useful than inventing a
                  rule; see the detection-wiki rule browser for real content. */}
              <p className="text-xs leading-relaxed text-muted">
                No signature mapped to this CVE. Detection coverage for the affected technology is browsable in
                Detection Wiki, and YARA/Sigma rule validation lives under the rule validator.
              </p>
              {data.cvss?.vector && <p className="mt-2 text-xs font-mono text-muted">Vector {data.cvss.vector}</p>}
            </div>
          </div>

          {data.cwe && data.cwe.length > 0 && (
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-muted mb-2">CWE</div>
              <div className="flex flex-wrap gap-1.5">
                {data.cwe.map((c) => (
                  <a
                    key={c}
                    href={`https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300 text-xs font-mono hover:bg-amber-500/20"
                  >
                    {c}
                  </a>
                ))}
              </div>
            </div>
          )}

          {data.references && data.references.length > 0 && (
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-muted mb-2">REFERENCES</div>
              <ul className="space-y-1">
                {data.references.slice(0, 8).map((r) => (
                  <li key={r}>
                    <a
                      href={r}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-sky-600 hover:underline break-all inline-flex items-center gap-1"
                    >
                      {r} <ExternalLink size={10} />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="bg-surface-200/50 p-4 sm:p-5 space-y-4 rounded-xl border border-line-1 h-fit">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono tracking-widest font-bold text-heading flex items-center gap-2">
              <Shield size={14} className="text-sky-500" /> IOCs
            </span>
            <span className="text-xs font-mono px-2 py-1 rounded bg-surface-100 border border-line-1 text-muted">
              {data.iocs?.length ?? 0} indicators
            </span>
          </div>
          <div className="space-y-2">
            {(data.iocs || []).map((ioc) => (
              <div key={ioc.value} className="rounded-lg bg-surface-100 border border-line-1 p-3">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-surface-300 border border-line-1 text-muted">
                    {ioc.type}
                  </span>
                  <button
                    onClick={() => copy(ioc.value)}
                    className="ml-auto p-1 rounded hover:bg-surface-300 dark:hover:bg-surface-200"
                  >
                    {copied === ioc.value ? (
                      <Check size={12} className="text-emerald-500" />
                    ) : (
                      <Copy size={12} className="text-muted" />
                    )}
                  </button>
                </div>
                <div className="font-mono text-sm text-heading break-all mt-2">{ioc.value}</div>
              </div>
            ))}
          </div>

          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-2">MITRE ATT&CK</div>
            <div className="flex flex-wrap gap-1.5">
              {(data.mitre || []).map((m) => (
                <Link
                  key={m.id}
                  to={`/threatintel/wiki/mitre?id=${m.id}`}
                  className="px-2 py-1 rounded bg-violet-500/10 border border-violet-500/20 text-violet-700 dark:text-violet-300 text-xs font-mono hover:bg-violet-500/20"
                >
                  {m.id} {m.name}
                </Link>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Link
              to={`/threatintel/cves/cves?q=${encodeURIComponent(data.cve_id)}`}
              className="h-9 rounded-lg bg-sky-500/10 border border-sky-500/20 text-xs font-mono text-sky-600 hover:bg-sky-500/20 grid place-items-center"
            >
              Search Intel
            </Link>
            <button
              onClick={() => {
                const all = (data.iocs || []).map((i) => i.value).join('\n');
                copy(all);
              }}
              className="h-9 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted hover:text-heading"
            >
              Copy IOCs
            </button>
            <button
              onClick={() => window.open(`/api/v1/live-feed/export?id=${data.cve_id}&format=stix`, '_blank')}
              className="h-9 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted hover:text-heading inline-flex items-center justify-center gap-1"
            >
              <Download size={12} /> STIX 2.1
            </button>
            <button
              onClick={() => window.open(`/api/v1/live-feed/export?id=${data.cve_id}&format=json`, '_blank')}
              className="h-9 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-muted hover:text-heading"
            >
              JSON
            </button>
          </div>

          <div className="pt-3 border-t border-line-1">
            <div className="font-mono text-xs tracking-widest text-muted mb-2">QUICK ACTIONS</div>
            <div className="grid grid-cols-2 gap-2">
              <Link
                to={`/dfir/cve?cve=${encodeURIComponent(data.cve_id)}`}
                className="h-9 rounded-lg bg-surface-100 text-white dark:text-heading text-xs font-mono grid place-items-center"
              >
                DFIR CVE
              </Link>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${data.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="h-9 rounded-lg border border-line-1 bg-surface-100 text-xs font-mono text-muted grid place-items-center"
              >
                NVD <ExternalLink size={12} className="ml-1" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </DataPageLayout>
  );
}
