import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import HexBrainLink from '../../components/HexBrainLink';
import { Copy, Check, ExternalLink, AlertTriangle, Shield, Search, Download, Bug, Brain, Star } from 'lucide-react';
import { errMessage } from '../../lib/log';
import VulnSocialBrief, { type PlatformCve } from '../../components/threatintel/VulnSocialBrief';

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

/** HexBrain enrichment (`api/src/lib/hexbrain.ts`), present only when the
 *  HEXBRAIN_API_KEY secret is configured and the lookup succeeded. */
interface HexBrainIntel {
  title?: string;
  cwe?: string;
  severity?: string;
  exploited_in_wild?: boolean;
  kev_date?: string;
  ransomware?: boolean;
  /** 0..1 predicted likelihood of exploitation in the next 30 days. */
  likelihood_30d?: number;
  /** 0..100, "N% of all CVEs are less likely". */
  likelihood_percentile?: number;
  exploit_count?: number;
  exploits?: Array<{ kind?: string; name?: string; url?: string; stars?: number; date?: string; desc?: string }>;
  nuclei_command?: string;
  positive_when?: string;
  impact?: string;
  fix?: string;
  references?: string[];
  bounty_reports?: Array<{ id?: number; title?: string; program?: string; url?: string }>;
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
  hexbrain?: HexBrainIntel;
  /** Consolidated plain-English verdict from api/src/lib/cve-verdict.ts. */
  verdict?: PlatformCve['verdict'];
}

export default function CveDetail(): JSX.Element {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const cveId = id || searchParams.get('id') || searchParams.get('cve') || '';
  const [data, setData] = useState<CveDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [view, setView] = useState<'decision' | 'platform'>('decision');

  // Scorisk is always a usable reference for a CVE, even when the NVD mirror
  // has no reference list for that id. Deduplicate so the same URL cannot
  // produce duplicate React keys when both sources carry it.
  const referenceRows = useMemo(() => {
    const primary = `https://scorisk.io/cve/${(data?.cve_id || cveId || '').toUpperCase()}`;
    const seen = new Set<string>();
    const rows: Array<{ url: string; host: string }> = [];
    for (const raw of [primary, ...(data?.references ?? [])]) {
      if (typeof raw !== 'string' || !raw.trim()) continue;
      const url = raw.trim();
      const key = url.replace(/\/+$/, '').toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      let host = 'reference';
      try {
        host = new URL(url).host;
      } catch {
        /* relative or malformed URL */
      }
      rows.push({ url, host });
      if (rows.length >= 9) break;
    }
    return rows;
  }, [data, cveId]);

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
          hexbrain: raw.hexbrain,
          verdict: raw.verdict,
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
        <div className="flex flex-wrap items-center gap-2">
          <div
            className="flex items-center gap-0.5 rounded-full border border-line-1 p-0.5"
            role="group"
            aria-label="CVE detail view"
          >
            {(
              [
                ['decision', 'Decision view'],
                ['platform', 'Platform view'],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setView(id)}
                aria-pressed={view === id}
                className={`rounded-full px-2.5 py-1 text-xs font-mono transition-colors ${view === id ? 'bg-surface-300 text-heading' : 'text-muted hover:text-heading'}`}
              >
                {label}
              </button>
            ))}
          </div>
          <button
            onClick={() => copy(data.cve_id)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-line-1 bg-surface-100 text-xs font-mono hover:bg-surface-200"
          >
            {copied === data.cve_id ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />} Copy ID
          </button>
          <Link
            to={`/dfir/cve?cve=${encodeURIComponent(data.cve_id)}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-100 text-heading text-xs font-mono"
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
      {view === 'decision' ? (
        <VulnSocialBrief cveId={data.cve_id} platform={data as PlatformCve} />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[1.15fr_0.85fr] gap-6">
          <div className="space-y-4">
            <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="font-mono text-[11px] tracking-widest text-sky-600 dark:text-sky-400 mb-2">
                DESCRIPTION
              </div>
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

            {data.hexbrain && (
              <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-mono text-[11px] tracking-widest text-orange-600 dark:text-orange-400 flex items-center gap-1.5">
                    <Brain size={12} /> HEXBRAIN
                  </div>
                  <HexBrainLink cve={data.cve_id} label="Full report" />
                </div>
                {data.hexbrain.exploited_in_wild && (
                  <div className="mb-2 text-xs font-bold text-rose-600 dark:text-rose-400">
                    Exploited in the wild
                    {data.hexbrain.kev_date && (
                      <span className="ml-1.5 font-mono font-normal">CISA KEV {data.hexbrain.kev_date}</span>
                    )}
                    {data.hexbrain.ransomware && <span className="ml-1.5 font-normal">· used by ransomware</span>}
                  </div>
                )}
                {data.hexbrain.likelihood_30d !== undefined && (
                  <div className="mb-2">
                    <div className="flex items-center justify-between text-xs font-mono mb-1">
                      <span className="text-muted">Likelihood of exploitation, next 30 days</span>
                      <span className="font-bold text-heading">{Math.round(data.hexbrain.likelihood_30d * 100)}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-surface-300 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          data.hexbrain.likelihood_30d >= 0.5
                            ? 'bg-rose-500'
                            : data.hexbrain.likelihood_30d >= 0.2
                              ? 'bg-amber-500'
                              : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.max(2, Math.round(data.hexbrain.likelihood_30d * 100))}%` }}
                      />
                    </div>
                    {data.hexbrain.likelihood_percentile !== undefined && (
                      <div className="mt-1 text-xs font-mono text-muted">
                        {Math.round(data.hexbrain.likelihood_percentile)}% of all tracked CVEs are less likely
                      </div>
                    )}
                  </div>
                )}
                {data.hexbrain.exploit_count !== undefined && (
                  <div className="text-xs font-mono text-amber-700 dark:text-amber-300">
                    {data.hexbrain.exploit_count} public exploit
                    {data.hexbrain.exploit_count === 1 ? '' : 's'} known
                  </div>
                )}
                {data.hexbrain.exploits && data.hexbrain.exploits.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {data.hexbrain.exploits.slice(0, 3).map((ex, i) => (
                      <li key={`${ex.url ?? ex.name ?? i}`} className="text-xs leading-relaxed">
                        {ex.url ? (
                          <a
                            href={ex.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sky-600 dark:text-sky-300 hover:underline break-all"
                          >
                            {ex.name || ex.url}
                          </a>
                        ) : (
                          <span className="text-body">{ex.name || ex.desc}</span>
                        )}
                        {ex.stars !== undefined && (
                          <span className="ml-1.5 text-muted inline-flex items-center gap-0.5">
                            <Star size={10} /> {ex.stars.toLocaleString()}
                          </span>
                        )}
                        {ex.date && <span className="ml-1.5 text-muted font-mono">{ex.date.slice(0, 10)}</span>}
                      </li>
                    ))}
                  </ul>
                )}
                {data.hexbrain.nuclei_command && (
                  <div className="mt-3">
                    <div className="font-mono text-[11px] tracking-widest text-muted mb-1">DETECTION CHECK</div>
                    <div className="flex items-center gap-2 rounded bg-surface-200 border border-line-1 px-2 py-1.5">
                      <code className="text-xs font-mono text-heading break-all flex-1">
                        {data.hexbrain.nuclei_command}
                      </code>
                      <button
                        onClick={() => copy(data.hexbrain!.nuclei_command!)}
                        className="p-1 rounded hover:bg-surface-300 dark:hover:bg-surface-200 shrink-0"
                        aria-label="Copy nuclei command"
                      >
                        {copied === data.hexbrain.nuclei_command ? (
                          <Check size={12} className="text-emerald-500" />
                        ) : (
                          <Copy size={12} className="text-muted" />
                        )}
                      </button>
                    </div>
                    {data.hexbrain.positive_when && (
                      <p className="mt-1 text-xs font-mono text-muted break-words">
                        Positive when: {data.hexbrain.positive_when.replace(/^Positive when:\s*/i, '')}
                      </p>
                    )}
                  </div>
                )}
                {data.hexbrain.impact && (
                  <p className="mt-2 text-xs leading-relaxed text-body">
                    <span className="font-bold">Impact: </span>
                    {data.hexbrain.impact}
                  </p>
                )}
                {data.hexbrain.fix && (
                  <p className="mt-1 text-xs leading-relaxed text-body">
                    <span className="font-bold">Fix: </span>
                    {data.hexbrain.fix}
                  </p>
                )}
                {data.hexbrain.bounty_reports && data.hexbrain.bounty_reports.length > 0 && (
                  <div className="mt-3">
                    <div className="font-mono text-[11px] tracking-widest text-muted mb-1">DISCLOSED REPORTS</div>
                    <ul className="space-y-1">
                      {data.hexbrain.bounty_reports.slice(0, 2).map((r) => (
                        <li key={r.id ?? r.url} className="text-xs leading-relaxed">
                          {r.url ? (
                            <a
                              href={r.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sky-600 dark:text-sky-300 hover:underline"
                            >
                              {r.title || r.program || r.url}
                            </a>
                          ) : (
                            <span className="text-body">{r.title || r.program}</span>
                          )}
                          {r.program && <span className="ml-1.5 text-muted font-mono">{r.program}</span>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

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

            {referenceRows.length > 0 && (
              <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
                <div className="font-mono text-[11px] tracking-widest text-muted mb-2">REFERENCES</div>
                <ul className="space-y-1.5">
                  {referenceRows.map(({ url, host }) => (
                    <li key={url}>
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={url}
                        className="text-xs font-mono text-sky-600 dark:text-sky-400 hover:underline inline-flex items-start gap-2"
                      >
                        <span className="shrink-0 text-muted">{host}</span>
                        <span className="break-all flex-1">{url}</span>
                        <ExternalLink size={10} className="shrink-0 mt-0.5" />
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
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <Link
                  to={`/dfir/cve?cve=${encodeURIComponent(data.cve_id)}`}
                  className="h-9 rounded-lg bg-surface-100 text-heading text-xs font-mono grid place-items-center"
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
                <a
                  href={`https://rdintel.com/cve/${data.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="h-9 rounded-lg border border-rose-500/30 bg-rose-500/10 text-xs font-mono text-rose-600 dark:text-rose-300 grid place-items-center"
                  title={`Open ${data.cve_id} on RD Intelligence: threat score, exploit signals, affected products`}
                >
                  RDIntel <ExternalLink size={12} className="ml-1" />
                </a>
                <a
                  href={`https://hexbrainai.com/cve/${data.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="h-9 rounded-lg border border-orange-500/30 bg-orange-500/10 text-xs font-mono text-orange-600 dark:text-orange-300 grid place-items-center"
                >
                  HexBrain <ExternalLink size={12} className="ml-1" />
                </a>
                <a
                  href={`https://scorisk.io/cve/${data.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="h-9 rounded-lg border border-sky-500/30 bg-sky-500/10 text-xs font-mono text-sky-600 dark:text-sky-300 grid place-items-center"
                  title={`Open ${data.cve_id} on Scorisk: CVE reference and enrichment notes`}
                >
                  Scorisk <ExternalLink size={12} className="ml-1" />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
