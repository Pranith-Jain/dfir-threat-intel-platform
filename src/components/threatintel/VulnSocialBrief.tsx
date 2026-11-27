/**
 * VulnSocial-style CVE decision view.
 *
 * Re-implements the information architecture REA-verified on
 * https://vulnsocial.com/cve/<id>: decision header, plain-English verdict,
 * at-a-glance telemetry, triage directive, multi-source CVSS, CWE, signal
 * velocity, categorized artifact links, affected software and researcher
 * signals. Data comes from this platform's mirrored VulnSocial facts plus the
 * existing CVE lookup — no upstream CSS, code or prose bodies are vendored.
 */
import { useMemo, useState, type JSX } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  ExternalLink,
  FileCode,
  GitBranch,
  Megaphone,
  ShieldAlert,
  Wrench,
} from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { relativeAgo } from '../../lib/relativeTime';

export interface PlatformCve {
  cve_id: string;
  description: string;
  published?: string;
  last_modified?: string;
  severity?: string;
  cvss?: { version?: string; base_score?: number; severity?: string; vector?: string };
  cwe?: unknown[];
  references?: Array<{ url?: string; name?: string; source?: string } | string>;
  kev?: { in_kev?: boolean; due_date?: string; required_action?: string };
  epss?: { score?: number; percentile?: number };
  poc?: { count?: number; urls?: string[] };
  verdict?: {
    urgency?: string;
    headline?: string;
    summary?: string;
    recommendation?: string;
    verdict?: string;
    sources?: Array<{ id: string; label: string; url?: string }>;
    signals?: Record<string, unknown>;
  };
}

interface VsBody {
  id: string;
  shareUrl: string;
  plainEnglish: string | null;
  vendors: string[];
  products: string[];
  versions: string[];
  totalMentions: number;
  totalDays: number;
  topClassification: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  cvssSource: string | null;
  inKev: boolean;
  kevDueDate: string | null;
  activeExploitation: boolean;
  exploitCode: boolean;
  poc: boolean;
  patch: boolean;
  sla: string | null;
  urgency: string | null;
  directive: string;
  pocUrls: string[];
  patchUrls: string[];
  fetchedAt?: string;
}

function Chip({
  children,
  tone = 'neutral',
}: {
  children: React.ReactNode;
  tone?: 'neutral' | 'critical' | 'active' | 'poc' | 'good';
}): JSX.Element {
  const cls = {
    neutral: 'border-line-1 text-muted',
    critical: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    active: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
    poc: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    good: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  }[tone];
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${cls}`}>
      {children}
    </span>
  );
}

function Section({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <section className="rounded-2xl border border-line-1 bg-surface-100 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-heading">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
        </div>
        {right}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function LinkList({ urls, empty }: { urls: string[]; empty: string }): JSX.Element {
  if (!urls.length) return <p className="text-mini text-muted">{empty}</p>;
  return (
    <ul className="grid gap-1.5 md:grid-cols-2">
      {urls.slice(0, 12).map((u, i) => {
        const safe = sanitizeUrl(u);
        return (
          <li
            key={`${u}-${i}`}
            className="flex items-center gap-2 rounded-lg border border-line-1 bg-surface-100/60 px-2.5 py-1.5 text-mini"
          >
            <span className="min-w-0 flex-1 truncate font-mono text-muted" title={u}>
              {u.replace(/^https?:\/\//, '').slice(0, 90)}
            </span>
            {safe && (
              <a
                href={safe}
                target="_blank"
                rel="noopener noreferrer"
                className="shrink-0 text-sky-600 hover:text-heading dark:text-sky-400"
                aria-label="Open source"
              >
                <ArrowUpRight size={12} />
              </a>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export default function VulnSocialBrief({ cveId, platform }: { cveId: string; platform: PlatformCve }): JSX.Element {
  const { data, loading, error } = useDataFetch<VsBody>({
    url: `/data/vulnsocial/cves/${encodeURIComponent(cveId)}.json`,
    ttl: 10 * 60_000,
  });
  const [artifactTab, setArtifactTab] = useState<'all' | 'poc' | 'patch' | 'official' | 'research'>('all');

  const refs = useMemo(() => {
    const rows: string[] = [];
    for (const r of platform.references ?? []) {
      const u = typeof r === 'string' ? r : r?.url;
      if (u) rows.push(u);
    }
    return [...new Set(rows)];
  }, [platform.references]);

  const artifacts = useMemo(() => {
    const classify = (u: string) =>
      /github\.com|exploit-db|metasploit|poc/i.test(u)
        ? 'poc'
        : /nvd\.nist|cisa\.gov|cve\.org/i.test(u)
          ? 'official'
          : /patch|advisory|update|security/i.test(u)
            ? 'patch'
            : 'research';
    const all = [...new Set([...(data?.pocUrls ?? []), ...(data?.patchUrls ?? []), ...refs])];
    return {
      all,
      poc: all.filter((u) => classify(u) === 'poc'),
      patch: all.filter((u) => classify(u) === 'patch'),
      official: all.filter((u) => classify(u) === 'official'),
      research: all.filter((u) => classify(u) === 'research'),
    };
  }, [data?.pocUrls, data?.patchUrls, refs]);

  const shown = artifacts[artifactTab];
  const plain = data?.plainEnglish ?? platform.verdict?.summary ?? platform.verdict?.headline ?? null;
  const urgency = data?.urgency ?? platform.verdict?.urgency ?? (platform.cvss?.severity ?? 'unknown').toUpperCase();
  const sla = data?.sla ?? platform.kev?.due_date ?? 'not stated';
  const directive =
    data?.directive ??
    platform.verdict?.recommendation ??
    platform.verdict?.verdict ??
    'No directive published for this CVE yet.';

  return (
    <div className="space-y-4">
      <section className="rounded-2xl border border-line-1 bg-surface-100 p-4">
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          {data?.activeExploitation || platform.kev?.in_kev ? <Chip tone="critical">Active exploitation</Chip> : null}
          {data?.exploitCode ? <Chip tone="active">Weaponized</Chip> : null}
          {data?.poc || (platform.poc?.count ?? 0) > 0 ? <Chip tone="poc">Public PoC</Chip> : null}
          {data?.patch ? <Chip tone="good">Patch available</Chip> : null}
          <Chip>
            Dominant:{' '}
            {data?.topClassification ??
              (platform.verdict?.signals?.trend ? String(platform.verdict.signals.trend) : 'Disclosure')}
          </Chip>
        </div>
        <div className="mt-2 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-heading">{cveId}</h1>
            <div className="mt-1 flex flex-wrap gap-2">
              {(data?.vendors ?? []).slice(0, 8).map((v) => (
                <span key={v} className="text-mini text-sky-700 dark:text-sky-300">
                  {v}
                </span>
              ))}
              {!data && <span className="text-mini text-muted">no VulnSocial mirror for this CVE</span>}
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-[11px] uppercase tracking-wider text-muted">Triage Priority</div>
            <div className="text-2xl font-semibold text-rose-600 dark:text-rose-400">{urgency}</div>
            <div className="font-mono text-[11px] text-muted">SLA: {sla}</div>
          </div>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-body">
          {platform.description || plain || 'No description published.'}
        </p>

        {plain && (
          <div className="mt-3 rounded-xl border border-sky-500/30 bg-sky-500/5 p-3">
            <div className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-sky-700 dark:text-sky-300">
              <AlertTriangle size={12} /> Plain-English verdict
            </div>
            <p className="mt-1.5 text-sm leading-relaxed text-body">{plain}</p>
            {platform.verdict?.recommendation && (
              <p className="mt-2 text-mini text-muted">{platform.verdict.recommendation}</p>
            )}
          </div>
        )}

        <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-line-1 p-3">
            <div className="font-mono text-[11px] uppercase tracking-wider text-muted">Exploitability</div>
            <p className="mt-1 text-mini text-body">
              Network · {platform.kev?.in_kev ? 'KEV' : 'unauthenticated'} · {platform.cvss?.vector ?? 'vector n/a'}
            </p>
          </div>
          <div className="rounded-xl border border-line-1 p-3">
            <div className="font-mono text-[11px] uppercase tracking-wider text-muted">CVSS</div>
            <p className="mt-1 text-lg font-semibold text-heading">
              {platform.cvss?.base_score ?? data?.cvssScore ?? 'n/a'}{' '}
              <span className="text-mini font-normal text-muted">
                {platform.cvss?.severity ?? data?.cvssSeverity ?? ''}
              </span>
            </p>
            <p className="font-mono text-[10px] text-muted">
              {platform.cvss?.version ?? 'v3.1'} · {platform.cvss?.severity ? 'CNA' : (data?.cvssSource ?? 'n/a')}
            </p>
          </div>
          <div className="rounded-xl border border-line-1 p-3">
            <div className="font-mono text-[11px] uppercase tracking-wider text-muted">EPSS</div>
            <p className="mt-1 text-lg font-semibold text-heading">
              {platform.epss?.score != null ? `${(platform.epss.score * 100).toFixed(1)}%` : 'n/a'}
            </p>
          </div>
          <div className="rounded-xl border border-line-1 p-3">
            <div className="font-mono text-[11px] uppercase tracking-wider text-muted">Latest signal</div>
            <p className="mt-1 text-mini text-body">
              {platform.last_modified ? relativeAgo(platform.last_modified) : 'n/a'}
            </p>
          </div>
        </div>
      </section>

      <div className="grid gap-3 md:grid-cols-5">
        {[
          {
            icon: AlertTriangle,
            label: 'Exploitation',
            value: data?.activeExploitation ? 'In the wild' : 'Not confirmed',
            sub: `${data?.totalMentions ?? 0} monitored reports`,
          },
          {
            icon: FileCode,
            label: 'PoC / Tooling',
            value: data?.poc ? 'Available' : 'Unknown',
            sub: `${artifacts.poc.length} repos / signals`,
          },
          {
            icon: Wrench,
            label: 'Patch Status',
            value: data?.patch ? 'Confirmed' : 'Unknown',
            sub: `${artifacts.patch.length} advisories`,
          },
          {
            icon: Activity,
            label: 'Momentum',
            value: data?.totalDays ? 'Observed' : 'Cooling',
            sub: `${data?.totalDays ?? 0} tracked days`,
          },
          {
            icon: Megaphone,
            label: 'Signal Volume',
            value: `${data?.totalMentions ?? refs.length}`,
            sub: 'mentions across sources',
          },
        ].map((m) => (
          <div key={m.label} className="rounded-xl border border-line-1 bg-surface-100 p-3">
            <div className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-muted">
              <m.icon size={11} /> {m.label}
            </div>
            <p className="mt-1 text-sm font-semibold text-heading">{m.value}</p>
            <p className="text-micro text-muted">{m.sub}</p>
          </div>
        ))}
      </div>

      <Section
        title="Triage Directive, CVSS Attribution & Weakness Profile"
        subtitle="Operational remediation guidance paired with multi-source scoring and CWE mappings."
        right={<Chip tone="critical">{sla}</Chip>}
      >
        <div className="rounded-xl border border-line-1 bg-surface-100/60 p-3">
          <div className="font-mono text-[11px] uppercase tracking-wider text-muted">Recommended SOC / VM Action</div>
          <p className="mt-1.5 text-sm font-medium leading-relaxed text-body">{directive}</p>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <h3 className="text-mini font-semibold text-heading">Multi-Source CVSS Attribution</h3>
            <div className="mt-1 overflow-hidden rounded-lg border border-line-1">
              <table className="w-full text-mini">
                <thead className="bg-surface-200/60 font-mono text-micro text-muted">
                  <tr>
                    <th className="p-2 text-left">Authority</th>
                    <th className="p-2 text-left">Version</th>
                    <th className="p-2 text-left">Score</th>
                    <th className="p-2 text-left">Vector</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-t border-line-1">
                    <td className="p-2">CNA {platform.cvss?.severity ? 'score' : (data?.cvssSource ?? 'n/a')}</td>
                    <td className="p-2 font-mono">{platform.cvss?.version ?? 'v3.1'}</td>
                    <td className="p-2 font-mono">
                      {platform.cvss?.base_score ?? data?.cvssScore ?? 'n/a'}{' '}
                      {platform.cvss?.severity ?? data?.cvssSeverity ?? ''}
                    </td>
                    <td className="p-2 font-mono text-micro">{platform.cvss?.vector ?? '—'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div>
            <h3 className="text-mini font-semibold text-heading">Weakness Classification (CWE)</h3>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {(platform.cwe ?? []).length ? (
                (platform.cwe ?? []).map((c, i) => {
                  const label = typeof c === 'string' ? c : JSON.stringify(c);
                  return (
                    <span key={i} className="rounded border border-line-1 px-2 py-0.5 font-mono text-micro text-body">
                      {label.slice(0, 80)}
                    </span>
                  );
                })
              ) : (
                <span className="text-mini text-muted">No CWE published</span>
              )}
            </div>
          </div>
        </div>
      </Section>

      <Section
        title="Threat Artifacts & Referenced URLs"
        subtitle="Deduplicated PoCs, vendor advisories, official records and researcher links."
        right={<span className="font-mono text-mini text-muted">{artifacts.all.length} links</span>}
      >
        <div className="mb-3 flex flex-wrap gap-1">
          {(
            [
              ['all', 'All'],
              ['poc', 'PoC & Exploits'],
              ['patch', 'Patches & Advisories'],
              ['official', 'NVD & CISA'],
              ['research', 'Research'],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setArtifactTab(id)}
              aria-pressed={artifactTab === id}
              className={`rounded-full border px-2.5 py-1 text-mini ${artifactTab === id ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
            >
              {label} {artifacts[id].length}
            </button>
          ))}
        </div>
        <LinkList urls={shown} empty="No links published for this category." />
      </Section>

      <Section
        title="Affected Software & CPE 2.3"
        subtitle="Vendors, products and versions normalized from the public record."
      >
        <div className="flex flex-wrap gap-1.5">
          {(data?.vendors ?? []).map((v) => (
            <span key={v} className="rounded-full border border-line-1 px-2 py-0.5 text-mini text-body">
              {v}
            </span>
          ))}
          {(data?.products ?? []).slice(0, 20).map((p) => (
            <span key={p} className="rounded-full border border-line-1 px-2 py-0.5 font-mono text-micro text-muted">
              {p}
            </span>
          ))}
          {!data && <span className="text-mini text-muted">No CPE mirror for this CVE</span>}
        </div>
        {(data?.versions ?? []).length > 0 && (
          <p className="mt-2 text-mini text-muted">
            <span className="font-mono">Versions: </span>
            {data!.versions.join(', ')}
          </p>
        )}
      </Section>

      {data && (
        <div className="flex flex-wrap items-center gap-3 text-mini text-muted">
          <Clock3 size={12} /> Mirrored {relativeAgo(data.fetchedAt)} ·{' '}
          <a
            href={sanitizeUrl(data.shareUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            upstream decision page <ExternalLink size={10} />
          </a>
          <span className="inline-flex items-center gap-1">
            <ShieldAlert size={12} /> factual metadata only
          </span>
          <span className="inline-flex items-center gap-1">
            <GitBranch size={12} /> {data.totalMentions} signals
          </span>
          <span className="inline-flex items-center gap-1">
            <CheckCircle2 size={12} /> {data.activeExploitation ? 'confirmed' : 'unconfirmed'} exploitation
          </span>
        </div>
      )}
      {loading && <p className="text-mini font-mono text-muted">loading decision data…</p>}
      {error && !data && (
        <p className="text-mini text-muted">No VulnSocial mirror available — showing this platform's data only.</p>
      )}
    </div>
  );
}
