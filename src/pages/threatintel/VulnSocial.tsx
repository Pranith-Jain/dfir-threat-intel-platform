/**
 * VulnSocial tab — the decision-data mirror of vulnsocial.com's radar.
 *
 * Factual triage metadata parsed from public server-rendered pages; no
 * upstream code, CSS or prose bodies. Every card links to this platform's
 * CVE detail page, which opens in the VulnSocial decision layout.
 */
import { useMemo, useState, type JSX } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ArrowUpRight, Clock3, ExternalLink, Search, ShieldAlert, Wrench } from 'lucide-react';
import { PageMeta } from '../../components/PageMeta';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { relativeAgo } from '../../lib/relativeTime';

interface VsRow {
  id: string;
  urgency: string | null;
  sla: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  kev: boolean;
  exploitation: boolean;
  poc: boolean;
  patch: boolean;
  mentions: number;
  directive: string;
  url: string;
}

interface VsIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  note: string;
  counts: { cves: number; withPlainEnglish: number };
  cves: VsRow[];
}

export default function VulnSocial({ bare = false }: { bare?: boolean }): JSX.Element {
  const { data, loading, error } = useDataFetch<VsIndex>({ url: '/data/vulnsocial/index.json', ttl: 10 * 60_000 });
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<'all' | 'kev' | 'exploited' | 'poc' | 'patched'>('all');

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.cves ?? []).filter((c) => {
      if (filter === 'kev' && !c.kev) return false;
      if (filter === 'exploited' && !c.exploitation) return false;
      if (filter === 'poc' && !c.poc) return false;
      if (filter === 'patched' && !c.patch) return false;
      if (needle && !`${c.id} ${c.directive}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data?.cves, q, filter]);

  const body = (
    <div className="space-y-4">
      <PageMeta
        title="VulnSocial — CVE decision radar"
        description="Public triage decisions (urgency, SLA, directive, CVSS and artifact links) mirrored from VulnSocial with attribution."
        section="Threat Intel"
        canonicalPath="/threatintel/cves/cves?tab=vulnsocial"
      />

      {data && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.cves}</span> decisions
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.withPlainEnglish}</span> plain-English briefs
          </span>
          <span>mirrored {relativeAgo(data.generatedAt)}</span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            vulnsocial.com <ExternalLink size={10} />
          </a>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search CVE id or directive…"
            className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
          />
        </div>
        {(
          [
            ['all', 'All'],
            ['kev', 'KEV'],
            ['exploited', 'Exploited'],
            ['poc', 'PoC'],
            ['patched', 'Patched'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            onClick={() => setFilter(id)}
            aria-pressed={filter === id}
            className={`rounded-full border px-2.5 py-1 text-mini ${filter === id ? 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-line-1 text-muted'}`}
          >
            {label}
          </button>
        ))}
      </div>

      {loading && !data && <p className="text-mini font-mono text-muted">loading decision radar…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className="grid gap-2 lg:grid-cols-2">
        {rows.map((c) => (
          <article key={c.id} className="surface-card p-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <Link
                to={`/threatintel/cve/${encodeURIComponent(c.id)}`}
                className="font-mono text-sm font-semibold text-heading hover:underline"
              >
                {c.id}
              </Link>
              <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 text-micro font-semibold text-rose-700 dark:text-rose-300">
                {c.urgency ?? 'unrated'}
              </span>
              {c.kev && (
                <span className="rounded border border-rose-500/40 px-1.5 py-0.5 font-mono text-micro text-rose-600 dark:text-rose-300">
                  KEV
                </span>
              )}
              {c.exploitation && (
                <span className="rounded border border-orange-500/40 px-1.5 py-0.5 font-mono text-micro text-orange-700 dark:text-orange-300">
                  exploited
                </span>
              )}
              {c.poc && (
                <span className="rounded border border-amber-500/40 px-1.5 py-0.5 font-mono text-micro text-amber-700 dark:text-amber-300">
                  PoC
                </span>
              )}
              {c.patch && (
                <span className="rounded border border-emerald-500/40 px-1.5 py-0.5 font-mono text-micro text-emerald-700 dark:text-emerald-300">
                  patch
                </span>
              )}
            </div>
            <p className="mt-2 line-clamp-2 text-mini leading-relaxed text-body">{c.directive}</p>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-micro text-muted">
              <span className="inline-flex items-center gap-1">
                <ShieldAlert size={10} /> CVSS {c.cvssScore ?? 'n/a'} {c.cvssSeverity ?? ''}
              </span>
              <span className="inline-flex items-center gap-1">
                <Clock3 size={10} /> SLA {c.sla ?? 'n/a'}
              </span>
              <span className="inline-flex items-center gap-1">
                <Activity size={10} /> {c.mentions} mentions
              </span>
              <a
                href={sanitizeUrl(c.url) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-auto inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
              >
                upstream <ExternalLink size={9} />
              </a>
              <Link
                to={`/threatintel/cve/${encodeURIComponent(c.id)}`}
                className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
              >
                decision <ArrowUpRight size={9} />
              </Link>
            </div>
          </article>
        ))}
      </div>

      {data && rows.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No decisions match that filter.</p>
      )}
      {data && (
        <p className="flex items-center gap-1.5 text-micro text-muted">
          <Wrench size={10} /> {data.note}
        </p>
      )}
    </div>
  );

  if (bare) return body;
  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <h1 className="mb-4 text-2xl font-bold text-heading">VulnSocial decision radar</h1>
      {body}
    </div>
  );
}
