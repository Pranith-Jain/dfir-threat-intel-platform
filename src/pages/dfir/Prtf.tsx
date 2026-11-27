/**
 * PRTF — Physical Red Team Framework (CC BY 4.0), mirrored with attribution.
 * 9 tactics / 108 techniques; every detail links back to redteam.vip/prtf.
 */
import { useMemo, useState, type JSX } from 'react';
import { ArrowUpRight, ExternalLink, Search, Wrench } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface PrtfRow {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  summary: string;
  toolCount: number;
  url: string;
}

interface PrtfBody extends PrtfRow {
  section: string | null;
  description: string;
  tools: Array<{ name: string; url: string | null }>;
  chains: Array<{ id: string; name: string }>;
  blue: { det?: string; cm?: string; refs?: unknown } | null;
}

interface PrtfIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  license: string;
  version: string;
  counts: { tactics: number; techniques: number };
  tactics: Array<{ id: string; name: string; description: string; count: number }>;
  techniques: PrtfRow[];
}

function Detail({ id }: { id: string }): JSX.Element {
  const { data, loading, error } = useDataFetch<PrtfBody>({
    url: `/api/v1/prtf/techniques/${encodeURIComponent(id)}`,
    ttl: 10 * 60_000,
  });
  if (loading && !data) return <p className="mt-3 text-mini font-mono text-muted">loading technique…</p>;
  if (error && !data) return <p className="mt-3 text-mini text-rose-600 dark:text-rose-400">{error}</p>;
  if (!data) return <p className="mt-3 text-mini font-mono text-muted">technique unavailable</p>;
  return (
    <div className="mt-3 space-y-3 border-t border-line-1 pt-3">
      <p className="text-mini leading-relaxed text-body">{data.description}</p>
      {data.tools.length > 0 && (
        <div>
          <div className="flex items-center gap-1.5 text-micro font-mono uppercase tracking-wider text-muted">
            <Wrench size={11} /> Tools
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {data.tools.map((t, i) =>
              t.url ? (
                <a
                  key={`${t.name}-${i}`}
                  href={sanitizeUrl(t.url) ?? undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded border border-line-1 px-1.5 py-0.5 text-micro text-sky-600 hover:underline dark:text-sky-400"
                >
                  {t.name} <ExternalLink size={9} className="inline" />
                </a>
              ) : (
                <span
                  key={`${t.name}-${i}`}
                  className="rounded border border-line-1 px-1.5 py-0.5 text-micro text-muted"
                >
                  {t.name}
                </span>
              )
            )}
          </div>
        </div>
      )}
      {data.chains.length > 0 && (
        <div className="text-mini">
          <span className="font-mono uppercase tracking-wider text-muted">Related: </span>
          <span className="text-body">{data.chains.map((c) => c.name).join(' → ')}</span>
        </div>
      )}
      {data.blue && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2.5 text-mini">
          <div className="mb-1 font-mono text-micro uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
            Blue-team view
          </div>
          {data.blue.det && (
            <p className="text-body">
              <span className="font-mono text-muted">detect: </span>
              {data.blue.det}
            </p>
          )}
          {data.blue.cm && (
            <p className="mt-1 text-body">
              <span className="font-mono text-muted">countermeasure: </span>
              {data.blue.cm}
            </p>
          )}
        </div>
      )}
      <a
        href={sanitizeUrl(data.url) ?? undefined}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
      >
        upstream technique <ExternalLink size={10} />
      </a>
    </div>
  );
}

export default function Prtf(): JSX.Element {
  const { data, loading, error } = useDataFetch<PrtfIndex>({ url: '/api/v1/prtf/', ttl: 10 * 60_000 });
  const [tactic, setTactic] = useState('all');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.techniques ?? []).filter((t) => {
      if (tactic !== 'all' && t.tacticId !== tactic) return false;
      if (needle && !`${t.id} ${t.name} ${t.summary}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data?.techniques, tactic, q]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Wrench size={28} />}
      title="PRTF"
      description="Physical Red Team Framework — 108 techniques across 9 tactics, from reconnaissance to persistence. Mirrored under CC BY 4.0 with attribution."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="PRTF — Physical Red Team Framework"
        description="A CC BY 4.0 taxonomy of physical security testing techniques, mirrored from redteam.vip with attribution and upstream links."
        section="DFIR"
        canonicalPath="/dfir/prtf"
      />

      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.techniques}</span> techniques
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.tactics}</span> tactics
          </span>
          <span className="font-mono">v{data.version}</span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            redteam.vip/prtf <ExternalLink size={10} />
          </a>
          <span className="text-micro">{data.license}</span>
        </div>
      )}

      <div className="mb-4 space-y-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search techniques by id, name or description…"
            className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setTactic('all')}
            aria-pressed={tactic === 'all'}
            className={`rounded-full border px-2.5 py-1 text-mini font-mono ${
              tactic === 'all'
                ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                : 'border-line-1 text-muted'
            }`}
          >
            all ({data?.counts.techniques ?? 0})
          </button>
          {(data?.tactics ?? []).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTactic(t.id)}
              aria-pressed={tactic === t.id}
              title={t.description}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono ${
                tactic === t.id
                  ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                  : 'border-line-1 text-muted'
              }`}
            >
              {t.id} {t.name} ({t.count})
            </button>
          ))}
        </div>
      </div>

      {loading && !data && <p className="text-mini font-mono text-muted">loading the taxonomy…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className="grid gap-2 lg:grid-cols-2">
        {rows.map((t) => (
          <div key={t.id} className="surface-card p-3">
            <button
              type="button"
              onClick={() => setOpen(open === t.id ? null : t.id)}
              aria-expanded={open === t.id}
              className="w-full text-left"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="font-mono text-micro text-muted">{t.id}</div>
                  <div className="text-sm font-semibold text-heading">{t.name}</div>
                </div>
                <ArrowUpRight
                  size={13}
                  className={`shrink-0 text-muted transition-transform ${open === t.id ? 'rotate-90' : ''}`}
                />
              </div>
              <p className="mt-1 line-clamp-2 text-mini text-muted">{t.summary}</p>
            </button>
            <div className="mt-1.5 flex items-center gap-2 text-micro text-muted">
              <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono">{t.tacticName}</span>
              <span>{t.toolCount} tools</span>
            </div>
            {open === t.id && <Detail id={t.id} />}
          </div>
        ))}
      </div>

      {data && rows.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No techniques match that filter.</p>
      )}
    </DataPageLayout>
  );
}
