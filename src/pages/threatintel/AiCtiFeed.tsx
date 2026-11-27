/**
 * OWASP GenAI Threat Intelligence Initiative — STIX 2.1 feed reader.
 *
 * Category A = threat actors using AI; Category B = actors attacking AI systems.
 * Factual STIX object metadata only, mirrored from the public feed with links
 * to the upstream repository (which has no reuse licence).
 */
import { useMemo, useState, type JSX } from 'react';
import { ExternalLink, Search } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { Tabs } from '../../components/ui/Tabs';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface Slim {
  id: string;
  slug: string;
  name: string;
  category: string | null;
  created: string | null;
  refCount: number;
}

interface Index {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  repoUrl: string;
  license: string;
  counts: Record<string, number>;
  actors: Slim[];
  techniques: Slim[];
  malware: Slim[];
  reports: Slim[];
  indicators: Array<{ id: string; name: string; category: string | null; labels: string[]; created: string | null }>;
}

interface Body extends Slim {
  description: string;
  labels: string[];
  modified: string | null;
  refs: Array<{ source: string | null; id: string | null; url: string | null }>;
  links: Array<{ type: string; target: string }>;
}

function CategoryChip({ value }: { value: string | null }): JSX.Element {
  const a = value === 'A';
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-micro ${
        a
          ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
          : value === 'B'
            ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
            : 'border-line-1 text-muted'
      }`}
    >
      {value ? `Cat ${value}` : 'uncategorised'}
    </span>
  );
}

function Detail({ kind, slug }: { kind: 'actors' | 'techniques' | 'malware'; slug: string }): JSX.Element {
  const { data, loading, error } = useDataFetch<Body>({
    url: `/api/v1/ai-cti-feed/${kind}/${encodeURIComponent(slug)}`,
    ttl: 10 * 60_000,
  });
  if (loading && !data) return <p className="mt-2 text-mini font-mono text-muted">loading object…</p>;
  if (error && !data) return <p className="mt-2 text-mini text-rose-600 dark:text-rose-400">{error}</p>;
  if (!data) return <p className="mt-2 text-mini font-mono text-muted">object unavailable</p>;
  return (
    <div className="mt-3 space-y-2 border-t border-line-1 pt-3">
      {data.description && <p className="text-mini leading-relaxed text-body">{data.description}</p>}
      {data.refs.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {data.refs.map((r, i) =>
            r.url ? (
              <a
                key={i}
                href={sanitizeUrl(r.url) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-sky-600 hover:underline dark:text-sky-400"
              >
                {r.source} {r.id} <ExternalLink size={9} className="inline" />
              </a>
            ) : (
              <span key={i} className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                {r.source} {r.id}
              </span>
            )
          )}
        </div>
      )}
      {data.links.length > 0 && (
        <p className="text-mini text-muted">
          <span className="font-mono uppercase tracking-wider">Relationships: </span>
          {data.links
            .slice(0, 10)
            .map((l) => `${l.type} → ${l.target.split('--')[1]?.slice(0, 8)}`)
            .join(', ')}
        </p>
      )}
    </div>
  );
}

function List({ rows, kind }: { rows: Slim[]; kind: 'actors' | 'techniques' | 'malware' }): JSX.Element {
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('all');
  const [open, setOpen] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter(
      (r) => (cat === 'all' || r.category === cat) && (!needle || `${r.name} ${r.id}`.toLowerCase().includes(needle))
    );
  }, [rows, q, cat]);
  return (
    <div className="py-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={`Search ${kind}…`}
            className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
          />
        </div>
        {['all', 'A', 'B'].map((c) => (
          <button
            key={c}
            type="button"
            onClick={() => setCat(c)}
            aria-pressed={cat === c}
            className={`rounded-full border px-2.5 py-1 font-mono text-mini ${
              cat === c ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'
            }`}
          >
            {c === 'all' ? 'all' : `Cat ${c}`}
          </button>
        ))}
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        {filtered.slice(0, 100).map((r) => (
          <div key={r.id} className="surface-card p-3">
            <button
              type="button"
              onClick={() => setOpen(open === r.slug ? null : r.slug)}
              aria-expanded={open === r.slug}
              className="w-full text-left"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-sm font-semibold text-heading">{r.name}</span>
                <CategoryChip value={r.category} />
              </div>
              <p className="mt-1 font-mono text-micro text-muted">{r.id}</p>
            </button>
            {open === r.slug && <Detail kind={kind} slug={r.slug} />}
          </div>
        ))}
      </div>
      {filtered.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No objects match that filter.</p>
      )}
    </div>
  );
}

export default function AiCtiFeed(): JSX.Element {
  const { data, loading, error } = useDataFetch<Index>({ url: '/api/v1/ai-cti-feed/', ttl: 10 * 60_000 });
  const [tab, setTab] = useState('actors');
  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ExternalLink size={28} />}
      title="GenAI Threat Intelligence"
      description="OWASP GenAI Threat Intelligence Initiative — AI threat actors and techniques as STIX 2.1, mirrored from the public feed."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="GenAI Threat Intelligence — OWASP initiative feed"
        description="Category A actors using AI and Category B actors attacking AI systems, from the public OWASP GenAI STIX 2.1 feed."
        section="Threat Intel"
        canonicalPath="/threatintel/ai-cti-feed"
      />

      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.objects}</span> STIX objects
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.actors}</span> actors
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.techniques}</span> techniques
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.indicators}</span> indicators
          </span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            aithreatintelfeed.org <ExternalLink size={10} />
          </a>
        </div>
      )}
      {loading && !data && <p className="text-mini font-mono text-muted">loading the feed…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      {data && (
        <Tabs
          tabs={[
            { id: 'actors', label: 'Actors', count: data.actors.length },
            { id: 'techniques', label: 'Techniques', count: data.techniques.length },
            { id: 'malware', label: 'Malware', count: data.malware.length },
            { id: 'indicators', label: 'Indicators', count: data.indicators.length },
            { id: 'about', label: 'About' },
          ]}
          active={tab}
          onChange={setTab}
          variant="underline"
        >
          {(active) =>
            active === 'actors' ? (
              <List rows={data.actors} kind="actors" />
            ) : active === 'techniques' ? (
              <List rows={data.techniques} kind="techniques" />
            ) : active === 'malware' ? (
              <List rows={data.malware} kind="malware" />
            ) : active === 'indicators' ? (
              <div className="py-4">
                <ul className="space-y-1">
                  {data.indicators.map((i) => (
                    <li
                      key={i.id}
                      className="flex items-center gap-2 rounded border border-line-1 bg-surface-100/60 px-2.5 py-1.5 text-mini"
                    >
                      <CategoryChip value={i.category} />
                      <span className="text-body">{i.name}</span>
                      <span className="ml-auto font-mono text-micro text-muted">
                        {i.id.split('--')[1]?.slice(0, 8)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="space-y-2 py-4 text-mini leading-relaxed text-body">
                <p>
                  <span className="font-mono text-muted">Source: </span>
                  {data.source} — published STIX 2.1 / TAXII 2.1 feed generated from the project's Git repository.
                </p>
                <p>
                  <span className="font-mono text-muted">Category A: </span>threat actors using AI to attack.{' '}
                  <span className="font-mono text-muted">Category B: </span>actors attacking AI systems (MITRE ATLAS).
                </p>
                <p>
                  <span className="font-mono text-muted">Licence: </span>
                  {data.license}
                </p>
                <a
                  href={sanitizeUrl(data.repoUrl) ?? undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                >
                  upstream repository <ExternalLink size={10} />
                </a>
              </div>
            )
          }
        </Tabs>
      )}
    </DataPageLayout>
  );
}
