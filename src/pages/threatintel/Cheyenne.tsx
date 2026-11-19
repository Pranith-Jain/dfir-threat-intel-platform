import { useMemo, useState, type ReactNode } from 'react';
import { ExternalLink, Github, Satellite, ShieldAlert, Star } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * Cheyenne — earth-observation tracking board, mirrored from
 * github.com/MJCruickshank/cheyenne (documentation mirror, not the app).
 *
 * The upstream tool is a local Python server + browser globe; this page
 * replicates its public documentation: feature set, 23 satellite fleets,
 * data sources, AIS feeds, limitations and credits. Snapshot built by
 * scripts/sync-cheyenne.mjs. Upstream text and fleet metadata are verbatim.
 */

interface Screenshot {
  alt: string;
  url: string;
}

interface Fleet {
  id: string;
  name: string;
  group: string;
  operator: string;
  sensor: string;
  instrument: string;
  gsd: string;
  revisit: string;
  color: string;
  access: string;
  defaultVisible: boolean;
}

interface CheyenneDataset {
  generatedAt: string;
  source: {
    name: string;
    fullName: string;
    url: string;
    description: string;
    stars: number;
    forks: number;
    pushedAt: string | null;
    license: string | null;
    readmeUrl: string;
    catalogUrl: string;
  };
  overview: string;
  features: Array<{ title: string; body: string }>;
  screenshots: Screenshot[];
  groups: Array<{ id: string; label: string; note: string }>;
  fleets: Fleet[];
  dataSources: Array<{ data: string; source: string; url: string | null }>;
  aisFeeds: Array<{ feed: string; url: string | null; area: string; key: string; usage: string }>;
  footprints: Array<{ label: string; source: string; reliability: string }>;
  limitations: string[];
  credits: Array<{ component: string; url: string | null; licence: string }>;
  creditsNote: string;
  install: { requirements: string[]; commands: string };
}

function OutLink({
  href,
  children,
  className,
}: {
  href: string | null | undefined;
  children: ReactNode;
  className?: string;
}) {
  const safe = sanitizeUrl(href ?? '');
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer" className={className}>
      {children} <ExternalLink size={10} className="inline" />
    </a>
  );
}

export default function Cheyenne(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<CheyenneDataset>({
    url: '/data/cheyenne/index.json',
    ttl: 15 * 60_000,
  });
  const [group, setGroup] = useState('all');

  const fleets = useMemo(() => (data?.fleets ?? []).filter((f) => group === 'all' || f.group === group), [data, group]);

  return (
    <DataPageLayout
      backTo="/threatintel/catalog?cat=osint"
      icon={<Satellite size={28} />}
      title="Cheyenne · Earth-Observation Board"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 font-mono text-xs text-emerald-700 dark:text-emerald-300">
            Mirror of github.com/MJCruickshank/cheyenne
          </span>
          {data && (
            <>
              <span className="inline-flex items-center gap-1 rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
                <Star size={10} /> {data.source.stars} stars
              </span>
              <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
                {data.fleets.length} satellite fleets
              </span>
              <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
                synced {relativeAgo(data.generatedAt)}
              </span>
            </>
          )}
        </span>
      }
      maxWidthClass="max-w-6xl"
      loading={loading && !data}
      error={error}
      onRetry={() => void refetch()}
    >
      {data && (
        <div className="space-y-8">
          {/* Overview + gallery */}
          <section className="space-y-4">
            <p className="max-w-4xl text-sm leading-relaxed text-body">{data.overview}</p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {data.screenshots.slice(0, 4).map((shot) => (
                <figure key={shot.url} className="overflow-hidden rounded-lg border border-line-1 bg-surface-100">
                  <img
                    src={shot.url}
                    alt={shot.alt}
                    loading="lazy"
                    referrerPolicy="no-referrer"
                    className="h-32 w-full object-cover object-top"
                  />
                  <figcaption className="line-clamp-2 p-2 text-[10px] leading-snug text-muted">{shot.alt}</figcaption>
                </figure>
              ))}
            </div>
            <p className="text-[11px] text-muted">
              Screenshots are loaded from the upstream repository ·{' '}
              <OutLink href={data.source.readmeUrl} className="underline hover:text-accent">
                source README
              </OutLink>
            </p>
          </section>

          {/* Features */}
          <section aria-labelledby="cheyenne-features">
            <h2 id="cheyenne-features" className="mb-3 flex items-center gap-2 text-lg font-bold text-heading">
              <Satellite size={18} /> Features
            </h2>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {data.features.map((f, i) => (
                <article key={f.title || i} className="surface-card rounded-xl border border-line-1 p-4">
                  <h3 className="text-sm font-bold text-heading">{f.title || `Feature ${i + 1}`}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-body">{f.body}</p>
                </article>
              ))}
            </div>
          </section>

          {/* Fleet catalog */}
          <section aria-labelledby="cheyenne-fleets">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h2 id="cheyenne-fleets" className="text-lg font-bold text-heading">
                Satellite fleets{' '}
                <span className="font-mono text-xs font-normal text-muted">({data.fleets.length})</span>
              </h2>
              <OutLink href={data.source.catalogUrl} className="font-mono text-[11px] text-muted hover:text-accent">
                web/catalog.json
              </OutLink>
            </div>
            <div className="mb-3 flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setGroup('all')}
                aria-pressed={group === 'all'}
                className={`rounded border px-2 py-1 font-mono text-[11px] ${
                  group === 'all'
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-line-1 text-muted hover:text-heading'
                }`}
              >
                All
              </button>
              {data.groups.map((g) => (
                <button
                  key={g.id}
                  type="button"
                  onClick={() => setGroup(g.id)}
                  aria-pressed={group === g.id}
                  title={g.note}
                  className={`rounded border px-2 py-1 font-mono text-[11px] ${
                    group === g.id
                      ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-line-1 text-muted hover:text-heading'
                  }`}
                >
                  {g.label}
                </button>
              ))}
            </div>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {fleets.map((f) => (
                <article key={f.id} className="surface-card rounded-lg border border-line-1 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ background: f.color || '#94a3b8' }}
                      />
                      <h3 className="font-mono text-xs font-bold text-heading">{f.name}</h3>
                    </div>
                    <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted">
                      {f.sensor}
                    </span>
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[10px]">
                    <dt className="font-mono uppercase tracking-wide text-muted">Operator</dt>
                    <dd className="text-body">{f.operator || '—'}</dd>
                    <dt className="font-mono uppercase tracking-wide text-muted">Instrument</dt>
                    <dd className="text-body">{f.instrument || '—'}</dd>
                    <dt className="font-mono uppercase tracking-wide text-muted">Resolution</dt>
                    <dd className="font-mono text-body">{f.gsd || '—'}</dd>
                    <dt className="font-mono uppercase tracking-wide text-muted">Revisit</dt>
                    <dd className="font-mono text-body">{f.revisit || '—'}</dd>
                  </dl>
                  {f.access && (
                    <p className="mt-2 border-t border-line-1 pt-2 text-[10px] leading-snug text-muted">{f.access}</p>
                  )}
                </article>
              ))}
            </div>
          </section>

          {/* Data sources */}
          <section aria-labelledby="cheyenne-sources">
            <h2 id="cheyenne-sources" className="mb-3 text-lg font-bold text-heading">
              Data sources
            </h2>
            <div className="overflow-x-auto rounded-xl border border-line-1">
              <table className="w-full min-w-[620px] text-left text-xs">
                <thead className="border-b border-line-1 bg-surface-100 text-[10px] uppercase tracking-wider text-muted">
                  <tr>
                    <th className="px-3 py-2">Data</th>
                    <th className="px-3 py-2">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-1">
                  {data.dataSources.map((row) => (
                    <tr key={row.data}>
                      <td className="px-3 py-2 font-semibold text-heading">{row.data}</td>
                      <td className="px-3 py-2 text-body">
                        {row.url ? (
                          <OutLink href={row.url} className="hover:text-accent">
                            {row.source}
                          </OutLink>
                        ) : (
                          row.source
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* AIS + future passes */}
          <section className="grid gap-4 lg:grid-cols-2">
            <div aria-labelledby="cheyenne-ais">
              <h2 id="cheyenne-ais" className="mb-2 text-lg font-bold text-heading">
                AIS ship tracking
              </h2>
              <div className="space-y-2">
                {data.aisFeeds.map((f) => (
                  <article key={f.feed} className="surface-card rounded-lg border border-line-1 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <OutLink
                        href={f.url}
                        className="font-mono text-xs font-bold text-heading hover:text-emerald-700 dark:hover:text-emerald-300"
                      >
                        {f.feed}
                      </OutLink>
                      <span className="font-mono text-[10px] text-muted">{f.key || 'no key'}</span>
                    </div>
                    <p className="mt-1 text-[11px] text-body">{f.area}</p>
                    <p className="mt-1 text-[10px] text-muted">{f.usage}</p>
                  </article>
                ))}
              </div>
            </div>
            <div aria-labelledby="cheyenne-passes">
              <h2 id="cheyenne-passes" className="mb-2 text-lg font-bold text-heading">
                What future footprints mean
              </h2>
              <div className="space-y-2">
                {data.footprints.map((f) => (
                  <article key={f.label} className="surface-card rounded-lg border border-line-1 p-3">
                    <h3 className="font-mono text-[11px] font-bold text-heading">{f.label}</h3>
                    <p className="mt-1 text-[11px] text-body">{f.source}</p>
                    <p className="mt-1 text-[10px] text-muted">{f.reliability}</p>
                  </article>
                ))}
              </div>
            </div>
          </section>

          {/* Install + limits */}
          <section className="grid gap-4 lg:grid-cols-2">
            <div aria-labelledby="cheyenne-install">
              <h2 id="cheyenne-install" className="mb-2 text-lg font-bold text-heading">
                Quick start
              </h2>
              <ul className="mb-3 list-disc space-y-1 pl-5 text-xs text-body">
                {data.install.requirements.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
              <pre className="overflow-x-auto rounded-lg border border-line-1 bg-surface-100 p-3 font-mono text-[11px] leading-relaxed text-body">
                {data.install.commands}
              </pre>
            </div>
            <div aria-labelledby="cheyenne-limits">
              <h2 id="cheyenne-limits" className="mb-2 flex items-center gap-2 text-lg font-bold text-heading">
                <ShieldAlert size={17} className="text-amber-500" /> Limitations
              </h2>
              <ul className="space-y-2">
                {data.limitations.map((l) => (
                  <li
                    key={l}
                    className="rounded-lg border border-line-1 bg-surface-100 px-3 py-2 text-[11px] leading-relaxed text-body"
                  >
                    {l}
                  </li>
                ))}
              </ul>
            </div>
          </section>

          {/* Credits */}
          <section aria-labelledby="cheyenne-credits">
            <h2 id="cheyenne-credits" className="mb-2 text-lg font-bold text-heading">
              Credits & licences
            </h2>
            <div className="overflow-x-auto rounded-xl border border-line-1">
              <table className="w-full min-w-[520px] text-left text-xs">
                <thead className="border-b border-line-1 bg-surface-100 text-[10px] uppercase tracking-wider text-muted">
                  <tr>
                    <th className="px-3 py-2">Component</th>
                    <th className="px-3 py-2">Licence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-1">
                  {data.credits.map((c) => (
                    <tr key={c.component}>
                      <td className="px-3 py-2 text-body">
                        {c.url ? (
                          <OutLink href={c.url} className="hover:text-accent">
                            {c.component}
                          </OutLink>
                        ) : (
                          c.component
                        )}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-muted">{c.licence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-2 text-[11px] leading-relaxed text-muted">{data.creditsNote}</p>
          </section>

          <section className="surface-card rounded-xl border border-line-1 p-4 text-[11px] leading-relaxed text-muted">
            <p className="mb-1 flex items-center gap-1.5 font-semibold text-heading">
              <Github size={13} /> Provenance
            </p>
            <p>
              Documentation mirror of{' '}
              <OutLink href={data.source.url} className="underline hover:text-accent">
                {data.source.fullName}
              </OutLink>{' '}
              (last upstream push {data.source.pushedAt ? relativeAgo(data.source.pushedAt) : 'unknown'}). Feature text,
              tables and screenshots are from the upstream README; fleet metadata is from its `web/catalog.json`.
              Cheyenne is not affiliated with or endorsed by the data providers it lists. Snapshot synced{' '}
              {relativeAgo(data.generatedAt)}.
            </p>
          </section>
        </div>
      )}
    </DataPageLayout>
  );
}
