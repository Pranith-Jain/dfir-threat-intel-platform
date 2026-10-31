import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { ExternalLink, Siren } from 'lucide-react';

/**
 * Incident Desk — identity-lens incident briefings
 * (iamnicholasmartin.co.uk/incidents, public RSS).
 *
 * Emergency briefings on live security incidents: machine identity, CA
 * misissuance, identity supply chains, secret management failures, AI-key
 * theft. The full feed (~17 briefs) is replicated through the platform API:
 *
 *   GET /api/v1/threat-intel/incident-desk            → index + briefs
 *   GET /api/v1/threat-intel/incident-desk/briefs/:slug → one brief
 */

interface Brief {
  title: string | null;
  link: string | null;
  guid: string | null;
  published: string | null;
  description: string | null;
  imageUrl: string | null;
  slug: string;
}

interface IncidentDeskResponse {
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  meta: {
    feedUrl: string;
    feedTitle: string | null;
  };
  counts: {
    briefs: number;
    withImage: number;
    byMonth: Record<string, number>;
  };
  briefs: Brief[];
}

export default function IncidentDesk(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<IncidentDeskResponse>({
    url: '/api/v1/threat-intel/incident-desk',
    ttl: 300_000,
  });

  const months = Object.entries(data?.counts.byMonth ?? {});

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Siren size={28} />}
      title="Incident Desk"
      description="Emergency briefings on live security incidents through an identity lens — machine identity, CA misissuance, identity supply chains, secret management failures, AI-key theft. Replicated from the public Incident Desk RSS feed."
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-4xl"
    >
      {/* Stats band */}
      <div className="grid grid-cols-3 gap-3 mb-8">
        {[
          ['Briefs replicated', String(data?.counts.briefs ?? '—')],
          ['With hero art', String(data?.counts.withImage ?? '—')],
          ['Months covered', String(months.length ? months.length : '—')],
        ].map(([label, value]) => (
          <div key={label} className="surface-card p-4 text-center">
            <div className="text-2xl font-display font-bold text-heading tabular-nums">{value}</div>
            <div className="text-micro font-mono uppercase tracking-wider text-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Briefs */}
      <ul className="space-y-4">
        {(data?.briefs ?? []).map((b) => (
          <li key={b.slug} className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-2 text-micro font-mono text-muted">
              {b.published && <time dateTime={b.published}>{new Date(b.published).toISOString().slice(0, 10)}</time>}
              <span
                className="px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 uppercase tracking-wider"
                title="Incident briefing"
              >
                incident
              </span>
            </div>
            <a
              href={b.link ?? b.guid ?? '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="block mt-2 text-lg font-bold text-heading hover:text-brand-600 dark:hover:text-brand-400"
            >
              {b.title ?? 'Untitled briefing'}
            </a>
            {b.description && <p className="mt-2 text-sm text-body leading-relaxed">{b.description}</p>}
            {b.imageUrl && (
              <a
                href={b.link ?? b.guid ?? '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="block mt-4 overflow-hidden rounded-xl border border-line-1"
                tabIndex={-1}
              >
                <img
                  src={b.imageUrl}
                  alt=""
                  loading="lazy"
                  className="w-full h-auto max-h-72 object-cover"
                  referrerPolicy="no-referrer"
                />
              </a>
            )}
            <div className="mt-3 text-micro font-mono text-muted">
              <a
                href={b.link ?? b.guid ?? '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 hover:underline"
              >
                read the briefing <ExternalLink size={10} />
              </a>
            </div>
          </li>
        ))}
      </ul>

      {/* Feed info footer */}
      <footer className="pt-6 mt-8 border-t border-line-1 text-sm text-muted">
        <p>
          Synced <strong>{data ? relativeAgo(data.syncedAt) : '—'}</strong>{' '}
          {data && (
            <>
              · briefs link back to{' '}
              <a
                href={data.sourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-brand-600 dark:text-brand-400 hover:underline"
              >
                iamnicholasmartin.co.uk/incidents <ExternalLink size={12} />
              </a>
            </>
          )}
        </p>
        <p className="mt-2">
          Replicated verbatim from the public RSS feed — summaries are the author's, not machine-generated. Incident
          reporting through an identity lens pairs well with the machine-identity angle of the{' '}
          <a href="/threatintel/feeds/cve-now" className="text-brand-600 dark:text-brand-400 hover:underline">
            CVE.now wire
          </a>
          .
        </p>
      </footer>
    </DataPageLayout>
  );
}
