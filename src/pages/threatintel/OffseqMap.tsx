import { useMemo, useState } from 'react';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import OffseqMapChart from './OffseqMapChart';
import { offseqCountryKey } from '../../lib/offseq-country';

/**
 * Global threat distribution from radar.offseq.com/map.
 *
 * Countries named in threat reports added in the last 30 days, shaded by how
 * often they appear; reports listing more than 10 target countries are left
 * out upstream. The detailed map (not the all-time flat map) is what the
 * upstream page renders, so that is what the sync captures.
 */

interface CountryRecord {
  name: string;
  count: number;
  severityBreakdown: Record<string, number>;
  typeBreakdown: Record<string, number>;
  latestThreat: string | null;
}

interface RecentThreat {
  title: string | null;
  slug: string | null;
  source: string | null;
  severity: string | null;
  cvssScore: number | null;
  publishedDate: string | null;
  cveId: string | null;
  countries: string[];
  url: string | null;
}

interface CountriesManifest {
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  windowDays: number;
  counts: { countries: number; mentions: number };
  countries: CountryRecord[];
  recentThreats: RecentThreat[];
}

function Breakdown({ label, values }: { label: string; values: Record<string, number> }): JSX.Element | null {
  const entries = Object.entries(values)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-wider text-muted">{label}</div>
      <div className="flex flex-wrap gap-1">
        {entries.map(([key, count]) => (
          <span
            key={key}
            className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 font-mono text-[10px] text-body"
          >
            {key} {count}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function OffseqMap(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<CountriesManifest>({
    url: '/data/threat-intel/offseq/countries.json',
    ttl: 10 * 60_000,
  });
  const [selected, setSelected] = useState<string | null>(null);

  const counts = useMemo(
    () => new Map((data?.countries ?? []).map((c) => [offseqCountryKey(c.name), c.count])),
    [data]
  );
  const max = Math.max(...counts.values(), 1);
  const selectedCountry = useMemo(
    () => (data?.countries ?? []).find((c) => offseqCountryKey(c.name) === selected) ?? null,
    [data, selected]
  );
  const ranked = (data?.countries ?? []).slice(0, 15);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold text-heading">Global threat distribution</h2>
          <p className="mt-1 max-w-3xl text-[11px] leading-relaxed text-muted">{data?.description ?? 'Loading…'}</p>
        </div>
        <button
          type="button"
          onClick={() => void refetch()}
          className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 text-[11px] text-muted hover:text-heading"
        >
          <RefreshCw size={11} /> refresh
        </button>
      </div>

      {loading && !data && <p className="py-8 text-center text-sm text-muted">Loading OffSeq country map…</p>}
      {error && !data && (
        <p className="py-8 text-center text-sm text-rose-600 dark:text-rose-400">OffSeq map unavailable: {error}</p>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: 'Countries named', value: data.counts.countries.toLocaleString('en-US') },
              { label: 'Country mentions', value: data.counts.mentions.toLocaleString('en-US') },
              { label: 'Most named', value: data.countries[0]?.name ?? '-' },
              { label: 'Window', value: `${data.windowDays} days` },
            ].map((s) => (
              <div key={s.label} className="surface-card rounded-xl border border-line-1 px-4 py-3">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{s.label}</div>
                <div className="truncate text-xl font-semibold tabular-nums text-heading" title={s.value}>
                  {s.value}
                </div>
              </div>
            ))}
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(240px,1fr)]">
            <div className="surface-card rounded-xl border border-line-1 p-3">
              <OffseqMapChart
                counts={counts}
                max={max}
                selected={selected}
                onSelect={(name) => setSelected(name ? offseqCountryKey(name) : null)}
              />
              <div className="mt-1 flex flex-wrap items-center gap-3 text-[10px] text-muted">
                <span>fewer</span>
                {['#fda4af', '#fb7185', '#e11d48', '#be123c', '#9f1239'].map((colour) => (
                  <span key={colour} className="inline-flex items-center gap-1">
                    <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: colour }} />
                  </span>
                ))}
                <span>more · peak {max}</span>
              </div>
            </div>

            <div className="space-y-3">
              <div className="surface-card rounded-xl border border-line-1 p-3">
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
                  Countries by threat count
                </div>
                <ol className="space-y-1.5">
                  {ranked.map((c) => (
                    <li key={c.name}>
                      <button
                        type="button"
                        onClick={() =>
                          setSelected((prev) => (prev === offseqCountryKey(c.name) ? null : offseqCountryKey(c.name)))
                        }
                        className={`block w-full rounded px-1.5 py-1 text-left transition-colors ${
                          selected === offseqCountryKey(c.name) ? 'bg-rose-500/10' : 'hover:bg-surface-100'
                        }`}
                      >
                        <span className="flex items-center justify-between gap-2 text-[11px]">
                          <span className="truncate text-heading">{c.name}</span>
                          <span className="font-mono tabular-nums text-muted">{c.count}</span>
                        </span>
                        <span className="mt-1 block h-1 overflow-hidden rounded-full bg-surface-2">
                          <span
                            className="block h-full rounded-full bg-rose-500"
                            style={{ width: `${Math.max(3, (c.count / max) * 100)}%` }}
                          />
                        </span>
                      </button>
                    </li>
                  ))}
                </ol>
              </div>

              {selectedCountry && (
                <div className="surface-card rounded-xl border border-line-1 p-3 text-[11px]">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="font-bold text-heading">{selectedCountry.name}</span>
                    <span className="font-mono tabular-nums text-rose-600 dark:text-rose-400">
                      {selectedCountry.count} threats
                    </span>
                  </div>
                  <div className="space-y-2">
                    <Breakdown label="Severity" values={selectedCountry.severityBreakdown} />
                    <Breakdown label="Type" values={selectedCountry.typeBreakdown} />
                  </div>
                  {selectedCountry.latestThreat && (
                    <p className="mt-2 text-[10px] text-muted">latest: {relativeAgo(selectedCountry.latestThreat)}</p>
                  )}
                </div>
              )}
            </div>
          </div>

          <section aria-labelledby="offseq-map-recent">
            <h3 id="offseq-map-recent" className="mb-2 text-sm font-bold text-heading">
              Recent threats with country attribution
            </h3>
            <ul className="divide-y divide-line-1 rounded-xl border border-line-1">
              {data.recentThreats.map((t) => (
                <li key={t.slug ?? t.title} className="px-3 py-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] text-muted">{t.source}</span>
                    {t.severity && (
                      <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-[10px] text-body">
                        {t.severity}
                      </span>
                    )}
                    {t.cvssScore != null && (
                      <span className="font-mono text-[10px] text-muted">CVSS {t.cvssScore}</span>
                    )}
                    <span className="ml-auto font-mono text-[10px] text-muted">
                      {t.publishedDate ? relativeAgo(t.publishedDate) : ''}
                    </span>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2">
                    {t.url && (
                      <a
                        href={t.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-semibold text-heading hover:text-rose-600 dark:hover:text-rose-400"
                      >
                        {t.title} <ExternalLink size={10} />
                      </a>
                    )}
                    {t.cveId && (
                      <span className="font-mono text-[10px] text-rose-600 dark:text-rose-400">{t.cveId}</span>
                    )}
                  </div>
                  {t.countries.length > 0 && (
                    <div className="mt-0.5 font-mono text-[10px] text-muted">{t.countries.slice(0, 8).join(' · ')}</div>
                  )}
                </li>
              ))}
            </ul>
          </section>

          <div className="border-t border-line-1 pt-3 text-[11px] leading-relaxed text-muted">
            Source: <strong className="text-body">OffSeq Threat Radar</strong> (radar.offseq.com/map) · {data.license} ·
            snapshot {relativeAgo(data.syncedAt)} · © 2026 SEQ SIA. Country names and counts are verbatim upstream
            values.
          </div>
        </>
      )}
    </div>
  );
}
