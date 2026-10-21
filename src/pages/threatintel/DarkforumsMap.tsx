/**
 * DarkForums IP Intelligence Map.
 *
 * `/threatintel/darkforums-ip`
 *
 * Forum IP/actor observations plotted by country, with an actor search that
 * shows the infrastructure behind a handle.
 *
 * ## Why the map is country-level
 *
 * The upstream dataset is geolocated with GeoLite2-Country, so it never had
 * better than a country centroid to offer. Points are scattered around that
 * centroid — deterministically, from a hash of the observation, so a point
 * stays where it was between reloads.
 *
 * ## Why each country loads separately
 *
 * 119k observations across 186 countries. One file with all of them would be
 * a ~7 MB download the browser then has to render as markers. The country
 * files are fetched on demand and capped at 5,000 points each, so the map
 * always has something to draw and always says when it is showing a subset.
 */

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Globe2, MapPin, Search, Server, Users } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Card } from '../../components/ui/Card';
import { StatCards } from '../../components/ui/StatCards';
import { useApiData } from '../../hooks/useApiData';
import { useClientComponent } from '../../lib/use-client-component';
import type { LeafletMapProps, LeafletMarkerSpec } from '../../components/threatintel/LeafletMap';

interface Country {
  iso: string;
  name: string;
  lat: number;
  lon: number;
  observations: number;
  actors: number;
  unique_ips: number;
}

interface Actor {
  username: string;
  ip_count: number;
  country_count: number;
  countries: Array<{ iso: string; count: number }>;
  ips: Array<{ ip: string; iso: string }>;
  ips_truncated: boolean;
}

interface IndexResponse {
  source: string;
  source_url: string;
  license: string;
  geo_source: string;
  synced_at: string;
  counts: {
    observations: number;
    unique_ips: number;
    actors: number;
    countries: number;
    unattributed: number;
    skipped_posts: number;
  };
  countries: Country[];
  top_actors: Actor[];
}

interface CountryResponse {
  iso: string;
  name: string;
  lat: number;
  lon: number;
  total: number;
  shown: number;
  truncated: boolean;
  actors: number;
  points: Array<{ ip: string; username: string; lat: number; lon: number }>;
}

interface ActorResponse {
  query: string;
  total: number;
  matches: Actor[];
}

const PIN_COLOR = '#e11d48';

/**
 * The map is loaded on the client only.
 *
 * Leaflet touches `window` when its module is evaluated, and the SSR entry
 * awaits every Suspense boundary (`stream.allReady`), so even a lazily
 * imported Leaflet module is evaluated on the server and throws there. A
 * `useEffect` never runs on the server, so the module is never evaluated
 * there — the server renders the placeholder and the client mounts the real
 * map once the chunk lands.
 */
const loadLeafletMap = () => import('../../components/threatintel/LeafletMap');

export default function DarkforumsMap(): JSX.Element {
  const [selected, setSelected] = useState<string | null>(null);
  const [actorQuery, setActorQuery] = useState('');
  const [actorSearch, setActorSearch] = useState('');
  const LeafletMap = useClientComponent<LeafletMapProps>(loadLeafletMap);

  const {
    data: index,
    loading,
    error,
    refetch,
  } = useApiData<IndexResponse>('/api/v1/threat-intel/darkforums-ip', { ttl: 300_000 });

  const countryUrl = selected ? `/api/v1/threat-intel/darkforums-ip/country/${selected}` : null;
  const { data: country } = useApiData<CountryResponse>(countryUrl, { ttl: 300_000 });

  const actorUrl = actorSearch
    ? `/api/v1/threat-intel/darkforums-ip/actors?q=${encodeURIComponent(actorSearch)}&limit=30`
    : null;
  const { data: actors } = useApiData<ActorResponse>(actorUrl, { ttl: 300_000 });

  useEffect(() => {
    const t = setTimeout(() => setActorSearch(actorQuery.trim()), 300);
    return () => clearTimeout(t);
  }, [actorQuery]);

  const countryByIso = useMemo(() => {
    const map = new Map<string, Country>();
    for (const c of index?.countries ?? []) map.set(c.iso, c);
    return map;
  }, [index]);

  /**
   * The marker list for the map.
   *
   * One bubble per country, sized by observation count and ringed in white
   * when selected, plus one small dot per observation in the selected
   * country. Both are plain data — the Leaflet component lives behind a lazy
   * import so it is never evaluated on the server.
   */
  const mapMarkers = useMemo(() => {
    const markers: LeafletMarkerSpec[] = (index?.countries ?? []).map((c) => ({
      id: `c-${c.iso}`,
      lat: c.lat,
      lng: c.lon,
      radius: Math.max(4, Math.min(22, Math.sqrt(c.observations) / 2)),
      color: c.iso === selected ? '#fff' : PIN_COLOR,
      weight: c.iso === selected ? 2 : 1,
      fillColor: PIN_COLOR,
      fillOpacity: c.iso === selected ? 0.85 : 0.45,
      popup: [
        c.name,
        `${c.observations.toLocaleString()} observations`,
        `${c.actors.toLocaleString()} actors · ${c.unique_ips.toLocaleString()} IPs`,
      ],
    }));
    for (const p of country?.points ?? []) {
      markers.push({
        id: `p-${p.ip}-${p.username}`,
        lat: p.lat,
        lng: p.lon,
        radius: 2.5,
        color: '#fbbf24',
        weight: 0.5,
        fillColor: '#fbbf24',
        fillOpacity: 0.8,
        popup: [p.username, p.ip],
      });
    }
    return markers;
  }, [index, country, selected]);

  const stats = [
    { label: 'Observations', value: index?.counts.observations ?? 0, icon: <MapPin size={16} /> },
    { label: 'Unique IPs', value: index?.counts.unique_ips ?? 0, icon: <Server size={16} /> },
    { label: 'Actors', value: index?.counts.actors ?? 0, icon: <Users size={16} /> },
    { label: 'Countries', value: index?.counts.countries ?? 0, icon: <Globe2 size={16} /> },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Globe2 size={28} />}
      title="DarkForums IP Intelligence"
      description="IP addresses and usernames observed on a cybercrime forum, plotted by country — with per-actor infrastructure grouping."
      maxWidthClass="max-w-7xl"
    >
      <div className="space-y-5">
        {error && (
          <Card padding="md" radius="panel" tone="rose">
            <p role="alert" className="flex items-center gap-2 text-tool text-rose-600 dark:text-rose-400">
              <AlertTriangle size={15} /> {error}
            </p>
            <button
              type="button"
              onClick={refetch}
              className="mt-3 rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
            >
              Retry
            </button>
          </Card>
        )}

        {loading && (
          <div className="flex items-center justify-center py-12" role="status" aria-busy="true">
            <span className="font-mono text-meta text-muted">Loading the IP intelligence map…</span>
          </div>
        )}

        {index && !loading && (
          <>
            <StatCards cards={stats} />

            <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
              {/* ── Map ──────────────────────────────────────────────────── */}
              <Card padding="none" radius="panel" tone="rose">
                <div className="h-[28rem] w-full overflow-hidden rounded-panel">
                  {LeafletMap ? (
                    <LeafletMap
                      center={
                        selected && countryByIso.get(selected)
                          ? {
                              lat: countryByIso.get(selected)!.lat,
                              lng: countryByIso.get(selected)!.lon,
                            }
                          : { lat: 20, lng: 0 }
                      }
                      zoom={selected && countryByIso.get(selected) ? 4 : 2}
                      minZoom={2}
                      maxZoom={8}
                      markers={mapMarkers}
                    />
                  ) : (
                    <div className="flex h-full w-full items-center justify-center bg-surface-200">
                      <span className="font-mono text-micro text-muted">Loading the map…</span>
                    </div>
                  )}
                </div>
                {country && (
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line-1 px-4 py-2.5">
                    <p className="font-mono text-micro text-muted">
                      {country.name} — showing {country.shown.toLocaleString()} of {country.total.toLocaleString()}{' '}
                      observations
                      {country.truncated ? ' (capped)' : ''}
                    </p>
                    <button
                      type="button"
                      onClick={() => setSelected(null)}
                      className="rounded border border-line-1 px-2.5 py-1 font-mono text-micro text-muted hover:border-brand-500/40"
                    >
                      Clear selection
                    </button>
                  </div>
                )}
              </Card>

              {/* ── Country list ─────────────────────────────────────────── */}
              <Card padding="none" radius="panel" tone="rose">
                <div className="max-h-[28rem] overflow-y-auto">
                  <table className="w-full text-left">
                    <thead className="sticky top-0 bg-surface-200">
                      <tr className="border-b border-line-1">
                        {['Country', 'Obs', 'Actors'].map((h) => (
                          <th
                            key={h}
                            scope="col"
                            className="px-3 py-2 font-mono text-micro uppercase tracking-wider text-muted"
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(index.countries ?? []).map((c) => (
                        <tr
                          key={c.iso}
                          onClick={() => setSelected(c.iso === selected ? null : c.iso)}
                          className={`cursor-pointer border-b border-line-1 last:border-0 hover:bg-surface-300 ${
                            c.iso === selected ? 'bg-brand-500/10' : ''
                          }`}
                        >
                          <td className="px-3 py-1.5 text-tool">
                            <span className="font-mono text-micro text-muted">{c.iso}</span> {c.name}
                          </td>
                          <td className="px-3 py-1.5 font-mono text-micro text-muted">
                            {c.observations.toLocaleString()}
                          </td>
                          <td className="px-3 py-1.5 font-mono text-micro text-muted">{c.actors.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </div>

            {/* ── Actor search ────────────────────────────────────────── */}
            <Card padding="md" radius="panel" tone="rose">
              <div className="mb-3 flex flex-wrap items-end gap-3">
                <div className="min-w-[14rem] flex-1">
                  <label
                    htmlFor="df-actor"
                    className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
                  >
                    Find an actor
                  </label>
                  <div className="relative">
                    <Search
                      size={14}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                      aria-hidden="true"
                    />
                    <input
                      id="df-actor"
                      value={actorQuery}
                      onChange={(e) => setActorQuery(e.target.value)}
                      placeholder="username"
                      spellCheck={false}
                      className="w-full rounded border border-line-1 bg-surface-100 py-2 pl-9 pr-3 font-mono text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                    />
                  </div>
                </div>
              </div>

              {actors && actors.matches.length === 0 && (
                <p className="text-meta text-muted">No actor matches “{actors.query}”.</p>
              )}

              {actors && actors.matches.length > 0 && (
                <div className="space-y-2">
                  <p className="font-mono text-micro text-muted">
                    {actors.total.toLocaleString()} actors match “{actors.query}”
                  </p>
                  {actors.matches.map((a) => (
                    <div key={a.username} className="rounded border border-line-1 bg-surface-100 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-tool text-heading">{a.username}</span>
                        <span className="font-mono text-micro text-muted">
                          {a.ip_count} IPs · {a.country_count} countries
                        </span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {a.countries.map((cc) => (
                          <span
                            key={cc.iso}
                            className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted"
                          >
                            {cc.iso} × {cc.count}
                          </span>
                        ))}
                      </div>
                      <details className="mt-2">
                        <summary className="cursor-pointer font-mono text-micro text-muted hover:text-heading">
                          Show {Math.min(a.ips.length, 25)} IPs
                        </summary>
                        <ul className="mt-1.5 grid gap-1 sm:grid-cols-2 lg:grid-cols-4">
                          {a.ips.slice(0, 25).map((ip) => (
                            <li key={ip.ip} className="font-mono text-micro text-muted">
                              {ip.ip} <span className="opacity-60">({ip.iso})</span>
                            </li>
                          ))}
                        </ul>
                        {a.ips_truncated && (
                          <p className="mt-1 font-mono text-micro text-muted">…and {a.ip_count - a.ips.length} more.</p>
                        )}
                      </details>
                    </div>
                  ))}
                </div>
              )}

              {!actorSearch && (
                <div>
                  <p className="mb-2 font-mono text-micro uppercase tracking-wider text-muted">Most active actors</p>
                  <ul className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                    {(index.top_actors ?? []).slice(0, 12).map((a) => (
                      <li key={a.username}>
                        <button
                          type="button"
                          onClick={() => setActorQuery(a.username)}
                          className="w-full rounded border border-line-1 bg-surface-100 px-2.5 py-1.5 text-left transition-colors hover:border-brand-500/40"
                        >
                          <span className="block truncate font-mono text-tool text-heading">{a.username}</span>
                          <span className="block font-mono text-micro text-muted">
                            {a.ip_count} IPs · {a.country_count} countries
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </Card>

            <p className="font-mono text-micro text-muted">
              Source: {index.source} · {index.license} · geolocation: {index.geo_source} ·{' '}
              {index.counts.unattributed.toLocaleString()} observations had no country match.
            </p>
          </>
        )}
      </div>
    </DataPageLayout>
  );
}
