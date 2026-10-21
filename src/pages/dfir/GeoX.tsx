/**
 * GeoX — geolocation-scoped X (Twitter) search queries.
 *
 * `/dfir/geox`
 *
 * X's `geocode:` operator searches posts whose author location falls inside
 * a circle. It is one of the few ways to narrow a social firehose to a
 * physical place, and it is under-used because the syntax is fiddly: the
 * radius is in kilometres, the coordinate order is `lat,lon`, and the filter
 * operators have to be appended *after* the geocode term or X ignores them.
 *
 * This tool does the fiddly part. Pick a point on the map (or search an
 * address), set a radius, and it emits the four ready-to-run query URLs:
 * everything, media, images and native video.
 *
 * ## A note on what this can and cannot do
 *
 * `geocode:` matches the **profile location** an author set, not the device
 * they posted from. That is a meaningful limitation: a user who left their
 * location as "London" appears in a London search from anywhere, and a user
 * who cleared it appears in none. The tool surfaces this caveat rather than
 * letting the analyst assume the posts are physically located where the
 * circle is.
 *
 * Everything runs client-side. The only network call is the Nominatim
 * geocoder, which the browser calls directly under its usage policy.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Check, Copy, Crosshair, Globe, MapPin, Minus, Plus, Search } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useClientComponent } from '../../lib/use-client-component';
import type { LeafletMapProps } from '../../components/threatintel/LeafletMap';
import { Card } from '../../components/ui/Card';

interface LatLng {
  lat: number;
  lng: number;
}

interface GeocodeResult {
  display_name: string;
  lat: string;
  lon: string;
}

const MIN_RADIUS_KM = 1;
const MAX_RADIUS_KM = 50;
const DEFAULT_RADIUS_KM = 5;

/** The four X search variants the tool emits. */
const FILTERS = [
  { id: 'all', label: 'All posts', suffix: '' },
  { id: 'media', label: 'Media', suffix: ' filter:media' },
  { id: 'images', label: 'Images', suffix: ' filter:images' },
  { id: 'videos', label: 'Native video', suffix: ' filter:native_video' },
] as const;

/**
 * The map is loaded on the client only.
 *
 * Leaflet touches `window` when its module is evaluated, and the SSR entry
 * awaits every Suspense boundary (`stream.allReady`), so even a lazily
 * imported Leaflet module is evaluated on the server and throws there. A
 * `useEffect` never runs on the server, so the module is never evaluated
 * there — the server renders the placeholder below and the client mounts
 * the real map once the chunk lands.
 */
const loadLeafletMap = () => import('../../components/threatintel/LeafletMap');

export default function GeoX(): JSX.Element {
  const [point, setPoint] = useState<LatLng>({ lat: 19.4326, lng: -99.1332 });
  const [radius, setRadius] = useState(DEFAULT_RADIUS_KM);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<GeocodeResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const LeafletMap = useClientComponent<LeafletMapProps>(loadLeafletMap);
  const [showResults, setShowResults] = useState(false);
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The geocode operator takes `lat,lon`; Leaflet calls the second field
  // `lng`. Converting at the one place the query is built keeps the rest of
  // the component in Leaflet's vocabulary.
  const geocode = useMemo(() => `geocode:${point.lat.toFixed(6)},${point.lng.toFixed(6)},${radius}km`, [point, radius]);

  const queries = useMemo(
    () =>
      FILTERS.map((f) => ({
        ...f,
        query: `${geocode}${f.suffix}`,
        url: `https://x.com/search?q=${encodeURIComponent(`${geocode}${f.suffix}`)}&src=typed_query&f=live`,
      })),
    [geocode]
  );

  const onPick = useCallback((lat: number, lon: number) => {
    setPoint({ lat: Number(lat.toFixed(6)), lng: Number(lon.toFixed(6)) });
  }, []);

  /**
   * Address lookup through Nominatim.
   *
   * Nominatim's usage policy requires an identifying User-Agent and caps
   * the request rate; the browser cannot set a User-Agent, so the request
   * is debounced (300 ms) and only fires once the query is long enough to
   * be worth a round trip.
   */
  const runSearch = useCallback(async (text: string) => {
    if (text.trim().length < 3) {
      setResults([]);
      setSearchError(null);
      return;
    }
    setSearching(true);
    setSearchError(null);
    try {
      const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
        text.trim()
      )}&addressdetails=1&limit=8`;
      const res = await fetch(url, { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error(`geocoder returned ${res.status}`);
      const json = (await res.json()) as GeocodeResult[];
      setResults(Array.isArray(json) ? json : []);
      setShowResults(json.length > 0);
    } catch (e) {
      setSearchError(e instanceof Error ? e.message : 'geocoder failed');
      setResults([]);
    } finally {
      setSearching(false);
    }
  }, []);

  useEffect(() => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => void runSearch(query), 300);
    return () => {
      if (searchTimer.current) clearTimeout(searchTimer.current);
    };
  }, [query, runSearch]);

  const copy = useCallback(async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      setCopied(null);
    }
  }, []);

  const useMyLocation = useCallback(() => {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => onPick(pos.coords.latitude, pos.coords.longitude),
      () => {
        /* denied or unavailable — the map click path still works */
      },
      { enableHighAccuracy: false, timeout: 8000 }
    );
  }, [onPick]);

  return (
    <DataPageLayout
      backTo="/dfir/catalog"
      icon={<Globe size={28} />}
      title="GeoX"
      description="Build X (Twitter) search queries scoped to a place — pick a point, set a radius, copy the query."
      maxWidthClass="max-w-7xl"
    >
      <div className="grid gap-5 lg:grid-cols-[1fr_22rem]">
        {/* ── Map ──────────────────────────────────────────────────────── */}
        <Card padding="none" radius="panel">
          <div className="relative h-[52vh] min-h-[22rem] w-full overflow-hidden rounded-panel sm:h-[30rem]">
            {LeafletMap ? (
              <LeafletMap
                center={point}
                zoom={12}
                circleRadiusKm={radius}
                onPick={onPick}
                markers={[
                  {
                    id: 'origin',
                    lat: point.lat,
                    lng: point.lng,
                    radius: 7,
                    color: '#6366f1',
                    fillColor: '#6366f1',
                    fillOpacity: 0.9,
                    weight: 2,
                  },
                ]}
              />
            ) : (
              <div className="flex h-full w-full items-center justify-center bg-surface-200">
                <span className="font-mono text-micro text-muted">Loading the map…</span>
              </div>
            )}

            {/* Radius control */}
            <div className="absolute right-3 top-3 z-[1000] flex flex-col overflow-hidden rounded border border-line-1 bg-surface-100 shadow-lg">
              <button
                type="button"
                onClick={() => setRadius((r) => Math.min(MAX_RADIUS_KM, r + 1))}
                disabled={radius >= MAX_RADIUS_KM}
                aria-label="Increase radius"
                className="flex min-h-[44px] min-w-[44px] items-center justify-center px-3 py-2 text-muted hover:bg-surface-300 hover:text-heading disabled:opacity-40"
              >
                <Plus size={14} />
              </button>
              <span className="border-y border-line-1 px-2.5 py-1 text-center font-mono text-micro text-heading">
                {radius} km
              </span>
              <button
                type="button"
                onClick={() => setRadius((r) => Math.max(MIN_RADIUS_KM, r - 1))}
                disabled={radius <= MIN_RADIUS_KM}
                aria-label="Decrease radius"
                className="flex min-h-[44px] min-w-[44px] items-center justify-center px-3 py-2 text-muted hover:bg-surface-300 hover:text-heading disabled:opacity-40"
              >
                <Minus size={14} />
              </button>
            </div>
          </div>
        </Card>

        {/* ── Controls ─────────────────────────────────────────────────── */}
        <div className="space-y-4">
          <Card padding="md" radius="panel">
            <label
              htmlFor="geox-address"
              className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
            >
              Find an address
            </label>
            <div className="relative">
              <Search
                size={14}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                aria-hidden="true"
              />
              <input
                id="geox-address"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. Paseo de la Reforma 222"
                spellCheck={false}
                className="w-full rounded border border-line-1 bg-surface-100 py-2 pl-9 pr-3 text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
              />
            </div>

            {searching && <p className="mt-2 font-mono text-micro text-muted">Searching…</p>}
            {searchError && (
              <p role="alert" className="mt-2 font-mono text-micro text-rose-600 dark:text-rose-400">
                {searchError}
              </p>
            )}
            {showResults && results.length > 0 && (
              <ul className="mt-2 max-h-48 overflow-y-auto">
                {results.map((r, i) => (
                  <li key={`${r.lat},${r.lon},${i}`}>
                    <button
                      type="button"
                      onClick={() => {
                        onPick(Number(r.lat), Number(r.lon));
                        setShowResults(false);
                      }}
                      className="w-full truncate rounded px-2 py-1.5 text-left text-tool text-heading hover:bg-surface-300"
                    >
                      <MapPin size={11} className="mr-1 inline text-muted" aria-hidden="true" />
                      {r.display_name}
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <div className="mt-3 flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={useMyLocation}
                className="inline-flex items-center gap-1.5 rounded border border-line-1 px-2.5 py-1.5 font-mono text-micro text-muted hover:border-brand-500/40"
              >
                <Crosshair size={12} /> Use my location
              </button>
              <span className="font-mono text-micro text-muted">
                {point.lat.toFixed(4)}, {point.lng.toFixed(4)}
              </span>
            </div>
          </Card>

          <Card padding="md" radius="panel">
            <h2 className="mb-3 font-display text-base font-semibold text-heading">X search queries</h2>
            <ul className="space-y-2.5">
              {queries.map((q) => (
                <li key={q.id}>
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="font-mono text-micro uppercase tracking-wider text-muted">{q.label}</span>
                    <button
                      type="button"
                      onClick={() => void copy(q.id, q.query)}
                      className="inline-flex min-h-[32px] items-center gap-1 rounded border border-line-1 px-2 py-1 font-mono text-micro text-muted hover:border-brand-500/40"
                    >
                      {copied === q.id ? <Check size={11} /> : <Copy size={11} />}
                      {copied === q.id ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <code className="block break-all rounded border border-line-1 bg-surface-100 px-2.5 py-1.5 font-mono text-micro text-heading">
                    {q.query}
                  </code>
                  <a
                    href={q.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="mt-1 inline-block font-mono text-micro text-brand-600 hover:underline dark:text-brand-400"
                  >
                    Open in X →
                  </a>
                </li>
              ))}
            </ul>
          </Card>

          <Card padding="sm" radius="panel">
            <p className="text-micro leading-relaxed text-muted">
              <strong className="text-tool">What `geocode:` actually matches.</strong> It searches the
              <em> profile location</em> an author set, not the device they posted from. A user who left their location
              as &ldquo;London&rdquo; appears in a London search from anywhere; a user who cleared it appears in none.
              Treat the result as a lead, not a location fix.
            </p>
          </Card>
        </div>
      </div>
    </DataPageLayout>
  );
}
