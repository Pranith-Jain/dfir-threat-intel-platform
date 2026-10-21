import { useEffect, useMemo } from 'react';
import { MapContainer, TileLayer, Marker, Popup, ZoomControl, useMap } from 'react-leaflet';
import L from 'leaflet';
import { DARK_TILE_CLASS, TILE_ATTRIBUTION, TILE_SUBDOMAINS, TILE_URL } from '../../lib/basemap-tiles';
import 'leaflet/dist/leaflet.css';

const CATEGORY_COLORS: Record<string, string> = {
  'Energy & Power': '#f59e0b',
  Telecom: '#3b82f6',
  'Oil & Gas': '#78716c',
  Water: '#06b6d4',
  Aviation: '#8b5cf6',
  Maritime: '#0ea5e9',
  'Rail & Transit': '#6366f1',
  Structures: '#64748b',
  Industrial: '#78716c',
  Military: '#ef4444',
  Government: '#10b981',
  Healthcare: '#ec4899',
  Education: '#f97316',
  Culture: '#a855f7',
  Tourism: '#14b8a6',
  Religious: '#eab308',
  Historic: '#a3a3a3',
  Agriculture: '#22c55e',
  Services: '#6366f1',
  Emergency: '#dc2626',
  'Cable Transport': '#0ea5e9',
  Monitoring: '#64748b',
  Community: '#10b981',
};

function markerIcon(color: string, size = 10): L.DivIcon {
  return L.divIcon({
    className: 'infra-pin',
    html: `<span style="display:block;width:${size}px;height:${size}px;border-radius:50%;background:${color};border:2px solid #fff;box-shadow:0 1px 3px rgba(0,0,0,.4);"></span>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

function FitBounds({ bbox }: { bbox: [number, number, number, number] }) {
  const map = useMap();
  useEffect(() => {
    const [s, w, n, e] = bbox;
    map.fitBounds(
      [
        [s, w],
        [n, e],
      ],
      { padding: [30, 30], maxZoom: 12 }
    );
  }, [map, bbox]);
  return null;
}

function GlobalView() {
  const map = useMap();
  useEffect(() => {
    map.setView([20, 0], 2);
  }, [map]);
  return null;
}

function MapControls({ onToggleDark }: { onToggleDark: () => void }) {
  const map = useMap();
  return (
    <div className="absolute top-2 right-2 z-[1000] flex gap-1">
      <button
        onClick={() => map.setView([20, 0], 2)}
        className="bg-surface-100 border border-line-1 rounded px-2 py-1 text-xs font-mono shadow hover:bg-surface-200 dark:hover:bg-surface-300"
        title="Reset to global view"
      >
        Globe
      </button>
      <button
        onClick={onToggleDark}
        className="bg-surface-100 border border-line-1 rounded px-2 py-1 text-xs font-mono shadow hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
        title="Toggle dark map tiles"
      >
        Tiles
      </button>
    </div>
  );
}

function CategoryLegend({ categories }: { categories: string[] }) {
  if (categories.length === 0) return null;
  return (
    <div className="absolute bottom-2 left-2 z-[1000] bg-surface-100/90 backdrop-blur rounded-xl border border-line-1 p-2 max-w-[200px] max-h-[180px] overflow-y-auto">
      <div className="text-micro font-mono font-semibold text-muted mb-1">Legend</div>
      {categories.map((cat) => (
        <div key={cat} className="flex items-center gap-1.5 text-micro font-mono text-muted py-0.5">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CATEGORY_COLORS[cat] ?? '#6366f1' }} />
          <span className="truncate">{cat}</span>
        </div>
      ))}
    </div>
  );
}

interface MapResult {
  id: string;
  name: string;
  lat: number;
  lon: number;
  category: string;
  tags: Record<string, string>;
}

export default function InfraMap({
  results,
  bbox,
  global,
  darkTiles,
  onToggleDark,
}: {
  results: MapResult[];
  bbox?: [number, number, number, number] | null;
  global?: boolean;
  darkTiles?: boolean;
  onToggleDark?: () => void;
}) {
  const center = useMemo(() => {
    if (bbox) {
      const [s, w, n, e] = bbox;
      return [(s + n) / 2, (w + e) / 2] as [number, number];
    }
    if (results.length > 0 && !global) {
      return [results[0]!.lat, results[0]!.lon] as [number, number];
    }
    return [20, 0] as [number, number];
  }, [bbox, results, global]);

  const zoom = global ? 2 : bbox ? undefined : results.length > 0 ? 5 : 2;

  const uniqueCategories = useMemo(() => {
    const seen = new Set<string>();
    return results
      .filter((r) => {
        if (seen.has(r.category)) return false;
        seen.add(r.category);
        return true;
      })
      .map((r) => r.category);
  }, [results]);

  // Carto's dark basemap now requires an API key, and an unauthenticated
  // request returns a gray "API KEY REQUIRED" watermark tile rather than
  // failing — so the dark map rendered as a gray box. The keyless OSM
  // standard layer is used for both themes, and the dark one is produced
  // with a CSS filter on the tile pane.
  const tileUrl = TILE_URL;
  const tileAttribution = TILE_ATTRIBUTION;

  return (
    <MapContainer
      center={center}
      zoom={zoom}
      style={{ height: '100%', width: '100%' }}
      scrollWheelZoom={true}
      zoomControl={false}
      // The dark toggle now switches the tile filter rather than the tile
      // provider — both themes use the same keyless OSM layer.
      className={darkTiles ? DARK_TILE_CLASS : ''}
    >
      <TileLayer attribution={tileAttribution} url={tileUrl} subdomains={TILE_SUBDOMAINS} maxZoom={19} />
      <ZoomControl position="topleft" />
      {onToggleDark && <MapControls onToggleDark={onToggleDark} />}
      {global && <GlobalView />}
      {bbox && !global && <FitBounds bbox={bbox} />}
      {results.map((r) => (
        <Marker key={r.id} position={[r.lat, r.lon]} icon={markerIcon(CATEGORY_COLORS[r.category] ?? '#6366f1')}>
          <Popup maxWidth={280} minWidth={180}>
            <div className="text-sm font-sans">
              <div className="font-semibold text-heading">{r.name}</div>
              <div className="text-xs text-muted mt-0.5">{r.category}</div>
              <div className="text-mini font-mono text-muted mt-1">
                {r.lat.toFixed(5)}, {r.lon.toFixed(5)}
              </div>
              {r.tags.operator && (
                <div className="text-mini text-muted mt-1">
                  <span className="text-muted">Operator:</span> {r.tags.operator}
                </div>
              )}
              {r.tags.man_made && (
                <div className="text-mini text-muted">
                  <span className="text-muted">Type:</span> {r.tags.man_made}
                </div>
              )}
              {r.tags.amenity && (
                <div className="text-mini text-muted">
                  <span className="text-muted">Amenity:</span> {r.tags.amenity}
                </div>
              )}
              {r.tags.website && (
                <a
                  href={r.tags.website}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-mini text-brand-600 hover:underline mt-1 block transition-colors"
                >
                  Website ↗
                </a>
              )}
            </div>
          </Popup>
        </Marker>
      ))}
      <CategoryLegend categories={uniqueCategories} />
    </MapContainer>
  );
}
