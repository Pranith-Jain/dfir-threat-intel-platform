/**
 * Client-only Leaflet map.
 *
 * Leaflet (and `react-leaflet`) touch `window` at module-evaluation time, so
 * importing either from a component that is server-rendered throws
 * `ReferenceError: window is not defined` during the prerender. The
 * prerender's ErrorBoundary catches it and the page still renders — but it
 * renders the *error* fallback instead of the page, which is a worse
 * first paint than a map placeholder.
 *
 * So all Leaflet usage lives in this one module, and pages reach it through
 * `lazy()` + `<Suspense>`. The server renders the Suspense fallback (a
 * skeleton panel); the client loads the chunk and mounts the real map.
 *
 * The props are deliberately plain data rather than Leaflet elements, so
 * the pages that use this never import Leaflet themselves.
 */

import { useEffect, useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Circle, Popup, useMap, useMapEvents } from 'react-leaflet';
import 'leaflet';
import 'leaflet/dist/leaflet.css';

export interface LeafletMarkerSpec {
  /** Stable key for React and for the popup. */
  id: string;
  lat: number;
  lng: number;
  /** Lines rendered in the popup. */
  popup?: string[];
  /** Circle radius in pixels. Omit for a plain pin. */
  radius?: number;
  color?: string;
  fillColor?: string;
  fillOpacity?: number;
  weight?: number;
}

export interface LeafletMapProps {
  center: { lat: number; lng: number };
  zoom: number;
  minZoom?: number;
  maxZoom?: number;
  markers?: LeafletMarkerSpec[];
  /** Radius circle, in kilometres, drawn around `center`. */
  circleRadiusKm?: number;
  circleColor?: string;
  /** Called with the clicked coordinates. */
  onPick?: (lat: number, lng: number) => void;
  /** Change this to re-centre the map on `center`. */
  recenterKey?: string;
  className?: string;
}

/** Move the map when `center` changes. */
function Recenter({ lat, lng, zoom }: { lat: number; lng: number; zoom: number }): null {
  const map = useMap();
  useEffect(() => {
    map.setView([lat, lng], zoom);
  }, [map, lat, lng, zoom]);
  return null;
}

/** Capture clicks on the map and turn them into coordinates. */
function ClickCapture({ onPick }: { onPick: (lat: number, lng: number) => void }): null {
  useMapEvents({
    click: (e) => onPick(e.latlng.lat, e.latlng.lng),
  });
  return null;
}

export default function LeafletMap({
  center,
  zoom,
  minZoom,
  maxZoom,
  markers = [],
  circleRadiusKm,
  circleColor = '#818cf8',
  onPick,
  className,
}: LeafletMapProps): JSX.Element {
  const style = useMemo(() => ({ height: '100%', width: '100%', background: '#0b1220' }), []);

  return (
    <MapContainer
      center={[center.lat, center.lng]}
      zoom={zoom}
      minZoom={minZoom}
      maxZoom={maxZoom}
      scrollWheelZoom
      style={style}
      className={className}
    >
      <TileLayer
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> &copy; <a href="https://carto.com/">CARTO</a>'
        subdomains="abcd"
        maxZoom={20}
      />
      {onPick && <ClickCapture onPick={onPick} />}
      <Recenter lat={center.lat} lng={center.lng} zoom={zoom} />

      {circleRadiusKm !== undefined && circleRadiusKm > 0 && (
        <Circle
          center={[center.lat, center.lng]}
          radius={circleRadiusKm * 1000}
          pathOptions={{ color: circleColor, weight: 1.5, fillColor: circleColor, fillOpacity: 0.12 }}
        />
      )}

      {markers.map((m) => {
        // Hoisted so the narrowing survives into the callback below.
        const popup = m.popup ?? [];
        return (
          <CircleMarker
            key={m.id}
            center={[m.lat, m.lng]}
            radius={m.radius ?? 6}
            pathOptions={{
              color: m.color ?? '#e11d48',
              weight: m.weight ?? 1,
              fillColor: m.fillColor ?? m.color ?? '#e11d48',
              fillOpacity: m.fillOpacity ?? 0.5,
            }}
          >
            {popup.length > 0 && (
              <Popup>
                {popup.map((line, i) => (
                  <span key={i}>
                    {i === 0 ? <strong>{line}</strong> : line}
                    {i < popup.length - 1 && <br />}
                  </span>
                ))}
              </Popup>
            )}
          </CircleMarker>
        );
      })}
    </MapContainer>
  );
}
