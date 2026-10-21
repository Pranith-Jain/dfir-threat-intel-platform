/**
 * Basemap tiles.
 *
 * ## Why this exists
 *
 * Both map components used to pull Carto's `basemaps.cartocdn.com/dark_all`
 * tiles. Carto now requires an API key for that endpoint, and an
 * unauthenticated request does not fail — it returns a 256×256 gray PNG
 * with "API KEY REQUIRED" written across it. The maps therefore rendered as
 * a gray box with a watermark, at every zoom level, on every page that has
 * a map. No error, no broken-image icon, no console message: just a map that
 * was not a map.
 *
 * The replacement is OpenStreetMap's standard tile layer, which is free,
 * needs no key, and has a published usage policy that covers a site of
 * this size. It is a light basemap, so the dark theme is produced with a
 * CSS filter on the tile pane — the standard technique for putting OSM
 * tiles behind a dark UI.
 *
 * If a keyed provider is ever wanted (Carto, MapTiler, Stadia), change
 * `TILE_URL` and drop the filter — that is the only thing that has to move.
 */

/** The OSM standard tile template. */
export const TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
export const TILE_SUBDOMAINS = 'abc';
export const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';
export const TILE_MAX_ZOOM = 19;

/**
 * CSS class that renders the light OSM tiles as a dark basemap.
 *
 * `invert` flips the light map to dark; the `hue-rotate` puts the blues
 * back where they belong (inverting turns water orange, and rotating the
 * hue 180° turns it back blue); the brightness/contrast trim keeps it from
 * looking flat.
 */
export const DARK_TILE_CLASS = 'leaflet-dark-tiles';
