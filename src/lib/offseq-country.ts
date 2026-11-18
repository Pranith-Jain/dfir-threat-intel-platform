/** Country-name normalization for the OffSeq 30-day country map.
 *
 * OffSeq uses common English country names; Natural Earth 110m (served from
 * /world-110m.json) uses a few longer forms. Keeping the mapping here avoids
 * exporting a helper from the chart component (Fast Refresh wants components
 * only) and gives the map + ranked list one shared notion of a country key.
 */
const TOPO_NAME_ALIASES: Record<string, string> = {
  'united states': 'United States of America',
  usa: 'United States of America',
  'united states of america': 'United States of America',
  uk: 'United Kingdom',
  'russian federation': 'Russia',
  'czech republic': 'Czechia',
};

export function offseqCountryKey(value: string): string {
  const key = value.trim().toLowerCase();
  return TOPO_NAME_ALIASES[key] ?? key;
}
