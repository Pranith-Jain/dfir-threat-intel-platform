/* eslint-disable @typescript-eslint/no-restricted-imports -- react-simple-maps: small inner chart; same exception as OsintMapChart */
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { offseqCountryKey } from '../../lib/offseq-country';

const WORLD_TOPO_URL = '/world-110m.json';

function colourFor(count: number, max: number): string {
  if (!count) return '#1e293b';
  const ratio = count / Math.max(max, 1);
  if (ratio >= 0.7) return '#9f1239';
  if (ratio >= 0.4) return '#be123c';
  if (ratio >= 0.2) return '#e11d48';
  if (ratio >= 0.08) return '#fb7185';
  return '#fda4af';
}

interface OffseqMapChartProps {
  counts: Map<string, number>;
  max: number;
  selected: string | null;
  onSelect: (name: string | null) => void;
}

export default function OffseqMapChart({ counts, max, selected, onSelect }: OffseqMapChartProps): JSX.Element {
  return (
    <ComposableMap
      projection="geoMercator"
      projectionConfig={{ scale: 140 }}
      width={900}
      height={460}
      style={{ width: '100%', height: 'auto' }}
    >
      <Geographies geography={WORLD_TOPO_URL}>
        {({ geographies }) =>
          geographies.map((geo) => {
            const topoName = (geo.properties as { name?: string } | null)?.name ?? '';
            const key = offseqCountryKey(topoName);
            const count = counts.get(key) ?? 0;
            const isSelected = key === offseqCountryKey(selected ?? '');
            return (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill={isSelected ? '#fbbf24' : colourFor(count, max)}
                stroke={isSelected ? '#fbbf24' : 'rgb(var(--surface-100, #0f172a))'}
                strokeWidth={isSelected ? 1.5 : 0.4}
                onClick={() => onSelect(isSelected ? null : topoName)}
                style={{
                  default: { outline: 'none', transition: 'fill 0.15s' },
                  hover: { outline: 'none', fill: '#fbbf24', cursor: 'pointer' },
                  pressed: { outline: 'none' },
                }}
              />
            );
          })
        }
      </Geographies>
    </ComposableMap>
  );
}
