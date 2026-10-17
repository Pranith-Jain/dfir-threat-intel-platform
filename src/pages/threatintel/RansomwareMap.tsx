import { Suspense, lazy, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { ClusterTabs, RANSOMWARE_TABS } from '../../components/threatintel/ClusterTabs';
import { Globe, Loader2, Pause, Play, RefreshCw, X, Skull } from 'lucide-react';
import { errMessage } from '../../lib/log';

const ThreatMapChart = lazy(() => import('../dfir/ThreatMapChart'));

interface RansomwareCountryAgg {
  country: string;
  countryCode: string;
  victim_count: number;
  groups: string[];
  top_victims: string[];
}

interface RansomwareMapResponse {
  generated_at: string;
  total_victims: number;
  total_countries: number;
  countries: RansomwareCountryAgg[];
}

const WORLD_TOPO_URL = '/world-110m.json';

const NUMERIC_TO_ALPHA2: Record<string, string> = {
  '004': 'AF',
  '008': 'AL',
  '012': 'DZ',
  '020': 'AD',
  '024': 'AO',
  '031': 'AZ',
  '032': 'AR',
  '036': 'AU',
  '040': 'AT',
  '044': 'BS',
  '048': 'BH',
  '050': 'BD',
  '051': 'AM',
  '052': 'BB',
  '056': 'BE',
  '060': 'BM',
  '064': 'BT',
  '068': 'BO',
  '070': 'BA',
  '072': 'BW',
  '076': 'BR',
  '084': 'BZ',
  '090': 'SB',
  '096': 'BN',
  '100': 'BG',
  '104': 'MM',
  '108': 'BI',
  '112': 'BY',
  '116': 'KH',
  '120': 'CM',
  '124': 'CA',
  '140': 'CF',
  '144': 'LK',
  '148': 'TD',
  '152': 'CL',
  '156': 'CN',
  '158': 'TW',
  '170': 'CO',
  '174': 'KM',
  '178': 'CG',
  '180': 'CD',
  '188': 'CR',
  '191': 'HR',
  '192': 'CU',
  '196': 'CY',
  '203': 'CZ',
  '204': 'BJ',
  '208': 'DK',
  '214': 'DO',
  '218': 'EC',
  '222': 'SV',
  '226': 'GQ',
  '231': 'ET',
  '232': 'ER',
  '233': 'EE',
  '242': 'FJ',
  '246': 'FI',
  '250': 'FR',
  '262': 'DJ',
  '266': 'GA',
  '268': 'GE',
  '270': 'GM',
  '276': 'DE',
  '288': 'GH',
  '300': 'GR',
  '320': 'GT',
  '324': 'GN',
  '328': 'GY',
  '332': 'HT',
  '340': 'HN',
  '344': 'HK',
  '348': 'HU',
  '352': 'IS',
  '356': 'IN',
  '360': 'ID',
  '364': 'IR',
  '368': 'IQ',
  '372': 'IE',
  '376': 'IL',
  '380': 'IT',
  '384': 'CI',
  '388': 'JM',
  '392': 'JP',
  '398': 'KZ',
  '400': 'JO',
  '404': 'KE',
  '408': 'KP',
  '410': 'KR',
  '414': 'KW',
  '417': 'KG',
  '418': 'LA',
  '422': 'LB',
  '426': 'LS',
  '428': 'LV',
  '430': 'LR',
  '434': 'LY',
  '440': 'LT',
  '442': 'LU',
  '450': 'MG',
  '454': 'MW',
  '458': 'MY',
  '462': 'MV',
  '466': 'ML',
  '470': 'MT',
  '478': 'MR',
  '484': 'MX',
  '496': 'MN',
  '498': 'MD',
  '499': 'ME',
  '504': 'MA',
  '508': 'MZ',
  '512': 'OM',
  '516': 'NA',
  '524': 'NP',
  '528': 'NL',
  '540': 'NC',
  '548': 'VU',
  '554': 'NZ',
  '558': 'NI',
  '562': 'NE',
  '566': 'NG',
  '578': 'NO',
  '586': 'PK',
  '591': 'PA',
  '598': 'PG',
  '600': 'PY',
  '604': 'PE',
  '608': 'PH',
  '616': 'PL',
  '620': 'PT',
  '624': 'GW',
  '626': 'TL',
  '630': 'PR',
  '634': 'QA',
  '642': 'RO',
  '643': 'RU',
  '646': 'RW',
  '682': 'SA',
  '686': 'SN',
  '688': 'RS',
  '694': 'SL',
  '702': 'SG',
  '703': 'SK',
  '704': 'VN',
  '705': 'SI',
  '706': 'SO',
  '710': 'ZA',
  '716': 'ZW',
  '724': 'ES',
  '728': 'SS',
  '729': 'SD',
  '740': 'SR',
  '748': 'SZ',
  '752': 'SE',
  '756': 'CH',
  '760': 'SY',
  '762': 'TJ',
  '764': 'TH',
  '768': 'TG',
  '776': 'TO',
  '780': 'TT',
  '784': 'AE',
  '788': 'TN',
  '792': 'TR',
  '795': 'TM',
  '800': 'UG',
  '804': 'UA',
  '807': 'MK',
  '818': 'EG',
  '826': 'GB',
  '834': 'TZ',
  '840': 'US',
  '854': 'BF',
  '858': 'UY',
  '860': 'UZ',
  '862': 'VE',
  '882': 'WS',
  '887': 'YE',
  '894': 'ZM',
};

function colourFor(count: number, max: number): string {
  if (count === 0 || max === 0) return '#1e293b';
  const intensity = Math.min(1, Math.log10(count + 1) / Math.log10(max + 1));
  const r = Math.round(180 + (245 - 180) * intensity);
  const g = Math.round(30 + (30 - 30) * intensity * 0.3);
  const b = Math.round(40 + (40 - 40) * (1 - intensity));
  return `rgb(${r}, ${g}, ${b})`;
}

const REFRESH_INTERVAL_MS = 300_000;

export default function RansomwareMap({ embedded = false }: { embedded?: boolean } = {}): JSX.Element {
  const [data, setData] = useState<RansomwareMapResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<{ alpha2: string; name: string } | null>(null);
  const [selected, setSelected] = useState<{ alpha2: string; name: string } | null>(null);
  const [globeView, setGlobeView] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const [nextRefreshIn, setNextRefreshIn] = useState(REFRESH_INTERVAL_MS / 1000);

  const loadRef = useRef<AbortController | null>(null);
  const load = async () => {
    loadRef.current?.abort();
    const ctrl = new AbortController();
    loadRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/ransomware-map', {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData((await r.json()) as RansomwareMapResponse);
    } catch (e) {
      console.error('RansomwareMap failed:', errMessage(e));
      if ((e as Error).name === 'AbortError') return;
      setError((e as Error).message);
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    loadRef.current = ctrl;
    void load();
    return () => ctrl.abort();
  }, []);

  useEffect(() => {
    if (!liveMode) return;
    const pollCtrl = new AbortController();
    setNextRefreshIn(REFRESH_INTERVAL_MS / 1000);
    const fetchTimer = window.setInterval(() => {
      if (document.visibilityState !== 'visible') return;
      void load();
      setNextRefreshIn(REFRESH_INTERVAL_MS / 1000);
    }, REFRESH_INTERVAL_MS);
    const countdownTimer = window.setInterval(() => {
      setNextRefreshIn((n) => Math.max(0, n - 1));
    }, 1000);
    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        void load();
        setNextRefreshIn(REFRESH_INTERVAL_MS / 1000);
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      pollCtrl.abort();
      window.clearInterval(fetchTimer);
      window.clearInterval(countdownTimer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [liveMode]);

  const countryByAlpha2 = useMemo(() => {
    const map = new Map<
      string,
      { country: string; countryCode: string; count: number; sources: Record<string, number>; sample_ips: string[] }
    >();
    if (data) {
      for (const c of data.countries) {
        map.set(c.countryCode, {
          country: c.country,
          countryCode: c.countryCode,
          count: c.victim_count,
          sources: {},
          sample_ips: c.top_victims,
        });
      }
    }
    return map;
  }, [data]);

  const aggByAlpha2 = useMemo(() => {
    const map = new Map<string, RansomwareCountryAgg>();
    if (data) {
      for (const c of data.countries) map.set(c.countryCode, c);
    }
    return map;
  }, [data]);

  const maxCount = data?.countries[0]?.victim_count ?? 0;
  const hoveredAgg = hovered ? aggByAlpha2.get(hovered.alpha2) : null;
  const selectedAgg = selected ? aggByAlpha2.get(selected.alpha2) : null;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Skull size={28} />}
      title="Ransomware Victim Map"
      description="Geographic distribution of ransomware victims aggregated from multiple trackers - Ransomlook, MyThreatIntel, ransomfeed.it, ransomwatch, ransomware.live, and Andrea Fortuna. Shaded by victim count per country."
      loading={loading && !data}
      error={error}
      maxWidthClass="max-w-6xl"
      accentClass="text-rose-600 dark:text-rose-400"
      headerExtra={
        !embedded && (
          <div className="mt-4">
            <ClusterTabs tabs={RANSOMWARE_TABS} ariaLabel="Ransomware intel" />
          </div>
        )
      }
      hideHeader={embedded}
      className={embedded ? '!py-4' : undefined}
    >
      {data && (
        <>
          {/* AI summary of the ransomware victim distribution by country.
              Public surface so every visitor sees the landscape take. */}
          {data.countries.length > 0 && (
            <AiSummaryCard
              surface="Ransomware victim map"
              items={data.countries.slice(0, 30).map((c) => ({
                title: c.country,
                body: `${c.victim_count} victims · groups: ${c.groups.join(', ')} · top: ${c.top_victims.slice(0, 5).join(', ')}`,
                source: c.country,
              }))}
              requireAdmin={false}
            />
          )}
          <header className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono text-muted mb-6">
            <span>
              <span className="text-heading text-base font-bold tabular-nums" aria-live="polite" aria-atomic="true">
                {data.total_victims}
              </span>{' '}
              victims
            </span>
            <span aria-hidden="true">·</span>
            <span>
              <span className="text-heading text-base font-bold tabular-nums">{data.total_countries}</span> countries
              affected
            </span>
            <span aria-hidden="true">·</span>
            <button
              type="button"
              onClick={() => setLiveMode((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border transition-colors ${
                liveMode
                  ? 'border-emerald-400/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'border-slate-300 dark:border-line-1 hover:border-rose-500/40'
              }`}
              aria-pressed={liveMode}
              title={liveMode ? 'Pause auto-refresh' : `Auto-refresh the map every ${REFRESH_INTERVAL_MS / 1000}s`}
            >
              {liveMode ? <Pause size={12} /> : <Play size={12} />}
              {liveMode ? (
                <>
                  <span className="hidden sm:inline">auto-refresh · next in </span>
                  <span className="tabular-nums">{nextRefreshIn}s</span>
                </>
              ) : (
                <>auto-refresh ({REFRESH_INTERVAL_MS / 1000 / 60}m)</>
              )}
            </button>
            <button
              type="button"
              onClick={() => setGlobeView((v) => !v)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border transition-colors ${
                globeView
                  ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-slate-300 dark:border-line-1 hover:border-rose-500/40'
              }`}
              aria-pressed={globeView}
            >
              <Globe size={12} />
              {globeView ? 'globe' : 'flat'}
            </button>
            <button
              type="button"
              onClick={() => void load()}
              disabled={loading}
              className="inline-flex items-center gap-1 hover:text-rose-600 dark:hover:text-rose-400 disabled:opacity-50"
              title="Refresh now"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> refresh
            </button>
          </header>

          <div className="grid lg:grid-cols-[1fr_280px] gap-6">
            <div
              className="rounded-xl border border-line-1 bg-surface-200 overflow-hidden relative"
              style={{ aspectRatio: '900 / 460', minHeight: 280 }}
            >
              <Suspense
                fallback={
                  <div className="flex items-center justify-center w-full h-full text-muted font-mono text-xs gap-2">
                    <Loader2 size={14} className="animate-spin" /> loading world map…
                  </div>
                }
              >
                <ThreatMapChart
                  topoUrl={WORLD_TOPO_URL}
                  numericToAlpha2={NUMERIC_TO_ALPHA2}
                  countryByAlpha2={countryByAlpha2}
                  maxCount={maxCount}
                  colourFor={colourFor}
                  onHover={setHovered}
                  onSelect={setSelected}
                  selectedAlpha2={selected?.alpha2 ?? null}
                  globeView={globeView}
                />
              </Suspense>
              {hoveredAgg && (
                <div className="absolute top-3 left-3 rounded-xl bg-surface-100/90 dark:bg-input-200/90 backdrop-blur px-3 py-2 text-xs font-mono text-slate-100 border border-rose-400/40 max-w-[240px]">
                  <div className="font-bold text-rose-300">{hoveredAgg.country}</div>
                  <div>{hoveredAgg.victim_count} victims</div>
                  <div className="text-muted">
                    {hoveredAgg.groups.length} group{hoveredAgg.groups.length !== 1 ? 's' : ''}
                  </div>
                </div>
              )}
              {hovered && !hoveredAgg && (
                <div className="absolute top-3 left-3 rounded-xl bg-surface-100/80 backdrop-blur px-3 py-1.5 text-xs font-mono text-inverted">
                  {hovered.name}: no victims reported
                </div>
              )}
            </div>

            <aside className="space-y-3">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted">Most targeted</h3>
              <ul className="space-y-1.5">
                {data.countries.slice(0, 15).map((c) => {
                  const isSelected = selected?.alpha2 === c.countryCode;
                  return (
                    <li key={c.countryCode}>
                      <button
                        type="button"
                        onClick={() => {
                          if (isSelected) setSelected(null);
                          else setSelected({ alpha2: c.countryCode, name: c.country });
                        }}
                        className={`w-full flex items-baseline justify-between gap-3 text-sm font-mono px-3 py-2 min-h-[44px] sm:min-h-0 sm:py-1.5 rounded border transition-colors ${
                          isSelected
                            ? 'border-rose-400/60 bg-rose-400/10 text-heading'
                            : 'border-line-1 bg-white dark:bg-surface-200 hover:border-rose-500/40'
                        }`}
                        aria-pressed={isSelected}
                      >
                        <span className="truncate">
                          <span className="text-muted mr-2">{c.countryCode}</span>
                          <span className="text-heading">{c.country}</span>
                        </span>
                        <span className="flex items-center gap-2 shrink-0">
                          <span className="text-mini text-muted tabular-nums">
                            {c.groups.length} group{c.groups.length !== 1 ? 's' : ''}
                          </span>
                          <span className="text-rose-600 dark:text-rose-400 font-bold">{c.victim_count}</span>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </aside>
          </div>

          {selected && selectedAgg && (
            <section className="mt-6 rounded-xl border border-rose-400/40 bg-rose-50/40 dark:border-rose-400/30 dark:bg-rose-500/5 p-4 sm:p-5">
              <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                <div>
                  <h3 className="font-display font-bold text-lg inline-flex items-center gap-2">
                    <span className="text-rose-600 dark:text-rose-400 font-mono text-xs uppercase tracking-wider">
                      Selected
                    </span>
                    {selectedAgg.country}
                    <span className="text-muted text-xs font-mono">({selectedAgg.countryCode})</span>
                  </h3>
                  <p className="text-xs font-mono text-muted mt-1">
                    <span className="font-semibold text-heading">{selectedAgg.victim_count}</span> victims
                    {' · '}
                    <span className="font-semibold text-heading">{selectedAgg.groups.length}</span> ransomware group
                    {selectedAgg.groups.length !== 1 ? 's' : ''}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelected(null)}
                  className="inline-flex items-center gap-1 text-xs font-mono px-3 py-2 min-h-[44px] sm:min-h-0 rounded border border-line-2 text-body hover:bg-surface-300 dark:hover:bg-surface-300"
                  aria-label="Clear country selection"
                >
                  <X size={12} /> clear
                </button>
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div>
                  <p className="text-mini font-mono uppercase tracking-wider text-muted mb-2">
                    Ransomware groups targeting {selectedAgg.country}
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedAgg.groups.map((g) => (
                      <span
                        key={g}
                        className="text-xs font-mono px-2 py-1 rounded bg-rose-200/30 dark:bg-rose-900/20 text-rose-800 dark:text-rose-200 border border-rose-300/30 dark:border-rose-700/30"
                      >
                        {g}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-mini font-mono uppercase tracking-wider text-muted mb-2">
                    Recent victims in {selectedAgg.country}
                  </p>
                  <ul className="space-y-1">
                    {selectedAgg.top_victims.map((victim) => (
                      <li key={victim}>
                        <Link
                          to={`/threatintel/ransomware-hub?q=${encodeURIComponent(victim)}`}
                          className="block rounded border border-rose-400/30 hover:border-rose-500/40 bg-surface-100 px-3 py-1.5 transition-colors font-mono text-sm text-heading"
                        >
                          {victim}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          )}
        </>
      )}
    </DataPageLayout>
  );
}
