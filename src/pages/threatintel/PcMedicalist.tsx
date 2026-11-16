import { useMemo, useState } from 'react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DigestAnalysisPanel } from '../../components/DigestAnalysisPanel';
import HexBrainLink from '../../components/HexBrainLink';
import { ShieldAlert, ExternalLink, Layers, Search, Loader2, Calendar, FileText } from 'lucide-react';

interface PcmIndexEntry {
  date: string;
  pushedAt: string | null;
  feedsTotal: number | null;
  itemsRaw: number | null;
  itemsDeduped: number | null;
  layerCounts: { layer: number; name: string; count: number }[];
  sizeBytes: number;
}

interface PcmItem {
  id: string | null;
  title: string;
  summary: string;
  url: string | null;
  source: string | null;
  category: string | null;
  severity: string | null;
  trust_score: number | null;
  cves: string[];
  technologies: string[];
  published: string | null;
}

interface PcmDigest {
  date: string;
  feedsTotal: number | null;
  itemsRaw: number | null;
  itemsDeduped: number | null;
  perFeed: Record<string, number>;
  postA: string | null;
  postB: string | null;
  layers: { layer: number; name: string; trust: number | null; count: number; top: PcmItem[] }[];
  sourceUrl: string;
  upstreamDigestUrl: string;
  rawMarkdownUrl: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  High: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  Medium: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  Low: 'bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300',
};

export default function PcMedicalist() {
  const [selectedDate, setSelectedDate] = useState<string | null>(null);
  const [activeLayer, setActiveLayer] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<PcmItem[] | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  const { data: indexData, loading: indexLoading } = useDataFetch<{
    total: number;
    returned: number;
    digests: PcmIndexEntry[];
  }>({
    url: '/api/v1/pcmedicalist/digests?limit=100',
  });

  const digests = useMemo(() => indexData?.digests ?? [], [indexData]);
  const currentDate = selectedDate ?? digests[0]?.date ?? null;

  const { data: digest, loading: digestLoading } = useDataFetch<PcmDigest>({
    url: currentDate ? `/api/v1/pcmedicalist/digests/${currentDate}` : '',
  });

  const isLoading = indexLoading || digestLoading;

  const runDeepSearch = async (query: string) => {
    setSearchQuery(query);
    if (!currentDate || !query.trim()) {
      setSearchResults(null);
      setSearchError(null);
      setSearching(false);
      return;
    }
    setSearching(true);
    setSearchError(null);
    try {
      const res = await fetch(
        `/api/v1/pcmedicalist/day/${currentDate}/search?q=${encodeURIComponent(query.trim())}&limit=100`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setSearchResults(body.items ?? []);
      if ((body as { stale?: boolean }).stale) setSearchError('Serving cached results — upstream fetch degraded.');
    } catch {
      setSearchError('Deep-dive search failed (upstream fetch).');
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  };

  const layers = digest?.layers ?? [];
  const shownLayer = layers.find((l) => l.layer === activeLayer) ?? layers[0] ?? null;

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<ShieldAlert size={20} />}
      title="PCMedicalist Intelligence Feed"
      description="Daily security-intel digest from the PCMedicalist Intelligence Network — 38+ feeds deduplicated into a 11-layer taxonomy with trust scoring, CVE tracking, and AI-security coverage."
    >
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-heading">PCMedicalist Security Intelligence Feed</h1>
          <p className="mt-1 text-sm text-muted">
            Source:{' '}
            <a
              href="https://app.pcmedicalist.com/intel"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 hover:underline dark:text-brand-400 transition-colors"
            >
              app.pcmedicalist.com/intel
            </a>{' '}
            &middot; CC BY 4.0 &middot; {indexData?.total ?? 0} digests
          </p>
        </div>
        {digests.length > 0 && (
          <select
            value={currentDate ?? ''}
            onChange={(e) => {
              setSelectedDate(e.target.value);
              setSearchResults(null);
              setSearchError(null);
              setActiveLayer(null);
            }}
            className="rounded-lg border border-line-2 bg-surface-100 px-3 py-2 text-sm text-heading"
          >
            {digests.map((d) => (
              <option key={d.date} value={d.date}>
                {d.date}
              </option>
            ))}
          </select>
        )}
      </div>

      {isLoading && <div className="py-12 text-center text-sm text-muted">Loading...</div>}

      {!isLoading && digest && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="text-2xl font-bold text-heading">{digest.feedsTotal ?? '—'}</div>
              <div className="text-xs text-muted">Feeds ingested</div>
            </div>
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="text-2xl font-bold text-heading">{(digest.itemsRaw ?? 0).toLocaleString()}</div>
              <div className="text-xs text-muted">Raw items</div>
            </div>
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="text-2xl font-bold text-heading">{(digest.itemsDeduped ?? 0).toLocaleString()}</div>
              <div className="text-xs text-muted">Deduplicated</div>
            </div>
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="text-2xl font-bold text-heading">{digest.layers.length}</div>
              <div className="text-xs text-muted">Intelligence layers</div>
            </div>
          </div>

          {currentDate && <DigestAnalysisPanel endpoint={`/api/v1/pcmedicalist/digests/${currentDate}/analysis`} />}

          {digest.perFeed && Object.keys(digest.perFeed).length > 0 && (
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="mb-2 text-xs font-semibold text-body">Top contributing feeds</div>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(digest.perFeed)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([feed, count]) => (
                    <span
                      key={feed}
                      className="rounded-full bg-surface-300/60 px-2.5 py-1 text-mini font-medium text-muted"
                    >
                      {feed} <span className="opacity-70">{count.toLocaleString()}</span>
                    </span>
                  ))}
              </div>
            </div>
          )}

          {digest.postA && (
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-heading">
                <FileText size={14} className="text-brand-500" /> Daily Security &amp; Standards Brief
              </div>
              <pre className="whitespace-pre-wrap font-sans text-xs leading-relaxed text-body">{digest.postA}</pre>
            </div>
          )}

          {digest.postB && (
            <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-heading">
                <FileText size={14} className="text-purple-500" /> Engineering &amp; Research Digest
              </div>
              <pre className="whitespace-pre-wrap font-sans text-xs leading-relaxed text-body">{digest.postB}</pre>
            </div>
          )}

          <div className="rounded-xl border border-line-1 bg-surface-100 p-4">
            <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-heading">
                <Layers size={14} className="text-emerald-500" /> Layers
              </div>
              <div className="flex items-center gap-2">
                <Search size={14} className="text-muted" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && runDeepSearch(e.currentTarget.value)}
                  placeholder="Deep-dive: search the full day feed…"
                  className="w-full rounded-lg border border-line-2 bg-surface-100 px-3 py-1.5 text-xs text-heading placeholder:text-muted sm:w-72"
                />
                <button
                  onClick={() => runDeepSearch(searchQuery)}
                  disabled={searching}
                  className="rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-medium text-on-fill hover:bg-brand-700 disabled:opacity-50"
                >
                  {searching ? <Loader2 size={12} className="animate-spin" /> : 'Search'}
                </button>
              </div>
            </div>

            <div className="mb-3 flex flex-wrap gap-1.5">
              {layers.map((l) => (
                <button
                  key={l.layer}
                  onClick={() => {
                    setActiveLayer(l.layer);
                    setSearchResults(null);
                  }}
                  className={`rounded-full px-2.5 py-1 text-mini font-medium ${
                    shownLayer?.layer === l.layer
                      ? 'bg-brand-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-surface-300/60 dark:text-slate-300'
                  }`}
                >
                  {l.name} <span className="opacity-70">{l.count}</span>
                </button>
              ))}
            </div>

            {searchResults !== null ? (
              <div className="space-y-2">
                {searchError && <p className="text-xs text-amber-500">{searchError}</p>}
                {searchResults.length === 0 ? (
                  <p className="py-6 text-center text-xs text-muted">
                    No items matched “{searchQuery}” in the full {digest.itemsRaw?.toLocaleString()}-item day feed.
                  </p>
                ) : (
                  searchResults.map((item, i) => <ItemRow key={item.id ?? i} item={item} />)
                )}
              </div>
            ) : shownLayer ? (
              <div className="space-y-2">
                <p className="text-xs text-muted">
                  {shownLayer.name} &middot; {shownLayer.count} items &middot; showing top {shownLayer.top.length} by
                  trust score
                </p>
                {shownLayer.top.map((item, i) => (
                  <ItemRow key={item.id ?? i} item={item} />
                ))}
              </div>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
            <Calendar size={12} /> Digest {digest.date}
            <span>&middot;</span>
            <a
              href={digest.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-500 hover:underline transition-colors"
            >
              View on pcmedicalist.com
            </a>
            <span>&middot;</span>
            <a
              href={digest.upstreamDigestUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-500 hover:underline transition-colors"
            >
              Upstream digest files
            </a>
          </div>
        </div>
      )}

      {!isLoading && !digest && <div className="py-12 text-center text-sm text-muted">No digests available yet.</div>}
    </DataPageLayout>
  );
}

function ItemRow({ item }: { item: PcmItem }) {
  const sevClass = SEVERITY_COLOR[item.severity ?? ''] ?? '';
  return (
    <div className="rounded-lg border border-line-1 bg-surface-200/60 px-3 py-2 dark:bg-surface-300/30">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          {item.url ? (
            <a
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm font-medium text-brand-600 hover:underline dark:text-brand-400 transition-colors"
            >
              {item.title} <ExternalLink size={11} />
            </a>
          ) : (
            <span className="text-sm font-medium text-heading">{item.title}</span>
          )}
          {item.summary && <p className="mt-0.5 line-clamp-2 text-xs text-muted">{item.summary}</p>}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          {sevClass && (
            <span className={`rounded-full px-2 py-0.5 text-micro font-semibold ${sevClass}`}>{item.severity}</span>
          )}
          {item.trust_score != null && (
            <span className="inline-flex items-center gap-1 text-micro font-medium text-muted">
              <span className="h-1 w-10 overflow-hidden rounded-full bg-track">
                <span
                  className={`block h-full rounded-full ${
                    item.trust_score >= 80 ? 'bg-emerald-500' : item.trust_score >= 50 ? 'bg-amber-500' : 'bg-slate-400'
                  }`}
                  style={{ width: `${Math.max(0, Math.min(100, item.trust_score))}%` }}
                />
              </span>
              trust {item.trust_score}
            </span>
          )}
        </div>
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-micro text-muted">
        {item.source && <span className="font-medium text-muted">{item.source}</span>}
        {item.category && <span>{item.category}</span>}
        {item.published && <span>{item.published.slice(0, 10)}</span>}
        {item.cves.length > 0 &&
          item.cves.slice(0, 3).map((c) => (
            <span key={c} className="inline-flex items-center gap-1">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${c}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded bg-red-50 px-1.5 py-0.5 font-mono text-micro text-red-600 hover:underline dark:bg-red-900/30 dark:text-red-300 transition-colors"
              >
                {c}
              </a>
              <HexBrainLink
                cve={c}
                label="HB"
                className="text-[10px] font-mono text-orange-600 dark:text-orange-300 hover:underline"
              />
            </span>
          ))}
        {item.technologies.length > 0 && (
          <span className="text-muted">tech: {item.technologies.slice(0, 3).join(', ')}</span>
        )}
      </div>
    </div>
  );
}
