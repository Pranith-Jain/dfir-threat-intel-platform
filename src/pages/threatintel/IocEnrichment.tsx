import { useState, useCallback, useEffect, useRef } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { CopyButton } from '../../components/ui/CopyButton';

import { Search, Loader2, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import { errMessage } from '../../lib/log';

/** Format an arbitrary enrichment value for readable key/value display. */
function formatEnrichValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value || '—';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '—';
    const preview = value
      .slice(0, 5)
      .map((v) => (typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)))
      .join(', ');
    return value.length > 5 ? `${preview}, … (+${value.length - 5} more)` : preview;
  }
  const json = JSON.stringify(value);
  return json.length > 240 ? `${json.slice(0, 240)}…` : json;
}

interface Source {
  id: string;
  label: string;
  url: string;
  hint: string;
  docsUrl?: string;
}

const SOURCES: Source[] = [
  {
    id: 'maltiverse',
    label: 'Maltiverse',
    url: '/api/v1/maltiverse/search?q=',
    hint: 'Search by IP, domain, hash, or keyword',
    docsUrl: 'https://maltiverse.com/search',
  },
  {
    id: 'inquest',
    label: 'InQuest Labs',
    url: '/api/v1/inquest/search?q=',
    hint: 'Search by IP, domain, hash, or keyword',
    docsUrl: 'https://labs.inquest.net',
  },
  {
    id: 'hackertarget',
    label: 'HackerTarget DNS',
    url: '/api/v1/hackertarget/dns?q=',
    hint: 'Search by domain or IP',
    docsUrl: 'https://hackertarget.com/host-search/',
  },
  {
    id: 'radar',
    label: 'Cloudflare Radar',
    url: '/api/v1/radar/domain?domain=',
    hint: 'Search by domain',
    docsUrl: 'https://radar.cloudflare.com',
  },
  {
    id: 'certspotter',
    label: 'CertSpotter (subdomains)',
    url: '/api/v1/certspotter/search?domain=',
    hint: 'Find subdomains via certificate transparency',
    docsUrl: 'https://certspotter.com',
  },
  {
    id: 'triage',
    label: 'Triage (malware)',
    url: '/api/v1/triage/search?q=',
    hint: 'Needs TRIAGE_API_KEY - search hashes, IPs, domains',
    docsUrl: 'https://tria.ge',
  },
];

export default function IocEnrichment(): JSX.Element {
  const [query, setQuery] = useState('');
  const [source, setSource] = useState<Source>(SOURCES[0]!);
  const [data, setData] = useState<unknown | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(true);
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const reqIdRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  // Close the source dropdown on click-outside or Escape (a native <select>
  // would get this for free; this custom one has to wire it up).
  useEffect(() => {
    if (!showDropdown) return;
    const onPointer = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowDropdown(false);
    };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [showDropdown]);

  useEffect(() => {
    setData(null);
    setError(null);
  }, [source]);

  // A successful-but-empty response (e.g. `{}` or `[]`) should read as "no
  // results", not a raw empty-object dump.
  const isEmptyResult =
    !!data &&
    (Array.isArray(data)
      ? data.length === 0
      : typeof data === 'object' && Object.keys(data as Record<string, unknown>).length === 0);

  const handleSearch = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    const myId = ++reqIdRef.current;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const res = await fetch(`${source.url}${encodeURIComponent(q)}`, { signal: controller.signal });
      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(errBody?.error ?? `HTTP ${res.status}`);
      }
      const json = await res.json();
      if (myId !== reqIdRef.current) return;
      setData(json);
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return;
      if (myId !== reqIdRef.current) return;
      setError(errMessage(e, 'Request failed'));
    } finally {
      if (myId === reqIdRef.current) setLoading(false);
    }
  }, [query, source]);

  // Abort any in-flight request on unmount (also prevents setState-after-unmount).
  useEffect(() => () => abortRef.current?.abort(), []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSearch();
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Search size={28} />}
      title="IOC Enrichment"
      description={
        <span className="font-mono text-sm">
          Query external free threat intel APIs - Maltiverse, InQuest Labs, HackerTarget DNS, Cloudflare Radar - from
          one interface. Supports IP, domain, hash, and keyword lookups.
        </span>
      }
      maxWidthClass="max-w-6xl"
      headerExtra={
        <div className="surface-card p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="relative">
                <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={source.hint}
                  className="w-full rounded-xl border border-line-1 bg-surface-100 py-2.5 pl-9 pr-4 font-mono text-tool text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/20 dark:placeholder:text-muted"
                  aria-label="Search query"
                />
              </div>
            </div>

            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setShowDropdown(!showDropdown)}
                aria-haspopup="listbox"
                aria-expanded={showDropdown}
                aria-label={`Data source: ${source.label}`}
                className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-100 px-3 py-2.5 font-mono text-tool text-heading hover:border-rose-500/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/20 min-w-[180px] justify-between"
              >
                <span>{source.label}</span>
                <ChevronDown size={14} className="text-muted" />
              </button>
              {showDropdown && (
                <div
                  role="listbox"
                  aria-label="Data source"
                  className="absolute right-0 top-full mt-1 z-10 w-full min-w-[220px] rounded-xl border border-line-1 bg-surface-100 shadow-e3"
                >
                  {SOURCES.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      role="option"
                      aria-selected={source.id === s.id}
                      onClick={() => {
                        setSource(s);
                        setShowDropdown(false);
                      }}
                      className={`w-full text-left px-3 py-2.5 text-tool font-mono transition-colors hover:bg-surface-300 dark:hover:bg-surface-300 ${
                        source.id === s.id ? 'text-rose-700 dark:text-rose-300 bg-rose-500/5' : 'text-body'
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={handleSearch}
              disabled={loading || !query.trim()}
              className="inline-flex items-center gap-2 rounded-xl bg-rose-600 px-4 py-2.5 font-mono text-tool font-semibold text-on-fill hover:bg-rose-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/40"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
              {loading ? 'Searching…' : 'Search'}
            </button>
          </div>

          {source.docsUrl && (
            <a
              href={source.docsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 mt-3 text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
            >
              <ExternalLink size={11} /> {source.label} docs
            </a>
          )}
        </div>
      }
      loading={loading}
      error={error}
      empty={!!data && isEmptyResult}
      emptyMessage={`No results from ${source.label} for this query.`}
    >
      {!!data && !isEmptyResult && (
        <div className="surface-card overflow-hidden">
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between p-4 text-left hover:bg-surface-200 dark:hover:bg-input-200 transition-colors"
          >
            <span className="font-display font-semibold text-sm flex items-center gap-2">
              {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Response from {source.label}
            </span>
            <span className="text-mini font-mono text-muted">{JSON.stringify(data).length.toLocaleString()} bytes</span>
          </button>
          {expanded && (
            <div className="p-4 pt-0 space-y-3">
              <div className="flex justify-end">
                <CopyButton value={JSON.stringify(data, null, 2)} label="Copy full JSON" />
              </div>
              <dl className="divide-y divide-line-1">
                {Object.entries(data as Record<string, unknown>).map(([key, value]) => (
                  <div key={key} className="flex flex-col gap-0.5 py-2 sm:flex-row sm:gap-3">
                    <dt className="font-mono text-mini uppercase tracking-wider text-muted sm:w-44 shrink-0 break-all">
                      {key}
                    </dt>
                    <dd className="font-mono text-meta text-heading break-all min-w-0">{formatEnrichValue(value)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </div>
      )}
    </DataPageLayout>
  );
}
