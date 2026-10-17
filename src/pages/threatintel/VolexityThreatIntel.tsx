import { useEffect, useMemo, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Users, ExternalLink, FileCode, ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';

interface RuleFile {
  name: string;
  kind: 'yara' | 'snort';
  download_url: string;
  size: number;
}
interface FolderEntry {
  name: string;
  label: string;
  year: string;
  date: string;
  has_indicators: boolean;
  indicators_url: string;
  rule_files: RuleFile[];
}
interface TreeResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  mode: 'folders';
  count: number;
  total: number;
  years: Record<string, number>;
  folders: FolderEntry[];
  stale?: boolean;
  upstream_error?: string;
}

interface Ioc {
  value: string;
  kind: 'hash' | 'domain' | 'ipv4' | 'url' | 'email' | 'other';
  entity_type: string;
  description: string;
}
interface FolderResponse {
  source: string;
  source_url: string;
  license: string;
  generated_at: string;
  mode: 'folder';
  folder: string;
  label: string;
  year: string;
  date: string;
  indicators_url: string;
  rule_files: RuleFile[];
  count: number;
  kinds: Record<string, number>;
  iocs: Ioc[];
  stale?: boolean;
  upstream_error?: string;
}

/** Only render http(s) links - every URL here comes from an untrusted upstream
 *  GitHub tree / CSV, so never let a `javascript:`/`data:` URL reach an href. */
function safeHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch (_catchErr) {
    console.error('safeHref failed:', errMessage(_catchErr));
    return null;
  }
}

const KIND_TONE: Record<string, string> = {
  hash: 'border-violet-500/50 text-violet-600 dark:text-violet-400 bg-violet-500/10',
  domain: 'border-sky-500/50 text-sky-600 dark:text-sky-400 bg-sky-500/10',
  ipv4: 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10',
  url: 'border-amber-500/50 text-amber-600 dark:text-amber-400 bg-amber-500/10',
  email: 'border-rose-500/50 text-rose-600 dark:text-rose-400 bg-rose-500/10',
  other: 'border-slate-400/50 text-slate-500 bg-slate-400/10',
};

function chip(active: boolean): string {
  return `text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
    active
      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
  }`;
}

/** IOC values can be huge (urls). Only pivot the pivot-able kinds to the checker;
 *  for `url`/`other` we still render the raw value but skip the IOC-check link. */
function pivotable(kind: Ioc['kind']): boolean {
  return kind === 'hash' || kind === 'domain' || kind === 'ipv4' || kind === 'url';
}

/** Upper bound on rendered IOC rows. */
const MAX_IOC_ROWS = 2000;
/** Stable empty array so the memo below keeps a constant identity. */
const EMPTY_IOCS: Ioc[] = [];

/** Hoisted to module scope: a fresh array identity on every render would
 *  defeat DataTable's internal sort memo over up to 2000 rows. */
const IOC_COLUMNS: DataTableColumn<Ioc>[] = [
  {
    key: 'indicator',
    header: 'indicator',
    sortValue: (ioc) => ioc.value,
    render: (ioc) => (
      <span className="font-mono break-all text-heading">
        {pivotable(ioc.kind) ? (
          <Link
            to={`/dfir/ioc-check?indicator=${encodeURIComponent(ioc.value)}`}
            className="hover:text-rose-600 dark:hover:text-rose-400"
            title="Pivot to IOC checker"
          >
            {ioc.value} →
          </Link>
        ) : (
          ioc.value
        )}
      </span>
    ),
  },
  {
    key: 'type',
    header: 'type',
    sortValue: (ioc) => ioc.kind,
    render: (ioc) => (
      <span className={`px-1.5 py-0.5 rounded border ${KIND_TONE[ioc.kind] ?? KIND_TONE.other}`}>
        {ioc.entity_type || ioc.kind}
      </span>
    ),
  },
  {
    key: 'context',
    header: 'context',
    render: (ioc) => <span className="text-muted">{ioc.description}</span>,
  },
];

interface FolderRowProps {
  folder: FolderEntry;
}

function FolderRow({ folder }: FolderRowProps): JSX.Element {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<FolderResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setErr(null);
    fetch(`/api/v1/volexity-threat-intel?folder=${encodeURIComponent(folder.name)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<FolderResponse>;
      })
      .then((d) => setData(d))
      .catch((e: { message?: string }) => setErr(e.message ?? 'unknown'))
      .finally(() => setLoading(false));
  }, [folder.name]);

  const toggle = (): void => {
    const next = !open;
    setOpen(next);
    if (next && !data && !loading) load();
  };

  // Stable identity so DataTable's sort memo survives unrelated re-renders.
  const visibleIocs = useMemo(() => data?.iocs.slice(0, MAX_IOC_ROWS) ?? EMPTY_IOCS, [data]);

  return (
    <div className="rounded-xl border border-line-1 bg-surface-200">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="w-full flex items-start gap-2 p-3 text-left"
      >
        <span className="text-muted mt-0.5 shrink-0">
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-semibold text-sm text-heading leading-snug break-words">{folder.label}</span>
          <span className="flex flex-wrap items-center gap-1.5 mt-1.5">
            {folder.has_indicators && (
              <span className="text-micro font-mono px-1.5 py-0.5 rounded border border-emerald-500/40 text-emerald-600 dark:text-emerald-400">
                iocs.csv
              </span>
            )}
            {folder.rule_files.map((rf) => (
              <span
                key={rf.name}
                className={`text-micro font-mono px-1.5 py-0.5 rounded border ${
                  rf.kind === 'yara'
                    ? 'border-violet-500/40 text-violet-600 dark:text-violet-400'
                    : 'border-amber-500/40 text-amber-600 dark:text-amber-400'
                }`}
              >
                {rf.kind === 'yara' ? 'YARA' : 'Snort'}: {rf.name}
              </span>
            ))}
          </span>
        </span>
        {folder.date && <span className="text-micro font-mono text-muted shrink-0">{folder.date}</span>}
        <PostAnalysisButton
          title={folder.label}
          description={`${folder.year} · ${folder.date} · ${folder.rule_files.length} rule(s)${folder.has_indicators ? ' · has indicators' : ''}`}
          source="volexity"
          compact
        />
      </button>

      {open && (
        <div className="px-3 pb-3 border-t border-line-1 pt-3">
          {/* rule-file download links (sourced from the cached tree, safeHref'd) */}
          {folder.rule_files.length > 0 && (
            <div className="flex flex-wrap gap-x-3 gap-y-1 mb-3">
              {folder.rule_files.map((rf) => {
                const href = safeHref(rf.download_url);
                return href ? (
                  <a
                    key={rf.name}
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 transition-colors"
                  >
                    <FileCode size={12} /> {rf.name}
                  </a>
                ) : (
                  <span key={rf.name} className="text-micro font-mono text-muted">
                    {rf.name}
                  </span>
                );
              })}
            </div>
          )}

          {loading && (
            <div className="flex items-center gap-2 py-3 text-muted">
              <Loader2 size={16} className="animate-spin" />
              <span className="text-xs font-mono">loading indicators…</span>
            </div>
          )}
          {err && <p className="text-xs text-rose-600 dark:text-rose-400 py-2">Failed to load: {err}</p>}

          {data && !loading && (
            <>
              {data.stale && (
                <p className="text-micro font-mono text-amber-600 dark:text-amber-400 mb-2">
                  ! cached indicators (upstream temporarily unavailable)
                </p>
              )}
              <div className="flex flex-wrap items-center gap-1.5 mb-2">
                {Object.entries(data.kinds)
                  .sort((a, b) => b[1] - a[1])
                  .map(([k, n]) => (
                    <span
                      key={k}
                      className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                        KIND_TONE[k] ?? KIND_TONE.other
                      }`}
                    >
                      {k} · {n}
                    </span>
                  ))}
                {data.count === 0 && (
                  <span className="text-micro font-mono text-muted">no indicator CSV in this folder</span>
                )}
              </div>

              {data.iocs.length > 0 && (
                <div className="overflow-x-auto">
                  <DataTable columns={IOC_COLUMNS} rows={visibleIocs} rowKey={(ioc, i) => `${ioc.value}-${i}`} />
                </div>
              )}

              {data.indicators_url &&
                (() => {
                  const href = safeHref(data.indicators_url);
                  return href ? (
                    <a
                      href={href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 mt-2 transition-colors"
                    >
                      raw iocs.csv <ExternalLink size={12} />
                    </a>
                  ) : null;
                })()}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function VolexityThreatIntel(): JSX.Element {
  const [data, setData] = useState<TreeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [year, setYear] = useState('all');
  const [query, setQuery] = useState('');

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/volexity-threat-intel', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<TreeResponse>;
      })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (!cancelled && e.name !== 'AbortError') setError(e.message ?? 'unknown');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  const years = useMemo(() => Object.entries(data?.years ?? {}).sort((a, b) => b[0].localeCompare(a[0])), [data]);

  const filtered = useMemo(() => {
    const list = data?.folders ?? [];
    const needle = query.trim().toLowerCase();
    return list.filter(
      (f) => (year === 'all' || f.year === year) && (!needle || f.label.toLowerCase().includes(needle))
    );
  }, [data, year, query]);

  const description = (
    <>
      Per-blogpost APT research folders from Volexity's public{' '}
      <a
        href="https://github.com/volexity/threat-intel"
        target="_blank"
        rel="noopener noreferrer"
        className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
      >
        threat-intel
      </a>{' '}
      repository - each folder ships an indicators CSV plus YARA / Snort detection rules. Expand a folder to load its
      indicators on demand and pivot any hash / domain / IP to the IOC checker. Licensed BSD-2-Clause; free to display
      and cite with attribution to Volexity.
    </>
  );

  const headerExtra =
    data && !error ? (
      <div className="space-y-2">
        {data.stale && (
          <p className="text-micro font-mono text-amber-600 dark:text-amber-400">
            ! showing cached data (upstream temporarily unavailable)
          </p>
        )}
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setYear('all')} className={chip(year === 'all')}>
            All years <span className="opacity-60">· {data.total}</span>
          </button>
          {years.map(([name, n]) => (
            <button type="button" key={name} onClick={() => setYear(name)} className={chip(year === name)}>
              {name} <span className="opacity-60">· {n}</span>
            </button>
          ))}
        </div>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter by actor / campaign…"
          className="w-full max-w-sm text-xs font-mono px-2.5 py-1.5 rounded border border-line-2 bg-surface-100 text-body focus:outline-none focus:border-rose-500/60"
        />
      </div>
    ) : undefined;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Users size={28} />}
      title="Volexity APT IOCs"
      description={description}
      headerExtra={headerExtra}
      loading={loading}
      error={error}
      empty={!loading && !error && !!data && filtered.length === 0}
      emptyMessage="No research folders match the filter."
    >
      {/* Page-level AI summary across the visible Volexity research folders.
          Public (requireAdmin={false}) so every visitor sees it. */}
      {filtered.length > 0 && (
        <AiSummaryCard
          surface="Volexity APT IOCs"
          items={filtered.slice(0, 30).map((f) => ({
            title: f.label,
            body: `${f.year} · ${f.date} · ${f.rule_files.length} rule(s)${f.has_indicators ? ' · has indicators' : ''}`,
            source: f.year,
          }))}
          requireAdmin={false}
        />
      )}
      <div className="grid gap-2">
        {filtered.map((folder) => (
          <FolderRow key={folder.name} folder={folder} />
        ))}
      </div>

      {data && (
        <p className="mt-6 text-micro font-mono text-muted text-center">
          Data:{' '}
          <a
            href={safeHref(data.source_url) ?? '#'}
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            {data.source}
          </a>{' '}
          - BSD-2-Clause; free to display and cite with attribution to Volexity · {data.total} research folders
        </p>
      )}
    </DataPageLayout>
  );
}
