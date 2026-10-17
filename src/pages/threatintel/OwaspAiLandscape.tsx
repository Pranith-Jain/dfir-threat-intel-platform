import { useEffect, useMemo, useState } from 'react';
import { Search, RefreshCw, ExternalLink, ChevronRight, ChevronDown, FolderTree, Info, Shield } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { relativeAgoSeeded } from '../../lib/relativeTime';

interface OwaspNode {
  title: string;
  description: string;
  url: string;
  type: 'umbrella' | 'sub-umbrella' | 'guide' | 'standard' | 'cheat sheet' | 'tool' | 'ctf';
  children?: OwaspNode[];
}

interface Landscape {
  name: string;
  description: string;
  source: string;
  fetchedAt: string;
  nodes: OwaspNode[];
}

interface Meta {
  source?: string;
  fetchedAt?: string;
  ok?: boolean;
  error?: string;
  counts?: { umbrellas: number; subUmbrellas: number; leaves: number };
}

// Light-mode-first palette, mirrors LlmThreatAtlas.tsx + AiDefense.tsx.
// Each entry is `text-… bg-… border-…` (light) followed by `dark:…` (dark).
// Tones follow the framework taxonomy: umbrellas = purple, sub-umbrellas =
// indigo, guides = emerald, standards = cyan, cheat sheets = amber,
// tools = rose, CTFs = rose.
const TYPE_PILL: Record<string, string> = {
  umbrella:
    'text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/40 border-purple-300 dark:border-purple-800',
  'sub-umbrella':
    'text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/40 border-indigo-300 dark:border-indigo-800',
  guide:
    'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  standard: 'text-sky-700 dark:text-sky-300 bg-cyan-50 dark:bg-cyan-950/40 border-cyan-300 dark:border-cyan-800',
  'cheat sheet':
    'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  tool: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  ctf: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
};

function flatten(nodes: OwaspNode[], depth = 0): { node: OwaspNode; depth: number }[] {
  const out: { node: OwaspNode; depth: number }[] = [];
  for (const n of nodes) {
    out.push({ node: n, depth });
    if (n.children?.length) out.push(...flatten(n.children, depth + 1));
  }
  return out;
}

function matches(node: OwaspNode, q: string, types: Set<string>): boolean {
  if (types.size > 0 && !types.has(node.type)) return false;
  if (!q) return true;
  const hay = `${node.title} ${node.description} ${node.url} ${node.type}`.toLowerCase();
  return hay.includes(q.toLowerCase());
}

function filterTree(nodes: OwaspNode[], q: string, types: Set<string>): OwaspNode[] {
  if (!q && types.size === 0) return nodes;
  const out: OwaspNode[] = [];
  for (const n of nodes) {
    if (n.children?.length) {
      const kids = filterTree(n.children, q, types);
      if (kids.length > 0 || matches(n, q, types)) {
        out.push({ ...n, children: kids });
        continue;
      }
    } else if (matches(n, q, types)) {
      out.push(n);
    }
  }
  return out;
}

function NodeRow({ node, depth, defaultOpen }: { node: OwaspNode; depth: number; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const hasKids = (node.children?.length ?? 0) > 0;
  const isLeaf = !hasKids;
  const pill = TYPE_PILL[node.type] ?? 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-muted';
  return (
    <div className="border-b border-line-1 last:border-b-0">
      <div
        className="flex items-start gap-3 px-3 py-3 hover:bg-surface-200 dark:hover:bg-surface-200/50 transition-colors"
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
      >
        <button
          type="button"
          onClick={() => hasKids && setOpen((v) => !v)}
          className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted ${
            hasKids ? 'hover:bg-slate-200/60 dark:hover:bg-surface-300/60' : 'opacity-0'
          }`}
          aria-label={open ? 'Collapse' : 'Expand'}
        >
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            {node.url ? (
              <a
                href={node.url}
                target="_blank"
                rel="noopener noreferrer"
                className={`font-medium ${isLeaf ? 'text-base text-heading' : 'text-base text-heading'} hover:text-rose-600 dark:hover:text-rose-400 hover:underline transition-colors`}
              >
                {node.title}
              </a>
            ) : (
              <span className={`font-medium ${isLeaf ? 'text-base text-heading' : 'text-base text-heading'}`}>
                {node.title}
              </span>
            )}
            <span className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${pill}`}>
              {node.type}
            </span>
            {isLeaf && node.url && (
              <a
                href={node.url}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-auto text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                aria-label="Open external"
              >
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            )}
          </div>
          {node.description && <p className="mt-1 text-sm text-muted leading-relaxed">{node.description}</p>}
        </div>
      </div>
      {hasKids && open && (
        <div>
          {node.children!.map((c) => (
            <NodeRow key={`${depth}-${c.title}`} node={c} depth={depth + 1} defaultOpen={defaultOpen} />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * OWASP AI Security Landscape - full tree of every OWASP project, initiative,
 * guide, cheat sheet, and CTF related to AI / ML / agentic security.
 *
 * Sourced from RicoKomenda/owasp-ai-security-visualizer on GitHub. Auto-synced
 * daily by the Worker cron (see worker/scheduled.ts `"30 0 * * *"` branch
 * where the landscape sync piggybacks on the briefing build);
 * the page reads /api/v1/owasp-ai-landscape which serves the cached tree
 * and falls back to a bundled seed before the first successful sync.
 */
export default function OwaspAiLandscape(): JSX.Element {
  const [data, setData] = useState<Landscape | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    Promise.all([
      fetch('/api/v1/owasp-ai-landscape', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }).then(
        (r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      ),
      fetch('/api/v1/owasp-ai-landscape/meta', {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      }).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))),
    ])
      .then(([landscape, m]) => {
        if (cancelled) return;
        setData(landscape);
        setMeta(m);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'fetch failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const allTypes = useMemo(() => {
    const seen = new Set<string>();
    const walk = (n: OwaspNode) => {
      seen.add(n.type);
      n.children?.forEach(walk);
    };
    data?.nodes.forEach(walk);
    return Array.from(seen).sort();
  }, [data]);

  const filtered = useMemo(() => {
    if (!data) return [];
    return filterTree(data.nodes, query, activeTypes);
  }, [data, query, activeTypes]);

  const flat = useMemo(() => flatten(filtered), [filtered]);
  const leafCount = meta?.counts?.leaves ?? flat.filter((f) => !f.node.children?.length).length;

  const toggleType = (t: string) => {
    setActiveTypes((prev) => {
      const n = new Set(prev);
      if (n.has(t)) n.delete(t);
      else n.add(t);
      return n;
    });
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Shield className="h-6 w-6" />}
      title="OWASP AI Security Landscape"
      description={
        <span>
          Auto-synced tree of every OWASP project, initiative, guide, cheat sheet, and CTF related to AI / ML / agentic
          security. Source:{' '}
          <a
            href="https://github.com/RicoKomenda/owasp-ai-security-visualizer"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            RicoKomenda/owasp-ai-security-visualizer
          </a>
          .
        </span>
      }
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
            aria-label="Refresh"
          >
            <RefreshCw className="h-3.5 w-3.5" /> refresh
          </button>
          <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">
            synced <span className="text-body">{relativeAgoSeeded(meta?.fetchedAt)}</span>
          </span>
          {meta?.ok === false && (
            <span
              className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-2 py-1 text-amber-700 dark:text-amber-300 font-mono"
              title={meta.error}
            >
              sync failing
            </span>
          )}
          {meta?.ok && meta.fetchedAt && !meta.fetchedAt.startsWith('1970') && (
            <span className="rounded border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-1 text-emerald-700 dark:text-emerald-300 font-mono">
              live
            </span>
          )}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      empty={!loading && !data}
      emptyMessage="No landscape data available."
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <>
          {/* Toolbar */}
          <section className="surface-card p-4 mb-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search resources…"
                  className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allTypes.map((t) => {
                  const active = activeTypes.has(t);
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() => toggleType(t)}
                      className={`text-micro font-mono uppercase tracking-wider rounded-full border px-2.5 py-0.5 transition-colors ${
                        active
                          ? TYPE_PILL[t]
                          : 'border-slate-300 dark:border-line-1 text-muted hover:border-slate-400 dark:hover:border-slate-500'
                      }`}
                    >
                      {t}
                    </button>
                  );
                })}
                {activeTypes.size > 0 && (
                  <button
                    type="button"
                    onClick={() => setActiveTypes(new Set())}
                    className="text-micro font-mono uppercase tracking-wider rounded-full border border-line-2 px-2.5 py-0.5 text-muted hover:text-body dark:hover:text-inverted"
                  >
                    clear
                  </button>
                )}
              </div>
            </div>
          </section>

          {/* Header cards */}
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Umbrellas" value={meta?.counts?.umbrellas ?? '-'} />
            <Stat label="Sub-initiatives" value={meta?.counts?.subUmbrellas ?? '-'} />
            <Stat label="Resources" value={leafCount} />
            <Stat
              label="Source"
              value={
                <a
                  href={data.source}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-rose-600 dark:text-rose-400 hover:underline truncate transition-colors"
                >
                  data.json
                </a>
              }
            />
          </div>

          {data.description && (
            <div className="mb-3 flex items-start gap-2 rounded-xl border border-sky-200 dark:border-sky-900 bg-sky-50 dark:bg-sky-950/30 p-3 text-sm text-body">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
              <span>{data.description}</span>
            </div>
          )}

          {/* Tree */}
          {filtered.length === 0 ? (
            <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <FolderTree className="mx-auto mb-2 h-8 w-8 text-muted" />
              No resources match the current filters.
            </div>
          ) : (
            <div className="overflow-hidden rounded-xl border border-line-1 bg-surface-100">
              {filtered.map((n) => (
                <NodeRow key={n.title} node={n} depth={0} defaultOpen={!query && activeTypes.size === 0} />
              ))}
            </div>
          )}
        </>
      )}
    </DataPageLayout>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="surface-card px-3 py-2">
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-lg font-semibold text-heading truncate">{value}</div>
    </div>
  );
}
