import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { SECTIONS, flattenTools, matchesQuery } from '../../data/threatintel-sections';
import { searchPages } from '../../data/pages-index';
import { detectIoc, getIocPivots, IOC_TYPE_LABEL } from '../../lib/dfir/ioc-detect';
import {
  Search,
  ExternalLink,
  AlertTriangle,
  Skull,
  Globe,
  Shield,
  Bug,
  FileText,
  Database,
  Fingerprint,
  Wrench,
  ArrowUpRight,
  Zap,
  Compass,
  BookOpen,
  Newspaper,
  Scale,
  type LucideIcon,
} from 'lucide-react';

interface SearchItem {
  label: string;
  description?: string;
  url?: string;
  source: string;
  subkind?: string;
  score?: number;
}

interface SearchSection {
  label: string;
  kind: string;
  total: number;
  items: SearchItem[];
}

interface UnifiedSearchResponse {
  q: string;
  generated_at: string;
  total: number;
  sections: SearchSection[];
}

const SECTION_ICONS: Record<string, typeof Search> = {
  ransomware: Skull,
  c2: AlertTriangle,
  iocs: Shield,
  detections: Bug,
  actors: Globe,
  cves: FileText,
  writeups: FileText,
  cybercrime: Database,
  correlation: Fingerprint,
  breaches: Database,
  malware: Bug,
};

const SECTION_COLORS: Record<string, string> = {
  ransomware: 'text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/10',
  c2: 'text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10',
  iocs: 'text-sky-600 dark:text-sky-400 border-sky-500/30 bg-sky-500/10',
  detections: 'text-violet-600 dark:text-violet-400 border-violet-500/30 bg-violet-500/10',
  actors: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
  cves: 'text-orange-600 dark:text-orange-400 border-orange-500/30 bg-orange-500/10',
  writeups: 'text-indigo-600 dark:text-indigo-400 border-indigo-500/30 bg-indigo-500/10',
  cybercrime: 'text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/10',
  correlation: 'text-teal-600 dark:text-teal-400 border-teal-500/30 bg-teal-500/10',
  breaches: 'text-brand-600 dark:text-brand-400 border-brand-500/30 bg-brand-500/10',
  malware: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
};

const PAGE_GROUP_ICONS: Record<string, LucideIcon> = {
  portfolio: Compass,
  dfir: Wrench,
  threatintel: Shield,
  admin: Scale,
  blog: Newspaper,
  'case-study': BookOpen,
};

const PAGE_GROUP_COLORS: Record<string, string> = {
  portfolio: 'text-body border-slate-400/40 bg-slate-500/10',
  dfir: 'text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/10',
  threatintel: 'text-emerald-600 dark:text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
  admin: 'text-amber-600 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
  blog: 'text-violet-600 dark:text-violet-300 border-violet-500/30 bg-violet-500/10',
  'case-study': 'text-indigo-600 dark:text-indigo-300 border-indigo-500/30 bg-indigo-500/10',
};

const DEBOUNCE_MS = 350;
const MAX_TOOL_MATCHES = 6;
const MAX_PAGE_MATCHES = 12;

export default function UnifiedSearch(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const initialQ = params.get('q') ?? '';
  const [query, setQuery] = useState(initialQ);
  const [data, setData] = useState<UnifiedSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const lastSearchedRef = useRef<string>('');

  // Instant, client-side TOOL matches over the catalog - no network, no backend
  // coupling. This is the "omnibox searches tools too" half.
  const allTools = flattenTools(SECTIONS);
  const toolMatches = useMemo(
    () => (query.trim() ? allTools.filter((t) => matchesQuery(t, query.trim())).slice(0, MAX_TOOL_MATCHES) : []),
    [allTools, query]
  );

  // Subpage matches - covers every registered route in App.tsx (DFIR,
  // threatintel, blog, projects, admin, plus common aliases). The pages
  // index is hand-curated; the search ranks by exact label, path,
  // description, and keyword bag so e.g. "ransomware" surfaces both the
  // Ransomware Live page and the SOC ransomware view.
  const pageMatches = useMemo(
    () => (query.trim() ? searchPages(query.trim(), { limit: MAX_PAGE_MATCHES }) : []),
    [query]
  );

  // Instant entity detection → typed quick-action pivots. Reuses the SAME
  // detector + pivot builder as the ⌘K palette and the /dfir landing, so the
  // deep-links stay in sync everywhere.
  const detected = useMemo(() => detectIoc(query.trim()), [query]);
  const pivots = useMemo(() => (detected ? getIocPivots(detected) : []), [detected]);

  // Pure fetch - no URL writes here, so this stays referentially STABLE (deps []).
  // Keeping it out of the debounce effect's dep chain is what prevents react-router's
  // unstable setParams identity from re-firing the search on every render.
  const runSearch = useCallback(async (raw: string) => {
    const q = raw.trim();
    if (!q) {
      setData(null);
      setError(null);
      lastSearchedRef.current = '';
      return;
    }
    if (q === lastSearchedRef.current) return; // already showing/loading this query
    lastSearchedRef.current = q;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/v1/unified-search?q=${encodeURIComponent(q)}`, {
        signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]),
      });
      if (!r.ok) throw new Error(`${r.status}`);
      const d = (await r.json()) as UnifiedSearchResponse;
      if (!ac.signal.aborted) setData(d);
    } catch (e) {
      logCatch(e);
      if ((e as Error).name === 'AbortError') return; // superseded / unmounted - swallow
      lastSearchedRef.current = '';
      setError(errMessage(e, 'search failed'));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, []);

  // Reflect the committed query in the ?q= URL param. GUARDED so it only navigates
  // when actually out of sync - otherwise the unstable setParams would churn
  // re-renders + history entries on every search cycle.
  useEffect(() => {
    const q = query.trim();
    if ((params.get('q') ?? '').trim() === q) return;
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        if (q) n.set('q', q);
        else n.delete('q');
        return n;
      },
      { replace: true }
    );
  }, [query, params, setParams]);

  // Sync query state when the URL param changes externally (e.g. ⌘K launcher
  // navigates to ?q=…, or browser back/forward). Without this, the in-memory
  // `query` (seeded only on mount) wins and the URL sync effect reverts the
  // param back to the stale value.
  useEffect(() => {
    const q = params.get('q') ?? '';
    setQuery((prev) => (prev === q ? prev : q));
  }, [params]);

  // Debounced live search as the user types (also covers the initial ?q= load).
  // Depends on `query` only (runSearch is stable), so URL syncs never re-fire it.
  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setData(null);
      lastSearchedRef.current = '';
      return;
    }
    const t = setTimeout(() => void runSearch(q), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [query, runSearch]);

  // Abort any in-flight search when the page unmounts.
  useEffect(() => () => abortRef.current?.abort(), []);

  // Top results, flattened, for the opt-in AI summary.
  const summaryItems = useMemo(() => {
    if (!data) return [];
    const out: Array<{ title: string; body?: string; source?: string }> = [];
    for (const s of data.sections) {
      for (const it of (s.items ?? []).slice(0, 6)) {
        out.push({ title: it.label, body: it.description, source: `${s.label} · ${it.source}` });
        if (out.length >= 30) return out;
      }
    }
    return out;
  }, [data]);

  const total = data?.total ?? 0;
  const hasQuery = query.trim().length > 0;
  const nothingAnywhere =
    hasQuery &&
    !loading &&
    !error &&
    total === 0 &&
    toolMatches.length === 0 &&
    pageMatches.length === 0 &&
    pivots.length === 0;

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Search size={28} />}
      title="Unified Search"
      description="One omnibox across the platform - tools, ransomware victims, C2 IPs, live IOCs, detections, actor timelines, CVEs, writeups, cybercrime forums, and breaches. Type an IP, hash, CVE, actor, or keyword; ranked by relevance with one-click pivots and an optional AI summary."
      maxWidthClass="max-w-5xl"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void runSearch(query);
        }}
        className="relative mb-6 max-w-2xl"
      >
        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search threat intelligence - e.g. LockBit, 185.234.72.0, CVE-2026-1234, RedLine…"
          aria-label="Search across all intelligence sources and tools"
          className="w-full pl-11 pr-4 py-3 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500 dark:focus:border-rose-400 font-mono"
        />
      </form>

      {/* Entity quick-actions - instant, from the detected indicator type. */}
      {detected && pivots.length > 0 && (
        <div className="mb-4 rounded-xl border border-rose-200/60 dark:border-rose-800/40 bg-rose-50/40 dark:bg-rose-950/10 p-3">
          <div className="mb-2 flex items-center gap-2">
            <Zap size={14} className="text-rose-600 dark:text-rose-400" />
            <span className="text-mini font-mono text-muted">
              Detected {IOC_TYPE_LABEL[detected.type]} - quick actions
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {pivots.map((p) =>
              p.external ? (
                <a
                  key={p.path}
                  href={sanitizeUrl(p.path) || undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 rounded border border-rose-500/30 bg-surface-100 px-2.5 py-1.5 text-mini font-mono text-rose-700 hover:border-rose-500/60 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-950/30 transition-colors"
                  title={p.desc}
                >
                  {p.label}
                  <ExternalLink size={11} className="opacity-70" />
                </a>
              ) : (
                <Link
                  key={p.path}
                  to={p.path}
                  className="inline-flex items-center gap-1.5 rounded border border-rose-500/30 bg-surface-100 px-2.5 py-1.5 text-mini font-mono text-rose-700 hover:border-rose-500/60 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-950/30"
                  title={p.desc}
                >
                  {p.label}
                  <ArrowUpRight size={11} className="opacity-70" />
                </Link>
              )
            )}
          </div>
        </div>
      )}

      {/* Tools - instant client-side catalog matches. */}
      {toolMatches.length > 0 && (
        <section className="mb-4 surface-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line-1 text-rose-600 dark:text-rose-400">
            <Wrench size={14} />
            <span className="font-display font-semibold text-sm">Tools</span>
            <span className="text-mini font-mono opacity-70">· {toolMatches.length}</span>
          </div>
          <ul className="divide-y divide-line-1 dark:divide-slate-800/50">
            {toolMatches.map(({ section, ...tool }) => (
              <li key={tool.to} className="px-4 py-2.5 hover:bg-surface-200 dark:hover:bg-input-200/50">
                <Link to={tool.to} className="flex items-start justify-between gap-2 group">
                  <div className="min-w-0">
                    <span className="text-sm font-medium text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400 block truncate">
                      {tool.label}
                    </span>
                    <span className="text-mini font-mono text-muted mt-0.5 block truncate">{tool.desc}</span>
                  </div>
                  <span className="shrink-0 mt-0.5 inline-flex items-center rounded border border-line-2 bg-surface-200/50 px-1.5 py-0.5 font-mono text-micro uppercase tracking-wider text-muted">
                    {section.label}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Pages - every registered subpage in the app (DFIR, threatintel,
          portfolio, blog, admin). Surfaces routes that aren't in the
          tile-level SECTIONS catalog. */}
      {pageMatches.length > 0 && (
        <section className="mb-4 surface-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line-1 text-body">
            <Compass size={14} />
            <span className="font-display font-semibold text-sm">Pages</span>
            <span className="text-mini font-mono opacity-70">· {pageMatches.length}</span>
          </div>
          <ul className="divide-y divide-line-1 dark:divide-slate-800/50">
            {pageMatches.map(({ page }) => {
              const Icon = PAGE_GROUP_ICONS[page.group] ?? Compass;
              const color = PAGE_GROUP_COLORS[page.group] ?? 'text-slate-500 border-slate-300 bg-slate-50';
              return (
                <li
                  key={`${page.group}:${page.path}`}
                  className="px-4 py-2.5 hover:bg-surface-200 dark:hover:bg-input-200/50"
                >
                  <Link to={page.path} className="flex items-start justify-between gap-2 group">
                    <div className="min-w-0 flex items-start gap-2">
                      <Icon
                        size={14}
                        aria-hidden="true"
                        className={`mt-0.5 shrink-0 inline-flex items-center justify-center rounded border px-1 py-0.5 ${color}`}
                      />
                      <div className="min-w-0">
                        <span className="text-sm font-medium text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400 block truncate">
                          {page.label}
                        </span>
                        <span className="text-mini font-mono text-muted mt-0.5 block truncate">{page.description}</span>
                      </div>
                    </div>
                    <span className="shrink-0 mt-0.5 inline-flex items-center rounded border border-line-2 bg-surface-200/50 px-1.5 py-0.5 font-mono text-micro uppercase tracking-wider text-muted">
                      {page.sectionLabel}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {loading && (
        <p role="status" className="font-mono text-sm text-muted py-8">
          Searching intelligence sources + live IOC/CVE check…
        </p>
      )}

      {error && (
        <p role="alert" className="font-mono text-sm text-rose-600 dark:text-rose-400">
          search error: {error}
        </p>
      )}

      {nothingAnywhere && (
        <div className="py-12 text-center">
          <Search size={32} className="mx-auto text-inverted dark:text-muted mb-3" />
          <p className="font-mono text-sm text-muted">
            No results for &ldquo;{query.trim()}&rdquo; across any tool or intelligence source.
          </p>
        </div>
      )}

      {data && total > 0 && (
        <div className="space-y-4">
          {/* Opt-in AI summary - public same-origin endpoint, button-triggered. */}
          <PostAnalysisButton
            title="Unified Search Digest"
            description="AI-powered threat analysis of the current feed."
            source="unifiedsearch"
          />
          <AiSummaryCard
            surface="Unified Search"
            items={summaryItems}
            endpoint="/api/v1/unified-search/summarize"
            requireAdmin={false}
            autoFetch={false}
            extraBody={{ q: data.q }}
          />

          <p className="text-meta font-mono text-muted">
            {total} live result{total === 1 ? '' : 's'} for &ldquo;{data.q}&rdquo;
          </p>
          {data.sections.map((section) => {
            const Icon = SECTION_ICONS[section.kind] ?? Search;
            const color =
              SECTION_COLORS[section.kind] ??
              'text-body border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-surface-300/50';
            return (
              <section key={section.kind} className="surface-card overflow-hidden">
                <div
                  className={`flex items-center gap-2 px-4 py-2.5 border-b border-line-1 ${color.split(' ').slice(0, 1).join(' ')}`}
                >
                  <Icon size={14} />
                  <span className="font-display font-semibold text-sm">{section.label}</span>
                  <span className="text-mini font-mono opacity-70">· {section.total}</span>
                </div>
                <ul className="divide-y divide-line-1 dark:divide-slate-800/50">
                  {(section.items ?? []).slice(0, 30).map((item, i) => (
                    <li
                      key={`${item.label}:${i}`}
                      className="px-4 py-2.5 hover:bg-surface-200 dark:hover:bg-input-200/50"
                    >
                      {item.url ? (
                        <a
                          href={sanitizeUrl(item.url) || undefined}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-start justify-between gap-2 group"
                        >
                          <div className="min-w-0">
                            <span className="text-sm font-medium text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400 truncate block">
                              {item.label}
                            </span>
                            {item.description && (
                              <span className="text-mini font-mono text-muted mt-0.5 block truncate">
                                {item.description}
                              </span>
                            )}
                          </div>
                          <ExternalLink size={12} className="shrink-0 mt-1 text-muted group-hover:text-rose-500" />
                        </a>
                      ) : (
                        <div>
                          <span className="text-sm font-medium text-heading truncate block">{item.label}</span>
                          {item.description && (
                            <span className="text-mini font-mono text-muted mt-0.5 block truncate">
                              {item.description}
                            </span>
                          )}
                        </div>
                      )}
                      <span className="text-micro font-mono text-muted mt-1 block">
                        {item.source}
                        {item.subkind ? ` · ${item.subkind}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
                {(section.items ?? []).length > 30 && (
                  <div className="px-4 py-2 text-mini font-mono text-muted border-t border-line-1/50">
                    + {(section.items ?? []).length - 30} more
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </DataPageLayout>
  );
}
