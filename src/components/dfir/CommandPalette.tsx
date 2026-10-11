import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, Command, ArrowRight, Loader2 } from 'lucide-react';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { SECTIONS, type Tool } from './ToolGrid';
import { useFeatures, toolVisible } from '../../lib/features';
import { detectIoc as detectIocBase, type IocType as BaseIocType } from '../../lib/dfir/ioc-detect';
import {
  loadCatalogIndex,
  KIND_LABEL,
  KIND_PILL,
  KIND_PRIORITY,
  type SearchEntry,
  type SearchKind,
} from '../../data/dfir/searchable-content';

/**
 * Cmd+K command palette. Mounted globally in App.tsx so it's reachable
 * from every route. Opens on Cmd+K (Ctrl+K on Linux/Windows), closes on
 * Esc / outside-click / selection.
 *
 * Search index has two layers:
 *   - Tools (61, synchronous) - the SECTIONS tile grid. Available the
 *     instant the palette opens.
 *   - Catalog content (~340 lazy, async) - wiki articles, Telegram
 *     channels, SecOps catalog, CVE resources, threat
 *     actors. Loaded once on first palette open and cached.
 *
 * Substring search, AND-tokenised on whitespace. Results sort by KIND_PRIORITY
 * (tools → wiki → actors → telegram → cve → secops) so the most
 * action-oriented hits surface first. A kind-filter chip row narrows the
 * result space when the index gets large.
 *
 * Recently-visited paths are stored in localStorage and shown when the
 * palette opens with no query.
 */

const RECENT_KEY = 'dfir.cmdk.recent';
const RECENT_MAX = 5;
const SHOW_LIMIT = 40;

interface FlatTool extends Tool {
  sectionLabel: string;
}

const TOOLS_FLAT: FlatTool[] = SECTIONS.flatMap((s) => s.tools.map((t) => ({ ...t, sectionLabel: s.label })));

/** Tools converted into the unified SearchEntry shape so the index is uniform. */
const TOOL_ENTRIES: SearchEntry[] = TOOLS_FLAT.map((t) => ({
  kind: 'tool',
  label: t.label,
  desc: t.desc,
  path: t.path,
  sectionLabel: t.sectionLabel,
}));

/** Path → icon component, populated from ToolGrid for the tool-kind rows. */
const TOOL_ICONS = new Map(TOOLS_FLAT.map((t) => [t.path, t.icon]));

/** Path → deployment flag gating the tool, for tools that have one. */
const TOOL_FLAG_BY_PATH = new Map(TOOLS_FLAT.map((t) => [t.path, t.requiresFlag]));

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as unknown;
    if (!Array.isArray(arr)) return [];
    return arr.filter((s) => typeof s === 'string').slice(0, RECENT_MAX);
  } catch {
    return [];
  }
}

function pushRecent(path: string): void {
  try {
    const cur = loadRecent().filter((p) => p !== path);
    cur.unshift(path);
    localStorage.setItem(RECENT_KEY, JSON.stringify(cur.slice(0, RECENT_MAX)));
  } catch {
    /* private mode / quota - silent */
  }
}

interface MatchedEntry extends SearchEntry {
  matchedBy: 'recent' | 'search' | 'pivot';
}

/**
 * Detect whether a query string is an IOC.
 * Pure regex - no network. Used to synthesize "pivot" entries at the top of
 * the command-palette results so typing e.g. "1.2.3.4" surfaces:
 *   → Check 1.2.3.4 in IOC Checker
 *   → Lookup 1.2.3.4 in ASN tool
 * Coverage:
 *   - Network indicators: IP, IPv6, domain, URL
 *   - File indicators: MD5, SHA-1, SHA-256
 *   - Vuln + actor identifiers: CVE, MITRE ATT&CK technique (Txxxx), MITRE Group ID (Gxxxx)
 *   - Identity indicators: ASN, email address, BTC address
 *   - Free-form: ransomware actor name (matched against curated lookup)
 */
type IocType = BaseIocType | 'actor-slug';

/** Known ransomware/APT actor slugs - kept in sync with api/src/lib/ransomware-mitre-groups.ts. */
const KNOWN_ACTOR_SLUGS = new Set([
  'lockbit',
  'alphv',
  'blackcat',
  'cl0p',
  'clop',
  'akira',
  'play',
  'playcrypt',
  'black basta',
  'blackbasta',
  'royal',
  'medusa',
  'bianlian',
  'qilin',
  'agenda',
  'conti',
  'revil',
  'sodinokibi',
  'darkside',
  'blackbyte',
  'hive',
  'ryuk',
  'ragnarlocker',
  'ragnar locker',
  'rhysida',
  'volt-typhoon',
  'lazarus-group',
  'fancy-bear',
]);

function detectIoc(raw: string): { type: IocType; value: string } | null {
  // Shared single-indicator detector (lib/dfir/ioc-detect), with the
  // palette-only actor-slug match layered on top. Detection logic is no
  // longer duplicated here - it lives in one place.
  const base = detectIocBase(raw);
  if (base) return base;
  const lower = raw.trim().toLowerCase();
  if (lower.length >= 3 && lower.length <= 30 && KNOWN_ACTOR_SLUGS.has(lower)) {
    return { type: 'actor-slug', value: lower };
  }
  return null;
}

/**
 * Build pivot entries for a detected IOC. Each pivot becomes a synthetic
 * top-row in the command palette that navigates to a tool route with the
 * indicator pre-filled.
 */
function buildPivots(query: string): MatchedEntry[] {
  const ioc = detectIoc(query);
  if (!ioc) return [];
  const enc = encodeURIComponent(ioc.value);
  const pivots: MatchedEntry[] = [];

  if (ioc.type === 'cve') {
    pivots.push({
      kind: 'tool',
      label: `CVE Lookup → ${ioc.value}`,
      desc: 'NVD + CISA KEV + heuristic actor scanning',
      path: `/dfir/cve?q=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    pivots.push({
      kind: 'tool',
      label: `CVE list page → search for ${ioc.value}`,
      desc: 'Filter platform CVE list - see actor pills + KEV flags inline',
      path: `/threatintel/cve-list?q=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  if (ioc.type === 'mitre-technique') {
    pivots.push({
      kind: 'tool',
      label: `MITRE technique → ${ioc.value}`,
      desc: 'Open ATT&CK matrix scoped to this technique - actors, mitigations, detections',
      path: `/threatintel/mitre?id=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  if (ioc.type === 'mitre-group') {
    pivots.push({
      kind: 'tool',
      label: `MITRE Group → ${ioc.value}`,
      desc: 'Open ATT&CK Group profile (techniques, software, references)',
      path: `https://attack.mitre.org/groups/${enc}/`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  if (ioc.type === 'asn') {
    pivots.push({
      kind: 'tool',
      label: `ASN Lookup → ${ioc.value}`,
      desc: 'Routes + prefixes + neighbours via team-cymru / RIPE',
      path: `/dfir/asn?asn=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  if (ioc.type === 'email') {
    pivots.push({
      kind: 'tool',
      label: `Breach check → ${ioc.value}`,
      desc: 'Have-I-Been-Pwned breach exposure for this address',
      path: `/dfir/breach?email=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  if (ioc.type === 'actor-slug') {
    pivots.push({
      kind: 'tool',
      label: `Actor timeline → ${ioc.value}`,
      desc: 'Gantt of leak-site cadence + MITRE Group profile + TTPs',
      path: `/threatintel/actor-timeline?actor=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    pivots.push({
      kind: 'tool',
      label: `Threat actors catalogue → ${ioc.value}`,
      desc: 'Curated APT/ransomware profile with full TTPs',
      path: `/threatintel/actors/${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    return pivots;
  }

  // All non-CVE IOCs get IOC Checker as the primary pivot.
  pivots.push({
    kind: 'tool',
    label: `IOC Checker → ${ioc.value}`,
    desc: `Run ${ioc.type} through 20+ providers (VT, AbuseIPDB, OTX, GreyNoise, threatfox, urlhaus, …)`,
    path: `/dfir/ioc-check?indicator=${enc}`,
    sectionLabel: 'IOC pivot',
    matchedBy: 'pivot',
  });

  // Cross-source correlation lookup is universal for network indicators -
  // the page's text filter accepts the indicator value directly.
  if (ioc.type === 'ip' || ioc.type === 'ipv6' || ioc.type === 'domain' || ioc.type === 'url') {
    pivots.push({
      kind: 'tool',
      label: `Correlation lookup → ${ioc.value.slice(0, 60)}${ioc.value.length > 60 ? '…' : ''}`,
      desc: 'Is this indicator in 2+ feeds? Confidence + per-feed attribution',
      // IocCorrelation owns the ?q= indicator filter; /threatintel/correlation
      // is a different page (sector cross-correlate) with no query box.
      path: `/threatintel/iocs/correlation?q=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
  }

  // Kind-specific secondary pivots.
  if (ioc.type === 'ip' || ioc.type === 'ipv6') {
    pivots.push({
      kind: 'tool',
      label: `IP Geolocation → ${ioc.value}`,
      desc: 'Country / city / ISP / org via ip-api.com',
      path: `/dfir/ioc-investigate?indicator=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
  } else if (ioc.type === 'domain') {
    pivots.push({
      kind: 'tool',
      label: `Domain Lookup → ${ioc.value}`,
      desc: 'WHOIS + DNS records + subdomains + cert transparency',
      path: `/dfir/domain-investigator?domain=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    pivots.push({
      kind: 'tool',
      label: `Cert Search → ${ioc.value}`,
      desc: 'crt.sh certificate transparency log lookup',
      path: `/dfir/cert-search?q=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
  } else if (ioc.type === 'url') {
    pivots.push({
      kind: 'tool',
      label: `URL Preview → ${ioc.value}`,
      desc: 'Server-side fetch + screenshot + headers - safe to inspect',
      path: `/dfir/url-preview?url=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
    pivots.push({
      kind: 'tool',
      label: `Wayback CDX → ${ioc.value}`,
      desc: 'Archive.org historical captures of this URL',
      path: `/dfir/wayback?url=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
  } else if (ioc.type.startsWith('hash-')) {
    pivots.push({
      kind: 'tool',
      label: `File Analysis → ${ioc.value.slice(0, 24)}…`,
      desc: 'Hash lookup across malware sample sources',
      // IOC Investigator's checker consumes ?indicator= for every type incl. hashes.
      path: `/dfir/ioc-investigate?indicator=${enc}`,
      sectionLabel: 'IOC pivot',
      matchedBy: 'pivot',
    });
  }

  return pivots;
}

function searchEntries(
  query: string,
  recent: string[],
  index: SearchEntry[],
  kindFilter: SearchKind | null
): MatchedEntry[] {
  const q = query.trim().toLowerCase();
  const filtered = kindFilter ? index.filter((e) => e.kind === kindFilter) : index;

  if (!q) {
    // No query: show recent paths first (only if they're in the current
    // filter), then fillers from the filtered set.
    const recentSet = new Set(recent);
    const recentEntries = recent
      .map((p) => filtered.find((e) => e.path === p))
      .filter((e): e is SearchEntry => Boolean(e))
      .map<MatchedEntry>((e) => ({ ...e, matchedBy: 'recent' }));
    const fillers = filtered
      .filter((e) => !recentSet.has(e.path))
      .sort((a, b) => KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind])
      .slice(0, SHOW_LIMIT - recentEntries.length)
      .map<MatchedEntry>((e) => ({ ...e, matchedBy: 'search' }));
    return [...recentEntries, ...fillers];
  }

  const tokens = q.split(/\s+/).filter(Boolean);
  return filtered
    .filter((e) => {
      const hay = `${e.label} ${e.desc} ${e.sectionLabel}`.toLowerCase();
      return tokens.every((tok) => hay.includes(tok));
    })
    .sort((a, b) => {
      // Primary sort: kind priority. Within same kind, prefer earlier label
      // matches (so a query "ioc" surfaces "IOC Checker" before "IOC Extractor").
      const dk = KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind];
      if (dk !== 0) return dk;
      const firstToken = tokens[0]!;
      const aIdx = a.label.toLowerCase().indexOf(firstToken);
      const bIdx = b.label.toLowerCase().indexOf(firstToken);
      const ax = aIdx < 0 ? 999 : aIdx;
      const bx = bIdx < 0 ? 999 : bIdx;
      return ax - bx;
    })
    .slice(0, SHOW_LIMIT)
    .map<MatchedEntry>((e) => ({ ...e, matchedBy: 'search' }));
}

const KIND_FILTER_ORDER: SearchKind[] = ['tool', 'wiki', 'actor', 'telegram', 'cve', 'secops'];

export function CommandPalette(): JSX.Element | null {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const [recent, setRecent] = useState<string[]>([]);
  const [catalog, setCatalog] = useState<SearchEntry[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [kindFilter, setKindFilter] = useState<SearchKind | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);
  const catalogLoadedRef = useRef(false);

  const features = useFeatures();

  const dialogRef = useFocusTrap({ isActive: open, onEscape: () => setOpen(false) });

  // Open on Cmd+K / Ctrl+K. Close on Esc.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((v) => !v);
        return;
      }
      if (open && e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  // Body-scroll lock while the palette is open (same treatment as Modal /
  // Drawer / mobile menu — without it, wheel + touch scroll the page behind
  // the fixed backdrop and the background rubber-bands on mobile).
  useEffect(() => {
    if (!open) return;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.overflow = 'hidden';
    document.body.style.paddingRight = `${scrollbarWidth}px`;
    return () => {
      document.body.style.overflow = '';
      document.body.style.paddingRight = '';
    };
  }, [open]);

  // When opening, hydrate recent + reset state + focus input + kick off
  // catalog lazy-load (only once per session).
  useEffect(() => {
    if (!open) return;
    const r = loadRecent();
    setRecent(r);
    setQuery('');
    setActiveIdx(0);
    setKindFilter(null);
    setTimeout(() => inputRef.current?.focus(), 0);

    if (!catalogLoadedRef.current) {
      catalogLoadedRef.current = true;
      setCatalogLoading(true);
      void loadCatalogIndex()
        .then((entries) => setCatalog(entries))
        .finally(() => setCatalogLoading(false));
    }
  }, [open]);

  const fullIndex = useMemo<SearchEntry[]>(
    () => [...TOOL_ENTRIES.filter((e) => toolVisible(TOOL_FLAG_BY_PATH.get(e.path), features)), ...catalog],
    [catalog, features]
  );
  const matches = useMemo(() => {
    const base = searchEntries(query, recent, fullIndex, kindFilter);
    // Pivots + the live-search launcher only when no kind-filter is active
    // (otherwise they'd be silently hidden by the filter, which is confusing).
    if (kindFilter && kindFilter !== 'tool') return base;
    const q = query.trim();
    // Always-present launcher into the upgraded Unified Search omnibox (tools +
    // live threat data). Lives at the very top so Enter on any query opens it.
    const launcher: MatchedEntry[] = q
      ? [
          {
            kind: 'tool',
            label: `Search live intel for "${q}"`,
            desc: 'Unified omnibox - tools + live threat data (ransomware, IOCs, CVEs, actors, breaches)',
            path: `/threatintel/unified-search?q=${encodeURIComponent(q)}`,
            sectionLabel: 'Live search',
            matchedBy: 'pivot',
          },
        ]
      : [];
    const pivots = buildPivots(query);
    return [...launcher, ...pivots, ...base];
  }, [query, recent, fullIndex, kindFilter]);

  const select = useCallback(
    (path: string) => {
      pushRecent(path);
      setOpen(false);
      navigate(path);
    },
    [navigate]
  );

  // Arrow-key navigation.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((i) => Math.min(i + 1, matches.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const m = matches[activeIdx];
        if (m) select(m.path);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, matches, activeIdx, select]);

  // Reset active index when matches change (query / filter shift).
  useEffect(() => {
    setActiveIdx(0);
  }, [query, kindFilter]);

  // Scroll active item into view.
  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.querySelector<HTMLElement>(`[data-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIdx, open]);

  // Counts per kind for the filter chip row, computed against the *full*
  // un-filtered index so the chip labels show the total per kind, not what
  // would survive the current chip's own filter.
  const kindCounts = useMemo(() => {
    const map = new Map<SearchKind, number>();
    for (const e of fullIndex) map.set(e.kind, (map.get(e.kind) ?? 0) + 1);
    return map;
  }, [fullIndex]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      ref={dialogRef as React.RefObject<HTMLDivElement>}
    >
      {/* Backdrop */}
      <button
        type="button"
        onClick={() => setOpen(false)}
        className="absolute inset-0 bg-surface-100/60 backdrop-blur-sm"
        aria-label="Close command palette"
      />

      {/* Modal */}
      <div className="relative w-full max-w-2xl rounded border border-line-1 bg-surface-100 shadow-e3 overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-line-1">
          <Search size={18} className="text-muted shrink-0" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded={matches.length > 0}
            aria-controls="cp-listbox"
            aria-activedescendant={matches.length > 0 ? `cp-option-${activeIdx}` : undefined}
            aria-autocomplete="list"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Search ${fullIndex.length} items - tools, wiki, channels, actors…`}
            className="flex-1 bg-transparent border-0 outline-none font-mono text-sm text-heading placeholder:text-muted"
            aria-label="Search"
          />
          {catalogLoading && (
            <Loader2 size={14} className="text-muted animate-spin shrink-0" aria-label="Loading catalog index" />
          )}
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="p-1 rounded text-muted hover:text-body dark:hover:text-inverted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        {/* Kind filter chip row */}
        <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 border-b border-line-1">
          <button
            type="button"
            onClick={() => setKindFilter(null)}
            className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border focus-visible:ring-2 focus-visible:ring-brand-500 ${
              kindFilter === null
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-brand-500/40'
            }`}
          >
            all <span className="opacity-60">· {fullIndex.length}</span>
          </button>
          {KIND_FILTER_ORDER.map((k) => {
            const count = kindCounts.get(k) ?? 0;
            if (count === 0) return null;
            const active = kindFilter === k;
            return (
              <button
                key={k}
                type="button"
                onClick={() => setKindFilter(active ? null : k)}
                className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border focus-visible:ring-2 focus-visible:ring-brand-500 ${
                  active ? KIND_PILL[k] : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-brand-500/40'
                }`}
              >
                {KIND_LABEL[k]} <span className="opacity-60">· {count}</span>
              </button>
            );
          })}
        </div>

        <ul
          ref={listRef}
          role="listbox"
          id="cp-listbox"
          aria-label="Search results"
          className="max-h-[55vh] overflow-y-auto py-2"
        >
          {matches.length === 0 && (
            <li className="px-4 py-3 text-sm font-mono text-muted">No matches for "{query}".</li>
          )}
          {matches.map((m, idx) => {
            const Icon = m.kind === 'tool' ? TOOL_ICONS.get(m.path) : null;
            const active = idx === activeIdx;
            return (
              <li
                key={`${m.kind}:${m.path}`}
                role="option"
                id={`cp-option-${idx}`}
                aria-selected={active}
                data-idx={idx}
              >
                <button
                  type="button"
                  onClick={() => select(m.path)}
                  onMouseEnter={() => setActiveIdx(idx)}
                  className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                    active ? 'bg-brand-500/10 text-heading' : 'text-body hover:bg-slate-100 dark:hover:bg-surface-300'
                  }`}
                >
                  {Icon ? (
                    <Icon size={16} className={active ? 'text-brand-600 dark:text-brand-400' : 'text-slate-500'} />
                  ) : (
                    <span
                      className={`w-4 text-center text-micro font-mono uppercase tracking-wider ${
                        active ? 'text-brand-600 dark:text-brand-400' : 'text-muted'
                      }`}
                      aria-hidden="true"
                    >
                      {m.kind === 'wiki'
                        ? 'W'
                        : m.kind === 'telegram'
                          ? 'T'
                          : m.kind === 'secops'
                            ? 'S'
                            : m.kind === 'cve'
                              ? 'C'
                              : m.kind === 'actor'
                                ? 'A'
                                : '·'}
                    </span>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2">
                      <span className="font-display font-semibold text-sm truncate">{m.label}</span>
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-1 rounded border ${KIND_PILL[m.kind]} shrink-0`}
                      >
                        {KIND_LABEL[m.kind]}
                      </span>
                      {m.matchedBy === 'recent' && (
                        <span className="text-micro uppercase tracking-wider px-1 rounded border border-cyan-500/30 bg-cyan-500/5 text-sky-700 dark:text-sky-300">
                          recent
                        </span>
                      )}
                      {m.matchedBy === 'pivot' && (
                        <span className="text-micro uppercase tracking-wider px-1 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                          pivot
                        </span>
                      )}
                    </div>
                    <div className="text-mini font-mono text-muted truncate">
                      {m.sectionLabel} · {m.desc}
                    </div>
                  </div>
                  {active && <ArrowRight size={14} className="text-brand-600 dark:text-brand-400 shrink-0" />}
                </button>
              </li>
            );
          })}
        </ul>

        <div className="border-t border-line-1 px-4 py-2 text-micro font-mono text-muted flex items-center gap-3">
          <Command size={10} aria-hidden="true" />
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
          <span className="ml-auto">⌘K to toggle</span>
        </div>
      </div>
    </div>
  );
}
