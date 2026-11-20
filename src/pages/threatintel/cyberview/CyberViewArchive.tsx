import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Archive, ChevronDown, Download, ExternalLink, Info, Search, ShieldCheck } from 'lucide-react';
import { DataPageLayout } from '../../../components/DataPageLayout';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import { CyberViewNav } from './CyberViewNav';

/**
 * Replication of the CyberView "Archive" page. The upstream page reads a
 * compact search index and only loads a month's full records when a row is
 * opened; here every mirrored file is pulled through `useDataFetch` so the
 * whole page works offline from the public/data mirror. All rendered text is
 * plain React text nodes — no HTML injection.
 */

const BASE = '/data/cyberview/data/archive';
const PAGE = 60;
const RECENT_CAP = 40;
const RECENT_FEW = 5;
const FILED_HOURS = 48;
const LATE_HOURS = 36;
const HOUR_MS = 3_600_000;

const CATEGORIES: Array<{ value: string; label: string }> = [
  { value: 'incident', label: 'Incidents' },
  { value: 'vuln', label: 'Patches and advisories' },
  { value: 'report', label: 'Threat reports' },
  { value: 'policy', label: 'Law and policy' },
  { value: 'enforcement', label: 'Law enforcement' },
  { value: 'investment', label: 'Investment and vendors' },
  { value: 'outage', label: 'Outages' },
];
const CAT_LABEL: Record<string, string> = Object.fromEntries(CATEGORIES.map((c) => [c.value, c.label]));
const SEV_LABEL = ['', 'Low', 'Medium', 'High'];

/* ── Mirrored data shapes ─────────────────────────────────────────────────── */

interface ArchiveIndex {
  built_at: string;
  total: number;
  kev_total: number;
  months: Array<{ month: string; count: number; by_category: Record<string, number>; high: number }>;
}

interface SearchDoc {
  built_at: string;
  fields: string[];
  rows: unknown[][];
}

interface EventRow {
  id: string;
  date: string;
  category: string;
  severity: number;
  status: string;
  title: string;
  org: string;
  country: string;
  cves: string[];
  tags: string[];
  actor: string;
  first_seen: string;
}

interface Source {
  name?: string;
  url: string;
}
interface Validation {
  state?: string;
  note?: string;
  checked_at?: string;
}
interface Review {
  state?: string;
  at?: string;
  first_at?: string;
  note?: string;
  flags?: string[];
}
interface FullEvent {
  id: string;
  title: string;
  summary?: string;
  plain?: string;
  exec?: string;
  action?: string;
  date: string;
  date_note?: string;
  category: string;
  severity: number;
  status: string;
  country?: string;
  org?: string;
  actor?: string;
  cves?: string[];
  tags?: string[];
  sources?: Source[];
  validation?: Validation;
  review?: Review;
  qa_checked_at?: string;
  first_seen?: string;
  updated_at?: string;
}
interface MonthDoc {
  month: string;
  events: FullEvent[];
}
interface KevEntry {
  id?: string;
  cve?: string;
  name?: string;
}

/* ── Small pure helpers ───────────────────────────────────────────────────── */

function mapRows(doc: SearchDoc | null): EventRow[] {
  if (!doc) return [];
  const at = (name: string): number => doc.fields.indexOf(name);
  const iId = at('id');
  const iDate = at('date');
  const iCat = at('category');
  const iSev = at('severity');
  const iStatus = at('status');
  const iTitle = at('title');
  const iOrg = at('org');
  const iCountry = at('country');
  const iCves = at('cves');
  const iTags = at('tags');
  const iActor = at('actor');
  const iSeen = at('first_seen');
  const str = (r: unknown[], i: number): string => (i >= 0 && r[i] != null ? String(r[i]) : '');
  const list = (r: unknown[], i: number): string[] =>
    i >= 0 && Array.isArray(r[i]) ? (r[i] as unknown[]).map((v) => String(v)) : [];
  return (doc.rows ?? []).map((r) => ({
    id: str(r, iId),
    date: str(r, iDate),
    category: str(r, iCat),
    severity: Number(iSev >= 0 ? r[iSev] : 0) || 0,
    status: str(r, iStatus),
    title: str(r, iTitle),
    org: str(r, iOrg),
    country: str(r, iCountry),
    cves: list(r, iCves),
    tags: list(r, iTags),
    actor: str(r, iActor),
    first_seen: str(r, iSeen),
  }));
}

function parseMs(value: string): number {
  const n = Date.parse(value);
  return Number.isFinite(n) ? n : 0;
}

function fmtDate(value: string): string {
  if (!value) return '';
  const d = new Date(`${value.slice(0, 10)}T12:00:00Z`);
  return Number.isNaN(d.getTime())
    ? value
    : d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function fmtMonth(value: string): string {
  const d = new Date(`${value}-15T12:00:00Z`);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
}

function fmtStamp(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

function ago(iso: string, refMs: number): string {
  const t = parseMs(iso);
  if (!t || !refMs) return '';
  const minutes = Math.max(0, Math.round((refMs - t) / 60_000));
  if (minutes < 60) return `${minutes} min ago`;
  if (minutes < 1_440) return `${Math.round(minutes / 60)} h ago`;
  return `${Math.round(minutes / 1_440)} days ago`;
}

/* ── Hash deep-link state ─────────────────────────────────────────────────── */

interface Filters {
  q: string;
  month: string;
  cat: string;
  sev: string;
  claims: boolean;
  recent: boolean;
}
const EMPTY_FILTERS: Filters = { q: '', month: '', cat: '', sev: '', claims: false, recent: false };

function readHash(): Filters {
  if (typeof window === 'undefined') return EMPTY_FILTERS;
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  return {
    q: p.get('q') ?? '',
    month: p.get('month') ?? '',
    cat: p.get('cat') ?? '',
    sev: p.get('sev') ?? '',
    claims: p.get('claims') === '1',
    recent: p.has('recent'),
  };
}

function writeHash(f: Filters): void {
  if (typeof window === 'undefined') return;
  const p = new URLSearchParams();
  if (f.q.trim()) p.set('q', f.q.trim());
  if (f.month) p.set('month', f.month);
  if (f.cat) p.set('cat', f.cat);
  if (f.sev) p.set('sev', f.sev);
  if (f.claims) p.set('claims', '1');
  if (f.recent) p.set('recent', '1');
  const hash = p.toString();
  try {
    history.replaceState(null, '', hash ? `#${hash}` : `${location.pathname}${location.search}`);
  } catch {
    /* non-browser / restricted context — filtering still works in-memory */
  }
}

/* ── Per-month loader: keeps useDataFetch call counts stable ──────────────── */

function MonthLoader({ month, onData }: { month: string; onData: (month: string, doc: MonthDoc) => void }): null {
  const res = useDataFetch<MonthDoc>({ url: `${BASE}/${encodeURIComponent(month)}.json`, ttl: 600_000 });
  useEffect(() => {
    if (res.data) onData(month, res.data);
  }, [res.data, month, onData]);
  return null;
}

/* ── One expandable event row (shared by recent + full list) ──────────────── */

function EventRowView({
  row,
  full,
  open,
  loading,
  onToggle,
  filed,
  kevIds,
}: {
  row: EventRow;
  full?: FullEvent;
  open: boolean;
  loading?: boolean;
  onToggle: () => void;
  filed?: string;
  kevIds: Set<string>;
}): JSX.Element {
  const label = CAT_LABEL[row.category] ?? row.category;
  const severity = SEV_LABEL[row.severity] ?? '';
  const cves = full?.cves?.length ? full.cves : row.cves;
  const sources = (full?.sources ?? []).filter((s) => s && Boolean(sanitizeUrl(s.url)));
  const eventLink = `#q=${encodeURIComponent(row.id)}`;

  return (
    <li className="surface-card overflow-hidden rounded-xl border border-line-1">
      <button
        type="button"
        aria-expanded={open}
        aria-label={`${row.title}. ${fmtDate(row.date)}. ${filed ? `${filed}. ` : ''}${label}, ${severity}, ${row.org || 'unknown organisation'}, ${row.country || 'unknown country'}. ${open ? 'Collapse' : 'Expand'} details`}
        onClick={onToggle}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-wash"
      >
        <ChevronDown
          size={14}
          aria-hidden="true"
          className={`mt-1 shrink-0 text-muted transition-transform ${open ? 'rotate-180' : ''}`}
        />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="font-mono text-meta text-muted">{fmtDate(row.date)}</span>
            <span className="text-sm font-semibold leading-snug text-heading">{row.title}</span>
          </span>
          <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {filed && (
              <span className="rounded border border-brand-400/40 bg-brand-500/10 px-1.5 py-0.5 font-mono text-mini text-accent-text">
                {filed}
              </span>
            )}
            <span className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 font-mono text-mini text-body">
              {label}
            </span>
            <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini text-muted">
              {severity}
            </span>
            {row.status === 'claimed' && (
              <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-mini text-amber-700 dark:text-amber-300">
                Unverified claim
              </span>
            )}
            {row.org && <span className="font-mono text-mini text-muted">{row.org}</span>}
            {row.country && <span className="font-mono text-mini text-muted">{row.country}</span>}
            {cves.slice(0, 3).map((cve) => (
              <span
                key={cve}
                className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini text-accent-text"
                title={kevIds.has(cve) ? 'In CISA Known Exploited Vulnerabilities' : cve}
              >
                {cve}
                {kevIds.has(cve) && <span className="ml-1 text-rose-600 dark:text-rose-400">KEV</span>}
              </span>
            ))}
          </span>
        </span>
      </button>

      {open && (
        <div className="border-t border-line-1 bg-surface-100 px-4 py-4 text-sm leading-relaxed text-body">
          {loading && !full && <p className="font-mono text-meta text-muted">Loading event details…</p>}
          {!loading && !full && (
            <p className="font-mono text-meta text-muted">Details are not available for this event.</p>
          )}
          {full && (
            <div className="space-y-4">
              {full.summary && <p>{full.summary}</p>}

              <p className="font-mono text-mini text-muted">
                Researched and written by CyberView AI (a Claude model) from the sources listed.
              </p>

              {full.plain && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                    Plain English
                  </h4>
                  <p className="mt-1">{full.plain}</p>
                </section>
              )}
              {full.exec && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                    Executive risk
                  </h4>
                  <p className="mt-1">{full.exec}</p>
                </section>
              )}
              {full.action && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                    Recommended action
                  </h4>
                  <p className="mt-1">
                    <strong className="text-heading">Do:</strong> {full.action}
                  </p>
                </section>
              )}
              {full.date_note && <p className="font-mono text-mini text-muted">Date note: {full.date_note}</p>}

              {full.tags && full.tags.length > 0 && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">Tags</h4>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {full.tags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini text-muted"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </section>
              )}

              {cves.length > 0 && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                    Related CVEs
                  </h4>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {cves.map((cve) => (
                      <span
                        key={cve}
                        className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini text-accent-text"
                        title={kevIds.has(cve) ? 'In CISA Known Exploited Vulnerabilities' : cve}
                      >
                        {cve}
                        {kevIds.has(cve) && <span className="ml-1 text-rose-600 dark:text-rose-400">KEV</span>}
                      </span>
                    ))}
                  </div>
                </section>
              )}

              {sources.length > 0 && (
                <section>
                  <h4 className="font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                    Sources ({sources.length})
                  </h4>
                  <ul className="mt-1.5 space-y-1">
                    {sources.slice(0, 6).map((s, i) => {
                      const safe = sanitizeUrl(s.url);
                      return (
                        <li key={`${s.url}-${i}`}>
                          <a
                            href={safe}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-meta text-accent-text hover:underline"
                          >
                            {s.name || safe.replace(/^https?:\/\//, '').split('/')[0]}
                            <ExternalLink size={10} aria-hidden="true" />
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              )}

              <section className="rounded-lg border border-line-1 bg-surface-200 p-3">
                <h4 className="flex items-center gap-1.5 font-mono text-meta font-semibold uppercase tracking-wide text-heading">
                  <ShieldCheck size={13} aria-hidden="true" /> Validation &amp; QA
                </h4>
                <p className="mt-1.5 font-mono text-mini text-muted">
                  Validation: <span className="text-body">{full.validation?.state ?? 'not recorded'}</span>
                  {' · '}Review: <span className="text-body">{full.review?.state ?? 'not recorded'}</span>
                  {full.review?.flags && full.review.flags.length > 0 && ` · flags: ${full.review.flags.join(', ')}`}
                </p>
                {full.validation?.note && <p className="mt-1 text-meta text-body">{full.validation.note}</p>}
                {full.review?.note && (
                  <p className="mt-1 text-meta text-body">
                    <strong className="text-heading">Reviewer note:</strong> {full.review.note}
                  </p>
                )}
                <p className="mt-2 font-mono text-mini text-muted">
                  First seen {fmtStamp(full.first_seen ?? row.first_seen)} · Updated {fmtStamp(full.updated_at)}
                  {full.qa_checked_at ? ` · QA checked ${fmtStamp(full.qa_checked_at)}` : ''}
                </p>
              </section>

              <a
                href={eventLink}
                className="inline-flex items-center gap-1 font-mono text-meta text-accent-text hover:underline"
              >
                Link to this event <ExternalLink size={11} aria-hidden="true" />
              </a>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */

export default function CyberViewArchive({ bare = false }: { bare?: boolean }): JSX.Element {
  const index = useDataFetch<ArchiveIndex>({ url: `${BASE}/index.json`, ttl: 600_000 });
  const search = useDataFetch<SearchDoc>({ url: `${BASE}/search.json`, ttl: 600_000 });
  const kev = useDataFetch<KevEntry[]>({ url: `${BASE}/kev.json`, ttl: 600_000 });

  const [monthsData, setMonthsData] = useState<Record<string, FullEvent[]>>({});
  const [filters, setFilters] = useState<Filters>(() => readHash());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set<string>());
  const [shown, setShown] = useState<number>(PAGE);
  const [recentAll, setRecentAll] = useState(false);

  const handleMonthData = useCallback((month: string, doc: MonthDoc) => {
    setMonthsData((prev) => (prev[month] ? prev : { ...prev, [month]: doc.events ?? [] }));
  }, []);

  const monthKeys = useMemo(
    () =>
      (index.data?.months ?? [])
        .map((m) => m.month)
        .sort()
        .reverse(),
    [index.data]
  );

  const rows = useMemo(() => mapRows(search.data), [search.data]);
  const fullById = useMemo(() => {
    const by: Record<string, FullEvent> = {};
    Object.values(monthsData).forEach((events) =>
      events.forEach((e) => {
        by[e.id] = e;
      })
    );
    return by;
  }, [monthsData]);
  const kevIds = useMemo(() => {
    const set = new Set<string>();
    (kev.data ?? []).forEach((k) => {
      if (k.cve) set.add(k.cve);
      if (k.id) set.add(k.id);
    });
    return set;
  }, [kev.data]);

  // An unverified claim is a `claimed` row (upstream's 33 hidden claims).
  // The full record's validation state is used as a second signal when present.
  const isUnverified = useCallback(
    (r: EventRow): boolean => {
      if (r.status === 'claimed') return true;
      const state = fullById[r.id]?.validation?.state ?? '';
      return state === 'unconfirmed_claim' || state === 'unverified';
    },
    [fullById]
  );

  const refMs = useMemo(() => rows.reduce((max, r) => Math.max(max, parseMs(r.first_seen)), 0), [rows]);
  const earliest = useMemo(
    () => rows.reduce((min, r) => (r.date && r.date < min ? r.date : min), '9999-99-99'),
    [rows]
  );
  const claimCount = useMemo(() => rows.filter(isUnverified).length, [rows, isUnverified]);

  const filtered = useMemo(() => {
    const needle = filters.q.trim().toLowerCase();
    const sevMin = Number(filters.sev || 0);
    return rows.filter((r) => {
      if (!filters.claims && isUnverified(r)) return false;
      if (filters.month && r.date.slice(0, 7) !== filters.month) return false;
      if (filters.cat && r.category !== filters.cat) return false;
      if (sevMin && r.severity < sevMin) return false;
      if (!needle) return true;
      const e = fullById[r.id];
      return [r.title, r.org, r.country, r.actor, r.cves.join(' '), r.tags.join(' '), r.id, e?.summary, e?.plain]
        .join(' ')
        .toLowerCase()
        .includes(needle);
    });
  }, [rows, filters, fullById, isUnverified]);

  const recentRows = useMemo(() => {
    return rows
      .filter((r) => {
        const filed = parseMs(r.first_seen);
        const happened = parseMs(`${r.date}T23:59:59Z`);
        return (
          Boolean(filed) &&
          Boolean(happened) &&
          refMs - filed < FILED_HOURS * HOUR_MS &&
          filed - happened > LATE_HOURS * HOUR_MS &&
          !isUnverified(r)
        );
      })
      .sort((a, b) => parseMs(b.first_seen) - parseMs(a.first_seen))
      .slice(0, RECENT_CAP);
  }, [rows, refMs, isUnverified]);

  // Hash → state (external links / browser back-forward), state → hash.
  useEffect(() => {
    const onHashChange = () => setFilters(readHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  useEffect(() => {
    writeHash(filters);
    setShown(PAGE);
  }, [filters]);

  const patch = useCallback((p: Partial<Filters>) => setFilters((prev) => ({ ...prev, ...p })), []);
  const toggleRow = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // #q=<event id> deep-links straight into a single event, as upstream does.
  // The ref makes this a one-shot per id so collapsing the row stays collapsed.
  const autoOpened = useRef<string | null>(null);
  useEffect(() => {
    const q = filters.q.trim();
    if (!q || autoOpened.current === q) return;
    if (!rows.some((r) => r.id === q) || filtered.length !== 1) return;
    autoOpened.current = q;
    setExpanded((prev) => new Set(prev).add(q));
  }, [filters.q, rows, filtered.length]);

  const recentExpanded = recentAll || filters.recent;
  const visible = filtered.slice(0, shown);
  const allLoaded = monthKeys.every((m) => Boolean(monthsData[m]));
  // Month detail files are large, so don't block the whole page on them —
  // individual expanded rows show their own loading state until a month lands.
  const loading = index.loading || search.loading || kev.loading;
  const error = index.error ?? search.error ?? kev.error;

  const body = (
    <>
      <CyberViewNav />

      <div className="space-y-8">
        <header className="space-y-2">
          <h1 className="text-2xl font-display font-semibold text-heading sm:text-3xl">Every event on file</h1>
          <p className="max-w-3xl text-sm leading-relaxed text-muted" aria-live="polite">
            {rows.length - claimCount} checked events since{' '}
            {earliest === '9999-99-99' ? 'the start' : fmtDate(earliest)}
            {claimCount > 0
              ? `, plus ${claimCount} unverified claim${claimCount === 1 ? '' : 's'} (hidden unless you include them)`
              : ''}
            . The map shows today and the six days before; everything else lives here.
          </p>
        </header>

        {(index.loading || search.loading) && !rows.length && (
          <p className="font-mono text-meta text-muted">Loading the archive index…</p>
        )}
        {error && <p className="font-mono text-meta text-rose-500">error: {error}</p>}

        {recentRows.length > 0 && (
          <section id="recent" aria-labelledby="recent-head" className="space-y-3">
            <div>
              <h2 id="recent-head" className="text-lg font-semibold text-heading">
                Recently filed ({recentRows.length})
              </h2>
              <p className="mt-1 max-w-3xl text-meta leading-relaxed text-muted">
                Events that research added in the last 48 hours but that happened earlier. The map&rsquo;s “Just added”
                list shows only new events, so these are filed here, each with the day it happened and when CyberView
                filed it.
              </p>
            </div>
            <ol className="space-y-2">
              {(recentExpanded ? recentRows : recentRows.slice(0, RECENT_FEW)).map((r) => (
                <EventRowView
                  key={`recent-${r.id}`}
                  row={r}
                  full={fullById[r.id]}
                  loading={!fullById[r.id] && !allLoaded}
                  open={expanded.has(r.id)}
                  onToggle={() => toggleRow(r.id)}
                  filed={`Filed ${ago(r.first_seen, refMs)}, happened ${fmtDate(r.date)}`}
                  kevIds={kevIds}
                />
              ))}
            </ol>
            {recentRows.length > RECENT_FEW && (
              <button
                type="button"
                onClick={() => {
                  setRecentAll(!recentExpanded);
                  patch({ recent: !recentExpanded });
                }}
                className="rounded-control border border-line-1 bg-surface-100 px-3 py-1.5 font-mono text-meta text-accent-text transition-colors hover:bg-wash"
              >
                {recentExpanded ? 'Show fewer' : `Show all ${recentRows.length}`}
              </button>
            )}
          </section>
        )}

        <section aria-label="Archive filters" className="surface-card rounded-xl border border-line-1 p-4">
          <form onSubmit={(e) => e.preventDefault()} role="search" className="flex flex-wrap items-end gap-3">
            <label className="min-w-[220px] flex-1">
              <span className="mb-1 block font-mono text-mini uppercase tracking-wide text-muted">Search</span>
              <span className="relative block">
                <Search
                  size={14}
                  aria-hidden="true"
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"
                />
                <input
                  type="search"
                  value={filters.q}
                  onChange={(e) => patch({ q: e.target.value })}
                  placeholder="Organisation, actor, CVE, country, tag"
                  aria-label="Search archived events"
                  className="w-full rounded-control border border-line-input bg-input-200 py-1.5 pl-8 pr-2 font-mono text-meta text-heading placeholder:text-muted"
                />
              </span>
            </label>
            <label>
              <span className="mb-1 block font-mono text-mini uppercase tracking-wide text-muted">Month</span>
              <select
                value={filters.month}
                onChange={(e) => patch({ month: e.target.value })}
                aria-label="Filter by month"
                className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading"
              >
                <option value="">All months</option>
                {monthKeys.map((m) => (
                  <option key={m} value={m}>
                    {fmtMonth(m)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="mb-1 block font-mono text-mini uppercase tracking-wide text-muted">Category</span>
              <select
                value={filters.cat}
                onChange={(e) => patch({ cat: e.target.value })}
                aria-label="Filter by category"
                className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading"
              >
                <option value="">All categories</option>
                {CATEGORIES.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="mb-1 block font-mono text-mini uppercase tracking-wide text-muted">Severity</span>
              <select
                value={filters.sev}
                onChange={(e) => patch({ sev: e.target.value })}
                aria-label="Filter by minimum severity"
                className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading"
              >
                <option value="">Any severity</option>
                <option value="1">Low and above</option>
                <option value="2">Medium and above</option>
                <option value="3">High</option>
              </select>
            </label>
            <label className="flex items-center gap-2 pb-1.5 font-mono text-meta text-body">
              <input
                type="checkbox"
                checked={filters.claims}
                onChange={(e) => patch({ claims: e.target.checked })}
                className="h-4 w-4 rounded border-line-input"
              />
              Include unverified claims
            </label>
          </form>
        </section>

        <section aria-label="Event list" className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="font-mono text-meta text-muted" aria-live="polite">
              {filtered.length} event{filtered.length === 1 ? '' : 's'}
              {filtered.length > shown ? `, showing ${shown}` : ''}
              {filters.month ? ` · ${fmtMonth(filters.month)}` : ''}
            </p>
            {!filters.claims && claimCount > 0 && (
              <p className="flex items-center gap-1.5 font-mono text-mini text-muted">
                <Info size={12} aria-hidden="true" />
                {claimCount} unverified claim{claimCount === 1 ? '' : 's'} hidden — tick “Include unverified claims” to
                show them.
              </p>
            )}
          </div>

          {visible.length === 0 ? (
            <p className="surface-card rounded-xl border border-dashed border-line-1 px-4 py-10 text-center text-sm text-muted">
              Nothing matches. Clear a filter or try another word.
            </p>
          ) : (
            <ol className="space-y-2">
              {visible.map((r) => (
                <EventRowView
                  key={r.id}
                  row={r}
                  full={fullById[r.id]}
                  loading={!fullById[r.id] && !allLoaded}
                  open={expanded.has(r.id)}
                  onToggle={() => toggleRow(r.id)}
                  kevIds={kevIds}
                />
              ))}
            </ol>
          )}

          {filtered.length > shown && (
            <button
              type="button"
              onClick={() => setShown((n) => n + PAGE)}
              className="rounded-control border border-line-1 bg-surface-100 px-4 py-2 font-mono text-meta font-semibold text-accent-text transition-colors hover:bg-wash"
            >
              Show more
            </button>
          )}
        </section>

        <section
          aria-labelledby="download-head"
          className="surface-card space-y-2 rounded-xl border border-line-1 bg-wash p-4"
        >
          <h2 id="download-head" className="flex items-center gap-2 text-base font-semibold text-heading">
            <Download size={16} aria-hidden="true" /> Download the data
          </h2>
          <p className="text-meta leading-relaxed text-muted">
            The full history in open formats, rebuilt on every update:{' '}
            <a href={`${BASE}/search.json`} className="text-accent-text hover:underline">
              every event (search index, JSON)
            </a>
            ,{' '}
            <a href={`${BASE}/kev.json`} className="text-accent-text hover:underline">
              every known-exploited entry (JSON)
            </a>
            ,{' '}
            <a href={`${BASE}/events.json`} className="text-accent-text hover:underline">
              full event records (JSON)
            </a>
            ,{' '}
            <a href={`${BASE}/index.json`} className="text-accent-text hover:underline">
              monthly index (JSON)
            </a>
            .
          </p>
          <p className="font-mono text-mini text-muted">
            Mirrored {fmtStamp(index.data?.built_at ?? search.data?.built_at)}
            {index.data ? ` · ${index.data.total} events · ${index.data.kev_total} KEV entries` : ''}. No unverified
            claims are included in the feeds.
          </p>
        </section>
      </div>

      <footer className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-4 font-mono text-mini text-muted">
        <span>CyberView archive — community research, AI-researched and reviewed.</span>
        <span className="ml-auto">
          Built {fmtStamp(index.data?.built_at ?? search.data?.built_at)} · {monthKeys.length} monthly file
          {monthKeys.length === 1 ? '' : 's'}
        </span>
      </footer>
    </>
  );

  return bare ? (
    <>
      {monthKeys.map((m) => (
        <MonthLoader key={m} month={m} onData={handleMonthData} />
      ))}
      {body}
    </>
  ) : (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Archive size={28} />}
      title="CyberView — Archive"
      description="Replication of CyberView's archive: every checked cyber event, with month/category/severity filters and full event detail."
      loading={loading}
      error={error}
      onRetry={() => {
        index.refetch();
        search.refetch();
        kev.refetch();
      }}
      maxWidthClass="max-w-6xl"
    >
      {monthKeys.map((m) => (
        <MonthLoader key={m} month={m} onData={handleMonthData} />
      ))}
      {body}
    </DataPageLayout>
  );
}
