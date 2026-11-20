import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Archive, ChevronDown, Download, ExternalLink, Info, Search, ShieldCheck } from 'lucide-react';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import { asArray, matches, text } from './shared-utils';
import { Badge, CyberViewPage, Empty, OutLink } from './shared-ui';
import { AiSummaryCard } from '../../../components/intel/AiSummaryCard';

// prettier-ignore
const mod = (() => {
  /** Replication of CyberView's event archive, served entirely from the public/data mirror. */
  const BASE = '/data/cyberview/data/archive';
  const PAGE = 60, RECENT_CAP = 40, RECENT_FEW = 5, HOUR_MS = 3_600_000;
  const opts = (s: string): Array<[string, string]> => s.split(',').map((p) => p.split('|') as [string, string]);
  const CATEGORIES = opts('incident|Incidents,vuln|Patches and advisories,report|Threat reports,policy|Law and policy,enforcement|Law enforcement,investment|Investment and vendors,outage|Outages');
  const CAT_LABEL = Object.fromEntries(CATEGORIES);
  const SEV_LABEL = ['', 'Low', 'Medium', 'High'];
  const SEV_OPTS = opts('|Any severity,1|Low and above,2|Medium and above,3|High');
  const FEEDS = opts('search.json|every event (search index, JSON),kev.json|every known-exploited entry (JSON),events.json|full event records (JSON),index.json|monthly index (JSON)');
  const H4 = 'font-mono text-meta font-semibold uppercase tracking-wide text-heading';
  const LABEL = 'mb-1 block font-mono text-mini uppercase tracking-wide text-muted';
  const MUTED = 'font-mono text-mini text-muted';
  const CVE = 'inline-flex rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini text-accent-text';
  const SELECT = 'rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading';
  const BTN = 'rounded-control border border-line-1 bg-surface-100 px-3 py-1.5 font-mono text-meta text-accent-text hover:bg-wash';
  const CHEVRON = 'mt-1 shrink-0 text-muted transition-transform';
  const LINK = 'inline-flex items-center gap-1 font-mono text-meta text-accent-text hover:underline';
  const PANEL = 'surface-card space-y-2 rounded-xl border border-line-1 bg-wash p-4';
  const FOOT = 'mt-8 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-4 font-mono text-mini text-muted';

  type Opt = [string, string];
  type ArchiveIndex = { built_at: string; total: number; kev_total: number; months: { month: string }[] };
  type SearchDoc = { built_at: string; fields: string[]; rows: unknown[][] };
  type RowA = { id: string; date: string; category: string };
  type RowB = { severity: number; status: string; title: string };
  type RowC = { org: string; country: string; actor: string; first_seen: string };
  type Row = RowA & RowB & RowC & { cves: string[]; tags: string[] };
  type Source = { name?: string; url: string };
  type VState = { state?: string; note?: string };
  type ReviewT = VState & { flags?: string[] };
  type FullA = { id: string; summary?: string; plain?: string; exec?: string; action?: string };
  type FullB = { date_note?: string; cves?: string[]; tags?: string[]; sources?: Source[] };
  type FullC = { validation?: VState; review?: ReviewT };
  type FullD = { qa_checked_at?: string; first_seen?: string; updated_at?: string };
  type FullEvent = FullA & FullB & FullC & FullD;
  type MonthDoc = { events: FullEvent[] };
  type KevEntry = { id?: string; cve?: string };
  type Filters = { q: string; month: string; cat: string; sev: string; claims: boolean; recent: boolean };
  const EMPTY_FILTERS: Filters = { q: '', month: '', cat: '', sev: '', claims: false, recent: false };

  const ms = (v: string): number => { const n = Date.parse(v); return Number.isFinite(n) ? n : 0; };
  function fmtDate(v: string): string {
    if (!v) return '';
    const d = new Date(`${v.slice(0, 10)}T12:00:00Z`);
    return Number.isNaN(d.getTime()) ? v : d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function fmtMonth(v: string): string {
    const d = new Date(`${v}-15T12:00:00Z`);
    return Number.isNaN(d.getTime()) ? v : d.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
  }
  function fmtStamp(v?: string): string {
    if (!v) return '—';
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? v : d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  }
  function ago(iso: string, ref: number): string {
    const t = ms(iso);
    if (!t || !ref) return '';
    const m = Math.max(0, Math.round((ref - t) / 60_000));
    return m < 60 ? `${m} min ago` : m < 1_440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1_440)} days ago`;
  }
  function mapRows(doc: SearchDoc | null): Row[] {
    if (!doc) return [];
    const v = (r: unknown[], n: string): string => { const i = doc.fields.indexOf(n); return i >= 0 ? text(r[i]) : ''; };
    const a = (r: unknown[], n: string): string[] => { const i = doc.fields.indexOf(n); return asArray((i >= 0 ? r[i] : null) as string[] | null).map(text); };
    return asArray(doc.rows).map((r) => ({
      id: v(r, 'id'), date: v(r, 'date'), category: v(r, 'category'), severity: +v(r, 'severity') || 0,
      status: v(r, 'status'), title: v(r, 'title'), org: v(r, 'org'), country: v(r, 'country'),
      cves: a(r, 'cves'), tags: a(r, 'tags'), actor: v(r, 'actor'), first_seen: v(r, 'first_seen'),
    }));
  }
  function readHash(): Filters {
    if (typeof window === 'undefined') return EMPTY_FILTERS;
    const p = new URLSearchParams(location.hash.replace(/^#/, ''));
    const f: Filters = { q: '', month: '', cat: '', sev: '', claims: p.get('claims') === '1', recent: p.has('recent') };
    (['q', 'month', 'cat', 'sev'] as const).forEach((k) => { f[k] = p.get(k) ?? ''; });
    return f;
  }
  function writeHash(f: Filters): void {
    if (typeof window === 'undefined') return;
    const p = new URLSearchParams();
    const q = f.q.trim();
    if (q) p.set('q', q);
    (['month', 'cat', 'sev'] as const).forEach((k) => { if (f[k]) p.set(k, f[k]); });
    if (f.claims) p.set('claims', '1');
    if (f.recent) p.set('recent', '1');
    const s = p.toString();
    try { history.replaceState(null, '', s ? `#${s}` : location.pathname + location.search); } catch { /* restricted */ }
  }

  function MonthLoader({ month, onData }: { month: string; onData: (m: string, d: MonthDoc) => void }): null {
    const res = useDataFetch<MonthDoc>({ url: `${BASE}/${encodeURIComponent(month)}.json`, ttl: 600_000 });
    useEffect(() => { if (res.data) onData(month, res.data); }, [res.data, month, onData]);
    return null;
  }

  /* ── Expanded-row building blocks ─────────────────────────────────────────── */

  function Detail({ title, children }: { title: string; children: ReactNode }): JSX.Element {
    return <section><h4 className={H4}>{title}</h4>{children}</section>;
  }
  function CveChip({ cve, kevIds }: { cve: string; kevIds: Set<string> }): JSX.Element {
    const kev = kevIds.has(cve);
    const title = kev ? 'In CISA Known Exploited Vulnerabilities' : cve;
    return <span className={CVE} title={title}>{cve}{kev && <b className="ml-1 text-rose-600 dark:text-rose-400">KEV</b>}</span>;
  }
  function Chips({ title, values, kevIds }: { title: string; values: string[]; kevIds?: Set<string> }): JSX.Element | null {
    if (!values.length) return null;
    return <Detail title={title}><div className="mt-1.5 flex flex-wrap gap-1.5">
      {values.map((v) => kevIds ? <CveChip key={v} cve={v} kevIds={kevIds} /> : <Badge key={v}>{v}</Badge>)}
    </div></Detail>;
  }
  function TextField({ t, v, prefix }: { t: string; v?: string; prefix?: boolean }): JSX.Element | null {
    if (!v) return null;
    return <Detail title={t}><p className="mt-1">{prefix && <strong className="text-heading">Do:</strong>} {v}</p></Detail>;
  }
  function Sources({ list }: { list: Source[] }): JSX.Element | null {
    if (!list.length) return null;
    return <Detail title={`Sources (${list.length})`}><ul className="mt-1.5 space-y-1">
      {list.slice(0, 6).map((s, i) => {
        const url = text(s.url);
        return <li key={`${url}-${i}`}><OutLink href={url} className="font-mono text-meta">
          {text(s.name) || sanitizeUrl(url).replace(/^https?:\/\//, '').split('/')[0]}
        </OutLink></li>;
      })}
    </ul></Detail>;
  }
  function Validation({ full, row }: { full: FullEvent; row: Row }): JSX.Element {
    const flags = asArray(full.review?.flags);
    return <section className="rounded-lg border border-line-1 bg-surface-200 p-3">
      <h4 className={`flex items-center gap-1.5 ${H4}`}><ShieldCheck size={13} aria-hidden="true" /> Validation &amp; QA</h4>
      <p className={MUTED}>
        Validation: <span className="text-body">{full.validation?.state ?? 'not recorded'}</span> · Review:{' '}
        <span className="text-body">{full.review?.state ?? 'not recorded'}</span>
        {flags.length > 0 && ` · flags: ${flags.join(', ')}`}
      </p>
      {full.validation?.note && <p className="text-meta">{full.validation.note}</p>}
      {full.review?.note && <p className="text-meta"><strong className="text-heading">Reviewer note:</strong> {full.review.note}</p>}
      <p className={MUTED}>
        First seen {fmtStamp(full.first_seen ?? row.first_seen)} · Updated {fmtStamp(full.updated_at)}
        {full.qa_checked_at && ` · QA checked ${fmtStamp(full.qa_checked_at)}`}
      </p>
    </section>;
  }

  /* ── One expandable event row (shared by recent + full list) ──────────────── */

  type RowP1 = { row: Row; full?: FullEvent; open: boolean };
  type RowP2 = { onToggle: () => void; kevIds: Set<string>; loading?: boolean; filed?: string };
  function EventRow(p: RowP1 & RowP2): JSX.Element {
    const { row, full, open, onToggle, kevIds, loading, filed } = p;
    const label = CAT_LABEL[row.category] ?? row.category;
    const sev = SEV_LABEL[row.severity] ?? '';
    const declared = asArray(full?.cves);
    const cves = declared.length ? declared : asArray(row.cves);
    const sources = asArray(full?.sources).filter((s) => s && sanitizeUrl(text(s.url)));
    const tags = asArray(full?.tags);
    const headCves = cves.slice(0, 3).map((c) => <CveChip key={c} cve={c} kevIds={kevIds} />);
    const aria = `${row.title}. ${fmtDate(row.date)}. ${filed ? `${filed}. ` : ''}${label}, ${sev}, ${row.org || 'unknown organisation'}, ${row.country || 'unknown country'}. ${open ? 'Collapse' : 'Expand'} details`;
    return <li className="surface-card overflow-hidden rounded-xl border border-line-1">
      <button type="button" {...{ 'aria-expanded': open, 'aria-label': aria }} onClick={onToggle}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-wash">
        <ChevronDown size={14} aria-hidden="true" className={`${CHEVRON} ${open ? 'rotate-180' : ''}`} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className={MUTED}>{fmtDate(row.date)}</span>
            <span className="text-sm font-semibold leading-snug text-heading">{row.title}</span>
          </span>
          <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {filed && <Badge tone="brand">{filed}</Badge>}
            <Badge>{label}</Badge><Badge>{sev}</Badge>
            {row.status === 'claimed' && <Badge tone="medium">Unverified claim</Badge>}
            {row.org && <span className={MUTED}>{row.org}</span>}
            {row.country && <span className={MUTED}>{row.country}</span>}
            {headCves}
          </span>
        </span>
      </button>
      {open && <div className="border-t border-line-1 bg-surface-100 px-4 py-4 text-sm leading-relaxed text-body">
        {!full && <p className={MUTED}>{loading ? 'Loading event details…' : 'Details are not available for this event.'}</p>}
        {full && <div className="space-y-4">
          {full.summary && <p>{full.summary}</p>}
          <p className={MUTED}>Researched and written by CyberView AI (a Claude model) from the sources listed.</p>
          <TextField t="Plain English" v={full.plain} />
          <TextField t="Executive risk" v={full.exec} />
          <TextField t="Recommended action" v={full.action} prefix />
          {full.date_note && <p className={MUTED}>Date note: {full.date_note}</p>}
          <Chips title="Tags" values={tags} />
          <Chips title="Related CVEs" values={cves} kevIds={kevIds} />
          <Sources list={sources} />
          <Validation full={full} row={row} />
          <a href={`#q=${encodeURIComponent(row.id)}`} className={LINK}>Link to this event <ExternalLink size={11} aria-hidden="true" /></a>
        </div>}
      </div>}
    </li>;
  }

  /* ── Filter controls ──────────────────────────────────────────────────────── */

  type SelP1 = { l: string; a?: string; v: string };
  type SelP2 = { o: Opt[]; on: (v: string) => void };
  const ARIA: Record<string, string> = { Month: 'Filter by month', Category: 'Filter by category', Severity: 'Filter by minimum severity' };
  function Select(p: SelP1 & SelP2): JSX.Element {
    const { l, a, v, o, on } = p;
    return <label><span className={LABEL}>{l}</span>
      <select value={v} onChange={(e) => on(e.target.value)} aria-label={a || ARIA[l]} className={SELECT}>
        {o.map(([value, txt]) => <option key={value} value={value}>{txt}</option>)}
      </select>
    </label>;
  }
  type FBarP1 = { filters: Filters; months: string[] };
  type FBarP2 = { patch: (p: Partial<Filters>) => void };
  function FilterBar(p: FBarP1 & FBarP2): JSX.Element {
    const { filters, months, patch } = p;
    const monthOpts: Opt[] = [['', 'All months'], ...months.map((m): Opt => [m, fmtMonth(m)])];
    const setMonth = (v: string) => patch({ month: v });
    const setCat = (v: string) => patch({ cat: v });
    const setSev = (v: string) => patch({ sev: v });
    return <section aria-label="Archive filters" className="surface-card rounded-xl border border-line-1 p-4">
      <form onSubmit={(e) => e.preventDefault()} role="search" className="flex flex-wrap items-end gap-3">
        <label className="min-w-[220px] flex-1"><span className={LABEL}>Search</span>
          <span className="relative block">
            <Search size={14} aria-hidden="true" className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input type="search" value={filters.q} onChange={(e) => patch({ q: e.target.value })}
              placeholder="Organisation, actor, CVE, country, tag" aria-label="Search archived events"
              className="w-full rounded-control border border-line-input bg-input-200 py-1.5 pl-8 pr-2 font-mono text-meta text-heading placeholder:text-muted" />
          </span>
        </label>
        <Select l="Month" v={filters.month} o={monthOpts} on={setMonth} />
        <Select l="Category" v={filters.cat} o={[['', 'All categories'], ...CATEGORIES]} on={setCat} />
        <Select l="Severity" v={filters.sev} o={SEV_OPTS} on={setSev} />
        <label className="flex items-center gap-2 pb-1.5 font-mono text-meta text-body">
          <input type="checkbox" checked={filters.claims} onChange={(e) => patch({ claims: e.target.checked })}
            className="h-4 w-4 rounded border-line-input" />
          Include unverified claims
        </label>
      </form>
    </section>;
  }

  /* ── Page ─────────────────────────────────────────────────────────────────── */

  function CyberViewArchive({ bare = false }: { bare?: boolean }): JSX.Element {
    const index = useDataFetch<ArchiveIndex>({ url: `${BASE}/index.json`, ttl: 600_000 });
    const search = useDataFetch<SearchDoc>({ url: `${BASE}/search.json`, ttl: 600_000 });
    const kev = useDataFetch<KevEntry[]>({ url: `${BASE}/kev.json`, ttl: 600_000 });
    const [months, setMonths] = useState<Record<string, FullEvent[]>>({});
    const [filters, setFilters] = useState(readHash);
    const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
    const [shown, setShown] = useState(PAGE);
    const [recentAll, setRecentAll] = useState(false);

    const derived = useMemo(() => {
      const rows = mapRows(search.data);
      const fullById: Record<string, FullEvent> = {};
      for (const e of Object.values(months).flat()) fullById[e.id] = e;
      const kevIds = new Set(asArray(kev.data).flatMap((k) => [k.cve, k.id]).filter(Boolean) as string[]);
      const unverified = (r: Row): boolean => r.status === 'claimed' ||
        ['unconfirmed_claim', 'unverified'].includes(fullById[r.id]?.validation?.state ?? '');
      const refMs = rows.reduce((m, r) => Math.max(m, ms(r.first_seen)), 0);
      const earliest = rows.reduce((m, r) => (r.date && r.date < m ? r.date : m), '9999-99-99');
      const claimCount = rows.filter(unverified).length;
      const q = filters.q.trim().toLowerCase();
      const min = Number(filters.sev || 0);
      const filtered = rows.filter((r) => {
        if (!filters.claims && unverified(r)) return false;
        if (filters.month && !r.date.startsWith(filters.month)) return false;
        if (filters.cat && r.category !== filters.cat) return false;
        if (min && r.severity < min) return false;
        const e = fullById[r.id];
        return !q || matches([r.title, r.org, r.country, r.actor, r.cves, r.tags, r.id, e?.summary, e?.plain].join(' '), q);
      });
      const recents = rows.filter((r) => {
        const filed = ms(r.first_seen);
        const happened = ms(`${r.date}T23:59:59Z`);
        return filed && happened && refMs - filed < 48 * HOUR_MS && filed - happened > 36 * HOUR_MS && !unverified(r);
      });
      const recentRows = recents.sort((a, b) => ms(b.first_seen) - ms(a.first_seen)).slice(0, RECENT_CAP);
      const monthKeys = asArray(index.data?.months).map((m) => m.month).sort().reverse();
      return { rows, fullById, kevIds, refMs, earliest, claimCount, filtered, recentRows, monthKeys };
    }, [index.data, search.data, months, kev.data, filters]);
    const { rows, fullById, kevIds, refMs, earliest, claimCount, filtered, recentRows, monthKeys } = derived;

    const addMonth = useCallback((m: string, d: MonthDoc) => setMonths((p) => (p[m] ? p : { ...p, [m]: asArray(d.events) })), []);
    // Hash → state (external links / browser back-forward), state → hash.
    useEffect(() => {
      const onHash = () => setFilters(readHash());
      addEventListener('hashchange', onHash);
      return () => removeEventListener('hashchange', onHash);
    }, []);
    useEffect(() => { writeHash(filters); setShown(PAGE); }, [filters]);
    const patch = useCallback((p: Partial<Filters>) => setFilters((f) => ({ ...f, ...p })), []);
    const toggle = useCallback((id: string) => setExpanded((p) => new Set(p).has(id)
      ? new Set([...p].filter((x) => x !== id)) : new Set(p).add(id)), []);
    // #q=<event id> deep-links straight into a single event, one-shot per id.
    const auto = useRef<string | null>(null);
    useEffect(() => {
      const q = filters.q.trim();
      if (!q || auto.current === q || !rows.some((r) => r.id === q) || filtered.length !== 1) return;
      auto.current = q;
      setExpanded((p) => new Set(p).add(q));
    }, [filters.q, rows, filtered.length]);

    const recentExpanded = recentAll || filters.recent;
    const visible = filtered.slice(0, shown);
    // Top of the currently visible (filtered) list, mapped to the AI summary
    // card's item shape using the normalized row + defensive text helpers.
    const summaryItems = visible.slice(0, 20).map((r) => {
      const full = fullById[r.id];
      return {
        title: text(r.title),
        body: text(full?.plain) || text(full?.summary),
        source: text(r.org) || 'CyberView',
      };
    });
    const summaryDay = index.data?.built_at?.slice(0, 10) ?? new Date().toISOString().slice(0, 10);
    const allLoaded = monthKeys.every((m) => Boolean(months[m]));
    const loading = index.loading || search.loading || kev.loading;
    const error = index.error ?? search.error ?? kev.error;
    const built = fmtStamp(index.data?.built_at ?? search.data?.built_at);
    const retry = () => [index, search, kev].forEach((r) => r.refetch());
    const toggleRecent = () => { setRecentAll(!recentExpanded); patch({ recent: !recentExpanded }); };
    const summary = `${rows.length - claimCount} checked events since ${earliest === '9999-99-99' ? 'the start' : fmtDate(earliest)}${claimCount > 0 ? `, plus ${claimCount} unverified claim${claimCount === 1 ? '' : 's'} (hidden unless you include them)` : ''}. The map shows today and the six days before; everything else lives here.`;
    const listInfo = `${filtered.length} event${filtered.length === 1 ? '' : 's'}${filtered.length > shown ? `, showing ${shown}` : ''}${filters.month ? ` · ${fmtMonth(filters.month)}` : ''}`;
    const claimNote = `${claimCount} unverified claim${claimCount === 1 ? '' : 's'} hidden — tick “Include unverified claims” to show them.`;
    const renderRows = (items: Row[], prefix: string, filed: boolean): ReactNode[] => items.map((r) => {
      const full = fullById[r.id];
      return <EventRow key={prefix + r.id} row={r} full={full} loading={!full && !allLoaded}
        open={expanded.has(r.id)} onToggle={() => toggle(r.id)}
        filed={filed ? `Filed ${ago(r.first_seen, refMs)}, happened ${fmtDate(r.date)}` : undefined} kevIds={kevIds} />;
    });

    return (
      <CyberViewPage bare={bare} icon={<Archive size={28} />} title="CyberView — Archive"
        description="Replication of CyberView's archive: every checked cyber event, with month/category/severity filters and full event detail."
        loading={loading} error={error} onRetry={retry}>
        {monthKeys.map((m) => <MonthLoader key={m} month={m} onData={addMonth} />)}
        <div className="space-y-8">
          <header className="space-y-2">
            <h1 className="text-2xl font-display font-semibold text-heading sm:text-3xl">Every event on file</h1>
            <p className="max-w-3xl text-sm leading-relaxed text-muted" aria-live="polite">{summary}</p>
          </header>
          {(index.loading || search.loading) && !rows.length && <p className={MUTED}>Loading the archive index…</p>}
          {error && <p className="font-mono text-meta text-rose-500">error: {error}</p>}

          {recentRows.length > 0 && <section id="recent" aria-labelledby="recent-head" className="space-y-3">
            <h2 id="recent-head" className="text-lg font-semibold text-heading">Recently filed ({recentRows.length})</h2>
            <p className="mt-1 max-w-3xl text-meta leading-relaxed text-muted">
              Events added in the last 48 hours that happened earlier. The map&rsquo;s “Just added” list shows only new
              events; these are filed here with the day they happened and when CyberView filed them.
            </p>
            <ol className="space-y-2">{renderRows(recentExpanded ? recentRows : recentRows.slice(0, RECENT_FEW), 'recent-', true)}</ol>
            {recentRows.length > RECENT_FEW && <button type="button" className={BTN} onClick={toggleRecent}>
              {recentExpanded ? 'Show fewer' : `Show all ${recentRows.length}`}
            </button>}
          </section>}

          <FilterBar filters={filters} months={monthKeys} patch={patch} />

          {summaryItems.length > 0 && <AiSummaryCard
            surface="CyberView archive"
            items={summaryItems}
            dayKey={summaryDay}
            requireAdmin={false}
            autoFetch={false}
          />}

          <section aria-label="Event list" className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-mono text-meta text-muted" aria-live="polite">{listInfo}</p>
              {!filters.claims && claimCount > 0 && <p className="flex items-center gap-1.5 font-mono text-mini text-muted">
                <Info size={12} aria-hidden="true" />{claimNote}
              </p>}
            </div>
            {visible.length === 0 ? <Empty>Nothing matches. Clear a filter or try another word.</Empty>
              : <ol className="space-y-2">{renderRows(visible, '', false)}</ol>}
            {filtered.length > shown && <button type="button" className={BTN} onClick={() => setShown((n) => n + PAGE)}>Show more</button>}
          </section>

          <section aria-labelledby="download-head" className={PANEL}>
            <h2 id="download-head" className="flex items-center gap-2 text-base font-semibold text-heading">
              <Download size={16} aria-hidden="true" /> Download the data
            </h2>
            <p className="text-meta leading-relaxed text-muted">The full history in open formats, rebuilt on every update:{' '}
              {FEEDS.map(([f, label], i) => <span key={f}>{i > 0 && ', '}
                <a href={`${BASE}/${f}`} className="text-accent-text hover:underline">{label}</a></span>)}.
            </p>
            <p className={MUTED}>Mirrored {built}
              {index.data && ` · ${index.data.total} events · ${index.data.kev_total} KEV entries`}. No unverified claims are included in the feeds.</p>
          </section>
        </div>
        <footer className={FOOT}>
          <span>CyberView archive — community research, AI-researched and reviewed.</span>
          <span className="ml-auto">Built {built} · {monthKeys.length} monthly file{monthKeys.length === 1 ? '' : 's'}</span>
        </footer>
      </CyberViewPage>
    );
  }

  return CyberViewArchive;
})();

export default mod;
