import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CalendarDays,
  Check,
  ChevronDown,
  Copy,
  Download,
  ExternalLink,
  FileText,
  Search,
  ShieldAlert,
  Target,
} from 'lucide-react';
import { DataPageLayout } from '../../../components/DataPageLayout';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import { CyberViewNav } from './CyberViewNav';

/**
 * Replication of the CyberView "Vulnerabilities" workbench. Every number on
 * this page is derived from the mirrored workbench.json / recent.json files;
 * nothing is fetched live and nothing typed into the search boxes leaves the
 * browser. The upstream ranking score is not stored in the mirror, so the
 * number shown is a transparent local approximation built from the weights
 * CyberView publishes in its own "How the score works" disclosure.
 */

interface Affected {
  vendor: string;
  product: string;
  part?: string;
  exact?: string;
  from?: string;
  from_incl?: boolean;
  to?: string;
  to_incl?: boolean;
  update?: string;
}
interface Repo {
  repos: number;
  top: Array<{ name: string; url: string; stars: number }>;
}
interface KevRow {
  repo: Repo | null;
  cve: string;
  vendor: string;
  product: string;
  name: string;
  added: string;
  due: string;
  ransomware: boolean;
  desc: string;
  cvss: number | null;
  epss: number | null;
  av: string;
  required: string;
  refs: string[];
  affected: Affected[];
}
interface VulnRow {
  repo: Repo | null;
  cve: string;
  event_id: string;
  title: string;
  date: string;
  severity: number;
  vendor: string;
  products: string[];
  desc: string;
  action: string;
  cvss: number | null;
  epss: number | null;
}
interface HuntCard {
  name: string;
  format: string;
  url: string;
  publisher: string;
  about: string;
  date?: string;
  event_id?: string;
  cve?: string;
}
interface Guide {
  cve: string;
  advisory: { name: string; url: string };
  check: string[];
  fixed: string[];
  workaround: string[];
  compromise_signs: string[];
  exposure: string | null;
  exploit_public: boolean;
  hunt: HuntCard[];
}
interface Analysis {
  cve: string;
  exploitation_status: string;
  how_exploited: string;
  exposure: string | null;
  detect: string[];
  caveats: string;
  remediation: {
    priority: string;
    steps: string[];
    fixed_versions: string[];
    workarounds: string[];
    verify: string[];
    if_compromised: string[];
  };
}
interface Workbench {
  built_at: string;
  kev: KevRow[];
  vulns: VulnRow[];
  guides: Record<string, Guide>;
  analyses: Record<string, Analysis>;
  event_of: Record<string, string>;
  hunt: HuntCard[];
}
interface RecentData {
  fields: string[];
  since: string;
  rows: unknown[][];
}
interface CveLite {
  id: string;
  pub: string;
  cvss: number | null;
  sev: string;
  vendor: string;
  product: string;
  title: string;
  kev: string;
  epss: number | null;
}
interface RankedRow {
  key: string;
  cve: string;
  vendor: string;
  product: string;
  name: string;
  desc: string;
  kev: boolean;
  ransomware: boolean;
  due: string | null;
  added: string;
  epss: number | null;
  required: string;
  refs: string[];
  affected: Affected[];
  repo: Repo | null;
  severity: number;
  date: string;
  products: string[];
  action: string;
}
enum Tab {
  Queue = 'queue',
  All = 'all',
  Inventory = 'inventory',
  Hunt = 'hunt',
}
const TABS: Array<{ id: Tab; label: string }> = [
  { id: Tab.Queue, label: 'Known exploited' },
  { id: Tab.All, label: 'All CVEs' },
  { id: Tab.Inventory, label: 'My software' },
  { id: Tab.Hunt, label: 'Hunt pack' },
];
const SHOW_FILTERS = [
  { id: 'everything', label: 'Everything' },
  { id: 'mine', label: 'Affects my software' },
  { id: 'week', label: 'Deadline within 7 days or passed' },
  { id: 'steps', label: 'Has check and fix steps' },
] as const;
type ShowFilter = (typeof SHOW_FILTERS)[number]['id'];
const INVENTORY_KEY = 'cwm.inv';
const PAGE_SIZE = 25;
const DAY_MS = 86_400_000;

function dayDiff(due: string | null, builtAt: string): number | null {
  if (!due) return null;
  const built = new Date(builtAt);
  if (Number.isNaN(built.getTime())) return null;
  const b = Date.UTC(built.getUTCFullYear(), built.getUTCMonth(), built.getUTCDate());
  const d = Date.parse(`${due.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(d)) return null;
  return Math.round((b - d) / DAY_MS);
}
function fmtBuilt(stamp: string): string {
  const d = new Date(stamp);
  if (Number.isNaN(d.getTime())) return stamp;
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}
function deadlineText(due: string | null, builtAt: string): string {
  const d = dayDiff(due, builtAt);
  if (d === null) return 'Not on CISA’s list';
  if (d === 0) return 'due today';
  if (d > 0) return `${d} day${d === 1 ? '' : 's'} overdue`;
  return `${-d} day${d === -1 ? '' : 's'} left`;
}
function epssText(v: number | null): string | null {
  return v === null || v === undefined ? null : `${Math.round(v * 100)}%`;
}
function affectedLabel(a: Affected): string {
  const bits = [a.vendor, a.product].filter(Boolean);
  if (a.exact) bits.push(a.exact);
  else if (a.from || a.to)
    bits.push(`${a.from_incl === false ? '(' : ''}${a.from ?? ''} → ${a.to ?? ''}${a.to_incl === false ? ')' : ''}`);
  else if (a.update) bits.push(a.update);
  return bits.join(' ').trim();
}
function hasSteps(cve: string, data: Workbench | null): boolean {
  if (!data) return false;
  const g = data.guides[cve];
  return Boolean(g && (g.check.length || g.fixed.length || g.workaround.length || g.compromise_signs.length));
}
function internetFacing(row: RankedRow, guide?: Guide): boolean {
  if (guide?.exposure) return guide.exposure === 'internet';
  return /\b(server|web|http|nginx|apache|firewall|vpn|exchange|email|gateway|router|appliance|cloud|portal|ssl|vcenter|remote|ftp|smtp|proxy|dsm|nas|cms|sharepoint|confluence|jenkins|gitlab)\b/i.test(
    `${row.product} ${row.products.join(' ')}`
  );
}
function publicExploit(row: RankedRow, guide?: Guide): boolean {
  return Boolean(guide?.exploit_public || (row.repo && row.repo.top.length > 0));
}
function matchInventory(row: RankedRow, inventory: string[]): 'version' | 'product' | null {
  if (!inventory.length) return null;
  const hay = `${row.vendor} ${row.product} ${row.products.join(' ')}`.toLowerCase();
  let best: 'version' | 'product' | null = null;
  for (const line of inventory) {
    const m = line.match(/^(.*?)\s+v?(\d+(?:[.\-_]\d+)*[a-z0-9.\-_]*)$/i);
    const name = (m?.[1] ?? line).trim().toLowerCase();
    const version = (m?.[2] ?? '').toLowerCase();
    if (name.length < 3 || !hay.includes(name)) continue;
    best = 'product';
    if (!version) continue;
    const hit = row.affected.some((a) => {
      const av = `${a.exact ?? ''} ${a.from ?? ''} ${a.to ?? ''} ${a.update ?? ''}`.trim().toLowerCase();
      const first = av.split(/\s+/)[0] ?? '';
      return Boolean(av) && (av.includes(version) || (version.includes(first) && first.length > 2));
    });
    if (hit) return 'version';
  }
  return best;
}
function priority(row: RankedRow, data: Workbench | null, inv: 'version' | 'product' | null): number {
  let s = row.kev ? 35 : row.severity === 3 ? 15 : 0;
  if (row.kev && row.ransomware) s += 10;
  if (row.epss !== null) s += Math.round(row.epss * 15);
  const guide = data?.guides[row.cve];
  if (publicExploit(row, guide)) s += 5;
  if (internetFacing(row, guide)) s += 10;
  const d = dayDiff(row.due, data?.built_at ?? '');
  if (row.kev && d !== null) {
    if (d > 0) s += 5;
    else if (d >= -7) s += 3;
  }
  if (inv === 'version') s += 20;
  else if (inv === 'product') s += 10;
  return Math.max(0, Math.min(100, s));
}
function ranked(data: Workbench | null): RankedRow[] {
  if (!data) return [];
  const out: RankedRow[] = data.kev.map((r) => ({
    key: r.cve,
    cve: r.cve,
    vendor: r.vendor,
    product: r.product,
    name: r.name,
    desc: r.desc,
    kev: true,
    ransomware: r.ransomware,
    due: r.due,
    added: r.added,
    epss: r.epss,
    required: r.required,
    refs: r.refs ?? [],
    affected: r.affected ?? [],
    repo: r.repo,
    severity: 0,
    date: r.added,
    products: [r.product],
    action: r.required,
  }));
  for (const v of data.vulns) {
    out.push({
      key: `v-${v.cve}-${v.event_id}`,
      cve: v.cve,
      vendor: v.vendor,
      product: v.products[0] ?? v.vendor,
      name: v.title,
      desc: v.desc,
      kev: false,
      ransomware: false,
      due: null,
      added: '',
      epss: v.epss,
      required: '',
      refs: [],
      affected: [],
      repo: v.repo,
      severity: v.severity,
      date: v.date,
      products: v.products,
      action: v.action,
    });
  }
  return out;
}
function recentRows(data: RecentData | null): CveLite[] {
  if (!data) return [];
  const ix = (f: string) => data.fields.indexOf(f);
  const at = (row: unknown[], f: string): unknown => {
    const i = ix(f);
    return i < 0 ? null : row[i];
  };
  const str = (v: unknown) => (v === null || v === undefined ? '' : String(v));
  return data.rows.map((row) => ({
    id: str(at(row, 'id')),
    pub: str(at(row, 'pub')),
    cvss: typeof at(row, 'cvss') === 'number' ? (at(row, 'cvss') as number) : null,
    sev: str(at(row, 'sev')),
    vendor: str(at(row, 'vendor')),
    product: str(at(row, 'product')),
    title: str(at(row, 'title')),
    kev: str(at(row, 'kev')),
    epss: typeof at(row, 'epss') === 'number' ? (at(row, 'epss') as number) : null,
  }));
}
function download(name: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}
function icsEscape(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/,/g, '\\,').replace(/;/g, '\\;').replace(/\r?\n/g, '\\n');
}
function icsDay(d: string): string {
  return d.slice(0, 10).replace(/-/g, '');
}

const SEV_LABEL: Record<string, string> = { H: 'High', M: 'Medium', L: 'Low', C: 'Critical' };
const BADGE = 'rounded border border-line-1 px-1.5 py-0.5 font-mono text-mini';
const BTN =
  'inline-flex items-center gap-1.5 rounded-control border border-line-1 bg-surface-100 px-2.5 py-1.5 font-mono text-meta text-body transition-colors hover:border-brand-400 hover:text-heading disabled:cursor-not-allowed disabled:opacity-50';

export default function CyberViewVulnerabilities({ bare = false }: { bare?: boolean }): JSX.Element {
  const work = useDataFetch<Workbench>({ url: '/data/cyberview/data/workbench.json', ttl: 600_000 });
  const recent = useDataFetch<RecentData>({ url: '/data/cyberview/data/cve/recent.json', ttl: 600_000 });
  const [tab, setTab] = useState<Tab>(Tab.Queue);
  const [query, setQuery] = useState('');
  const [show, setShow] = useState<ShowFilter>('everything');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cveQuery, setCveQuery] = useState('');
  const [lookupMsg, setLookupMsg] = useState('');
  const [lookup, setLookup] = useState<CveLite | null>(null);
  const [page, setPage] = useState(0);
  const [huntFormat, setHuntFormat] = useState('all');
  const [huntMine, setHuntMine] = useState(false);
  const [copyMsg, setCopyMsg] = useState('');
  const [invText, setInvText] = useState(() => {
    try {
      return localStorage.getItem(INVENTORY_KEY) ?? '';
    } catch {
      return '';
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(INVENTORY_KEY, invText);
    } catch {
      /* storage may be disabled; the list still works in memory */
    }
  }, [invText]);

  const data = work.data;
  const builtAt = data?.built_at ?? '';
  const inventory = useMemo(
    () =>
      invText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean),
    [invText]
  );
  const allRows = useMemo(() => ranked(data), [data]);
  const scored = useMemo(
    () => allRows.map((r) => ({ row: r, score: priority(r, data, matchInventory(r, inventory)) })),
    [allRows, data, inventory]
  );

  const pastDeadline = allRows.filter((r) => r.kev && (dayDiff(r.due, builtAt) ?? 0) > 0).length;
  const totalFlaws = (data?.kev.length ?? 0) + (data?.vulns.length ?? 0);
  const need = scored
    .filter(({ row }) => dayDiff(row.due, builtAt) !== null && (dayDiff(row.due, builtAt) ?? 0) <= 0)
    .sort((a, b) => (dayDiff(a.row.due, builtAt) ?? 0) - (dayDiff(b.row.due, builtAt) ?? 0));
  const overdue = scored
    .filter(({ row }) => {
      const d = dayDiff(row.due, builtAt) ?? 0;
      return d > 0 && d <= 14;
    })
    .sort((a, b) => (dayDiff(a.row.due, builtAt) ?? 0) - (dayDiff(b.row.due, builtAt) ?? 0));
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return [...scored]
      .filter(({ row }) => {
        if (show === 'mine' && !matchInventory(row, inventory)) return false;
        if (show === 'week') {
          const d = dayDiff(row.due, builtAt);
          // Ahead by at most seven days, or already past.
          if (d === null || d < -7) return false;
        }
        if (show === 'steps' && !hasSteps(row.cve, data)) return false;
        if (!needle) return true;
        return `${row.cve} ${row.vendor} ${row.product} ${row.name} ${row.desc}`.toLowerCase().includes(needle);
      })
      .sort((a, b) => b.score - a.score || a.row.cve.localeCompare(b.row.cve));
  }, [scored, query, show, inventory, builtAt, data]);

  const huntCards = useMemo<HuntCard[]>(() => {
    if (!data) return [];
    const guides: Record<string, Guide> = data.guides;
    const fromGuides = Object.values(guides).flatMap((g: Guide) =>
      g.hunt.map((h) => ({ ...h, cve: g.cve, event_id: data.event_of[g.cve] ?? h.event_id }))
    );
    return [...data.hunt, ...fromGuides];
  }, [data]);
  const formats = useMemo(
    () => ['all', ...Array.from(new Set(huntCards.map((h) => h.format).filter(Boolean)))],
    [huntCards]
  );
  const cardAffectsMine = (h: HuntCard): boolean => {
    if (!h.cve) {
      const cves = Object.keys(data?.event_of ?? {}).filter((c) => data?.event_of[c] === h.event_id);
      return cves.some((c) => {
        const r = allRows.find((x) => x.cve === c);
        return Boolean(r && matchInventory(r, inventory));
      });
    }
    const r = allRows.find((x) => x.cve === h.cve);
    return Boolean(r && matchInventory(r, inventory));
  };
  const visibleHunt = huntCards.filter(
    (h) => (huntFormat === 'all' || h.format === huntFormat) && (!huntMine || cardAffectsMine(h))
  );

  const cveList = useMemo(() => recentRows(recent.data), [recent.data]);
  const recentList = cveList.filter((r) => !recent.data?.since || r.pub >= recent.data.since);
  const cveSearch = recentList.filter((r) =>
    `${r.id} ${r.vendor} ${r.product} ${r.title}`.toLowerCase().includes(cveQuery.trim().toLowerCase())
  );
  const paged = cveSearch.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  const pages = Math.max(1, Math.ceil(cveSearch.length / PAGE_SIZE));

  const affectedCves = allRows.filter((r) => matchInventory(r, inventory));
  const unmatchedCount =
    inventory.length -
    new Set(
      affectedCves.flatMap((r) => {
        const hay = `${r.vendor} ${r.product} ${r.products.join(' ')}`.toLowerCase();
        return inventory.filter((line) => hay.includes((line.split(/\s+v?\d/)[0] ?? line).trim().toLowerCase()));
      })
    ).size;

  const openCve = (cve: string) => {
    setTab(Tab.Queue);
    setExpanded(cve);
    setQuery('');
    setShow('everything');
  };
  const toCalendar = () => {
    const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//CyberView replication//Patch deadlines//EN'];
    for (const { row } of need) {
      if (!row.due) continue;
      const start = icsDay(row.due);
      lines.push(
        'BEGIN:VEVENT',
        `UID:${row.cve}-${start}@cyberview.local`,
        `DTSTAMP:${start}T000000Z`,
        `DTSTART;VALUE=DATE:${start}`,
        `SUMMARY:${icsEscape(`Patch ${row.cve} — ${row.product}`)}`,
        `DESCRIPTION:${icsEscape(`${row.name}. ${row.required}`.slice(0, 500))}`,
        'BEGIN:VALARM',
        'TRIGGER:-P3D',
        'ACTION:DISPLAY',
        `DESCRIPTION:${icsEscape(`Patch ${row.cve} in 3 days`)}`,
        'END:VALARM',
        'END:VEVENT'
      );
    }
    lines.push('END:VCALENDAR');
    download('cyberview-deadlines.ics', lines.join('\r\n'), 'text/calendar;charset=utf-8');
  };
  const toCsv = () => {
    const cell = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const lines = ['priority,cve,vendor,product,name,known_exploited,ransomware,due,epss'];
    for (const { row, score } of filtered) {
      lines.push(
        [
          score,
          row.cve,
          row.vendor,
          row.product,
          row.name,
          row.kev,
          row.ransomware,
          row.due ?? '',
          epssText(row.epss) ?? '',
        ]
          .map(cell)
          .join(',')
      );
    }
    download('cyberview-patch-queue.csv', lines.join('\n'), 'text/csv;charset=utf-8');
  };
  const copyChangeRequest = async () => {
    const lines = [
      `CyberView patch change request — data built ${fmtBuilt(builtAt)}`,
      '',
      `Top ${Math.min(filtered.length, 10)} priorities (local approximation of the upstream ranking):`,
      ...filtered
        .slice(0, 10)
        .map(
          ({ row, score }, i) =>
            `${i + 1}. [priority ${score}] ${row.cve} — ${row.vendor} ${row.product} — ${deadlineText(row.due, builtAt)}${row.ransomware ? ' — ransomware' : ''}`
        ),
      '',
      'Check and fix steps and source links are on the matching rows in the patch queue.',
    ];
    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      setCopyMsg('Change request copied to clipboard.');
    } catch {
      setCopyMsg('Clipboard unavailable — select the rows manually.');
    }
  };
  const huntPlan = () => {
    const lines = [
      `CyberView hunt plan — data built ${fmtBuilt(builtAt)}`,
      `Format filter: ${huntFormat}${huntMine ? ' · only my software' : ''}`,
      '',
      ...visibleHunt.map((h, i) => {
        const linked =
          h.cve ?? Object.keys(data?.event_of ?? {}).find((c) => data?.event_of[c] === h.event_id) ?? 'no linked CVE';
        return `${i + 1}. ${h.name} (${h.format}) — ${h.publisher}${h.date ? ` — ${h.date}` : ''}\n   Flaw: ${linked}\n   About: ${h.about}\n   ${h.url}`;
      }),
    ];
    download('cyberview-hunt-plan.txt', lines.join('\n'), 'text/plain;charset=utf-8');
  };

  const timelineGroup = (items: typeof need, empty: string) => (
    <ul className="grid gap-1.5">
      {items.slice(0, 8).map(({ row }) => (
        <li key={row.key}>
          <button
            type="button"
            onClick={() => openCve(row.cve)}
            className="flex w-full flex-wrap items-center gap-x-2 gap-y-0.5 rounded-control border border-line-1 bg-surface-100 px-2.5 py-1.5 text-left font-mono text-meta transition-colors hover:border-brand-400"
          >
            <span className="min-w-0 flex-1 truncate text-body">{row.product}</span>
            <span className="text-accent-text">{row.cve}</span>
            <span
              className={
                dayDiff(row.due, builtAt) !== null && (dayDiff(row.due, builtAt) ?? 0) > 0
                  ? 'text-rose-600 dark:text-rose-400'
                  : 'text-muted'
              }
            >
              {deadlineText(row.due, builtAt)}
            </span>
          </button>
        </li>
      ))}
      {items.length === 0 && <li className="font-mono text-meta text-muted">{empty}</li>}
    </ul>
  );

  const expandedPanel = ({ row, score }: { row: RankedRow; score: number }) => {
    const guide = data?.guides[row.cve];
    const analysis = data?.analyses[row.cve];
    const list = (label: string, items: string[]) =>
      items.length > 0 && (
        <div className="mt-2">
          <p className="font-mono text-meta font-semibold text-heading">{label}</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-meta leading-relaxed text-body">
            {items.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      );
    return (
      <div className="space-y-3 border-t border-line-1 px-4 py-4">
        <p className="text-meta leading-relaxed text-body">{row.desc}</p>
        {row.required && (
          <p className="rounded-lg border border-line-1 bg-wash px-3 py-2 text-meta leading-relaxed text-body">
            <span className="font-mono font-semibold text-heading">Required action: </span>
            {row.required}
          </p>
        )}
        {!row.kev && row.action && (
          <p className="rounded-lg border border-line-1 bg-wash px-3 py-2 text-meta leading-relaxed text-body">
            <span className="font-mono font-semibold text-heading">Suggested action: </span>
            {row.action}
          </p>
        )}
        {guide?.advisory && (
          <p className="text-meta">
            <span className="font-mono text-muted">Vendor advisory: </span>
            <a
              href={sanitizeUrl(guide.advisory.url) ?? '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-accent-text hover:underline"
            >
              {guide.advisory.name} <ExternalLink size={10} aria-hidden="true" />
            </a>
          </p>
        )}
        {row.refs.length > 0 && (
          <div>
            <p className="font-mono text-meta font-semibold text-heading">CISA references</p>
            <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
              {row.refs.map((r, i) => (
                <li key={i}>
                  <a
                    href={sanitizeUrl(r) ?? '#'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-mini text-accent-text hover:underline"
                  >
                    {r.replace(/^https?:\/\//, '').slice(0, 60)} <ExternalLink size={9} aria-hidden="true" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
        {row.affected.length > 0 && (
          <div>
            <p className="font-mono text-meta font-semibold text-heading">Affected versions</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {row.affected.slice(0, 40).map((a, i) => (
                <span key={i} className={BADGE}>
                  {affectedLabel(a)}
                </span>
              ))}
              {row.affected.length > 40 && <span className={BADGE}>+{row.affected.length - 40} more</span>}
            </div>
          </div>
        )}
        {guide && (
          <div className="rounded-lg border border-line-1 bg-surface-100 p-3">
            <p className="font-mono text-meta font-semibold text-heading">Check and fix steps</p>
            {list('Check', guide.check)}
            {list('Fixed versions', guide.fixed)}
            {list('Workarounds', guide.workaround)}
            {list('Signs of compromise', guide.compromise_signs)}
          </div>
        )}
        {analysis && (
          <div className="rounded-lg border border-line-1 bg-surface-100 p-3">
            <p className="font-mono text-meta font-semibold text-heading">Exploit and fix analysis</p>
            {analysis.exploitation_status && (
              <p className="mt-1 text-meta leading-relaxed text-body">{analysis.exploitation_status}</p>
            )}
            {analysis.how_exploited && (
              <p className="mt-2 text-meta leading-relaxed text-body">{analysis.how_exploited}</p>
            )}
            {list('Detection', analysis.detect)}
            {list('Remediation', analysis.remediation?.steps ?? [])}
            {list('Verify', analysis.remediation?.verify ?? [])}
            {analysis.caveats && <p className="mt-2 text-mini italic text-muted">{analysis.caveats}</p>}
          </div>
        )}
        {row.repo && row.repo.top.length > 0 && (
          <div>
            <p className="font-mono text-meta font-semibold text-heading">
              Public exploit code ({row.repo.repos} repos found)
            </p>
            <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
              {row.repo.top.map((r) => (
                <li key={r.url}>
                  <a
                    href={sanitizeUrl(r.url) ?? '#'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-mini text-accent-text hover:underline"
                  >
                    {r.name} <span className="text-muted">★ {r.stars}</span>{' '}
                    <ExternalLink size={9} aria-hidden="true" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
        <p className="font-mono text-mini text-muted">priority {score} (local approximation)</p>
      </div>
    );
  };

  const body = (
    <>
      <CyberViewNav />

      <div className="space-y-6">
        <header className="space-y-2">
          <h2 className="text-2xl font-display font-semibold text-heading sm:text-3xl">Vulnerabilities</h2>
          <p className="font-mono text-meta text-muted">
            {totalFlaws} exploited or high-risk flaws ranked · {pastDeadline} past the federal deadline · data built{' '}
            {fmtBuilt(builtAt)}
          </p>
        </header>

        <div role="search" className="surface-card rounded-xl border border-line-1 bg-surface-100 p-3">
          <label className="flex items-center gap-2">
            <Search size={14} className="shrink-0 text-muted" aria-hidden="true" />
            <span className="sr-only">Search</span>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="CVE, vendor or product"
              aria-label="Search vulnerabilities"
              className="w-full rounded-control border border-line-input bg-input-200 px-2.5 py-1.5 font-mono text-meta text-heading placeholder:text-muted"
            />
          </label>
          <p className="mt-1.5 font-mono text-mini text-muted">
            Filters the list below. Nothing you type is sent anywhere.
          </p>
        </div>

        <div role="tablist" aria-label="Vulnerabilities" className="flex flex-wrap gap-1 border-b border-line-1">
          {TABS.map((t) => {
            const count = t.id === Tab.Queue ? totalFlaws : t.id === Tab.Hunt ? huntCards.length : null;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                id={`tab-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`panel-${t.id}`}
                onClick={() => setTab(t.id)}
                className={`border-b-2 px-3 py-2 font-mono text-meta font-semibold transition-colors ${
                  tab === t.id
                    ? 'border-brand-500 text-accent-text'
                    : 'border-transparent text-muted hover:text-heading'
                }`}
              >
                {t.label}
                {count !== null ? ` (${count})` : ''}
              </button>
            );
          })}
        </div>

        {(work.loading || recent.loading) && !data && (
          <p className="font-mono text-meta text-muted">Loading the patch workbench…</p>
        )}
        {(work.error || recent.error) && (
          <p role="alert" className="font-mono text-meta text-rose-500">
            error: {work.error ?? recent.error}
          </p>
        )}

        {tab === Tab.Queue && (
          <section role="tabpanel" id="panel-queue" aria-labelledby="tab-queue" className="space-y-6">
            <div className="surface-card rounded-xl border border-line-1 p-4">
              <h3 className="text-lg font-semibold text-heading">How long do we have to patch?</h3>
              <p className="mt-1 max-w-3xl text-meta leading-relaxed text-muted">
                Flaws CISA confirms attackers are using, measured from today. A bar to the right is time left before the
                US federal deadline; a bar to the left is how long ago it passed. Use the deadline as an upper limit for
                your own patching.
              </p>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div>
                  <h4 className="font-mono text-meta font-semibold text-heading">Deadline ahead ({need.length})</h4>
                  <div className="mt-2">{timelineGroup(need, 'No deadlines ahead.')}</div>
                  {need.length > 8 && (
                    <p className="mt-2 font-mono text-mini text-muted">
                      +{need.length - 8} more in the list below (use the Show filter: deadline within 7 days or passed).
                    </p>
                  )}
                </div>
                <div>
                  <h4 className="font-mono text-meta font-semibold text-heading">
                    Deadline passed in the last two weeks ({overdue.length})
                  </h4>
                  <div className="mt-2">{timelineGroup(overdue, 'Nothing passed in the last two weeks.')}</div>
                  {overdue.length > 8 && (
                    <p className="mt-2 font-mono text-mini text-muted">
                      +{overdue.length - 8} more in the list below (use the Show filter: deadline within 7 days or
                      passed).
                    </p>
                  )}
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <button type="button" className={BTN} onClick={toCalendar} aria-label="Deadlines to calendar">
                  <CalendarDays size={13} aria-hidden="true" /> Deadlines to calendar
                </button>
                <button type="button" className={BTN} onClick={toCsv} aria-label="Download CSV">
                  <Download size={13} aria-hidden="true" /> Download CSV
                </button>
                <button type="button" className={BTN} onClick={copyChangeRequest} aria-label="Copy change request">
                  <Copy size={13} aria-hidden="true" /> Copy change request
                </button>
              </div>
              {copyMsg && (
                <p className="mt-2 font-mono text-mini text-muted" role="status">
                  {copyMsg}
                </p>
              )}
              <p className="mt-2 font-mono text-mini text-muted">
                Source: CISA Known Exploited Vulnerabilities catalog. The deadline binds US federal agencies only.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="show-filter" className="font-mono text-meta text-muted">
                Show
              </label>
              <select
                id="show-filter"
                value={show}
                onChange={(e) => setShow(e.target.value as ShowFilter)}
                className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading"
              >
                {SHOW_FILTERS.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label}
                  </option>
                ))}
              </select>
              <span className="ml-auto font-mono text-mini text-muted">{filtered.length} rows shown</span>
            </div>

            {inventory.length === 0 && (
              <p className="font-mono text-meta text-muted">
                No software list loaded, so this is the general ranking. Add yours under{' '}
                <button
                  type="button"
                  className="text-accent-text hover:underline"
                  onClick={() => setTab(Tab.Inventory)}
                >
                  My software
                </button>{' '}
                to see which versions you run are affected. It stays in this browser.
              </p>
            )}

            <details className="surface-card rounded-xl border border-line-1 p-3">
              <summary className="cursor-pointer font-mono text-meta font-semibold text-heading">
                How the score works
              </summary>
              <p className="mt-2 text-meta leading-relaxed text-body">
                CyberView publishes these weights: known exploited per CISA 35 (or 15 if only high severity) · used by
                ransomware groups 10 · EPSS up to 15 · public exploit code 5 · internet-facing 10 · federal deadline
                passed 5 or within 7 days 3 · an affected version you run 20, or a product you run needing a version
                check 10.
              </p>
              <p className="mt-1 text-meta leading-relaxed text-muted">
                The upstream score itself is not in the mirror, and internet-facing is partly inferred from product
                names, so the number here is a local approximation of that ranking — useful for ordering, not an exact
                reproduction of upstream points.
              </p>
            </details>

            <p className="font-mono text-meta text-muted">
              Highest priority first. The number is the local priority approximation.
            </p>
            <ol className="space-y-1.5">
              {filtered.map(({ row, score }) => {
                const open = expanded === row.key;
                return (
                  <li key={row.key} className="surface-card overflow-hidden rounded-xl border border-line-1">
                    <button
                      type="button"
                      aria-expanded={open}
                      onClick={() => setExpanded(open ? null : row.key)}
                      className="flex w-full flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2.5 text-left transition-colors hover:bg-wash"
                    >
                      <span
                        className="grid h-8 w-8 shrink-0 place-items-center rounded-control border border-line-1 bg-wash font-mono text-meta font-bold text-accent-text"
                        title="priority (local approximation of the upstream score)"
                        aria-label={`priority ${score}`}
                      >
                        {score}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex flex-wrap items-center gap-x-2 font-mono text-meta">
                          <b className="text-accent-text">{row.cve}</b>
                          <span className="text-body">
                            {row.vendor} {row.product}
                          </span>
                          <ChevronDown
                            size={12}
                            className={`text-muted transition-transform ${open ? 'rotate-180' : ''}`}
                            aria-hidden="true"
                          />
                        </span>
                        <span className="mt-0.5 block truncate text-meta text-heading">{row.name}</span>
                        <span className="mt-1 flex flex-wrap gap-1">
                          <span
                            className={`${BADGE} ${row.kev ? 'border-rose-500/40 text-rose-600 dark:text-rose-400' : 'text-muted'}`}
                          >
                            {row.kev ? 'Known exploited' : 'Not on CISA’s list'}
                          </span>
                          {row.ransomware && (
                            <span className={`${BADGE} border-rose-500/40 text-rose-600 dark:text-rose-400`}>
                              <AlertTriangle size={9} className="mr-0.5 inline" aria-hidden="true" />
                              Ransomware
                            </span>
                          )}
                          <span
                            className={`${BADGE} ${row.kev && (dayDiff(row.due, builtAt) ?? 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-muted'}`}
                          >
                            {deadlineText(row.due, builtAt)}
                          </span>
                          {epssText(row.epss) && (
                            <span className={`${BADGE} text-accent-text`}>EPSS {epssText(row.epss)}</span>
                          )}
                          {hasSteps(row.cve, data) && (
                            <span className={`${BADGE} text-emerald-600 dark:text-emerald-400`}>
                              <Check size={9} className="mr-0.5 inline" aria-hidden="true" />
                              Check and fix steps
                            </span>
                          )}
                          {data?.analyses[row.cve] && (
                            <span className={`${BADGE} text-emerald-600 dark:text-emerald-400`}>
                              Exploit and fix analysis
                            </span>
                          )}
                          {matchInventory(row, inventory) && (
                            <span className={`${BADGE} border-brand-500/40 text-accent-text`}>Affects my software</span>
                          )}
                        </span>
                      </span>
                    </button>
                    {open && expandedPanel({ row, score })}
                  </li>
                );
              })}
              {filtered.length === 0 && (
                <li className="py-8 text-center font-mono text-meta text-muted">No rows match this filter.</li>
              )}
            </ol>
          </section>
        )}

        {tab === Tab.All && (
          <section role="tabpanel" id="panel-all" aria-labelledby="tab-all" className="space-y-4">
            <div className="surface-card rounded-xl border border-line-1 p-4">
              <h3 className="text-lg font-semibold text-heading">Browse every recent CVE</h3>
              <p className="mt-1 text-meta leading-relaxed text-muted">
                Type an id in the box and press Look up. Only the mirrored recent-CVE file is read; nothing is sent
                anywhere.
              </p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <input
                  type="search"
                  value={cveQuery}
                  onChange={(e) => {
                    setCveQuery(e.target.value);
                    setLookup(null);
                    setLookupMsg('');
                    setPage(0);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter')
                      setLookup(cveList.find((r) => r.id.toLowerCase() === cveQuery.trim().toLowerCase()) ?? null);
                  }}
                  placeholder="CVE-2024-3400"
                  aria-label="Look up a CVE id"
                  className="w-full max-w-xs rounded-control border border-line-input bg-input-200 px-2.5 py-1.5 font-mono text-meta text-heading placeholder:text-muted"
                />
                <button
                  type="button"
                  className={BTN}
                  onClick={() => {
                    const id = cveQuery.trim().toLowerCase();
                    if (!/^cve-\d{4}-\d+$/.test(id)) {
                      setLookup(null);
                      setLookupMsg('Use a CVE id like CVE-2024-3400.');
                      return;
                    }
                    const hit = cveList.find((r) => r.id.toLowerCase() === id) ?? null;
                    setLookup(hit);
                    setLookupMsg(hit ? '' : 'Not in the mirrored recent list.');
                  }}
                >
                  Look up
                </button>
                <span className="font-mono text-mini text-muted" role="status" aria-live="polite">
                  {lookupMsg}
                </span>
              </div>
              {lookup && (
                <div className="mt-3 rounded-lg border border-line-1 bg-wash p-3">
                  <p className="font-mono text-meta font-semibold text-accent-text">
                    {lookup.id} · {SEV_LABEL[lookup.sev] ?? (lookup.sev || 'Unknown')} · CVSS {lookup.cvss ?? '—'}
                  </p>
                  <p className="mt-1 text-meta text-body">{lookup.title}</p>
                  <p className="mt-1 font-mono text-mini text-muted">
                    {lookup.vendor} {lookup.product} · published {lookup.pub || '—'}
                    {lookup.kev ? ' · on CISA list' : ''}
                  </p>
                </div>
              )}
            </div>
            <div className="surface-card overflow-hidden rounded-xl border border-line-1">
              <div className="grid grid-cols-[110px_70px_60px_1fr_90px] gap-2 border-b border-line-1 px-3 py-2 font-mono text-mini uppercase tracking-wide text-muted">
                <span>CVE</span>
                <span>Severity</span>
                <span>CVSS</span>
                <span>Title</span>
                <span>Published</span>
              </div>
              {paged.map((r) => (
                <div
                  key={r.id}
                  className="grid grid-cols-[110px_70px_60px_1fr_90px] gap-2 border-b border-line-1 px-3 py-2 text-meta last:border-b-0"
                >
                  <span className="truncate font-mono text-accent-text">{r.id}</span>
                  <span className="font-mono text-muted">{SEV_LABEL[r.sev] ?? (r.sev || '—')}</span>
                  <span className="font-mono text-body">{r.cvss ?? '—'}</span>
                  <span className="truncate text-body" title={r.title}>
                    {r.title}
                    <span className="ml-1 font-mono text-mini text-muted">{r.vendor}</span>
                  </span>
                  <span className="font-mono text-mini text-muted">{r.pub}</span>
                </div>
              ))}
              {paged.length === 0 && (
                <p className="px-3 py-8 text-center font-mono text-meta text-muted">No CVEs match.</p>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                className={BTN}
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
              >
                ← Prev
              </button>
              <span className="font-mono text-meta text-muted">
                Page {page + 1} of {pages}
              </span>
              <button
                type="button"
                className={BTN}
                disabled={page + 1 >= pages}
                onClick={() => setPage((p) => Math.min(pages - 1, p + 1))}
              >
                Next →
              </button>
              <span className="ml-auto font-mono text-mini text-muted">
                Loaded {recentList.length} CVEs since {recent.data?.since ?? '—'} · {cveSearch.length} shown
              </span>
            </div>
          </section>
        )}

        {tab === Tab.Inventory && (
          <section role="tabpanel" id="panel-inventory" aria-labelledby="tab-inventory" className="space-y-4">
            <div className="surface-card rounded-xl border border-line-1 p-4">
              <h3 className="text-lg font-semibold text-heading">My software</h3>
              <p className="mt-1 max-w-2xl text-meta leading-relaxed text-muted">
                Paste one product per line, with a version if you know it, for example{' '}
                <code className="font-mono text-accent-text">Google Chromium 131</code>. Matching happens here in your
                browser against the mirrored affected-version ranges. Nothing is uploaded or sent anywhere.
              </p>
              <label htmlFor="inv" className="mt-3 block font-mono text-meta text-muted">
                Software list
              </label>
              <textarea
                id="inv"
                rows={8}
                value={invText}
                onChange={(e) => setInvText(e.target.value)}
                placeholder={'Google Chromium 131\nMicrosoft Office 2021\nApache Struts 2.5.30'}
                className="mt-1 w-full rounded-control border border-line-input bg-input-200 p-3 font-mono text-meta text-heading placeholder:text-muted"
              />
              <p className="mt-2 font-mono text-mini text-muted">
                Stored locally in this browser (localStorage key “{INVENTORY_KEY}”). {inventory.length} lines entered ·{' '}
                {affectedCves.length} affected CVEs · {Math.max(0, unmatchedCount)} unmatched lines.
              </p>
            </div>
            <div className="surface-card overflow-hidden rounded-xl border border-line-1">
              <h4 className="border-b border-line-1 px-3 py-2 font-mono text-meta font-semibold text-heading">
                Affected CVEs in the patch queue
              </h4>
              {affectedCves.length === 0 ? (
                <p className="px-3 py-8 text-center font-mono text-meta text-muted">
                  No matches yet — add a product above.
                </p>
              ) : (
                <ul className="divide-y divide-line-1">
                  {affectedCves.map((r) => (
                    <li key={r.key} className="flex flex-wrap items-center gap-2 px-3 py-2">
                      <span className="font-mono text-meta text-accent-text">{r.cve}</span>
                      <span className="min-w-0 flex-1 truncate text-meta text-body">
                        {r.product} — {r.name}
                      </span>
                      <span className={`${BADGE} text-muted`}>{deadlineText(r.due, builtAt)}</span>
                      <button
                        type="button"
                        className="font-mono text-mini text-accent-text hover:underline"
                        onClick={() => openCve(r.cve)}
                      >
                        Open in queue
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        )}

        {tab === Tab.Hunt && (
          <section role="tabpanel" id="panel-hunt" aria-labelledby="tab-hunt" className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="hunt-format" className="font-mono text-meta text-muted">
                Format
              </label>
              <select
                id="hunt-format"
                value={huntFormat}
                onChange={(e) => setHuntFormat(e.target.value)}
                className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading"
              >
                {formats.map((f) => (
                  <option key={f} value={f}>
                    {f === 'all' ? 'all' : f}
                  </option>
                ))}
              </select>
              <label className="inline-flex items-center gap-2 font-mono text-meta text-muted">
                <input type="checkbox" checked={huntMine} onChange={(e) => setHuntMine(e.target.checked)} /> only my
                software
              </label>
              <button type="button" className={`${BTN} ml-auto`} onClick={huntPlan} aria-label="Download hunt plan">
                <Download size={13} aria-hidden="true" /> Download hunt plan
              </button>
            </div>
            <p className="font-mono text-mini text-muted">
              {visibleHunt.length} of {huntCards.length} hunt resources shown
            </p>
            <ul className="grid gap-3 lg:grid-cols-2">
              {visibleHunt.map((h, i) => (
                <li key={`${h.name}-${i}`} className="surface-card rounded-xl border border-line-1 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Target size={14} className="text-accent-text" aria-hidden="true" />
                    <a
                      href={sanitizeUrl(h.url) ?? '#'}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-meta font-semibold text-heading hover:text-accent-text"
                    >
                      {h.name} <ExternalLink size={11} aria-hidden="true" />
                    </a>
                    <span className={`${BADGE} ml-auto uppercase text-muted`}>{h.format}</span>
                  </div>
                  <p className="mt-2 text-meta leading-relaxed text-body">{h.about}</p>
                  <p className="mt-2 font-mono text-mini text-muted">
                    {h.publisher}
                    {h.date ? ` · ${h.date}` : ''}
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line-1 pt-2">
                    <span className="font-mono text-mini text-muted">
                      Flaw: {h.cve ?? h.event_id ?? 'linked advisory'}
                    </span>
                    <button
                      type="button"
                      className="ml-auto font-mono text-mini text-accent-text hover:underline"
                      onClick={() => (h.cve ? openCve(h.cve) : setTab(Tab.Queue))}
                    >
                      See in patch queue →
                    </button>
                  </div>
                </li>
              ))}
              {visibleHunt.length === 0 && (
                <li className="py-8 text-center font-mono text-meta text-muted">
                  No hunt resources match these filters.
                </li>
              )}
            </ul>
          </section>
        )}

        <footer className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-4 font-mono text-mini text-muted">
          <span>
            <ShieldAlert size={11} className="mr-1 inline" aria-hidden="true" />
            CyberView replication — community research, locally mirrored.
          </span>
          <a
            href="https://xanderhutch.github.io/CyberView/vulnerabilities.html"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-accent-text hover:underline"
          >
            <FileText size={10} aria-hidden="true" /> Original CyberView page{' '}
            <ExternalLink size={9} aria-hidden="true" />
          </a>
          <span className="ml-auto">Built {fmtBuilt(builtAt)}</span>
        </footer>
      </div>
    </>
  );

  return bare ? (
    body
  ) : (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="CyberView — Vulnerabilities"
      description="Replication of CyberView's patch workbench: known-exploited flaws ranked by federal deadline and EPSS, check-and-fix steps, a hunt pack and a CVE browser."
      onRetry={() => {
        work.refetch();
        recent.refetch();
      }}
      loading={work.loading || recent.loading}
      error={work.error ?? recent.error}
      maxWidthClass="max-w-7xl"
    >
      {body}
    </DataPageLayout>
  );
}
