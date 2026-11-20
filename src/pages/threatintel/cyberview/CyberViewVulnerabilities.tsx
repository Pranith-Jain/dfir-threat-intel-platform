import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  CalendarDays,
  Check,
  ChevronDown,
  Copy,
  Download,
  FileText,
  Search,
  ShieldAlert,
  Target,
} from 'lucide-react';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { asArray, matches, text } from './shared-utils';
import { Badge, CyberViewPage, Empty, OutLink, Pager, Section } from './shared-ui';

/**
 * CyberView "Vulnerabilities" workbench replication. All numbers come from the
 * mirrored workbench.json / recent.json; nothing is fetched live and nothing
 * typed into the search boxes leaves the browser. The upstream ranking score is
 * not stored in the mirror, so the number is a transparent local approximation
 * built from the weights CyberView publishes in its own score disclosure.
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
interface Scored {
  row: RankedRow;
  score: number;
}
const Tab = { Queue: 'queue', All: 'all', Inventory: 'inventory', Hunt: 'hunt' } as const;
type Tab = (typeof Tab)[keyof typeof Tab];
const TABS = [
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
const SEV_LABEL: Record<string, string> = { H: 'High', M: 'Medium', L: 'Low', C: 'Critical' };
const CARD = 'surface-card rounded-xl border border-line-1';
const HEAD = 'font-mono text-meta font-semibold text-heading';
const LINK = 'font-mono text-mini text-accent-text hover:underline';
const INPUT =
  'rounded-control border border-line-input bg-input-200 px-2.5 py-1.5 font-mono text-meta text-heading placeholder:text-muted';
const SELECT = 'rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-meta text-heading';
const BTN =
  'inline-flex items-center gap-1.5 rounded-control border border-line-1 bg-surface-100 px-2.5 py-1.5 font-mono text-meta text-body transition-colors hover:border-brand-400 hover:text-heading disabled:cursor-not-allowed disabled:opacity-50';

function dayDiff(due: string | null, builtAt: string): number | null {
  if (!due) return null;
  const built = new Date(builtAt);
  if (Number.isNaN(built.getTime())) return null;
  const b = Date.UTC(built.getUTCFullYear(), built.getUTCMonth(), built.getUTCDate());
  const d = Date.parse(`${text(due).slice(0, 10)}T00:00:00Z`);
  return Number.isNaN(d) ? null : Math.round((b - d) / DAY_MS);
}
function fmtBuilt(stamp: string): string {
  const d = new Date(stamp);
  return Number.isNaN(d.getTime()) ? stamp : `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}
function deadlineText(due: string | null, builtAt: string): string {
  const d = dayDiff(due, builtAt);
  return d === null
    ? 'Not on CISA’s list'
    : d === 0
      ? 'due today'
      : d > 0
        ? `${d} day${d === 1 ? '' : 's'} overdue`
        : `${-d} day${d === -1 ? '' : 's'} left`;
}
function epssText(v: number | null): string | null {
  return v == null ? null : `${Math.round(v * 100)}%`;
}
function affectedLabel(a: Affected): string {
  const bits = [text(a.vendor), text(a.product)].filter(Boolean);
  if (a.exact) bits.push(a.exact);
  else if (a.from || a.to)
    bits.push(`${a.from_incl === false ? '(' : ''}${a.from ?? ''} → ${a.to ?? ''}${a.to_incl === false ? ')' : ''}`);
  else if (a.update) bits.push(a.update);
  return bits.join(' ').trim();
}
function hasSteps(cve: string, data: Workbench | null): boolean {
  const g = data?.guides?.[cve];
  return Boolean(
    g &&
    (asArray(g.check).length ||
      asArray(g.fixed).length ||
      asArray(g.workaround).length ||
      asArray(g.compromise_signs).length)
  );
}
function internetFacing(row: RankedRow, guide?: Guide): boolean {
  if (guide?.exposure) return guide.exposure === 'internet';
  return /\b(server|web|http|nginx|apache|firewall|vpn|exchange|email|gateway|router|appliance|cloud|portal|ssl|vcenter|remote|ftp|smtp|proxy|dsm|nas|cms|sharepoint|confluence|jenkins|gitlab)\b/i.test(
    `${row.product} ${asArray(row.products).join(' ')}`
  );
}
function publicExploit(row: RankedRow, guide?: Guide): boolean {
  return Boolean(guide?.exploit_public || (row.repo && asArray(row.repo.top).length > 0));
}
function matchInventory(row: RankedRow, inventory: string[]): 'version' | 'product' | null {
  if (!inventory.length) return null;
  const hay = `${row.vendor} ${row.product} ${asArray(row.products).join(' ')}`.toLowerCase();
  let best: 'version' | 'product' | null = null;
  for (const line of inventory) {
    const m = line.match(/^(.*?)\s+v?(\d+(?:[.\-_]\d+)*[a-z0-9.\-_]*)$/i);
    const name = (m?.[1] ?? line).trim().toLowerCase();
    const version = (m?.[2] ?? '').toLowerCase();
    if (name.length < 3 || !hay.includes(name)) continue;
    best = 'product';
    if (!version) continue;
    const hit = asArray(row.affected).some((a) => {
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
  if (typeof row.epss === 'number') s += Math.round(row.epss * 15);
  const guide = data?.guides?.[row.cve];
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
  const out: RankedRow[] = asArray(data.kev).map((r) => ({
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
    refs: asArray(r.refs),
    affected: asArray(r.affected),
    repo: r.repo,
    severity: 0,
    date: r.added,
    products: [r.product],
    action: r.required,
  }));
  for (const v of asArray(data.vulns))
    out.push({
      key: `v-${v.cve}-${v.event_id}`,
      cve: v.cve,
      vendor: v.vendor,
      product: asArray(v.products)[0] ?? v.vendor,
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
      products: asArray(v.products),
      action: v.action,
    });
  return out;
}
function recentRows(data: RecentData | null): CveLite[] {
  if (!data) return [];
  const fields = asArray(data.fields);
  const at = (row: unknown[], f: string) => {
    const i = fields.indexOf(f);
    return i < 0 ? null : row[i];
  };
  const num = (row: unknown[], f: string) => (typeof at(row, f) === 'number' ? (at(row, f) as number) : null);
  return asArray(data.rows).map((row) => ({
    id: text(at(row, 'id')),
    pub: text(at(row, 'pub')),
    cvss: num(row, 'cvss'),
    sev: text(at(row, 'sev')),
    vendor: text(at(row, 'vendor')),
    product: text(at(row, 'product')),
    title: text(at(row, 'title')),
    kev: text(at(row, 'kev')),
    epss: num(row, 'epss'),
  }));
}
function download(name: string, contents: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
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
  return text(d).slice(0, 10).replace(/-/g, '');
}

/* Extracted detail sections shared by the expandable queue rows. */
function DetailList({ label, items }: { label: string; items: string[] }) {
  const list = asArray(items);
  return list.length ? (
    <div className="mt-2">
      <p className={HEAD}>{label}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-meta leading-relaxed text-body">
        {list.map((s, i) => (
          <li key={i}>{text(s)}</li>
        ))}
      </ul>
    </div>
  ) : null;
}
function ActionNote({ label, value }: { label: string; value: string }) {
  return (
    <p className="rounded-lg border border-line-1 bg-wash px-3 py-2 text-meta leading-relaxed text-body">
      <span className="font-mono font-semibold text-heading">{label}: </span>
      {value}
    </p>
  );
}
function RefLinks({ urls }: { urls: string[] }) {
  const list = asArray(urls);
  return list.length ? (
    <div>
      <p className={HEAD}>CISA references</p>
      <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
        {list.map((r, i) => (
          <li key={i}>
            <OutLink href={text(r)} className="font-mono text-mini">
              {text(r)
                .replace(/^https?:\/\//, '')
                .slice(0, 60)}
            </OutLink>
          </li>
        ))}
      </ul>
    </div>
  ) : null;
}
function AffectedChips({ affected }: { affected: Affected[] }) {
  const list = asArray(affected);
  return list.length ? (
    <div>
      <p className={HEAD}>Affected versions</p>
      <div className="mt-1 flex flex-wrap gap-1">
        {list.slice(0, 40).map((a, i) => (
          <Badge key={i} className="font-mono text-mini">
            {affectedLabel(a)}
          </Badge>
        ))}
        {list.length > 40 && <Badge>+{list.length - 40} more</Badge>}
      </div>
    </div>
  ) : null;
}
function GuideBox({ guide }: { guide?: Guide }) {
  return guide ? (
    <div className="rounded-lg border border-line-1 bg-surface-100 p-3">
      <p className={HEAD}>Check and fix steps</p>
      <DetailList label="Check" items={asArray(guide.check)} />
      <DetailList label="Fixed versions" items={asArray(guide.fixed)} />
      <DetailList label="Workarounds" items={asArray(guide.workaround)} />
      <DetailList label="Signs of compromise" items={asArray(guide.compromise_signs)} />
    </div>
  ) : null;
}
function AnalysisBox({ analysis }: { analysis?: Analysis }) {
  return analysis ? (
    <div className="rounded-lg border border-line-1 bg-surface-100 p-3">
      <p className={HEAD}>Exploit and fix analysis</p>
      {analysis.exploitation_status && (
        <p className="mt-1 text-meta leading-relaxed text-body">{analysis.exploitation_status}</p>
      )}
      {analysis.how_exploited && <p className="mt-2 text-meta leading-relaxed text-body">{analysis.how_exploited}</p>}
      <DetailList label="Detection" items={asArray(analysis.detect)} />
      <DetailList label="Remediation" items={asArray(analysis.remediation?.steps)} />
      <DetailList label="Verify" items={asArray(analysis.remediation?.verify)} />
      {analysis.caveats && <p className="mt-2 text-mini italic text-muted">{analysis.caveats}</p>}
    </div>
  ) : null;
}
function RepoLinks({ repo }: { repo: Repo | null }) {
  const top = asArray(repo?.top);
  return top.length ? (
    <div>
      <p className={HEAD}>Public exploit code ({repo?.repos} repos found)</p>
      <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
        {top.map((r) => (
          <li key={r.url}>
            <OutLink href={text(r.url)} className="font-mono text-mini">
              {text(r.name)} <span className="text-muted">★ {r.stars}</span>
            </OutLink>
          </li>
        ))}
      </ul>
    </div>
  ) : null;
}
function TimelineGroup({
  items,
  empty,
  builtAt,
  onOpen,
}: {
  items: Scored[];
  empty: string;
  builtAt: string;
  onOpen: (cve: string) => void;
}) {
  return (
    <ul className="grid gap-1.5">
      {items.slice(0, 8).map(({ row }) => {
        const late = dayDiff(row.due, builtAt) !== null && (dayDiff(row.due, builtAt) ?? 0) > 0;
        return (
          <li key={row.key}>
            <button
              type="button"
              onClick={() => onOpen(row.cve)}
              className="flex w-full flex-wrap items-center gap-x-2 gap-y-0.5 rounded-control border border-line-1 bg-surface-100 px-2.5 py-1.5 text-left font-mono text-meta transition-colors hover:border-brand-400"
            >
              <span className="min-w-0 flex-1 truncate text-body">{row.product}</span>
              <span className="text-accent-text">{row.cve}</span>
              <span className={late ? 'text-rose-600 dark:text-rose-400' : 'text-muted'}>
                {deadlineText(row.due, builtAt)}
              </span>
            </button>
          </li>
        );
      })}
      {items.length === 0 && (
        <li>
          <Empty>{empty}</Empty>
        </li>
      )}
    </ul>
  );
}
function CveRow({ r }: { r: CveLite }) {
  return (
    <div className="grid grid-cols-[110px_70px_60px_1fr_90px] gap-2 border-b border-line-1 px-3 py-2 text-meta last:border-b-0">
      <span className="truncate font-mono text-accent-text">{r.id}</span>
      <span className="font-mono text-muted">{SEV_LABEL[r.sev] ?? (r.sev || '—')}</span>
      <span className="font-mono text-body">{r.cvss ?? '—'}</span>
      <span className="truncate text-body" title={r.title}>
        {r.title}
        <span className="ml-1 font-mono text-mini text-muted">{r.vendor}</span>
      </span>
      <span className="font-mono text-mini text-muted">{r.pub}</span>
    </div>
  );
}
function HuntCardView({ h, onOpen }: { h: HuntCard; onOpen: (cve?: string) => void }) {
  return (
    <li className={`${CARD} p-4`}>
      <div className="flex flex-wrap items-center gap-2">
        <Target size={14} className="text-accent-text" aria-hidden="true" />
        <OutLink
          href={text(h.url)}
          className="inline-flex items-center gap-1 font-mono text-meta font-semibold text-heading hover:text-accent-text"
        >
          {h.name}
        </OutLink>
        <Badge className="ml-auto uppercase">{text(h.format)}</Badge>
      </div>
      <p className="mt-2 text-meta leading-relaxed text-body">{h.about}</p>
      <p className="mt-2 font-mono text-mini text-muted">
        {h.publisher}
        {h.date ? ` · ${h.date}` : ''}
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line-1 pt-2">
        <span className="font-mono text-mini text-muted">Flaw: {h.cve ?? h.event_id ?? 'linked advisory'}</span>
        <button type="button" className={LINK} onClick={() => onOpen(h.cve)}>
          See in patch queue →
        </button>
      </div>
    </li>
  );
}
function QueueRow({
  entry,
  open,
  builtAt,
  onToggle,
  onExpand,
  badges,
}: {
  entry: Scored;
  open: boolean;
  builtAt: string;
  onToggle: () => void;
  onExpand: ReactNode;
  badges: ReactNode;
}) {
  const { row, score } = entry;
  const d = dayDiff(row.due, builtAt) ?? 0;
  return (
    <li className="surface-card overflow-hidden rounded-xl border border-line-1">
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
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
            <Badge tone={row.kev ? 'high' : 'neutral'}>{row.kev ? 'Known exploited' : 'Not on CISA’s list'}</Badge>
            {row.ransomware && (
              <Badge tone="high">
                <AlertTriangle size={9} className="mr-0.5 inline" aria-hidden="true" /> Ransomware
              </Badge>
            )}
            <Badge tone={row.kev && d > 0 ? 'high' : 'neutral'}>{deadlineText(row.due, builtAt)}</Badge>
            {badges}
          </span>
        </span>
      </button>
      {open && onExpand}
    </li>
  );
}

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
      /* storage may be disabled */
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
    () => allRows.map((row) => ({ row, score: priority(row, data, matchInventory(row, inventory)) })),
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
          if (d === null || d < -7) return false;
        } // ahead ≤7 days or passed
        if (show === 'steps' && !hasSteps(row.cve, data)) return false;
        return !needle || matches(`${row.cve} ${row.vendor} ${row.product} ${row.name} ${row.desc}`, needle);
      })
      .sort((a, b) => b.score - a.score || a.row.cve.localeCompare(b.row.cve));
  }, [scored, query, show, inventory, builtAt, data]);

  const huntCards = useMemo<HuntCard[]>(() => {
    if (!data) return [];
    const fromGuides = Object.values(data.guides ?? {}).flatMap((g) =>
      asArray(g.hunt).map((h) => ({ ...h, cve: g.cve, event_id: data.event_of?.[g.cve] ?? h.event_id }))
    );
    return [...asArray(data.hunt), ...fromGuides];
  }, [data]);
  const formats = useMemo(
    () => ['all', ...Array.from(new Set(huntCards.map((h) => h.format).filter(Boolean)))],
    [huntCards]
  );
  const cardAffectsMine = (h: HuntCard) => {
    const cves = h.cve ? [h.cve] : Object.keys(data?.event_of ?? {}).filter((c) => data?.event_of?.[c] === h.event_id);
    return cves.some((c) => {
      const r = allRows.find((x) => x.cve === c);
      return Boolean(r && matchInventory(r, inventory));
    });
  };
  const visibleHunt = huntCards.filter(
    (h) => (huntFormat === 'all' || h.format === huntFormat) && (!huntMine || cardAffectsMine(h))
  );

  const cveList = useMemo(() => recentRows(recent.data), [recent.data]);
  const recentList = cveList.filter((r) => !recent.data?.since || r.pub >= recent.data.since);
  const cveSearch = recentList.filter((r) => matches(`${r.id} ${r.vendor} ${r.product} ${r.title}`, cveQuery.trim()));
  const paged = cveSearch.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  const pages = Math.max(1, Math.ceil(cveSearch.length / PAGE_SIZE));

  const affectedCves = allRows.filter((r) => matchInventory(r, inventory));
  const unmatchedCount =
    inventory.length -
    new Set(
      affectedCves.flatMap((r) => {
        const hay = `${r.vendor} ${r.product} ${asArray(r.products).join(' ')}`.toLowerCase();
        return inventory.filter((line) =>
          hay.includes(
            text(line.split(/\s+v?\d/)[0] ?? line)
              .trim()
              .toLowerCase()
          )
        );
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
        `DTSTART;VALUE:DATE:${start}`,
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
    const cell = (v: unknown) => `"${text(v).replace(/"/g, '""')}"`;
    const lines = ['priority,cve,vendor,product,name,known_exploited,ransomware,due,epss'];
    for (const { row, score } of filtered)
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
          h.cve ?? Object.keys(data?.event_of ?? {}).find((c) => data?.event_of?.[c] === h.event_id) ?? 'no linked CVE';
        return `${i + 1}. ${h.name} (${h.format}) — ${h.publisher}${h.date ? ` — ${h.date}` : ''}\n   Flaw: ${linked}\n   About: ${h.about}\n   ${h.url}`;
      }),
    ];
    download('cyberview-hunt-plan.txt', lines.join('\n'), 'text/plain;charset=utf-8');
  };
  const expandedPanel = ({ row, score }: Scored) => {
    const guide = data?.guides?.[row.cve];
    const analysis = data?.analyses?.[row.cve];
    return (
      <div className="space-y-3 border-t border-line-1 px-4 py-4">
        <p className="text-meta leading-relaxed text-body">{row.desc}</p>
        {row.required && <ActionNote label="Required action" value={row.required} />}
        {!row.kev && row.action && <ActionNote label="Suggested action" value={row.action} />}
        {guide?.advisory && (
          <p className="text-meta">
            <span className="font-mono text-muted">Vendor advisory: </span>
            <OutLink href={text(guide.advisory.url)} className="inline-flex items-center gap-1">
              {text(guide.advisory.name)}
            </OutLink>
          </p>
        )}
        <RefLinks urls={row.refs} />
        <AffectedChips affected={row.affected} />
        <GuideBox guide={guide} />
        <AnalysisBox analysis={analysis} />
        <RepoLinks repo={row.repo} />
        <p className="font-mono text-mini text-muted">priority {score} (local approximation)</p>
      </div>
    );
  };
  const scoreBadges = (row: RankedRow) => (
    <>
      {epssText(row.epss) && <Badge tone="brand">EPSS {epssText(row.epss)}</Badge>}
      {hasSteps(row.cve, data) && (
        <Badge tone="good">
          <Check size={9} className="mr-0.5 inline" aria-hidden="true" /> Check and fix steps
        </Badge>
      )}
      {data?.analyses?.[row.cve] && <Badge tone="good">Exploit and fix analysis</Badge>}
      {matchInventory(row, inventory) && <Badge tone="brand">Affects my software</Badge>}
    </>
  );

  return (
    <CyberViewPage
      bare={bare}
      icon={<ShieldAlert size={28} />}
      title="CyberView — Vulnerabilities"
      description="Replication of CyberView's patch workbench: known-exploited flaws ranked by federal deadline and EPSS, check-and-fix steps, a hunt pack and a CVE browser."
      loading={work.loading || recent.loading}
      error={work.error ?? recent.error}
      onRetry={() => {
        work.refetch();
        recent.refetch();
      }}
      maxWidthClass="max-w-7xl"
    >
      <div className="space-y-6">
        <header className="space-y-2">
          <h2 className="text-2xl font-display font-semibold text-heading sm:text-3xl">Vulnerabilities</h2>
          <p className="font-mono text-meta text-muted">
            {totalFlaws} exploited or high-risk flaws ranked · {pastDeadline} past the federal deadline · data built{' '}
            {fmtBuilt(builtAt)}
          </p>
        </header>

        <div role="search" className={`${CARD} bg-surface-100 p-3`}>
          <label className="flex items-center gap-2">
            <Search size={14} className="shrink-0 text-muted" aria-hidden="true" />
            <span className="sr-only">Search</span>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="CVE, vendor or product"
              aria-label="Search vulnerabilities"
              className={`w-full ${INPUT}`}
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
                className={`border-b-2 px-3 py-2 font-mono text-meta font-semibold transition-colors ${tab === t.id ? 'border-brand-500 text-accent-text' : 'border-transparent text-muted hover:text-heading'}`}
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
            <Section title="How long do we have to patch?">
              <div className={`${CARD} p-4`}>
                <p className="mt-1 max-w-3xl text-meta leading-relaxed text-muted">
                  Flaws CISA confirms attackers are using, measured from today. A bar to the right is time left before
                  the US federal deadline; a bar to the left is how long ago it passed. Use the deadline as an upper
                  limit for your own patching.
                </p>
                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <div>
                    <h4 className={HEAD}>Deadline ahead ({need.length})</h4>
                    <div className="mt-2">
                      <TimelineGroup items={need} empty="No deadlines ahead." builtAt={builtAt} onOpen={openCve} />
                    </div>
                    {need.length > 8 && (
                      <p className="mt-2 font-mono text-mini text-muted">
                        +{need.length - 8} more in the list below (use the Show filter: deadline within 7 days or
                        passed).
                      </p>
                    )}
                  </div>
                  <div>
                    <h4 className={HEAD}>Deadline passed in the last two weeks ({overdue.length})</h4>
                    <div className="mt-2">
                      <TimelineGroup
                        items={overdue}
                        empty="Nothing passed in the last two weeks."
                        builtAt={builtAt}
                        onOpen={openCve}
                      />
                    </div>
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
            </Section>

            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="show-filter" className="font-mono text-meta text-muted">
                Show
              </label>
              <select
                id="show-filter"
                value={show}
                onChange={(e) => setShow(e.target.value as ShowFilter)}
                className={SELECT}
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

            <details className={`${CARD} p-3`}>
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
              {filtered.map((entry) => (
                <QueueRow
                  key={entry.row.key}
                  entry={entry}
                  open={expanded === entry.row.key}
                  builtAt={builtAt}
                  onToggle={() => setExpanded(expanded === entry.row.key ? null : entry.row.key)}
                  onExpand={expandedPanel(entry)}
                  badges={scoreBadges(entry.row)}
                />
              ))}
              {filtered.length === 0 && (
                <li>
                  <Empty>No rows match this filter.</Empty>
                </li>
              )}
            </ol>
          </section>
        )}

        {tab === Tab.All && (
          <section role="tabpanel" id="panel-all" aria-labelledby="tab-all" className="space-y-4">
            <Section title="Browse every recent CVE">
              <div className={`${CARD} p-4`}>
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
                    className={`max-w-xs ${INPUT}`}
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
            </Section>
            <div className="surface-card overflow-hidden rounded-xl border border-line-1">
              <div className="grid grid-cols-[110px_70px_60px_1fr_90px] gap-2 border-b border-line-1 px-3 py-2 font-mono text-mini uppercase tracking-wide text-muted">
                <span>CVE</span>
                <span>Severity</span>
                <span>CVSS</span>
                <span>Title</span>
                <span>Published</span>
              </div>
              {paged.map((r) => (
                <CveRow key={r.id} r={r} />
              ))}
              {paged.length === 0 && <Empty>No CVEs match.</Empty>}
            </div>
            <Pager page={page} pages={pages} onPage={setPage} />
            <p className="font-mono text-mini text-muted">
              Page {page + 1} of {pages} · Loaded {recentList.length} CVEs since {recent.data?.since ?? '—'} ·{' '}
              {cveSearch.length} shown
            </p>
          </section>
        )}

        {tab === Tab.Inventory && (
          <section role="tabpanel" id="panel-inventory" aria-labelledby="tab-inventory" className="space-y-4">
            <Section title="My software">
              <div className={`${CARD} p-4`}>
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
                  Stored locally in this browser (localStorage key “{INVENTORY_KEY}”). {inventory.length} lines entered
                  · {affectedCves.length} affected CVEs · {Math.max(0, unmatchedCount)} unmatched lines.
                </p>
              </div>
            </Section>
            <div className="surface-card overflow-hidden rounded-xl border border-line-1">
              <h4 className={HEAD + ' border-b border-line-1 px-3 py-2'}>Affected CVEs in the patch queue</h4>
              {affectedCves.length === 0 ? (
                <Empty>No matches yet — add a product above.</Empty>
              ) : (
                <ul className="divide-y divide-line-1">
                  {affectedCves.map((r) => (
                    <li key={r.key} className="flex flex-wrap items-center gap-2 px-3 py-2">
                      <span className="font-mono text-meta text-accent-text">{r.cve}</span>
                      <span className="min-w-0 flex-1 truncate text-meta text-body">
                        {r.product} — {r.name}
                      </span>
                      <Badge
                        tone={
                          dayDiff(r.due, builtAt) !== null && (dayDiff(r.due, builtAt) ?? 0) > 0 ? 'high' : 'neutral'
                        }
                      >
                        {deadlineText(r.due, builtAt)}
                      </Badge>
                      <button type="button" className={LINK} onClick={() => openCve(r.cve)}>
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
            <Section title="Hunt pack">
              <div className="flex flex-wrap items-center gap-3">
                <label htmlFor="hunt-format" className="font-mono text-meta text-muted">
                  Format
                </label>
                <select
                  id="hunt-format"
                  value={huntFormat}
                  onChange={(e) => setHuntFormat(e.target.value)}
                  className={SELECT}
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
              <p className="mt-2 font-mono text-mini text-muted">
                {visibleHunt.length} of {huntCards.length} hunt resources shown
              </p>
            </Section>
            <ul className="grid gap-3 lg:grid-cols-2">
              {visibleHunt.map((h, i) => (
                <HuntCardView key={`${h.name}-${i}`} h={h} onOpen={(cve) => (cve ? openCve(cve) : setTab(Tab.Queue))} />
              ))}
              {visibleHunt.length === 0 && (
                <li>
                  <Empty>No hunt resources match these filters.</Empty>
                </li>
              )}
            </ul>
          </section>
        )}

        <footer className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line-1 pt-4 font-mono text-mini text-muted">
          <span>
            <ShieldAlert size={11} className="mr-1 inline" aria-hidden="true" /> CyberView replication — community
            research, locally mirrored.
          </span>
          <OutLink
            href="https://xanderhutch.github.io/CyberView/vulnerabilities.html"
            className="inline-flex items-center gap-1 text-accent-text hover:underline"
          >
            <FileText size={10} aria-hidden="true" /> Original CyberView page
          </OutLink>
          <span className="ml-auto">Built {fmtBuilt(builtAt)}</span>
        </footer>
      </div>
    </CyberViewPage>
  );
}
