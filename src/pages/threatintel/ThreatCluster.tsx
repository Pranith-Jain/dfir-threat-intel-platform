import { useEffect, useMemo, useRef, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { fetchJsonCached } from '../../lib/api-client';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';
import {
  Activity,
  AlertTriangle,
  Bug,
  Check,
  Copy,
  ExternalLink,
  Flame,
  Globe,
  Link as LinkIcon,
  Search,
  Shield,
  Skull,
} from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Types (mirror the API JSON)                                        */
/* ------------------------------------------------------------------ */

type TabId = 'clusters' | 'vulnerabilities' | 'exploits' | 'victims' | 'iocs' | 'misp';

interface TcIndex {
  source: string;
  url: string;
  description: string;
  syncedAt: string;
  lastBuildDates: Record<string, string | null>;
  counts: {
    clusters: number;
    vulnerabilities: number;
    exploits: number;
    victims: number;
    iocs: number;
    mispEvents: number;
  };
  feeds: { id: string; title: string; url: string; window: string }[];
}

interface TcCluster {
  slug: string;
  title: string;
  pubDate: string | null;
  sourceCount: number | null;
  sizeBytes: number;
}
interface TcClusterDetail extends TcCluster {
  link: string;
  description: string;
}

interface TcVuln {
  cveId: string;
  title: string;
  pubDate: string | null;
  sizeBytes: number;
}
interface TcVulnDetail extends TcVuln {
  link: string;
  description: string;
}

interface TcExploit {
  cveId: string;
  title: string;
  pubDate: string | null;
  severity: string | null;
  inKev: boolean;
  sizeBytes: number;
}
interface TcExploitDetail extends TcExploit {
  link: string;
  description: string;
}

interface TcVictim {
  id: string;
  victim: string;
  group: string | null;
  sector: string | null;
  country: string | null;
  pubDate: string | null;
  sizeBytes: number;
}
interface TcVictimDetail extends TcVictim {
  link: string;
  description: string;
}

interface TcIoc {
  type: string;
  value: string;
  confidence: string;
  reason: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source_count: number;
  sources: { source: string; url: string; pub_date: string | null }[];
}

interface TcMispEvent {
  uuid: string;
  info: string | null;
  date: string | null;
  threat_level_id: string | null;
  tags: string[];
  orgc: string | null;
}

/* ------------------------------------------------------------------ */
/*  Shared bits                                                        */
/* ------------------------------------------------------------------ */

const COUNT_KEY: Record<TabId, keyof TcIndex['counts']> = {
  clusters: 'clusters',
  vulnerabilities: 'vulnerabilities',
  exploits: 'exploits',
  victims: 'victims',
  iocs: 'iocs',
  misp: 'mispEvents',
};

const TABS: { id: TabId; label: string; icon: typeof Flame }[] = [
  { id: 'clusters', label: 'Trending Clusters', icon: Flame },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
  { id: 'exploits', label: 'Exploits', icon: Bug },
  { id: 'victims', label: 'Dark Web Victims', icon: Skull },
  { id: 'iocs', label: 'IOC Blocklist', icon: Shield },
  { id: 'misp', label: 'MISP Events', icon: Activity },
];

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  MEDIUM: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  LOW: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
};

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function FmtDate({ iso }: { iso: string | null | undefined }) {
  return <span className="opacity-70">{fmtDate(iso)}</span>;
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border ${cls}`}>
      {children}
    </span>
  );
}

function SearchBox({
  query,
  setQuery,
  placeholder,
}: {
  query: string;
  setQuery: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="relative flex-1">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
      <input
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={placeholder}
        className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Per-tab card components                                            */
/* ------------------------------------------------------------------ */

function ClusterCard({ item }: { item: TcCluster }) {
  return (
    <details className="group rounded-xl border border-line-1 bg-surface-100/50 p-4 open:border-rose-500/30 [content-visibility:auto] [contain-intrinsic-size:auto_180px]">
      <summary className="cursor-pointer list-none">
        <div className="flex items-start justify-between gap-2 mb-1.5">
          <h3 className="text-sm font-bold text-heading leading-snug">{item.title}</h3>
          {item.sourceCount != null && (
            <Badge cls="border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300 shrink-0">
              <LinkIcon className="w-2.5 h-2.5" />
              {item.sourceCount} sources
            </Badge>
          )}
        </div>
        <p className="text-mini text-muted mt-1 font-mono">
          <FmtDate iso={item.pubDate} />
        </p>
      </summary>
      <ClusterDetailBody slug={item.slug} />
    </details>
  );
}

function ExploitBadges({ severity, inKev }: { severity: string | null; inKev: boolean }) {
  return (
    <>
      {inKev && <Badge cls="border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 shrink-0">KEV</Badge>}
      {severity && (
        <Badge cls={SEVERITY_STYLES[severity] ?? 'border-slate-300 dark:border-line-1 text-slate-500 shrink-0'}>
          {severity}
        </Badge>
      )}
    </>
  );
}

const IOC_TYPE_STYLES: Record<string, string> = {
  domain: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  ipv4: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  ipv6: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

function IocCard({ ioc, copied, onCopy }: { ioc: TcIoc; copied: boolean; onCopy: () => void }) {
  const typeMeta = IOC_TYPE_STYLES[ioc.type] ?? 'border-slate-300 dark:border-line-1 text-slate-500';
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <Badge cls={typeMeta}>{ioc.type}</Badge>
          <h3 className="font-mono text-sm font-semibold text-heading truncate">{ioc.value}</h3>
        </div>
        <button
          onClick={onCopy}
          className="inline-flex items-center gap-1 px-2 py-1 rounded text-micro font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors shrink-0"
          title="Copy value"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
        </button>
      </div>
      {ioc.reason && <p className="text-xs text-body mt-0.5 leading-relaxed">{ioc.reason}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-2 text-mini text-muted font-mono">
        <span>{ioc.source_count} sources</span>
        {ioc.first_seen && <FmtDate iso={ioc.first_seen} />}
        {ioc.sources.slice(0, 3).map((s) => (
          <a
            key={s.url || s.source}
            href={sanitizeUrl(s.url) ?? undefined}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
          >
            {s.source}
            <ExternalLink className="w-2.5 h-2.5" />
          </a>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Page                                                               */
/* ------------------------------------------------------------------ */

export default function ThreatCluster(): JSX.Element {
  const [tab, setTab] = useState<TabId>('clusters');
  const [idx, setIdx] = useState<TcIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Per-tab list state
  const [clusters, setClusters] = useState<TcCluster[]>([]);
  const [vulns, setVulns] = useState<TcVuln[]>([]);
  const [exploits, setExploits] = useState<TcExploit[]>([]);
  const [victims, setVictims] = useState<TcVictim[]>([]);
  const [iocs, setIocs] = useState<TcIoc[]>([]);
  const [misp, setMisp] = useState<TcMispEvent[]>([]);

  // Filters
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setIdx(await fetchJsonCached<TcIndex>('/api/v1/threat-intel/threatcluster', 60_000));
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }

  const loadedTabs = useRef<Set<TabId>>(new Set());

  useEffect(() => {
    if (loadedTabs.current.has(tab)) return;
    loadedTabs.current.add(tab);
    const base = '/api/v1/threat-intel/threatcluster';
    const endpoint =
      tab === 'iocs'
        ? `${base}/iocs?limit=1000`
        : tab === 'misp'
          ? `${base}/misp?limit=500`
          : `${base}/${tab}?limit=500`;
    (async () => {
      try {
        const json = await fetchJsonCached<Record<string, unknown>>(endpoint, 60_000);
        if (tab === 'clusters') setClusters((json.clusters as TcCluster[]) ?? []);
        else if (tab === 'vulnerabilities') setVulns((json.vulnerabilities as TcVuln[]) ?? []);
        else if (tab === 'exploits') setExploits((json.exploits as TcExploit[]) ?? []);
        else if (tab === 'victims') setVictims((json.victims as TcVictim[]) ?? []);
        else if (tab === 'iocs') setIocs((json.iocs as TcIoc[]) ?? []);
        else if (tab === 'misp') setMisp((json.events as TcMispEvent[]) ?? []);
      } catch {
        // Allow a retry on the next tab visit — memoizing a FAILED load made
        // one transient 500 show "0 of 0" for the whole session.
        loadedTabs.current.delete(tab);
      }
    })();
  }, [tab]);

  const filteredClusters = useMemo(() => {
    const n = query.toLowerCase().trim();
    if (!n) return clusters;
    return clusters.filter((c) => `${c.title} ${c.slug}`.toLowerCase().includes(n));
  }, [clusters, query]);

  const filteredVulns = useMemo(() => {
    const n = query.toLowerCase().trim();
    if (!n) return vulns;
    return vulns.filter((v) => `${v.cveId} ${v.title}`.toLowerCase().includes(n));
  }, [vulns, query]);

  const filteredExploits = useMemo(() => {
    const n = query.toLowerCase().trim();
    return exploits.filter((e) => {
      if (sevFilter !== 'all' && (e.severity ?? '').toUpperCase() !== sevFilter) return false;
      if (kevOnly && !e.inKev) return false;
      if (n && !`${e.cveId} ${e.title}`.toLowerCase().includes(n)) return false;
      return true;
    });
  }, [exploits, query, sevFilter, kevOnly]);

  const filteredVictims = useMemo(() => {
    const n = query.toLowerCase().trim();
    if (!n) return victims;
    return victims.filter((v) =>
      `${v.victim} ${v.group ?? ''} ${v.sector ?? ''} ${v.country ?? ''}`.toLowerCase().includes(n)
    );
  }, [victims, query]);

  const filteredIocs = useMemo(() => {
    const n = query.toLowerCase().trim();
    return iocs.filter((i) => {
      if (typeFilter !== 'all' && i.type !== typeFilter) return false;
      if (n && !`${i.value} ${i.reason ?? ''}`.toLowerCase().includes(n)) return false;
      return true;
    });
  }, [iocs, query, typeFilter]);

  const filteredMisp = useMemo(() => {
    const n = query.toLowerCase().trim();
    if (!n) return misp;
    return misp.filter((e) => `${e.info ?? ''} ${e.tags.join(' ')}`.toLowerCase().includes(n));
  }, [misp, query]);

  async function copyAllIocs() {
    const text = iocs.map((i) => i.value).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopiedValue('__all__');
      setTimeout(() => setCopiedValue(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  const victimsGroups = useMemo(() => {
    const m = new Map<string, number>();
    for (const v of victims) if (v.group) m.set(v.group, (m.get(v.group) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  }, [victims]);

  const iocTypes = useMemo(() => {
    const m = new Map<string, number>();
    for (const i of iocs) m.set(i.type, (m.get(i.type) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [iocs]);

  const setQuerySafe = (v: string) => setQuery(v);

  const summaryItems = useMemo(() => {
    const source = 'threatcluster.io';
    const tabLabel = TABS.find((t) => t.id === tab)?.label ?? tab;
    const items =
      tab === 'clusters'
        ? filteredClusters.slice(0, 30).map((c) => ({ title: c.title, body: `${c.slug}`, source }))
        : tab === 'vulnerabilities'
          ? filteredVulns.slice(0, 30).map((v) => ({ title: `${v.cveId} — ${v.title}`, body: `${v.cveId}`, source }))
          : tab === 'exploits'
            ? filteredExploits.slice(0, 30).map((e) => ({
                title: `${e.cveId} — ${e.title}`,
                body: `severity: ${e.severity ?? 'unknown'}${e.inKev ? ' · in CISA KEV' : ''}`,
                source,
              }))
            : tab === 'victims'
              ? filteredVictims.slice(0, 30).map((v) => ({
                  title: v.victim,
                  body: `group: ${v.group ?? 'unknown'} · sector: ${v.sector ?? 'unknown'} · country: ${v.country ?? 'unknown'}`,
                  source,
                }))
              : tab === 'iocs'
                ? filteredIocs.slice(0, 30).map((i) => ({
                    title: i.value,
                    body: `${i.type} · ${i.confidence} · ${i.reason ?? 'no reason'}`,
                    source: i.sources.map((s) => s.source).join(', ') || source,
                  }))
                : tab === 'misp'
                  ? filteredMisp.slice(0, 30).map((e) => ({
                      title: e.info ?? e.uuid,
                      body: `L${e.threat_level_id ?? '?'} · ${e.tags.join(', ') || 'no tags'}`,
                      source: e.orgc ?? 'MISP',
                    }))
                  : [];
    return { surface: `ThreatCluster · ${tabLabel}`, items };
  }, [tab, filteredClusters, filteredVulns, filteredExploits, filteredVictims, filteredIocs, filteredMisp]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<Globe size={28} />}
      title="ThreatCluster Feeds"
      description={
        <>
          Replicated public feeds from{' '}
          <a
            href="https://threatcluster.io/feeds"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            threatcluster.io
          </a>
          — trending threat clusters, CVEs, weaponised exploits, dark-web victims, and a high-confidence IOC blocklist.
          Upstream feeds refresh hourly.
        </>
      }
      loading={loading && !idx}
      error={error}
      onRetry={load}
    >
      {idx && (
        <>
          {/* AI summary — above all UI elements so it's the first card */}
          {summaryItems.items.length > 0 && (
            <AiSummaryCard
              surface={summaryItems.surface}
              items={summaryItems.items}
              requireAdmin={false}
              className="mb-5"
            />
          )}

          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-5">
            {[
              { label: 'Clusters', value: idx.counts.clusters, cls: 'text-rose-600 dark:text-rose-400' },
              {
                label: 'Vulnerabilities',
                value: idx.counts.vulnerabilities,
                cls: 'text-amber-600 dark:text-amber-400',
              },
              { label: 'Exploits', value: idx.counts.exploits, cls: 'text-orange-600 dark:text-orange-400' },
              { label: 'Victims', value: idx.counts.victims, cls: 'text-violet-600 dark:text-violet-400' },
              { label: 'IOCs', value: idx.counts.iocs, cls: 'text-emerald-600 dark:text-emerald-400' },
              { label: 'MISP events', value: idx.counts.mispEvents, cls: 'text-slate-500' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>

          {/* Tab nav */}
          <div className="flex flex-wrap gap-1.5 mb-4 border-b border-line-1 pb-3">
            {TABS.map((t) => {
              const Icon = t.icon;
              const active = tab === t.id;
              const count = idx.counts[COUNT_KEY[t.id]];
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition ${
                    active
                      ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                      : 'border-line-1 text-slate-500 hover:border-rose-500/30'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {t.label}
                  <span className="opacity-60">{count}</span>
                </button>
              );
            })}
          </div>

          {/* Per-tab body */}
          {tab === 'clusters' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search trending clusters…" />
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredClusters.length} of {clusters.length} clusters · top 50 trending from the last 7 days
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredClusters.map((c) => (
                  <ClusterCard key={c.slug} item={c} />
                ))}
              </div>
            </>
          )}

          {tab === 'vulnerabilities' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search CVEs (id, product, vendor)…" />
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredVulns.length} of {vulns.length} CVEs · last 7 days, enriched by ThreatCluster
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredVulns.map((v) => {
                  return (
                    <details
                      key={v.cveId}
                      className="group rounded-xl border border-line-1 bg-surface-100/50 p-4 open:border-rose-500/30 [content-visibility:auto] [contain-intrinsic-size:auto_180px]"
                    >
                      <summary className="cursor-pointer list-none">
                        <div className="flex items-start justify-between gap-2 mb-1.5">
                          <div>
                            <h3 className="font-mono text-sm font-bold text-heading">{v.cveId}</h3>
                            <p className="text-mini text-muted mt-0.5 font-mono">
                              <FmtDate iso={v.pubDate} />
                            </p>
                          </div>
                          <span className="font-mono text-micro text-muted group-open:text-rose-500">expand</span>
                        </div>
                      </summary>
                      <VulnDetailBody cveId={v.cveId} />
                    </details>
                  );
                })}
              </div>
            </>
          )}

          {tab === 'exploits' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search exploits (CVE id, product)…" />
                <select
                  value={sevFilter}
                  onChange={(e) => setSevFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
                <button
                  onClick={() => setKevOnly((v) => !v)}
                  className={`px-3 py-2 rounded-xl text-sm font-mono border transition ${
                    kevOnly
                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                      : 'border-line-1 text-slate-500 hover:border-rose-500/30'
                  }`}
                >
                  KEV only
                </button>
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredExploits.length} of {exploits.length} exploits · public PoCs from the last 30 days,
                sorted by exploit availability then CVSS
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredExploits.map((e) => (
                  <details
                    key={e.cveId}
                    className="group rounded-xl border border-line-1 bg-surface-100/50 p-4 open:border-rose-500/30 [content-visibility:auto] [contain-intrinsic-size:auto_180px]"
                  >
                    <summary className="cursor-pointer list-none">
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <div className="min-w-0">
                          <h3 className="font-mono text-sm font-bold text-heading truncate">{e.cveId}</h3>
                          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                            <ExploitBadges severity={e.severity} inKev={e.inKev} />
                            <span className="text-mini text-muted font-mono">
                              <FmtDate iso={e.pubDate} />
                            </span>
                          </div>
                        </div>
                        <span className="font-mono text-micro text-muted group-open:text-rose-500 shrink-0">
                          expand
                        </span>
                      </div>
                    </summary>
                    <ExploitDetailBody cveId={e.cveId} />
                  </details>
                ))}
              </div>
            </>
          )}

          {tab === 'victims' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search victims, groups, sectors…" />
              </div>
              {/* Group pills */}
              <div className="flex flex-wrap items-center gap-1.5 mb-3">
                <span className="text-xs text-muted mr-1 font-mono">groups:</span>
                {victimsGroups.map(([g, n]) => (
                  <button
                    key={g}
                    onClick={() => setQuery(query === g ? '' : g)}
                    className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                      query === g
                        ? 'border-violet-500/60 bg-violet-500/10 text-violet-700 dark:text-violet-300'
                        : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-violet-500/30'
                    }`}
                  >
                    {g} <span className="opacity-60">{n}</span>
                  </button>
                ))}
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredVictims.length} of {victims.length} victims · newly observed on ransomware leak sites,
                last 14 days
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredVictims.map((v) => (
                  <details
                    key={v.id}
                    className="group rounded-xl border border-line-1 bg-surface-100/50 p-4 open:border-rose-500/30"
                  >
                    <summary className="cursor-pointer list-none">
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <div className="min-w-0">
                          <h3 className="text-sm font-bold text-heading leading-snug">{v.victim}</h3>
                          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                            <Badge cls="border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300">
                              {v.group ?? 'unknown group'}
                            </Badge>
                            {v.sector && v.sector !== 'Not Found' && (
                              <span className="text-mini text-muted font-mono">{v.sector}</span>
                            )}
                            {v.country && <span className="text-mini text-muted font-mono">{v.country}</span>}
                          </div>
                        </div>
                        <span className="font-mono text-micro text-muted group-open:text-rose-500 shrink-0">
                          expand
                        </span>
                      </div>
                      <p className="text-mini text-muted mt-1 font-mono">
                        <FmtDate iso={v.pubDate} />
                      </p>
                    </summary>
                    <VictimDetailBody id={v.id} />
                  </details>
                ))}
              </div>
            </>
          )}

          {tab === 'iocs' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search value, reason, source…" />
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All types</option>
                  {iocTypes.map(([t, n]) => (
                    <option key={t} value={t}>
                      {t} ({n})
                    </option>
                  ))}
                </select>
                <button
                  onClick={copyAllIocs}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                >
                  {copiedValue === '__all__' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  {copiedValue === '__all__' ? 'Copied!' : 'Copy all'}
                </button>
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredIocs.length} of {iocs.length} high-confidence IOCs · last 30 days · paste into pfSense
                / Pi-hole / firewall blocklists
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {filteredIocs.map((i) => (
                  <IocCard
                    key={i.value}
                    ioc={i}
                    copied={copiedValue === i.value}
                    onCopy={async () => {
                      try {
                        await navigator.clipboard.writeText(i.value);
                        setCopiedValue(i.value);
                        setTimeout(() => setCopiedValue(null), 1500);
                      } catch {
                        /* clipboard unavailable */
                      }
                    }}
                  />
                ))}
              </div>
            </>
          )}

          {tab === 'misp' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuerySafe} placeholder="Search MISP events by title or tag…" />
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredMisp.length} of {misp.length} MISP events · slim manifest pass-through
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {filteredMisp.map((e) => (
                  <div key={e.uuid} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <h3 className="text-sm font-bold text-heading leading-snug">{e.info ?? e.uuid}</h3>
                      <Badge cls="border-slate-300 dark:border-line-1 text-slate-500 shrink-0">
                        L{e.threat_level_id ?? '?'}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 mt-2">
                      {e.date && <span className="text-mini text-muted font-mono">{e.date}</span>}
                      {e.tags.slice(0, 5).map((t) => (
                        <span
                          key={t}
                          className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: threatcluster.io · feeds refresh hourly upstream, replicated here on the threat-intel sync cadence
            {idx.syncedAt && <> · synced {fmtDate(idx.syncedAt)}</>}
          </div>
        </>
      )}
    </DataPageLayout>
  );
}

/* ------------------------------------------------------------------ */
/*  On-demand detail bodies                                            */
/* ------------------------------------------------------------------ */

function useDetail<T>(path: string) {
  const [body, setBody] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchJsonCached<T>(path, 60_000)
      .then((j) => {
        if (!cancelled) setBody(j);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [path]);
  return { body, loading };
}

function DetailLink({ href }: { href: string | null | undefined }) {
  const safe = sanitizeUrl(href);
  if (!safe) return null;
  return (
    <a
      href={safe}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="inline-flex items-center gap-1 mt-2 text-xs text-rose-600 dark:text-rose-400 hover:underline"
    >
      View on ThreatCluster <ExternalLink className="w-3 h-3" />
    </a>
  );
}

function ClusterDetailBody({ slug }: { slug: string }) {
  const { body, loading } = useDetail<TcClusterDetail>(`/api/v1/threat-intel/threatcluster/clusters/${slug}`);
  if (loading || !body) return <p className="mt-2 text-mini text-muted font-mono">{loading ? 'loading…' : '—'}</p>;
  return (
    <>
      <p className="mt-2 text-xs text-body leading-relaxed whitespace-pre-line">{body.description}</p>
      <PostAnalysisButton title={body.title} description={body.description} source="threatcluster.io" compact />
      <DetailLink href={body.link} />
    </>
  );
}

function VulnDetailBody({ cveId }: { cveId: string }) {
  const { body, loading } = useDetail<TcVulnDetail>(`/api/v1/threat-intel/threatcluster/vulnerabilities/${cveId}`);
  if (loading || !body) return <p className="mt-2 text-mini text-muted font-mono">{loading ? 'loading…' : '—'}</p>;
  return (
    <>
      <p className="mt-2 text-xs text-body leading-relaxed">{body.description}</p>
      <PostAnalysisButton
        title={`${body.cveId} — ${body.title}`}
        description={body.description}
        source="threatcluster.io"
        compact
      />
      <DetailLink href={body.link} />
    </>
  );
}

function ExploitDetailBody({ cveId }: { cveId: string }) {
  const { body, loading } = useDetail<TcExploitDetail>(`/api/v1/threat-intel/threatcluster/exploits/${cveId}`);
  if (loading || !body) return <p className="mt-2 text-mini text-muted font-mono">{loading ? 'loading…' : '—'}</p>;
  return (
    <>
      <p className="mt-2 text-xs text-body leading-relaxed">{body.description}</p>
      <PostAnalysisButton
        title={`${body.cveId} — ${body.title}`}
        description={body.description}
        source="threatcluster.io"
        compact
      />
      <DetailLink href={body.link} />
    </>
  );
}

function VictimDetailBody({ id }: { id: string }) {
  const { body, loading } = useDetail<TcVictimDetail>(`/api/v1/threat-intel/threatcluster/victims/${id}`);
  if (loading || !body) return <p className="mt-2 text-mini text-muted font-mono">{loading ? 'loading…' : '—'}</p>;
  return (
    <>
      <p className="mt-2 text-xs text-body leading-relaxed">{body.description}</p>
      <PostAnalysisButton title={body.victim} description={body.description} source="threatcluster.io" compact />
      <DetailLink href={body.link} />
    </>
  );
}
