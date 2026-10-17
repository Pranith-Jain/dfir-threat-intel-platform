import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Activity, ChevronDown, ChevronUp, ExternalLink, Globe, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface GroupRow {
  slug: string;
  name: string;
  victims_7d: number;
  victims_total: number;
  last_seen: string | null;
  origins: string[];
  online: boolean | null;
  mirrors: number;
  up_mirrors: number;
  has_profile: boolean;
  blurb: string;
}

interface GroupsIndex {
  source: string;
  sourceUrl: string;
  syncedAt: string | null;
  builtAt: string;
  counts: { groups: number; sites_up: number; active_week: number; profiled: number; with_activity: number };
  recent: string[];
}

interface VictimSample {
  victim: string;
  discovered: string;
  origin: string;
  source_url: string;
}

interface GroupBody extends GroupRow {
  meta: string | null;
  mirrors_detail: { fqdn: string; title: string | null; available: boolean; updated: string | null }[];
  victims_sample: VictimSample[];
}

type StatusFilter = 'all' | 'online' | 'offline' | 'unknown';
type SortMode = 'recent' | 'name' | 'victims';

function StatusBadge({ online }: { online: boolean | null }) {
  if (online === true) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> LEAK SITE UP
      </span>
    );
  }
  if (online === false) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> OFFLINE
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-300" /> UNPROBED
    </span>
  );
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function GroupCard({ row, recent }: { row: GroupRow; recent: boolean }) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState<GroupBody | null>(null);
  const [loadingBody, setLoadingBody] = useState(false);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !body && (row.has_profile || row.victims_7d > 0)) {
      setLoadingBody(true);
      try {
        const r = await fetch(`/api/v1/ransomware-groups/groups/${encodeURIComponent(row.slug)}`);
        if (r.ok) setBody((await r.json()) as GroupBody);
      } catch {
        /* non-fatal — card still shows the index row */
      } finally {
        setLoadingBody(false);
      }
    }
  };

  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <button type="button" onClick={toggle} className="w-full text-left" aria-expanded={open}>
        <div className="flex items-start justify-between gap-2 mb-1">
          <div className="min-w-0 flex items-center gap-2">
            <h3 className="text-sm font-bold text-heading truncate font-mono">{row.name}</h3>
            {recent && (
              <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-sky-500/10 text-sky-700 dark:text-sky-300 border border-sky-500/30 shrink-0">
                RECENT
              </span>
            )}
            {row.has_profile && (
              <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-violet-500/10 text-violet-700 dark:text-violet-300 border border-violet-500/30 shrink-0">
                PROFILE
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <StatusBadge online={row.online} />
            {open ? (
              <ChevronUp className="w-3.5 h-3.5 text-muted" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-muted" />
            )}
          </div>
        </div>
        <p className="text-xs text-muted leading-snug line-clamp-2">{row.blurb}</p>
        <p className="text-mini text-muted font-mono mt-1.5">
          {row.victims_7d} victims / 7d · {row.victims_total} tracked · last seen {fmtDate(row.last_seen)}
          {row.mirrors > 0 && ` · ${row.up_mirrors}/${row.mirrors} mirrors up`}
        </p>
      </button>
      {open && (
        <div className="mt-3 pt-3 border-t border-line-1">
          {loadingBody && <p className="text-mini font-mono text-muted">loading profile…</p>}
          {body?.meta && <p className="text-xs text-body leading-relaxed mb-2">{body.meta}</p>}
          {body && body.victims_sample.length > 0 && (
            <div className="mb-2">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Recent victims</div>
              <ul className="space-y-1">
                {body.victims_sample.slice(0, 5).map((v) => (
                  <li key={`${v.victim}-${v.discovered}`} className="text-xs font-mono text-body truncate">
                    {v.victim}{' '}
                    <span className="text-muted">
                      · {fmtDate(v.discovered)} · {v.origin}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {body && body.mirrors_detail.length > 0 && (
            <div className="mb-2">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
                Mirrors (.onion — needs Tor)
              </div>
              <ul className="space-y-0.5">
                {body.mirrors_detail.slice(0, 4).map((m) => (
                  <li key={m.fqdn} className="text-xs font-mono text-muted truncate">
                    <span className={m.available ? 'text-emerald-600 dark:text-emerald-400' : ''}>
                      {m.available ? '●' : '○'}
                    </span>{' '}
                    {m.fqdn}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <PostAnalysisButton
            title={`${row.name} ransomware group`}
            description={`${row.name}: ${row.victims_7d} victims in the last 7d, ${row.victims_total} tracked. Leak site ${row.online === true ? 'reachable' : row.online === false ? 'offline' : 'unprobed'}. ${row.blurb}`}
            source="ransomlook.io + ransomware.live"
            compact
          />
        </div>
      )}
    </div>
  );
}

export default function RansomwareGroups(): JSX.Element {
  const [idx, setIdx] = useState<GroupsIndex | null>(null);
  const [rows, setRows] = useState<GroupRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [activeOnly, setActiveOnly] = useState(false);
  const [profileOnly, setProfileOnly] = useState(false);
  const [sort, setSort] = useState<SortMode>('recent');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [iRes, gRes] = await Promise.all([
        fetch('/api/v1/ransomware-groups/'),
        fetch('/api/v1/ransomware-groups/groups?limit=620&sort=recent'),
      ]);
      if (!iRes.ok) throw new Error(`index HTTP ${iRes.status}`);
      if (!gRes.ok) throw new Error(`groups HTTP ${gRes.status}`);
      setIdx((await iRes.json()) as GroupsIndex);
      setRows(((await gRes.json()) as { groups: GroupRow[] }).groups ?? []);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase().trim();
    const weekAgo = Date.now() - 7 * 24 * 3600 * 1000;
    const out = rows.filter((g) => {
      if (status === 'online' && g.online !== true) return false;
      if (status === 'offline' && g.online !== false) return false;
      if (status === 'unknown' && g.online !== null) return false;
      if (activeOnly && (!g.last_seen || Date.parse(g.last_seen) < weekAgo)) return false;
      if (profileOnly && !g.has_profile) return false;
      if (needle && !`${g.slug} ${g.name} ${g.blurb}`.toLowerCase().includes(needle)) return false;
      return true;
    });
    return [...out].sort((a, b) => {
      if (sort === 'name') return a.slug.localeCompare(b.slug);
      if (sort === 'victims') return b.victims_7d - a.victims_7d;
      return String(b.last_seen ?? '').localeCompare(String(a.last_seen ?? ''));
    });
  }, [rows, query, status, activeOnly, profileOnly, sort]);

  const recentSet = useMemo(() => new Set(idx?.recent ?? []), [idx]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<ShieldAlert size={28} />}
      title="Ransomware Groups"
      description={
        <>
          Every tracked ransomware leak site in one directory — status, recent victims, and profiles. Ransomware crews
          publish victims on their own extortion sites before anyone notifies the victim; this mirrors{' '}
          <a
            href="https://www.ransomlook.io/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Ransomlook
          </a>{' '}
          +{' '}
          <a
            href="https://www.ransomware.live/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            ransomware.live
          </a>{' '}
          aggregation. Status comes from clearnet reachability probes — .onion mirrors need Tor to visit.
        </>
      }
      headerExtra={
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }
      loading={loading && !idx}
      error={error}
      onRetry={load}
    >
      {idx && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mb-5">
            {[
              { label: 'Groups tracked', value: idx.counts.groups, cls: 'text-slate-500' },
              { label: 'Sites up now', value: idx.counts.sites_up, cls: 'text-emerald-600 dark:text-emerald-400' },
              { label: 'Active this week', value: idx.counts.active_week, cls: 'text-rose-600 dark:text-rose-400' },
              { label: 'With profiles', value: idx.counts.profiled, cls: 'text-violet-600 dark:text-violet-400' },
              { label: 'With activity', value: idx.counts.with_activity, cls: 'text-sky-600 dark:text-sky-400' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                type="text"
                placeholder="Search groups…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
              />
            </div>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as StatusFilter)}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
            >
              <option value="all">All groups</option>
              <option value="online">Leak site up</option>
              <option value="offline">Offline</option>
              <option value="unknown">Unprobed</option>
            </select>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as SortMode)}
              className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
            >
              <option value="recent">Recently active</option>
              <option value="victims">Most victims (7d)</option>
              <option value="name">A–Z</option>
            </select>
            <button
              onClick={() => setActiveOnly((v) => !v)}
              className={`px-3 py-2 rounded-xl text-sm font-mono border flex items-center gap-1.5 transition ${
                activeOnly
                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  : 'border-line-1 text-slate-500 hover:border-rose-500/30'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Active week
            </button>
            <button
              onClick={() => setProfileOnly((v) => !v)}
              className={`px-3 py-2 rounded-xl text-sm font-mono border transition ${
                profileOnly
                  ? 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300'
                  : 'border-line-1 text-slate-500 hover:border-violet-500/30'
              }`}
            >
              Profiles
            </button>
          </div>

          <div className="flex items-center justify-between mb-3 text-xs text-muted font-mono">
            <span>
              Showing {filtered.length} of {rows.length} groups
            </span>
            {idx.syncedAt && <span>synced {fmtDate(idx.syncedAt)}</span>}
          </div>

          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted font-mono text-sm">No groups match your filters</div>
          ) : (
            <>
              <AiSummaryCard
                surface="Ransomware Groups Directory"
                items={filtered.slice(0, 30).map((g) => ({
                  title: g.name,
                  body: `${g.victims_7d} victims/7d · leak site ${g.online === true ? 'up' : g.online === false ? 'offline' : 'unprobed'} · ${g.blurb}`,
                  source: 'ransomlook.io + ransomware.live',
                }))}
                requireAdmin={false}
              />
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filtered.map((g) => (
                  <GroupCard key={g.slug} row={g} recent={recentSet.has(g.slug)} />
                ))}
              </div>
            </>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono flex items-center gap-2">
            <Globe className="w-3.5 h-3.5" />
            <span>
              Source: Ransomlook.io + ransomware.live ·{' '}
              <a
                href={sanitizeUrl(idx.sourceUrl) ?? undefined}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
              >
                upstream <ExternalLink className="w-2.5 h-2.5" />
              </a>{' '}
              · offline ≠ gone — crews go quiet and return under the same name
            </span>
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
