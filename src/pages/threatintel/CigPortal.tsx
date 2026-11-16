import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, FileClock, GitFork, History, Skull } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

/**
 * Mirror of the MBSD CIG Ransomware Information Portal
 * (mbsd.jp/cig-ransomware-portal): the Japanese ransomware-group knowledge
 * base with per-group activity flags, bilingual group profiles, group
 * relationship notes, affiliate chains and a dataset changelog. Data files
 * are synced verbatim daily (scripts/sync-cig-portal.mjs); the large
 * bilingual profile corpus lazy-loads only when a group row expands.
 */

interface CigGroup {
  name: string;
  flags: {
    withintwoweeks: boolean;
    leaksite: boolean;
    hackerforum: boolean;
    telegram: boolean;
    noencryption: boolean;
    shadowsyndigate: boolean;
    precursor: boolean;
    hacktivist: boolean;
    sameaffiliate: boolean;
    isOther: boolean;
  };
  firstappearyear: string | null;
  rebrands: string[];
  relationships: string[];
  relationship_count: number;
}

interface CigIndex {
  generated_at: string;
  upstream: {
    portal: string;
    publisher: string;
    dataset_version: string | null;
    dataset_updated: string | null;
    notes_db: string | null;
  };
  sync_problems: string[];
  stats: Record<string, number>;
  first_appearance_years: Array<{ year: string; count: number }>;
  groups: CigGroup[];
  chains: string[][];
  update_history: Array<{
    date: string;
    version: string;
    events: Array<{ type: string; items: Array<{ name: string }> }>;
  }>;
}

type CigProfile = {
  profile: { ja: string; en: string } | null;
  relationships: Array<{ group: string; ja: string; en: string }>;
  rebrandlist: string[];
};

const FLAG_LABELS: Record<string, string> = {
  leaksite: 'leak site',
  hackerforum: 'forum',
  telegram: 'telegram',
  noencryption: 'no encryption',
  shadowsyndigate: 'ShadowSyndicate',
  precursor: 'precursor',
  hacktivist: 'hacktivist',
  sameaffiliate: 'same affiliate',
  isOther: 'other',
};

export default function CigPortal(): JSX.Element {
  const [data, setData] = useState<CigIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeOnly, setActiveOnly] = useState(true);
  const [flagFilter, setFlagFilter] = useState<string>('all');
  const [query, setQuery] = useState('');
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<Record<string, CigProfile> | null>(null);
  const [lang, setLang] = useState<'en' | 'ja'>('en');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/data/cig-portal/index.json', { signal: AbortSignal.timeout(15000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as CigIndex;
        if (!cancelled) setData(json);
      } catch (e) {
        if (!cancelled) setError(errMessage(e, 'Failed to load CIG portal data'));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // The bilingual profile corpus (group boxcomment + relationship notes) is
  // large (1.5 MB); fetch it once, on first expansion, not on page load.
  useEffect(() => {
    if (!openGroup || profiles || error) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/data/cig-portal/profiles.json', { signal: AbortSignal.timeout(20000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as Record<string, CigProfile>;
        if (!cancelled) setProfiles(json);
      } catch (e) {
        if (!cancelled) setError(errMessage(e, 'Failed to load group profiles'));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [openGroup, profiles, error]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.groups || []).filter((g) => {
      if (activeOnly && !g.flags.withintwoweeks) return false;
      if (flagFilter !== 'all') {
        if (flagFilter === 'all-active') return true;
        if (!(g.flags as unknown as Record<string, boolean>)[flagFilter]) return false;
      }
      if (!q) return true;
      return (
        g.name.toLowerCase().includes(q) ||
        g.rebrands.some((r) => r.toLowerCase().includes(q)) ||
        g.relationships.some((r) => r.toLowerCase().includes(q))
      );
    });
  }, [data, activeOnly, flagFilter, query]);

  const statTiles = useMemo(() => {
    const s = data?.stats || {};
    return [
      { label: 'GROUPS TRACKED', value: s.groups ?? 0 },
      { label: 'ACTIVE (2 WEEKS)', value: s.active_within_2w ?? 0 },
      { label: 'LEAK SITES', value: s.leaksite ?? 0 },
      { label: 'NO ENCRYPTION', value: s.noencryption ?? 0 },
      { label: 'RELATIONSHIPS', value: s.with_relationships ?? 0 },
      { label: 'AFFILIATE CHAINS', value: data?.chains.length ?? 0 },
    ];
  }, [data]);

  return (
    <DataPageLayout
      backTo="/threatintel/ransomware-hub"
      icon={<Skull size={28} />}
      title="CIG Ransomware Portal"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-300 text-xs font-mono">
            {data?.stats.groups ?? '...'} ransomware groups
          </span>
          <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
            Mirror of MBSD CIG portal (Japan)
          </span>
          {data?.upstream.dataset_updated && (
            <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
              Dataset v{data.upstream.dataset_version} - {data.upstream.dataset_updated}
            </span>
          )}
        </span>
      }
      maxWidthClass="max-w-7xl"
      error={error}
      loading={!data && !error}
    >
      <div className="space-y-5">
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          {statTiles.map((t) => (
            <div key={t.label} className="rounded-xl bg-surface-100 border border-line-1 p-4">
              <div className="text-[11px] font-mono tracking-widest text-muted mb-1">{t.label}</div>
              <div className="text-2xl font-bold text-heading">{t.value}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-56">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search group names, rebrands, linked groups..."
              className="w-full px-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-sm font-mono text-heading placeholder:text-muted/60"
            />
          </div>
          <label className="inline-flex items-center gap-2 text-xs font-mono text-muted cursor-pointer">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(e) => setActiveOnly(e.target.checked)}
              className="accent-rose-500"
            />
            Active in last 2 weeks
          </label>
          <select
            value={flagFilter}
            onChange={(e) => setFlagFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-heading"
          >
            <option value="all">All activity types</option>
            {Object.entries(FLAG_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label} ({data?.stats[key] ?? 0})
              </option>
            ))}
          </select>
        </div>

        <div className="text-xs font-mono text-muted">{filtered.length} groups</div>

        {/* Group browser */}
        <div className="space-y-1.5">
          {filtered.map((g) => {
            const isOpen = openGroup === g.name;
            const profile = profiles?.[g.name];
            return (
              <div key={g.name} className="rounded-lg bg-surface-100 border border-line-1 overflow-hidden">
                <button
                  onClick={() => setOpenGroup(isOpen ? null : g.name)}
                  className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-surface-200/60"
                >
                  {isOpen ? (
                    <ChevronDown size={14} className="text-muted shrink-0" />
                  ) : (
                    <ChevronRight size={14} className="text-muted shrink-0" />
                  )}
                  <span className="font-mono text-sm text-heading font-bold truncate">{g.name}</span>
                  {g.flags.withintwoweeks && (
                    <span className="px-1.5 py-0.5 rounded bg-rose-500 text-on-fill text-[9px] font-mono font-bold shrink-0">
                      ACTIVE 2W
                    </span>
                  )}
                  {g.firstappearyear && (
                    <span className="text-[10px] font-mono text-muted shrink-0">{g.firstappearyear}</span>
                  )}
                  <span className="ml-auto flex flex-wrap gap-1 justify-end">
                    {g.rebrands.length > 0 && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300 text-[9px] font-mono">
                        {g.rebrands.length} rebrand{g.rebrands.length === 1 ? '' : 's'}
                      </span>
                    )}
                    {g.relationship_count > 0 && (
                      <span className="px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-700 dark:text-violet-300 text-[9px] font-mono">
                        {g.relationship_count} link{g.relationship_count === 1 ? '' : 's'}
                      </span>
                    )}
                    {g.flags.leaksite && (
                      <span className="px-1.5 py-0.5 rounded bg-surface-300 border border-line-1 text-muted text-[9px] font-mono">
                        leak site
                      </span>
                    )}
                    {g.flags.telegram && (
                      <span className="px-1.5 py-0.5 rounded bg-sky-500/10 border border-sky-500/20 text-sky-700 dark:text-sky-300 text-[9px] font-mono">
                        telegram
                      </span>
                    )}
                    {g.flags.hacktivist && (
                      <span className="px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-700 dark:text-orange-300 text-[9px] font-mono">
                        hacktivist
                      </span>
                    )}
                    {g.flags.noencryption && (
                      <span className="px-1.5 py-0.5 rounded bg-surface-300 border border-line-1 text-muted text-[9px] font-mono">
                        no encryption
                      </span>
                    )}
                  </span>
                </button>

                {isOpen && (
                  <div className="px-4 pb-4 pt-1 border-t border-line-1 space-y-3">
                    {!profiles && <p className="text-xs font-mono text-muted">Loading bilingual profile corpus...</p>}
                    {profile && (
                      <>
                        {profile.profile && (
                          <div>
                            <div className="flex items-center justify-between mb-1.5">
                              <span className="font-mono text-[10px] tracking-widest text-muted uppercase">
                                Group profile
                              </span>
                              <div className="flex gap-1">
                                {(['en', 'ja'] as const).map((l) => (
                                  <button
                                    key={l}
                                    onClick={() => setLang(l)}
                                    className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                                      lang === l
                                        ? 'bg-sky-500/20 text-sky-700 dark:text-sky-300 font-bold'
                                        : 'text-muted hover:text-heading'
                                    }`}
                                  >
                                    {l}
                                  </button>
                                ))}
                              </div>
                            </div>
                            <p className="text-xs text-body leading-relaxed whitespace-pre-line bg-surface-200/50 rounded-lg border border-line-1 p-3">
                              {lang === 'en'
                                ? profile.profile.en || profile.profile.ja
                                : profile.profile.ja || profile.profile.en}
                            </p>
                          </div>
                        )}
                        {profile.relationships.length > 0 && (
                          <div>
                            <div className="font-mono text-[10px] tracking-widest text-muted uppercase mb-1.5 flex items-center gap-1">
                              <GitFork size={10} /> Reported relationships
                            </div>
                            <div className="space-y-1.5">
                              {profile.relationships.map((r) => (
                                <div key={r.group} className="rounded-lg bg-surface-200/50 border border-line-1 p-2.5">
                                  <div className="font-mono text-xs font-bold text-heading">{r.group}</div>
                                  <p className="text-[11px] text-muted mt-1 leading-relaxed">
                                    {lang === 'en' ? r.en || r.ja : r.ja || r.en}
                                  </p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {profile.rebrandlist.length > 0 && (
                          <div className="flex flex-wrap gap-1.5">
                            {profile.rebrandlist.map((r) => (
                              <span
                                key={r}
                                className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300 text-[10px] font-mono"
                              >
                                rebrand: {r}
                              </span>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Affiliate chains */}
        {data && data.chains.length > 0 && (
          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-3 flex items-center gap-1.5">
              <GitFork size={12} /> AFFILIATE CHAINS (shared-operator lineages)
            </div>
            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {data.chains.slice(0, 20).map((chain, i) => (
                <div key={i} className="flex flex-wrap items-center gap-1 text-[11px] font-mono">
                  {chain.map((name, j) => (
                    <span key={`${name}-${j}`} className="flex items-center gap-1">
                      {j > 0 && <span className="text-muted/50">-</span>}
                      <span className="px-1.5 py-0.5 rounded bg-surface-300 border border-line-1 text-muted">
                        {name}
                      </span>
                    </span>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Dataset changelog */}
        {data && data.update_history.length > 0 && (
          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-3 flex items-center gap-1.5">
              <History size={12} /> DATASET CHANGELOG (latest 8)
            </div>
            <div className="space-y-2">
              {data.update_history.slice(0, 8).map((h) => (
                <div key={h.version} className="flex flex-wrap items-start gap-2 text-xs">
                  <span className="font-mono text-muted w-24 shrink-0">{h.date}</span>
                  <span className="font-mono text-[10px] text-muted w-20 shrink-0">v{h.version}</span>
                  <span className="flex flex-wrap gap-1">
                    {h.events.map((ev) =>
                      ev.items.slice(0, 4).map((it) => (
                        <span
                          key={`${ev.type}-${it.name}`}
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            ev.type === 'added'
                              ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300'
                              : 'bg-sky-500/10 border border-sky-500/20 text-sky-700 dark:text-sky-300'
                          }`}
                        >
                          {ev.type === 'added' ? '+' : '~'} {it.name}
                        </span>
                      ))
                    )}
                    {h.events.some((ev) => ev.items.length > 4) && (
                      <span className="text-[10px] text-muted self-center">
                        +{h.events.reduce((n, ev) => n + Math.max(0, ev.items.length - 4), 0)} more
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* References */}
        {data && (
          <div className="rounded-xl bg-surface-100 border border-line-1 p-4">
            <div className="font-mono text-[11px] tracking-widest text-muted mb-3 flex items-center gap-1.5">
              <FileClock size={12} /> SOURCE REFERENCES
            </div>
            <p className="text-xs text-muted leading-relaxed">
              The upstream dataset carries{' '}
              {data.stats.groups ? Math.round((data.stats.references || 0) as number) || '' : ''} co-occurrence
              references mapping pairs of groups to the reports that tie them together; the full list ships with the
              mirror at{' '}
              <a
                href="/data/cig-portal/reference.json"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-sky-500"
              >
                /data/cig-portal/reference.json
              </a>
              .
            </p>
          </div>
        )}
      </div>

      <div className="mt-8 pt-4 border-t border-line-1 text-[11px] font-mono text-muted leading-relaxed">
        Data mirrored from the{' '}
        <a
          href={data?.upstream.portal || 'https://www.mbsd.jp/cig-ransomware-portal/'}
          target="_blank"
          rel="noopener noreferrer"
          className="underline hover:text-sky-500"
        >
          MBSD CIG Ransomware Information Portal
        </a>{' '}
        ({data?.upstream.publisher || 'MBSD'}). Group profiles, relationship notes and the changelog belong to MBSD and
        stay in their original bilingual form. Synced{' '}
        {data?.generated_at ? new Date(data.generated_at).toISOString().slice(0, 16).replace('T', ' ') : ''} UTC via the
        daily sync workflow.
      </div>
    </DataPageLayout>
  );
}
