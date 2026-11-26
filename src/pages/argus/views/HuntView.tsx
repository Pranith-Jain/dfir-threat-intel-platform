import { useState, useMemo } from 'react';
import {
  Crosshair,
  ExternalLink,
  Search,
  Database,
  Filter,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Target,
  Grid,
  BookOpen,
  GitBranch,
  Copy,
  Star,
  Check,
} from 'lucide-react';
import type { Actor, Detection } from '../types';
import { NATION_PALETTE } from '../data/countries';

interface Props {
  actors: Actor[];
}

type Tab = 'detections' | 'ttp-matrix' | 'ioc' | 'sector-pivot' | 'repos';

// Tabs use a lucide icon only — the previous emoji set was the
// "emoji icons in nav" AI tell.
const TABS: { key: Tab; label: string; icon: typeof Database }[] = [
  { key: 'detections', label: 'Detections', icon: Database },
  { key: 'ttp-matrix', label: 'TTP × APT Matrix', icon: Grid },
  { key: 'ioc', label: 'IOC Search', icon: Search },
  { key: 'sector-pivot', label: 'Sector Pivot', icon: Target },
  { key: 'repos', label: 'Repositories', icon: BookOpen },
];

const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const REPOS = [
  {
    name: 'SigmaHQ/sigma',
    url: 'https://github.com/SigmaHQ/sigma',
    description: 'Generic signature format for SIEM systems',
    lang: 'Sigma',
    stars: 8200,
  },
  {
    name: 'elastic/detection-rules',
    url: 'https://github.com/elastic/detection-rules',
    description: 'Elastic Security detection rules',
    lang: 'KQL',
    stars: 5100,
  },
  {
    name: 'splunk/security_content',
    url: 'https://github.com/splunk/security_content',
    description: 'Splunk security analytics use cases',
    lang: 'SPL',
    stars: 1800,
  },
  {
    name: 'chainguard-dev/malcontent',
    url: 'https://github.com/chainguard-dev/malcontent',
    description: 'Cross-platform malware scanner',
    lang: 'Multi',
    stars: 1200,
  },
  {
    name: 'fireeye/red_team_tool_countermeasures',
    url: 'https://github.com/fireeye/red_team_tool_countermeasures',
    description: 'YARA rules for detecting red team tools',
    lang: 'YARA',
    stars: 1100,
  },
  {
    name: 'threathunter-dev/threathunter',
    url: 'https://github.com/threathunter-dev/threathunter',
    description: 'Threat hunting queries for Splunk/Elastic',
    lang: 'KQL',
    stars: 450,
  },
  {
    name: 'microsoft/Microsoft-365-Defender-Hunting-Queries',
    url: 'https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries',
    description: 'M365 Defender hunting queries',
    lang: 'KQL',
    stars: 1800,
  },
  {
    name: 'SigmaHQ/detection-rules',
    url: 'https://github.com/SigmaHQ/detection-rules',
    description: 'Sigma detection rules collection',
    lang: 'Sigma',
    stars: 6800,
  },
];

export function HuntView({ actors }: Props) {
  const [tab, setTab] = useState<Tab>('detections');
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => setExpanded((e) => ({ ...e, [id]: !e[id] }));

  return (
    <div className="absolute inset-0 flex flex-col">
      {/* Header */}
      <div className="shrink-0 border-b border-line-1 p-4">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
              <Crosshair size={18} className="text-rose-600 dark:text-rose-400" /> Threat Hunting
            </h1>
            <span className="text-mini font-mono text-muted">
              {actors.length} actor{actors.length !== 1 ? 's' : ''} loaded
            </span>
          </div>
          <p className="text-meta text-muted mb-3">
            Hand-tuned KQL and CrowdStrike CQL queries. Pair with the TTP × APT matrix and sector pivot to triage
            exposure.
          </p>

          <div className="flex items-center gap-3 flex-wrap">
            {/* Tabs */}
            <div className="flex gap-1">
              {TABS.map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setTab(key)}
                  data-active={tab === key}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-meta font-medium transition-colors
                    border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
                    data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
                >
                  <Icon size={12} aria-hidden="true" />
                  {label}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative ml-auto">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search titles, platforms…"
                className="w-52 h-7 pl-7 pr-2.5 rounded-md bg-surface-100 border border-line-1 text-meta text-muted placeholder:text-muted focus:outline-none focus:border-accent/50"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-7xl mx-auto p-4">
          {tab === 'detections' && (
            <DetectionsTab
              actors={actors}
              search={search}
              sourceFilter={sourceFilter}
              setSourceFilter={setSourceFilter}
              expanded={expanded}
              toggleExpand={toggleExpand}
            />
          )}
          {tab === 'ttp-matrix' && <TTPMatrixTab actors={actors} expanded={expanded} toggleExpand={toggleExpand} />}
          {tab === 'ioc' && <IOCTab actors={actors} search={search} />}
          {tab === 'sector-pivot' && (
            <SectorPivotTab actors={actors} search={search} expanded={expanded} toggleExpand={toggleExpand} />
          )}
          {tab === 'repos' && <ReposTab search={search} />}
        </div>
      </div>
    </div>
  );
}

/* ── Detections Tab ────────────────────────────────────────────── */

function DetectionsTab({
  actors,
  search,
  sourceFilter,
  setSourceFilter,
  expanded,
  toggleExpand,
}: {
  actors: Actor[];
  search: string;
  sourceFilter: string | null;
  setSourceFilter: (s: string | null) => void;
  expanded: Record<string, boolean>;
  toggleExpand: (id: string) => void;
}) {
  const allDetections = useMemo(() => {
    const out: (Detection & { actorId: string; actorName: string; nation: string })[] = [];
    actors.forEach((a) =>
      a.detections.forEach((d) => {
        out.push({ ...d, actorId: a.id, actorName: a.name, nation: a.country });
      })
    );
    return out;
  }, [actors]);

  const sources = useMemo(() => [...new Set(allDetections.map((d) => d.source))].sort(), [allDetections]);

  const filtered = useMemo(() => {
    let items = allDetections;
    if (sourceFilter) items = items.filter((d) => d.source === sourceFilter);
    if (search) {
      const q = search.toLowerCase();
      items = items.filter((d) => d.title.toLowerCase().includes(q) || d.actorName.toLowerCase().includes(q));
    }
    return items;
  }, [allDetections, sourceFilter, search]);

  return (
    <div className="space-y-3">
      {/* Source filters */}
      <div className="flex items-center gap-2 flex-wrap mb-4">
        <Filter size={12} className="text-muted" />
        <button
          onClick={() => setSourceFilter(null)}
          data-active={sourceFilter === null}
          className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
            data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
        >
          All ({allDetections.length})
        </button>
        {sources.map((s) => {
          const count = allDetections.filter((d) => d.source === s).length;
          return (
            <button
              key={s}
              onClick={() => setSourceFilter(s)}
              data-active={sourceFilter === s}
              className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
                data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
            >
              {s} ({count})
            </button>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="py-12 text-center text-muted text-sm">
          <AlertTriangle size={16} className="inline mr-2 opacity-50" />
          No detections match current filters.
        </div>
      )}

      {filtered.map((d, i) => {
        const key = `${d.actorId}-${d.source}-${i}`;
        const isOpen = expanded[key];
        const n = NATION_PALETTE[d.nation];
        return (
          <div key={key} className="surface-card overflow-hidden">
            <button
              onClick={() => toggleExpand(key)}
              className="w-full flex items-center gap-3 p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300 transition-all duration-200 hover:-translate-y-px"
            >
              {isOpen ? (
                <ChevronDown size={12} className="text-muted shrink-0" />
              ) : (
                <ChevronRight size={12} className="text-muted shrink-0" />
              )}
              <span
                className="h-5 w-7 rounded flex items-center justify-center text-micro font-mono font-semibold shrink-0"
                style={{ background: `${n?.color ?? '#555'}22`, color: n?.color ?? '#888' }}
              >
                {d.nation}
              </span>
              <span className="text-tool text-muted flex-1 truncate">{d.title}</span>
              <span className="text-micro px-1.5 py-0.5 rounded bg-surface-300 text-muted border border-line-1 shrink-0">
                {d.source}
              </span>
              <span className="text-mini font-mono text-muted shrink-0">{d.actorName}</span>
            </button>
            {isOpen && (
              <div className="px-3 pb-3 pt-0 border-t border-line-1">
                <div className="mt-2 flex items-center gap-2">
                  <a
                    href={d.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-mini text-rose-600 dark:text-rose-400 hover:underline flex items-center gap-1 transition-colors"
                  >
                    <ExternalLink size={10} /> View detection rule
                  </a>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ── TTP × APT Matrix Tab ─────────────────────────────────────── */

function TTPMatrixTab({
  actors,
  expanded,
  toggleExpand,
}: {
  actors: Actor[];
  expanded: Record<string, boolean>;
  toggleExpand: (id: string) => void;
}) {
  const [tacticFilter, setTacticFilter] = useState<string | null>(null);
  const [copiedCell, setCopiedCell] = useState<string | null>(null);

  // Build matrix: tactic → technique → actors using it
  const matrix = useMemo(() => {
    const map = new Map<string, Map<string, string[]>>();

    actors.forEach((actor) => {
      actor.ttps.forEach((ttp) => {
        if (!map.has(ttp.tactic)) map.set(ttp.tactic, new Map());
        const tacticMap = map.get(ttp.tactic)!;
        if (!tacticMap.has(ttp.id)) tacticMap.set(ttp.id, []);
        tacticMap.get(ttp.id)!.push(actor.id);
      });
    });

    return map;
  }, [actors]);

  const tactics = useMemo(() => {
    const t = [...matrix.keys()];
    return TACTIC_ORDER.filter((tactic) => t.includes(tactic));
  }, [matrix]);

  const filteredTactics = useMemo(() => {
    if (!tacticFilter) return tactics;
    return tactics.filter((t) => t === tacticFilter);
  }, [tactics, tacticFilter]);

  const totalTechniques = useMemo(() => {
    let count = 0;
    matrix.forEach((m) => (count += m.size));
    return count;
  }, [matrix]);

  const copyCell = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCell(text);
    setTimeout(() => setCopiedCell(null), 1500);
  };

  return (
    <div className="space-y-4">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        <div className="surface-card p-3">
          <div className="text-mini text-muted mb-1">Total Techniques</div>
          <div className="text-xl font-bold text-body">{totalTechniques}</div>
        </div>
        <div className="surface-card p-3">
          <div className="text-mini text-muted mb-1">Active Actors</div>
          <div className="text-xl font-bold text-body">{actors.length}</div>
        </div>
        <div className="surface-card p-3">
          <div className="text-mini text-muted mb-1">Tactics</div>
          <div className="text-xl font-bold text-body">{tactics.length}</div>
        </div>
      </div>

      {/* Tactic filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={12} className="text-muted" />
        <button
          onClick={() => setTacticFilter(null)}
          data-active={tacticFilter === null}
          className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
            data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
        >
          All Tactics
        </button>
        {tactics.map((t) => {
          const techniqueCount = matrix.get(t)?.size ?? 0;
          return (
            <button
              key={t}
              onClick={() => setTacticFilter(t)}
              data-active={tacticFilter === t}
              className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
                data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
            >
              {t.replace(/-/g, ' ')} ({techniqueCount})
            </button>
          );
        })}
      </div>

      {/* Heatmap Table */}
      <div className="surface-card overflow-x-auto">
        <table className="w-full text-mini">
          <thead>
            <tr className="border-b border-line-1">
              <th className="text-left p-2 text-muted font-medium sticky left-0 bg-surface-100">Technique</th>
              {actors.map((actor) => (
                <th key={actor.id} className="p-2 text-center min-w-[40px]">
                  <div className="flex flex-col items-center gap-0.5">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ background: NATION_PALETTE[actor.country]?.color ?? '#888' }}
                    />
                    <span className="text-micro font-mono text-muted truncate max-w-[50px]">
                      {actor.apt ?? actor.name.split(' ')[0]}
                    </span>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredTactics.map((tactic) => {
              const techniques = matrix.get(tactic);
              if (!techniques) return null;
              return (
                <tr key={tactic} className="border-b border-line-1/30">
                  <td className="p-2 font-mono text-micro text-muted sticky left-0 bg-surface-100 capitalize">
                    {tactic.replace(/-/g, ' ')}
                  </td>
                  {actors.map((actor) => {
                    const techniquesForActor = [...techniques.entries()].filter(([, actorIds]) =>
                      actorIds.includes(actor.id)
                    );
                    return (
                      <td key={actor.id} className="p-1 text-center">
                        {techniquesForActor.length > 0 ? (
                          <div className="flex flex-wrap gap-0.5 justify-center">
                            {techniquesForActor.slice(0, 2).map(([tid]) => (
                              <button
                                key={tid}
                                onClick={() => copyCell(tid)}
                                className="px-1 py-0.5 rounded text-micro font-mono bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition-colors"
                                title={tid}
                              >
                                {copiedCell === tid ? <Check size={8} className="inline" /> : tid.split('.')[0]}
                              </button>
                            ))}
                            {techniquesForActor.length > 2 && (
                              <span className="text-micro text-muted">+{techniquesForActor.length - 2}</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-inverted dark:text-line-1/30">—</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Technique Detail List */}
      <div className="space-y-2 mt-6">
        <h3 className="text-tool font-semibold text-body">Technique Details</h3>
        {filteredTactics.map((tactic) => {
          const techniques = matrix.get(tactic);
          if (!techniques) return null;
          return (
            <div key={tactic} className="surface-card overflow-hidden">
              <button
                onClick={() => toggleExpand(`tactic-${tactic}`)}
                className="w-full flex items-center gap-3 p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300 transition-all duration-200"
              >
                {expanded[`tactic-${tactic}`] ? (
                  <ChevronDown size={12} className="text-muted" />
                ) : (
                  <ChevronRight size={12} className="text-muted" />
                )}
                <span className="text-meta font-semibold text-body capitalize">{tactic.replace(/-/g, ' ')}</span>
                <span className="text-micro text-muted">({techniques.size} techniques)</span>
              </button>
              {expanded[`tactic-${tactic}`] && (
                <div className="px-3 pb-3 pt-0 border-t border-line-1">
                  {[...techniques.entries()].map(([tid, actorIds]) => (
                    <div key={tid} className="py-2 border-b border-line-1/30 last:border-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-micro text-rose-600 dark:text-rose-400">{tid}</span>
                        <span className="text-mini text-muted">
                          {actorIds.length} actor{actorIds.length !== 1 ? 's' : ''}
                        </span>
                        <button
                          onClick={() => copyCell(tid)}
                          className="text-muted hover:text-muted dark:hover:text-inverted transition-colors"
                        >
                          <Copy size={10} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── IOC Index Tab ─────────────────────────────────────────────── */

function IOCTab({ actors, search }: { actors: Actor[]; search: string }) {
  const [sectorFilter, setSectorFilter] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<'all' | 'malware' | 'cve' | 'ttp'>('all');

  const allSectors = useMemo(() => {
    const s = new Set<string>();
    actors.forEach((a) => a.sectors.forEach((sec) => s.add(sec)));
    return [...s].sort();
  }, [actors]);

  const filtered = useMemo(() => {
    let items = actors;
    if (sectorFilter) items = items.filter((a) => a.sectors.includes(sectorFilter));
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (a) =>
          a.malware.some((m) => m.name.toLowerCase().includes(q)) ||
          a.cves.some((c) => c.id.toLowerCase().includes(q)) ||
          a.ttps.some((t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)) ||
          a.name.toLowerCase().includes(q) ||
          a.sectors.some((s) => s.toLowerCase().includes(q))
      );
    }
    return items;
  }, [actors, sectorFilter, search]);

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Filter size={12} className="text-muted" />
          <button
            onClick={() => setSectorFilter(null)}
            data-active={sectorFilter === null}
            className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
              data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
          >
            All sectors
          </button>
          {allSectors.map((s) => (
            <button
              key={s}
              onClick={() => setSectorFilter(s)}
              data-active={sectorFilter === s}
              className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300 capitalize
                data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40"
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1">
          {(['all', 'malware', 'cve', 'ttp'] as const).map((type) => (
            <button
              key={type}
              onClick={() => setTypeFilter(type)}
              data-active={typeFilter === type}
              className="px-2 py-0.5 rounded-full text-mini border border-line-1 text-muted hover:bg-surface-300 dark:hover:bg-surface-300
                data-[active=true]:bg-accent/15 data-[active=true]:text-rose-600 dark:text-rose-400 data-[active=true]:border-accent/40 capitalize"
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* IOC table */}
      <div className="surface-card overflow-x-auto">
        <table className="w-full min-w-[720px] text-meta">
          <thead>
            <tr className="border-b border-line-1">
              <th className="text-left p-2.5 text-muted font-medium">Actor</th>
              {(typeFilter === 'all' || typeFilter === 'malware') && (
                <th className="text-left p-2.5 text-muted font-medium">Malware</th>
              )}
              {(typeFilter === 'all' || typeFilter === 'cve') && (
                <th className="text-left p-2.5 text-muted font-medium">CVEs</th>
              )}
              {(typeFilter === 'all' || typeFilter === 'ttp') && (
                <th className="text-left p-2.5 text-muted font-medium">Key TTPs</th>
              )}
              <th className="text-left p-2.5 text-muted font-medium">Sectors</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => {
              const n = NATION_PALETTE[a.country];
              return (
                <tr
                  key={a.id}
                  className="border-b border-line-1/50 hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                >
                  <td className="p-2.5">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full shrink-0" style={{ background: n?.color }} />
                      <span className="text-muted font-medium">{a.name}</span>
                      {a.apt && <span className="text-micro font-mono text-muted">{a.apt}</span>}
                    </div>
                  </td>
                  {(typeFilter === 'all' || typeFilter === 'malware') && (
                    <td className="p-2.5">
                      <div className="flex flex-wrap gap-1">
                        {a.malware.map((m) => (
                          <span
                            key={m.name}
                            className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 text-micro border border-purple-500/20"
                          >
                            {m.name}
                          </span>
                        ))}
                      </div>
                    </td>
                  )}
                  {(typeFilter === 'all' || typeFilter === 'cve') && (
                    <td className="p-2.5">
                      <div className="flex flex-wrap gap-1">
                        {a.cves.slice(0, 3).map((c) => (
                          <span
                            key={c.id}
                            className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 text-micro font-mono border border-red-500/20"
                          >
                            {c.id}
                          </span>
                        ))}
                        {a.cves.length > 3 && <span className="text-micro text-muted">+{a.cves.length - 3}</span>}
                      </div>
                    </td>
                  )}
                  {(typeFilter === 'all' || typeFilter === 'ttp') && (
                    <td className="p-2.5">
                      <div className="flex flex-wrap gap-1">
                        {a.ttps.slice(0, 3).map((t) => (
                          <span
                            key={t.id}
                            className="px-1.5 py-0.5 rounded bg-brand-500/10 text-brand-400 text-micro font-mono border border-brand-500/20"
                          >
                            {t.id}
                          </span>
                        ))}
                        {a.ttps.length > 3 && <span className="text-micro text-muted">+{a.ttps.length - 3}</span>}
                      </div>
                    </td>
                  )}
                  <td className="p-2.5">
                    <div className="flex flex-wrap gap-1">
                      {a.sectors.slice(0, 3).map((s) => (
                        <span
                          key={s}
                          className="px-1.5 py-0.5 rounded bg-surface-300 text-muted text-micro border border-line-1 capitalize"
                        >
                          {s}
                        </span>
                      ))}
                      {a.sectors.length > 3 && <span className="text-micro text-muted">+{a.sectors.length - 3}</span>}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-muted text-sm">
            <AlertTriangle size={16} className="inline mr-2 opacity-50" />
            No IOCs match current filters.
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Sector Pivot Tab ──────────────────────────────────────────── */

function SectorPivotTab({
  actors,
  search,
  expanded,
  toggleExpand,
}: {
  actors: Actor[];
  search: string;
  expanded: Record<string, boolean>;
  toggleExpand: (id: string) => void;
}) {
  const sectorData = useMemo(() => {
    const map = new Map<string, { actors: Actor[]; totalTTPs: number; totalCVEs: number; totalMalware: number }>();

    actors.forEach((actor) => {
      actor.sectors.forEach((sector) => {
        if (!map.has(sector)) map.set(sector, { actors: [], totalTTPs: 0, totalCVEs: 0, totalMalware: 0 });
        const data = map.get(sector)!;
        data.actors.push(actor);
        data.totalTTPs += actor.ttps.length;
        data.totalCVEs += actor.cves.length;
        data.totalMalware += actor.malware.length;
      });
    });

    return [...map.entries()]
      .map(([sector, data]) => ({ sector, ...data }))
      .sort((a, b) => b.actors.length - a.actors.length);
  }, [actors]);

  const filtered = useMemo(() => {
    if (!search) return sectorData;
    const q = search.toLowerCase();
    return sectorData.filter(
      (s) => s.sector.toLowerCase().includes(q) || s.actors.some((a) => a.name.toLowerCase().includes(q))
    );
  }, [sectorData, search]);

  return (
    <div className="space-y-3">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <div className="surface-card p-3 text-center">
          <div className="text-xl font-bold text-body">{sectorData.length}</div>
          <div className="text-micro text-muted uppercase tracking-wider">Sectors</div>
        </div>
        <div className="surface-card p-3 text-center">
          <div className="text-xl font-bold text-body">{sectorData.reduce((sum, s) => sum + s.actors.length, 0)}</div>
          <div className="text-micro text-muted uppercase tracking-wider">Actor-Links</div>
        </div>
        <div className="surface-card p-3 text-center">
          <div className="text-xl font-bold text-body">{sectorData.reduce((sum, s) => sum + s.totalCVEs, 0)}</div>
          <div className="text-micro text-muted uppercase tracking-wider">CVEs</div>
        </div>
        <div className="surface-card p-3 text-center">
          <div className="text-xl font-bold text-body">{sectorData.reduce((sum, s) => sum + s.totalMalware, 0)}</div>
          <div className="text-micro text-muted uppercase tracking-wider">Malware</div>
        </div>
      </div>

      {filtered.length === 0 && (
        <div className="py-12 text-center text-muted text-sm">
          <AlertTriangle size={16} className="inline mr-2 opacity-50" />
          No sectors match current filters.
        </div>
      )}

      {filtered.map(({ sector, actors: sectorActors, totalTTPs, totalCVEs, totalMalware }) => (
        <div key={sector} className="surface-card overflow-hidden">
          <button
            onClick={() => toggleExpand(`sector-${sector}`)}
            className="w-full flex items-center gap-3 p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300 transition-all duration-200"
          >
            {expanded[`sector-${sector}`] ? (
              <ChevronDown size={12} className="text-muted" />
            ) : (
              <ChevronRight size={12} className="text-muted" />
            )}
            <Target size={14} className="text-rose-600 dark:text-rose-400" />
            <span className="text-tool font-semibold text-body capitalize flex-1">{sector.replace(/-/g, ' ')}</span>
            <span className="text-micro px-2 py-0.5 rounded-full bg-surface-300 text-muted border border-line-1">
              {sectorActors.length} actor{sectorActors.length !== 1 ? 's' : ''}
            </span>
            <div className="flex items-center gap-3 text-micro text-muted">
              <span>{totalTTPs} TTPs</span>
              <span>{totalCVEs} CVEs</span>
              <span>{totalMalware} malware</span>
            </div>
          </button>

          {expanded[`sector-${sector}`] && (
            <div className="px-3 pb-3 pt-0 border-t border-line-1">
              <div className="mt-2 space-y-2">
                {sectorActors.map((actor) => {
                  const n = NATION_PALETTE[actor.country];
                  return (
                    <div key={actor.id} className="flex items-center gap-2 p-2 rounded bg-surface-200/50">
                      <span
                        className="h-4 w-6 rounded flex items-center justify-center text-micro font-mono font-semibold shrink-0"
                        style={{ background: `${n?.color ?? '#555'}22`, color: n?.color ?? '#888' }}
                      >
                        {actor.country}
                      </span>
                      <span className="text-meta text-muted font-medium">{actor.name}</span>
                      {actor.apt && <span className="text-micro font-mono text-muted">{actor.apt}</span>}
                      <span className="text-micro text-muted ml-auto">
                        {actor.ttps.length} TTPs · {actor.cves.length} CVEs
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ── Repositories Tab ──────────────────────────────────────────── */

function ReposTab({ search }: { search: string }) {
  const filtered = useMemo(() => {
    if (!search) return REPOS;
    const q = search.toLowerCase();
    return REPOS.filter(
      (r) =>
        r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.lang.toLowerCase().includes(q)
    );
  }, [search]);

  const langColors: Record<string, string> = {
    Sigma: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    KQL: 'text-brand-400 bg-brand-500/10 border-brand-500/20',
    SPL: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    YARA: 'text-red-400 bg-red-500/10 border-red-500/20',
    Multi: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-4">
        <span className="text-meta text-muted">{filtered.length} repositories</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {filtered.map((repo) => (
          <a
            key={repo.name}
            href={repo.url}
            target="_blank"
            rel="noopener noreferrer"
            className="surface-card p-4 hover:bg-surface-200 dark:hover:bg-surface-300 transition-all duration-200 hover:-translate-y-px group block"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <GitBranch size={12} className="text-muted shrink-0" />
                  <span className="text-tool font-semibold text-body truncate group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
                    {repo.name}
                  </span>
                </div>
                <p className="text-mini text-muted leading-relaxed">{repo.description}</p>
              </div>
              <ExternalLink
                size={12}
                className="text-muted group-hover:text-rose-600 dark:group-hover:text-rose-400 shrink-0 mt-1 transition-colors"
              />
            </div>
            <div className="flex items-center gap-3 mt-3">
              <span
                className={`px-2 py-0.5 rounded-full text-micro font-medium border ${langColors[repo.lang] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/20'}`}
              >
                {repo.lang}
              </span>
              <span className="text-micro text-muted flex items-center gap-1">
                <Star size={10} className="shrink-0" /> {repo.stars.toLocaleString()}
              </span>
            </div>
          </a>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="py-12 text-center text-muted text-sm">
          <AlertTriangle size={16} className="inline mr-2 opacity-50" />
          No repositories match current filters.
        </div>
      )}
    </div>
  );
}
