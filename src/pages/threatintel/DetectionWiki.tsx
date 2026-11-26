import { useEffect, useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Search, ExternalLink, Database, Shield, FlaskConical, BarChart3, Globe, Layers, Server } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

// ── Types ─────────────────────────────────────────────────────────────

interface DwTechnique {
  id: string;
  name: string;
  tactic: string;
  ruleCount: number;
  isSubtechnique: boolean;
  parentTechnique?: string;
}

interface DwTacticColumn {
  tactic: string;
  techniques: DwTechnique[];
  totalRules: number;
}

interface DwTechniquesIndex {
  generatedAt: string;
  source: string;
  totalRules: number;
  techniqueCount: number;
  subtechniqueCount: number;
  tacticCount: number;
  matrix: DwTacticColumn[];
  all: DwTechnique[];
}

interface DwPlatform {
  name: string;
  slug: string;
  description: string;
  events: number;
  rulesWithSamples: number;
  totalRules?: number;
}

interface DwPlatformDetail {
  generatedAt: string;
  source: string;
  platform: string;
  slug: string;
  description: string;
  events: number;
  rulesWithSamples: number;
  totalRules: number | null;
  sampleEvents: Array<Record<string, unknown>>;
  sampleCount: number;
  note: string;
}

interface DwLabEntry {
  slug: string;
  title: string;
  author: string;
  date: string;
  description: string;
  techniques: string[];
}

interface DwWindowsProvider {
  name: string;
  slug: string;
  events: number;
  samples: number;
  rules: number;
  channel: string;
}
interface DwWindowsCatalog {
  totalProviders: number;
  totalEvents: number;
  providersWithSamples: number;
  providers: DwWindowsProvider[];
}
interface DwSecurityAuditingEvent {
  id: number;
  title: string;
  channel: string;
  hasSample: boolean;
  hasRule: boolean;
  tactic: string | null;
}
interface DwSecurityAuditingCatalog {
  provider: string;
  channel: string;
  eventCount: number;
  sampleCount: number;
  rulesCount: number;
  events: DwSecurityAuditingEvent[];
}
interface DwIndex {
  generatedAt: string;
  source: string;
  description: string;
  stats: {
    totalRules: number;
    eventCount: number;
    techniqueCount: number;
    subtechniqueCount: number;
    platformCount: number;
    labCount: number;
    tacticCount: number;
    windowsProviders?: number;
    securityAuditingEvents?: number;
    totalWindowsEvents?: number;
    totalWindowsProviders?: number;
  };
  platforms: string[];
  vendors: string[];
  topTechniques: DwTechnique[];
}

type Tab = 'matrix' | 'top' | 'platforms' | 'windows' | 'auditing' | 'labs';

const TABS: { id: Tab; label: string; icon: typeof Shield }[] = [
  { id: 'matrix', label: 'ATT&CK Matrix', icon: Shield },
  { id: 'top', label: 'Top Techniques', icon: BarChart3 },
  { id: 'windows', label: 'Windows Catalog', icon: Server },
  { id: 'auditing', label: 'Security Auditing', icon: Layers },
  { id: 'platforms', label: 'Platforms', icon: Globe },
  { id: 'labs', label: 'Detection Labs', icon: FlaskConical },
];

const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const TACTIC_SHORT: Record<string, string> = {
  Reconnaissance: 'Recon',
  'Resource Development': 'ResDev',
  'Initial Access': 'InitAcc',
  Execution: 'Exec',
  Persistence: 'Persist',
  'Privilege Escalation': 'PrivEsc',
  'Defense Evasion': 'DefEvas',
  'Credential Access': 'CredAcc',
  Discovery: 'Disc',
  'Lateral Movement': 'LatMov',
  Collection: 'Collect',
  'Command and Control': 'C2',
  Exfiltration: 'Exfil',
  Impact: 'Impact',
};

// ── Heatmap color ─────────────────────────────────────────────────────

function ruleHeatColor(count: number, max: number): string {
  if (count === 0) return 'bg-slate-100 dark:bg-slate-800/40 text-slate-400';
  const ratio = count / max;
  if (ratio > 0.5) return 'bg-rose-500/30 text-rose-900 dark:text-rose-200 border-rose-500/40';
  if (ratio > 0.25) return 'bg-orange-500/25 text-orange-800 dark:text-orange-200 border-orange-500/30';
  if (ratio > 0.1) return 'bg-amber-500/20 text-amber-800 dark:text-amber-200 border-amber-500/25';
  if (ratio > 0.03) return 'bg-emerald-500/15 text-emerald-800 dark:text-emerald-200 border-emerald-500/20';
  return 'bg-slate-100 dark:bg-slate-800/60 text-muted border-slate-200 dark:border-slate-700';
}

function ruleHeatBg(count: number, max: number): string {
  if (count === 0) return '#f8fafc';
  const ratio = count / max;
  if (ratio > 0.5) return 'rgba(244,63,94,0.35)';
  if (ratio > 0.25) return 'rgba(249,115,22,0.3)';
  if (ratio > 0.1) return 'rgba(245,158,11,0.25)';
  if (ratio > 0.03) return 'rgba(16,185,129,0.2)';
  return '#f1f5f9';
}

// ── Component ─────────────────────────────────────────────────────────

export default function DetectionWiki(): JSX.Element {
  const [index, setIndex] = useState<DwIndex | null>(null);
  const [techData, setTechData] = useState<DwTechniquesIndex | null>(null);
  const [platforms, setPlatforms] = useState<DwPlatform[]>([]);
  const [labs, setLabs] = useState<DwLabEntry[]>([]);
  const [windowsCatalog, setWindowsCatalog] = useState<DwWindowsCatalog | null>(null);
  const [auditingCatalog, setAuditingCatalog] = useState<DwSecurityAuditingCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('matrix');
  const [search, setSearch] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [onlyWithRules, setOnlyWithRules] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState<string | null>(null);
  const [platformDetail, setPlatformDetail] = useState<DwPlatformDetail | null>(null);
  const [platformDetailLoading, setPlatformDetailLoading] = useState(false);
  const [platformDetailError, setPlatformDetailError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    const safeJson = async (url: string): Promise<unknown | null> => {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const r = await fetch(url, { signal: ctrl.signal });
          if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
          const ct = r.headers.get('content-type') ?? '';
          if (!ct.includes('json') && !ct.includes('application/json')) {
            const text = await r.text();
            if (text.trimStart().startsWith('<!doctype') || text.trimStart().startsWith('<html')) {
              throw new Error(`Expected JSON but got HTML for ${url} — file missing or not deployed`);
            }
            throw new Error(`Unexpected content-type ${ct} for ${url}`);
          }
          return await r.json();
        } catch (e) {
          if (e instanceof DOMException && e.name === 'AbortError') throw e;
          if (attempt === 2) throw e;
          await new Promise((res) => setTimeout(res, 300 * 2 ** attempt + Math.random() * 200));
        }
      }
      return null;
    };
    Promise.all([
      safeJson('/data/detection-wiki/index.json').then((d) => d as DwIndex),
      safeJson('/data/detection-wiki/techniques.json').then((d) => d as DwTechniquesIndex),
      safeJson('/data/detection-wiki/platforms.json')
        .then((d) => d as DwPlatform[])
        .catch(() => [] as DwPlatform[]),
      safeJson('/data/detection-wiki/labs.json')
        .then((d) => d as DwLabEntry[])
        .catch(() => [] as DwLabEntry[]),
      safeJson('/data/detection-wiki/windows.json').catch(() => null) as Promise<DwWindowsCatalog | null>,
      safeJson('/data/detection-wiki/security-auditing.json').catch(
        () => null
      ) as Promise<DwSecurityAuditingCatalog | null>,
    ])
      .then(([idx, tech, plat, lab, win, audit]) => {
        if (cancelled) return;
        setIndex(idx);
        setTechData(tech);
        setPlatforms(plat);
        setLabs(lab);
        if (win) setWindowsCatalog(win);
        if (audit) setAuditingCatalog(audit);
      })
      .catch((e) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  useEffect(() => {
    if (!selectedPlatform) {
      setPlatformDetail(null);
      setPlatformDetailError(null);
      return;
    }
    let cancelled = false;
    setPlatformDetailLoading(true);
    setPlatformDetailError(null);
    fetch(`/data/detection-wiki/platforms-detail/${selectedPlatform}.json`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const ct = r.headers.get('content-type') ?? '';
        if (!ct.includes('json') && !ct.includes('application/json')) {
          const text = await r.text();
          if (text.trimStart().startsWith('<!doctype'))
            throw new Error(`Platform ${selectedPlatform} not found — file missing`);
          throw new Error(`Unexpected content-type ${ct}`);
        }
        return r.json();
      })
      .then((d: DwPlatformDetail) => {
        if (!cancelled) setPlatformDetail(d);
      })
      .catch((e: Error) => {
        if (!cancelled) setPlatformDetailError(e.message);
      })
      .finally(() => {
        if (!cancelled) setPlatformDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedPlatform]);

  useEffect(() => {
    if (tab !== 'platforms') setSelectedPlatform(null);
  }, [tab]);

  const filteredTechniques = useMemo(() => {
    if (!techData) return [] as DwTechnique[];
    let list = techData.all;
    if (selectedTactic) list = list.filter((t) => t.tactic === selectedTactic);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
    }
    return list;
  }, [techData, search, selectedTactic]);

  const maxRules = useMemo(() => {
    if (!techData) return 1;
    return Math.max(...techData.all.map((t) => t.ruleCount), 1);
  }, [techData]);

  const matrixTactics = useMemo(() => {
    if (!techData) return [] as DwTacticColumn[];
    let cols = techData.matrix;
    if (selectedTactic) cols = cols.filter((c) => c.tactic === selectedTactic);
    return cols;
  }, [techData, selectedTactic]);

  const filteredWindowsProviders = useMemo(() => {
    if (!windowsCatalog) return [] as DwWindowsProvider[];
    let list = windowsCatalog.providers;
    if (onlyWithRules) list = list.filter((p) => p.rules > 0);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((p) => `${p.name} ${p.slug} ${p.channel}`.toLowerCase().includes(q));
    }
    return list;
  }, [windowsCatalog, search, onlyWithRules]);

  const filteredAuditingEvents = useMemo(() => {
    if (!auditingCatalog) return [] as DwSecurityAuditingEvent[];
    let list = auditingCatalog.events;
    if (onlyWithRules) list = list.filter((e) => e.hasRule);
    if (selectedTactic) list = list.filter((e) => e.tactic === selectedTactic);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((e) => `${e.id} ${e.title} ${e.channel} ${e.tactic ?? ''}`.toLowerCase().includes(q));
    }
    return list;
  }, [auditingCatalog, search, selectedTactic, onlyWithRules]);

  const filteredPlatforms = useMemo(() => {
    if (!search) return platforms;
    const q = search.toLowerCase();
    return platforms.filter((p) => `${p.name} ${p.description}`.toLowerCase().includes(q));
  }, [platforms, search]);

  const filteredLabs = useMemo(() => {
    if (!search) return labs;
    const q = search.toLowerCase();
    return labs.filter((l) => `${l.title} ${l.description} ${l.techniques.join(' ')}`.toLowerCase().includes(q));
  }, [labs, search]);

  const briefingItems = useMemo(
    () =>
      (techData?.all ?? []).slice(0, 50).map((t) => ({
        title: `${t.id} ${t.name}`,
        body: `${t.tactic} · ${t.ruleCount} detection rules${t.isSubtechnique ? ' (sub-technique)' : ''}.`,
        source: `https://attack.mitre.org/techniques/${t.id.split('.').join('/')}/`,
      })),
    [techData]
  );

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Database size={28} className="text-brand-600 dark:text-brand-400" />}
      title="Detection Wiki"
      description={
        <span>
          <strong>{index?.stats.totalRules.toLocaleString() ?? '15,957'}</strong> detection rules from Sigma, Elastic,
          Splunk, Kusto, YARA-L, Panther, and Sublime — mapped to <strong>{index?.stats.techniqueCount ?? 218}</strong>{' '}
          MITRE ATT&CK techniques across <strong>{index?.stats.platformCount ?? 17}</strong> platforms ·{' '}
          <strong>{windowsCatalog?.totalProviders.toLocaleString() ?? '1,518'}</strong> Windows providers (
          <strong>{windowsCatalog?.totalEvents.toLocaleString() ?? '103,315'}</strong> events) ·{' '}
          <strong>{auditingCatalog?.eventCount ?? 426}</strong> Security-Auditing events · 6 detection labs. Source:{' '}
          <a
            href="https://detection.wiki"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
          >
            detection.wiki <ExternalLink size={11} />
          </a>
        </span>
      }
      loading={loading}
      error={error}
    >
      {/* Stats strip */}
      {index && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-6">
          <StatCard label="Detection Rules" value={index.stats.totalRules.toLocaleString()} accent="rose" />
          <StatCard label="ATT&CK Techniques" value={index.stats.techniqueCount} accent="brand" />
          <StatCard
            label="Windows Providers"
            value={windowsCatalog?.totalProviders.toLocaleString() ?? '1,518'}
            accent="emerald"
          />
          <StatCard
            label="Windows Events"
            value={windowsCatalog?.totalEvents.toLocaleString() ?? '103,315'}
            accent="emerald"
          />
          <StatCard label="Sec-Auditing" value={auditingCatalog?.eventCount ?? 426} accent="amber" />
          <StatCard label="Events Cataloged" value={index.stats.eventCount.toLocaleString()} accent="amber" />
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4 overflow-x-auto pb-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono whitespace-nowrap border transition-colors ${
              tab === t.id
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
          >
            <t.icon size={12} /> {t.label}
          </button>
        ))}
      </div>

      <DetectionAiBriefing
        surface="Detection Wiki"
        source="detection-wiki"
        items={briefingItems}
        dayKey={techData?.generatedAt?.slice(0, 10) ?? index?.generatedAt?.slice(0, 10)}
        label="ATT&CK techniques"
      />

      {/* Search + filters */}
      <div className="surface-card p-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={
                tab === 'windows'
                  ? 'Search Windows providers, channels…'
                  : tab === 'auditing'
                    ? 'Search Event IDs, titles, tactics…'
                    : tab === 'platforms'
                      ? 'Search platforms…'
                      : 'Search techniques, tactics…'
              }
              className="w-full pl-9 pr-3 py-2 rounded border border-line-1 bg-surface-100 font-mono text-sm focus:border-brand-500/50 focus:outline-none"
            />
          </div>
          {(tab === 'auditing' || tab === 'windows') && (
            <label className="flex items-center gap-1.5 text-xs font-mono text-muted shrink-0">
              <input
                type="checkbox"
                checked={onlyWithRules}
                onChange={(e) => setOnlyWithRules(e.target.checked)}
                className="w-3 h-3 rounded border-line-2"
              />
              only with rules
            </label>
          )}
          {selectedTactic && (
            <button
              onClick={() => setSelectedTactic(null)}
              className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline"
            >
              clear tactic
            </button>
          )}
        </div>
        {/* Tactic filter chips */}
        <div className="flex flex-wrap gap-1.5 mt-2">
          {TACTIC_ORDER.map((t) => {
            const active = selectedTactic === t;
            return (
              <button
                key={t}
                onClick={() => setSelectedTactic(active ? null : t)}
                className={`text-micro font-mono px-2 py-0.5 rounded-full border transition-colors ${
                  active
                    ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                    : 'border-line-1 text-slate-500 hover:border-brand-500/40'
                }`}
              >
                {TACTIC_SHORT[t] ?? t}
              </button>
            );
          })}
        </div>
        {tab !== 'matrix' && tab !== 'top' && (
          <p className="text-micro font-mono text-muted mt-2">
            {tab === 'windows' &&
              `${filteredWindowsProviders.length} of ${windowsCatalog?.providers.length ?? 0} sampled providers (of ${windowsCatalog?.totalProviders.toLocaleString() ?? '1,518'} total) · ${windowsCatalog?.totalEvents.toLocaleString() ?? '103,315'} events`}
            {tab === 'auditing' &&
              `${filteredAuditingEvents.length} of ${auditingCatalog?.events.length ?? 0} sampled events (of ${auditingCatalog?.eventCount ?? 426} total) · ${auditingCatalog?.sampleCount ?? 222} with samples · ${auditingCatalog?.rulesCount ?? 133} mapped to rules`}
            {tab === 'platforms' && `${filteredPlatforms.length} platforms`}
            {tab === 'labs' && `${filteredLabs.length} labs`}
          </p>
        )}
      </div>

      {/* ── ATT&CK Matrix ─────────────────────────────────────────── */}
      {tab === 'matrix' && (
        <div className="space-y-3">
          <p className="text-xs text-muted font-mono">
            Heatmap by rule count — darker = more detection rules cover this technique. Click a tactic chip above to
            focus.
          </p>
          <div className="space-y-2">
            {matrixTactics.map((col) => (
              <div key={col.tactic} className="surface-card overflow-hidden">
                <button
                  onClick={() => setSelectedTactic(selectedTactic === col.tactic ? null : col.tactic)}
                  className="w-full flex items-center justify-between p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                >
                  <span className="font-mono text-sm font-semibold text-heading">{col.tactic}</span>
                  <span className="text-xs font-mono text-muted">
                    {col.totalRules.toLocaleString()} rules · {col.techniques.length} techniques
                  </span>
                </button>
                <div className="px-3 pb-3 flex flex-wrap gap-1">
                  {col.techniques.map((t) => (
                    <a
                      key={t.id}
                      href={`https://attack.mitre.org/techniques/${t.id.split('.').join('/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`px-2 py-1 rounded text-micro font-mono border transition-colors hover:opacity-80 ${ruleHeatColor(t.ruleCount, maxRules)}`}
                      title={`${t.name} — ${t.ruleCount} rules`}
                    >
                      {t.isSubtechnique ? (
                        <span className="opacity-60">{t.id.split('.')[0]}</span>
                      ) : (
                        <span className="font-semibold">{t.id}</span>
                      )}{' '}
                      <span className="opacity-80">{t.ruleCount}</span>
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Top Techniques ─────────────────────────────────────────── */}
      {tab === 'top' && (
        <div className="space-y-2">
          {filteredTechniques
            .filter((t) => !t.isSubtechnique)
            .sort((a, b) => b.ruleCount - a.ruleCount)
            .slice(0, 50)
            .map((t) => (
              <a
                key={t.id}
                href={`https://attack.mitre.org/techniques/${t.id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="surface-card p-3 flex items-center gap-3 hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors group"
              >
                <div
                  className="w-16 h-8 rounded flex items-center justify-center font-mono text-xs font-bold border"
                  style={{ background: ruleHeatBg(t.ruleCount, maxRules) }}
                >
                  {t.ruleCount}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                    {t.id} {t.name}
                  </div>
                  <div className="text-micro text-muted">{t.tactic}</div>
                </div>
                <ExternalLink size={12} className="text-muted group-hover:text-brand-500 shrink-0" />
              </a>
            ))}
        </div>
      )}

      {/* ── Windows Catalog ────────────────────────────────────────── */}
      {tab === 'windows' && (
        <div className="space-y-2">
          <p className="text-xs text-muted font-mono">
            Windows Event Log providers —{' '}
            <a
              href="https://detection.wiki/windows/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              detection.wiki/windows <ExternalLink size={10} />
            </a>{' '}
            · 103,315 events across 1,518 providers (top 74 sampled here). Channel = where the event is logged.
          </p>
          <div className="overflow-x-auto rounded border border-line-1">
            <table className="w-full text-xs font-mono">
              <thead className="bg-surface-200 text-muted">
                <tr>
                  <th className="text-left px-3 py-2">Provider</th>
                  <th className="text-right px-3 py-2">Events</th>
                  <th className="text-right px-3 py-2">Samples</th>
                  <th className="text-right px-3 py-2">Rules</th>
                  <th className="text-left px-3 py-2">Channel</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-1">
                {filteredWindowsProviders.slice(0, 100).map((p) => (
                  <tr key={p.slug} className="hover:bg-surface-200 dark:hover:bg-surface-200 transition-colors">
                    <td className="px-3 py-2">
                      <a
                        href={`https://detection.wiki/${p.slug}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-semibold text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
                      >
                        {p.name} <ExternalLink size={10} />
                      </a>
                    </td>
                    <td className="text-right px-3 py-2">{p.events.toLocaleString()}</td>
                    <td className="text-right px-3 py-2">{p.samples.toLocaleString()}</td>
                    <td className="text-right px-3 py-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-micro ${p.rules > 0 ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-slate-100 text-slate-400 dark:bg-slate-700 dark:text-slate-500'}`}
                      >
                        {p.rules}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted truncate max-w-[180px]">{p.channel}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-micro font-mono text-muted">
            Data from{' '}
            <a
              href="https://detection.wiki/windows/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              detection.wiki/windows
            </a>{' '}
            · showing top providers by sample data. Full catalog has 1,518 providers.
          </p>
        </div>
      )}

      {/* ── Security Auditing (Microsoft-Windows-Security-Auditing) ─────── */}
      {tab === 'auditing' && (
        <div className="space-y-2">
          <p className="text-xs text-muted font-mono">
            <a
              href="https://detection.wiki/microsoft-windows-security-auditing/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              Microsoft-Windows-Security-Auditing <ExternalLink size={10} />
            </a>{' '}
            · 426 events in the Security channel · 222 with sample data · 133 mapped to detection rules. Subset of 87
            high-value events shown here (full catalog via API).
          </p>
          <div className="overflow-x-auto rounded border border-line-1">
            <table className="w-full text-xs font-mono">
              <thead className="bg-surface-200 text-muted">
                <tr>
                  <th className="text-left px-3 py-2">ID</th>
                  <th className="text-left px-3 py-2">Title</th>
                  <th className="text-center px-2 py-2">Sample</th>
                  <th className="text-center px-2 py-2">Rule</th>
                  <th className="text-left px-3 py-2">Tactic</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-1">
                {filteredAuditingEvents.slice(0, 100).map((e) => (
                  <tr key={e.id} className="hover:bg-surface-200 dark:hover:bg-surface-200 transition-colors">
                    <td className="px-3 py-2 font-bold">
                      <a
                        href={`https://detection.wiki/microsoft-windows-security-auditing/#${e.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-brand-600 dark:text-brand-400 hover:underline"
                      >
                        {e.id}
                      </a>
                    </td>
                    <td className="px-3 py-2 max-w-[420px] truncate" title={e.title}>
                      {e.title}
                    </td>
                    <td className="text-center px-2 py-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-micro ${e.hasSample ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-slate-100 text-slate-400'}`}
                      >
                        {e.hasSample ? 'Y' : 'N'}
                      </span>
                    </td>
                    <td className="text-center px-2 py-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-micro ${e.hasRule ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-slate-100 text-slate-400'}`}
                      >
                        {e.hasRule ? 'Y' : 'N'}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {e.tactic ? (
                        <span className="px-1.5 py-0.5 rounded text-micro bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                          {e.tactic}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <a
              href="https://detection.wiki/microsoft-windows-security-auditing/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              Full Security-Auditing catalog <ExternalLink size={10} />
            </a>
            <span className="text-xs font-mono text-muted">·</span>
            <a
              href="/api/v1/detection-wiki/security-auditing"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-mono text-muted hover:underline inline-flex items-center gap-1"
            >
              API <ExternalLink size={10} />
            </a>
          </div>
        </div>
      )}

      {/* ── Platforms ──────────────────────────────────────────────── */}
      {tab === 'platforms' && (
        <>
          {selectedPlatform ? (
            <div className="space-y-3">
              <button
                onClick={() => setSelectedPlatform(null)}
                className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
              >
                ← Back to platforms
              </button>
              {platformDetailLoading && (
                <p className="text-xs text-muted font-mono py-8 text-center">Loading {selectedPlatform}…</p>
              )}
              {platformDetailError && (
                <p className="text-xs text-rose-600 font-mono py-4">
                  Failed to load {selectedPlatform}: {platformDetailError}
                </p>
              )}
              {platformDetail && (
                <div className="surface-card p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-mono text-base font-bold text-heading">{platformDetail.platform}</h3>
                      <p className="text-xs text-muted">{platformDetail.description}</p>
                      <a
                        href={platformDetail.source}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 mt-1"
                      >
                        {platformDetail.source.replace('https://', '')} <ExternalLink size={10} />
                      </a>
                    </div>
                    <span className="text-xs font-mono px-2 py-1 rounded bg-surface-300">{platformDetail.slug}</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                    <div className="surface-card p-2 text-center">
                      <div className="text-muted">Events</div>
                      <div className="font-bold text-heading">{platformDetail.events.toLocaleString()}</div>
                    </div>
                    <div className="surface-card p-2 text-center">
                      <div className="text-muted">Rules w/ samples</div>
                      <div className="font-bold text-emerald-600">{platformDetail.rulesWithSamples}</div>
                    </div>
                    <div className="surface-card p-2 text-center">
                      <div className="text-muted">Total rules</div>
                      <div className="font-bold">{platformDetail.totalRules ?? '—'}</div>
                    </div>
                  </div>
                  {platformDetail.note && (
                    <p className="text-xs text-muted font-mono bg-surface-200 p-2 rounded">{platformDetail.note}</p>
                  )}
                  <div className="text-xs font-mono text-muted">
                    {platformDetail.sampleCount} sample events{' '}
                    {platformDetail.sampleEvents.length > 0
                      ? `· showing ${Math.min(platformDetail.sampleEvents.length, 5)}`
                      : ''}
                  </div>
                  {platformDetail.sampleEvents.length > 0 && (
                    <div className="overflow-x-auto rounded border border-line-1 max-h-96 overflow-y-auto">
                      <table className="w-full text-xs font-mono">
                        <thead className="bg-surface-200 sticky top-0">
                          <tr>
                            {Object.keys(platformDetail.sampleEvents[0] as Record<string, unknown>)
                              .slice(0, 5)
                              .map((k) => (
                                <th key={k} className="text-left px-2 py-1 text-muted">
                                  {k}
                                </th>
                              ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line-1">
                          {platformDetail.sampleEvents.slice(0, 5).map((ev, i) => (
                            <tr key={i} className="hover:bg-surface-200 dark:hover:bg-surface-200">
                              {Object.values(ev)
                                .slice(0, 5)
                                .map((v, j) => (
                                  <td key={j} className="px-2 py-1 truncate max-w-[180px]">
                                    {String(v)}
                                  </td>
                                ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <a
                    href={`https://detection.wiki/${platformDetail.slug}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
                  >
                    Open {platformDetail.platform} on detection.wiki <ExternalLink size={10} />
                  </a>
                </div>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {filteredPlatforms.map((p) => (
                <button
                  key={p.slug}
                  onClick={() => setSelectedPlatform(p.slug)}
                  className="surface-card p-4 text-left hover:border-brand-500/40 hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors group"
                >
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-mono text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400">
                      {p.name}
                    </h3>
                    <span className="text-micro font-mono text-muted">{p.events.toLocaleString()} events</span>
                  </div>
                  <p className="text-xs text-muted leading-relaxed mb-2">{p.description}</p>
                  <div className="flex gap-3 text-micro font-mono text-muted">
                    <span>{p.rulesWithSamples} rules w/ samples</span>
                    {p.totalRules && <span>· {p.totalRules} total rules</span>}
                  </div>
                  <div className="mt-2 text-micro font-mono text-brand-600 dark:text-brand-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    View details →
                  </div>
                </button>
              ))}
              {filteredPlatforms.length === 0 && (
                <p className="text-xs text-muted font-mono col-span-full text-center py-8">
                  No platforms match "{search}"
                </p>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Labs ───────────────────────────────────────────────────── */}
      {tab === 'labs' && (
        <div className="space-y-3">
          <p className="text-xs text-muted font-mono">
            Hands-on detection analysis labs from detection.wiki. Each lab includes KQL queries, sample data, and
            step-by-step analysis. Per-lab bodies with KQL available via{' '}
            <a
              href="/api/v1/detection-wiki/labs"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              /api/v1/detection-wiki/labs <ExternalLink size={10} />
            </a>{' '}
            and MCP <span className="font-mono bg-surface-300 px-1 py-0.5 rounded">dw_list_labs</span>.
          </p>
          {filteredLabs.map((lab) => (
            <a
              key={lab.slug}
              href={`https://detection.wiki/labs/${lab.slug}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="surface-card p-4 block hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors group"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <FlaskConical size={14} className="text-brand-600 dark:text-brand-400" />
                    <span className="font-mono text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                      {lab.title}
                    </span>
                  </div>
                  <p className="text-xs text-muted leading-relaxed">{lab.description}</p>
                </div>
                <ExternalLink size={12} className="text-muted group-hover:text-brand-500 shrink-0 mt-1" />
              </div>
              <div className="flex flex-wrap gap-1.5 mt-2">
                <span className="text-micro font-mono text-muted">
                  {lab.author} · {lab.date}
                </span>
                {lab.techniques.map((tech) => (
                  <span
                    key={tech}
                    className="text-micro font-mono px-1.5 py-0.5 rounded bg-brand-500/10 text-brand-700 dark:text-brand-300 border border-brand-500/20"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </a>
          ))}
        </div>
      )}

      {/* Source link */}
      <div className="mt-6 text-center">
        <a
          href="https://detection.wiki"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline"
        >
          Open detection.wiki <ExternalLink size={10} />
        </a>
      </div>
    </DataPageLayout>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  accent = 'brand',
}: {
  label: string;
  value: number | string;
  accent?: 'brand' | 'emerald' | 'amber' | 'rose';
}): JSX.Element {
  const color =
    accent === 'emerald'
      ? 'text-emerald-500 dark:text-emerald-400'
      : accent === 'amber'
        ? 'text-amber-500 dark:text-amber-400'
        : accent === 'rose'
          ? 'text-rose-500 dark:text-rose-400'
          : 'text-brand-500 dark:text-brand-400';
  return (
    <div className="surface-card px-3 py-2">
      <div className="text-micro uppercase tracking-wide text-muted font-mono">{label}</div>
      <div className={`font-bold font-mono ${color} text-xl`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
}
