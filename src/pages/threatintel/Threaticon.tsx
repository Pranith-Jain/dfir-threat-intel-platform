import { useEffect, useMemo, useRef, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { Bug, Check, Copy, Crosshair, ExternalLink, Globe, Map as MapIcon, Search, Skull, Target } from 'lucide-react';
import { errMessage } from '../../lib/log';

/* ------------------------------------------------------------------ */
/*  Types (mirror the API JSON)                                        */
/* ------------------------------------------------------------------ */

type TabId = 'actors' | 'malware' | 'coverage' | 'map';

interface TiIndex {
  source: string;
  url: string;
  description: string;
  syncedAt: string;
  builtAt: string;
  counts: {
    actors: number;
    actorsWithProfiles: number;
    malwareFamilies: number;
    malwareCategories: number;
    techniques: number;
    tactics: number;
    originCountries: number;
    targetedCountries: number;
    sectors: number;
  };
  tactics: Record<string, { techniqueCount: number; coveragePct: number }>;
}

interface TiActor {
  slug: string;
  id: number;
  name: string;
  mitreId: string | null;
  status: string | null;
  tlp: string | null;
  confidence: number | null;
  types: string[];
  originCode: string | null;
  countryOfOrigin: string | null;
  techniquesCount: number;
  toolsCount: number;
  targetedCountriesCount: number;
  tagsCount: number;
  added: string | null;
}

interface TiActorDetail extends TiActor {
  sophistication: string | null;
  resourceLevel: string | null;
  motivation: string | null;
  tags: string[];
  aliases: string[];
  targetedSectors: string[];
  targetedCountries: string[];
  tactics: string[];
  techniques: string[];
  tools: string[];
  iocPatterns: string[];
  keyCapabilities: string[];
  recommendedActions: string[];
  campaignsText: string | null;
  description: string | null;
  goals: string | null;
  killChain: string | null;
  sourceUrl: string;
}

interface TiMalwareFamily {
  id: number;
  name: string;
  category: string | null;
  tlp: string | null;
  confidence: number | null;
  status: string | null;
}

interface TiCoverageTechnique {
  patternId: number;
  techniqueId: string;
  name: string;
  tactic: string;
  rules: number;
}

interface TiMapEntry {
  code: string;
  count: number;
}

interface TiMapBody {
  builtAt: string;
  origin: TiMapEntry[];
  targeted: TiMapEntry[];
  sectors: { sector: string; count: number }[];
}

/* ------------------------------------------------------------------ */
/*  Shared bits                                                        */
/* ------------------------------------------------------------------ */

const TABS: { id: TabId; label: string; icon: typeof Globe }[] = [
  { id: 'actors', label: 'Threat Actors', icon: Skull },
  { id: 'malware', label: 'Malware', icon: Bug },
  { id: 'coverage', label: 'Detection Coverage', icon: Crosshair },
  { id: 'map', label: 'Threat Map', icon: MapIcon },
];

const TLP_STYLES: Record<string, string> = {
  red: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  amber: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  green: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  white: 'border-slate-300 dark:border-line-1 text-slate-500',
};

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
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

function Confidence({ value }: { value: number | null }) {
  if (value == null) return null;
  return (
    <div className="flex items-center gap-1.5 text-mini text-muted font-mono">
      <div className="w-14 h-1.5 rounded-full bg-track dark:bg-surface-100/10 overflow-hidden">
        <div
          className={`h-full rounded-full ${value >= 70 ? 'bg-emerald-500' : value >= 40 ? 'bg-amber-500' : 'bg-rose-500'}`}
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      </div>
      <span>{value}%</span>
    </div>
  );
}

function ActorCard({ item, copied, onCopy }: { item: TiActor; copied: boolean; onCopy: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="group rounded-xl border border-line-1 bg-surface-100/50 p-4 open:border-rose-500/30"
      open={open}
      onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}
    >
      <summary className="cursor-pointer list-none">
        <div className="flex items-start justify-between gap-2 mb-1.5">
          <div className="min-w-0">
            <h3 className="text-sm font-bold text-heading leading-snug">{item.name}</h3>
            {item.mitreId && (
              <span className="text-mini font-mono text-muted">
                <a
                  href={sanitizeUrl(`https://attack.mitre.org/groups/${item.mitreId}/`) ?? undefined}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="text-sky-600 dark:text-sky-400 hover:underline inline-flex items-center gap-0.5"
                  onClick={(e) => e.stopPropagation()}
                >
                  {item.mitreId}
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            {item.status && (
              <Badge
                cls={
                  item.status.toLowerCase() === 'active'
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-300 dark:border-line-1 text-slate-500'
                }
              >
                {item.status}
              </Badge>
            )}
            {item.tlp && (
              <Badge cls={TLP_STYLES[item.tlp.toLowerCase()] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}>
                {item.tlp.toUpperCase()}
              </Badge>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
          {item.types.slice(0, 3).map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-violet-500/10 text-violet-700 dark:text-violet-300"
            >
              {t}
            </span>
          ))}
          {item.originCode && (
            <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
              {item.countryOfOrigin ?? item.originCode}
            </span>
          )}
          <Confidence value={item.confidence} />
        </div>
        <p className="text-mini text-muted mt-1.5 font-mono">
          {item.techniquesCount} techniques · {item.toolsCount} tools · {item.targetedCountriesCount} countries
        </p>
        <span className="inline-block font-mono text-micro text-muted group-open:text-rose-500 mt-1">profile</span>
      </summary>
      {open && <ActorDetailBody slug={item.slug} onCopy={onCopy} copied={copied} />}
    </details>
  );
}

function ActorDetailBody({ slug, onCopy, copied }: { slug: string; onCopy: () => void; copied: boolean }) {
  const { body, loading } = useDetail<TiActorDetail>(`/api/v1/threat-intel/threaticon/actors/${slug}`);
  if (loading) return <p className="text-mini text-muted font-mono mt-3">loading profile…</p>;
  if (!body)
    return <p className="text-mini text-muted font-mono mt-3">profile unavailable (is the sync build done?)</p>;
  return (
    <div className="mt-3 pt-3 border-t border-line-1 space-y-3 text-sm">
      {body.description && <p className="text-body leading-relaxed">{body.description}</p>}
      <PostAnalysisButton
        title={body.name}
        description={`${body.description ?? ''}\n\nsophistication: ${body.sophistication ?? 'n/a'} · motivation: ${body.motivation ?? 'n/a'} · sectors: ${body.targetedSectors.join(', ') || 'n/a'}\nCapabilities: ${body.keyCapabilities.join('; ') || 'n/a'}\nRecommended actions: ${body.recommendedActions.join('; ') || 'n/a'}`}
        source="threaticon.com"
        compact
      />
      {body.goals && (
        <p className="text-xs text-muted leading-relaxed">
          <span className="font-mono text-muted">goals: </span>
          {body.goals}
        </p>
      )}
      <div className="grid sm:grid-cols-2 gap-2 text-mini font-mono text-muted">
        <div>sophistication: {body.sophistication ?? '—'}</div>
        <div>resource level: {body.resourceLevel ?? '—'}</div>
        <div>motivation: {body.motivation ?? '—'}</div>
        <div>added: {body.added ?? '—'}</div>
      </div>
      {body.aliases.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">aliases:</span>
          {body.aliases.map((a) => (
            <span
              key={a}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body"
            >
              {a}
            </span>
          ))}
        </div>
      )}
      {body.tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">tags:</span>
          {body.tags.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-violet-500/10 text-violet-700 dark:text-violet-300"
            >
              {t}
            </span>
          ))}
        </div>
      )}
      {body.targetedSectors.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">sectors:</span>
          {body.targetedSectors.map((s) => (
            <span
              key={s}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-amber-500/10 text-amber-700 dark:text-amber-300"
            >
              {s}
            </span>
          ))}
        </div>
      )}
      {body.targetedCountries.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">targeted:</span>
          {body.targetedCountries.map((c) => (
            <span
              key={c}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-sky-500/10 text-sky-700 dark:text-sky-300"
            >
              {c}
            </span>
          ))}
        </div>
      )}
      {body.tactics.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">tactics:</span>
          {body.tactics.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-rose-500/10 text-rose-700 dark:text-rose-300"
            >
              {t}
            </span>
          ))}
        </div>
      )}
      {body.techniques.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">techniques:</span>
          {body.techniques.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body"
            >
              {t}
            </span>
          ))}
        </div>
      )}
      {body.tools.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini text-muted font-mono mr-1">tools:</span>
          {body.tools.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 text-micro font-mono rounded bg-orange-500/10 text-orange-700 dark:text-orange-300"
            >
              {t}
            </span>
          ))}
        </div>
      )}
      {body.iocPatterns.length > 0 && (
        <div className="text-mini text-muted font-mono">
          <div className="mb-1 text-muted">IOC patterns:</div>
          <div className="flex flex-wrap gap-1.5">
            {body.iocPatterns.map((p) => (
              <span
                key={p}
                className="px-1.5 py-0.5 rounded bg-surface-300 dark:bg-surface-100/5 text-body font-mono text-micro break-all"
              >
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
      {body.keyCapabilities.length > 0 && (
        <ul className="list-disc pl-4 text-xs text-body space-y-0.5">
          {body.keyCapabilities.map((k) => (
            <li key={k}>{k}</li>
          ))}
        </ul>
      )}
      {body.campaignsText && (
        <p className="text-xs text-muted leading-relaxed">
          <span className="font-mono text-muted">campaigns: </span>
          {body.campaignsText}
        </p>
      )}
      {body.recommendedActions.length > 0 && (
        <ul className="list-disc pl-4 text-xs text-body space-y-0.5">
          {body.recommendedActions.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-2 text-mini">
        <button
          onClick={onCopy}
          className="inline-flex items-center gap-1 px-2 py-1 rounded text-micro font-mono border border-line-1 text-muted hover:border-rose-500/30 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          title="Copy source URL"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied!' : 'Copy source URL'}
        </button>
        <a
          href={sanitizeUrl(body.sourceUrl) ?? undefined}
          target="_blank"
          rel="noopener noreferrer nofollow"
          className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
        >
          threaticon.com profile
          <ExternalLink className="w-2.5 h-2.5" />
        </a>
        {body.killChain && (
          <a
            href={sanitizeUrl(`https://threaticon.com${body.killChain}`) ?? undefined}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
          >
            kill-chain graph
            <ExternalLink className="w-2.5 h-2.5" />
          </a>
        )}
      </div>
    </div>
  );
}

function MalwareCard({ fam }: { fam: TiMalwareFamily }) {
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <h3 className="font-mono text-sm font-semibold text-heading truncate">{fam.name}</h3>
        {fam.tlp && (
          <Badge cls={TLP_STYLES[fam.tlp.toLowerCase()] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}>
            {fam.tlp.toUpperCase()}
          </Badge>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {fam.category && (
          <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-rose-500/10 text-rose-700 dark:text-rose-300">
            {fam.category}
          </span>
        )}
        {fam.status && (
          <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
            {fam.status}
          </span>
        )}
        <Confidence value={fam.confidence} />
      </div>
      <PostAnalysisButton
        title={`${fam.name} malware family`}
        description={`Malware family: ${fam.name}${fam.category ? ` (${fam.category})` : ''}${fam.status ? `, status: ${fam.status}` : ''}${fam.tlp ? `, TLP: ${fam.tlp}` : ''}. Confidence: ${fam.confidence ?? 'n/a'}.`}
        source="threaticon.com"
        compact
      />
    </div>
  );
}

function CoverageCard({ tech }: { tech: TiCoverageTechnique }) {
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <h3 className="font-mono text-sm font-semibold text-heading">{tech.techniqueId}</h3>
        <Badge cls="border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 shrink-0">
          {tech.rules} rules
        </Badge>
      </div>
      <p className="text-sm text-body leading-snug">{tech.name}</p>
      <p className="text-mini text-muted mt-1 font-mono">{tech.tactic}</p>
      <PostAnalysisButton
        title={`${tech.techniqueId} — ${tech.name}`}
        description={`MITRE technique ${tech.techniqueId} (${tech.name}) in tactic ${tech.tactic}. ${tech.rules} detection rules mapped.`}
        source="threaticon.com"
        compact
      />
    </div>
  );
}

function CountryList({ title, entries, tone }: { title: string; entries: TiMapEntry[]; tone: string }) {
  const max = Math.max(1, ...entries.map((e) => e.count));
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <h3 className="text-sm font-bold text-heading mb-3">{title}</h3>
      <div className="space-y-1.5">
        {entries.length === 0 && <p className="text-mini text-muted font-mono">no data</p>}
        {entries.map((e) => (
          <div key={e.code} className="flex items-center gap-2">
            <span className="font-mono text-mini text-muted w-8 shrink-0">{e.code}</span>
            <div className="flex-1 h-2 rounded-full bg-surface-300 dark:bg-surface-100/5 overflow-hidden">
              <div
                className={`h-full rounded-full ${tone}`}
                style={{ width: `${Math.round((e.count / max) * 100)}%` }}
              />
            </div>
            <span className="font-mono text-mini text-muted w-10 text-right shrink-0">{e.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SectorList({ sectors }: { sectors: { sector: string; count: number }[] }) {
  const max = Math.max(1, ...sectors.map((s) => s.count));
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
      <h3 className="text-sm font-bold text-heading mb-3">Targeted Sectors</h3>
      <div className="space-y-1.5">
        {sectors.length === 0 && <p className="text-mini text-muted font-mono">no data</p>}
        {sectors.map((s) => (
          <div key={s.sector} className="flex items-center gap-2">
            <span className="text-mini text-body flex-1 truncate">{s.sector}</span>
            <div className="w-24 h-2 rounded-full bg-surface-300 dark:bg-surface-100/5 overflow-hidden">
              <div
                className="h-full rounded-full bg-violet-500"
                style={{ width: `${Math.round((s.count / max) * 100)}%` }}
              />
            </div>
            <span className="font-mono text-mini text-muted w-10 text-right shrink-0">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Page                                                               */
/* ------------------------------------------------------------------ */

export default function ThreaticonFeeds() {
  const [idx, setIdx] = useState<TiIndex | null>(null);
  const [tab, setTab] = useState<TabId>('actors');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [actors, setActors] = useState<TiActor[]>([]);
  const [families, setFamilies] = useState<TiMalwareFamily[]>([]);
  const [coverage, setCoverage] = useState<TiCoverageTechnique[]>([]);
  const [mapBody, setMapBody] = useState<TiMapBody | null>(null);

  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [countryFilter, setCountryFilter] = useState('all');
  const [tlpFilter, setTlpFilter] = useState('all');
  const [hasMitre, setHasMitre] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [tacticFilter, setTacticFilter] = useState('all');
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/threaticon');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setIdx((await res.json()) as TiIndex);
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
    const base = '/api/v1/threat-intel/threaticon';
    const endpoint =
      tab === 'actors'
        ? `${base}/actors?limit=1000`
        : tab === 'malware'
          ? `${base}/malware?limit=10000`
          : tab === 'coverage'
            ? `${base}/coverage?limit=5000`
            : `${base}/map`;
    (async () => {
      try {
        const r = await fetch(endpoint);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const json = (await r.json()) as Record<string, unknown>;
        if (tab === 'actors') setActors((json.actors as TiActor[]) ?? []);
        else if (tab === 'malware') setFamilies((json.families as TiMalwareFamily[]) ?? []);
        else if (tab === 'coverage') setCoverage((json.techniques as TiCoverageTechnique[]) ?? []);
        else if (tab === 'map') setMapBody(json as unknown as TiMapBody);
      } catch {
        // Allow a retry on the next visit — memoizing a FAILED load made one
        // transient 500 show an empty tab forever (map tab rendered nothing).
        loadedTabs.current.delete(tab);
      }
    })();
  }, [tab]);

  const actorTypes = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of actors) for (const t of a.types) m.set(t, (m.get(t) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  }, [actors]);

  const actorCountries = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of actors) if (a.originCode) m.set(a.originCode, (m.get(a.originCode) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [actors]);

  const malwareCategories = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of families) if (f.category) m.set(f.category, (m.get(f.category) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [families]);

  const coverageTactics = useMemo(() => {
    const m = new Map<string, number>();
    for (const t of coverage) m.set(t.tactic, (m.get(t.tactic) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [coverage]);

  const filteredActors = useMemo(() => {
    const n = query.toLowerCase().trim();
    return actors.filter((a) => {
      if (typeFilter !== 'all' && !a.types.some((t) => t.toLowerCase().includes(typeFilter.toLowerCase())))
        return false;
      if (countryFilter !== 'all' && a.originCode?.toLowerCase() !== countryFilter) return false;
      if (tlpFilter !== 'all' && a.tlp?.toLowerCase() !== tlpFilter) return false;
      if (hasMitre && !a.mitreId) return false;
      if (n && !`${a.name} ${a.mitreId ?? ''} ${a.countryOfOrigin ?? ''}`.toLowerCase().includes(n)) return false;
      return true;
    });
  }, [actors, query, typeFilter, countryFilter, tlpFilter, hasMitre]);

  const filteredFamilies = useMemo(() => {
    const n = query.toLowerCase().trim();
    return families.filter((f) => {
      if (categoryFilter !== 'all' && f.category?.toLowerCase() !== categoryFilter) return false;
      if (n && !`${f.name} ${f.category ?? ''}`.toLowerCase().includes(n)) return false;
      return true;
    });
  }, [families, query, categoryFilter]);

  const filteredCoverage = useMemo(() => {
    const n = query.toLowerCase().trim();
    return coverage.filter((t) => {
      if (tacticFilter !== 'all' && t.tactic.toLowerCase() !== tacticFilter) return false;
      if (n && !`${t.techniqueId} ${t.name}`.toLowerCase().includes(n)) return false;
      return true;
    });
  }, [coverage, query, tacticFilter]);

  async function copyText(slug: string) {
    const a = actors.find((x) => x.slug === slug);
    if (!a) return;
    try {
      await navigator.clipboard.writeText(`https://threaticon.com/threat-actors/${a.id}`);
      setCopied(slug);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  const COUNT_KEY: Record<'actors' | 'malware' | 'coverage' | 'map', keyof TiIndex['counts']> = {
    actors: 'actors',
    malware: 'malwareFamilies',
    coverage: 'techniques',
    map: 'targetedCountries',
  };

  const summaryItems = useMemo(() => {
    const source = 'threaticon.com';
    const tabLabel = TABS.find((t) => t.id === tab)?.label ?? tab;
    const items =
      tab === 'actors'
        ? filteredActors.slice(0, 30).map((a) => ({
            title: a.name,
            body: `types: ${a.types.join(', ') || 'unknown'} · origin: ${a.countryOfOrigin ?? 'unknown'} · ${a.status ?? 'no status'}`,
            source,
          }))
        : tab === 'malware'
          ? filteredFamilies.slice(0, 30).map((f) => ({
              title: f.name,
              body: `category: ${f.category ?? 'unknown'} · confidence: ${f.confidence ?? 'n/a'}%`,
              source,
            }))
          : tab === 'coverage'
            ? filteredCoverage.slice(0, 30).map((t) => ({
                title: `${t.techniqueId} — ${t.name}`,
                body: `tactic: ${t.tactic} · ${t.rules} detection rules`,
                source,
              }))
            : [];
    return { surface: `Threaticon · ${tabLabel}`, items };
  }, [tab, filteredActors, filteredFamilies, filteredCoverage]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<Target size={28} />}
      title="Threaticon"
      description={
        <>
          Replicated threat-intel platform from{' '}
          <a
            href="https://threaticon.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            threaticon.com
          </a>
          — a STIX 2.1 actor catalog, malware family dictionary, ATT&CK detection-coverage dataset, and a country-level
          threat map. (The extended public-preview catalog — campaigns, attack patterns, controls — was removed
          2026-09-13 to stay under the Workers 20k static-asset cap.) controls, and a 480k IOC dictionary.
        </>
      }
      loading={loading && !idx}
      error={error}
      onRetry={load}
    >
      {idx && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-5">
            {[
              { label: 'Actors', value: idx.counts.actors, cls: 'text-rose-600 dark:text-rose-400' },
              {
                label: 'Malware families',
                value: idx.counts.malwareFamilies,
                cls: 'text-amber-600 dark:text-amber-400',
              },
              { label: 'Techniques', value: idx.counts.techniques, cls: 'text-orange-600 dark:text-orange-400' },
              { label: 'Tactics', value: idx.counts.tactics, cls: 'text-violet-600 dark:text-violet-400' },
              { label: 'Origins', value: idx.counts.originCountries, cls: 'text-sky-600 dark:text-sky-400' },
              { label: 'Targeted countries', value: idx.counts.targetedCountries, cls: 'text-slate-500' },
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
              const count = idx.counts[COUNT_KEY[t.id as keyof typeof COUNT_KEY]];
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
                  {count != null && <span className="opacity-60">{count}</span>}
                </button>
              );
            })}
          </div>

          {/* Top-level AI threat analysis for the active tab */}
          {summaryItems.items.length > 0 && (
            <div className="mb-4">
              <PostAnalysisButton
                title={`Threaticon ${tab.charAt(0).toUpperCase() + tab.slice(1)} Digest \u2014 ${summaryItems.items.length} items`}
                description={summaryItems.items
                  .slice(0, 20)
                  .map((it) => `${it.title}: ${it.body}`)
                  .join('\n')}
                source="threaticon.com"
              />
            </div>
          )}

          {/* AI summary of the active tab */}
          {summaryItems.items.length > 0 && (
            <AiSummaryCard surface={summaryItems.surface} items={summaryItems.items} requireAdmin={false} />
          )}

          {/* Actors tab */}
          {tab === 'actors' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuery} placeholder="Search actors (name, MITRE ID, country)…" />
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All types</option>
                  {actorTypes.map(([t, n]) => (
                    <option key={t} value={t}>
                      {t} ({n})
                    </option>
                  ))}
                </select>
                <select
                  value={countryFilter}
                  onChange={(e) => setCountryFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All origins</option>
                  {actorCountries.map(([c, n]) => (
                    <option key={c} value={c}>
                      {c} ({n})
                    </option>
                  ))}
                </select>
                <select
                  value={tlpFilter}
                  onChange={(e) => setTlpFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All TLP</option>
                  {['red', 'amber', 'green', 'white'].map((t) => (
                    <option key={t} value={t}>
                      {t.toUpperCase()}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => setHasMitre((v) => !v)}
                  className={`px-3 py-2 rounded-xl text-sm font-mono border transition ${
                    hasMitre
                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                      : 'border-line-1 text-slate-500 hover:border-rose-500/30'
                  }`}
                >
                  MITRE only
                </button>
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredActors.length} of {actors.length} actors · STIX 2.1 catalog replicated from
                threaticon.com
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredActors.map((a) => (
                  <ActorCard key={a.slug} item={a} copied={copied === a.slug} onCopy={() => copyText(a.slug)} />
                ))}
              </div>
            </>
          )}

          {/* Malware tab */}
          {tab === 'malware' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuery} placeholder="Search malware families…" />
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All categories</option>
                  {malwareCategories.map(([c, n]) => (
                    <option key={c} value={c}>
                      {c} ({n})
                    </option>
                  ))}
                </select>
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredFamilies.length} of {families.length} malware families · the Threaticon catalog doubles
                as the entity-extraction dictionary for ThreatCluster-derived profiles
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredFamilies.map((f) => (
                  <MalwareCard key={f.id} fam={f} />
                ))}
              </div>
            </>
          )}

          {/* Coverage tab */}
          {tab === 'coverage' && (
            <>
              <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <SearchBox query={query} setQuery={setQuery} placeholder="Search techniques (T-number, name)…" />
                <select
                  value={tacticFilter}
                  onChange={(e) => setTacticFilter(e.target.value)}
                  className="px-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading focus:outline-none focus:border-rose-500"
                >
                  <option value="all">All tactics</option>
                  {coverageTactics.map(([t, n]) => (
                    <option key={t} value={t}>
                      {t} ({n})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-wrap gap-1.5 mb-3">
                {Object.entries(idx.tactics ?? {}).map(([tactic, meta]) => (
                  <span
                    key={tactic}
                    className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-1 text-muted"
                    title={`${meta.techniqueCount} techniques · ${meta.coveragePct}% covered`}
                  >
                    {tactic} {meta.coveragePct}%
                  </span>
                ))}
              </div>
              <div className="text-xs text-muted font-mono mb-3">
                Showing {filteredCoverage.length} of {coverage.length} techniques · every technique the platform ships
                detection content for, with rule counts
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {filteredCoverage.map((t) => (
                  <CoverageCard key={t.patternId} tech={t} />
                ))}
              </div>
            </>
          )}

          {/* Map tab */}
          {tab === 'map' && mapBody && (
            <>
              <div className="text-xs text-muted font-mono mb-3">
                Country-level attribution derived from {actors.length} actor profiles · built {fmtDate(mapBody.builtAt)}
              </div>
              <div className="grid gap-2 lg:grid-cols-2 mb-4">
                <CountryList title="Actor origins" entries={mapBody.origin} tone="bg-rose-500" />
                <CountryList title="Targeted countries" entries={mapBody.targeted} tone="bg-sky-500" />
              </div>
              <SectorList sectors={mapBody.sectors} />
            </>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: threaticon.com · catalog replicated on the threat-intel sync cadence
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
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(path);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const json = (await r.json()) as T;
        if (!cancelled) setBody(json);
      } catch {
        if (!cancelled) setBody(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [path]);
  return { body, loading };
}
