import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef, useEffect } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Textarea } from '../../components/ui/Input';
import {
  Search,
  Loader2,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  FileText,
  Hash,
  Globe,
  Monitor,
  Users,
  Bug,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { adminAuthHeaders } from '../../lib/admin-token';

// ── Types mirroring the backend API ──────────────────────────────────────

type EntityType =
  'actor' | 'ransomware' | 'cve' | 'malware' | 'ip' | 'domain' | 'hash' | 'product' | 'sector' | 'unknown';

interface ResolvedEntity {
  type: EntityType;
  id: string;
  label: string;
  confidence: number;
  aliases: string[];
  source: string;
  context?: Record<string, unknown>;
}

interface EntityLink {
  source_id: string;
  source_type: EntityType;
  target_id: string;
  target_type: EntityType;
  relationship: string;
  confidence: number;
}

interface EntityProfile {
  entity: ResolvedEntity;
  links: EntityLink[];
  techniques?: Array<{ id: string; name: string; tactic: string }>;
  dna_profile?: Record<string, unknown>;
  cves?: string[];
  cross_references: Array<{ source_id: string; source_name: string; label: string }>;
}

type ViewMode = 'resolve' | 'extract';

// Entity types are categorical, not severity - so they use a restrained,
// non-status palette (indigo/violet/teal/sky) grouped by kind, leaving
// rose/amber/emerald free to mean critical/caution/good. Types that share a
// hue are told apart by their icon: adversary (indigo), malicious code
// (violet), vulnerability (teal), and network/file indicators (sky).
const ENTITY_TYPE_CONFIG: Record<string, { label: string; icon: typeof Shield; color: string }> = {
  actor: {
    label: 'Actor',
    icon: Users,
    color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-300',
  },
  ransomware: {
    label: 'Ransomware',
    icon: Bug,
    color: 'bg-violet-100 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300',
  },
  malware: {
    label: 'Malware',
    icon: Bug,
    color: 'bg-violet-100 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300',
  },
  cve: { label: 'CVE', icon: Shield, color: 'bg-teal-100 text-teal-700 dark:bg-teal-500/10 dark:text-teal-300' },
  ip: { label: 'IP', icon: Monitor, color: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300' },
  domain: { label: 'Domain', icon: Globe, color: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300' },
  hash: { label: 'Hash', icon: Hash, color: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300' },
  unknown: {
    label: 'Unknown',
    icon: AlertTriangle,
    color: 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300',
  },
};

function EntityBadge({ type, size = 'sm' }: { type: EntityType; size?: 'sm' | 'md' }) {
  const cfg = (ENTITY_TYPE_CONFIG[type] ?? ENTITY_TYPE_CONFIG.unknown)!;
  const Icon = cfg.icon;
  const s = size === 'sm' ? 'text-micro px-1.5 py-0.5' : 'text-xs px-2 py-1';
  return (
    <span className={`inline-flex items-center gap-1 rounded font-mono font-medium ${s} ${cfg.color}`}>
      <Icon size={size === 'sm' ? 10 : 12} />
      {cfg.label}
    </span>
  );
}

function ConfidenceBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-rose-500';
  return (
    <div className="flex items-center gap-2 text-mini font-mono text-muted">
      <div className="h-1.5 w-16 rounded-full bg-track overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span>{pct}%</span>
    </div>
  );
}

export default function EntityResolution(): JSX.Element {
  const [mode, setMode] = useState<ViewMode>('resolve');
  const [query, setQuery] = useState('');
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [entity, setEntity] = useState<ResolvedEntity | null>(null);
  const [profile, setProfile] = useState<EntityProfile | null>(null);
  const [showFull, setShowFull] = useState(false);
  const [extracted, setExtracted] = useState<ResolvedEntity[]>([]);
  const [relevantPirs, setRelevantPirs] = useState<PirRef[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function fetchRelevantPirs(q: string, signal: AbortSignal) {
    try {
      const res = await fetch(`/api/v1/threat-intel/pirs/relevant?q=${encodeURIComponent(q.trim())}`, {
        headers: adminAuthHeaders(),
        signal,
      });
      if (res.ok) {
        const data = (await res.json()) as { results: PirRef[] };
        setRelevantPirs(data.results);
      }
    } catch (_catchErr) {
      console.error('fetchRelevantPirs failed:', errMessage(_catchErr));
      /* non-fatal */
    }
  }

  interface PirRef {
    id: string;
    title: string;
    priority: string;
    status: string;
    category: string;
    consumer: string;
    matched_in: string[];
  }

  const resolveCtrlRef = useRef<AbortController | null>(null);
  const resolve = async (q: string) => {
    if (!q.trim()) return;
    resolveCtrlRef.current?.abort();
    const ctrl = new AbortController();
    resolveCtrlRef.current = ctrl;
    const signal = AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]);
    setLoading(true);
    setError(null);
    setEntity(null);
    setProfile(null);
    setShowFull(false);
    setRelevantPirs([]);
    try {
      const res = await fetch(`/api/v1/threat-intel/entities/resolve?q=${encodeURIComponent(q.trim())}&full=true`, {
        signal,
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? 'Resolution failed');
      }
      const data = await res.json();
      if (ctrl.signal.aborted) return;
      if (!data.resolved) {
        setError(`No entity found for "${q.trim()}"`);
        return;
      }
      setEntity(data.entity);
      setProfile({
        entity: data.entity,
        links: data.links ?? [],
        techniques: data.techniques,
        dna_profile: data.dna_profile,
        cves: data.cves,
        cross_references: data.cross_references ?? [],
      });
      fetchRelevantPirs(q.trim(), signal);
    } catch (e) {
      logCatch(e);
      if ((e as Error).name === 'AbortError') return;
      setError(errMessage(e));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  };

  const extractCtrlRef = useRef<AbortController | null>(null);
  const extract = async () => {
    if (!text.trim()) return;
    extractCtrlRef.current?.abort();
    const ctrl = new AbortController();
    extractCtrlRef.current = ctrl;
    setLoading(true);
    setError(null);
    setExtracted([]);
    try {
      const res = await fetch('/api/v1/threat-intel/entities/extract', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: text.trim() }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30000)]),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error ?? 'Extraction failed');
      }
      const data = await res.json();
      if (!ctrl.signal.aborted) setExtracted(data.entities ?? []);
    } catch (e) {
      logCatch(e);
      if ((e as Error).name === 'AbortError') return;
      setError(errMessage(e));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === 'resolve') resolve(query);
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Search size={28} />}
      title="Entity Resolution"
      description="Resolve threat actor names, ransomware groups, CVEs, IPs, domains, and hashes against a 500+ entry alias index with heuristic NVD/KEV actor scanning."
      maxWidthClass="max-w-4xl"
    >
      {/* Mode toggle */}
      <div className="flex gap-1 mb-6 p-0.5 rounded-xl bg-surface-300 w-fit">
        <button
          type="button"
          onClick={() => setMode('resolve')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors ${
            mode === 'resolve'
              ? 'bg-white dark:bg-surface-300 text-heading shadow-e1'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
          }`}
        >
          Resolve entity
        </button>
        <button
          type="button"
          onClick={() => setMode('extract')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors ${
            mode === 'extract'
              ? 'bg-white dark:bg-surface-300 text-heading shadow-e1'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
          }`}
        >
          Extract from text
        </button>
      </div>

      {mode === 'resolve' ? (
        <>
          <form onSubmit={handleSubmit} className="mb-8">
            <div className="relative">
              <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. LockBit, CVE-2024-1709, 8.8.8.8, Scattered Spider, 185.234.72.0"
                className="w-full rounded-xl border border-line-1 bg-surface-100 py-2.5 pl-9 pr-20 font-mono text-tool text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/20 dark:placeholder:text-muted"
              />
              <button
                type="submit"
                disabled={loading || !query.trim()}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded px-3 py-1 text-mini font-mono font-medium bg-rose-600 text-on-fill hover:bg-rose-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? <Loader2 size={14} className="animate-spin" /> : 'Resolve'}
              </button>
            </div>
          </form>

          {error && (
            <div className="mb-6 rounded-xl border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950 p-4 text-sm text-rose-700 dark:text-rose-300 font-mono">
              {error}
            </div>
          )}

          {entity && (
            <div className="space-y-4 animate-fade-in-up">
              {/* Entity header */}
              <div className="surface-card p-5">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <EntityBadge type={entity.type} size="md" />
                      <span className="text-micro font-mono text-muted">
                        source: {entity.source.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <h2 className="font-display font-bold text-xl text-heading">{entity.label}</h2>
                    <p className="font-mono text-meta text-muted mt-0.5">{entity.id}</p>
                  </div>
                  <ConfidenceBar score={entity.confidence} />
                </div>

                {entity.aliases.length > 0 && (
                  <div className="mt-3">
                    <span className="text-mini font-mono font-medium text-muted uppercase tracking-wider">Aliases</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {entity.aliases.map((a) => (
                        <span
                          key={a}
                          className="rounded border border-line-1 px-2 py-0.5 text-mini font-mono text-muted"
                        >
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {entity.context && Object.keys(entity.context).length > 0 && (
                  <div className="mt-3">
                    <span className="text-mini font-mono font-medium text-muted uppercase tracking-wider">Context</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {Object.entries(entity.context).map(([k, v]) => (
                        <span
                          key={k}
                          className="rounded border border-line-1 px-2 py-0.5 text-mini font-mono text-muted"
                        >
                          {k}={Array.isArray(v) ? v.join(', ') : String(v)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-2">
                  <button
                    type="button"
                    onClick={() => setShowFull(!showFull)}
                    className="inline-flex items-center gap-1 text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline"
                  >
                    {showFull ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    {showFull ? 'Hide full profile' : 'Show full profile'}
                  </button>
                </div>

                {/* PIR relevance */}
                {relevantPirs.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-line-1">
                    <p className="text-micro font-mono font-semibold text-muted uppercase tracking-wider mb-2">
                      Relevant PIRs ({relevantPirs.length})
                    </p>
                    <div className="space-y-1.5">
                      {relevantPirs.map((pir) => (
                        <a
                          key={pir.id}
                          href={`/threatintel/pir-dashboard`}
                          className="flex items-center gap-2 text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                        >
                          <span
                            className={`px-1 py-0.5 rounded text-micro uppercase ${
                              pir.priority === 'critical'
                                ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300'
                                : pir.priority === 'high'
                                  ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                                  : 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted'
                            }`}
                          >
                            {pir.priority}
                          </span>
                          <span className="flex-1 truncate">{pir.title}</span>
                          <span className="text-micro text-muted">{pir.matched_in.join(', ')}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Full profile (conditionally shown) */}
              {showFull && profile && (
                <>
                  {/* Cross-references */}
                  {profile.cross_references.length > 0 && (
                    <div className="surface-card p-5">
                      <h3 className="text-xs font-mono font-semibold text-muted uppercase tracking-wider mb-3">
                        Cross-references
                      </h3>
                      <div className="grid gap-2">
                        {profile.cross_references.map((ref) => (
                          <div key={ref.source_id} className="flex items-center gap-2 text-meta font-mono">
                            <ExternalLink size={12} className="text-muted shrink-0" />
                            <span className="text-muted">{ref.source_name}:</span>
                            <span className="text-heading">{ref.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* CVEs */}
                  {profile.cves && profile.cves.length > 0 && (
                    <div className="surface-card p-5">
                      <h3 className="text-xs font-mono font-semibold text-muted uppercase tracking-wider mb-3">
                        Linked CVEs ({profile.cves.length})
                      </h3>
                      <div className="flex flex-wrap gap-1.5">
                        {profile.cves.map((cve) => (
                          <span
                            key={cve}
                            className="rounded border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-950 px-2 py-0.5 text-mini font-mono text-amber-700 dark:text-amber-300"
                          >
                            {cve}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Links */}
                  {profile.links.length > 0 && (
                    <div className="surface-card p-5">
                      <h3 className="text-xs font-mono font-semibold text-muted uppercase tracking-wider mb-3">
                        Relationships ({profile.links.length})
                      </h3>
                      <div className="grid gap-2">
                        {profile.links.map((link, i) => (
                          <div key={i} className="flex items-center gap-2 text-meta font-mono">
                            <EntityBadge type={link.source_type} />
                            <span className="text-muted text-mini">{link.relationship.replace(/_/g, ' ')}</span>
                            <EntityBadge type={link.target_type} />
                            <span className="text-heading">{link.target_id}</span>
                            <ConfidenceBar score={link.confidence} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </>
      ) : (
        <>
          <div className="mb-8">
            <label
              htmlFor="extract-text"
              className="block mb-2 text-xs font-mono font-semibold text-muted uppercase tracking-wider"
            >
              Paste text to extract entities
            </label>
            <Textarea
              id="extract-text"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={6}
              placeholder="Paste a threat report, blog post, or any text containing CVE IDs, threat actor names, ransomware group references, IPs, domains, or hashes..."
              className="w-full"
              mono={false}
            />
            <div className="flex justify-end mt-2">
              <button
                type="button"
                onClick={() => void extract()}
                disabled={loading || !text.trim()}
                className="inline-flex items-center gap-1.5 rounded px-4 py-1.5 text-mini font-mono font-medium bg-rose-600 text-on-fill hover:bg-rose-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? <Loader2 size={14} className="animate-spin" /> : <FileText size={14} />}
                {loading ? 'Extracting...' : 'Extract entities'}
              </button>
            </div>
          </div>

          {error && (
            <div className="mb-6 rounded-xl border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950 p-4 text-sm text-rose-700 dark:text-rose-300 font-mono">
              {error}
            </div>
          )}

          {extracted.length > 0 && (
            <div className="animate-fade-in-up">
              <p className="text-xs font-mono text-muted mb-3">
                Found {extracted.length} entit{extracted.length === 1 ? 'y' : 'ies'}
              </p>
              <div className="grid gap-2">
                {extracted.map((e) => {
                  const cfg = (ENTITY_TYPE_CONFIG[e.type] ?? ENTITY_TYPE_CONFIG.unknown)!;
                  const Icon = cfg.icon;
                  return (
                    <div key={e.id} className="surface-card p-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Icon size={16} className="text-muted shrink-0" />
                        <div>
                          <div className="flex items-center gap-2 mb-0.5">
                            <EntityBadge type={e.type} />
                            <span className="font-mono font-medium text-sm text-heading">{e.label}</span>
                          </div>
                          <span className="font-mono text-mini text-muted">{e.id}</span>
                        </div>
                      </div>
                      <ConfidenceBar score={e.confidence} />
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {!loading && text && extracted.length === 0 && !error && (
            <div className="rounded-xl border border-dashed border-line-2 p-8 text-center text-tool text-muted font-mono">
              No entities found in the provided text. Try pasting something with CVE IDs, actor names, IPs, domains, or
              hashes.
            </div>
          )}
        </>
      )}
    </DataPageLayout>
  );
}
