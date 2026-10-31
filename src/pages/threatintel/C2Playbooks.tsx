import { useEffect, useMemo, useState } from 'react';
import { Check, Copy, ExternalLink, Fingerprint, Lock, Radar, Search, Telescope } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { fetchJsonCached, api } from '../../lib/api-client';

// ─── Manifest shapes (public/data/c2-playbooks/, build-time snapshot) ───

interface C2PlaybookEntry {
  id: string;
  family: string;
  category: string;
  technique: string;
  engine: string;
  query: string;
  externalUrl: string;
  notes?: string;
  hash?: string;
}

interface C2PlaybooksIndex {
  source: string;
  license: string;
  portedFrom: string;
  builtAt: string;
  counts: { entries: number; engines: number; categories: number; families: number };
  engines: Record<string, number>;
  categories: Record<string, number>;
  topFamilies: { family: string; count: number }[];
  faviconHashes: { family: string; hash: string }[];
  jarmHashes: { family: string; hash: string }[];
}

interface EngineSection {
  engine: string;
  count: number;
  entries: C2PlaybookEntry[];
}

const ENGINE_COLORS: Record<string, string> = {
  shodan: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
  urlscan: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30',
  censys: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30',
  netlas: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30',
  fofa: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
  zoomeye: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
  etugen: 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30',
  silentpush: 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30',
  validin: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30',
};

const CATEGORY_COLORS: Record<string, string> = {
  'C2 Framework': 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
  'Info Stealer': 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
  RAT: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30',
  'Favicon Fingerprint': 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30',
  'APT Infrastructure': 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30',
  'Phishing Framework': 'bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30',
  Botnet: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30',
};

function categoryColor(category: string): string {
  return CATEGORY_COLORS[category] ?? 'bg-slate-500/15 text-muted border-slate-500/30';
}

type FingerprintKind = 'favicon-mmh3' | 'jarm' | 'sha256';

/** Detect the fingerprint type the way api/src/lib/c2-playbooks-manifest.ts does. */
function detectFingerprint(value: string): FingerprintKind | null {
  const v = value.trim();
  if (!v) return null;
  if (/^-?\d{1,10}$/.test(v)) return 'favicon-mmh3';
  const hex = v.toLowerCase();
  if (/^[a-f\d]{62}$/.test(hex)) return 'jarm';
  if (/^[a-f\d]{64}$/.test(hex)) return 'sha256';
  return null;
}

interface FpResult {
  kind: FingerprintKind;
  families: string[];
}

// ─── Seed hunt planner (GET /api/v1/mantis-hunt/preview) ────────────────────

interface HuntFeatureRow {
  kind: string;
  value: string;
  weight: number;
}

interface HuntQuery {
  provider: string;
  query: string;
  mode: string;
  external_url: string;
  estimated_strength: number;
  signals: { kind: string; value: string }[];
  notes?: string;
}

interface HuntSignature {
  slug: string;
  name: string;
  family: string;
  description: string;
  false_positive_notes: string;
  matched_evidence: { kind: string; value: string }[];
}

interface HuntPlan {
  seed: string;
  seedKind: 'ip' | 'domain';
  generatedAt: string;
  features: { count: number; ranked: HuntFeatureRow[] };
  queries: HuntQuery[];
  signatures: HuntSignature[];
  readiness: { provider: string; label: string; keyEnv: string | null; available: boolean }[];
  notes: string;
  cached?: boolean;
}

export default function C2Playbooks() {
  const [index, setIndex] = useState<C2PlaybooksIndex | null>(null);
  const [entries, setEntries] = useState<C2PlaybookEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [engine, setEngine] = useState<string>('all');
  const [category, setCategory] = useState<string>('all');
  const [visible, setVisible] = useState(100);
  const [refreshKey, setRefreshKey] = useState(0);

  // Fingerprint checker state
  const [fpInput, setFpInput] = useState('');
  const [fpResult, setFpResult] = useState<FpResult | null>(null);

  // Seed hunt planner state
  const [huntSeed, setHuntSeed] = useState('');
  const [huntPlan, setHuntPlan] = useState<HuntPlan | null>(null);
  const [huntLoading, setHuntLoading] = useState(false);
  const [huntError, setHuntError] = useState<string | null>(null);

  const runHuntPlan = (raw: string) => {
    const seed = raw.trim();
    if (!seed || huntLoading) return;
    setHuntSeed(seed);
    setHuntLoading(true);
    setHuntError(null);
    api
      .get<HuntPlan>(`/api/v1/mantis-hunt/preview?seed=${encodeURIComponent(seed)}`, { timeoutMs: 45_000 })
      .then((plan) => {
        setHuntPlan(plan);
        setHuntLoading(false);
      })
      .catch((e) => {
        setHuntError(String(e instanceof Error ? e.message : e));
        setHuntPlan(null);
        setHuntLoading(false);
      });
  };

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    // Manifest-first: the whole catalog (index + one section per engine) ships
    // as static JSON under /data/c2-playbooks/, so search, filters, and the
    // favicon/JARM checker all run client-side with zero API calls.
    fetchJsonCached<C2PlaybooksIndex>('/data/c2-playbooks/index.json', 300_000)
      .then(async (idx) => {
        if (!alive) return;
        const engines = Object.keys(idx.engines);
        const loaded = await Promise.all(
          engines.map((eng) =>
            fetchJsonCached<EngineSection>(
              `/data/c2-playbooks/sections/${encodeURIComponent(eng)}.json`,
              300_000
            ).catch(() => null)
          )
        );
        if (!alive) return;
        const all = loaded.filter((s): s is EngineSection => Boolean(s)).flatMap((s) => s.entries);
        setIndex(idx);
        setEntries(all);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setError(String(e));
        setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  const categories = useMemo(() => {
    if (!index) return [];
    return Object.entries(index.categories)
      .sort((a, b) => b[1] - a[1])
      .map(([name]) => name);
  }, [index]);

  const q = search.toLowerCase().trim();
  const filtered = useMemo(() => {
    return entries.filter((e) => {
      if (engine !== 'all' && e.engine !== engine) return false;
      if (category !== 'all' && e.category.toLowerCase() !== category.toLowerCase()) return false;
      if (q) {
        const hay = `${e.family} ${e.technique} ${e.category} ${e.query} ${e.notes ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [entries, engine, category, q]);

  useEffect(() => {
    setVisible(100);
  }, [engine, category, search]);

  const runFingerprint = (raw: string) => {
    setFpInput(raw);
    const kind = detectFingerprint(raw);
    if (!kind || !index) {
      setFpResult(null);
      return;
    }
    const v = raw.trim();
    if (kind === 'favicon-mmh3') {
      const families = [...new Set(index.faviconHashes.filter((f) => f.hash === v).map((f) => f.family))];
      setFpResult(families.length ? { kind, families } : null);
    } else if (kind === 'jarm') {
      const families = [...new Set(index.jarmHashes.filter((j) => j.hash === v.toLowerCase()).map((j) => j.family))];
      setFpResult(families.length ? { kind, families } : null);
    } else {
      // Payload SHA-256 lives on urlscan entries, not the index.
      const families = [
        ...new Set(entries.filter((e) => e.hash?.toLowerCase() === v.toLowerCase()).map((e) => e.family)),
      ];
      setFpResult(families.length ? { kind, families } : null);
    }
  };

  const engineList = useMemo(() => {
    if (!index) return [];
    return Object.entries(index.engines).sort((a, b) => b[1] - a[1]);
  }, [index]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Radar size={28} />}
      title="C2 Hunting Playbooks"
      description={
        <p className="text-muted max-w-2xl">
          1,029 curated hunting queries for C2 and phishing infrastructure across 9 engines - Shodan, Netlas, URLscan,
          Censys, FOFA, ZoomEye, Etugen, Silent Push, and Validin. Favicon (MMH3), JARM, and payload SHA-256
          fingerprints for RATs, info stealers, and C2 frameworks. Ported from MANTIS's c2_hunting_catalog.py into a
          build-time manifest (MIT, fareedfauzi/MANTIS).
        </p>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      maxWidthClass="max-w-6xl"
    >
      {index && (
        <div className="space-y-6">
          {/* Stats */}
          <section className="surface-card p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-brand-500/15 text-brand-700 dark:text-brand-300 border-brand-500/30">
                {index.counts.entries} queries
              </span>
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                {index.counts.engines} engines
              </span>
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                {index.counts.families} families
              </span>
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                {index.counts.categories} categories
              </span>
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                {index.faviconHashes.length} favicon hashes
              </span>
              <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                {index.jarmHashes.length} JARM
              </span>
              <span className="text-micro font-mono text-muted ml-auto">built {index.builtAt.slice(0, 10)}</span>
            </div>

            {/* Engine filter chips */}
            <div className="flex flex-wrap gap-2 mt-4 pt-4 border-b border-line-1 pb-4">
              <button
                type="button"
                onClick={() => setEngine('all')}
                className={`text-xs font-mono px-2.5 py-1 rounded border transition-colors ${engine === 'all' ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'}`}
              >
                All <span className="opacity-60">· {entries.length}</span>
              </button>
              {engineList.map(([eng, count]) => (
                <button
                  type="button"
                  key={eng}
                  onClick={() => setEngine(eng)}
                  className={`text-xs font-mono px-2.5 py-1 rounded border transition-colors ${engine === eng ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300' : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'}`}
                >
                  {eng} <span className="opacity-60">· {count}</span>
                </button>
              ))}
            </div>

            {/* Search + category */}
            <div className="flex flex-wrap items-center gap-3 mt-4">
              <div className="relative flex-1 min-w-[240px]">
                <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search family, technique, or query - e.g. cobalt strike, favicon, JARM..."
                  className="w-full font-mono text-sm pl-8 pr-3 py-2 rounded border border-line-2 bg-surface-200 text-heading placeholder:text-muted focus:outline-none focus:border-rose-500/50"
                />
              </div>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="font-mono text-sm px-3 py-2 rounded border border-line-2 bg-surface-200 text-heading focus:outline-none focus:border-rose-500/50"
              >
                <option value="all">All categories ({entries.length})</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat} ({index.categories[cat]})
                  </option>
                ))}
              </select>
            </div>
          </section>

          {/* Fingerprint checker */}
          <section className="surface-card p-4">
            <h2 className="font-display font-bold text-lg flex items-center gap-2">
              <Fingerprint size={17} className="text-rose-600 dark:text-rose-400" /> Fingerprint checker
            </h2>
            <p className="text-xs text-muted mt-1">
              Paste a favicon MMH3 hash (Shodan <code>http.favicon.hash:</code> value), a JARM fingerprint, or a payload
              SHA-256 to see which families it matches.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              <input
                type="text"
                value={fpInput}
                onChange={(e) => runFingerprint(e.target.value)}
                placeholder="-859291042 / 29d... / abc123def..."
                className="flex-1 min-w-[240px] font-mono text-sm px-3 py-2 rounded border border-line-2 bg-surface-200 text-heading placeholder:text-muted focus:outline-none focus:border-rose-500/50"
              />
              {fpInput && (
                <button
                  type="button"
                  onClick={() => {
                    setFpInput('');
                    setFpResult(null);
                  }}
                  className="text-xs font-mono px-2.5 py-1 rounded border border-line-2 text-muted hover:text-rose-600 dark:hover:text-rose-400 hover:border-rose-500/40"
                >
                  clear
                </button>
              )}
            </div>
            {fpInput.trim() && (
              <div className="mt-3">
                {detectFingerprint(fpInput) === null ? (
                  <p className="text-sm text-muted font-mono">
                    Not a recognizable fingerprint - expect an MMH3 int, JARM 62 hex, or SHA-256.
                  </p>
                ) : fpResult ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono text-muted">
                      {fpResult.kind === 'favicon-mmh3'
                        ? 'favicon MMH3'
                        : fpResult.kind === 'jarm'
                          ? 'JARM'
                          : 'payload SHA-256'}{' '}
                      →
                    </span>
                    {fpResult.families.map((fam) => (
                      <span
                        key={fam}
                        className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30"
                      >
                        {fam}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm font-mono text-muted">
                    No match for this{' '}
                    {detectFingerprint(fpInput) === 'jarm'
                      ? 'JARM'
                      : detectFingerprint(fpInput) === 'favicon-mmh3'
                        ? 'favicon hash'
                        : 'payload hash'}{' '}
                    in the catalog - try its family name above or hunt it directly.
                  </p>
                )}
              </div>
            )}
          </section>

          {/* Seed hunt planner (MANTIS infra-hunt planner port, keyless upstreams) */}
          <section className="surface-card p-4">
            <h2 className="font-display font-bold text-lg flex items-center gap-2">
              <Telescope size={17} className="text-rose-600 dark:text-rose-400" /> Seed hunt planner
            </h2>
            <p className="text-xs text-muted mt-1">
              Paste an IP or domain and get a ready-to-run engine query plan: crt.sh + RIPEstat seed intel (no keys
              needed) feeds the MANTIS infra-hunt planner, which composes per-engine compound queries with launch links.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              <input
                type="text"
                value={huntSeed}
                onChange={(e) => setHuntSeed(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') runHuntPlan(huntSeed);
                }}
                placeholder="185.216.35.17 or c2.example-domain.com"
                className="flex-1 min-w-[240px] font-mono text-sm px-3 py-2 rounded border border-line-2 bg-surface-200 text-heading placeholder:text-muted focus:outline-none focus:border-rose-500/50"
              />
              <button
                type="button"
                onClick={() => runHuntPlan(huntSeed)}
                disabled={huntLoading || !huntSeed.trim()}
                className="text-xs font-mono px-3 py-2 rounded border border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300 disabled:opacity-40"
              >
                {huntLoading ? 'planning...' : 'plan hunt'}
              </button>
            </div>
            {huntError && <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mt-3">{huntError}</p>}
            {huntPlan && (
              <div className="mt-4 space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-brand-500/15 text-brand-700 dark:text-brand-300 border-brand-500/30">
                    {huntPlan.seedKind} seed
                  </span>
                  <span className="text-micro font-mono text-muted">
                    {huntPlan.features.count} signals · {huntPlan.queries.length} engine queries ·{' '}
                    {huntPlan.signatures.length} signature matches{huntPlan.cached ? ' · cached' : ''} ·{' '}
                    {huntPlan.generatedAt.slice(0, 10)}
                  </span>
                </div>

                {/* Ranked seed signals */}
                <div className="flex flex-wrap gap-1.5">
                  {huntPlan.features.ranked.slice(0, 10).map((f, i) => (
                    <span
                      key={`${f.kind}:${f.value}:${i}`}
                      className="text-micro font-mono px-1.5 py-0.5 rounded border bg-slate-500/10 text-muted border-slate-500/30"
                      title={`weight ${f.weight}`}
                    >
                      {f.kind}
                      <span className="opacity-70">
                        :{f.value.length > 34 ? `${f.value.slice(0, 34)}...` : f.value}
                      </span>
                    </span>
                  ))}
                </div>

                {/* Signature pack matches */}
                {huntPlan.signatures.map((sig) => (
                  <div key={sig.slug} className="rounded border border-rose-500/30 bg-rose-500/10 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30">
                        {sig.family}
                      </span>
                      <span className="text-sm text-heading">{sig.name}</span>
                    </div>
                    <p className="text-xs text-muted mt-1">
                      {sig.description} - matched:{' '}
                      {sig.matched_evidence.map((ev) => `${ev.kind}=${ev.value}`).join(', ')}
                    </p>
                    <p className="text-micro font-mono text-muted mt-1">{sig.false_positive_notes}</p>
                  </div>
                ))}

                {/* Composed engine queries */}
                <div className="grid gap-2">
                  {huntPlan.queries.map((q, i) => {
                    const readiness = huntPlan.readiness.find((r) => r.provider === q.provider);
                    return (
                      <div key={`${q.provider}:${i}`} className="rounded border border-line-1 bg-surface-200 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${ENGINE_COLORS[q.provider] ?? 'bg-slate-500/15 text-muted border-slate-500/30'}`}
                          >
                            {q.provider}
                          </span>
                          <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-slate-500/15 text-muted border-slate-500/30">
                            {q.mode}
                          </span>
                          {readiness?.available ? (
                            <span className="text-micro font-mono px-1.5 py-0.5 rounded border bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30">
                              key ready
                            </span>
                          ) : (
                            <span className="text-micro font-mono px-1.5 py-0.5 rounded border bg-slate-500/10 text-muted border-slate-500/30 inline-flex items-center gap-1">
                              <Lock size={9} />
                              {readiness?.keyEnv ? `needs ${readiness.keyEnv}` : 'no key binding'}
                            </span>
                          )}
                          <span className="text-micro font-mono text-muted ml-auto">
                            strength {q.estimated_strength}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 mt-1.5">
                          <code className="font-mono text-xs text-muted flex-1 break-all">{q.query}</code>
                          <CopyQueryButton query={q.query} />
                        </div>
                        {q.notes && <p className="text-micro font-mono text-muted mt-1">{q.notes}</p>}
                        {sanitizeUrl(q.external_url) && (
                          <a
                            href={sanitizeUrl(q.external_url)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 mt-1.5"
                          >
                            run on {q.provider} <ExternalLink size={10} />
                          </a>
                        )}
                      </div>
                    );
                  })}
                </div>
                <p className="text-micro font-mono text-muted">{huntPlan.notes}</p>
              </div>
            )}
          </section>

          {/* Results */}
          <section className="surface-card p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-3 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted">
                {engine === 'all' ? 'All playbooks' : `${engine} playbooks`}
                <span className="ml-2 text-muted">({filtered.length})</span>
              </h2>
              {filtered.length > 0 && (
                <span className="text-micro font-mono text-muted">
                  showing {Math.min(visible, filtered.length)} of {filtered.length}
                </span>
              )}
            </div>
            <div className="grid gap-2">
              {filtered.slice(0, visible).map((e) => (
                <div key={e.id} className="rounded border border-line-1 bg-surface-200 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${categoryColor(e.category)}`}
                    >
                      {e.family}
                    </span>
                    <span className="text-sm text-heading">{e.technique}</span>
                    <span
                      className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${ENGINE_COLORS[e.engine] ?? 'bg-slate-500/15 text-muted border-slate-500/30'}`}
                    >
                      {e.engine}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1.5">
                    <code className="font-mono text-xs text-muted flex-1 break-all">{e.query}</code>
                    <CopyQueryButton query={e.query} />
                  </div>
                  {e.notes && <p className="text-micro font-mono text-muted mt-1">{e.notes}</p>}
                  {sanitizeUrl(e.externalUrl) && (
                    <a
                      href={sanitizeUrl(e.externalUrl)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-micro font-mono text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 mt-1.5"
                    >
                      run on {e.engine} <ExternalLink size={10} />
                    </a>
                  )}
                </div>
              ))}
              {filtered.length === 0 && (
                <p className="text-sm text-muted font-mono py-6 text-center">
                  No playbooks match - try a broader query or clear the engine filter.
                </p>
              )}
            </div>
            {filtered.length > visible && (
              <div className="flex justify-center mt-4">
                <button
                  type="button"
                  onClick={() => setVisible((v) => v + 100)}
                  className="text-xs font-mono px-3 py-1.5 rounded border border-line-2 text-muted hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
                >
                  show {Math.min(100, filtered.length - visible)} more
                </button>
              </div>
            )}
          </section>

          {/* Top families */}
          {index.topFamilies.length > 0 && (
            <section className="surface-card p-4">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted mb-3">
                Top families in the catalog
              </h2>
              <div className="flex flex-wrap gap-2">
                {index.topFamilies.map((f) => (
                  <button
                    type="button"
                    key={f.family}
                    onClick={() => {
                      setSearch(f.family.toLowerCase());
                      setCategory('all');
                    }}
                    className="text-xs font-mono px-2 py-1 rounded border border-line-2 text-muted hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
                    title={`Search ${f.family} playbooks`}
                  >
                    {f.family} <span className="opacity-60">· {f.count}</span>
                  </button>
                ))}
              </div>
            </section>
          )}

          <section className="surface-card p-4">
            <p className="text-xs font-mono text-muted">
              Source: MANTIS c2_hunting_catalog.py + infra_hunt_service.py ({index.license}) - ported to a build-time
              manifest by scripts/build-c2-playbooks.mjs. The catalog API lives at
              <code className="mx-1">/api/v1/c2-playbooks/entries</code>; the seed hunt planner runs at
              <code className="mx-1">/api/v1/mantis-hunt/preview?seed=</code>(keyless crt.sh + RIPEstat upstreams).
            </p>
          </section>
        </div>
      )}
    </DataPageLayout>
  );
}

/** Small copy button for a playbook query string. */
function CopyQueryButton({ query }: { query: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label="Copy query"
      onClick={() => {
        navigator.clipboard?.writeText(query).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          },
          () => undefined
        );
      }}
      className="text-muted hover:text-rose-600 dark:hover:text-rose-400 p-1"
    >
      {copied ? <Check size={12} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={12} />}
    </button>
  );
}
