/**
 * PromptIntel — IoPC (Indicators of Prompt Compromise) workspace.
 *
 * Two data tiers, shown honestly:
 *   - The taxonomy (domains, 35 techniques, 308 framework mappings) is served
 *     from the committed mirror, so browsing costs nothing and works without
 *     a key.
 *   - The live surfaces (prompt feed, agent protections, indicator checks)
 *     spend the PromptIntel account's Community allowance — 100 requests a
 *     day, and 5 prompt reads / 5 checks / 20 hash lookups a day — so each
 *     one is a deliberate click, and the UI says what it costs before it
 *     happens.
 *
 * Nothing here invents a technique name or a mapping: every string comes from
 * the mirror or the upstream envelope, and every record deep-links upstream.
 */
import { useCallback, useEffect, useMemo, useState, type JSX, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  ExternalLink,
  Fingerprint,
  Layers,
  Loader2,
  ScanSearch,
  Search,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { PageMeta } from '../../components/PageMeta';
import { Tabs } from '../../components/ui/Tabs';
import { api, ApiError } from '../../lib/api-client';
import { useDataFetch } from '../../hooks/useDataFetch';
import { errMessage } from '../../lib/log';

/* ─── Types (mirror of worker/lib/promptintel-manifest.ts) ─────────────── */

interface PiFramework {
  name: string;
  version: string | null;
  url: string | null;
}

interface PiDomain {
  id: string;
  name: string;
  description: string;
  techniques: string[];
}

interface PiEntrySlim {
  id: string;
  name: string;
  domain: string;
  domainName: string;
  summary: string;
  url: string;
  maturity: string;
  evidence: string | null;
  reviewed: string | null;
  frameworks: string[];
  mappingCount: number;
}

interface PiMappingRow {
  entry: string;
  name: string;
  domain: string;
  framework: string;
  ref: string;
  item: string;
  relationship: string;
}

interface PiIndex {
  source: string;
  sourceUrl: string;
  license: string;
  syncedAt: string;
  taxonomyVersion: string;
  counts: { domains: number; techniques: number; frameworks: number; mappings: number };
  frameworks: PiFramework[];
  domains: PiDomain[];
  entries: PiEntrySlim[];
  mappings: PiMappingRow[];
}

interface PiEntryBody {
  id: string;
  name: string;
  description: string;
  differs: string;
  maturity: string;
  evidence: string | null;
  reviewed: string | null;
  statusLine: string;
  mappings: Array<{ framework: string; ref: string; name: string; relationship: string }>;
  url: string;
}

interface PiStats {
  taxonomyVersion: string;
  liveVersion: string | null;
  mirrorStale: boolean;
  syncedAt: string;
  counts: PiIndex['counts'];
  keyed: boolean;
  plan: string;
}

interface PiTranslateResponse {
  taxonomyVersion: string;
  source: { framework: string; ref: string; item: string } | null;
  entries: Array<{ id: string; name: string; domain: string; relationship: string }>;
  matches: Array<{
    framework: string;
    ref: string;
    item: string;
    relationship: string;
    via: string[];
    kind: 'threat' | 'control';
  }>;
}

/** Upstream envelopes are `{success, data}`; the payload shape varies by route. */
type Envelope = { success?: boolean; data?: unknown; error?: string; message?: string };

function pickList<T>(data: unknown, keys: string[]): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === 'object') {
    for (const k of keys) {
      const v = (data as Record<string, unknown>)[k];
      if (Array.isArray(v)) return v as T[];
    }
  }
  return [];
}

/* ─── Small UI atoms ──────────────────────────────────────────────────── */

function Chip({
  children,
  tone = 'neutral',
}: {
  children: ReactNode;
  tone?: 'neutral' | 'good' | 'warn' | 'bad' | 'info';
}): JSX.Element {
  const toneClass = {
    neutral: 'border-line-2 dark:border-line-1 text-muted',
    good: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    warn: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    bad: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    info: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  }[tone];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-micro font-mono ${toneClass}`}
    >
      {children}
    </span>
  );
}

function maturityTone(m: string): 'good' | 'warn' | 'bad' | 'neutral' {
  if (m === 'active') return 'good';
  if (m === 'experimental') return 'warn';
  if (m === 'deprecated') return 'bad';
  return 'neutral';
}

function KeyGate({ children }: { children: ReactNode }): JSX.Element {
  return (
    <div className="surface-card p-6 text-center">
      <ShieldCheck className="mx-auto h-6 w-6 text-muted" />
      <p className="mt-2 text-sm font-semibold text-heading">The live PromptIntel API is not configured</p>
      <p className="mx-auto mt-1 max-w-md text-mini text-muted">
        Set <code className="font-mono">PROMPTINTEL_API_KEY</code> with{' '}
        <code className="font-mono">wrangler secret put PROMPTINTEL_API_KEY</code> to unlock prompt text, agent
        protections and indicator checks. The taxonomy tabs work without it.
      </p>
      <div className="mt-3">{children}</div>
    </div>
  );
}

/** Live-fetch hook that keeps the HTTP status, so a 501 renders as a gate. */
function useLive<T>(url: string | null): {
  data: T | null;
  error: string | null;
  status: number | null;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!url) {
      setData(null);
      setError(null);
      setStatus(null);
      setLoading(false);
      return;
    }
    let alive = true;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    api
      .get<Envelope>(url, { signal: ctrl.signal })
      .then((res) => {
        if (!alive) return;
        setData(res as T);
        setStatus(200);
      })
      .catch((e) => {
        if (!alive) return;
        setStatus(e instanceof ApiError ? e.status : null);
        setError(errMessage(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
      ctrl.abort();
    };
  }, [url, tick]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data, error, status, loading, reload };
}

/* ─── Taxonomy tab ────────────────────────────────────────────────────── */

function EntryDetail({ id }: { id: string }): JSX.Element {
  const { data, loading, error } = useDataFetch<PiEntryBody>({
    url: `/api/v1/promptintel/taxonomy/entries/${encodeURIComponent(id)}`,
    ttl: 10 * 60_000,
  });
  if (loading && !data) return <p className="mt-3 text-mini font-mono text-muted">loading entry…</p>;
  if (error && !data) return <p className="mt-3 text-mini text-rose-600 dark:text-rose-400">{error}</p>;
  if (!data) return <p className="mt-3 text-mini font-mono text-muted">entry unavailable</p>;

  const byFramework = new Map<string, PiEntryBody['mappings']>();
  for (const m of data.mappings) {
    const list = byFramework.get(m.framework) ?? [];
    list.push(m);
    byFramework.set(m.framework, list);
  }

  return (
    <div className="mt-3 space-y-3 border-t border-line-1 pt-3">
      {data.description && <p className="text-sm leading-relaxed text-body">{data.description}</p>}
      {data.differs && (
        <p className="text-xs leading-relaxed text-muted">
          <span className="font-mono uppercase tracking-wider">how it differs: </span>
          {data.differs}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone={maturityTone(data.maturity)}>{data.maturity}</Chip>
        {data.evidence && <Chip tone="info">evidence: {data.evidence}</Chip>}
        {data.reviewed && <Chip>reviewed {data.reviewed}</Chip>}
        <a
          href={data.url}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
        >
          upstream <ExternalLink className="h-2.5 w-2.5" />
        </a>
      </div>
      {byFramework.size > 0 && (
        <div className="space-y-2">
          <div className="text-micro font-mono uppercase tracking-wider text-muted">Framework mappings</div>
          {[...byFramework.entries()].map(([framework, rows]) => (
            <div
              key={framework}
              className="rounded-lg border border-line-1 bg-surface-50/60 p-2.5 dark:bg-surface-100/40"
            >
              <div className="text-mini font-semibold text-heading">{framework}</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {rows.map((r) => (
                  <span
                    key={`${r.ref}-${r.relationship}`}
                    className="inline-flex items-baseline gap-1 rounded border border-line-2 px-1.5 py-0.5 text-micro dark:border-line-1"
                    title={`${r.name || r.ref} — ${r.relationship}`}
                  >
                    <span className="font-mono font-semibold text-fg">{r.ref}</span>
                    {r.name && <span className="text-muted">{r.name}</span>}
                    <span className="font-mono text-muted/70">{r.relationship.replace(/_/g, ' ')}</span>
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TaxonomyTab({ index }: { index: PiIndex }): JSX.Element {
  const [domain, setDomain] = useState<string>('all');
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const entries = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return index.entries.filter((e) => {
      if (domain !== 'all' && e.domain !== domain) return false;
      if (!needle) return true;
      return `${e.id} ${e.name} ${e.summary} ${e.frameworks.join(' ')}`.toLowerCase().includes(needle);
    });
  }, [index.entries, domain, query]);

  return (
    <div className="space-y-4">
      <div className="surface-card p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search techniques, ids, frameworks…"
              className="w-64 rounded-lg border border-line-2 bg-surface-50 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none dark:border-line-1 dark:bg-surface-100"
            />
          </div>
          <div className="flex flex-wrap gap-1">
            <button
              type="button"
              onClick={() => setDomain('all')}
              aria-pressed={domain === 'all'}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono transition-colors ${
                domain === 'all'
                  ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                  : 'border-line-2 text-muted hover:border-sky-500/40 dark:border-line-1'
              }`}
            >
              all ({index.entries.length})
            </button>
            {index.domains.map((d) => (
              <button
                key={d.id}
                type="button"
                onClick={() => setDomain(d.id)}
                aria-pressed={domain === d.id}
                title={d.description}
                className={`rounded-full border px-2.5 py-1 text-mini font-mono transition-colors ${
                  domain === d.id
                    ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                    : 'border-line-2 text-muted hover:border-sky-500/40 dark:border-line-1'
                }`}
              >
                {d.id} ({d.techniques.length})
              </button>
            ))}
          </div>
        </div>
        {domain !== 'all' && (
          <p className="mt-2 text-mini text-muted">
            <span className="font-mono text-fg">
              {index.domains.find((d) => d.id === domain)?.id} {index.domains.find((d) => d.id === domain)?.name}
            </span>{' '}
            — {index.domains.find((d) => d.id === domain)?.description}
          </p>
        )}
      </div>

      <div className="grid gap-2 md:grid-cols-2">
        {entries.map((e) => {
          const isOpen = open === e.id;
          return (
            <div key={e.id} className={`surface-card p-3 transition-colors ${isOpen ? 'border-sky-500/40' : ''}`}>
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : e.id)}
                aria-expanded={isOpen}
                className="flex w-full items-start gap-2 text-left"
              >
                <span className="mt-0.5 rounded bg-surface-200/70 px-1.5 py-0.5 font-mono text-micro text-muted dark:bg-surface-100">
                  {e.id}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold text-heading">{e.name}</span>
                  <span className="mt-0.5 block text-mini leading-relaxed text-muted">{e.summary}</span>
                </span>
                <ArrowRight
                  className={`mt-1 h-3.5 w-3.5 shrink-0 text-muted transition-transform ${isOpen ? 'rotate-90' : ''}`}
                />
              </button>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <Chip tone={maturityTone(e.maturity)}>{e.maturity}</Chip>
                <Chip>{e.mappingCount} mappings</Chip>
                {e.frameworks.slice(0, 2).map((f) => (
                  <Chip key={f} tone="info">
                    {f.replace(/\s*\(.*\)$/, '')}
                  </Chip>
                ))}
                {e.frameworks.length > 2 && <Chip>+{e.frameworks.length - 2}</Chip>}
              </div>
              {isOpen && <EntryDetail id={e.id} />}
            </div>
          );
        })}
      </div>
      {entries.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No technique matches that filter.</p>
      )}
    </div>
  );
}

/* ─── Translate tab ───────────────────────────────────────────────────── */

const FRAMEWORK_SHORT: Record<string, string> = {
  'OWASP Top 10 for LLM Applications': 'OWASP_LLM',
  'OWASP Top 10 for Agentic Applications': 'OWASP_AGENTIC',
  'MITRE ATLAS': 'MITRE_ATLAS',
  'Google Secure AI Framework (SAIF)': 'SAIF',
  'CSA Autonomous Action Runtime Management (AARM)': 'AARM',
  'NIST AI Risk Management Framework (AI RMF)': 'NIST_AI_RMF',
};

function TranslateTab({ index }: { index: PiIndex }): JSX.Element {
  const [framework, setFramework] = useState('OWASP Top 10 for LLM Applications');
  const [ref, setRef] = useState('LLM01');
  const [submitted, setSubmitted] = useState<{ framework: string; ref: string } | null>(null);

  const url = submitted
    ? `/api/v1/promptintel/taxonomy/translate?framework=${encodeURIComponent(submitted.framework)}&ref=${encodeURIComponent(submitted.ref)}`
    : null;
  const { data, loading, error } = useDataFetch<PiTranslateResponse>({ url, ttl: 5 * 60_000 });

  const refsFor = useMemo(() => {
    const rows = index.mappings.filter((m) => m.framework === framework);
    return [...new Map(rows.map((r) => [r.ref, r.item])).entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [index.mappings, framework]);

  const grouped = useMemo(() => {
    const out = new Map<string, PiTranslateResponse['matches']>();
    for (const m of data?.matches ?? []) {
      const list = out.get(m.framework) ?? [];
      list.push(m);
      out.set(m.framework, list);
    }
    return out;
  }, [data]);

  return (
    <div className="space-y-4">
      <div className="surface-card p-4">
        <p className="text-mini text-muted">
          PromptIntel publishes no framework-to-framework table. The link is derived the way it documents it:{' '}
          <span className="text-fg">both items map to the same IoPC technique</span>. The techniques are listed under
          each match as <code className="font-mono">via</code>, so you can audit the claim instead of trusting it.
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="text-mini">
            <span className="mb-1 block font-mono uppercase tracking-wider text-muted">Framework</span>
            <select
              value={framework}
              onChange={(e) => {
                setFramework(e.target.value);
                setSubmitted(null);
              }}
              className="rounded-lg border border-line-2 bg-surface-50 px-2 py-1.5 text-mini text-fg dark:border-line-1 dark:bg-surface-100"
            >
              {index.frameworks.map((f) => (
                <option key={f.name} value={f.name}>
                  {FRAMEWORK_SHORT[f.name] ?? f.name} {f.version ? `(${f.version})` : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="text-mini">
            <span className="mb-1 block font-mono uppercase tracking-wider text-muted">Item</span>
            <input
              list="pi-refs"
              value={ref}
              onChange={(e) => setRef(e.target.value)}
              className="w-48 rounded-lg border border-line-2 bg-surface-50 px-2 py-1.5 font-mono text-mini text-fg dark:border-line-1 dark:bg-surface-100"
            />
            <datalist id="pi-refs">
              {refsFor.map(([id, item]) => (
                <option key={id} value={id}>
                  {item}
                </option>
              ))}
            </datalist>
          </label>
          <button
            type="button"
            onClick={() => setSubmitted({ framework, ref: ref.trim() })}
            disabled={!ref.trim()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 px-3 py-1.5 text-mini font-semibold text-sky-700 transition-colors hover:bg-sky-500/20 disabled:opacity-40 dark:text-sky-300"
          >
            <Sparkles className="h-3.5 w-3.5" /> Translate
          </button>
        </div>
      </div>

      {loading && <p className="text-mini font-mono text-muted">translating…</p>}
      {error && !loading && <p className="surface-card p-4 text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      {data?.source && (
        <div className="surface-card p-4">
          <div className="text-micro font-mono uppercase tracking-wider text-muted">Source item</div>
          <div className="mt-1 text-sm font-semibold text-heading">
            <span className="font-mono text-sky-700 dark:text-sky-300">{data.source.ref}</span> {data.source.item}
            <span className="ml-2 text-mini font-normal text-muted">{data.source.framework}</span>
          </div>
          {data.entries.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-micro font-mono uppercase tracking-wider text-muted">via</span>
              {data.entries.map((e) => (
                <Chip key={e.id} tone="info">
                  {e.id} {e.name}
                </Chip>
              ))}
            </div>
          )}
        </div>
      )}

      {grouped.size > 0 && (
        <div className="grid gap-2 md:grid-cols-2">
          {[...grouped.entries()].map(([fw, rows]) => (
            <div key={fw} className="surface-card p-3">
              <div className="text-mini font-semibold text-heading">
                {FRAMEWORK_SHORT[fw] ?? fw} <span className="font-normal text-muted">· {rows.length}</span>
              </div>
              <ul className="mt-1.5 space-y-1">
                {rows.map((m) => (
                  <li key={`${m.ref}-${m.relationship}`} className="flex items-baseline gap-1.5 text-mini">
                    <span className="shrink-0 font-mono font-semibold text-fg">{m.ref}</span>
                    <span className="min-w-0 flex-1 text-body">{m.item}</span>
                    <Chip tone={m.kind === 'control' ? 'good' : 'neutral'}>{m.relationship.replace(/_/g, ' ')}</Chip>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {submitted && !loading && !error && data && !data.source && (
        <p className="surface-card p-4 text-mini text-muted">
          No IoPC technique maps to <code className="font-mono">{submitted.framework}</code>:
          <code className="font-mono"> {submitted.ref}</code>. Either the item is not in IoPC {index.taxonomyVersion},
          or the id is spelled differently upstream.
        </p>
      )}
    </div>
  );
}

/* ─── Prompts tab (live, quota-costly) ────────────────────────────────── */

interface PiPrompt {
  id: string;
  title?: string;
  severity?: string;
  category?: string;
  tags?: string[];
  author?: string;
  created_at?: string;
  technique_ids?: string[];
  has_nova_rule?: boolean;
  text_withheld?: boolean;
  is_public?: boolean;
  text?: string;
  follow_ups?: string[];
  nova_rule?: string;
  url?: string;
}

function severityTone(s: string | undefined): 'bad' | 'warn' | 'info' | 'good' | 'neutral' {
  if (s === 'critical') return 'bad';
  if (s === 'high') return 'warn';
  if (s === 'medium') return 'info';
  if (s === 'low') return 'good';
  return 'neutral';
}

function PromptsTab({ keyed }: { keyed: boolean }): JSX.Element {
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);

  const listUrl = keyed
    ? `/api/v1/promptintel/prompts?limit=20${query ? `&search=${encodeURIComponent(query)}` : ''}`
    : null;
  const list = useLive<Envelope>(listUrl);
  const detail = useLive<Envelope>(openId ? `/api/v1/promptintel/prompts/${encodeURIComponent(openId)}` : null);

  if (!keyed) return <KeyGate>Taxonomy and translation are unaffected.</KeyGate>;

  const prompts = pickList<PiPrompt>(list.data?.data, ['prompts', 'items', 'results']);
  const detailBody = (detail.data?.data ?? null) as PiPrompt | null;

  return (
    <div className="space-y-4">
      <div className="surface-card p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(search.trim());
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search approved adversarial prompts…"
              className="w-72 rounded-lg border border-line-2 bg-surface-50 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none dark:border-line-1 dark:bg-surface-100"
            />
          </div>
          <button
            type="submit"
            className="rounded-lg border border-line-2 px-3 py-1.5 text-mini font-semibold text-fg transition-colors hover:border-sky-500/40 dark:border-line-1"
          >
            Search
          </button>
        </form>
        <p className="mt-2 text-micro text-muted">
          The list omits attack text on the Community plan. Opening one in full costs{' '}
          <span className="font-mono text-fg">1 of 5</span> daily reads — the answer is then cached for 12 hours.
        </p>
      </div>

      {list.loading && <p className="text-mini font-mono text-muted">loading prompts…</p>}
      {list.error && (
        <p className="surface-card p-4 text-mini text-rose-600 dark:text-rose-400">
          {list.status === 429 ? 'PromptIntel daily or per-minute limit reached. ' : ''}
          {list.error}
        </p>
      )}

      <div className="grid gap-2 md:grid-cols-2">
        {prompts.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setOpenId(openId === p.id ? null : p.id)}
            aria-expanded={openId === p.id}
            className={`surface-card p-3 text-left transition-colors hover:border-sky-500/40 ${
              openId === p.id ? 'border-sky-500/40' : ''
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <span className="text-sm font-semibold text-heading">{p.title ?? p.id}</span>
              <Chip tone={severityTone(p.severity)}>{p.severity ?? 'unrated'}</Chip>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              {p.category && <Chip>{p.category}</Chip>}
              {(p.technique_ids ?? []).slice(0, 3).map((t) => (
                <Chip key={t} tone="info">
                  {t}
                </Chip>
              ))}
              {p.has_nova_rule && <Chip tone="good">NOVA rule</Chip>}
              {p.text_withheld && <Chip tone="warn">text withheld</Chip>}
            </div>
          </button>
        ))}
      </div>

      {openId && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="text-mini font-mono uppercase tracking-wider text-muted">prompt {openId}</div>
            <button type="button" onClick={() => setOpenId(null)} className="text-mini text-muted hover:text-fg">
              close
            </button>
          </div>
          {detail.loading && <p className="mt-2 text-mini font-mono text-muted">reading…</p>}
          {detail.error && (
            <p className="mt-2 text-mini text-rose-600 dark:text-rose-400">
              {detail.status === 429
                ? 'That was the 5th read today, or the per-minute limit. Resets at 00:00 UTC.'
                : detail.error}
            </p>
          )}
          {detailBody && (
            <div className="mt-2 space-y-3">
              <div className="text-sm font-semibold text-heading">{detailBody.title ?? detailBody.id}</div>
              {detailBody.text ? (
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-line-1 bg-surface-50 p-3 font-mono text-xs text-body dark:bg-surface-100/60">
                  {detailBody.text}
                </pre>
              ) : (
                <p className="text-mini text-muted">No attack text in this record.</p>
              )}
              {(detailBody.follow_ups ?? []).length > 0 && (
                <div>
                  <div className="text-micro font-mono uppercase tracking-wider text-muted">Follow-up steps</div>
                  <ol className="mt-1 list-decimal space-y-1 pl-5 text-xs text-body">
                    {(detailBody.follow_ups ?? []).map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                </div>
              )}
              {detailBody.nova_rule && (
                <div>
                  <div className="text-micro font-mono uppercase tracking-wider text-muted">NOVA rule</div>
                  <pre className="mt-1 max-h-60 overflow-auto whitespace-pre-wrap rounded-lg border border-line-1 bg-surface-50 p-3 font-mono text-xs text-body dark:bg-surface-100/60">
                    {detailBody.nova_rule}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Agent feed tab (live) ───────────────────────────────────────────── */

interface PiFeedItem {
  id: string;
  fingerprint?: string;
  category?: string;
  severity?: string;
  confidence?: number;
  action?: string;
  title?: string;
  description?: string;
  source?: string;
  technique_ids?: string[];
  expires_at?: string;
  revoked?: boolean;
  indicators_withheld?: boolean;
  analysis_withheld?: boolean;
}

function FeedTab({ keyed }: { keyed: boolean }): JSX.Element {
  const [severity, setSeverity] = useState('');
  const url = keyed ? `/api/v1/promptintel/agent-feed${severity ? `?severity=${severity}` : ''}` : null;
  const { data, loading, error, status } = useLive<Envelope>(url);

  if (!keyed) return <KeyGate>Taxonomy and translation are unaffected.</KeyGate>;

  const items = pickList<PiFeedItem>(data?.data, ['items', 'feed', 'protections', 'results']);

  return (
    <div className="space-y-4">
      <div className="surface-card p-4">
        <p className="text-mini text-muted">
          Curated, approved protections with a fingerprint to enforce and an expiry. When{' '}
          <code className="font-mono">expires_at</code> passes, stop enforcing it. Community keys get the title and a
          description preview with indicators withheld — that is upstream's rule, not a local one.
        </p>
        <div className="mt-2 flex flex-wrap gap-1">
          {['', 'critical', 'high', 'medium', 'low'].map((s) => (
            <button
              key={s || 'all'}
              type="button"
              onClick={() => setSeverity(s)}
              aria-pressed={severity === s}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono transition-colors ${
                severity === s
                  ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                  : 'border-line-2 text-muted hover:border-sky-500/40 dark:border-line-1'
              }`}
            >
              {s || 'all'}
            </button>
          ))}
        </div>
      </div>

      {loading && <p className="text-mini font-mono text-muted">loading protections…</p>}
      {error && (
        <p className="surface-card p-4 text-mini text-rose-600 dark:text-rose-400">
          {status === 403 ? 'This feed needs an Enterprise key. ' : ''}
          {error}
        </p>
      )}

      <div className="space-y-2">
        {items.map((item) => (
          <div key={item.id} className="surface-card p-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <span className="text-sm font-semibold text-heading">{item.title ?? item.id}</span>
              <div className="flex flex-wrap items-center gap-1.5">
                <Chip tone={severityTone(item.severity)}>{item.severity ?? 'unrated'}</Chip>
                {item.action && <Chip tone="warn">{item.action}</Chip>}
                {item.category && <Chip>{item.category}</Chip>}
                {item.revoked && <Chip tone="bad">revoked</Chip>}
              </div>
            </div>
            {item.description && <p className="mt-1.5 text-mini leading-relaxed text-body">{item.description}</p>}
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              {(item.technique_ids ?? []).map((t) => (
                <Chip key={t} tone="info">
                  {t}
                </Chip>
              ))}
              {item.indicators_withheld && <Chip tone="warn">indicators withheld</Chip>}
              {typeof item.confidence === 'number' && <Chip>confidence {item.confidence.toFixed(2)}</Chip>}
              {item.expires_at && <Chip>expires {item.expires_at.slice(0, 10)}</Chip>}
              {item.source && (
                <a
                  href={item.source}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
                >
                  source <ExternalLink className="h-2.5 w-2.5" />
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
      {!loading && !error && items.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No protections match that filter.</p>
      )}
    </div>
  );
}

/* ─── Check tab (live, quota-costly) ──────────────────────────────────── */

function CheckTab({ keyed }: { keyed: boolean }): JSX.Element {
  const [value, setValue] = useState('');
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const isHash = /^[a-f0-9]{64}$/i.test(value.trim());

  const run = useCallback(async () => {
    const v = value.trim();
    if (!v) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setStatus(null);
    setSubmitted(v);
    try {
      const path = /^[a-f0-9]{64}$/i.test(v)
        ? `/api/v1/promptintel/artifacts/lookup?sha256=${encodeURIComponent(v.toLowerCase())}`
        : `/api/v1/promptintel/check?value=${encodeURIComponent(v)}`;
      const res = await api.get<Envelope>(path);
      setResult(res);
      setStatus(200);
    } catch (e) {
      setStatus(e instanceof ApiError ? e.status : null);
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  }, [value]);

  if (!keyed) return <KeyGate>Taxonomy and translation are unaffected.</KeyGate>;

  return (
    <div className="space-y-4">
      <div className="surface-card p-4">
        <p className="text-mini text-muted">
          A URL, domain, IP, file path or skill/MCP name goes to the indicator check (
          <span className="font-mono text-fg">5 a day</span>). A 64-hex SHA-256 goes to the agent-file lookup (
          <span className="font-mono text-fg">20 a day</span>). Both are cached for 24h, so asking twice is free. A miss
          is <em>not</em> a clean result.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
          className="mt-3 flex flex-wrap items-center gap-2"
        >
          <div className="relative min-w-0 flex-1">
            <Fingerprint className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="https://… · example.com · 8.8.8.8 · <sha256> · some-skill-name"
              className="w-full rounded-lg border border-line-2 bg-surface-50 py-1.5 pl-8 pr-3 font-mono text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none dark:border-line-1 dark:bg-surface-100"
            />
          </div>
          <button
            type="submit"
            disabled={busy || !value.trim()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 px-3 py-1.5 text-mini font-semibold text-sky-700 transition-colors hover:bg-sky-500/20 disabled:opacity-40 dark:text-sky-300"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
            {isHash ? 'Look up hash' : 'Check indicator'}
          </button>
        </form>
      </div>

      {error && (
        <p className="surface-card p-4 text-mini text-rose-600 dark:text-rose-400">
          {status === 429 ? 'Daily allowance spent (resets at 00:00 UTC). ' : ''}
          {error}
        </p>
      )}

      {result != null && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="text-micro font-mono uppercase tracking-wider text-muted">
              verdict for {submitted?.slice(0, 80)}
              {submitted && submitted.length > 80 ? '…' : ''}
            </div>
            <a
              href="https://promptintel.securitybreak.io/indicators/"
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
            >
              how indicators work <ExternalLink className="h-2.5 w-2.5" />
            </a>
          </div>
          <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-line-1 bg-surface-50 p-3 font-mono text-xs text-body dark:bg-surface-100/60">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

/* ─── Page ────────────────────────────────────────────────────────────── */

const TABS = [
  { id: 'taxonomy', label: 'Taxonomy' },
  { id: 'translate', label: 'Translate' },
  { id: 'prompts', label: 'Prompts' },
  { id: 'feed', label: 'Agent feed' },
  { id: 'check', label: 'Check' },
];

export function PromptIntel(): JSX.Element {
  const [tab, setTab] = useState('taxonomy');
  const index = useDataFetch<PiIndex>({ url: '/api/v1/promptintel/taxonomy', ttl: 30 * 60_000 });
  const stats = useDataFetch<PiStats>({ url: '/api/v1/promptintel/stats', ttl: 10 * 60_000 });

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <PageMeta
        title="PromptIntel — IoPC taxonomy and prompt intelligence"
        description="Indicators of Prompt Compromise: 9 domains and 35 techniques mapped to OWASP LLM, OWASP Agentic, MITRE ATLAS, Google SAIF, CSA AARM and NIST AI RMF, plus the live prompt and agent-protection feeds."
        section="Threat Intel"
        canonicalPath="/threatintel/promptintel"
      />

      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-heading">PromptIntel</h1>
          {index.data && <Chip tone="info">IoPC {index.data.taxonomyVersion}</Chip>}
          {stats.data && (
            <Chip tone={stats.data.keyed ? 'good' : 'warn'}>
              {stats.data.keyed ? 'live API configured' : 'mirror only'}
            </Chip>
          )}
          {stats.data?.mirrorStale && (
            <Chip tone="warn">
              <AlertTriangle className="h-2.5 w-2.5" /> mirror behind {stats.data.liveVersion}
            </Chip>
          )}
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted">
          Indicators of Prompt Compromise — an open, versioned classification of how AI systems and agents are attacked,
          from SecurityBreak. The taxonomy is mirrored locally so browsing is free; the prompt and agent-protection
          feeds are live and quota-aware.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-mini text-muted">
          {index.data && (
            <>
              <span>
                <span className="font-mono text-fg">{index.data.counts.techniques}</span> techniques
              </span>
              <span>
                <span className="font-mono text-fg">{index.data.counts.domains}</span> domains
              </span>
              <span>
                <span className="font-mono text-fg">{index.data.counts.mappings}</span> framework mappings
              </span>
              <span>
                <span className="font-mono text-fg">{index.data.counts.frameworks}</span> frameworks
              </span>
            </>
          )}
          <a
            href="https://promptintel.securitybreak.io/taxonomy/"
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            upstream taxonomy <ExternalLink className="h-2.5 w-2.5" />
          </a>
          <Link
            to="/threatintel/ai-escape"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            <BookOpen className="h-2.5 w-2.5" /> AI Escape Watch
          </Link>
        </div>
      </header>

      {index.loading && !index.data && (
        <div className="flex items-center gap-2 text-mini font-mono text-muted">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> loading the IoPC mirror…
        </div>
      )}
      {index.error && !index.data && (
        <div className="surface-card p-6">
          <p className="text-sm font-semibold text-heading">The taxonomy mirror is unavailable</p>
          <p className="mt-1 text-mini text-muted">
            {index.error} — rebuild it with <code className="font-mono">node scripts/sync-promptintel.mjs</code>.
          </p>
        </div>
      )}

      {index.data && (
        <>
          <Tabs tabs={TABS} active={tab} onChange={setTab} variant="underline" className="mb-4">
            {(active) =>
              active === 'taxonomy' ? (
                <TaxonomyTab index={index.data!} />
              ) : active === 'translate' ? (
                <TranslateTab index={index.data!} />
              ) : active === 'prompts' ? (
                <PromptsTab keyed={Boolean(stats.data?.keyed)} />
              ) : active === 'feed' ? (
                <FeedTab keyed={Boolean(stats.data?.keyed)} />
              ) : (
                <CheckTab keyed={Boolean(stats.data?.keyed)} />
              )
            }
          </Tabs>

          <footer className="mt-6 flex flex-wrap items-center gap-2 border-t border-line-1 pt-3 text-micro text-muted">
            <Layers className="h-3 w-3" />
            <span>{index.data.license}</span>
            <span className="font-mono">mirrored {index.data.syncedAt.slice(0, 10)}</span>
          </footer>
        </>
      )}
    </div>
  );
}
