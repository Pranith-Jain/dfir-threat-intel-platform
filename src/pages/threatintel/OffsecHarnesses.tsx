import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { ExternalLink, Filter, Github, Loader2, Search, ShieldCheck, Terminal, Users } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * Offsec Harness Index — open-source offensive-AI agent harnesses tracked on
 * offsecharnesses.ai (154 tracked, 14 seen in real attacks). Reads the
 * replicated manifest through the platform API:
 *   GET /api/v1/oh/                 slim index (counts, stats, tiers, rows)
 *   GET /api/v1/oh/harnesses/:slug  full harness (quoted uses, sources, incidents)
 *   GET /api/v1/oh/sources          primary reports
 * Upstream publishes no reuse licence — metadata and deep links only.
 */

interface HarnessSlim {
  slug: string;
  name: string;
  table: string | null;
  tier: string | null;
  kind: string | null;
  description: string | null;
  repo: string | null;
  url: string;
  stars: number | null;
  license: string | null;
  lastPush: string | null;
  actors: Array<{ name: string; note: string | null }>;
  useTags: string[];
  breach: string | null;
  keyFigure: string | null;
  sourceCount: number;
  incidentCount: number;
}

interface HarnessBody extends HarnessSlim {
  whatItDid: string | null;
  note: string | null;
  uses: Array<{ tag: string; basis: string | null; source: string | null; quote: string | null }>;
  sourceIds: string[];
  incidents: Array<{ id: string; title: string; date: string; url: string }>;
  upstreamUrl: string;
}

interface OhIndex {
  source: string;
  sourceUrl: string;
  license: string;
  builtAt: string;
  upstreamData: string;
  evidenceReviewed: string | null;
  tiers: Record<string, string>;
  useTags: Array<{ key: string; label: string; def: string }>;
  counts: {
    tracked: number;
    inTheWild: number;
    confirmed: number;
    observed: number;
    actors: number;
    sources: number;
    breaches: number;
  };
  stats: OhStats;
  harnesses: HarnessSlim[];
  webPages: Record<string, string>;
}

interface OhStats {
  evidenceRows: number;
  fieldRows: number;
  byTier: Record<string, number>;
  byKind: Record<string, number>;
  byUseTag: Array<{ name: string; count: number }>;
  actors: Array<{ name: string; count: number }>;
  sourceCount: number;
  referenceCount: number;
  breaches: number;
  withRepo: number;
}

interface OhSource {
  id: string;
  publisher: string;
  kind: string;
  date: string;
  title: string;
  url: string;
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500';

const TIER_STYLES: Record<string, string> = {
  confirmed: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  observed:
    'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  'no attack on record':
    'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/40 border-slate-300 dark:border-slate-700',
};

const TAG_LABELS: Record<string, string> = {
  recon: 'Recon',
  scan: 'Scanning',
  vuln: 'Vuln discovery',
  exploit: 'Exploitation',
  exploitdev: 'Exploit dev',
  postex: 'Post-exploitation',
  research: 'Research',
};

type Tab = 'evidence' | 'field' | 'sources' | 'about';

function badge(text: string, cls?: string): JSX.Element {
  return (
    <span
      className={`text-[11px] font-bold px-2 py-0.5 rounded border ${cls ?? 'text-muted bg-surface-100 border-line-1'}`}
    >
      {text}
    </span>
  );
}

export default function OffsecHarnesses(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<OhIndex>({ url: '/api/v1/oh/', ttl: 300_000 });
  const { data: sourcesData } = useDataFetch<{ sources: OhSource[] }>({ url: '/api/v1/oh/sources', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('evidence');
  const [tier, setTier] = useState('');
  const [useTag, setUseTag] = useState('');
  const [actor, setActor] = useState('');
  const [q, setQ] = useState('');
  const [body, setBody] = useState<HarnessBody | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.harnesses ?? []).filter((h) => {
      if (tab === 'evidence' && h.table !== 'evidence') return false;
      if (tab === 'field' && h.table !== 'field') return false;
      if (tier && h.tier !== tier) return false;
      if (useTag && !h.useTags.includes(useTag)) return false;
      if (actor && !h.actors.some((a) => a.name === actor)) return false;
      if (
        needle &&
        !`${h.name} ${h.description ?? ''} ${h.actors.map((a) => a.name).join(' ')}`.toLowerCase().includes(needle)
      )
        return false;
      return true;
    });
  }, [data, tab, tier, useTag, actor, q]);

  const briefingItems = useMemo(
    () =>
      (data?.harnesses ?? []).slice(0, 50).map((h) => ({
        title: h.name,
        body: `${h.tier ?? 'untiered'}${h.description ? ` — ${h.description.slice(0, 220)}` : ''}${
          h.actors.length ? ` · actors: ${h.actors.map((a) => a.name).join(', ')}` : ''
        }${h.useTags.length ? ` · uses: ${h.useTags.join(', ')}` : ''}`,
        source: h.url || data?.sourceUrl || 'offsecharnesses.ai',
      })),
    [data]
  );

  const actorOptions = data?.stats.actors ?? [];
  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'evidence', label: `In the wild (${data?.counts.inTheWild ?? '…'})` },
    { id: 'field', label: `Field (${data?.stats.fieldRows ?? '…'})` },
    { id: 'sources', label: `Sources (${data?.counts.sources ?? '…'})` },
    { id: 'about', label: 'About' },
  ];

  async function open(slug: string) {
    setBodyLoading(true);
    setBody(null);
    try {
      setBody(await api.get<HarnessBody>(`/api/v1/oh/harnesses/${encodeURIComponent(slug)}`));
    } catch {
      setBody(null);
    } finally {
      setBodyLoading(false);
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Terminal size={28} />}
      title="Offsec Harness Index"
      description={
        <>
          Open-source offensive-AI agent harnesses verifiable on GitHub, and which ones attackers are known to have run
          in real operations — from{' '}
          <a
            href={data?.sourceUrl ?? 'https://offsecharnesses.ai/'}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            offsecharnesses.ai
          </a>
          . {data?.counts.tracked ?? '…'} tracked, {data?.counts.inTheWild ?? '…'} seen in attacks (
          {data?.counts.confirmed ?? '…'} confirmed / {data?.counts.observed ?? '…'} observed),{' '}
          {data?.counts.actors ?? '…'} actors, {data?.counts.sources ?? '…'} primary reports.
        </>
      }
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-500/15 text-brand-600 dark:text-brand-300 border-brand-400/40'
                : 'text-muted hover:text-heading border-line-1'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <DetectionAiBriefing
        surface="Offsec Harness Index"
        source="offsec-harnesses"
        items={briefingItems}
        dayKey={data?.builtAt?.slice(0, 10)}
        label="harnesses"
      />

      {(tab === 'evidence' || tab === 'field') && (
        <>
          {tab === 'evidence' && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              {[
                ['Tracked', data?.counts.tracked],
                ['In the wild', data?.counts.inTheWild],
                ['Confirmed', data?.counts.confirmed],
                ['Breaches', data?.counts.breaches],
              ].map(([label, value]) => (
                <div key={String(label)} className="surface-card p-3">
                  <div className="text-2xl font-bold text-heading">{value ?? '…'}</div>
                  <div className="text-xs text-muted">{label}</div>
                </div>
              ))}
            </div>
          )}

          <div className="surface-card p-3 mb-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Filter size={14} /> Filters
            </div>
            <select
              className={inputCls}
              value={tier}
              onChange={(e) => setTier(e.target.value)}
              aria-label="Evidence tier"
            >
              <option value="">All tiers</option>
              <option value="confirmed">Confirmed</option>
              <option value="observed">Observed</option>
              <option value="no attack on record">No attack on record</option>
            </select>
            <select
              className={inputCls}
              value={useTag}
              onChange={(e) => setUseTag(e.target.value)}
              aria-label="Use tag"
            >
              <option value="">All use tags</option>
              {(data?.useTags ?? []).map((t) => (
                <option key={t.key} value={t.key}>
                  {t.label}
                </option>
              ))}
            </select>
            <select className={inputCls} value={actor} onChange={(e) => setActor(e.target.value)} aria-label="Actor">
              <option value="">All actors</option>
              {actorOptions.slice(0, 40).map((a) => (
                <option key={a.name} value={a.name}>
                  {a.name} ({a.count})
                </option>
              ))}
            </select>
            <div className="relative sm:col-span-2 lg:col-span-3">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                className={`${inputCls} pl-9`}
                placeholder="Search harnesses, actors, descriptions…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
          </div>

          <p className="text-xs text-muted mb-3">Showing {rows.length} harnesses</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {rows.map((h) => (
              <button
                key={h.slug}
                onClick={() => void open(h.slug)}
                className="surface-card w-full text-left p-3 hover:border-brand-400 transition-colors"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-heading">{h.name}</span>
                  {h.tier && badge(h.tier, TIER_STYLES[h.tier])}
                  {h.breach === 'Yes' &&
                    badge(
                      'breach',
                      'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800'
                    )}
                  {h.stars != null && (
                    <span className="text-xs text-muted ml-auto inline-flex items-center gap-1">
                      <Github size={11} /> {h.stars.toLocaleString()}
                    </span>
                  )}
                </div>
                {h.description && <p className="text-sm text-muted mt-1.5 line-clamp-2">{h.description}</p>}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {h.useTags.map((t) => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-surface-100 text-muted">
                      {TAG_LABELS[t] ?? t}
                    </span>
                  ))}
                  {h.actors.slice(0, 2).map((a) => (
                    <span
                      key={a.name}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-surface-100 text-muted inline-flex items-center gap-1"
                    >
                      <Users size={9} /> {a.name}
                    </span>
                  ))}
                  {h.keyFigure && <span className="text-[10px] text-brand-500">{h.keyFigure}</span>}
                </div>
              </button>
            ))}
          </div>
        </>
      )}

      {tab === 'sources' && (
        <div className="space-y-2">
          <p className="text-xs text-muted mb-2">
            {data?.counts.sources ?? '…'} primary reports behind {data?.stats.referenceCount ?? '…'} discovery
            references.
          </p>
          {(sourcesData?.sources ?? []).map((s) => (
            <div key={s.id} className="surface-card p-3">
              <a
                href={s.url}
                target="_blank"
                rel="noreferrer"
                className="text-sm font-medium text-brand-500 hover:underline inline-flex items-center gap-1"
              >
                {s.title} <ExternalLink size={12} />
              </a>
              <div className="flex flex-wrap gap-2 mt-1 text-xs text-muted">
                <span>{s.publisher}</span>
                <span>· {s.kind}</span>
                <span>· {s.date}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'about' && (
        <div className="surface-card p-5 text-sm text-muted space-y-3">
          <p>
            A harness is counted as <b>confirmed</b> when a vendor, IR firm, CERT, government or AI lab shows it in a
            real operation; <b>observed</b> when it was aimed at real targets or found on attacker infrastructure with
            no breach stated; <b>no attack on record</b> when primary reporting says nothing — which is not the same as
            no attack happening. An outlined use tag is the project's own README claim, not a tested result.
          </p>
          <p>
            This replication stores structured metadata and short factual descriptions only, deep-linking every harness,
            source and reference upstream. Upstream publishes no reuse licence. Data reviewed{' '}
            {data?.evidenceReviewed ?? '…'}; GitHub facts as of {data?.webPages ? 'the upstream field snapshot' : '…'}.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <a
              href={data?.webPages.index ?? 'https://offsecharnesses.ai/'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream index <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.data ?? 'https://offsecharnesses.ai/data/'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream data <ExternalLink size={13} />
            </a>
            <a
              href={data?.upstreamData ?? 'https://github.com/danielmiessler/substrate'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream dataset repo <ExternalLink size={13} />
            </a>
          </div>
        </div>
      )}

      <Modal
        open={bodyLoading || body !== null}
        onClose={() => setBody(null)}
        title={body?.name ?? 'Loading…'}
        size="lg"
      >
        {bodyLoading && (
          <div className="flex items-center gap-2 py-8 justify-center text-muted">
            <Loader2 size={18} className="animate-spin" /> Loading harness…
          </div>
        )}
        {body && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              {body.tier && badge(body.tier, TIER_STYLES[body.tier])}
              {body.kind && badge(body.kind)}
              {body.stars != null && <span className="text-xs text-muted">{body.stars.toLocaleString()} stars</span>}
              {body.license && <span className="text-xs text-muted">{body.license}</span>}
            </div>
            {body.description && <p className="text-sm text-muted">{body.description}</p>}
            {body.whatItDid && (
              <div className="surface-card p-3">
                <div className="text-xs font-semibold text-heading mb-1">What it did</div>
                <p className="text-sm text-muted leading-relaxed">{body.whatItDid}</p>
              </div>
            )}
            {body.keyFigure && (
              <div className="flex items-center gap-2 text-sm">
                <ShieldCheck size={14} className="text-brand-500" />
                <span className="text-heading font-medium">{body.keyFigure}</span>
              </div>
            )}
            <div>
              <div className="text-xs font-semibold text-heading mb-2">Uses (with source quotes)</div>
              <ul className="space-y-2">
                {body.uses.map((u, i) => (
                  <li key={i} className="text-sm border-l-2 border-brand-400/50 pl-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-brand-500 font-medium">{TAG_LABELS[u.tag] ?? u.tag}</span>
                      <span className="text-[10px] text-muted">{u.basis}</span>
                      {u.source && (
                        <a
                          href={u.source}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[11px] text-brand-500 hover:underline inline-flex items-center gap-1"
                        >
                          source <ExternalLink size={10} />
                        </a>
                      )}
                    </div>
                    {u.quote && <p className="text-xs text-muted mt-1 italic line-clamp-4">“{u.quote}”</p>}
                  </li>
                ))}
              </ul>
            </div>
            {body.incidents.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-heading mb-2">Related incidents</div>
                <ul className="space-y-1">
                  {body.incidents.map((i) => (
                    <li key={i.id}>
                      <a
                        href={i.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-sm text-brand-500 hover:underline inline-flex items-center gap-1"
                      >
                        {i.title} <ExternalLink size={11} />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="flex flex-wrap gap-3 pt-1">
              {body.repo && (
                <a
                  href={body.repo}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
                >
                  <Github size={13} /> Repository <ExternalLink size={12} />
                </a>
              )}
              <a
                href={body.upstreamUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
              >
                Upstream entry <ExternalLink size={13} />
              </a>
            </div>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
