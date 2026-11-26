import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { Crosshair, ExternalLink, Fingerprint, Radar, Search, ShieldAlert, Target } from 'lucide-react';

/**
 * Agentic Attack Detections — ThreatDefence's open detection corpus for
 * AI-agent attack frameworks (MIT). Mirrors framework coverage, sourced
 * indicators and an ATT&CK layer into public/data/aad/ via
 * scripts/build-aad-manifest.mjs; read here through the platform API.
 *
 *   GET /api/v1/aad/                 → slim index
 *   GET /api/v1/aad/frameworks/:slug → coverage, techniques, indicators
 *   GET /api/v1/aad/indicators       → filtered IOC search
 *   GET /api/v1/aad/attack           → ATT&CK Navigator layer
 */

interface Counts {
  kqlHunts: number;
  analytics: number;
  sigma: number;
  suricata: number;
  yara: number;
  indicators: number;
}
interface Framework {
  slug: string;
  name: string;
  description: string;
  seenIn: string;
  counts: Counts;
  techniqueCount: number;
}
interface Indicator {
  value: string;
  confidence: string;
  context: string;
  actor: string;
  source: string;
  sourceUrl: string;
  reported: string;
  framework: string;
  type?: string;
}
interface Technique {
  id: string;
  score: number;
  comment: string;
}
interface FrameworkBody extends Framework {
  techniques: Technique[];
  indicators: Indicator[];
  indicatorsTruncated: boolean;
  upstreamUrl: string;
}
interface Index {
  source: string;
  sourceUrl: string;
  license: string;
  description: string;
  generatedAt: string;
  stats: {
    frameworks: number;
    indicators: number;
    indicatorTypes: number;
    attackTechniques: number;
    behaviorRules: number;
    generalRules: number;
  };
  indicatorTypes: Array<{ type: string; count: number }>;
  frameworks: Framework[];
  shared: {
    behaviors: { count: number; rules: Array<{ path: string; kind: string; name: string }> };
    general: { count: number; rules: Array<{ path: string; kind: string; name: string }> };
  };
}

type Tab = 'frameworks' | 'indicators' | 'attack' | 'shared' | 'stats';

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';
const selectCls = `${inputCls} max-w-xs`;

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-line-1 bg-surface-100 dark:bg-surface-100 px-4 py-3">
      <div className="text-2xl font-semibold text-heading">{value}</div>
      <div className="text-xs text-muted mt-1">{label}</div>
    </div>
  );
}

export default function AgenticAttacks(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<Index>({
    url: '/api/v1/aad/',
    ttl: 300_000,
  });
  const [tab, setTab] = useState<Tab>('frameworks');
  const [q, setQ] = useState('');
  const [iocType, setIocType] = useState('');
  const [framework, setFramework] = useState('');
  const [body, setBody] = useState<FrameworkBody | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [iocLoading, setIocLoading] = useState(false);
  const { data: attack } = useDataFetch<{ techniques: Technique[]; maxValue: number }>({
    url: '/api/v1/aad/attack',
    ttl: 300_000,
  });

  const frameworks = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.frameworks ?? []).filter(
      (r) => !needle || `${r.name} ${r.slug} ${r.description} ${r.seenIn}`.toLowerCase().includes(needle)
    );
  }, [data, q]);

  async function open(slug: string) {
    setBodyLoading(true);
    setBody(null);
    try {
      setBody(await api.get<FrameworkBody>(`/api/v1/aad/frameworks/${encodeURIComponent(slug)}`));
    } catch {
      setBody(null);
    } finally {
      setBodyLoading(false);
    }
  }

  async function searchIndicators() {
    setIocLoading(true);
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (iocType) params.set('type', iocType);
      if (framework) params.set('framework', framework);
      if (q.trim()) params.set('q', q.trim());
      const res = await api.get<{ indicators: Indicator[] }>(`/api/v1/aad/indicators?${params}`);
      setIndicators(res.indicators ?? []);
    } catch {
      setIndicators([]);
    } finally {
      setIocLoading(false);
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'frameworks', label: `Frameworks (${data?.stats.frameworks ?? '…'})` },
    { id: 'indicators', label: `Indicators (${data?.stats.indicators ?? '…'})` },
    { id: 'attack', label: `ATT&CK (${data?.stats.attackTechniques ?? '…'})` },
    { id: 'shared', label: 'Shared rules' },
    { id: 'stats', label: 'Stats' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Crosshair size={28} />}
      title="Agentic Attack Detections"
      description={
        <>
          Detection rules, hunting queries and sourced indicators for AI-agent attack frameworks, curated by{' '}
          <a
            href={data?.sourceUrl ?? 'https://github.com/ThreatDefence/agentic-attack-detections'}
            target="_blank"
            rel="noreferrer"
            className="text-brand-600 hover:underline inline-flex items-center gap-1"
          >
            ThreatDefence <ExternalLink size={12} />
          </a>
          . MIT licensed; data mirrored locally.
        </>
      }
      loading={loading}
      error={error}
      onRetry={refetch}
      maxWidthClass="max-w-6xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-white border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'frameworks' && (
        <>
          <div className="relative mb-4 max-w-md">
            <Search size={16} className="absolute left-3 top-2.5 text-muted" />
            <input
              className={`${inputCls} pl-9`}
              placeholder="Search frameworks, actors, targets…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {frameworks.map((f) => (
              <button
                key={f.slug}
                onClick={() => open(f.slug)}
                className="text-left rounded-xl border border-line-1 bg-surface-100 dark:bg-surface-100 hover:border-brand-400 transition-colors p-4"
              >
                <div className="font-semibold text-heading">{f.name}</div>
                <div className="text-xs text-muted mt-1 line-clamp-2">
                  {f.description || f.seenIn || 'Console-level coverage from upstream source review.'}
                </div>
                <div className="flex flex-wrap gap-2 mt-3 text-[11px] text-muted">
                  <span>KQL {f.counts.kqlHunts}</span>
                  <span>Sigma {f.counts.sigma}</span>
                  <span>Suricata {f.counts.suricata}</span>
                  <span>YARA {f.counts.yara}</span>
                  <span>IOCs {f.counts.indicators}</span>
                  <span className="text-brand-600 dark:text-brand-400">ATT&amp;CK {f.techniqueCount}</span>
                </div>
              </button>
            ))}
          </div>
          {frameworks.length === 0 && <p className="text-sm text-muted py-8 text-center">No frameworks match “{q}”.</p>}
        </>
      )}

      {tab === 'indicators' && (
        <>
          <div className="flex flex-wrap gap-2 mb-4">
            <input
              className={`${inputCls} max-w-sm`}
              placeholder="Search indicator value or context…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <select className={selectCls} value={iocType} onChange={(e) => setIocType(e.target.value)}>
              <option value="">All IOC types</option>
              {(data?.indicatorTypes ?? []).map((t) => (
                <option key={t.type} value={t.type}>
                  {t.type} ({t.count})
                </option>
              ))}
            </select>
            <select className={selectCls} value={framework} onChange={(e) => setFramework(e.target.value)}>
              <option value="">All frameworks</option>
              {(data?.frameworks ?? []).map((f) => (
                <option key={f.slug} value={f.slug}>
                  {f.name}
                </option>
              ))}
            </select>
            <button
              onClick={searchIndicators}
              className="px-4 py-2 rounded-xl bg-brand-600 text-on-fill text-sm font-medium"
            >
              Search
            </button>
          </div>
          {iocLoading && <p className="text-sm text-muted">Searching…</p>}
          <div className="rounded-xl border border-line-1 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-surface-200 dark:bg-surface-200 text-left text-xs text-muted">
                <tr>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Value</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Framework</th>
                  <th className="px-3 py-2">Source</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((it, i) => (
                  <tr key={`${it.value}-${i}`} className="border-t border-line-1 align-top">
                    <td className="px-3 py-2 text-xs">{it.type}</td>
                    <td className="px-3 py-2 font-mono text-xs break-all">{it.value}</td>
                    <td className="px-3 py-2 text-xs">{it.confidence}</td>
                    <td className="px-3 py-2 text-xs">{it.framework}</td>
                    <td className="px-3 py-2 text-xs">
                      {it.sourceUrl ? (
                        <a
                          href={it.sourceUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="text-brand-600 hover:underline inline-flex items-center gap-1"
                        >
                          {it.source} <ExternalLink size={11} />
                        </a>
                      ) : (
                        it.source || '—'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!iocLoading && indicators.length === 0 && (
            <p className="text-sm text-muted py-8 text-center">Choose filters and press Search.</p>
          )}
        </>
      )}

      {tab === 'attack' && (
        <div className="rounded-xl border border-line-1 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-surface-200 dark:bg-surface-200 text-left text-xs text-muted">
              <tr>
                <th className="px-3 py-2">Technique</th>
                <th className="px-3 py-2">Rules</th>
                <th className="px-3 py-2">Coverage</th>
              </tr>
            </thead>
            <tbody>
              {(attack?.techniques ?? []).map((t) => (
                <tr key={t.id} className="border-t border-line-1 align-top">
                  <td className="px-3 py-2">
                    <a
                      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-600 hover:underline inline-flex items-center gap-1"
                    >
                      {t.id} <ExternalLink size={11} />
                    </a>
                  </td>
                  <td className="px-3 py-2">{t.score}</td>
                  <td className="px-3 py-2 text-xs text-muted">{t.comment}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'shared' && (
        <div className="grid gap-4 md:grid-cols-2">
          {(['behaviors', 'general'] as const).map((key) => (
            <div key={key} className="rounded-xl border border-line-1 p-4">
              <h3 className="font-semibold text-heading capitalize flex items-center gap-2">
                {key === 'behaviors' ? <Radar size={16} /> : <Target size={16} />}
                {key === 'behaviors' ? 'AI agent behaviors' : 'General intrusion'} ({data?.shared[key].count ?? 0})
              </h3>
              <div className="mt-3 space-y-1 text-xs text-muted max-h-96 overflow-y-auto">
                {(data?.shared[key].rules ?? []).map((r) => (
                  <div key={r.path} className="font-mono break-all">
                    {r.path}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'stats' && data && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <Stat label="Frameworks" value={data.stats.frameworks} />
          <Stat label="Indicators" value={data.stats.indicators} />
          <Stat label="IOC types" value={data.stats.indicatorTypes} />
          <Stat label="ATT&CK techniques" value={data.stats.attackTechniques} />
          <Stat label="Behavior rules" value={data.stats.behaviorRules} />
          <Stat label="General rules" value={data.stats.generalRules} />
          <div className="col-span-full rounded-xl border border-line-1 p-4 text-sm text-muted">
            <Fingerprint size={16} className="inline mr-2" />
            Source: {data.source} · License: {data.license} · Built {data.generatedAt}
          </div>
        </div>
      )}

      <Modal
        open={body !== null || bodyLoading}
        onClose={() => setBody(null)}
        size="xl"
        title={body?.name ?? 'Loading framework…'}
      >
        {bodyLoading && <p className="text-sm text-muted">Loading…</p>}
        {body && (
          <div className="space-y-5 text-sm">
            <div className="text-muted">{body.description || body.seenIn}</div>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 rounded border border-line-1">KQL hunts {body.counts.kqlHunts}</span>
              <span className="px-2 py-1 rounded border border-line-1">Analytics {body.counts.analytics}</span>
              <span className="px-2 py-1 rounded border border-line-1">Sigma {body.counts.sigma}</span>
              <span className="px-2 py-1 rounded border border-line-1">Suricata {body.counts.suricata}</span>
              <span className="px-2 py-1 rounded border border-line-1">YARA {body.counts.yara}</span>
              <span className="px-2 py-1 rounded border border-line-1">IOCs {body.counts.indicators}</span>
            </div>
            <div>
              <h4 className="font-semibold text-heading flex items-center gap-2 mb-2">
                <ShieldAlert size={15} /> ATT&amp;CK techniques ({body.techniques.length})
              </h4>
              <div className="space-y-1 max-h-56 overflow-y-auto">
                {body.techniques.map((t) => (
                  <div key={t.id} className="text-xs">
                    <span className="text-brand-600 font-medium">{t.id}</span>{' '}
                    <span className="text-muted">· {t.score} rules</span> — {t.comment}
                  </div>
                ))}
                {body.techniques.length === 0 && <div className="text-muted">No per-framework layer upstream.</div>}
              </div>
            </div>
            <div>
              <h4 className="font-semibold text-heading mb-2">
                Sourced indicators ({body.indicators.length}
                {body.indicatorsTruncated ? '+ (truncated)' : ''})
              </h4>
              <div className="space-y-1 max-h-56 overflow-y-auto">
                {body.indicators.map((it, i) => (
                  <div key={`${it.value}-${i}`} className="text-xs flex gap-2">
                    <span className="text-muted w-20 shrink-0">{it.type}</span>
                    <span className="font-mono break-all">{it.value}</span>
                    <span className="text-muted shrink-0">{it.confidence}</span>
                  </div>
                ))}
              </div>
            </div>
            <a
              href={body.upstreamUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-600 hover:underline text-xs"
            >
              View framework rules upstream <ExternalLink size={12} />
            </a>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
