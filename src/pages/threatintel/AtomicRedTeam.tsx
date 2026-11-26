import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { Activity, ExternalLink, FlaskConical, Search, Target } from 'lucide-react';

/**
 * Atomic Red Team — the public ATT&CK test catalog behind atomicredteam.io,
 * replicated from redcanaryco/atomic-red-team (MIT) into public/data/art/ by
 * scripts/build-art-manifest.mjs. Only test metadata is mirrored; executor
 * commands stay upstream and every test deep-links its canonical YAML.
 *
 *   GET /api/v1/art/                      → slim technique index
 *   GET /api/v1/art/techniques/:id        → per-technique test metadata
 *   GET /api/v1/art/stats                 → platform/executor breakdowns
 */

interface Test {
  name: string;
  guid: string;
  description: string;
  platforms: string[];
  executor: { name: string; elevationRequired: boolean; hasCleanup: boolean };
  inputArguments: string[];
  dependencyCount: number;
}
interface Technique {
  id: string;
  displayName: string;
  testCount: number;
  platforms: string[];
  executors: string[];
  subtechnique: boolean;
  upstreamUrl: string;
}
interface TechniqueBody extends Technique {
  tests: Test[];
  siteUrl: string;
}
interface Index {
  source: string;
  sourceUrl: string;
  siteUrl: string;
  license: string;
  generatedAt: string;
  stats: { techniques: number; tests: number; platforms: number; executors: number; failed: number };
  platformCounts: Record<string, number>;
  executorCounts: Record<string, number>;
  techniques: Technique[];
}

type Tab = 'techniques' | 'stats';

const inputCls =
  'w-full px-3 py-2 bg-input-200 border border-line-input rounded-control text-sm text-heading placeholder:text-muted';
const selectCls = `${inputCls} w-full sm:w-auto sm:max-w-xs`;

function Breakdown({ title, counts }: { title: string; counts: Record<string, number> }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, n]) => n));
  return (
    <div className="rounded-xl border border-line-1 p-4">
      <h3 className="font-semibold text-heading mb-3">{title}</h3>
      <div className="space-y-2">
        {entries.map(([key, n]) => (
          <div key={key}>
            <div className="flex justify-between text-xs text-muted mb-1">
              <span>{key}</span>
              <span>{n}</span>
            </div>
            <div className="h-1.5 rounded-full bg-surface-300 overflow-hidden">
              <div className="h-full bg-brand-500" style={{ width: `${(n / max) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AtomicRedTeam(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<Index>({
    url: '/api/v1/art/',
    ttl: 300_000,
  });
  const [tab, setTab] = useState<Tab>('techniques');
  const [q, setQ] = useState('');
  const [platform, setPlatform] = useState('');
  const [executor, setExecutor] = useState('');
  const [sub, setSub] = useState('');
  const [body, setBody] = useState<TechniqueBody | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.techniques ?? []).filter((r) => {
      if (needle && !`${r.id} ${r.displayName}`.toLowerCase().includes(needle)) return false;
      if (platform && !r.platforms.includes(platform)) return false;
      if (executor && !r.executors.includes(executor)) return false;
      if (sub === 'true' && !r.subtechnique) return false;
      if (sub === 'false' && r.subtechnique) return false;
      return true;
    });
  }, [data, q, platform, executor, sub]);

  async function open(id: string) {
    setBodyLoading(true);
    setBody(null);
    try {
      setBody(await api.get<TechniqueBody>(`/api/v1/art/techniques/${encodeURIComponent(id)}`));
    } catch {
      setBody(null);
    } finally {
      setBodyLoading(false);
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'techniques', label: `Techniques (${data?.stats.techniques ?? '…'})` },
    { id: 'stats', label: 'Stats' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<FlaskConical size={28} />}
      title="Atomic Red Team"
      description={
        <>
          MIT ATT&amp;CK technique catalog with ~1,950 atomic test descriptions, mirrored from{' '}
          <a
            href={data?.siteUrl ?? 'https://www.atomicredteam.io'}
            target="_blank"
            rel="noreferrer"
            className="text-accent-text hover:underline inline-flex items-center gap-1"
          >
            atomicredteam.io <ExternalLink size={12} />
          </a>
          . Executor commands stay upstream — each test deep-links its canonical YAML.
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
            className={`px-4 py-2.5 min-h-11 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-on-fill border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'techniques' && (
        <>
          <div className="flex flex-wrap gap-2 mb-4">
            <div className="relative flex-1 min-w-0 sm:min-w-60">
              <Search size={16} className="absolute left-3 top-2.5 text-muted" />
              <input
                className={`${inputCls} pl-9`}
                placeholder="Search ATT&CK id or technique name…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <select className={selectCls} value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="">All platforms</option>
              {Object.keys(data?.platformCounts ?? {}).map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <select className={selectCls} value={executor} onChange={(e) => setExecutor(e.target.value)}>
              <option value="">All executors</option>
              {Object.keys(data?.executorCounts ?? {}).map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
            <select className={`${inputCls} w-full sm:w-40`} value={sub} onChange={(e) => setSub(e.target.value)}>
              <option value="">All techniques</option>
              <option value="true">Sub-techniques</option>
              <option value="false">Base techniques</option>
            </select>
          </div>
          <div className="rounded-xl border border-line-1 overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead className="bg-surface-200 text-left text-xs text-muted">
                <tr>
                  <th className="px-3 py-2">ID</th>
                  <th className="px-3 py-2">Technique</th>
                  <th className="px-3 py-2">Tests</th>
                  <th className="px-3 py-2">Platforms</th>
                  <th className="px-3 py-2">Executors</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 300).map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => open(r.id)}
                    className="border-t border-line-1 cursor-pointer hover:bg-surface-200 dark:hover:bg-surface-200"
                  >
                    <td className="px-3 py-2 font-mono text-xs text-accent-text">{r.id}</td>
                    <td className="px-3 py-2">{r.displayName}</td>
                    <td className="px-3 py-2">{r.testCount}</td>
                    <td className="px-3 py-2 text-xs text-muted">{r.platforms.join(', ') || '—'}</td>
                    <td className="px-3 py-2 text-xs text-muted">{r.executors.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length > 300 && (
            <p className="text-xs text-muted mt-2">Showing first 300 of {rows.length} matches — narrow the filters.</p>
          )}
          {rows.length === 0 && <p className="text-sm text-muted py-8 text-center">No techniques match the filters.</p>}
        </>
      )}

      {tab === 'stats' && data && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
            <div className="rounded-xl border border-line-1 px-4 py-3">
              <div className="text-2xl font-semibold text-heading">{data.stats.techniques}</div>
              <div className="text-xs text-muted">Techniques</div>
            </div>
            <div className="rounded-xl border border-line-1 px-4 py-3">
              <div className="text-2xl font-semibold text-heading">{data.stats.tests}</div>
              <div className="text-xs text-muted">Atomic tests</div>
            </div>
            <div className="rounded-xl border border-line-1 px-4 py-3">
              <div className="text-2xl font-semibold text-heading">{data.stats.platforms}</div>
              <div className="text-xs text-muted">Platforms</div>
            </div>
            <div className="rounded-xl border border-line-1 px-4 py-3">
              <div className="text-2xl font-semibold text-heading">{data.stats.executors}</div>
              <div className="text-xs text-muted">Executor types</div>
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Breakdown title="Platforms" counts={data.platformCounts} />
            <Breakdown title="Executors" counts={data.executorCounts} />
          </div>
        </>
      )}

      <Modal
        open={body !== null || bodyLoading}
        onClose={() => setBody(null)}
        size="xl"
        title={body ? `${body.id} · ${body.displayName}` : 'Loading technique…'}
      >
        {bodyLoading && <p className="text-sm text-muted">Loading…</p>}
        {body && (
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 rounded border border-line-1">
                <Activity size={12} className="inline mr-1" />
                {body.tests.length} tests
              </span>
              <span className="px-2 py-1 rounded border border-line-1">
                {body.platforms.join(', ') || 'no platform'}
              </span>
              <span className="px-2 py-1 rounded border border-line-1">MIT license</span>
            </div>
            <div className="space-y-3 max-h-[55vh] overflow-y-auto">
              {body.tests.map((t) => (
                <div key={t.guid} className="rounded-lg border border-line-1 p-3">
                  <div className="font-semibold text-heading flex items-center gap-2">
                    <Target size={14} /> {t.name}
                  </div>
                  <div className="text-xs text-muted mt-1">{t.description}</div>
                  <div className="text-mini text-muted mt-2 flex flex-wrap gap-3">
                    <span>Executor: {t.executor.name || '—'}</span>
                    <span>Elevation: {t.executor.elevationRequired ? 'yes' : 'no'}</span>
                    <span>Platforms: {t.platforms.join(', ') || '—'}</span>
                    <span>Inputs: {t.inputArguments.join(', ') || 'none'}</span>
                    <span>Dependencies: {t.dependencyCount}</span>
                  </div>
                </div>
              ))}
            </div>
            <a
              href={body.upstreamUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-accent-text hover:underline text-xs"
            >
              View atomic test definitions (executor commands) upstream <ExternalLink size={12} />
            </a>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
