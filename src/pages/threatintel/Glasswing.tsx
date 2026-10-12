import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataState } from '../../components/DataState';
import { fetchJsonCached } from '../../lib/api-client';
import { Bot, ExternalLink } from 'lucide-react';

interface Finding {
  cveId: string;
  findingId: string | null;
  ecosystem: string | null;
  weakness: string | null;
  severity: string | null;
  discoveredAt: string | null;
  title: string | null;
  nvdUrl: string | null;
  findingUrl: string | null;
}

interface LedgerMeta {
  schemaVersion: string;
  generatedAt: string;
  sourceUrl: string;
  attribution: string;
  total: number;
  bySeverity: Record<string, number>;
  severityRanked: Array<{ id: string; count: number }>;
  ecosystemCount: number;
  topEcosystems: Array<{ id: string; findings: number }>;
  earliestDiscovery: string | null;
}

interface FindingsResponse {
  total: number;
  findings: Finding[];
}

const SEV_TONE: Record<string, string> = {
  critical: 'text-rose-600 dark:text-rose-400',
  high: 'text-amber-600 dark:text-amber-400',
  medium: 'text-yellow-700 dark:text-yellow-500',
  low: 'text-muted',
};

/**
 * Anthropic Project Glasswing disclosure ledger.
 *
 * The distinguishing property is provenance: these CVEs were found by an AI
 * agent, not a human researcher. Both NVD and GHSA carry the ids; neither
 * records that origin, so this is the only place the distinction survives.
 */
export default function Glasswing(): JSX.Element {
  const [meta, setMeta] = useState<LedgerMeta | null>(null);
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState('');
  const [ecosystem, setEcosystem] = useState('');

  useEffect(() => {
    fetchJsonCached<LedgerMeta>('/api/v1/glasswing', 600_000)
      .then(setMeta)
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '200' });
    if (severity) params.set('severity', severity);
    if (ecosystem) params.set('ecosystem', ecosystem);
    fetchJsonCached<FindingsResponse>(`/api/v1/glasswing/findings?${params.toString()}`, 600_000)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [severity, ecosystem]);

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      icon={<Bot size={28} />}
      title="Project Glasswing Ledger"
      description="CVEs assigned to findings disclosed through Anthropic's AI vulnerability-discovery programme, with the affected ecosystem, weakness class and internal finding id."
      maxWidthClass="max-w-6xl"
    >
      <div className="surface-card p-3 mb-5 border-l-2 border-sky-500">
        <p className="text-xs text-muted">
          <strong className="text-sky-700 dark:text-sky-400">Why this is not just another CVE list.</strong> NVD and
          GitHub Advisories both carry these identifiers, and neither records who or what found the bug. The origin is
          the whole signal: an AI agent located these unaided. Each row keeps the ecosystem (<code>torvalds/linux</code>
          ,<code> twigphp/twig</code>) because that is the join key against your own asset inventory, and the weakness
          class because the class recurs far more than the specific CVE does.
        </p>
      </div>

      {meta && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
            <div className="surface-card p-3">
              <div className="text-xs font-mono text-muted uppercase tracking-wider">Findings with a CVE</div>
              <div className="text-2xl font-mono font-semibold">{meta.total}</div>
            </div>
            <div className="surface-card p-3">
              <div className="text-xs font-mono text-muted uppercase tracking-wider">Ecosystems</div>
              <div className="text-2xl font-mono font-semibold">{meta.ecosystemCount}</div>
            </div>
            <div className="surface-card p-3">
              <div className="text-xs font-mono text-muted uppercase tracking-wider">Critical + High</div>
              <div className="text-2xl font-mono font-semibold text-rose-600 dark:text-rose-400">
                {(meta.bySeverity.critical ?? 0) + (meta.bySeverity.high ?? 0)}
              </div>
            </div>
            <div className="surface-card p-3">
              <div className="text-xs font-mono text-muted uppercase tracking-wider">Earliest discovery</div>
              <div className="text-2xl font-mono font-semibold">{meta.earliestDiscovery ?? '—'}</div>
            </div>
          </div>

          <div className="surface-card p-4 mb-5">
            <h2 className="text-sm font-semibold mb-3">Most-affected projects</h2>
            <div className="flex flex-wrap gap-1.5">
              {meta.topEcosystems.map((e) => (
                <button
                  key={e.id}
                  type="button"
                  onClick={() => setEcosystem(ecosystem === e.id ? '' : e.id)}
                  aria-pressed={ecosystem === e.id}
                  className={`font-mono text-xs px-2 py-1 border rounded transition-colors ${
                    ecosystem === e.id
                      ? 'border-accent text-accent bg-surface-2'
                      : 'border-line-2 text-muted hover:text-fg'
                  }`}
                >
                  {e.id}
                  <span className="ml-1.5 opacity-70">{e.findings}</span>
                </button>
              ))}
            </div>
          </div>
        </>
      )}

      <div className="surface-card p-4 mb-5 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-xs font-mono text-muted uppercase tracking-wider">Severity</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="px-2 py-1.5 text-sm font-mono bg-surface-1 border border-line-2 rounded"
          >
            <option value="">Any</option>
            {meta?.severityRanked.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} ({s.count})
              </option>
            ))}
          </select>
        </label>
        {ecosystem && (
          <button
            type="button"
            onClick={() => setEcosystem('')}
            className="text-xs font-mono px-2 py-1.5 border border-line-2 rounded hover:bg-surface-2"
          >
            clear project filter: {ecosystem}
          </button>
        )}
      </div>

      <DataState
        loading={loading}
        error={error}
        empty={!data || data.findings.length === 0}
        emptyLabel="No findings match these filters"
        skeletonVariant="table"
        onRetry={() => setLoading(true)}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line-2 text-left font-mono text-xs uppercase tracking-wider text-muted">
                <th className="py-2 pr-3">CVE</th>
                <th className="py-2 pr-3">Project</th>
                <th className="py-2 pr-3">Weakness</th>
                <th className="py-2 pr-3">Severity</th>
                <th className="py-2 pr-3 text-right">Discovered</th>
                <th className="py-2 pr-3" />
              </tr>
            </thead>
            <tbody>
              {data?.findings.map((f) => (
                <tr key={f.cveId} className="border-b border-line-1 hover:bg-surface-2">
                  <td className="py-2 pr-3 whitespace-nowrap">
                    <Link to={`/threatintel/cve/${f.cveId}`} className="font-mono text-accent hover:underline">
                      {f.cveId}
                    </Link>
                    <div className="font-mono text-[10px] text-muted">{f.findingId}</div>
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs">{f.ecosystem}</td>
                  <td className="py-2 pr-3 font-mono text-xs text-muted">{f.weakness}</td>
                  <td className={`py-2 pr-3 font-mono text-xs font-semibold ${SEV_TONE[f.severity ?? ''] ?? ''}`}>
                    {f.severity}
                  </td>
                  <td className="py-2 pr-3 text-right font-mono text-xs text-muted whitespace-nowrap">
                    {f.discoveredAt}
                  </td>
                  <td className="py-2 pr-3 text-right">
                    {f.findingUrl && (
                      <a
                        href={f.findingUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 text-xs font-mono text-accent hover:underline"
                      >
                        write-up <ExternalLink size={11} aria-hidden />
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </DataState>

      {meta && (
        <p className="mt-8 text-xs font-mono text-muted">
          ledger synced {new Date(meta.generatedAt).toISOString().slice(0, 10)} ·{' '}
          <a href={meta.sourceUrl} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
            source
          </a>{' '}
          · {meta.attribution}
        </p>
      )}
    </DataPageLayout>
  );
}
