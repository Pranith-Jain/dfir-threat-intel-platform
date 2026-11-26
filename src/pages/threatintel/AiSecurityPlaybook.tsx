import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { ExternalLink, Layers, ListTree, ShieldQuestion, Tag } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * AI Security Playbook — taxonomy layer from aisecurity.zone.
 *
 * LICENCE SCOPE: upstream declares no reuse licence (no LICENSE file, /terms/
 * and /license/ 404, and the repository named in its own CONTRIBUTING page
 * returns 404). This page therefore renders STRUCTURE ONLY — the 8 system
 * divisions, the 20 published risk identifiers, and public CVE references deep-
 * linked to the original. It deliberately shows no chapter prose: that is the
 * author's expression, and every card links out so a reader gets the real text.
 *
 * Companion verticals: cairn / nova / denali carry the executable detection
 * logic. This one answers "what is this class of problem called, which part of
 * the stack does it live in, and where do I read more".
 *
 * Reads:
 *   GET /api/v1/ai-playbook/          → index (counts + layers + identifiers)
 *   GET /api/v1/ai-playbook/cves      → CVE refs joined to our local KEV feed
 *   GET /api/v1/ai-playbook/stats     → counts, KEV matches, cache state
 */

interface Layer {
  id: string;
  name: string;
  slug: string;
  chapters: number;
  summary: string;
  url: string;
  riskIds: string[];
}

interface RiskId {
  id: string;
  name: string;
  scheme: 'owasp-llm' | 'agentic-asi';
  layer: string;
  layerName: string | null;
  url: string;
}

interface Index {
  source: string;
  sourceUrl: string;
  author: string;
  license: string;
  licenseNote: string;
  replicatedAt: string;
  scope: string;
  counts: {
    layers: number;
    chapters: number;
    riskIds: number;
    owaspLlm: number;
    agenticAsi: number;
    cveRefs: number;
  };
  layers: Layer[];
  riskIds: RiskId[];
}

interface CveRef {
  cveId: string;
  kev: boolean;
  vendor: string | null;
  product: string | null;
  name: string | null;
  dateAdded: string | null;
  dueDate: string | null;
}

const SCHEME_LABEL: Record<RiskId['scheme'], string> = {
  'owasp-llm': 'OWASP LLM Top 10',
  'agentic-asi': 'Agentic Security Index',
};

export default function AiSecurityPlaybook(): JSX.Element {
  const [selectedLayer, setSelectedLayer] = useState<string | null>(null);

  const index = useDataFetch<Index>({ url: '/api/v1/ai-playbook/' });
  const cves = useDataFetch<{ total: number; kevMatched: number; cves: CveRef[] }>({
    url: '/api/v1/ai-playbook/cves',
  });

  const riskIds = useMemo(() => {
    const all = index.data?.riskIds ?? [];
    if (!selectedLayer) return all;
    return all.filter((r) => r.layer === selectedLayer);
  }, [index.data, selectedLayer]);

  const grouped = useMemo(() => {
    const byScheme: Record<string, RiskId[]> = {};
    for (const r of riskIds) (byScheme[r.scheme] ||= []).push(r);
    return byScheme;
  }, [riskIds]);

  const briefingItems = useMemo(
    () =>
      (index.data?.riskIds ?? []).slice(0, 50).map((r) => ({
        title: `${r.id} ${r.name}`,
        body: `${SCHEME_LABEL[r.scheme] ?? r.scheme} · division ${r.layer}${r.layerName ? ` (${r.layerName})` : ''}`,
        source: r.url,
      })),
    [index.data]
  );

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ListTree size={22} />}
      title="AI Security Playbook"
      description="Taxonomy layer: 8 system divisions and 20 risk identifiers (OWASP LLM01-10 + ASI01-10). Structure and identifiers only — upstream has no reuse licence, so every card deep-links to the original."
      loading={index.loading}
      error={index.error}
      onRetry={index.refetch}
      metaDescription="AI security taxonomy: 8 system divisions, 20 risk identifiers (OWASP LLM Top 10 and the Agentic Security Index), and cited CVEs joined to CISA KEV."
    >
      {index.data && (
        <div className="space-y-8">
          {/* Scope notice — this is the licence position, stated where a reader
              sees the data rather than buried in a footer. */}
          <div className="border-l-4 border-amber-500 bg-amber-50 dark:bg-amber-950/20 px-4 py-3">
            <p className="text-sm font-semibold flex items-center gap-2">
              <ShieldQuestion size={16} />
              Structure replicated — prose is not
            </p>
            <p className="text-mini font-mono mt-1 text-muted">{index.data.licenseNote}</p>
            <a
              href={index.data.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-mini font-mono mt-2 underline hover:text-brand-600 dark:hover:text-brand-400"
            >
              Read the original ({index.data.author}) <ExternalLink size={12} />
            </a>
          </div>

          <DetectionAiBriefing
            surface="AI Security Playbook"
            source="ai-playbook"
            items={briefingItems}
            dayKey={index.data?.replicatedAt?.slice(0, 10)}
            label="risk identifiers"
          />

          {/* Counts */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              ['Divisions', index.data.counts.layers],
              ['Chapters', index.data.counts.chapters],
              ['Risk IDs', index.data.counts.riskIds],
              ['OWASP LLM', index.data.counts.owaspLlm],
              ['ASI', index.data.counts.agenticAsi],
            ].map(([label, value]) => (
              <div key={String(label)} className="surface-card px-3 py-2">
                <p className="text-mini font-mono text-muted">{label}</p>
                <p className="text-xl font-bold tabular-nums">{value}</p>
              </div>
            ))}
          </div>

          {/* Layers */}
          <section>
            <h2 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Layers size={18} /> System divisions
            </h2>
            <div className="grid gap-3 md:grid-cols-2">
              {index.data.layers.map((l) => (
                <button
                  key={l.id}
                  type="button"
                  onClick={() => setSelectedLayer(selectedLayer === l.id ? null : l.id)}
                  aria-pressed={selectedLayer === l.id}
                  className={`text-left surface-card px-4 py-3 hover:border-brand-500/50 focus-visible:outline-none focus-visible:border-brand-500 ${
                    selectedLayer === l.id ? 'border-brand-500' : ''
                  }`}
                >
                  <p className="font-semibold flex items-baseline gap-2">
                    <span className="font-mono text-brand-600 dark:text-brand-400">{l.id}</span>
                    {l.name}
                    <span className="text-mini font-mono text-muted ml-auto">
                      {l.chapters} ch · {l.riskIds.length} IDs
                    </span>
                  </p>
                  <p className="text-mini font-mono text-muted mt-1">{l.summary}</p>
                </button>
              ))}
            </div>
            {selectedLayer && (
              <button
                type="button"
                onClick={() => setSelectedLayer(null)}
                className="mt-2 text-mini font-mono underline hover:text-brand-600 dark:hover:text-brand-400"
              >
                Clear filter
              </button>
            )}
          </section>

          {/* Risk identifiers */}
          <section>
            <h2 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Tag size={18} /> Risk identifiers
              {selectedLayer && (
                <span className="text-mini font-mono text-muted">filtered to division {selectedLayer}</span>
              )}
            </h2>
            {Object.entries(grouped).map(([scheme, ids]) => (
              <div key={scheme} className="mb-4">
                <h3 className="text-sm font-mono text-muted mb-2">
                  {SCHEME_LABEL[scheme as RiskId['scheme']] ?? scheme} ({ids.length})
                </h3>
                <div className="grid gap-2 md:grid-cols-2">
                  {ids.map((r) => (
                    <a
                      key={r.id}
                      href={r.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="surface-card px-3 py-2 hover:border-brand-500/50 flex items-start gap-2"
                    >
                      <span className="font-mono text-brand-600 dark:text-brand-400 shrink-0">{r.id}</span>
                      <span className="min-w-0">
                        <span className="block text-sm">{r.name}</span>
                        <span className="block text-mini font-mono text-muted">
                          division {r.layer}
                          {r.layerName ? ` · ${r.layerName}` : ''}
                        </span>
                      </span>
                      <ExternalLink size={12} className="ml-auto shrink-0 text-muted" />
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </section>

          {/* Cited CVEs, enriched from OUR KEV feed */}
          <section>
            <h2 className="text-lg font-semibold mb-1">Cited CVEs</h2>
            <p className="text-mini font-mono text-muted mb-3">
              {cves.data ? `${cves.data.kevMatched} of ${cves.data.total} are in our CISA KEV snapshot.` : 'Loading…'}{' '}
              Enrichment comes from our own synced feed, never upstream.
            </p>
            {cves.data && cves.data.cves.length === 0 && (
              <p className="text-sm font-mono text-muted">No CVE references recorded.</p>
            )}
            <div className="grid gap-2 md:grid-cols-2">
              {(cves.data?.cves ?? []).map((c) => (
                <div key={c.cveId} className="surface-card px-3 py-2">
                  <p className="flex items-center gap-2">
                    <span className="font-mono text-sm">{c.cveId}</span>
                    {c.kev ? (
                      <span className="text-mini font-mono px-1.5 py-0.5 bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-300">
                        CISA KEV
                      </span>
                    ) : (
                      <span className="text-mini font-mono px-1.5 py-0.5 surface-card text-muted">not in KEV</span>
                    )}
                  </p>
                  {c.vendor && (
                    <p className="text-mini font-mono text-muted mt-1">
                      {c.vendor} {c.product}
                      {c.dateAdded ? ` · added ${c.dateAdded}` : ''}
                      {c.dueDate ? ` · due ${c.dueDate}` : ''}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </section>
        </div>
      )}
    </DataPageLayout>
  );
}
