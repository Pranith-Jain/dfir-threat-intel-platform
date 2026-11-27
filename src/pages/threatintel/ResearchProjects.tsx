/**
 * Research projects — metadata-only reference page for Grid-STIX (GPL-3.0)
 * and ARTEX-CC (AGPL-3.0). No upstream code, prose or images are vendored.
 */
import { type JSX } from 'react';
import { ExternalLink, FileText } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface Project {
  id: string;
  name: string;
  repo: string;
  url: string;
  license: string;
  summary: string;
  facts: Array<{ label: string; value: string }>;
  capabilities: string[];
  headings: string[];
  note: string;
}

interface Index {
  generatedAt: string;
  source: string;
  counts: { projects: number };
  projects: Project[];
}

export default function ResearchProjects(): JSX.Element {
  const { data, loading, error } = useDataFetch<Index>({ url: '/data/research-projects/index.json', ttl: 10 * 60_000 });
  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<FileText size={28} />}
      title="Research Projects"
      description="Metadata and upstream links for two open security research projects — Grid-STIX (electrical-grid ontology) and ARTEX-CC (MCP pentest bridge)."
      maxWidthClass="max-w-6xl"
    >
      <PageMeta
        title="Security research projects — Grid-STIX and ARTEX-CC"
        description="Factual metadata and public headings only; no upstream code or prose is vendored. Both projects carry copyleft licences."
        section="Threat Intel"
        canonicalPath="/threatintel/research-projects"
      />

      <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-mini leading-relaxed text-amber-800 dark:text-amber-200">
        Both projects are copyleft (GPL-3.0 / AGPL-3.0). This page stores only short original summaries, factual counts
        and public headings — no upstream code, README prose or images. Follow the links for the real documentation.
      </div>

      {loading && !data && <p className="text-mini font-mono text-muted">loading project metadata…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className="grid gap-4 md:grid-cols-2">
        {(data?.projects ?? []).map((p) => (
          <article key={p.id} className="surface-card p-4">
            <div className="flex items-start justify-between gap-2">
              <h2 className="text-lg font-semibold text-heading">{p.name}</h2>
              <span className="rounded border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 font-mono text-micro text-sky-700 dark:text-sky-300">
                {p.license}
              </span>
            </div>
            <p className="mt-1 font-mono text-micro text-muted">{p.repo}</p>
            <p className="mt-3 text-sm leading-relaxed text-body">{p.summary}</p>
            <dl className="mt-3 space-y-1.5">
              {p.facts.map((f) => (
                <div key={f.label} className="flex gap-2 text-mini">
                  <dt className="w-24 shrink-0 font-mono text-muted">{f.label}</dt>
                  <dd className="text-body">{f.value}</dd>
                </div>
              ))}
            </dl>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {p.capabilities.map((c) => (
                <span key={c} className="rounded-full border border-line-1 px-2 py-0.5 text-micro text-muted">
                  {c}
                </span>
              ))}
            </div>
            {p.headings.length > 0 && (
              <details className="mt-3">
                <summary className="cursor-pointer font-mono text-micro text-muted">
                  public README headings ({p.headings.length})
                </summary>
                <ul className="mt-1 list-inside list-disc space-y-0.5 text-mini text-muted">
                  {p.headings.map((h, i) => (
                    <li key={i}>{h}</li>
                  ))}
                </ul>
              </details>
            )}
            <div className="mt-4 flex flex-wrap gap-3">
              <a
                href={sanitizeUrl(p.url) ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-mini text-sky-600 hover:underline dark:text-sky-400"
              >
                repository <ExternalLink size={10} />
              </a>
            </div>
            <p className="mt-2 text-micro text-muted">{p.note}</p>
          </article>
        ))}
      </div>
    </DataPageLayout>
  );
}
