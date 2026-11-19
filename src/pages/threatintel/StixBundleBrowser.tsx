import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AlertTriangle, Download, GitBranch, Search, Shield, Eye } from 'lucide-react';
import {
  STIX_BUNDLES,
  SEVERITY_COLORS,
  type Severity,
  type StixBundleEntry,
} from '../../data/threatintel/stix-bundles';
import { Link } from 'react-router-dom';
import { sanitizeUrl } from '../../lib/sanitize-url';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export default function StixBundleBrowser(): JSX.Element {
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [activeSev, setActiveSev] = useState<Severity | null>(null);

  const filtered = useMemo(() => {
    let list = STIX_BUNDLES;
    if (activeSev) list = list.filter((b) => b.severity === activeSev);
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter(
        (b) =>
          b.title.toLowerCase().includes(q) ||
          b.description.toLowerCase().includes(q) ||
          b.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return list;
  }, [query, activeSev]);

  const totalIocs = STIX_BUNDLES.reduce((s, b) => s + b.iocCount, 0);
  const totalObjects = STIX_BUNDLES.reduce((s, b) => s + b.objectCount, 0);

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    STIX_BUNDLES.forEach((b) => {
      c[b.severity] = (c[b.severity] || 0) + 1;
    });
    return c;
  }, []);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<GitBranch size={28} />}
      title="STIX Bundle Browser"
      maxWidthClass="max-w-5xl"
      description={
        <>
          STIX 2.1 threat intelligence bundles - import into OpenCTI, MISP, or any STIX-aware platform.{' '}
          {STIX_BUNDLES.length} campaigns · {totalIocs.toLocaleString()} IOCs · {totalObjects.toLocaleString()} objects.
          Curated from{' '}
          <a
            href="https://the-hunters-ledger.com/stix/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            The Hunter's Ledger
          </a>{' '}
          (CC BY-NC 4.0).
        </>
      }
      headerExtra={
        <div className="flex items-center gap-3 mt-2">
          <a
            href="https://the-hunters-ledger.com/stix/hunters-ledger-stix-bundles.zip"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 hover:border-emerald-500/70 transition-colors"
          >
            <Download size={12} /> Download all (.zip)
          </a>
        </div>
      }
    >
      <div className="flex items-center gap-2 mb-4">
        <div className="relative flex-1 max-w-md">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search bundles, tags…"
            className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
          />
        </div>
        <span className="text-xs font-mono text-muted">{filtered.length} bundles</span>
      </div>

      <div className="flex flex-wrap gap-1.5 mb-6">
        <button
          type="button"
          onClick={() => setActiveSev(null)}
          className={`text-xs font-mono px-3 py-1.5 rounded-xl border transition-colors ${
            !activeSev
              ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
              : 'border-line-1 text-slate-500 hover:border-slate-300 dark:hover:border-line-1'
          }`}
        >
          All ({STIX_BUNDLES.length})
        </button>
        {SEVERITIES.map((sev) => (
          <button
            type="button"
            key={sev}
            onClick={() => setActiveSev(activeSev === sev ? null : sev)}
            className={`text-xs font-mono px-3 py-1.5 rounded-xl border transition-colors ${
              activeSev === sev
                ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                : 'border-line-1 text-slate-500 hover:border-slate-300 dark:hover:border-line-1'
            }`}
          >
            {sev.toUpperCase()} ({sevCounts[sev] || 0})
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {filtered.map((bundle) => (
          <BundleCard key={bundle.id} bundle={bundle} />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-sm font-mono text-muted">No bundles match your search.</div>
      )}
    </DataPageLayout>
  );
}

function BundleCard({ bundle }: { bundle: StixBundleEntry }): JSX.Element {
  return (
    <div className="surface-card p-4 transition-all hover:border-line-2 dark:hover:border-line-1 hover:shadow-e3 hover:shadow-slate-200/50 dark:hover:shadow-slate-900/50">
      <div className="flex items-start gap-4">
        <span
          className={`inline-flex items-center gap-1 text-micro font-mono font-semibold px-2 py-1 rounded border uppercase tracking-wider flex-shrink-0 ${SEVERITY_COLORS[bundle.severity]}`}
        >
          {bundle.severity === 'critical' && <AlertTriangle size={10} />}
          {bundle.severity === 'high' && <Shield size={10} />}
          {bundle.severity}
        </span>

        <div className="flex-1 min-w-0">
          <h3 className="font-mono font-semibold text-sm text-heading leading-snug mb-1">{bundle.title}</h3>
          <p className="text-xs text-muted leading-relaxed mb-2 line-clamp-2">{bundle.description}</p>
          <div className="flex items-center gap-3 text-mini font-mono text-muted mb-2">
            <span>{bundle.date}</span>
            <span>·</span>
            <span>{bundle.objectCount} objects</span>
            <span>·</span>
            <span>{bundle.iocCount} IOCs</span>
            <span>·</span>
            <span>{bundle.source}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {bundle.tags.map((tag) => (
              <span key={tag} className="text-micro font-mono px-2 py-0.5 rounded border border-line-1 text-muted">
                {tag}
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-2 flex-shrink-0">
          <a
            href={sanitizeUrl(bundle.downloadUrl)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-mini font-mono px-3 py-1.5 rounded-xl border border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <Download size={11} /> JSON
          </a>
          <Link
            to={bundle.viewerPath}
            className="inline-flex items-center gap-1.5 text-mini font-mono px-3 py-1.5 rounded-xl border border-line-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <Eye size={11} /> View
          </Link>
        </div>
      </div>
    </div>
  );
}
