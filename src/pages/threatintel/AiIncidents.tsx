import { useEffect, useMemo, useState } from 'react';
import { Newspaper, Search, ExternalLink } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

interface Report {
  id: string;
  guid: string;
  title: string;
  link: string;
  pubDate: string | null;
  citeId: string | null;
  reportNum: string | null;
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

export default function AiIncidents(): JSX.Element {
  const [reports, setReports] = useState<Report[]>([]);
  const [total, setTotal] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);
  const [bodies, setBodies] = useState<Record<string, string>>({});

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/ai-security/incidents?limit=100');
      if (!r.ok) throw new Error(`incidents HTTP ${r.status}`);
      const j = (await r.json()) as { total: number; reports: Report[] };
      setReports(j.reports ?? []);
      setTotal(j.total ?? 0);
      const h = await (await fetch('/api/v1/ai-security/')).json().catch(() => null);
      setUpdatedAt((h as { latestIncidentAt?: string } | null)?.latestIncidentAt ?? null);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase().trim();
    if (!needle) return reports;
    return reports.filter((r) => `${r.title} ${r.id} ${r.citeId ?? ''}`.toLowerCase().includes(needle));
  }, [reports, query]);

  const openBody = async (id: string) => {
    if (bodies[id] !== undefined || openId === id) {
      setOpenId(openId === id ? null : id);
      return;
    }
    setOpenId(id);
    try {
      const r = await fetch(`/api/v1/ai-security/incidents/${encodeURIComponent(id)}`);
      if (r.ok) {
        const j = (await r.json()) as { description?: string };
        setBodies((m) => ({ ...m, [id]: j.description ?? '' }));
      }
    } catch {
      /* non-fatal */
    }
  };

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      backLabel="AI Security"
      icon={<Newspaper size={28} />}
      title="AI Incidents"
      description={
        <>
          Daily mirror of the{' '}
          <a
            href="https://incidentdatabase.ai"
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="text-sky-600 dark:text-sky-400 hover:underline"
          >
            AI Incident Database
          </a>{' '}
          RSS feed — harms in the wild, tracked per cite. Rows link back upstream; sync runs daily via the ai-security
          workflow.
        </>
      }
      loading={loading && reports.length === 0}
      error={error}
      onRetry={load}
    >
      <AiSummaryCard
        surface="AI Incidents"
        items={filtered.slice(0, 15).map((r) => ({
          title: r.title,
          body: `${fmtDate(r.pubDate)} · cite ${r.citeId ?? '—'} · report ${r.reportNum ?? r.id}`,
          source: r.link,
        }))}
        requireAdmin={false}
      />
      <div className="relative my-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
        <input
          type="text"
          placeholder="Search incident titles, cite ids…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
        />
      </div>
      <p className="mb-3 text-micro font-mono text-muted">
        {filtered.length} / {total} reports · latest {fmtDate(updatedAt)}
      </p>
      <div className="grid gap-2">
        {filtered.map((r) => {
          const open = openId === r.id;
          return (
            <div key={r.guid} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
              <button
                type="button"
                onClick={() => void openBody(r.id)}
                className="w-full text-left"
                aria-expanded={open}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-micro font-mono text-muted">
                    cite {r.citeId ?? '—'} · #{r.reportNum ?? r.id}
                  </span>
                  <span className="text-micro font-mono text-muted">{fmtDate(r.pubDate)}</span>
                </div>
                <h3 className="text-sm font-bold text-heading mt-1 leading-snug">{r.title || '(untitled report)'}</h3>
              </button>
              {open && (
                <div className="mt-2 pt-2 border-t border-line-1">
                  {bodies[r.id] && <p className="text-xs text-body leading-relaxed">{bodies[r.id]}</p>}
                  <a
                    href={sanitizeUrl(r.link) ?? undefined}
                    target="_blank"
                    rel="noopener noreferrer nofollow"
                    className="inline-flex items-center gap-1 text-xs text-sky-600 dark:text-sky-400 hover:underline mt-2"
                  >
                    Open upstream report <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </DataPageLayout>
  );
}
