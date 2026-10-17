import { useEffect, useMemo, useState } from 'react';
import { Bug, Search, ExternalLink, Flame } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

interface Vuln {
  id: string;
  title: string;
  sources: string[];
  severity: string | null;
  cvssBase: number | null;
  epss: number | null;
  kev: boolean;
  kevSources: string[];
  published: string | null;
  link: string;
  aliases: string[];
  packages: string[];
  vendor: string | null;
  product: string | null;
}

interface VulnBody extends Vuln {
  description: string;
  references: string[];
  euvdId: string | null;
  kevDateAdded: string | null;
  epssPercentile: number | null;
}

function fmtEpss(e: number | null): string {
  if (e === null || e === undefined) return '—';
  return e.toFixed(e < 0.01 ? 4 : 2);
}

export default function AiVulns(): JSX.Element {
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [kevTotal, setKevTotal] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [bodies, setBodies] = useState<Record<string, VulnBody>>({});

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/ai-security/vulns?limit=300');
      if (!r.ok) throw new Error(`vulns HTTP ${r.status}`);
      const j = (await r.json()) as { total: number; kev: number; vulns: Vuln[] };
      setVulns(j.vulns ?? []);
      setTotal(j.total ?? 0);
      setKevTotal(j.kev ?? 0);
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
    return vulns.filter((v) => {
      if (kevOnly && !v.kev) return false;
      if (
        needle &&
        !`${v.id} ${v.title} ${(v.aliases ?? []).join(' ')} ${(v.packages ?? []).join(' ')} ${v.vendor ?? ''} ${v.product ?? ''}`
          .toLowerCase()
          .includes(needle)
      )
        return false;
      return true;
    });
  }, [vulns, query, kevOnly]);

  const openBody = async (id: string) => {
    if (bodies[id] !== undefined || openId === id) {
      setOpenId(openId === id ? null : id);
      return;
    }
    setOpenId(id);
    try {
      const r = await fetch(`/api/v1/ai-security/vulns/${encodeURIComponent(id)}`);
      if (r.ok) {
        const j = (await r.json()) as VulnBody;
        setBodies((m) => ({ ...m, [id]: j }));
      }
    } catch {
      /* non-fatal */
    }
  };

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      backLabel="AI Security"
      icon={<Bug size={28} />}
      title="AI Vulns"
      description="Realtime AI vulnerability tracking — ENISA EUVD + NVD + OSV watchlist (litellm, vllm, langchain, mcp, transformers…), CISA/EU KEV overlap, FIRST EPSS exploit-probability. KEV-listed rows first. Sync runs daily via the ai-security workflow."
      loading={loading && vulns.length === 0}
      error={error}
      onRetry={load}
    >
      <AiSummaryCard
        surface="AI Vulns"
        items={filtered.slice(0, 15).map((v) => ({
          title: `${v.id} — ${v.title}`,
          body: `${v.kev ? 'KEV · ' : ''}EPSS ${fmtEpss(v.epss)} · ${v.severity ?? 'unscored'}`,
          source: v.link,
        }))}
        requireAdmin={false}
      />
      <div className="flex flex-col sm:flex-row gap-3 my-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            type="text"
            placeholder="Search CVE/GHSA ids, packages, vendors…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
          />
        </div>
        <button
          type="button"
          onClick={() => setKevOnly(!kevOnly)}
          className={`px-3 py-2 rounded-xl text-xs font-mono font-medium border transition inline-flex items-center gap-1.5 ${
            kevOnly
              ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
              : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
          }`}
        >
          <Flame className="w-3.5 h-3.5" /> KEV only · {kevTotal}
        </button>
      </div>
      <p className="mb-3 text-micro font-mono text-muted">
        {filtered.length} / {total} vulns
      </p>
      <div className="grid gap-2">
        {filtered.map((v) => {
          const open = openId === v.id;
          const body = bodies[v.id];
          return (
            <div key={v.id} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
              <button
                type="button"
                onClick={() => void openBody(v.id)}
                className="w-full text-left"
                aria-expanded={open}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-micro font-mono text-muted">{v.id}</span>
                  {v.kev && (
                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                      <Flame className="w-2.5 h-2.5" /> KEV
                    </span>
                  )}
                  {v.cvssBase != null && (
                    <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
                      CVSS {v.cvssBase}
                    </span>
                  )}
                  <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
                    EPSS {fmtEpss(v.epss)}
                  </span>
                  {(v.sources ?? []).slice(0, 4).map((s) => (
                    <span
                      key={s}
                      className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted"
                    >
                      {s}
                    </span>
                  ))}
                </div>
                <h3 className="text-sm font-bold text-heading mt-1 leading-snug">{v.title}</h3>
                <p className="text-mini font-mono text-muted mt-1">
                  {(v.packages ?? []).join(', ') || v.product || v.vendor || 'package n/a'} ·{' '}
                  {v.published ?? 'date n/a'}
                </p>
              </button>
              {open && (
                <div className="mt-2 pt-2 border-t border-line-1 space-y-2">
                  {body && <p className="text-xs text-body leading-relaxed">{body.description}</p>}
                  {body && body.references.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {body.references.slice(0, 6).map((u) => (
                        <a
                          key={u}
                          href={sanitizeUrl(u) ?? undefined}
                          target="_blank"
                          rel="noopener noreferrer nofollow"
                          className="inline-flex items-center gap-0.5 text-xs text-sky-600 dark:text-sky-400 hover:underline"
                        >
                          ref <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ))}
                    </div>
                  )}
                  <a
                    href={sanitizeUrl(v.link) ?? undefined}
                    target="_blank"
                    rel="noopener noreferrer nofollow"
                    className="inline-flex items-center gap-1 text-xs text-sky-600 dark:text-sky-400 hover:underline"
                  >
                    Open upstream record <ExternalLink className="w-2.5 h-2.5" />
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
