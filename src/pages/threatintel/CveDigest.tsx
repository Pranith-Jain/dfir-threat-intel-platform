import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  CalendarClock,
  Check,
  Download,
  ExternalLink,
  RefreshCw,
  Rss,
  Search,
  ShieldAlert,
} from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { useToast } from '../../components/ui/Toast';
import { SEVERITY_TONE } from '../../components/severity';

interface DigestEntry {
  cve_id: string;
  published: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  score: number | null;
  cvss_vector?: string;
  description: string;
  cwe_id?: string;
  exploit_status?: string;
  is_in_kev: boolean;
  priority_score: number | null;
  epss?: number;
  epss_percentile?: number;
  reference: string;
  ctiwatch_url: string;
}

interface DigestResponse {
  generated_at: string;
  window_start: string;
  window_end: string;
  window_hours: number;
  partial: boolean;
  count: number;
  upstream_total: number | null;
  severity: Record<DigestEntry['severity'], number>;
  kev_count: number;
  exploit_count: number;
  daily_volume: { date: string; total: number; critical: number } | null;
  sources: { id: string; ok: boolean; count: number }[];
  entries: DigestEntry[];
}

const SEVERITY_PILL: Record<DigestEntry['severity'], string> = {
  CRITICAL: SEVERITY_TONE.critical,
  HIGH: SEVERITY_TONE.high,
  MEDIUM: SEVERITY_TONE.medium,
  LOW: SEVERITY_TONE.low,
  UNKNOWN: 'border-line-2 dark:border-line-1 text-muted',
};

function rel(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const h = Math.round(mins / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/**
 * Daily CVE digest — every CVE published in the last 24 hours.
 *
 * Separate page (and API route) from the "All Recent" list on purpose: that
 * list is a recent SAMPLE bounded by NVD paging, while this page promises a
 * complete window anchored on ctiwatch's `published_after`. The two link to
 * each other rather than merging, because merging would push a ~900-row
 * payload onto a route with a 10ms CPU cap.
 */
export default function CveDigest({ bare }: { bare?: boolean }): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<DigestResponse>({
    url: '/api/v1/cve-digest',
    ttl: 120_000,
    staleWhileRevalidate: true,
  });
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState<Set<DigestEntry['severity']>>(new Set());
  const [kevOnly, setKevOnly] = useState(false);
  const [exploitOnly, setExploitOnly] = useState(false);
  const [feedUrl, setFeedUrl] = useState<string | null>(null);
  const [feedCopied, setFeedCopied] = useState(false);
  const toast = useToast();

  /**
   * Mint (once) and copy the RSS subscribe URL.
   *
   * The feed is gated by a signed path-scoped token, so the bare
   * `/api/v1/cve-digest/rss` link only resolves same-origin — a reader app
   * gets a 401. The token comes from /feed-url, which is itself behind the
   * normal API gate, so it is minted on demand rather than on page load.
   */
  const copyFeedUrl = async (): Promise<void> => {
    let url = feedUrl;
    if (!url) {
      try {
        const res = await fetch('/api/v1/cve-digest/feed-url');
        if (!res.ok) throw new Error(`feed-url ${res.status}`);
        url = ((await res.json()) as { url: string }).url;
        setFeedUrl(url);
      } catch {
        toast.error('Could not mint a feed link — is the API reachable?');
        return;
      }
    }
    try {
      await navigator.clipboard.writeText(url);
      setFeedCopied(true);
      setTimeout(() => setFeedCopied(false), 2000);
    } catch {
      toast.error('Clipboard blocked — open the link below and copy it manually');
    }
  };

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.entries.filter((e) => {
      if (sevFilter.size > 0 && !sevFilter.has(e.severity)) return false;
      if (kevOnly && !e.is_in_kev) return false;
      if (exploitOnly && (!e.exploit_status || e.exploit_status === 'none')) return false;
      if (!q) return true;
      return (
        e.cve_id.toLowerCase().includes(q) ||
        (e.description ?? '').toLowerCase().includes(q) ||
        (e.cwe_id ?? '').toLowerCase().includes(q)
      );
    });
  }, [data, query, sevFilter, kevOnly, exploitOnly]);

  const toggleSev = (s: DigestEntry['severity']) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const body = (
    <div>
      {data?.partial && (
        <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300 flex gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            Showing {data.count.toLocaleString()} of {(data.upstream_total ?? data.count).toLocaleString()} CVEs — the
            anonymous ctiwatch scope stops at offset 1000. A free API key (CTIWATCH_API_KEY) lifts the ceiling on heavy
            patch days.
          </span>
        </div>
      )}
      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="inline-flex items-center gap-1.5 rounded border border-line-2 dark:border-line-1 px-2 py-1 text-muted">
            <CalendarClock className="w-3.5 h-3.5" />
            {data.count.toLocaleString()} CVEs · last {data.window_hours}h
          </span>
          {(Object.keys(data.severity) as Array<DigestEntry['severity']>).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => toggleSev(s)}
              className={`px-2 py-1 rounded border ${sevFilter.has(s) ? SEVERITY_PILL[s] : 'border-line-2 dark:border-line-1 text-muted'}`}
              title={`Toggle ${s} (click to filter)`}
            >
              {s} {data.severity[s].toLocaleString()}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setKevOnly((v) => !v)}
            className={`px-2 py-1 rounded border ${kevOnly ? 'border-rose-500/60 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-line-2 dark:border-line-1 text-muted'}`}
            title="Show only CISA KEV"
          >
            KEV {data.kev_count}
          </button>
          <button
            type="button"
            onClick={() => setExploitOnly((v) => !v)}
            className={`px-2 py-1 rounded border ${exploitOnly ? 'border-orange-500/60 bg-orange-500/10 text-orange-700 dark:text-orange-300' : 'border-line-2 dark:border-line-1 text-muted'}`}
            title="Show only rows with a known exploit status"
          >
            Exploited {data.exploit_count}
          </button>
          {data.daily_volume && (
            <span className="px-2 py-1 text-muted" title="VulnTracker's independent daily count for cross-check">
              VulnTracker {data.daily_volume.date}: {data.daily_volume.total.toLocaleString()} total /{' '}
              {data.daily_volume.critical.toLocaleString()} critical
            </span>
          )}
        </div>
      )}
      <div className="mb-4 flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by CVE ID, keyword, or CWE…"
            className="w-full rounded-lg border border-line-2 dark:border-line-1 bg-surface-100 dark:bg-surface-200 pl-9 pr-3 py-2 text-sm"
          />
        </div>
        <button
          type="button"
          onClick={() => void refetch()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line-2 dark:border-line-1 px-3 py-2 text-xs font-mono text-muted hover:text-body"
          title="Refetch (serves the hourly cron warm)"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
        {/* Same warmed payload, alternate representations — a native anchor so
            the browser handles the download (CSV) directly, no extra fetch.
            RSS is different: the feed is token-gated so a reader app (which
            sends no same-origin headers) needs the signed URL, not this link. */}
        <a
          href="/api/v1/cve-digest/csv"
          download
          className="inline-flex items-center gap-1.5 rounded-lg border border-line-2 dark:border-line-1 px-3 py-2 text-xs font-mono text-muted hover:text-body"
          title="Download this 24h window as CSV (spreadsheets, SIEM import)"
        >
          <Download className="w-3.5 h-3.5" /> CSV
        </a>
        <button
          type="button"
          onClick={() => void copyFeedUrl()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line-2 dark:border-line-1 px-3 py-2 text-xs font-mono text-muted hover:text-body"
          title="Copy the RSS subscribe link into your reader (Feedly, Inoreader…). Treat it like a password — anyone with it can read the feed."
        >
          {feedCopied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Rss className="w-3.5 h-3.5" />}
          {feedCopied ? 'Copied' : 'RSS'}
        </button>
        {feedUrl && (
          <a
            href={feedUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center rounded-lg border border-line-2 dark:border-line-1 px-2 py-2 text-muted hover:text-body"
            title="Open the signed feed URL (this is what you paste into a reader)"
            aria-label="Open the signed RSS feed URL"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        )}
      </div>
      {feedUrl && (
        <p className="mt-2 break-all font-mono text-[11px] text-muted">
          Feed URL (valid until the 1st UTC): <span className="text-body">{feedUrl}</span>
        </p>
      )}

      {loading && <p className="text-sm text-muted font-mono">Loading the last-24h digest…</p>}
      {error && (
        <p className="text-sm text-rose-600 dark:text-rose-400 font-mono">
          Digest warming — the hourly cron builds it within the hour.{' '}
          <button type="button" onClick={() => void refetch()} className="underline">
            Retry
          </button>
        </p>
      )}
      {data && !loading && (
        <p className="mb-3 text-xs font-mono text-muted">
          {filtered.length.toLocaleString()} of {data.count.toLocaleString()} shown · window{' '}
          {new Date(data.window_start).toLocaleString()} → {new Date(data.window_end).toLocaleString()} · generated{' '}
          {rel(data.generated_at)}
        </p>
      )}
      <div className="space-y-2">
        {filtered.map((e) => (
          <article key={e.cve_id} className="rounded-lg border border-line-1 bg-surface-100 dark:bg-surface-200 p-3">
            <div className="flex items-baseline justify-between gap-2 mb-1 flex-wrap">
              <div className="flex items-center gap-2 flex-wrap">
                <a
                  href={e.ctiwatch_url}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-sm font-semibold text-sky-600 dark:text-sky-400 hover:underline inline-flex items-center gap-1"
                  title={`Open ${e.cve_id} on ctiwatch.com`}
                >
                  {e.cve_id} <ExternalLink className="w-3 h-3" />
                </a>
                <span className={`px-1.5 py-0.5 rounded text-micro font-mono border ${SEVERITY_PILL[e.severity]}`}>
                  {e.severity}
                  {e.score !== null ? ` ${e.score.toFixed(1)}` : ''}
                </span>
                {e.is_in_kev && (
                  <span
                    className="px-1.5 py-0.5 rounded text-micro font-mono border border-rose-500/40 text-rose-600 dark:text-rose-400"
                    title="CISA Known Exploited Vulnerabilities"
                  >
                    KEV
                  </span>
                )}
                {e.exploit_status && e.exploit_status !== 'none' && (
                  <span
                    className="px-1.5 py-0.5 rounded text-micro font-mono border border-orange-500/40 text-orange-600 dark:text-orange-400"
                    title={`ctiwatch exploit_status: ${e.exploit_status}`}
                  >
                    {e.exploit_status.replace(/_/g, ' ')}
                  </span>
                )}
                {e.epss !== undefined && (
                  <span
                    className="px-1.5 py-0.5 rounded text-micro font-mono border border-line-2 dark:border-line-1 text-muted"
                    title={`EPSS ${(e.epss * 100).toFixed(2)}%${e.epss_percentile !== undefined ? ` · percentile ${(e.epss_percentile * 100).toFixed(1)}%` : ''}`}
                  >
                    EPSS {(e.epss * 100).toFixed(1)}%
                  </span>
                )}
              </div>
              <span className="text-mini font-mono text-muted" title={`Published ${e.published}`}>
                {rel(e.published)}
              </span>
            </div>
            {e.description && <p className="text-xs text-body leading-relaxed mb-1">{e.description}</p>}
            <div className="flex items-center gap-2 text-mini text-muted flex-wrap font-mono">
              {e.cwe_id && <span>{e.cwe_id}</span>}
              {e.cvss_vector && (
                <span className="truncate max-w-full" title={e.cvss_vector}>
                  {e.cvss_vector}
                </span>
              )}
              <a
                href={e.reference}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-0.5 hover:text-body"
              >
                Ref <ExternalLink className="w-2.5 h-2.5" />
              </a>
              <a
                href={`https://rdintel.com/cve/${e.cve_id}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-0.5 text-rose-600 hover:underline dark:text-rose-400"
                title={`Open ${e.cve_id} on RD Intelligence`}
              >
                RDIntel <ExternalLink className="w-2.5 h-2.5" />
              </a>
              <a
                href={`https://hexbrainai.com/cve/${e.cve_id}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-0.5 text-orange-600 hover:underline dark:text-orange-300"
                title={`Open ${e.cve_id} on HexBrain`}
              >
                HexBrain <ExternalLink className="w-2.5 h-2.5" />
              </a>
              {e.priority_score !== null && <span title="ctiwatch priority score">prio {e.priority_score}</span>}
            </div>
          </article>
        ))}
      </div>
      {data && filtered.length === 0 && !loading && (
        <p className="text-sm text-muted font-mono mt-4 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4" /> No CVEs match the current filters.
        </p>
      )}
    </div>
  );

  if (bare) return body;
  return (
    <div>
      <p className="text-xs text-muted mb-4">
        Every CVE published in the last 24 hours, anchored on ctiwatch —{' '}
        <Link to="/threatintel/cves/cves?tab=all" className="text-sky-600 dark:text-sky-400 hover:underline">
          All Recent
        </Link>{' '}
        is the sampled feed, this page is the complete window.
      </p>
      {body}
    </div>
  );
}
