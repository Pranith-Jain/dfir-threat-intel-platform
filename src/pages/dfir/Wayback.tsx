import { logCatch } from '../../lib/log';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { History, Search, Loader2, ExternalLink, AlertTriangle, CheckCircle2 } from 'lucide-react';
interface Snapshot {
  timestamp: string; // YYYYMMDDhhmmss
  original: string;
  status: string;
  mime: string;
  digest: string;
  length: string;
}

// Worker-proxied - see api/src/routes/wayback.ts for upstream behaviour and
// rationale (browser-direct fetch was hitting NetworkError on Firefox when
// IA returned 5xx without CORS headers).
const CDX_BASE = '/api/v1/wayback/cdx';

function buildCdxUrl(target: string, limit = 200): string {
  const params = new URLSearchParams({ url: target, limit: String(limit) });
  return `${CDX_BASE}?${params.toString()}`;
}

function fmtTs(ts: string): string {
  if (ts.length < 14) return ts;
  return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)} ${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)} UTC`;
}

function snapshotUrl(ts: string, target: string): string {
  return `https://web.archive.org/web/${ts}/${target}`;
}

function statusClass(status: string): string {
  if (status.startsWith('2')) return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300';
  if (status.startsWith('3')) return 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300';
  if (status.startsWith('4')) return 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300';
  if (status.startsWith('5')) return 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300';
  return 'border-slate-300 dark:border-line-1 text-slate-500';
}

export default function Wayback(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [url, setUrl] = useState(searchParams.get('url') ?? '');
  const [snapshots, setSnapshots] = useState<Snapshot[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Epoch ms when the shared IA cooldown clears. While set, Lookup is
  // disabled and auto-fetch is suppressed - manual retries during the
  // window are exactly what keep IA's IP-wide throttle alive.
  const [cooldownUntil, setCooldownUntil] = useState<number | null>(null);
  const [nowTick, setNowTick] = useState(Date.now());
  const initialDone = useRef(false);

  const cooldownRemaining = cooldownUntil !== null ? Math.max(0, Math.ceil((cooldownUntil - nowTick) / 1000)) : 0;
  const inCooldown = cooldownRemaining > 0;

  useEffect(() => {
    if (cooldownUntil === null) return;
    const id = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, [cooldownUntil]);

  useEffect(() => {
    if (cooldownUntil !== null && nowTick >= cooldownUntil) {
      setCooldownUntil(null);
      setError(null);
    }
  }, [nowTick, cooldownUntil]);

  const lookup = async (override?: string) => {
    const t = (override ?? url).trim();
    if (!t) return;
    // Hard block during the shared cooldown - firing here is the root cause
    // of the recurring throttle (every request re-arms IA's IP-wide ban).
    if (cooldownUntil !== null && Date.now() < cooldownUntil) return;
    if (override) setUrl(override);
    setLoading(true);
    setError(null);
    setSnapshots(null);
    setSearchParams({ url: t }, { replace: false });
    try {
      // CDX returns [[header...],[row...],...] as 2D array.
      const res = await fetch(buildCdxUrl(t));
      if (!res.ok) {
        // Server returns structured { error, upstream_status, hint, retry_after_seconds }
        // - surface the human-readable hint when available, else fall back to
        // the HTTP code so the analyst at least sees what happened.
        let detail: { error?: string; hint?: string; retry_after_seconds?: number } = {};
        try {
          detail = (await res.json()) as typeof detail;
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* upstream returned non-JSON */
        }
        if (res.status === 429 && detail.retry_after_seconds) {
          setCooldownUntil(Date.now() + detail.retry_after_seconds * 1000);
          setNowTick(Date.now());
          throw new Error(
            detail.hint ??
              `Internet Archive is rate-limiting all Wayback lookups from this site. Cooling down - Lookup re-enables automatically.`
          );
        }
        if (detail.hint) throw new Error(detail.hint);
        if (detail.error) throw new Error(detail.error);
        throw new Error(`Wayback Machine unreachable (HTTP ${res.status})`);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      const data = (await res.json()) as string[][];
      if (!Array.isArray(data) || data.length === 0) {
        setSnapshots([]);
        return;
      }
      const [, ...rows] = data;
      const parsed: Snapshot[] = rows.map(([timestamp, original, status, mime, digest, length]) => ({
        timestamp: timestamp!,
        original: original!,
        status: status!,
        mime: mime!,
        digest: digest!,
        length: length!,
      }));
      setSnapshots(parsed);
    } catch (e) {
      logCatch(e);
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  // Auto-fetch from URL on first mount.
  useEffect(() => {
    if (initialDone.current) return;
    const initial = searchParams.get('url');
    if (initial) {
      initialDone.current = true;
      void lookup(initial);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stats = useMemo(() => {
    if (!snapshots || snapshots.length === 0) return null;
    const sorted = [...snapshots].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const statusCounts: Record<string, number> = {};
    for (const s of snapshots) {
      const bucket = s.status ? `${s.status[0]}xx` : 'unknown';
      statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
    }
    return { first, last, statusCounts };
  }, [snapshots]);

  // Sortable columns. Default: timestamp desc (most recent first).
  type SortKey = 'timestamp' | 'status' | 'mime' | 'length';
  const [sortKey, setSortKey] = useState<SortKey>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const displaySnapshots = useMemo(() => {
    if (!snapshots) return [];
    const cmp = (a: Snapshot, b: Snapshot): number => {
      switch (sortKey) {
        case 'timestamp':
          return a.timestamp.localeCompare(b.timestamp);
        case 'status':
          return (a.status || '').localeCompare(b.status || '');
        case 'mime':
          return (a.mime || '').localeCompare(b.mime || '');
        case 'length': {
          const an = parseInt(a.length || '0', 10) || 0;
          const bn = parseInt(b.length || '0', 10) || 0;
          return an - bn;
        }
      }
    };
    const sorted = [...snapshots].sort(cmp);
    return sortDir === 'desc' ? sorted.reverse() : sorted;
  }, [snapshots, sortKey, sortDir]);

  const onHeaderClick = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'timestamp' ? 'desc' : 'asc');
    }
  };

  return (
    <div className="max-w-6xl">

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <History size={28} className="text-brand-600 dark:text-brand-400" /> Wayback Machine Pivot
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          Paste a URL - get the Internet Archive snapshot timeline (first / last seen, status-code distribution, deduped
          via content digest). Useful for phishing-site evolution, infrastructure churn, and content provenance.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Powered by the public Internet Archive CDX API. Capped at 200 snapshots per query for responsiveness; for
          deeper history use{' '}
          <a
            href="https://web.archive.org/web/*/example.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            archive.org's calendar view
          </a>
          .
        </p>
      </div>

      <section className="surface-card p-4 mb-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void lookup();
          }}
          className="flex flex-wrap gap-2"
        >
          <div className="relative flex-1 min-w-[280px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com  (or example.com/some/path)"
              className="w-full pl-9 pr-3 py-2 rounded border border-line-2 bg-surface-200 font-mono text-sm focus:border-brand-500/60 focus:outline-none"
              aria-label="URL to look up"
              autoComplete="off"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim() || inCooldown}
            className="text-sm font-mono px-3 py-2 rounded border border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300 hover:border-brand-500 disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-1.5 transition-colors"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <History size={14} />}
            {loading ? 'Loading' : inCooldown ? `Cooldown ${cooldownRemaining}s` : 'Lookup'}
          </button>
        </form>
        {error && (
          <p className="mt-2 text-xs font-mono text-rose-600 dark:text-rose-400 inline-flex items-start gap-1.5">
            <AlertTriangle size={12} className="mt-0.5 shrink-0" />
            <span>
              {error}
              {inCooldown && (
                <>
                  {' '}
                  <span className="text-muted">Auto-retry available in {cooldownRemaining}s - no need to refresh.</span>
                </>
              )}
            </span>
          </p>
        )}
      </section>

      {snapshots && snapshots.length === 0 && !error && (
        <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 mb-6 text-sm font-mono text-amber-700 dark:text-amber-300 inline-flex items-center gap-2">
          <AlertTriangle size={14} /> No snapshots found for this URL. The Internet Archive may not have crawled it, or
          the path is too specific - try the bare domain.
        </section>
      )}

      {stats && (
        <section className="surface-card p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">Timeline summary</h2>
            <span className="text-mini font-mono text-muted inline-flex items-center gap-1.5">
              <CheckCircle2 size={12} className="text-emerald-500" /> {snapshots?.length ?? 0} unique snapshots
            </span>
          </div>
          <div className="grid gap-2 sm:grid-cols-3 mb-3 text-meta font-mono">
            <Stat
              label="First seen"
              value={fmtTs(stats.first.timestamp)}
              url={snapshotUrl(stats.first.timestamp, stats.first.original)}
            />
            <Stat
              label="Last seen"
              value={fmtTs(stats.last.timestamp)}
              url={snapshotUrl(stats.last.timestamp, stats.last.original)}
            />
            <Stat label="Span" value={daysBetween(stats.first.timestamp, stats.last.timestamp)} />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(stats.statusCounts).map(([bucket, n]) => (
              <span
                key={bucket}
                className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${statusClass(bucket[0]!)}`}
              >
                {bucket} · {n}
              </span>
            ))}
          </div>
        </section>
      )}

      {displaySnapshots.length > 0 && (
        <section className="surface-card p-4 mb-6">
          <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
            Snapshots (sorted by {sortKey} {sortDir})
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-meta font-mono">
              <thead className="text-left text-micro uppercase tracking-wider text-muted">
                <tr>
                  {(['timestamp', 'status', 'mime', 'length'] as const).map((k) => (
                    <th
                      key={k}
                      scope="col"
                      className="pb-2 pr-3 cursor-pointer hover:text-brand-600 dark:hover:text-brand-400 select-none"
                      onClick={() => onHeaderClick(k)}
                      title="Click to sort"
                    >
                      {k}
                      <span className="ml-1 opacity-60">{sortKey === k ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}</span>
                    </th>
                  ))}
                  <th scope="col" className="pb-2 pr-3">
                    Open
                  </th>
                </tr>
              </thead>
              <tbody>
                {displaySnapshots.slice(0, 100).map((s) => (
                  <tr key={`${s.timestamp}-${s.digest}`} className="border-t border-line-1">
                    <td className="py-1.5 pr-3 text-body whitespace-nowrap">{fmtTs(s.timestamp)}</td>
                    <td className="py-1.5 pr-3">
                      <span
                        className={`text-micro uppercase tracking-wider px-1.5 py-0.5 rounded border ${statusClass(s.status || '0')}`}
                      >
                        {s.status || '-'}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 text-muted">{s.mime || '-'}</td>
                    <td className="py-1.5 pr-3 text-muted">{s.length}</td>
                    <td className="py-1.5 pr-3">
                      <div className="flex items-center gap-2">
                        <a
                          href={snapshotUrl(s.timestamp, s.original)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                        >
                          view <ExternalLink size={10} />
                        </a>
                        <Link
                          to={`/dfir/url-preview?url=${encodeURIComponent(snapshotUrl(s.timestamp, s.original))}`}
                          className="text-micro text-amber-700 dark:text-amber-300 hover:underline"
                          title="Server-side preview of this archived snapshot (SSRF-guarded)"
                        >
                          preview
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {displaySnapshots.length > 100 && (
              <p className="mt-3 text-mini font-mono text-muted">
                Showing the 100 most recent of {displaySnapshots.length}. Re-run with a more specific URL or use{' '}
                <a
                  href={`https://web.archive.org/web/*/${url}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                >
                  archive.org's calendar view
                </a>
                .
              </p>
            )}
          </div>
        </section>
      )}

      <section className="surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-2">
          Companion lookups
        </h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted list-disc pl-5">
          <li>
            <Link to="/dfir/domain-investigator" className="text-brand-600 dark:text-brand-400 hover:underline">
              Domain Lookup
            </Link>{' '}
            - RDAP, DNS, email-auth posture.
          </li>
          <li>
            <Link to="/dfir/url-preview" className="text-brand-600 dark:text-brand-400 hover:underline">
              URL Preview
            </Link>{' '}
            - server-side metadata for live URLs.
          </li>
          <li>
            <Link to="/dfir/domain-investigator" className="text-brand-600 dark:text-brand-400 hover:underline">
              Exposure Scanner
            </Link>{' '}
            - subdomains and open ports.
          </li>
        </ul>
      </section>
    </div>
  );
}

function Stat({ label, value, url }: { label: string; value: string; url?: string }): JSX.Element {
  return (
    <div className="rounded border border-line-1 bg-surface-200 p-2.5">
      <div className="text-micro font-mono uppercase tracking-[0.2em] text-muted mb-1">{label}</div>
      {url ? (
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
        >
          {value} <ExternalLink size={10} />
        </a>
      ) : (
        <span className="text-heading">{value}</span>
      )}
    </div>
  );
}

function daysBetween(a: string, b: string): string {
  // YYYYMMDDhhmmss → ISO
  const toIso = (s: string) =>
    `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
  const start = new Date(toIso(a)).getTime();
  const end = new Date(toIso(b)).getTime();
  if (!start || !end) return '-';
  const days = Math.round((end - start) / 86_400_000);
  if (days <= 1) return '<1 day';
  if (days < 365) return `${days} days`;
  const years = (days / 365).toFixed(1);
  return `${years} years`;
}
