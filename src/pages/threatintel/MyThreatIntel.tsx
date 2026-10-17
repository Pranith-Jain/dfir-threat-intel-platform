import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { CopyButton } from '../../components/ui/CopyButton';
import { relativeAgo as shortRel } from '../../lib/relativeTime';
import { ExternalLink, Globe, Loader2, Radar, RefreshCw, Search } from 'lucide-react';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { StatBar } from '../../components/StatBar';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';

/**
 * MyThreatIntel dashboard - one surface over the official REST API
 * (proxied at /api/v1/mti, Bearer token injected server-side). Source
 * picker fans across all nine intelligence categories; each renders its
 * documented columns plus a distribution bar over the most meaningful
 * categorical field. Matches the portfolio design system (DataState,
 * StatBar, card/pill primitives) - no new chart deps.
 */

// NOTE: the upstream `events` source is permanently empty - MyThreatIntel
// serves CTI victim/event data via `ransomware`, so that tab IS the CTI
// events view. `events` is intentionally omitted to avoid a dead tab.
const SOURCES = ['iocs', 'malware', 'cve', 'ransomware', 'leaks', 'groups', 'markets', 'onions'] as const;
type Source = (typeof SOURCES)[number];

const SOURCE_LABEL: Record<Source, string> = {
  iocs: 'Indicators (IOC)',
  malware: 'Malware samples',
  cve: 'Vulnerabilities',
  ransomware: 'CTI events (victims)',
  leaks: 'Leaks',
  groups: 'Threat groups',
  markets: 'Darknet markets',
  onions: 'Onion services',
};

/** Documented columns per source (key → header). */
const COLUMNS: Record<Source, { key: string; label: string }[]> = {
  iocs: [
    { key: 'sha256', label: 'SHA256' },
    { key: 'file_name', label: 'Detection' },
    { key: 'type', label: 'File' },
    { key: 'signature', label: 'Signature' },
    { key: 'tags', label: 'Tags' },
    { key: 'date', label: 'Date' },
  ],
  malware: [
    { key: 'sha256', label: 'SHA256' },
    { key: 'file_name', label: 'File name' },
    { key: 'signature', label: 'Signature' },
    { key: 'tags', label: 'Tags' },
    { key: 'type', label: 'Type' },
    { key: 'date', label: 'Date' },
  ],
  cve: [
    { key: 'cve', label: 'CVE' },
    { key: 'severity', label: 'Severity' },
    { key: 'score', label: 'Score' },
    { key: 'cvss_version', label: 'CVSS' },
    { key: 'published', label: 'Published' },
    { key: 'description', label: 'Description' },
  ],
  ransomware: [
    { key: 'date', label: 'Date' },
    { key: 'victim', label: 'Victim' },
    { key: 'gang', label: 'Gang' },
    { key: 'country', label: 'Country' },
    { key: 'website', label: 'Website' },
    { key: 'description', label: 'Description' },
  ],
  leaks: [
    { key: 'name', label: 'Name' },
    { key: 'size', label: 'Size' },
    { key: 'date', label: 'Date' },
    { key: 'url', label: 'URL' },
  ],
  groups: [
    { key: 'group_id', label: 'Group' },
    { key: 'description', label: 'Profile' },
  ],
  markets: [
    { key: 'market', label: 'Market' },
    { key: 'status', label: 'Status' },
    { key: 'page_title', label: 'Page title' },
    { key: 'last_visit', label: 'Last visit' },
    { key: 'onion', label: 'Onion' },
  ],
  onions: [
    { key: 'onion', label: 'Onion' },
    { key: 'status', label: 'Status' },
    { key: 'page_title', label: 'Page title' },
    { key: 'last_visit', label: 'Last visit' },
  ],
};

/** Field the distribution bar groups by (null = no meaningful categorical). */
const DIST_KEY: Record<Source, string | null> = {
  iocs: 'type',
  malware: 'type',
  cve: 'severity',
  ransomware: 'gang',
  leaks: 'type',
  groups: null,
  markets: 'status',
  onions: 'status',
};

type MtiRow = Record<string, unknown>;

interface MtiResponse {
  source: string;
  generated_at: string;
  total: number;
  count: number;
  items: MtiRow[];
  /** True when served from the cached last-good fallback (upstream was down). */
  stale?: boolean;
}

function cellText(v: unknown): string {
  if (v == null) return '-';
  if (Array.isArray(v)) return v.join(', ');
  const s = String(v).trim();
  return s && s !== 'N/D' ? s : '-';
}

function DistBar({ rows, distKey }: { rows: MtiRow[]; distKey: string | null }): JSX.Element | null {
  const buckets = useMemo(() => {
    if (!distKey) return [] as [string, number][];
    const m = new Map<string, number>();
    for (const r of rows) {
      const raw = r[distKey];
      const k = (Array.isArray(raw) ? raw[0] : raw) ? String(Array.isArray(raw) ? raw[0] : raw).trim() : 'unknown';
      m.set(k || 'unknown', (m.get(k || 'unknown') ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [rows, distKey]);

  if (buckets.length === 0) return null;
  const max = buckets[0]?.[1] ?? 1;

  return (
    <section className="surface-card p-4 mb-6">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-3">distribution by {distKey}</div>
      <div className="space-y-2">
        {buckets.map(([label, n]) => (
          <div key={label} className="flex items-center gap-3">
            <div className="w-32 sm:w-44 truncate font-mono text-xs text-muted" title={label}>
              {label}
            </div>
            <div className="flex-1 h-2.5 rounded bg-surface-300 overflow-hidden">
              <div
                className="h-full rounded bg-rose-500/70 dark:bg-rose-400/70"
                style={{ width: `${Math.max(3, Math.round((n / max) * 100))}%` }}
              />
            </div>
            <div className="w-12 text-right font-mono text-xs tabular-nums text-muted">{n}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

interface DnsRow {
  fuzzer?: string;
  domain?: string;
  dns_a?: string[];
  dns_aaaa?: string[];
  dns_mx?: string[];
  dns_ns?: string[];
}
interface DnsResponse {
  domain: string;
  generated_at: string;
  count: number;
  items: DnsRow[];
}

function recArr(v: string[] | undefined): string {
  return v && v.length > 0 ? v.join(', ') : '-';
}

/** Shared "integration disabled" banner - token unset vs. token rejected. */
function DisabledBanner({ reason }: { reason: 'not_configured' | 'token_invalid' }): JSX.Element {
  return (
    <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-6 text-sm text-amber-800 dark:text-amber-200">
      {reason === 'token_invalid' ? (
        <>
          <strong className="font-semibold">MyThreatIntel token expired or invalid.</strong> The upstream API rejected
          the configured credential (HTTP 401). The site operator needs to refresh the{' '}
          <code className="font-mono text-xs">MYTHREATINTEL_API_TOKEN</code> secret with a valid key.
        </>
      ) : (
        <>
          <strong className="font-semibold">Operator dashboard disabled.</strong> Ask the site operator to enable the
          MyThreatIntel integration.
        </>
      )}
    </div>
  );
}

/**
 * Active dnstwist typosquatting scan (MyThreatIntel `source=dns`). On-demand -
 * the operator enters an apex domain (+ optional extra TLDs / keywords) and we
 * fire a live scan. The upstream takes 30–120s, so this is a deliberate button
 * press with a long-running loading state, not an auto-fetch.
 */
function DnsScanPanel(): JSX.Element {
  const [domain, setDomain] = useState('');
  const [tlds, setTlds] = useState('');
  const [words, setWords] = useState('');
  const [data, setData] = useState<DnsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [disabledReason, setDisabledReason] = useState<'not_configured' | 'token_invalid' | null>(null);
  const [onlyRegistered, setOnlyRegistered] = useState(false);

  const scan = async (e: React.FormEvent) => {
    e.preventDefault();
    const d = domain.trim().toLowerCase();
    if (!d) return;
    setLoading(true);
    setError(null);
    setData(null);
    setDisabledReason(null);
    try {
      const params = new URLSearchParams({ domain: d });
      if (tlds.trim()) params.set('tlds', tlds.trim());
      if (words.trim()) params.set('words', words.trim());
      const r = await fetch(`/api/v1/mti-dns?${params.toString()}`);
      if (r.status === 503) {
        const j = (await r.json().catch(() => ({}))) as { error?: string };
        if (j.error === 'not_configured') {
          setDisabledReason('not_configured');
          return;
        }
      }
      if (r.status === 502) {
        const j = (await r.json().catch(() => ({}))) as { error?: string; upstream_status?: number | null };
        if (j.error === 'upstream_unavailable' && (j.upstream_status === 401 || j.upstream_status === 403)) {
          setDisabledReason('token_invalid');
          return;
        }
      }
      if (r.status === 400) {
        const j = (await r.json().catch(() => ({}))) as { detail?: string };
        throw new Error(j.detail || 'invalid domain');
      }
      if (!r.ok) throw new Error(`scan failed (${r.status})`);
      setData((await r.json()) as DnsResponse);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const rows = useMemo(() => {
    if (!data) return [] as DnsRow[];
    return onlyRegistered ? data.items.filter((r) => (r.dns_a?.length ?? 0) > 0) : data.items;
  }, [data, onlyRegistered]);

  return (
    <div>
      <form onSubmit={scan} className="surface-card p-4 mb-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="apex domain - e.g. company.com"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
            aria-label="Target apex domain"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="inline-flex items-center justify-center gap-1.5 text-xs font-mono px-4 py-2 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:border-rose-500/70 disabled:opacity-50 transition-colors"
          >
            {loading ? <Loader2 size={13} className="animate-spin" /> : <Globe size={13} />}
            {loading ? 'scanning…' : 'scan'}
          </button>
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={tlds}
            onChange={(e) => setTlds(e.target.value)}
            placeholder="extra TLDs (optional) - ru,cn,xyz,top"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-xs focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
            aria-label="Extra TLDs"
          />
          <input
            type="text"
            value={words}
            onChange={(e) => setWords(e.target.value)}
            placeholder="keywords (optional) - login,secure,vpn"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-xs focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
            aria-label="Keyword variants"
          />
        </div>
        <p className="text-mini font-mono text-muted">
          Live dnstwist scan - typically 30–120s depending on domain and TLD breadth.
        </p>
      </form>

      {disabledReason ? (
        <DisabledBanner reason={disabledReason} />
      ) : (
        <DataState
          loading={loading}
          error={error}
          empty={!!data && rows.length === 0}
          emptyLabel={onlyRegistered ? 'No resolving look-alike domains found.' : 'No permutations returned.'}
          rows={8}
        >
          {data && (
            <>
              <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
                <p className="text-mini font-mono text-muted">
                  {data.count.toLocaleString()} permutations for <span className="text-body">{data.domain}</span> ·
                  showing {rows.length.toLocaleString()}
                </p>
                <button
                  type="button"
                  onClick={() => setOnlyRegistered((v) => !v)}
                  className={`text-mini font-mono px-2 py-1 rounded border ${
                    onlyRegistered
                      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                      : 'border-slate-300 dark:border-line-1 text-slate-500'
                  }`}
                >
                  registered only
                </button>
              </div>
              <div className="overflow-x-auto rounded-xl border border-line-1">
                <DataTable
                  columns={
                    [
                      {
                        key: 'fuzzer',
                        header: 'Permutation',
                        sortValue: (r: (typeof rows)[number]) => r.fuzzer ?? '',
                        render: (r) => (
                          <span className="font-mono text-mini text-muted whitespace-nowrap">{r.fuzzer || '-'}</span>
                        ),
                      },
                      {
                        key: 'domain',
                        header: 'Domain',
                        sortValue: (r: (typeof rows)[number]) => r.domain ?? '',
                        render: (r) => (
                          <span className="font-mono text-meta text-heading break-all">{r.domain || '-'}</span>
                        ),
                      },
                      {
                        key: 'dns_a',
                        header: 'A',
                        render: (r) => (
                          <span className="font-mono text-mini text-muted break-all">{recArr(r.dns_a)}</span>
                        ),
                      },
                      {
                        key: 'dns_mx',
                        header: 'MX',
                        render: (r) => (
                          <span className="font-mono text-mini text-muted break-all">{recArr(r.dns_mx)}</span>
                        ),
                      },
                      {
                        key: 'dns_ns',
                        header: 'NS',
                        render: (r) => (
                          <span className="font-mono text-mini text-muted break-all">{recArr(r.dns_ns)}</span>
                        ),
                      },
                      {
                        key: 'registered',
                        header: 'Registered',
                        sortValue: (r: (typeof rows)[number]) => ((r.dns_a?.length ?? 0) > 0 ? 'yes' : 'no'),
                        render: (r) => {
                          const registered = (r.dns_a?.length ?? 0) > 0;
                          return registered ? (
                            <span className="text-mini font-mono px-2 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                              resolves
                            </span>
                          ) : (
                            <span className="text-mini font-mono text-muted">-</span>
                          );
                        },
                      },
                    ] as DataTableColumn<(typeof rows)[number]>[]
                  }
                  rows={rows}
                  rowKey={(r, i) => `${r.domain}-${i}`}
                  rowClassName={() => 'hover:bg-slate-50/60 dark:hover:bg-surface-200/40'}
                />
              </div>
            </>
          )}
        </DataState>
      )}
    </div>
  );
}

export default function MyThreatIntel(): JSX.Element {
  const [view, setView] = useState<'records' | 'dns'>('records');
  const [source, setSource] = useState<Source>('iocs');
  const [data, setData] = useState<MtiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // null = healthy. 'not_configured' = no token secret set. 'token_invalid' =
  // token set but upstream rejected it (401/403 → expired or wrong key).
  const [disabledReason, setDisabledReason] = useState<'not_configured' | 'token_invalid' | null>(null);
  const [query, setQuery] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    // The DNS tab owns its own fetch lifecycle - don't fire the records query
    // (and a needless upstream call) while it's active.
    if (view !== 'records') return;
    let cancelled = false;
    setLoading(true);
    // Clear the previous source's data so the table doesn't show stale
    // rows from tab N-1 while tab N is loading.
    setData(null);
    setError(null);
    setDisabledReason(null);
    fetch(`/api/v1/mti?source=${source}&limit=300`)
      .then(async (r) => {
        if (r.status === 503) {
          const j = (await r.json().catch(() => ({}))) as { error?: string };
          if (j.error === 'not_configured') {
            if (!cancelled) setDisabledReason('not_configured');
            return null;
          }
        }
        // Token is set but upstream rejected it (expired / invalid key). The
        // proxy surfaces the real upstream status in the 502 body - read it so
        // we can show a precise message instead of a generic "upstream 502".
        if (r.status === 502) {
          const j = (await r.json().catch(() => ({}))) as { error?: string; upstream_status?: number | null };
          if (j.error === 'upstream_unavailable' && (j.upstream_status === 401 || j.upstream_status === 403)) {
            if (!cancelled) setDisabledReason('token_invalid');
            return null;
          }
        }
        if (!r.ok) throw new Error(`upstream ${r.status}`);
        return r.json() as Promise<MtiResponse>;
      })
      .then((d) => {
        if (!cancelled && d) setData(d);
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [source, refreshKey, view]);

  const cols = COLUMNS[source];
  const filtered = useMemo(() => {
    if (!data) return [] as MtiRow[];
    const q = query.trim().toLowerCase();
    if (!q) return data.items;
    return data.items.filter((row) => cols.some((c) => cellText(row[c.key]).toLowerCase().includes(q)));
  }, [data, query, cols]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Radar size={28} />}
      title="MyThreatIntel"
      description="Live view of the MyThreatIntel CTI platform via its authenticated REST API. The bearer token is held as a Worker secret and injected server-side - it never reaches the browser."
      maxWidthClass="max-w-6xl"
      headerExtra={
        <p className="text-xs text-muted font-mono mb-6">
          9 sources: IOCs, malware, CVEs, ransomware ops, CTI events, leaks, threat groups, darknet markets, onion
          services.
        </p>
      }
    >
      <section className="surface-card p-4 mb-4">
        <div className="flex flex-wrap items-center gap-1.5 mb-3">
          {SOURCES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                setSource(s);
                setView('records');
              }}
              className={`text-xs font-mono px-3 py-1.5 rounded border transition-colors ${
                view === 'records' && source === s
                  ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                  : 'border-line-1 text-muted hover:border-rose-500/40'
              }`}
            >
              {SOURCE_LABEL[s]}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setView('dns')}
            className={`inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border transition-colors ${
              view === 'dns'
                ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                : 'border-line-1 text-muted hover:border-rose-500/40'
            }`}
          >
            <Globe size={12} /> DNS typosquat
          </button>
        </div>
        {view === 'records' && (
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={`Filter ${SOURCE_LABEL[source].toLowerCase()}…`}
                className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
                aria-label="Filter records"
              />
            </div>
            <button
              type="button"
              onClick={() => setRefreshKey((k) => k + 1)}
              className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40"
            >
              <RefreshCw size={12} /> refresh
            </button>
          </div>
        )}
      </section>

      {view === 'dns' ? (
        <DnsScanPanel />
      ) : disabledReason ? (
        <DisabledBanner reason={disabledReason} />
      ) : (
        <>
          {data?.stale && (
            <div className="mb-4 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm font-mono text-amber-800 dark:text-amber-200">
              ! Live MyThreatIntel feed is temporarily unavailable - showing the last cached snapshot. Data may be out
              of date.
            </div>
          )}
          {data && (
            <StatBar
              items={[
                { label: 'source', value: SOURCE_LABEL[source] },
                { label: 'total upstream', value: data.total.toLocaleString() },
                { label: 'in view', value: filtered.length.toLocaleString() },
                { label: 'generated', value: shortRel(data.generated_at) || '-' },
              ]}
            />
          )}

          {data && <DistBar rows={data.items} distKey={DIST_KEY[source]} />}

          <DataState
            loading={loading}
            error={error}
            empty={!loading && !error && filtered.length === 0}
            emptyLabel="No records for this source / filter."
            onRetry={() => setRefreshKey((k) => k + 1)}
            rows={10}
          >
            <div className="overflow-x-auto rounded-xl border border-line-1">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-surface-200 text-left">
                    {cols.map((col) => (
                      <th
                        key={col.key}
                        scope="col"
                        className="px-3 py-2 font-mono text-mini uppercase tracking-wider text-muted whitespace-nowrap"
                      >
                        {col.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((row, i) => (
                    <tr
                      key={i}
                      className="border-t border-line-1/70 align-top hover:bg-surface-200/60 dark:hover:bg-surface-200/40"
                    >
                      {cols.map((col) => {
                        const text = cellText(row[col.key]);
                        const isHash = col.key === 'sha256';
                        const safeUrl = col.key === 'url' || col.key === 'onion' ? sanitizeUrl(text) : '';
                        const isUrl = safeUrl !== '';
                        const isLong = col.key === 'description' || col.key === 'page_title';
                        return (
                          <td
                            key={col.key}
                            className={`px-3 py-2 ${
                              isHash ? 'font-mono text-mini text-violet-700 dark:text-violet-300' : 'text-body'
                            } ${isLong ? 'max-w-md' : 'whitespace-nowrap'}`}
                          >
                            {text === '-' ? (
                              <span className="text-muted">-</span>
                            ) : isHash ? (
                              <span className="inline-flex items-center">
                                <span className="truncate inline-block max-w-[16rem] align-middle" title={text}>
                                  {text}
                                </span>
                                <CopyButton size={11} className="ml-1 align-middle" value={text} />
                              </span>
                            ) : isUrl ? (
                              <a
                                href={safeUrl || undefined}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400 hover:underline break-all transition-colors"
                              >
                                {text.length > 48 ? text.slice(0, 45) + '…' : text} <ExternalLink size={11} />
                              </a>
                            ) : isLong ? (
                              <span className="block max-w-md whitespace-normal leading-snug">{text}</span>
                            ) : (
                              text
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </DataState>
        </>
      )}
    </DataPageLayout>
  );
}
