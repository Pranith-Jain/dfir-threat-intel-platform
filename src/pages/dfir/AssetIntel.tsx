import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, useCallback, type FormEvent } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Search,
  Globe,
  Server,
  AlertTriangle,
  Network,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Users,
  Building2,
  Clock,
  Mail,
  ScanLine,
} from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { ArtifactTable, type HostArtifact } from '../../components/dfir/ArtifactTable';

const API = '/api/v1';
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

// ── Host Intel types ────────────────────────────────────────────────

interface HostIntel {
  ip: string;
  asn?: number;
  org?: string;
  country?: string;
  hostnames: string[];
  open_ports: number[];
  vulns: string[];
  last_seen?: string;
  artifact_count: number;
  artifacts: HostArtifact[];
  risk_tags: string[];
  sources_used: string[];
}

// ── WHOIS History types ─────────────────────────────────────────────

interface WhoisSnapshot {
  id: number;
  domain: string;
  registrar?: string;
  registrant_name?: string;
  registrant_org?: string;
  registrant_email?: string;
  created_date?: string;
  expires_date?: string;
  updated_date?: string;
  nameservers: string[];
  status: string[];
  source: string;
  snapshot_at: string;
}

interface WhoisChange {
  id: number;
  domain: string;
  change_type: string;
  field_name: string;
  old_value?: string;
  new_value?: string;
  detected_at: string;
}

interface DomainPivot {
  domain: string;
  match_reason: string;
  match_value: string;
  first_seen: string;
  last_seen: string;
  snapshot_count: number;
  current_registrar?: string;
}

interface HistoryResult {
  domain: string;
  current: WhoisSnapshot | null;
  snapshots: WhoisSnapshot[];
  changes: WhoisChange[];
  summary: {
    total_snapshots: number;
    ownership_transfers: number;
    registrar_changes: number;
    nameserver_changes: number;
    first_seen: string;
    last_seen: string;
  };
}

interface PivotResult {
  target: string;
  pivot_type: string;
  related_domains: DomainPivot[];
  total_found: number;
  query_time_ms: number;
}

// ── Shared helpers ──────────────────────────────────────────────────

const CHANGE_COLORS: Record<string, string> = {
  registrant: 'text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/50',
  registrar:
    'text-brand-600 dark:text-brand-400 bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800/50',
  nameservers:
    'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/50',
  status:
    'text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-950/20 border-purple-200 dark:border-purple-800/50',
};

const PIVOT_ICONS: Record<string, typeof Mail> = {
  shared_registrant_email: Mail,
  shared_registrant_org: Building2,
  shared_nameserver: Server,
  shared_registrar: Globe,
};

function formatDate(d?: string) {
  if (!d) return '-';
  try {
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch (_catchErr) {
    console.error('formatDate failed:', errMessage(_catchErr));
    return d;
  }
}

function formatDateTime(d?: string) {
  if (!d) return '-';
  try {
    return new Date(d).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch (_catchErr) {
    console.error('formatDateTime failed:', errMessage(_catchErr));
    return d;
  }
}

function typeFromQuery(q: string): 'ip' | 'domain' | null {
  if (IPV4_RE.test(q.trim())) return 'ip';
  if (DOMAIN_RE.test(q.trim())) return 'domain';
  return null;
}

// ── Sub-components ──────────────────────────────────────────────────

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="font-mono text-micro uppercase tracking-wider text-muted">{label}</div>
      <div className="font-mono text-sm text-heading mt-0.5 break-all">{value}</div>
    </div>
  );
}

function Loading({ text = 'Loading…' }: { text?: string }) {
  return (
    <div className="flex items-center gap-2 font-mono text-sm text-muted py-4">
      <RefreshCw size={14} className="animate-spin" /> {text}
    </div>
  );
}

function ErrorBanner({ error }: { error: string }) {
  return (
    <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/50 text-rose-700 dark:text-rose-300 text-sm font-mono mb-6">
      <AlertTriangle size={14} className="inline mr-2" />
      {error}
    </div>
  );
}

// ── Host Intel Panel ────────────────────────────────────────────────

function HostIntelPanel({ data }: { data: HostIntel }) {
  return (
    <section className="surface-card p-6">
      <div className="flex items-baseline justify-between flex-wrap gap-2">
        <h2 className="font-display font-bold text-2xl tracking-tight flex items-center gap-3">
          <Server size={22} className="text-brand-600" /> {data.ip}
        </h2>
        <span className="font-mono text-sm text-muted">{data.artifact_count} artifacts</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mt-5">
        <Stat label="Country" value={data.country ?? '-'} />
        <Stat label="ASN" value={data.asn ? `AS${data.asn}` : '-'} />
        <Stat label="Org" value={data.org ?? '-'} />
        <Stat label="Open ports" value={data.open_ports.length ? String(data.open_ports.length) : '-'} />
        <Stat label="CVEs" value={data.vulns.length ? String(data.vulns.length) : '-'} />
        <Stat label="Last seen" value={data.last_seen?.slice(0, 10) ?? '-'} />
      </div>

      {data.open_ports.length > 0 && (
        <div className="mt-4">
          <div className="font-mono text-micro uppercase tracking-wider text-muted mb-1.5">Ports</div>
          <div className="flex flex-wrap gap-1.5">
            {data.open_ports.map((p) => (
              <span key={p} className="font-mono text-xs px-1.5 py-0.5 rounded bg-surface-300 text-body">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.risk_tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-4">
          {data.risk_tags.map((t) => (
            <span
              key={t}
              className="font-mono text-micro px-1.5 py-0.5 rounded border text-rose-600 dark:text-rose-400 border-rose-300/50 dark:border-rose-500/30"
            >
              {t}
            </span>
          ))}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {data.hostnames.length > 0 && (
          <Link
            to={`/dfir/asset-intel?q=${data.hostnames[0]}`}
            className="inline-flex items-center gap-1 text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline"
          >
            <Globe size={12} /> {data.hostnames[0]}
          </Link>
        )}
      </div>

      <p className="mt-3 font-mono text-xs text-muted">sources: {data.sources_used.join(', ') || 'none responded'}</p>
    </section>
  );
}

// ── WHOIS History Panel ─────────────────────────────────────────────

function WhoisPanel({ data }: { data: HistoryResult }) {
  const [pivots, setPivots] = useState<PivotResult | null>(null);
  const [pivotLoading, setPivotLoading] = useState(false);
  const [expandedSnapshot, setExpandedSnapshot] = useState<number | null>(null);

  const fetchPivots = useCallback(async (domain: string, type = 'all') => {
    setPivotLoading(true);
    try {
      const res = await fetch(`${API}/domain/history/pivot?domain=${encodeURIComponent(domain)}&type=${type}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = (await res.json()) as PivotResult;
      setPivots(result);
    } catch (_catchErr) {
      console.error('WhoisPanel failed:', errMessage(_catchErr));
      /* swallow */
    } finally {
      setPivotLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!pivots && data.domain) void fetchPivots(data.domain);
  }, [data.domain, pivots, fetchPivots]);

  return (
    <div className="space-y-6">
      <section className="surface-card p-6">
        <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
          <Globe size={20} className="text-brand-600" /> {data.domain}
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          {[
            { label: 'Snapshots', value: data.summary.total_snapshots, icon: Clock },
            { label: 'Ownership Transfers', value: data.summary.ownership_transfers, icon: Users },
            { label: 'Registrar Changes', value: data.summary.registrar_changes, icon: Building2 },
            { label: 'NS Changes', value: data.summary.nameserver_changes, icon: Server },
          ].map(({ label, value, icon: Icon }) => (
            <div key={label} className="p-3 rounded-xl border border-line-1 bg-surface-200">
              <div className="flex items-center gap-2 mb-1">
                <Icon size={14} className="text-muted" />
                <span className="text-mini font-mono uppercase text-muted">{label}</span>
              </div>
              <span className="text-2xl font-mono font-bold">{value}</span>
            </div>
          ))}
        </div>

        {data.current && (
          <div className="mb-5 p-4 rounded-xl border border-line-1 bg-surface-200">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Globe size={14} className="text-brand-600" /> Current Registration
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted">Registrar:</span>{' '}
                <span className="font-mono">{data.current.registrar ?? '-'}</span>
              </div>
              <div>
                <span className="text-muted">Created:</span>{' '}
                <span className="font-mono">{formatDate(data.current.created_date)}</span>
              </div>
              <div>
                <span className="text-muted">Expires:</span>{' '}
                <span className="font-mono">{formatDate(data.current.expires_date)}</span>
              </div>
              <div>
                <span className="text-muted">Updated:</span>{' '}
                <span className="font-mono">{formatDate(data.current.updated_date)}</span>
              </div>
              {data.current.registrant_email && (
                <div className="sm:col-span-2">
                  <span className="text-muted">Registrant:</span>{' '}
                  <span className="font-mono">{data.current.registrant_email}</span>
                </div>
              )}
              {data.current.nameservers.length > 0 && (
                <div className="sm:col-span-2">
                  <span className="text-muted">Nameservers:</span>{' '}
                  <span className="font-mono text-xs">{data.current.nameservers.join(', ')}</span>
                </div>
              )}
            </div>
          </div>
        )}

        <div>
          <h3 className="text-sm font-semibold mb-3">Snapshot Timeline</h3>
          <div className="space-y-2">
            {data.snapshots.length === 0 ? (
              <p className="text-sm text-muted text-center py-4">No WHOIS history recorded yet.</p>
            ) : (
              data.snapshots.map((snap, i) => (
                <div key={snap.id} className="border border-line-1 rounded-xl bg-surface-100 overflow-hidden">
                  <button
                    onClick={() => setExpandedSnapshot(expandedSnapshot === snap.id ? null : snap.id)}
                    className="w-full flex items-center justify-between p-3 text-left hover:bg-surface-200 dark:hover:bg-surface-300/50"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${i === 0 ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
                      />
                      <span className="text-sm font-mono">{formatDateTime(snap.snapshot_at)}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-surface-300 text-muted">{snap.source}</span>
                    </div>
                    {expandedSnapshot === snap.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </button>
                  {expandedSnapshot === snap.id && (
                    <div className="px-3 pb-3 pt-1 border-t border-line-1 text-sm space-y-1">
                      <div>
                        <span className="text-muted">Registrar:</span>{' '}
                        <span className="font-mono">{snap.registrar ?? '-'}</span>
                      </div>
                      <div>
                        <span className="text-muted">Created:</span>{' '}
                        <span className="font-mono">{formatDate(snap.created_date)}</span>
                      </div>
                      <div>
                        <span className="text-muted">Expires:</span>{' '}
                        <span className="font-mono">{formatDate(snap.expires_date)}</span>
                      </div>
                      {snap.registrant_email && (
                        <div>
                          <span className="text-muted">Registrant Email:</span>{' '}
                          <span className="font-mono">{snap.registrant_email}</span>
                        </div>
                      )}
                      {snap.registrant_org && (
                        <div>
                          <span className="text-muted">Registrant Org:</span>{' '}
                          <span className="font-mono">{snap.registrant_org}</span>
                        </div>
                      )}
                      {snap.nameservers.length > 0 && (
                        <div>
                          <span className="text-muted">Nameservers:</span>{' '}
                          <span className="font-mono text-xs">{snap.nameservers.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="surface-card p-6">
        <h3 className="font-display font-bold text-lg mb-3">Related Domains</h3>
        {pivotLoading ? (
          <Loading text="Searching for related domains…" />
        ) : pivots && pivots.related_domains.length > 0 ? (
          <div className="space-y-2">
            <p className="text-sm text-muted mb-3">
              Found <span className="font-bold text-brand-600">{pivots.total_found}</span> related domains
            </p>
            {pivots.related_domains.map((d) => {
              const PivotIcon = PIVOT_ICONS[d.match_reason] ?? Network;
              return (
                <div
                  key={`${d.domain}-${d.match_reason}`}
                  className="p-3 rounded-xl border border-line-1 bg-surface-200"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <PivotIcon size={14} className="text-brand-600" />
                      <Link
                        to={`/dfir/asset-intel?q=${d.domain}`}
                        className="font-mono text-sm font-medium hover:text-brand-600"
                      >
                        {d.domain}
                      </Link>
                    </div>
                    <a
                      href={`https://${d.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-muted hover:text-brand-600 transition-colors"
                    >
                      <ExternalLink size={12} />
                    </a>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-2 text-mini">
                    <span className="px-1.5 py-0.5 rounded bg-brand-50 dark:bg-brand-950/20 text-brand-700 dark:text-brand-300">
                      {d.match_reason.replace(/_/g, ' ')}
                    </span>
                    <span className="text-muted">{d.match_value}</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : pivots ? (
          <p className="text-sm text-muted text-center py-4">No related domains found.</p>
        ) : null}
      </section>

      {data.changes.length > 0 && (
        <section className="surface-card p-6">
          <h3 className="font-display font-bold text-lg mb-3">
            Detected Changes
            <span className="ml-2 px-1.5 py-0.5 rounded-full text-micro bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400 align-middle">
              {data.changes.length}
            </span>
          </h3>
          <div className="space-y-2">
            {data.changes.map((change) => {
              const colorClass =
                CHANGE_COLORS[change.change_type] ?? 'text-slate-600 bg-slate-50 dark:bg-surface-300 border-line-1';
              return (
                <div key={change.id} className={`p-3 rounded-xl border ${colorClass}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-semibold uppercase">{change.change_type}</span>
                    <span className="text-xs text-muted ml-auto">{formatDateTime(change.detected_at)}</span>
                  </div>
                  <div className="text-sm grid grid-cols-1 sm:grid-cols-2 gap-1">
                    <div className="line-through text-muted font-mono text-xs break-all">{change.old_value ?? '-'}</div>
                    <div className="font-mono text-xs break-all">{change.new_value ?? '-'}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

export default function AssetIntel(): JSX.Element {
  const [searchParams] = useSearchParams();
  const initial = searchParams.get('q') ?? '';
  const [input, setInput] = useState(initial);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hostIntel, setHostIntel] = useState<HostIntel | null>(null);
  const [whoisData, setWhoisData] = useState<HistoryResult | null>(null);

  const qtype = typeFromQuery(input);

  const scan = useCallback(async (q: string) => {
    const t = typeFromQuery(q);
    if (!t) return;

    setLoading(true);
    setError(null);
    setHostIntel(null);
    setWhoisData(null);

    try {
      if (t === 'ip') {
        const r = await fetch(`${API}/host?ip=${encodeURIComponent(q.trim())}`);
        if (!r.ok) {
          const body = (await r.json().catch(() => null)) as { error?: string } | null;
          throw new Error(body?.error ?? `${r.status}`);
        }
        setHostIntel((await r.json()) as HostIntel);
      } else {
        const r = await fetch(`${API}/domain/history?domain=${encodeURIComponent(q.trim())}`);
        if (!r.ok) {
          const body = (await r.json().catch(() => ({}))) as { message?: string };
          throw new Error(body.message ?? `HTTP ${r.status}`);
        }
        setWhoisData((await r.json()) as HistoryResult);
      }
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'lookup failed'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initial && typeFromQuery(initial)) void scan(initial.trim());
  }, [initial, scan]);

  useEffect(() => {
    setInput(initial);
  }, [initial]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (input.trim() && typeFromQuery(input)) void scan(input.trim());
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-8 text-heading">
      <BackLink to="/dfir">back</BackLink>

      <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Asset Intelligence</h1>
      <p className="text-muted mb-8 max-w-3xl">
        Unified IP and domain asset intelligence - exposed host view, WHOIS history, domain pivoting, and artifact
        analysis. Inspired by etugen.io's asset reconnaissance capabilities.
      </p>

      <form onSubmit={onSubmit} className="mb-8">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <ScanLine size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="IP (8.8.8.8) or domain (example.com)"
              className="w-full pl-10 pr-4 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            />
          </div>
          <button
            type="submit"
            disabled={!qtype || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 inline-flex items-center gap-2 transition-colors"
          >
            {loading ? <RefreshCw size={16} className="animate-spin" /> : <Search size={16} />}
            {loading ? 'Scanning…' : 'Scan'}
          </button>
        </div>
        {input && !qtype && (
          <p className="mt-1.5 text-xs font-mono text-amber-600 dark:text-amber-400">
            Enter a valid IPv4 address or domain name
          </p>
        )}
      </form>

      {loading && <Loading text={qtype === 'ip' ? 'Scanning exposed host…' : 'Fetching WHOIS history…'} />}
      {error && <ErrorBanner error={error} />}

      {hostIntel && (
        <div className="space-y-6">
          <HostIntelPanel data={hostIntel} />
          <section className="surface-card p-6">
            <h3 className="font-display font-bold text-lg mb-3">Exposed services &amp; artifacts</h3>
            <ArtifactTable artifacts={hostIntel.artifacts} />
          </section>
        </div>
      )}

      {whoisData && <WhoisPanel data={whoisData} />}

      {!loading && !error && !hostIntel && !whoisData && !initial && (
        <div className="text-center py-16">
          <ScanLine size={48} className="mx-auto mb-4 text-inverted dark:text-muted" />
          <p className="text-muted">Enter an IP address or domain to begin asset intelligence</p>
          <p className="text-xs text-muted mt-1">
            IP → exposed host, open ports, CVEs, artifacts · Domain → WHOIS history, registration changes, related
            domains
          </p>
        </div>
      )}
    </div>
  );
}
