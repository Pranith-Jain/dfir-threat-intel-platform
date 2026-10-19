import { useEffect, useMemo, useState, useRef } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';
import { AlertTriangle, Loader2, RefreshCw, Search, Shield } from 'lucide-react';

interface CtiIoc {
  id: string | null;
  type: string | null;
  value: string | null;
  confidence_score: number | null;
  is_active: boolean;
  first_seen: string | null;
  last_seen: string | null;
  tags: string[];
  context: string | null;
  source_name: string | null;
  threat_actor: string | null;
}
interface CtiVuln {
  cve_id: string | null;
  title: string | null;
  severity: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  is_kev: boolean;
  exploit_status: string | null;
  published_date: string | null;
  cwe: string[];
  vendor: string | null;
  product: string | null;
  priority_score: number | null;
  epss: number | null;
  tags: string[];
}
interface CtiVictim {
  id: string | null;
  name: string | null;
  group: string | null;
  country: string | null;
  sector: string | null;
  attack_date: string | null;
  website: string | null;
  source: string | null;
}
interface CtiActor {
  id: string | null;
  name: string | null;
  country: string | null;
  aliases: string[];
  motivation: string | null;
  sophistication: string | null;
  source: string | null;
  active: boolean;
  description: string | null;
}
interface CtiCampaign {
  id: string | null;
  name: string | null;
  type: string | null;
  impact: string | null;
  is_active: boolean;
  started: string | null;
  description: string | null;
}
interface CtiIndex {
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  stats: {
    total_iocs?: number;
    total_cves?: number;
    total_threat_actors?: number;
    active_campaigns?: number;
    total_victims?: number;
    kev_count?: number;
    sources_count?: number;
    last_updated?: string;
  } | null;
  victimStats: {
    by_group?: { group_name: string; count: number }[];
    by_sector?: { sector: string; count: number }[];
    by_country?: { country: string; count: number }[];
  } | null;
  counts: { iocs: number; vulnerabilities: number; kev: number; actors: number; victims: number; campaigns: number };
  iocs: CtiIoc[];
  vulnerabilities: CtiVuln[];
  kev: CtiVuln[];
  actors: CtiActor[];
  victims: CtiVictim[];
  campaigns: CtiCampaign[];
}
interface CtiVulnBody extends CtiVuln {
  description: string | null;
  references: string[];
  affected_products: unknown[];
  sizeBytes: number;
}
interface CtiVictimBody extends CtiVictim {
  description: string | null;
  sizeBytes: number;
}

const TABS = ['overview', 'iocs', 'cves', 'victims', 'actors'] as const;
type Tab = (typeof TABS)[number];

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function Ctiwatch(): JSX.Element {
  const [data, setData] = useState<CtiIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [query, setQuery] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<CtiVulnBody | null>(null);
  const [selectedVictim, setSelectedVictim] = useState<CtiVictimBody | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/threat-intel/ctiwatch');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData((await res.json()) as CtiIndex);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const detailSeqRef = useRef(0);
  const loadVuln = async (cveId: string | null) => {
    if (!cveId) return;
    const seq = ++detailSeqRef.current;
    setDetailLoading(true);
    setSelectedVictim(null);
    try {
      const res = await fetch(`/api/v1/threat-intel/ctiwatch/vulnerabilities/${encodeURIComponent(cveId)}`);
      if (!res.ok) return;
      const body = (await res.json()) as CtiVulnBody;
      if (seq !== detailSeqRef.current) return;
      setSelectedVuln(body);
    } catch {
      /* */
    } finally {
      if (seq === detailSeqRef.current) setDetailLoading(false);
    }
  };
  const loadVictim = async (id: string | null) => {
    if (!id) return;
    const seq = ++detailSeqRef.current;
    setDetailLoading(true);
    setSelectedVuln(null);
    try {
      const res = await fetch(`/api/v1/threat-intel/ctiwatch/victims/${encodeURIComponent(id)}`);
      if (!res.ok) return;
      const body = (await res.json()) as CtiVictimBody;
      if (seq !== detailSeqRef.current) return;
      setSelectedVictim(body);
    } catch {
      /* */
    } finally {
      if (seq === detailSeqRef.current) setDetailLoading(false);
    }
  };

  const needle = query.toLowerCase().trim();
  const filteredIocs = useMemo(() => {
    if (!data) return [];
    return data.iocs.filter(
      (i) =>
        !needle ||
        `${i.value ?? ''} ${i.type ?? ''} ${(i.tags || []).join(' ')} ${i.context ?? ''}`.toLowerCase().includes(needle)
    );
  }, [data, needle]);
  const filteredVulns = useMemo(() => {
    if (!data) return [];
    const list = kevOnly ? data.kev : data.vulnerabilities;
    return list.filter(
      (v) => !needle || `${v.cve_id ?? ''} ${v.title ?? ''} ${(v.tags || []).join(' ')}`.toLowerCase().includes(needle)
    );
  }, [data, needle, kevOnly]);
  const filteredVictims = useMemo(() => {
    if (!data) return [];
    return data.victims.filter(
      (v) =>
        !needle ||
        `${v.name ?? ''} ${v.group ?? ''} ${v.country ?? ''} ${v.sector ?? ''}`.toLowerCase().includes(needle)
    );
  }, [data, needle]);
  const filteredActors = useMemo(() => {
    if (!data) return [];
    return data.actors.filter(
      (a) =>
        !needle ||
        `${a.name ?? ''} ${a.country ?? ''} ${(a.aliases || []).join(' ')} ${a.description ?? ''}`
          .toLowerCase()
          .includes(needle)
    );
  }, [data, needle]);

  return (
    <DataPageLayout
      backTo="/threatintel/feeds"
      backLabel="Threat Feeds"
      icon={<AlertTriangle size={28} />}
      title="CTIWatch"
      description={
        <>
          <a
            href="https://ctiwatch.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sky-600 dark:text-sky-400 hover:underline transition-colors"
          >
            ctiwatch.com
          </a>{' '}
          — public vulnerability + IOC database: 2M+ IOCs, 400k+ CVEs, 4k+ KEV, 10k+ threat actors, 35k+ victims.
        </>
      }
      headerExtra={
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-meta font-mono border border-line-1 text-muted hover:border-sky-500/30 hover:text-sky-600 dark:hover:text-sky-400 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      }
      loading={loading && !data}
      error={error}
      onRetry={load}
    >
      {data && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
            {[
              { label: 'IOCs', value: data.counts.iocs, cls: 'text-slate-500' },
              { label: 'CVEs', value: data.counts.vulnerabilities, cls: 'text-slate-500' },
              { label: 'KEV', value: data.counts.kev, cls: 'text-rose-600 dark:text-rose-400' },
              { label: 'Victims', value: data.counts.victims, cls: 'text-orange-600 dark:text-orange-400' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="surface-card/50 shadow-e1 p-2.5">
                <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">{label}</div>
                <div className={`text-lg font-bold ${cls}`}>{value}</div>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 mb-4">
            {TABS.map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3 py-1.5 rounded text-xs font-mono font-medium border transition ${tab === t ? 'border-sky-500/60 bg-sky-500/10 text-sky-600 dark:text-sky-400' : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-slate-400'}`}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              type="text"
              placeholder="Search…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-sky-500"
            />
          </div>

          {tab === 'overview' && (
            <div className="space-y-3">
              {data.stats && (
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {Object.entries(data.stats)
                    .filter(([, v]) => typeof v === 'number')
                    .map(([k, v]) => (
                      <div key={k} className="surface-card/50 shadow-e1 p-2.5">
                        <div className="text-mini uppercase tracking-wider mb-0.5 text-muted">
                          {k.replace(/_/g, ' ')}
                        </div>
                        <div className="text-lg font-bold text-muted">{String(v)}</div>
                      </div>
                    ))}
                </div>
              )}
              {data.victimStats?.by_group && (
                <div>
                  <div className="text-xs text-muted font-mono mb-2">Top threat groups (by victims)</div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.victimStats.by_group.slice(0, 20).map((g) => (
                      <span
                        key={g.group_name}
                        className="px-2 py-1 text-micro font-mono rounded border border-line-2 text-muted"
                      >
                        {g.group_name} <span className="opacity-60">{g.count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {data.victimStats?.by_sector && (
                <div>
                  <div className="text-xs text-muted font-mono mb-2">Victims by sector</div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.victimStats.by_sector.slice(0, 20).map((s) => (
                      <span
                        key={s.sector}
                        className="px-2 py-1 text-micro font-mono rounded border border-line-2 text-muted"
                      >
                        {s.sector} <span className="opacity-60">{s.count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === 'iocs' && (
            <div className="space-y-2">
              <div className="text-xs text-muted font-mono mb-2">
                Showing {filteredIocs.length} of {data.iocs.length} IOCs
              </div>
              {filteredIocs.slice(0, 200).map((i) => (
                <div key={i.id ?? i.value} className="rounded-xl border border-line-1 bg-surface-100/50 p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                      {i.type}
                    </span>
                    {i.confidence_score != null && (
                      <span className="text-micro font-mono text-muted">conf {i.confidence_score}</span>
                    )}
                    {i.is_active && (
                      <span className="text-micro font-mono text-emerald-600 dark:text-emerald-400">ACTIVE</span>
                    )}
                  </div>
                  <div className="mt-1 font-mono text-sm text-heading break-all">{i.value}</div>
                  {i.context && <div className="mt-1 text-mini text-muted line-clamp-2">{i.context}</div>}
                  {i.tags?.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {i.tags.slice(0, 6).map((t) => (
                        <span key={t} className="px-1.5 py-0.5 text-micro rounded border border-line-2 text-muted">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="mt-1 text-micro text-muted font-mono">
                    {i.source_name} · {fmtDate(i.last_seen)}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === 'cves' && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 mb-3">
                <button
                  onClick={() => setKevOnly((v) => !v)}
                  className={`px-3 py-1.5 rounded text-xs font-mono border flex items-center gap-1.5 transition ${kevOnly ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-line-1 text-slate-500 hover:border-rose-500/30'}`}
                >
                  <Shield className="w-3.5 h-3.5" />
                  KEV only
                </button>
                <span className="text-xs text-muted font-mono">Showing {filteredVulns.length}</span>
              </div>
              {filteredVulns.slice(0, 200).map((v) => (
                <button
                  key={v.cve_id}
                  onClick={() => loadVuln(v.cve_id)}
                  className="w-full text-left rounded-xl border border-line-1 bg-surface-100/50 p-3 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    {v.severity && (
                      <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                        {v.severity}
                      </span>
                    )}
                    {v.is_kev && (
                      <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300">
                        KEV
                      </span>
                    )}
                    {v.cvss_score != null && (
                      <span className="text-micro font-mono text-muted">CVSS {v.cvss_score}</span>
                    )}
                    {v.exploit_status && v.exploit_status !== 'none' && (
                      <span className="text-micro font-mono text-amber-600 dark:text-amber-400">
                        {v.exploit_status}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 font-mono text-sm text-heading">{v.cve_id}</div>
                  {v.title && <div className="mt-0.5 text-mini text-muted line-clamp-1">{v.title}</div>}
                  <div className="mt-1 text-micro text-muted font-mono">
                    {fmtDate(v.published_date)}
                    {v.vendor ? ` · ${v.vendor}` : ''}
                  </div>
                </button>
              ))}
              {selectedVuln && (
                <div className="mt-4 rounded-xl border border-line-1 bg-surface-200/60 dark:bg-surface-100/40 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="font-mono text-sm text-heading">{selectedVuln.cve_id}</div>
                    <button onClick={() => setSelectedVuln(null)} className="text-xs text-muted hover:text-heading">
                      close
                    </button>
                  </div>
                  {detailLoading && (
                    <div className="text-xs text-muted font-mono">
                      <Loader2 className="inline w-3.5 h-3.5 animate-spin" /> loading…
                    </div>
                  )}
                  {selectedVuln.description && (
                    <div className="text-sm text-body leading-relaxed">{selectedVuln.description}</div>
                  )}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-mini font-mono">
                    <Detail label="Severity" value={selectedVuln.severity ?? '—'} />
                    <Detail label="CVSS vector" value={selectedVuln.cvss_vector ?? '—'} mono />
                    <Detail label="KEV" value={selectedVuln.is_kev ? 'yes' : 'no'} />
                    <Detail label="Exploit status" value={selectedVuln.exploit_status ?? 'none'} />
                    <Detail label="Published" value={selectedVuln.published_date ?? '—'} />
                    <Detail label="EPSS" value={selectedVuln.epss != null ? String(selectedVuln.epss) : '—'} />
                  </div>
                  {selectedVuln.cwe?.length > 0 && (
                    <div className="text-mini font-mono text-muted">CWE: {selectedVuln.cwe.join(', ')}</div>
                  )}
                  {selectedVuln.references?.length > 0 && (
                    <div className="text-mini font-mono text-muted">{selectedVuln.references.length} references</div>
                  )}
                </div>
              )}
            </div>
          )}

          {tab === 'victims' && (
            <div className="space-y-2">
              <div className="text-xs text-muted font-mono mb-2">
                Showing {filteredVictims.length} of {data.victims.length} victims
              </div>
              {filteredVictims.slice(0, 200).map((v) => (
                <button
                  key={v.id ?? v.name}
                  onClick={() => loadVictim(v.id)}
                  className="w-full text-left rounded-xl border border-line-1 bg-surface-100/50 p-3 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    {v.group && (
                      <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                        {v.group}
                      </span>
                    )}
                    {v.country && <span className="text-micro font-mono text-muted">{v.country}</span>}
                    {v.sector && <span className="text-micro font-mono text-muted">{v.sector}</span>}
                  </div>
                  <div className="mt-1 text-sm text-heading">{v.name ?? '—'}</div>
                  <div className="mt-1 text-micro text-muted font-mono">
                    {fmtDate(v.attack_date)}
                    {v.website ? ` · ${v.website}` : ''}
                  </div>
                </button>
              ))}
              {selectedVictim && (
                <div className="mt-4 rounded-xl border border-line-1 bg-surface-200/60 dark:bg-surface-100/40 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="font-mono text-sm text-heading">{selectedVictim.name}</div>
                    <button onClick={() => setSelectedVictim(null)} className="text-xs text-muted hover:text-heading">
                      close
                    </button>
                  </div>
                  {detailLoading && (
                    <div className="text-xs text-muted font-mono">
                      <Loader2 className="inline w-3.5 h-3.5 animate-spin" /> loading…
                    </div>
                  )}
                  {selectedVictim.description && (
                    <div className="text-sm text-body leading-relaxed">{selectedVictim.description}</div>
                  )}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-mini font-mono">
                    <Detail label="Group" value={selectedVictim.group ?? '—'} />
                    <Detail label="Country" value={selectedVictim.country ?? '—'} />
                    <Detail label="Sector" value={selectedVictim.sector ?? '—'} />
                    <Detail label="Attack date" value={selectedVictim.attack_date ?? '—'} />
                    <Detail label="Website" value={selectedVictim.website ?? '—'} mono />
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === 'actors' && (
            <div className="space-y-2">
              <div className="text-xs text-muted font-mono mb-2">
                Showing {filteredActors.length} of {data.actors.length} actors
              </div>
              {filteredActors.slice(0, 200).map((a) => (
                <div key={a.id ?? a.name} className="rounded-xl border border-line-1 bg-surface-100/50 p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-heading">{a.name}</span>
                    {a.country && <span className="text-micro font-mono text-muted">{a.country}</span>}
                    {a.motivation && (
                      <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                        {a.motivation}
                      </span>
                    )}
                    {a.active && (
                      <span className="text-micro font-mono text-emerald-600 dark:text-emerald-400">ACTIVE</span>
                    )}
                  </div>
                  {a.aliases?.length > 0 && (
                    <div className="mt-1 text-micro text-muted font-mono">aka {a.aliases.join(', ')}</div>
                  )}
                  {a.description && <div className="mt-1 text-mini text-muted line-clamp-2">{a.description}</div>}
                </div>
              ))}
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-line-1 text-xs text-muted font-mono">
            Source: ctiwatch.com · {data.counts.iocs} IOCs · {data.counts.vulnerabilities} CVEs · {data.counts.kev} KEV
            · {data.counts.victims} victims · synced{' '}
            {data.syncedAt
              ? new Date(data.syncedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
              : '—'}
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-micro text-muted uppercase tracking-wider">{label}</div>
      <div className={`text-mini text-body break-all ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  );
}
