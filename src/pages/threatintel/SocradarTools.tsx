/**
 * /threatintel/tools/socradar-tools -- SOCRadar-Inspired Free Tools
 *
 * DDoS Intelligence, FortiBleed Checker, Healthcare Breach Tracker.
 */

import { useEffect, useState, useCallback, type FormEvent } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';
import {
  Search,
  Loader2,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Activity,
  Database,
  Lock,
  Hospital,
  Server,
} from 'lucide-react';

// ── Types ──

interface BotnetEntry {
  ip: string;
  port: number;
  malware: string;
  status: string;
  firstSeen: string;
  lastSeen: string;
  urlhausLink: string;
}

interface ThreatFoxIOC {
  ioc: string;
  iocType: string;
  malware: string;
  confidence: number;
  firstSeen: string;
}

interface DDoSDashboard {
  stats: {
    totalBotnets: number;
    activeC2: number;
    topMalware: Array<{ name: string; count: number }>;
    lastUpdated: string;
  };
  botnets: BotnetEntry[];
  threatFoxC2: ThreatFoxIOC[];
}

interface FortiResult {
  target: string;
  isFortiGate: boolean;
  version: string | null;
  vulnerability: string | null;
  cvss: number | null;
  severity: string | null;
  details: string[];
  recommendations: string[];
}

interface HealthBreach {
  id: string;
  name: string;
  breachType: string;
  individualsAffected: number;
  state: string;
  dateReported: string;
  severity: string;
  description: string;
}

interface ThreatReportCountry {
  name: string;
  riskLevel: string;
  topActors: string[];
  topMalware: string[];
  criticalSectors: string[];
  recentIncidents: string[];
  phishingExposure: string;
  ransomwareVictims: number;
}

interface ThreatReportIndustry {
  name: string;
  riskLevel: string;
  topActors: string[];
  commonVectors: string[];
  recentIncidents: string[];
  exposureLevel: string;
  complianceNotes: string;
}

interface ThreatReportAssessment {
  domain: string;
  riskLevel: string;
  riskScore: number;
  sections: {
    emailSecurity?: { spf: string; dmarc: string };
    ssl?: { issuer: string; grade: string };
    recommendations: string[];
  };
}

// ── Tabs ──

type Tab = 'ddos' | 'fortibleed' | 'healthcare' | 'reports';

export default function SocradarTools() {
  const [tab, setTab] = useState<Tab>('ddos');
  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Shield size={26} />}
      title="Tactical Radar Free Tools"
      description="DDoS intelligence, FortiGate breach check, healthcare breach tracking."
    >
      <div role="tablist" aria-label="Tabs" className="flex gap-1 mb-6 border-b border-line-1">
        {(
          [
            ['ddos', 'DDoS Intelligence', Activity],
            ['fortibleed', 'FortiBleed Check', Lock],
            ['healthcare', 'Healthcare Breaches', Hospital],
            ['reports', 'Threat Reports', Shield],
          ] as const
        ).map(([id, label, Icon]) => (
          <button
            type="button"
            key={id}
            role="tab"
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-mono font-semibold border-b-2 transition-colors ${
              tab === id
                ? 'border-rose-500 text-rose-600 dark:text-rose-400'
                : 'border-transparent text-muted hover:text-slate-900 dark:hover:text-slate-100'
            }`}
          >
            <Icon size={14} /> {label}
          </button>
        ))}
      </div>
      {tab === 'ddos' && <DDoSPanel />}
      {tab === 'fortibleed' && <FortiBleedPanel />}
      {tab === 'healthcare' && <HealthcarePanel />}
      {tab === 'reports' && <ThreatReportsPanel />}
    </DataPageLayout>
  );
}

// ── DDoS Intelligence ──

function DDoSPanel() {
  const [data, setData] = useState<DDoSDashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQ, setSearchQ] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/ddos/dashboard');
      if (!res.ok) throw new Error('Failed');
      setData(await res.json());
    } catch (_catchErr) {
      console.error('DDoSPanel failed:', errMessage(_catchErr));
      setError('Failed to load DDoS intelligence');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const searchResults =
    data?.botnets.filter(
      (b) =>
        !searchQ ||
        (b.ip && b.ip.includes(searchQ)) ||
        (b.malware && b.malware.toLowerCase().includes(searchQ.toLowerCase()))
    ) || [];

  return (
    <div className="space-y-6">
      {loading && (
        <div className="flex items-center gap-2 text-muted py-12 justify-center font-mono text-sm">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading DDoS intelligence...
        </div>
      )}
      {error && (
        <div className="p-3 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 flex items-center gap-2 font-mono text-sm">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {data && (
        <>
          {/* KPI Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Botnet C2 Servers', value: data.stats.totalBotnets, icon: Server, color: 'text-rose-500' },
              { label: 'Active C2', value: data.stats.activeC2, icon: Activity, color: 'text-amber-500' },
              { label: 'Threat Fox IOCs', value: data.threatFoxC2.length, icon: Shield, color: 'text-violet-500' },
              { label: 'Sources', value: 3, icon: Database, color: 'text-sky-500' },
            ].map((kpi) => (
              <div key={kpi.label} className="surface-card p-3">
                <div className="flex items-center gap-2 mb-1">
                  <kpi.icon size={12} className={kpi.color} />
                  <span className="text-micro font-mono text-muted">{kpi.label}</span>
                </div>
                <p className="text-xl font-display font-bold">{kpi.value.toLocaleString()}</p>
              </div>
            ))}
          </div>

          {/* Top Malware */}
          {data.stats.topMalware.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="font-display font-semibold text-sm mb-2">Top Botnet Malware</h3>
              <div className="space-y-1.5">
                {data.stats.topMalware.map((m) => (
                  <div key={m.name} className="flex items-center gap-2">
                    <span className="text-mini font-mono truncate flex-1">{m.name}</span>
                    <div className="w-32 h-2 bg-surface-300 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-rose-500 rounded-full"
                        style={{ width: `${(m.count / data.stats.topMalware[0]!.count) * 100}%` }}
                      />
                    </div>
                    <span className="text-micro font-mono text-muted w-8 text-right">{m.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Search */}
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder="Search by IP or malware family..."
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-rose-500"
              />
            </div>
          </div>

          {/* Botnet List */}
          <div className="surface-card overflow-hidden">
            <div className="p-3 border-b border-line-1">
              <h3 className="font-display font-semibold text-sm">Botnet C2 Servers (Feodo Tracker)</h3>
            </div>
            <div className="divide-y divide-line-1">
              {searchResults.slice(0, 30).map((b, i) => (
                <div
                  key={b.ip + i}
                  role="button"
                  tabIndex={0}
                  className="px-3 py-2 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors cursor-pointer"
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setExpanded(expanded === i ? null : i);
                    }
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-mini font-mono font-semibold text-heading">
                        {b.ip}:{b.port}
                      </span>
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300">
                        {b.malware}
                      </span>
                      <span
                        className={`text-micro font-mono px-1.5 py-0.5 rounded ${b.status === 'online' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-surface-300 text-slate-500'}`}
                      >
                        {b.status}
                      </span>
                    </div>
                    {expanded === i ? (
                      <ChevronUp size={12} className="text-muted" />
                    ) : (
                      <ChevronDown size={12} className="text-muted" />
                    )}
                  </div>
                  {expanded === i && (
                    <div className="mt-2 pt-2 border-t border-line-1 text-micro font-mono text-muted space-y-1">
                      <p>
                        First seen: {b.firstSeen} | Last seen: {b.lastSeen}
                      </p>
                      {b.urlhausLink && (
                        <a
                          href={b.urlhausLink}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-rose-600 dark:text-rose-400 hover:underline flex items-center gap-1 transition-colors"
                        >
                          URLhaus <ExternalLink size={8} />
                        </a>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── FortiBleed Check ──

function FortiBleedPanel() {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState<FortiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async (e: FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`/api/v1/fortibleed/check?target=${encodeURIComponent(target)}`);
      if (!res.ok) throw new Error('Check failed');
      setResult(await res.json());
    } catch (_catchErr) {
      console.error('FortiBleedPanel failed:', errMessage(_catchErr));
      setError('Check failed');
    }
    setLoading(false);
  };

  const sevColor = (s: string | null) => {
    if (s === 'CRITICAL')
      return 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800';
    if (s === 'HIGH')
      return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800';
    if (s === 'INFO')
      return 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800';
    return 'bg-slate-100 dark:bg-surface-300 text-muted border-line-1';
  };

  return (
    <div className="space-y-6">
      <div className="surface-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Lock size={14} className="text-amber-500" />
          <h3 className="font-display font-semibold text-sm">FortiGate / FortiOS Vulnerability Check</h3>
        </div>
        <p className="text-meta font-mono text-muted mb-3">
          Checks for CVE-2024-21762 (CVSS 9.8) - FortiGate SSL VPN out-of-bound write RCE. Enter a domain or IP.
        </p>
        <form onSubmit={handleCheck} className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com or 203.0.113.10"
            className="flex-1 px-3 py-2 bg-surface-100 border border-line-1 rounded font-mono text-tool focus:outline-none focus:border-rose-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-rose-600 dark:bg-rose-500 text-on-fill font-mono text-sm font-semibold rounded hover:bg-rose-700 dark:hover:bg-rose-400 disabled:opacity-50 transition-colors"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : 'Check'}
          </button>
        </form>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 flex items-center gap-2 font-mono text-sm">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {result && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="font-display font-semibold text-sm">{result.target}</h3>
              {result.version && <p className="text-meta font-mono text-muted">Version: {result.version}</p>}
            </div>
            {result.severity && (
              <span
                className={`text-micro font-mono font-semibold px-2 py-0.5 rounded border ${sevColor(result.severity)}`}
              >
                {result.severity}
                {result.cvss ? ` ${result.cvss}` : ''}
              </span>
            )}
          </div>

          <div
            className={`p-3 rounded mb-3 ${result.isFortiGate ? 'bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800' : 'bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800'}`}
          >
            <p
              className={`text-sm font-mono font-semibold ${result.isFortiGate ? 'text-amber-700 dark:text-amber-300' : 'text-emerald-700 dark:text-emerald-300'}`}
            >
              {result.isFortiGate ? '! FortiGate Detected' : 'No FortiGate detected'}
            </p>
          </div>

          {result.details.length > 0 && (
            <div className="mb-3">
              <h4 className="text-mini font-display font-semibold mb-1">Details</h4>
              <ul className="space-y-0.5">
                {result.details.map((d, i) => (
                  <li key={i} className="text-meta font-mono text-body">
                    • {d}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.recommendations.length > 0 && (
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Recommendations</h4>
              <ul className="space-y-0.5">
                {result.recommendations.map((r, i) => (
                  <li key={i} className="text-meta font-mono text-body">
                    → {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.vulnerability && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${result.vulnerability}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline flex items-center gap-1 transition-colors"
              >
                View on NVD <ExternalLink size={8} />
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Healthcare Breach Tracker ──

function HealthcarePanel() {
  const [data, setData] = useState<{
    stats: {
      totalBreaches: number;
      totalIndividuals: number;
      topStates: Array<{ state: string; count: number; individuals: number }>;
      topTypes: Array<{ type: string; count: number }>;
    };
    breaches: HealthBreach[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQ, setSearchQ] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/health-breach/dashboard');
      if (!res.ok) throw new Error('Failed');
      setData(await res.json());
    } catch (_catchErr) {
      console.error('HealthcarePanel failed:', errMessage(_catchErr));
      setError('Failed to load healthcare breach data');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const filtered =
    data?.breaches.filter(
      (b) =>
        !searchQ ||
        (b.name && b.name.toLowerCase().includes(searchQ.toLowerCase())) ||
        (b.state && b.state.toLowerCase().includes(searchQ.toLowerCase()))
    ) || [];

  const fmtNum = (n: number) => {
    if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
  };

  const sevColor = (s: string) => {
    if (s === 'critical') return 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300';
    if (s === 'high') return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300';
    if (s === 'medium') return 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300';
    return 'bg-slate-100 dark:bg-surface-300 text-muted';
  };

  return (
    <div className="space-y-6">
      {loading && (
        <div className="flex items-center gap-2 text-muted py-12 justify-center font-mono text-sm">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading healthcare breach data...
        </div>
      )}
      {error && (
        <div className="p-3 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 flex items-center gap-2 font-mono text-sm">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="surface-card p-3">
              <span className="text-micro font-mono text-muted">Total Breaches</span>
              <p className="text-xl font-display font-bold">{data.stats.totalBreaches}</p>
            </div>
            <div className="surface-card p-3">
              <span className="text-micro font-mono text-muted">Individuals Affected</span>
              <p className="text-xl font-display font-bold">{fmtNum(data.stats.totalIndividuals)}</p>
            </div>
            <div className="surface-card p-3">
              <span className="text-micro font-mono text-muted">Top Targeted State</span>
              <p className="text-xl font-display font-bold">{data.stats.topStates[0]?.state || 'N/A'}</p>
            </div>
          </div>

          {data.stats.topStates.length > 0 && (
            <div className="surface-card p-4">
              <h3 className="font-display font-semibold text-sm mb-2">Top Targeted States</h3>
              <div className="space-y-1.5">
                {data.stats.topStates.slice(0, 8).map((s) => (
                  <div key={s.state} className="flex items-center gap-2">
                    <span className="text-mini font-mono w-8">{s.state}</span>
                    <div className="flex-1 h-2 bg-surface-300 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-rose-500 rounded-full"
                        style={{ width: `${(s.individuals / data.stats.topStates[0]!.individuals) * 100}%` }}
                      />
                    </div>
                    <span className="text-micro font-mono text-muted w-16 text-right">{fmtNum(s.individuals)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder="Search by name or state..."
                className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-rose-500"
              />
            </div>
          </div>

          <div className="surface-card overflow-hidden">
            <div className="divide-y divide-line-1">
              {filtered.slice(0, 30).map((b, i) => (
                <div
                  key={b.id}
                  role="button"
                  tabIndex={0}
                  className="px-3 py-2 hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors cursor-pointer"
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setExpanded(expanded === i ? null : i);
                    }
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-mini font-mono font-semibold text-heading truncate">{b.name}</span>
                        <span
                          className={`text-micro font-mono font-semibold px-1.5 py-0.5 rounded ${sevColor(b.severity)}`}
                        >
                          {b.severity}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-micro font-mono text-muted">
                        <span>{fmtNum(b.individualsAffected)} affected</span>
                        {b.state && <span>• {b.state}</span>}
                        <span>• {b.dateReported?.split('T')[0]}</span>
                      </div>
                    </div>
                    {expanded === i ? (
                      <ChevronUp size={12} className="text-muted" />
                    ) : (
                      <ChevronDown size={12} className="text-muted" />
                    )}
                  </div>
                  {expanded === i && b.description && (
                    <div className="mt-2 pt-2 border-t border-line-1">
                      <p className="text-meta font-mono text-body">{b.description}</p>
                      <p className="text-micro font-mono text-muted mt-1">Type: {b.breachType}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Threat Reports ──

function ThreatReportsPanel() {
  const [reportType, setReportType] = useState<'country' | 'industry' | 'external'>('country');
  const [country, setCountry] = useState('US');
  const [industry, setIndustry] = useState('healthcare');
  const [domain, setDomain] = useState('');
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = async (type: string, params: Record<string, string>) => {
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const p = new URLSearchParams(params);
      const res = await fetch(`/api/v1/threat-reports/${type}?${p}`);
      if (!res.ok) throw new Error('Failed');
      setData(await res.json());
    } catch (_catchErr) {
      console.error('ThreatReportsPanel failed:', errMessage(_catchErr));
      setError('Failed to generate report');
    }
    setLoading(false);
  };

  const handleGenerate = () => {
    if (reportType === 'country') fetchReport('country', { country });
    else if (reportType === 'industry') fetchReport('industry', { industry });
    else fetchReport('external', { domain });
  };

  const riskColor = (r: string) => {
    if (r === 'CRITICAL')
      return 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800';
    if (r === 'HIGH')
      return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800';
    if (r === 'MEDIUM')
      return 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800';
    return 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800';
  };

  return (
    <div className="space-y-6">
      <div className="surface-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Shield size={14} className="text-violet-500" />
          <h3 className="font-display font-semibold text-sm">Threat Intelligence Reports</h3>
        </div>
        <div className="flex flex-wrap gap-2 mb-3">
          {(
            [
              ['country', 'Country'],
              ['industry', 'Industry'],
              ['external', 'External Assessment'],
            ] as const
          ).map(([t, label]) => (
            <button
              type="button"
              key={t}
              role="tab"
              onClick={() => setReportType(t)}
              className={`px-3 py-1.5 rounded text-mini font-mono font-semibold border transition-colors ${
                reportType === t
                  ? 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300'
                  : 'bg-slate-50 dark:bg-surface-100 border-line-1 text-muted'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex gap-2 items-end">
          {reportType === 'country' && (
            <div className="flex-1">
              <label htmlFor="tr-country" className="block text-micro font-mono text-muted mb-1">
                Country Code
              </label>
              <select
                id="tr-country"
                value={country}
                onChange={(e) => setCountry(e.target.value)}
                className="text-meta font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 focus:outline-none"
              >
                {['US', 'GB', 'DE', 'IN', 'BR', 'JP', 'FR', 'AU', 'CA', 'IT'].map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          )}
          {reportType === 'industry' && (
            <div className="flex-1">
              <label htmlFor="tr-industry" className="block text-micro font-mono text-muted mb-1">
                Industry
              </label>
              <select
                id="tr-industry"
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                className="text-meta font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 focus:outline-none"
              >
                {[
                  'healthcare',
                  'finance',
                  'manufacturing',
                  'government',
                  'technology',
                  'education',
                  'retail',
                  'energy',
                  'telecom',
                  'legal',
                ].map((i) => (
                  <option key={i} value={i}>
                    {i.charAt(0).toUpperCase() + i.slice(1)}
                  </option>
                ))}
              </select>
            </div>
          )}
          {reportType === 'external' && (
            <div className="flex-1">
              <label htmlFor="tr-domain" className="block text-micro font-mono text-muted mb-1">
                Domain
              </label>
              <input
                id="tr-domain"
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="w-full px-3 py-1.5 bg-surface-100 border border-line-1 rounded font-mono text-meta focus:outline-none focus:border-rose-500"
              />
            </div>
          )}
          <button
            type="button"
            onClick={handleGenerate}
            disabled={loading || (reportType === 'external' && !domain)}
            className="px-4 py-1.5 bg-rose-600 dark:bg-rose-500 text-on-fill text-mini font-mono font-semibold rounded hover:bg-rose-700 dark:hover:bg-rose-400 disabled:opacity-50 transition-colors"
          >
            {loading ? <Loader2 size={12} className="animate-spin" /> : 'Generate'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 flex items-center gap-2 font-mono text-sm">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {data && !!data.country && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-display font-semibold text-sm">
              {(data.country as ThreatReportCountry).name} Threat Landscape
            </h3>
            <span
              className={`text-micro font-mono font-semibold px-2 py-0.5 rounded border ${riskColor((data.country as ThreatReportCountry).riskLevel)}`}
            >
              {(data.country as ThreatReportCountry).riskLevel}
            </span>
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Top Threat Actors</h4>
              <div className="flex flex-wrap gap-1">
                {((data.country as ThreatReportCountry).topActors || []).map((a) => (
                  <span
                    key={a}
                    role="tab"
                    className="text-micro font-mono px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Top Malware</h4>
              <div className="flex flex-wrap gap-1">
                {((data.country as ThreatReportCountry).topMalware || []).map((m) => (
                  <span
                    key={m}
                    role="tab"
                    className="text-micro font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300"
                  >
                    {m}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Critical Sectors</h4>
              <div className="flex flex-wrap gap-1">
                {((data.country as ThreatReportCountry).criticalSectors || []).map((s) => (
                  <span
                    key={s}
                    role="tab"
                    className="text-micro font-mono px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Recent Incidents</h4>
              <ul className="space-y-0.5">
                {((data.country as ThreatReportCountry).recentIncidents || []).map((inc, i) => (
                  <li key={i} className="text-micro font-mono text-body">
                    • {inc}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-line-1 flex gap-4 text-micro font-mono text-muted">
            <span>
              Phishing: <span className="text-heading">{(data.country as ThreatReportCountry).phishingExposure}</span>
            </span>
            <span>
              Ransomware victims:{' '}
              <span className="text-heading">
                {(data.country as ThreatReportCountry).ransomwareVictims?.toLocaleString()}
              </span>
            </span>
          </div>
        </div>
      )}

      {data && !!data.industry && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-display font-semibold text-sm">
              {(data.industry as ThreatReportIndustry).name} Threat Landscape
            </h3>
            <span
              className={`text-micro font-mono font-semibold px-2 py-0.5 rounded border ${riskColor((data.industry as ThreatReportIndustry).riskLevel)}`}
            >
              {(data.industry as ThreatReportIndustry).riskLevel}
            </span>
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Top Threat Actors</h4>
              <div className="flex flex-wrap gap-1">
                {((data.industry as ThreatReportIndustry).topActors || []).map((a) => (
                  <span
                    key={a}
                    role="tab"
                    className="text-micro font-mono px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Common Attack Vectors</h4>
              <ul className="space-y-0.5">
                {((data.industry as ThreatReportIndustry).commonVectors || []).map((v, i) => (
                  <li key={i} className="text-micro font-mono text-body">
                    • {v}
                  </li>
                ))}
              </ul>
            </div>
            <div className="sm:col-span-2">
              <h4 className="text-mini font-display font-semibold mb-1">Recent Incidents</h4>
              <ul className="space-y-0.5">
                {((data.industry as ThreatReportIndustry).recentIncidents || []).map((inc, i) => (
                  <li key={i} className="text-micro font-mono text-body">
                    • {inc}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-line-1 text-micro font-mono text-muted">
            <span>
              Exposure: <span className="text-heading">{(data.industry as ThreatReportIndustry).exposureLevel}</span>
            </span>
            <span className="ml-4">
              Compliance:{' '}
              <span className="text-heading">{(data.industry as ThreatReportIndustry).complianceNotes}</span>
            </span>
          </div>
        </div>
      )}

      {data && !!data.assessment && (
        <div className="surface-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-display font-semibold text-sm">
              {(data.assessment as ThreatReportAssessment).domain} External Threat Assessment
            </h3>
            <span
              className={`text-micro font-mono font-semibold px-2 py-0.5 rounded border ${riskColor((data.assessment as ThreatReportAssessment).riskLevel)}`}
            >
              {(data.assessment as ThreatReportAssessment).riskLevel} (
              {(data.assessment as ThreatReportAssessment).riskScore}/100)
            </span>
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">Email Security</h4>
              <div className="space-y-1 text-micro font-mono">
                <p>
                  SPF:{' '}
                  <span
                    className={
                      (data.assessment as ThreatReportAssessment).sections?.emailSecurity?.spf === 'Implemented'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-rose-600 dark:text-rose-400'
                    }
                  >
                    {(data.assessment as ThreatReportAssessment).sections?.emailSecurity?.spf}
                  </span>
                </p>
                <p>
                  DMARC:{' '}
                  <span
                    className={
                      (data.assessment as ThreatReportAssessment).sections?.emailSecurity?.dmarc === 'Implemented'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-rose-600 dark:text-rose-400'
                    }
                  >
                    {(data.assessment as ThreatReportAssessment).sections?.emailSecurity?.dmarc}
                  </span>
                </p>
              </div>
            </div>
            <div>
              <h4 className="text-mini font-display font-semibold mb-1">SSL/TLS</h4>
              <div className="space-y-1 text-micro font-mono">
                <p>
                  Status:{' '}
                  <span
                    className={
                      (data.assessment as ThreatReportAssessment).sections?.ssl?.issuer === 'Valid'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-rose-600 dark:text-rose-400'
                    }
                  >
                    {(data.assessment as ThreatReportAssessment).sections?.ssl?.issuer}
                  </span>
                </p>
                <p>
                  Grade:{' '}
                  <span className="text-heading">
                    {(data.assessment as ThreatReportAssessment).sections?.ssl?.grade}
                  </span>
                </p>
              </div>
            </div>
            <div className="sm:col-span-2">
              <h4 className="text-mini font-display font-semibold mb-1">Recommendations</h4>
              <ul className="space-y-0.5">
                {((data.assessment as ThreatReportAssessment).sections?.recommendations || []).map((r, i) => (
                  <li key={i} className="text-micro font-mono text-body">
                    → {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
