import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, useCallback } from 'react';
import { BackLink } from '../../components/BackLink';
import { api } from '../../lib/api-client';
import { adminAuthHeaders, readAdminToken } from '../../lib/admin-token';
import { Shield, Globe, AlertTriangle, Loader2, Plus, Trash2, RefreshCw, Eye } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';

interface WatchedDomain {
  domain: string;
  alert_types: string[];
  added_at: string;
  last_checked: string;
  cert_count: number;
}

interface CertInfo {
  id: number;
  common_name: string;
  names: string[];
  issuer: string;
  not_before: string;
  not_after: string;
  serial: string;
  first_seen: string;
  alert?: { type: string; message: string };
}

const ALERT_BADGE: Record<string, string> = {
  new_subdomain: 'bg-blue-100 text-brand-800 dark:bg-blue-900/30 dark:text-brand-300',
  suspicious_name: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
  wildcard: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  ca_change: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
  short_validity: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  ip_cert: 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
};

export default function CtMonitor(): JSX.Element {
  const [watched, setWatched] = useState<WatchedDomain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [certs, setCerts] = useState<CertInfo[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [certsLoading, setCertsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchWatched = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<{ watched?: WatchedDomain[] }>('/api/v1/ct-monitor/watched', {
        headers: adminAuthHeaders(),
      });
      setWatched(data.watched ?? []);
    } catch (err) {
      console.error('CtMonitor failed:', errMessage(err));
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchCerts = useCallback(async (domain: string) => {
    setCertsLoading(true);
    try {
      const data = await api.get<{ certs?: CertInfo[] }>(
        `/api/v1/ct-monitor/certs?domain=${encodeURIComponent(domain)}&days=30`,
        { headers: adminAuthHeaders() }
      );
      setCerts(data.certs ?? []);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setCertsLoading(false);
    }
  }, []);

  const addDomain = useCallback(async () => {
    if (!newDomain.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await api.post(
        '/api/v1/ct-monitor/watch',
        {
          domain: newDomain.trim(),
          alert_types: ['new_subdomain', 'suspicious_name', 'wildcard', 'short_validity'],
        },
        { headers: adminAuthHeaders() }
      );
      setNewDomain('');
      await fetchWatched();
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setLoading(false);
    }
  }, [newDomain, fetchWatched]);

  const removeDomain = useCallback(
    async (domain: string) => {
      try {
        await api.delete(`/api/v1/ct-monitor/watch/${encodeURIComponent(domain)}`, {
          headers: adminAuthHeaders(),
        });
        await fetchWatched();
        if (selectedDomain === domain) {
          setSelectedDomain(null);
          setCerts([]);
        }
      } catch (err) {
        logCatch(err);
        setError(errMessage(err));
      }
    },
    [selectedDomain, fetchWatched]
  );

  useEffect(() => {
    // The watchlist endpoint is admin-gated; only fetch it when an admin token
    // is present so public visitors don't get a 401 error banner on load.
    if (readAdminToken()) fetchWatched();
  }, [fetchWatched]);
  useEffect(() => {
    if (selectedDomain) fetchCerts(selectedDomain);
  }, [selectedDomain, fetchCerts]);

  const alertCerts = certs.filter((c) => c.alert);

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Shield size={28} className="text-brand-600 dark:text-brand-400" /> Certificate Transparency Monitor
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Monitor CT logs for new subdomains, suspicious certificates, and domain changes.
        </p>
      </div>

      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void addDomain()}
            placeholder="example.com"
            className="flex-1 bg-surface-200 border border-line-1 rounded-xl px-4 py-2.5 text-sm font-mono text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            onClick={addDomain}
            disabled={loading || !newDomain.trim()}
            className="px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center gap-2"
          >
            <Plus size={14} /> Watch
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
          <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="surface-card/40 shadow-e1 p-5">
          <h2 className="font-display font-bold text-sm mb-4 flex items-center gap-2">
            <Eye size={14} className="text-brand-600 dark:text-brand-400" /> Watched ({watched.length})
          </h2>
          {loading && watched.length === 0 ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="animate-spin text-muted" />
            </div>
          ) : watched.length === 0 ? (
            <p className="text-sm text-muted py-4">No domains watched yet.</p>
          ) : (
            <div className="space-y-1.5">
              {watched.map((w) => (
                <div
                  key={w.domain}
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelectedDomain(w.domain)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSelectedDomain(w.domain);
                    }
                  }}
                  className={`w-full text-left p-3 rounded-xl border transition-colors cursor-pointer ${selectedDomain === w.domain ? 'border-brand-500/60 bg-brand-500/5' : 'border-line-1 hover:border-brand-500/30'}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-mono">{w.domain}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        removeDomain(w.domain);
                      }}
                      className="p-1 rounded hover:bg-rose-100 dark:hover:bg-rose-900/20 text-muted hover:text-rose-500"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                  <div className="text-micro font-mono text-muted mt-0.5">
                    {w.cert_count} certs · {w.last_checked ? new Date(w.last_checked).toLocaleDateString() : 'Never'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-2 surface-card/40 shadow-e1 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display font-bold text-sm flex items-center gap-2">
              <Globe size={14} className="text-brand-600 dark:text-brand-400" /> Certs{' '}
              {selectedDomain && <span className="font-mono text-xs text-muted">· {selectedDomain}</span>}
            </h2>
            {selectedDomain && (
              <button
                onClick={() => fetchCerts(selectedDomain)}
                className="p-1.5 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 text-muted"
              >
                <RefreshCw size={14} />
              </button>
            )}
          </div>
          {!selectedDomain ? (
            <p className="text-sm text-muted py-8 text-center">Select a domain to view certificates</p>
          ) : certsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="animate-spin text-muted" />
            </div>
          ) : certs.length === 0 ? (
            <p className="text-sm text-muted py-8 text-center">No certificates found in the last 30 days</p>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {alertCerts.length > 0 && (
                <div className="mb-3">
                  <h3 className="text-xs font-mono text-rose-600 dark:text-rose-400 mb-2 flex items-center gap-1.5">
                    <AlertTriangle size={12} /> Alerts ({alertCerts.length})
                  </h3>
                  {alertCerts.map((cert) => (
                    <CertCard key={cert.id} cert={cert} highlight />
                  ))}
                </div>
              )}
              <h3 className="text-xs font-mono text-muted">All ({certs.length})</h3>
              {certs.map((cert) => (
                <CertCard key={cert.id} cert={cert} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CertCard({ cert, highlight }: { cert: CertInfo; highlight?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      className={`rounded-xl p-3 cursor-pointer transition-colors ${highlight ? 'border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/20' : 'border border-line-1 hover:border-brand-500/30'}`}
      onClick={() => setExpanded(!expanded)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setExpanded(!expanded);
        }
      }}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="font-mono text-sm truncate">{cert.common_name}</div>
          <div className="text-micro text-muted mt-0.5 truncate">Issuer: {cert.issuer?.slice(0, 50)}…</div>
        </div>
        {cert.alert && (
          <span className={`text-micro font-mono px-1.5 py-0.5 rounded ${ALERT_BADGE[cert.alert.type] ?? ''}`}>
            {cert.alert.type}
          </span>
        )}
      </div>
      {cert.alert && <div className="text-xs text-rose-600 dark:text-rose-400 mt-1.5">{cert.alert.message}</div>}
      {expanded && (
        <div className="mt-3 pt-3 border-t border-line-1 text-xs space-y-2">
          <div>
            <span className="text-micro font-mono uppercase tracking-wider text-muted">Names</span>
            <div className="mt-1 flex flex-wrap gap-1">
              {cert.names.map((n, i) => (
                <span key={i} className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 text-muted">
                  {n}
                </span>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">Valid From</span>
              <div>{new Date(cert.not_before).toLocaleDateString()}</div>
            </div>
            <div>
              <span className="text-micro font-mono uppercase tracking-wider text-muted">Valid Until</span>
              <div>{new Date(cert.not_after).toLocaleDateString()}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-micro font-mono uppercase tracking-wider text-muted">Serial</span>
            <code className="text-micro font-mono text-body truncate">{cert.serial}</code>
            <CopyButton value={cert.serial} />
          </div>
        </div>
      )}
    </div>
  );
}
