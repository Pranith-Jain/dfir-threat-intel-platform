import { useEffect, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { fetchJsonCached } from '../../lib/api-client';
import { Bell, BellOff, RefreshCw, CheckCircle, XCircle, AlertTriangle, Shield, Info, Skull } from 'lucide-react';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { turnstileHeaders } from '../../lib/turnstile';
import { errMessage } from '../../lib/log';

interface Alert {
  id: string;
  alert_type: string;
  title: string;
  description: string;
  confidence: number;
  severity: string;
  source: string;
  source_url: string;
  topics: string[];
  matched_assets: string[];
  matched_sector: number;
  read: number;
  dismissed: number;
  tlp: string;
  created_at: string;
}

interface AlertStats {
  total: number;
  unread: number;
  bySeverity: Array<{ severity: string; count: number }>;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: typeof AlertTriangle }> = {
  critical: { color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/20', icon: Skull },
  high: {
    color: 'text-orange-600 dark:text-orange-400',
    bg: 'bg-orange-50 dark:bg-orange-900/20',
    icon: AlertTriangle,
  },
  medium: { color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/20', icon: Shield },
  low: { color: 'text-brand-600 dark:text-brand-400', bg: 'bg-blue-50 dark:bg-blue-900/20', icon: Info },
  info: { color: 'text-slate-500', bg: 'bg-slate-50 dark:bg-white/5', icon: Bell },
};

const TLP_COLORS: Record<string, string> = {
  RED: 'bg-red-600 text-white',
  AMBER: 'bg-amber-500 text-white',
  GREEN: 'bg-green-500 text-white',
  CLEAR: 'bg-slate-300 text-slate-700 dark:bg-surface-300 dark:text-slate-200',
};

export default function AlertFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats>({ total: 0, unread: 0, bySeverity: [] });
  const [filter, setFilter] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (filter !== 'all') params.set('severity', filter);
      const [alertData, statsData] = await Promise.all([
        fetchJsonCached<{ alerts?: Alert[] }>(`/api/v1/estate/alerts?${params}`, 30_000),
        fetchJsonCached<AlertStats>('/api/v1/estate/alerts/stats', 30_000),
      ]);
      setAlerts(alertData.alerts ?? []);
      setStats(statsData);
    } catch (e) {
      console.error('AlertFeed failed:', errMessage(e));
      setError(errMessage(e, 'Failed to load alerts'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // loadAlerts is a plain function (not useCallback) that closes over filter;
    // re-running on filter change is the intended trigger.
    loadAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  const markRead = async (id: string) => {
    await fetch(`/api/v1/estate/alerts/${id}/read`, {
      method: 'POST',
      headers: await turnstileHeaders('estate-alert-read'),
    });
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: 1 } : a)));
    setStats((prev) => ({ ...prev, unread: Math.max(0, prev.unread - 1) }));
  };

  const dismiss = async (id: string) => {
    await fetch(`/api/v1/estate/alerts/${id}/dismiss`, {
      method: 'POST',
      headers: await turnstileHeaders('estate-alert-dismiss'),
    });
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  };

  const severityCount = (sev: string) => stats.bySeverity.find((s) => s.severity === sev)?.count ?? 0;

  return (
    <DataPageLayout
      backTo="/threatintel"
      title="Alert Feed"
      description="Prioritised threat intelligence alerts - noise-filtered, confidence-scored, and matched to your estate."
      icon={<Bell />}
      loading={loading && alerts.length === 0}
      error={error}
      onRetry={loadAlerts}
      empty={!loading && alerts.length === 0 && !error}
      emptyMessage="No alerts to show. Configure your estate to receive personalised threat intelligence."
      emptyIcon={<BellOff size={32} className="text-inverted" />}
    >
      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        {SEVERITIES.map((sev) => {
          const cfg = SEVERITY_CONFIG[sev]!;
          const Icon = cfg.icon;
          return (
            <button
              type="button"
              key={sev}
              onClick={() => setFilter(filter === sev ? 'all' : sev)}
              className={`rounded-xl border p-4 text-left transition-all ${
                filter === sev
                  ? 'border-amber-500 dark:border-amber-400 bg-amber-50 dark:bg-amber-900/10'
                  : 'border-slate-200/60 dark:border-line-1 bg-white dark:bg-surface-200 hover:border-amber-300'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <Icon size={16} className={cfg.color} />
                <span className="text-xs font-medium uppercase text-muted">{sev}</span>
              </div>
              <span className="text-2xl font-bold">{severityCount(sev)}</span>
            </button>
          );
        })}
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2 text-sm text-muted">
          <Bell size={16} />
          <span>
            {stats.total} alerts · <span className="font-semibold text-amber-600">{stats.unread} unread</span>
          </span>
        </div>
        <button
          type="button"
          onClick={loadAlerts}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-sm font-medium text-body hover:bg-surface-300 dark:hover:bg-surface-200 transition-colors"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Alert cards */}
      <div className="space-y-3">
        {/* AI summary of the visible estate alerts. Public surface so every
            visitor sees the analyst take on the prioritised alerts. */}
        {alerts.length > 0 && (
          <>
            <PostAnalysisButton
              title="Estate alert feed Digest"
              description="AI-powered threat analysis of the current feed."
              source="alertfeed"
            />
            <AiSummaryCard
              surface="Estate alert feed"
              items={alerts.slice(0, 30).map((a) => ({
                title: a.title,
                body: `${a.severity} · ${a.alert_type} · ${a.description} · topics: ${a.topics.join(', ')} · assets: ${a.matched_assets.join(', ')}`,
                source: a.source,
              }))}
              requireAdmin={false}
            />
          </>
        )}
        {alerts.map((alert) => {
          const cfg = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.info!;
          const Icon = cfg.icon;
          const hoursAgo = Math.floor((Date.now() - new Date(alert.created_at).getTime()) / 3600000);

          return (
            <div
              key={alert.id}
              className={`rounded-xl border p-4 transition-all ${
                !alert.read
                  ? 'border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-900/5'
                  : 'border-slate-200/60 dark:border-line-1 bg-white dark:bg-surface-200'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-xl ${cfg.bg} ${cfg.color}`}>
                  <Icon size={18} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-semibold text-sm">{alert.title}</h3>
                        <span
                          className={`text-xs px-1.5 py-0.5 rounded font-bold ${TLP_COLORS[alert.tlp] ?? TLP_COLORS.CLEAR}`}
                        >
                          TLP:{alert.tlp}
                        </span>
                        <span className={`text-xs px-1.5 py-0.5 rounded-full font-medium ${cfg.color} ${cfg.bg}`}>
                          {alert.severity}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {!alert.read && (
                        <button
                          type="button"
                          onClick={() => markRead(alert.id)}
                          className="p-1.5 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 text-muted hover:text-green-500"
                          title="Mark read"
                        >
                          <CheckCircle size={14} />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => dismiss(alert.id)}
                        className="p-1.5 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 text-muted hover:text-red-500"
                        title="Dismiss"
                      >
                        <XCircle size={14} />
                      </button>
                    </div>
                  </div>
                  <p className="text-sm text-muted mt-1 line-clamp-2">{alert.description}</p>
                  <div className="flex items-center gap-3 mt-2 text-xs text-muted">
                    <span>
                      {hoursAgo < 1
                        ? 'Just now'
                        : hoursAgo < 24
                          ? `${hoursAgo}h ago`
                          : `${Math.floor(hoursAgo / 24)}d ago`}
                    </span>
                    <span className="flex items-center gap-1">
                      Confidence:
                      <span
                        className={`font-medium ${
                          alert.confidence >= 80
                            ? 'text-green-500'
                            : alert.confidence >= 60
                              ? 'text-yellow-500'
                              : 'text-slate-500'
                        }`}
                      >
                        {alert.confidence}%
                      </span>
                    </span>
                    {alert.source && <span>Source: {alert.source}</span>}
                    {alert.matched_sector === 1 && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-50 dark:bg-amber-900/20 text-amber-600 dark:text-amber-400 font-medium">
                        Sector match
                      </span>
                    )}
                  </div>
                  {alert.topics.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {alert.topics.map((t) => (
                        <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                  {alert.matched_assets.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {alert.matched_assets.map((a) => (
                        <span
                          key={a}
                          className="text-xs px-1.5 py-0.5 rounded bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 font-mono"
                        >
                          {a}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </DataPageLayout>
  );
}
