import { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, AlertTriangle, Shield, Globe, FileText, Activity, ExternalLink, Loader2 } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface ProviderHit {
  source: string;
  verdict: string;
  score: number;
  description: string;
  tags: string[];
}

interface TelegramHit {
  channel: string;
  message: string;
  date: string;
}

interface BreachHit {
  name: string;
  source: string;
  breach_date?: string;
  data_classes?: string[];
  description?: string;
}

interface HuntV2Result {
  q: string;
  type: string;
  ioc_providers: { hits: ProviderHit[]; malicious_count: number; max_score: number; total_checked: number };
  telegram_leaks: { hits: TelegramHit[]; count: number };
  breach_data: { hits: BreachHit[]; count: number };
  whois: Record<string, unknown> | null;
  cert_logs: { count: number; recent: string[] };
  composite: { score: number; verdict: string; confidence: string; summary: string[] };
}

const VERDICT_COLORS: Record<string, string> = {
  malicious: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/40',
  suspicious: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/40',
  clean: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/40',
  unknown: 'bg-slate-200 dark:bg-surface-300 text-muted border-slate-300 dark:border-line-1',
};

const PROVIDER_VERDICT_CHIP: Record<string, string> = {
  malicious: 'bg-rose-500/15 text-rose-600 dark:text-rose-400',
  suspicious: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
  clean: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
  unknown: 'bg-slate-100 dark:bg-surface-300 text-muted',
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high: 'text-emerald-600 dark:text-emerald-400',
  medium: 'text-amber-600 dark:text-amber-400',
  low: 'text-muted',
};

export default function ThreatHunt(): JSX.Element {
  const [searchParams] = useSearchParams();
  const initialInput = searchParams.get('indicator') ?? '';
  const [query, setQuery] = useState(initialInput);
  const [hunting, setHunting] = useState(false);
  const [result, setResult] = useState<HuntV2Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  const doHunt = async (override?: string) => {
    const q = (override ?? query).trim();
    if (!q || q.length < 3) return;
    setHunting(true);
    setResult(null);
    setError(null);
    try {
      const r = await fetch(`/api/v1/hunt/v2?q=${encodeURIComponent(q)}`);
      if (!r.ok) {
        setError(`HTTP ${r.status}`);
        return;
      }
      setResult((await r.json()) as HuntV2Result);
    } catch (e) {
      console.error('ThreatHunt failed:', errMessage(e));
      setError(errMessage(e, 'Hunt failed'));
    }
    setHunting(false);
  };

  const autoRanRef = useRef(false);
  useEffect(() => {
    if (autoRanRef.current) return;
    if (initialInput && initialInput.length >= 3) {
      autoRanRef.current = true;
      doHunt(initialInput);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialInput]);

  const comp = result?.composite;
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up mb-8">
        <h1 className="text-3xl sm:text-4xl font-display font-bold flex items-center gap-3">
          <Search size={28} className="text-brand-600 dark:text-brand-400" /> Threat Hunt
        </h1>
        <p className="text-muted mt-2 max-w-2xl">
          Deep-dive hunt across IOC providers, Telegram leaks, breach databases, WHOIS, and certificate logs.
        </p>
      </div>

      <div className="mb-8">
        <div className="flex gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void doHunt()}
            placeholder="IP, domain, email, or hash..."
            className="flex-1 px-4 py-2.5 rounded-xl border border-line-2 bg-surface-100 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40"
          />
          <button
            onClick={() => void doHunt()}
            disabled={hunting || query.length < 3}
            className="px-5 py-2.5 rounded-xl bg-brand-600 text-on-fill text-sm font-semibold hover:bg-brand-700 disabled:opacity-50 transition-colors inline-flex items-center gap-2"
          >
            {hunting ? (
              <>
                <Loader2 size={14} className="animate-spin" /> Hunting...
              </>
            ) : (
              'Hunt'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 rounded-xl border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/30 p-4">
          <p className="text-sm font-mono text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      {result && comp && (
        <div className="animate-fade-in-up space-y-6">
          {/* Verdict banner */}
          <div className={`rounded-xl border p-5 ${VERDICT_COLORS[comp.verdict]}`}>
            <div className="flex items-center gap-4 mb-3">
              <span className="text-xs font-mono px-2 py-1 rounded bg-surface-100/20 text-inherit uppercase">
                {result.type}
              </span>
              <code className="text-sm font-mono font-semibold">{result.q}</code>
            </div>
            <div className="flex flex-wrap gap-4">
              <div>
                <p className="text-mini font-mono opacity-70 mb-0.5">Verdict</p>
                <p className="text-xl font-bold font-display capitalize">{comp.verdict}</p>
              </div>
              <div>
                <p className="text-mini font-mono opacity-70 mb-0.5">Score</p>
                <p className="text-xl font-bold font-display">{comp.score}/100</p>
              </div>
              <div>
                <p className="text-mini font-mono opacity-70 mb-0.5">Confidence</p>
                <p className={`text-xl font-bold font-display capitalize ${CONFIDENCE_COLORS[comp.confidence]}`}>
                  {comp.confidence}
                </p>
              </div>
              {result.ioc_providers.total_checked > 0 && (
                <div>
                  <p className="text-mini font-mono opacity-70 mb-0.5">Providers</p>
                  <p className="text-xl font-bold font-display">
                    {result.ioc_providers.hits.length}/{result.ioc_providers.total_checked}
                  </p>
                </div>
              )}
            </div>
            {comp.summary.length > 0 && (
              <div className="mt-3 space-y-1">
                {comp.summary.map((s) => (
                  <p key={s} className="text-xs font-mono opacity-80 flex items-center gap-2">
                    <Activity size={10} /> {s}
                  </p>
                ))}
              </div>
            )}
          </div>

          {/* IOC Providers */}
          <Section
            icon={<Shield size={14} />}
            title="IOC Providers"
            count={result.ioc_providers.hits.length}
            subtitle={
              result.ioc_providers.total_checked > 0
                ? `${result.ioc_providers.hits.length} with signals out of ${result.ioc_providers.total_checked} checked`
                : undefined
            }
          >
            {result.ioc_providers.hits.length === 0 ? (
              <p className="text-xs font-mono text-muted py-2">
                {result.ioc_providers.total_checked > 0
                  ? `Checked ${result.ioc_providers.total_checked} providers - no threat signals found`
                  : 'No IOC provider hits'}
              </p>
            ) : (
              <div className="space-y-1">
                {result.ioc_providers.hits.map((h) => (
                  <div key={h.source} className="px-3 py-2 rounded-xl bg-surface-200/50">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-micro font-mono px-1.5 py-0.5 rounded ${PROVIDER_VERDICT_CHIP[h.verdict] ?? PROVIDER_VERDICT_CHIP.unknown}`}
                        >
                          {h.verdict}
                        </span>
                        <span className="text-xs font-mono font-medium">{h.source}</span>
                      </div>
                      <span className="text-xs font-mono text-muted">{h.score}/100</span>
                    </div>
                    {h.description && (
                      <p className="text-mini font-mono text-muted mt-1 line-clamp-2">{h.description}</p>
                    )}
                    {h.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {h.tags.slice(0, 6).map((t) => (
                          <span key={t} className="text-micro font-mono px-1 py-0.5 rounded bg-surface-300 text-muted">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* Telegram Leaks */}
          <Section icon={<AlertTriangle size={14} />} title="Telegram Leaks" count={result.telegram_leaks.count}>
            {result.telegram_leaks.hits.length === 0 ? (
              <p className="text-xs font-mono text-muted py-2">No Telegram leak mentions</p>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {result.telegram_leaks.hits.map((h) => (
                  <div key={`${h.channel}-${h.date}`} className="px-3 py-2 rounded-xl bg-surface-200/50">
                    <p className="text-mini font-mono text-brand-600 dark:text-brand-400">{h.channel}</p>
                    <p className="text-xs font-mono text-muted mt-0.5 line-clamp-2">{h.message}</p>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* Breach Data */}
          <Section icon={<FileText size={14} />} title="Breach Databases" count={result.breach_data.count}>
            {result.breach_data.hits.length === 0 ? (
              <p className="text-xs font-mono text-muted py-2">No breach records found</p>
            ) : (
              <div className="space-y-1">
                {result.breach_data.hits.map((b) => (
                  <div key={b.name} className="px-3 py-2 rounded-xl bg-surface-200/50">
                    <p className="text-xs font-mono font-medium">{b.name}</p>
                    {b.description && <p className="text-mini font-mono text-muted mt-0.5">{b.description}</p>}
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* WHOIS */}
          {result.whois && (
            <Section icon={<Globe size={14} />} title="WHOIS / RDAP" count={0}>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(result.whois).map(([k, v]) => (
                  <div key={k} className="text-xs font-mono">
                    <span className="text-muted">{k.replace(/_/g, ' ')}: </span>
                    <span className="text-heading">{String(v).slice(0, 60)}</span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Certificate Logs */}
          {result.cert_logs.count > 0 && (
            <Section icon={<FileText size={14} />} title="Certificate Transparency" count={result.cert_logs.count}>
              <div className="text-xs font-mono text-muted space-y-1">
                <p>{result.cert_logs.count} certificates found</p>
                {result.cert_logs.recent.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {result.cert_logs.recent.map((s) => (
                      <span key={s} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300">
                        {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Deep links */}
          <div className="flex flex-wrap gap-3 pt-2">
            <a
              href={`/dfir/ioc-investigate?indicator=${encodeURIComponent(result.q)}`}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-line-1 text-xs font-mono text-muted hover:border-brand-500/40 transition-colors"
            >
              <ExternalLink size={12} /> Full IOC Check (streaming)
            </a>
            <a
              href={`/dfir/breach?q=${encodeURIComponent(result.q)}`}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-line-1 text-xs font-mono text-muted hover:border-brand-500/40 transition-colors"
            >
              <ExternalLink size={12} /> Breach Deep Dive
            </a>
          </div>
        </div>
      )}

      {!result && !hunting && !error && (
        <div className="text-center py-16 text-muted">
          <Search size={32} className="mx-auto mb-3 opacity-50" />
          <p className="text-sm font-mono">Enter an IP, domain, email, or hash to start hunting</p>
        </div>
      )}
    </div>
  );
}

function Section({
  icon,
  title,
  count,
  subtitle,
  children,
}: {
  icon: JSX.Element;
  title: string;
  count: number;
  subtitle?: string;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <div className="surface-card p-4">
      <h2 className="font-display font-semibold text-sm flex items-center gap-2 mb-1">
        {icon} {title} {count > 0 && <span className="text-xs font-mono text-muted">({count})</span>}
      </h2>
      {subtitle && <p className="text-mini font-mono text-muted mb-3">{subtitle}</p>}
      <div className={subtitle ? '' : 'mt-3'}>{children}</div>
    </div>
  );
}
