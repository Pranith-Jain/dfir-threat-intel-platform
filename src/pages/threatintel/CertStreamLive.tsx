import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Pause, Play, RefreshCw, Radio, ExternalLink, Search, ShieldAlert } from 'lucide-react';

interface CertStreamItem {
  id: number;
  common_name: string;
  dns_names: string[];
  issuer: string;
  entry_timestamp: string;
  not_before?: string;
  not_after?: string;
  crtsh_url: string;
}

interface CertStreamResponse {
  keyword: string;
  high_water: number;
  total: number;
  items: CertStreamItem[];
  generated_at: string;
  source?: string;
  upstream_error?: string;
}

const POLL_MS = 15_000;
const MAX_BUFFER = 500;
const STORAGE_KEY = 'threatintel.certstream.keyword';

// Defaults are bare apex domains so the secondary upstream (Cert Spotter)
// can serve them when crt.sh is 502'ing - that lifecycle is the most
// common analyst use case (watch certs for MY brand). Wildcard patterns
// (`%anthrop%`) still work but are crt.sh-only; the page surfaces a
// "upstream degraded" banner when crt.sh is down and a wildcard is set.
const SAMPLES: { label: string; keyword: string }[] = [
  { label: 'anthropic.com', keyword: 'anthropic.com' },
  { label: 'cloudflare.com', keyword: 'cloudflare.com' },
  { label: 'github.com', keyword: 'github.com' },
  { label: '%g1thub% (wildcard)', keyword: '%g1thub%' },
];

function suspicionScore(item: CertStreamItem, keyword: string): number {
  const kw = keyword.replace(/%/g, '').toLowerCase();
  if (!kw) return 0;
  let score = 0;
  for (const name of item.dns_names) {
    if (name === kw || name.endsWith(`.${kw}`)) continue; // legit
    if (name.includes(kw)) score += 1;
    if (/[0-9]/.test(name.replace(kw, ''))) score += 1;
    if (/-(login|secure|verify|update|account|auth)\b/.test(name)) score += 2;
    if (/(xn--|punycode)/.test(name)) score += 2;
  }
  if (item.issuer.toLowerCase().includes("let's encrypt")) score += 1;
  return score;
}

function formatTimeAgo(iso: string): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Math.max(0, Date.now() - t);
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function CertStreamLive(): JSX.Element {
  const [keyword, setKeyword] = useState(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) ?? '';
    } catch (_catchErr) {
      console.error('CertStreamLive failed:', errMessage(_catchErr));
      return '';
    }
  });
  const [streaming, setStreaming] = useState(false);
  const [items, setItems] = useState<CertStreamItem[]>([]);
  const [highWater, setHighWater] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastPoll, setLastPoll] = useState<string | null>(null);
  const [upstreamDegraded, setUpstreamDegraded] = useState<string | null>(null);
  const [showOnlySuspicious, setShowOnlySuspicious] = useState(false);
  const watermarkRef = useRef(0);

  const poll = useCallback(async (kw: string) => {
    if (!kw.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(
        `/api/v1/certstream?keyword=${encodeURIComponent(kw.trim())}&since=${watermarkRef.current}`
      );
      const data = (await r.json()) as CertStreamResponse | { error: string };
      if (!r.ok || 'error' in data) {
        setError('error' in data ? data.error : `HTTP ${r.status}`);
        return;
      }
      // API now returns 200 with `upstream_error` when serving stale.
      // Surface a soft banner instead of taking the stream down.
      setUpstreamDegraded(data.upstream_error ?? null);
      if (data.items.length > 0) {
        setItems((prev) => {
          const merged = [...data.items, ...prev];
          const seen = new Set<number>();
          return merged
            .filter((it) => {
              if (seen.has(it.id)) return false;
              seen.add(it.id);
              return true;
            })
            .slice(0, MAX_BUFFER);
        });
        watermarkRef.current = Math.max(watermarkRef.current, data.high_water);
        setHighWater(watermarkRef.current);
      }
      setLastPoll(data.generated_at);
    } catch (e) {
      logCatch(e);
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!streaming) return;
    void poll(keyword);
    const t = window.setInterval(() => {
      if (document.visibilityState !== 'visible') return; // don't poll a hidden/background tab
      void poll(keyword);
    }, POLL_MS);
    // Catch up immediately when the tab returns to the foreground.
    const onVisible = () => {
      if (document.visibilityState === 'visible') void poll(keyword);
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.clearInterval(t);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [streaming, keyword, poll]);

  // Reset buffered certs + watermark when the keyword changes mid-stream, so
  // the new keyword's results aren't mixed with (or skipped behind) the old.
  const prevKeywordRef = useRef(keyword);
  useEffect(() => {
    if (prevKeywordRef.current === keyword) return;
    prevKeywordRef.current = keyword;
    if (streaming) {
      setItems([]);
      watermarkRef.current = 0;
      setHighWater(0);
    }
  }, [keyword, streaming]);

  const start = () => {
    if (!keyword.trim()) return;
    try {
      localStorage.setItem(STORAGE_KEY, keyword.trim());
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* localStorage unavailable - fine, just won't persist */
    }
    setItems([]);
    watermarkRef.current = 0;
    setHighWater(0);
    setStreaming(true);
  };

  const displayItems = showOnlySuspicious ? items.filter((it) => suspicionScore(it, keyword) >= 2) : items;

  const headerExtra = (
    <section className="surface-card p-5">
      <div className="mb-3">
        <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
          live
        </span>
      </div>
      <label htmlFor="cs-keyword" className="block text-xs font-mono uppercase tracking-wider text-muted mb-1.5">
        Watch keyword
      </label>
      <div className="flex flex-col sm:flex-row gap-2">
        <input
          id="cs-keyword"
          type="text"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          disabled={streaming}
          placeholder="e.g. %anthrop%   (use % as wildcard)"
          className="flex-1 rounded border border-line-2 bg-surface-200 px-3 py-2 text-sm font-mono focus:border-rose-500 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !streaming) start();
          }}
        />
        {streaming ? (
          <button
            type="button"
            onClick={() => setStreaming(false)}
            className="inline-flex items-center justify-center gap-1.5 rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950 px-3 py-2 text-xs font-mono font-semibold text-rose-600 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-900"
          >
            <Pause size={12} /> Stop
          </button>
        ) : (
          <button
            type="button"
            onClick={start}
            disabled={!keyword.trim()}
            className="inline-flex items-center justify-center gap-1.5 rounded bg-rose-600 px-3 py-2 text-xs font-mono font-semibold text-on-fill hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Play size={12} /> Start stream
          </button>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="text-micro font-mono uppercase tracking-wider text-muted">samples:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.label}
            type="button"
            onClick={() => setKeyword(s.keyword)}
            className="text-mini font-mono rounded border border-line-2 px-2 py-0.5 text-muted hover:text-rose-600 dark:hover:text-rose-400 hover:border-rose-500/40"
          >
            {s.label}
          </button>
        ))}
      </div>
    </section>
  );

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Radio size={28} />}
      title="CertStream - live CT log"
      description="Live Certificate Transparency feed filtered by a keyword. Polls crt.sh every 15s and tickers in newly-issued certificates matching your watch term. Use %substring% for fuzzy lookalikes (typosquats, homographs, brand impersonations) or a bare term for an exact apex match."
      headerExtra={headerExtra}
    >
      {error && (
        <div className="rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950 p-3 text-xs font-mono text-rose-700 dark:text-rose-300 mb-4">
          {error}
          {error.includes('crt.sh') && (
            <div className="mt-1 text-rose-600/80 dark:text-rose-400/80">
              crt.sh's public nginx 502s under load. The stream will resume automatically when upstream recovers
              (usually within 30–60s).
            </div>
          )}
        </div>
      )}
      {upstreamDegraded && !error && (
        <div className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950 p-3 text-xs font-mono text-amber-700 dark:text-amber-300 mb-4">
          <span className="font-bold">crt.sh degraded</span>
          {keyword.includes('%') ? (
            <>
              {' '}
              - wildcard patterns can only be served by crt.sh, which is currently returning 502.
              <span className="block mt-1 text-amber-800/80 dark:text-amber-300/80">
                For a bare apex domain (e.g. <code className="font-mono">anthropic.com</code>), the page auto-falls-back
                to Cert Spotter - try a non-wildcard keyword to keep the stream live.
              </span>
            </>
          ) : (
            <> - falling back to Cert Spotter. ({upstreamDegraded})</>
          )}
        </div>
      )}

      {streaming && (
        <div className="surface-card p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <div className="text-xs font-mono text-muted">
              {loading ? (
                <span className="inline-flex items-center gap-1">
                  <RefreshCw size={11} className="animate-spin" /> polling crt.sh…
                </span>
              ) : (
                <>
                  <span className="text-body font-semibold">{items.length}</span> certs buffered · high-water id{' '}
                  <code>{highWater || '-'}</code>
                  {lastPoll && <> · last poll {formatTimeAgo(lastPoll)}</>}
                </>
              )}
            </div>
            <label className="inline-flex items-center gap-1.5 text-mini font-mono text-muted select-none cursor-pointer">
              <input
                type="checkbox"
                checked={showOnlySuspicious}
                onChange={(e) => setShowOnlySuspicious(e.target.checked)}
                className="rounded border-line-3"
              />
              Only suspicious (≥2 signal)
            </label>
          </div>

          {displayItems.length === 0 ? (
            <p className="text-center text-xs font-mono text-muted py-6">
              {items.length === 0
                ? 'Waiting for first batch… crt.sh re-indexes every 30-60s.'
                : 'No items match the current filter.'}
            </p>
          ) : (
            <ul className="space-y-2 max-h-[60vh] overflow-y-auto pr-1">
              {displayItems.map((it) => {
                const score = suspicionScore(it, keyword);
                const sus = score >= 2;
                return (
                  <li
                    key={it.id}
                    className={`rounded-xl border p-3 transition-colors ${
                      sus
                        ? 'border-rose-300 dark:border-rose-800 bg-rose-50/60 dark:bg-rose-950/40'
                        : 'border-line-1 bg-slate-50 dark:bg-input-200'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                          {sus && (
                            <span
                              title={`suspicion score ${score}`}
                              className="inline-flex items-center gap-0.5 text-micro font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30"
                            >
                              <ShieldAlert size={9} /> sus·{score}
                            </span>
                          )}
                          <code className="text-sm font-mono text-heading truncate">
                            {it.common_name || it.dns_names[0] || '(no CN)'}
                          </code>
                        </div>
                        {it.dns_names.length > 1 && (
                          <div className="text-micro font-mono text-muted truncate">
                            + {it.dns_names.length - 1} SAN{it.dns_names.length - 1 !== 1 ? 's' : ''}:{' '}
                            {it.dns_names.slice(1, 4).join(', ')}
                            {it.dns_names.length > 4 ? '…' : ''}
                          </div>
                        )}
                      </div>
                      <a
                        href={it.crtsh_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                        title="Open on crt.sh"
                      >
                        <ExternalLink size={12} />
                      </a>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-micro font-mono text-muted mt-1">
                      <span>issuer: {it.issuer}</span>
                      {it.entry_timestamp && <span>logged {formatTimeAgo(it.entry_timestamp)}</span>}
                      <Link
                        to={`/dfir/cert-search?domain=${encodeURIComponent(
                          (it.common_name || it.dns_names[0] || '').replace(/^\*\./, '')
                        )}`}
                        className="text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-0.5"
                      >
                        <Search size={9} /> investigate
                      </Link>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {!streaming && (
        <div className="rounded-xl border border-dashed border-line-2 bg-surface-200/60 dark:bg-input-200/40 p-8 text-center">
          <Radio size={28} className="mx-auto text-muted mb-2" />
          <p className="text-sm font-mono text-muted">
            Enter a keyword and press <span className="text-rose-600 dark:text-rose-400">Start stream</span> to begin
            polling.
          </p>
          <p className="text-mini font-mono text-muted mt-2">
            Tip: brand-name fuzzy patterns (e.g. <code>%g1thub%</code>) surface lookalike issuances within minutes of
            certificate creation.
          </p>
        </div>
      )}
    </DataPageLayout>
  );
}
