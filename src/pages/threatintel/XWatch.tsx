import { logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { DataPageLayout, useInsideDataPageLayout } from '../../components/DataPageLayout';
import { XClaimsPanel } from '../../components/threatintel/XClaimsPanel';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';
import { turnstileHeaders } from '../../lib/turnstile';
import {
  RefreshCw,
  ExternalLink,
  AlertTriangle,
  Loader2,
  MessageSquare,
  Repeat,
  Heart,
  BarChart3,
  Search,
  Plus,
  X as XIcon,
  Twitter,
  Settings,
  CheckCircle2,
} from 'lucide-react';

interface TweetItem {
  id: string;
  url: string;
  text: string;
  created_at: string;
  created_at_ms: number;
  author: { screen_name: string; name: string; avatar_url?: string; verified?: boolean };
  reply_count?: number;
  retweet_count?: number;
  favorite_count?: number;
  view_count?: number;
  media: Array<{ type: 'photo' | 'video' | 'gif'; url: string }>;
  is_retweet: boolean;
  is_reply: boolean;
  is_quote: boolean;
  is_pinned: boolean;
}

interface FirehoseResponse {
  handle: string;
  display_name: string;
  bio?: string;
  followers_count?: number;
  items: TweetItem[];
  generated_at: string;
  cached: boolean;
  stale?: boolean;
  upstream_error?: string;
  degraded?: boolean;
  fallback?: string;
  authed_error?: string;
}

interface StatusResponse {
  ok: boolean;
  configured: boolean;
  reason?: string;
  setup?: string[];
}

interface HandleSection {
  id: string;
  label: string;
  handles: string[];
}

const SECTIONS: HandleSection[] = [
  {
    id: 'researchers',
    label: 'Independent researchers',
    handles: [
      'vxunderground',
      'malwrhunterteam',
      'BushidoToken',
      'cyberknow20',
      '_JohnHammond',
      'SecureChap',
      'DeepTechTR',
      'ctrlaltintel',
      'co11ateral',
      'phatomcandle',
      'HakaiOffsec',
      'ptdbugs',
      '0x534c',
      'Sox0j',
      'Cypher1984',
      'blueteamsec1',
      'blackorbird',
    ],
  },
  {
    id: 'cti-feeds',
    label: 'CTI / breach feeds',
    handles: [
      'DailyDarkWeb',
      'DarkWebInformer',
      'FalconFeedsio',
      'MonThreat',
      'VivekIntel',
      'DarkForumss',
      'VulnCheckAI',
      'ransomnews',
      'LeakRadario',
      'IBreaches',
      'etugenio',
      'drb_ra',
      '3xp0rtblog',
      'alphahunt_io',
      'CTI__Updates',
      'spchainattack',
    ],
  },
  {
    id: 'vendors',
    label: 'Vendor labs',
    handles: [
      'TalosSecurity',
      'Mandiant',
      'Unit42_Intel',
      'CrowdStrike',
      'SentinelOne',
      'huntresslabs',
      'MsftSecIntel',
      'Netlas_io',
      'fofabot',
      '_CPResearch_',
      'ThreatrayLabs',
      'ReliaQuestTR',
      'SlowMist_Team',
      'Kb4Threatlabs',
      'DFRLab',
      'modat_magnify',
      'stealthmole_int',
      'whiteintel_io',
      'AikidoSecurity',
      'cloudsa',
      'SpiderLabs',
    ],
  },
  {
    id: 'osint',
    label: 'OSINT',
    handles: [
      'osintspectator',
      'sector035',
      'bellingcat',
      'osintdojo',
      'nixintel',
      'Cyber_O51NT',
      'weezerOSINT',
      'OsintJobs',
      'cyb_detective',
      'Cyber_Sudo',
    ],
  },
  {
    id: 'ir-dfir',
    label: 'IR / DFIR',
    handles: ['TheDFIRReport', 'AnyRun_app', 'DFIR_Radar', 'inversecos'],
  },
  {
    id: 'news',
    label: 'News',
    handles: ['briankrebs', 'BleepinComputer', 'SecurityWeek', 'TheRegister', 'thehackersnews'],
  },
];

const DEFAULT_HANDLE = SECTIONS[0]!.handles[0]!;
const STORAGE_KEY_CUSTOM = 'x-watch.custom-handles';
const STORAGE_KEY_LAST = 'x-watch.last-handle';
const HANDLE_RE = /^[A-Za-z0-9_]{1,15}$/;

function loadCustomHandles(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_CUSTOM);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((h): h is string => typeof h === 'string' && HANDLE_RE.test(h));
  } catch (_catchErr) {
    logCatch(_catchErr, 'XWatch/loadCustomHandles');
    return [];
  }
}

function formatTimeAgo(iso: string | number): string {
  const t = typeof iso === 'number' ? iso : Date.parse(iso);
  if (!Number.isFinite(t) || t === 0) return '';
  const diff = Math.max(0, Date.now() - t);
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function compactNumber(n?: number): string {
  if (!n || n < 1) return '';
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export default function XWatch(): JSX.Element {
  const insideLayout = useInsideDataPageLayout();
  const [active, setActive] = useState<string>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY_LAST) ?? DEFAULT_HANDLE;
    } catch (_catchErr) {
      logCatch(_catchErr, 'XWatch');
      return DEFAULT_HANDLE;
    }
  });
  const [customHandles, setCustomHandles] = useState<string[]>(() => loadCustomHandles());
  const [addInput, setAddInput] = useState('');
  const [filter, setFilter] = useState('');
  const [sinceDays, setSinceDays] = useState<number>(() => {
    try {
      return Number(localStorage.getItem('x-watch.since-days') ?? '7') || 7;
    } catch (_catchErr) {
      logCatch(_catchErr, 'XWatch');
      return 7;
    }
  });
  const [includeReplies, setIncludeReplies] = useState<boolean>(() => {
    try {
      return localStorage.getItem('x-watch.include-replies') === '1';
    } catch (_catchErr) {
      logCatch(_catchErr, 'XWatch');
      return false;
    }
  });
  const [includePinned, setIncludePinned] = useState<boolean>(() => {
    try {
      return localStorage.getItem('x-watch.include-pinned') === '1';
    } catch (_catchErr) {
      logCatch(_catchErr, 'XWatch');
      return false;
    }
  });
  const [data, setData] = useState<FirehoseResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authStatus, setAuthStatus] = useState<StatusResponse | null>(null);
  /** Per-handle "items in current window" count. undefined = not probed
   *  yet; 0 = probed and confirmed inactive (hidden from default lists). */
  const [activity, setActivity] = useState<Record<string, number | undefined>>({});
  const [showInactive, setShowInactive] = useState(false);
  const [probing, setProbing] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY_LAST, active);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* localStorage unavailable */
    }
  }, [active]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY_CUSTOM, JSON.stringify(customHandles));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* localStorage unavailable */
    }
  }, [customHandles]);

  useEffect(() => {
    try {
      localStorage.setItem('x-watch.since-days', String(sinceDays));
      localStorage.setItem('x-watch.include-replies', includeReplies ? '1' : '0');
      localStorage.setItem('x-watch.include-pinned', includePinned ? '1' : '0');
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* localStorage unavailable */
    }
  }, [sinceDays, includeReplies, includePinned]);

  // One-time auth status probe on mount.
  useEffect(() => {
    fetch('/api/v1/x-firehose?status')
      .then((r) => r.json())
      .then((s: StatusResponse) => setAuthStatus(s))
      .catch(() => setAuthStatus({ ok: false, configured: false }));
  }, []);

  const load = (handle: string) => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    setData(null);
    const qs = new URLSearchParams({
      handle,
      count: '40',
      since_days: String(sinceDays),
      include_replies: includeReplies ? '1' : '0',
      include_pinned: includePinned ? '1' : '0',
    });
    fetch(`/api/v1/x-firehose?${qs.toString()}`, {
      signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
    })
      .then(async (r) => {
        const body = (await r.json()) as
          FirehoseResponse | { error: string; hint?: string; status?: number; code?: string; detail?: string };
        if (cancelled) return;
        if (!r.ok || 'error' in body) {
          // Surface the specific upstream cause so the operator knows whether
          // to refresh cookies, update query IDs, or just retry - instead of
          // a single opaque "could not load tweets".
          const b = body as { error?: string; code?: string; detail?: string };
          if (r.status === 429) setError('rate-limited - try again in a moment');
          else if (b.code === 'stale_qid')
            setError('X query IDs look stale - refresh them in api/src/lib/twitter-auth-graphql.ts');
          else if (b.code === 'auth_expired') setError('X cookies expired - refresh them in admin > X Cookies');
          else if (b.code === 'auth_missing') setError('X cookies not configured - add them in admin > X Cookies');
          else if (r.status === 503 || r.status === 401) setError('service unavailable');
          else setError(b.detail ? `could not load tweets: ${b.detail}` : 'could not load tweets');
          // 503/401 → service unavailable - show the soft banner.
          if (r.status === 503 || r.status === 401) {
            setAuthStatus({ ok: false, configured: false });
          }
        } else {
          setData(body);
          // Keep the activity map in sync so the pill counter matches
          // what the user sees in the active panel.
          setActivity((prev) => ({ ...prev, [handle]: body.items.length }));
        }
      })
      .catch((e) => !cancelled && (e as { name?: string }).name !== 'AbortError' && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  };

  useEffect(() => {
    // Only auto-load when service is up. Save the user a wasted request
    // when we already know auth is down.
    if (authStatus && !authStatus.configured) return;
    return load(active);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, sinceDays, includeReplies, includePinned, authStatus?.configured]);

  // Probe every handle on mount + whenever the window/auth changes so
  // inactive handles can be hidden by default. Uses the server-side
  // batch endpoint which staggers upstream X calls to avoid rate limits.
  useEffect(() => {
    if (authStatus && !authStatus.configured) return;
    const allHandles = Array.from(new Set([...SECTIONS.flatMap((s) => s.handles), ...customHandles]));
    let cancelled = false;
    const ctrl = new AbortController();
    setProbing(true);
    setActivity((prev) => {
      const next: Record<string, number | undefined> = {};
      for (const h of allHandles) next[h] = h === active ? prev[h] : undefined;
      return next;
    });

    const CHUNK = 40;
    const chunks: string[][] = [];
    for (let i = 0; i < allHandles.length; i += CHUNK) chunks.push(allHandles.slice(i, i + CHUNK));

    (async () => {
      const merged: Record<string, number | undefined> = {};
      for (const chunk of chunks) {
        if (cancelled) return;
        try {
          const r = await fetch('/api/v1/x-firehose/probe-batch', {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...(await turnstileHeaders('x-probe-batch')) },
            body: JSON.stringify({ handles: chunk, since_days: sinceDays }),
            signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(120_000)]),
          });
          if (!r.ok) continue;
          const body = (await r.json()) as {
            results: Record<string, { count: number; status: string }>;
          };
          for (const [h, v] of Object.entries(body.results)) {
            if (v.status === 'ok') merged[h] = v.count;
            else if (v.status === 'not_found') merged[h] = 0;
            // rate_limited / error → leave undefined (unknown, not inactive)
          }
        } catch {
          /* network error - leave handles as unknown */
        }
      }
      if (cancelled) return;
      setActivity((prev) => ({ ...prev, ...merged }));
      setProbing(false);
    })();

    return () => {
      cancelled = true;
      ctrl.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sinceDays, includeReplies, authStatus?.configured]);

  const isInactive = (h: string): boolean => activity[h] === 0;

  const addHandle = () => {
    const h = addInput.trim().replace(/^@/, '');
    if (!HANDLE_RE.test(h)) {
      setError(`invalid handle: "${h}" (1-15 chars, A-Z 0-9 _)`);
      return;
    }
    setCustomHandles((prev) => (prev.includes(h) ? prev : [...prev, h]));
    setAddInput('');
    setActive(h);
  };

  const removeCustom = (h: string) => {
    setCustomHandles((prev) => prev.filter((x) => x !== h));
    if (active === h) setActive(DEFAULT_HANDLE);
  };

  const filteredTweets = useMemo(() => {
    if (!data) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return data.items;
    return data.items.filter((t) => t.text.toLowerCase().includes(q));
  }, [data, filter]);

  const postSummaries = usePostSummaries({
    surface: 'X Watch Cybersec',
    items: filteredTweets.map((t) => ({
      id: t.id,
      title: t.text.slice(0, 120),
      body: t.text,
      source: t.author?.name ?? '',
    })),
  });

  return (
    <DataPageLayout
      backTo="/threatintel"
      hideBack={insideLayout}
      icon={<Twitter size={28} />}
      title="X firehose"
      description='Live chronological tweets from cybersec accounts. Filter by handle, time window, replies, and pinned. Inactive handles (no posts within the selected window) are hidden by default - click "+N inactive" in each section to surface them.'
      headerExtra={
        authStatus?.configured ? (
          <span className="text-micro font-mono px-1.5 py-0.5 rounded border bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
            live
          </span>
        ) : undefined
      }
    >
      {authStatus?.configured && <XClaimsPanel />}

      {authStatus && !authStatus.configured && (
        <section className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50/60 dark:bg-amber-950/40 p-5 mb-6">
          <div className="flex items-start gap-2">
            <Settings size={16} className="text-amber-700 dark:text-amber-300 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-display font-bold text-base text-amber-900 dark:text-amber-200">
                Service temporarily unavailable
              </h2>
              <p className="text-xs font-mono text-amber-800 dark:text-amber-300 mt-1">
                The live X feed is offline right now. Try the{' '}
                <Link to="/threatintel/social/firehose" className="underline">
                  cybersec X firehose
                </Link>{' '}
                or the{' '}
                <Link to="/threatintel/social/firehose" className="underline">
                  Bluesky / Mastodon firehose
                </Link>{' '}
                while it recovers.
              </p>
            </div>
          </div>
        </section>
      )}

      <div className="space-y-4 mb-6">
        {SECTIONS.map((sec) => {
          const inactive = sec.handles.filter((h) => isInactive(h) && active !== h);
          const visible = showInactive ? sec.handles : sec.handles.filter((h) => !isInactive(h) || active === h);
          if (visible.length === 0 && inactive.length === 0) return null;
          return (
            <div key={sec.id}>
              <h3 className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">
                {sec.label}
                <span className="opacity-60 ml-1.5">
                  · {sec.handles.length - inactive.length}/{sec.handles.length} active
                </span>
                {probing && <Loader2 size={9} className="inline ml-1 animate-spin text-muted" aria-label="probing" />}
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {visible.map((h) => {
                  const count = activity[h];
                  const dim = isInactive(h);
                  return (
                    <button
                      key={h}
                      type="button"
                      onClick={() => setActive(h)}
                      className={`text-xs font-mono px-2 py-1 rounded border transition-colors inline-flex items-center gap-1 ${
                        active === h
                          ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                          : dim
                            ? 'border-slate-300/40 dark:border-line-1/40 text-slate-500 opacity-50'
                            : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
                      }`}
                      title={
                        count !== undefined
                          ? `${count} fresh tweet${count !== 1 ? 's' : ''} in last ${sinceDays}d`
                          : 'probing…'
                      }
                    >
                      @{h}
                      {count !== undefined && count > 0 && (
                        <span className="text-micro text-emerald-600 dark:text-emerald-400">·{count}</span>
                      )}
                    </button>
                  );
                })}
                {!showInactive && inactive.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setShowInactive(true)}
                    className="text-micro font-mono px-1.5 py-1 rounded border border-dashed border-line-2 text-muted hover:text-muted dark:hover:text-inverted"
                    title={`Hidden - no posts in last ${sinceDays}d: ${inactive.map((h) => '@' + h).join(', ')}`}
                  >
                    +{inactive.length} inactive
                  </button>
                )}
              </div>
            </div>
          );
        })}
        {showInactive && (
          <button
            type="button"
            onClick={() => setShowInactive(false)}
            className="text-micro font-mono px-2 py-0.5 rounded border border-dashed border-line-2 text-muted hover:text-muted dark:hover:text-inverted"
          >
            hide inactive again
          </button>
        )}
        {customHandles.length > 0 && (
          <div>
            <h3 className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">Your watchlist</h3>
            <div className="flex flex-wrap gap-1.5">
              {customHandles.map((h) => (
                <span
                  key={h}
                  className={`inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded border transition-colors ${
                    active === h
                      ? 'border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300'
                      : 'border-slate-300 dark:border-line-1 text-muted hover:border-rose-500/40'
                  }`}
                >
                  <button type="button" onClick={() => setActive(h)}>
                    @{h}
                  </button>
                  <button
                    type="button"
                    onClick={() => removeCustom(h)}
                    className="text-muted hover:text-rose-600"
                    title="remove from watchlist"
                    aria-label={`Remove @${h} from watchlist`}
                  >
                    <XIcon size={10} />
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 flex-1 min-w-[200px]">
            <span className="text-muted">@</span>
            <input
              type="text"
              value={addInput}
              onChange={(e) => setAddInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addHandle()}
              placeholder="add custom handle…"
              className="flex-1 px-2 py-1 rounded border border-line-2 bg-surface-100 text-sm font-mono focus:outline-none focus:border-rose-500"
            />
          </div>
          <button
            type="button"
            onClick={addHandle}
            disabled={!addInput.trim()}
            className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 disabled:opacity-40 transition-colors"
          >
            <Plus size={11} /> add
          </button>
          <label className="inline-flex items-center gap-1 text-mini font-mono text-muted">
            window:
            <select
              value={sinceDays}
              onChange={(e) => setSinceDays(Number(e.target.value))}
              className="border border-line-2 bg-surface-100 px-1.5 py-0.5 text-mini font-mono rounded focus:outline-none focus:border-rose-500"
            >
              {[1, 3, 7, 14, 30].map((d) => (
                <option key={d} value={d}>
                  {d}d
                </option>
              ))}
            </select>
          </label>
          <label className="inline-flex items-center gap-1 text-mini font-mono text-muted cursor-pointer">
            <input
              type="checkbox"
              checked={includeReplies}
              onChange={(e) => setIncludeReplies(e.target.checked)}
              className="rounded border-line-3"
            />
            replies
          </label>
          <label className="inline-flex items-center gap-1 text-mini font-mono text-muted cursor-pointer">
            <input
              type="checkbox"
              checked={includePinned}
              onChange={(e) => setIncludePinned(e.target.checked)}
              className="rounded border-line-3"
            />
            pinned
          </label>
          <button
            type="button"
            onClick={() => load(active)}
            disabled={loading || (authStatus && !authStatus.configured) === true}
            className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 disabled:opacity-50"
          >
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> refresh
          </button>
        </div>
      </div>

      <div className="surface-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
          <div>
            <h2 className="text-xl font-display font-bold inline-flex items-center gap-2">
              @{active}
              {data?.display_name && data.display_name !== active && (
                <span className="text-sm font-mono text-muted">· {data.display_name}</span>
              )}
            </h2>
            {data?.bio && <p className="text-meta font-mono text-muted mt-0.5 max-w-2xl">{data.bio}</p>}
            <div className="flex items-center gap-2 text-micro font-mono mt-1 flex-wrap">
              {data?.followers_count !== undefined && (
                <span className="text-muted">{compactNumber(data.followers_count)} followers</span>
              )}
              {data?.cached && (
                <span className="text-amber-600 dark:text-amber-400">
                  <CheckCircle2 size={9} className="inline" /> cached
                </span>
              )}
              {data?.stale && (
                <span className="text-amber-700 dark:text-amber-300" title={data.upstream_error}>
                  <AlertTriangle size={9} className="inline" /> stale
                </span>
              )}
              {data?.degraded && (
                <span
                  className="text-amber-700 dark:text-amber-300"
                  title={`Authenticated feed unavailable (${data.authed_error ?? 'upstream'}) - showing the anonymous curated timeline`}
                >
                  <AlertTriangle size={9} className="inline" /> anonymous fallback
                </span>
              )}
              <a
                href={`https://x.com/${active}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-0.5 transition-colors"
              >
                open on x.com <ExternalLink size={9} />
              </a>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="search"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="filter tweets…"
                className="pl-7 pr-2 py-1 rounded border border-line-2 bg-surface-200 text-xs font-mono focus:outline-none focus:border-rose-500"
              />
            </div>
          </div>
        </div>

        {error && (
          <div className="rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950 p-3 text-xs font-mono text-rose-700 dark:text-rose-300 mb-3 inline-flex items-start gap-2">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" /> {error}
          </div>
        )}

        {loading && !data && (
          <p className="text-xs font-mono text-muted inline-flex items-center gap-1">
            <Loader2 size={11} className="animate-spin" /> fetching authenticated timeline for @{active}…
          </p>
        )}

        {!loading && data && filteredTweets.length === 0 && (
          <div className="text-xs font-mono text-muted rounded border border-dashed border-line-2 p-4 text-center">
            {data.items.length === 0 ? (
              <>
                No tweets within the last <span className="text-body">{sinceDays}d</span> for{' '}
                <span className="text-body">@{active}</span>.
                {!includeReplies && (
                  <>
                    {' '}
                    <button
                      type="button"
                      onClick={() => setIncludeReplies(true)}
                      className="text-rose-600 dark:text-rose-400 hover:underline"
                    >
                      Include replies
                    </button>{' '}
                    or{' '}
                  </>
                )}
                <button
                  type="button"
                  onClick={() => setSinceDays(30)}
                  className="text-rose-600 dark:text-rose-400 hover:underline"
                >
                  widen window
                </button>
                .
              </>
            ) : (
              <>No tweets match the search filter.</>
            )}
          </div>
        )}

        {filteredTweets.length > 0 && (
          <>
            <PostAnalysisButton
              title="X Watch Cybersec Digest"
              description="AI-powered threat analysis of the current feed."
              source="xwatch"
            />
            <AiSummaryCard
              surface="X Watch Cybersec"
              items={filteredTweets.slice(0, 30).map((t) => ({
                title: t.text.slice(0, 120),
                body: t.text,
                source: t.author?.name ?? '',
              }))}
              requireAdmin={false}
            />
            <ul className="space-y-2">
              {filteredTweets.map((t) => (
                <li key={t.id} className="rounded-xl border border-line-1 bg-surface-200 p-3">
                  <div className="flex items-start gap-3">
                    {t.author.avatar_url && (
                      <img
                        loading="lazy"
                        src={t.author.avatar_url}
                        alt={t.author.name}
                        className="w-9 h-9 rounded-full shrink-0"
                      />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline gap-2 mb-1">
                        <span className="font-display font-semibold text-sm text-heading">{t.author.name}</span>
                        <span className="text-mini font-mono text-muted">@{t.author.screen_name}</span>
                        {t.is_pinned && (
                          <span className="text-micro font-mono px-1 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300">
                            pinned
                          </span>
                        )}
                        {t.is_retweet && (
                          <span className="text-micro font-mono px-1 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                            retweet
                          </span>
                        )}
                        {t.is_quote && (
                          <span className="text-micro font-mono px-1 py-0.5 rounded border border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300">
                            quote
                          </span>
                        )}
                        {t.is_reply && (
                          <span className="text-micro font-mono px-1 py-0.5 rounded border border-line-2 text-muted">
                            reply
                          </span>
                        )}
                        <a
                          href={sanitizeUrl(t.url) || undefined}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="ml-auto text-micro font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-0.5 transition-colors"
                          title={t.created_at}
                        >
                          {formatTimeAgo(t.created_at_ms || t.created_at)} <ExternalLink size={9} />
                        </a>
                      </div>
                      <p className="text-sm text-heading whitespace-pre-wrap break-words">{t.text}</p>
                      <PostSummary text={postSummaries.get(String(t.id))} />
                      {t.media.length > 0 && (
                        <div className="mt-2 grid grid-cols-2 gap-1.5">
                          {t.media.slice(0, 4).map((m, i) => (
                            <a
                              key={`${t.id}-m-${i}`}
                              href={sanitizeUrl(t.url) || undefined}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block rounded overflow-hidden border border-line-1"
                            >
                              <img
                                src={m.url}
                                alt={m.type}
                                loading="lazy"
                                width={400}
                                height={128}
                                className="w-full h-32 object-cover"
                              />
                            </a>
                          ))}
                        </div>
                      )}
                      <div className="mt-2 flex items-center gap-3 text-micro font-mono text-muted">
                        {t.reply_count !== undefined && (
                          <span className="inline-flex items-center gap-0.5">
                            <MessageSquare size={10} /> {compactNumber(t.reply_count) || '0'}
                          </span>
                        )}
                        {t.retweet_count !== undefined && (
                          <span className="inline-flex items-center gap-0.5">
                            <Repeat size={10} /> {compactNumber(t.retweet_count) || '0'}
                          </span>
                        )}
                        {t.favorite_count !== undefined && (
                          <span className="inline-flex items-center gap-0.5">
                            <Heart size={10} /> {compactNumber(t.favorite_count) || '0'}
                          </span>
                        )}
                        {t.view_count !== undefined && t.view_count > 0 && (
                          <span className="inline-flex items-center gap-0.5">
                            <BarChart3 size={10} /> {compactNumber(t.view_count)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}

        {data && (
          <p className="mt-4 text-micro font-mono text-muted text-center">
            refreshed {formatTimeAgo(data.generated_at)}
          </p>
        )}
      </div>
    </DataPageLayout>
  );
}
