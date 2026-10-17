import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import {
  Brain,
  ExternalLink,
  RefreshCw,
  Radio,
  Loader2,
  Search,
  AlertTriangle,
  CheckCircle2,
  BarChart3,
  Shield,
} from 'lucide-react';
import {
  fetchAggregatedFeed,
  formatRelativeTime,
  type AggregatedFeedItem,
  type AggregatedFeedSourceStatus,
} from '../../services/rssService';
import {
  landingThreatGovernment,
  landingThreatIndia,
  landingThreatVendor,
  landingThreatInvestigation,
  landingThreatReddit,
  landingThreatVulns,
  landingThreatNews,
  rssFeeds,
} from '../../data/rssFeeds';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { FeedSummaryPanel } from '../../components/threatintel/FeedSummaryPanel';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';

/**
 * Threat Feeds - sectioned aggregator for the threat-intelligence half of
 * "what's happening." Industry / AI / general-tech content lives in
 * /threatintel/tech-ai-news; scam-watch content lives in /threatintel/scam-watch.
 */

interface Section {
  id: string;
  label: string;
  blurb: string;
  feedIds: string[];
}

const SECTIONS: Section[] = [
  {
    id: 'gov',
    label: 'Government advisories',
    blurb: 'CISA alerts, medical-device advisories, ICS-CERT - authoritative US-government feeds.',
    feedIds: landingThreatGovernment,
  },
  {
    id: 'india',
    label: 'India',
    blurb: 'India-scoped cyber-attacks, data breaches, ransomware, and CERT-In advisory coverage.',
    feedIds: landingThreatIndia,
  },
  {
    id: 'vendor',
    label: 'Vendor research',
    blurb: 'Threat-research labs publishing IOCs, malware analysis, and active-campaign trackers.',
    feedIds: landingThreatVendor,
  },
  {
    id: 'investigation',
    label: 'Investigation & dark web',
    blurb: 'Long-form IR write-ups, leak-site posts, breach disclosures, MITRE ATT&CK research.',
    feedIds: landingThreatInvestigation,
  },
  {
    id: 'reddit',
    label: 'Reddit infosec',
    blurb: 'r/netsec, r/Malware, r/blueteamsec, r/threatintel - community-curated threat content.',
    feedIds: landingThreatReddit,
  },
  {
    id: 'vulns',
    label: 'Vulnerabilities',
    blurb: 'CVE Details and Exploit-DB - fresh disclosures and proof-of-concept code.',
    feedIds: landingThreatVulns,
  },
  {
    id: 'news',
    label: 'Security news',
    blurb: 'Independent press - Krebs, Bleeping, SecurityWeek, Schneier, The Register, Wired Security.',
    feedIds: landingThreatNews,
  },
];

const ALL_FEED_IDS = SECTIONS.flatMap((s) => s.feedIds);

const SECTION_LABELS: Record<string, string> = Object.fromEntries(SECTIONS.map((s) => [s.id, s.label]));

const SECTION_STYLES: Record<string, string> = {
  gov: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  vendor: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  investigation: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  reddit: 'border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  vulns: 'border-cyan-500/30 bg-cyan-500/10 text-sky-700 dark:text-sky-300',
  news: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300',
};

const DISABLED_STORAGE_KEY = 'feed:sources:disabled';

function loadDisabled(): Set<string> {
  try {
    const raw = localStorage.getItem(DISABLED_STORAGE_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch (_catchErr) {
    console.error('loadDisabled failed:', errMessage(_catchErr));
    return new Set();
  }
}

export default function ThreatFeeds(): JSX.Element {
  const [items, setItems] = useState<AggregatedFeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [feedsReturned, setFeedsReturned] = useState(0);
  const [feedStatuses, setFeedStatuses] = useState<AggregatedFeedSourceStatus[]>([]);
  const [disabled, setDisabled] = useState<Set<string>>(() => loadDisabled());
  const [showSourcePanel, setShowSourcePanel] = useState(false);
  const [showDigest, setShowDigest] = useState(false);
  const [topAnalysis, setTopAnalysis] = useState<{
    summary: string;
    threat_level: string;
    confidence: string;
    impact: string;
    recommended_actions: string[];
    related_ttps?: string[];
    iocs?: string[];
    raw?: string;
  } | null>(null);
  const [topAnalysisLoading, setTopAnalysisLoading] = useState(false);
  const [topAnalysisError, setTopAnalysisError] = useState<string | null>(null);
  const [topAnalysisExpanded, setTopAnalysisExpanded] = useState(true);
  const [topAnalysisModel, setTopAnalysisModel] = useState<string | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(DISABLED_STORAGE_KEY, JSON.stringify([...disabled]));
    } catch (_catchErr) {
      console.error('ThreatFeeds failed:', errMessage(_catchErr));
      /* localStorage unavailable */
    }
  }, [disabled]);

  // Only request the feeds the user has enabled. Re-runs when the toggle set
  // changes so re-enabling a feed pulls it without a manual refresh click.
  const enabledFeedIds = useMemo(() => ALL_FEED_IDS.filter((id) => !disabled.has(id)), [disabled]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setItems([]);
    try {
      const data = await fetchAggregatedFeed(enabledFeedIds, { limit: 300, perSource: 12 });
      if (!data) throw new Error('no aggregator-eligible feeds configured');
      setItems(data.items);
      setFeedsReturned(data.feeds_returned);
      setFeedStatuses(data.feeds ?? []);
    } catch (e) {
      logCatch(e);
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [enabledFeedIds]);

  useEffect(() => {
    void load();
  }, [load]);

  const urlToSection = useMemo(() => {
    const map = new Map<string, string>();
    for (const sec of SECTIONS) {
      for (const fid of sec.feedIds) {
        const url = rssFeeds.find((r) => r.id === fid)?.url;
        if (url) map.set(url, sec.id);
      }
    }
    return map;
  }, []);

  const annotated = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items
      .map((it) => ({ item: it, section: urlToSection.get(it.source_url) ?? 'other' }))
      .filter(({ item, section }) => {
        if (activeSection !== 'all' && section !== activeSection) return false;
        if (!q) return true;
        const hay = `${item.title ?? ''} ${item.description ?? ''}`.toLowerCase();
        return q
          .split(/\s+/)
          .filter(Boolean)
          .every((tok) => hay.includes(tok));
      });
  }, [items, urlToSection, activeSection, search]);

  const fetchTopAnalysis = useCallback(async () => {
    if (topAnalysis) {
      setTopAnalysisExpanded((p) => !p);
      return;
    }
    if (annotated.length === 0) return;
    setTopAnalysisLoading(true);
    setTopAnalysisError(null);
    setTopAnalysisExpanded(true);
    try {
      const top = annotated.slice(0, 20);
      const combined = top
        .map(({ item }) => `${item.title ?? 'untitled'}: ${stripHtml(item.description ?? '').slice(0, 200)}`)
        .join('\n');
      const res = await fetch('/api/v1/threat-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'event',
          title: `Threat Feeds Digest \u2014 ${top.length} latest items from ${new Set(top.map(({ item }) => item.source)).size} sources`,
          description: combined.slice(0, 4000),
          source: 'threatfeeds-aggregated',
        }),
        // LLM completions at this token budget regularly take 20-40s under
        // provider load; 35s aborted valid requests and read as "button
        // does nothing".
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const parsed = data.analysis as {
        summary: string;
        threat_level: string;
        confidence: string;
        impact: string;
        recommended_actions: string[];
        related_ttps?: string[];
        iocs?: string[];
        raw?: string;
      } | null;
      if (!parsed || (!parsed.summary && !parsed.raw)) {
        // A null analysis used to be set verbatim, silently returning the
        // panel to "Click to generate…" with no feedback.
        throw new Error(data?.error ?? 'empty analysis — try again');
      }
      if (data?.parse_failed) {
        setTopAnalysis({ ...parsed, raw: String(parsed?.raw ?? '') } as NonNullable<typeof topAnalysis>);
      } else {
        setTopAnalysis(parsed);
      }
      setTopAnalysisModel(data.model);
    } catch (e) {
      setTopAnalysisError((e as Error).message);
    } finally {
      setTopAnalysisLoading(false);
    }
  }, [annotated, topAnalysis]);

  const sectionCounts = useMemo(() => {
    const counts: Record<string, number> = { all: items.length };
    for (const sec of SECTIONS) counts[sec.id] = 0;
    for (const it of items) {
      const sec = urlToSection.get(it.source_url);
      if (sec) counts[sec] = (counts[sec] ?? 0) + 1;
    }
    return counts;
  }, [items, urlToSection]);

  // Per-feed status indexed by URL so the source panel can show ok/items or
  // the failure reason next to each feed name.
  const statusByUrl = useMemo(() => {
    const m = new Map<string, AggregatedFeedSourceStatus>();
    for (const s of feedStatuses) m.set(s.url, s);
    return m;
  }, [feedStatuses]);

  const failedCount = feedStatuses.filter((s) => !s.ok).length;

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/threatintel"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Radio size={28} className="text-brand-600 dark:text-brand-400" /> Threat Feeds
        </h1>
        <p className="text-muted mb-2 max-w-2xl">
          Live aggregator of threat-intelligence sources. {ALL_FEED_IDS.length} feeds fetched server-side, deduped,
          sorted by publication time, bucketed into six sections.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Industry / AI / general-tech content lives in{' '}
          <Link to="/threatintel/catalog?cat=social" className="text-brand-600 dark:text-brand-400 hover:underline">
            Tech &amp; AI News
          </Link>
          ; scam-watch content in{' '}
          <Link to="/threatintel/social/crypto-scam" className="text-brand-600 dark:text-brand-400 hover:underline">
            Scam Watch
          </Link>
          ; ransomware leak-sites and breach disclosures with their own watchlist UI in{' '}
          <Link to="/threatintel/catalog?cat=darkweb" className="text-brand-600 dark:text-brand-400 hover:underline">
            Dark Web Watch
          </Link>
          .
        </p>
      </div>

      {/* ─── Top-level AI Feed Analysis Card ─── */}
      {annotated.length > 0 && (
        <div className="relative mb-6 surface-card rounded-xl border border-brand-200/60 dark:border-brand-400/20 bg-gradient-to-br from-brand-50/40 via-white to-white dark:from-brand-500/[0.04] dark:via-surface-200 dark:to-surface-200 shadow-sm overflow-hidden before:absolute before:inset-x-0 before:top-0 before:h-[2px] before:bg-gradient-to-r before:from-brand-500 before:via-rose-500 before:to-brand-500">
          <button
            type="button"
            onClick={() => void fetchTopAnalysis()}
            className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-brand-50/50 dark:hover:bg-surface-100/5 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center justify-center w-6 h-6 rounded-lg bg-brand-500/10 dark:bg-brand-400/15">
                <Brain size={14} className="text-brand-600 dark:text-brand-400" />
              </span>
              <span className="text-sm font-display font-bold text-heading">AI Threat Analysis</span>
              {topAnalysis && (
                <span className="text-micro font-mono text-muted ml-1">
                  {topAnalysisModel && topAnalysisModel.split(':').pop()}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {!topAnalysisLoading && !topAnalysis && (
                <span className="text-mini font-mono text-brand-600 dark:text-brand-400 hover:underline">
                  Analyze Feed
                </span>
              )}
              <span className="text-micro text-muted">{topAnalysisExpanded ? '▲' : '▼'}</span>
            </div>
          </button>

          {topAnalysisExpanded && (
            <div className="px-4 pb-4">
              {topAnalysisLoading && !topAnalysis && (
                <div className="flex items-center gap-2 py-4 text-sm text-muted">
                  <Loader2 size={14} className="animate-spin" />
                  Analyzing feed content…
                </div>
              )}

              {topAnalysisError && (
                <div className="flex items-center justify-between py-3">
                  <p className="text-sm text-rose-600 dark:text-rose-400">{topAnalysisError}</p>
                  <button
                    type="button"
                    onClick={() => void fetchTopAnalysis()}
                    className="flex items-center gap-1.5 text-xs font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    <RefreshCw size={12} /> Retry
                  </button>
                </div>
              )}

              {topAnalysis && !topAnalysis.raw && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 text-micro font-mono rounded border ${topAnalysis.threat_level === 'critical' ? 'text-rose-700 dark:text-rose-400 bg-rose-500/10 border-rose-500/30' : topAnalysis.threat_level === 'high' ? 'text-orange-700 dark:text-orange-400 bg-orange-500/10 border-orange-500/30' : topAnalysis.threat_level === 'medium' ? 'text-amber-700 dark:text-amber-400 bg-amber-500/10 border-amber-500/30' : 'text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30'}`}
                    >
                      <Shield size={10} />
                      {topAnalysis.threat_level?.toUpperCase()}
                    </span>
                    <span className="text-micro font-mono text-muted">conf: {topAnalysis.confidence}</span>
                  </div>

                  <p className="text-sm text-body leading-relaxed">{topAnalysis.summary}</p>

                  {topAnalysis.impact && (
                    <div className="rounded-xl bg-surface-300/50 p-2.5">
                      <span className="text-micro font-mono uppercase text-muted block mb-0.5">Impact</span>
                      <p className="text-xs text-body">{topAnalysis.impact}</p>
                    </div>
                  )}

                  {topAnalysis.related_ttps?.filter(Boolean).length ? (
                    <div>
                      <span className="text-micro font-mono uppercase text-muted block mb-1">MITRE ATT&CK</span>
                      <div className="flex flex-wrap gap-1">
                        {topAnalysis.related_ttps.filter(Boolean).map((t, i) => (
                          <span
                            key={i}
                            className="text-micro font-mono px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-700 dark:text-purple-400 border border-purple-500/20"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  {topAnalysis.recommended_actions?.length > 0 && (
                    <div>
                      <span className="text-micro font-mono uppercase text-muted block mb-1">Actions</span>
                      <ul className="space-y-0.5">
                        {topAnalysis.recommended_actions.map((a, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-xs text-muted">
                            <span className="text-brand-400 mt-0.5">•</span>
                            {a}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {topAnalysis?.raw && (
                <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 p-3">
                  <p className="text-xs text-amber-600 dark:text-amber-400 mb-1.5">Unstructured model output:</p>
                  <p className="text-xs text-body leading-relaxed whitespace-pre-wrap font-mono">{topAnalysis.raw}</p>
                </div>
              )}

              {!topAnalysisLoading && !topAnalysisError && !topAnalysis && (
                <p className="text-sm text-muted py-2 italic">
                  Click to generate an AI-powered threat analysis of the latest {annotated.length} feed items.
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* AI Summary — prominent, above filters so it's the first actionable card */}
      {annotated.length > 0 && (
        <div className="mb-6">
          <AiSummaryCard
            surface="Threat Feeds"
            items={annotated.slice(0, 30).map(({ item }) => ({
              title: item.title ?? '(untitled)',
              body: stripHtml(item.description ?? ''),
              source: item.source,
            }))}
            requireAdmin={false}
          />
        </div>
      )}

      {/* Filters */}
      <section className="mb-6 surface-card p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Search size={14} className="text-brand-600 dark:text-brand-400" aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title or description - e.g. CVE-2026, lockbit, exchange RCE"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            aria-label="Search Threat Feeds"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="text-xs font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
            >
              clear
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setActiveSection('all')}
            className={`text-xs font-mono px-2 py-1 rounded border transition-colors ${
              activeSection === 'all'
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
          >
            All <span className="opacity-60">· {sectionCounts.all ?? 0}</span>
          </button>
          {SECTIONS.map((sec) => (
            <button
              key={sec.id}
              onClick={() => setActiveSection(sec.id)}
              className={`text-xs font-mono px-2 py-1 rounded border transition-colors ${
                activeSection === sec.id
                  ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                  : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
              }`}
            >
              {sec.label} <span className="opacity-60">· {sectionCounts[sec.id] ?? 0}</span>
            </button>
          ))}
          <button
            onClick={() => setShowSourcePanel((v) => !v)}
            className={`ml-auto text-xs font-mono px-2 py-1 rounded border inline-flex items-center gap-1.5 ${
              showSourcePanel
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
            title="Pick which feeds to query"
            aria-pressed={showSourcePanel}
          >
            sources{' '}
            <span className="opacity-60">
              · {enabledFeedIds.length}/{ALL_FEED_IDS.length}
            </span>
          </button>
          <button
            onClick={() => void load()}
            disabled={loading}
            className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1.5 disabled:opacity-50"
          >
            {loading ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
            {loading ? 'fetching' : 'refresh'}
          </button>
        </div>

        {showSourcePanel && (
          <div className="rounded-xl border border-line-1 bg-surface-200 p-3 space-y-3 max-h-[420px] overflow-y-auto">
            <div className="flex items-center justify-between gap-2">
              <p className="text-mini font-mono text-muted">
                Toggle individual feeds. Disabling a feed both hides it AND skips the upstream fetch. Persisted in
                localStorage.
              </p>
              <div className="flex gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => setDisabled(new Set())}
                  className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 hover:border-brand-500/40"
                >
                  enable all
                </button>
                <button
                  type="button"
                  onClick={() => setDisabled(new Set(ALL_FEED_IDS))}
                  className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-2 hover:border-rose-500/40"
                >
                  disable all
                </button>
              </div>
            </div>
            {SECTIONS.map((sec) => (
              <div key={sec.id}>
                <h3 className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">
                  {sec.label}
                  <span className="ml-1.5 opacity-60">
                    · {sec.feedIds.filter((id) => !disabled.has(id)).length}/{sec.feedIds.length} on
                  </span>
                </h3>
                <div className="grid sm:grid-cols-2 gap-1">
                  {sec.feedIds.map((fid) => {
                    const meta = rssFeeds.find((r) => r.id === fid);
                    const status = meta?.url ? statusByUrl.get(meta.url) : undefined;
                    const isEnabled = !disabled.has(fid);
                    return (
                      <button
                        key={fid}
                        type="button"
                        onClick={() =>
                          setDisabled((prev) => {
                            const next = new Set(prev);
                            if (next.has(fid)) next.delete(fid);
                            else next.add(fid);
                            return next;
                          })
                        }
                        className={`flex items-center gap-2 rounded px-2 py-1 text-left border transition-colors ${
                          isEnabled
                            ? 'border-line-1 bg-white dark:bg-surface-200 hover:border-brand-500/40'
                            : 'border-slate-200/40 dark:border-line-1/40 bg-slate-100/40 dark:bg-input-200/40 opacity-60'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={isEnabled}
                          onChange={() => {
                            /* button handles it */
                          }}
                          className="rounded border-line-3 shrink-0"
                          tabIndex={-1}
                        />
                        <span className="flex-1 min-w-0">
                          <span className="block font-mono text-mini text-body truncate">{meta?.name ?? fid}</span>
                          {isEnabled && status && (
                            <span
                              className={`block text-micro font-mono truncate ${
                                status.ok
                                  ? 'text-emerald-600 dark:text-emerald-400'
                                  : 'text-rose-600 dark:text-rose-400'
                              }`}
                              title={status.error}
                            >
                              {status.ok ? (
                                <>
                                  <CheckCircle2 size={8} className="inline" /> {status.items} items
                                </>
                              ) : (
                                <>
                                  <AlertTriangle size={8} className="inline" /> {status.error ?? 'failed'}
                                </>
                              )}
                            </span>
                          )}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        {activeSection !== 'all' && (
          <p className="text-mini font-mono text-muted">
            <span className="text-body">{SECTIONS.find((s) => s.id === activeSection)?.label}:</span>{' '}
            {SECTIONS.find((s) => s.id === activeSection)?.blurb}
          </p>
        )}
      </section>

      {error && (
        <p role="alert" className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4">
          Could not load: {error}
        </p>
      )}

      <p className="text-mini font-mono text-muted mb-3">
        Showing {annotated.length} of {items.length} · {feedsReturned} of {enabledFeedIds.length} enabled feeds returned
        data
        {failedCount > 0 && (
          <>
            {' · '}
            <button
              type="button"
              onClick={() => setShowSourcePanel(true)}
              className="text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-0.5"
            >
              <AlertTriangle size={10} /> {failedCount} failed (click for details)
            </button>
          </>
        )}
      </p>

      {/* AI Digest Button */}
      {annotated.length > 0 && (
        <div className="mb-4">
          <button
            type="button"
            onClick={() => setShowDigest((p) => !p)}
            className={`inline-flex items-center gap-2 text-xs font-mono px-4 py-2 rounded-xl border transition-colors ${
              showDigest
                ? 'border-brand-500/50 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                : 'border-line-1 text-slate-500 hover:bg-slate-50 dark:hover:bg-surface-300'
            }`}
          >
            <BarChart3 size={14} />
            {showDigest ? 'Hide Summary' : 'Show Feed Summary'}
          </button>
        </div>
      )}

      {showDigest && (
        <div className="mb-6">
          <FeedSummaryPanel
            entries={annotated.map(({ item, section }) => ({
              title: item.title,
              link: item.link,
              source: item.source,
              pubDate: item.pubDate,
              section,
            }))}
            sectionLabels={SECTION_LABELS}
            onClose={() => setShowDigest(false)}
          />
        </div>
      )}

      <ul className="space-y-2">
        {annotated.slice(0, 200).map(({ item, section }) => (
          <li
            key={item.link ?? `${item.title}-${item.pubDate}`}
            className="rounded border border-line-1 bg-surface-100 p-3 [content-visibility:auto] [contain-intrinsic-size:auto_140px]"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2 mb-1">
              <a
                href={sanitizeUrl(item.link) || undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="font-display font-semibold text-sm text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
              >
                {item.title || '(untitled)'} <ExternalLink size={11} />
              </a>
              <div className="flex items-center gap-2">
                <span
                  className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SECTION_STYLES[section] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}`}
                >
                  {section}
                </span>
                <PostAnalysisButton
                  title={item.title}
                  description={item.description}
                  source={item.source}
                  link={item.link}
                  compact
                />
              </div>
            </div>
            <div className="text-mini font-mono text-muted mb-1">
              <span>{item.source || 'feed'}</span>
              {item.pubDate && <> · {formatRelativeTime(item.pubDate)}</>}
            </div>
            {item.description && (
              <p className="text-meta font-mono text-muted leading-relaxed line-clamp-3">
                {stripHtml(item.description)}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function stripHtml(s: string): string {
  return s
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .trim();
}
