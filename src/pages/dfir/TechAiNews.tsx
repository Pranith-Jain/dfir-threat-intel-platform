import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { ExternalLink, RefreshCw, Sparkles, Loader2, Search } from 'lucide-react';
import {
  fetchAggregatedFeed,
  formatRelativeTime,
  type AggregatedFeedItem,
  type AggregatedFeedSourceStatus,
} from '../../services/rssService';
import { SourceTogglePanel } from '../../components/threatintel/SourceTogglePanel';
import { rssFeeds } from '../../data/rssFeeds';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { usePostSummaries } from '../../components/intel/usePostSummaries';
import { PostSummary } from '../../components/intel/PostSummary';

/**
 * Tech & AI News - sectioned aggregator for the non-threat half of "what's
 * happening." Threat-intel content lives in /threatintel/darkweb and /threatintel/scam-watch
 * and stays out of this surface deliberately.
 */

interface Section {
  id: string;
  label: string;
  blurb: string;
  feedIds: string[];
}

const SECTIONS: Section[] = [
  {
    id: 'ai',
    label: 'AI',
    blurb: 'Model releases, AI funding, agentic-AI products, AI-system security incidents.',
    // gnews-* removed 2026-05-24: Google News rate-limits Worker IPs
    // aggressively and returns 503 on most queries, producing persistent
    // "timeout / http_503" failures with no recovery path. The remaining
    // sources cover the same beat without the unreliable upstream.
    feedIds: [
      'techcrunch-ai',
      'verge-ai',
      'openai-news',
      'google-ai',
      'anthropic-blog',
      'huggingface-blog',
      'the-decoder',
      'import-ai',
      'deepmind-blog',
      'mit-ai-news',
    ],
  },
  {
    id: 'funding',
    label: 'Cybersecurity funding & M&A',
    blurb: 'Series A-D rounds, acquisitions, IPOs, vendor consolidation in the security industry.',
    feedIds: ['techcrunch-security', 'venturebeat-security'],
  },
  {
    id: 'general',
    label: 'General tech',
    blurb: 'Broader infrastructure, OS, networking, devices, and the security crossover.',
    feedIds: ['ars-tech', 'mit-tech-review'],
  },
  {
    id: 'yc',
    label: 'YC & startups',
    blurb: 'Y Combinator essays and announcements, plus the Hacker News front page.',
    feedIds: ['yc-blog', 'hn-frontpage'],
  },
  {
    id: 'finance',
    label: 'Finance & Banking',
    blurb:
      'Banking-sector cyber attacks, fintech breaches, payment system security, financial-industry risk intelligence.',
    // Note: gnews-* feeds removed - Google News rate-limits Worker IPs
    // with 503 on all queries (same as the AI section, q.v. lines 33-36).
    feedIds: ['finextra', 'bankinfosecurity', 'payments-dive', 'banking-dive'],
  },
];

const ALL_FEED_IDS = SECTIONS.flatMap((s) => s.feedIds);

const SECTION_STYLES: Record<string, string> = {
  ai: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  funding: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  general: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  finance: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
};

const DISABLED_STORAGE_KEY = 'tech-ai-news:disabled';

function loadDisabled(): Set<string> {
  try {
    const raw = localStorage.getItem(DISABLED_STORAGE_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch (_catchErr) {
    console.error('loadDisabled failed:', errMessage(_catchErr));
    return new Set();
  }
}

export default function TechAiNews(): JSX.Element {
  const [items, setItems] = useState<AggregatedFeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [feedsReturned, setFeedsReturned] = useState(0);
  const [feedStatuses, setFeedStatuses] = useState<AggregatedFeedSourceStatus[]>([]);
  const [disabled, setDisabled] = useState<Set<string>>(() => loadDisabled());
  const [showSourcePanel, setShowSourcePanel] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(DISABLED_STORAGE_KEY, JSON.stringify([...disabled]));
    } catch (_catchErr) {
      console.error('TechAiNews failed:', errMessage(_catchErr));
      /* localStorage unavailable */
    }
  }, [disabled]);

  const enabledFeedIds = useMemo(() => ALL_FEED_IDS.filter((id) => !disabled.has(id)), [disabled]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setItems([]);
    try {
      const data = await fetchAggregatedFeed(enabledFeedIds, { limit: 250, perSource: 20 });
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

  const postSummaries = usePostSummaries({
    surface: 'Tech & AI News',
    items: annotated.map(({ item }) => ({
      id: String(item.link ?? `${item.title}-${item.pubDate}`),
      title: item.title ?? '',
      body: item.description ?? '',
      source: item.source ?? '',
    })),
  });

  const sectionCounts = useMemo(() => {
    const counts: Record<string, number> = { all: items.length };
    for (const sec of SECTIONS) counts[sec.id] = 0;
    for (const it of items) {
      const sec = urlToSection.get(it.source_url);
      if (sec) counts[sec] = (counts[sec] ?? 0) + 1;
    }
    return counts;
  }, [items, urlToSection]);

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
          <Sparkles size={28} className="text-brand-600 dark:text-brand-400" /> Tech &amp; AI News
        </h1>
        <p className="text-muted mb-2 max-w-2xl">
          Live aggregator of AI lab announcements, cybersecurity vendor funding, and broader tech-industry signal.{' '}
          {ALL_FEED_IDS.length} sources fetched server-side, deduped, sorted by publication time.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Threat-intel content (ransomware activity, breach disclosures, scam victim reports) lives separately in{' '}
          <Link to="/threatintel/catalog?cat=darkweb" className="text-brand-600 dark:text-brand-400 hover:underline">
            Dark Web Watch
          </Link>{' '}
          and{' '}
          <Link to="/threatintel/social/crypto-scam" className="text-brand-600 dark:text-brand-400 hover:underline">
            Scam Watch
          </Link>
          . This page is the "what's the industry building / paying for" surface.
        </p>
      </div>

      {/* AI Summary — prominent, above filters */}
      {annotated.length > 0 && (
        <div className="mb-6">
          <AiSummaryCard
            surface="Tech & AI News"
            items={annotated.slice(0, 30).map(({ item }) => ({
              title: item.title ?? '',
              body: item.description ?? '',
              source: item.source ?? '',
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
            placeholder="Search title or description - e.g. wiz, snyk, gpt-5, $100m, anthropic"
            className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            aria-label="Search Tech & AI News"
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

        {activeSection !== 'all' && (
          <p className="text-mini font-mono text-muted">
            <span className="text-body">{SECTIONS.find((s) => s.id === activeSection)?.label}:</span>{' '}
            {SECTIONS.find((s) => s.id === activeSection)?.blurb}
          </p>
        )}

        {showSourcePanel && (
          <SourceTogglePanel
            sections={SECTIONS}
            allFeedIds={ALL_FEED_IDS}
            disabled={disabled}
            feedStatuses={feedStatuses}
            onToggle={(id) =>
              setDisabled((prev) => {
                const next = new Set(prev);
                if (next.has(id)) next.delete(id);
                else next.add(id);
                return next;
              })
            }
            onEnableAll={() => setDisabled(new Set())}
            onDisableAll={() => setDisabled(new Set(ALL_FEED_IDS))}
          />
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
        {feedStatuses.filter((s) => !s.ok).length > 0 && (
          <>
            {' · '}
            <button
              type="button"
              onClick={() => setShowSourcePanel(true)}
              className="text-rose-600 dark:text-rose-400 hover:underline"
            >
              {feedStatuses.filter((s) => !s.ok).length} failed (details)
            </button>
          </>
        )}
      </p>

      <ul className="space-y-2">
        {annotated.slice(0, 200).map(({ item, section }) => (
          <li
            key={item.link ?? `${item.title}-${item.pubDate}`}
            className="rounded border border-line-1 bg-surface-100 p-3"
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
              <span
                className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SECTION_STYLES[section] ?? 'border-slate-300 dark:border-line-1 text-slate-500'}`}
              >
                {section}
              </span>
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
            <PostSummary text={postSummaries.get(String(item.link ?? `${item.title}-${item.pubDate}`))} />
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
