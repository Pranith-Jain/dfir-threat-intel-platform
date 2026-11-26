import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { ExternalLink, Filter, Github, Rss, Search, Shield, Wrench } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * Kitploit directory replication — newest tools, CVE evidence cards and the
 * three public RSS feeds from kitploit.com/en. Its robots.txt disallows /api/,
 * so only crawlable HTML + feeds are mirrored; every item deep-links upstream.
 *   GET /api/v1/kp/             slim index
 *   GET /api/v1/kp/feeds/:name  full feed items (updates|exploits|blog)
 */

interface KpTool {
  id: string;
  title: string;
  url: string;
  provider: string | null;
  repo: string | null;
  description: string | null;
  image: string | null;
  categories: string[];
  stars: string | null;
}

interface KpExploit {
  id: string;
  cve: string | null;
  title: string;
  url: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  epss: string | null;
  exploitCount: number | null;
  evidence: string | null;
}

interface KpFeedItemRef {
  title: string | null;
  url: string | null;
  published: string | null;
}

interface FeedItem {
  title: string | null;
  url: string | null;
  description: string | null;
  published: string | null;
  guid: string | null;
  image: string | null;
}

interface KpIndex {
  source: string;
  sourceUrl: string;
  license: string;
  robots: string;
  builtAt: string;
  counts: { tools: number; exploits: number; updates: number; exploitUpdates: number; blogPosts: number };
  stats: {
    byProvider: Record<string, number>;
    byCategory: Record<string, number>;
    byCvssSeverity: Record<string, number>;
    sourceLinks: number;
  };
  tools: KpTool[];
  exploits: KpExploit[];
  feeds: Record<string, KpFeedItemRef[]>;
  webPages: Record<string, string>;
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  high: 'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800',
  medium: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  low: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
};

type Tab = 'tools' | 'exploits' | 'feeds' | 'about';
type FeedName = 'updates' | 'exploits' | 'blog';

function fmtDate(raw: string | null): string {
  if (!raw) return '';
  const d = new Date(raw);
  return Number.isNaN(d.getTime())
    ? raw
    : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

export default function Kitploit(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<KpIndex>({ url: '/api/v1/kp/', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('tools');
  const [toolQ, setToolQ] = useState('');
  const [category, setCategory] = useState('');
  const [exploitQ, setExploitQ] = useState('');
  const [severity, setSeverity] = useState('');
  const [feed, setFeed] = useState<FeedName>('updates');
  const {
    data: feedData,
    loading: feedLoading,
    error: feedError,
  } = useDataFetch<{ items: FeedItem[] }>({
    url: `/api/v1/kp/feeds/${feed}`,
    ttl: 300_000,
  });

  const tools = useMemo(() => {
    const needle = toolQ.trim().toLowerCase();
    return (data?.tools ?? []).filter((t) => {
      if (category && !t.categories.includes(category)) return false;
      if (
        needle &&
        !`${t.title} ${t.description ?? ''} ${t.repo ?? ''} ${t.categories.join(' ')}`.toLowerCase().includes(needle)
      )
        return false;
      return true;
    });
  }, [data, toolQ, category]);

  const exploits = useMemo(() => {
    const needle = exploitQ.trim().toLowerCase();
    return (data?.exploits ?? []).filter((e) => {
      if (severity && e.cvssSeverity !== severity) return false;
      if (needle && !`${e.cve ?? ''} ${e.title}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data, exploitQ, severity]);

  const briefingItems = useMemo(
    () =>
      [
        ...(data?.tools ?? []).map((t) => ({
          title: t.title,
          body: `${t.categories.join(', ') || 'uncategorized'}${
            t.description ? ` — ${t.description.slice(0, 220)}` : ''
          }${t.provider ? ` · ${t.provider}` : ''}`,
          source: t.url,
        })),
        ...(data?.exploits ?? []).map((e) => ({
          title: e.cve ?? e.title,
          body: `${e.title}${e.cvssSeverity ? ` · CVSS ${e.cvssScore} ${e.cvssSeverity}` : ''}${
            e.epss ? ` · EPSS ${e.epss}` : ''
          }${e.evidence ? ` — ${e.evidence.slice(0, 200)}` : ''}`,
          source: e.url,
        })),
      ].slice(0, 50),
    [data]
  );

  const categories = Object.entries(data?.stats.byCategory ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 30);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'tools', label: `Tools (${data?.counts.tools ?? '…'})` },
    { id: 'exploits', label: `Exploits (${data?.counts.exploits ?? '…'})` },
    { id: 'feeds', label: 'Feeds' },
    { id: 'about', label: 'About' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Wrench size={28} />}
      title="Kitploit Directory"
      description={
        <>
          A local mirror of the crawlable surface of{' '}
          <a
            href={data?.sourceUrl ?? 'https://kitploit.com/en'}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            kitploit.com/en
          </a>{' '}
          — newest security tools, CVE exploit evidence and project feeds. {data?.counts.tools ?? '…'} tool cards,{' '}
          {data?.counts.exploits ?? '…'} CVE cards and {data?.counts.updates ?? '…'} update items. Its robots.txt
          disallows <code className="text-xs">/api/</code>, so this replication uses only public HTML and RSS.
        </>
      }
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-500/15 text-brand-600 dark:text-brand-300 border-brand-400/40'
                : 'text-muted hover:text-heading border-line-1'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <DetectionAiBriefing
        surface="Kitploit Directory"
        source="kitploit"
        items={briefingItems}
        dayKey={data?.builtAt?.slice(0, 10)}
        label="tools and CVE cards"
      />

      {tab === 'tools' && (
        <>
          <div className="surface-card p-3 mb-5 grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Filter size={14} /> Filters
            </div>
            <select
              className={inputCls}
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              aria-label="Category"
            >
              <option value="">All categories</option>
              {categories.map(([name, n]) => (
                <option key={name} value={name}>
                  {name} ({n})
                </option>
              ))}
            </select>
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                className={`${inputCls} pl-9`}
                placeholder="Search tools…"
                value={toolQ}
                onChange={(e) => setToolQ(e.target.value)}
              />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {tools.map((t) => (
              <a
                key={t.id}
                href={t.url}
                target="_blank"
                rel="noreferrer"
                className="surface-card p-3 hover:border-brand-400 transition-colors block"
              >
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-heading truncate">{t.title}</span>
                  {t.provider && (
                    <span className="text-[10px] text-muted inline-flex items-center gap-1 ml-auto">
                      <Github size={10} /> {t.provider}
                    </span>
                  )}
                </div>
                {t.description && <p className="text-xs text-muted mt-1.5 line-clamp-2">{t.description}</p>}
                <div className="flex flex-wrap gap-1 mt-2">
                  {t.categories.slice(0, 4).map((c) => (
                    <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-surface-100 text-muted">
                      {c}
                    </span>
                  ))}
                  {t.stars && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-100 text-muted">★ {t.stars}</span>
                  )}
                </div>
                {t.repo && <div className="text-[10px] font-mono text-muted mt-2 truncate">{t.repo}</div>}
              </a>
            ))}
          </div>
        </>
      )}

      {tab === 'exploits' && (
        <>
          <div className="surface-card p-3 mb-5 grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Filter size={14} /> Filters
            </div>
            <select
              className={inputCls}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              aria-label="CVSS severity"
            >
              <option value="">All severities</option>
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                className={`${inputCls} pl-9`}
                placeholder="Search CVEs…"
                value={exploitQ}
                onChange={(e) => setExploitQ(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-2">
            {exploits.map((e) => (
              <a
                key={e.id}
                href={e.url}
                target="_blank"
                rel="noreferrer"
                className="surface-card p-3 hover:border-brand-400 transition-colors block"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-brand-500">{e.cve ?? e.id}</span>
                  {e.cvssSeverity && (
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded border ${SEVERITY_STYLES[e.cvssSeverity.toLowerCase()] ?? SEVERITY_STYLES.medium}`}
                    >
                      CVSS {e.cvssScore} · {e.cvssSeverity}
                    </span>
                  )}
                  {e.epss && <span className="text-[10px] text-muted">EPSS {e.epss}</span>}
                  <span className="text-[10px] text-muted ml-auto">{e.exploitCount ?? '…'} exploits</span>
                </div>
                <p className="text-sm text-heading mt-1.5">{e.title}</p>
                {e.evidence && <p className="text-xs text-muted mt-1">{e.evidence}</p>}
              </a>
            ))}
          </div>
          <p className="text-xs text-muted mt-3">
            The full CVE feed ({data?.counts.exploitUpdates ?? '…'} items) is on the Feeds tab. No exploit code is
            vendored — every card links to its upstream evidence page.
          </p>
        </>
      )}

      {tab === 'feeds' && (
        <>
          <div className="flex flex-wrap gap-2 mb-4">
            {(['updates', 'exploits', 'blog'] as FeedName[]).map((name) => (
              <button
                key={name}
                onClick={() => setFeed(name)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                  feed === name
                    ? 'bg-brand-500/15 text-brand-600 dark:text-brand-300 border-brand-400/40'
                    : 'text-muted hover:text-heading border-line-1'
                }`}
              >
                {name} (
                {data?.counts[name === 'updates' ? 'updates' : name === 'exploits' ? 'exploitUpdates' : 'blogPosts'] ??
                  '…'}
                )
              </button>
            ))}
            <a
              href={
                feed === 'blog'
                  ? `${data?.sourceUrl ?? ''}/blog/rss.xml`
                  : `${data?.sourceUrl ?? ''}/${feed === 'exploits' ? 'exploits/' : ''}rss.xml`
              }
              target="_blank"
              rel="noreferrer"
              className="ml-auto inline-flex items-center gap-1 text-sm text-brand-500 hover:underline"
            >
              <Rss size={14} /> Upstream feed
            </a>
          </div>
          {feedLoading && <p className="text-sm text-muted">Loading feed…</p>}
          {feedError && <p className="text-sm text-rose-500">Feed failed to load: {feedError}</p>}
          <div className="space-y-2">
            {(feedData?.items ?? []).map((item, i) => (
              <div key={item.guid ?? i} className="surface-card p-3">
                <div className="flex flex-wrap items-center gap-2">
                  {item.title && (
                    <a
                      href={item.url ?? '#'}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sm font-medium text-heading hover:text-brand-500 inline-flex items-center gap-1"
                    >
                      {item.title} <ExternalLink size={11} />
                    </a>
                  )}
                  <span className="text-xs text-muted ml-auto">{fmtDate(item.published)}</span>
                </div>
                {item.description && <p className="text-xs text-muted mt-1 line-clamp-2">{item.description}</p>}
              </div>
            ))}
          </div>
        </>
      )}

      {tab === 'about' && (
        <div className="surface-card p-5 text-sm text-muted space-y-3">
          <p>
            Kitploit curates hacking, penetration-testing and cybersecurity tools plus public CVE evidence. This
            replication reads only the surfaces its <code className="text-xs">robots.txt</code> allows — HTML listing
            pages and RSS feeds. The upstream JSON API is explicitly disallowed and is never called.
          </p>
          <p>
            No reuse licence is published, so the manifest stores structured metadata and short factual descriptions
            only. Every tool, CVE and feed item deep-links upstream; no images or exploit code are vendored.
          </p>
          <p>
            Because the public listing pages only expose the newest items, this mirror is a snapshot of recent additions
            rather than the entire directory.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <a
              href={data?.webPages.home ?? 'https://kitploit.com/en'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Upstream home <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.tools ?? 'https://kitploit.com/en/tools'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              All tools <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.exploits ?? 'https://kitploit.com/en/exploits'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              All exploits <ExternalLink size={13} />
            </a>
            <a
              href={data?.webPages.feeds ?? 'https://kitploit.com/en/feeds'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-brand-500 hover:underline text-sm"
            >
              Feeds <ExternalLink size={13} />
            </a>
          </div>
        </div>
      )}
      <div className="flex items-center gap-1 text-xs text-muted mt-6">
        <Shield size={12} /> Snapshot built {data?.builtAt ? fmtDate(data.builtAt) : '…'} · metadata and links only
      </div>
    </DataPageLayout>
  );
}
