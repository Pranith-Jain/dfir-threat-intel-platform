import { useEffect, useMemo, useState } from 'react';
import { Link, useParams, Navigate } from 'react-router-dom';
import { ArrowLeft, Search } from 'lucide-react';
import { DataState } from '../components/DataState';
import { estimateReadingTime } from '../lib/content-utils';
import { PageMeta } from '../components/PageMeta';

interface PostEntry {
  slug: string;
  title: string;
  type: string;
  excerpt: string;
  publishedAt: string;
  tags: string[];
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

// Stable display order for the type-filter chip strip. Any type not in this
// list still works as a filter but appears at the end in discovery order.
const TYPE_ORDER = ['cve', 'actor', 'malware', 'ransom', 'breach', 'scam', 'aisec', 'intel', 'briefing'] as const;

/**
 * Human-readable label + one-line description per case-study type. Used by
 * the /blog/c/:type category landing route to give each category its own
 * H1 + intro paragraph, and by the in-page chip strip via fall-through.
 * Adding a new type? Append a row here - the index page picks it up via
 * the actual post data and the landing page falls back to the type slug.
 */
const TYPE_META: Record<string, { label: string; blurb: string }> = {
  cve: {
    label: 'CVE deep-dives',
    blurb: 'Vulnerability analyses - affected products, exploit chains, KEV status, patch priority.',
  },
  actor: {
    label: 'Threat actors',
    blurb: 'Group profiles - TTPs, named operations, MITRE ATT&CK mapping, recent activity.',
  },
  malware: {
    label: 'Malware analysis',
    blurb: 'Family deep-dives - capabilities, sandbox detonation, IOCs, attribution.',
  },
  ransom: {
    label: 'Ransomware',
    blurb: 'Leak-site claims, affiliate movement, negotiation economics, double-extortion.',
  },
  breach: {
    label: 'Breach disclosures',
    blurb: 'Public breach analyses - scope, sensitivity, data classes, response timeline.',
  },
  scam: {
    label: 'Fraud & scams',
    blurb: 'BEC, social-engineering, deepfake fraud, crypto-tracing, victim reports.',
  },
  aisec: {
    label: 'AI security',
    blurb: 'Prompt injection, MCP audits, agent attack surface, model risk.',
  },
  intel: {
    label: 'Intelligence',
    blurb: 'OSINT, dark-web monitoring, sector targeting, geopolitical CTI.',
  },
  briefing: {
    label: 'Briefings',
    blurb: 'Synthesised daily and weekly intel summaries across active threats.',
  },
};

function metaFor(type: string): { label: string; blurb: string } {
  return TYPE_META[type] ?? { label: type, blurb: 'Case studies in this category.' };
}

export default function Blog() {
  // `/blog/c/:type` reaches the same component as `/blog`. When a type is
  // present in the URL we render in "category mode": replace the H1 + intro
  // with the category label + blurb, lock the type filter on, and add a
  // breadcrumb back to /blog. The user can still search-and-narrow within
  // the category, but the chip strip is hidden because the URL already
  // expresses the choice.
  //
  // `/blog/t/:tag` reaches the same component in "tag mode": lock the tag
  // filter on, show a breadcrumb, and hide the tag chip strip. This gives
  // every tag a shareable landing page (and fixes the old bug where tag
  // chips on post pages linked to /blog/c/<tag>, which 404'd for any tag
  // that wasn't also a CaseStudyType).
  const { type: routeType, tag: routeTag } = useParams<{ type?: string; tag?: string }>();
  const [posts, setPosts] = useState<PostEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | null>(routeType ?? null);

  // Sync the filter when the route param changes (e.g. navigating
  // /blog/c/actor -> /blog/c/malware reuses this component instance).
  // Unconditional mirror: a falsy param (navigating /blog/c/actor -> /blog)
  // must CLEAR the filter, otherwise /blog keeps showing the category subset.
  useEffect(() => {
    setTypeFilter(routeType ?? null);
  }, [routeType]);

  // Per-page meta varies with the /blog/c/:type route. Category
  // landings get their own title + description so Google
  // doesn't see 9 near-duplicate versions of the same page.
  const blogMeta = routeType ? metaFor(routeType) : null;
  const [tagFilter, setTagFilter] = useState<string | null>(routeTag ?? null);

  // Sync the tag filter when the route param changes (e.g. navigating
  // /blog/t/ransomware -> /blog/t/cobalt-strike reuses this component).
  // Unconditional mirror — see the type-filter effect above.
  useEffect(() => {
    setTagFilter(routeTag ?? null);
  }, [routeTag]);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/blog/posts', { signal: AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]) })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d: { posts: PostEntry[] } = await r.json();
        setPosts(d.posts);
      })
      .catch((e: Error) => {
        if (e.name !== 'AbortError') setError(e.message);
      })
      .finally(() => {
        setLoading(false);
      });
    return () => ac.abort();
  }, [reloadKey]);

  // Counts per type so the chip strip can show "actor · 12" - analyst-grade
  // affordance: tells you where the volume is before you filter.
  const typeCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const p of posts) m.set(p.type, (m.get(p.type) ?? 0) + 1);
    return m;
  }, [posts]);

  // Sort the present types by canonical order; unknown types sort alphabetic
  // at the tail so a future post type doesn't silently disappear.
  const presentTypes = useMemo(() => {
    const types = Array.from(typeCounts.keys());
    types.sort((a, b) => {
      const ai = (TYPE_ORDER as readonly string[]).indexOf(a);
      const bi = (TYPE_ORDER as readonly string[]).indexOf(b);
      if (ai === -1 && bi === -1) return a.localeCompare(b);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });
    return types;
  }, [typeCounts]);

  const allTags = useMemo(() => {
    const m = new Map<string, number>();
    for (const p of posts) {
      for (const t of p.tags) {
        m.set(t, (m.get(t) ?? 0) + 1);
      }
    }
    return m;
  }, [posts]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return posts.filter((p) => {
      if (typeFilter && p.type !== typeFilter) return false;
      if (tagFilter && !p.tags.includes(tagFilter)) return false;
      if (!q) return true;
      return (
        p.title.toLowerCase().includes(q) ||
        p.excerpt.toLowerCase().includes(q) ||
        p.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [posts, query, typeFilter, tagFilter]);

  const hasFilter = Boolean(query.trim() || (typeFilter && !routeType) || (tagFilter && !routeTag));
  const inCategoryMode = Boolean(routeType);
  const inTagMode = Boolean(routeTag);
  const categoryMeta = inCategoryMode ? metaFor(routeType!) : null;

  // Guard against typo URLs like /blog/c/whoops - surface a 404-ish state
  // (redirect to the index) so we don't render an empty category page
  // with an unfamiliar slug as the H1. We only flag this once posts have
  // loaded; before that we keep showing the loading skeleton.
  const isUnknownType =
    inCategoryMode && !loading && !error && posts.length > 0 && !posts.some((p) => p.type === routeType);
  if (isUnknownType) return <Navigate to="/blog" replace />;

  // Same guard for /blog/t/<unknown-tag> — redirect to the index instead
  // of rendering an empty tag landing page with a bogus slug as the H1.
  const isUnknownTag =
    inTagMode && !loading && !error && posts.length > 0 && !posts.some((p) => p.tags.includes(routeTag!));
  if (isUnknownTag) return <Navigate to="/blog" replace />;

  return (
    <>
      <PageMeta
        title={blogMeta ? blogMeta.label : inTagMode ? `#${routeTag}` : 'Blog'}
        description={
          blogMeta
            ? blogMeta.blurb
            : inTagMode
              ? `Case studies tagged “${routeTag}”.`
              : 'Case studies, briefings, and CVEs from the security desk. Phishing, BEC, ransomware, and detection engineering.'
        }
        canonicalPath={routeType ? `/blog/c/${routeType}` : inTagMode ? `/blog/t/${routeTag}` : '/blog'}
      />
      <div className="max-w-3xl mx-auto text-heading">
        {(inCategoryMode || inTagMode) && (
          <Link
            to="/blog"
            className="inline-flex items-center gap-2 text-xs font-mono uppercase tracking-[0.16em] text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-4"
          >
            <ArrowLeft size={12} /> all case studies
          </Link>
        )}
        <h1 className="font-display text-3xl sm:text-4xl font-semibold tracking-tight mb-2">
          {inCategoryMode ? categoryMeta!.label : inTagMode ? `#${routeTag}` : 'Case Studies'}
        </h1>
        <p className="text-muted mb-6 leading-relaxed">
          {inCategoryMode
            ? categoryMeta!.blurb
            : inTagMode
              ? `Case studies tagged “${routeTag}”.`
              : 'Security research, threat analysis, and deep dives.'}
        </p>

        {/* Category strip - only on the /blog index (not on /blog/c/:type),
          and only once posts have loaded. Each present category becomes a
          chip that routes to its own landing page. Gives every category a
          shareable URL while keeping the in-page chip filter as a quick
          alternative below. */}
        {!inCategoryMode && presentTypes.length > 1 && (
          <nav aria-label="Browse by category" className="mb-6 flex flex-wrap items-center gap-1.5">
            <span className="text-mini font-mono uppercase tracking-[0.18em] text-muted mr-1">browse:</span>
            {presentTypes.map((t) => (
              <Link
                key={t}
                to={`/blog/c/${t}`}
                className="text-meta font-mono px-2.5 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
              >
                {metaFor(t)
                  .label.toLowerCase()
                  .replace(/ deep-dives$| analysis$/, '')}
                <span className="ml-1 opacity-60">· {typeCounts.get(t) ?? 0}</span>
              </Link>
            ))}
          </nav>
        )}

        {/* Filter bar - only renders once posts are loaded (avoids a flash of
          empty chips while the data is in flight). The chip strip is hidden
          in category mode since the URL already expresses the type, but the
          search input stays so the user can narrow within the category. */}
        {posts.length > 0 && (
          <section className="surface-card p-3 mb-6">
            <div className="relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by title, excerpt, or tag…"
                aria-label="Filter case studies"
                className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              />
            </div>
            {!inCategoryMode && presentTypes.length > 1 && (
              <div className="flex flex-wrap items-center gap-1.5 mt-3">
                <span className="text-mini font-mono text-muted mr-1">type:</span>
                {presentTypes.map((t) => {
                  const active = typeFilter === t;
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setTypeFilter(active ? null : t)}
                      className={`text-mini font-mono px-2 py-1 rounded border ${
                        active
                          ? 'border-brand-500/60 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                          : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-brand-500/40'
                      }`}
                    >
                      {t} <span className="opacity-70">· {typeCounts.get(t) ?? 0}</span>
                    </button>
                  );
                })}
                {hasFilter && (
                  <button
                    type="button"
                    onClick={() => {
                      setTypeFilter(null);
                      setTagFilter(null);
                      setQuery('');
                    }}
                    className="text-mini font-mono text-brand-600 dark:text-brand-400 hover:underline ml-2"
                  >
                    clear
                  </button>
                )}
              </div>
            )}
            {!inCategoryMode && !inTagMode && allTags.size > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 mt-2 pt-2 border-t border-line-1">
                <span className="text-mini font-mono text-muted mr-1">tags:</span>
                {[
                  'all',
                  ...Array.from(allTags.entries())
                    .sort((a, b) => b[1] - a[1])
                    .map(([t]) => t),
                ].map((t) => {
                  const isAll = t === 'all';
                  const active = isAll ? !tagFilter : tagFilter === t;
                  return (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setTagFilter(isAll ? null : t)}
                      className={`text-mini font-mono px-2 py-1 rounded border ${
                        active
                          ? 'border-brand-500/60 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                          : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-brand-500/40'
                      }`}
                    >
                      {isAll ? 'all' : t}
                      {!isAll && <span className="opacity-70"> · {allTags.get(t) ?? 0}</span>}
                    </button>
                  );
                })}
              </div>
            )}
            <p className="text-mini font-mono text-muted mt-3">
              Showing <span className="text-body">{filtered.length}</span> of{' '}
              <span className="text-body">{posts.length}</span> case studies.
            </p>
          </section>
        )}

        <DataState
          loading={loading}
          error={error}
          empty={filtered.length === 0}
          emptyLabel={hasFilter ? 'No case studies match the current filter.' : 'No case studies published yet.'}
          onRetry={() => setReloadKey((k) => k + 1)}
          rows={6}
        >
          <div className="space-y-6">
            {filtered.map((p, idx) => (
              <article
                key={p.slug}
                className={`surface-card card-hover p-5 hover:border-brand-500/40 ${
                  idx === 0 && !hasFilter ? 'ring-1 ring-brand-500/20' : ''
                }`}
              >
                <Link to={`/blog/${p.slug}`} className="group block">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-micro font-mono uppercase tracking-[0.16em] text-brand-600 dark:text-brand-400 bg-brand-500/10 px-2 py-0.5 rounded">
                      {metaFor(p.type)
                        .label.toLowerCase()
                        .replace(/ deep-dives$| analysis$/, '')}
                    </span>
                    {idx === 0 && !hasFilter && (
                      <span className="text-micro font-mono uppercase tracking-wider text-amber-600 dark:text-amber-400">
                        latest
                      </span>
                    )}
                  </div>
                  <h2 className="font-display text-xl font-semibold text-heading transition-colors group-hover:text-brand-600 dark:group-hover:text-brand-400">
                    {p.title}
                  </h2>
                  <p className="text-muted mt-2 leading-relaxed">{p.excerpt}</p>
                </Link>
                <div className="flex flex-wrap items-center gap-3 mt-3 text-xs text-muted">
                  <span className="font-medium text-body">Pranith Jain</span>
                  <span aria-hidden="true" className="text-inverted dark:text-muted">
                    ·
                  </span>
                  <time>{formatDate(p.publishedAt)}</time>
                  <span aria-hidden="true" className="text-inverted dark:text-muted">
                    ·
                  </span>
                  <span>{estimateReadingTime(p.excerpt)} min read</span>
                </div>
                {p.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {p.tags.map((t) => (
                      <Link
                        key={t}
                        to={`/blog/t/${t}`}
                        // The tag chips were 21px tall — well under the
                        // 44px touch minimum, 340 of them on one phone
                        // screen. `min-h-[32px]` plus a taller padding
                        // keeps the chip compact but tappable.
                        className={`inline-flex min-h-[32px] items-center rounded border px-2 py-1 text-mini font-mono transition-colors ${
                          tagFilter === t
                            ? 'border-brand-500/60 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                            : 'border-slate-200 bg-slate-50 text-slate-600 dark:border-line-1 dark:bg-surface-200 dark:text-muted hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400'
                        }`}
                        title={`Browse tag: ${t}`}
                      >
                        {t}
                      </Link>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        </DataState>

        <section className="mt-16 surface-card p-6">
          <h2 className="font-display font-bold text-lg text-heading mb-1">Stay updated</h2>
          <p className="text-sm text-muted mb-4">
            New case studies land when I finish an investigation worth writing up. Subscribe via{' '}
            <a
              href="/blog/rss.xml"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline font-semibold transition-colors"
            >
              RSS
            </a>{' '}
            to get notified.
          </p>
          <a
            href="/blog/rss.xml"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded border border-line-2 hover:border-brand-500/40 hover:bg-brand-500/5 transition-colors"
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M4 11a9 9 0 0 1 9 9" />
              <path d="M4 4a16 16 0 0 1 16 16" />
              <circle cx="5" cy="19" r="1" />
            </svg>
            Subscribe via RSS
          </a>
        </section>
      </div>
    </>
  );
}
