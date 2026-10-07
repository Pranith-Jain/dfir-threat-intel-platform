import { logCatch } from '../../lib/log';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  getJson,
  getObjectUrl,
  postJson,
  postJsonWithBody,
  approveSocialPlatform,
  unapproveSocialPlatform,
  getSocialQueue,
} from './adminApi';
import type { SocialQueueItem, SocialQueueResponse } from './adminApi';
import { bestTimeHint, type SocialPlatform } from './socialHints';
import { splitSocial } from '../../lib/social-parts';
import { SearchFilter } from './SearchFilter';

interface ScheduleEntry {
  scheduledAt?: string;
  status: 'pending' | 'approved' | 'posted' | 'failed';
  postedAt?: string;
  postUrl?: string;
  error?: string;
  attempts?: number;
}
interface SocialScheduleData {
  slug: string;
  twitter?: ScheduleEntry;
  linkedin?: ScheduleEntry;
  instagram?: ScheduleEntry;
  updatedAt: string;
}

function toLocalInput(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

interface PostEntry {
  slug: string;
  title: string;
  type: string;
  excerpt: string;
  publishedAt: string;
  tags: string[];
}

interface CarouselSlide {
  index: number;
  headline: string;
  body?: string;
  bullets?: string[];
  kind?: string;
}

/** Factual per-platform checks (see SocialCheck in api/src/case-study/types.ts).
 *  No score: the composite score and the slop-phrase counter are gone. These
 *  are measurements and ground-truth lookups only. */
interface SocialCheck {
  char_count: number;
  over_limit: boolean;
  ungrounded_cves: string[];
  untrusted_urls: number;
}

interface SocialContent {
  slug: string;
  twitter: string;
  linkedin: string;
  instagram?: string;
  carousel?: { format: 'instagram'; slides: CarouselSlide[] };
  generatedAt: string;
  hooks?: string[];
  _validation?: {
    twitter_check?: SocialCheck;
    linkedin_check?: SocialCheck;
    instagram_check?: SocialCheck;
  };
}

interface SocialEntry {
  loadingTwitter?: boolean;
  loadingLinkedin?: boolean;
  data: SocialContent | null;
  error: string | null;
  // Per-platform presence from the cheap /social-index list, so button state
  // doesn't need the full per-post /social fetch on load.
  hasTwitter: boolean;
  hasLinkedin: boolean;
}

type SocialState = Record<string, SocialEntry>;

export default function PublishedTab() {
  const [posts, setPosts] = useState<PostEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [social, setSocial] = useState<SocialState>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    // Clear expanded so it can't reference a slug that no longer exists
    // after an unpublish/refresh.
    setExpanded(null);
    try {
      const d = await getJson<{ posts: PostEntry[] }>('/posts');
      setPosts(d.posts);
      // ONE /social-index list call instead of a /social fetch per post (each
      // of which read 3 KV keys). Full content is fetched lazily on expand.
      let idx: Record<string, { twitter: boolean; linkedin: boolean }> = {};
      try {
        idx = (await getJson<{ index: Record<string, { twitter: boolean; linkedin: boolean }> }>('/social-index'))
          .index;
      } catch (_catchErr) {
        console.error('PublishedTab failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
        /* index is optional */
      }
      const initial: SocialState = {};
      for (const p of d.posts) {
        initial[p.slug] = {
          loadingTwitter: false,
          loadingLinkedin: false,
          data: null,
          error: null,
          hasTwitter: idx[p.slug]?.twitter ?? false,
          hasLinkedin: idx[p.slug]?.linkedin ?? false,
        };
      }
      setSocial(initial);
    } catch (e) {
      logCatch(e);
      setError(e instanceof Error ? e.message : 'failed to load');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function unpublish(slug: string) {
    // Destructive - match DraftsTab.reject's confirm UX.
    if (!window.confirm(`Unpublish /blog/${slug}? This removes the post from the site.`)) return;
    setActionMsg(null);
    try {
      await postJson(`/posts/${encodeURIComponent(slug)}/unpublish`);
      setActionMsg(`Unpublished /blog/${slug}`);
      await load();
    } catch (e) {
      console.error('unpublish failed:', e instanceof Error ? e.message : String(e));
      setActionMsg(`unpublish failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  function setSocialAndExpand(slug: string, update: Partial<SocialEntry>) {
    setSocial((prev) => {
      const next = { ...prev, [slug]: { ...prev[slug], ...update } as SocialEntry };
      return next;
    });
    setExpanded(slug);
  }

  // Lazy-load the full social content the first time a row is expanded (the
  // list view only knows per-platform presence, not the copy itself).
  async function viewSocial(slug: string) {
    if (expanded === slug) {
      setExpanded(null);
      return;
    }
    if (!social[slug]?.data) {
      try {
        const r = await getJson<{ ok: boolean; social: SocialContent }>(`/social/${encodeURIComponent(slug)}`);
        if (r.ok) setSocial((prev) => ({ ...prev, [slug]: { ...prev[slug], data: r.social } as SocialEntry }));
      } catch (_catchErr) {
        console.error('viewSocial failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
        /* social content is optional */
      }
    }
    setExpanded(slug);
  }

  async function generateTwitter(slug: string) {
    setSocial((prev) => {
      const entry = prev[slug] ?? { data: null, error: null, hasTwitter: false, hasLinkedin: false };
      return { ...prev, [slug]: { ...entry, loadingTwitter: true, error: null } };
    });
    try {
      const r = await postJsonWithBody<{
        ok: boolean;
        platform: string;
        content: string;
        generatedAt: string;
        error?: string;
      }>(`/social/${encodeURIComponent(slug)}/twitter`, {});
      if (r.ok) {
        setSocialAndExpand(slug, {
          loadingTwitter: false,
          error: null,
        });
        if (r.content) {
          setSocial((prev) => {
            const existing = prev[slug]?.data ?? { slug, twitter: '', linkedin: '', generatedAt: r.generatedAt };
            const entry = prev[slug] ?? { data: null, error: null, hasTwitter: false, hasLinkedin: false };
            return {
              ...prev,
              [slug]: { ...entry, data: { ...existing, twitter: r.content }, error: null, hasTwitter: true },
            };
          });
        }
      } else {
        setSocialAndExpand(slug, { loadingTwitter: false, error: r.error ?? 'failed' });
      }
    } catch (e) {
      logCatch(e);
      setSocialAndExpand(slug, { loadingTwitter: false, error: e instanceof Error ? e.message : String(e) });
    }
  }

  async function generateLinkedin(slug: string) {
    setSocial((prev) => {
      const entry = prev[slug] ?? { data: null, error: null, hasTwitter: false, hasLinkedin: false };
      return { ...prev, [slug]: { ...entry, loadingLinkedin: true, error: null } };
    });
    try {
      const r = await postJsonWithBody<{
        ok: boolean;
        platform: string;
        content: string;
        generatedAt: string;
        error?: string;
      }>(`/social/${encodeURIComponent(slug)}/linkedin`, {});
      if (r.ok) {
        setSocialAndExpand(slug, {
          loadingLinkedin: false,
          error: null,
        });
        if (r.content) {
          setSocial((prev) => {
            const existing = prev[slug]?.data ?? { slug, twitter: '', linkedin: '', generatedAt: r.generatedAt };
            const entry = prev[slug] ?? { data: null, error: null, hasTwitter: false, hasLinkedin: false };
            return {
              ...prev,
              [slug]: { ...entry, data: { ...existing, linkedin: r.content }, error: null, hasLinkedin: true },
            };
          });
        }
      } else {
        setSocialAndExpand(slug, { loadingLinkedin: false, error: r.error ?? 'failed' });
      }
    } catch (e) {
      logCatch(e);
      setSocialAndExpand(slug, { loadingLinkedin: false, error: e instanceof Error ? e.message : String(e) });
    }
  }

  if (loading) return <p className="text-muted">Loading…</p>;
  if (error)
    return (
      <div>
        <p className="text-rose-600 dark:text-rose-400 mb-2">Failed to load: {error}</p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );
  if (posts.length === 0)
    return (
      <div>
        {actionMsg && <p className="text-xs font-mono text-muted mb-2">{actionMsg}</p>}
        <SocialQueueAgenda />
        <p className="text-muted">No published posts.</p>
      </div>
    );

  return (
    <div>
      {actionMsg && <p className="text-xs font-mono text-muted mb-2">{actionMsg}</p>}
      <SocialQueueAgenda />
      <p className="text-xs text-muted mb-4">Click a row to expand/collapse social content.</p>
      <SearchFilter items={posts} placeholder="Filter published posts…">
        {(filtered) => (
          <div className="overflow-x-auto">
            <DataTable
              columns={
                [
                  {
                    key: 'type',
                    header: 'Type',
                    sortValue: (p: (typeof filtered)[number]) => p.type,
                    render: (p) => <span className="text-muted uppercase text-xs">{p.type}</span>,
                  },
                  {
                    key: 'title',
                    header: 'Title',
                    sortValue: (p: (typeof filtered)[number]) => p.title,
                    render: (p) => <span className="text-heading">{p.title}</span>,
                  },
                  {
                    key: 'publishedAt',
                    header: 'Published',
                    sortValue: (p: (typeof filtered)[number]) => p.publishedAt,
                    render: (p) => (
                      <span className="text-muted text-xs whitespace-nowrap">
                        {new Date(p.publishedAt).toLocaleString()}
                      </span>
                    ),
                  },
                  {
                    key: 'slug',
                    header: 'Slug',
                    sortValue: (p: (typeof filtered)[number]) => p.slug,
                    render: (p) => (
                      <a
                        href={`/blog/${p.slug}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-body hover:underline transition-colors"
                      >
                        {p.slug}
                      </a>
                    ),
                  },
                  {
                    key: 'social',
                    header: 'Social',
                    render: (p) => {
                      const s = social[p.slug];
                      const hasTwitter = !!s?.hasTwitter;
                      const hasLinkedin = !!s?.hasLinkedin;
                      return (
                        <div className="flex flex-wrap gap-1.5">
                          <button
                            onClick={() => generateTwitter(p.slug)}
                            disabled={s?.loadingTwitter}
                            className={`px-2 py-1 border rounded text-xs disabled:opacity-50 ${hasTwitter ? 'border-line-1 hover:bg-slate-100 dark:hover:bg-surface-300' : 'border-emerald-200 dark:border-emerald-800 hover:bg-emerald-50 dark:hover:bg-emerald-900/30'}`}
                          >
                            {s?.loadingTwitter ? '…' : hasTwitter ? 'Re-Tweet' : 'Tweet'}
                          </button>
                          <button
                            onClick={() => generateLinkedin(p.slug)}
                            disabled={s?.loadingLinkedin}
                            className={`px-2 py-1 border rounded text-xs disabled:opacity-50 ${hasLinkedin ? 'border-line-1 hover:bg-slate-100 dark:hover:bg-surface-300' : 'border-blue-200 dark:border-blue-800 hover:bg-blue-50 dark:hover:bg-blue-900/30'}`}
                          >
                            {s?.loadingLinkedin ? '…' : hasLinkedin ? 'Re-LinkedIn' : 'LinkedIn'}
                          </button>
                        </div>
                      );
                    },
                  },
                  {
                    key: 'actions',
                    header: 'Actions',
                    render: (p) => (
                      <div className="flex gap-1.5">
                        <button
                          onClick={() => viewSocial(p.slug)}
                          className="px-2 py-1 border border-line-1 rounded text-xs text-body hover:bg-surface-300 dark:hover:bg-surface-300"
                        >
                          View
                        </button>
                        <button
                          onClick={() => unpublish(p.slug)}
                          className="px-2 py-1 border border-rose-200 dark:border-rose-800 rounded text-xs text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50"
                        >
                          Unpublish
                        </button>
                      </div>
                    ),
                  },
                ] as DataTableColumn<(typeof filtered)[number]>[]
              }
              rows={filtered}
              rowKey={(p) => p.slug}
            />
          </div>
        )}
      </SearchFilter>

      {expanded && social[expanded]?.data && (
        <SocialContentPanel
          data={social[expanded].data!}
          onClose={() => setExpanded(null)}
          onRegenTwitter={() => generateTwitter(expanded)}
          onRegenLinkedin={() => generateLinkedin(expanded)}
          regenTwitterBusy={social[expanded]?.loadingTwitter ?? false}
          regenLinkedinBusy={social[expanded]?.loadingLinkedin ?? false}
        />
      )}

      {expanded && social[expanded]?.error && (
        <div className="mt-4 p-3 rounded bg-rose-50 dark:bg-rose-900/30 text-rose-600 dark:text-rose-300 border border-rose-200 dark:border-rose-800 text-sm">
          {social[expanded]?.error}
        </div>
      )}
    </div>
  );
}

// ─── Content-calendar agenda ─────────────────────────────────────────────────

/** Compact upcoming-queue panel shown at the top of the Published view.
 *  Fetches /social-queue once on mount; shows the autopost switch state
 *  and a sorted list of queued items. */
function SocialQueueAgenda() {
  const [data, setData] = useState<SocialQueueResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getSocialQueue()
      .then(setData)
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  if (err)
    return (
      <p className="text-xs text-rose-600 dark:text-rose-400 mb-4" role="alert">
        Queue unavailable: {err}
      </p>
    );
  if (!data) return null;

  const { autopostEnabled, queue } = data;

  return (
    <section aria-label="Content calendar queue" className="mb-6 rounded border border-line-1 bg-surface-200/40 p-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-mini font-semibold uppercase tracking-wider text-muted">Upcoming queue</h3>
        <span
          className={`px-2 py-0.5 rounded text-micro font-semibold border ${
            autopostEnabled
              ? 'bg-emerald-50 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700/50'
              : 'bg-slate-100 dark:bg-surface-300 text-muted border-line-1'
          }`}
          aria-label={autopostEnabled ? 'Auto-post is ON' : 'Auto-post is OFF - review only'}
        >
          {autopostEnabled ? 'Auto-post: ON' : 'Auto-post: OFF - review only'}
        </span>
      </div>

      {queue.length === 0 ? (
        <p className="text-xs text-muted">No items in queue.</p>
      ) : (
        <ul className="space-y-1" aria-label="Queued social posts">
          {queue.map((item: SocialQueueItem) => (
            <li key={`${item.slug}-${item.platform}`} className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span className="font-mono text-muted whitespace-nowrap">
                {item.scheduledAt ? new Date(item.scheduledAt).toLocaleString() : '-'}
              </span>
              <span className="text-muted" aria-hidden="true">
                ·
              </span>
              <span className="font-mono text-body">{item.slug}</span>
              <span className="text-muted" aria-hidden="true">
                ·
              </span>
              <span className="uppercase text-muted">{item.platform}</span>
              <span className="text-muted" aria-hidden="true">
                ·
              </span>
              <QueueStatusBadge item={item} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function QueueStatusBadge({ item }: { item: SocialQueueItem }) {
  const { status, postUrl, error, attempts } = item;
  const base = 'px-1.5 py-0.5 rounded text-micro border';
  if (status === 'posted') {
    const badge = (
      <span
        className={`${base} bg-emerald-50 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-700/50`}
      >
        posted
      </span>
    );
    return postUrl ? (
      <a href={postUrl} target="_blank" rel="noopener noreferrer" className="underline underline-offset-2">
        {badge}
      </a>
    ) : (
      badge
    );
  }
  if (status === 'approved') {
    return (
      <span
        className={`${base} bg-sky-50 dark:bg-sky-900/40 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-700/50`}
      >
        approved
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span
        className={`${base} bg-rose-50 dark:bg-rose-900/40 text-rose-600 dark:text-rose-300 border-rose-200 dark:border-rose-700/50`}
        title={error ?? 'unknown error'}
      >
        failed{attempts != null ? ` (${attempts})` : ''}
      </span>
    );
  }
  // pending
  return (
    <span
      className={`${base} bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-700/40`}
    >
      pending
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Per-platform factual checks.
 *
 * Replaces the "readiness gate" badge, which scored the three platforms
 * against each other (hook diversity, body overlap, composite scores) and
 * rendered a READY / REVIEW verdict. That verdict was advisory only and had
 * no relationship to whether the copy was any good, so it mostly told you
 * things you could see by reading the posts.
 *
 * What is worth surfacing is what the server could not verify: a CVE id with
 * no match in the research dossier, an over-limit post the platform will
 * truncate, a link that was stripped for pointing at an untrusted host.
 */
function CheckBadges({ checks }: { checks: Record<string, SocialCheck | undefined> }) {
  const rows = Object.entries(checks).filter(([, c]) => c !== undefined);
  if (rows.length === 0) return null;

  const issues = rows.flatMap(([platform, c]) => {
    const list: string[] = [];
    if (c!.over_limit) list.push(`${platform}: over the character limit (${c!.char_count})`);
    if (c!.ungrounded_cves.length > 0) {
      list.push(`${platform}: ${c!.ungrounded_cves.length} CVE(s) not in the research dossier`);
    }
    if (c!.untrusted_urls > 0) list.push(`${platform}: ${c!.untrusted_urls} untrusted link(s) stripped`);
    return list;
  });

  if (issues.length === 0) return null;

  return (
    <div className="mb-4 rounded border border-amber-200 dark:border-amber-700/50 bg-amber-50 dark:bg-amber-900/20 p-3">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="text-xs font-mono font-semibold text-amber-700 dark:text-amber-300">
          ⚠ CHECK THESE BEFORE POSTING
        </span>
        <span className="text-xs font-mono text-muted">
          {rows.map(([p, c]) => `${p} ${c!.char_count}ch`).join(' · ')}
        </span>
      </div>
      <ul className="space-y-0.5 text-xs text-amber-700 dark:text-amber-400">
        {issues.map((t, i) => (
          <li key={i}>{t}</li>
        ))}
      </ul>
    </div>
  );
}

type PostState = {
  posting: boolean;
  result: { ok: boolean; postUrl?: string; error?: string } | null;
};

function SocialContentPanel({
  data,
  onClose,
  onRegenTwitter,
  onRegenLinkedin,
  regenTwitterBusy,
  regenLinkedinBusy,
}: {
  data: SocialContent;
  onClose: () => void;
  onRegenTwitter: () => void;
  onRegenLinkedin: () => void;
  regenTwitterBusy: boolean;
  regenLinkedinBusy: boolean;
}) {
  const [postState, setPostState] = useState<{ twitter: PostState; linkedin: PostState }>({
    twitter: { posting: false, result: null },
    linkedin: { posting: false, result: null },
  });
  const [schedRefresh, setSchedRefresh] = useState(0);
  // Hook apply regenerates the stored copy server-side; refetch it here so
  // the displayed Twitter/LinkedIn text updates without collapse/re-expand.
  const [refreshed, setRefreshed] = useState<SocialContent | null>(null);
  const [refreshBusy, setRefreshBusy] = useState(false);

  const effective = refreshed ?? data;

  async function refreshSocial(slug: string) {
    setRefreshBusy(true);
    try {
      const d = await getJson<{ ok: boolean; social: SocialContent }>(`/social/${encodeURIComponent(slug)}`);
      if (d.social) setRefreshed(d.social);
    } catch (e) {
      console.error('refreshSocial failed:', e instanceof Error ? e.message : String(e));
    } finally {
      setRefreshBusy(false);
    }
  }

  async function postToPlatform(slug: string, platform: 'twitter' | 'linkedin') {
    setPostState((prev) => ({
      ...prev,
      [platform]: { posting: true, result: null },
    }));
    try {
      const r = await postJson<{ ok: boolean; postUrl?: string; error?: string }>(
        `/social/${encodeURIComponent(slug)}/post-${platform}`
      );
      setPostState((prev) => ({
        ...prev,
        [platform]: { posting: false, result: r },
      }));
      setSchedRefresh((n) => n + 1);
    } catch (e) {
      console.error('postToPlatform failed:', e instanceof Error ? e.message : String(e));
      setPostState((prev) => ({
        ...prev,
        [platform]: { posting: false, result: { ok: false, error: e instanceof Error ? e.message : String(e) } },
      }));
    }
  }

  return (
    <div className="mt-6 rounded border border-line-1 p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-body">Social Content</h3>
        <button
          onClick={onClose}
          className="text-xs text-muted hover:text-body dark:hover:text-inverted transition-colors"
        >
          Close
        </button>
      </div>
      <p className="text-xs text-muted mb-4">Generated {new Date(effective.generatedAt).toLocaleString()}</p>

      {effective._validation && (
        <CheckBadges
          checks={{
            twitter: effective._validation.twitter_check,
            linkedin: effective._validation.linkedin_check,
            instagram: effective._validation.instagram_check,
          }}
        />
      )}

      {effective.hooks && effective.hooks.length > 0 && (
        <HookSelector
          hooks={effective.hooks}
          slug={effective.slug}
          onHookSelected={() => {
            // Refetch the regenerated copy so the panels below stop showing
            // the pre-hook text (schedRefresh only refreshes the schedule).
            void refreshSocial(effective.slug);
            setSchedRefresh((n) => n + 1);
          }}
          busy={refreshBusy}
        />
      )}

      <SchedulePanel slug={effective.slug} refreshTrigger={schedRefresh} />

      <SocialSection
        heading="Twitter Thread"
        text={effective.twitter}
        onRegen={onRegenTwitter}
        regenBusy={regenTwitterBusy}
        onPost={() => postToPlatform(effective.slug, 'twitter')}
        postingBusy={postState.twitter.posting}
        postResult={postState.twitter.result}
        postLabel="Post to X"
      />
      <SocialSection
        heading="LinkedIn Post"
        text={effective.linkedin}
        onRegen={onRegenLinkedin}
        regenBusy={regenLinkedinBusy}
        onPost={() => postToPlatform(effective.slug, 'linkedin')}
        postingBusy={postState.linkedin.posting}
        postResult={postState.linkedin.result}
        postLabel="Post to LinkedIn"
        tight
      />

      {effective.instagram && (
        <InstagramSection slug={effective.slug} caption={effective.instagram} carousel={effective.carousel} />
      )}
    </div>
  );
}

/** Instagram caption + carousel preview + download + mark-posted. */
function InstagramSection({
  slug,
  caption,
  carousel,
}: {
  slug: string;
  caption: string;
  carousel?: SocialContent['carousel'];
}) {
  const [copied, setCopied] = useState(false);
  // objectUrls[i] is either undefined (not yet fetched), null (loading),
  // 'error' (fetch failed for that slide), or a blob URL string (ready).
  const [objectUrls, setObjectUrls] = useState<(string | null | undefined | 'error')[]>([]);
  const [fetchErr, setFetchErr] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  // Track blob URLs created so we can revoke them on unmount.
  const urlsRef = useRef<string[]>([]);

  const slides = carousel?.slides ?? [];
  const total = slides.length;

  // Fetch all slide PNGs as blob URLs when this component mounts (or when
  // the slide count changes). Revoke previous URLs first.
  useEffect(() => {
    if (total === 0) return;

    // Initialise slots to null (loading).
    setObjectUrls(Array<null>(total).fill(null));
    setFetchErr(null);

    // Revoke any previously held URLs.
    for (const u of urlsRef.current) URL.revokeObjectURL(u);
    urlsRef.current = [];

    let cancelled = false;

    async function fetchAll() {
      const results: (string | null | 'error')[] = Array<null>(total).fill(null);
      for (let i = 0; i < total; i++) {
        if (cancelled) break;
        try {
          const url = await getObjectUrl(`/social/carousel/${encodeURIComponent(slug)}/${i}.png`);
          // Fix 1: if cleanup ran while the fetch was in flight, revoke
          // the newly-created blob URL immediately and bail - never push it.
          if (cancelled) {
            URL.revokeObjectURL(url);
            break;
          }
          urlsRef.current.push(url);
          results[i] = url;
          setObjectUrls([...results]);
        } catch (e) {
          console.error('fetchAll failed:', e instanceof Error ? e.message : String(e));
          if (!cancelled) {
            // Fix 4: mark only the failing slide as 'error' so the UI can
            // distinguish a load failure from an in-progress load.
            results[i] = 'error';
            setObjectUrls([...results]);
            setFetchErr(e instanceof Error ? e.message : String(e));
          }
        }
      }
    }

    void fetchAll();

    return () => {
      cancelled = true;
      for (const u of urlsRef.current) URL.revokeObjectURL(u);
      urlsRef.current = [];
    };
  }, [slug, total]);

  function copyCaption() {
    navigator.clipboard.writeText(caption).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function downloadAll() {
    setDownloading(true);
    for (let i = 0; i < total; i++) {
      const url = objectUrls[i];
      if (!url || url === 'error') continue;
      const a = document.createElement('a');
      a.href = url;
      a.download = `${slug}-ig-${i + 1}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
    setDownloading(false);
  }

  return (
    <div className="mb-6 last:mb-0">
      {/* Section heading */}
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-pink-600 dark:text-pink-400">Instagram</h4>
      </div>

      {/* Caption */}
      <div className="mb-3">
        <div className="flex items-center justify-between mb-1">
          <span className="text-micro uppercase tracking-wider text-muted">Caption</span>
          <button
            onClick={copyCaption}
            className="px-2 py-0.5 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
          >
            {copied ? 'Copied!' : 'Copy caption'}
          </button>
        </div>
        <textarea
          readOnly
          value={caption}
          rows={5}
          className="w-full bg-surface-100 rounded p-3 text-xs text-body font-mono leading-relaxed border border-line-1 resize-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-pink-500 focus-visible:ring-offset-1"
          aria-label="Instagram caption"
        />
      </div>

      {/* Carousel preview */}
      {total > 0 && (
        <div className="mb-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-micro uppercase tracking-wider text-muted">Carousel slides ({total})</span>
            <button
              onClick={downloadAll}
              disabled={downloading || objectUrls.every((u) => !u)}
              aria-label={downloading ? 'Downloading slides…' : 'Download all slides'}
              className="px-2 py-0.5 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
            >
              {downloading ? '…' : 'Download all'}
            </button>
          </div>

          {/* Fix 3: aria-live so placeholder→image transitions and errors are
              announced to screen readers without requiring assertive. */}
          <div aria-live="polite">
            {fetchErr && <p className="text-xs text-rose-600 dark:text-rose-400 mb-2">Slide load error: {fetchErr}</p>}

            <div
              className="flex gap-3 overflow-x-auto pb-2"
              role="list"
              aria-label={`Instagram carousel slides for ${slug}`}
            >
              {slides.map((slide, i) => {
                const url = objectUrls[i];
                const isError = url === 'error';
                const isLoading = url === null || url === undefined;
                return (
                  <div
                    key={`${slug}-${slide.index}`}
                    role="listitem"
                    className="flex-shrink-0 flex flex-col items-center gap-1"
                  >
                    {!isLoading && !isError && url ? (
                      <img
                        loading="lazy"
                        src={url}
                        alt={`Carousel slide ${i + 1} of ${total}: ${slide.headline}`}
                        className="w-40 h-40 object-cover rounded border border-line-1"
                      />
                    ) : (
                      // Fix 4: distinct aria-label for errored vs loading slides;
                      // inner visual span is aria-hidden since the div announces it.
                      <div
                        className="w-40 h-40 rounded border border-line-1 bg-surface-300 flex items-center justify-center"
                        aria-label={
                          isError ? `Slide ${i + 1} of ${total} failed to load` : `Loading slide ${i + 1} of ${total}`
                        }
                      >
                        <span aria-hidden="true" className="text-xs text-muted">
                          {isError ? 'err' : '…'}
                        </span>
                      </div>
                    )}
                    <span className="text-micro text-muted">
                      {i + 1}/{total}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Mark-posted row - reuses the same SchedulePanel which now includes instagram */}
      {/* (SchedulePanel already renders the instagram row via SocialPlatform union) */}
    </div>
  );
}

/** One platform's generated copy, with the link + carousel blocks split out so
 *  each can be copied separately - the link must go in the first comment/reply,
 *  not the post body, so you never paste it into the post itself. */
function SocialSection({
  heading,
  text,
  onRegen,
  regenBusy,
  tight,
  onPost,
  postingBusy,
  postResult,
  postLabel,
}: {
  heading: string;
  text: string;
  onRegen: () => void;
  regenBusy: boolean;
  /** Tighter line-height for paragraph-shaped copy (LinkedIn). Twitter
   *  threads are line-shaped and keep the looser height. */
  tight?: boolean;
  onPost?: () => void;
  postingBusy?: boolean;
  postResult?: { ok: boolean; postUrl?: string; error?: string } | null;
  postLabel?: string;
}) {
  const parts = splitSocial(text);
  const [copied, setCopied] = useState<string | null>(null);
  function copy(key: string, value: string) {
    navigator.clipboard.writeText(value).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  }
  return (
    <div className="mb-6 last:mb-0">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-brand-600 dark:text-brand-400">{heading}</h4>
        <div className="flex items-center gap-2">
          {onPost && (
            <button
              onClick={onPost}
              disabled={postingBusy}
              className="px-2 py-1 border border-emerald-200 dark:border-emerald-700 rounded text-xs hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50 transition-colors"
              title={postLabel}
            >
              {postingBusy ? '…' : (postLabel ?? 'Post')}
            </button>
          )}
          <button
            onClick={onRegen}
            disabled={regenBusy}
            className="text-micro uppercase tracking-wider text-muted hover:text-body dark:hover:text-inverted disabled:opacity-50 transition-colors"
            title="Regenerate"
          >
            {regenBusy ? '…' : 'Regenerate'}
          </button>
          <button
            onClick={() => copy('body', parts.body)}
            className="px-2 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300"
          >
            {copied === 'body' ? 'Copied!' : 'Copy post'}
          </button>
        </div>
      </div>
      <pre
        className={`bg-surface-100 dark:bg-surface-200 rounded p-3 text-xs text-body whitespace-pre-wrap font-mono ${
          tight ? 'leading-normal' : 'leading-relaxed'
        } max-h-80 overflow-y-auto`}
      >
        {parts.body}
      </pre>
      {parts.link && (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted">{parts.link.label}:</span>
          <span className="font-mono text-body break-all">{parts.link.value}</span>
          <button
            onClick={() => copy('link', parts.link!.value)}
            className="px-2 py-0.5 border border-sky-200 dark:border-sky-700 rounded hover:bg-sky-50 dark:hover:bg-sky-900/30"
          >
            {copied === 'link' ? 'Copied!' : 'Copy link'}
          </button>
        </div>
      )}
      {parts.carousel && (
        <div className="mt-2">
          <div className="flex items-center justify-between mb-1">
            <span className="text-micro uppercase tracking-wider text-muted">Carousel outline</span>
            <button
              onClick={() => copy('carousel', parts.carousel!)}
              className="px-2 py-0.5 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300"
            >
              {copied === 'carousel' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <pre className="bg-surface-100 rounded p-2 text-xs text-muted whitespace-pre-wrap font-mono max-h-40 overflow-y-auto">
            {parts.carousel}
          </pre>
        </div>
      )}

      {postResult && (
        <div
          className={`mt-2 text-xs ${postResult.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}
        >
          {postResult.ok
            ? `Posted! ${postResult.postUrl ? `(${postResult.postUrl})` : ''}`
            : `Post failed: ${postResult.error ?? 'unknown error'}`}
        </div>
      )}
    </div>
  );
}

/** A/B hook selection panel. Shows alternative opening hooks generated by the
 *  LLM and lets the operator pick one to regenerate the social copy with. */
function HookSelector({
  hooks,
  slug,
  onHookSelected,
  busy = false,
}: {
  hooks: string[];
  slug: string;
  onHookSelected: () => void;
  busy?: boolean;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const [regenerating, setRegenerating] = useState<number | null>(null);
  const [result, setResult] = useState<string | null>(null);

  async function applyHook(index: number) {
    setRegenerating(index);
    setResult(null);
    try {
      const r = await postJsonWithBody<{ ok: boolean; social: { twitter: string; linkedin: string } }>(
        `/social/${encodeURIComponent(slug)}/use-hook`,
        { hook: hooks[index] }
      );
      if (r.ok) {
        setSelected(index);
        onHookSelected();
        setResult('Social copy regenerated with this hook');
      } else {
        setResult('Failed to apply hook');
      }
    } catch (e) {
      setResult(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setRegenerating(null);
    }
  }

  // Reset when hooks change (e.g. after full regeneration)
  const hooksKey = hooks.join('|');
  useEffect(() => {
    setSelected(null);
    setResult(null);
  }, [hooksKey]);

  return (
    <div
      className={`mb-6 rounded border border-amber-200 dark:border-amber-700/50 bg-amber-50/50 dark:bg-amber-900/10 p-3 ${busy ? 'opacity-70' : ''}`}
    >
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-mini font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400">
          A/B Hook Selection
        </h4>
        {result && <span className="text-micro text-muted">{result}</span>}
      </div>
      <p className="text-micro text-muted mb-2">
        Pick an alternative opening hook. The social copy will be regenerated with the chosen angle as a strong
        preference.
      </p>
      <div className="space-y-1.5">
        {hooks.map((hook, i) => (
          <div
            key={`${slug}-${i}`}
            className={`flex items-start gap-2 p-2 rounded text-xs border cursor-pointer transition-colors ${
              selected === i
                ? 'bg-amber-100 dark:bg-amber-900/30 border-amber-400 dark:border-amber-600'
                : 'bg-white dark:bg-surface-100 border-line-1 hover:border-amber-300 dark:hover:border-amber-700'
            }`}
            onClick={() => void applyHook(i)}
          >
            <span
              className={`inline-flex items-center justify-center w-4 h-4 mt-0.5 rounded-full text-micro font-bold ${
                selected === i ? 'bg-amber-500 text-white' : 'bg-slate-200 dark:bg-surface-300 text-muted'
              }`}
            >
              {i + 1}
            </span>
            <span className="flex-1 text-body leading-relaxed">{hook}</span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                void applyHook(i);
              }}
              disabled={regenerating === i}
              className={`px-2 py-0.5 rounded text-micro border whitespace-nowrap ${
                selected === i
                  ? 'bg-amber-500 text-white border-amber-500'
                  : 'border-line-1 hover:bg-slate-100 dark:hover:bg-surface-300'
              } disabled:opacity-50`}
            >
              {regenerating === i ? '…' : selected === i ? 'Active' : 'Use'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Per-platform posting queue: status badge, scheduled time, approve/unapprove
 *  (twitter + linkedin only), and the manual mark-posted toggle for all three. */
function SchedulePanel({ slug, refreshTrigger = 0 }: { slug: string; refreshTrigger?: number }) {
  const [sched, setSched] = useState<SocialScheduleData | null>(null);
  const [busy, setBusy] = useState<SocialPlatform | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  // Controlled datetime-local values per platform so Approve always reads the
  // current typed value, not stale server state (bug fix: uncontrolled input
  // would silently discard a new time typed before clicking Approve).
  const [localTimes, setLocalTimes] = useState<Partial<Record<SocialPlatform, string>>>({});

  const loadSched = useCallback(async () => {
    try {
      const r = await getJson<{ schedule: SocialScheduleData | null }>(`/social-schedule/${encodeURIComponent(slug)}`);
      setSched(r.schedule);
      // Initialise controlled inputs from the freshly-loaded schedule so any
      // previously-saved times are reflected after a reload.
      if (r.schedule) {
        const times: Partial<Record<SocialPlatform, string>> = {};
        for (const p of ['twitter', 'linkedin', 'instagram'] as SocialPlatform[]) {
          times[p] = toLocalInput(r.schedule[p]?.scheduledAt);
        }
        setLocalTimes(times);
      }
    } catch (_catchErr) {
      console.error('SchedulePanel failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
      /* schedule is optional */
    }
  }, [slug]);

  useEffect(() => {
    void loadSched();
  }, [loadSched, refreshTrigger]);

  async function saveTime(platform: SocialPlatform, localValue: string) {
    setBusy(platform);
    setMsg(null);
    try {
      const scheduledAt = localValue ? new Date(localValue).toISOString() : '';
      const r = await postJsonWithBody<{ ok: boolean; schedule: SocialScheduleData }>(
        `/social-schedule/${encodeURIComponent(slug)}/${platform}`,
        { scheduledAt }
      );
      setSched(r.schedule);
      setMsg(localValue ? `${platform} time saved` : `${platform} time cleared`);
    } catch (e) {
      console.error('saveTime failed:', e instanceof Error ? e.message : String(e));
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function togglePosted(platform: SocialPlatform, current: ScheduleEntry['status']) {
    setBusy(platform);
    setMsg(null);
    try {
      const r =
        current === 'posted'
          ? await postJsonWithBody<{ ok: boolean; schedule: SocialScheduleData }>(
              `/social-schedule/${encodeURIComponent(slug)}/${platform}`,
              { status: 'pending' }
            )
          : await postJson<{ ok: boolean; schedule: SocialScheduleData }>(
              `/social-schedule/${encodeURIComponent(slug)}/${platform}/mark-posted`
            );
      setSched(r.schedule);
    } catch (e) {
      console.error('togglePosted failed:', e instanceof Error ? e.message : String(e));
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleApprove(platform: SocialPlatform) {
    setBusy(platform);
    setMsg(null);
    try {
      // Read the CURRENT controlled input value, not the stale server state.
      const localValue = localTimes[platform] ?? '';
      const scheduledAt = localValue ? new Date(localValue).toISOString() : undefined;
      const r = await approveSocialPlatform(slug, platform, scheduledAt);
      setSched(r.schedule as SocialScheduleData);
      setMsg(`${platform} approved`);
    } catch (e) {
      console.error('handleApprove failed:', e instanceof Error ? e.message : String(e));
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleUnapprove(platform: SocialPlatform) {
    setBusy(platform);
    setMsg(null);
    try {
      const r = await unapproveSocialPlatform(slug, platform);
      setSched(r.schedule as SocialScheduleData);
      setMsg(`${platform} unapproved`);
    } catch (e) {
      console.error('handleUnapprove failed:', e instanceof Error ? e.message : String(e));
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  const rows: SocialPlatform[] = ['twitter', 'linkedin', 'instagram'];

  return (
    <div className="mb-6 rounded border border-line-1 bg-surface-200/40 p-3">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-mini font-semibold uppercase tracking-wider text-muted">Posting queue</h4>
        {msg && <span className="text-micro text-muted">{msg}</span>}
      </div>
      <div className="space-y-3">
        {rows.map((platform) => {
          const entry = sched?.[platform];
          const status: ScheduleEntry['status'] = entry?.status ?? 'pending';
          const overdue =
            status === 'pending' && entry?.scheduledAt ? new Date(entry.scheduledAt).getTime() < Date.now() : false;
          const canAutoPost = platform === 'twitter' || platform === 'linkedin';

          return (
            <div key={platform} className="flex flex-wrap items-center gap-2 text-xs">
              <span className="w-16 uppercase text-muted">{platform}</span>

              {/* Status badge */}
              {status === 'posted' && entry?.postUrl ? (
                <a
                  href={entry.postUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={`px-1.5 py-0.5 rounded text-micro bg-emerald-50 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-700/50 underline underline-offset-2`}
                  aria-label={`${platform} posted - view post`}
                >
                  posted
                  {entry?.postedAt ? ` ${new Date(entry.postedAt).toLocaleDateString()}` : ''}
                </a>
              ) : (
                <span
                  className={`px-1.5 py-0.5 rounded text-micro ${
                    status === 'posted'
                      ? 'bg-emerald-50 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-700/50'
                      : status === 'approved'
                        ? 'bg-sky-50 dark:bg-sky-900/40 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-700/50'
                        : status === 'failed'
                          ? 'bg-rose-50 dark:bg-rose-900/40 text-rose-600 dark:text-rose-300 border border-rose-200 dark:border-rose-700/50'
                          : 'bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-700/40'
                  }`}
                  aria-label={`${platform} status: ${status}`}
                >
                  {status}
                  {entry?.postedAt ? ` ${new Date(entry.postedAt).toLocaleDateString()}` : ''}
                </span>
              )}

              {/* Failed: show error + attempts */}
              {status === 'failed' && (entry?.error ?? entry?.attempts != null) && (
                <span
                  className="text-micro text-rose-600 dark:text-rose-400 truncate max-w-[14rem]"
                  title={entry?.error ?? ''}
                >
                  {entry?.error ? `${entry.error}` : ''}
                  {entry?.attempts != null ? ` (attempt ${entry.attempts})` : ''}
                </span>
              )}

              {overdue && (
                <span className="px-1.5 py-0.5 rounded text-micro bg-rose-50 dark:bg-rose-900/40 text-rose-600 dark:text-rose-300 border border-rose-200 dark:border-rose-700/50">
                  overdue
                </span>
              )}

              {/* Approved hint */}
              {status === 'approved' && (
                <span className="text-micro text-sky-600 dark:text-sky-400">
                  {entry?.scheduledAt
                    ? `auto-post at ${new Date(entry.scheduledAt).toLocaleString()}`
                    : 'auto-post queued'}
                </span>
              )}

              <input
                type="datetime-local"
                value={localTimes[platform] ?? ''}
                onChange={(e) => setLocalTimes((prev) => ({ ...prev, [platform]: e.target.value }))}
                onBlur={(e) => void saveTime(platform, e.target.value)}
                disabled={busy === platform}
                aria-label={`${platform} planned post time (saved on blur)`}
                className="bg-surface-100 border border-line-1 rounded px-1.5 py-0.5 text-body disabled:opacity-50"
                title="Planned post time (saved on blur)"
              />

              {/* Approve / Unapprove - twitter + linkedin only */}
              {canAutoPost && (status === 'pending' || status === 'failed') && (
                <button
                  onClick={() => void handleApprove(platform)}
                  disabled={busy === platform}
                  aria-label={`Approve ${platform} for auto-posting`}
                  className="px-2 py-0.5 border border-sky-200 dark:border-sky-700 rounded hover:bg-sky-50 dark:hover:bg-sky-900/30 disabled:opacity-50"
                >
                  Approve
                </button>
              )}
              {canAutoPost && status === 'approved' && (
                <button
                  onClick={() => void handleUnapprove(platform)}
                  disabled={busy === platform}
                  aria-label={`Unapprove ${platform} - return to pending`}
                  className="px-2 py-0.5 border border-line-1 rounded hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
                >
                  Unapprove
                </button>
              )}

              {/* Manual mark-posted toggle - all platforms */}
              <button
                onClick={() => void togglePosted(platform, status)}
                disabled={busy === platform}
                aria-label={status === 'posted' ? `Mark ${platform} as pending` : `Mark ${platform} as posted`}
                className="px-2 py-0.5 border border-line-1 rounded hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
              >
                {status === 'posted' ? 'Mark pending' : 'Mark posted'}
              </button>

              <span className="text-micro text-muted">{bestTimeHint(platform)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
