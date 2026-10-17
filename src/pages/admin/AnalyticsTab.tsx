import { useCallback, useEffect, useState } from 'react';
import { getSocialAnalytics, saveSocialMetrics } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { errMessage } from '../../lib/log';
import type {
  SocialAnalyticsPost,
  SocialAnalyticsByType,
  SocialAnalyticsResponse,
  SocialPostMetrics,
} from './adminApi';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtNum(n: number | undefined): string {
  if (n == null) return '-';
  return n.toLocaleString();
}

/** Simple bar as a CSS-width div. `value` is already the max in the set. */
function EngagementBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="h-2 rounded bg-track overflow-hidden" style={{ width: '4rem' }} aria-hidden="true">
      <div className="h-full bg-brand-500 dark:bg-brand-400 rounded" style={{ width: `${pct}%` }} />
    </div>
  );
}

// ─── Manual-metrics form ─────────────────────────────────────────────────────

interface MetricsFormState {
  slug: string;
  platform: 'twitter' | 'linkedin' | 'instagram';
  impressions: string;
  likes: string;
  reposts: string;
  replies: string;
  clicks: string;
  postUrl: string;
}

const BLANK_FORM: MetricsFormState = {
  slug: '',
  platform: 'linkedin',
  impressions: '',
  likes: '',
  reposts: '',
  replies: '',
  clicks: '',
  postUrl: '',
};

function parseOptInt(s: string): number | undefined {
  const n = parseInt(s, 10);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function MetricsForm({ onSaved }: { onSaved: () => void }) {
  const [form, setForm] = useState<MetricsFormState>(BLANK_FORM);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function set(field: keyof MetricsFormState, value: string) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.slug.trim()) {
      setMsg('Slug is required.');
      return;
    }
    setBusy(true);
    setMsg(null);
    const metrics: SocialPostMetrics & { postUrl?: string } = {
      impressions: parseOptInt(form.impressions),
      likes: parseOptInt(form.likes),
      reposts: parseOptInt(form.reposts),
      replies: parseOptInt(form.replies),
      clicks: parseOptInt(form.clicks),
      postUrl: form.postUrl.trim() || undefined,
    };
    try {
      await saveSocialMetrics(form.slug.trim(), form.platform, metrics);
      setMsg('Saved.');
      setForm(BLANK_FORM);
      onSaved();
    } catch (err) {
      console.error('handleSubmit failed:', errMessage(err));
      setMsg(`Save failed: ${errMessage(err)}`);
    } finally {
      setBusy(false);
    }
  }

  const inputCls =
    'w-28 px-2 py-1 bg-white dark:bg-surface-200 border border-line-1 rounded text-sm text-heading disabled:opacity-50';

  return (
    <section aria-labelledby="manual-metrics-heading" className="rounded border border-line-1 p-4">
      <h2 id="manual-metrics-heading" className="text-sm font-semibold uppercase tracking-wider text-body mb-3">
        Add / update metrics manually
      </h2>
      <p className="text-xs text-muted mb-4">
        For LinkedIn and Instagram: read the numbers off the platform and enter them here. Twitter is auto-refreshed by
        the cron.
      </p>
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3">
        <div className="flex flex-wrap gap-3 items-end">
          {/* Slug */}
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Slug</span>
            <input
              type="text"
              value={form.slug}
              onChange={(e) => set('slug', e.target.value)}
              placeholder="my-case-study"
              disabled={busy}
              aria-label="Post slug"
              required
              className="w-44 px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            />
          </label>

          {/* Platform */}
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-muted mb-1">Platform</span>
            <select
              value={form.platform}
              onChange={(e) => set('platform', e.target.value as MetricsFormState['platform'])}
              disabled={busy}
              aria-label="Platform"
              className="px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
            >
              <option value="linkedin">LinkedIn</option>
              <option value="instagram">Instagram</option>
              <option value="twitter">Twitter / X</option>
            </select>
          </label>
        </div>

        {/* Metrics numbers */}
        <div className="flex flex-wrap gap-3 items-end">
          {(
            [
              { field: 'impressions', label: 'Impressions' },
              { field: 'likes', label: 'Likes' },
              { field: 'reposts', label: 'Reposts' },
              { field: 'replies', label: 'Replies' },
              { field: 'clicks', label: 'Clicks' },
            ] as Array<{ field: keyof MetricsFormState; label: string }>
          ).map(({ field, label }) => (
            <label key={field} className="block">
              <span className="block text-xs uppercase tracking-wider text-muted mb-1">{label}</span>
              <input
                type="number"
                min={0}
                value={form[field]}
                onChange={(e) => set(field, e.target.value)}
                disabled={busy}
                aria-label={label}
                className={inputCls}
              />
            </label>
          ))}
        </div>

        {/* Post URL */}
        <label className="block">
          <span className="block text-xs uppercase tracking-wider text-muted mb-1">Post URL (optional)</span>
          <input
            type="url"
            value={form.postUrl}
            onChange={(e) => set('postUrl', e.target.value)}
            placeholder="https://www.linkedin.com/posts/…"
            disabled={busy}
            aria-label="Post URL"
            className="w-full max-w-sm px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading disabled:opacity-50"
          />
        </label>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={busy}
            className="px-4 py-1.5 border border-line-2 rounded text-sm text-body hover:bg-surface-300 dark:hover:bg-surface-300 hover:text-heading dark:hover:text-white disabled:opacity-50 transition-colors"
          >
            {busy ? 'Saving…' : 'Save metrics'}
          </button>
          {msg && (
            <span className="text-xs font-mono text-muted" role="status">
              {msg}
            </span>
          )}
        </div>
      </form>
    </section>
  );
}

// ─── By-type summary table ────────────────────────────────────────────────────

function ByTypeTable({ rows }: { rows: SocialAnalyticsByType[] }) {
  const maxAvg = Math.max(...rows.map((r) => r.avgEngagement), 1);

  return (
    <section aria-labelledby="by-type-heading">
      <h2 id="by-type-heading" className="text-sm font-semibold uppercase tracking-wider text-body mb-3">
        What performs - by content type
      </h2>
      <div className="overflow-x-auto rounded border border-line-1">
        <DataTable
          columns={
            [
              {
                key: 'type',
                header: 'Type',
                sortValue: (row: (typeof rows)[number]) => row.type,
                render: (row) => <span className="font-mono text-xs uppercase text-body">{row.type}</span>,
              },
              {
                key: 'posts',
                header: 'Posts',
                align: 'right',
                sortValue: (row: (typeof rows)[number]) => row.posts,
                render: (row) => <span className="text-muted">{row.posts}</span>,
              },
              {
                key: 'avgEngagement',
                header: 'Avg engagement',
                align: 'right',
                sortValue: (row: (typeof rows)[number]) => row.avgEngagement,
                render: (row) => (
                  <div className="flex items-center justify-end gap-2">
                    <EngagementBar value={row.avgEngagement} max={maxAvg} />
                    <span className="text-heading tabular-nums">{row.avgEngagement.toFixed(1)}</span>
                  </div>
                ),
              },
              {
                key: 'totalEngagement',
                header: 'Total engagement',
                align: 'right',
                sortValue: (row: (typeof rows)[number]) => row.totalEngagement,
                render: (row) => <span className="tabular-nums text-body">{row.totalEngagement.toLocaleString()}</span>,
              },
              {
                key: 'totalImpressions',
                header: 'Total impressions',
                align: 'right',
                sortValue: (row: (typeof rows)[number]) => row.totalImpressions,
                render: (row) => <span className="tabular-nums text-body">{fmtNum(row.totalImpressions)}</span>,
              },
            ] as DataTableColumn<(typeof rows)[number]>[]
          }
          rows={rows}
          rowKey={(row) => row.type}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-200/40'}
        />
      </div>
    </section>
  );
}

// ─── Per-post table ───────────────────────────────────────────────────────────

function PostsTable({ posts }: { posts: SocialAnalyticsPost[] }) {
  return (
    <section aria-labelledby="posts-heading">
      <h2 id="posts-heading" className="text-sm font-semibold uppercase tracking-wider text-body mb-3">
        Per-post breakdown
      </h2>
      <div className="overflow-x-auto rounded border border-line-1">
        <DataTable
          columns={
            [
              {
                key: 'slug',
                header: 'Slug',
                sortValue: (p: (typeof posts)[number]) => p.slug,
                render: (p) => (
                  <a
                    href={`/blog/${p.slug}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-body hover:underline transition-colors"
                    aria-label={`Open blog post ${p.slug}`}
                  >
                    {p.slug}
                  </a>
                ),
              },
              {
                key: 'platform',
                header: 'Platform',
                sortValue: (p: (typeof posts)[number]) => p.platform,
                render: (p) => <span className="text-xs text-muted">{p.platform}</span>,
              },
              {
                key: 'engagement',
                header: 'Engagement',
                align: 'right',
                sortValue: (p: (typeof posts)[number]) => p.engagement,
                render: (p) => <span className="tabular-nums text-body">{p.engagement.toLocaleString()}</span>,
              },
              {
                key: 'likes',
                header: 'Likes',
                align: 'right',
                sortValue: (p: (typeof posts)[number]) => p.metrics.likes ?? 0,
                render: (p) => (
                  <span className="tabular-nums text-body">{(p.metrics.likes ?? 0).toLocaleString()}</span>
                ),
              },
              {
                key: 'reposts',
                header: 'Reposts',
                align: 'right',
                sortValue: (p: (typeof posts)[number]) => p.metrics.reposts ?? 0,
                render: (p) => (
                  <span className="tabular-nums text-body">{(p.metrics.reposts ?? 0).toLocaleString()}</span>
                ),
              },
              {
                key: 'replies',
                header: 'Replies',
                align: 'right',
                sortValue: (p: (typeof posts)[number]) => p.metrics.replies ?? 0,
                render: (p) => (
                  <span className="tabular-nums text-body">{(p.metrics.replies ?? 0).toLocaleString()}</span>
                ),
              },
              {
                key: 'impressions',
                header: 'Impressions',
                align: 'right',
                sortValue: (p: (typeof posts)[number]) => p.metrics.impressions ?? 0,
                render: (p) => <span className="tabular-nums text-body">{fmtNum(p.metrics.impressions ?? 0)}</span>,
              },
              {
                key: 'link',
                header: 'Post link',
                render: (p) =>
                  p.postUrl ? (
                    <a
                      href={p.postUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-brand-600 dark:text-brand-400 hover:underline"
                    >
                      view
                    </a>
                  ) : (
                    <span className="text-xs text-muted">-</span>
                  ),
              },
              {
                key: 'fetched',
                header: 'Fetched',
                sortValue: (p: (typeof posts)[number]) => p.fetchedAt,
                render: (p) => <span className="text-xs text-muted">{new Date(p.fetchedAt).toLocaleDateString()}</span>,
              },
            ] as DataTableColumn<(typeof posts)[number]>[]
          }
          rows={posts}
          rowKey={(p, i) => `${p.slug}-${p.platform}-${i}`}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-200/40'}
        />
      </div>
    </section>
  );
}

// ─── Main AnalyticsTab ────────────────────────────────────────────────────────

export default function AnalyticsTab() {
  const [data, setData] = useState<SocialAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getSocialAnalytics();
      setData(d);
    } catch (e) {
      console.error('AnalyticsTab failed:', errMessage(e));
      setError(errMessage(e, 'failed to load'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !data) return <p className="text-muted">Loading…</p>;

  if (error && !data)
    return (
      <div>
        <p className="text-rose-600 dark:text-rose-400 mb-2" role="alert">
          Failed to load: {error}
        </p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );

  const hasPosts = (data?.posts.length ?? 0) > 0;
  const hasByType = (data?.byType.length ?? 0) > 0;

  return (
    <div className="space-y-6">
      {/* Empty state */}
      {!hasPosts && (
        <p className="text-muted text-sm">
          No engagement data yet - auto-refreshes hourly for posted tweets; add LinkedIn/Instagram numbers manually
          using the form below.
        </p>
      )}

      {/* By-type table */}
      {hasByType && <ByTypeTable rows={data!.byType} />}

      {/* Per-post table */}
      {hasPosts && <PostsTable posts={data!.posts} />}

      {/* Manual entry form - always visible so operator can add numbers any time */}
      <MetricsForm onSaved={() => void load()} />
    </div>
  );
}
