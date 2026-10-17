import { useCallback, useEffect, useRef, useState } from 'react';
import { getJson, postJson, postJsonWithBody } from './adminApi';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { SearchFilter } from './SearchFilter';
import { errMessage } from '../../lib/log';

/**
 * Drafts queue - populated by the publisher when BLOG_APPROVAL_REQUIRED
 * is on. Each draft is a fully-generated post sitting in `drafts:<slug>`
 * awaiting an admin approve, reject, or regenerate. Approve copies the
 * post to the public index + refreshes RSS; reject deletes it; regenerate
 * re-runs postProcess in 'fix' mode (deterministic, no LLM) by default
 * or 'rewrite' mode (full LLM with optional admin notes) when the admin
 * needs a substantive rewrite.
 *
 * If the flag isn't set on the worker, the list will always be empty
 * (the publisher writes directly to `posts:` instead). The tab shows
 * a banner in that case so the admin isn't confused by an empty queue.
 */

interface DraftEntry {
  slug: string;
  title: string;
  type: string;
  excerpt: string;
  publishedAt: string;
  tags: string[];
  candidateId?: string;
}

interface DraftPreview {
  post: {
    slug: string;
    title: string;
    type: string;
    excerpt: string;
    publishedAt: string;
    body: string;
    tags: string[];
    iocs: Array<{ type: string; value: string }>;
    sources: Array<{ name: string; url: string }>;
    quality?: { total: number };
    linkVerification?: {
      checked: number;
      verified: number;
      unchecked: number;
      broken: number;
      brokenUrls?: string[];
    };
  };
  bodyHtml: string;
}

export default function DraftsTab() {
  const [drafts, setDrafts] = useState<DraftEntry[]>([]);
  const [approvalRequired, setApprovalRequired] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<DraftPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const latestPreviewReq = useRef<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getJson<{ drafts: DraftEntry[]; approvalRequired: boolean }>('/drafts');
      setDrafts(d.drafts);
      setApprovalRequired(d.approvalRequired);
    } catch (e) {
      console.error('DraftsTab failed:', errMessage(e));
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function loadPreview(slug: string) {
    latestPreviewReq.current = slug;
    setPreviewLoading(slug);
    setActionMsg(null);
    try {
      const p = await getJson<DraftPreview>(`/drafts/${encodeURIComponent(slug)}`);
      if (latestPreviewReq.current !== slug) return; // superseded by a newer click
      setPreview(p);
    } catch (e) {
      console.error('loadPreview failed:', errMessage(e));
      if (latestPreviewReq.current !== slug) return;
      setActionMsg(`preview failed: ${errMessage(e)}`);
    } finally {
      if (latestPreviewReq.current === slug) setPreviewLoading(null);
    }
  }

  async function approve(slug: string) {
    if (!window.confirm(`Approve and publish "${slug}"? This will go live immediately.`)) return;
    setActionBusy(`approve:${slug}`);
    setActionMsg(null);
    try {
      const r = await postJson<{ ok: boolean; slug: string; approvedAt: string }>(
        `/drafts/${encodeURIComponent(slug)}/approve`
      );
      setActionMsg(`approved ${r.slug} → /blog/${r.slug}`);
      // Close preview if we just approved the one being previewed.
      if (preview?.post.slug === slug) setPreview(null);
      await load();
    } catch (e) {
      console.error('approve failed:', errMessage(e));
      setActionMsg(`approve failed: ${errMessage(e)}`);
    } finally {
      setActionBusy(null);
    }
  }

  async function reject(slug: string) {
    if (!window.confirm(`Reject and delete draft "${slug}"? This cannot be undone.`)) return;
    setActionBusy(`reject:${slug}`);
    setActionMsg(null);
    try {
      await postJson(`/drafts/${encodeURIComponent(slug)}/reject`);
      setActionMsg(`rejected ${slug}`);
      if (preview?.post.slug === slug) setPreview(null);
      await load();
    } catch (e) {
      console.error('reject failed:', errMessage(e));
      setActionMsg(`reject failed: ${errMessage(e)}`);
    } finally {
      setActionBusy(null);
    }
  }

  /**
   * Regenerate a draft in place. Two modes:
   *  - 'fix' (default, no LLM): runs the existing body back through
   *    postProcess. Auto-linkifies recognised publisher labels in the
   *    References section, drops disallowed URLs, refreshes QA. Free.
   *  - 'rewrite' (LLM): re-issues generatePost with optional admin
   *    `notes` injected into the prompt. Costs one LLM call.
   * On success, refreshes the preview panel with the new body so the
   * admin sees exactly what changed.
   */
  async function regenerate(slug: string, mode: 'fix' | 'rewrite', notes?: string) {
    const verb = mode === 'fix' ? 'Regenerate (fix)' : 'Regenerate (rewrite)';
    const confirmMsg =
      mode === 'fix'
        ? `Run postProcess on "${slug}"? No LLM call - auto-linkifies References and refreshes QA.`
        : `Regenerate "${slug}" with the LLM? This will cost one inference call${notes ? ' and use your notes' : ''}.`;
    if (!window.confirm(confirmMsg)) return;
    setActionBusy(`regen:${slug}`);
    setActionMsg(null);
    try {
      const r = await postJsonWithBody<{
        ok: boolean;
        slug: string;
        title: string;
        body: string;
        bodyHtml: string;
        iocs: DraftPreview['post']['iocs'];
        qa?: DraftPreview['post']['quality'];
        changed: boolean;
        mode: 'fix' | 'rewrite';
        error?: string;
        message?: string;
      }>(`/drafts/${encodeURIComponent(slug)}/regenerate`, { mode, notes });
      if (!r.ok) {
        setActionMsg(`${verb} failed: ${r.message ?? r.error ?? 'unknown error'}`);
        return;
      }
      setActionMsg(
        r.changed
          ? `${verb} done: ${r.slug} (body updated, ${r.qa ? `QA ${r.qa.total}` : 'no QA'})`
          : `${verb} done: no changes needed`
      );
      // If the regen produced a different slug (LLM rewrite can rename),
      // close the current preview and reload the list so the new slug
      // appears in the table. Otherwise refresh the in-place preview
      // with the new body.
      if (preview?.post.slug === slug) {
        if (r.slug !== slug) {
          setPreview(null);
        } else {
          setPreview({
            post: {
              ...preview.post,
              slug: r.slug,
              title: r.title,
              body: r.body,
              iocs: r.iocs,
              // Include fresh QA score so DraftPreviewPanel doesn't show the
              // pre-regen total after a successful regenerate.
              quality: r.qa ?? preview.post.quality,
            },
            bodyHtml: r.bodyHtml,
          });
        }
      }
      await load();
    } catch (e) {
      console.error('handler failed:', errMessage(e));
      setActionMsg(`${verb} failed: ${errMessage(e)}`);
    } finally {
      setActionBusy(null);
    }
  }

  if (loading) return <p className="text-muted">Loading…</p>;
  if (error)
    return (
      <div>
        <p className="text-rose-400 mb-2">Failed to load: {error}</p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );

  return (
    <div>
      {/* Gate-mode banner - explains the tab's purpose differently
          depending on whether BLOG_APPROVAL_REQUIRED is on or off. */}
      {approvalRequired === false && (
        <div className="mb-4 rounded border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          <strong>Approval gate is OFF.</strong> The publisher is auto-publishing every post directly to /blog. To
          enable human review, set <code className="font-mono">BLOG_APPROVAL_REQUIRED=true</code> on the worker (
          <code className="font-mono">wrangler secret put BLOG_APPROVAL_REQUIRED</code>) and the next cron-triggered
          publish will land here instead.
        </div>
      )}
      {approvalRequired === true && (
        <div className="mb-4 rounded border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/30 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
          <strong>Approval gate is ON.</strong> New publisher runs write drafts here; nothing reaches /blog until you
          click Approve.
        </div>
      )}

      {actionMsg && (
        <div className="mb-4 rounded border border-line-1 bg-surface-100 px-3 py-2 text-xs font-mono text-body">
          {actionMsg}
        </div>
      )}

      {drafts.length === 0 ? (
        <p className="text-muted">No drafts pending.</p>
      ) : (
        <SearchFilter items={drafts} placeholder="Filter drafts…">
          {(filtered) => (
            <div className="overflow-x-auto">
              <DataTable
                columns={
                  [
                    {
                      key: 'type',
                      header: 'Type',
                      sortValue: (d: (typeof filtered)[number]) => d.type,
                      render: (d) => <span className="text-muted uppercase text-xs">{d.type}</span>,
                    },
                    {
                      key: 'title',
                      header: 'Title',
                      sortValue: (d: (typeof filtered)[number]) => d.title,
                      render: (d) => <span className="text-heading">{d.title}</span>,
                    },
                    {
                      key: 'generated',
                      header: 'Generated',
                      sortValue: (d: (typeof filtered)[number]) => d.publishedAt,
                      render: (d) => (
                        <span className="text-muted text-xs whitespace-nowrap">
                          {new Date(d.publishedAt).toLocaleString()}
                        </span>
                      ),
                    },
                    {
                      key: 'slug',
                      header: 'Slug',
                      sortValue: (d: (typeof filtered)[number]) => d.slug,
                      render: (d) => <span className="font-mono text-xs text-muted break-all">{d.slug}</span>,
                    },
                    {
                      key: 'actions',
                      header: 'Actions',
                      render: (d) => {
                        const isPreviewing = preview?.post.slug === d.slug;
                        const previewBusy = previewLoading === d.slug;
                        const approveBusy = actionBusy === `approve:${d.slug}`;
                        const rejectBusy = actionBusy === `reject:${d.slug}`;
                        return (
                          <div className="flex flex-wrap gap-1.5">
                            <button
                              onClick={() => (isPreviewing ? setPreview(null) : void loadPreview(d.slug))}
                              disabled={previewBusy}
                              className="px-2 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
                            >
                              {previewBusy ? '…' : isPreviewing ? 'Hide' : 'Preview'}
                            </button>
                            <button
                              onClick={() => void approve(d.slug)}
                              disabled={approveBusy || rejectBusy}
                              className="px-2 py-1 border border-emerald-200 dark:border-emerald-800 rounded text-xs text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50"
                            >
                              {approveBusy ? '…' : 'Approve'}
                            </button>
                            <button
                              onClick={() => void reject(d.slug)}
                              disabled={approveBusy || rejectBusy}
                              className="px-2 py-1 border border-rose-200 dark:border-rose-900 rounded text-xs text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50"
                            >
                              {rejectBusy ? '…' : 'Reject'}
                            </button>
                          </div>
                        );
                      },
                    },
                  ] as DataTableColumn<(typeof filtered)[number]>[]
                }
                rows={filtered}
                rowKey={(d) => d.slug}
              />
            </div>
          )}
        </SearchFilter>
      )}

      {preview && (
        <DraftPreviewPanel
          preview={preview}
          onClose={() => setPreview(null)}
          onApprove={() => void approve(preview.post.slug)}
          onReject={() => void reject(preview.post.slug)}
          onRegenerate={(mode, notes) => void regenerate(preview.post.slug, mode, notes)}
          actionBusy={actionBusy}
        />
      )}
    </div>
  );
}

function DraftPreviewPanel({
  preview,
  onClose,
  onApprove,
  onReject,
  onRegenerate,
  actionBusy,
}: {
  preview: DraftPreview;
  onClose: () => void;
  onApprove: () => void;
  onReject: () => void;
  onRegenerate: (mode: 'fix' | 'rewrite', notes?: string) => void;
  actionBusy: string | null;
}) {
  const { post, bodyHtml } = preview;
  const approveBusy = actionBusy === `approve:${post.slug}`;
  const rejectBusy = actionBusy === `reject:${post.slug}`;
  const regenBusy = actionBusy === `regen:${post.slug}`;

  // Inline editing state
  const [editing, setEditing] = useState(false);
  const [editTitle, setEditTitle] = useState(post.title);
  const [editBody, setEditBody] = useState(post.body);
  const [saving, setSaving] = useState(false);

  // Re-sanitize the server-rendered HTML in the browser before injecting it -
  // defense-in-depth matching the public BlogPost path, rather than trusting
  // the server regex sanitizer as the only layer. DOMPurify is loaded lazily
  // (no static isomorphic-dompurify import per the project lint rule).
  const [safeHtml, setSafeHtml] = useState('');
  useEffect(() => {
    let cancelled = false;
    void import('isomorphic-dompurify').then(({ default: DOMPurify }) => {
      if (!cancelled) {
        setSafeHtml(
          DOMPurify.sanitize(bodyHtml ?? '', {
            ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|#|\/):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
          })
        );
      }
    });
    return () => {
      cancelled = true;
    };
  }, [bodyHtml]);

  // Reset edit state when preview changes
  useEffect(() => {
    setEditTitle(post.title);
    setEditBody(post.body);
    setEditing(false);
  }, [post.title, post.body]);

  async function saveEdit() {
    setSaving(true);
    try {
      const r = await postJsonWithBody<{
        ok: boolean;
        slug: string;
        body: string;
        bodyHtml: string;
        qa?: { total: number };
      }>(`/drafts/${encodeURIComponent(post.slug)}/edit`, { title: editTitle, body: editBody });
      if (r.ok) {
        setEditing(false);
        // Re-fetch the draft preview to get fresh QA + rendered HTML
        const fresh = await getJson<DraftPreview>(`/drafts/${encodeURIComponent(post.slug)}`);
        if (fresh) {
          Object.assign(preview, fresh);
        }
      }
    } catch (e) {
      console.error('saveEdit failed:', errMessage(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mt-6 rounded border border-line-1 p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-body">Preview</h3>
          <p className="text-xs text-muted mt-0.5">
            <span className="font-mono">{post.slug}</span> · type <span className="uppercase">{post.type}</span>
            {post.quality?.total !== undefined && <> · quality {post.quality.total}</>}
            {post.iocs.length > 0 && <> · {post.iocs.length} IOCs</>}
            {post.sources.length > 0 && <> · {post.sources.length} sources</>}
          </p>
          {post.linkVerification && <LinkVerifyBadge lv={post.linkVerification} />}
        </div>
        <div className="flex items-center gap-2">
          {!editing && (
            <button
              onClick={() => setEditing(true)}
              className="text-xs text-muted hover:text-heading dark:hover:text-inverted"
            >
              Edit
            </button>
          )}
          <button
            onClick={onClose}
            className="text-xs text-muted hover:text-heading dark:hover:text-inverted transition-colors"
          >
            Close
          </button>
        </div>
      </div>

      {editing ? (
        <div className="mb-4 space-y-3">
          <div>
            <label className="block text-xs uppercase tracking-wider text-muted mb-1">Title</label>
            <input
              type="text"
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              className="w-full px-2 py-1 bg-surface-100 border border-line-1 rounded text-sm text-heading"
            />
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wider text-muted mb-1">Body (markdown)</label>
            <textarea
              value={editBody}
              onChange={(e) => setEditBody(e.target.value)}
              rows={20}
              className="w-full bg-surface-100 border border-line-1 rounded p-3 text-xs font-mono text-body leading-relaxed resize-y"
            />
          </div>
        </div>
      ) : (
        <>
          <h1 className="text-xl font-bold text-heading mb-1">{post.title}</h1>
          <p className="text-sm text-muted mb-4">
            <span className="font-mono text-micro uppercase tracking-wider text-muted mr-1.5">Excerpt</span>
            {post.excerpt}
          </p>
          <div
            className={
              'mb-4 bg-white dark:bg-surface-100 border border-line-1 rounded p-4 max-h-[60vh] overflow-y-auto text-sm leading-relaxed text-body ' +
              '[&_h1]:text-xl [&_h1]:font-bold [&_h1]:text-slate-900 dark:[&_h1]:text-slate-100 [&_h1]:mt-4 [&_h1]:mb-2 ' +
              '[&_h2]:text-lg [&_h2]:font-bold [&_h2]:text-slate-900 dark:[&_h2]:text-slate-100 [&_h2]:mt-5 [&_h2]:mb-2 ' +
              '[&_h3]:text-base [&_h3]:font-semibold [&_h3]:text-slate-900 dark:[&_h3]:text-slate-100 [&_h3]:mt-4 [&_h3]:mb-2 ' +
              '[&_p]:mb-3 ' +
              '[&_a]:text-brand-600 dark:[&_a]:text-brand-400 [&_a]:underline [&_a:hover]:text-brand-700 dark:[&_a:hover]:text-brand-300 ' +
              '[&_ul]:list-disc [&_ul]:pl-5 [&_ul]:mb-3 ' +
              '[&_ol]:list-decimal [&_ol]:pl-5 [&_ol]:mb-3 ' +
              '[&_li]:mb-1 ' +
              '[&_code]:font-mono [&_code]:text-[0.85em] [&_code]:bg-slate-100 dark:[&_code]:bg-slate-900 [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded ' +
              '[&_pre]:bg-slate-100 dark:[&_pre]:bg-slate-900 [&_pre]:p-3 [&_pre]:rounded [&_pre]:overflow-x-auto [&_pre]:mb-3 ' +
              '[&_strong]:text-slate-800 dark:[&_strong]:text-slate-100 [&_strong]:font-semibold ' +
              '[&_blockquote]:border-l-2 [&_blockquote]:border-slate-200 dark:[&_blockquote]:border-slate-700 [&_blockquote]:pl-3 [&_blockquote]:text-slate-500 dark:[&_blockquote]:text-muted [&_blockquote]:my-3'
            }
            dangerouslySetInnerHTML={{ __html: safeHtml }}
          />
        </>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {editing ? (
          <>
            <button
              onClick={() => void saveEdit()}
              disabled={saving}
              className="px-3 py-1.5 border border-brand-500 rounded text-sm text-on-fill bg-brand-500 hover:bg-brand-600 disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            <button
              onClick={() => {
                setEditing(false);
                setEditTitle(post.title);
                setEditBody(post.body);
              }}
              disabled={saving}
              className="px-3 py-1.5 border border-line-2 rounded text-sm text-body hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            <button
              onClick={onApprove}
              disabled={approveBusy || rejectBusy}
              className="px-3 py-1.5 border border-emerald-200 dark:border-emerald-700 rounded text-sm text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50 transition-colors"
            >
              {approveBusy ? 'Approving…' : 'Approve & publish'}
            </button>
            <button
              onClick={onReject}
              disabled={approveBusy || rejectBusy || !!regenBusy}
              className="px-3 py-1.5 border border-rose-200 dark:border-rose-900 rounded text-sm text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50 transition-colors"
            >
              {rejectBusy ? 'Rejecting…' : 'Reject & delete'}
            </button>
            <RegenInline
              busy={regenBusy}
              disabled={approveBusy || rejectBusy || !!regenBusy}
              onRegen={(mode, notes) => onRegenerate(mode, notes)}
            />
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Reference-link verification badge. Shows how many citations resolved
 * live (verified), how many were kept on the benefit of the doubt
 * (unchecked - a WAF block / 5xx / timeout, NOT proof the page is gone),
 * and how many were confirmed dead and pruned before publish (broken).
 * The broken URLs are listed in a tooltip so the admin can see exactly
 * what was dropped.
 */
function LinkVerifyBadge({
  lv,
}: {
  lv: { checked: number; verified: number; unchecked: number; broken: number; brokenUrls?: string[] };
}) {
  const pill = 'px-1.5 py-0.5 rounded border text-micro font-mono ';
  return (
    <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
      <span className="text-micro uppercase tracking-wider text-muted mr-0.5">Links</span>
      <span
        className={pill + 'border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300'}
        title={`${lv.verified} of ${lv.checked} reference URLs resolved live (2xx)`}
      >
        {lv.verified} verified
      </span>
      {lv.unchecked > 0 && (
        <span
          className={pill + 'border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300'}
          title={`${lv.unchecked} URL(s) could not be confirmed dead (403/429/5xx/timeout) and were kept on the benefit of the doubt. Spot-check these.`}
        >
          {lv.unchecked} unchecked
        </span>
      )}
      {lv.broken > 0 && (
        <span
          className={pill + 'border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300'}
          title={`Pruned before publish:\n${(lv.brokenUrls ?? []).join('\n')}`}
        >
          {lv.broken} broken (pruned)
        </span>
      )}
    </div>
  );
}

/**
 * Inline regenerate controls for the preview panel. Smaller than the
 * table-row regenerate menu because the preview footer has less horizontal
 * space; the textarea is hidden behind a toggle so the row stays tight
 * until the admin actively opts into a rewrite.
 */
function RegenInline({
  busy,
  disabled,
  onRegen,
}: {
  busy: boolean;
  disabled: boolean;
  onRegen: (mode: 'fix' | 'rewrite', notes?: string) => void;
}) {
  const [showNotes, setShowNotes] = useState(false);
  const [notes, setNotes] = useState('');
  return (
    <div className="flex flex-col gap-1.5 flex-1 min-w-[260px]">
      <div className="flex gap-1.5">
        <button
          onClick={() => onRegen('fix')}
          disabled={disabled}
          className="px-3 py-1.5 border border-emerald-200 dark:border-emerald-800 rounded text-sm text-emerald-700 dark:text-emerald-300 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 disabled:opacity-50"
          title="Run postProcess (no LLM call) - auto-linkify References, refresh QA"
        >
          {busy ? '…' : 'Regen (fix)'}
        </button>
        <button
          onClick={() => setShowNotes((s) => !s)}
          disabled={disabled}
          className="px-3 py-1.5 border border-amber-200 dark:border-amber-700 rounded text-sm text-amber-700 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-900/30 disabled:opacity-50"
        >
          {showNotes ? 'Cancel rewrite' : 'Regen (rewrite)…'}
        </button>
      </div>
      {showNotes && (
        <div className="flex flex-col gap-1.5">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Admin notes for the rewrite (e.g. add an attack-flow chart instead of the Sigma rule)"
            rows={3}
            className="w-full bg-surface-300 border border-line-1 rounded px-2 py-1 text-heading text-xs font-mono"
          />
          <button
            onClick={() => {
              onRegen('rewrite', notes);
              setNotes('');
              setShowNotes(false);
            }}
            disabled={disabled}
            className="self-start px-3 py-1 border border-amber-200 dark:border-amber-700 rounded text-xs text-amber-700 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-900/30 disabled:opacity-50"
          >
            Send to LLM
          </button>
        </div>
      )}
    </div>
  );
}
