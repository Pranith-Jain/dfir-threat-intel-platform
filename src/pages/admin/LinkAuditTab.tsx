import { useState } from 'react';
import { getJson, postJson } from './adminApi';
import { errMessage } from '../../lib/log';

interface AuditPost {
  slug: string;
  title: string;
  type: string;
  checked: number;
  verified: number;
  unchecked: number;
  broken: number;
  brokenUrls: string[];
  truncated?: boolean;
  statuses?: Record<string, string>;
}

interface AuditResult {
  scanned: number;
  checked: number;
  verified: number;
  unchecked: number;
  broken: number;
  posts: AuditPost[];
  nextAfter?: string;
  done: boolean;
}

interface FixResult {
  ok: boolean;
  fixed: boolean;
  backedOff: boolean;
  droppedSources: string[];
  droppedRefBullets: number;
  verified: number;
  unchecked: number;
  broken: number;
}

function hostOf(u: string): string {
  try {
    return new URL(u).hostname.replace(/^www\./, '');
  } catch {
    return u;
  }
}

export default function LinkAuditTab() {
  const [audits, setAudits] = useState<AuditPost[]>([]);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<{
    checked: number;
    verified: number;
    unchecked: number;
    broken: number;
  } | null>(null);
  const [fixing, setFixing] = useState<Record<string, boolean>>({});
  const [fixResults, setFixResults] = useState<Record<string, FixResult>>({});
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  async function runAudit() {
    setLoading(true);
    setAudits([]);
    setFixResults({});
    setActionMsg(null);
    const allPosts: AuditPost[] = [];
    const totals = { checked: 0, verified: 0, unchecked: 0, broken: 0 };
    let after = '';
    try {
      // Page through posts in budgeted passes until all are scanned.
      for (;;) {
        const r = await getJson<AuditResult>(`/links/audit${after ? `?after=${after}` : ''}`);
        for (const p of r.posts) allPosts.push(p);
        totals.checked += r.checked;
        totals.verified += r.verified;
        totals.unchecked += r.unchecked;
        totals.broken += r.broken;
        setAudits([...allPosts]);
        setSummary({ ...totals });
        if (r.done) break;
        after = r.nextAfter ?? '';
      }
    } catch (e) {
      setActionMsg(errMessage(e, 'audit failed'));
    } finally {
      setLoading(false);
    }
  }

  async function fixPost(slug: string) {
    setFixing((prev) => ({ ...prev, [slug]: true }));
    try {
      const r = await postJson<FixResult>(`/links/${encodeURIComponent(slug)}/audit-fix`);
      setFixResults((prev) => ({ ...prev, [slug]: r }));
      setActionMsg(r.fixed ? `Fixed ${slug} — ${r.broken} broken link(s) pruned` : `No broken links found in ${slug}`);
      // Remove the post from the audit list (now fixed) or update counts.
      setAudits((prev) => prev.filter((a) => a.slug !== slug));
    } catch (e) {
      setActionMsg(errMessage(e, `fix failed for ${slug}`));
    } finally {
      setFixing((prev) => ({ ...prev, [slug]: false }));
    }
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <button
          onClick={() => void runAudit()}
          disabled={loading}
          className="px-3 py-1.5 border border-amber-200 dark:border-amber-700/60 text-amber-700 dark:text-amber-300 rounded text-sm hover:bg-amber-50 dark:hover:bg-amber-900/30 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Scanning…' : 'Audit all posts'}
        </button>
        {summary && (
          <span className="text-xs font-mono text-muted">
            {summary.checked} checked — <span className="text-emerald-600">{summary.verified} ok</span> —{' '}
            <span className="text-muted">{summary.unchecked} unchecked</span> —{' '}
            <span className="text-rose-600">{summary.broken} broken</span>
          </span>
        )}
        {actionMsg && <span className="text-xs font-mono text-muted">{actionMsg}</span>}
      </div>

      {audits.length === 0 && !loading && (
        <p className="text-muted text-sm">
          Click "Audit all posts" to deep-verify every citation (soft-404 title sniff ON). Scans in budgeted passes —
          free-plan safe.
        </p>
      )}

      {audits.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted border-b border-line-1">
              <tr>
                <th className="py-2 pr-4">Post</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4 text-right">Checked</th>
                <th className="py-2 pr-4 text-right">Verified</th>
                <th className="py-2 pr-4 text-right">Unchecked</th>
                <th className="py-2 pr-4 text-right">Broken</th>
                <th className="py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {audits.map((a) => (
                <tr key={a.slug} className="border-b border-line-1">
                  <td className="py-2 pr-4 text-heading max-w-md truncate" title={a.title}>
                    <a
                      href={`/blog/${a.slug}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:underline text-brand-600 dark:text-brand-400"
                    >
                      {a.title.length > 60 ? a.title.slice(0, 60) + '…' : a.title}
                    </a>
                  </td>
                  <td className="py-2 pr-4 text-muted uppercase text-xs">{a.type}</td>
                  <td className="py-2 pr-4 text-right text-body tabular-nums">{a.checked}</td>
                  <td className="py-2 pr-4 text-right text-emerald-600 dark:text-emerald-400 tabular-nums">
                    {a.verified}
                  </td>
                  <td className="py-2 pr-4 text-right text-muted tabular-nums">{a.unchecked}</td>
                  <td className="py-2 pr-4 text-right tabular-nums">
                    {a.broken > 0 ? (
                      <span className="text-rose-600 dark:text-rose-400 font-medium">{a.broken}</span>
                    ) : (
                      <span className="text-muted">0</span>
                    )}
                    {a.brokenUrls.length > 0 && (
                      <div className="text-xs text-rose-500 dark:text-rose-400 text-left mt-1 max-w-sm">
                        {a.brokenUrls.map((u) => (
                          <div key={u} className="truncate" title={u}>
                            {hostOf(u)}
                          </div>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-2 whitespace-nowrap">
                    {a.broken > 0 && (
                      <button
                        onClick={() => void fixPost(a.slug)}
                        disabled={fixing[a.slug]}
                        className="px-2 py-1 border border-rose-200 dark:border-rose-700/60 text-rose-700 dark:text-rose-300 rounded text-xs hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50 transition-colors"
                      >
                        {fixing[a.slug] ? 'Fixing…' : 'Fix'}
                      </button>
                    )}
                    {fixResults[a.slug] && (
                      <span className="ml-2 text-xs font-mono text-emerald-600 dark:text-emerald-400">
                        {fixResults[a.slug]!.fixed ? 'Fixed' : 'Clean'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
