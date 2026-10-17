import { useCallback, useEffect, useState } from 'react';
import { getJson, postJson, postJsonWithBody } from './adminApi';
import { SearchFilter } from './SearchFilter';
import { errMessage } from '../../lib/log';

interface Candidate {
  key: string;
  type: string;
  title: string;
  rationale: string;
  score: number;
  evidence: Record<string, unknown>;
  discoveredAt: string;
  status: string;
}

/** Pull up to 3 source URLs out of a candidate's evidence so an operator can
 *  verify provenance before approving. Mirrors the shapes the backend
 *  discovery runners store (urls[], sources[], victims[].url, sourceUrl,
 *  cveId). The evidence is already loaded with each candidate; it was just
 *  never surfaced. */
function sourceLinksFrom(ev: Record<string, unknown>): string[] {
  const urls = new Set<string>();
  const push = (u: unknown) => {
    if (typeof u === 'string' && /^https?:\/\//.test(u)) urls.add(u);
  };
  push(ev.url); // breach, aisec, vulncheck, euvd, phishunt
  if (Array.isArray(ev.urls)) ev.urls.forEach(push); // cve, actor
  if (Array.isArray(ev.sources)) ev.sources.forEach(push); // agentic-trends, briefing, platform-data
  push(ev.sourceUrl);
  if (Array.isArray(ev.victims)) {
    for (const v of ev.victims) {
      if (v && typeof v === 'object') push((v as Record<string, unknown>).url);
    }
  }
  if (typeof ev.cveId === 'string') {
    const autoUrl = `https://nvd.nist.gov/vuln/detail/${ev.cveId}`;
    if (!urls.has(autoUrl)) urls.add(autoUrl);
  }
  return Array.from(urls).slice(0, 3);
}

function hostOf(u: string): string {
  try {
    return new URL(u).hostname.replace(/^www\./, '');
  } catch (_catchErr) {
    console.error('hostOf failed:', errMessage(_catchErr));
    return u;
  }
}

type LinkStatus = 'ok' | 'broken' | 'unchecked';

function statusBadge(status: LinkStatus): string {
  switch (status) {
    case 'ok':
      return '●';
    case 'broken':
      return '○';
    case 'unchecked':
      return '?';
  }
}

function statusColor(status: LinkStatus): string {
  switch (status) {
    case 'ok':
      return 'text-emerald-500';
    case 'broken':
      return 'text-rose-500';
    case 'unchecked':
      return 'text-muted';
  }
}

function statusTitle(status: LinkStatus): string {
  switch (status) {
    case 'ok':
      return 'Link verified';
    case 'broken':
      return 'Link returned error';
    case 'unchecked':
      return 'Link status not checked';
  }
}

function linkStatusFor(ev: Record<string, unknown>, url: string): LinkStatus {
  const statuses = (ev as Record<string, unknown>).sourceLinkStatuses;
  if (statuses && typeof statuses === 'object') {
    const s = (statuses as Record<string, string>)[url];
    if (s === 'ok' || s === 'broken') return s;
  }
  return 'unchecked';
}

export default function PendingTab() {
  const [pending, setPending] = useState<Candidate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getJson<{ pending: Candidate[] }>('/candidates');
      setPending(d.pending);
    } catch (e) {
      console.error('PendingTab failed:', errMessage(e));
      setError(errMessage(e, 'failed to load'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function approve(id: string, type: string) {
    setActionMsg(null);
    try {
      const res = await postJsonWithBody<{ ok: boolean; result: Record<string, unknown>; errors?: string[] }>(
        `/candidates/${encodeURIComponent(id)}/generate?type=${encodeURIComponent(type)}`,
        { formats: ['blog'] }
      );
      if (res.ok) {
        setActionMsg(`Blog draft created from ${id}`);
      } else {
        setActionMsg(`approve failed: ${(res.errors ?? ['unknown']).join(', ')}`);
      }
      await load();
    } catch (e) {
      console.error('approve failed:', errMessage(e));
      setActionMsg(`approve failed: ${errMessage(e)}`);
    }
  }

  async function skip(id: string, type: string) {
    setActionMsg(null);
    try {
      await postJson(`/candidates/${encodeURIComponent(id)}/skip?type=${encodeURIComponent(type)}`);
      setActionMsg(`Skipped ${id}`);
      await load();
    } catch (e) {
      console.error('skip failed:', errMessage(e));
      setActionMsg(`skip failed: ${errMessage(e)}`);
    }
  }

  async function clearAll() {
    if (!window.confirm('Clear all pending candidates? They will be suppressed for 30 days.')) return;
    setActionMsg(null);
    try {
      const res = await postJson<{ cleared: number }>('/candidates/skip-all');
      setActionMsg(`Cleared ${res.cleared} candidate(s)`);
      await load();
    } catch (e) {
      console.error('clearAll failed:', errMessage(e));
      setActionMsg(`clear all failed: ${errMessage(e)}`);
    }
  }

  if (loading) return <p className="text-muted">Loading…</p>;
  if (error)
    return (
      <div>
        <p className="text-rose-700 dark:text-rose-400 mb-2">Failed to load: {error}</p>
        <button onClick={() => void load()} className="px-3 py-1 border border-line-1 rounded text-sm">
          Retry
        </button>
      </div>
    );
  if (pending.length === 0)
    return (
      <div>
        {actionMsg && <p className="text-xs font-mono text-muted mb-2">{actionMsg}</p>}
        <p className="text-muted">No pending candidates.</p>
      </div>
    );

  return (
    <SearchFilter
      items={pending.map((c) => ({ slug: c.key, title: c.title, type: c.type }))}
      placeholder="Filter pending candidates…"
    >
      {(filtered) => {
        const filteredKeys = new Set(filtered.map((f) => f.slug));
        const shown = pending.filter((c) => filteredKeys.has(c.key));
        return (
          <div className="overflow-x-auto">
            <div className="flex items-center justify-between mb-2">
              {actionMsg ? <p className="text-xs font-mono text-muted">{actionMsg}</p> : <span />}
              <button
                onClick={() => void clearAll()}
                className="px-2 py-1 border border-rose-200 dark:border-rose-700/60 text-rose-700 dark:text-rose-300 rounded text-xs hover:bg-rose-50 dark:hover:bg-rose-900/30"
              >
                Clear all
              </button>
            </div>
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wider text-muted border-b border-line-1">
                <tr>
                  <th scope="col" className="py-2 pr-4">
                    Type
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Title
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Score
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Rationale
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Source
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    Discovered
                  </th>
                  <th scope="col" className="py-2">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((c) => {
                  return (
                    <tr key={`${c.type}:${c.key}`} className="border-b border-line-1 align-top">
                      <td className="py-2 pr-4 text-muted uppercase text-xs">{c.type}</td>
                      <td className="py-2 pr-4 text-heading">{c.title}</td>
                      <td className="py-2 pr-4 text-body tabular-nums">{c.score.toFixed(2)}</td>
                      <td className="py-2 pr-4 text-muted max-w-md">{c.rationale}</td>
                      <td className="py-2 pr-4 text-xs max-w-[12rem]">
                        {(() => {
                          const links = sourceLinksFrom(c.evidence);
                          if (links.length === 0) return <span className="text-muted">-</span>;
                          return (
                            <div className="flex flex-col gap-0.5">
                              {links.map((u) => {
                                const st = linkStatusFor(c.evidence, u);
                                return (
                                  <span key={u} className="flex items-center gap-1 truncate">
                                    <span
                                      className={`shrink-0 ${statusColor(st)} cursor-default`}
                                      title={statusTitle(st)}
                                    >
                                      {statusBadge(st)}
                                    </span>
                                    <a
                                      href={u}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      title={u}
                                      className="text-brand-600 dark:text-brand-400 hover:underline truncate transition-colors"
                                    >
                                      {hostOf(u)}
                                    </a>
                                  </span>
                                );
                              })}
                            </div>
                          );
                        })()}
                      </td>
                      <td className="py-2 pr-4 text-muted text-xs whitespace-nowrap">
                        {new Date(c.discoveredAt).toLocaleString()}
                      </td>
                      <td className="py-2 whitespace-nowrap">
                        <div className="flex flex-wrap gap-1">
                          <button
                            onClick={() => approve(c.key, c.type)}
                            className="px-2 py-1 bg-emerald-100 dark:bg-emerald-700/40 border border-emerald-200 dark:border-emerald-600/60 rounded text-xs hover:bg-emerald-200 dark:hover:bg-emerald-700/60"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => skip(c.key, c.type)}
                            className="px-2 py-1 border border-line-1 rounded text-xs hover:bg-surface-300 dark:hover:bg-surface-300"
                          >
                            Skip
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        );
      }}
    </SearchFilter>
  );
}
