/**
 * Forum actor directory.
 *
 * `/threatintel/forum-actors`
 *
 * Ported from Actores Maliciosos Search: look up an account on a
 * compromised forum by handle or by the address registered with it, and
 * pivot on what the account exposes — registration and last-seen IPs, dates,
 * activity.
 *
 * ## What is deliberately absent
 *
 * The upstream tool returns the whole MyBB row, which includes the password
 * hash, the salt and the session key. None of that is here. The page says
 * so explicitly, because an analyst comparing this with the upstream tool
 * should not have to wonder whether the omission is a bug.
 */

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, AtSign, CalendarClock, Globe, KeyRound, Search, ShieldOff, User } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Card } from '../../components/ui/Card';
import { StatCards } from '../../components/ui/StatCards';
import { useApiData } from '../../hooks/useApiData';

interface ActorHit {
  uid: string;
  username: string;
  usergroup?: string;
  display_group?: string;
  title?: string;
  posts?: number;
  threads?: number;
  reputation?: number;
  registered_at?: string;
  last_active_at?: string;
  last_post_at?: string;
  registration_ip?: string;
  last_ip?: string;
  website?: string;
  timezone?: string;
  warning_points?: number;
}

interface SearchResponse {
  generated_at: string;
  query: string;
  mode: 'email' | 'username';
  total: number;
  matches: ActorHit[];
}

interface StatsResponse {
  source: string;
  source_url: string;
  license: string;
  synced_at: string;
  counts: {
    accounts: number;
    actors: number;
    with_email: number;
    with_ip: number;
    actor_shards: number;
    email_shards: number;
    misaligned_dropped: number;
  };
  excluded_columns: string[];
  note: string;
}

function fmtDate(value: string | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function ForumActors(): JSX.Element {
  const [input, setInput] = useState('');
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const url = query ? `/api/v1/threat-intel/forum-actors?q=${encodeURIComponent(query)}` : null;
  const { data, loading } = useApiData<SearchResponse>(url, { ttl: 120_000 });
  const { data: stats } = useApiData<StatsResponse>('/api/v1/threat-intel/forum-actors/stats', { ttl: 300_000 });

  const submit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const q = input.trim();
      if (q.length < 2) {
        setError('Enter at least two characters.');
        return;
      }
      setError(null);
      setQuery(q);
    },
    [input]
  );

  useEffect(() => {
    if (!data) return;
    if (data.total === 0) setError('No account matched that handle or address.');
    else setError(null);
  }, [data]);

  const cards = [
    { label: 'Accounts', value: stats?.counts.actors ?? 0, icon: <User size={16} /> },
    { label: 'With an IP', value: stats?.counts.with_ip ?? 0, icon: <Globe size={16} /> },
    { label: 'Shards', value: stats?.counts.actor_shards ?? 0, icon: <KeyRound size={16} /> },
    {
      label: 'Corrupt dropped',
      value: stats?.counts.misaligned_dropped ?? 0,
      icon: <ShieldOff size={16} />,
    },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<User size={28} />}
      title="Forum Actors"
      description="Search 324k accounts from a compromised MyBB forum by handle or registered address — and pivot on the IPs and dates they expose."
      maxWidthClass="max-w-6xl"
    >
      <div className="space-y-5">
        <Card padding="md" radius="panel" tone="rose">
          <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[16rem] flex-1">
              <label htmlFor="fa-q" className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted">
                Handle or registered email
              </label>
              <div className="relative">
                <Search
                  size={14}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                  aria-hidden="true"
                />
                <input
                  id="fa-q"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="e.g. handle, or an address the account registered with"
                  spellCheck={false}
                  autoComplete="off"
                  className="w-full rounded border border-line-1 bg-surface-100 py-2 pl-9 pr-3 text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                />
              </div>
            </div>
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 font-mono text-meta text-on-fill transition-colors hover:bg-brand-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              <Search size={14} /> Search
            </button>
          </form>

          <p className="mt-3 flex items-start gap-2 rounded border border-line-1 bg-surface-100 px-3 py-2 text-micro text-muted">
            <ShieldOff size={13} className="mt-0.5 flex-shrink-0" />
            <span>
              Password hashes, salts, session keys and private per-user state are not copied out of the source database
              — {stats?.excluded_columns.length ?? 0} columns are excluded, and the list is published in the API so the
              omission can be audited. Email addresses are searched through a salted hash, so the plaintext corpus is
              not replicated either.
            </span>
          </p>

          {error && (
            <p role="alert" className="mt-3 flex items-center gap-1.5 text-meta text-rose-600 dark:text-rose-400">
              <AlertTriangle size={13} /> {error}
            </p>
          )}
        </Card>

        {stats && <StatCards cards={cards} />}

        {loading && (
          <div className="flex items-center justify-center py-12" role="status" aria-busy="true">
            <span className="font-mono text-meta text-muted">Searching the actor directory…</span>
          </div>
        )}

        {data && !loading && data.matches.length > 0 && (
          <div className="space-y-3">
            {data.matches.map((a) => (
              <Card key={`${a.uid}-${a.username}`} padding="md" radius="panel" tone="rose">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-lg font-semibold text-heading">{a.username}</span>
                      {a.title && (
                        <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                          {a.title}
                        </span>
                      )}
                      {a.warning_points ? (
                        <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-micro text-amber-700 dark:text-amber-300">
                          {a.warning_points} warnings
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 font-mono text-micro text-muted">
                      uid {a.uid} · group {a.usergroup ?? '—'} · {a.posts ?? 0} posts · {a.threads ?? 0} threads · rep{' '}
                      {a.reputation ?? 0}
                    </p>
                  </div>
                  <div className="text-right font-mono text-micro text-muted">
                    <p>
                      <CalendarClock size={11} className="mr-1 inline" aria-hidden="true" />
                      registered {fmtDate(a.registered_at)}
                    </p>
                    <p>last active {fmtDate(a.last_active_at)}</p>
                  </div>
                </div>

                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  {a.registration_ip && (
                    <div className="rounded border border-line-1 bg-surface-100 px-2.5 py-1.5">
                      <p className="font-mono text-micro uppercase tracking-wider text-muted">Registration IP</p>
                      <p className="font-mono text-tool text-heading">{a.registration_ip}</p>
                    </div>
                  )}
                  {a.last_ip && (
                    <div className="rounded border border-line-1 bg-surface-100 px-2.5 py-1.5">
                      <p className="font-mono text-micro uppercase tracking-wider text-muted">Last-seen IP</p>
                      <p className="font-mono text-tool text-heading">{a.last_ip}</p>
                    </div>
                  )}
                </div>

                {a.website && (
                  <p className="mt-2 flex items-center gap-1.5 font-mono text-micro text-muted">
                    <AtSign size={11} aria-hidden="true" /> {a.website}
                  </p>
                )}
              </Card>
            ))}
          </div>
        )}

        {stats && (
          <p className="font-mono text-micro text-muted">
            Source: {stats.source} · {stats.license} · synced {fmtDate(stats.synced_at)} ·{' '}
            {stats.counts.accounts.toLocaleString()} accounts in the source dump, {stats.counts.actors.toLocaleString()}{' '}
            carried forward, {stats.counts.misaligned_dropped} dropped because their fields did not match their columns.
          </p>
        )}
      </div>
    </DataPageLayout>
  );
}
