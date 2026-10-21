/**
 * Daily sweep of the newly-registered domain watchlist.
 *
 * Runs on the hourly cron with a KV skip marker, so it actually sweeps once
 * a day — the upstream feed publishes one file per day, so sweeping more
 * often would re-read the same file and re-find the same domains.
 *
 * The write path is deliberately idempotent: the unique index on
 * `(watch_id, domain, registered_on)` means a re-sweep of the same day
 * cannot double-count, which is what allows the sweep to run unguarded by
 * a "did we already run today" flag in the database.
 */

import type { D1Database } from '@cloudflare/workers-types';
import { fetchDayDomains, isoDaysAgo, matchDomains, prepareKeywords } from './domain-monitor';

export interface DomainSweepResult {
  /** Watches that were checked. */
  watches: number;
  /** Domains recorded across all watches. */
  recorded: number;
  /** Days examined. */
  days: string[];
  /** True when at least one upstream day file was unavailable. */
  degraded: boolean;
}

interface WatchRow {
  id: string;
  keyword: string;
  normalized: string;
}

/**
 * Check every enabled watch against the last two days of registrations.
 *
 * Two days rather than one: a watch added at 09:00 should not miss
 * registrations from 00:00–09:00 the same day, and the upstream file for
 * "today" is often published late.
 */
export async function sweepDomainWatches(
  db: D1Database,
  opts: { days?: number; now?: Date } = {}
): Promise<DomainSweepResult> {
  const days = opts.days ?? 2;
  const now = opts.now ?? new Date();
  const window = Array.from({ length: days }, (_, i) => isoDaysAgo(i, now));

  const { results: watches } = await db
    .prepare('SELECT id, keyword, normalized FROM domain_watchlist WHERE enabled = 1 LIMIT 200')
    .all<WatchRow>();

  if (watches.length === 0) {
    return { watches: 0, recorded: 0, days: window, degraded: false };
  }

  const fetched = await Promise.all(window.map((date) => fetchDayDomains(date)));
  const degraded = fetched.some((f) => !f.ok);

  let recorded = 0;
  const nowIso = new Date().toISOString();

  for (const watch of watches) {
    const keywords = prepareKeywords([watch.normalized]);
    if (keywords.length === 0) continue;

    for (const day of fetched) {
      if (!day.ok) continue;
      const matches = matchDomains(day.domains.join('\n'), keywords);
      for (const domain of matches) {
        try {
          await db
            .prepare(
              `INSERT OR IGNORE INTO domain_watch_matches
                 (id, watch_id, domain, registered_on, detected_at, matched_keyword)
               VALUES (?, ?, ?, ?, ?, ?)`
            )
            .bind(
              `dwm_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
              watch.id,
              domain,
              day.date,
              nowIso,
              watch.keyword
            )
            .run();
          recorded++;
        } catch {
          // A unique-index conflict means this domain was already recorded
          // for this watch on this day — which is the expected outcome of a
          // re-sweep, not an error.
        }
      }
    }

    await db
      .prepare(
        `UPDATE domain_watchlist
         SET last_checked_at = ?,
             match_count = (SELECT COUNT(*) FROM domain_watch_matches WHERE watch_id = ?)
         WHERE id = ?`
      )
      .bind(nowIso, watch.id, watch.id)
      .run()
      .catch(() => {
        /* a failed counter update must not abort the sweep */
      });
  }

  return { watches: watches.length, recorded, days: window, degraded };
}
