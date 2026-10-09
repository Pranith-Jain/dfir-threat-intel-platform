import { describe, it, expect } from 'vitest';
import type { D1Database } from '@cloudflare/workers-types';
import { runTelegramLeakScanner } from '../../src/routes/telegram-leak-monitor';
import type { TelegramFeedItem } from '../../src/routes/telegram-feed';

/**
 * Regression cover for the leak scanner's write path.
 *
 * The live symptom was `telegram_leak_entries` frozen for a week while the feed
 * itself stayed healthy (30+ channels OK, ~190 matching messages an hour) and
 * `telegram_watched_channels.last_scraped` kept advancing every 3h. Every
 * signal an operator would check said "fine", because the caller only logged
 * when `leaks_found > 0` — a scanner that matched nothing and a scanner that
 * never ran looked identical from outside.
 *
 * NOTE ON THE ORIGINAL DIAGNOSIS. An earlier revision of this file claimed the
 * stall was a D1 "50 statements per invocation" cap and asserted the scanner
 * was shedding leaks to fit a budget. That was wrong: a `db.batch()` is a
 * single D1 call regardless of statement count (the 1,494-statement
 * `breach_forum_status` snapshot has written every hour without incident), so
 * that cap was discarding ~150 of ~190 leaks an hour for no reason at all. The
 * tests below pin the properties that are actually true and worth protecting.
 */

/** Fake D1 that records what the scanner submits. */
function recordingD1() {
  let statements = 0;
  let batches = 0;
  let failAtBatch = -1;
  const inserts: string[] = [];
  const updates: string[] = [];
  const db = {
    prepare: (sql: string) => {
      if (/FROM telegram_watched_channels WHERE active/.test(sql)) {
        return { all: async () => ({ results: [] }) } as unknown;
      }
      if (/FROM telegram_discovered_channels/.test(sql)) {
        return { all: async () => ({ results: [] }) } as unknown;
      }
      return { sql, bind: (...args: unknown[]) => ({ sql, args }) };
    },
    batch: async (stmts: Array<{ sql: string; args: unknown[] }>) => {
      batches++;
      // Record AFTER the failure check — a real batch is atomic, so a rejected
      // call persists nothing. Recording first would make the fake claim rows
      // that were in fact rolled back.
      if (batches === failAtBatch) throw new Error('simulated D1 rejection');
      statements += stmts.length;
      for (const s of stmts) {
        if (/INSERT OR IGNORE INTO telegram_leak_entries/i.test(s.sql)) inserts.push(String(s.args[1]));
        if (/UPDATE telegram_watched_channels/i.test(s.sql)) updates.push(String(s.args[2]));
      }
      return stmts.map(() => ({ meta: { changes: 1 } }));
    },
  } as unknown as D1Database;
  return {
    db,
    inserts,
    updates,
    batches: () => batches,
    statements: () => statements,
    failBatch: (n: number) => {
      failAtBatch = n;
    },
  };
}

/** A CVE-feed-shaped message: matches the CVE rule, high volume, low value. */
function cveMessage(i: number): TelegramFeedItem {
  return {
    channel_handle: 'cvedetector',
    channel_name: 'CVE Detector',
    channel_topic: 'osint',
    channel_blurb: '',
    permalink: `https://t.me/CVEDetector/${1000 + i}`,
    datetime: new Date(Date.UTC(2026, 9, 9, 12, i % 60)).toISOString(),
    text: `CVE-2026-1${(100 + i).toString().padStart(3, '0')} remote code execution in an edge appliance. Patch available.`,
    views: undefined,
  };
}

/** A credential paste: the shape an analyst actually cares about. */
function credentialMessage(): TelegramFeedItem {
  return {
    channel_handle: 'secharvester',
    channel_name: 'SecHarvester',
    channel_topic: 'leaks',
    channel_blurb: '',
    permalink: 'https://t.me/secharvester/999999',
    datetime: new Date(Date.UTC(2026, 9, 9, 13, 0)).toISOString(),
    text:
      'LEAK: database leaked. 240 credential lines, email:password pairs — ' +
      'alice@corp.example:Passw0rd, bob@corp.example:Passw0rd, carol@corp.example:Passw0rd, ' +
      'dave@corp.example:Passw0rd, erin@corp.example:Passw0rd, frank@corp.example:Passw0rd, ' +
      'grace@corp.example:Passw0rd, heidi@corp.example:Passw0rd, ivan@corp.example:Passw0rd, ' +
      'judy@corp.example:Passw0rd, mallory@corp.example:Passw0rd, ' +
      'https://ghostbin.com/p4ste123',
    views: undefined,
  };
}

describe('runTelegramLeakScanner — capture completeness', () => {
  it('records every matched message from a high-volume pass', async () => {
    // The regression the wrong "budget" fix would have introduced: 190 CVE-feed
    // messages is what one hourly pass produced in production, and all 190
    // must be persisted. Nothing is dropped.
    const { db, inserts } = recordingD1();
    const result = await runTelegramLeakScanner(
      db,
      Array.from({ length: 190 }, (_, i) => cveMessage(i))
    );

    expect(inserts).toHaveLength(190);
    expect(result.leaks_found).toBe(190);
  });

  it('persists a credential paste that arrives after a burst of CVE chatter', async () => {
    const { db, inserts } = recordingD1();
    await runTelegramLeakScanner(db, [...Array.from({ length: 190 }, (_, i) => cveMessage(i)), credentialMessage()]);
    expect(inserts).toContain('https://t.me/secharvester/999999');
  });

  it('bumps leak_count once per channel, not once per leak', async () => {
    const { db, updates } = recordingD1();
    await runTelegramLeakScanner(db, [credentialMessage(), ...Array.from({ length: 10 }, (_, i) => cveMessage(i))]);
    // 11 leaks across 2 channels → 2 UPDATEs, not 11. This is the one part of
    // the original change that was a genuine win: the old code issued an
    // UPDATE per match purely to increment a counter.
    expect(updates).toHaveLength(2);
  });
});

describe('runTelegramLeakScanner — atomicity blast radius', () => {
  it('does not let one failed chunk discard the rest of the run', async () => {
    // A `db.batch()` is atomic, so a single bad statement rolls back everything
    // sharing the call. Chunking plus an isolated catch means a failure costs
    // that chunk only — and, critically, does not propagate to the caller,
    // which would abort the remainder of the hourly cron pipeline.
    const { db, failBatch } = recordingD1();
    failBatch(2);
    await expect(
      runTelegramLeakScanner(
        db,
        Array.from({ length: 150 }, (_, i) => cveMessage(i))
      )
    ).resolves.toBeDefined();
  });

  it('loses only the failed chunk, not the whole run', async () => {
    const { db, failBatch, inserts } = recordingD1();
    // 150 messages → two chunks of 100 + 50. Fail the first.
    failBatch(1);
    const result = await runTelegramLeakScanner(
      db,
      Array.from({ length: 150 }, (_, i) => cveMessage(i))
    );
    // Before chunking this was all-or-nothing: the single 150-statement batch
    // would have rolled back and reported zero.
    expect(inserts).toHaveLength(50);
    expect(result.leaks_found).toBe(50);
  });
});
