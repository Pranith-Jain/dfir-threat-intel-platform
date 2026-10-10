interface PulseSnapshot {
  id: string;
  kind: string;
  title: string;
  severity: string;
  timestamp: string;
}

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import {
  GLOBAL_PULSE_CACHE as GP_CACHE_KEY,
  GP_RESPONSE_KEY as GP_KV_KEY,
} from '../../api/src/routes/global-pulse/config';
import apiApp from '../../api/src/index';
import { signInternalToken } from '../../api/src/lib/internal-token';
import type { GlobalPulseResponse } from '../../api/src/routes/global-pulse/types';

const MAX_CONNECTIONS = 50;

/**
 * Alarm poll interval for pollFeeds.
 *
 * Derived from the per-colo Cache-API entry's own TTL (CACHE_TTL in
 * global-pulse/config.ts) rather than picked independently. pollFeeds tries
 * the Cache API first and only pays a KV read on a miss, so polling faster
 * than the entry's TTL guarantees a share of polls land on an expired entry
 * and re-read a payload that was already served from cache microseconds
 * earlier. Keeping the two in step removes those guaranteed-miss reads.
 */
const POLL_INTERVAL_MS = 120_000;

// ── On-demand self-heal (no cron) ──────────────────────────────────────────
// The DO used to only READ the cache, so the page's freshness was gated on the
// hourly queue-warm + `*/30` full-rebuild crons. When those lagged or failed,
// the map sat on stale data and the external-fetcher layers (c2_tracker,
// supply_chain_attacks, blocklist, cisa_advisory, briefing, …) rendered 0 —
// those layers are only populated by the `?force=1` FULL build, which a
// browser-triggered request can't survive (free-plan 10ms CPU cap on the
// stateless worker; the DO has a 30s budget).
//
// Now the DO rebuilds itself: a WS connect, the 30s alarm, or a nudge from the
// HTTP read path runs the SAME in-process `?force=1` full build the cron used —
// but only when the data being served is stale, throttled to at most one
// rebuild per window so concurrent visitors can't stampede it. The page drives
// its own freshness: open it and every layer refills within ~10-20s, no cron
// required. The crons stay as the background safety net for idle periods.
// Rebuild cadence.
//
// These were 5m (stale) / 4m (throttle). A rebuild is NOT cheap: the in-process
// `?force=1` build reads one `gp:warm:<key>` per entry in GP_FEEDS — 29 KV
// reads — and KV reads are billed per key on the free plan (100k/day). At a
// 4-minute throttle that is up to 360 rebuilds/day ≈ 10.4k billed reads, all
// re-fetching the SAME 29 keys.
//
// Those keys are only rewritten hourly, by the queue consumer that warms one
// feed per invocation (`global-pulse/config.ts` GP_FEEDS + enqueueGpFeeds).
// Rebuilding every 4 minutes therefore re-read 29 keys ~12x more often than
// their contents can possibly have changed. Aligning the rebuild to a quarter
// of the upstream cadence keeps the map just as fresh (the source data cannot
// be newer than one cron tick regardless) while cutting those rebuilds from
// ~360/day to ~96/day ≈ 2.8k reads. The WS still pushes a new snapshot to
// connected clients on every rebuild, so the live experience is unchanged.
const REBUILD_STALE_MS = 15 * 60_000; // serve data older than this → rebuild
const REBUILD_THROTTLE_MS = 12 * 60_000; // at most one rebuild per instance per window

// Extends the platform DurableObject base class so `this.ctx` and `this.env`
// are inherited (typed DurableObjectState and Env respectively). The previous
// `private env: unknown` forced a cast at every use site.
export class GlobalPulseDO extends DurableObject<Env> {
  private sessions = new Map<string, WebSocket>();
  private lastSnapshot = new Map<string, PulseSnapshot>();
  private ipConnections = new Map<string, number>();
  private lastGeneratedAt = '';
  private lastRebuildAt = 0;

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade') !== 'websocket') {
      // Internal self-heal nudge from the /api/v1/global-pulse read path: when
      // the handler serves a stale payload it asks us to rebuild on-demand.
      if (new URL(request.url).pathname === '/rebuild-if-stale') {
        this.ctx.waitUntil(this.maybeRebuildAndRefresh());
        return new Response('ok');
      }
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    if (this.sessions.size >= MAX_CONNECTIONS) {
      return new Response('Too many connections', { status: 429 });
    }

    const clientIp = request.headers.get('cf-connecting-ip') ?? 'unknown';
    const ipCount = this.ipConnections.get(clientIp) ?? 0;
    if (ipCount >= 5) {
      return new Response('Too many connections from this IP', { status: 429 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const sessionId = crypto.randomUUID();

    this.sessions.set(sessionId, server);
    this.ipConnections.set(clientIp, ipCount + 1);
    server.accept();

    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      this.sessions.delete(sessionId);
      const remaining = this.ipConnections.get(clientIp) ?? 1;
      if (remaining <= 1) this.ipConnections.delete(clientIp);
      else this.ipConnections.set(clientIp, remaining - 1);
      // Don't clear snapshot or alarm immediately — keep 5m grace so the
      // next visitor gets a warm snapshot and the pollFeeds alarm can still
      // refresh KV in the background. The alarm() handler will GC when truly idle.
      if (this.sessions.size === 0) {
        this.ipConnections.clear();
        // Re-arm one final alarm for the grace window so KV stays fresh even without clients
        const next = new Date(Date.now() + 30_000);
        this.ctx.storage?.setAlarm(next.getTime()).catch(() => {});
      }
    };
    server.addEventListener('close', cleanup);
    server.addEventListener('error', cleanup);

    // A client that closes immediately after the upgrade makes send() throw
    // inside fetch(), aborting before the 101 response is returned (client
    // sees 503 + burns a WS rate-limit slot). Post-accept sends are
    // best-effort — never let them escape the handshake.
    try {
      server.send(JSON.stringify({ type: 'connected' }));
    } catch {
      /* client gone — later sends are individually guarded */
    }

    if (this.lastSnapshot.size === 0) {
      await this.pollFeeds();
    }

    const events = Array.from(this.lastSnapshot.values());
    try {
      server.send(JSON.stringify({ type: 'snapshot', events, generated_at: this.lastGeneratedAt }));
    } catch {
      /* client gone */
    }

    // Keep polling every 30s while clients are connected. The alarm is also
    // kept alive for 5m after the last client disconnects so a nudge from
    // the HTTP read path (maybeNudgeDo → /rebuild-if-stale) can still land
    // and refresh KV even when the DO would otherwise be hibernated. This
    // closes the "1 viewer leaves, next viewer sees 30m stale" gap.
    //
    // Poll interval is POLL_INTERVAL_MS (120s), not 30s: pollFeeds reads the
    // per-colo Cache API first and only falls back to a billed KV get when that
    // entry is cold. GLOBAL_PULSE's CACHE_TTL is 120s, so a 30s alarm missed
    // that entry on roughly every other tick and paid a KV read for a payload
    // it already had. Matching the alarm to the entry TTL removes the
    // guaranteed-miss polls (~1.4k billed reads/day at 30s).
    const next = new Date(Date.now() + POLL_INTERVAL_MS);
    this.ctx.storage?.setAlarm(next.getTime()).catch(() => {});

    // Page visit → refresh stale data on-demand (cron-free). Runs in the
    // background so the WS handshake isn't delayed by a ~10-20s rebuild.
    this.ctx.waitUntil(this.maybeRebuildAndRefresh());

    return new Response(null, { status: 101, webSocket: client });
  }

  override async alarm(): Promise<void> {
    await this.pollFeeds();
    await this.maybeRebuildAndRefresh();
    // Re-arm while clients exist, or for 5m grace after last disconnect
    // (lastRebuildAt tracks recent activity; pollFeeds keeps KV/Cache fresh).
    const graceMs = 5 * 60_000;
    const hasRecentActivity = Date.now() - this.lastRebuildAt < graceMs;
    if (this.sessions.size > 0 || hasRecentActivity) {
      const next = new Date(Date.now() + POLL_INTERVAL_MS);
      this.ctx.storage?.setAlarm(next.getTime()).catch(() => {});
    }
    // Fully idle → clear snapshot to free memory; next connect re-polls cold.
    if (this.sessions.size === 0 && !hasRecentActivity && this.lastSnapshot.size > 0) {
      // Keep lastGeneratedAt for staleness check, but clear events to force fresh read next time
      // (snapshot re-populated on next pollFeeds).
    }
  }

  /**
   * Rebuild the full map on-demand when the data we're serving is stale.
   * Runs the same in-process `?force=1` build the 30-min cron uses - inside
   * this DO's 30s CPU budget - then broadcasts the fresh snapshot. Throttled
   * to at most one rebuild per REBUILD_THROTTLE_MS per instance and skipped
   * entirely while the last broadcast is younger than REBUILD_STALE_MS.
   */
  private async maybeRebuildAndRefresh(): Promise<void> {
    const now = Date.now();
    if (now - this.lastRebuildAt < REBUILD_THROTTLE_MS) return;
    const age = this.lastGeneratedAt ? now - new Date(this.lastGeneratedAt).getTime() : Infinity;
    if (age < REBUILD_STALE_MS) return;
    this.lastRebuildAt = now;

    const tokenSecret = (this.env as unknown as { INTERNAL_TOKEN_SECRET?: string }).INTERNAL_TOKEN_SECRET;
    if (!tokenSecret) return;

    try {
      const token = await signInternalToken('global-pulse-do', tokenSecret);
      const res = await apiApp.fetch(
        new Request('https://self/api/v1/global-pulse?force=1', {
          headers: { 'x-internal-token': token },
        }),
        this.env as never,
        this.ctx as never
      );
      if (!res.ok) {
        console.log(JSON.stringify({ job: 'gp-do-rebuild', status: 'failed', http: res.status }));
        return;
      }
      const body = (await res.json()) as GlobalPulseResponse;
      this.applySnapshot(body);
      console.log(
        JSON.stringify({
          job: 'gp-do-rebuild',
          status: 'ok',
          events: body.events?.length ?? 0,
          generated_at: body.generated_at,
        })
      );
    } catch (_catchErr) {
      console.error('handler failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
      /* best-effort — the next alarm / connect retries */
    }
  }

  private async pollFeeds(): Promise<void> {
    try {
      // Try Cache API first (per-colo, fast). Fall back to KV (global) if
      // the cache entry expired — the handler writes to both, but the
      // Cache API entry has a 300s TTL and may be cold if no request has
      // triggered a rebuild recently. Without this KV fallback, the DO
      // silently stops broadcasting once the cache expires, making the
      // page appear "stuck at 1 hour ago".
      const cache = caches.default;
      const cached = await cache.match(new Request(GP_CACHE_KEY));
      let bodyText: string | null = null;

      if (cached) {
        bodyText = await cached.text();
      } else {
        // KV fallback — global, so any colo can read the last successful build.
        const kv = this.env.KV_CACHE;
        if (kv) {
          bodyText = await kv.get(GP_KV_KEY, 'text');
        }
      }

      if (!bodyText) return;

      const body = JSON.parse(bodyText) as GlobalPulseResponse;
      this.applySnapshot(body);
    } catch (_catchErr) {
      console.error('handler failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
      /* cache miss */
    }
  }

  /**
   * Diff a fresh payload against the last broadcast and push the changes to
   * connected clients. Shared by pollFeeds (cache/KV read) and
   * maybeRebuildAndRefresh (on-demand `?force=1` build response).
   */
  private applySnapshot(body: { generated_at?: string; events?: PulseSnapshot[] }): void {
    const newGeneratedAt = body.generated_at ?? '';
    const newEvents = body.events ?? [];

    if (newGeneratedAt === this.lastGeneratedAt && this.lastSnapshot.size > 0) {
      return;
    }

    const newIds = new Set(newEvents.map((e) => e.id));
    const added: PulseSnapshot[] = [];
    const removed: string[] = [];

    for (const [id] of this.lastSnapshot) {
      if (!newIds.has(id)) removed.push(id);
    }

    for (const event of newEvents) {
      const prev = this.lastSnapshot.get(event.id);
      if (!prev) {
        added.push(event);
      } else if (
        prev.kind !== event.kind ||
        prev.title !== event.title ||
        prev.severity !== event.severity ||
        prev.timestamp !== event.timestamp
      ) {
        added.push(event);
      }
    }

    this.lastSnapshot.clear();
    for (const event of newEvents) {
      this.lastSnapshot.set(event.id, event);
    }
    this.lastGeneratedAt = newGeneratedAt;

    if (added.length > 0 || removed.length > 0) {
      this.broadcast({
        type: 'update',
        added,
        removed,
        total: newEvents.length,
        generated_at: newGeneratedAt,
      });
    }
  }

  private broadcast(msg: unknown): void {
    const payload = JSON.stringify(msg);
    for (const [id, ws] of this.sessions) {
      try {
        ws.send(payload);
      } catch (_catchErr) {
        console.error('handler failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
        this.sessions.delete(id);
      }
    }
  }
}
