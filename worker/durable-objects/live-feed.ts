import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';

interface FeedSnapshot {
  type: string;
  total: number;
  generated_at: string;
}

// Imported, not hardcoded: this key belongs to the live-iocs route and this
// file was pinned at v11 while the route advanced to v13, so the WebSocket DO
// read a key nothing ever wrote and reported `total: 0` for the iocs layer.
// A literal here silently drifts again on the next route-side bump; the import
// cannot.
import { LIVE_IOCS_CACHE_KEY } from '../../api/src/routes/live-iocs';

const CACHE_KEYS = [
  { key: 'https://ransomware-recent-cache.internal/v8-af-source', label: 'ransomware' },
  { key: LIVE_IOCS_CACHE_KEY, label: 'iocs' },
  { key: 'https://cve-recent-cache.internal/v10-750-paged', label: 'cves' },
  { key: 'https://malware-samples-cache.internal/v3-500', label: 'malware' },
  { key: 'https://breach-cache.internal/v6-hibp-only', label: 'breaches' },
  { key: 'https://actor-timeline-cache.internal/v3-mti', label: 'actors' },
];

// Maximum concurrent WebSocket connections per Durable Object instance.
// Prevents resource exhaustion from an attacker opening thousands of
// connections. At 50 connections, each polling 6 feeds every 30s, the
// DO stays well within Cloudflare's CPU/subrequest limits.
const MAX_CONNECTIONS = 50;

export class LiveFeedDO extends DurableObject<Env> {
  private sessions = new Map<string, WebSocket>();
  private lastSnapshots = new Map<string, FeedSnapshot>();
  /** Per-IP connection tracking for abuse prevention. */
  private ipConnections = new Map<string, number>();

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade') !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    // Enforce max concurrent connections to prevent resource exhaustion.
    if (this.sessions.size >= MAX_CONNECTIONS) {
      return new Response('Too many connections', { status: 429 });
    }

    // Per-IP limit: max 5 connections per IP to prevent single-client abuse.
    const clientIp = request.headers.get('cf-connecting-ip') ?? 'unknown';
    const ipCount = this.ipConnections.get(clientIp) ?? 0;
    if (ipCount >= 5) {
      return new Response('Too many connections from this IP', { status: 429 });
    }

    const pair = new WebSocketPair();
    // WebSocketPair is a { 0, 1 } pair — index directly so both halves stay
    // typed WebSocket (Object.values widens to WebSocket[], which is
    // element-possibly-undefined under noUncheckedIndexedAccess).
    const client = pair[0];
    const server = pair[1];
    const sessionId = crypto.randomUUID();

    this.sessions.set(sessionId, server);
    this.ipConnections.set(clientIp, ipCount + 1);
    server.accept();

    // Guard against double cleanup: a socket fires BOTH 'close' and 'error',
    // and both listeners point here. Without the flag the per-IP counter is
    // decremented twice, corrupting the accounting and easing slot capture.
    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      this.sessions.delete(sessionId);
      const remaining = this.ipConnections.get(clientIp) ?? 1;
      if (remaining <= 1) this.ipConnections.delete(clientIp);
      else this.ipConnections.set(clientIp, remaining - 1);
      if (this.sessions.size === 0) {
        this.lastSnapshots.clear();
        this.ipConnections.clear();
        this.ctx.storage?.deleteAlarm().catch(() => {});
      }
    };
    server.addEventListener('close', cleanup);
    server.addEventListener('error', cleanup);

    // Post-accept sends are best-effort — a client that closed immediately
    // must not blow up the handshake (see global-pulse.ts).
    try {
      server.send(JSON.stringify({ type: 'connected', feeds: CACHE_KEYS.map((c) => c.label) }));
    } catch {
      /* client gone — later sends are individually guarded */
    }

    if (this.lastSnapshots.size === 0) {
      await this.pollFeeds();
    }

    for (const s of this.lastSnapshots.values()) {
      try {
        server.send(JSON.stringify({ type: 'snapshot', feed: s.type, total: s.total, generated_at: s.generated_at }));
      } catch {
        /* client gone */
      }
    }

    if (this.sessions.size > 0) {
      const next = new Date(Date.now() + 30_000);
      this.ctx.storage?.setAlarm(next.getTime()).catch(() => {});
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  override async alarm(): Promise<void> {
    await this.pollFeeds();
    if (this.sessions.size > 0) {
      const next = new Date(Date.now() + 30_000);
      this.ctx.storage?.setAlarm(next.getTime()).catch(() => {});
    }
  }

  private async pollFeeds(): Promise<void> {
    const cache = caches.default;
    // Read the 6 feed snapshots concurrently. Each label's snapshot/broadcast
    // is independent and order-free, so the previous sequential await-chain
    // (which blocked the first WebSocket handshake on a cold instance) only
    // added latency. JS is single-threaded, so the per-label lastSnapshots.set
    // calls can't race.
    await Promise.all(
      CACHE_KEYS.map(async ({ key, label }) => {
        try {
          const cached = await cache.match(new Request(key));
          if (!cached) return;

          const body = (await cached.json()) as Record<string, unknown>;
          const total = (body.total ?? body.count ?? 0) as number;
          const generated_at = (body.generated_at ?? '') as string;
          const prev = this.lastSnapshots.get(label);
          const prevTotal = prev?.total ?? 0;

          if (prev && total !== prevTotal) {
            const delta = total - prevTotal;
            if (delta > 0) {
              this.broadcast({
                type: 'update',
                feed: label,
                total,
                delta,
                generated_at,
                previous_total: prevTotal,
                new_total: total,
              });
            }
          }

          this.lastSnapshots.set(label, { type: label, total, generated_at });
        } catch (_catchErr) {
          console.error('handler failed:', _catchErr instanceof Error ? _catchErr.message : String(_catchErr));
          /* cache miss */
        }
      })
    );
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
