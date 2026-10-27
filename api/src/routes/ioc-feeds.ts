import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badGateway } from '../lib/api-error';

import { buildSummary, FEED_SOURCES, type SourceId } from '../lib/ioc-feed-parsers';
import { abuseChFeedRequestForEnv, type AbuseChFeedSource } from '../lib/abusech';
import { safeErrorMessage } from '../lib/error';

const TIMEOUT_MS = 15_000;
const VALID_SOURCES = new Set<string>(Object.keys(FEED_SOURCES));
const ABUSECH_SOURCES = new Set<SourceId>(['urlhaus', 'malwarebazaar', 'threatfox']);

export async function iocFeedSummaryHandler(c: Context<{ Bindings: Env }>) {
  const sourceParam = c.req.query('source');

  if (!sourceParam) {
    return c.json(
      {
        error: 'missing source param',
        valid_sources: Array.from(VALID_SOURCES),
      },
      400
    );
  }

  if (!VALID_SOURCES.has(sourceParam)) {
    return c.json(
      {
        error: `unknown source: ${sourceParam}`,
        valid_sources: Array.from(VALID_SOURCES),
      },
      400
    );
  }

  const sourceId = sourceParam as SourceId;
  const feed = FEED_SOURCES[sourceId];

  try {
    const abuse = ABUSECH_SOURCES.has(sourceId)
      ? abuseChFeedRequestForEnv(c.env, sourceId as AbuseChFeedSource, { days: 7 })
      : null;
    const upstream = await fetch(abuse?.url ?? feed.url, {
      ...abuse?.init,
      redirect: 'follow',
      headers: {
        'user-agent': 'pranithjain-ioc-feed-aggregator/1.0',
        accept: '*/*',
        ...((abuse?.init.headers as Record<string, string> | undefined) ?? {}),
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (upstream.status === 429) {
      const retryAfter = upstream.headers.get('retry-after') ?? '60';
      return c.json(
        { error: 'upstream_rate_limited', upstream: new URL(feed.url).host, source: sourceId, upstream_status: 429 },
        429,
        { 'retry-after': retryAfter, 'cache-control': 'no-store' }
      );
    }
    if (!upstream.ok) {
      return badGateway(c, `upstream ${upstream.status} from ${feed.url}`);
    }

    const rawBody = await upstream.text();
    const summary = buildSummary(sourceId, rawBody);

    return c.json(summary, 200, {
      'Cache-Control': `public, max-age=${summary.cache_control_seconds}`,
    });
  } catch (err) {
    logError('handler failed', err);
    return badGateway(c, safeErrorMessage(c.env as unknown as Record<string, unknown>, err));
  }
}
