/**
 * ThreatMon IntelHub — Infostealer Investigation.
 *
 * Proxies the free ThreatMon IntelHub infostealer search at
 * intelhub.threatmon.io. Searches stolen credentials, infected devices,
 * and exposed identities linked to a domain.
 *
 * API:
 *   POST https://intelhub.threatmon.io/api/infostealer-search?domain=<domain>&scope=<scope>
 *   → { requestId: string }
 *
 *   GET  https://intelhub.threatmon.io/api/infostealer-stream?requestId=<id>
 *   → SSE stream with events: result, count, failed
 *
 * We consume the SSE stream and return the aggregated results.
 */

import { errMessage } from './err';

export interface InfostealerRecord {
  id: number;
  domain: string;
  url: string;
  ip: string;
  username: string;
  date: string;
  isEmployee: boolean;
}

export interface ThreatMonSearchResult {
  query: string;
  scope: 'company' | 'third-party';
  records: InfostealerRecord[];
  totalCount: number;
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'failed';
    ms: number;
    error?: string;
  }>;
}

type InfostealerScope = 'company' | 'third-party';

const THREATMON_BASE = 'https://intelhub.threatmon.io';

export async function threatmonInfostealerSearch(
  domain: string,
  scope: InfostealerScope = 'company'
): Promise<ThreatMonSearchResult> {
  const result: ThreatMonSearchResult = {
    query: domain,
    scope,
    records: [],
    totalCount: 0,
    diagnostics: [],
  };

  if (!domain || domain.trim().length < 2) {
    result.diagnostics.push({
      provider: 'validator',
      status: 'failed',
      ms: 0,
      error: 'domain must be at least 2 characters',
    });
    return result;
  }

  const t0 = Date.now();

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'user-agent':
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    accept: 'application/json, text/event-stream',
    origin: 'https://intelhub.threatmon.io',
    referer: 'https://intelhub.threatmon.io/infostealer-investigation',
  };

  try {
    // Step 1: POST to initiate search
    const postRes = await fetch(
      `${THREATMON_BASE}/api/infostealer-search?domain=${encodeURIComponent(domain)}&scope=${scope}`,
      { method: 'POST', cache: 'no-store', headers, signal: AbortSignal.timeout(10000) }
    );

    if (!postRes.ok) {
      const body = await postRes.text().catch(() => '');
      const isCfChallenge = postRes.status === 403 && body.includes('Just a moment');
      result.diagnostics.push({
        provider: 'threatmon',
        status: 'failed',
        ms: Date.now() - t0,
        error: isCfChallenge
          ? 'Cloudflare challenge block — ThreatMon requires browser-side access. Use the deep-link at https://intelhub.threatmon.io/infostealer-investigation'
          : `threatmon returned ${postRes.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const postData = (await postRes.json()) as { requestId?: string; error?: string };
    if (!postData.requestId) {
      result.diagnostics.push({
        provider: 'threatmon',
        status: 'failed',
        ms: Date.now() - t0,
        error: postData.error ?? 'no requestId returned',
      });
      return result;
    }

    // Step 2: Consume SSE stream
    const streamRes = await fetch(
      `${THREATMON_BASE}/api/infostealer-stream?requestId=${encodeURIComponent(postData.requestId)}`,
      {
        headers: { accept: 'text/event-stream', 'user-agent': headers['user-agent'] ?? 'Mozilla/5.0' },
        signal: AbortSignal.timeout(30000),
      }
    );

    if (!streamRes.ok) {
      const body = await streamRes.text().catch(() => '');
      result.diagnostics.push({
        provider: 'threatmon',
        status: 'failed',
        ms: Date.now() - t0,
        error: `threatmon stream returned ${streamRes.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const text = await streamRes.text();

    // Parse SSE events
    for (const block of text.split('\n\n')) {
      let event = 'message';
      const dataLines: string[] = [];
      for (const line of block.split('\n')) {
        if (line.startsWith('event:')) event = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
      }
      if (dataLines.length === 0) continue;
      const raw = dataLines.join('\n');

      if (event === 'result') {
        try {
          const parsed = JSON.parse(raw) as {
            results?: Array<{
              id: number;
              domain?: string;
              url?: string;
              ip?: string;
              username?: string;
              date?: string;
              isEmployee?: boolean;
            }>;
          };
          const recs = (parsed.results ?? []).map((r) => ({
            id: r.id,
            domain: r.domain ?? domain,
            url: r.url ?? '',
            ip: r.ip ?? '',
            username: r.username ?? '',
            date: r.date ?? '',
            isEmployee: r.isEmployee ?? false,
          }));
          result.records.push(...recs);
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* non-JSON event data */
        }
      } else if (event === 'count') {
        try {
          const parsed = JSON.parse(raw) as { count?: number };
          if (typeof parsed.count === 'number') {
            result.totalCount = parsed.count;
          }
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* ignore */
        }
      } else if (event === 'failed') {
        result.diagnostics.push({
          provider: 'threatmon',
          status: 'failed',
          ms: Date.now() - t0,
          error: 'search timed out',
        });
        return result;
      }
    }

    result.diagnostics.push({ provider: 'threatmon', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'threatmon',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}
