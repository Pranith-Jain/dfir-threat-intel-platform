import { errMessage } from './err';
export interface TraceixAvResult {
  engine: string;
  engine_type: string;
  file_hash: string;
  verdict: 'Safe' | 'Malicious' | 'Unknown' | 'Failed';
}

export interface TraceixLookupResult {
  hash: string;
  avResults: TraceixAvResult[];
  success: boolean;
  requestTimestamp?: number;
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'skipped' | 'failed';
    ms: number;
    error?: string;
  }>;
}

interface EnvWithTraceix {
  TRACEIX_API_KEY?: string;
}

const TRACEIX_BASE = 'https://ai.perkinsfund.org';

function isValidSha256(s: string): boolean {
  return /^[0-9a-f]{64}$/i.test(s);
}

export async function traceixLookup(env: EnvWithTraceix, hash: string): Promise<TraceixLookupResult> {
  const result: TraceixLookupResult = {
    hash,
    avResults: [],
    success: false,
    diagnostics: [],
  };

  if (!isValidSha256(hash)) {
    result.diagnostics.push({
      provider: 'validator',
      status: 'failed',
      ms: 0,
      error: 'not a valid SHA-256 hash (expected 64 hex characters)',
    });
    return result;
  }

  if (!env.TRACEIX_API_KEY) {
    result.diagnostics.push({
      provider: 'traceix',
      status: 'skipped',
      ms: 0,
      error: 'TRACEIX_API_KEY not set',
    });
    return result;
  }

  const t0 = Date.now();
  try {
    const res = await fetch(`${TRACEIX_BASE}/api/v1/traceix/av/lookup`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.TRACEIX_API_KEY,
      },
      body: JSON.stringify({ sha256: hash }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      result.diagnostics.push({
        provider: 'traceix',
        status: 'failed',
        ms: Date.now() - t0,
        error: `traceix returned ${res.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const body = (await res.json()) as {
      success: boolean;
      results?: TraceixAvResult[];
      request_timestamp?: number;
      error?: { error_message?: string };
    };

    if (!body.success) {
      result.diagnostics.push({
        provider: 'traceix',
        status: 'failed',
        ms: Date.now() - t0,
        error: body.error?.error_message ?? 'traceix returned success=false',
      });
      return result;
    }

    result.success = true;
    result.requestTimestamp = body.request_timestamp;
    result.avResults = body.results ?? [];
    result.diagnostics.push({
      provider: 'traceix',
      status: 'ok',
      ms: Date.now() - t0,
    });
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    result.diagnostics.push({
      provider: 'traceix',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  return result;
}
