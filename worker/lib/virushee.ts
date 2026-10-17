import { errMessage } from './err';
export interface VirusheeResult {
  found?: boolean;
  hash?: string;
  positives?: number;
  total?: number;
  scan_results?: Array<{
    engine?: string;
    detected?: boolean;
    result?: string;
  }>;
}

export async function virusheeCheck(
  hash: string
): Promise<{ success: boolean; data?: VirusheeResult; error?: string }> {
  const result: { success: boolean; data?: VirusheeResult; error?: string } = { success: false };
  try {
    const res = await fetch(`https://api.virushee.com/check/hash?hash=${encodeURIComponent(hash)}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (res.status === 404) {
      result.success = true;
      return result;
    }
    if (!res.ok) {
      result.error = `Virushee returned ${res.status}`;
      return result;
    }
    result.data = (await res.json()) as VirusheeResult;
    result.success = true;
  } catch (e) {
    console.error('virusheeCheck failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}
