import { errMessage } from './err';
type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';

function detectHashType(hash: string): HashAlgorithm | null {
  const len = hash.length;
  if (len === 32 && /^[a-f0-9]{32}$/i.test(hash)) return 'md5';
  if (len === 40 && /^[a-f0-9]{40}$/i.test(hash)) return 'sha1';
  if (len === 64 && /^[a-f0-9]{64}$/i.test(hash)) return 'sha256';
  if (len === 96 && /^[a-f0-9]{96}$/i.test(hash)) return 'sha384';
  if (len === 128 && /^[a-f0-9]{128}$/i.test(hash)) return 'sha512';
  return null;
}

export interface DehashResult {
  found: boolean;
  hash: string;
  hash_type: string;
  decrypted?: string;
  error?: string;
}

export async function dehashLookup(hash: string): Promise<DehashResult> {
  const hashType = detectHashType(hash);
  if (!hashType) {
    return { found: false, hash, hash_type: 'unknown', error: 'unsupported hash type' };
  }

  try {
    const res = await fetch(`https://api.dehash.lt/api/v1/lookup?hash=${encodeURIComponent(hash)}&type=${hashType}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });

    if (res.status === 404) {
      return { found: false, hash, hash_type: hashType };
    }
    if (!res.ok) {
      return { found: false, hash, hash_type: hashType, error: `Dehash.lt returned ${res.status}` };
    }

    const data = (await res.json()) as {
      found?: boolean;
      hash?: string;
      type?: string;
      decrypted?: string;
      error?: string;
    };

    if (!data.found || !data.decrypted) {
      return { found: false, hash, hash_type: hashType };
    }

    return { found: true, hash, hash_type: hashType, decrypted: data.decrypted };
  } catch (e) {
    console.error('handler failed:', errMessage(e));
    return { found: false, hash, hash_type: hashType, error: errMessage(e) };
  }
}
