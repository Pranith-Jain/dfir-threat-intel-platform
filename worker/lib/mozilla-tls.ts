import { errMessage } from './err';
export interface MozillaTlsResult {
  scanId?: number;
  url?: string;
  status?: string;
  results?: {
    score?: number;
    grade?: string;
    protocols?: string[];
    cipherSuites?: string[];
    vulnerabilities?: string[];
    warnings?: string[];
  };
}

export async function mozillaTlsScan(
  url: string
): Promise<{ success: boolean; data?: MozillaTlsResult; error?: string }> {
  const result: { success: boolean; data?: MozillaTlsResult; error?: string } = { success: false };
  try {
    // The hosted TLS Observatory (tls-observatory.services.mozilla.com) was
    // retired (NXDOMAIN). The live successor with the same A+…F grade
    // semantics is the HTTP Observatory.
    const res = await fetch(
      `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${encodeURIComponent(url)}`,
      {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(20000),
      }
    );
    if (!res.ok) {
      result.error = `Mozilla Observatory returned ${res.status}`;
      return result;
    }
    result.data = (await res.json()) as MozillaTlsResult;
    result.success = true;
  } catch (e) {
    console.error('mozillaTlsScan failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}
