import { errMessage } from './err';
interface EnvWithFullhunt {
  FULLHUNT_API_KEY?: string;
}

export interface FullhuntDomainResult {
  host?: string;
  ip?: string;
  isp?: string;
  asn?: { asn?: number; org?: string; country?: string };
  technologies?: string[];
  cloud_provider?: string;
  ports?: Array<{ port: number; protocol: string; service: string; status: string }>;
  subdomains?: string[];
  dns?: Record<string, unknown>;
  whois?: Record<string, string>;
}

export async function fullhuntDomainDetails(env: EnvWithFullhunt, domain: string) {
  const result: { success: boolean; data?: FullhuntDomainResult; error?: string; status?: number } = {
    success: false,
  };

  if (!env.FULLHUNT_API_KEY) {
    result.error = 'FULLHUNT_API_KEY not set';
    return result;
  }

  try {
    // NOTE: upstream retired the `api.fullhunt.io` host (NXDOMAIN); the API now
    // lives on `fullhunt.io` (docs.fullhunt.io).
    const res = await fetch(`https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/details`, {
      headers: { 'X-API-Key': env.FULLHUNT_API_KEY, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });

    result.status = res.status;

    if (res.status === 401 || res.status === 403) {
      result.error = 'API key rejected';
      return result;
    }
    if (!res.ok) {
      result.error = `FullHunt returned ${res.status}`;
      return result;
    }

    result.data = (await res.json()) as FullhuntDomainResult;
    result.success = true;
  } catch (e) {
    console.error('fullhuntDomainDetails failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}

export async function fullhuntSubdomains(env: EnvWithFullhunt, domain: string) {
  const result: { success: boolean; data?: { subdomains?: string[] }; error?: string } = {
    success: false,
  };

  if (!env.FULLHUNT_API_KEY) {
    result.error = 'FULLHUNT_API_KEY not set';
    return result;
  }

  try {
    const res = await fetch(`https://fullhunt.io/api/v1/domain/${encodeURIComponent(domain)}/subdomains`, {
      headers: { 'X-API-Key': env.FULLHUNT_API_KEY, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      result.error = `FullHunt subdomains returned ${res.status}`;
      return result;
    }

    result.data = await res.json();
    result.success = true;
  } catch (e) {
    console.error('fullhuntSubdomains failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}
