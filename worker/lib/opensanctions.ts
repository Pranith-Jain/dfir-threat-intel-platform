import { errMessage } from './err';
export interface OpensanctionsMatch {
  schema?: string;
  id?: string;
  caption?: string;
  properties?: Record<string, string[]>;
  datasets?: string[];
  score?: number;
  topics?: string[];
}

export interface OpensanctionsSearchResponse {
  total?: { value?: number };
  results?: OpensanctionsMatch[];
}

export async function opensanctionsSearch(q: string, limit = 20, env?: { OPENSANCTIONS_API_KEY?: string }) {
  const result: { success: boolean; data?: OpensanctionsSearchResponse; error?: string } = {
    success: false,
  };

  // The hosted OpenSanctions API requires Authorization: ApiKey … since 2025.
  const apiKey = env?.OPENSANCTIONS_API_KEY;
  if (!apiKey) {
    result.error = 'OPENSANCTIONS_API_KEY not set — free key at opensanctions.org';
    return result;
  }

  try {
    const res = await fetch(
      `https://api.opensanctions.org/search/default?q=${encodeURIComponent(q)}&limit=${Math.min(limit, 100)}`,
      {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'pranithjain-threatintel/1.0',
          Authorization: `ApiKey ${apiKey}`,
        },
        signal: AbortSignal.timeout(15000),
      }
    );

    if (!res.ok) {
      result.error = `OpenSanctions returned ${res.status}`;
      return result;
    }

    result.data = (await res.json()) as OpensanctionsSearchResponse;
    result.success = true;
  } catch (e) {
    console.error('opensanctionsSearch failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}

export async function opensanctionsEntity(id: string, env?: { OPENSANCTIONS_API_KEY?: string }) {
  const result: { success: boolean; data?: unknown; error?: string } = { success: false };

  const apiKey = env?.OPENSANCTIONS_API_KEY;
  if (!apiKey) {
    result.error = 'OPENSANCTIONS_API_KEY not set — free key at opensanctions.org';
    return result;
  }

  try {
    const res = await fetch(`https://api.opensanctions.org/entities/${encodeURIComponent(id)}`, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `ApiKey ${apiKey}`,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (res.status === 404) {
      result.error = 'entity not found';
      return result;
    }
    if (!res.ok) {
      result.error = `OpenSanctions returned ${res.status}`;
      return result;
    }

    result.data = await res.json();
    result.success = true;
  } catch (e) {
    console.error('opensanctionsEntity failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}

export async function opensanctionsStats(env?: { OPENSANCTIONS_API_KEY?: string }) {
  const result: { success: boolean; data?: unknown; error?: string } = { success: false };

  const apiKey = env?.OPENSANCTIONS_API_KEY;
  if (!apiKey) {
    result.error = 'OPENSANCTIONS_API_KEY not set — free key at opensanctions.org';
    return result;
  }

  try {
    const res = await fetch('https://api.opensanctions.org/statistics', {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `ApiKey ${apiKey}`,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      result.error = `OpenSanctions stats returned ${res.status}`;
      return result;
    }

    result.data = await res.json();
    result.success = true;
  } catch (e) {
    console.error('opensanctionsStats failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}
