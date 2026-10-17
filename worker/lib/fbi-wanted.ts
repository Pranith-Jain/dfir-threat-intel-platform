import { errMessage } from './err';
export async function fbiWantedSearch(q: string) {
  const result: { success: boolean; data?: unknown; error?: string; total?: number } = { success: false };
  try {
    const res = await fetch(`https://api.fbi.gov/wanted/v1/list?title=${encodeURIComponent(q)}&pageSize=10`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      result.error = `FBI API returned ${res.status}`;
      return result;
    }
    const data = (await res.json()) as { total?: number; items?: unknown[] };
    result.data = data;
    result.total = data.total;
    result.success = true;
  } catch (e) {
    console.error('fbiWantedSearch failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}

export async function fbiWantedList(page = 1, pageSize = 20) {
  const result: { success: boolean; data?: unknown; error?: string } = { success: false };
  try {
    const res = await fetch(`https://api.fbi.gov/wanted/v1/list?page=${page}&pageSize=${pageSize}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      result.error = `FBI API returned ${res.status}`;
      return result;
    }
    result.data = await res.json();
    result.success = true;
  } catch (e) {
    console.error('fbiWantedList failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}
