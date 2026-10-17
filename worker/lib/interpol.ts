import { errMessage } from './err';
export async function interpolSearch(params: {
  name?: string;
  forename?: string;
  nationality?: string;
  page?: number;
}) {
  const result: { success: boolean; data?: unknown; error?: string; total?: number } = { success: false };
  try {
    const searchParams = new URLSearchParams();
    if (params.name) searchParams.set('name', params.name);
    if (params.forename) searchParams.set('forename', params.forename);
    if (params.nationality) searchParams.set('nationality', params.nationality);
    searchParams.set('page', String(params.page ?? 1));

    const res = await fetch(`https://ws-public.interpol.int/notices/v1/red?${searchParams.toString()}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      result.error = `Interpol returned ${res.status}`;
      return result;
    }
    const data = (await res.json()) as { total?: number };
    result.data = data;
    result.total = data.total;
    result.success = true;
  } catch (e) {
    console.error('interpolSearch failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}

export async function interpolNoticeDetail(noticeId: string) {
  const result: { success: boolean; data?: unknown; error?: string } = { success: false };
  try {
    const res = await fetch(`https://ws-public.interpol.int/notices/v1/red/${encodeURIComponent(noticeId)}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 404) {
      result.error = 'notice not found';
      return result;
    }
    if (!res.ok) {
      result.error = `Interpol returned ${res.status}`;
      return result;
    }
    result.data = await res.json();
    result.success = true;
  } catch (e) {
    console.error('interpolNoticeDetail failed:', errMessage(e));
    result.error = errMessage(e);
  }
  return result;
}
