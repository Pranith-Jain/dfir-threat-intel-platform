import { errMessage } from './err';
export interface OpencveCve {
  cve_id: string;
  summary: string;
  cvss31: number | null;
  cvss40: number | null;
  severity: string;
  kev: boolean;
  epss: number | null;
  vendors: string[];
  products: string[];
  weaknesses: string[];
  references: string[];
  created_at: string;
  updated_at: string;
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function strArr(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map(String).filter(Boolean).slice(0, 50);
}

/**
 * Normalize an OpenCVE v2 CVE object defensively — the API is still in
 * beta and field names shift between releases, so every field is probed
 * across its known aliases.
 */
export function normalizeOpencveCve(raw: Record<string, unknown>): OpencveCve {
  const metrics = (raw.metrics ?? raw.cvss ?? {}) as Record<string, unknown>;
  const cvss31 =
    num(metrics.cvss31) ??
    num(metrics.cvss_v31) ??
    num((metrics.cvss31 as Record<string, unknown> | undefined)?.base_score);
  const cvss40 =
    num(metrics.cvss40) ??
    num(metrics.cvss_v40) ??
    num((metrics.cvss40 as Record<string, unknown> | undefined)?.base_score);
  const vendorsRaw = raw.vendors ?? raw.affected_vendors ?? [];
  const vendors = Array.isArray(vendorsRaw)
    ? vendorsRaw
        .map((v) => (typeof v === 'string' ? v : str((v as Record<string, unknown>).name)))
        .filter(Boolean)
        .slice(0, 50)
    : [];
  const refsRaw = raw.references ?? raw.refs ?? [];
  const references = Array.isArray(refsRaw)
    ? refsRaw
        .map((r) => (typeof r === 'string' ? r : str((r as Record<string, unknown>).url)))
        .filter(Boolean)
        .slice(0, 50)
    : [];
  return {
    cve_id: str(raw.cve_id ?? raw.id ?? raw.cve),
    summary: str(raw.summary ?? raw.description ?? '').slice(0, 2000),
    cvss31,
    cvss40,
    severity: str(raw.severity ?? (metrics as Record<string, unknown>).severity ?? '').toLowerCase(),
    kev: Boolean(raw.kev ?? raw.cisa_kev ?? (raw as Record<string, unknown>).is_kev),
    epss: num(raw.epss ?? (metrics as Record<string, unknown>).epss),
    vendors,
    products: strArr(raw.products ?? raw.affected_products),
    weaknesses: strArr(raw.weaknesses ?? raw.cwes).map((w) => (w.startsWith('CWE-') ? w : `CWE-${w}`)),
    references,
    created_at: str(raw.created_at ?? raw.created ?? ''),
    updated_at: str(raw.updated_at ?? raw.updated ?? raw.modified ?? ''),
  };
}

export async function opencveGetCve(
  cveId: string,
  env?: { OPENCVE_API_TOKEN?: string },
  signal?: AbortSignal
): Promise<{ success: boolean; data?: OpencveCve; error?: string }> {
  const result: { success: boolean; data?: OpencveCve; error?: string } = { success: false };

  // OpenCVE Cloud (app.opencve.io) uses per-organization Bearer tokens.
  const token = env?.OPENCVE_API_TOKEN;
  if (!token) {
    result.error = 'OPENCVE_API_TOKEN not set — free org token at app.opencve.io';
    return result;
  }

  try {
    const res = await fetch(`https://app.opencve.io/api/v2/cves/${encodeURIComponent(cveId.toUpperCase())}`, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'pranithjain-threatintel/1.0',
        Authorization: `Bearer ${token}`,
      },
      signal: signal ?? AbortSignal.timeout(15000),
    });

    if (res.status === 404) {
      result.error = `CVE ${cveId} not found in OpenCVE`;
      return result;
    }
    if (!res.ok) {
      result.error = `OpenCVE returned ${res.status}`;
      return result;
    }

    result.data = normalizeOpencveCve((await res.json()) as Record<string, unknown>);
    result.success = true;
  } catch (e) {
    console.error('opencveGetCve failed:', errMessage(e));
    result.error = errMessage(e);
  }

  return result;
}
