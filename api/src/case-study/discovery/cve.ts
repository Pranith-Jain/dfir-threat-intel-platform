import type { Candidate, DedupRecord } from '../types';
import { cveKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { verifyUrl, type LinkStatus } from '../../lib/verify-url';
import { formatAffectedVersions } from '../../lib/cve-versions';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse?: string;
}

interface NvdCveItem {
  id: string;
  metrics?: {
    cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV2?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
  };
  configurations?: Array<{
    nodes: Array<{
      cpeMatch: Array<{
        criteria: string;
        vulnerable: boolean;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  }>;
  weaknesses?: Array<{
    description: Array<{ value: string }>;
  }>;
}

interface NvdResponse {
  vulnerabilities: Array<{ cve: NvdCveItem }>;
}

export interface DiscoverDeps {
  fetch: typeof globalThis.fetch;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
}

async function enrichFromNvd(
  fetchFn: typeof globalThis.fetch,
  cveId: string
): Promise<Partial<Record<string, unknown>>> {
  try {
    const url = `${NVD_API}?cveId=${cveId}`;
    const r = await fetchFn(url, { headers: { 'User-Agent': 'pranithjain.qzz.io case-study-discovery' } });
    if (!r.ok) return {};
    const data = (await r.json()) as NvdResponse;
    const cve = data.vulnerabilities?.[0]?.cve;
    if (!cve) return {};

    const metrics = cve.metrics;
    const cvssSource = metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? metrics?.cvssMetricV2?.[0];
    const cvss = cvssSource
      ? {
          score: cvssSource.cvssData.baseScore,
          severity: cvssSource.cvssData.baseSeverity,
          vector: cvssSource.cvssData.vectorString,
        }
      : undefined;

    // Exact affected versions from NVD CPE match bounds. The earlier version
    // of this block read `parts[4]` — the CPE PRODUCT field — and shipped
    // product names as "affected versions". The shared helper reads the
    // bounds (`versionStart*/versionEnd*`), which is where "from X up to but
    // not including Y" actually lives, and produces the same labels as the
    // research dossier.
    const affectedVersions = formatAffectedVersions(cve.configurations);

    // Extract CWE
    const cwe = cve.weaknesses
      ?.map((w) => w.description?.[0]?.value)
      .filter(Boolean)
      .join(', ');

    return {
      cvss,
      affectedVersions,
      cwe: cwe ?? '',
    } as Record<string, unknown>;
  } catch {
    return {};
  }
}

export async function discoverCves(deps: DiscoverDeps): Promise<Candidate[]> {
  const { fetch, now, getDedup } = deps;
  const candidates: Candidate[] = [];

  try {
    const r = await fetch(KEV_URL, { headers: { 'User-Agent': 'pranithjain.qzz.io case-study-discovery' } });
    if (!r.ok) throw new Error(`KEV fetch ${r.status}`);
    const data = (await r.json()) as { vulnerabilities: KevEntry[] };

    const fourteenDaysAgo = new Date(now.getTime() - 14 * 24 * 3600 * 1000);
    const entries = data.vulnerabilities.filter((k) => {
      const dateAdded = new Date(k.dateAdded + 'T00:00:00Z');
      return dateAdded >= fourteenDaysAgo;
    });

    // Enrich with NVD data in parallel
    const nvdResults = await Promise.allSettled(entries.map((k) => enrichFromNvd(fetch, k.cveID)));

    for (let i = 0; i < entries.length; i++) {
      const k = entries[i];
      if (!k) continue;
      // Bind the settled result to a single local so TS narrows the
      // discriminated union — `.value` only exists on the fulfilled arm,
      // and re-indexing the array twice loses that narrowing.
      const settled = nvdResults[i];
      const nvdExtra = settled?.status === 'fulfilled' ? settled.value : {};

      const dateAdded = new Date(k.dateAdded + 'T00:00:00Z');
      const stable = cveKey(k.cveID);
      const dedup = await getDedup(stable);

      const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cveID)}`;
      const nvdUrlResult = await verifyUrl(nvdUrl, 3000);
      // Nuanced verdict: 'broken' only for a confirmed-dead URL (404/410/
      // soft-404/NXDOMAIN); WAF blocks + 5xx + timeouts stay 'unchecked'.
      const nvdStatus: LinkStatus = nvdUrlResult.linkStatus;
      const sourceLinkStatuses: Record<string, LinkStatus> = {
        [nvdUrl]: nvdStatus,
      };

      const evidence = {
        cveId: k.cveID,
        vendor: k.vendorProject,
        product: k.product,
        name: k.vulnerabilityName,
        description: k.shortDescription,
        kev: true,
        kevAddedAt: dateAdded.toISOString(),
        ransomwareUse: k.knownRansomwareCampaignUse === 'Known',
        urls: [nvdUrl],
        sourceLinkStatuses,
        ...nvdExtra,
      };

      const severity = severityScore({ kev: true, cvss: (nvdExtra.cvss as { score: number })?.score });
      const score = finalScore({
        recency: recencyScore(dateAdded.toISOString(), now),
        severity,
        novelty: noveltyScore(dedup, now),
        sourceWeight: 1.0,
      });

      // vulnerabilityName is often the full NVD title which already includes vendor
      // and product. Avoid triple/tandem repeats like "Microsoft Microsoft Exchange...".
      const titleVendor = k.vendorProject.charAt(0).toUpperCase() + k.vendorProject.slice(1);
      const nameIncludesVendor = k.vulnerabilityName.toLowerCase().startsWith(titleVendor.toLowerCase());
      const nameIncludesProduct = k.vulnerabilityName.toLowerCase().includes(k.product.toLowerCase());
      const productAlreadyHasVendor = k.product.toLowerCase().includes(k.vendorProject.toLowerCase());
      const titleName =
        nameIncludesVendor || nameIncludesProduct
          ? k.vulnerabilityName
          : productAlreadyHasVendor
            ? `${k.product} ${k.vulnerabilityName}`
            : `${titleVendor} ${k.product} ${k.vulnerabilityName}`;

      candidates.push({
        key: stable,
        type: 'cve',
        title: `${k.cveID} — ${titleName}`,
        rationale: `Added to CISA KEV ${k.dateAdded}` + (evidence.ransomwareUse ? '; known ransomware use' : ''),
        score,
        evidence,
        discoveredAt: now.toISOString(),
        status: 'pending',
      });
    }
  } catch {}

  return candidates;
}
