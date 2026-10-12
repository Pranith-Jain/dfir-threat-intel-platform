import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest } from '../lib/api-error';
import { fetchResilient } from '../lib/fetch-resilient';
import { assessPackageRisk, remediationSla, type RiskAssessment } from '../lib/package-risk';
import { enrichForRisk } from '../lib/package-risk-enrich';
import { buildPurl } from '../lib/purl';

/**
 * Package verdict checker — inspired by projectdiscovery/depx.
 *
 * Checks if a specific package is known-malicious by querying the
 * OpenSSF Malicious Packages database (OSV format). Returns a verdict
 * (clean/malicious) with advisory details.
 *
 * GET /api/v1/package-verdict?ecosystem=npm&package=lodash
 * GET /api/v1/package-verdict?ref=npm:lodash
 */

const GH_API_BASE = 'https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious';
const OSV_API = 'https://api.osv.dev/v1/query';

interface Advisory {
  id: string;
  summary: string;
  modified: string;
  published?: string;
  withdrawn?: boolean;
  /** Present on OSV records; absent means no fixed version is known. */
  fixed?: boolean;
}

interface VerdictResponse {
  schema_version: string;
  command: string;
  data: {
    ref: string;
    purl: string;
    verdict: 'clean' | 'malicious' | 'unknown';
    confidence: 'high' | 'medium' | 'low';
    ids: string[];
    package_ecosystem: string;
    package_name: string;
    registry_url: string;
    advisories: Advisory[];
    /** Additive. The binary `verdict` above is unchanged. */
    risk?: RiskAssessment;
    remediation?: { window: string; action: string };
    enrichment?: {
      cvss: number | null;
      epss: number | null;
      kev: boolean;
      cveCount: number;
      degraded: boolean;
      reason?: string;
    };
    checked_ecosystems?: string[];
    matched_ecosystems?: string[];
  };
  timestamp: string;
}

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  pypi: 'pypi',
  pyPI: 'pypi',
  go: 'go',
  golang: 'go',
  maven: 'maven',
  rubygems: 'rubygems',
  'crates.io': 'crates.io',
  cargo: 'crates.io',
  nuget: 'nuget',
  packagist: 'packagist',
};

const REGISTRY_URLS: Record<string, string> = {
  npm: 'https://www.npmjs.com/package/',
  pypi: 'https://pypi.org/project/',
  go: 'https://pkg.go.dev/',
  maven: 'https://mvnrepository.com/artifact/',
  rubygems: 'https://rubygems.org/gems/',
  'crates.io': 'https://crates.io/crates/',
  nuget: 'https://www.nuget.org/packages/',
  packagist: 'https://packagist.org/packages/',
};

function normalizeEco(eco: string): string {
  return ECOSYSTEM_MAP[eco.toLowerCase()] ?? eco.toLowerCase();
}

async function checkOssf(ecosystem: string, packageName: string, token?: string): Promise<Advisory[]> {
  // Try the GitHub Contents API to list advisories for this package
  const path = `${GH_API_BASE}/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`;
  try {
    const res = await fetchResilient(
      path,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'pranithjain-dfir/1.0',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      },
      { attempts: 2, timeoutMs: 10_000 }
    );
    if (!res.ok) return [];
    const entries = (await res.json()) as Array<{ name: string; type: string }>;
    return entries
      .filter((e) => e.type === 'file' && e.name.endsWith('.json'))
      .map((e) => ({
        id: e.name.replace('.json', ''),
        summary: `Malicious package advisory: ${packageName}`,
        modified: '',
      }));
  } catch (_catchErr) {
    logError('checkOssf failed', _catchErr);
    return [];
  }
}

async function checkOsv(ecosystem: string, packageName: string): Promise<Advisory[]> {
  try {
    const ecoMap: Record<string, string> = {
      npm: 'npm',
      pypi: 'PYPI',
      go: 'Go',
      maven: 'MAVEN',
      rubygems: 'RUBYGEMS',
      'crates.io': 'CRATES',
      nuget: 'NUGET',
      packagist: 'PACKAGIST',
    };
    const osvEco = ecoMap[ecosystem] ?? ecosystem.toUpperCase();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(OSV_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: packageName, ecosystem: osvEco },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return [];
    const data = (await res.json()) as {
      vulns?: Array<{ id: string; summary?: string; modified?: string; published?: string; withdrawn?: string }>;
    };
    return (data.vulns ?? []).map((v) => ({
      id: v.id,
      summary: v.summary ?? `Vulnerability in ${packageName}`,
      modified: v.modified ?? '',
      published: v.published,
      withdrawn: Boolean(v.withdrawn),
    }));
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

export async function packageVerdictHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  try {
    let ecosystem: string;
    let packageName: string;

    // Support ?ref=npm:lodash or ?ecosystem=npm&package=lodash
    const ref = c.req.query('ref');
    if (ref) {
      const parts = ref.split(':');
      if (parts.length !== 2) {
        return badRequest(c, 'invalid ref format; expected ecosystem:package (e.g. npm:lodash)');
      }
      ecosystem = normalizeEco(parts[0] ?? '');
      packageName = parts[1] ?? '';
    } else {
      ecosystem = normalizeEco(c.req.query('ecosystem') ?? '');
      packageName = (c.req.query('package') ?? '').trim();
    }

    if (!ecosystem || !packageName) {
      return badRequest(c, 'missing required params: ecosystem + package, or ref');
    }

    const githubToken = c.env.GITHUB_TOKEN;

    // Check OSSF + OSV in parallel — OSV is optional, degrade gracefully
    const [ossfAdvisories, osvAdvisories] = await Promise.all([
      checkOssf(ecosystem, packageName, githubToken).catch(() => [] as Advisory[]),
      checkOsv(ecosystem, packageName).catch(() => [] as Advisory[]),
    ]);

    // Deduplicate advisories by ID
    const seen = new Set<string>();
    const advisories: Advisory[] = [];
    for (const a of [...osvAdvisories, ...ossfAdvisories]) {
      if (!seen.has(a.id)) {
        seen.add(a.id);
        advisories.push(a);
      }
    }

    const isMalicious = advisories.some((a) => a.id.startsWith('MAL-') && !a.withdrawn);
    const verdict = isMalicious ? 'malicious' : advisories.length > 0 ? 'clean' : 'unknown';
    const confidence = isMalicious ? 'high' : advisories.length > 0 ? 'medium' : 'low';

    // ── composite risk ──────────────────────────────────────────────
    // The binary verdict above stays exactly as it was: it is a correct answer
    // to "is this package in the malicious registry" and several callers depend
    // on it. The risk score is additive, so nothing that reads `verdict` changes
    // behaviour.
    const enrich = await enrichForRisk(c.env, advisories).catch(() => null);
    const risk = assessPackageRisk({
      malicious: isMalicious,
      cvss: enrich?.cvss ?? null,
      epss: enrich?.epss ?? null,
      kev: enrich?.kev ?? false,
      hasUnfixedAdvisory: advisories.some((a) => !a.withdrawn && !a.fixed),
      newestAdvisoryAgeDays: enrich?.newestAgeDays ?? null,
      advisoryCount: advisories.length,
    });
    const sla = remediationSla(risk.verdict);

    const response: VerdictResponse = {
      schema_version: '1',
      command: 'check',
      data: {
        ref: `${ecosystem}:${packageName}`,
        purl: buildPurl({ type: ecosystem, name: packageName }),
        verdict,
        confidence,
        ids: advisories.map((a) => a.id),
        package_ecosystem: ecosystem,
        package_name: packageName,
        registry_url: `${REGISTRY_URLS[ecosystem] ?? ''}${packageName}`,
        advisories,
        risk,
        remediation: sla,
        enrichment: enrich
          ? {
              cvss: enrich.cvss,
              epss: enrich.epss,
              kev: enrich.kev,
              cveCount: enrich.cves.length,
              degraded: enrich.degraded,
            }
          : { cvss: null, epss: null, kev: false, cveCount: 0, degraded: true, reason: 'risk enrichment unavailable' },
      },
      timestamp: new Date().toISOString(),
    };

    return c.json(response, 200, {
      'Cache-Control': 'public, max-age=3600',
    });
  } catch (err) {
    logError('handler failed', err);
    return c.json(
      { error: 'package verdict lookup failed', message: err instanceof Error ? err.message : 'Unknown error' },
      500,
      { 'Cache-Control': 'no-store' }
    );
  }
}
