import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { githubHeaders, type GithubEnv } from '../lib/github-api';

/**
 * Detection-rule registry: aggregates metadata + recent commits for the major
 * open-source detection rule repos. Surfaces "what's new in detections" without
 * needing a GitHub token (uses unauthenticated metadata + commits.atom RSS).
 *
 * Cached 1 h in Cache API. Source list intentionally curated; ad-hoc additions
 * should go through the existing feeds proxy allow-list.
 */

/** Exported so /api/v1/feed-status can read the same cached payload directly. */
export const DETECTION_RULES_CACHE_KEY = 'https://detection-rules-cache.internal/v4-goxdr';
const CACHE_KEY = DETECTION_RULES_CACHE_KEY;
const CACHE_TTL_SECONDS = 3600;
const FETCH_TIMEOUT_MS = 10_000;

interface SourceConfig {
  id: string;
  label: string;
  repo: string; // owner/name
  type:
    'Sigma' | 'YARA' | 'Elastic' | 'Splunk SPL' | 'KQL' | 'Suricata' | 'Snort' | 'PowerShell' | 'DLP' | 'Supply chain';
  description: string;
  rules_path: string; // path within the repo where rules live (for direct browse link)
  homepage?: string;
}

const SOURCES: SourceConfig[] = [
  {
    id: 'sigma',
    label: 'SigmaHQ/sigma',
    repo: 'SigmaHQ/sigma',
    type: 'Sigma',
    description:
      'Generic signature format. Thousands of cross-platform detection rules covering Windows, Linux, cloud, and proxy logs.',
    rules_path: 'rules',
  },
  {
    id: 'signature-base',
    label: 'Neo23x0/signature-base',
    repo: 'Neo23x0/signature-base',
    type: 'YARA',
    description:
      "Florian Roth's signature base. The de-facto YARA rule reference for malware, webshells, and post-exploitation tooling.",
    rules_path: 'yara',
  },
  {
    id: 'elastic-rules',
    label: 'elastic/detection-rules',
    repo: 'elastic/detection-rules',
    type: 'Elastic',
    description: 'Elastic SIEM detection rules with full MITRE ATT&CK mapping. TOML format, very actively maintained.',
    rules_path: 'rules',
  },
  {
    id: 'splunk-content',
    label: 'splunk/security_content',
    repo: 'splunk/security_content',
    type: 'Splunk SPL',
    description: 'Splunk Enterprise Security Content Update detections. SPL queries with MITRE mapping.',
    rules_path: 'detections',
  },
  {
    id: 'sentinel',
    label: 'Azure/Azure-Sentinel',
    repo: 'Azure/Azure-Sentinel',
    type: 'KQL',
    description: 'Microsoft Sentinel detection rules in KQL. The largest open-source KQL detection collection.',
    rules_path: 'Detections',
  },
  {
    id: 'slimkql-detections-ai',
    label: 'SlimKQL/Detections.AI',
    repo: 'SlimKQL/Detections.AI',
    type: 'KQL',
    description:
      'KQL detection-rule mirror maintained by SlimKQL. Defender XDR / Sentinel rules with a focus on AI-related and identity-attack detections — complements Azure-Sentinel with a sharper, niche selection.',
    rules_path: 'KQL',
  },
  {
    id: 'goxdr',
    label: 'gokselatakan/GoXDR',
    repo: 'gokselatakan/GoXDR',
    type: 'KQL',
    description:
      'Curated KQL query library for Microsoft Sentinel + Defender XDR. 100+ queries covering identity attacks, NTLM abuse, LDAP recon, lateral movement, and shadow IT — searchable with severity/platform filters at goxdr.fyi.',
    rules_path: '.',
    homepage: 'https://goxdr.fyi',
  },
  {
    id: 'emerging-threats',
    label: 'EmergingThreats / Suricata',
    repo: 'OISF/suricata',
    type: 'Suricata',
    description:
      'Suricata IDS engine. Pair with the open ET ruleset at rules.emergingthreats.net/open/ for live detection content.',
    rules_path: 'rules',
    homepage: 'https://rules.emergingthreats.net/open/',
  },
  // Snort sources — community + Talos VRT, the two reference Snort
  // signature ecosystems. Snort and Suricata share rule grammar, so most
  // rules here are also Suricata-compatible.
  {
    id: 'snort3-community',
    label: 'snort3/snort3',
    repo: 'snort3/snort3',
    type: 'Snort',
    description:
      'Cisco Talos open-source Snort 3 engine. Reference for the rule grammar; community rules live in the etc/snort/ tree and at snort.org/downloads/#rule-downloads.',
    rules_path: 'etc/snort',
    homepage: 'https://www.snort.org/',
  },
  {
    id: 'snort-rules-community',
    label: 'shirkdog/snortrules-community',
    repo: 'shirkdog/snortrules-community',
    type: 'Snort',
    description:
      'Community mirror of the Snort 2/3 community ruleset. Refreshed in step with snort.org Community Rules releases — handy for analysts who want a tracked git history of rule churn.',
    rules_path: 'rules',
    homepage: 'https://www.snort.org/downloads',
  },
  {
    id: 'ptresearch-attackdetection',
    label: 'ptresearch/AttackDetection',
    repo: 'ptresearch/AttackDetection',
    type: 'Snort',
    description:
      'Positive Technologies open ruleset — Snort + Suricata signatures for active exploits, post-compromise traffic patterns, and red-team tooling.',
    rules_path: '.',
    homepage: 'https://github.com/ptresearch/AttackDetection',
  },
  // PowerShell detection / hardening — the two most-cited reference
  // libraries. PowerShellMafia/PowerSploit is the offensive baseline
  // detection engineers map AGAINST; Get-InjectedThread / Atomic Red Team
  // PowerShell payloads are the test-firing substrates.
  {
    id: 'powersploit',
    label: 'PowerShellMafia/PowerSploit',
    repo: 'PowerShellMafia/PowerSploit',
    type: 'PowerShell',
    description:
      'The reference offensive PowerShell module collection — Invoke-Mimikatz, PowerView, PowerUp. Map detections AGAINST this; defenders use it as the "what does this look like on the wire / in event logs" substrate.',
    rules_path: '.',
    homepage: 'https://github.com/PowerShellMafia/PowerSploit',
  },
  {
    id: 'atomic-red-team-powershell',
    label: 'redcanaryco/atomic-red-team (PowerShell)',
    repo: 'redcanaryco/atomic-red-team',
    type: 'PowerShell',
    description:
      'Atomic Red Team — small, test-firing payloads mapped to MITRE ATT&CK. The PowerShell-related YAMLs under atomics/T1059.001/ are the canonical "did your detection trip on this?" set.',
    rules_path: 'atomics/T1059.001',
    homepage: 'https://atomicredteam.io/',
  },
  {
    id: 'powershell-detection-revoke-obfuscation',
    label: 'danielbohannon/Revoke-Obfuscation',
    repo: 'danielbohannon/Revoke-Obfuscation',
    type: 'PowerShell',
    description:
      'Daniel Bohannon’s obfuscation-detection toolkit. Statistical features + ML-style classifier for PowerShell payloads; pair with Invoke-Obfuscation to generate your eval corpus.',
    rules_path: '.',
    homepage: 'https://github.com/danielbohannon/Revoke-Obfuscation',
  },
  {
    id: 'gitleaks',
    label: 'gitleaks/gitleaks',
    repo: 'gitleaks/gitleaks',
    type: 'DLP',
    description:
      'Open-source secrets detection. Default ruleset (config/gitleaks.toml) covers ~150 secret types — AWS, GCP, Azure, GitHub, Stripe, JWT, PEM, etc.',
    rules_path: 'config',
    homepage: 'https://gitleaks.io',
  },
  {
    id: 'trufflehog',
    label: 'trufflesecurity/trufflehog',
    repo: 'trufflesecurity/trufflehog',
    type: 'DLP',
    description:
      'Secret-scanning engine with hundreds of detectors and live verification. Detector definitions live under pkg/detectors/ — one per credential type.',
    rules_path: 'pkg/detectors',
    homepage: 'https://trufflesecurity.com',
  },
  {
    id: 'guarddog',
    label: 'DataDog/guarddog',
    repo: 'DataDog/guarddog',
    type: 'Supply chain',
    description:
      'Supply-chain malware scanner for PyPI and npm. Semgrep-style YAML rules detect package-takeover, install-script abuse, obfuscation, and exfil patterns — different from credential-leak scanners.',
    rules_path: 'guarddog/analyzer/sourcecode',
  },
  {
    id: 'detect-secrets',
    label: 'Yelp/detect-secrets',
    repo: 'Yelp/detect-secrets',
    type: 'DLP',
    description:
      'Pre-commit-friendly secret scanner with pluggable detectors. Useful as a CI gate for the patterns gitleaks already covers, with different tuning trade-offs.',
    rules_path: 'detect_secrets/plugins',
  },
  {
    id: 'threathunter-playbook',
    label: 'OTRF/ThreatHunter-Playbook',
    repo: 'OTRF/ThreatHunter-Playbook',
    type: 'Sigma',
    description:
      'Detection logic mapped to MITRE ATT&CK — Jupyter notebooks with Sigma rules, Splunk queries, and threat-hunting methodologies for each technique. Community-driven, regularly updated.',
    rules_path: 'detections',
    homepage: 'https://threathunterplaybook.com/',
  },
];

interface RecentCommit {
  source_id: string;
  source_label: string;
  type: string;
  title: string;
  author: string;
  link: string;
  pubDate: string;
}

interface SourceEntry {
  id: string;
  label: string;
  repo: string;
  type: string;
  description: string;
  rules_path: string;
  homepage?: string;
  // From GitHub API
  stars?: number;
  forks?: number;
  pushed_at?: string;
  default_branch?: string;
  open_issues?: number;
  // Direct links
  repo_url: string;
  rules_url: string;
  commits_url: string;
}

interface DetectionRulesResponse {
  generated_at: string;
  sources: SourceEntry[];
  recent_commits: RecentCommit[];
  /** Sources that returned 429 / 403-with-zero-quota — their meta/commits in this response are stale or empty, not authoritative. Empty array on a healthy response. */
  rate_limited_sources?: string[];
}

interface GhRepo {
  stargazers_count?: number;
  forks_count?: number;
  pushed_at?: string;
  default_branch?: string;
  open_issues_count?: number;
}

// Aggregator-style 429 handling: GitHub anonymous API caps at 60/hr per IP.
// We can't fail the whole response if one repo gets rate-limited, but we
// SHOULD surface which ones did so the UI can show "n/a (rate limited)"
// instead of "0 stars" implying an empty repo.
type FetchResult<T> = { value: T; rate_limited: boolean };

async function fetchRepoMeta(repo: string, env?: GithubEnv): Promise<FetchResult<GhRepo | null>> {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: githubHeaders(env),

      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true },
    });
    if (res.status === 429 || res.status === 403) {
      // GitHub returns 403 with a `x-ratelimit-remaining: 0` header when
      // the unauthenticated quota is exhausted — treat both as rate-limit.
      const remaining = res.headers.get('x-ratelimit-remaining');
      if (res.status === 429 || remaining === '0') return { value: null, rate_limited: true };
    }
    if (!res.ok) return { value: null, rate_limited: false };
    return { value: (await res.json()) as GhRepo, rate_limited: false };
  } catch (_catchErr) {
    logError('fetchRepoMeta failed', _catchErr);
    return { value: null, rate_limited: false };
  }
}

async function fetchRecentCommits(source: SourceConfig): Promise<FetchResult<RecentCommit[]>> {
  const url = `https://github.com/${source.repo}/commits.atom`;
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: {
        'user-agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-dfir/1.0 Safari/537.36',
        accept: 'application/atom+xml, application/xml',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true },
    });
    if (res.status === 429) return { value: [], rate_limited: true };
    if (!res.ok) return { value: [], rate_limited: false };
    const body = await res.text();
    const out: RecentCommit[] = [];
    const entryRe = /<entry>([\s\S]*?)<\/entry>/g;
    let m: RegExpExecArray | null;
    while ((m = entryRe.exec(body)) !== null && out.length < 8) {
      const inner = m[1];
      if (!inner) continue;
      const title = (inner.match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1] ?? '')
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/, '$1')
        .trim()
        .slice(0, 200);
      const link = inner.match(/<link[^>]*href=["']([^"']+)/)?.[1] ?? '';
      const author = inner.match(/<author>[\s\S]*?<name>([\s\S]*?)<\/name>/)?.[1]?.trim() ?? '';
      const updated = inner.match(/<updated>([\s\S]*?)<\/updated>/)?.[1]?.trim() ?? '';
      if (!title) continue;
      out.push({
        source_id: source.id,
        source_label: source.label,
        type: source.type,
        title,
        author,
        link,
        pubDate: updated,
      });
    }
    return { value: out, rate_limited: false };
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return { value: [], rate_limited: false };
  }
}

/**
 * Pure-data fetcher exposed for /api/v1/snapshot. Returns the body without
 * Response wrapping so the snapshot handler can compose it directly without
 * a worker-internal HTTP call (which Cloudflare 522s on same-worker recursion).
 */
export async function fetchDetectionRules(env?: GithubEnv): Promise<DetectionRulesResponse> {
  const results = await Promise.all(
    SOURCES.map(async (source) => {
      const [metaResult, commitsResult] = await Promise.all([
        fetchRepoMeta(source.repo, env),
        fetchRecentCommits(source),
      ]);
      const meta = metaResult.value;
      const entry: SourceEntry = {
        id: source.id,
        label: source.label,
        repo: source.repo,
        type: source.type,
        description: source.description,
        rules_path: source.rules_path,
        homepage: source.homepage,
        stars: meta?.stargazers_count,
        forks: meta?.forks_count,
        pushed_at: meta?.pushed_at,
        default_branch: meta?.default_branch,
        open_issues: meta?.open_issues_count,
        repo_url: `https://github.com/${source.repo}`,
        rules_url: `https://github.com/${source.repo}/tree/${meta?.default_branch ?? 'main'}/${source.rules_path}`,
        commits_url: `https://github.com/${source.repo}/commits/${meta?.default_branch ?? 'main'}`,
      };
      return {
        entry,
        commits: commitsResult.value,
        rate_limited: metaResult.rate_limited || commitsResult.rate_limited,
        source_id: source.id,
      };
    })
  );

  const sources: SourceEntry[] = results.map((r) => r.entry);
  const recentCommits: RecentCommit[] = results
    .flatMap((r) => r.commits)
    .sort((a, b) => {
      const da = new Date(a.pubDate).getTime() || 0;
      const db = new Date(b.pubDate).getTime() || 0;
      return db - da;
    })
    .slice(0, 30);
  const rateLimitedSources = results.filter((r) => r.rate_limited).map((r) => r.source_id);

  return {
    generated_at: new Date().toISOString(),
    sources,
    recent_commits: recentCommits,
    ...(rateLimitedSources.length > 0 ? { rate_limited_sources: rateLimitedSources } : {}),
  };
}

export async function detectionRulesHandler(c: Context<{ Bindings: Env }>) {
  const cache = caches.default;
  const cacheReq = new Request(CACHE_KEY);
  const cached = await cache.match(cacheReq);
  if (cached) {
    return new Response(cached.body, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
        'x-cache': 'HIT',
      },
    });
  }

  const body = await fetchDetectionRules(c.env);

  const json = JSON.stringify(body);
  const response = new Response(json, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${CACHE_TTL_SECONDS}`,
      'x-cache': 'MISS',
    },
  });
  c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
  return response;
}
