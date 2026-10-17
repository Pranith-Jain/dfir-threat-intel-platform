/**
 * CTI Analyst Agent — Full tool registry.
 * 65+ tools across all CTI domains: IOC enrichment, vulnerability intel,
 * actor profiling, malware analysis, domain/host intel, detection rules,
 * relationship graphs, campaign tracking, STIX/TAXII, dark web, phishing,
 * breach monitoring, and more.
 */
import type { AgentTool } from './types';
import { getRecipeDetail, RECIPES } from './recipes';

const API_BASE = 'https://pranithjain.qzz.io';

async function apiFetch<T>(
  self: Fetcher | undefined,
  path: string,
  apiKey?: string,
  init?: RequestInit,
  internalHeader?: Record<string, string>
): Promise<T> {
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...(internalHeader ?? {}),
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (apiKey) headers['authorization'] = `Bearer ${apiKey}`;
  // Default 20s per-call timeout — long enough for the heaviest
  // actor-enrich fan-out, short enough that one stalled upstream
  // can't pin the agent loop. Callers can override via `init.signal`.
  const initWithTimeout: RequestInit = init?.signal ? init : { ...init, signal: AbortSignal.timeout(20_000) };
  const req = new Request(`${API_BASE}${path}`, { ...initWithTimeout, headers });
  const res = self ? await self.fetch(req) : await fetch(req);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

async function apiFetchSse(
  self: Fetcher | undefined,
  path: string,
  apiKey?: string,
  internalHeader?: Record<string, string>
): Promise<{ events: Array<{ event: string; data: unknown }> }> {
  const headers: Record<string, string> = { accept: 'text/event-stream', ...(internalHeader ?? {}) };
  if (apiKey) headers['authorization'] = `Bearer ${apiKey}`;
  // SSE streams are long-lived; cap at 60s so a wedged upstream
  // can't pin the agent loop. (Real IOC-check streams typically
  // complete in <5s; 60s leaves headroom for large indicator fan-outs.)
  const req = new Request(`${API_BASE}${path}`, { headers, signal: AbortSignal.timeout(60_000) });
  const res = self ? await self.fetch(req) : await fetch(req);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${body.slice(0, 200)}`);
  }
  const text = await res.text();
  const events: Array<{ event: string; data: unknown }> = [];
  for (const block of text.split('\n\n')) {
    let event = 'message';
    const dataLines: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) continue;
    const raw = dataLines.join('\n');
    let data: unknown = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* keep raw */
    }
    events.push({ event, data });
  }
  return { events };
}

export function buildToolRegistry(
  self?: Fetcher,
  apiKey?: string,
  internalHeader?: Record<string, string>
): AgentTool[] {
  const ih = internalHeader;

  return [
    // ══════════════════════════════════════════════════════════════════════
    //  IOC ENRICHMENT & REPUTATION
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'check_ioc',
      description:
        'Multi-provider IOC reputation check (56 registered providers, 12-37 queried per indicator type depending on coverage: VirusTotal, AbuseIPDB, Shodan, AlienVault, GreyNoise, CrowdSec, StopForumSpam, DShield, TweetFeed, Spamhaus, ThreatFox, URLhaus, IPsum, and more). Returns composite score, admiralty grade, per-provider verdicts with detection ratios, geolocation, ASN, abuse reports.',
      params: [{ name: 'indicator', type: 'string', description: 'IP, domain, URL, or file hash', required: true }],
      execute: (args) =>
        apiFetchSse(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(String(args.indicator))}`, apiKey, ih),
    },
    {
      name: 'enrich_ioc_deep',
      description:
        'Deep IOC enrichment — single-call orchestrator that fans out to every relevant source: reputation check from up to 37 providers (varies by indicator type — IP gets the most, hash gets fewer) incl. tre.ge, Webamon, Maltiverse, AbuseIPDB, Shodan, Censys, GreyNoise + DNS/WHOIS/CT + BuiltWith tech stack + breach via ProjectDiscovery + passive DNS + relationships. Returns a unified verdict with source-level provenance, tags, and the top contributing sources.',
      params: [{ name: 'indicator', type: 'string', description: 'IP, domain, URL, or file hash', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/ioc/enrich-deep?indicator=${encodeURIComponent(String(args.indicator))}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'lookup_tre_ge',
      description:
        'tre.ge (Threat Reputation Engine) lookup — aggregated reputation across multiple sources for IP / domain / URL / hash. Returns reputation verdict, abuse score, ASN, country, source attributions, tags, and first/last seen timestamps. tre.ge is one of the 51+ providers in check_ioc — this tool extracts the tre.ge slice so the agent can cite it cleanly.',
      params: [
        {
          name: 'indicator',
          type: 'string',
          description: 'IP, domain, URL, or hash to look up',
          required: true,
        },
      ],
      execute: (args) =>
        apiFetchSse(self, `/api/v1/ioc/check?indicator=${encodeURIComponent(String(args.indicator))}`, apiKey, ih).then(
          (res) => {
            // Extract the 'done' event which contains the merged provider results
            const doneEvent = res.events.find((e) => e.event === 'done');
            const data = doneEvent?.data as
              { providers?: Array<{ source?: string; verdict?: string; score?: number }> } | undefined;
            const providers = data?.providers ?? [];
            const tre = providers.find((p) => p.source === 'tre-ge');
            return (
              tre ?? {
                source: 'tre-ge',
                verdict: 'not_queried',
                note: 'tre.ge was not included in this enrichment pass',
              }
            );
          }
        ),
    },
    {
      name: 'maltiverse_verify',
      description:
        'Maltiverse search — malware / IOC / domain correlation. Returns classification, tags, blacklists, and the Maltiverse sample-level verdict for the indicator.',
      params: [{ name: 'q', type: 'string', description: 'Indicator or family name to verify', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/maltiverse?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_ipinfo',
      description: 'IP intel — Shodan InternetDB ports/CVEs + IPinfo geo/org + LeakIX exposure. Cached 30 min.',
      params: [{ name: 'ip', type: 'string', description: 'IPv4 address', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/host?ip=${encodeURIComponent(String(args.ip))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_dns',
      description: 'DNS-over-HTTPS record lookup via HackerTarget — A, AAAA, MX, NS, TXT, SOA, CNAME, CAA.',
      params: [{ name: 'name', type: 'string', description: 'Domain name', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/hackertarget/dns?q=${encodeURIComponent(String(args.name))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_reverse_dns',
      description: 'Reverse IP lookup — domains hosted on the same IP via HackerTarget.',
      params: [{ name: 'ip', type: 'string', description: 'IP address', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/hackertarget/reverse-ip?q=${encodeURIComponent(String(args.ip))}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'breach_check',
      description:
        'Breach / infostealer exposure — checks email or domain against XposedOrNot, LeakCheck, LeakIX, HudsonRock, ProjectDiscovery and HackMyIP. Returns the source, breach name, breach date, pwn count, and data classes exposed.',
      params: [
        {
          name: 'target',
          type: 'string',
          description: 'Email address or domain',
          required: true,
        },
        {
          name: 'type',
          type: 'enum',
          description: 'Target type (email or domain)',
          required: true,
          enum: ['email', 'domain'],
        },
      ],
      execute: (args) => {
        const t = args.type === 'email' || args.type === 'domain' ? args.type : 'email';
        return apiFetch(
          self,
          `/api/v1/breach/${t}?${t}=${encodeURIComponent(String(args.target))}`,
          apiKey,
          undefined,
          ih
        );
      },
    },
    {
      name: 'breach_disclosures_recent',
      description:
        'Recent public breach disclosures — names, dates, data classes exposed, affected record counts. Useful for "what just leaked" pivots.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/breach-disclosures', apiKey, undefined, ih),
    },
    {
      name: 'correlate_iocs',
      description:
        'Cross-source IOC correlation. Find which feeds report this indicator, source count, shared infrastructure, overlapping campaigns.',
      params: [{ name: 'q', type: 'string', description: 'IOC or keyword to correlate', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/ioc-correlation?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    {
      name: 'get_ioc_lifecycle',
      description:
        "IOC temporal lifecycle — first seen, last seen, activity trend, decay rate, observation count. Is this indicator still active? NOTE: Only returns data for IOCs previously observed through this platform's IOC check pipeline. Returns {found:false} for unobserved indicators.",
      params: [{ name: 'indicator', type: 'string', description: 'IOC to check lifecycle', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/ioc-lifecycle?indicator=${encodeURIComponent(String(args.indicator))}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'get_relationships',
      description:
        'IOC relationship graph — connections to threat actors, malware families, campaigns, CVEs, other indicators. Shows the attack graph.',
      params: [{ name: 'indicator', type: 'string', description: 'IOC to map relationships', required: true }],
      execute: (args) => {
        const enc = encodeURIComponent(String(args.indicator));
        return apiFetch(self, `/api/v1/relationship-graph?indicator=${enc}&q=${enc}`, apiKey, undefined, ih);
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  THREAT ACTOR INTELLIGENCE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'enrich_actor',
      description:
        'Threat actor profile — aliases, country, MITRE techniques, campaigns, malware families, OTX pulses, linked CVEs.',
      params: [
        {
          name: 'actor',
          type: 'string',
          description: 'Actor name or slug (APT28, lazarus-group, lockbit)',
          required: true,
        },
      ],
      execute: (args) =>
        apiFetch(self, `/api/v1/actor-enrich?name=${encodeURIComponent(String(args.actor))}`, apiKey, undefined, ih),
    },
    {
      name: 'actor_timeline',
      description: 'Actor activity timeline — posting cadence, victim disclosures over time, operational tempo.',
      params: [{ name: 'actor', type: 'string', description: 'Actor slug', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/actor-timeline?actor=${encodeURIComponent(String(args.actor))}`, apiKey, undefined, ih),
    },
    {
      name: 'actor_cves',
      description: 'CVEs attributed to a specific threat actor. Use slug format (apt28, lazarus-group, lockbit).',
      params: [{ name: 'actor', type: 'string', description: 'Actor slug (apt28, lazarus-group)', required: true }],
      execute: (args) => {
        const name = String(args.actor).trim();
        return apiFetch(self, `/api/v1/actor-cves?name=${encodeURIComponent(name)}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'search_malpedia',
      description:
        'Search Malpedia for malware families or threat actors. Returns descriptions, references, YARA rules. For actors, use the actor name (e.g. "APT28", "Fancy Bear"). For malware, use the family name.',
      params: [
        {
          name: 'q',
          type: 'string',
          description: 'Search query — actor name, malware family, or keyword',
          required: true,
        },
      ],
      execute: (args) =>
        apiFetch(self, `/api/v1/malpedia/search?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CVE & VULNERABILITY INTELLIGENCE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'lookup_cve',
      description:
        'CVE lookup — CVSS score/vector, EPSS probability, CISA KEV status, affected products, references, known exploitation.',
      params: [{ name: 'cve_id', type: 'string', description: 'CVE ID (CVE-2024-3094)', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/cve/lookup?id=${encodeURIComponent(String(args.cve_id))}`, apiKey, undefined, ih),
    },
    {
      name: 'search_triage',
      description:
        'Recorded Future Triage sandbox search — malware samples by family, tag, hash, URL. Returns analysis, configs, C2.',
      params: [
        {
          name: 'q',
          type: 'string',
          description: 'Triage query (family:name, tag:ransomware, md5:...)',
          required: true,
        },
      ],
      execute: (args) =>
        apiFetch(self, `/api/v1/triage/search?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    // ══════════════════════════════════════════════════════════════════════
    //  SUPPLY CHAIN / SBOM
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'scan_package',
      description:
        'deps.dev deep intel for ONE open-source package: resolved latest version, OpenSSF Scorecard, license, resolved dependency-graph size, and known advisory IDs (incl. MAL- malicious-package). Use for a single package; use scan_dependencies for a lockfile/batch of packages.',
      params: [
        {
          name: 'system',
          type: 'enum',
          description: 'Package ecosystem',
          required: true,
          enum: ['npm', 'go', 'maven', 'pypi', 'cargo', 'nuget', 'rubygems'],
        },
        { name: 'name', type: 'string', description: 'Package name', required: true },
        {
          name: 'version',
          type: 'string',
          description: 'Optional pinned version (defaults to latest)',
          required: false,
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/supply-chain/package?system=${encodeURIComponent(String(args.system))}` +
            `&name=${encodeURIComponent(String(args.name))}` +
            (args.version ? `&version=${encodeURIComponent(String(args.version))}` : ''),
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'scan_dependencies',
      description:
        'Scan a dependency list for known vulnerabilities + malicious-package (MAL-) advisories via OSV.dev. ' +
        'Input is one or more "eco:name@ver" specs separated by newlines and/or commas (version optional), ' +
        'e.g. "npm:left-pad@1.3.0\\nPyPI:requests, npm:lodash". Returns OSV vuln IDs (CVE/GHSA/MAL-) per package, ' +
        'with summaries/severity/fixed version for up to 35 distinct advisories.',
      params: [
        {
          name: 'packages',
          type: 'string',
          description:
            'Newline/comma-separated "eco:name@ver" specs (version optional), e.g. "npm:left-pad@1.3.0, PyPI:requests"',
          required: true,
        },
      ],
      execute: (args) => {
        // Parse "eco:name@ver" lines/commas → {packages:[{name,ecosystem,version?}]}
        // mirroring osvScanSchema EXACTLY (else validate('json') 400s the valid request).
        const packages = String(args.packages ?? '')
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .map((spec) => {
            const colon = spec.indexOf(':');
            if (colon < 1) return null; // need "eco:..."
            const ecosystem = spec.slice(0, colon).trim();
            const rest = spec.slice(colon + 1).trim();
            const at = rest.lastIndexOf('@');
            const name = (at > 0 ? rest.slice(0, at) : rest).trim();
            const version = at > 0 ? rest.slice(at + 1).trim() : '';
            if (!ecosystem || !name) return null;
            return version ? { name, ecosystem, version } : { name, ecosystem };
          })
          .filter((p): p is { name: string; ecosystem: string; version?: string } => p !== null)
          .slice(0, 250); // mirror osvScanSchema .max(250)
        if (packages.length === 0) {
          return Promise.reject(new Error('scan_dependencies: no valid "eco:name@ver" specs parsed from input'));
        }
        return apiFetch(
          self,
          '/api/v1/osv/scan',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ packages }),
          },
          ih
        );
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  DOMAIN & HOST INTELLIGENCE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'lookup_domain',
      description: 'Full domain intel — DNS records, WHOIS/RDAP, CT logs, SPF/DKIM/DMARC, blocklist hits.',
      params: [{ name: 'domain', type: 'string', description: 'Domain name', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/domain/lookup?domain=${encodeURIComponent(String(args.domain))}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'lookup_ip_geo',
      description: 'IP geolocation, ASN, company, VPN/proxy/tor detection.',
      params: [{ name: 'ip', type: 'string', description: 'IPv4 or IPv6', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/ip-geo?ip=${encodeURIComponent(String(args.ip))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_builtwith',
      description:
        'Technology stack discovery — what technologies a domain uses (web servers, frameworks, analytics, hosting).',
      params: [{ name: 'domain', type: 'string', description: 'Domain name', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/builtwith?domain=${encodeURIComponent(String(args.domain))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_certificate_transparency',
      description: 'Certificate Transparency log analysis — all SSL certificates issued for a domain or IP address.',
      params: [{ name: 'target', type: 'string', description: 'Domain or IP address', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/ct-log?target=${encodeURIComponent(String(args.target))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_wayback_advanced',
      description:
        'Enhanced Wayback Machine archive search — historical snapshots with context, DNS records, and content analysis.',
      params: [
        { name: 'domain', type: 'string', description: 'Domain name', required: true },
        {
          name: 'date_range',
          type: 'string',
          description: 'Date range (e.g., 2020-01-01..2024-12-31)',
          required: false,
        },
        {
          name: 'filter',
          type: 'enum',
          description: 'Filter by content type',
          required: false,
          enum: ['html', 'js', 'css', 'all'],
        },
      ],
      execute: (args) => {
        const p = new URLSearchParams({ domain: String(args.domain) });
        if (args.date_range) p.set('date_range', String(args.date_range));
        if (args.filter) p.set('filter', String(args.filter));
        return apiFetch(self, `/api/v1/wayback/advanced?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'urlscan_ip_search',
      description:
        'Search urlscan.io for all scans involving an IP address. Returns URLs, domains, screenshot, and threat classifications associated with the IP.',
      params: [{ name: 'ip', type: 'string', description: 'IPv4 address', required: true }],
      execute: (args) => {
        const enc = encodeURIComponent(String(args.ip));
        return apiFetch(self, `/api/v1/urlscan-ip?ip=${enc}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'lookup_asn',
      description: 'ASN intelligence — name, country, network ranges, RIR, BGP peers.',
      params: [{ name: 'asn', type: 'string', description: 'AS number (AS13335)', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/asn/lookup?asn=${encodeURIComponent(String(args.asn))}`, apiKey, undefined, ih),
    },
    {
      name: 'get_domain_history',
      description: 'WHOIS history — registration snapshots, ownership changes over time.',
      params: [{ name: 'domain', type: 'string', description: 'Domain', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/domain/history?domain=${encodeURIComponent(String(args.domain))}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'pivot_domain',
      description: 'Pivot by shared registrant email/org/nameservers/registrar — maps attacker infrastructure.',
      params: [
        { name: 'domain', type: 'string', description: 'Domain to pivot from', required: true },
        {
          name: 'type',
          type: 'enum',
          description: 'Pivot type',
          required: false,
          enum: ['email', 'org', 'nameserver', 'registrar', 'all'],
        },
      ],
      execute: (args) => {
        const p = new URLSearchParams({ domain: String(args.domain) });
        if (args.type) p.set('type', String(args.type));
        return apiFetch(self, `/api/v1/domain/history/pivot?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'search_registrant',
      description: 'Find all domains by registrant email or org — infrastructure mapping.',
      params: [
        { name: 'email', type: 'string', description: 'Registrant email', required: false },
        { name: 'org', type: 'string', description: 'Registrant org', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams();
        if (args.email) p.set('email', String(args.email));
        if (args.org) p.set('org', String(args.org));
        return apiFetch(self, `/api/v1/domain/history/search?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'get_domain_certs',
      description: 'CT log certificates for domain — new subdomains, cert details.',
      params: [
        { name: 'domain', type: 'string', description: 'Domain', required: true },
        { name: 'days', type: 'number', description: 'Look back days (30)', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams({ domain: String(args.domain) });
        if (args.days) p.set('days', String(args.days));
        return apiFetch(self, `/api/v1/ct-monitor/certs?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'scan_website',
      description: 'Website security scan — headers, SSL, technologies, vulnerabilities.',
      params: [{ name: 'url', type: 'string', description: 'URL to scan', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/web-scan?url=${encodeURIComponent(String(args.url))}`, apiKey, undefined, ih),
    },
    {
      name: 'wayback_lookup',
      description: 'Wayback Machine historical snapshots — track changes over time.',
      params: [{ name: 'url', type: 'string', description: 'URL to check', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/wayback/cdx?url=${encodeURIComponent(String(args.url))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  RANSOMWARE & BREACH INTELLIGENCE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'get_ransomware_activity',
      description:
        'Ransomware group activity only — leak-site posts, victim disclosures. Does NOT return data for nation-state APT actors (APT28, Lazarus, etc.). Use actor_timeline for APT activity.',
      params: [
        {
          name: 'group',
          type: 'string',
          description:
            'Ransomware group slug (lockbit, clop, blackbasta) — only works for known ransomware gangs, NOT APT actors',
          required: false,
        },
      ],
      execute: (args) => {
        const hasGroup = args.group && String(args.group).trim().length > 0;
        const path = hasGroup
          ? `/api/v1/ransomware-recent?group=${encodeURIComponent(String(args.group).toLowerCase().trim())}`
          : '/api/v1/ransomware-recent';
        return apiFetch(self, path, apiKey, undefined, ih);
      },
    },
    {
      name: 'get_ransomware_negotiations',
      description:
        'Ransomware negotiation data — demands, discounts, settlement patterns from ransomware.live PRO and MyThreatIntel. Only returns data for known ransomware groups with negotiation transcripts.',
      params: [{ name: 'group', type: 'string', description: 'Ransomware group (optional)', required: false }],
      execute: (args) => {
        const p = args.group ? `?group=${encodeURIComponent(String(args.group))}` : '';
        return apiFetch(self, `/api/v1/negotiations${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'get_victim_releaks',
      description:
        'Re-leak detection — victims appearing on 2+ distinct ransomware group leak sites, indicating failed double-extortion, affiliate disputes, or data re-publishing. Returns group pairs, sector aggregates, and monthly timeline. No params needed.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/victim-releaks', apiKey, undefined, ih),
    },
    {
      name: 'get_ransomware_group_profile',
      description:
        'Full ransomware group intelligence profile from ransomware.live PRO — description, aliases, locations, tools, exploited CVEs, MITRE TTPs, CSIRT notes, YARA rules. Use this for in-depth group analysis (e.g. LockBit, Clop, Qilin, BlackBasta). Requires the ransomware group slug.',
      params: [
        {
          name: 'slug',
          type: 'string',
          description:
            'Ransomware group slug (lockbit, clop, qilin, blackbasta, play, bianlian, blackcat, akira, ransomhouse, etc.)',
          required: true,
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          `/api/v1/rl/group/${encodeURIComponent(String(args.slug).toLowerCase().trim())}`,
          apiKey,
          undefined,
          ih
        ),
    },
    {
      name: 'get_ransomware_stats',
      description:
        'Global ransomware activity statistics from ransomware.live PRO — monthly victim counts, group rankings, attack volume trends, sector breakdown. No params needed.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/rl/stats', apiKey, undefined, ih),
    },
    {
      name: 'search_actor_usernames',
      description:
        'Search threat-actor usernames across 25+ cybercrime forums (Exploit, XSS, Cracked, BreachForums, Nulled, LeakBase, RaidForums archive, etc.). Returns matching usernames, forum count, and per-forum details. Use to find actor handles, cross-reference identities, or track persona changes.',
      params: [{ name: 'q', type: 'string', description: 'Username or partial handle to search', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/actor-usernames?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    {
      name: 'get_cyber_crime_news',
      description:
        'Cybercrime news aggregation from 8+ sources (law enforcement press releases, crypto-crime research, fraud intelligence, ransomware reporting). Returns headlines, source, date, and links. Useful for situational awareness and incorporating current cybercrime developments into reports.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/cyber-crime', apiKey, undefined, ih),
    },
    {
      name: 'get_supply_chain_attacks',
      description:
        'Software supply-chain compromise incidents (npm/PyPI/container/AI-agent ecosystems) from supplychainattack.org. Returns title, status, severity, ecosystems, attack vectors, blast radius, remediation, package IOCs, and GHSA sources. Filter by ecosystem/status/severity.',
      params: [
        {
          name: 'ecosystem',
          type: 'string',
          description: 'Ecosystem filter, e.g. npm/pypi (optional)',
          required: false,
        },
        {
          name: 'status',
          type: 'string',
          description: 'Incident status: active/contained/resolved (optional)',
          required: false,
        },
        {
          name: 'severity',
          type: 'string',
          description: 'Severity: critical/high/medium/low (optional)',
          required: false,
        },
        { name: 'limit', type: 'number', description: 'Max incidents (optional)', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams();
        if (args.ecosystem) p.set('ecosystem', String(args.ecosystem));
        if (args.status) p.set('status', String(args.status));
        if (args.severity) p.set('severity', String(args.severity));
        if (args.limit) p.set('limit', String(args.limit));
        const qs = p.toString();
        return apiFetch(self, `/api/v1/supply-chain-attacks${qs ? `?${qs}` : ''}`, apiKey, undefined, ih);
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  DETECTION RULES & HUNTING
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'generate_yara_rule',
      description:
        'AI-generate detection rules in YARA, Sigma, KQL, Splunk, Lucene, EQL, Snort/Suricata format. Include MITRE mapping.',
      params: [
        { name: 'description', type: 'string', description: 'What to detect', required: true },
        { name: 'family', type: 'string', description: 'Malware family name', required: false },
        { name: 'strings', type: 'string', description: 'Known malicious strings (comma-separated)', required: false },
        {
          name: 'format',
          type: 'enum',
          description: 'Rule format',
          required: false,
          enum: ['yara', 'sigma', 'kql', 'splunk', 'snort', 'suricata'],
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/rules/generate',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              description: String(args.description),
              type: args.format ? String(args.format) : 'yara',
              family: args.family ? String(args.family) : undefined,
              strings: args.strings
                ? String(args.strings)
                    .split(',')
                    .map((s) => s.trim())
                : undefined,
            }),
          },
          ih
        ),
    },
    {
      name: 'generate_hunting_queries',
      description: 'AI-generate SIEM hunting queries for threat hunting. Supports Splunk, KQL, Sigma, Elastic, YARA.',
      params: [
        { name: 'threat', type: 'string', description: 'Threat description to hunt for', required: true },
        {
          name: 'siem',
          type: 'enum',
          description: 'Target SIEM',
          required: false,
          enum: ['splunk', 'kql', 'sigma', 'elastic', 'yara'],
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/hunting-queries/generate',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ threat: String(args.threat), siem: args.siem ? String(args.siem) : 'splunk' }),
          },
          ih
        ),
    },
    {
      name: 'get_detections',
      description: 'Detection engine output — rules that fired against live IOC stream with severity.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/detections', apiKey, undefined, ih),
    },
    {
      name: 'get_yara_rules',
      description: 'Community YARA rules from YARAify/abuse.ch for a malware family.',
      params: [{ name: 'q', type: 'string', description: 'Malware family or keyword', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/yara-hub?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  MITRE ATT&CK & KILL CHAIN
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'lookup_mitre',
      description:
        'MITRE ATT&CK technique lookup by EXACT ID. Must be in format T1234 or T1234.001 (e.g. T1566, T1566.001). Do NOT use technique names — only IDs work.',
      params: [
        {
          name: 'technique_id',
          type: 'string',
          description: 'Exact technique ID (T1566 or T1566.001)',
          required: true,
        },
      ],
      execute: (args) => {
        const id = String(args.technique_id).trim();
        if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) {
          return Promise.reject(new Error(`Invalid technique ID format: "${id}". Expected T1234 or T1234.001`));
        }
        const enc = encodeURIComponent(id);
        return apiFetch(self, `/api/v1/mitre/technique?id=${enc}&technique=${enc}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'reconstruct_attack_chain',
      description:
        'Map IOCs to MITRE ATT&CK kill chain — reconstruct attack progression, identify gaps, predict next moves.',
      params: [
        { name: 'indicators', type: 'string', description: 'Comma-separated IOCs', required: true },
        { name: 'actor', type: 'string', description: 'Known actor (optional)', required: false },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/attack-chain/reconstruct',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              indicators: String(args.indicators)
                .split(',')
                .map((s) => s.trim()),
              // Handler/schema expect `actors` (array), not `actor` (singular).
              // Sending `actor` was silently ignored → the attack chain was
              // reconstructed without actor context, and when combined with
              // the missing ioc_techniques table (now guarded) contributed to
              // the tool's 0% success rate.
              actors: args.actor ? [String(args.actor)] : undefined,
            }),
          },
          ih
        ),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CAMPAIGN TRACKING
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'analyze_campaign',
      description: 'Campaign lifecycle analysis — phase detection, predictive modeling, kill chain mapping.',
      params: [
        { name: 'actor', type: 'string', description: 'Threat actor slug (apt28, lazarus-group)', required: true },
        { name: 'iocs', type: 'string', description: 'Known IOCs (comma-separated)', required: false },
      ],
      execute: (args) => {
        const indicators = args.iocs
          ? String(args.iocs)
              .split(',')
              .map((v) => {
                const val = v.trim();
                const type = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)
                  ? 'ipv4'
                  : /^[a-fA-F0-9]{32,64}$/.test(val)
                    ? 'hash'
                    : /^https?:\/\//.test(val)
                      ? 'url'
                      : /\./.test(val)
                        ? 'domain'
                        : 'ipv4';
                return { value: val, type };
              })
          : [];
        return apiFetch(
          self,
          '/api/v1/threat-intel/campaign/analyze',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ actor: String(args.actor), indicators }),
          },
          ih
        );
      },
    },
    {
      name: 'cross_campaign_correlate',
      description: 'Find connections between campaigns — shared infrastructure, tooling, TTPs.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/threat-intel/cross-campaign/correlations', apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  PHISHING INTELLIGENCE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'analyze_phishing_url',
      description: 'Analyze URL for phishing — PhishTank, OpenPhish, URLhaus checks, visual similarity.',
      params: [{ name: 'url', type: 'string', description: 'URL to analyze', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/phishing/analyze',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ url: String(args.url) }),
          },
          ih
        ),
    },
    {
      name: 'analyze_phishing_email',
      description: 'Parse raw email for phishing — headers, SPF/DKIM/DMARC, URL extraction, risk score.',
      params: [{ name: 'raw_email', type: 'string', description: 'Full raw email source', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/phishing/analyze',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'text/plain' },
            body: String(args.raw_email),
          },
          ih
        ),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  MALWARE ANALYSIS
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'malware_family_detail',
      description: 'Malware family intelligence — IOCs, behavior, variants, YARA rules.',
      params: [{ name: 'family', type: 'string', description: 'Malware family name', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/malware-iocs/${encodeURIComponent(String(args.family))}`, apiKey, undefined, ih),
    },
    {
      name: 'sample_scan',
      description: 'Multi-provider hash fan-out — VirusTotal, MalwareBazaar, Triage, sandbox deep links.',
      params: [{ name: 'hash', type: 'string', description: 'File hash (MD5/SHA1/SHA256)', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/sample/scan?hash=${encodeURIComponent(String(args.hash))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  DARK WEB & CYBERCRIME
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'get_breach_forums',
      description: 'Breach forum monitoring — recent posts, actor claims, data leaks.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/breach-forums', apiKey, undefined, ih),
    },
    {
      name: 'search_telegram_leaks',
      description: 'Telegram leak channel search — leaked data, credentials, databases.',
      params: [{ name: 'q', type: 'string', description: 'Search query', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/telegram-leaks/search?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CRYPTO & FINANCIAL
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'trace_crypto_address',
      description: 'Cryptocurrency wallet tracing — balance, transactions, associated entities.',
      params: [
        { name: 'address', type: 'string', description: 'Wallet address', required: true },
        {
          name: 'chain',
          type: 'enum',
          description: 'Blockchain',
          required: false,
          enum: ['bitcoin', 'ethereum', 'monero'],
        },
      ],
      execute: (args) => {
        const p = new URLSearchParams({ address: String(args.address) });
        if (args.chain) p.set('chain', String(args.chain));
        return apiFetch(self, `/api/v1/crypto-trace?${p}`, apiKey, undefined, ih);
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  SEARCH & CORRELATION
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'unified_search',
      description:
        'Cross-source search across ALL feeds — briefings, IOCs, ransomware, detections, CVEs, writeups, cybercrime, malware.',
      params: [{ name: 'q', type: 'string', description: 'Search query', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/unified-search?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    {
      name: 'cross_correlate',
      description: 'Cross-correlation engine — CVE→actor→sector→coverage. Surfaces actionable intel gaps.',
      params: [
        { name: 'query', type: 'string', description: 'Correlation query', required: true },
        {
          name: 'type',
          type: 'enum',
          description: 'Query type',
          required: false,
          enum: ['cve', 'actor', 'sector', 'campaign'],
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/threat-intel/correlate',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ query: String(args.query), type: args.type ?? 'auto' }),
          },
          ih
        ),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  STIX / STRUCTURED INTEL
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'build_stix_bundle',
      description:
        'Build STIX 2.1 bundle for an indicator, actor, or CVE. Produces structured threat intelligence objects with relationships.',
      params: [
        { name: 'indicator', type: 'string', description: 'IOC (IP, domain, hash, URL)', required: false },
        { name: 'actor', type: 'string', description: 'Threat actor name', required: false },
        { name: 'cve', type: 'string', description: 'CVE ID', required: false },
      ],
      execute: (args) => {
        const body: Record<string, unknown> = { include_relationships: true };
        if (args.indicator) body.indicator = String(args.indicator);
        if (args.actor) body.actor = String(args.actor);
        if (args.cve) body.cve = String(args.cve);
        return apiFetch(
          self,
          '/api/v1/intel-bundle/build',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          },
          ih
        );
      },
    },
    {
      name: 'parse_threat_report',
      description:
        'Parse threat report to extract IOCs, actors, malware, MITRE techniques, CVEs. You MUST provide EITHER `text` (the report content) OR `url` (a public report URL) — one is required, the tool fails with "text or url required" if both are empty. Max 100K chars.',
      params: [
        {
          name: 'text',
          type: 'string',
          description: 'Report text to parse (max 100K chars). REQUIRED unless url is given.',
          required: false,
        },
        {
          name: 'url',
          type: 'string',
          description:
            'Public report URL to fetch+parse (content must be under 100K chars). REQUIRED unless text is given.',
          required: false,
        },
      ],
      execute: (args) => {
        if (!args.text && !args.url) {
          // Return a structured error (not a throw) so the agent observer can
          // surface it as a data gap instead of a tool failure that tanks the
          // tool-health success rate. The previous `Promise.reject` made this
          // tool report 0% success even though the route itself works fine —
          // the planner just wasn't passing text/url.
          return Promise.resolve({
            error: 'text or url required',
            iocs: { ipv4: [], ipv6: [], domains: [], urls: [], hashes: { md5: [], sha1: [], sha256: [] } },
            threat_actors: [],
            malware: [],
            mitre_techniques: [],
            cves: [],
            sectors: [],
            affected_products: [],
            summary: 'parse_threat_report was called without text or url — no report to parse.',
            meta: { extracted_at: new Date().toISOString(), method: 'error', confidence: 'low' },
          });
        }
        // Truncate text if too long
        let text = args.text ? String(args.text) : undefined;
        if (text && text.length > 95000) text = text.slice(0, 95000) + '\n[truncated]';
        return apiFetch(
          self,
          '/api/v1/report/parse',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ text, url: args.url }),
          },
          ih
        ).catch((err) => {
          // If URL content was too long, return a helpful error
          if (String(err).includes('too long')) {
            return {
              error: 'Report content exceeds 100K limit. Try with a shorter URL or paste relevant sections as text.',
            };
          }
          throw err;
        });
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  THREAT LANDSCAPE & PREDICTIVE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'get_threat_pulse',
      description:
        'Global threat overview — top actors, trending malware, most exploited CVEs, geopolitical events (past week).',
      params: [],
      execute: () => apiFetch(self, '/api/v1/threat-pulse', apiKey, undefined, ih),
    },
    {
      name: 'get_ransomware_map',
      description: 'Ransomware geographic map — victims by country and sector.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/ransomware-map', apiKey, undefined, ih),
    },
    {
      name: 'get_c2_tracker',
      description: 'C2 server tracker — active C2 infrastructure with framework identification.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/c2-tracker', apiKey, undefined, ih),
    },
    {
      name: 'get_predictive_forecasts',
      description: 'Threat forecasting — predicted emerging threats based on historical patterns.',
      params: [],
      execute: () => apiFetch(self, '/api/v1/threat-intel/predictive/forecasts', apiKey, undefined, ih),
    },

    {
      name: 'webamon_search',
      description:
        "Search Webamon's domain index — 750M+ scanned domains. Accepts Lucene field queries or plain text. Useful queries: domain_name:example.com (exact domain), meta.risk_score:>5 (risky), page_title:login, tag:nrd_*, fingerprint.tech:*wordpress. Use for domain risk assessment, infrastructure discovery, or finding related malicious infrastructure.",
      params: [
        { name: 'query', type: 'string', description: 'Lucene field query or free-text term', required: true },
        { name: 'size', type: 'number', description: 'Results per page (max 100)', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams({ search: String(args.query) });
        if (args.size) p.set('size', String(args.size));
        return apiFetch(self, `/api/v1/webamon/search?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'webamon_scan',
      description:
        'Submit a URL or domain to Webamon sandbox for live analysis — headers, certs, technologies, scripts, cookies, resources.',
      params: [{ name: 'url', type: 'string', description: 'URL or domain to scan', required: true }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/webamon/scan',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ submission_url: String(args.url) }),
          },
          ih
        ),
    },
    {
      name: 'webamon_report',
      description:
        'Get a published Webamon scan report by ID — certificates, servers, cookies, technologies, resources, scripts.',
      params: [{ name: 'report_id', type: 'string', description: 'Webamon report ID', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/webamon/report/${encodeURIComponent(String(args.report_id))}`, apiKey, undefined, ih),
    },
    {
      name: 'webamon_domain',
      description: 'Lookup full domain infrastructure from Webamon — DNS, CT logs, ASN, risk score, tech stack.',
      params: [{ name: 'domain', type: 'string', description: 'Domain name', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/webamon/domain/${encodeURIComponent(String(args.domain))}`, apiKey, undefined, ih),
    },
    {
      name: 'webamon_server',
      description: 'Lookup server intelligence from Webamon — IP, ASN, country, open ports, running services.',
      params: [{ name: 'ip', type: 'string', description: 'IP address', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/webamon/server/${encodeURIComponent(String(args.ip))}`, apiKey, undefined, ih),
    },
    {
      name: 'webamon_resource',
      description: 'Lookup file/resource intelligence from Webamon by SHA256 hash — MIME type, size, observed URLs.',
      params: [{ name: 'sha256', type: 'string', description: 'SHA256 hash', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/webamon/resource/${encodeURIComponent(String(args.sha256))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  EXPLOIT-DB & SECURITY UPDATES (NEW)
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'lookup_exploit_db',
      description:
        'Search Exploit-DB and related sources for exploits by CVE ID or keyword. Returns exploit references, platforms, and descriptions.',
      params: [{ name: 'q', type: 'string', description: 'CVE ID or search keyword', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/exploit-db?q=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },
    {
      name: 'lookup_cisa_kev',
      description:
        'CISA Known Exploited Vulnerabilities lookup. Filter by CVE, vendor, product, or days. Returns vulnerability details, due dates, and ransomware use flags.',
      params: [
        { name: 'q', type: 'string', description: 'CVE ID, vendor, or product keyword', required: false },
        { name: 'cve', type: 'string', description: 'Specific CVE ID', required: false },
        { name: 'vendor', type: 'string', description: 'Vendor name filter', required: false },
        { name: 'product', type: 'string', description: 'Product name filter', required: false },
        { name: 'days', type: 'number', description: 'Look back N days', required: false },
        {
          name: 'ransomware_only',
          type: 'boolean',
          description: 'Only vulnerabilities tied to ransomware',
          required: false,
        },
      ],
      execute: (args) => {
        const p = new URLSearchParams();
        if (args.q) p.set('q', String(args.q));
        if (args.cve) p.set('cve', String(args.cve));
        if (args.vendor) p.set('vendor', String(args.vendor));
        if (args.product) p.set('product', String(args.product));
        if (args.days) p.set('days', String(args.days));
        if (args.ransomware_only) p.set('ransomware_only', 'true');
        return apiFetch(self, `/api/v1/cisa-kev?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'lookup_security_updates',
      description:
        'Search vendor security advisories and CISA KEV for updates. Query by vendor, product, or keyword. Returns recent security patches and vulnerabilities.',
      params: [
        { name: 'q', type: 'string', description: 'Search keyword', required: false },
        { name: 'vendor', type: 'string', description: 'Vendor name', required: false },
        { name: 'product', type: 'string', description: 'Product name', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams();
        if (args.q) p.set('q', String(args.q));
        if (args.vendor) p.set('vendor', String(args.vendor));
        if (args.product) p.set('product', String(args.product));
        return apiFetch(self, `/api/v1/security-updates?${p}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'passive_dns_lookup',
      description:
        'Passive DNS history lookup — subdomains, historical IPs, first/last seen timestamps. Uses crt.sh and optional SecurityTrails for historical DNS data.',
      params: [{ name: 'q', type: 'string', description: 'Domain or IP address', required: true }],
      execute: (args) =>
        apiFetch(self, `/api/v1/passive-dns?query=${encodeURIComponent(String(args.q))}`, apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  BLOCKLISTS & DEFENSIVE OUTPUT
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'get_blocklists',
      description: 'Blocklist metadata — IP counts, generation time, available formats (pfSense, iptables, Suricata).',
      params: [],
      execute: () => apiFetch(self, '/api/v1/blocklists/meta', apiKey, undefined, ih),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  DETECTION RULE VALIDATION & CONVERSION
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'validate_detection_rule',
      description:
        'Validate a detection rule before delivering it: YARA (braces, sections, string refs, hex tokens, duplicate names), Sigma (schema + logsource + detection + condition identifiers), Suricata/Snort (header grammar, msg/sid/rev, local sid range), osquery (read-only guard, paren balance, known tables). Always run this on generated rules; fix reported errors before returning them.',
      params: [
        {
          name: 'kind',
          type: 'enum',
          description: 'Rule kind',
          required: true,
          enum: ['yara', 'sigma', 'suricata', 'snort', 'osquery'],
        },
        { name: 'source', type: 'string', description: 'Full rule text to validate', required: true },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/rules/validate',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ kind: String(args.kind), source: String(args.source) }),
          },
          ih
        ),
    },
    {
      name: 'convert_sigma_rule',
      description:
        'Convert a Sigma rule to Splunk SPL or Microsoft Sentinel KQL. Handles field modifiers (contains/startswith/endswith/re/null/gt/lt), multi-value lists, N-of expansions, and optional field-name mapping.',
      params: [
        { name: 'yaml', type: 'string', description: 'Sigma rule YAML source', required: true },
        { name: 'target', type: 'enum', description: 'Target query language', required: true, enum: ['splunk', 'kql'] },
        {
          name: 'field_map_json',
          type: 'string',
          description: 'Optional JSON object mapping Sigma field names to target names',
          required: false,
        },
      ],
      execute: (args) => {
        let fieldNameMap: Record<string, string> | undefined;
        if (args.field_map_json) {
          try {
            fieldNameMap = JSON.parse(String(args.field_map_json)) as Record<string, string>;
          } catch {
            return Promise.resolve({ error: 'field_map_json is not valid JSON' });
          }
        }
        return apiFetch(
          self,
          '/api/v1/rules/sigma/convert',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ yaml: String(args.yaml), target: String(args.target), fieldNameMap }),
          },
          ih
        );
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  OBSERVABLE EXTRACTION (DETERMINISTIC)
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'extract_observables_fast',
      description:
        'Deterministic regex-based IOC extraction from raw text — no AI. Handles defanged indicators (hxxp, [.], [at], [dot]); extracts IPs, domains, URLs, emails, hashes, CVEs, mutexes, registry keys, file paths, crypto addresses with positions. Use for large inputs or literal extraction; use parse_threat_report for actors/mitre/context.',
      params: [
        {
          name: 'text',
          type: 'string',
          description: 'Raw text to extract observables from (max 500k chars)',
          required: true,
        },
        {
          name: 'max_hits',
          type: 'number',
          description: 'Cap on unique observables returned (default 2000)',
          required: false,
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/observables/extract',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              text: String(args.text ?? '').slice(0, 500_000),
              ...(args.max_hits ? { maxHits: Number(args.max_hits) } : {}),
            }),
          },
          ih
        ),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  STATIC FILE TRIAGE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'static_triage_file',
      description:
        'Static file triage from base64 bytes (max ~6MB decoded): magic-byte family detection, SHA-256 (+MD5/SHA-1), entropy per section, PE header parse, packer signals (UPX etc.), embedded artifacts (embedded PE/nested zip/OLE). No execution — pure structural analysis.',
      params: [
        { name: 'data_base64', type: 'string', description: 'Base64-encoded file bytes', required: true },
        { name: 'filename', type: 'string', description: 'Original filename hint (optional)', required: false },
      ],
      execute: (args) => {
        const b64 = String(args.data_base64 ?? '').replace(/\s+/g, '');
        if (!b64) return Promise.resolve({ error: 'data_base64 is required' });
        const approxBytes = Math.floor((b64.length * 3) / 4);
        if (approxBytes > 8 * 1024 * 1024)
          return Promise.resolve({ error: `file too large for static triage (${approxBytes} bytes > 8MB limit)` });
        return apiFetch(
          self,
          '/api/v1/file/triage-static',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ dataBase64: b64, ...(args.filename ? { filename: String(args.filename) } : {}) }),
          },
          ih
        );
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  NETWORK SIGNAL ANALYTICS
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'detect_c2_beaconing',
      description:
        'Score connection timestamps to one destination for C2 beacon periodicity: mean/stddev inter-arrival, jitter ratio, payload-size consistency. Returns 0-100 beacon score with verdict.',
      params: [
        {
          name: 'timestamps',
          type: 'string',
          description: 'Comma-separated timestamps (epoch ms or ISO 8601)',
          required: true,
        },
        { name: 'destination', type: 'string', description: 'Destination ip or host:port', required: false },
        {
          name: 'bytes',
          type: 'string',
          description: 'Optional comma-separated per-connection byte counts',
          required: false,
        },
      ],
      execute: (args) => {
        const parse = (s: unknown) =>
          String(s ?? '')
            .split(',')
            .map((v) => v.trim())
            .filter(Boolean);
        const ts = parse(args.timestamps);
        if (ts.length < 4) return Promise.resolve({ error: 'need at least 4 timestamps' });
        const bytes = args.bytes ? parse(args.bytes).map(Number).filter(Number.isFinite) : undefined;
        return apiFetch(
          self,
          '/api/v1/net-analytics/beacon',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              timestamps: ts,
              ...(args.destination ? { destination: String(args.destination) } : {}),
              ...(bytes && bytes.length ? { bytes } : {}),
            }),
          },
          ih
        );
      },
    },
    {
      name: 'detect_dns_tunneling',
      description:
        'Heuristic DNS-tunneling detection over query names targeting one zone: label length distribution, Shannon entropy, uniqueness ratio. Returns 0-100 tunnel score with verdict and indicators.',
      params: [
        { name: 'queries', type: 'string', description: 'Newline/comma-separated DNS query names', required: true },
        {
          name: 'zone',
          type: 'string',
          description: 'Authoritative zone; inferred from queries when omitted',
          required: false,
        },
      ],
      execute: (args) => {
        const queries = String(args.queries ?? '')
          .split(/[\n,]+/)
          .map((q) => q.trim())
          .filter(Boolean);
        if (queries.length < 5) return Promise.resolve({ error: 'need at least 5 DNS queries' });
        return apiFetch(
          self,
          '/api/v1/net-analytics/dns-tunnel',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ queries, ...(args.zone ? { zone: String(args.zone) } : {}) }),
          },
          ih
        );
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  RECIPES (executable playbooks)
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'get_recipe',
      description:
        'Fetch a proven multi-step investigation playbook (file-triage, phishing-email, c2-identification, dns-tunnel-hunt, report-ioc-sweep). Returns ordered steps with tool names, argument templates ({input}/{ioc} placeholders), and why each step matters. Follow it step-by-step when the query matches.',
      params: [
        {
          name: 'recipe_id',
          type: 'enum',
          description: 'Playbook to fetch',
          required: true,
          enum: ['file-triage', 'phishing-email', 'c2-identification', 'dns-tunnel-hunt', 'report-ioc-sweep'],
        },
      ],
      execute: (args) => {
        const recipe = getRecipeDetail(String(args.recipe_id));
        if (!recipe)
          return Promise.resolve({
            error: `unknown recipe "${String(args.recipe_id)}"`,
            available: RECIPES.map((r) => r.id),
          });
        return Promise.resolve({ ok: true, ...recipe });
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  ENDPOINT ACQUISITION (VELOCIRAPTOR BRIDGE)
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'velo_list_clients',
      description:
        'List Velociraptor-managed endpoints (hostname, OS, arch, labels, last-seen). Optional hostname search. Requires VELO_API_URL configured — returns {configured:false} gracefully when not.',
      params: [
        { name: 'search', type: 'string', description: 'Hostname/client-id filter', required: false },
        { name: 'limit', type: 'number', description: 'Max clients (default 50, max 500)', required: false },
      ],
      execute: (args) => {
        const p = new URLSearchParams();
        if (args.search) p.set('search', String(args.search));
        if (args.limit) p.set('limit', String(Math.min(Number(args.limit), 500)));
        const qs = p.toString() ? `?${p}` : '';
        return apiFetch(self, `/api/v1/velociraptor/clients${qs}`, apiKey, undefined, ih);
      },
    },
    {
      name: 'velo_get_client',
      description: 'Get one managed endpoint by client id (C.xxxx) — OS build, labels, last check-in.',
      params: [{ name: 'client_id', type: 'string', description: "Velociraptor client id ('C.1234')", required: true }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/client',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ client_id: String(args.client_id) }),
          },
          ih
        ),
    },
    {
      name: 'velo_list_flows',
      description:
        'List recent collections (flows) on an endpoint — artifact names, state (RUNNING/FINISHED/ERROR), created time.',
      params: [
        { name: 'client_id', type: 'string', description: 'Velociraptor client id', required: true },
        { name: 'limit', type: 'number', description: 'Max flows (default 20)', required: false },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/flows',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              client_id: String(args.client_id),
              ...(args.limit ? { limit: Number(args.limit) } : {}),
            }),
          },
          ih
        ),
    },
    {
      name: 'velo_collect_artifact',
      description:
        'Launch a Velociraptor artifact collection on a managed endpoint (evidence acquisition): e.g. Windows.KapeFiles.Collect, Custom.Detection.*, Windows.Sysinternals.Autoruns. Returns flow id; poll with velo_get_flow_status then fetch rows with velo_get_flow_results.',
      params: [
        { name: 'client_id', type: 'string', description: 'Velociraptor client id', required: true },
        { name: 'artifacts', type: 'string', description: 'Comma-separated artifact names (max 10)', required: true },
        {
          name: 'parameters_json',
          type: 'string',
          description: 'Optional JSON object of artifact env parameters',
          required: false,
        },
        { name: 'urgent', type: 'boolean', description: 'Queue ahead of scheduled hunts', required: false },
      ],
      execute: (args) => {
        let parameters: Record<string, string> | undefined;
        if (args.parameters_json) {
          try {
            parameters = JSON.parse(String(args.parameters_json)) as Record<string, string>;
          } catch {
            return Promise.resolve({ error: 'parameters_json is not valid JSON' });
          }
        }
        return apiFetch(
          self,
          '/api/v1/velociraptor/collect',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              client_id: String(args.client_id),
              artifacts: String(args.artifacts)
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean)
                .slice(0, 10),
              ...(parameters ? { parameters } : {}),
              urgent: args.urgent === true,
            }),
          },
          ih
        );
      },
    },
    {
      name: 'velo_get_flow_status',
      description: 'Poll a Velociraptor collection status — state, duration, bytes collected, files loaded.',
      params: [
        { name: 'client_id', type: 'string', description: 'Velociraptor client id', required: true },
        {
          name: 'flow_id',
          type: 'string',
          description: "Flow id from velo_collect_artifact ('F.xxxx')",
          required: true,
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/flow',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ client_id: String(args.client_id), flow_id: String(args.flow_id) }),
          },
          ih
        ),
    },
    {
      name: 'velo_get_flow_results',
      description:
        'Fetch collected rows from a finished Velociraptor collection (VQL results table with columns + pagination). This is the evidence payload for the investigation.',
      params: [
        { name: 'client_id', type: 'string', description: 'Velociraptor client id', required: true },
        { name: 'flow_id', type: 'string', description: 'Flow id', required: true },
        { name: 'artifact', type: 'string', description: 'Filter to one collected artifact', required: false },
        { name: 'offset', type: 'number', description: 'Row offset for pagination', required: false },
        { name: 'rows', type: 'number', description: 'Max rows per call (default 100, max 1000)', required: false },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/results',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              client_id: String(args.client_id),
              flow_id: String(args.flow_id),
              ...(args.artifact ? { artifact: String(args.artifact) } : {}),
              ...(args.offset ? { offset: Number(args.offset) } : {}),
              ...(args.rows ? { rows: Math.min(Number(args.rows), 1000) } : {}),
            }),
          },
          ih
        ),
    },

    {
      name: 'velo_create_hunt',
      description:
        'Launch a Velociraptor HUNT across all managed endpoints (or a label subset) — fleet-wide sweep for IOCs/artifacts. Returns hunt id; poll with velo_get_hunt. Use for proactive sweeps after confirming an IOC on one endpoint.',
      params: [
        { name: 'artifacts', type: 'string', description: 'Comma-separated artifact names (max 10)', required: true },
        { name: 'parameters_json', type: 'string', description: 'Optional JSON artifact parameters', required: false },
        {
          name: 'label',
          type: 'string',
          description: 'Restrict to endpoints with this label (omit = all endpoints)',
          required: false,
        },
        { name: 'expire_hours', type: 'number', description: 'Hunt expiry in hours (default 7 days)', required: false },
      ],
      execute: (args) => {
        let parameters: Record<string, string> | undefined;
        if (args.parameters_json) {
          try {
            parameters = JSON.parse(String(args.parameters_json)) as Record<string, string>;
          } catch {
            return Promise.resolve({ error: 'parameters_json is not valid JSON' });
          }
        }
        return apiFetch(
          self,
          '/api/v1/velociraptor/hunts/create',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              artifacts: String(args.artifacts)
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean)
                .slice(0, 10),
              ...(parameters ? { parameters } : {}),
              ...(args.label ? { label: String(args.label) } : {}),
              ...(args.expire_hours ? { expire_hours: Number(args.expire_hours) } : {}),
            }),
          },
          ih
        );
      },
    },
    {
      name: 'velo_get_hunt',
      description: 'Poll a Velociraptor hunt — state, scheduled/completed/erroring client counts.',
      params: [{ name: 'hunt_id', type: 'string', description: "Hunt id ('H.xxxx')", required: true }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/hunt',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ hunt_id: String(args.hunt_id) }),
          },
          ih
        ),
    },
    {
      name: 'velo_list_hunts',
      description: 'List recent Velociraptor hunts across the fleet — descriptions, states, client completion counts.',
      params: [{ name: 'limit', type: 'number', description: 'Max hunts (default 20)', required: false }],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/velociraptor/hunts',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ ...(args.limit ? { limit: Number(args.limit) } : {}) }),
          },
          ih
        ),
    },

    // ══════════════════════════════════════════════════════════════════════
    //  REPORT DELIVERY
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'share_saved_report',
      description:
        'Publish a saved report at a public share URL (capability-token link, no login needed) and optionally attach MSSP branding (orgName/logoUrl/accent/footer/classification). Use as the final delivery step after saving an investigation report.',
      params: [
        {
          name: 'report_id',
          type: 'string',
          description: 'Saved-report id from POST /api/v1/saved-reports',
          required: true,
        },
        {
          name: 'branding_json',
          type: 'string',
          description: 'Optional branding JSON: orgName, logoUrl, accent, footer, classification',
          required: false,
        },
      ],
      execute: (args) => {
        const run = async (): Promise<unknown> => {
          if (args.branding_json) {
            try {
              const branding = JSON.parse(String(args.branding_json));
              await apiFetch(
                self,
                `/api/v1/saved-reports/${encodeURIComponent(String(args.report_id))}/branding`,
                apiKey,
                {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ branding }),
                },
                ih
              );
            } catch {
              /* non-fatal — share still proceeds */
            }
          }
          return apiFetch(
            self,
            `/api/v1/saved-reports/${encodeURIComponent(String(args.report_id))}/share`,
            apiKey,
            { method: 'POST' },
            ih
          );
        };
        return run();
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  SAMPLE SUBMISSION (DETONATION BRIDGE)
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'submit_sample_for_analysis',
      description:
        'Upload a suspicious file (base64, max ~32MB decoded) to analysis providers: Hybrid Analysis detonation (Windows 10 sandbox) and/or VirusTotal multi-engine scan. Returns per-provider submission ids/links; poll with get_sample_analysis_status. Use after static_triage_file when deeper behavioral evidence is needed.',
      params: [
        { name: 'data_base64', type: 'string', description: 'Base64-encoded sample bytes', required: true },
        { name: 'filename', type: 'string', description: 'Original filename', required: false },
        {
          name: 'providers',
          type: 'string',
          description: "Comma-separated subset: 'hybridanalysis,virustotal' (default both)",
          required: false,
        },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/sample-submission/upload',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              dataBase64: String(args.data_base64 ?? '').replace(/\s+/g, ''),
              ...(args.filename ? { filename: String(args.filename).slice(0, 200) } : {}),
              ...(args.providers
                ? {
                    providers: String(args.providers)
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean),
                  }
                : {}),
            }),
          },
          ih
        ),
    },
    {
      name: 'get_sample_analysis_status',
      description:
        'Poll analysis results for a submitted sample: VirusTotal analysis id (multi-engine verdict stats) and/or Hybrid Analysis sha256 (detonation state, threat score, AV detection ratio).',
      params: [
        {
          name: 'virustotal_analysis_id',
          type: 'string',
          description: 'Analysis id from submit_sample_for_analysis',
          required: false,
        },
        { name: 'sha256', type: 'string', description: 'Sample SHA-256 (for Hybrid Analysis state)', required: false },
      ],
      execute: (args) => {
        const vtId = args.virustotal_analysis_id ? String(args.virustotal_analysis_id) : '';
        const sha = args.sha256 ? String(args.sha256).toLowerCase() : '';
        if (!vtId && !sha) return Promise.resolve({ error: 'virustotal_analysis_id or sha256 required' });
        return apiFetch(
          self,
          '/api/v1/sample-submission/status',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ ...(vtId ? { virustotalAnalysisId: vtId } : {}), ...(sha ? { sha256: sha } : {}) }),
          },
          ih
        );
      },
    },

    // ══════════════════════════════════════════════════════════════════════
    //  IR & RESPONSE
    // ══════════════════════════════════════════════════════════════════════
    {
      name: 'generate_ir_playbook',
      description: 'AI-generate incident response playbook — steps, tools, timeline, criticality.',
      params: [
        {
          name: 'scenario',
          type: 'string',
          description: 'Incident type (ransomware, phishing, data breach, etc.)',
          required: true,
        },
        { name: 'actor', type: 'string', description: 'Known threat actor (optional)', required: false },
      ],
      execute: (args) =>
        apiFetch(
          self,
          '/api/v1/ir-playbooks/generate',
          apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ scenario: String(args.scenario), actor: args.actor }),
          },
          ih
        ),
    },
  ];
}

/**
 * Produce a compact, structured summary of a tool result for the observer LLM.
 *
 * Per the agent-harness observation contract, every tool response fed to the
 * planner/observer should carry a one-line `summary` plus the key fields the
 * LLM needs to decide the next action — not a raw JSON blob truncated mid-
 * array. This switch dispatches on the tool name and extracts the fields that
 * matter for that tool's domain; unknown tools fall back to bounded JSON.
 *
 * The output is always a string (for prompt embedding) and always ≤ maxLen.
 */
export function summarizeToolResult(tool: string, result: unknown, maxLen = 2000): string {
  const summary = toolSummary(tool, result);
  if (summary.length <= maxLen) return summary;
  return summary.slice(0, maxLen) + `\n... [truncated, ${summary.length} chars total]`;
}

/**
 * Per-tool structured extractor. Returns a compact string of the form:
 *   `<one-line verdict> | <key=value> ... | raw: <bounded json>`
 * The leading verdict line is what the observer needs to decide the next
 * action without parsing the full payload; the trailing raw slice preserves
 * detail for fields the extractor does not know about.
 */
function toolSummary(tool: string, result: unknown): string {
  if (!result || typeof result !== 'object') {
    return String(result ?? '(no data)');
  }
  const data = result as Record<string, unknown>;
  const parts: string[] = [];

  // ── Shared verdict/score extraction (most reputation/enrichment tools) ──
  const verdict = pickVerdict(data);
  const score = pickScore(data);
  const items = pickArray(data, ['items', 'results', 'records', 'iocs', 'indicators', 'providers', 'sources']);

  switch (tool) {
    // ── IOC reputation / deep enrichment ─────────────────────────────────
    case 'check_ioc':
    case 'enrich_ioc_deep':
    case 'maltiverse_verify':
    case 'lookup_tre_ge': {
      parts.push(verdict ? `verdict=${verdict}` : 'verdict=unknown');
      if (score !== null) parts.push(`score=${score}`);
      if (data.malicious === true) parts.push('malicious=true');
      if (typeof data.asn === 'string') parts.push(`asn=${data.asn}`);
      if (typeof data.country === 'string') parts.push(`geo=${data.country}`);
      if (items) parts.push(`providers=${items.length}`);
      return (
        parts.join(' | ') +
        rawTail(data, ['verdict', 'score', 'malicious', 'asn', 'country', 'items', 'results', 'providers'])
      );
    }

    // ── Vulnerability intel ──────────────────────────────────────────────
    case 'lookup_cve':
    case 'lookup_cisa_kev': {
      const cvss = (data.cvss as Record<string, unknown> | undefined)?.score ?? data.cvssScore;
      const epss = (data.epss as Record<string, unknown> | undefined)?.score ?? data.epssScore;
      parts.push(data.kev === true ? 'kev=listed' : 'kev=no');
      if (cvss !== undefined && cvss !== null) parts.push(`cvss=${cvss}`);
      if (epss !== undefined && epss !== null) parts.push(`epss=${epss}`);
      if (typeof data.exploit_status === 'string') parts.push(`exploit=${data.exploit_status}`);
      if (Array.isArray(data.threat_actors) && data.threat_actors.length)
        parts.push(`actors=${data.threat_actors.length}`);
      return parts.join(' | ') + rawTail(data, ['kev', 'cvss', 'epss', 'exploit_status', 'threat_actors', 'patch_url']);
    }

    // ── Actor / ransomware profiling ────────────────────────────────────
    case 'enrich_actor':
    case 'get_ransomware_group_profile':
    case 'search_malpedia':
    case 'actor_timeline': {
      const name = data.name ?? data.actor ?? data.group;
      if (typeof name === 'string') parts.push(`actor=${name}`);
      const malware = pickArray(data, ['malware', 'malware_families', 'tools']);
      if (malware) parts.push(`malware=${malware.length}`);
      const mitre = pickArray(data, ['mitre', 'techniques', 'ttps', 'attack_patterns']);
      if (mitre) parts.push(`mitre=${mitre.length}`);
      const aliases = pickArray(data, ['aliases', 'also_known_as', 'names']);
      if (aliases) parts.push(`aliases=${aliases.length}`);
      return (
        parts.join(' | ') + rawTail(data, ['name', 'actor', 'malware', 'mitre', 'techniques', 'aliases', 'description'])
      );
    }

    // ── Domain / host / DNS intel ───────────────────────────────────────
    case 'lookup_domain':
    case 'lookup_dns':
    case 'lookup_reverse_dns':
    case 'lookup_ipinfo':
    case 'lookup_asn':
    case 'lookup_builtwith':
    case 'lookup_certificate_transparency': {
      if (typeof data.domain === 'string') parts.push(`domain=${data.domain}`);
      if (typeof data.ip === 'string') parts.push(`ip=${data.ip}`);
      if (typeof data.asn === 'string' || typeof data.asn === 'number') parts.push(`asn=${data.asn}`);
      if (typeof data.registrar === 'string') parts.push(`registrar=${data.registrar}`);
      if (typeof data.created === 'string') parts.push(`created=${data.created}`);
      if (items) parts.push(`records=${items.length}`);
      return (
        parts.join(' | ') +
        rawTail(data, ['domain', 'ip', 'asn', 'registrar', 'created', 'records', 'items', 'results'])
      );
    }

    // ── Hash / sample analysis ──────────────────────────────────────────
    case 'sample_scan':
    case 'traceix_lookup': {
      parts.push(verdict ? `verdict=${verdict}` : 'verdict=unknown');
      if (typeof data.malicious === 'boolean') parts.push(`malicious=${data.malicious}`);
      const detections = pickArray(data, ['detections', 'scans', 'engines']);
      if (detections) parts.push(`detections=${detections.length}`);
      return parts.join(' | ') + rawTail(data, ['verdict', 'malicious', 'detections', 'scans', 'engines']);
    }

    // ── Search / feed / list tools ──────────────────────────────────────
    case 'unified_search':
    case 'darkweb_multi_search':
    case 'cyber_news':
    case 'get_cyber_crime_news':
    case 'get_ransomware_activity':
    case 'get_victim_releaks':
    case 'breach_disclosures_recent':
    case 'get_threat_pulse': {
      if (items) parts.push(`results=${items.length}`);
      if (typeof data.total === 'number') parts.push(`total=${data.total}`);
      const first = items && items.length > 0 ? items[0] : null;
      if (first && typeof first === 'object') {
        const title = (first as Record<string, unknown>).title ?? (first as Record<string, unknown>).name;
        if (typeof title === 'string') parts.push(`top="${title.slice(0, 80)}"`);
      }
      return parts.join(' | ') + rawTail(data, ['items', 'results', 'total', 'records']);
    }

    // ── Relationship / correlation ──────────────────────────────────────
    case 'get_relationships':
    case 'correlate_iocs':
    case 'cross_correlate':
    case 'cross_campaign_correlate': {
      const rels = pickArray(data, ['relationships', 'correlations', 'edges', 'links']);
      if (rels) parts.push(`relationships=${rels.length}`);
      const nodes = pickArray(data, ['nodes', 'iocs', 'entities']);
      if (nodes) parts.push(`nodes=${nodes.length}`);
      return parts.join(' | ') + rawTail(data, ['relationships', 'correlations', 'edges', 'nodes', 'iocs']);
    }

    case 'validate_detection_rule': {
      const valid = data.valid === true;
      parts.push(valid ? 'valid=true' : 'valid=false');
      if (typeof data.rules === 'number') parts.push(`rules=${data.rules}`);
      const errs = Array.isArray(data.errors) ? (data.errors as unknown[]) : null;
      const warns = Array.isArray(data.warnings) ? (data.warnings as unknown[]) : null;
      if (errs) parts.push(`errors=${errs.length}`);
      if (warns) parts.push(`warnings=${warns.length}`);
      return parts.join(' | ') + rawTail(data, ['valid', 'rules', 'errors', 'warnings', 'parsed', 'tables']);
    }
    case 'convert_sigma_rule': {
      if (data.ok !== true && typeof data.error === 'string')
        return `convert failed | error=${String(data.error).slice(0, 120)}`;
      parts.push('ok=true');
      if (typeof data.query === 'string') parts.push(`query="${data.query.slice(0, 160)}"`);
      return parts.join(' | ');
    }
    case 'extract_observables_fast': {
      const counts = data.counts as Record<string, number> | undefined;
      let total = 0;
      if (counts && typeof counts === 'object') {
        for (const v of Object.values(counts)) total += Number(v) || 0;
        const nz = Object.entries(counts).filter(([, v]) => v > 0);
        if (nz.length) parts.push(`counts={${nz.map(([k, v]) => `${k}:${v}`).join(', ')}}`);
      }
      parts.push(`total=${total}`);
      if (data.truncated === true) parts.push('truncated=true');
      return parts.join(' | ') + rawTail(data, ['counts', 'observables']);
    }
    case 'static_triage_file': {
      const ft = data.fileType as { family?: string; detail?: string } | undefined;
      if (ft?.family) parts.push(`family=${ft.family}${ft.detail ? `(${ft.detail})` : ''}`);
      const ent = data.entropy as { overall?: number } | undefined;
      if (typeof ent?.overall === 'number') parts.push(`entropy=${ent.overall}`);
      const sig = data.packerSignals as unknown[] | undefined;
      if (sig) parts.push(`packerSignals=${sig.length}`);
      const emb = data.embeddedArtifacts as unknown[] | undefined;
      if (emb) parts.push(`embedded=${emb.length}`);
      if (typeof data.sha256 === 'string') parts.push(`sha256=${data.sha256.slice(0, 16)}…`);
      return (
        parts.join(' | ') +
        rawTail(data, [
          'fileType',
          'entropy',
          'packerSignals',
          'embeddedArtifacts',
          'sha256',
          'pe',
          'zipMembers',
          'scriptIndicators',
          'md5',
          'sha1',
        ])
      );
    }
    case 'detect_c2_beaconing': {
      const st = data.intervalStats as { jitterRatio?: number; meanMs?: number } | undefined;
      if (typeof data.beaconScore === 'number') parts.push(`beaconScore=${data.beaconScore}`);
      if (typeof data.verdict === 'string') parts.push(`verdict=${data.verdict}`);
      if (st?.jitterRatio !== undefined) parts.push(`jitter=${st.jitterRatio}`);
      if (st?.meanMs !== undefined) parts.push(`meanInterval=${st.meanMs}ms`);
      if (typeof data.connections === 'number') parts.push(`connections=${data.connections}`);
      return parts.join(' | ') + rawTail(data, ['intervalStats', 'beaconScore', 'verdict', 'connections', 'notes']);
    }
    case 'detect_dns_tunneling': {
      if (typeof data.tunnelScore === 'number') parts.push(`tunnelScore=${data.tunnelScore}`);
      if (typeof data.verdict === 'string') parts.push(`verdict=${data.verdict}`);
      if (typeof data.entropyAvg === 'number') parts.push(`entropy=${data.entropyAvg}`);
      if (typeof data.avgLabelLength === 'number') parts.push(`avgLabel=${data.avgLabelLength}`);
      if (typeof data.queriesAnalyzed === 'number') parts.push(`queries=${data.queriesAnalyzed}`);
      return (
        parts.join(' | ') +
        rawTail(data, [
          'tunnelScore',
          'verdict',
          'entropyAvg',
          'avgLabelLength',
          'queriesAnalyzed',
          'indicators',
          'sampleLabels',
        ])
      );
    }

    default: {
      // Unknown tool — best-effort generic summary, then bounded raw JSON.
      if (verdict) parts.push(`verdict=${verdict}`);
      if (score !== null) parts.push(`score=${score}`);
      if (items) parts.push(`items=${items.length}`);
      const header = parts.length > 0 ? parts.join(' | ') + ' | ' : '';
      return header + `raw: ${boundedJson(data, 1200)}`;
    }
  }
}

/** Extract a human-readable verdict from common field names. */
function pickVerdict(data: Record<string, unknown>): string | null {
  for (const k of ['verdict', 'status', 'classification', 'reputation', 'threat']) {
    const v = data[k];
    if (typeof v === 'string' && v.length > 0 && v.length < 40) return v;
  }
  if (data.malicious === true) return 'malicious';
  if (data.malicious === false) return 'benign';
  return null;
}

/** Extract a numeric score from common field names. */
function pickScore(data: Record<string, unknown>): number | null {
  for (const k of ['score', 'confidence_score', 'risk_score', 'threat_score', 'abuse_score']) {
    const v = data[k];
    if (typeof v === 'number') return v;
  }
  return null;
}

/** Return the first array found under any of the candidate keys. */
function pickArray(data: Record<string, unknown>, keys: string[]): unknown[] | null {
  for (const k of keys) {
    if (Array.isArray(data[k]) && data[k].length > 0) return data[k] as unknown[];
  }
  return null;
}

/**
 * Append a bounded raw-JSON tail for fields the per-tool extractor didn't
 * surface. Omits the `omit` keys so the tail carries only new detail.
 */
function rawTail(data: Record<string, unknown>, omit: string[]): string {
  const pruned: Record<string, unknown> = {};
  const omitSet = new Set(omit);
  let size = 0;
  for (const [k, v] of Object.entries(data)) {
    if (omitSet.has(k)) continue;
    // Skip large nested arrays/objects — they blow the budget and the count
    // is already surfaced by the header.
    if (Array.isArray(v) && v.length > 5) {
      pruned[k] = `[${v.length} items]`;
    } else if (v && typeof v === 'object') {
      pruned[k] = '{...}';
    } else {
      pruned[k] = v;
    }
    size++;
    if (size >= 12) break; // cap the tail breadth
  }
  const json = JSON.stringify(pruned);
  if (json.length <= 2) return ''; // empty object
  return ` | raw: ${json.slice(0, 800)}`;
}

/** Bounded JSON stringification for the unknown-tool fallback. */
function boundedJson(data: unknown, maxLen: number): string {
  const json = JSON.stringify(data, null, 0);
  if (json.length <= maxLen) return json;
  return json.slice(0, maxLen) + `... [+${json.length - maxLen} chars]`;
}

export function describeTools(tools: AgentTool[]): string {
  return tools
    .map((t) => {
      // Compress: first sentence of description only, omit optional param
      // descriptions. This cuts tool-description context ~40% (from ~6K to
      // ~3.6K tokens) leaving more context for working memory + data.
      const shortDesc = t.description.split('.')[0];
      const requiredParams = t.params.filter((p) => p.required);
      const paramStr = requiredParams.length === 0 ? '' : ` (${requiredParams.map((p) => p.name).join(', ')})`;
      return `- ${t.name}${paramStr}: ${shortDesc}`;
    })
    .join('\n');
}
