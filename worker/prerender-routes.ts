/**
 * Single source of truth for the routes prerendered to static HTML at build
 * time (scripts/prerender.mjs renders each one to dist/__prerendered/<slug>.html;
 * worker/router.ts serves those files directly so users see real content
 * before React parses).
 *
 * Lives in its own IMPORT-FREE leaf module because two consumers need the list
 * from opposite sides of an existing dependency edge: worker/router.ts (the
 * serving side) already imports from worker/og-rewriter.ts (the rewriting
 * side), so og-rewriter importing the map back from router.ts would create a
 * cycle. Both import from here instead.
 *
 * Cloudflare Assets canonicalizes `*.html` paths by redirecting to the
 * extension-less form (e.g. /foo.html → 307 /foo). env.ASSETS.fetch()
 * returns the redirect verbatim and our code doesn't follow it, so we
 * have to ask for the canonical (extension-less) URL directly. The
 * file is still at __prerendered/<slug>.html on disk.
 *
 * Slug rule (must match scripts/prerender.mjs): '/' → 'home',
 * '/dfir/diamond' → 'dfir__diamond' (slashes replaced with double
 * underscore to avoid creating nested directories).
 */
export const PRERENDERED_ROUTES = new Map<string, string>([
  // ── Portfolio ─────────────────────────────────────────────────
  ['/', '/__prerendered/home'],
  ['/about', '/__prerendered/about'],
  ['/skills', '/__prerendered/skills'],
  ['/experience', '/__prerendered/experience'],
  ['/projects', '/__prerendered/projects'],
  ['/anarchy', '/__prerendered/anarchy'],
  ['/blog', '/__prerendered/blog'],

  // ── Landings ──────────────────────────────────────────────────
  ['/dfir', '/__prerendered/dfir'],
  ['/threatintel', '/__prerendered/threatintel'],
  ['/radar', '/__prerendered/radar'],
  ['/threatintel/catalog', '/__prerendered/threatintel__catalog'],
  ['/threatintel/actors/hub', '/__prerendered/threatintel__actors__hub'],
  ['/threatintel/actors/attribution', '/__prerendered/threatintel__actors__attribution'],
  ['/threatintel/campaigns/cross', '/__prerendered/threatintel__campaigns__cross'],
  ['/threatintel/campaigns/reference', '/__prerendered/threatintel__campaigns__reference'],
  ['/threatintel/breach-hub', '/__prerendered/threatintel__breach-hub'],
  ['/threatintel/darkweb/watch', '/__prerendered/threatintel__darkweb__watch'],
  ['/threatintel/darkweb/markets', '/__prerendered/threatintel__darkweb__markets'],
  ['/threatintel/darkweb/deepdark', '/__prerendered/threatintel__darkweb__deepdark'],
  ['/threatintel/darkweb/crime', '/__prerendered/threatintel__darkweb__crime'],
  ['/threatintel/darkweb/infostealer', '/__prerendered/threatintel__darkweb__infostealer'],
  ['/threatintel/darkweb/leaks', '/__prerendered/threatintel__darkweb__leaks'],
  ['/threatintel/ransomware-hub', '/__prerendered/threatintel__ransomware-hub'],
  ['/threatintel/darkweb/recon', '/__prerendered/threatintel__darkweb__recon'],
  ['/threatintel/predictive/dashboard', '/__prerendered/threatintel__predictive__dashboard'],
  ['/threatintel/predictive/global-pulse', '/__prerendered/threatintel__predictive__global-pulse'],
  ['/threatintel/predictive/threat-pulse', '/__prerendered/threatintel__predictive__threat-pulse'],
  ['/threatintel/predictive/certstream', '/__prerendered/threatintel__predictive__certstream'],
  ['/threatintel/predictive/metrics', '/__prerendered/threatintel__predictive__metrics'],
  ['/threatintel/predictive/predictions', '/__prerendered/threatintel__predictive__predictions'],
  ['/threatintel/predictive/predictive', '/__prerendered/threatintel__predictive__predictive'],
  ['/threatintel/detections/detections', '/__prerendered/threatintel__detections__detections'],
  ['/threatintel/detections/disarm', '/__prerendered/threatintel__detections__disarm'],
  ['/threatintel/detections/yara', '/__prerendered/threatintel__detections__yara'],
  ['/threatintel/detections/signal', '/__prerendered/threatintel__detections__signal'],
  ['/threatintel/flowviz', '/__prerendered/threatintel__flowviz'],
  ['/threatintel/phishing/phish', '/__prerendered/threatintel__phishing__phish'],
  ['/threatintel/phishing/urls', '/__prerendered/threatintel__phishing__urls'],
  ['/threatintel/phishing/scam', '/__prerendered/threatintel__phishing__scam'],
  ['/threatintel/supply-chain', '/__prerendered/threatintel__supply-chain'],
  ['/threatintel/external/external', '/__prerendered/threatintel__external__external'],
  ['/threatintel/entity-graph', '/__prerendered/threatintel__entity-graph'],
  ['/threatintel/external/awesome', '/__prerendered/threatintel__external__awesome'],
  ['/threatintel/feeds/catalog', '/__prerendered/threatintel__feeds__catalog'],
  ['/threatintel/feeds/sources', '/__prerendered/threatintel__feeds__sources'],
  ['/threatintel/feeds/quality', '/__prerendered/threatintel__feeds__quality'],
  ['/threatintel/feeds/scheduler', '/__prerendered/threatintel__feeds__scheduler'],
  ['/threatintel/feeds/threatfeeds', '/__prerendered/threatintel__feeds__threatfeeds'],
  ['/threatintel/feeds/mythreatintel', '/__prerendered/threatintel__feeds__mythreatintel'],
  ['/threatintel/infra/cloud', '/__prerendered/threatintel__infra__cloud'],
  ['/threatintel/infra/infra', '/__prerendered/threatintel__infra__infra'],
  ['/threatintel/infra/webamon', '/__prerendered/threatintel__infra__webamon'],
  ['/threatintel/infra/domain', '/__prerendered/threatintel__infra__domain'],
  ['/threatintel/iocs/live', '/__prerendered/threatintel__iocs__live'],
  ['/threatintel/iocs/enrichment', '/__prerendered/threatintel__iocs__enrichment'],
  ['/threatintel/iocs/feeds', '/__prerendered/threatintel__iocs__feeds'],
  ['/threatintel/iocs/entity', '/__prerendered/threatintel__iocs__entity'],
  ['/threatintel/iocs/c2', '/__prerendered/threatintel__iocs__c2'],
  ['/threatintel/iocs/map', '/__prerendered/threatintel__iocs__map'],
  ['/threatintel/iocs/correlation', '/__prerendered/threatintel__iocs__correlation'],
  ['/threatintel/wiki/wiki', '/__prerendered/threatintel__wiki__wiki'],
  ['/threatintel/wiki/mitre', '/__prerendered/threatintel__wiki__mitre'],
  ['/threatintel/wiki/f3ead', '/__prerendered/threatintel__wiki__f3ead'],
  ['/threatintel/wiki/f2t2ea', '/__prerendered/threatintel__wiki__f2t2ea'],
  ['/threatintel/wiki/ooda', '/__prerendered/threatintel__wiki__ooda'],
  ['/threatintel/wiki/kill-chain-v2', '/__prerendered/threatintel__wiki__kill-chain-v2'],
  ['/threatintel/wiki/unified-kill-chain', '/__prerendered/threatintel__wiki__unified-kill-chain'],
  ['/threatintel/wiki/insider', '/__prerendered/threatintel__wiki__insider'],
  ['/threatintel/wiki/owasp', '/__prerendered/threatintel__wiki__owasp'],
  ['/threatintel/wiki/llm', '/__prerendered/threatintel__wiki__llm'],
  ['/threatintel/malware/iocs', '/__prerendered/threatintel__malware__iocs'],
  ['/threatintel/malware/sandbox', '/__prerendered/threatintel__malware__sandbox'],
  ['/threatintel/malware/malpedia', '/__prerendered/threatintel__malware__malpedia'],
  ['/threatintel/malware/maltrail', '/__prerendered/threatintel__malware__maltrail'],
  ['/threatintel/osint/framework', '/__prerendered/threatintel__osint__framework'],
  ['/threatintel/osint/cli', '/__prerendered/threatintel__osint__cli'],
  ['/threatintel/osint/map', '/__prerendered/threatintel__osint__map'],
  ['/threatintel/osint/certs', '/__prerendered/threatintel__osint__certs'],
  ['/threatintel/osint/toolbox', '/__prerendered/threatintel__osint__toolbox'],
  ['/threatintel/osint/secops', '/__prerendered/threatintel__osint__secops'],
  ['/threatintel/osint/directory', '/__prerendered/threatintel__osint__directory'],
  ['/threatintel/cti-bookmarks', '/__prerendered/threatintel__cti-bookmarks'],
  ['/threatintel/research-hub/reports', '/__prerendered/threatintel__research-hub__reports'],
  ['/threatintel/research-hub/ai', '/__prerendered/threatintel__research-hub__ai'],
  ['/threatintel/research-hub/agentic', '/__prerendered/threatintel__research-hub__agentic'],
  ['/threatintel/research-hub/writeups', '/__prerendered/threatintel__research-hub__writeups'],
  ['/threatintel/research-hub/signal', '/__prerendered/threatintel__research-hub__signal'],
  ['/threatintel/research-hub/redhunt', '/__prerendered/threatintel__research-hub__redhunt'],
  ['/threatintel/research-hub/redhunt-labs', '/__prerendered/threatintel__research-hub__redhunt-labs'],
  ['/threatintel/research-hub/volexity', '/__prerendered/threatintel__research-hub__volexity'],
  ['/threatintel/research-hub/post', '/__prerendered/threatintel__research-hub__post'],
  ['/threatintel/research-hub/attack-flow', '/__prerendered/threatintel__research-hub__attack-flow'],
  ['/threatintel/research-hub/knowledge', '/__prerendered/threatintel__research-hub__knowledge'],
  ['/threatintel/research-hub/ach', '/__prerendered/threatintel__research-hub__ach'],
  ['/threatintel/social/firehose', '/__prerendered/threatintel__social__firehose'],
  ['/threatintel/social/news', '/__prerendered/threatintel__social__news'],
  ['/threatintel/social/crypto-scam', '/__prerendered/threatintel__social__crypto-scam'],
  ['/threatintel/tools/copilot', '/__prerendered/threatintel__tools__copilot'],
  ['/threatintel/tools/mcp', '/__prerendered/threatintel__tools__mcp'],
  ['/threatintel/tools/stix-hub', '/__prerendered/threatintel__tools__stix-hub'],
  ['/threatintel/tools/tg-intel-search', '/__prerendered/threatintel__tools__tg-intel-search'],
  ['/threatintel/tools/socradar-tools', '/__prerendered/threatintel__tools__socradar-tools'],
  ['/threatintel/tools/directory', '/__prerendered/threatintel__tools__directory'],
  ['/threatintel/tools/darknet-intel', '/__prerendered/threatintel__tools__darknet-intel'],
  ['/threatintel/tools/unified-search', '/__prerendered/threatintel__tools__unified-search'],
  ['/threatintel/vera', '/__prerendered/threatintel__vera'],
  ['/threatintel/cves/cves', '/__prerendered/threatintel__cves__cves'],
  ['/threatintel/cves/advisories', '/__prerendered/threatintel__cves__advisories'],
  ['/threatintel/cves/resources', '/__prerendered/threatintel__cves__resources'],
  // ── DFIR: static catalogs & education ─────────────────────────
  ['/dfir/diamond', '/__prerendered/dfir__diamond'],
  ['/dfir/owasp', '/__prerendered/dfir__owasp'],
  ['/dfir/lolbins', '/__prerendered/dfir__lolbins'],
  ['/dfir/kill-chain', '/__prerendered/dfir__kill-chain'],
  ['/dfir/grc', '/__prerendered/dfir__grc'],
  ['/dfir/data-classification', '/__prerendered/dfir__data-classification'],
  ['/dfir/privacy-hub', '/__prerendered/dfir__privacy-hub'],

  // ── DFIR: utilities & decoders ────────────────────────────────
  ['/dfir/timestamp', '/__prerendered/dfir__timestamp'],
  ['/dfir/hash-calc', '/__prerendered/dfir__hash-calc'],
  ['/dfir/codec', '/__prerendered/dfir__codec'],
  ['/dfir/punycode', '/__prerendered/dfir__punycode'],
  ['/dfir/brand-impersonation', '/__prerendered/dfir__brand-impersonation'],

  // ── DFIR: image / media ───────────────────────────────────────
  ['/dfir/image-intel', '/__prerendered/dfir__image-intel'],
  ['/dfir/exif', '/__prerendered/dfir__exif'],

  // ── DFIR: file format analyzers ───────────────────────────────
  ['/dfir/plist-protobuf', '/__prerendered/dfir__plist-protobuf'],
  ['/dfir/pcap-triage', '/__prerendered/dfir__pcap-triage'],
  ['/dfir/registry-hive', '/__prerendered/dfir__registry-hive'],
  ['/dfir/evtx', '/__prerendered/dfir__evtx'],
  ['/dfir/sqlite', '/__prerendered/dfir__sqlite'],
  ['/dfir/ios-backup', '/__prerendered/dfir__ios-backup'],
  ['/dfir/apk-analyzer', '/__prerendered/dfir__apk-analyzer'],

  // ── DFIR: binary / log analyzers ──────────────────────────────
  ['/dfir/web-log', '/__prerendered/dfir__web-log'],
  ['/dfir/prefetch', '/__prerendered/dfir__prefetch'],
  ['/dfir/procedure-extract', '/__prerendered/dfir__procedure-extract'],
  ['/dfir/powershell-deobf', '/__prerendered/dfir__powershell-deobf'],

  // ── DFIR: detection & analysis ────────────────────────────────
  ['/dfir/rule-converter', '/__prerendered/dfir__rule-converter'],
  ['/dfir/prompt-injection', '/__prerendered/dfir__prompt-injection'],
  ['/dfir/pi-taxonomy', '/__prerendered/dfir__pi-taxonomy'],
  ['/dfir/mcp-audit', '/__prerendered/dfir__mcp-audit'],
  ['/dfir/cve-prioritizer', '/__prerendered/dfir__cve-prioritizer'],
  ['/dfir/fusion-exposure', '/__prerendered/dfir__fusion-exposure'],
  ['/dfir/risk-register', '/__prerendered/dfir__risk-register'],
  ['/dfir/attack-path', '/__prerendered/dfir__attack-path'],
  ['/dfir/grc-evidence', '/__prerendered/dfir__grc-evidence'],
  ['/dfir/vulnerability-ops', '/__prerendered/dfir__vulnerability-ops'],
  ['/dfir/ransomware-quant', '/__prerendered/dfir__ransomware-quant'],
  ['/dfir/patch-task-mgr', '/__prerendered/dfir__patch-task-mgr'],
  ['/dfir/soc-automation', '/__prerendered/dfir__soc-automation'],

  // ── DFIR: cloud security ──────────────────────────────────────
  ['/dfir/iam-hub', '/__prerendered/dfir__iam-hub'],
  ['/dfir/sg-analyzer', '/__prerendered/dfir__sg-analyzer'],
  ['/dfir/cloudtrail-triage', '/__prerendered/dfir__cloudtrail-triage'],
  ['/dfir/terraform-scan', '/__prerendered/dfir__terraform-scan'],

  // ── DFIR: API security ────────────────────────────────────────
  ['/dfir/openapi-audit', '/__prerendered/dfir__openapi-audit'],
  ['/dfir/secret-scan', '/__prerendered/dfir__secret-scan'],
  ['/dfir/medusa-scan', '/__prerendered/dfir__medusa-scan'],
  ['/dfir/graphql-audit', '/__prerendered/dfir__graphql-audit'],
  ['/dfir/osv-scan', '/__prerendered/dfir__osv-scan'],

  // ── DFIR: STIX ────────────────────────────────────────────────
  // ── DFIR: catalog + per-hub category landings (2026-06-17) ───
  // ── DFIR: catalog + per-hub category landings (2026-06-17) ───
  ['/dfir/catalog', '/__prerendered/dfir__catalog'],
  ['/dfir/threat-graph', '/__prerendered/dfir__threat-graph'],
  ['/dfir/ir-playbooks', '/__prerendered/dfir__ir-playbooks'],
  ['/dfir/stealer-parser', '/__prerendered/dfir__stealer-parser'],

  // ── DFIR: security frameworks ─────────────────────────────────
  ['/dfir/nhi', '/__prerendered/dfir__nhi'],
  ['/dfir/jwt', '/__prerendered/dfir__jwt'],
  ['/dfir/zero-trust-ai-agents', '/__prerendered/dfir__zero-trust-ai-agents'],

  // ── DFIR: dark web workbench ──────────────────────────────────
  ['/dfir/pgp-tool', '/__prerendered/dfir__pgp-tool'],

  // ── DFIR: investigator workbenches ────────────────────────────
  ['/dfir/domain-investigator', '/__prerendered/dfir__domain-investigator'],
  ['/dfir/ioc-investigate', '/__prerendered/dfir__ioc-investigate'],
  ['/dfir/username-investigator', '/__prerendered/dfir__username-investigator'],
  ['/dfir/yara-workbench', '/__prerendered/dfir__yara-workbench'],
  ['/dfir/stix-workbench', '/__prerendered/dfir__stix-workbench'],
  ['/dfir/malware-analyzer', '/__prerendered/dfir__malware-analyzer'],

  // ── DFIR: specialist tools ───────────────────────────────────
  ['/dfir/attack-navigator', '/__prerendered/dfir__attack-navigator'],
  ['/dfir/vuln-toolkit', '/__prerendered/dfir__vuln-toolkit'],
  ['/dfir/sec-headers-live', '/__prerendered/dfir__sec-headers-live'],
  ['/dfir/osint-mapper', '/__prerendered/dfir__osint-mapper'],
  ['/dfir/notebooks', '/__prerendered/dfir__notebooks'],

  // ── DFIR: triage & forensic tools ────────────────────────────
  ['/dfir/dnscope', '/__prerendered/dfir__dnscope'],
  ['/dfir/tracerules', '/__prerendered/dfir__tracerules'],
  ['/dfir/phone-hub', '/__prerendered/dfir__phone-hub'],
  ['/dfir/infostealer-intel', '/__prerendered/dfir__infostealer-intel'],

  // ── DFIR: AI agent tools ─────────────────────────────────────
  ['/dfir/agent-suite', '/__prerendered/dfir__agent-suite'],

  // ── DFIR: tools that fetch /api/v1/* on mount ─────────────────
  ['/dfir/phishing', '/__prerendered/dfir__phishing'],
  ['/dfir/whois-history', '/__prerendered/dfir__whois-history'],
  ['/dfir/passive-dns', '/__prerendered/dfir__passive-dns'],
  // /dfir/sql-workspace removed: the page (SqlWorkspace.tsx) has no route in
  // App.tsx, so this mapped to a prerender that was never generated — it was
  // served as the bare SPA shell, cached 24h as "prerendered".
  ['/dfir/open-directory', '/__prerendered/dfir__open-directory'],
  ['/dfir/exposure', '/__prerendered/dfir__exposure'],
  ['/dfir/exposed-host', '/__prerendered/dfir__exposed-host'],
  ['/dfir/cve', '/__prerendered/dfir__cve'],
  ['/dfir/cert-search', '/__prerendered/dfir__cert-search'],
  ['/dfir/asn', '/__prerendered/dfir__asn'],
  ['/dfir/breach', '/__prerendered/dfir__breach'],
  ['/dfir/url-preview', '/__prerendered/dfir__url-preview'],
  ['/dfir/subdomain-takeover', '/__prerendered/dfir__subdomain-takeover'],
  ['/dfir/extract', '/__prerendered/dfir__extract'],
  ['/dfir/google-dorks', '/__prerendered/dfir__google-dorks'],
  ['/dfir/linux-triage', '/__prerendered/dfir__linux-triage'],
  ['/dfir/email-defense', '/__prerendered/dfir__email-defense'],
  ['/dfir/dmarc-analyzer', '/__prerendered/dfir__dmarc-analyzer'],
  ['/dfir/dlp-scan', '/__prerendered/dfir__dlp-scan'],
  ['/dfir/wayback', '/__prerendered/dfir__wayback'],
  ['/dfir/log-parser', '/__prerendered/dfir__log-parser'],
  ['/dfir/socmint', '/__prerendered/dfir__socmint'],
  ['/dfir/eml', '/__prerendered/dfir__eml'],
  ['/dfir/email-rep', '/__prerendered/dfir__email-rep'],
  ['/dfir/email-osnit', '/__prerendered/dfir__email-osnit'],

  // ── ThreatIntel: static catalogs ──────────────────────────────
  // '/threatintel/briefings' removed from PRERENDERED_ROUTES: list is
  // data-driven (fetches /api/v1/briefings/list on mount). Prerendering
  // the empty initial state causes a React 18 hydration mismatch that
  // leaves the stale SSR'd list visible. Same root cause as the detail-
  // page fix above (DYNAMIC_ROUTE_FALLBACKS).

  // ── ThreatIntel: pages ────────────────────────────────────────
  ['/threatintel/about', '/__prerendered/threatintel__about'],
  ['/threatintel/mcp-search', '/__prerendered/threatintel__mcp-search'],
  ['/threatintel/live-center', '/__prerendered/threatintel__live-center'],
  ['/threatintel/telegram', '/__prerendered/threatintel__telegram'],
  ['/threatintel/source-health', '/__prerendered/threatintel__source-health'],
  ['/threatintel/soc-dashboard', '/__prerendered/threatintel__soc-dashboard'],

  // ── ThreatIntel: live-feed surfaces ───────────────────────────
  // '/threatintel/reddit' removed — redirect route, prerender is empty shell
  // '/threatintel/status' removed — redirect route, prerender is empty shell
  // '/threatintel/metrics' removed — redirect route, prerender is empty shell

  ['/threatintel/ransomware-live', '/__prerendered/threatintel__ransomware-live'],
  ['/threatintel/cyberpulse', '/__prerendered/threatintel__cyberpulse'],
  ['/threatintel/onion-watch', '/__prerendered/threatintel__onion-watch'],

  // ── Daily Briefs ────────────────────────────────────────────────
  ['/daily-briefs', '/__prerendered/daily-briefs'],

  // ── Phase 4 (2026-06-04): 43 real static routes that existed in App.tsx
  //    but had no entry here, so they were served as the bare SPA shell.
  //    See scripts/prerender.mjs for the matching ROUTES entries.

  // ── Portfolio (2) ────────────────────────────────────────────
  ['/admin', '/__prerendered/admin'],

  // ── DFIR: real pages (10) ────────────────────────────────────
  ['/dfir/asset-intel', '/__prerendered/dfir__asset-intel'],
  ['/dfir/blocklists', '/__prerendered/dfir__blocklists'],
  ['/dfir/ct-monitor', '/__prerendered/dfir__ct-monitor'],
  ['/dfir/file', '/__prerendered/dfir__file'],
  ['/dfir/host-graph', '/__prerendered/dfir__host-graph'],

  // ── Phase 5: New gap features ─────────────────────────────────
  ['/dfir/export-hub', '/__prerendered/dfir__export-hub'],
  ['/dfir/ai-suite', '/__prerendered/dfir__ai-suite'],
  ['/dfir/crypto-tracer', '/__prerendered/dfir__crypto-tracer'],
  ['/dfir/report-hub', '/__prerendered/dfir__report-hub'],
  ['/dfir/pivex', '/__prerendered/dfir__pivex'],
  ['/dfir/phishops', '/__prerendered/dfir__phishops'],
  ['/dfir/phishbook', '/__prerendered/dfir__phishbook'],
  ['/dfir/ai-threats', '/__prerendered/dfir__ai-threats'],
  ['/dfir/oss-feeds', '/__prerendered/dfir__oss-feeds'],

  // ── ThreatIntel: real pages, not redirects (28) ──────────────
  ['/threatintel/tools/stix-bundles', '/__prerendered/threatintel__tools__stix-bundles'],
  ['/dfir/copilot', '/__prerendered/dfir__copilot'],
  ['/dfir/orkl', '/__prerendered/dfir__orkl'],
  ['/dfir/wifi-investigation', '/__prerendered/dfir__wifi-investigation'],
  ['/dfir/traceix', '/__prerendered/dfir__traceix'],
  ['/dfir/nhi-scan', '/__prerendered/dfir__nhi-scan'],
  ['/dfir/whoxy', '/__prerendered/dfir__whoxy'],
  ['/dfir/winreg', '/__prerendered/dfir__winreg'],
  ['/dfir/sigbase', '/__prerendered/dfir__sigbase'],
  ['/dfir/lots', '/__prerendered/dfir__lots'],
  ['/dfir/malapi', '/__prerendered/dfir__malapi'],
  ['/dfir/car', '/__prerendered/dfir__car'],
  ['/dfir/capec', '/__prerendered/dfir__capec'],
  ['/dfir/hijacklibs', '/__prerendered/dfir__hijacklibs'],
  ['/dfir/veris', '/__prerendered/dfir__veris'],
  ['/dfir/engage', '/__prerendered/dfir__engage'],
  // ── Standalone SPA pages ──────────────────────────────────────
  ['/threatintel/external/cerast', '/__prerendered/threatintel__external__cerast'],
  ['/threatintel/external/threatmon', '/__prerendered/threatintel__external__threatmon'],
  // ── Previously shell-only static pages (SEO/CWV: crawlable first paint) ─
  ['/argus', '/__prerendered/argus'],
  ['/dfir/agent-history', '/__prerendered/dfir__agent-history'],
  ['/dfir/csrf-poc', '/__prerendered/dfir__csrf-poc'],
  ['/dfir/detection-chokepoints', '/__prerendered/dfir__detection-chokepoints'],
  ['/dfir/one-time-secret', '/__prerendered/dfir__one-time-secret'],
  ['/dfir/xss-payloads', '/__prerendered/dfir__xss-payloads'],
  ['/threatintel/detection-wiki', '/__prerendered/threatintel__detection-wiki'],
  ['/threatintel/threat-actor-monitor', '/__prerendered/threatintel__threat-actor-monitor'],
  ['/threatintel/alerts', '/__prerendered/threatintel__alerts'],
  ['/threatintel/infra/ai-honeypot', '/__prerendered/threatintel__infra__ai-honeypot'],
  ['/threatintel/infra/ai-llm-intel', '/__prerendered/threatintel__infra__ai-llm-intel'],
]);
