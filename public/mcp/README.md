# DFIR-ThreatIntel MCP - tool catalog

**423 tools** | live at `https://pranithjain.qzz.io/api/mcp` (streamable HTTP).

## Quick start

1. Generate an API key at `/api/v1/admin/keys` (admin token required).
2. Drop one of the config snippets in this directory into your MCP client config:
   - **Claude Desktop**: `claude-desktop.json` -> `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
   - **Cursor**: `cursor.json` -> `~/.cursor/mcp.json`.
   - **VS Code (Copilot)**: `vscode-mcp.json` -> `.vscode/mcp.json` in your workspace.
3. Replace `<your-api-key>` with a real key.
4. Restart your client. Tools appear as `mcp__dfir-threatintel__<tool_name>`.

## Tools by category

### other (309)

- `ai_advisories` - AI advisory firehose — per-package GHSA advisories, cvelistV5 CVE commits matched to known AI CVEs, tool release trains (garak, PyRIT, promptfoo, litellm, vllm, ollama, langchain, MCP SDK, MITRE ATLAS, OWASP GenAI), ExploitDB PoCs.
- `ai_playbook_cve_refs` - CVE references cited by the AI Security Playbook, enriched against our local CISA KEV snapshot so you can see which are known-exploited. Enrichment comes from our own feed, never upstream.
- `ai_playbook_get_layer` - Get one AI Security Playbook division by roman id (I..VIII) or slug, including the risk identifiers it defines.
- `ai_playbook_get_risk_id` - Get one AI-security risk identifier by id (e.g. LLM01, ASI06), with its name, taxonomy and defining division.
- `ai_playbook_list_layers` - List the 8 system divisions of the AI Security Playbook (I model .. VIII governance), with chapter counts and the risk identifiers each division defines.
- `ai_playbook_list_risk_ids` - List the 20 AI-security risk identifiers: OWASP Top 10 for LLM Applications (LLM01-LLM10) and the Agentic Security Index (ASI01-ASI10). Filter by scheme or layer, or search by id/name.
- `ai_playbook_stats` - AI Security Playbook manifest stats: division/chapter/identifier counts, KEV matches, licence scope, and edge cache state.
- `ai_research` - AI security research feed — Hacktron, Palo Alto Unit42, Cloud Security Alliance, BleepingComputer AI-filtered items with links back upstream.
- `ai_threats_get` - Return the full entry body for an AI-capable threat actor — includes full brief, aliases, raw TTP markdown, reported/activity dates, and MITRE technique IDs. Use ai_threats_list first to discover slugs.
- `ai_threats_list` - List AI-capable threat actors from the Cybershujin tracker (79 entries, MIT). Each entry documents real-world confirmed use of AI/LLMs by threat actors. Filter by table (main/deepfake), category, TTP, or keyword.
- `ai_threats_stats` - Return cache + manifest stats for the AI Threat Actors data: total entries, index load state, body-cache hit ratios.
- `ai_vuln_get` - Full body for one AI vuln: description, references, aliases, affected packages, KEV dates, EPSS percentile. Call ai_vulns first to discover IDs.
- `ai_vulns` - Realtime AI vulnerability tracking — EUVD + NVD + OSV watchlist (litellm, vllm, langchain, mcp, transformers…), CISA/EU KEV overlap, FIRST EPSS exploit-probability. KEV-listed rows sort first.
- `anarchy_get_course` - Return the full body of a single Anarchy course by ID. Includes title, full description, tags, and external href. Use anarchy_list_courses first to discover IDs.
- `anarchy_list_courses` - List courses from the Anarchy (kazamadono.github.io) portal — 1708 courses across 20 tracks (AI/ML, Low Level, PsyOps, Defensive, Offensive, OSINT, Game Hacking, BugBounty, Crypto, Reversing, Cloud, Forensics, CTF, Blockchain, IoT/HW, Dev/CS, Math). Filter by tag, difficulty, provider, hours, or free-text query. Daily sync from https://kazamadono.github.io/courses.json.
- `anarchy_recommend` - Rank Anarchy courses for a user library. Deterministic scorer (no LLM): tag affinity with saved/done/doing courses, same-provider affinity, and a difficulty ladder one rung above completed courses. Excludes library courses. Empty library returns beginner-friendly popular picks.
- `anarchy_similar` - Courses similar to one Anarchy course: shared tracks first, then same provider, then same difficulty. Use anarchy_list_courses first to discover IDs.
- `anarchy_stats` - Return cache + manifest stats for the Anarchy course catalog: course counts, top tags, sync timestamps, and LRU cache hit/miss ratios.
- `briefings_related` - Find prior briefings related to a given briefing — links by shared IOCs (domains/IPs/hashes/URL hosts) or shared tactic keywords, ranked by match count then severity then recency. Case-triage linkage (port of the CTI case-queue related-case matcher).
- `btc_abuse_check` - Check a Bitcoin address for abuse/scam reports on ChainAbuse. Returns the `verdict` field, which is authoritative: "flagged" means abuse reports exist, "clean" means the lookup completed and found none, and "unknown" means the lookup did NOT complete (missing CHAINABUSE_API_KEY or upstream error) — an "unknown" verdict is NOT evidence of a clean address and must not be reported as such. On "flagged", reports include categories (phishing, ransomware, scam, etc.), descriptions, and associated scam types. Useful for tracing illicit crypto transactions.
- `bw_get_breach` - Return the full body of a single breach/leak claim by slug. Includes description, source URL, activity sector, and references. Use bw_list_breaches first to discover slugs.
- `bw_list_breaches` - List live breach/leak/ransomware claims from free public trackers. Filter by threat actor group, category (ransomware, data_breach, combo_list, source_code, credential_leak), severity, country, days back, or free-text keyword.
- `bw_list_groups` - List threat actor groups tracked in the Breach Watch database with their breach counts and top category. Filter by keyword or minimum count.
- `bw_stats` - Return cache + manifest stats for the Breach Watch data: breach counts, group counts, categories, and LRU body-cache hit/miss ratios.
- `cairn_get_family` - Return the full CAIRN family report (summary + verbatim markdown body): samples, binary details, TTPs, detection guidance. Use cairn_list_families first to discover slugs.
- `cairn_get_rule` - Return the full body of a CAIRN rule: strings, condition, confidence, artifact class, family, and reference. Use cairn_list_rules first to discover names.
- `cairn_list_families` - List the 10 published CAIRN AI-malware families (PROMPTLOCK, HONESTCUE, CLOSEDQUORUM, TEAMPCP, LAMEHUG, …) with platform and archetype. Filter by archetype (A0–A11) or keyword.
- `cairn_list_filters` - List the 27 CAIRN VirusTotal acquisition channels (24 enabled): discovery/prompt/agentic/runtime/api/evasion/offensive/script/hunt queries with min detections. Filter by category or keyword.
- `cairn_list_rules` - List CAIRN cognitive-artifact detection rules (26 total: 9 T1 primitive, 8 T2 behavioral, 9 T3 family attribution). Filter by tier, family, or keyword.
- `cairn_scan_text` - Run CAIRN tiered rules over pasted VT-metadata scan text (AV labels, PE strings, sandbox IOCs, ScriptBlock text). Returns T1/T2/T3 matches sorted with family attribution first. Pure local matching, no binary needed.
- `cairn_stats` - Return CAIRN manifest stats: rule counts by tier, filter/family/archetype counts, source + license, and edge cache ratios.
- `campaigns_get` - Return the full details of a single threat campaign entry by slug, including writeup links, TTPs, targets, and geography. Use campaigns_list first to discover slugs.
- `campaigns_list` - List currently active threat campaigns from the curated tracker. Filter by status (active, dormant, concluded), category (ransomware, apt, malware, phishing, c2, supply-chain, cyber-espionage, hacktivism, other), or keyword.
- `campaigns_stats` - Return cache + manifest stats for the Active Campaigns tracker: total campaigns, active vs dormant/concluded breakdown, categories, and index cache status.
- `capec_get` - Return the full details of a single CAPEC attack pattern by slug: abstraction, likelihood, severity, prerequisites, CWE/ATT&CK links. Use capec_list first to discover slugs.
- `capec_list` - List MITRE CAPEC attack patterns: how adversaries exploit weaknesses, with CWE and ATT&CK links. Filter by abstraction (Meta, Standard, Detailed), status, domain, CWE ID, technique ID, or keyword.
- `capec_stats` - Return cache + manifest stats for the CAPEC directory: totals by abstraction and status.
- `car_get` - Return the full details of a single CAR analytic by slug: ATT&CK coverage, D3FEND mappings, and implementation names. Use car_list first to discover slugs.
- `car_list` - List MITRE Cyber Analytics Repository (CAR) analytics: validated detection ideas mapped to ATT&CK techniques. Filter by technique ID (e.g. "T1059"), platform, or keyword.
- `car_stats` - Return cache + manifest stats for the CAR directory: total analytics and covered technique count.
- `cerast_domain_search` - Search Cerast Intelligence for exposed paths and misconfigurations on observed domains. Returns domain, path, category, impact level, OpenPageRank score, version, and first-seen date. Useful for discovering staging/dev environments, exposed admin panels, and misconfigured endpoints.
- `convert_sigma_rule` - Convert a Sigma rule to Splunk SPL or Microsoft Sentinel KQL. Handles field modifiers (contains/startswith/endswith/re/null), multi-value lists, N-of expansions, and optional field-name mapping.
- `cti_bookmarks_get` - Return the full details of a single CTI bookmark by slug. Use cti_bookmarks_list first to discover slugs.
- `cti_bookmarks_list` - List curated CTI bookmarks (threat intel links, tools, feeds, frameworks). Filter by level (Operational, Tactical, Strategic, Tools), category, integration status (live, reference, missing), or keyword.
- `cti_bookmarks_stats` - Return cache + manifest stats for the CTI Bookmarks directory: totals by level and integration status (live/reference/missing gap counts).
- `cyber_news` - Aggregate cybersecurity news from 11 RSS feeds across 5 tiers (Advisory, Exploit, Research, Vendor, Community). Supports tier filtering and keyword search. Sources: CISA, Rapid7, Packet Storm, BleepingComputer, Hacker News, GitHub Security, ZDI, Reddit netsec/exploitdev/bugbounty.
- `db_get_brief` - Return the full daily intelligence brief for a given type and date. Includes executive summary, key findings, events/incidents, and structured data. Use db_list_briefs to discover available dates.
- `db_list_briefs` - List available daily intelligence briefs by type (cyber, deepfake, disaster). Returns dates and metadata. Use db_get_brief to retrieve the full brief body.
- `db_stats` - Return cache + manifest stats for the Daily Briefs data: index loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.
- `dehash_lookup` - Look up a cryptographic hash (md5/sha1/sha256/sha384/sha512) against Dehash.lt to find its plaintext value. Useful for cracking password hashes or identifying known hash values. No API key required.
- `denali_evaluate_activity` - Run Denali stateless checks over runtime activity JSON: repeated failed AI sign-ins (≥3/24h per actor+app), high-impact consent grants, retrieval→mutation sequences (5-min window). Proves sequence + identity only — never intent.
- `denali_get_doc` - Return a verbatim Denali ADR/guide body (markdown): onboarding contracts, correlation semantics, runtime detection design. Use denali_list_docs first to discover slugs.
- `denali_get_rule` - Return the full semantics of one Denali rule: inputs, thresholds/windows/scopes, and what the evidence does NOT prove. Use denali_list_rules first to discover UIDs.
- `denali_list_docs` - List the 38 Denali architecture ADRs + guides (onboarding contracts, code-to-cloud, runtime AIDR, hosted multi-tenancy). Filter by kind or keyword.
- `denali_list_rules` - List the 9 deterministic Denali correlation rules (3 issue + 6 runtime detection) with exact UIDs, thresholds, and evidence bounds. Filter by kind or keyword.
- `denali_stats` - Return Denali manifest stats: rule/taxonomy/doc counts, evidence principles, source + license, and edge cache ratios.
- `depx_check` - Check if a specific package is known-malicious. Queries the OpenSSF Malicious Packages database and OSV. Returns verdict (clean/malicious/unknown) with advisory details. Inspired by projectdiscovery/depx.
- `depx_feed` - Feed of recently disclosed malicious packages from the OpenSSF Malicious Packages database. Returns packages disclosed within the time window, with ecosystem breakdown and disclosure age. Inspired by projectdiscovery/depx.
- `depx_stats` - Supply-chain intelligence statistics — ecosystem breakdown, recent advisory counts, and disclosure trends from the OpenSSF Malicious Packages database.
- `detect_c2_beaconing` - Score connection timestamps to one destination for C2 beacon periodicity: mean/stddev inter-arrival, jitter ratio, payload-size consistency. Returns 0-100 beacon score with verdict.
- `detect_dns_tunneling` - Heuristic DNS-tunneling detection over query names targeting one zone: label length distribution, Shannon entropy, uniqueness ratio → 0-100 tunnel score with verdict and indicators.
- `digest_analyze` - Get the analyst note for a Webamon daily threat brief or PCMedicalist digest: deterministic key signals plus a cached LLM assessment. Nothing generates on read — briefs are immutable per date.
- `dn_abuseipdb_blacklist` - Get AbuseIPDB blacklist of the most reported malicious IP addresses. Requires ABUSEIPDB_API_KEY.
- `dn_abuseipdb_check` - Check an IP address on AbuseIPDB for abuse reports: confidence score, ISP, country, report count, categories. Requires ABUSEIPDB_API_KEY.
- `dn_abuseipdb_check_block` - Check an entire CIDR network block for abuse reports on AbuseIPDB. Requires ABUSEIPDB_API_KEY.
- `dn_abuseipdb_reports` - Get individual abuse reports for an IP from AbuseIPDB with detailed comments and categories. Requires ABUSEIPDB_API_KEY.
- `dn_bazaar_hash` - Look up a malware sample in MalwareBazaar by MD5, SHA1, or SHA256 hash. Returns tags, signature, file type, first/last seen. Free, no key.
- `dn_bazaar_recent` - Get the most recently submitted malware samples from MalwareBazaar (last 100). Free, no key.
- `dn_bazaar_tag` - Search MalwareBazaar by tag or YARA signature name. Free, no key.
- `dn_greynoise_check` - Quick check: is this IP a known scanner or known benign service? Returns classification only (benign/malicious/unknown). Free, no key.
- `dn_greynoise_ip` - Look up an IP on GreyNoise Community: classification (benign/malicious/unknown), internet scanner detection, ASN, country. Free, no API key required.
- `dn_hibp_breach` - Get details of a specific data breach by name from HIBP: description, data classes, pwn count, breach date. Free, no key.
- `dn_hibp_data_classes` - List all data classes (types of compromised data) known to HIBP: emails, passwords, credit cards, SSNs, etc. Free, no key.
- `dn_hibp_latest` - Get the most recently added data breaches from HIBP. Free, no key.
- `dn_hibp_password` - Check if a password has appeared in known breaches using HIBP k-anonymity (only SHA-1 prefix sent). Returns breach count. Free, no key.
- `dn_hybrid_feed` - Get the latest malware detonation feed from Hybrid Analysis: recently analyzed samples with verdicts and threat scores. Requires HYBRID_ANALYSIS_API_KEY.
- `dn_hybrid_search` - Search Hybrid Analysis sandbox by file hash: verdict, AV detection rate, MITRE ATT&CK techniques, network indicators. Requires HYBRID_ANALYSIS_API_KEY.
- `dn_intelx_phonebook` - IntelligenceX Phonebook — find emails, domains, and URLs associated with a search term. Requires INTELX_API_KEY (paid).
- `dn_intelx_phonebook_results` - Retrieve IntelligenceX Phonebook search results by search_id. Requires INTELX_API_KEY.
- `dn_intelx_search` - Search IntelligenceX for leaked data, dark web content, paste sites, and breach archives. Requires INTELX_API_KEY (paid).
- `dn_intelx_search_results` - Retrieve results for an IntelligenceX search by search_id (from dn_intelx_search). Requires INTELX_API_KEY.
- `dn_otx_cve` - Look up threat intelligence for a CVE on AlienVault OTX: related pulses, indicators, and exploitation activity. Free, no key.
- `dn_otx_domain` - Look up threat intelligence for a domain on AlienVault OTX: pulse info, WHOIS, reputation, associated malware. Free, no key.
- `dn_otx_hash` - Look up threat intelligence for a file hash (MD5, SHA1, SHA256) on AlienVault OTX. Free, no key.
- `dn_otx_ip` - Look up threat intelligence for an IP address on AlienVault OTX: pulse info, reputation, country, ASN, associated malware. Free, no key.
- `dn_pulsedive_explore` - Explore linked indicators using Pulsedive advanced queries. Returns related IOCs with risk levels. Free, no key.
- `dn_pulsedive_indicator` - Look up an indicator (IP, domain, URL, or hash) on Pulsedive: risk level, threats, feeds, and linked indicators. Free, no key required.
- `dn_pulsedive_search` - Search Pulsedive indicators by value. Returns matching indicators with risk levels. Free, no key.
- `dn_ransomlook_groups` - List all ransomware groups tracked by RansomLook (582+). Free, no key.
- `dn_ransomlook_recent` - Fetch the most recent ransomware posts and victim claims from RansomLook. Free, no key.
- `dn_ransomware_country` - Get ransomware victims filtered by ISO 3166-1 alpha-2 country code from ransomware.live. Free, no key.
- `dn_ransomware_group` - Get a detailed profile for a specific ransomware group from ransomware.live: description, aliases, tools, TTPs, CVEs. Free, no key.
- `dn_ransomware_search` - Search ransomware victims by keyword (company name, domain, etc.) across ransomware.live. Free, no key.
- `dn_ransomware_sector` - Get ransomware victims filtered by sector/industry from ransomware.live. Free, no key.
- `dn_ransomware_victims` - Get all victims claimed by a specific ransomware group from ransomware.live. Free, no key.
- `dn_sources` - List all available darknet intel data sources with configuration status, API key status, tool counts, and free/paid indicators.
- `dn_threatfox_iocs` - Get recent IOCs from ThreatFox reported in the last N days. Free, no key.
- `dn_threatfox_malware` - Search ThreatFox IOCs by malware family using Malpedia naming. Free, no key.
- `dn_threatfox_search` - Search ThreatFox IOCs by IP, domain, hash, or URL. Free, no key.
- `dn_threatfox_tag` - Search ThreatFox IOCs by tag (e.g. Cobalt Strike, Emotet, AgentTesla). Free, no key.
- `dn_urlhaus_lookup` - Look up a URL or host in URLhaus for malware distribution. Free, no key.
- `dn_urlhaus_tag` - Search URLhaus entries by tag. Free, no key.
- `dn_vulners_exploit` - Search specifically for exploits (ExploitDB entries) on Vulners. Returns exploit code references and details. Free.
- `dn_vulners_id` - Look up a vulnerability by ID (CVE, EDB, GHSA) on Vulners. Returns CVSS, description, affected products, and exploit availability. Free, no key.
- `dn_vulners_search` - Search the Vulners vulnerability database using Lucene queries. Returns matching CVEs/exploits with CVSS scores. Free.
- `dw_get_attack` - Return the MITRE ATT&CK coverage index from detection.wiki: tactics with total rules per tactic and technique counts. This mirrors https://detection.wiki/attack/ and https://detection.wiki/rules/.
- `dw_get_attack_technique` - Return a single ATT&CK technique body as it appears under https://detection.wiki/attack/Txxxx/: technique metadata, rule count, tactic, and cross-references. Use dw_list_techniques or dw_get_attack first to discover IDs.
- `dw_get_lab` - Return the full body of a single detection.wiki lab: title, description, ATT&CK techniques, KQL queries, and raw markdown body. Use dw_list_labs first to discover slugs.
- `dw_get_platform` - Return detailed event catalog for a single detection.wiki platform (e.g. macOS ESF, auditd, AWS CloudTrail, Defender XDR, Entra ID): total events, sampled event types, and source URL. Use dw_list_platforms first to discover slugs.
- `dw_get_security_auditing_event` - Return a single Microsoft-Windows-Security-Auditing event by Event ID: title, channel, sample/rule flags, and ATT&CK tactic. Use dw_list_security_auditing_events first to discover IDs.
- `dw_get_technique` - Return a single MITRE ATT&CK technique from the detection.wiki mirror: name, tactic, detection rule count, and whether it is a sub-technique. Use dw_list_techniques first to discover IDs.
- `dw_get_windows_provider` - Return a single Windows Event Log provider by slug: event count, samples, rules, and channel. Use dw_list_windows_providers first to discover slugs.
- `dw_list_labs` - List hands-on detection labs from detection.wiki: title, author, date, description, and mapped ATT&CK techniques. Filter by keyword. Use dw_get_lab to fetch the full body with KQL queries.
- `dw_list_platforms` - List the 17 platform telemetry catalogs indexed by detection.wiki: Windows, AWS, Azure, M365, GCP, Kubernetes, Okta, GitHub, and more. Each entry has event count and rule coverage.
- `dw_list_rules` - List sampled detection rules from detection.wiki (15,957 total): rule ID, title, vendor (Sigma/Elastic/Splunk/Kusto/YARA-L/Panther/Sublime), technique, tactic, platform, and status. Full rule bodies live at detection.wiki per technique; use dw_get_attack_technique for per-technique coverage.
- `dw_list_security_auditing_events` - List Microsoft-Windows-Security-Auditing events (Security channel, 426 total): event ID, title, and whether it has sample data or a mapped detection rule. Filter by keyword, ATT&CK tactic, sample/rule presence. Use dw_get_security_auditing_event to fetch a single event.
- `dw_list_techniques` - List MITRE ATT&CK techniques indexed by detection.wiki: technique ID, name, tactic, and number of detection rules. Filter by tactic, keyword, minimum rule count, or subtechnique inclusion. Use dw_get_technique to fetch a single technique.
- `dw_list_windows_providers` - List Windows Event Log providers from the detection.wiki Windows catalog: provider name, slug, event count, samples with field definitions, and detection-rule coverage. Covers 1,518 providers (74 sampled with counts, 103,315 total events). Filter by keyword or whether they have rules.
- `dw_stats` - Return cache + manifest stats for the detection.wiki mirror: 15k rules, 218 techniques, 1,518 Windows providers, 426 Security-Auditing events, 17 platforms, 6 labs, and LRU body-cache info.
- `email_check_registration` - Check which platforms an email address is registered on using site-specific APIs (not just HTTP status codes). Returns rich profile metadata when available. Inspired by kaifcodec/user-scanner (MIT, 2.4k stars). Checks 20+ platforms: GitHub, GitLab, Instagram, TikTok, Etsy, Spotify, Steam, and more.
- `email_list_registration_platforms` - List all platforms available for email registration checking. Returns platform IDs, names, and categories.
- `engage_get` - Return the details of a single Engage approach by slug: goal, phase, and matrix link. Use engage_list first to discover slugs.
- `engage_list` - List MITRE Engage adversary-engagement approaches: deception/denial techniques organized by goal (Collect, Detect, Prevent, Direct, Disrupt, Reassure, Motivate, Elicit…) and phase (Prepare, Engage, Understand). Filter by goal, phase, or keyword.
- `engage_stats` - Return cache + manifest stats for the Engage matrix: phases, goals, approach count.
- `escape_get` - Return one incident docket: assigned task, summary, 7-stage containment chain, absent guardrails, disputed figures, sources. Use escape_list first to discover ids.
- `escape_list` - List AI agent containment-failure incidents (15-entry seed registry, CBS-scored). Filter by class (containment-breach/agent-hijack/supply-chain/tool-misuse/injection), severity, evidence tier, absent guardrail, autonomy, or keyword.
- `escape_stats` - Registry stats (entries, Tier A, eval-env breaches, autonomous count, median dwell, most-absent guardrail, days-since clock inputs), per-guardrail absent counts, month timeline buckets, and the 10 guardrail definitions + provenance trackers.
- `etda_get_actor` - Return the full actor body for a single APT threat actor from the ETDA Threat Group Cards vertical. Includes names (with vendor sources), aliases, country, sponsor, motivation, description, sectors, tools, operations, counter operations, MITRE ATT&CK link, and information references. Use etda_list_actors first to discover slugs.
- `etda_get_aptmap_data` - Return a specific APTmap malware analysis data file by filename. These are frequency-distribution statistics from 29GB of PE malware samples attributed to APT groups. Use etda_list_aptmap_data first to discover available files.
- `etda_list_actors` - List APT threat actors from the ETDA Threat Group Cards vertical. 504 actors (416 APT, 54 other, 34 unknown). Filter by category, country, MITRE ATT&CK reference, or keyword. Each entry includes aliases, country, sponsor, motivation, observed period, and counts of tools/operations.
- `etda_list_aptmap_data` - List all available APTmap malware analysis data files from the AndreaCristaldi/APTmap repo. These contain frequency-distribution statistics from 29GB of PE malware samples attributed to APT groups. Includes certificates, exports, functions, hashes, imports, resources, sections, strings, xrefs, file types, and file sizes.
- `etda_list_sectors` - List all observed target sectors across the ETDA actor database. Returns the count of actors that target each sector.
- `etda_stats` - Return cache + manifest stats for the APT Actors data: index loaded, APTmap loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.
- `extract_observables_fast` - Deterministic regex-based IOC extraction from raw text — no AI. Handles defanged indicators (hxxp, [.], [at], [dot]); extracts IPs, domains, URLs, emails, hashes, CVEs, mutexes, registry keys, file paths, and crypto addresses with positions.
- `fbi_wanted_list` - List current FBI wanted persons with pagination. No API key required.
- `fbi_wanted_search` - Search the FBI Wanted database for wanted persons by name. Returns titles, descriptions, reward amounts, and field offices. No API key required.
- `flowviz_list_techniques` - Search the FlowViz ATT&CK technique index (MITRE enterprise techniques with tactic names) used for attack-flow action nodes and autocomplete. Filter by keyword (id or name) and/or tactic id (e.g. TA0001). Upstream: davidljohnson/flowviz (MIT).
- `flowviz_validate_graph` - Validate a FlowViz attack-flow graph ({nodes[], edges[]}) structurally: node types, technique-id shape, dangling edges, source-excerpt grounding. Returns errors + warnings without calling any LLM.
- `frameworks_list` - List integrated security frameworks (TID-CMM and UTIOM): ids, versions, homepage, licence, and domain/phase counts. Data replicated from tid-cmm.com (CC BY 4.0) and utiom.de (CC BY-SA 4.0).
- `fullhunt_domain` - Discover attack surface for a domain via FullHunt: open ports, technologies, subdomains, ASN, cloud provider, and WHOIS data. Requires FULLHUNT_API_KEY secret (free at fullhunt.io).
- `fullhunt_subdomains` - Enumerate subdomains for a domain via FullHunt. Returns discovered subdomain names. Requires FULLHUNT_API_KEY secret.
- `get_cert_in_advisories` - CERT-In (Indian Computer Emergency Response Team) advisories — vendor-reported vulnerabilities affecting Indian enterprises, with severity, CVEs, products affected, and the official CIAD-YYYY-NNNN ID. Filter by CVE, year, severity, or keyword.
- `get_cross_report_graph` - Cross-report knowledge-graph snapshot. Returns the top N most-referenced nodes (IOCs, actors, malware, CVEs, techniques, campaigns) across every ingested source, with the edges that connect them. Filter by node type and time window.
- `get_detections` - Get the latest detection rules feed — Sigma, YARA, and Snort rules mapped to threat actors, malware families, and MITRE ATT&CK techniques.
- `get_feed_status` - Get the health and freshness status of all 30+ threat intelligence feed sources. Shows last update time, error rates, and data volume.
- `get_ioc_lifecycle` - Get the lifecycle data for an IOC — when it first appeared, last seen, activity trend, and decay rate. Use this to understand if an indicator is still active or dormant.
- `get_recipe` - Fetch a proven multi-step investigation playbook (file-triage, phishing-email, c2-identification, dns-tunnel-hunt, report-ioc-sweep). Returns ordered steps with tool names, argument templates ({input}/{ioc} placeholders), and why each step matters.
- `get_sample_analysis_status` - Poll analysis results for a submitted sample: VirusTotal verdict stats and/or Hybrid Analysis detonation state + threat score + AV detection ratio.
- `get_threat_pulse` - Get a global threat overview — top active threat actors, trending malware families, most exploited CVEs, and geopolitical cyber events from the past week.
- `get_trending_iocs` - Get the most active IOCs in the last 24 hours. Returns indicators with highest observation counts and scores, useful for identifying emerging threats.
- `heatwave_lookup` - Check a SENDING domain against the Validity Heatwave cold-email blocklist (keyless). Returns listed status (warming/active/pre-warming), stage, relative score band, observation ages, DNS answer, and related listed domains. Warming ≠ phishing; not-listed ≠ clean. Never apply to URL/content/DKIM verdicts.
- `hijacklibs_get` - Return the full details of a single HijackLibs DLL by slug: vulnerable executables, expected locations, CVE. Use hijacklibs_list first to discover slugs.
- `hijacklibs_list` - List HijackLibs DLL hijacking candidates: DLLs abusable for sideloading/phantom/search-order/environment-variable hijacking (T1574.001). Filter by hijack type, vendor, CVE presence, or keyword.
- `hijacklibs_stats` - Return cache + manifest stats for the HijackLibs directory: totals by hijack type and CVE count.
- `intelx_phonebook` - IntelligenceX Phonebook — find emails, domains, and URLs associated with a search term (name, domain, keyword). Requires INTELX_API_KEY (paid).
- `intelx_search` - Search IntelligenceX for leaked data, paste sites, breach archives, and dark-web content. Supports emails, domains, URLs, BTC addresses, IBANs, credit cards, phone numbers. Requires INTELX_API_KEY (paid).
- `interpol_notice_detail` - Get details of a specific INTERPOL Red Notice by entity ID. Returns full charge info, arrest warrant details, and physical description. No API key required.
- `interpol_search` - Search INTERPOL Red Notices for wanted persons by name, forename, or nationality. Returns entity IDs, charges, and issuing countries. No API key required.
- `lookup_cisa_kev` - Search the CISA Known Exploited Vulnerabilities (KEV) catalog. Filter by CVE ID, vendor, product, keyword, recency (days), or ransomware-only. Returns matching KEV entries with date_added, due_date, and ransomware status. The full catalog has 1,200+ actively-exploited vulnerabilities.
- `lookup_mitre` - Look up a MITRE ATT&CK technique by ID. Returns technique name, description, tactics, mitigations, and detection guidance.
- `lots_get` - Return the full details of a single LOTS site by slug, including abuse description. Use lots_list first to discover slugs.
- `lots_list` - List Living Off Trusted Sites (LOTS): legitimate domains attackers abuse for phishing, C2, exfiltration, or downloads. Filter by tag (Phishing, C&C, Download, Exfiltration), provider, or keyword.
- `lots_stats` - Return cache + manifest stats for the LOTS directory: total sites and per-tag counts.
- `malapi_get` - Return the full details of a single Windows API by slug: description, library, attack categories, and Microsoft docs link. Use malapi_list first to discover slugs.
- `malapi_list` - List Windows APIs abused by attackers (MalAPI.io catalog). Filter by attack category (Enumeration, Injection, Evasion, Spying, Internet, Anti-Debugging, Ransomware, Helper), DLL library, or keyword.
- `malapi_stats` - Return cache + manifest stats for the MalAPI catalog: total APIs and attack categories.
- `mozilla_tls_scan` - Scan a domain's security posture using the Mozilla Observatory (successor to the retired TLS Observatory). Returns grade (A+ through F) and test counts. No API key required.
- `nova_get_rule` - Return the full body of a NOVA rule: keyword/regex patterns, semantic prompts + thresholds, LLM prompts + thresholds, and the condition. Use nova_list_rules first to discover names.
- `nova_list_rules` - List NOVA prompt-hunting rules (69 total across jailbreak, injection, encoding, exfiltration, incidents). Filter by category (e.g. "prompt_manipulation/jailbreak"), severity, or keyword.
- `nova_scan_prompt` - Scan a prompt against NOVA rules on the edge (keyword/regex stage with Unicode normalization). Rules gated on semantics/LLM evaluation return needs-semantics/needs-llm instead of a false negative. Never sends the prompt anywhere.
- `nova_stats` - Return NOVA manifest stats: rule/pattern counts, severity mix, keyword-only coverage, source + license, and edge cache ratios.
- `nova_taxonomy` - Return the NOVA threat taxonomy: 4 categories (prompt manipulation, abusing legitimate functions, suspicious prompt patterns, abnormal outputs) with 38 threat types and examples.
- `onion_lookup` - Look up metadata for a .onion address via the CIRCL AIL Project. Returns first/last seen dates, status, tags, PGP keys, certificates, open ports, page title, and associated Bitcoin addresses. No API key required.
- `opencve_get_cve` - Get an enriched CVE record from OpenCVE Cloud: summary, CVSS v3.1/v4.0, severity, KEV flag, EPSS, vendors/products, CWE weaknesses, and references. Requires OPENCVE_API_TOKEN (free org token at app.opencve.io).
- `opensanctions_entity` - Get detailed entity information from OpenSanctions by ID. Returns full properties, associated datasets, topics, and schema. Use after opensanctions_search to explore a specific match. Requires OPENSANCTIONS_API_KEY.
- `opensanctions_search` - Search OpenSanctions for entities (individuals, companies, vessels) flagged in sanctions lists, PEP (politically exposed persons) databases, and crime watchlists. Requires OPENSANCTIONS_API_KEY (free for public-interest work at opensanctions.org).
- `opensanctions_stats` - Get OpenSanctions dataset statistics: total entities, datasets, countries covered, and schema counts. Requires OPENSANCTIONS_API_KEY.
- `osint_get_portal` - Return the full details of a single OSINT portal entry by slug. Use osint_list_portals first to discover slugs.
- `osint_list_portals` - List OSINT portals and resources from the curated directory. Filter by category (threat-intel, paste-monitoring, dark-web, reputation, certificate, dns, domain, ip, hash, email, username, social-media, phone, crypto, breach, whois, forensics, misc), keyword, or free/paid status.
- `osint_stats` - Return cache + manifest stats for the OSINT Portal Directory: total portals, indexed categories, and index cache status.
- `oss_feeds_get_category` - Return all feeds in a specific category with full URLs. Use oss_feeds_list first to discover category names.
- `oss_feeds_list` - List open-source threat intel feeds from the curated catalog (145+ feeds, BSD-3-Clause). Filter by vendor, category, status, or keyword. Each entry shows vendor, description, category, and feed status.
- `oss_feeds_stats` - Return cache + manifest stats for the OSS Feed Registry: total feeds, category breakdown, status breakdown, cache state.
- `pcm_get_digest` - Return a single PCMedicalist Intelligence Feed digest body for a date: run summary, the two generated social posts, and the top items per intelligence layer (11-layer taxonomy).
- `pcm_get_latest_digest` - Return the most recent PCMedicalist Intelligence Feed digest: run summary + social posts + top items per layer.
- `pcm_list_digests` - List PCMedicalist Intelligence Feed digests. Filter by date range or keyword. Each entry has date, run metrics (feeds/items raw vs deduped), and per-layer counts.
- `pcm_search_items` - Search items within a PCMedicalist digest body. Filters against the mirrored top-items per layer (capped): filter by layer id, keyword, CVE, or limit.
- `pcm_stats` - Return cache + manifest stats for the PCMedicalist feed: digest counts, latest date, and LRU body-cache hit/miss ratios.
- `phone_osint` - Investigate a phone number — E.164 parsing, carrier/line-type detection, country lookup, messaging platform checks (WhatsApp/Telegram), breach exposure, and Google dorks. Returns structured JSON with parsed phone details, lookup URLs, and security flags.
- `pi_get_entry` - Retrieve a single IoPC taxonomy entry (e.g. IOPC-T1.001 or IOPC-R012) with framework mappings and relationships. Requires server-side PROMPTINTEL_API_KEY.
- `pi_search_prompts` - Search the PromptIntel Indicators-of-Prompt-Compromise feed: adversarial AI prompts with severity and category filters. Requires server-side PROMPTINTEL_API_KEY.
- `poc_scan` - Search GitHub for public exploit/PoC repositories for a CVE. Returns repo URLs, star counts, language, age, and whether the repo has actual code. Bypasses GitHub 1000-result limit via monthly pagination.
- `proc_list_rules` - List learned procedure-extraction rules (analyst corrections promoted to guardrails): technique-grounding, exploit-mapping, provenance. Optionally rank by relevance to a report excerpt. Upstream design: netandneedle/procedure-extraction-pipeline (Apache-2.0).
- `ransom_group_get` - Return one ransomware group: victim counts, last seen, leak-site mirrors (.onion needs Tor), victim sample, abridged profile meta. Use ransom_groups_list first to discover slugs.
- `ransom_groups_list` - List ransomware leak-site groups from the directory (620 groups, Ransomlook + ransomware.live). Filter by keyword, leak-site status (online/offline/unknown), active-this-week, or profile presence. Sort by recent activity, victim count, or name.
- `reports_get` - Return the full details of a single report entry by slug. Use reports_list first to discover slugs.
- `reports_list` - List reports and reading resources from the curated library. Filter by category (annual-threat-report, reference, framework, standard, learning, whitepaper, research), keyword, year, or publisher.
- `reports_stats` - Return cache + manifest stats for the Reports & Reading Library: total entries, categories, and index cache status.
- `reverse_image_search` - Generate reverse image search URLs across 8+ engines (Google Lens, Yandex, TinEye, Bing, Baidu, SauceNAO, IQDB, KarmaDecay). Validates image reachability and returns categorized deep links for manual investigation.
- `soc_cve_report` - Generate a SOC CVE intelligence report. Takes a list of up to 50 CVE IDs and bundles CVE lookup + PoC scan + health check into a downloadable CSV or Markdown report. Returns executive summary, CVSS/EPSS/KEV details, PoC repos, and pipeline health.
- `static_triage_file` - Static file triage from base64 bytes (max ~6MB decoded): magic-byte family detection, hashes, entropy analysis, PE header parse, packer signals (UPX etc.), embedded artifacts (embedded PE/nested zip/OLE). No execution — pure structural analysis.
- `stix_query_bundles` - Query the STIX 2.1 intelligence bundle store with PostgREST-style filters. Returns threat intelligence bundles matching your criteria. Use stix_translate first to convert natural language to structured filter parameters. Supports filters: source_type (eq.osint/eq.darknet), threat_actors (cs.{APT29}), malware_names, sectors, countries_target, vulnerabilities, date ranges (stix_published_at=gte.), and more. Supports select, order, limit, offset.
- `stix_query_iocs` - Query the threat intelligence IOC store with PostgREST-style filters. Returns indicators of compromise with their type, validity period, and source bundle reference. Supports filtering by ioc_type (eq.ipv4, eq.domain, eq.hash_sha256), date ranges, and source. Also supports per-type active IOC queries via ioc_type filter. Use seq_id for incremental sync.
- `stix_translate` - Translate a natural language threat intelligence question into structured STIX 2.1 query parameters. Given plain English, returns the classified intent, extracted entities, and filter parameters to use with stix_query_bundles. Supports actors, malware, CVEs, sectors, countries, campaigns, time ranges, and strategic queries.
- `submit_sample_for_analysis` - Upload a suspicious file (base64, max ~32MB decoded) to Hybrid Analysis (detonation) and/or VirusTotal (multi-engine scan). Returns submission ids/links; poll with get_sample_analysis_status.
- `tam_get_group` - Return a single APT group body: aliases, MITRE Group ID, suspected_origin, target_sectors, and upstream flag. Use tam_list_groups first to discover names/slugs.
- `tam_list_groups` - List APT threat-actor groups from the Global Threat Actor Monitor replication. Upstream 40 groups + expanded to 81 covering Russia/China/NK/Iran eCrime/ransomware/infostealer. Filter by origin country, keyword, or upstream-only. Use tam_get_group to fetch full aliases + sectors.
- `tam_list_sources` - List OSINT RSS/Atom feed sources polled by the Global Threat Actor Monitor (30 upstream -> 39 expanded): name, URL, category (news/vendor/gov), upstream flag. Filter by category or keyword. Feeds are polled every 10 minutes with concurrent bounded fetch.
- `tam_list_techniques` - List MITRE ATT&CK techniques curated for the Threat Actor Monitor (29 upstream -> 108 expanded) with Kill Chain mapping and detection keywords. Filter by tactic, kill chain stage, or keyword. Use for killchain_mapper scoring.
- `tam_stats` - Return cache + manifest stats for the Global Threat Actor Monitor replication: 40->81 groups, 29->108 techniques, 30->39 OSINT feeds, 7 Kill Chain stages, and LRU cache info.
- `tc_feed` - List ThreatCluster (threatcluster.io) public feed summaries: trending threat clusters, CVE vulnerabilities, exploits with public PoCs, dark-web victims, and the IOC blocklist — with per-feed counts and last build dates.
- `tc_get_cluster` - Return the full ThreatCluster trending-cluster body: title, publication date, source count, link to the cluster page (summary + timeline + source articles), and full description with key points. Use tc_feed with feed=clusters to discover slugs.
- `tc_get_cve` - Return a single ThreatCluster CVE item from the vulnerabilities feed (7-day window) or the exploits feed (30-day window, public PoCs). Full description, severity, CISA KEV status (exploits only), and a link to the ThreatCluster CVE page. Use tc_feed with feed=vulnerabilities or feed=exploits first.
- `tc_get_entity` - Return the full ThreatCluster entity profile: threat summary, mention frequency by day (first/last seen), recent activity (clusters / victims / CVEs / MISP events), and a weighted related-entity graph derived from record-level co-occurrence (e.g. a ransomware group links to the sectors and countries it hit, a threat actor links to the malware and CVEs co-mentioned with it). Use tc_list_entities to discover slugs.
- `tc_list_entities` - List ThreatCluster-derived entity profiles: threat actors (MISP galaxy attribution), ransomware groups and sectors (dark-web victims), malware families (Daily-Hunt dictionary matching), and CVEs (feed + cluster-text extraction). Filter by type, keyword, or minimum mention count. Each entry has a name, aliases, mention count, and first/last seen dates. Deterministic build-time extraction — no LLM in the loop.
- `tc_list_iocs` - List high-confidence malicious domains and IPs from the ThreatCluster IOC blocklist (last 30 days). Each IOC has a type, reason, first/last seen, and the source articles that reported it. Ready for firewall / Pi-hole / pfSense blocklists.
- `tc_list_misp_events` - List the slim MISP manifest pass-through from ThreatCluster (misp/manifest.json): event UUID, title, date, threat level, and tags per event. For full MISP ingestion use the upstream remote feed directly (https://threatcluster.io/misp/manifest.json).
- `tc_list_victims` - List newly observed ransomware leak-site victims from the ThreatCluster Dark Web Victims feed (14-day window). Filter by ransom group, sector, country, or keyword. Each entry has a victim name, claiming group, sector, country, and publication date.
- `tg_boolean_search` - Search Telegram leak messages with boolean AND/OR/NOT operators and field qualifiers. Fields: text, channel.title, channel.username, severity, leak_type. Supports wildcards (prefix*) and exact phrases ("quoted").
- `tg_live_search` - Keyword-search public Telegram channels LIVE (t.me/s previews matched in memory, nothing stored). AND-semantics across tokens. Returns snippets + permalinks + per-channel diagnostics. Sequential fetches; keep to ≤8 channels.
- `tg_saved_search_create` - Save a Telegram boolean search query for one-click reuse.
- `tg_saved_search_delete` - Delete a saved Telegram search query.
- `tg_saved_searches_list` - List saved Telegram boolean search queries.
- `tg_timeline` - Get Telegram message volume timeline data (messages per day) with severity breakdown. Useful for visualizing activity spikes.
- `threatmon_infostealer_search` - Search ThreatMon IntelHub for compromised credentials and infected devices linked to a domain via real stealer malware logs. Returns compromised URLs, IPs, usernames, dates, and employee/user classification. Data sourced from ~2.18B compromised users and ~10.47B leaked credentials.
- `ti_brief_sector` - Return a sector-specific threat brief (Financial, Healthcare, or Government) from the threat-intel vertical. Each brief includes an executive summary, top N sector-relevant threats with risk assessments and recommended actions.
- `ti_export_stix` - Export IOC family indicators as a STIX 2.1 bundle. Reads the IOC family body from the threat-intel manifest, converts each indicator to a STIX indicator object with pattern, and wraps in a bundle with TLP marking. Importable into OpenCTI, MISP, or any TAXII 2.1 consumer.
- `ti_get_ctiwatch_victim` - Return the full CTIWatch victim record for one id: name, group, country, sector, attack date, website, and description. Use the CTIWatch index (ti_list is not paginated for victims — fetch /api/v1/threat-intel/ctiwatch and read .victims).
- `ti_get_ctiwatch_vuln` - Return the full CTIWatch vulnerability body for one CVE id: title, description, severity, CVSS, KEV flag, exploit status, published date, CWEs, vendor/product, priority score, EPSS, references, and affected products. Use ti_list_ctiwatch_vulns to discover CVE ids.
- `ti_get_cve` - Return the full CVE body with CVSS vector, CWE IDs, references, and (where populated) BSI description and LLM summary/recommended action. Use ti_list_cves first to discover CVE IDs.
- `ti_get_darknet_category` - Return all sites in a darknetlist.is category (markets, search, forums, news, security, communications, crypto, tools, ai) with full details: onion URLs, status, latency, HTTP codes, fingerprints.
- `ti_get_darknet_site` - Return the full site body from the darknetlist.is directory: name, DWD ID, category, onion URL, clearnet URL (if any), live status, mirror counts, latency, HTTP code, page size, and fingerprint. Use ti_list_darknet first to discover site slugs (DWD IDs).
- `ti_get_detection_list` - Return the full detection list body with all entries (indicator values + metadata: description, tool, severity, category, reference, regex). Optionally search within the list by keyword or severity. Use ti_list_detection_lists first to discover slugs.
- `ti_get_dphish_indicator` - Return the full dPhish indicator body for one slug: STIX id, observable value, category, pattern (STIX or YARA), description, created/modified dates, validity window, revoked status, confidence, OpenCTI score, labels, and indicator types. Use ti_list_dphish to discover slugs (e.g. "melbetegypt.com-1a2b3c").
- `ti_get_ioc` - Return the full IOC family body with indicators, MITRE techniques, context, and (where populated) LLM summary. Use ti_list_iocs first to discover family slugs.
- `ti_get_living_threat_incident` - Return the full Living Threat Repository incident for one slug: per-kill-chain-stage analyses with ATT&CK tactic/technique mappings, per-stage detection + remediation notes, CVEs, threat actors, tools, behavioral / data-exfiltration indicators, detection rules, diamond-model + kill-chain summaries, priority/relevance scores, pyramid of pain, and post-incident recommendations. Use ti_list_living_threat to discover slugs (e.g. "amnesiastealer-macos-malware-021625").
- `ti_get_offseq_threat` - Return the full OffSeq threat body for one slug: title, description, severity, CVSS, CVE ids, AI-generated summary and impact, Mirage exploitation telemetry (countries), patch availability, known threat actors, affected countries, references, and tags. Use ti_list_offseq_threats to discover slugs.
- `ti_get_threaticon_actor` - Return the full Threaticon actor profile: executive summary, key capabilities, goals & targeting, MITRE ATT&CK tactics and techniques (T-numbers), software/tooling, IOC patterns, recommended actions, campaigns & victims, targeted sectors and countries, aliases, and confidence. Use ti_list_threaticon_actors to discover slugs.
- `ti_list_ctiwatch_vulns` - List recent CVEs from CTIWatch (ctiwatch.com): CVE id, title, severity, CVSS, KEV flag, exploit status, published date, CWEs, vendor/product, priority score, and EPSS. Filter by KEV-only, severity, or keyword. Use ti_get_ctiwatch_vuln for the full body (description, references, affected products).
- `ti_list_cves` - List CVEs from the threat-intel vertical (NVD + CISA KEV). CVEs are enriched with priority scoring (CVSS + KEV + recency). Filter by severity, KEV-only, vendor, recency, or keyword.
- `ti_list_darknet` - List Tor-accessible sites from the darknetlist.is directory (markets, forums, news, security, comms, crypto, tools, AI). Each site has live up/down status, onion URL, response code, and fingerprint. Filter by category, status, recommended, or keyword.
- `ti_list_detection_lists` - List SOC/DFIR detection lists (suspicious named pipes, ports, user-agents, mutexes, ransomware extensions, etc.) sourced from mthcht/awesome-lists. Each list is a curated CSV of indicators with metadata (tool, severity, category, reference). Filter by category or keyword.
- `ti_list_dphish` - List phishing indicators from the dPhish public TAXII 2.1 collection (dphish.com): malicious domains, phishing URLs, sender IPs, phone numbers, and attachment detection rules — with active/revoked status, STIX observable type, confidence, OpenCTI score, and validity window. Filter by category, active-only, or keyword. Use ti_get_dphish_indicator to fetch the full STIX body (pattern, description, labels).
- `ti_list_iocs` - List IOC families (ransomware, malware, APT groups, C2 frameworks, stealers, phishing kits) from the threat-intel vertical, sourced from Daily-Hunt references and tracked by this Worker.
- `ti_list_kev` - Return the full CISA Known Exploited Vulnerabilities (KEV) snapshot — actively exploited CVEs with required actions and due dates. Each entry includes vendor, product, short description, required action, and due date.
- `ti_list_living_threat` - List incidents from the Living Threat Repository (living-threat.rabitanoor.com): real-world incidents mapped to MITRE ATT&CK tactic/technique chains, with severity, priority score, CVEs/actor/tool counts. Filter by tactic, technique ID (e.g. T1190), severity, actor name, keyword, or minimum priority score. Use ti_get_living_threat_incident to fetch the full incident (per-kill-chain-stage analyses, detection + remediation notes, hunt-pack guidance).
- `ti_list_malwareanalyzer` - List URL entries from the MalwareAnalyzer by Cyble public feeds (malwareanalyzer.com): verdict=malicious URLs (live malicious feed) or newly-observed scans. Each entry has url, hostname, apex, verdict, score, brands, categories, and scan time. Filter by verdict, category, or keyword. For per-IOC intelligence on any indicator, call ti_malwareanalyzer_lookup.
- `ti_list_offseq_threats` - List recent threats from the OffSeq Threat Radar (radar.offseq.com): AI-enriched threat records across ~40 upstream sources (CVEs, malware, breaches, security news) with severity, CVSS, KEV/exploitation telemetry (Mirage honeypot), tags, and CVE ids. Filter by type, severity, exploited-only, or keyword. Use ti_get_offseq_threat for the full body (AI summary, impact, references, affected countries).
- `ti_list_threaticon_actors` - List threat-actor profiles from the Threaticon catalog (threaticon.com): name, MITRE ATT&CK ID, status, TLP, confidence, types, origin country, and per-actor technique/tool/geo counts. Filter by type, country, TLP, status, MITRE presence, or keyword. Use ti_get_threaticon_actor to fetch the full profile.
- `ti_malwareanalyzer_lookup` - Live reputation lookup for a single IOC (IPv4/IPv6, domain, URL, or hash) against MalwareAnalyzer by Cyble (malwareanalyzer.com, keyless): verdict, 0-100 score, first/last seen, prevalence, tags like benigne/malicious categories. Use for enrichment during an investigation. For bulk URL feeds use ti_list_malwareanalyzer.
- `ti_search_malwarebazaar` - Search MalwareBazaar (abuse.ch) for malware samples by tag or signature. Returns SHA-256, MD5, file name, type, malware family signature, tags, and timestamps. Tries tag search first, falls back to signature. Free API — no key required.
- `ti_search_otx` - Search AlienVault OTX for threat pulses matching a query. Returns pulse metadata (name, tags, TLP, malware families, MITRE ATT&CK IDs) and indicators for the top 5 pulses. Requires OTX_API_KEY (free at otx.alienvault.com).
- `ti_search_ransomware_live` - Search ransomware.live for ransomware group profiles. Returns group description, .onion leak-site URLs, recent victims (with country/sector), MITRE ATT&CK TTPs, and known tools. Free public API — no key required.
- `ti_search_threatfox` - Search ThreatFox (abuse.ch) for IOCs matching a search term. Returns IOC type, value, malware family, confidence, timestamps, and reporter. Free API — no key required. Useful for looking up specific IPs, domains, URLs, or hashes against ThreatCrowd's crowdsourced IOC database.
- `ti_stats` - Return cache + manifest stats for the Threat Intel data: index loaded, KEV loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.
- `ti_threaticon_coverage` - Return the Threaticon ATT&CK detection-coverage dataset: every technique the platform ships detection content for, its tactic, and the number of detection rules, plus per-tactic coverage percentages. Filter by tactic, minimum rule count, or keyword. Use for gap analysis when planning detection coverage.
- `tid_cmm_get_domain` - Get a TID-CMM domain by id (TI, TM, DC, DE, AV, AA, IR, GV) with its sub-capabilities, weights, and level descriptors. TID-CMM v1.5 · ATT&CK Enterprise v19.2 (697 techniques). Source: tid-cmm.com (CC BY 4.0).
- `tid_cmm_search` - Search / filter TID-CMM domains and sub-capabilities by keyword. Returns the model plus matched domains (keyword matches id/name/intent). TID-CMM v1.5 · 8 domains · 58 sub-capabilities.
- `tools_get` - Get the full profile for a specific security tool by slug.
- `tools_list` - List security tools from the curated Tools Directory. Filter by category (recon, exploitation, post-exploitation, defense, detection, forensics, osint, c2, phishing, crypto, mobile, cloud, network, reverse-engineering, web, misc), keyword, or offensive/defensive scope.
- `tor_exit_check` - Check if a specific IP address is a known Tor exit node. Returns boolean and the queried IP.
- `tor_exit_details` - Get detailed Tor exit node information including fingerprints, published timestamps, and exit addresses. More comprehensive than the bulk exit list.
- `tor_exit_nodes` - Get current Tor exit node IP addresses from the official Tor Project bulk exit list. Useful for identifying if traffic originates from the Tor network.
- `tor_fetch_onion` - Fetch raw HTML from a .onion URL via tor2web gateway. Returns page HTML and status code. Note: uses public tor2web proxies, not a local Tor SOCKS5 daemon — for true Tor anonymity, use tor locally.
- `tor_scrape_onion` - Fetch and parse a .onion site via tor2web gateway. Returns structured data: title, links, body text, status code. Useful for extracting content from dark web sites.
- `tor_search_onion` - Search for .onion sites using the Ahmia.fi search engine. Returns matching pages with title, URL, and description. Note: Ahmia selectively indexes .onion sites; not all dark web content is discoverable.
- `tor_status` - Check the dark web access gateway status. Uses public tor2web gateways to reach .onion sites (no local Tor daemon required). Returns available gateways and method info.
- `trace_crypto_address` - Trace a cryptocurrency wallet address. Returns balance, transaction history, and associated entities from blockchain explorers.
- `traceix_lookup` - Look up a SHA-256 file hash against traceix.com (PCEF) for antivirus/reputation results. Returns per-engine verdicts (Safe/Malicious/Unknown/Failed). Powered by Perkins Fund AI. Requires TRACEIX_API_KEY secret.
- `truecaller_lookup` - Reverse phone number lookup via Truecaller — get caller name, carrier, spam score, and location data. Requires TRUECALLER_API_KEY secret (register at truecaller.com).
- `username_generate_patterns` - Generate username variations for typosquatting detection and OSINT. Returns common patterns: leetspeak, double letters, prefix/suffix variations, dot/underscore/hyphen separators, number suffixes.
- `username_scrape_profiles` - Scrape profile metadata (display name, bio, avatar, follower counts) from platforms where the username is found. Returns rich profile data, not just found/not-found.
- `utiom_get` - Get the full UTIOM (Unified Threat-Informed Operations Model) manifest: 7 phases across 3 pillars, doctrine (7 laws), assessment tools, framework family (TID-CMM / TIR-CMM / RSMM / KEVMAP), and standards alignment (NIST CSF 2.0, ISO 27001, NIS2, DORA). Source: utiom.de v1.3 (CC BY-SA 4.0).
- `validate_detection_rule` - Validate a detection rule before use: YARA (structure, string refs, hex tokens, dup names), Sigma (schema + logsource + detection + condition identifiers), Suricata/Snort (header grammar, msg/sid/rev, local sid range), osquery (read-only guard, paren balance, known tables).
- `velo_collect_artifact` - Launch a Velociraptor artifact collection on a managed endpoint (evidence acquisition): e.g. Windows.KapeFiles.Collect. Returns flow id; poll with velo_get_flow_status then velo_get_flow_results.
- `velo_create_hunt` - Launch a Velociraptor HUNT across all managed endpoints (or a label subset) — fleet-wide artifact sweep. Returns hunt id; poll with velo_get_hunt.
- `velo_get_client` - Get one Velociraptor-managed endpoint by client id (C.xxxx) — OS build, labels, last check-in.
- `velo_get_flow_results` - Fetch collected rows from a finished Velociraptor collection (VQL results table with pagination) — the evidence payload for the investigation.
- `velo_get_flow_status` - Poll a Velociraptor collection status — state, duration, bytes collected, files loaded.
- `velo_get_hunt` - Poll a Velociraptor hunt — state, scheduled/completed/erroring client counts.
- `velo_list_clients` - List Velociraptor-managed endpoints (hostname, OS, arch, labels, last-seen). Optional hostname search. Degrades gracefully when VELO_API_URL is not configured.
- `velo_list_flows` - List recent collections (flows) on a managed endpoint — artifact names, state (RUNNING/FINISHED/ERROR), created time.
- `velo_list_hunts` - List recent Velociraptor hunts across the fleet — descriptions, states, completion counts.
- `veris_get_field` - Return the full enumerated values + human labels for a single VERIS taxonomy field. Use veris_list_fields first to discover slugs.
- `veris_list_fields` - List VERIS incident-taxonomy fields: the standard vocabulary for describing who did what to which asset with what result (actor.external.motive, action.hacking.variety, asset.assets.variety…). Filter by section (action, actor, asset, attribute, victim, impact, timeline, discovery_method, …) or keyword.
- `veris_stats` - Return cache + manifest stats for the VERIS taxonomy: field counts by section.
- `virushee_check` - Check a file hash (MD5/SHA1/SHA256) against the Virushee multi-engine AV database. Returns detection ratio and per-engine results. No API key required.
- `wdtb_get_brief` - Return the full Webamon Daily Threat Brief for a given date. Includes estate stats, KPIs (new domains, takedowns, infra changes), notable movements (growth/takedown/rotation/lure-refresh), campaigns worth a look, and emerging clusters. Use wdtb_list_briefs to discover dates.
- `wdtb_latest` - Return the most recent Webamon Daily Threat Brief. Includes estate stats, KPIs, notable movements, campaigns, and emerging clusters.
- `wdtb_list_briefs` - List available Webamon Daily Threat Briefs. Returns dates and metadata (KPI count, campaign count, movement count). Use wdtb_get_brief to retrieve the full brief.
- `wdtb_stats` - Return cache + manifest stats for the Webamon DTB data: index loaded, body-cache sizes and hit ratios.
- `webamon_campaign_changes` - Webamon per-campaign change events — the daily-digest feed. For each campaign: new domains, IPs, ASNs, cert issuers, page titles, and domains that went offline / came online within the window. Powers the "by the numbers" estate brief. Requires WEBAMON_API_KEY secret.
- `webamon_campaign_intel` - Webamon aggregated daily-brief digest in one call: global stats + top campaigns by 24h delta + change events in the window + emerging clusters, rolled up into "by the numbers" totals (new domains, takedowns, infra changes, new lure titles). Requires WEBAMON_API_KEY secret.
- `webamon_campaign_stats` - Webamon global estate rollup — total tracked campaigns, unique domains, online percentage, and aggregate activity. The headline numbers for the campaign-intelligence estate. Requires WEBAMON_API_KEY secret.
- `webamon_campaigns` - List tracked phishing / malware-delivery campaigns from Webamon campaign intelligence (intel.webamon.com). Returns campaign cards with 24h domain delta, 7d activity, unique-domain totals, tags, and first/last seen. Sort by delta_24h to see the fastest-growing estates. Requires WEBAMON_API_KEY secret.
- `webamon_clusters` - Webamon emerging fingerprint clusters — groups of domains sharing a fingerprint (links/ssl/dom/domains/asn/scripts/tech) not yet promoted to tracked campaigns. Returns severity (critical/high/watch), unique-domain count, 24h delta, and the seed_query to pivot into search. Requires WEBAMON_API_KEY secret.
- `whoxy_reverse_whois` - Reverse WHOIS lookup via whoxy.com — find all domains associated with an email, owner name, company, or keyword. Searches 705M+ WHOIS records. Returns domain names, registrant info, and dates. Requires WHOXY_API_KEY secret.
- `wifi_investigation` - Investigate a wireless network by BSSID (MAC address) or SSID (network name). Returns OUI vendor lookup, MAC bit analysis (privacy/multicast), default SSID detection, WiGLE.net links, and security flags for rogue AP detection.
- `ws_add_connection` - Define a relationship between two subjects in a workspace.
- `ws_add_finding` - Log a finding with source, trust score, and confidence in a workspace.
- `ws_add_subject` - Register a subject (entity) in a workspace investigation.
- `ws_create` - Create a new investigation workspace for AEAD lifecycle tracking.
- `ws_export_stix` - Export workspace indicators as STIX 2.1 bundle or flat IOC list.
- `ws_exposure` - Calculate composite exposure score (0-100) for a target based on IOC reputation, breach exposure, infrastructure, attack surface, and threat intel.
- `ws_get` - Get a workspace with all subjects, connections, findings, and timeline.
- `ws_list` - List investigation workspaces. Each workspace is a full AEAD-lifecycle case with subjects, connections, findings, and timeline.
- `ws_render_graph` - Render an ASCII box-drawing relationship graph, timeline, or risk heatmap from workspace data.
- `ws_workflow_advance` - Advance a workspace to the next AEAD phase (Acquire→Enrich→Assess→Deliver→Complete).
- `ws_workflow_summary` - Get workspace summary: phase progress, findings breakdown, recommended commands.

### si (39)

- `si_copilot_ask` - Ask a threat intelligence question with role-aware context. Choose your analyst persona to get answers framed for your role. Roles: ciso (strategic risk), detection (TTPs/rules), ir (IOCs/triage), cti (context/attribution). Covers any threat intel question — actors, malware, campaigns, CVEs, sectors, IOCs, trends.
- `si_copilot_roles` - List the available analyst personas for the role-aware copilot. Each role frames threat intelligence differently: ciso (risk posture, strategic, executive view), detection (TTPs, detection rules, hunting), ir (IOCs, containment, triage), cti (contextual analysis, attribution, trends).
- `si_enrich_agent` - Enrich a single IOC (IP/hash/domain/URL) using the Threat Intel Enrichment Agent. Runs a multi-step autonomous investigation across 30+ providers (VirusTotal, AbuseIPDB, Shodan, PhantomCandle, Malpedia, etc.), extracts MITRE ATT&CK TTPs, and returns a structured threat assessment with per-provider diagnostics. For deep analysis, set 'deep: true' to run the full multi-step chain with report generation (takes 10-30s).
- `si_enrich_ip` - Enrich a single IPv4/IPv6 address using the platform's IPinfo / AbuseIPDB / Shodan / Shodan-InternetDB / VPNAPI providers. Returns the same shape as upstream security-investigator/enrich_ips.py. Use si_enrich_ip_batch for up to 25 IPs in one call.
- `si_enrich_ip_batch` - Enrich up to 25 IP addresses in one call. Returns an array of the same shape as si_enrich_ip. Order is preserved. IPs that fail validation are returned with a single "validator:failed" diagnostic and empty enrichment fields.
- `si_enrich_ip_stix` - Enrich an IP address and return the results as a STIX 2.1 bundle. Combines si_enrich_ip (IPinfo/AbuseIPDB/Shodan/VPNAPI) with STIX 2.1 indicator, vulnerability, and relationship objects. The bundle is importable into OpenCTI, MISP, or any TAXII 2.1 consumer. Returns both the enrichment data and the STIX bundle.
- `si_enrich_ip_stix_batch` - Enrich up to 10 IP addresses and return all results in a single STIX 2.1 bundle. Each IP produces indicator + optional ASN + vulnerability objects. The combined bundle is importable into OpenCTI/MISP. Returns per-IP enrichment data plus the merged STIX bundle.
- `si_get_automation` - Return a scheduled-workflow definition (Copilot App / GitHub Actions) for running the skills unattended. Three automations ship: daily-threat-pulse, daily-mcp-auth-health-check, weekly-threat-intel-campaign.
- `si_get_doc` - Return the full markdown body of a single knowledge-base doc. Get slugs from si_list_docs.
- `si_get_query` - Return the full markdown body of a single KQL query (Defender XDR / Sentinel hunting query, IoC correlation, or campaign playbook). Use si_list_queries first to discover slugs.
- `si_get_ref` - Return a reference dataset by name. Get names from si_list_ref. Common: mitre-attck-enterprise (MITRE ATT&CK enterprise matrix, ~32 KB), known-kql-tables (M365 Defender table inventory, ~17 KB), m365-platform-coverage (coverage map, ~16 KB), ingestion-qN (Sentinel ingestion-scan query result schemas).
- `si_get_routing_prompt` - Return the upstream .github/copilot-instructions.md verbatim — the universal skill-detection / routing prompt. Clients should load this once at session start to learn how to map natural language to the right si_* tool. ~91 KB.
- `si_get_script` - Return the raw body of a detection-manifest asset. Use si_list_scripts to discover filenames.
- `si_get_skill` - Return the full SKILL.md body (markdown) for a single security investigation skill. Use si_list_skills first to discover slugs.
- `si_hypos_generate` - HYPOS: hypothesis engine for threat hunting. Given a free-text anomaly description and optional IOCs / environment, return ranked hypotheses with kill-chain phase, MITRE techniques, what-to-look-for signals, sample KQL, and matched SI skills.
- `si_kql_to_ah_url` - Encode a KQL query into a Defender XDR Advanced Hunting deep link. Mirrors upstream kql_to_ah_url.py: UTF-16LE → GZip → Base64url. Optionally append &tid=<tenant_id> for cross-tenant linking. Returns the URL.
- `si_list_docs` - List the 10 deep-dive knowledge-base docs from the upstream repo (Sentinel Exposure Graph guide, signinlog anomalies KQL cookbook, identity protection, honeypot investigation, ingestion cost best practices, etc). Each is a long-form markdown guide.
- `si_list_queries` - List the KQL queries shipped in this Worker (Defender XDR / Sentinel hunt library replicated from SCStelz/security-investigator, MIT). Filter by domain (cloud / email / endpoint / identity / incidents / network / threat-intelligence) or free-text keyword.
- `si_list_ref` - List the reference datasets available via si_get_ref: MITRE ATT&CK enterprise catalog, known KQL tables for the M365 platform, M365 platform coverage matrix, and the 11 Sentinel ingestion-scan query schemas.
- `si_list_scripts` - List the detection-manifest assets that ship in the SI bundle: example-detection-manifest.json (input template), sentinel-chokepoint-rules.json (detection rules), sentinel-ingestion-drilldown.md (companion guide).
- `si_list_skills` - List the security investigation skills shipped in this Worker (replicated from SCStelz/security-investigator, MIT). Each skill is a guided KQL+playbook workflow. Filter by category or free-text keyword.
- `si_osm_check` - Check whether a package, container image, repository, URL, domain, IP, or crypto wallet is flagged as malicious in the OpenSourceMalware community threat database. Covers supply-chain threats (npm, PyPI, Maven, NuGet, etc.), container registries (Docker Hub, GHCR, Quay), and attacker infrastructure (domains, IPs, wallets).
- `si_osm_latest` - Retrieve the 100 most recent verified threat reports from OpenSourceMalware for any supported ecosystem (npm, pypi, crates, nuget, maven, go, packagist, rubygems, vscode, openvsx, brew, skills) or asset type (repository, domain, wallet, ip, url, container).
- `si_parse_email_headers` - MAILSCOPE: parse raw email headers, extract the Received hop chain, compute SPF/DKIM/DMARC verdicts, and flag spoofing/impersonation patterns. Returns a 0-100 risk score.
- `si_parse_text` - PARSE-X: extract IOCs, file paths, registry keys, processes, DLLs, CVEs, MITRE techniques, hashes, emails, ports, MACs, and ASNs from raw text. Handles defang (hxxp, [.], (dot)) and Cyrillic/Greek homographs.
- `si_promptvault_categories` - PROMPTVAULT: list the valid prompt categories.
- `si_promptvault_create` - PROMPTVAULT: add a new prompt to the vault. Returns the created entry.
- `si_promptvault_get` - PROMPTVAULT: fetch a single prompt by slug. Auto-increments the download counter.
- `si_promptvault_list` - PROMPTVAULT: list community AI prompts for SOC analysts, detection engineers, and threat hunters. Filter by category, tag, or text search.
- `si_promptvault_rate` - PROMPTVAULT: rate a prompt 1-5 stars. Returns the updated entry with new rating count and average.
- `si_render_png` - Render an SVG dashboard and rasterise it to PNG (base64-encoded in the JSON response). Same manifest + data shape as si_render_svg, but the output is a portable bitmap you can embed in markdown, email, or social previews. Uses the bundled @resvg/resvg-wasm + Hanken Grotesk TTF.
- `si_render_svg` - Render an SVG dashboard from a manifest + data. Returns a self-contained <svg> string with inline styles, no external dependencies. Use si_render_svg_dashboard(slug) to get the canonical manifest for a skill, then pass its body as manifestYaml here. Supports all 14 widget types: title-banner, kpi-card, delta-kpi-card, score-card, donut-chart, stacked-bar-chart, horizontal-bar-chart, line-chart, waterfall-chart, sparkline, progress-bar, table-widget, recommendation-cards, assessment-banner, coverage-matrix. Unknown types render as a dashed warning panel.
- `si_render_svg_dashboard` - Return the SVG widget manifest (YAML) for a skill that ships one (14 of 25 skills do). The manifest declares canvas, palette, and a list of widget instances to render. Pair with si_get_skill({slug: "svg-dashboard"}) for the component-library reference. Returns {hasManifest:false,...} if the skill has no SVG manifest.
- `si_shiftlog_close` - SHIFTLOG: close a shift entry (sets ended_at to now, or to a provided ISO timestamp).
- `si_shiftlog_create` - SHIFTLOG: start a new SOC shift handover entry. Returns the created entry including its id (sl_...).
- `si_shiftlog_get` - SHIFTLOG: fetch a single shift handover entry by id (sl_...).
- `si_shiftlog_list` - SHIFTLOG: list recent shift handover entries. Filter by author, shift, or openOnly (excludes closed shifts).
- `si_shiftlog_update` - SHIFTLOG: patch a shift entry (notes, open cases, IOCs, escalations, endedAt).
- `si_stats` - Return cache + manifest stats for the Security Investigator data: index loaded, body-cache sizes and hit ratios. Useful for diagnosing cold-start latency.

### domain (9)

- `get_domain_certs` - Get recent certificates for a domain from Certificate Transparency logs. Shows new subdomains, certificate details, and any alerts.
- `get_domain_history` - Get the WHOIS history for a domain. Returns all historical registration snapshots, ownership changes, registrar changes, and nameserver changes over time. Essential for tracking domain ownership transfers and identifying infrastructure reuse by threat actors.
- `lookup_asn` - ASN intelligence lookup. Returns AS name, country, network ranges, RIR registration, and BGP peer info.
- `lookup_domain` - Domain intelligence lookup. Returns DNS records (A, AAAA, MX, NS, TXT, SOA), WHOIS/RDAP registration data, CT log (certificate transparency) entries, SPF/DKIM/DMARC email authentication analysis, and threat intel hits from blocklists and IOC feeds.
- `lookup_ip_geo` - Get IP geolocation, ASN, company, and privacy detection (VPN/proxy/tor/hosting). Uses IPinfo and Spur.us for anonymization detection.
- `pivot_domain` - Pivot across domains by shared registrant attributes. Find other domains owned by the same entity by matching registrant email, organization, nameservers, or registrar. Critical for mapping attacker infrastructure — if a malicious domain shares its registrant email with 50 other domains, those are likely all owned by the same threat actor.
- `search_registrant` - Search for all domains registered by a specific email address or organization name. Returns domains, registration dates, and snapshot counts. Useful for finding all infrastructure operated by a known threat actor.
- `watch_domain_ct` - Add a domain to Certificate Transparency monitoring. Alerts on new subdomains, suspicious patterns, wildcard certs, and more. Uses crt.sh for unlimited free CT log queries.
- `wayback_lookup` - Check the Wayback Machine (archive.org) for historical snapshots of a URL. Useful for tracking website changes or recovering deleted content.

### hudson (9)

- `hr_account` - Check Hudson Rock Cavalier API account status, permissions, and quota. Use to verify the API key is valid.
- `hr_assets_discovery` - Discover all compromised URLs for a domain (attack surface mapping). Returns URLs where credentials were stolen, occurrence counts, and compromise types.
- `hr_domain_overview` - Get domain compromise overview statistics from Hudson Rock — compromised employee/user counts, last compromise dates, and upload timelines. Useful for risk posture assessment.
- `hr_infection_analysis` - AI-powered infection source analysis for a specific stealer log. Returns the likely infection URL, confidence score, timeline of suspicious activity, and analyst summary. Works best with Lumma stealers.
- `hr_search_domain` - Search for domain-wide infostealer compromises via Hudson Rock Cavalier API. Returns compromised employees, users, and third-party exposures with stealer families and infection dates.
- `hr_search_email` - Search for compromised credentials by email address via Hudson Rock Cavalier API. Returns infostealer infections, stealer families, compromised URLs, and credential types (employee/user/third-party).
- `hr_search_ip` - Search for compromises by IP address or CIDR range via Hudson Rock Cavalier API. Useful for IR when you have a suspicious IP.
- `hr_search_username` - Search for compromised credentials by username via Hudson Rock Cavalier API.
- `hr_third_party_risk` - Assess third-party / supply-chain risk for a domain. Returns employee URLs, third-party service URLs, and user URLs where credentials were compromised — indicating supply chain exposure.

### intel (7)

- `get_blocklists` - Get pre-generated firewall blocklists in pfSense, iptables, and Suricata formats. Derived from aggregated threat intel feeds.
- `get_live_iocs` - Get the most recent live IOCs aggregated from 12+ providers (URLhaus, ThreatFox, AlienVault OTX, SANS ISC, etc). Items are normalized, allowlist-filtered (RFC 5737, vendor docs), and confidence-scored. Supports filtering by IOC kind.
- `get_ransomware_activity` - Get recent ransomware activity — latest victims, group activity, and leak-site posts from ransomware.live and other trackers.
- `get_relationships` - Get the relationship graph for an IOC — shows connections to threat actors, malware families, campaigns, CVEs, and other indicators.
- `get_supply_chain_attacks` - Software supply-chain compromise incidents (npm/PyPI/container/AI-agent ecosystems) from supplychainattack.org — title, status, severity, ecosystems, attack vectors, blast radius, remediation, package IOCs, and GHSA sources. Filter by ecosystem/status/severity.
- `get_today_briefing` - Get today's threat intelligence briefing. A curated digest of the latest CVEs, ransomware activity, data breaches, and emerging threats from the past 24 hours. When format=markdown returns a TI Mindmap HUB-style rich formatted report.
- `list_briefings` - List recent threat intelligence briefings (daily and weekly). Returns slug, date, type, and summary for each.

### ioc (6)

- `check_ioc` - Check reputation of an IP address, domain, URL, or file hash (MD5/SHA1/SHA256) across 30+ threat intelligence providers. Returns composite score, admiralty grade, and per-provider verdicts.
- `correlate_iocs` - Search correlated IOCs. Find relationships between indicators — shared infrastructure, overlapping campaigns, and linked threat actors.
- `ioc_watchlist_add` - Add an IOC to the watchlist for proactive alerting. Supported types: ip, domain, url, hash, cve, email. Alerts fire when the IOC appears in feeds.
- `ioc_watchlist_alerts` - List recent alerts from the IOC watchlist.
- `ioc_watchlist_list` - List all watched IOCs. Optionally filter by type.
- `ioc_watchlist_stats` - Get watchlist dashboard stats: total watches, alerts by type, webhook delivery rate.

### notebook (6)

- `notebook_add_entry` - Add a note, IOC, finding, timeline event, or artifact to a notebook.
- `notebook_create` - Create a new investigation notebook.
- `notebook_delete` - Delete a notebook and all its entries.
- `notebook_get` - Get a notebook with all its entries.
- `notebook_list` - List investigation notebooks. Each notebook is a persistent investigation session with notes, IOCs, findings, and timeline entries stored in D1.
- `notebook_update` - Update a notebook title, description, status, or severity.

### phishing (5)

- `analyze_phishing_email` - Analyze raw email source for phishing indicators. Parses headers, checks SPF/DKIM/DMARC, extracts URLs, and computes a risk score with flags.
- `analyze_phishing_url` - Analyze a URL for phishing indicators. Checks against PhishTank, OpenPhish, URLhaus, and performs visual similarity analysis.
- `analyze_url_risk` - Correlate a URL across VirusTotal, Google Safe Browsing, urlscan.io, AbuseIPDB, and WHOIS domain age using the weighted IntelX risk engine. Returns a 0-100 risk score, verdict (Critical/High/Suspicious/Low/No Strong Threat Evidence), confidence, static heuristic flags (punycode, shorteners, keywords, @-symbol, IP hosts), and a per-provider evidence chain with score breakdown.
- `dl_check_domain` - Check whether a domain (or URL host) is on the Destroylist phishing/scam blacklist (github.com/phishdestroy/destroylist, MIT): ~193k curated primary domains replicated locally (zero egress) plus parent-domain matching, so a phishing page on a listed apex matches too. Returns listed status, matched feed entry, verdict, and feed sync timestamp.
- `dl_stats` - Return Destroylist feed statistics: primary/community/DNS-active domain counts, root-domain rollup count, last sync time, bucket layout, and per-isolate bucket cache health. Use before bulk checks to confirm the manifest is loaded.

### analysis (5)

- `analyze_report` - Unified per-report analyzer. Runs summary + IOC extraction (with allowlist + confidence) + MITRE ATT&CK TTP mapping + 5W context + CVE extraction + image-OCR + STIX 2.1 bundle in a single round-trip. Accepts text, URL, or both; optionally takes image URLs to OCR. When format=markdown returns a TI Mindmap HUB-style rich formatted markdown report.
- `extract_fivew` - Extract the classic 5W grid (who/what/when/where/why) from a free-text report. Single LLM call; returns structured JSON with a per-grid confidence score.
- `extract_iocs_from_image` - Fetch an image and run Workers AI vision over it to extract IOCs that are only visible in screenshots (IPs, domains, URLs, hashes, CVEs, emails). Returns the OCR text + the per-IOC confidence band.
- `extract_ttps` - Extract MITRE ATT&CK techniques from a free-text threat report. Returns technique IDs, tactic labels, confidence (high/medium/low), and the supporting evidence string. Combines a deterministic keyword scanner with an LLM pass and merges the results.
- `parse_threat_report` - Parse a threat intelligence report or article to extract structured data: IOCs (IPs, domains, URLs, hashes), threat actors, malware families, MITRE ATT&CK techniques, CVEs, targeted sectors, and an executive summary. Use this when analyzing threat reports, blog posts, or incident write-ups.

### sigbase (5)

- `sigbase_get_ioc` - Return the entries of a single IOC list by slug: hashes (md5/sha1/sha256 + comment), C2 domains/IPs, filename regexes (with score + false-positive exclusion), or malicious keywords. Optional keyword filter narrows entries.
- `sigbase_get_rule` - Return the full YARA source of a single rule file by slug, plus its parsed rule blocks (name + meta: description, author, reference, date, hash, score, id). Use sigbase_list_rules first to discover slugs. Bodies include the header comment and the raw .yar text.
- `sigbase_list_iocs` - List the IOC lists in the Neo23x0 signature-base feed (hashes, C2 servers, filenames, keywords). Returns entry counts per list. Use sigbase_get_ioc to fetch entries.
- `sigbase_list_rules` - List YARA rule files from the Neo23x0 signature-base feed. Filter by category tag (apt, malware, expl, gen, thr...), author, or free-text keyword. Each file contains 1+ rules with metadata (description, author, date, score, references).
- `sigbase_stats` - Return cache + manifest stats for the Signature-Base data: YARA file/rule counts, IOC list/entry counts, external-variable rule files, and LRU body-cache hit/miss ratios.

### winreg (4)

- `winreg_get_artifact` - Return the full body of a single Windows Registry forensic artifact by slug. Includes registry keys, description, forensic value, parsers, and MITRE mapping. Use winreg_list_artifacts first to discover slugs.
- `winreg_list_artifacts` - List Windows Registry forensic artifacts from the WinReg DFIR reference. Filter by category, hive, MITRE technique, or free-text keyword.
- `winreg_list_categories` - List the Windows Registry artifact categories in the WinReg DFIR reference. Returns category keys, names, descriptions, and artifact counts.
- `winreg_stats` - Return cache + manifest stats for the WinReg DFIR data: artifact counts, hive types, MITRE technique coverage, and LRU body-cache hit/miss ratios.

### cve (3)

- `cve_health` - Check the health of CVE data pipelines. Validates NVD API, EPSS API, CISA KEV, GitHub API rate limit, KV intel cache (EPSS coverage, KEV count, field completeness), and Exploit-DB mirror availability. Returns overall status (healthy/degraded/unhealthy) with per-check details.
- `cve_poc_map` - Get the cached CVE-to-GitHub-repo mapping. Pass ?id=CVE-XXXX-XXXXX for a single CVE, or ?year=YYYY for a year-scoped index of all mapped CVEs. Results are KV-cached for 24h.
- `lookup_cve` - Look up a CVE by ID. Returns description, CVSS score, EPSS probability, CISA KEV status, affected products, and references.

### identity (3)

- `nhi_inventory` - Summarize a non-human & agent identity (NHI) inventory: counts by identity type and risk tier, plus orphaned and long-lived-secret tallies. Input is the inventory JSON (a list of NHI records or {'identities': [...]}); only id and name are required per record. Deterministic, local, no LLM.
- `nhi_owasp_catalog` - Return the OWASP Non-Human Identities (NHI) Top 10 — 2025 catalog (NHI1-NHI10 with titles and summaries), the tiering-rule inventory the NHI scanner enforces (rule id, floor tier, rationale), policy thresholds (rotation/staleness windows, wildcard scope tokens), and the allowed inventory field values (types, privileges, credentials). Use this to understand what nhi_scan checks before running an inventory.
- `nhi_scan` - Scan a non-human & agent identity (NHI) inventory and get a risk report: per-identity Tier 1-4 (critical→baseline) from a transparent floor-tier rules engine, plus OWASP NHI Top 10 findings (NHI1-NHI10) each with evidence and a least-privilege remediation. Input is the inventory JSON (a list of NHI records or {'identities': [...]}); only id and name are required per record — fields like type, privilege, credential, secret_storage, last_rotated_days, last_used_days, exposure, scopes, autonomous, third_party, human_used, shared_across_env, used_by fall back to safe defaults. Returns the full report as JSON, or Markdown with format=markdown.

### pdns (3)

- `passive_dns_overlap` - Find IPs shared between multiple domains (infrastructure overlap detection). Useful for mapping shared malicious hosting.
- `passive_dns_query` - Query passive DNS for a domain or IP. Returns historical DNS resolutions, infrastructure migrations, and fast-flux detection. Sources: VirusTotal, URLscan, crt.sh, CIRCL.
- `passive_dns_reverse` - Reverse passive DNS lookup: find all domains that historically resolved to a given IP. Reads from accumulated D1 cache.

### search (3)

- `search_malpedia` - Search Malpedia for malware families or threat actors. Returns matching entries with descriptions and references.
- `search_triage` - Search Recorded Future Triage sandbox for malware samples by family, tag, hash, URL, or domain. Returns analysis results, behavioral reports, and extracted configs.
- `unified_search` - Cross-source search across all threat intelligence feeds. Search by keyword, IOC, actor name, malware family, or CVE to find matching entries across briefings, live feeds, ransomware data, and more.

### breach (2)

- `breach_vip_search` - Search the BreachVIP breach corpus (10B+ records, 1000+ datasets) directly. Supports 10 field types (email, username, domain, ip, phone, password, name, uuid, steamid, discordid). Returns grouped metadata: breach name, record count, and exposed data classes — raw credentials are never surfaced.
- `check_breach` - Check if an email address or domain has been exposed in known data breaches. Returns breach names, dates, and exposed data types.

### detection (2)

- `generate_yara_rule` - Generate a YARA detection rule using AI. Provide a description of what to detect, and optionally known strings, malware family name, and target file type. Returns a syntactically valid YARA rule with metadata.
- `validate_yara_rule` - Validate a YARA rule syntax. Checks for balanced braces, required sections, and proper string definitions.

### actor (1)

- `enrich_actor` - Get a threat actor profile. Returns aliases, country attribution, MITRE ATT&CK techniques, known campaigns, and associated malware families.

### osint (1)

- `google_dorks` - Generate and execute Google dork queries for a domain. Useful for finding exposed files, login pages, and sensitive information.

### exposure (1)

- `scan_website` - Scan a website for security issues — checks security headers, SSL certificate, technologies, and potential vulnerabilities.

## Machine-readable

Full manifest with per-tool metadata: `mcp-manifest.json` at the site root.
