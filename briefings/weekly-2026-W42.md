# Weekly Threat Briefing — 2026-10-12 – 2026-10-18

> **weekly** · 2026-10-12 – 2026-10-18 · Generated 2026-10-25 00:45 UTC

## Executive Summary

This week (2026-10-12 – 2026-10-18), CISA added 9 new KEV entries and 382 additional high/critical CVEs were published (NVD, cvefeed.io, MyThreatIntel), including 53 critical-severity affecting Adobe, Ahsay, e107inc. Active threat indicators across URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, LLM ThreatIntel, and TweetFeed — 19,063 unique after cross-source dedup; all 19063 indicators (8831 malware-distribution URLs, 2442 malicious domains, 2210 suspicious IPs, 5580 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 846 |
| CVEs | 391 |
| KEVs | 9 |
| IOCs | 19063 |
| Critical | 53 |
| High | 329 |
| Ransomware victims | 455 |

## Critical Remote Code Execution Vulnerabilities (38)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-55573: e107: Unsafe deserialization in install.php allows unauthenticated RCE via POP chain | `T1190`, `T1059.007` | [VulnTracker digest] e107inc e107 — e107: Unsafe deserialization in install.php allows unauthenticated RCE via POP chain |
| 🔴 critical | CVE-2026-109219: The Mang Board plugin for WordPress is vulnerable to Arbitrary File Upload in all versi… | `T1190` | The Mang Board plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.4.4 v |
| 🔴 critical | CVE-2026-103768: The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnera… | `T1190` | The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to Arbitrary File Upload in a |
| 🔴 critical | CVE-2026-94169: Improper Control of Generation of Code ('Code Injection') vulnerability in Theme-one Th… | `T1059` | Improper Control of Generation of Code ('Code Injection') vulnerability in Theme-one The Grid the-grid allows Command In |
| 🔴 critical | CVE-2026-92262: MariaDB server is a community developed fork of MySQL server. | `T1190` | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3 |
| 🔴 critical | CVE-2026-111687: WeRSS (we-mp-rss) through 1.5.3 contains a remote code execution vulnerability that all… | `T1190` | WeRSS (we-mp-rss) through 1.5.3 contains a remote code execution vulnerability that allows unauthenticated attackers to  |
| 🟠 high | CVE-2026-90920: Maximo AI Service Code Injection | — | [cvefeed.io] Maximo AI Service Code Injection |
| 🟠 high | CVE-2026-49483: Code for IBMi: Uses IBM i components with blind check allowing arbitrary code execution | `T1190` | [cvefeed.io] Code for IBMi: Uses IBM i components with blind check allowing arbitrary code execution |
| 🟠 high | CVE-2026-84318: Nginx UI: MCP `nginx_config_add` Bypasses Directive Validation — Authenticated RCE | `T1190` | [cvefeed.io] Nginx UI: MCP `nginx_config_add` Bypasses Directive Validation — Authenticated RCE |
| 🟠 high | CVE-2026-84317: Nginx UI: MCP nginx_config_add skips config directive validation → authenticated nginx … | `T1190` | [cvefeed.io] Nginx UI: MCP nginx_config_add skips config directive validation → authenticated nginx directive injection  |
| 🟠 high | CVE-2026-84316: Nginx UI: nginx config directive denylist (ValidateConfigFile) is bypassable via same-l… | `T1190` | [cvefeed.io] Nginx UI: nginx config directive denylist (ValidateConfigFile) is bypassable via same-line ";" separation → |
| 🟠 high | CVE-2026-94512: SQL Server Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] SQL Server Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-85886: Microsoft SQL Server Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft SQL Server Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-67625: Microsoft SQL Server Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft SQL Server Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-65674: Microsoft SQL Server Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft SQL Server Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-49950: Xorbits Xoscar 0.11.2 Unauthenticated Deserialization RCE via Actor Pool | `T1190`, `T1059.007` | [cvefeed.io] Xorbits Xoscar 0.11.2 Unauthenticated Deserialization RCE via Actor Pool |
| 🟠 high | CVE-2026-106624: ColdFusion \| Improper Control of Generation of Code ('Code Injection') (CWE-94) | — | [cvefeed.io] ColdFusion \| Improper Control of Generation of Code ('Code Injection') (CWE-94) |
| 🟠 high | CVE-2026-106621: ColdFusion \| Improper Control of Generation of Code ('Code Injection') (CWE-94) | — | [cvefeed.io] ColdFusion \| Improper Control of Generation of Code ('Code Injection') (CWE-94) |
| 🟠 high | CVE-2026-54566: Markdown Preview Enhanced: Remote Code Execution via VM Sandbox Escape in `.crossnote/c… | `T1190` | [cvefeed.io] Markdown Preview Enhanced: Remote Code Execution via VM Sandbox Escape in `.crossnote/config.js` and `.cros |
| 🟠 high | CVE-2026-85714: Stirling-PDF: Remote Code Execution via H2 | `T1190` | [cvefeed.io] Stirling-PDF: Remote Code Execution via H2 |
| 🟠 high | CVE-2026-54525: Markdown Preview Enhanced: One Click RCE via Markdown Link Command Injection on Windows | `T1190`, `T1059` | [cvefeed.io] Markdown Preview Enhanced: One Click RCE via Markdown Link Command Injection on Windows |
| 🟠 high | CVE-2026-111281: Jooan JA-A12 Unauthenticated Root RCE via SetDiagMode Hard-Coded Credentials | `T1190` | [cvefeed.io] Jooan JA-A12 Unauthenticated Root RCE via SetDiagMode Hard-Coded Credentials |
| 🟠 high | CVE-2026-108452: Microsoft Office SharePoint Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office SharePoint Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108451: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108450: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108449: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108447: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108446: Microsoft Office Excel Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Excel Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108445: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108444: Microsoft Office Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108443: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108442: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-108441: Microsoft Office Word Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Microsoft Office Word Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-92553: The YaySMTP – WP Mail SMTP with Email Logs, Tracking & Reports plugin for WordPress is … | `T1190` | The YaySMTP – WP Mail SMTP with Email Logs, Tracking & Reports plugin for WordPress is vulnerable to Arbitrary File Uplo |
| 🟠 high | CVE-2026-111311: The DoubleScale \| All-in-One CRM – Sales, Multi-Channel Marketing, Newsletter, Booking,… | `T1190` | The DoubleScale \| All-in-One CRM – Sales, Multi-Channel Marketing, Newsletter, Booking, Helpdesk, Automation, MCP & More |
| 🟠 high | CVE-2026-111391: SGLang 0.5.10 through 0.5.22 contains a code injection vulnerability in _evaluate_filte… | — | SGLang 0.5.10 through 0.5.22 contains a code injection vulnerability in _evaluate_filter() that allows remote attackers  |
| 🟠 high | CVE-2026-92798: The User Registration & Membership plugin for WordPress is vulnerable to Arbitrary Shor… | — | The User Registration & Membership plugin for WordPress is vulnerable to Arbitrary Shortcode Execution in versions up to |
| ⚪ unknown | CVE-2026-0322: Palo Alto Networks PAN-OS — Palo Alto Networks PAN-OS Code Injection Vulnerability | `T1190` | Palo Alto Networks PAN-OS contains a code injection vulnerability that could allow an authenticated attacker with networ |

## Command Injection (15)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-110536: D-Link DIR-868L HNAP CGI cgibin system os command injection | `T1059` | [VulnTracker digest] D-Link DIR-868L — D-Link DIR-868L HNAP CGI cgibin system os command injection |
| 🔴 critical | CVE-2026-89310: SQL Command Injection Vulnerability in JTL-WMS | `T1059` | [VulnTracker digest] JTL SW GmbH JTL-WMS — SQL Command Injection Vulnerability in JTL-WMS |
| 🔴 critical | CVE-2026-110392: Samsung QA-Board — Unauthenticated OS command injection via output redo/tuning | `T1059` | [VulnTracker digest] Samsung Open Source QA-Board — Samsung QA-Board — Unauthenticated OS command injection via output r |
| 🔴 critical | CVE-2026-102608: ZoneMinder is a free, open source closed-circuit television software application. | — | ZoneMinder is a free, open source closed-circuit television software application. Prior to 1.38.3, downloadEvents() manu |
| 🟠 high | CVE-2026-111451: Wheels CLI 4.0.0 through 4.1.1 insufficiently validates or escapes caller-supplied valu… | `T1059.007` | Wheels CLI 4.0.0 through 4.1.1 insufficiently validates or escapes caller-supplied values and package contents. Deploy r |
| 🟠 high | CVE-2026-104715: A flaw was found in cifs-utils. | `T1068` | A flaw was found in cifs-utils. This flaw allows an unprivileged local user to achieve privilege escalation. When a priv |
| 🟠 high | CVE-2026-92115: The WP Photo Album Plus plugin for WordPress is vulnerable to authenticated Command Inj… | `T1190`, `T1059` | The WP Photo Album Plus plugin for WordPress is vulnerable to authenticated Command Injection in all versions up to, and |
| 🟠 high | CVE-2026-88755: Z.ai ZCode v3.11.2.6792 was discovered to automatically establish connections with MCP … | `T1190` | Z.ai ZCode v3.11.2.6792 was discovered to automatically establish connections with MCP servers declared inside a reposit |
| 🟠 high | CVE-2026-92263: SparkyFitness is a self-hosted, AI-powered health and fitness tracker for families. | — | SparkyFitness is a self-hosted, AI-powered health and fitness tracker for families. Prior to 1.6.0, the api/admin/backup |
| 🟠 high | CVE-2026-102607: ZoneMinder is a free, open source closed-circuit television software application. | — | ZoneMinder is a free, open source closed-circuit television software application. Prior to 1.38.3, the exportEvents() fu |
| 🟠 high | CVE-2026-30971: ZoneMinder is a free, open source closed-circuit television software application. | — | ZoneMinder is a free, open source closed-circuit television software application. Prior to 1.39.2, 1.38.2, and 1.36.40,  |
| 🟠 high | CVE-2026-96620: Claude Agent SDK: Argument Injection via resume Option Allows Arbitrary Command Execution | — | [cvefeed.io] Claude Agent SDK: Argument Injection via resume Option Allows Arbitrary Command Execution |
| 🟠 high | CVE-2026-111853: An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. | `T1059` | An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. An OS command injection vulnerability exists in |
| ⚪ unknown | CVE-2026-96951: Microsoft Windows — Microsoft Windows Command Injection Vulnerability | `T1059` | Microsoft Windows Shell contains a command injection vulnerability that allows an unauthorized attacker to bypass a secu |
| ⚪ unknown | CVE-2026-105134: Ahsay AhsayCBS — Ahsay AhsayCBS Command Injection Vulnerability | `T1059` | Ahsay AhsayCBS contains a command injection vulnerability that could allow a remote attacker to execute operating system |

## Authentication & Authorization Bypass (68)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105279: In the default configuration, the archive accepts DICOM associations from an unregister… | — | In the default configuration, the archive accepts DICOM associations from an unregistered calling AE. A remote peer can  |
| 🔴 critical | CVE-2026-97851: The storage status-change REST service allows location records still associated with DI… | — | The storage status-change REST service allows location records still associated with DICOM instances to be changed to de |
| 🔴 critical | CVE-2026-57169: Dockhand is a Docker management application. | — | Dockhand is a Docker management application. Prior to 1.0.34, the in-browser container terminal endpoint /api/containers |
| 🔴 critical | CVE-2026-111626: Webreaper Damselfly through 4.5.3 contains an authentication bypass vulnerability that … | `T1078` | Webreaper Damselfly through 4.5.3 contains an authentication bypass vulnerability that allows unauthenticated attackers  |
| 🔴 critical | CVE-2026-111641: FastapiAdmin through 3.0 contains an authentication bypass vulnerability that allows un… | `T1078` | FastapiAdmin through 3.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain |
| 🔴 critical | CVE-2026-111643: Misaka Danmu Server through 2.8.9 contains an authentication bypass vulnerability that … | `T1078` | Misaka Danmu Server through 2.8.9 contains an authentication bypass vulnerability that allows unauthenticated attackers  |
| 🔴 critical | CVE-2026-111673: IceCMS through 4.1.5 contains a missing authentication vulnerability that allows unauth… | `T1078` | IceCMS through 4.1.5 contains a missing authentication vulnerability that allows unauthenticated attackers to modify, de |
| 🔴 critical | CVE-2026-111704: LangChat through commit 2a6285a contains a missing authentication vulnerability that al… | `T1078` | LangChat through commit 2a6285a contains a missing authentication vulnerability that allows unauthenticated remote attac |
| 🔴 critical | CVE-2026-110653: The Appointment Booking Plugin – LatePoint \| Calendar & Scheduling for WordPress plugin… | `T1078` | The Appointment Booking Plugin – LatePoint \| Calendar & Scheduling for WordPress plugin for WordPress is vulnerable to A |
| 🔴 critical | CVE-2026-111911: phpMyFAQ 4.0.0 before 4.1.9 contains an authentication bypass vulnerability where WebAu… | `T1078` | phpMyFAQ 4.0.0 before 4.1.9 contains an authentication bypass vulnerability where WebAuthn registration endpoints attach |
| 🟠 high | CVE-2026-93909: IBM WebSphere Application Server Liberty is affected by an authentication bypass | `T1078` | [cvefeed.io] IBM WebSphere Application Server Liberty is affected by an authentication bypass |
| 🟠 high | CVE-2026-93895: IBM WebSphere Application Server Liberty Improper Access Control | — | [cvefeed.io] IBM WebSphere Application Server Liberty Improper Access Control |
| 🟠 high | CVE-2026-57489: FileRise: AUTH_BYPASS reverse-proxy header trust without source IP validation enables f… | `T1078` | [cvefeed.io] FileRise: AUTH_BYPASS reverse-proxy header trust without source IP validation enables full authentication b |
| 🟠 high | CVE-2026-110769: holaOS through 2026.822.1 Missing Authorization in Channel-Gateway Connectors | — | [cvefeed.io] holaOS through 2026.822.1 Missing Authorization in Channel-Gateway Connectors |
| 🟠 high | CVE-2026-111322: Archon 0.2.13 through 0.11.1 Missing Authentication via /api/* Control API | `T1078` | [cvefeed.io] Archon 0.2.13 through 0.11.1 Missing Authentication via /api/* Control API |
| 🟠 high | CVE-2026-111312: OpenHealth through 0.2.0 Missing Authentication via /api/health-data/[id] Route | `T1078` | [cvefeed.io] OpenHealth through 0.2.0 Missing Authentication via /api/health-data/[id] Route |
| 🟠 high | CVE-2026-111283: BMC Helix Network Management before 26.3.01 Authentication Bypass via SAML Configuration | `T1078` | [cvefeed.io] BMC Helix Network Management before 26.3.01 Authentication Bypass via SAML Configuration |
| 🟠 high | CVE-2026-92629: A potential improper authorization vulnerability was reported in Lenovo Baiying PC Clie… | `T1190` | A potential improper authorization vulnerability was reported in Lenovo Baiying PC Client, distributed exclusively in th |
| 🟠 high | CVE-2026-111446: Wheels 4.0.0 through 4.1.2 exposes password-less development tools under /wheels/* to r… | — | Wheels 4.0.0 through 4.1.2 exposes password-less development tools under /wheels/* to remote clients when enablePublicCo |
| 🟠 high | CVE-2026-103525: The FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler plugin for WordPre… | — | The FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler plugin for WordPress is vulnerable to Insecure Dire |
| 🟠 high | CVE-2026-103895: The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress is vu… | `T1078` | The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress is vulnerable to Authentication Bypass |
| 🟠 high | CVE-2026-107659: The Modula Image Gallery – Photo Grid & Video Gallery plugin for WordPress is vulnerabl… | — | The Modula Image Gallery – Photo Grid & Video Gallery plugin for WordPress is vulnerable to Sensitive Information Exposu |
| 🟠 high | CVE-2026-107746: The FunnelKit – Funnel Builder for WooCommerce Checkout plugin for WordPress is vulnera… | — | The FunnelKit – Funnel Builder for WooCommerce Checkout plugin for WordPress is vulnerable to authorization bypass in al |
| 🟠 high | CVE-2026-110590: The Klarna for WooCommerce plugin for WordPress is vulnerable to authorization bypass i… | — | The Klarna for WooCommerce plugin for WordPress is vulnerable to authorization bypass in all versions up to, and includi |
| 🟠 high | CVE-2026-110135: The OTP Login & Register Woocommerce WordPress plugin before 2.7.3 does not adequately … | — | The OTP Login & Register Woocommerce WordPress plugin before 2.7.3 does not adequately limit one-time-password verificat |
| 🟠 high | CVE-2026-75903: The Vulnity Security plugin for WordPress is vulnerable to authentication bypass in all… | `T1078` | The Vulnity Security plugin for WordPress is vulnerable to authentication bypass in all versions up to, and including, 1 |
| 🟠 high | CVE-2026-109119: Improper Privilege Management in the user management API endpoint (/api/users/{username… | — | Improper Privilege Management in the user management API endpoint (/api/users/{username_or_id}) in Rdiffweb allows authe |
| 🟠 high | CVE-2026-111396: Missing Authorization vulnerability in Liquid Web / StellarWP Advanced Post Manager adv… | — | Missing Authorization vulnerability in Liquid Web / StellarWP Advanced Post Manager advanced-post-manager allows Exploit |
| 🟠 high | CVE-2026-105667: In the default configuration, the HL7 listener accepts ADT^A40 patient-merge messages w… | — | In the default configuration, the HL7 listener accepts ADT^A40 patient-merge messages without authenticating the sending |
| 🟠 high | CVE-2026-106705: ELADMIN (eladmin-mp) up to 2.7 contains an improper access control vulnerability in the… | — | ELADMIN (eladmin-mp) up to 2.7 contains an improper access control vulnerability in the role management module. The endp |
| 🟠 high | CVE-2026-97380: MariaDB server is a community developed fork of MySQL server. | — | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3 |
| 🟠 high | CVE-2026-109587: Incorrect authorization in the Arm Cortex-R82 (Armv8-R AArch64) MPU port in FreeRTOS-Ke… | — | Incorrect authorization in the Arm Cortex-R82 (Armv8-R AArch64) MPU port in FreeRTOS-Kernel V11.3.0 and V11.3.1 might al |
| 🟠 high | CVE-2026-111605: Jpom through 2.11.12 contains an authorization bypass vulnerability in SshFileControlle… | — | Jpom through 2.11.12 contains an authorization bypass vulnerability in SshFileController that allows authenticated works |
| 🟠 high | CVE-2026-111606: Huly Platform through 0.7.432 contains a missing authorization vulnerability that allow… | — | Huly Platform through 0.7.432 contains a missing authorization vulnerability that allows any authenticated user to merge |
| 🟠 high | CVE-2026-111607: Jeepay through 3.2.9 contains an insecure direct object reference vulnerability that al… | — | Jeepay through 3.2.9 contains an insecure direct object reference vulnerability that allows authenticated merchant users |
| 🟠 high | CVE-2026-111613: AllData through 0.7.1 contains an unauthenticated JDBC injection vulnerability that all… | — | AllData through 0.7.1 contains an unauthenticated JDBC injection vulnerability that allows remote attackers to open arbi |
| 🟠 high | CVE-2026-111627: HestiaCP before 1.10.5 contains an authorization bypass vulnerability that allows non-R… | — | HestiaCP before 1.10.5 contains an authorization bypass vulnerability that allows non-ROOT_USER administrators to perfor |
| 🟠 high | CVE-2026-111638: sshportal through 1.19.5 contains a missing authorization vulnerability in the manageme… | — | sshportal through 1.19.5 contains a missing authorization vulnerability in the management shell 'key show' command that  |
| 🟠 high | CVE-2026-111639: bbs-go through 4.4.6 contains an authentication bypass vulnerability in the /api/login/… | `T1078` | bbs-go through 4.4.6 contains an authentication bypass vulnerability in the /api/login/google_one_tap endpoint that allo |
| 🟠 high | CVE-2026-111644: Misaka Danmu Server through 2.8.9 contains a missing authentication vulnerability that … | `T1078` | Misaka Danmu Server through 2.8.9 contains a missing authentication vulnerability that allows unauthenticated attackers  |
| 🟠 high | CVE-2026-111650: ChronoFrame through 1.0.0 contains a missing authentication vulnerability in the server… | `T1078` | ChronoFrame through 1.0.0 contains a missing authentication vulnerability in the server/api/wizard/ handlers that allows |
| 🟠 high | CVE-2026-111671: Cube-studio through 2026.09.01 contains an insecure direct object reference vulnerabili… | — | Cube-studio through 2026.09.01 contains an insecure direct object reference vulnerability that allows authenticated user |
| 🟠 high | CVE-2026-111680: APIPark through 1.9.7-beta contains an authorization bypass vulnerability that allows a… | — | APIPark through 1.9.7-beta contains an authorization bypass vulnerability that allows authenticated team managers to acc |
| 🟠 high | CVE-2026-111681: EFAK through 5.1.0 contains a missing authorization vulnerability that allows authentic… | — | EFAK through 5.1.0 contains a missing authorization vulnerability that allows authenticated low-privilege users to manag |
| 🟠 high | CVE-2026-111684: Magistrala through 1.0.0 contains an authorization bypass vulnerability that allows aut… | — | Magistrala through 1.0.0 contains an authorization bypass vulnerability that allows authenticated workspace members to v |
| 🟠 high | CVE-2026-111691: WIMOOR through commit ec86736 contains an authentication bypass vulnerability that allo… | `T1078` | WIMOOR through commit ec86736 contains an authentication bypass vulnerability that allows attackers to impersonate any t |
| 🟠 high | CVE-2026-111695: Shaiwz data-platform-open through commit efeacd3 contains an insecure direct object ref… | — | Shaiwz data-platform-open through commit efeacd3 contains an insecure direct object reference vulnerability that allows  |
| 🟠 high | CVE-2026-111701: OtterMind Nubase through 0.1.4 contains a missing authentication vulnerability that all… | `T1078` | OtterMind Nubase through 0.1.4 contains a missing authentication vulnerability that allows unauthenticated attackers to  |
| 🟠 high | CVE-2026-111702: ChatOllama through commit 96c3ce5 contains an insecure direct object reference vulnerab… | — | ChatOllama through commit 96c3ce5 contains an insecure direct object reference vulnerability that allows remote attacker |
| 🟠 high | CVE-2026-111706: 99AI through 4.3.0 contains a missing authentication vulnerability in the POST /api/cha… | `T1078` | 99AI through 4.3.0 contains a missing authentication vulnerability in the POST /api/chatLog/exportExcel route that allow |
| | _+18 more…_ | | |

## Privilege Escalation (22)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-77524: KEDA: Privilege escalation from namespace admin to cluster admin via KEDA TriggerAuthen… | `T1068` | [VulnTracker digest] kedacore keda — KEDA: Privilege escalation from namespace admin to cluster admin via KEDA TriggerAu |
| 🔴 critical | CVE-2026-104798: The My Calendar – Accessible Event Manager plugin for WordPress is vulnerable to Privil… | `T1068` | The My Calendar – Accessible Event Manager plugin for WordPress is vulnerable to Privilege Escalation in all versions up |
| 🔴 critical | CVE-2026-109515: The MailOptin – Popup, Optin Forms & Email Newsletters for Mailchimp, HubSpot, AWeber Etc. | `T1068` | The MailOptin – Popup, Optin Forms & Email Newsletters for Mailchimp, HubSpot, AWeber Etc. plugin for WordPress is vulne |
| 🔴 critical | CVE-2026-89079: The Theme My Login plugin for WordPress is vulnerable to privilege escalation via accou… | `T1068` | The Theme My Login plugin for WordPress is vulnerable to privilege escalation via account takeover in versions up to, an |
| 🔴 critical | CVE-2026-111708: WhaTicket Community through commit cf04795 contains an authentication bypass vulnerabil… | `T1078` | WhaTicket Community through commit cf04795 contains an authentication bypass vulnerability that allows unauthenticated a |
| 🔴 critical | CVE-2026-110372: Incorrect Privilege Assignment vulnerability in Brainstorm Force OttoKit suretriggers a… | `T1068` | Incorrect Privilege Assignment vulnerability in Brainstorm Force OttoKit suretriggers allows Privilege Escalation.This i |
| 🟠 high | CVE-2026-109567: Rapyd Admin from 9.0.0 before 9.20.0 Privilege Escalation via UsersEdit Component | `T1068` | [cvefeed.io] Rapyd Admin from 9.0.0 before 9.20.0 Privilege Escalation via UsersEdit Component |
| 🟠 high | CVE-2026-96956: SQL Server Elevation of Privilege Vulnerability | `T1068` | [cvefeed.io] SQL Server Elevation of Privilege Vulnerability |
| 🟠 high | CVE-2026-68883: Microsoft SQL Server Elevation of Privilege Vulnerability | `T1068` | [cvefeed.io] Microsoft SQL Server Elevation of Privilege Vulnerability |
| 🟠 high | CVE-2026-104745: The Customer Email Verification for WooCommerce plugin for WordPress is vulnerable to P… | `T1068` | The Customer Email Verification for WooCommerce plugin for WordPress is vulnerable to Privilege Escalation via the `alg_ |
| 🟠 high | CVE-2026-109400: The InstaWP Connect – 1-click WP Staging & Migration plugin for WordPress is vulnerable… | `T1068` | The InstaWP Connect – 1-click WP Staging & Migration plugin for WordPress is vulnerable to Privilege Escalation in all v |
| 🟠 high | CVE-2026-111114: The Nexter Extension – Security, Performance, Code Snippets & Site Toolkit plugin for W… | `T1068` | The Nexter Extension – Security, Performance, Code Snippets & Site Toolkit plugin for WordPress is vulnerable to Privile |
| 🟠 high | CVE-2026-109447: The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role… | `T1068` | The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role Editor plugin for WordPress is v |
| 🟠 high | CVE-2026-85659: The PilotPress plugin for WordPress is vulnerable to Privilege Escalation via Account T… | `T1068` | The PilotPress plugin for WordPress is vulnerable to Privilege Escalation via Account Takeover in all versions up to, an |
| 🟠 high | CVE-2026-86008: Mailu is a mail server distributed as a set of Docker images. | — | Mailu is a mail server distributed as a set of Docker images. Prior to 8577c929b4ade04d3cd4210cf036601abd793556, a domai |
| 🟠 high | CVE-2026-81452: Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain a Least Priv… | `T1068` | Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain a Least Privilege Violation vulnerability. A  |
| 🟠 high | CVE-2026-102917: IBM i 7.3, 7.4, 7.5, and 7.6 is vulnerable to an authenticated attacker elevating their… | — | IBM i 7.3, 7.4, 7.5, and 7.6 is vulnerable to an authenticated attacker elevating their privilege. A bad actor could exp |
| 🟠 high | CVE-2026-96627: Arcane is an interface for managing Docker containers, images, networks, and volumes. | — | Arcane is an interface for managing Docker containers, images, networks, and volumes. Prior to 2.6.0, UpdateUser in back |
| 🟠 high | CVE-2026-111909: phpMyFAQ before 4.1.9 contains a missing authorization vulnerability in the deleteUser(… | — | phpMyFAQ before 4.1.9 contains a missing authorization vulnerability in the deleteUser() API that allows authenticated n |
| 🟠 high | CVE-2026-111893: phpMyFAQ 4.2.0-alpha before 4.2.0-beta Privilege Escalation via Group Category Restrict… | `T1068` | [cvefeed.io] phpMyFAQ 4.2.0-alpha before 4.2.0-beta Privilege Escalation via Group Category Restrictions API |
| 🟠 high | CVE-2026-110031: The Salon Booking System  WordPress plugin before 10.31.11 does not prevent users holdi… | — | The Salon Booking System  WordPress plugin before 10.31.11 does not prevent users holding its custom salon staff role fr |
| 🟠 high | CVE-2026-110373: Incorrect Privilege Assignment vulnerability in Hamid Alinia Login with phone number lo… | `T1068` | Incorrect Privilege Assignment vulnerability in Hamid Alinia Login with phone number login-with-phone-number allows Priv |

## SQL & NoSQL Injection (24)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-55572: e107: SQL injection in alt_auth plugin (otherdb / e107db backends) via login username | `T1190` | [VulnTracker digest] e107inc e107 — e107: SQL injection in alt_auth plugin (otherdb / e107db backends) via login usernam |
| 🔴 critical | CVE-2026-111444: Wheels through 4.1.2 allows SQL injection on MySQL/MariaDB with backslash escaping enab… | `T1190` | Wheels through 4.1.2 allows SQL injection on MySQL/MariaDB with backslash escaping enabled (NO_BACKSLASH_ESCAPES absent) |
| 🔴 critical | CVE-2026-94388: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in halfdata Green Pop |
| 🔴 critical | CVE-2026-109894: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Arraytics Booktics |
| 🟠 high | CVE-2026-55684: WeGIA: SQL Injection in html/socio/sistema/cadastro_cobrancas_geracao.php | `T1190` | [cvefeed.io] WeGIA: SQL Injection in html/socio/sistema/cadastro_cobrancas_geracao.php |
| 🟠 high | CVE-2026-55683: WeGIA: SQL Injection in html/socio/sistema/cadastro_cobranca.php | `T1190` | [cvefeed.io] WeGIA: SQL Injection in html/socio/sistema/cadastro_cobranca.php |
| 🟠 high | CVE-2026-55681: WeGIA: SQL Injection in html/matPat/restaurar_produto_desocultar.php via id_produto par… | `T1190` | [cvefeed.io] WeGIA: SQL Injection in html/matPat/restaurar_produto_desocultar.php via id_produto parameter |
| 🟠 high | CVE-2026-55680: WeGIA: Unauthenticated SQL Injection in cadastro_cobranca.php via "codigo" parameter | `T1190` | [cvefeed.io] WeGIA: Unauthenticated SQL Injection in cadastro_cobranca.php via "codigo" parameter |
| 🟠 high | CVE-2026-111389: Frappe HRMS 14.x before 14.38.2, 15.x before 15.64.0, and 16.x before 16.18.0 contains … | `T1190` | Frappe HRMS 14.x before 14.38.2, 15.x before 15.64.0, and 16.x before 16.18.0 contains a SQL injection vulnerability in  |
| 🟠 high | CVE-2026-93953: The Backuply – Backup, Restore, Migrate and Clone plugin for WordPress is vulnerable to… | `T1068`, `T1190` | The Backuply – Backup, Restore, Migrate and Clone plugin for WordPress is vulnerable to SQL Injection via the Biographic |
| 🟠 high | CVE-2026-92766: The Vitepos – Point of Sale (POS) for WooCommerce plugin for WordPress is vulnerable to… | `T1190` | The Vitepos – Point of Sale (POS) for WooCommerce plugin for WordPress is vulnerable to generic SQL Injection via the 's |
| 🟠 high | CVE-2026-111399: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in PT Norther Lights  |
| 🟠 high | CVE-2026-86047: MariaDB server is a community developed fork of MySQL server. | — | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3 |
| 🟠 high | CVE-2026-111634: Helical Insight through 7.0.0 contains an sql injection vulnerability that allows authe… | `T1190` | Helical Insight through 7.0.0 contains an sql injection vulnerability that allows authenticated viewers to inject SQL th |
| 🟠 high | CVE-2026-111685: IceCMS through 4.1.5 contains an unauthenticated sql injection vulnerability that allow… | `T1190` | IceCMS through 4.1.5 contains an unauthenticated sql injection vulnerability that allows remote attackers to inject SQL  |
| 🟠 high | CVE-2026-111686: IceCMS through 4.1.5 contains an unauthenticated sql injection vulnerability that allow… | `T1190` | IceCMS through 4.1.5 contains an unauthenticated sql injection vulnerability that allows remote attackers to inject SQL  |
| 🟠 high | CVE-2026-111700: WebVella ERP through 1.8.8 contains an sql injection vulnerability that allows any auth… | `T1190` | WebVella ERP through 1.8.8 contains an sql injection vulnerability that allows any authenticated user to inject SQL thro |
| 🟠 high | CVE-2026-111866: A weakness has been identified in nemoTyrant manong up to 7c9e5228e133b9267ad3a415833bc… | `T1190` | A weakness has been identified in nemoTyrant manong up to 7c9e5228e133b9267ad3a415833bc9bb53193bb4. This impacts the fun |
| 🟠 high | CVE-2026-111871: A weakness has been identified in itsmeravitejak Online-Examination-System up to e6208e… | `T1190` | A weakness has been identified in itsmeravitejak Online-Examination-System up to e6208e630b14657999bbfe4c9912302d2a1e244 |
| 🟠 high | CVE-2026-111872: A security vulnerability has been detected in itsmeravitejak Online-Examination-System … | `T1190` | A security vulnerability has been detected in itsmeravitejak Online-Examination-System up to e6208e630b14657999bbfe4c991 |
| 🟠 high | CVE-2026-111873: A vulnerability was detected in itsmeravitejak Online-Examination-System up to e6208e63… | `T1190` | A vulnerability was detected in itsmeravitejak Online-Examination-System up to e6208e630b14657999bbfe4c9912302d2a1e2449. |
| 🟠 high | CVE-2026-96534: The Modern Events Calendar Lite WordPress plugin before 7.37.0, Modern Event Calendar P… | `T1190` | The Modern Events Calendar Lite WordPress plugin before 7.37.0, Modern Event Calendar Pro WordPress plugin before 7.37.0 |
| 🟠 high | CVE-2026-110895: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in DevItems Support G |
| 🟠 high | CVE-2026-111990: A weakness has been identified in kishan0725 Hospital Management System up to 777fda46b… | `T1190` | A weakness has been identified in kishan0725 Hospital Management System up to 777fda46b77a820977a5ba616283dbfbc40bf7e1.  |

## Cross-Site Scripting (40)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-18516: An output escaping vulnerability in the Audit Logs component of Crafty Controller allow… | `T1059.007` | An output escaping vulnerability in the Audit Logs component of Crafty Controller allows a remote, unauthenticated attac |
| 🔴 critical | CVE-2026-44977: countly-server is the server-side part of Countly, a product analytics solution. | — | countly-server is the server-side part of Countly, a product analytics solution. Prior to 24.05.50 and 25.03.44, plugins |
| 🟠 high | CVE-2026-109558: EdgeEver 1.6.0 through 1.112.0 Stored XSS via TemplatesPane Template Preview | `T1059.007` | [cvefeed.io] EdgeEver 1.6.0 through 1.112.0 Stored XSS via TemplatesPane Template Preview |
| 🟠 high | CVE-2026-107758: The Colibri Page Builder plugin for WordPress is vulnerable to Stored Cross-Site Script… | `T1059.007` | The Colibri Page Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'comment' parameter i |
| 🟠 high | CVE-2026-109207: The RSS Aggregator by Feedzy – Feed to Post, Autoblogging, News & YouTube Video Feeds A… | `T1059.007` | The RSS Aggregator by Feedzy – Feed to Post, Autoblogging, News & YouTube Video Feeds Aggregator plugin for WordPress is |
| 🟠 high | CVE-2026-109990: The Flying Scripts: Delay JavaScript to Improve Site Speed & Performance plugin for Wor… | `T1059.007` | The Flying Scripts: Delay JavaScript to Improve Site Speed & Performance plugin for WordPress is vulnerable to Stored Cr |
| 🟠 high | CVE-2026-97339: The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress is vulnerable to Sto… | `T1059.007` | The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comm |
| 🟠 high | CVE-2026-109998: The Mang Board plugin for WordPress is vulnerable to Stored Cross-Site Scripting via th… | `T1059.007` | The Mang Board plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'content' parameter in all vers |
| 🟠 high | CVE-2026-100186: The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role… | `T1059.007` | The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role Editor plugin for WordPress is v |
| 🟠 high | CVE-2026-103999: The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Stored Cross-… | `T1059.007` | The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Stored Cross-Site Scripting via File Upload in |
| 🟠 high | CVE-2026-104000: The Simply Schedule Appointments plugin for WordPress is vulnerable to Stored Cross-Sit… | `T1059.007` | The Simply Schedule Appointments plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'status' para |
| 🟠 high | CVE-2026-107764: The SiteOrigin CSS plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Sc… | `T1059.007` | The SiteOrigin CSS plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting via the 'url (comment_aut |
| 🟠 high | CVE-2026-109232: The Salon Booking System – Appointment Booking for Salons, Barbershops & Spas plugin fo… | `T1059.007` | The Salon Booking System – Appointment Booking for Salons, Barbershops & Spas plugin for WordPress is vulnerable to Stor |
| 🟠 high | CVE-2026-109513: The NotificationX – FOMO, Live Sales Notification, WooCommerce Sales Popup, GDPR, Socia… | `T1059.007` | The NotificationX – FOMO, Live Sales Notification, WooCommerce Sales Popup, GDPR, Social Proof, Announcement Banner & Fl |
| 🟠 high | CVE-2026-111122: The SiteOrigin CSS plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Sc… | `T1059.007` | The SiteOrigin CSS plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting via the 'href' parameter  |
| 🟠 high | CVE-2026-89051: The WP Ghost (Hide My WP Ghost) – Security & Firewall plugin for WordPress is vulnerabl… | `T1059.007` | The WP Ghost (Hide My WP Ghost) – Security & Firewall plugin for WordPress is vulnerable to Stored Cross-Site Scripting  |
| 🟠 high | CVE-2026-95686: The Opti-Behavior – Self-Hosted Heatmaps, Session Recordings, Funnels, A/B Testing & Sm… | `T1059.007` | The Opti-Behavior – Self-Hosted Heatmaps, Session Recordings, Funnels, A/B Testing & Smart Insights plugin for WordPress |
| 🟠 high | CVE-2026-95809: The Opti-Behavior – Self-Hosted Heatmaps, Session Recordings, Funnels, A/B Testing & Sm… | `T1059.007` | The Opti-Behavior – Self-Hosted Heatmaps, Session Recordings, Funnels, A/B Testing & Smart Insights plugin for WordPress |
| 🟠 high | CVE-2026-96570: The Schema & Structured Data for WP & AMP plugin for WordPress is vulnerable to Stored … | `T1059.007` | The Schema & Structured Data for WP & AMP plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'sas |
| 🟠 high | CVE-2026-107768: The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPr… | `T1059.007` | The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross |
| 🟠 high | CVE-2026-109193: The HivePress – Business Directory, Listings & Classified Ads Plugin plugin for WordPre… | `T1059.007` | The HivePress – Business Directory, Listings & Classified Ads Plugin plugin for WordPress is vulnerable to Stored Cross- |
| 🟠 high | CVE-2026-110701: The CP Multi View Events Calendar plugin for WordPress is vulnerable to Stored Cross-Si… | `T1059.007` | The CP Multi View Events Calendar plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'CalendarTit |
| 🟠 high | CVE-2026-96339: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Houzez.co Houzez h |
| 🟠 high | CVE-2026-97640: The WPConsent – Cookie Banner & Cookie Consent for Privacy Compliance (GDPR / CCPA / EU… | `T1059.007` | The WPConsent – Cookie Banner & Cookie Consent for Privacy Compliance (GDPR / CCPA / EU Compliance Cookie Notice) plugin |
| 🟠 high | CVE-2026-87111: The User Registration PRO – Custom Registration Form, Login Form, and User Profile Word… | `T1059.007` | The User Registration PRO – Custom Registration Form, Login Form, and User Profile WordPress Plugin plugin for WordPress |
| 🟠 high | CVE-2026-109224: The SureCart – Ecommerce Made Easy For Selling Physical Products, Digital Downloads, Su… | `T1059.007` | The SureCart – Ecommerce Made Easy For Selling Physical Products, Digital Downloads, Subscriptions, Donations, & Payment |
| 🟠 high | CVE-2026-96768: The GoSMTP Pro plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Co… | `T1059.007` | The GoSMTP Pro plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via Email Log Body  |
| 🟠 high | CVE-2026-107648: The WP Sessions Time Monitoring Full Automatic plugin for WordPress is vulnerable to St… | `T1059.007` | The WP Sessions Time Monitoring Full Automatic plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the |
| 🟠 high | CVE-2026-109208: The LearnPress – WordPress LMS Plugin for Create and Sell Online Courses plugin for Wor… | `T1059.007` | The LearnPress – WordPress LMS Plugin for Create and Sell Online Courses plugin for WordPress is vulnerable to Stored Cr |
| 🟠 high | CVE-2026-103899: The EU VAT Assistant for WooCommerce plugin for WordPress is vulnerable to Stored Cross… | `T1068`, `T1059.007` | The EU VAT Assistant for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'vat_numb |
| 🟠 high | CVE-2026-96660: The User Registration & Membership – Free & Paid Memberships, Subscriptions, Content Re… | `T1059.007` | The User Registration & Membership – Free & Paid Memberships, Subscriptions, Content Restriction, User Profile, Custom U |
| 🟠 high | CVE-2026-110384: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Heateor Support Fa |
| 🟠 high | CVE-2026-100316: The European VAT Compliance Assistant for WooCommerce plugin for WordPress is vulnerabl… | `T1059.007` | The European VAT Compliance Assistant for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting  |
| 🟠 high | CVE-2026-111110: The Payment forms, Buy now buttons, and Invoicing System \| GetPaid plugin for WordPress… | `T1059.007` | The Payment forms, Buy now buttons, and Invoicing System \| GetPaid plugin for WordPress is vulnerable to Stored Cross-Si |
| 🟠 high | CVE-2026-109701: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in PAYCOMET PAYCOMET  |
| 🟠 high | CVE-2026-110981: The WP Photo Album Plus WordPress plugin before 9.2.11.002 does not properly escape a c… | — | The WP Photo Album Plus WordPress plugin before 9.2.11.002 does not properly escape a category navigation value before r |
| 🟠 high | CVE-2026-108485: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in ThemeGrill eStore  |
| 🟠 high | CVE-2026-109895: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Arraytics Booktics |
| 🟠 high | CVE-2026-110382: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in NSquared Simply Sc |
| 🟠 high | CVE-2026-110897: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in IdeaBox Creations  |

## Memory Corruption (37)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-97229: Integer Overflow or Wraparound in GitLab | — | [VulnTracker digest] GitLab GitLab — Integer Overflow or Wraparound in GitLab |
| 🔴 critical | CVE-2026-102692: RIOT is an open-source microcontroller operating system designed for Internet of Things… | `T1203` | RIOT is an open-source microcontroller operating system designed for Internet of Things devices and other embedded syste |
| 🔴 critical | CVE-2026-102693: RIOT is an open-source microcontroller operating system designed for Internet of Things… | `T1203` | RIOT is an open-source microcontroller operating system designed for Internet of Things devices and other embedded syste |
| 🔴 critical | CVE-2026-49868: RIOT is an open-source microcontroller operating system designed for Internet of Things… | — | RIOT is an open-source microcontroller operating system designed for Internet of Things devices and other embedded syste |
| 🔴 critical | CVE-2026-85746: MariaDB server is a community developed fork of MySQL server. | — | MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3 |
| 🔴 critical | CVE-2026-85748: MariaDB server is a community developed fork of MySQL server. | `T1190` | MariaDB server is a community developed fork of MySQL server. From 12.3.1 until 12.3.3 and 13.0.2, SYS_REFCURSOR handlin |
| 🔴 critical | CVE-2026-111711: Netcore NR256CN through 1.5.140116 contains a pre-authentication stack overflow vulnera… | — | Netcore NR256CN through 1.5.140116 contains a pre-authentication stack overflow vulnerability in the Boa web server's us |
| 🟠 high | CVE-2026-96266: IBM Power Systems Firmware Buffer Overflow | `T1203` | [cvefeed.io] IBM Power Systems Firmware Buffer Overflow |
| 🟠 high | CVE-2026-96264: IBM Power Systems Firmware Buffer Overflow | `T1203` | [cvefeed.io] IBM Power Systems Firmware Buffer Overflow |
| 🟠 high | CVE-2026-96263: IBM Power Systems Firmware Buffer Overflow | `T1203` | [cvefeed.io] IBM Power Systems Firmware Buffer Overflow |
| 🟠 high | CVE-2026-96262: IBM Power Systems Firmware Buffer Overflow | `T1203` | [cvefeed.io] IBM Power Systems Firmware Buffer Overflow |
| 🟠 high | CVE-2026-55383: InvoiceShelf: Public EmailLog token type confusion allows cross-company invoice disclosure | — | [cvefeed.io] InvoiceShelf: Public EmailLog token type confusion allows cross-company invoice disclosure |
| 🟠 high | CVE-2026-63626: Mongoose: ppp_handle_ipv6cp() uses attacker-controlled length without bounds check — OO… | — | [cvefeed.io] Mongoose: ppp_handle_ipv6cp() uses attacker-controlled length without bounds check — OOB read and heap over |
| 🟠 high | CVE-2026-111282: iso14229 before 0.10.1 Out-of-Bounds Read via Handle_0x38_RequestFileTransfer | — | [cvefeed.io] iso14229 before 0.10.1 Out-of-Bounds Read via Handle_0x38_RequestFileTransfer |
| 🟠 high | CVE-2026-111280: snap7 through 1.4.3 Out-of-Bounds Write via TSnap7MicroClient::opReadArea | — | [cvefeed.io] snap7 through 1.4.3 Out-of-Bounds Write via TSnap7MicroClient::opReadArea |
| 🟠 high | CVE-2026-111379: FreeRDP before 3.32.0 contains a heap buffer overflow vulnerability in persistent_cache… | `T1203` | FreeRDP before 3.32.0 contains a heap buffer overflow vulnerability in persistent_cache_read_entry_v3 that allows local  |
| 🟠 high | CVE-2026-111380: FreeRDP from 3.29.0 before 3.32.0 contains an integer overflow in the Apple audin backe… | — | FreeRDP from 3.29.0 before 3.32.0 contains an integer overflow in the Apple audin backends (audin_mac.m, audin_ios.m), w |
| 🟠 high | CVE-2026-111381: FreeRDP before 3.32.0 contains a heap buffer overflow vulnerability in persistent_cache… | `T1203` | FreeRDP before 3.32.0 contains a heap buffer overflow vulnerability in persistent_cache_read_entry_v2 that allows local  |
| 🟠 high | CVE-2026-111382: FreeRDP before 3.32.0 contains a client-side heap out-of-bounds write vulnerability in … | — | FreeRDP before 3.32.0 contains a client-side heap out-of-bounds write vulnerability in general_LumaToYUV444 and general_ |
| 🟠 high | CVE-2026-105959: A flaw was found in spice-server. | `T1203` | A flaw was found in spice-server. The GLZ encoder dictionary restore path truncates a size_t allocation size to int when |
| 🟠 high | CVE-2026-105958: A flaw was found in spice-server. | — | A flaw was found in spice-server. Multiple migration data handlers use client-supplied offsets from SPICE_MSGC_MIGRATE_D |
| 🟠 high | CVE-2026-63618: Exposure of Sensitive Information (system level configuration info) to an Unauthorized … | — | Exposure of Sensitive Information (system level configuration info) to an Unauthorized Actor vulnerability in Apache Kyl |
| 🟠 high | CVE-2026-102941: The package github.com/gomarkdown/markdown is a Go library for parsing Markdown text an… | — | The package github.com/gomarkdown/markdown is a Go library for parsing Markdown text and rendering as HTML. Prior to 0.0 |
| 🟠 high | CVE-2026-46472: An issue was discovered in GStreamer gst-plugins-good before 1.28.2. | — | An issue was discovered in GStreamer gst-plugins-good before 1.28.2. While parsing an MP4 file, the isomp4 plugin's qtde |
| 🟠 high | CVE-2026-48503: libIEC61850 is an open-source implementation of IEC 61850 client and server protocols i… | — | libIEC61850 is an open-source implementation of IEC 61850 client and server protocols including MMS, GOOSE, Sampled Valu |
| 🟠 high | CVE-2026-48741: libIEC61850 is an open-source implementation of IEC 61850 client and server protocols i… | — | libIEC61850 is an open-source implementation of IEC 61850 client and server protocols including MMS, GOOSE, Sampled Valu |
| 🟠 high | CVE-2026-57486: pupnp is an SDK for development of UPnP device and control point applications. | — | pupnp is an SDK for development of UPnP device and control point applications. Prior to 2.0.2, ixmlNode_compare in ixml/ |
| 🟠 high | CVE-2026-57488: pupnp is an SDK for development of UPnP device and control point applications. | — | pupnp is an SDK for development of UPnP device and control point applications. Prior to 2.0.2, raw_to_int in upnp/src/ge |
| 🟠 high | CVE-2026-109588: Numeric truncation of the buffer length in the MPU buffer authorization check in FreeRT… | — | Numeric truncation of the buffer length in the MPU buffer authorization check in FreeRTOS-Kernel V11.3.0 and V11.3.1 on  |
| 🟠 high | CVE-2026-111710: Netcore NR256CN through 1.5.140116 contains a NULL pointer dereference vulnerability in… | — | Netcore NR256CN through 1.5.140116 contains a NULL pointer dereference vulnerability in the Boa web server's user_auth() |
| 🟠 high | CVE-2026-102834: JavaCV provides Java interfaces to OpenCV, FFmpeg, and other multimedia libraries. | — | JavaCV provides Java interfaces to OpenCV, FFmpeg, and other multimedia libraries. Prior to 1.5.14, IPCameraFrameGrabber |
| 🟠 high | CVE-2026-62439: A flaw was found in GIMP. | `T1190`, `T1203` | A flaw was found in GIMP. An integer overflow occurs in the file-pvr plug-in when calculating memory buffer sizes for im |
| 🟠 high | CVE-2026-96626: Arcane is an interface for managing Docker containers, images, networks, and volumes. | — | Arcane is an interface for managing Docker containers, images, networks, and volumes. Prior to 2.5.0, UpdateRegistry and |
| 🟠 high | CVE-2026-111880: FreeRDP versions from 2.0.0 before 3.32.0 contain a heap out-of-bounds write in the ser… | — | FreeRDP versions from 2.0.0 before 3.32.0 contain a heap out-of-bounds write in the server hash-callback NTLM path that  |
| 🟠 high | CVE-2026-111881: FreeRDP from 3.14.1 before 3.32.0 contains an integer underflow in the WinPR BMP writer… | — | FreeRDP from 3.14.1 before 3.32.0 contains an integer underflow in the WinPR BMP writer, where a mismatched stride calcu |
| 🟠 high | CVE-2026-112018: cgltf through 1.15 contains a heap out-of-bounds write vulnerability in cgltf_accessor_… | — | cgltf through 1.15 contains a heap out-of-bounds write vulnerability in cgltf_accessor_unpack_floats() that allows attac |
| 🟠 high | CVE-2026-112021: snac2 before 2.93 contains a heap-based buffer overflow vulnerability in _xs_json_load_… | `T1203` | snac2 before 2.93 contains a heap-based buffer overflow vulnerability in _xs_json_load_lexer() that allows unauthenticat |

## Insecure Deserialization (9)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-104730: The Sunshine Photo Cart – Client Photo Gallery & Photo Proofing for Photographers plugi… | `T1059.007` | The Sunshine Photo Cart – Client Photo Gallery & Photo Proofing for Photographers plugin for WordPress is vulnerable to  |
| 🔴 critical | CVE-2026-104736: The LearnPress plugin for WordPress is vulnerable to PHP Object Injection in versions u… | `T1059.007` | The LearnPress plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 4.4.10 via d |
| 🔴 critical | CVE-2026-110886: Deserialization of Untrusted Data vulnerability in QuantumCloud Conversational Forms fo… | `T1059.007` | Deserialization of Untrusted Data vulnerability in QuantumCloud Conversational Forms for ChatBot conversational-forms al |
| 🟠 high | CVE-2026-93905: IBM WebSphere Application Server Liberty is affected by a deserialization of untrusted … | `T1059.007` | [cvefeed.io] IBM WebSphere Application Server Liberty is affected by a deserialization of untrusted data |
| 🟠 high | CVE-2026-75941: A potential vulnerability was reported in the Lenovo Legion Zone application, distribut… | `T1190` | A potential vulnerability was reported in the Lenovo Legion Zone application, distributed exclusively in the Chinese mar |
| 🟠 high | CVE-2026-104932: The Search Regex plugin for WordPress is vulnerable to PHP Object Injection in version … | `T1059.007` | The Search Regex plugin for WordPress is vulnerable to PHP Object Injection in version 3.5 via deserialization of untrus |
| 🟠 high | CVE-2026-97296: Deserialization of Untrusted Data vulnerability in Rocketgenius, Inc Gravity Forms grav… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Rocketgenius, Inc Gravity Forms gravityforms allows Object Injection. |
| 🟠 high | CVE-2026-104734: The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress is… | `T1059.007` | The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress is vulnerable to PHP Object Injecti |
| 🟠 high | CVE-2026-107436: Deserialization of Untrusted Data vulnerability in WP Chill Strong Testimonials strong-… | `T1059.007` | Deserialization of Untrusted Data vulnerability in WP Chill Strong Testimonials strong-testimonials allows Object Inject |

## Path Traversal & File Disclosure (14)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-90530: ColdFusion \| Improper Limitation of a Pathname to a Restricted Directory ('Path Travers… | — | [cvefeed.io] ColdFusion \| Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (CWE-22) |
| 🟠 high | CVE-2026-110767: Gitingest through 0.3.1 Arbitrary File Read via Symlink in Blob Ingestion | — | [cvefeed.io] Gitingest through 0.3.1 Arbitrary File Read via Symlink in Blob Ingestion |
| 🟠 high | CVE-2026-84823: A flaw was found in WildFly. | — | A flaw was found in WildFly. A user with the `Monitor` role, which is the lowest standard Role-Based Access Control (RBA |
| 🟠 high | CVE-2026-109221: The Groundhogg — CRM, Newsletters, and Marketing Automation plugin for WordPress is vul… | `T1190` | The Groundhogg — CRM, Newsletters, and Marketing Automation plugin for WordPress is vulnerable to arbitrary file deletio |
| 🟠 high | CVE-2026-103896: The 10Web Booster – Website speed optimization, Cache & Page Speed optimizer plugin for… | — | The 10Web Booster – Website speed optimization, Cache & Page Speed optimizer plugin for WordPress is vulnerable to a lim |
| 🟠 high | CVE-2026-41582: countly-server is the server-side part of Countly, a product analytics solution. | — | countly-server is the server-side part of Countly, a product analytics solution. Prior to 24.05.50 and 25.03.44, public  |
| 🟠 high | CVE-2026-42269: countly-server is the server-side part of Countly, a product analytics solution. | — | countly-server is the server-side part of Countly, a product analytics solution. Prior to 24.05.50 and 25.03.44, the aut |
| 🟠 high | CVE-2026-111854: An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. | — | An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. A path traversal vulnerability in the SCPI FILE |
| 🟠 high | CVE-2026-111855: An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. | — | An issue was discovered on Tektronix 3 Series MDO devices before 1.21.1. A path traversal vulnerability exists in the we |
| 🟠 high | CVE-2026-112005: WhoDB 0.104.0 before 0.135.0 contains a path traversal vulnerability that allows remote… | — | WhoDB 0.104.0 before 0.135.0 contains a path traversal vulnerability that allows remote attackers to read and write arbi |
| 🟠 high | CVE-2026-112015: Omnigent 0.3.0 before 0.14.0 contains a path traversal vulnerability that allows authen… | — | Omnigent 0.3.0 before 0.14.0 contains a path traversal vulnerability that allows authenticated users to escape the works |
| 🟠 high | CVE-2026-112051: Xinference through 4.0.1 Path Traversal via model_name in Custom Model Registration | — | [cvefeed.io] Xinference through 4.0.1 Path Traversal via model_name in Custom Model Registration |
| ⚪ unknown | CVE-2026-76519: Cisco Secure Email Gateway — Cisco Secure Email Gateway Relative Path Traversal Vulnerability | — | Cisco Secure Email Gateway contains a relative path traversal vulnerability that could allow an unauthenticated, remote  |
| ⚪ unknown | CVE-2025-61624: Fortinet Multiple Products — Fortinet Multiple Products Path Traversal Vulnerability | — | FortiOS, FortiPAM, FortiProxy, and FortiSwitchManager contain a path traversal vulnerability that may allow an authentic |

## SSRF, CSRF & Open Redirect (12)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-89111: OAuth2 SSRF vulnerability in SAP Cloud SDK for Python | — | [VulnTracker digest] SAP_SE SAP Cloud — OAuth2 SSRF vulnerability in SAP Cloud SDK for Python |
| 🟠 high | CVE-2026-95634: CAI Content Credentials \| Server-Side Request Forgery (SSRF) (CWE-918) | — | [cvefeed.io] CAI Content Credentials \| Server-Side Request Forgery (SSRF) (CWE-918) |
| 🟠 high | CVE-2026-34634: ColdFusion \| Server-Side Request Forgery (SSRF) (CWE-918) | — | [cvefeed.io] ColdFusion \| Server-Side Request Forgery (SSRF) (CWE-918) |
| 🟠 high | CVE-2026-106622: ColdFusion \| Server-Side Request Forgery (SSRF) (CWE-918) | — | [cvefeed.io] ColdFusion \| Server-Side Request Forgery (SSRF) (CWE-918) |
| 🟠 high | CVE-2026-111210: A vulnerability was determined in bitcoinj up to 0.17. | — | A vulnerability was determined in bitcoinj up to 0.17. Affected is the function url.openConnection of the file PaymentSe |
| 🟠 high | CVE-2026-110015: The Salon Booking System  WordPress plugin before 10.31.9 does not correctly verify the… | — | The Salon Booking System  WordPress plugin before 10.31.9 does not correctly verify the authenticity of REST API request |
| 🟠 high | CVE-2026-111413: Cross-Site Request Forgery (CSRF) vulnerability in aThemeArt aThemeArt Theme Helper ath… | — | Cross-Site Request Forgery (CSRF) vulnerability in aThemeArt aThemeArt Theme Helper athemeart-theme-helper allows Cross  |
| 🟠 high | CVE-2026-111663: Chaskiq through 2.0.3 contains a server-side request forgery vulnerability that allows … | — | Chaskiq through 2.0.3 contains a server-side request forgery vulnerability that allows unauthenticated attackers to fetc |
| 🟠 high | CVE-2026-59970: Tandoor Recipes is an application for managing recipes, planning meals, and building sh… | — | Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.6.10, pa |
| 🟠 high | CVE-2026-49410: OpenHuman is an open-source agent harness available as a desktop application and Rust l… | — | OpenHuman is an open-source agent harness available as a desktop application and Rust library. Versions before 0.56.0 al |
| 🟠 high | CVE-2026-111884: phpMyFAQ before 4.1.9 and 4.2.0-alpha before 4.2.0-beta does not require the current pa… | — | phpMyFAQ before 4.1.9 and 4.2.0-alpha before 4.2.0-beta does not require the current password when changing an account e |
| 🟠 high | CVE-2026-111907: phpMyFAQ 4.0.0 before 4.1.9 contains a cross-site request forgery vulnerability in the … | — | phpMyFAQ 4.0.0 before 4.1.9 contains a cross-site request forgery vulnerability in the POST /admin/api/update-database e |

## Cryptographic Weaknesses (6)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-111690: Simple Admin Core through 1.8.7 contains an authentication bypass vulnerability that al… | `T1078` | Simple Admin Core through 1.8.7 contains an authentication bypass vulnerability that allows unauthenticated attackers to |
| 🔴 critical | CVE-2026-111692: DataBuff ai-apm-web through 0.1.10 contains an authentication bypass vulnerability that… | `T1078` | DataBuff ai-apm-web through 0.1.10 contains an authentication bypass vulnerability that allows unauthenticated attackers |
| 🟠 high | CVE-2026-111612: netdisk-fast-download through 0.4.8 contains an information disclosure vulnerability th… | — | netdisk-fast-download through 0.4.8 contains an information disclosure vulnerability that allows unauthenticated attacke |
| 🟠 high | CVE-2026-111633: ZKEACMS through 4.4 contains an authentication bypass vulnerability that allows unauthe… | `T1078` | ZKEACMS through 4.4 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge REST  |
| 🟠 high | CVE-2026-111636: OpenBMB StaffDeck through 0.5.6 contains an authentication bypass vulnerability that al… | `T1078` | OpenBMB StaffDeck through 0.5.6 contains an authentication bypass vulnerability that allows unauthenticated attackers to |
| 🟠 high | CVE-2026-111642: FastapiAdmin through 3.0 contains a hard-coded JWT signing secret in backend/app/config… | — | FastapiAdmin through 3.0 contains a hard-coded JWT signing secret in backend/app/config/setting.py that allows low-privi |

## Information Disclosure (2)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-111719: Roncoo-pay through commit 9428382 Information Disclosure via /f2fPay/order/query | — | [cvefeed.io] Roncoo-pay through commit 9428382 Information Disclosure via /f2fPay/order/query |
| 🟠 high | CVE-2026-110889: Generation of Error Message Containing Sensitive Information vulnerability in Gantry Ga… | — | Generation of Error Message Containing Sensitive Information vulnerability in Gantry Gantry 5 Framework gantry5 allows R |

## Denial of Service (11)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-111378: FreeRDP from 3.0.0 before 3.32.0 contains an uncontrolled resource consumption vulnerab… | — | FreeRDP from 3.0.0 before 3.32.0 contains an uncontrolled resource consumption vulnerability in parse_nla_mode_pdu that  |
| 🟠 high | CVE-2026-107564: An unauthenticated remote attacker may use an allocation of resources without limits or… | — | An unauthenticated remote attacker may use an allocation of resources without limits or throttling weakness in the affec |
| 🟠 high | CVE-2026-105273: MP4Parser does not adequately validate MP4 box sizes. | — | MP4Parser does not adequately validate MP4 box sizes. A malformed box can cause parsing to make no forward progress and  |
| 🟠 high | CVE-2026-107621: JPEGParser can enter an infinite loop while parsing a specially crafted or truncated st… | — | JPEGParser can enter an infinite loop while parsing a specially crafted or truncated stream. |
| 🟠 high | CVE-2026-57487: pupnp is an SDK for development of UPnP device and control point applications. | — | pupnp is an SDK for development of UPnP device and control point applications. Prior to 2.0.2, Transfer-Encoding: chunke |
| 🟠 high | CVE-2026-77630: pupnp is an SDK for development of UPnP device and control point applications. | — | pupnp is an SDK for development of UPnP device and control point applications. Prior to 22.0.4, parse_hostport in upnp/s |
| 🟠 high | CVE-2026-77474: destructive_command_guard (dcg) is a command-line safety tool that blocks destructive s… | — | destructive_command_guard (dcg) is a command-line safety tool that blocks destructive shell commands before AI coding ag |
| 🟠 high | CVE-2026-68498: StreamReadConstraints.maxNameLength (default 50,000 characters) is intended to bound ho… | — | StreamReadConstraints.maxNameLength (default 50,000 characters) is intended to bound how much memory a single JSON Objec |
| 🟠 high | CVE-2026-111901: phpMyFAQ 4.2.0-alpha before 4.2.0-beta contains an uncontrolled resource consumption vu… | — | phpMyFAQ 4.2.0-alpha before 4.2.0-beta contains an uncontrolled resource consumption vulnerability in the unauthenticate |
| 🟠 high | CVE-2026-111923: Fleet before 4.89.0 contains an unbounded recursion vulnerability in Apple MDM enrollme… | — | Fleet before 4.89.0 contains an unbounded recursion vulnerability in Apple MDM enrollment property list parsing that all |
| 🟠 high | CVE-2026-111924: Fleet before 4.83.0 contains a denial of service vulnerability that allows unauthentica… | — | Fleet before 4.83.0 contains a denial of service vulnerability that allows unauthenticated attackers to exhaust server m |

## Network Infrastructure & IoT Device Vulnerabilities (2)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-96265: IBM Power Systems Firmware Improper Memory Buffer Restriction | — | [cvefeed.io] IBM Power Systems Firmware Improper Memory Buffer Restriction |
| 🟠 high | CVE-2026-102551: Improper verification of the source of a communication channel in the IPv6 Router Adver… | — | Improper verification of the source of a communication channel in the IPv6 Router Advertisement handler in Amazon FreeRT |

## Critical-Severity Vulnerabilities (8)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105899: ColdFusion \| Unrestricted Upload of File with Dangerous Type (CWE-434) | — | [VulnTracker digest] Adobe ColdFusion 2025 — ColdFusion \| Unrestricted Upload of File with Dangerous Type (CWE-434) |
| 🔴 critical | CVE-2026-90532: Adobe Experience Manager \| Incorrect Authorization (CWE-863) | — | [VulnTracker digest] Adobe Adobe Experience Manager as a Cloud Service — Adobe Experience Manager \| Incorrect Authorizat |
| 🔴 critical | CVE-2026-108390: HestiaCP Low-Privileged User to Root via Config-Field Injection and PATH Hijacking | — | [VulnTracker digest] hestiacp hestiacp — HestiaCP Low-Privileged User to Root via Config-Field Injection and PATH Hijack |
| 🔴 critical | CVE-2026-107617: An attacker can use a hard-coded credential to log in to EseeCloud devices. | — | An attacker can use a hard-coded credential to log in to EseeCloud devices. |
| 🔴 critical | CVE-2026-95182: An untrusted search path in DeepSeek Harness (dsh) commit c291e796 allows attackers to … | `T1190` | An untrusted search path in DeepSeek Harness (dsh) commit c291e796 allows attackers to execute arbitrary code via supply |
| 🔴 critical | CVE-2026-111693: DataBuff ai-apm-web through 0.1.10 contains a hard-coded default credentials vulnerabil… | — | DataBuff ai-apm-web through 0.1.10 contains a hard-coded default credentials vulnerability that allows unauthenticated a |
| 🔴 critical | CVE-2026-111823: CVE-2026-111823 | — | [VulnTracker digest] Mage mage-ai — CVE-2026-111823 |
| 🔴 critical | CVE-2026-111998: Vanus 0.8.0 through 0.9.0 contains a default credentials vulnerability that allows unau… | — | Vanus 0.8.0 through 0.9.0 contains a default credentials vulnerability that allows unauthenticated remote attackers to g |

## High-Severity Vulnerabilities (81)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-44828: Qexo initialization endpoint can reset setup state and expose stored credentials | — | [cvefeed.io] Qexo initialization endpoint can reset setup state and expose stored credentials |
| 🟠 high | CVE-2026-84360: Nginx UI: OTP secure-session step-up can be bypassed via MCP configuration tools | — | [cvefeed.io] Nginx UI: OTP secure-session step-up can be bypassed via MCP configuration tools |
| 🟠 high | CVE-2026-84319: Nginx UI: MCP configuration tools bypass restricted directive validation and allow seco… | — | [cvefeed.io] Nginx UI: MCP configuration tools bypass restricted directive validation and allow secondary authenticated  |
| 🟠 high | CVE-2026-84315: Nginx UI OTP secure-session step-up is missing on sensitive mutation routes | — | [cvefeed.io] Nginx UI OTP secure-session step-up is missing on sensitive mutation routes |
| 🟠 high | CVE-2026-84314: Nginx UI: Account Takeover via Missing `RequireSecureSession` on User Management Endpoint | — | [cvefeed.io] Nginx UI: Account Takeover via Missing `RequireSecureSession` on User Management Endpoint |
| 🟠 high | CVE-2026-84313: Nginx UI: TOTP / passkey enrolment requires no re-authentication, enabling persistent a… | — | [cvefeed.io] Nginx UI: TOTP / passkey enrolment requires no re-authentication, enabling persistent account takeover |
| 🟠 high | CVE-2026-53997: Netherman Portal del Hermano Account Takeover via Password Reset Oracle | — | [cvefeed.io] Netherman Portal del Hermano Account Takeover via Password Reset Oracle |
| 🟠 high | CVE-2026-18537: IBM Maximo Application Suite - Location Service for Esri Component Code Execution | — | [cvefeed.io] IBM Maximo Application Suite - Location Service for Esri Component Code Execution |
| 🟠 high | CVE-2026-18529: IBM Maximo Application Suite - Location Service for Esri Component Code Execution | — | [cvefeed.io] IBM Maximo Application Suite - Location Service for Esri Component Code Execution |
| 🟠 high | CVE-2026-109569: sandboxed.sh through 1.3.0 Container Escape via nsenter Missing Root Namespace | — | [cvefeed.io] sandboxed.sh through 1.3.0 Container Escape via nsenter Missing Root Namespace |
| 🟠 high | CVE-2026-109566: Rapyd Admin 9.0.0 before 9.20.0 Hard-Coded Super-Admin Credentials via AuthSeeder | — | [cvefeed.io] Rapyd Admin 9.0.0 before 9.20.0 Hard-Coded Super-Admin Credentials via AuthSeeder |
| 🟠 high | CVE-2026-109563: N3.js before 2.11.1 ReDoS via N3Lexer Numeric-Literal Regex | — | [cvefeed.io] N3.js before 2.11.1 ReDoS via N3Lexer Numeric-Literal Regex |
| 🟠 high | CVE-2026-109559: EdgeEver Desktop 1.6.26 through 1.112.0 Navigation Allowlist Bypass via will-navigate | — | [cvefeed.io] EdgeEver Desktop 1.6.26 through 1.112.0 Navigation Allowlist Bypass via will-navigate |
| 🟠 high | npp-ml (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-12. Review versio |
| 🟠 high | @coopeuch (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-12. Review versio |
| 🟠 high | @myorder-frontend-commons (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-12. Review versio |
| 🟠 high | @s4yhiitestpoc (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-12. Review versio |
| 🟠 high | CVE-2026-97381: Legacy Update ActiveX control accepts unauthorized hosting origins | — | [cvefeed.io] Legacy Update ActiveX control accepts unauthorized hosting origins |
| 🟠 high | CVE-2026-95639: Photoshop Desktop \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] Photoshop Desktop \| Incorrect Authorization (CWE-863) |
| 🟠 high | CVE-2026-75995: ColdFusion \| Improper Input Validation (CWE-20) | — | [cvefeed.io] ColdFusion \| Improper Input Validation (CWE-20) |
| 🟠 high | CVE-2026-75994: ColdFusion \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] ColdFusion \| Incorrect Authorization (CWE-863) |
| 🟠 high | CVE-2026-71385: ColdFusion \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] ColdFusion \| Incorrect Authorization (CWE-863) |
| 🟠 high | CVE-2026-106620: ColdFusion \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] ColdFusion \| Incorrect Authorization (CWE-863) |
| 🟠 high | CVE-2026-106619: ColdFusion \| Improper Input Validation (CWE-20) | — | [cvefeed.io] ColdFusion \| Improper Input Validation (CWE-20) |
| 🟠 high | CVE-2026-106618: ColdFusion \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] ColdFusion \| Incorrect Authorization (CWE-863) |
| 🟠 high | CVE-2026-106617: ColdFusion \| Incorrect Authorization (CWE-863) | — | [cvefeed.io] ColdFusion \| Incorrect Authorization (CWE-863) |
| 🟠 high | passwordcracker (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-13. Review versio |
| 🟠 high | passwordcrackv2 (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-13. Review versio |
| 🟠 high | crelic-bqwheel-52f66a3f1d (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-13. Review versio |
| 🟠 high | CVE-2026-108336: Token Signing Key Allows Unauthenticated Administrative Access | — | [cvefeed.io] Token Signing Key Allows Unauthenticated Administrative Access |
| 🟠 high | CVE-2026-108335: Password Reset Functionality Missing Brute-Force Protection | — | [cvefeed.io] Password Reset Functionality Missing Brute-Force Protection |
| 🟠 high | CVE-2026-71854: OpenAEV has unauthenticated access and missing object-level authorization on player les… | — | [cvefeed.io] OpenAEV has unauthenticated access and missing object-level authorization on player lessons API |
| 🟠 high | CVE-2026-61843: FileRise: Unauthenticated File Overwrite Through Upload-Enabled Folder Shares | — | [cvefeed.io] FileRise: Unauthenticated File Overwrite Through Upload-Enabled Folder Shares |
| 🟠 high | CVE-2026-57490: FileRise: WebDAV authentication bypasses TOTP/MFA entirely | — | [cvefeed.io] FileRise: WebDAV authentication bypasses TOTP/MFA entirely |
| 🟠 high | CVE-2026-104108: FileRise OIDC login can bind an attacker identity to an existing local account | — | [cvefeed.io] FileRise OIDC login can bind an attacker identity to an existing local account |
| 🟠 high | CVE-2026-103977: FileRise: Session-scoped TOTP rate limiting permits repeated verification attempts | — | [cvefeed.io] FileRise: Session-scoped TOTP rate limiting permits repeated verification attempts |
| 🟠 high | CVE-2026-55682: WeGIA: Session Fixation via User-Controlled PHPSESSID Cookie + DB_HOST Leak in html/seg… | — | [cvefeed.io] WeGIA: Session Fixation via User-Controlled PHPSESSID Cookie + DB_HOST Leak in html/seguranca/sessionStart. |
| 🟠 high | CVE-2026-102986: Plane: Any Authenticated User Can Upload and Delete Assets in Any Published Project via… | — | [cvefeed.io] Plane: Any Authenticated User Can Upload and Delete Assets in Any Published Project via /api/public/assets/ |
| 🟠 high | CVE-2026-55786: Flyto2 Core: Unauthenticated Command Execution via HTTP MCP `execute_module` | — | [cvefeed.io] Flyto2 Core: Unauthenticated Command Execution via HTTP MCP `execute_module` |
| 🟠 high | CVE-2026-110770: Databasus 3.7.0 through 3.61.0 Account Takeover via Password Reset Brute-Force | — | [cvefeed.io] Databasus 3.7.0 through 3.61.0 Account Takeover via Password Reset Brute-Force |
| 🟠 high | CVE-2026-110765: FlexPrice through 2.1.38 QuickBooks Webhook Signature Verification Bypass | — | [cvefeed.io] FlexPrice through 2.1.38 QuickBooks Webhook Signature Verification Bypass |
| 🟠 high | CVE-2026-110761: ILIAS before 9.24, 10.12, and 11.5 PHP Object Injection via Test Results Import | — | [cvefeed.io] ILIAS before 9.24, 10.12, and 11.5 PHP Object Injection via Test Results Import |
| 🟠 high | babel-polyfill-plugin-corejs2 (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-14. Review versio |
| 🟠 high | eth-react-provider (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-14. Review versio |
| 🟠 high | saeka (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-14. Review versio |
| 🟠 high | CVE-2026-111366: cool-admin-midway through 8.0.0 Authorization Bypass via /admin/sys/user Endpoints | — | [cvefeed.io] cool-admin-midway through 8.0.0 Authorization Bypass via /admin/sys/user Endpoints |
| 🟠 high | CVE-2026-111356: MacCMS v10 through 2026.1000.4056 Account Takeover via Password Recovery Brute-Force | — | [cvefeed.io] MacCMS v10 through 2026.1000.4056 Account Takeover via Password Recovery Brute-Force |
| 🟠 high | CVE-2026-111352: ThinkCMF through 8.0.1 Incorrect Authorization in Admin REST API | — | [cvefeed.io] ThinkCMF through 8.0.1 Incorrect Authorization in Admin REST API |
| 🟠 high | CVE-2026-111347: go-ldap-admin through 0.6.2 Hard-Coded RSA Private Key via /base/decryptpwd | — | [cvefeed.io] go-ldap-admin through 0.6.2 Hard-Coded RSA Private Key via /base/decryptpwd |
| 🟠 high | CVE-2026-111330: JuggleIM im-server through 1.8.16 Weak Password Hashing via Unsalted SHA-1 | — | [cvefeed.io] JuggleIM im-server through 1.8.16 Weak Password Hashing via Unsalted SHA-1 |
| | _+31 more…_ | | |

## Other Vulnerabilities (2)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-105133: Ahsay AhsayCBS — Ahsay AhsayCBS Improper Authentication Vulnerability | — | Ahsay AhsayCBS contains an improper authentication vulnerability that could allow a remote attacker to bypass authentica |
| ⚪ unknown | CVE-2026-21589: Atlassian Multiple Products — Atlassian Multiple Products Files or Directories Accessible to External Parties Vulnerability | — | Multiple Atlassian products (Bitbucket Data Center ,Confluence Data Center, Jira Service Management Data Center, Jira So |

## Ransomware activity (ransomware.live + peers) (455)

_Victim claims rolled up from the 7 daily briefings covering this window. Most active groups: n0n (96), thegentlemen (46), qilin (30)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | AAA Architectural Hardware — claimed by akira | — | AAA Architectural Hardware Co. has been a leader in architectural hardware for over 80 years, o ffer… |
| 🟠 high | Aeroklas Duys / Duys Engineering Group — claimed by deadlock (ZA) | — | Aeroklas Duys (Pty) Ltd a specialized automotive manufacturing company It was formed as a strategic … |
| 🟠 high | Albertin Alcide e Figli S.n.c. — claimed by majinahanashi | — | LEAK
2026-10-04
Albertin Alcide e Figli S.n.c. manufactures plates, stamps, and printing forms for hot stamping, flexogr |
| 🟠 high | Amantya Technologies — claimed by orova | — | Amantya brings together deep expertise in AI, software, data, cloud, telecom, GIS, and digital engineering to help enter |
| 🟠 high | Apical Group (commodity processing and logistics) — claimed by n0n | — | Commodity processing / logistics · Singapore |
| 🟠 high | April Asia (port agency operations) — claimed by n0n | — | Port agency / logistics · Indonesia |
| 🟠 high | Asyaport (container terminal operations) — claimed by n0n | — | Port terminal operations · Turkey |
| 🟠 high | BigID — claimed by thegentlemen (US) | — | bigid.com Revenue $100 Million BigID is the enterprise data security platform that finds and classifies sensitive data a |
| 🟠 high | BKH ICD (inland container depot operations) — claimed by n0n | — | Inland container depot · South Korea |
| 🟠 high | BMT IQ (marine surveying and inspection) — claimed by n0n | — | Marine surveying · United Kingdom |
| 🟠 high | BNCT Busan New Container Terminal — claimed by n0n | — | Port terminal operations · South Korea |
| 🟠 high | brookslawfirm.com — claimed by incransom | — | brookslawfirm.com listed by incransom. |
| 🟠 high | Camellia Line (ferry and RoRo operations) — claimed by n0n | — | Ferry / RoRo shipping · Japan |
| 🟠 high | Canadian Mennonite University (CMU) — claimed by dragonforce | — | Canadian Mennonite University (CMU) is a Christian institution in Winnipeg, Manitoba, offering undergraduate degrees in  |
| 🟠 high | CFG SERRAMENTI S.r.l. — claimed by majinahanashi | — | PENDING
Publication scheduled: 2026-10-14T20:43:00Z
Attachments: 1 |
| 🟠 high | Claire's Inc. — claimed by darkproject | — | Claire's Inc. suffered a cyberattack that disrupted its operations and compromised customers and employees data. |
| 🟠 high | Cognosis Limited — claimed by nightspire | — | Cognosis Limited listed by nightspire. |
| 🟠 high | Company #24 — claimed by n0n | — | smart building & surveillance integration · California, USA |
| 🟠 high | ConAuto — claimed by qilin | — | Automotive Parts |
| 🟠 high | Concord Eye Center — claimed by interlock | — | http://www.concordeyecenternh.com/
									A private ophthalmology clinic specializing in various fields. However, it c |
| 🟠 high | Confluent — claimed by thegentlemen (US) | — | confluent.io Revenue $1.16 Billion Confluent is the enterprise data streaming platform built on Apache Kafka that lets c |
| 🟠 high | CULines (container shipping) — claimed by n0n | — | Container shipping · China |
| 🟠 high | Dong-A Tanker (oil tanker operations) — claimed by n0n | — | Oil tanker shipping · South Korea |
| 🟠 high | Dongkuk Steel (steel manufacturing) — claimed by n0n | — | Steel manufacturing · South Korea |
| 🟠 high | Engineers Contractors Fabricators Inc. (ECF) — claimed by interlock | — | https://ecfinc.net/
									ECF, Inc., a piping and insulation contractor specializing in the design and construction o |
| 🟠 high | Eurogate Tanger (container terminal operations) — claimed by n0n | — | Port terminal operations · Morocco |
| 🟠 high | EUSU Logistics (logistics operations) — claimed by n0n | — | Logistics · South Korea |
| 🟠 high | Eversource Energy — claimed by redact | — | Revenue: $14B USD \| Sector: Energy Distribution \| Stock Ticker: NYSE:ES \| Data Size: 3.8 TB \| Files: 751,887 |
| 🟠 high | Fondy Food Pantry — claimed by nightspire | — | Fondy Food Pantry listed by nightspire. |
| 🟠 high | Franklin Miller Inc. — claimed by darkproject | — | As a result of the attack on "Franklin Miller", more than 250 GB of confidential data were stolen. The organization lost |
| 🟠 high | G** Re******* Ltd — claimed by nightspire | — | G** Re******* Ltd listed by nightspire. |
| 🟠 high | Gatetech Technology — claimed by orova | — | Gatetech have dedicated light metal casting industry for over 20 years, be able to offer one stop service from casting t |
| 🟠 high | GCS Kuwait (port community system operations) — claimed by n0n | — | Port community IT · Kuwait |
| 🟠 high | GlobalNet LCL (port agency operations) — claimed by n0n | — | Port agency / logistics · Indonesia |
| 🟠 high | GNCNet / DGT Busan (port community IT) — claimed by n0n | — | Port IT services · South Korea |
| 🟠 high | Greentech Environmental — claimed by interlock | — | https://greentechenv.com/
									Greentech Environmental LLC, a manufacturer of air purification systems using patente |
| 🟠 high | hb0b — claimed by bavacai | — | hb0b listed by bavacai. |
| 🟠 high | hiqbio.com — claimed by safepay | — | The company focuses on applying marine biotechnology to human health, animal health, functional foods and sustainable aq |
| 🟠 high | HPC Hamburg Port Consulting (port operations) — claimed by n0n | — | Port consulting / terminal operations · Germany |
| 🟠 high | HYSYTECH S.r.l. — claimed by majinahanashi | — | LEAK
2026-10-02
HYSYTECH S.r.l. is an Italian engineering and technology company that designs and builds industrial proc |
| 🟠 high | i2r Packaging Solutions Limited — claimed by majinahanashi | — | PENDING
Publication scheduled: 2026-10-15T01:35:00Z
Attachments: 1 |
| 🟠 high | ILCS Pelindo (port logistics operations) — claimed by n0n | — | Port logistics · Indonesia |
| 🟠 high | KFC — claimed by thegentlemen (US) | — | kfc.com Revenue $36.4 Billion KFC runs 34,747 restaurants across 150+ countries and about 99% are franchised, run by loc |
| 🟠 high | KOIKE Sanso Kogoyo Co. Ltd. — claimed by exitium | — | Website: koike-japan.com
You have time until Tuesday(10.13.2026). If you wouldn't contact us we will start selling data. |
| 🟠 high | Korea Ferry (ferry operations) — claimed by n0n | — | Ferry / RoRo shipping · South Korea |
| 🟠 high | KP Industries — claimed by nightspire | — | KP Industries listed by nightspire. |
| 🟠 high | KVH — claimed by everest | — | 2 posts - 1h |
| 🟠 high | Laerdal — claimed by everest | — | 2 posts - 1h |
| 🟠 high | Libre Wireless Technologies — claimed by orova | — | Explore our certified platforms, ranging from MAVID, renowned for being the industry's most integrated, energy-efficient |
| 🟠 high | Louis Fusco — claimed by akira | — | Louis Fusco Landscape Architects is a full-service landscape architectural design firm led by principal Louis Fusco. The |
| | _+405 more…_ | | |

---
Sources: CISA KEV, NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, LLM ThreatIntel, TweetFeed
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W42)*