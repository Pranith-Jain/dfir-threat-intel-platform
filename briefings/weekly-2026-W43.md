# Weekly Threat Briefing — 2026-10-19 – 2026-10-25

> **weekly** · 2026-10-19 – 2026-10-25 · Generated 2026-10-28 14:25 UTC

## Executive Summary

This week (2026-10-19 – 2026-10-25), CISA added 7 new KEV entries and 359 additional high/critical CVEs were published (NVD, cvefeed.io, MyThreatIntel), including 63 critical-severity affecting Plex, argoproj, DrayTek. Active threat indicators across URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, and LLM ThreatIntel — 6,131 unique after cross-source dedup; all 6131 indicators (2000 malware-distribution URLs, 416 malicious domains, 1462 suspicious IPs, 2253 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 729 |
| CVEs | 366 |
| KEVs | 7 |
| IOCs | 6131 |
| Critical | 63 |
| High | 296 |
| Ransomware victims | 363 |

## Critical Remote Code Execution Vulnerabilities (26)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-112371: H3C Magic NX15 RPC esps write code injection | — | [VulnTracker digest] H3C Magic NX15 — H3C Magic NX15 RPC esps write code injection |
| 🔴 critical | CVE-2026-111058: Mercury: Unauthenticated Remote Code Execution via /api/kernels | `T1190` | [VulnTracker digest] mljar mercury — Mercury: Unauthenticated Remote Code Execution via /api/kernels |
| 🔴 critical | CVE-2026-114108: HKUDS Vibe-Trading before 0.1.7 Missing Authentication in FastAPI Server Enabling RCE | `T1190`, `T1078` | [VulnTracker digest] HKUDS Vibe-Trading — HKUDS Vibe-Trading before 0.1.7 Missing Authentication in FastAPI Server Enabl |
| 🔴 critical | CVE-2026-79851: Unauthenticated Buffer Overflow Vulnerability leads to Remote Code Execution in AOS-10 | `T1190`, `T1203` | [VulnTracker digest] Hewlett Packard Enterprise (HPE) Unknown product — Unauthenticated Buffer Overflow Vulnerability le |
| 🔴 critical | CVE-2026-79850: Authentication Bypass Leading to Remote Code Execution in AOS-8 | `T1190`, `T1078` | [VulnTracker digest] Hewlett Packard Enterprise (HPE) Unknown product — Authentication Bypass Leading to Remote Code Exe |
| 🔴 critical | CVE-2026-115547: An input validation issue in the Okta Access Gateway (OAG) Admin Console allows the pro… | — | An input validation issue in the Okta Access Gateway (OAG) Admin Console allows the processing of specially formatted co |
| 🔴 critical | CVE-2026-94267: The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom F… | `T1190` | The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom Fields: Extended PRO WordPress plu |
| 🔴 critical | CVE-2026-53942: Conda Organization Infrastructure is a centralized location for infrastructure codes. | — | Conda Organization Infrastructure is a centralized location for infrastructure codes. Prior to commit 9c0f238, a GitHub  |
| 🔴 critical | CVE-2026-55486: The Goobi viewer is a web application that allows digitised material to be displayed in… | `T1059.007` | The Goobi viewer is a web application that allows digitised material to be displayed in a web browser. From version 25.0 |
| 🟠 high | CVE-2026-112900: Pillow: Argument Injection in Ghostscript call, potentially leading into RCE | `T1190` | [cvefeed.io] Pillow: Argument Injection in Ghostscript call, potentially leading into RCE |
| 🟠 high | CVE-2026-114112: Sharp before 0.35.4 RCE via bundled libheif AVIF decoding | `T1190` | [VulnTracker digest] lovell sharp — Sharp before 0.35.4 RCE via bundled libheif AVIF decoding |
| 🟠 high | CVE-2026-114111: Sharp before 0.35.5 RCE via librsvg Dependency Memory Vulnerability | `T1190` | [VulnTracker digest] lovell sharp — Sharp before 0.35.5 RCE via librsvg Dependency Memory Vulnerability |
| 🟠 high | CVE-2026-105014: Azure Pipelines Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Azure Pipelines Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-79891: Unauthenticated Buffer Overflow Vulnerability leads to Remote Code Execution in AOS-8 | `T1190`, `T1203` | [cvefeed.io] Unauthenticated Buffer Overflow Vulnerability leads to Remote Code Execution in AOS-8 |
| 🟠 high | CVE-2026-79889: Multiple Unauthenticated Buffer Overflow vulnerabilities in AOS-8 Web Interface result … | `T1190`, `T1203` | [cvefeed.io] Multiple Unauthenticated Buffer Overflow vulnerabilities in AOS-8 Web Interface result in Remote Code Execu |
| 🟠 high | CVE-2026-79888: Unauthenticated Buffer Overflow allows Remote Code Execution in web interface | `T1190`, `T1203` | [cvefeed.io] Unauthenticated Buffer Overflow allows Remote Code Execution in web interface |
| 🟠 high | CVE-2026-79887: Authentication Bypass in Web Interface of AOS-8 allows Remote Command Execution (RCE) | `T1190`, `T1078` | [cvefeed.io] Authentication Bypass in Web Interface of AOS-8 allows Remote Command Execution (RCE) |
| 🟠 high | CVE-2026-115727: AgenticSeek before commit 409840c contains a remote code execution vulnerability becaus… | `T1190` | AgenticSeek before commit 409840c contains a remote code execution vulnerability because llm_server/app.py hardcodes Fla |
| 🟠 high | CVE-2026-57142: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.87 to before version 4.6.61, PraisonAI recipe execution has a  |
| 🟠 high | CVE-2026-115895: Happy DOM is a JavaScript implementation of a web browser without its graphical user in… | — | Happy DOM is a JavaScript implementation of a web browser without its graphical user interface. From 17.0.0 until 21.0.4 |
| 🟠 high | CVE-2026-115935: The app/process-api-response-headers action accepts fake Craft API response headers fro… | — | The app/process-api-response-headers action accepts fake Craft API response headers from any authenticated control panel |
| 🟠 high | CVE-2026-115938: Craft CMS allows any authenticated control panel user to submit an element-search condi… | `T1059` | Craft CMS allows any authenticated control panel user to submit an element-search condition whose element selector is ev |
| 🟠 high | CVE-2026-113673: The GeoDirectory  WordPress plugin before 2.8.194 does not properly escape administrato… | `T1190` | The GeoDirectory  WordPress plugin before 2.8.194 does not properly escape administrator-defined text before writing it  |
| 🟠 high | CVE-2026-115970: A vulnerability has been found in Travisun Opptrix 0.4.0. | — | A vulnerability has been found in Travisun Opptrix 0.4.0. This impacts an unknown function of the file /api/system-updat |
| ⚪ unknown | CVE-2026-110936: Siemens Software Center — Siemens Software Center Uncontrolled Search Path Element Vulnerability | `T1190` | Siemens Software Center contains an uncontrolled search path element vulnerability that could allow an authenticated loc |
| ⚪ unknown | CVE-2026-110447: Collabora Collabora Online – Built-in CODE Server — Collabora Online – Built-in CODE Server OS Command Injection Vulnerability | `T1190`, `T1059` | Collabora Collabora Online – Built-in CODE Server when used within the NextCloud platform contains an OS command injecti |

## Command Injection (19)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-112370: H3C Magic NX15 usrlist sub_416874 os command injection | `T1059` | [VulnTracker digest] H3C Magic NX15 — H3C Magic NX15 usrlist sub_416874 os command injection |
| 🔴 critical | CVE-2026-108983: GV-ASManager Web Server Command Injection Vulnerability | `T1059` | [VulnTracker digest] GeoVision Inc. GV-ASManager — GV-ASManager Web Server Command Injection Vulnerability |
| 🔴 critical | CVE-2026-113506: aaPanel File Manager common.py ExecShell os command injection | `T1059` | [VulnTracker digest] N/A aaPanel — aaPanel File Manager common.py ExecShell os command injection |
| 🔴 critical | CVE-2026-113391: DrayTek Vigor2960 Upload Endpoint mainfunction.cgi uploadlangs command injection | `T1059` | [VulnTracker digest] DrayTek Vigor2960 — DrayTek Vigor2960 Upload Endpoint mainfunction.cgi uploadlangs command injectio |
| 🔴 critical | CVE-2026-113390: DrayTek Vigor2960 CGI mainfunction.cgi sub_182B0 os command injection | `T1059` | [VulnTracker digest] DrayTek Vigor2960 — DrayTek Vigor2960 CGI mainfunction.cgi sub_182B0 os command injection |
| 🔴 critical | CVE-2026-113389: DrayTek Vigor2960 CGI Process mainfunction.cgi set_table command injection | `T1059` | [VulnTracker digest] DrayTek Vigor2960 — DrayTek Vigor2960 CGI Process mainfunction.cgi set_table command injection |
| 🔴 critical | CVE-2026-114575: TOTOLINK A950RG product.so UploadCustomModule command injection | `T1059` | [VulnTracker digest] TOTOLINK A950RG — TOTOLINK A950RG product.so UploadCustomModule command injection |
| 🔴 critical | CVE-2026-115995: A security vulnerability has been detected in Unitree Robotics Unitree Go2 up to 1.1.11.4. | `T1059` | A security vulnerability has been detected in Unitree Robotics Unitree Go2 up to 1.1.11.4. The impacted element is the f |
| 🟠 high | CVE-2026-110243: Kiloview E3 NDI Encoder OS Command Injection | `T1059` | [cvefeed.io] Kiloview E3 NDI Encoder OS Command Injection |
| 🟠 high | CVE-2026-107861: Kiloview E3 NDI Encoder OS Command Injection | `T1059` | [cvefeed.io] Kiloview E3 NDI Encoder OS Command Injection |
| 🟠 high | CVE-2026-109122: Kiloview E3 NDI Encoder OS Command Injection | `T1059` | [cvefeed.io] Kiloview E3 NDI Encoder OS Command Injection |
| 🟠 high | CVE-2026-79890: Unauthenticated Command Injection Vulnerabilities in AOS-8 Accessed by the PAPI Protocol | `T1059` | [cvefeed.io] Unauthenticated Command Injection Vulnerabilities in AOS-8 Accessed by the PAPI Protocol |
| 🟠 high | CVE-2026-115726: Aider through 0.86.2 contains a command execution vulnerability that allows attackers t… | — | Aider through 0.86.2 contains a command execution vulnerability that allows attackers to run shell commands by committin |
| 🟠 high | CVE-2026-56838: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.87 to before version 4.6.59, PraisonAI recipe execution blocks |
| 🟠 high | CVE-2026-57117: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.6.10 to before version 4.6.59, LocalManagedAgent / SandboxedAgen |
| 🟠 high | CVE-2026-50056: A local privilege escalation vulnerability in the zmmailboxdmgr launcher of Zimbra Coll… | `T1068` | A local privilege escalation vulnerability in the zmmailboxdmgr launcher of Zimbra Collaboration Suite (ZCS) allows the  |
| 🟠 high | CVE-2026-39902: Cacti is an open source performance and fault management framework. | — | Cacti is an open source performance and fault management framework. Prior to version 1.2.31, the prior blocklist ([;&\| ` |
| 🟠 high | CVE-2026-115969: A flaw has been found in Travisun Opptrix 0.4.0. | `T1059` | A flaw has been found in Travisun Opptrix 0.4.0. This affects an unknown function of the file /api/auth/setup of the com |
| ⚪ unknown | CVE-2026-106931: EG Secure Solutions SiteGuard Server Edition — EG Secure Solutions SiteGuard Server Edition OS Command Injection Vulnerability | `T1059` | EG Secure Solutions SiteGuard Server Edition contains an OS command injection vulnerability which may allow an attacker  |

## Authentication & Authorization Bypass (32)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-57116: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.2.1 to before version 4.6.59, PraisonAI's AgentOS FastAPI deploy |
| 🔴 critical | CVE-2026-46651: The Goobi viewer is a web application that allows digitised material to be displayed in… | — | The Goobi viewer is a web application that allows digitised material to be displayed in a web browser. From version 24.0 |
| 🔴 critical | CVE-2026-110956: The asVereinbase  WordPress plugin before 1.1.8 does not require a valid password or a … | — | The asVereinbase  WordPress plugin before 1.1.8 does not require a valid password or a genuine second factor before auth |
| 🔴 critical | CVE-2026-115933: Postiz signs its session, invitation and password reset tokens with one shared secret a… | — | Postiz signs its session, invitation and password reset tokens with one shared secret and without any marker of what a t |
| 🟠 high | CVE-2026-82166: Dell Application Store Missing Authentication Vulnerability | `T1078` | [cvefeed.io] Dell Application Store Missing Authentication Vulnerability |
| 🟠 high | CVE-2026-76291: Improper Access Control through Scheduled Search Safeguards in Splunk Enterprise | — | [cvefeed.io] Improper Access Control through Scheduled Search Safeguards in Splunk Enterprise |
| 🟠 high | CVE-2026-114509: Laravel TokenGuard authentication bypass through non-string API credentials | `T1078` | [cvefeed.io] Laravel TokenGuard authentication bypass through non-string API credentials |
| 🟠 high | CVE-2026-110825: Kiloview E3 NDI Encoder Missing Authentication for Critical Function | `T1078` | [cvefeed.io] Kiloview E3 NDI Encoder Missing Authentication for Critical Function |
| 🟠 high | CVE-2026-115546: Okta Access Gateway (OAG) does not validate the selected authentication source during s… | — | Okta Access Gateway (OAG) does not validate the selected authentication source during sign-on. An authenticated user wit |
| 🟠 high | CVE-2026-94262: The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom F… | — | The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom Fields: Extended PRO WordPress plu |
| 🟠 high | CVE-2026-112359: Missing Authorization vulnerability in Amauri.IO WPMobile.App wpappninja allows Exploit… | — | Missing Authorization vulnerability in Amauri.IO WPMobile.App wpappninja allows Exploiting Incorrectly Configured Access |
| 🟠 high | CVE-2026-25716: Missing Authorization vulnerability in Hallo Welt! | — | Missing Authorization vulnerability in Hallo Welt! GmbH BlueSpice (Extension:BlueSpiceUserManager) allows any authentica |
| 🟠 high | CVE-2026-56832: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.2 to before version 4.6.59, praisonai.bots.DiscordApproval app |
| 🟠 high | CVE-2026-56835: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 3.11.0 to before version 4.6.59, PraisonAI's Slack bot applies its |
| 🟠 high | CVE-2026-56836: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.112 to before version 4.6.59, PraisonAI's installed console en |
| 🟠 high | CVE-2026-56837: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.6.56 to before version 4.6.59, PraisonAI's LinearBot starts a pu |
| 🟠 high | CVE-2026-57146: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.115 to before version 4.6.61, the published A2U advisory GHSA- |
| 🟠 high | CVE-2026-93639: A missing authorization vulnerability in Zimbra Collaboration Suite (ZCS) allows a dele… | — | A missing authorization vulnerability in Zimbra Collaboration Suite (ZCS) allows a delegated administrator with no expli |
| 🟠 high | CVE-2026-55457: The Goobi viewer is a web application that allows digitised material to be displayed in… | — | The Goobi viewer is a web application that allows digitised material to be displayed in a web browser. Prior to version  |
| 🟠 high | CVE-2026-55459: The Goobi viewer is a web application that allows digitised material to be displayed in… | — | The Goobi viewer is a web application that allows digitised material to be displayed in a web browser. From version 25.0 |
| 🟠 high | CVE-2026-112342: Tandoor Recipes before 2.7.0 contains an improper cache-key design in cookbook/helper/p… | — | Tandoor Recipes before 2.7.0 contains an improper cache-key design in cookbook/helper/permission_helper.py that allows a |
| 🟠 high | CVE-2026-79977: The WireGuard VPN service in subsys/net/lib/wireguard/wg.c updated the peer endpoint fr… | — | The WireGuard VPN service in subsys/net/lib/wireguard/wg.c updated the peer endpoint from a message it could not authent |
| 🟠 high | CVE-2026-65824: OpenReception's appointment booking software provides an end-to-end encrypted appointme… | — | OpenReception's appointment booking software provides an end-to-end encrypted appointment booking platform. Prior to ver |
| 🟠 high | CVE-2026-115975: Broken access control in JiraController in Cervantes version v1.3-beta could allow an a… | — | Broken access control in JiraController in Cervantes version v1.3-beta could allow an attacker to create, edit, or delet |
| 🟠 high | CVE-2026-114191: Missing Authorization vulnerability in Knit Pay UPI QR Code Payment Gateway for WooComm… | — | Missing Authorization vulnerability in Knit Pay UPI QR Code Payment Gateway for WooCommerce upi-qr-code-payment-for-wooc |
| 🟠 high | CVE-2026-116006: A vulnerability was detected in YunaiV/zhijiantianya ruoyi-vue-pro up to 2026.09. | — | A vulnerability was detected in YunaiV/zhijiantianya ruoyi-vue-pro up to 2026.09. The affected element is an unknown fun |
| 🟠 high | CVE-2026-116068: Dokploy through 0.30.10 contains an authorization bypass vulnerability that allows owne… | — | Dokploy through 0.30.10 contains an authorization bypass vulnerability that allows owners or admins of any organization  |
| 🟠 high | CVE-2026-116163: Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication … | `T1078` | Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, |
| 🟠 high | CVE-2026-116183: phpMyFAQ before 4.1.10 contains an object-level authorization bypass vulnerability that… | — | phpMyFAQ before 4.1.10 contains an object-level authorization bypass vulnerability that allows unauthenticated attackers |
| 🟠 high | CVE-2026-116199: Snipe-IT before 8.6.3 contains an authentication bypass in GoogleAuthController::handle… | `T1078` | Snipe-IT before 8.6.3 contains an authentication bypass in GoogleAuthController::handleGoogleCallback, which logs in the |
| 🟠 high | CVE-2026-116201: Snipe-IT before 8.5.0 contains a SAML assertion replay vulnerability that allows attack… | — | Snipe-IT before 8.5.0 contains a SAML assertion replay vulnerability that allows attackers to reuse captured assertions  |
| 🟠 high | CVE-2026-116208: YesWiki from 4.6.2 before 4.7.0 contains a missing authorization vulnerability in Activ… | — | YesWiki from 4.6.2 before 4.7.0 contains a missing authorization vulnerability in ActivityPubService::syncActorPosts tha |

## Privilege Escalation (10)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-25784: Initialization of a Resource with an Insecure Default vulnerability in Hallo Welt! | `T1068` | Initialization of a Resource with an Insecure Default vulnerability in Hallo Welt! GmbH BlueSpice (container image blues |
| 🟠 high | CVE-2026-97785: AAD App Proxy Elevation of Privilege Vulnerability | `T1068` | [cvefeed.io] AAD App Proxy Elevation of Privilege Vulnerability |
| 🟠 high | CVE-2026-83938: Azure Kubernetes Configuration Service Elevation of Privilege Vulnerability | `T1068` | [cvefeed.io] Azure Kubernetes Configuration Service Elevation of Privilege Vulnerability |
| 🟠 high | CVE-2026-110063: VM Inspector for Azure Virtual Machines Elevation of Privilege Vulnerability | `T1068` | [cvefeed.io] VM Inspector for Azure Virtual Machines Elevation of Privilege Vulnerability |
| 🟠 high | CVE-2026-111982: The User Profile Builder  WordPress plugin before 4.0.5 does not verify that a user is … | — | The User Profile Builder  WordPress plugin before 4.0.5 does not verify that a user is authorized to edit the specific a |
| 🟠 high | CVE-2026-94268: The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom F… | — | The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.8, Advanced Custom Fields: Extended PRO WordPress plu |
| 🟠 high | CVE-2026-50057: A local privilege escalation vulnerability in the Zimbra Collaboration Suite (ZCS) MTA … | `T1068` | A local privilege escalation vulnerability in the Zimbra Collaboration Suite (ZCS) MTA package allows the Unix zimbra ac |
| 🟠 high | CVE-2026-93640: A local privilege escalation vulnerability in the optional dnscache package of Zimbra C… | `T1068` | A local privilege escalation vulnerability in the optional dnscache package of Zimbra Collaboration Suite (ZCS) allows t |
| 🟠 high | CVE-2026-115807: The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role… | `T1068` | The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role Editor plugin for WordPress is v |
| 🟠 high | CVE-2026-110018: The aBlocks – Gutenberg Blocks, User Dashboard Builder, Popup Builder, Form Builder & A… | `T1068` | The aBlocks – Gutenberg Blocks, User Dashboard Builder, Popup Builder, Form Builder & Animation Builder plugin for WordP |

## SQL & NoSQL Injection (14)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-112860: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in xnau webdesign Par |
| 🔴 critical | CVE-2026-111402: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Tribulant Software |
| 🔴 critical | CVE-2026-112866: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WPFactory Product  |
| 🔴 critical | CVE-2026-116207: YesWiki 4.6.0 before 4.7.0 and 5.0.0-alpha1 before 5.0.0-alpha4 contains an unauthentic… | `T1190` | YesWiki 4.6.0 before 4.7.0 and 5.0.0-alpha1 before 5.0.0-alpha4 contains an unauthenticated SQL injection vulnerability  |
| 🟠 high | CVE-2026-112837: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Ruben Garcia GamiP |
| 🟠 high | CVE-2026-114621: baserCMS is a website development framework. | — | baserCMS is a website development framework. In versions 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2, list and detail acti |
| 🟠 high | CVE-2026-115999: A vulnerability has been found in mansi-k Restaurant_IMS d7ad49f61ab7cc1ec6eb359ac2b537… | `T1190` | A vulnerability has been found in mansi-k Restaurant_IMS d7ad49f61ab7cc1ec6eb359ac2b5378bdbde0694. Affected is the funct |
| 🟠 high | CVE-2026-116048: A vulnerability was detected in krupalshah EmployeeRecruitmentSystem up to 922ff6d20827… | `T1190` | A vulnerability was detected in krupalshah EmployeeRecruitmentSystem up to 922ff6d208278282e7c8e36d70d9ae356adec9fe. Aff |
| 🟠 high | CVE-2026-116049: A flaw has been found in krupalshah EmployeeRecruitmentSystem up to 922ff6d208278282e7c… | `T1190` | A flaw has been found in krupalshah EmployeeRecruitmentSystem up to 922ff6d208278282e7c8e36d70d9ae356adec9fe. Affected b |
| 🟠 high | CVE-2026-116050: A vulnerability has been found in krupalshah Employee Recruitment System up to 922ff6d2… | `T1190` | A vulnerability has been found in krupalshah Employee Recruitment System up to 922ff6d208278282e7c8e36d70d9ae356adec9fe. |
| 🟠 high | CVE-2026-116211: YesWiki 4.5.0 before 4.7.0 contains an SQL injection vulnerability in PageManager::save… | `T1190` | YesWiki 4.5.0 before 4.7.0 contains an SQL injection vulnerability in PageManager::save(), where the date_maj_fiche fiel |
| 🟠 high | CVE-2026-116060: A vulnerability was determined in SourceCodester Performance Indicator System 1.0. | `T1190` | A vulnerability was determined in SourceCodester Performance Indicator System 1.0. This affects an unknown part of the f |
| 🟠 high | CVE-2026-116061: A vulnerability was identified in SourceCodester Performance Indicator System 1.0. | `T1190` | A vulnerability was identified in SourceCodester Performance Indicator System 1.0. This vulnerability affects unknown co |
| 🟠 high | CVE-2026-116062: A security flaw has been discovered in SourceCodester Performance Indicator System 1.0. | `T1190` | A security flaw has been discovered in SourceCodester Performance Indicator System 1.0. This issue affects some unknown  |

## Cross-Site Scripting (22)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-109198: The Anti-Spam by CleanTalk – Spam Protection Without CAPTCHA plugin for WordPress is vu… | `T1059.007` | The Anti-Spam by CleanTalk – Spam Protection Without CAPTCHA plugin for WordPress is vulnerable to Stored Cross-Site Scr |
| 🟠 high | CVE-2026-109936: The Otter Blocks  WordPress plugin before 3.2.8 does not correctly bound a pattern it u… | `T1059.007` | The Otter Blocks  WordPress plugin before 3.2.8 does not correctly bound a pattern it uses to rewrite its dynamic-conten |
| 🟠 high | CVE-2026-113499: The LiteSpeed Cache WordPress plugin before 7.9.2 does not restrict one of its HTML rew… | — | The LiteSpeed Cache WordPress plugin before 7.9.2 does not restrict one of its HTML rewriting routines to stylesheet con |
| 🟠 high | CVE-2026-113500: The LiteSpeed Cache WordPress plugin before 7.9.2 does not limit one of its HTML optimi… | — | The LiteSpeed Cache WordPress plugin before 7.9.2 does not limit one of its HTML optimization routines to stylesheet con |
| 🟠 high | CVE-2026-112835: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in e4jvikwp VikRentCa |
| 🟠 high | CVE-2026-112838: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in e4jvikwp VikRentCa |
| 🟠 high | CVE-2026-56840: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.2 to before version 4.6.59, praisonai.bots.HTTPApproval render |
| 🟠 high | CVE-2026-112849: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in AivahThemes Hostme |
| 🟠 high | CVE-2026-112863: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Hogash KALLYAS kal |
| 🟠 high | CVE-2026-10632: A reflected cross-site scripting vulnerability in the Classic Web Client of Zimbra Coll… | `T1059.007` | A reflected cross-site scripting vulnerability in the Classic Web Client of Zimbra Collaboration Suite (ZCS) allows an a |
| 🟠 high | CVE-2026-115457: baserCMS is a website development framework. | `T1059.007` | baserCMS is a website development framework. In versions 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2, global shortcode exp |
| 🟠 high | CVE-2026-50053: A request attribute override vulnerability in Zimbra Collaboration Suite (ZCS) allows u… | `T1059.007` | A request attribute override vulnerability in Zimbra Collaboration Suite (ZCS) allows unauthenticated requests to /h/* t |
| 🟠 high | CVE-2026-87901: Improper sanitization in the registration module allows reflected Cross-Site Scripting. | `T1059.007` | Improper sanitization in the registration module allows reflected Cross-Site Scripting. |
| 🟠 high | CVE-2026-102786: Joomla Extension - phoca.cz - Authenticated stored cross-site scripting through HTML at… | `T1059.007` | [cvefeed.io] Joomla Extension - phoca.cz - Authenticated stored cross-site scripting through HTML attribute injection in |
| 🟠 high | CVE-2026-112207: The Download Monitor WordPress plugin before 5.3.4 does not properly validate that a cl… | — | The Download Monitor WordPress plugin before 5.3.4 does not properly validate that a clicked link belongs to the site be |
| 🟠 high | CVE-2026-112844: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Arraytics WP Event |
| 🟠 high | CVE-2026-112869: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Noah Hearle We’re  |
| 🟠 high | CVE-2026-114178: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Bold Grid W3 Total |
| 🟠 high | CVE-2026-114179: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in wordplus BP Better |
| 🟠 high | CVE-2026-114694: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Pixelite Events Ma |
| 🟠 high | CVE-2026-114695: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Infomaniak Network |
| 🟠 high | CVE-2026-114697: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in QuarkA QA Analytic |

## Memory Corruption (23)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-110264: Integer Overflow or Wraparound in GitLab | — | [VulnTracker digest] GitLab GitLab — Integer Overflow or Wraparound in GitLab |
| 🔴 critical | CVE-2026-53921: odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. | — | odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 I |
| 🔴 critical | CVE-2026-115889: Wasmtime is a runtime for WebAssembly. | — | Wasmtime is a runtime for WebAssembly. Prior to 36.0.19 and 43.0.0, the Cranelift compiler backend bit-packs SSA value i |
| 🟠 high | CVE-2026-112896: Pillow: TIFF encoder ColorMap plane-size mismatch causes a heap out-of-bounds read | — | [cvefeed.io] Pillow: TIFF encoder ColorMap plane-size mismatch causes a heap out-of-bounds read |
| 🟠 high | CVE-2026-112405: Pillow: NULL pointer dereference in Image.merge via an unvalidated band 0 | — | [cvefeed.io] Pillow: NULL pointer dereference in Image.merge via an unvalidated band 0 |
| 🟠 high | CVE-2026-112403: Pillow: Heap buffer overflow in ImagingJpegDecode | `T1203` | [cvefeed.io] Pillow: Heap buffer overflow in ImagingJpegDecode |
| 🟠 high | CVE-2026-112402: Pillow: Double free in ImagingScaleAffine on calloc failure via Image.transform | — | [cvefeed.io] Pillow: Double free in ImagingScaleAffine on calloc failure via Image.transform |
| 🟠 high | CVE-2026-112398: Pillow: Heap buffer overflow in FlashPix (FPX) JPEG decoding leads to code execution | `T1203` | [cvefeed.io] Pillow: Heap buffer overflow in FlashPix (FPX) JPEG decoding leads to code execution |
| 🟠 high | CVE-2026-76788: Stack out-of-bounds write in the OSDP Control Panel reply parser | — | [cvefeed.io] Stack out-of-bounds write in the OSDP Control Panel reply parser |
| 🟠 high | CVE-2026-112393: Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO | `T1203` | [cvefeed.io] Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO |
| 🟠 high | CVE-2026-93442: IBM QRadar SIEM Out-of-bounds Read | — | [cvefeed.io] IBM QRadar SIEM Out-of-bounds Read |
| 🟠 high | CVE-2026-115504: CFITSIO through 4.7.0 Out-of-Bounds Write via ffgcls2 in getcols.c | — | [cvefeed.io] CFITSIO through 4.7.0 Out-of-Bounds Write via ffgcls2 in getcols.c |
| 🟠 high | CVE-2026-79886: Unauthenticated Buffer Overflow Vulnerability leads to Denial-of-Service in AOS-8 | `T1203` | [cvefeed.io] Unauthenticated Buffer Overflow Vulnerability leads to Denial-of-Service in AOS-8 |
| 🟠 high | CVE-2026-115484: A flaw was found in the iscsiuio component of open-iscsi. | — | A flaw was found in the iscsiuio component of open-iscsi. The DHCPv4 option parser incorrectly calculates the length of  |
| 🟠 high | CVE-2026-115486: A flaw was found in the iscsiuio component of open-iscsi. | — | A flaw was found in the iscsiuio component of open-iscsi. The IPv6 Neighbor Discovery handler accesses link-layer addres |
| 🟠 high | CVE-2026-115723: Snap7 through 1.4.3 contains an out-of-bounds write vulnerability in the passive partne… | — | Snap7 through 1.4.3 contains an out-of-bounds write vulnerability in the passive partner that allows a malicious active  |
| 🟠 high | CVE-2026-56833: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 3.8.1 to before version 4.6.59, PraisonAI's Dynamic Context module |
| 🟠 high | CVE-2026-56834: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 3.8.1 to before version 4.6.59, PraisonAI's Dynamic Context Discov |
| 🟠 high | CVE-2026-115863: ConnMan through 2.0 has a stack-based buffer overflow via a DHCPv6 Reply message. | `T1203` | ConnMan through 2.0 has a stack-based buffer overflow via a DHCPv6 Reply message. This occurs in get_domains in gdhcp/cl |
| 🟠 high | CVE-2026-79979: The arm64 MMU backend invalidates a single virtual address from the TLB with invalidate… | `T1203` | The arm64 MMU backend invalidates a single virtual address from the TLB with invalidate_tlb_page() in arch/arm64/core/mm |
| 🟠 high | CVE-2026-79982: The Bluetooth HCI USB transport class of the new USB device stack, subsys/usb/device_ne… | `T1190` | The Bluetooth HCI USB transport class of the new USB device stack, subsys/usb/device_next/class/bt_hci.c, copies every c |
| 🟠 high | CVE-2026-116014: open62541 1.5.0 before 1.5.7 contains an integer overflow in UA_DataType_fromStructureD… | — | open62541 1.5.0 before 1.5.7 contains an integer overflow in UA_DataType_fromStructureDescription() that wraps the 16-bi |
| 🟠 high | CVE-2026-116149: ImageMagick before 6.9.13-58 and 7.x before 7.1.2-33 contains a stack-based buffer over… | `T1203` | ImageMagick before 6.9.13-58 and 7.x before 7.1.2-33 contains a stack-based buffer overflow in the handling of bzip2 com |

## Insecure Deserialization (22)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-78162: Apache Camel: Camel-Hazelcast Managed Instances Missing Java Deserialization Filter (In… | `T1059.007` | [VulnTracker digest] Apache Software Foundation Apache Camel — Apache Camel: Camel-Hazelcast Managed Instances Missing J |
| 🔴 critical | CVE-2026-112862: Deserialization of Untrusted Data vulnerability in xnau webdesign Participants Database… | `T1059.007` | Deserialization of Untrusted Data vulnerability in xnau webdesign Participants Database participants-database allows Obj |
| 🔴 critical | CVE-2026-112846: Deserialization of Untrusted Data vulnerability in ThemeREX Group Save Life save-life a… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Group Save Life save-life allows Object Injection.This issue |
| 🔴 critical | CVE-2026-112847: Deserialization of Untrusted Data vulnerability in ThemeREX ZenSoul zensoul allows Obje… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX ZenSoul zensoul allows Object Injection.This issue affects Z |
| 🔴 critical | CVE-2026-112848: Deserialization of Untrusted Data vulnerability in AivahThemes Hostme v2 hostmev2 allow… | `T1059.007` | Deserialization of Untrusted Data vulnerability in AivahThemes Hostme v2 hostmev2 allows Object Injection.This issue aff |
| 🔴 critical | CVE-2026-112851: Deserialization of Untrusted Data vulnerability in ThemeREX Group HotLock hotlock allow… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Group HotLock hotlock allows Object Injection.This issue aff |
| 🔴 critical | CVE-2026-112853: Deserialization of Untrusted Data vulnerability in axiomthemes Hallelujah hallelujah al… | `T1059.007` | Deserialization of Untrusted Data vulnerability in axiomthemes Hallelujah hallelujah allows Object Injection.This issue  |
| 🔴 critical | CVE-2026-112854: Deserialization of Untrusted Data vulnerability in axiomthemes Holistic Center holistic… | `T1059.007` | Deserialization of Untrusted Data vulnerability in axiomthemes Holistic Center holistic-center allows Object Injection.T |
| 🔴 critical | CVE-2026-112855: Deserialization of Untrusted Data vulnerability in axiomthemes Redy redy allows Object … | `T1059.007` | Deserialization of Untrusted Data vulnerability in axiomthemes Redy redy allows Object Injection.This issue affects Redy |
| 🔴 critical | CVE-2026-112856: Deserialization of Untrusted Data vulnerability in ThemeREX Group Vagabonds vagabonds a… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Group Vagabonds vagabonds allows Object Injection.This issue |
| 🔴 critical | CVE-2026-112857: Deserialization of Untrusted Data vulnerability in axiomthemes Reprizo reprizo allows O… | `T1059.007` | Deserialization of Untrusted Data vulnerability in axiomthemes Reprizo reprizo allows Object Injection.This issue affect |
| 🔴 critical | CVE-2026-112858: Deserialization of Untrusted Data vulnerability in axiomthemes Rhodos rhodos allows Obj… | `T1059.007` | Deserialization of Untrusted Data vulnerability in axiomthemes Rhodos rhodos allows Object Injection.This issue affects  |
| 🔴 critical | CVE-2026-112859: Deserialization of Untrusted Data vulnerability in ThemeREX Group Little Birdies little… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Group Little Birdies little-birdies allows Object Injection. |
| 🔴 critical | CVE-2026-115806: The Prime Mover – Backup and Migration plugin for WordPress is vulnerable to PHP Object… | `T1059.007` | The Prime Mover – Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, |
| 🔴 critical | CVE-2026-114196: Deserialization of Untrusted Data vulnerability in paytiumsupport Paytium paytium allow… | `T1059.007` | Deserialization of Untrusted Data vulnerability in paytiumsupport Paytium paytium allows Object Injection.This issue aff |
| 🔴 critical | CVE-2026-94075: Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsl… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsletters-lite allows Object Injecti |
| 🟠 high | CVE-2026-29001: TastyIgniter 4.4.5 PHP Object Injection via Settings Deserialization | `T1059.007` | [cvefeed.io] TastyIgniter 4.4.5 PHP Object Injection via Settings Deserialization |
| 🟠 high | CVE-2026-112332: Motor.NET &lt; 0.19.0 Denial of Service via JsonNet Deserialization | `T1059.007` | [cvefeed.io] Motor.NET &lt; 0.19.0 Denial of Service via JsonNet Deserialization |
| 🟠 high | CVE-2026-112852: Deserialization of Untrusted Data vulnerability in ThemeREX Group Helion helion allows … | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Group Helion helion allows Object Injection.This issue affec |
| 🟠 high | CVE-2026-114624: baserCMS is a website development framework. | `T1059.007` | baserCMS is a website development framework. In versions 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2, the widget-area enti |
| 🟠 high | CVE-2026-57845: Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability … | `T1059.007` | Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute  |
| 🟠 high | CVE-2026-114704: Deserialization of Untrusted Data vulnerability in Christoph Vielgrader Relevanssi  rel… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Christoph Vielgrader Relevanssi  relevanssi allows Object Injection.T |

## Path Traversal & File Disclosure (16)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-46652: The Goobi viewer is a web application that allows digitised material to be displayed in… | `T1190` | The Goobi viewer is a web application that allows digitised material to be displayed in a web browser. From version 24.0 |
| 🔴 critical | CVE-2026-115812: Relative path traversal during model archive extraction in Amazon Web Services Multi Mo… | `T1190` | Relative path traversal during model archive extraction in Amazon Web Services Multi Model Server 1.1.11 and earlier mig |
| 🔴 critical | CVE-2026-115931: Postiz lets a signed-in user ask the backend to run a function on one of their connecte… | — | Postiz lets a signed-in user ask the backend to run a function on one of their connected channels. The backend did not r |
| 🔴 critical | CVE-2026-115932: When a post is published, Postiz treats a media path that is not a web address as a fil… | — | When a post is published, Postiz treats a media path that is not a web address as a file on the server's disk, but it do |
| 🟠 high | CVE-2026-53995: MLflow 3.17.1 Path Traversal via Trace ID API | — | [cvefeed.io] MLflow 3.17.1 Path Traversal via Trace ID API |
| 🟠 high | CVE-2026-114140: nbconvert: File write via path traversal in cell output filenames | — | [cvefeed.io] nbconvert: File write via path traversal in cell output filenames |
| 🟠 high | CVE-2026-115497: The Music Store – WordPress eCommerce plugin for WordPress is vulnerable to Directory T… | — | The Music Store – WordPress eCommerce plugin for WordPress is vulnerable to Directory Traversal in all versions up to, a |
| 🟠 high | CVE-2026-112904: Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or e… | — | Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or ecommerce stores. In versions 1.0. |
| 🟠 high | CVE-2026-112850: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote … | — | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in |
| 🟠 high | CVE-2026-57113: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 2.6.0 to before version 4.6.59, PraisonAI's template loader accept |
| 🟠 high | CVE-2026-63120: pghoard is a PostgreSQL backup daemon and restore tooling that stores backup data in cl… | — | pghoard is a PostgreSQL backup daemon and restore tooling that stores backup data in cloud object stores. Prior to versi |
| 🟠 high | CVE-2026-114622: baserCMS is a website development framework. | — | baserCMS is a website development framework. In versions 5.2.3 before 5.3.2 and 5.4.0 before 5.4.2, the optional BcTheme |
| 🟠 high | CVE-2026-116009: Camaleon CMS before 2.9.3 contains a path traversal vulnerability that allows users wit… | — | Camaleon CMS before 2.9.3 contains a path traversal vulnerability that allows users with only the media permission to wr |
| 🟠 high | CVE-2026-116067: Paisa before 0.7.8 contains a path traversal vulnerability in the GetFile, GetSheet, De… | — | Paisa before 0.7.8 contains a path traversal vulnerability in the GetFile, GetSheet, DeleteBackups, and DeleteSheetBacku |
| 🟠 high | CVE-2026-116171: SiYuan 3.5.4 before 3.8.7 on Windows contains a sensitive-path denylist bypass in IsSen… | — | SiYuan 3.5.4 before 3.8.7 on Windows contains a sensitive-path denylist bypass in IsSensitivePath because the Windows ex |
| 🟠 high | CVE-2026-116191: Rclone before 1.75.2 contains a path traversal vulnerability in serve webdav that allow… | — | Rclone before 1.75.2 contains a path traversal vulnerability in serve webdav that allows unauthenticated attackers to wr |

## SSRF, CSRF & Open Redirect (10)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-57114: PraisonAI is a multi-agent teams system. | — | PraisonAI is a multi-agent teams system. From version 4.5.126 to before version 4.6.59, PraisonAI's Async Jobs API valid |
| 🟠 high | CVE-2026-93631: A cross-site request forgery vulnerability in the OAuth extension of Zimbra Collaborati… | — | A cross-site request forgery vulnerability in the OAuth extension of Zimbra Collaboration Suite (ZCS) Network Edition al |
| 🟠 high | CVE-2026-115810: Tandoor Recipes before 2.7.0 contains a server-side request forgery vulnerability in th… | — | Tandoor Recipes before 2.7.0 contains a server-side request forgery vulnerability in the Pestle importer that allows aut |
| 🟠 high | CVE-2026-116000: A security flaw has been discovered in Zylon PrivateGPT 1.0.0/1.0.1. | — | A security flaw has been discovered in Zylon PrivateGPT 1.0.0/1.0.1. This vulnerability affects the function load_file_f |
| 🟠 high | CVE-2026-116176: vLLM from 0.9.2 before 0.24.0 contains a server-side request forgery vulnerability that… | — | vLLM from 0.9.2 before 0.24.0 contains a server-side request forgery vulnerability that allows API callers to force outb |
| 🟠 high | CVE-2026-116204: YesWiki before 4.7.0 contains a cross-site request forgery vulnerability in the despam … | — | YesWiki before 4.7.0 contains a cross-site request forgery vulnerability in the despam action (tools/security/actions/de |
| 🟠 high | CVE-2026-116094: A vulnerability was determined in EyouCMS up to 1.8.3. | — | A vulnerability was determined in EyouCMS up to 1.8.3. This impacts the function remote_file_to_local of the file applic |
| 🟠 high | CVE-2026-116192: rclone from 1.37 before 1.74.2 SSRF via --rc-serve scheme-relative remote roots | — | [cvefeed.io] rclone from 1.37 before 1.74.2 SSRF via --rc-serve scheme-relative remote roots |
| ⚪ unknown | CVE-2026-96655: Plex Media Server — Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | — | Plex Media Server contains a server-side request forgery (SSRF) vulnerability that could allow an authenticated user to  |
| ⚪ unknown | CVE-2026-96652: Plex Media Server — Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | — | Plex Media Server contains a server-side request forgery (SSRF) vulnerability which could allow an attacker using any X- |

## Cryptographic Weaknesses (2)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-114820: Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise … | — | Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE |
| 🟠 high | CVE-2026-92450: Kiloview E3 NDI Encoder Use of Hard-coded Credentials | — | [cvefeed.io] Kiloview E3 NDI Encoder Use of Hard-coded Credentials |

## Information Disclosure (1)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-112781: Grav 2.0.0 before 2.2.2 Information Disclosure via Form config-*@ Directives | — | [cvefeed.io] Grav 2.0.0 before 2.2.2 Information Disclosure via Form config-*@ Directives |

## Denial of Service (25)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-112894: Pillow: Quadratic-time DoS in PDF save_all (PdfParser.next_object_id) | — | [cvefeed.io] Pillow: Quadratic-time DoS in PDF save_all (PdfParser.next_object_id) |
| 🟠 high | CVE-2026-112406: Pillow: Infinite loop in PdfParser.rewrite_pages on page tree Parent cycle | — | [cvefeed.io] Pillow: Infinite loop in PdfParser.rewrite_pages on page tree Parent cycle |
| 🟠 high | CVE-2026-112400: Pillow: GIF seek keeps rejected size after DecompressionBombError, allowing DoS | — | [cvefeed.io] Pillow: GIF seek keeps rejected size after DecompressionBombError, allowing DoS |
| 🟠 high | CVE-2026-112390: Pillow: Infinite loop in MIC n_frames when the embedded TIFF | — | [cvefeed.io] Pillow: Infinite loop in MIC n_frames when the embedded TIFF |
| 🟠 high | CVE-2026-112782: Grav before 1.7.53.5 and 2.2.2 Image Pixel Limit Bypass Denial of Service | — | [cvefeed.io] Grav before 1.7.53.5 and 2.2.2 Image Pixel Limit Bypass Denial of Service |
| 🟠 high | CVE-2026-93441: IBM QRadar SIEM HTTP Receiver protocol is vulnerable to a denial of service | — | [cvefeed.io] IBM QRadar SIEM HTTP Receiver protocol is vulnerable to a denial of service |
| 🟠 high | CVE-2026-96640: Pillow PDF append accepts malformed shared page-tree DAG causing resource exhaustion | — | [cvefeed.io] Pillow PDF append accepts malformed shared page-tree DAG causing resource exhaustion |
| 🟠 high | CVE-2026-114143: toml-node: Quadratic-complexity DoS via long dotted keys or table paths in toml.parse() | — | [cvefeed.io] toml-node: Quadratic-complexity DoS via long dotted keys or table paths in toml.parse() |
| 🟠 high | CVE-2026-114141: toml-node: Quadratic-complexity DoS via many array-of-tables headers in toml.parse() | — | [cvefeed.io] toml-node: Quadratic-complexity DoS via many array-of-tables headers in toml.parse() |
| 🟠 high | CVE-2026-111810: Apache Traffic Server: Unthrottled per-header diagnostic logging enables a log-flood de… | — | [cvefeed.io] Apache Traffic Server: Unthrottled per-header diagnostic logging enables a log-flood denial of service |
| 🟠 high | CVE-2026-115506: libexpat through 2.9.0 Denial of Service via Billion Laughs Detection Delay | — | [cvefeed.io] libexpat through 2.9.0 Denial of Service via Billion Laughs Detection Delay |
| 🟠 high | CVE-2026-112331: Motor.NET &lt; 0.19.0 Kafka Denial of Service via Structured CloudEvent Mapping | — | [cvefeed.io] Motor.NET &lt; 0.19.0 Kafka Denial of Service via Structured CloudEvent Mapping |
| 🟠 high | CVE-2026-112330: Motor.NET &lt; 0.19.0 RabbitMQ Denial of Service via CloudEvents Headers | — | [cvefeed.io] Motor.NET &lt; 0.19.0 RabbitMQ Denial of Service via CloudEvents Headers |
| 🟠 high | CVE-2026-115728: @hapi/content from 6.0.1 before 6.0.3 contains a regular expression denial of service v… | — | @hapi/content from 6.0.1 before 6.0.3 contains a regular expression denial of service vulnerability in Content.dispositi |
| 🟠 high | CVE-2026-115776: Twisted is an event-based framework for internet applications, supporting Python 3.6+. | — | Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.word |
| 🟠 high | CVE-2026-115778: Twisted is an event-based framework for internet applications, supporting Python 3.6+. | — | Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.conc |
| 🟠 high | CVE-2026-115775: Twisted: Unauthenticated Remote Denial of Service in the Twisted words domish XML Eleme… | — | [cvefeed.io] Twisted: Unauthenticated Remote Denial of Service in the Twisted words domish XML Element Stream via an Unb |
| 🟠 high | CVE-2026-116011: Crow before 1.3.4 contains an uncontrolled recursion vulnerability in crow::json::load(… | — | Crow before 1.3.4 contains an uncontrolled recursion vulnerability in crow::json::load() that allows remote unauthentica |
| 🟠 high | CVE-2026-116177: vLLM from 0.10.2 before 0.25.0 contains an uncontrolled resource consumption vulnerabil… | — | vLLM from 0.10.2 before 0.25.0 contains an uncontrolled resource consumption vulnerability that allows unauthenticated a |
| 🟠 high | CVE-2026-116179: vLLM from 0.18.0 before 0.31.0 contains a resource exhaustion vulnerability that allows… | — | vLLM from 0.18.0 before 0.31.0 contains a resource exhaustion vulnerability that allows API clients to bypass the video/ |
| 🟠 high | CVE-2026-116180: vLLM from 0.8.5 before 0.31.0 has a denial of service flaw. | — | vLLM from 0.8.5 before 0.31.0 has a denial of service flaw. LogprobsTensors.empty_cpu() in vllm/v1/outputs.py allocates  |
| 🟠 high | CVE-2026-116178: vLLM 0.20.0 before 0.30.0 DoS via /inference/v1/generate mm_placeholders | — | [cvefeed.io] vLLM 0.20.0 before 0.30.0 DoS via /inference/v1/generate mm_placeholders |
| 🟠 high | CVE-2026-116174: vLLM 0.22.0 before 0.24.0 Denial of Service via Rust gRPC Generate | — | [cvefeed.io] vLLM 0.22.0 before 0.24.0 Denial of Service via Rust gRPC Generate |
| 🟠 high | CVE-2026-116173: vLLM 0.22.0 before 0.24.0 Denial of Service via gRPC output_candidates.token_ids | — | [cvefeed.io] vLLM 0.22.0 before 0.24.0 Denial of Service via gRPC output_candidates.token_ids |
| 🟠 high | CVE-2026-116172: vLLM 0.22.0 before 0.24.0 DoS via Rust gRPC CandidateTokens.top_n | — | [cvefeed.io] vLLM 0.22.0 before 0.24.0 DoS via Rust gRPC CandidateTokens.top_n |

## Network Infrastructure & IoT Device Vulnerabilities (4)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-113744: Tenda AC19 httpd Web Management Service SetFirewallCfg formSetFirewallCfg stack-based o… | — | [VulnTracker digest] Tenda AC19 — Tenda AC19 httpd Web Management Service SetFirewallCfg formSetFirewallCfg stack-based  |
| 🔴 critical | CVE-2026-113736: D-Link DHP-W610AV HNAP Login defaultvalue.xml login_prepare_hnap empty password | — | [VulnTracker digest] D-Link DHP-W610AV — D-Link DHP-W610AV HNAP Login defaultvalue.xml login_prepare_hnap empty password |
| 🔴 critical | CVE-2026-55981: A firmware verification vulnerability in Creative Sound
Blaster Katana could allow an a… | — | A firmware verification vulnerability in Creative Sound
Blaster Katana could allow an attacker to modify a legitimate fi |
| 🟠 high | CVE-2026-19741: Zephyr's OpenThread integration defined CONFIG_OPENTHREAD_JOINER_PSKD with default "J01… | — | Zephyr's OpenThread integration defined CONFIG_OPENTHREAD_JOINER_PSKD with default "J01NME" in modules/openthread/Kconfi |

## Critical-Severity Vulnerabilities (10)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-90910: Apache Answer: Reaction API authorization bypass for restricted content | — | [VulnTracker digest] Apache Software Foundation Apache Answer — Apache Answer: Reaction API authorization bypass for res |
| 🔴 critical | CVE-2026-103091: Insecure Default Policy and Unrestricted OIDC Enrollment in Google OSS Agent Mesh (SAM) | — | [VulnTracker digest] Google SAM — Insecure Default Policy and Unrestricted OIDC Enrollment in Google OSS Agent Mesh (SAM |
| 🔴 critical | CVE-2026-113709: Argo CD: A Kustomize Helm config home can run commands in the repo-server | — | [VulnTracker digest] argoproj argo-cd — Argo CD: A Kustomize Helm config home can run commands in the repo-server |
| 🔴 critical | CVE-2026-113708: Argo CD: A Kustomize remote ref can run commands in the repo-server | — | [VulnTracker digest] argoproj argo-cd — Argo CD: A Kustomize remote ref can run commands in the repo-server |
| 🔴 critical | CVE-2026-113672: Argo CD: A Jsonnet import can read files from the repo-server | — | [VulnTracker digest] argoproj argo-cd — Argo CD: A Jsonnet import can read files from the repo-server |
| 🔴 critical | CVE-2026-71195: CVE-2026-71195 | — | [VulnTracker digest] OpenStack Manila — CVE-2026-71195 |
| 🔴 critical | CVE-2026-114119: Best Practice Software Bp Premier before 1.14.1.1128 Hardcoded SQL Server Administrativ… | — | [VulnTracker digest] Best Practice Software Bp Premier — Best Practice Software Bp Premier before 1.14.1.1128 Hardcoded  |
| 🔴 critical | CVE-2026-54630: Part-DB is an open source inventory management system for electronic components. | — | Part-DB is an open source inventory management system for electronic components. Prior to version 2.12.1, the part attac |
| 🔴 critical | CVE-2026-63244: An authentication
bypass vulnerability in WizLearn Technologies' Learning Management Sy… | — | An authentication
bypass vulnerability in WizLearn Technologies' Learning Management System (LMS)
could allow an unauthe |
| 🔴 critical | CVE-2026-115893: Wasmtime is a runtime for WebAssembly. | — | Wasmtime is a runtime for WebAssembly. Prior to 36.0.19, 48.0.7, and 49.0.4, the Cranelift compiler backend on aarch64 c |

## High-Severity Vulnerabilities (128)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-112897: Pillow: TiffDecode returns uninitialized memory as pixels for short JPEG strips | — | [cvefeed.io] Pillow: TiffDecode returns uninitialized memory as pixels for short JPEG strips |
| 🟠 high | CVE-2026-112895: Pillow: Unbounded recursion parsing a PDF page tree or trailer chain (incomplete fix fo… | — | [cvefeed.io] Pillow: Unbounded recursion parsing a PDF page tree or trailer chain (incomplete fix for CVE-2026-42310) |
| 🟠 high | CVE-2026-112893: Pillow: Invalid free in FreeType glyph rendering when a stroker is active | — | [cvefeed.io] Pillow: Invalid free in FreeType glyph rendering when a stroker is active |
| 🟠 high | CVE-2026-112892: Pillow: MSP RLE decoder expands a tiny file into unbounded memory | — | [cvefeed.io] Pillow: MSP RLE decoder expands a tiny file into unbounded memory |
| 🟠 high | CVE-2026-112404: Pillow: OOB read in TiffDecode.c tile and RGBA paths leaks heap memory into pixels | — | [cvefeed.io] Pillow: OOB read in TiffDecode.c tile and RGBA paths leaks heap memory into pixels |
| 🟠 high | CVE-2026-112399: Pillow: APNG background disposal allocates full canvas before decompression bomb check | — | [cvefeed.io] Pillow: APNG background disposal allocates full canvas before decompression bomb check |
| 🟠 high | CVE-2026-112397: Pillow: Out-of-bounds access in _imagingmorph on a zero-width image | — | [cvefeed.io] Pillow: Out-of-bounds access in _imagingmorph on a zero-width image |
| 🟠 high | CVE-2026-112392: Pillow: NULL dereference in ImagingExpand via rank filters on zero-size images | — | [cvefeed.io] Pillow: NULL dereference in ImagingExpand via rank filters on zero-size images |
| 🟠 high | CVE-2026-112360: Netis EAP930 CGI Endpoint debug return200 backdoor | — | [cvefeed.io] Netis EAP930 CGI Endpoint debug return200 backdoor |
| 🟠 high | CVE-2026-92559: IBM App Connect Enterprise is vulnerable to a credential exposure | — | [cvefeed.io] IBM App Connect Enterprise is vulnerable to a credential exposure |
| 🟠 high | CVE-2026-91668: Vulnerability in the Oracle Data Integrator produc | — | [cvefeed.io] Vulnerability in the Oracle Data Integrator produc |
| 🟠 high | CVE-2026-91665: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91663: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91658: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91656: Vulnerability in Oracle Essbase (component: Federa | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Federa |
| 🟠 high | CVE-2026-91655: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91653: Vulnerability in Oracle Essbase (component: Essbas | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Essbas |
| 🟠 high | CVE-2026-91651: Vulnerability in Oracle Essbase (component: Essbas | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Essbas |
| 🟠 high | CVE-2026-91647: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91644: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91638: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91637: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91635: Vulnerability in Oracle Essbase (component: Securi | — | [cvefeed.io] Vulnerability in Oracle Essbase (component: Securi |
| 🟠 high | CVE-2026-91625: Vulnerability in the Oracle Agile Product Lifecycl | — | [cvefeed.io] Vulnerability in the Oracle Agile Product Lifecycl |
| 🟠 high | CVE-2026-91624: Vulnerability in the Oracle Agile Product Lifecycl | — | [cvefeed.io] Vulnerability in the Oracle Agile Product Lifecycl |
| 🟠 high | CVE-2026-91622: Vulnerability in the Oracle Agile Product Lifecycl | — | [cvefeed.io] Vulnerability in the Oracle Agile Product Lifecycl |
| 🟠 high | CVE-2026-91610: Vulnerability in Oracle REST Data Services (compon | — | [cvefeed.io] Vulnerability in Oracle REST Data Services (compon |
| 🟠 high | CVE-2026-91597: Vulnerability in the Oracle Business Intelligence | — | [cvefeed.io] Vulnerability in the Oracle Business Intelligence |
| 🟠 high | CVE-2026-91579: Vulnerability in the Oracle BI Publisher product o | — | [cvefeed.io] Vulnerability in the Oracle BI Publisher product o |
| 🟠 high | CVE-2026-91573: Vulnerability in the Oracle Agile Product Lifecycl | — | [cvefeed.io] Vulnerability in the Oracle Agile Product Lifecycl |
| 🟠 high | CVE-2026-91563: Vulnerability in the Oracle OLAP component of Orac | — | [cvefeed.io] Vulnerability in the Oracle OLAP component of Orac |
| 🟠 high | CVE-2026-91550: Vulnerability in the Oracle Agile Product Lifecycl | — | [cvefeed.io] Vulnerability in the Oracle Agile Product Lifecycl |
| 🟠 high | debbug (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | deebug (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | semer (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | ssemver (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | @ziedzzz (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | abbishal-poc-as-dependency (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | animatecss-tailwind-bridge (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | eacq-payform-core (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | tellyo-colours (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | tinkoff-cache-path (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | tostpro (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-20. Review versio |
| 🟠 high | CVE-2026-76298: Use of Hard-coded Cryptographic Key in the PostgreSQL Sidecar Service in Splunk Enterprise | — | [cvefeed.io] Use of Hard-coded Cryptographic Key in the PostgreSQL Sidecar Service in Splunk Enterprise |
| 🟠 high | CVE-2026-103090: Unauthenticated Biscuit Credential Disclosure via GET /enroll/status in Google OSS Agen… | — | [cvefeed.io] Unauthenticated Biscuit Credential Disclosure via GET /enroll/status in Google OSS Agent Mesh (SAM) |
| 🟠 high | CVE-2026-91403: Vulnerability in the Oracle Java SE, Oracle GraalV | — | [cvefeed.io] Vulnerability in the Oracle Java SE, Oracle GraalV |
| 🟠 high | CVE-2026-114383: TOTOLINK EX200 wireless.so cstecgi.cgi setWiFiAclAddConfig stack-based overflow | — | [cvefeed.io] TOTOLINK EX200 wireless.so cstecgi.cgi setWiFiAclAddConfig stack-based overflow |
| 🟠 high | CVE-2026-114382: TOTOLINK EX200 lan.so cstecgi.cgi setStaticDhcpConfig stack-based overflow | — | [cvefeed.io] TOTOLINK EX200 lan.so cstecgi.cgi setStaticDhcpConfig stack-based overflow |
| 🟠 high | CVE-2026-96639: Pillow multi-frame loaders can reuse stale native image storage after mode transitions | — | [cvefeed.io] Pillow multi-frame loaders can reuse stale native image storage after mode transitions |
| 🟠 high | CVE-2026-114142: toml-node: Prototype pollution: parsing a TOML document can write to Object.prototype | — | [cvefeed.io] toml-node: Prototype pollution: parsing a TOML document can write to Object.prototype |
| | _+78 more…_ | | |

## Other Vulnerabilities (2)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-96656: Plex Media Server — Plex Media Server External Control of File Name or Path Vulnerability | — | Plex Media Server contains an external control of file name or path vulnerability which can allow an admin user to write |
| ⚪ unknown | CVE-2026-96654: Plex Media Server — Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability | — | Plex Media Server contains an improper neutralization of encoded URI schemes in a web page vulnerability that could allo |

## Ransomware activity (ransomware.live + peers) (363)

_Victim claims rolled up from the 7 daily briefings covering this window. Most active groups: n0n (55), qilin (37), braincipher (34)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | AdminData.part1.rar — claimed by braincipher | — | AdminData.part1.rar listed by braincipher. |
| 🟠 high | AdminData.part2.rar — claimed by braincipher | — | AdminData.part2.rar listed by braincipher. |
| 🟠 high | Amagi Media Labs — claimed by n0n | — | media technology / broadcast playout · United States |
| 🟠 high | American Campus — claimed by helix | — | American Campus listed by helix. |
| 🟠 high | Baker Donelson — claimed by redact | — | Baker Donelson listed by redact. |
| 🟠 high | Baltimore Tank Lines — claimed by storm | — | Baltimore Tank Lines listed by storm. |
| 🟠 high | Bay Alarm — claimed by helix | — | Bay Alarm listed by helix. |
| 🟠 high | Belcorp — claimed by qilin | — | Business Services |
| 🟠 high | chooseultimate.com — claimed by lockbit5 (US) | — | Ultimate Health Plans is a local Medicare Advantage Plan based in Spring Hill, Florida, serving vari... |
| 🟠 high | Company #92 — claimed by n0n | — | IT services · South Korea |
| 🟠 high | Company #93 — claimed by n0n (US) | — | healthcare support services · United States \| [PENDING EXPOSURE] |
| 🟠 high | Company #94 — claimed by n0n (US) | — | automotive retail · United States \| [PENDING EXPOSURE] |
| 🟠 high | CREDIN — claimed by qilin | — | CREDIN listed by qilin. |
| 🟠 high | Dental Team FL — claimed by qilin | — | Dental Team FL listed by qilin. |
| 🟠 high | Far West Contractors — claimed by deadlock | — | Far West Contractors listed by deadlock. |
| 🟠 high | Finzly Corp — claimed by n0n (US) | — | fintech payments · US \| Network configuration and access secrets for payment infrastructure; Cloud environment topology  |
| 🟠 high | Froggys Fog — claimed by n0n (US) | — | special-effects fog fluid manufacturer and distributor (order management and shipping operations) · Tennessee, USA \| The |
| 🟠 high | GardaWorld — claimed by qilin | — | GardaWorld listed by qilin. |
| 🟠 high | Greggio Argento — claimed by deadlock | — | Greggio Argento listed by deadlock. |
| 🟠 high | Grupo Cronica — claimed by qilin | — | Grupo Cronica listed by qilin. |
| 🟠 high | GTL Concreto e Logística LTDA — claimed by emperador | — | GTL Concreto e Logística LTDA listed by emperador. |
| 🟠 high | Hotel DuPont — claimed by n0n (US) | — | hospitality · United States \| Network and phone system configurations for a hospitality property, including access crede |
| 🟠 high | Johnson & Pace — claimed by qilin | — | Johnson & Pace listed by qilin. |
| 🟠 high | Kingwood Endoscopy — claimed by n0n (US) | — | Healthcare - Ambulatory Surgery Center (US) · Texas, US \| The complete network configuration of an outpatient endoscopy  |
| 🟠 high | Latham & Watkins — claimed by leakeddata | — | Founded in 1934, Latham & Watkins is an international law firm specializing in activism, communication… |
| 🟠 high | Latham & Watkins — claimed by silentransomgroup | — | Latham & Watkins listed by silentransomgroup. |
| 🟠 high | Merit Financial Group — claimed by storm | — | Merit Financial Group listed by storm. |
| 🟠 high | Patriot Maritime — claimed by storm | — | Patriot Maritime listed by storm. |
| 🟠 high | Personify Health — claimed by helix | — | Personify Health listed by helix. |
| 🟠 high | PingCAP / TiDB Cloud — claimed by fulcrumsec | — | PingCAP / TiDB Cloud listed by fulcrumsec. |
| 🟠 high | POWERsonic Industries Inc. — claimed by aurora | — | POWERsonic Industries Inc. listed by aurora. |
| 🟠 high | Quikrete — claimed by helix | — | Quikrete listed by helix. |
| 🟠 high | RedirectedFolders.part01.rar — claimed by braincipher | — | RedirectedFolders.part01.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part02.rar — claimed by braincipher | — | RedirectedFolders.part02.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part03.rar — claimed by braincipher | — | RedirectedFolders.part03.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part04.rar — claimed by braincipher | — | RedirectedFolders.part04.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part05.rar — claimed by braincipher | — | RedirectedFolders.part05.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part06.rar — claimed by braincipher | — | RedirectedFolders.part06.rar listed by braincipher. |
| 🟠 high | RedirectedFolders.part07.rar — claimed by braincipher | — | RedirectedFolders.part07.rar listed by braincipher. |
| 🟠 high | Rheem Global — claimed by helix | — | Rheem Global listed by helix. |
| 🟠 high | Rosenberg & Pittinsky — claimed by globalsecretgroup | — | Rosenberg & Pittinsky listed by globalsecretgroup. |
| 🟠 high | Salauno — claimed by qilin | — | Salauno listed by qilin. |
| 🟠 high | SalesData.part1.rar — claimed by braincipher | — | SalesData.part1.rar listed by braincipher. |
| 🟠 high | SalesData.part2.rar — claimed by braincipher | — | SalesData.part2.rar listed by braincipher. |
| 🟠 high | Seetelhotels.de — claimed by incransom | — | Seetelhotels.de listed by incransom. |
| 🟠 high | Seminole Schools — claimed by globalsecretgroup | — | Seminole Schools listed by globalsecretgroup. |
| 🟠 high | SkyWorld Air Cargo — claimed by qilin | — | SkyWorld Air Cargo listed by qilin. |
| 🟠 high | Smith Douglas Homes — claimed by helix | — | Smith Douglas Homes listed by helix. |
| 🟠 high | Southwire — claimed by helix | — | Southwire listed by helix. |
| 🟠 high | StudioAdviser.rar — claimed by braincipher | — | StudioAdviser.rar listed by braincipher. |
| | _+313 more…_ | | |

---
Sources: CISA KEV, NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, LLM ThreatIntel
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W43)*