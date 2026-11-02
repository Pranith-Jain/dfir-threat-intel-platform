# Weekly Threat Briefing — 2026-10-05 – 2026-10-11

> **weekly** · 2026-10-05 – 2026-10-11 · Generated 2026-10-18 00:45 UTC

## Executive Summary

This week (2026-10-05 – 2026-10-11), 378 high/critical CVEs were published across NVD, cvefeed.io and MyThreatIntel, including 44 critical-severity; none have been added to CISA KEV yet. Active threat indicators across URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, and LLM ThreatIntel — 17,773 unique after cross-source dedup; all 10801 indicators (3331 malware-distribution URLs, 2230 malicious domains, 1233 suspicious IPs, 4007 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 591 |
| CVEs | 378 |
| KEVs | 0 |
| IOCs | 17773 |
| Critical | 44 |
| High | 305 |
| Ransomware victims | 213 |

## Critical Remote Code Execution Vulnerabilities (18)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105857: Payload: RCE in Payload Form Builder | `T1190` | [VulnTracker digest] payloadcms payload — Payload: RCE in Payload Form Builder |
| 🔴 critical | CVE-2026-104028: The Anton Extensions WordPress plugin through 1.2.2 does not perform any capability che… | `T1190` | The Anton Extensions WordPress plugin through 1.2.2 does not perform any capability check, nonce verification, or file-t |
| 🟠 high | CVE-2026-12171: auto-changelog before 2.6.1 merges configuration from inside the target repository (the… | — | auto-changelog before 2.6.1 merges configuration from inside the target repository (the .auto-changelog file and the aut |
| 🟠 high | CVE-2026-101919: A flaw was found in the HyperShift operator. | `T1190` | A flaw was found in the HyperShift operator. The operator copies user-provided Kubernetes configuration (kubeconfig) sec |
| 🟠 high | CVE-2026-105642: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 6.56.0 until 6.67.0, an image processing library bundled with Ghost c |
| 🟠 high | CVE-2026-105677: Ghost is a Node.js content management system. | `T1190` | Ghost is a Node.js content management system. From 6.10.3 until 6.64.0, a vulnerability in how Ghost loads theme transla |
| 🟠 high | CVE-2026-105812: Code injection via unencoded configuration values during Python code generation in Bedr… | — | [cvefeed.io] Code injection via unencoded configuration values during Python code generation in Bedrock AgentCore Starte |
| 🟠 high | CVE-2026-79801: Unauthenticated Missing Integrity Verification allows Remote Code Execution in ClearPas… | `T1190` | [cvefeed.io] Unauthenticated Missing Integrity Verification allows Remote Code Execution in ClearPass Policy Manager Cli |
| 🟠 high | CVE-2026-79800: Authenticated Path Traversal Vulnerability Leads to Remote Code Execution in ClearPass … | `T1190` | [cvefeed.io] Authenticated Path Traversal Vulnerability Leads to Remote Code Execution in ClearPass Policy Manager |
| 🟠 high | CVE-2026-76754: Unauthenticated SQL Injection Vulnerability leads to Remote Code Execution in ClearPass… | `T1190` | [cvefeed.io] Unauthenticated SQL Injection Vulnerability leads to Remote Code Execution in ClearPass Policy Manager |
| 🟠 high | CVE-2026-76751: Missing Integrity Verification in the OnGuard Agent of ClearPass Policy Manager Allows … | `T1190` | [cvefeed.io] Missing Integrity Verification in the OnGuard Agent of ClearPass Policy Manager Allows Unauthenticated Remo |
| 🟠 high | CVE-2026-76750: Unauthenticated Deserialization of Untrusted Data allows Remote Code Execution in the W… | `T1190`, `T1059.007` | [cvefeed.io] Unauthenticated Deserialization of Untrusted Data allows Remote Code Execution in the Web Interface of HPE  |
| 🟠 high | CVE-2026-105816: Vault Vulnerable to Arbitrary Code Execution via Plugin Catalog Entries Restored From R… | `T1190` | [cvefeed.io] Vault Vulnerable to Arbitrary Code Execution via Plugin Catalog Entries Restored From Raft Snapshots |
| 🟠 high | CVE-2026-76501: Cisco Nexus 9000 Series Switches SRv6 OAM (NGOAM) Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Cisco Nexus 9000 Series Switches SRv6 OAM (NGOAM) Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-76486: Cisco Nexus 3000 and 9000 Series Switches VXLAN OAM (NGOAM) Remote Code Execution Vulne… | `T1190` | [cvefeed.io] Cisco Nexus 3000 and 9000 Series Switches VXLAN OAM (NGOAM) Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-76485: Cisco Nexus 3000 and 9000 Series Switches VXLAN OAM (NGOAM) Remote Code Execution Vulne… | `T1190` | [cvefeed.io] Cisco Nexus 3000 and 9000 Series Switches VXLAN OAM (NGOAM) Remote Code Execution Vulnerability |
| 🟠 high | CVE-2026-76471: Cisco NX-OS Software NX-API Remote Code Execution Vulnerability | `T1190` | [cvefeed.io] Cisco NX-OS Software NX-API Remote Code Execution Vulnerability |
| 🟡 medium | CVE-2026-105808: Sourcecodester Simple Student Information System | `T1059.007` | [dbu.gs] XSS; Code Injection (public exploit available, fix available) |

## Command Injection (10)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105691: Penpot is an open-source design and prototyping platform. | — | Penpot is an open-source design and prototyping platform. Prior to 2.18.0, the SVG exporter places an attacker-controlle |
| 🔴 critical | CVE-2026-105697: Langflow is a tool for building and deploying AI-powered agents and workflows. | `T1059` | Langflow is a tool for building and deploying AI-powered agents and workflows. Before Langflow 1.10.3, the MCP stdio tra |
| 🔴 critical | CVE-2026-105740: Langflow is a tool for building and deploying AI-powered agents and workflows. | `T1190` | Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.0, any authenticated Langflo |
| 🔴 critical | CVE-2026-108540: A flaw has been found in OpenSpug Spug up to 3.4.0/4.0.1. | `T1059` | A flaw has been found in OpenSpug Spug up to 3.4.0/4.0.1. This impacts an unknown function of the file /exec/transfer of |
| 🔴 critical | CVE-2026-108576: A vulnerability was found in TOZED X300 up to 6.01.3. | `T1059` | A vulnerability was found in TOZED X300 up to 6.01.3. This vulnerability affects the function process_ping of the compon |
| 🟠 high | CVE-2026-79803: Authenticated Command Injection Leading to Privilege Escalation in ClearPass Policy Man… | `T1059`, `T1068` | [cvefeed.io] Authenticated Command Injection Leading to Privilege Escalation in ClearPass Policy Manager API |
| 🟠 high | CVE-2026-79802: Command Injection Vulnerability in the ClearPass Policy Manager Client Software | `T1059` | [cvefeed.io] Command Injection Vulnerability in the ClearPass Policy Manager Client Software |
| 🟠 high | CVE-2026-108744: pbi-cli 3.10.1 through 3.12.0 contains an OS command injection vulnerability in desktop… | `T1059` | pbi-cli 3.10.1 through 3.12.0 contains an OS command injection vulnerability in desktop_sync.py that passes unquoted .pb |
| 🟠 high | CVE-2026-108963: databasement before 1.8.2 allows remote code execution because it runs certain commands… | `T1190`, `T1059` | databasement before 1.8.2 allows remote code execution because it runs certain commands (e.g., mariadb-dump) with a data |
| 🟠 high | CVE-2026-108976: GNU Emacs before 31.2 (and TRAMP through 2.8.2) allows OS command injection via a filen… | `T1059` | GNU Emacs before 31.2 (and TRAMP through 2.8.2) allows OS command injection via a filename because tramp-user-regexp has |

## Authentication & Authorization Bypass (63)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-79820: A remote user validation failure vulnerability exists in HPE Integrated Lights-Out (iLO… | — | A remote user validation failure vulnerability exists in HPE Integrated Lights-Out (iLO) 7 firmware. |
| 🔴 critical | CVE-2026-105637: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, ProjectBulkAssetEndpoint.post in apps/api/plane/app/vie |
| 🔴 critical | CVE-2026-105639: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane's signup flow creates a logged-in User row for an |
| 🔴 critical | CVE-2026-105640: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane trusts email addresses returned by Gitea OAuth an |
| 🔴 critical | CVE-2026-100103: Authentication bypass via default auth token in P4Search | `T1078` | [VulnTracker digest] Perfoce P4 (Helix Core) — Authentication bypass via default auth token in P4Search |
| 🔴 critical | CVE-2026-106372: Google Google Chrome | — | [dbu.gs] Incorrect Authorization (fix available) |
| 🔴 critical | CVE-2026-106241: Google Google Chrome | — | [dbu.gs] Incorrect Authorization (fix available) |
| 🔴 critical | CVE-2026-108707: Wukong_HRM through commit 186115e contains an authentication bypass vulnerability in Pa… | `T1078` | Wukong_HRM through commit 186115e contains an authentication bypass vulnerability in ParamAspect that allows unauthentic |
| 🔴 critical | CVE-2026-81649: The Fundiin cho WooCommerce WordPress plugin through 3.4.0 does not have proper authori… | `T1059.007` | The Fundiin cho WooCommerce WordPress plugin through 3.4.0 does not have proper authorisation on several of its REST API |
| 🔴 critical | CVE-2026-84251: The click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1 does not have autho… | — | The click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1 does not have authorisation and CSRF checks when upd |
| 🔴 critical | CVE-2026-84252: The click5 CRM add-on to WPForms WordPress plugin through 1.0.3 does not have authorisa… | — | The click5 CRM add-on to WPForms WordPress plugin through 1.0.3 does not have authorisation and CSRF checks when updatin |
| 🔴 critical | CVE-2026-84253: The click5 CRM add-on to Gravity Forms WordPress plugin through 1.0.3 does not have aut… | — | The click5 CRM add-on to Gravity Forms WordPress plugin through 1.0.3 does not have authorisation and CSRF checks when u |
| 🔴 critical | CVE-2026-84254: The click5 CRM add-on to Contact Form 7 WordPress plugin through 1.0.4 does not have au… | — | The click5 CRM add-on to Contact Form 7 WordPress plugin through 1.0.4 does not have authorisation and CSRF checks when  |
| 🔴 critical | CVE-2026-84734: The Mindstien Quick Login WordPress plugin through 1.0 does not correctly validate a va… | — | The Mindstien Quick Login WordPress plugin through 1.0 does not correctly validate a value supplied in the request again |
| 🔴 critical | CVE-2026-84737: The Freeton WP WordPress plugin through 1.0.0 does not correctly validate the activatio… | — | The Freeton WP WordPress plugin through 1.0.0 does not correctly validate the activation code when authenticating a user |
| 🔴 critical | CVE-2026-85121: The Insurify  WordPress plugin through 1.0 does not have authorisation and nonce checks… | — | The Insurify  WordPress plugin through 1.0 does not have authorisation and nonce checks on one of its AJAX actions, allo |
| 🔴 critical | CVE-2026-86706: The Quick quotes  WordPress plugin through 1.0.0 does not perform any capability or non… | — | The Quick quotes  WordPress plugin through 1.0.0 does not perform any capability or nonce check on one of its AJAX actio |
| 🔴 critical | CVE-2026-86717: The Insurify  WordPress plugin through 1.0 does not have authorisation and nonce checks… | — | The Insurify  WordPress plugin through 1.0 does not have authorisation and nonce checks on one of its AJAX actions, allo |
| 🟠 high | CVE-2026-105170: A weakness has been identified in kishor-23 food-waste-management-system 411989e3ecb828… | `T1078` | A weakness has been identified in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03d7d93/b3a70b |
| 🟠 high | CVE-2026-105307: A vulnerability was detected in Casdoor up to 3.161.1. | `T1078` | A vulnerability was detected in Casdoor up to 3.161.1. Affected is the function ApiFilter of the file routers/authz_filt |
| 🟠 high | CVE-2026-104891: mppx-condition-gate provides conditional free-access wrappers for mppx payment methods. | — | mppx-condition-gate provides conditional free-access wrappers for mppx payment methods. Prior to @insumermodel/mppx-cond |
| 🟠 high | CVE-2026-104971: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, DuplicateAssetEndpoint fetches a source FileAsset witho |
| 🟠 high | CVE-2026-104975: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane's dashboard asset endpoints in plane/app/views/as |
| 🟠 high | CVE-2026-104978: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane's project invitation list endpoint is accessible  |
| 🟠 high | CVE-2026-104979: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, IntakeIssuePublicViewSet.create in Plane v1.3.1 writes  |
| 🟠 high | CVE-2026-105629: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, BulkEstimatePointEndpoint.destroy resolves an estimate  |
| 🟠 high | CVE-2026-105631: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, WorkspaceFileAssetEndpoint.get and WorkspaceAssetDownlo |
| 🟠 high | CVE-2026-105633: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, the V2 issue-attachment PATCH endpoint accepts issue_id |
| 🟠 high | CVE-2026-105635: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, ProjectJoinEndpoint at GET /api/workspaces/{slug}/proje |
| 🟠 high | CVE-2026-45524: In isSystem of WifiPermissionsUtil.java, there is a possible sandbox escape due to a mi… | — | In isSystem of WifiPermissionsUtil.java, there is a possible sandbox escape due to a missing permission check. This coul |
| 🟠 high | CVE-2026-97303: Missing Authorization vulnerability in Apps Mav Scratch & Win – Giveaways and Contests … | — | Missing Authorization vulnerability in Apps Mav Scratch & Win – Giveaways and Contests scratch-win-giveaways-for-website |
| 🟠 high | CVE-2026-105741: Langflow is a tool for building and deploying AI-powered agents and workflows. | — | Langflow is a tool for building and deploying AI-powered agents and workflows. From 1.5.0 until 1.10.3, an IP spoofing v |
| 🟠 high | CVE-2026-77226: Camunda 7.24.0 before 7.24.15 contains an incorrect authorization vulnerability in the … | — | Camunda 7.24.0 before 7.24.15 contains an incorrect authorization vulnerability in the Admin web application's first-run |
| 🟠 high | CVE-2026-105761: Dify is an open-source LLM app development platform. | — | Dify is an open-source LLM app development platform. Prior to 1.16.0, the PUT /console/api/apps/&lt;app_id&gt;/server en |
| 🟠 high | CVE-2026-91107: openSIS Classic 9.3 - Insecure Direct Object Reference (IDOR) | — | [cvefeed.io] openSIS Classic 9.3 - Insecure Direct Object Reference (IDOR) |
| 🟠 high | CVE-2026-79797: Improper Access Control in HPE Networking ClearPass Android Client Application | — | [cvefeed.io] Improper Access Control in HPE Networking ClearPass Android Client Application |
| 🟠 high | CVE-2026-79796: Authentication Bypass Vulnerabilities in ClearPass Policy Manager | `T1078` | [cvefeed.io] Authentication Bypass Vulnerabilities in ClearPass Policy Manager |
| 🟠 high | CVE-2026-76752: Authentication Bypass Vulnerabilities in HPE Networking ClearPass Policy Manager Allow … | `T1078` | [cvefeed.io] Authentication Bypass Vulnerabilities in HPE Networking ClearPass Policy Manager Allow Unauthorized Adminis |
| 🟠 high | CVE-2026-106314: Google Google Chrome | — | [dbu.gs] Incorrect Authorization (fix available) |
| 🟠 high | CVE-2026-106387: Google Google Chrome | — | [dbu.gs] Missing Authorization (fix available) |
| 🟠 high | CVE-2026-106194: Google Google Chrome | — | [dbu.gs] Missing Authorization (fix available) |
| 🟠 high | CVE-2026-106309: Google Google Chrome | — | [dbu.gs] Incorrect Authorization (fix available) |
| 🟠 high | CVE-2026-106191: Google Google Chrome | — | [dbu.gs] Missing Authorization (fix available) |
| 🟠 high | CVE-2026-76268: Missing Authentication for Critical Function in the Patroni REST API in Splunk Enterprise | `T1078` | [cvefeed.io] Missing Authentication for Critical Function in the Patroni REST API in Splunk Enterprise |
| 🟠 high | CVE-2026-76498: Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Im… | — | [cvefeed.io] Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Improper Access Contro |
| 🟠 high | CVE-2026-108695: MultiVendorX WordPress plugin through 5.0.19 contains an incorrect authorization vulner… | — | MultiVendorX WordPress plugin through 5.0.19 contains an incorrect authorization vulnerability that allows vendor accoun |
| 🟠 high | CVE-2026-108708: Wukong_HRM through commit 186115e contains a missing authorization vulnerability becaus… | — | Wukong_HRM through commit 186115e contains a missing authorization vulnerability because EmployeeAspect assigns every ca |
| 🟠 high | CVE-2026-108522: A vulnerability was found in Studio-Saelix Sencho up to 0.94.1. | — | A vulnerability was found in Studio-Saelix Sencho up to 0.94.1. This affects an unknown part of the file /api/auth/login |
| 🟠 high | CVE-2026-106029: The WeddingCity Lite  WordPress plugin through 1.0.4 does not perform any authorisation… | — | The WeddingCity Lite  WordPress plugin through 1.0.4 does not perform any authorisation or validity checks before deleti |
| 🟠 high | CVE-2026-88827: The Disable Users WordPress plugin through 1.0.5 does not enforce its account-disabling… | — | The Disable Users WordPress plugin through 1.0.5 does not enforce its account-disabling control on all authentication pa |
| | _+13 more…_ | | |

## Privilege Escalation (10)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-85118: The AI Content Generator Marketing WordPress plugin through 1.0.0 does not enforce a no… | — | The AI Content Generator Marketing WordPress plugin through 1.0.0 does not enforce a nonce or capability check on some o |
| 🟠 high | CVE-2026-77805: In Progress® Telerik® Fiddler® Classic for Windows, versions prior to v6.0.20262.10021,… | `T1068` | In Progress® Telerik® Fiddler® Classic for Windows, versions prior to v6.0.20262.10021, the integrity check applied to t |
| 🟠 high | CVE-2026-105634: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.3.0, the ProjectMemberViewSet.partial_update method allows a |
| 🟠 high | CVE-2026-58841: In multiple functions of VirtualAudioControllerTest.java, there is a possible permissio… | — | In multiple functions of VirtualAudioControllerTest.java, there is a possible permission bypass due to a logic error in  |
| 🟠 high | CVE-2026-105773: Canimaan Software ClamXAV versions 3.3 - 3.11 contains a local privilege escalation vul… | `T1190`, `T1068` | Canimaan Software ClamXAV versions 3.3 - 3.11 contains a local privilege escalation vulnerability in the Privileged Help |
| 🟠 high | CVE-2026-76748: Authenticated Privilege Escalation Vulnerability in the API of AOS-S | `T1068` | [cvefeed.io] Authenticated Privilege Escalation Vulnerability in the API of AOS-S |
| 🟠 high | CVE-2026-103694: The Mobile builder WordPress plugin through 1.4.2 does not properly restrict which user… | — | The Mobile builder WordPress plugin through 1.4.2 does not properly restrict which user meta keys a logged-in user can u |
| 🟠 high | CVE-2026-104680: The Envira Gallery  WordPress plugin before 1.16.2 does not verify that a user holds th… | — | The Envira Gallery  WordPress plugin before 1.16.2 does not verify that a user holds the capability WordPress reserves f |
| 🟠 high | CVE-2026-85126: The Crowdfundly WordPress plugin through 2.2.2 does not have capability checks on some … | — | The Crowdfundly WordPress plugin through 2.2.2 does not have capability checks on some of its AJAX actions, allowing use |
| 🟠 high | CVE-2026-108740: GoatCounter through 2.7.0 contains a mass assignment privilege escalation vulnerability… | `T1068` | GoatCounter through 2.7.0 contains a mass assignment privilege escalation vulnerability in the userPrefSave handler that |

## SQL & NoSQL Injection (45)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-88395: GouGuOA v6.0.5 and before is vulnerable to SQL Injection in /home/message/rubbish via t… | `T1190` | GouGuOA v6.0.5 and before is vulnerable to SQL Injection in /home/message/rubbish via the keywords parameter. |
| 🔴 critical | CVE-2026-103352: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WP BASE WP BASE Bo |
| 🟠 high | CVE-2026-105169: A security flaw has been discovered in kishor-23 food-waste-management-system 411989e3e… | `T1190` | A security flaw has been discovered in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03d7d93/b |
| 🟠 high | CVE-2026-105172: A vulnerability was detected in itsourcecode Online Admission System 1.0. | `T1190` | A vulnerability was detected in itsourcecode Online Admission System 1.0. Affected by this issue is some unknown functio |
| 🟠 high | CVE-2026-105175: A vulnerability was found in SourceCodester Drug Recommendation System 1.0. | `T1190` | A vulnerability was found in SourceCodester Drug Recommendation System 1.0. This issue affects some unknown processing o |
| 🟠 high | CVE-2026-105182: A security flaw has been discovered in SourceCodester Online Reviewer Management System… | `T1190` | A security flaw has been discovered in SourceCodester Online Reviewer Management System 1.0. Impacted is an unknown func |
| 🟠 high | CVE-2026-105183: A weakness has been identified in itsourcecode Online Admission System 1.0. | `T1190` | A weakness has been identified in itsourcecode Online Admission System 1.0. The affected element is an unknown function  |
| 🟠 high | CVE-2026-105184: A security vulnerability has been detected in itsourcecode Online Admission System 1.0. | `T1190` | A security vulnerability has been detected in itsourcecode Online Admission System 1.0. The impacted element is an unkno |
| 🟠 high | CVE-2026-105185: A vulnerability was detected in itsourcecode Online Admission System 1.0. | `T1190` | A vulnerability was detected in itsourcecode Online Admission System 1.0. This affects an unknown function of the file / |
| 🟠 high | CVE-2026-105229: A weakness has been identified in kishor-23 food-waste-management-system 411989e3ecb828… | `T1190` | A weakness has been identified in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03d7d93/b3a70b |
| 🟠 high | CVE-2026-105230: A security vulnerability has been detected in kishor-23 food-waste-management-system 41… | `T1190` | A security vulnerability has been detected in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03 |
| 🟠 high | CVE-2026-105231: A vulnerability was detected in kishor-23 food-waste-management-system 411989e3ecb82895… | `T1190` | A vulnerability was detected in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03d7d93/b3a70b2c |
| 🟠 high | CVE-2026-105232: A flaw has been found in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7… | `T1190` | A flaw has been found in kishor-23 food-waste-management-system 411989e3ecb82895e53dca7865f72145f03d7d93/b3a70b2c492dc99 |
| 🟠 high | CVE-2026-105246: A vulnerability was found in SourceCodester Online Reviewer Management System 1.0. | `T1190` | A vulnerability was found in SourceCodester Online Reviewer Management System 1.0. Impacted is an unknown function of th |
| 🟠 high | CVE-2026-105247: A vulnerability was determined in SourceCodester Online Reviewer Management System 1.0. | `T1190` | A vulnerability was determined in SourceCodester Online Reviewer Management System 1.0. The affected element is an unkno |
| 🟠 high | CVE-2026-104389: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Sirv Sirv sirv all |
| 🟠 high | CVE-2026-104408: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Groundhogg Groundh |
| 🟠 high | CVE-2026-105253: A vulnerability was determined in itsourcecode Online Admission System Project 1.0. | `T1190` | A vulnerability was determined in itsourcecode Online Admission System Project 1.0. This issue affects some unknown proc |
| 🟠 high | CVE-2026-105383: A vulnerability has been found in onetwothreeneth HospitalManagementSystem up to 9ef91e… | `T1190` | A vulnerability has been found in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61 |
| 🟠 high | CVE-2026-105384: A vulnerability was found in UNION HospitalManagementSystem up to 9ef91ed6007314b647311… | `T1190` | A vulnerability was found in UNION HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61d. Affected is  |
| 🟠 high | CVE-2026-105385: A vulnerability was determined in onetwothreeneth HospitalManagementSystem up to 9ef91e… | `T1190` | A vulnerability was determined in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61 |
| 🟠 high | CVE-2026-105386: A vulnerability was identified in onetwothreeneth HospitalManagementSystem up to 9ef91e… | `T1190` | A vulnerability was identified in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61 |
| 🟠 high | CVE-2026-105387: A security flaw has been discovered in girishsaraf Online-Appointment-Booking-System up… | `T1190` | A security flaw has been discovered in girishsaraf Online-Appointment-Booking-System up to f427b4757128ca253d33d0cc4e87b |
| 🟠 high | CVE-2026-103066: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WP BASE WP BASE Bo |
| 🟠 high | CVE-2026-105675: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 4.39.0 until 6.64.0, staff users with permission to view staff invite |
| 🟠 high | CVE-2026-105468: A vulnerability was found in girishsaraf Online-Appointment-Booking-System up to f427b4… | `T1190` | A vulnerability was found in girishsaraf Online-Appointment-Booking-System up to f427b4757128ca253d33d0cc4e87bbb9c999a4d |
| 🟠 high | CVE-2026-105469: A vulnerability was determined in girishsaraf Online-Appointment-Booking-System up to f… | `T1190` | A vulnerability was determined in girishsaraf Online-Appointment-Booking-System up to f427b4757128ca253d33d0cc4e87bbb9c9 |
| 🟠 high | CVE-2026-105470: A vulnerability was identified in girishsaraf Online-Appointment-Booking-System up to f… | `T1190` | A vulnerability was identified in girishsaraf Online-Appointment-Booking-System up to f427b4757128ca253d33d0cc4e87bbb9c9 |
| 🟠 high | CVE-2026-79798: Authenticated SQL Injection Vulnerabilities in ClearPass Policy Manager Web-Based Manag… | `T1190` | [cvefeed.io] Authenticated SQL Injection Vulnerabilities in ClearPass Policy Manager Web-Based Management Interface |
| 🟠 high | CVE-2026-79794: Authenticated SQL Injection Vulnerability in ClearPass Policy Manager Web-based Managem… | `T1190` | [cvefeed.io] Authenticated SQL Injection Vulnerability in ClearPass Policy Manager Web-based Management Interface |
| 🟠 high | CVE-2026-95605: WordPress WP Data Access plugin &lt;= 5.5.82 - SQL Injection vulnerability | `T1190` | [cvefeed.io] WordPress WP Data Access plugin &lt;= 5.5.82 - SQL Injection vulnerability |
| 🟠 high | CVE-2026-103695: The Mobile builder WordPress plugin through 1.4.2 does not sanitise and escape a parame… | `T1190` | The Mobile builder WordPress plugin through 1.4.2 does not sanitise and escape a parameter before using it in a SQL stat |
| 🟠 high | CVE-2026-81420: The Tcard WP WordPress plugin through 1.8.0 does not sanitise and escape a parameter be… | `T1190` | The Tcard WP WordPress plugin through 1.8.0 does not sanitise and escape a parameter before using it in a SQL statement  |
| 🟠 high | CVE-2026-88930: The Social Web Suite  WordPress plugin through 4.1.12 does not require its shared secre… | `T1190` | The Social Web Suite  WordPress plugin through 4.1.12 does not require its shared secret to be set before accepting requ |
| 🟠 high | CVE-2026-89195: The Site Setup Wizard WordPress plugin through 1.5.8 does not properly sanitise and esc… | `T1190` | The Site Setup Wizard WordPress plugin through 1.5.8 does not properly sanitise and escape a parameter before using it i |
| 🟠 high | CVE-2026-89213: The Llavero.io WordPress plugin through 0.1.4 does not properly sanitise and escape a p… | `T1190` | The Llavero.io WordPress plugin through 0.1.4 does not properly sanitise and escape a parameter before using it in a SQL |
| 🟠 high | CVE-2026-89214: The WpCues Basic Quiz WordPress plugin through 1.6.5 does not properly sanitise and esc… | `T1190` | The WpCues Basic Quiz WordPress plugin through 1.6.5 does not properly sanitise and escape values before using them in a |
| 🟠 high | CVE-2026-89232: The Recordbrowser WordPress plugin through 1.1.7 does not sanitise and escape a paramet… | — | The Recordbrowser WordPress plugin through 1.1.7 does not sanitise and escape a parameter before using it in a SQL query |
| 🟠 high | CVE-2026-89234: The WP-Partner WordPress plugin through 1.2.1 does not sanitise and escape a parameter … | — | The WP-Partner WordPress plugin through 1.2.1 does not sanitise and escape a parameter before using it in a SQL query, a |
| 🟠 high | CVE-2026-89285: The Datalist it WordPress plugin through 0.0.3 does not sanitize and escape several req… | `T1190` | The Datalist it WordPress plugin through 0.0.3 does not sanitize and escape several request parameters before using them |
| 🟠 high | CVE-2026-89287: The ASPL Product Quotation WordPress plugin through 1.1.0 does not sanitize and escape … | `T1190` | The ASPL Product Quotation WordPress plugin through 1.1.0 does not sanitize and escape a parameter before using it in SQ |
| 🟠 high | CVE-2026-89297: The Loja Automática WordPress plugin through 1.0.0 does not properly sanitize and escap… | `T1190` | The Loja Automática WordPress plugin through 1.0.0 does not properly sanitize and escape a parameter before using it in  |
| 🟠 high | CVE-2026-89299: The WP Verify API WordPress plugin through 1.0.0 does not properly sanitize and escape … | `T1190` | The WP Verify API WordPress plugin through 1.0.0 does not properly sanitize and escape a parameter before using it in a  |
| 🟠 high | CVE-2026-89302: The Post Voting System WordPress plugin through 1.0 does not properly sanitize and esca… | `T1190` | The Post Voting System WordPress plugin through 1.0 does not properly sanitize and escape a parameter before using it in |
| 🟠 high | CVE-2026-108571: A weakness has been identified in Xinhu Rainrock RockOA up to 2.7.6. | `T1190` | A weakness has been identified in Xinhu Rainrock RockOA up to 2.7.6. This impacts the function kqjcmdModel::returnchuli  |

## Cross-Site Scripting (27)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-106102: Quasar Framework: Stored/Reflected XSS via unescaped SSR meta tag rendering in getHead() | `T1059.007` | [VulnTracker digest] quasarframework quasar — Quasar Framework: Stored/Reflected XSS via unescaped SSR meta tag renderin |
| 🟠 high | CVE-2026-105294: Legcord 1.1.0 through 1.3.0 contains a configuration injection vulnerability that allow… | `T1059.007` | Legcord 1.1.0 through 1.3.0 contains a configuration injection vulnerability that allows script in the Discord page to w |
| 🟠 high | CVE-2025-15643: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Jose Fernandez Ads |
| 🟠 high | CVE-2026-105630: Plane is an open-source project management tool. | `T1059.007` | Plane is an open-source project management tool. Prior to 1.4.0, an authenticated low-privilege workspace member, includ |
| 🟠 high | CVE-2026-100515: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in VillaTheme Photo R |
| 🟠 high | CVE-2026-105643: Ghost is a Node.js content management system. | `T1059.007` | Ghost is a Node.js content management system. From version 6.34.0 until 6.67.0, embed cards in the Ghost editor could by |
| 🟠 high | CVE-2026-105649: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 4.22.0 until 6.65.0, SVG media thumbnails and SVG images uploaded wit |
| 🟠 high | CVE-2026-105650: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 2.1.0 until 6.64.0, embedding a URL from an attacker-controlled websi |
| 🟠 high | CVE-2026-105651: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 5.94.0 until 6.64.0, when creating a bookmark card, Ghost could store |
| 🟠 high | CVE-2026-105679: Ghost is a Node.js content management system. | — | Ghost is a Node.js content management system. From 6.22.1 until 6.64.0, Ghost restricted the content type used to serve  |
| 🟠 high | CVE-2026-79799: Unauthenticated Stored Cross-Site Scripting (XSS) Vulnerability in ClearPass Policy Man… | `T1059.007` | [cvefeed.io] Unauthenticated Stored Cross-Site Scripting (XSS) Vulnerability in ClearPass Policy Manager Web-Based Manag |
| 🟠 high | CVE-2026-103305: The Prenotazioni WordPress plugin through 1.7.5 does not have authorisation and CSRF ch… | `T1059.007` | The Prenotazioni WordPress plugin through 1.7.5 does not have authorisation and CSRF checks when saving its settings, an |
| 🟠 high | CVE-2026-84258: The click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1 does not sanitise a… | `T1059.007` | The click5 CRM add-on to Ninja Forms WordPress plugin through 1.0.1 does not sanitise and escape content submitted throu |
| 🟠 high | CVE-2026-84259: The click5 CRM add-on to WPForms WordPress plugin through 1.0.3 does not sanitise and e… | `T1059.007` | The click5 CRM add-on to WPForms WordPress plugin through 1.0.3 does not sanitise and escape content submitted through a |
| 🟠 high | CVE-2026-84260: The click5 CRM add-on to Gravity Forms WordPress plugin through 1.0.3 does not sanitise… | `T1059.007` | The click5 CRM add-on to Gravity Forms WordPress plugin through 1.0.3 does not sanitise and escape content submitted thr |
| 🟠 high | CVE-2026-84261: The click5 CRM add-on to Contact Form 7 WordPress plugin through 1.0.4 does not sanitis… | `T1059.007` | The click5 CRM add-on to Contact Form 7 WordPress plugin through 1.0.4 does not sanitise and escape content submitted th |
| 🟠 high | CVE-2026-86798: The HootBoard  WordPress plugin through 3.1.4 does not perform any authorisation check … | — | The HootBoard  WordPress plugin through 3.1.4 does not perform any authorisation check on some of its REST endpoints, an |
| 🟠 high | CVE-2026-87760: The Web Vitals Tracking WordPress plugin through 5.4.2 does not validate or escape perf… | `T1059.007` | The Web Vitals Tracking WordPress plugin through 5.4.2 does not validate or escape performance measurements submitted by |
| 🟠 high | CVE-2026-87761: The Adwised Web Push Notification WordPress plugin through 2.5.7 does not perform any c… | `T1059.007` | The Adwised Web Push Notification WordPress plugin through 2.5.7 does not perform any capability or nonce check before a |
| 🟠 high | CVE-2026-87762: The Adwised Web Push Notification WordPress plugin through 2.5.7 does not have authoris… | — | The Adwised Web Push Notification WordPress plugin through 2.5.7 does not have authorisation checks on several state-cha |
| 🟠 high | CVE-2026-87764: The BuddyPress Instant Chat WordPress plugin through 1.6 does not check that the sender… | — | The BuddyPress Instant Chat WordPress plugin through 1.6 does not check that the sender of a chat message belongs to the |
| 🟠 high | CVE-2026-88826: The SmugMug Embed WordPress plugin through 3.13 does not have authorisation or CSRF che… | — | The SmugMug Embed WordPress plugin through 3.13 does not have authorisation or CSRF checks on an AJAX action that stores |
| 🟠 high | CVE-2026-88903: The Topcontent WordPress plugin through 1.2.1 does not properly authorise one of its re… | — | The Topcontent WordPress plugin through 1.2.1 does not properly authorise one of its request handlers and disables HTML  |
| 🟠 high | CVE-2026-88905: The KeyWord Collector WordPress plugin through 1.4 does not have any authorisation or n… | — | The KeyWord Collector WordPress plugin through 1.4 does not have any authorisation or nonce check when saving its settin |
| 🟠 high | CVE-2026-91829: The Subscribe to Comments WordPress plugin before 2.3.3 does not properly validate a pa… | `T1059.007` | The Subscribe to Comments WordPress plugin before 2.3.3 does not properly validate a parameter before reflecting it into |
| 🟠 high | CVE-2026-96227: The Piotnet Forms WordPress plugin through 1.0.30 does not authenticate or validate a f… | `T1059.007` | The Piotnet Forms WordPress plugin through 1.0.30 does not authenticate or validate a form-submission file-upload reques |
| 🟡 medium | CVE-2026-105879: Crocoblock Jetelements | `T1059.007` | [dbu.gs] XSS (fix available) |

## Memory Corruption (33)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105285: A security vulnerability has been detected in Totolink A3002MU 1.0.0-B20230403.1455. | `T1203` | A security vulnerability has been detected in Totolink A3002MU 1.0.0-B20230403.1455. This affects an unknown function of |
| 🔴 critical | CVE-2026-105778: Tenda Ac5 | `T1203` | [dbu.gs] Stack Overflow; Buffer Overflow (public exploit available) |
| 🔴 critical | CVE-2026-106417: Google Google Chrome | — | [dbu.gs] Integer Overflow (fix available) |
| 🔴 critical | CVE-2026-55330: Google Android | — | [dbu.gs] Use After Free (fix available) |
| 🔴 critical | CVE-2026-106446: Handlebars: JavaScript Injection via AST Type Confusion in compile (Program.blockParams) | — | [VulnTracker digest] handlebars-lang handlebars.js — Handlebars: JavaScript Injection via AST Type Confusion in compile  |
| 🟠 high | CVE-2026-20519: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20520: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20521: In Video HAL, there is a possible escalation of privilege due to a missing bounds check. | — | In Video HAL, there is a possible escalation of privilege due to a missing bounds check. This could lead to local escala |
| 🟠 high | CVE-2026-20522: In neuropilot, there is a possible out of bounds write due to a missing bounds check. | — | In neuropilot, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalatio |
| 🟠 high | CVE-2026-20523: In neuropilot, there is a possible out of bounds write due to a missing bounds check. | — | In neuropilot, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalatio |
| 🟠 high | CVE-2026-20526: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20531: In apu, there is a possible memory corruption due to use after free. | `T1203` | In apu, there is a possible memory corruption due to use after free. This could lead to local escalation of privilege wi |
| 🟠 high | CVE-2026-20586: In vdec, there is a possible out of bounds write due to a missing bounds check. | — | In vdec, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of  |
| 🟠 high | CVE-2026-19184: The NXP GAU ADC driver (drivers/adc/adc_mcux_gau_adc.c) validated the caller-supplied s… | `T1068`, `T1203` | The NXP GAU ADC driver (drivers/adc/adc_mcux_gau_adc.c) validated the caller-supplied sequence->buffer_size, which is ex |
| 🟠 high | CVE-2026-49878: In wpas_handle_robust_av_scs_recv_action of robust_av.c, there is a possible out-of-bou… | `T1190` | In wpas_handle_robust_av_scs_recv_action of robust_av.c, there is a possible out-of-bounds write due to a logic error in |
| 🟠 high | CVE-2026-49885: In rw_t4t_update_file of rw_t4t.cc, there is a possible out-of-bounds write due to an i… | — | In rw_t4t_update_file of rw_t4t.cc, there is a possible out-of-bounds write due to an integer overflow. This could lead  |
| 🟠 high | CVE-2026-49937: In multiple functions of MessageQueueBase.h, there is a possible out of bounds read due… | — | In multiple functions of MessageQueueBase.h, there is a possible out of bounds read due to an incorrect bounds check. Th |
| 🟠 high | CVE-2026-55280: In multiple locations, there is a possible out-of-bounds write due to uninitialized data. | — | In multiple locations, there is a possible out-of-bounds write due to uninitialized data. This could lead to remote esca |
| 🟠 high | CVE-2026-55286: In stpropnci_process of stpropnci.cc, there is a possible out of bounds write due to an… | — | In stpropnci_process of stpropnci.cc, there is a possible out of bounds write due to an incorrect bounds check. This cou |
| 🟠 high | CVE-2026-58815: In multiple locations, there is a possible out of bounds write due to an incorrect boun… | — | In multiple locations, there is a possible out of bounds write due to an incorrect bounds check. This could lead to loca |
| 🟠 high | CVE-2026-58835: In cfg2prop of btif_storage.cc, there is a possible out-of-bounds write due to a heap b… | `T1190`, `T1203` | In cfg2prop of btif_storage.cc, there is a possible out-of-bounds write due to a heap buffer overflow. This could lead t |
| 🟠 high | CVE-2026-58854: In multiple locations, there is a possible memory corruption due to type confusion. | `T1203` | In multiple locations, there is a possible memory corruption due to type confusion. This could lead to local escalation  |
| 🟠 high | CVE-2026-58865: In multiple functions of PduParser.java, there is a possible persistent denial of servi… | — | In multiple functions of PduParser.java, there is a possible persistent denial of service due to a missing bounds check. |
| 🟠 high | CVE-2026-106547: HDF5 heap buffer overflow in H5VM_array_fill via crafted fill-value metadata | `T1203` | [cvefeed.io] HDF5 heap buffer overflow in H5VM_array_fill via crafted fill-value metadata |
| 🟠 high | CVE-2026-106062: Red Hat Red Hat Enterprise Linux 10 | `T1203` | [dbu.gs] Buffer Overflow (fix available) |
| 🟠 high | CVE-2026-106269: Google Google Chrome | — | [dbu.gs] Use After Free (fix available) |
| 🟠 high | CVE-2026-106256: Google Google Chrome | — | [dbu.gs] Information Disclosure (fix available) |
| 🟠 high | CVE-2026-19577: net_route_ipv6_packet() in subsys/net/ip/route_ipv6.c resolved the nexthop's link-layer… | — | net_route_ipv6_packet() in subsys/net/ip/route_ipv6.c resolved the nexthop's link-layer address with net_nbr_get_lladdr( |
| 🟠 high | CVE-2026-19669: The user-mode syscall verifiers z_vrfy_fuel_gauge_get_props() and z_vrfy_fuel_gauge_set… | — | The user-mode syscall verifiers z_vrfy_fuel_gauge_get_props() and z_vrfy_fuel_gauge_set_props() in drivers/fuel_gauge/fu |
| 🟠 high | CVE-2026-19736: The NXP MCUX TRNG entropy driver in drivers/entropy/entropy_mcux_trng.c passed the call… | `T1203` | The NXP MCUX TRNG entropy driver in drivers/entropy/entropy_mcux_trng.c passed the caller's byte count straight to the v |
| 🟠 high | CVE-2026-19935: The Bluetooth LE host queues received L2CAP connection-oriented channel (CoC) data for … | — | The Bluetooth LE host queues received L2CAP connection-oriented channel (CoC) data for deferred processing through a str |
| 🟡 medium | CVE-2026-105707: Uptrace Uptrace | — | [dbu.gs] Information Disclosure; Generation of Error Message Containing Sensitive Information (public exploit available) |
| 🟡 medium | CVE-2026-25269: Qualcomm Snapdragon | `T1203` | [dbu.gs] Memory Corruption |

## Insecure Deserialization (8)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-97283: Deserialization of Untrusted Data vulnerability in Liquid Web / StellarWP Advanced Post… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Liquid Web / StellarWP Advanced Post Manager advanced-post-manager al |
| 🟠 high | CVE-2026-104905: FacturaScripts before version 2026.7 contains a PHP object injection vulnerability in W… | — | FacturaScripts before version 2026.7 contains a PHP object injection vulnerability in WidgetSelect::processFormData() th |
| 🟠 high | CVE-2026-103349: Deserialization of Untrusted Data vulnerability in Rymera Web Co Product Feed PRO for W… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Rymera Web Co Product Feed PRO for WooCommerce woo-product-feed-pro a |
| 🟠 high | CVE-2026-100506: Deserialization of Untrusted Data vulnerability in WP Spell Check WP Spell Check wp-spe… | `T1059.007` | Deserialization of Untrusted Data vulnerability in WP Spell Check WP Spell Check wp-spell-check allows Object Injection. |
| 🟠 high | CVE-2026-100511: Deserialization of Untrusted Data vulnerability in Vektor Inc. | `T1059.007` | Deserialization of Untrusted Data vulnerability in Vektor Inc. VK Google Job Posting Manager vk-google-job-posting-manag |
| 🟠 high | CVE-2026-103348: Deserialization of Untrusted Data vulnerability in Smackcoders Inc. | `T1059.007` | Deserialization of Untrusted Data vulnerability in Smackcoders Inc. WP Ultimate Exporter wp-ultimate-exporter allows Obj |
| 🟠 high | CVE-2026-93617: Deserialization of Untrusted Data vulnerability in WP Sunshine Sunshine Photo Cart suns… | `T1059.007` | Deserialization of Untrusted Data vulnerability in WP Sunshine Sunshine Photo Cart sunshine-photo-cart allows Object Inj |
| 🟠 high | CVE-2026-97257: Deserialization of Untrusted Data vulnerability in PressTigers Simple Event Planner sim… | `T1059.007` | Deserialization of Untrusted Data vulnerability in PressTigers Simple Event Planner simple-event-planner allows Object I |

## Path Traversal & File Disclosure (8)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-105293: Legcord 1.1.0 through 1.3.0 contains a path traversal vulnerability in theme IPC handle… | `T1059.007` | Legcord 1.1.0 through 1.3.0 contains a path traversal vulnerability in theme IPC handlers that allows script in the Disc |
| 🟠 high | CVE-2026-105314: Papermerge 3.5.3 allows remote code execution by a standard user via directory traversa… | `T1190` | Papermerge 3.5.3 allows remote code execution by a standard user via directory traversal in a /api/documents/upload call |
| 🟠 high | CVE-2026-102262: Newell Brands DYMO ID 1.5.1.71 resolves its plugin Modules directory relative to the pr… | — | Newell Brands DYMO ID 1.5.1.71 resolves its plugin Modules directory relative to the process working directory. An attac |
| 🟠 high | CVE-2026-105744: Docling simplifies document processing by parsing diverse formats and providing integra… | — | Docling simplifies document processing by parsing diverse formats and providing integrations with the generative AI ecos |
| 🟠 high | CVE-2026-79805: Authenticated Path Traversal Vulnerability Leads to Unauthorized File Access and Modifi… | — | [cvefeed.io] Authenticated Path Traversal Vulnerability Leads to Unauthorized File Access and Modification in ClearPass  |
| 🟠 high | CVE-2026-108902: pH7Builder (pH7 Social Dating CMS) before 18.5.0 contains a path traversal vulnerabilit… | — | pH7Builder (pH7 Social Dating CMS) before 18.5.0 contains a path traversal vulnerability in the picture module deletePho |
| 🟡 medium | CVE-2026-106552: Openbsd Openssh | — | [dbu.gs] Relative Path Traversal (fix available) |
| 🟡 medium | CVE-2026-106494: Backstage Backend-Defaults | — | [dbu.gs] Path traversal (fix available) |

## SSRF, CSRF & Open Redirect (10)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105636: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, the webhook delivery task in apps/api/plane/bgtasks/web |
| 🟠 high | CVE-2026-105238: A flaw has been found in ChatGPTNextWeb NextChat up to 2.16.1. | — | A flaw has been found in ChatGPTNextWeb NextChat up to 2.16.1. This vulnerability affects the function proxyHandler of t |
| 🟠 high | CVE-2026-104407: Cross-Site Request Forgery (CSRF) vulnerability in Blubrry Podcasting PowerPress Podcas… | — | Cross-Site Request Forgery (CSRF) vulnerability in Blubrry Podcasting PowerPress Podcasting powerpress allows Cross Site |
| 🟠 high | CVE-2026-105290: A vulnerability was determined in feelec-yishu feelcrm-os 1.0.0. | — | A vulnerability was determined in feelec-yishu feelcrm-os 1.0.0. This affects an unknown part of the file App/Feelcrm/In |
| 🟠 high | CVE-2026-92931: CWE-918: Server-Side Request Forgery in the Progress @progress/sitefinity-nextjs-sdk np… | — | CWE-918: Server-Side Request Forgery in the Progress @progress/sitefinity-nextjs-sdk npm package versions 15.1.8326 thro |
| 🟠 high | CVE-2026-104973: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, the fix for CVE-2026-30242 validates webhook IP address |
| 🟠 high | CVE-2026-104977: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, the fix for CVE-2026-27706 and GHSA-jcc6-f9v6-f7jw, an  |
| 🟠 high | CVE-2026-105628: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane's OAuth avatar synchronization flow fetches avata |
| 🟠 high | CVE-2026-105762: Dify: Unauthenticated Server-Side Request Forgery in /console/api/remote-files/upload e… | — | [cvefeed.io] Dify: Unauthenticated Server-Side Request Forgery in /console/api/remote-files/upload endpoint |
| 🟡 medium | CVE-2026-106032: Aws Bedrock Agentcore Starter Toolkit | — | [dbu.gs] SSRF (fix available) |

## Cryptographic Weaknesses (2)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-108860: BotSharp through 5.2.0 contains an authentication bypass vulnerability that allows unau… | `T1078` | BotSharp through 5.2.0 contains an authentication bypass vulnerability that allows unauthenticated remote attackers to f |
| 🟠 high | CVE-2026-105392: A vulnerability has been found in Lybbn Django-Vue-Lyadmin up to 3.2.12. | — | A vulnerability has been found in Lybbn Django-Vue-Lyadmin up to 3.2.12. The impacted element is an unknown function of  |

## Information Disclosure (2)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-103334: Insertion of Sensitive Information Into Sent Data vulnerability in Etoile Web Design In… | — | Insertion of Sensitive Information Into Sent Data vulnerability in Etoile Web Design Incorporated Five Star Restaurant R |
| 🟠 high | CVE-2026-106501: Backstage: Sensitive information exposure in Scaffolder | — | [cvefeed.io] Backstage: Sensitive information exposure in Scaffolder |

## Denial of Service (9)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-55266: In qsort of libufdt_sysdeps_vendor.c, there is a possible out-of-bounds write due to re… | — | In qsort of libufdt_sysdeps_vendor.c, there is a possible out-of-bounds write due to resource exhaustion. This could lea |
| 🟠 high | CVE-2026-58859: In multiple places, there is a possible  denial of service due to an uncaught exception. | — | In multiple places, there is a possible  denial of service due to an uncaught exception. This could lead to local escala |
| 🟠 high | CVE-2026-57546: Qualcomm Snapdragon | — | [dbu.gs] DoS; Buffer Over-read |
| 🟠 high | CVE-2026-97716: Denial of Service in Absolute Secure Access | — | [cvefeed.io] Denial of Service in Absolute Secure Access |
| 🟠 high | CVE-2026-97714: Denial of service vulnerability in Secure Access | — | [cvefeed.io] Denial of service vulnerability in Secure Access |
| 🟠 high | CVE-2026-14854: The WooCommerce Bookings WordPress plugin before 3.11.0 does not limit a user-supplied … | — | The WooCommerce Bookings WordPress plugin before 3.11.0 does not limit a user-supplied value before using it to allocate |
| 🟠 high | CVE-2026-108714: MCP Kotlin SDK through 0.15.0 contains an uncontrolled memory allocation vulnerability … | — | MCP Kotlin SDK through 0.15.0 contains an uncontrolled memory allocation vulnerability that allows remote clients to exh |
| 🟠 high | CVE-2026-108859: mcp-go through 1.2.1 contains a denial of service vulnerability in StreamableHTTPServer… | — | mcp-go through 1.2.1 contains a denial of service vulnerability in StreamableHTTPServer.ServeHTTP that allows remote una |
| 🟡 medium | CVE-2026-104046: Red Hat Red Hat Enterprise Linux 10 | — | [dbu.gs] Allocation of Resources Without Limits (fix available) |

## Network Infrastructure & IoT Device Vulnerabilities (7)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-76500: Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Im… | — | [cvefeed.io] Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Improper Control of a  |
| 🟠 high | CVE-2026-76499: Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Im… | — | [cvefeed.io] Cisco Application Policy Infrastructure Controller Hardening Release: October 2026 - Improper Neutralizatio |
| 🟠 high | CVE-2026-76484: Cisco License On-Prem Security Hardening Release | — | [cvefeed.io] Cisco License On-Prem Security Hardening Release |
| 🟠 high | CVE-2026-76483: Cisco License On-Prem Security Hardening Release | — | [cvefeed.io] Cisco License On-Prem Security Hardening Release |
| 🟠 high | CVE-2026-76482: Cisco License On-Prem Security Hardening Release | — | [cvefeed.io] Cisco License On-Prem Security Hardening Release |
| 🟠 high | CVE-2026-76480: Cisco License On-Prem Security Hardening Release | — | [cvefeed.io] Cisco License On-Prem Security Hardening Release |
| 🟠 high | CVE-2026-76472: Cisco Meraki Security Hardening Release October 2026 - Improper Neutralization of Speci… | — | [cvefeed.io] Cisco Meraki Security Hardening Release October 2026 - Improper Neutralization of Special Elements Vulnerab |

## Critical-Severity Vulnerabilities (7)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-105284: A weakness has been identified in Totolink A3002MU 1.0.0-B20230403.1455. | — | A weakness has been identified in Totolink A3002MU 1.0.0-B20230403.1455. The impacted element is the function sub_40FCFC |
| 🔴 critical | CVE-2026-105638: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, Plane's magic-code email login uses a six-digit numeric |
| 🔴 critical | CVE-2026-105641: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, the deployments/aio/community/ and deployments/cli/comm |
| 🔴 critical | CVE-2026-63692: CVE-2026-63692 | — | [VulnTracker digest] Dell Container Storage Modules — CVE-2026-63692 |
| 🔴 critical | CVE-2026-63688: CVE-2026-63688 | — | [VulnTracker digest] Dell Dell Container Storage Modules (CSM) — CVE-2026-63688 |
| 🔴 critical | CVE-2026-67269: CVE-2026-67269 | — | [VulnTracker digest] Dell Container Storage Modules (CSM) — CVE-2026-67269 |
| 🔴 critical | CVE-2026-108753: Agnaistic agnai through 1.0.555 contains a hard-coded credentials vulnerability in self… | — | Agnaistic agnai through 1.0.555 contains a hard-coded credentials vulnerability in self-host.docker-compose.yml, which s |

## High-Severity Vulnerabilities (103)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-105223: maclof kubernetes-client 0.17.0 before 0.32.0 disables TLS certificate verification in … | — | maclof kubernetes-client 0.17.0 before 0.32.0 disables TLS certificate verification in parseKubeconfig() and parseKubeco |
| 🟠 high | CVE-2026-105295: GitAhead 2.5.0 through 2.7.1 contains an insecure update mechanism that installs downlo… | — | GitAhead 2.5.0 through 2.7.1 contains an insecure update mechanism that installs downloaded updates without integrity or |
| 🟠 high | CVE-2026-20524: In apu, there is a possible memory corruption due to improper input validation. | `T1203` | In apu, there is a possible memory corruption due to improper input validation. This could lead to local escalation of p |
| 🟠 high | CVE-2026-19185: The system-call verifier for i3c_do_ccc() in drivers/i3c/i3c_handlers.c validated the o… | — | The system-call verifier for i3c_do_ccc() in drivers/i3c/i3c_handlers.c validated the outer struct i3c_ccc_payload, the  |
| 🟠 high | CVE-2026-104890: Kunstmaan CMS is an open source content management system based on the Symfony framework. | — | Kunstmaan CMS is an open source content management system based on the Symfony framework. Prior to 7.3.2, src/Kunstmaan/ |
| 🟠 high | CVE-2026-102282: adm-zip is a JavaScript library for creating and extracting ZIP archives in Node.js. | — | adm-zip is a JavaScript library for creating and extracting ZIP archives in Node.js. Prior to 0.6.1, adm-zip applies the |
| 🟠 high | CVE-2026-104970: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. From 0.13 until 1.4.0, InstanceAdminSignUpEndpoint in apps/api/plane/li |
| 🟠 high | CVE-2026-105382: A flaw has been found in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b… | — | A flaw has been found in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61d. This a |
| 🟠 high | CVE-2026-104974: Plane is an open-source project management tool. | — | Plane is an open-source project management tool. Prior to 1.4.0, a user whose account has been deactivated by setting is |
| 🟠 high | CVE-2026-49933: In handle_le_monitor_device_event of msft.cc, there is a possible control-flow hijack i… | — | In handle_le_monitor_device_event of msft.cc, there is a possible control-flow hijack in the privileged bluetooth proces |
| 🟠 high | CVE-2026-55269: In FilterCapturedPacket of snoop_logger.cc, there is a possible memory safety issue due… | — | In FilterCapturedPacket of snoop_logger.cc, there is a possible memory safety issue due to improper input validation. Th |
| 🟠 high | CVE-2026-55270: In dialInternal in multiple locations, there is a possible permission bypass due to a c… | — | In dialInternal in multiple locations, there is a possible permission bypass due to a confused deputy. This could lead t |
| 🟠 high | CVE-2026-58880: In handle_app_val_response of btif_rc.cc, there is a possible way to achieve code execu… | — | In handle_app_val_response of btif_rc.cc, there is a possible way to achieve code execution due to a race condition. Thi |
| 🟠 high | CVE-2026-104852: GraphQL Tools has prototype pollution in well-established utility function `mergeDeep` | — | [cvefeed.io] GraphQL Tools has prototype pollution in well-established utility function `mergeDeep` |
| 🟠 high | CVE-2026-105783: Joplin Web Clipper pairing allows cross-origin theft of a permanent API token | — | [cvefeed.io] Joplin Web Clipper pairing allows cross-origin theft of a permanent API token |
| 🟠 high | CVE-2026-105763: Twenty: Plaintext IMAP/SMTP/CalDAV password disclosure to any workspace member via /met… | — | [cvefeed.io] Twenty: Plaintext IMAP/SMTP/CalDAV password disclosure to any workspace member via /metadata GraphQL |
| 🟠 high | CVE-2026-21589: Atlassian Data Center and Server Arbitrary File Access Vulnerability | — | [cvefeed.io] Atlassian Data Center and Server Arbitrary File Access Vulnerability |
| 🟠 high | CVE-2026-94201: Filtering an :atom attribute with unsafe_to_atom? can exhaust the BEAM atom table in Ash | — | [cvefeed.io] Filtering an :atom attribute with unsafe_to_atom? can exhaust the BEAM atom table in Ash |
| 🟠 high | base58-check-helper (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bip39-wordlist-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitciin (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitcion-ruby (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitcion (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitcoij-ruby (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitcoin-address-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | bitcoin-rpc-lite (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | blockchain-sync-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | btc-wallet-tools (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | coinmarket-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | crylto-toolbox (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | cryoto-toolbox (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | crypti-toolbox (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | crypto-key-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | crypto-mnemonic-tools (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | electrum-protocol-lite (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | eth-address-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | eth-keystore-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | etherdum.rb (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | etheremu.rb (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | ethereum-tx-helper (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | hdkey-derive-helper (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | kecack (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | keccka (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | ligbtning-invoice (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | lighthing-invoice (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | lightinng-invoice (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | lightning-invoice-utils (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | merkle-proof-lite (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | rate-limit-mini (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| 🟠 high | req-throttle-mini (rubygems) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-05. Review versio |
| | _+53 more…_ | | |

## Medium-Severity Vulnerabilities (13)

_Medium-severity issues across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟡 medium | CVE-2026-104045: Red Hat Red Hat Enterprise Linux 10 | — | [dbu.gs] Missing Release of Resource after Effective Lifetime (fix available) |
| 🟡 medium | CVE-2026-106317: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106316: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106337: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106251: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106282: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106276: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106285: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106305: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106272: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106302: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106232: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |
| 🟡 medium | CVE-2026-106229: Google Google Chrome | — | [dbu.gs] UI Misrepresentation of Critical Information (fix available) |

## Low-Severity Vulnerabilities (2)

_Low-severity issues across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟢 low | CVE-2026-106582: Openbsd Openssh | — | [dbu.gs] Tracked vulnerability (fix available) |
| 🟢 low | CVE-2026-106584: Openbsd Openssh | — | [dbu.gs] Tracked vulnerability (fix available) |

## Other Vulnerabilities (1)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-104626: Gitea Gitea | — | [dbu.gs] Tracked vulnerability |

## Ransomware activity (ransomware.live + peers) (213)

_Victim claims rolled up from the 4 daily briefings covering this window. Most active groups: thegentlemen (39), n0n (18), vypr (14)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | A...n — claimed by silentransomgroup | — | Redacted entry - full company name pending disclosure (FULL DATA TIMER active). |
| 🟠 high | Agio International — claimed by vypr (US) | — | Agio International specializes in distinctive outdoor furniture designs that merge beauty, quality, and affordability, c |
| 🟠 high | anwo.cl — claimed by safepay | — | The company was established in 1984 by Víctor Herrmann and has developed into one of the major HVAC distribution busines |
| 🟠 high | Asia Era One — claimed by qilin | — | Business Services |
| 🟠 high | Bender Tribunenbau — claimed by lamashtu | — | bender-tribuenen.de - Bender GmbH Tribunenbau is a German manufacturer of mobile and permanent grandstands, stages, podi |
| 🟠 high | bwi-bau.de — claimed by safepay | — | The organization was established in October 1964 as a subsidiary of the Construction Industry Association of North Rhine |
| 🟠 high | Cam Group LLC — claimed by doommageddon | — | upcoming \| — \| 0 files |
| 🟠 high | capitalbankhaiti.biz — claimed by lockbit5 | — | Capital Bank SA provides a comprehensive range of traditional and online banking services tailored f... |
| 🟠 high | Champaign Unit 4 School District — claimed by vypr (US) | — | Champaign Unit 4 School District is dedicated to empowering each learner to thrive in a diverse and changing world. The  |
| 🟠 high | Circulating Air — claimed by vypr (US) | — | Circulating Air, Inc. specializes in HVAC services in Los Angeles and surrounding areas, offering quality repair, instal |
| 🟠 high | Company #1 — claimed by n0n | — | technology · United States |
| 🟠 high | Company #2 — claimed by n0n | — | Financial services · Canada |
| 🟠 high | Company #3 — claimed by n0n | — | IT managed services · United States |
| 🟠 high | dd-automation.ch — claimed by safepay | — | The company was entered into the Swiss commercial register in 1997 and specializes in electrical engineering, automation |
| 🟠 high | duhaas.sk — claimed by safepay | — | The company was subsequently transformed into a limited liability company in 1992 and established as a joint-stock compa |
| 🟠 high | ENKA Schools — claimed by doommageddon | — | upcoming \| — \| 0 files |
| 🟠 high | Eteam — claimed by byod | — | Eteam was informed they had been breached, just ignored us, we are not giving any more chances, Enjoy their full BPO lis |
| 🟠 high | Fluge Audiovisuales — claimed by lamashtu | — | fluge.es - Fluge Audiovisuales is a Spanish company and market leader in AV equipment rental (sound, lighting, video, st |
| 🟠 high | Franklin Empire — claimed by byod | — | [PSA] You know we have over 700GB of Data, AWS Keys to your buckets, (which we dumped), Moonshot AI API keys, SMTP crede |
| 🟠 high | Gen3 — claimed by vypr (US) | — | Gen3 CO is a leading subcontractor specializing in the installation of various exterior wall systems, including composit |
| 🟠 high | Global Security Concepts — claimed by qilin | — | Business Services |
| 🟠 high | grundens.com — claimed by safepay | — | The company's origins can be traced to 1911, when Carl A. Grundén, the son of a fisherman from Grundsund on … |
| 🟠 high | Grupo Industrial Tauro — claimed by lamashtu | — | grupotauro.com - is a Mexican steel-products manufacturer based in Monterrey (Nuevo León): perimeter protection and mesh |
| 🟠 high | H&L Manufacturing — claimed by interlock | — | https://hlmanufacturing.com/
									H&L Manufacturing is a contract manufacturer serving various industries, including |
| 🟠 high | halservice.it — claimed by safepay | — | Established in 1990, the company initially focused on system integration and information-technology services and later e |
| 🟠 high | ikhasas.com — claimed by safepay | — | The group was incorporated as iKHASAS Sdn. Bhd. in 2008 and subsequently expanded beyond construction into property deve |
| 🟠 high | Infomedia A/S — claimed by aurora | — | Infomedia A/S — Denmark's premier media monitoring company, co-owned by the country's two largest media conglomerates (J |
| 🟠 high | JPS Health Network — claimed by vypr (US) | — | John Peter Smith Hospital, JPS Surgical Center - Arlington, a network of community-based health centers, school-based he |
| 🟠 high | M** A******* G********** O******* a** P***** S****** A********* — claimed by netrunner (US) | — | M** A******* G********** O******* a** P***** S****** A********* listed by netrunner. |
| 🟠 high | Medical Data Rx — claimed by vypr (US) | — | Technical Solutions Group, located in the heart of Mid-Michigan, is dedicated to assisting small businesses with their t |
| 🟠 high | METROCOLOR S.A. — claimed by emperador | — | A Peruvian company from the printing industry.
Commercial printing, packaging, labels, boxes, books, 
magazines, booklet |
| 🟠 high | Millensys — claimed by bavacai | — | Millensys listed by bavacai. |
| 🟠 high | Millensys — claimed by medusalocker (BR) | — | Organization with 2 emails extracted. Domain: millensys.com |
| 🟠 high | Nelson Mullins Riley & Scarborough — claimed by leakeddata | — | They offered $8.000.000 to keep the data from being published. |
| 🟠 high | Nelson Mullins Riley & Scarborough — claimed by silentransomgroup (US) | — | They offered $8.000.000 to keep the data from being published. |
| 🟠 high | O2 Dental Group — claimed by interlock | — | http://www.o2smiles.com/
									O2 Dental Group of Wilmington makes your dental care easy by providing a variety of fa |
| 🟠 high | Onsemi — claimed by qilin | — | Electronics |
| 🟠 high | PANCARIBBEAN LOGISTICS GROUP — claimed by emperador | — | Panamanian logistics company operating 
in the field of international cargo transportation.
Financial documents, persona |
| 🟠 high | part02.simplexengg.in — claimed by eclipse (IN) | — | [AI generated] N/A |
| 🟠 high | Praxis EMR — claimed by insomnia | — | Praxis EMR is a highly rated EHR for physicians and medical providers, using AI to boost efficiency and accuracy. It let |
| 🟠 high | R***e Pa****** — claimed by nightspire | — | R***e Pa****** listed by nightspire. |
| 🟠 high | Royal Selangor — claimed by byod | — | [PSA] Both, your Registered Users & Customer list have been affected. 300K Lines Total, Includes: Names, Emails, Phone N |
| 🟠 high | Rueegseggerag — claimed by bavacai | — | Rueegseggerag listed by bavacai. |
| 🟠 high | Rueegseggerag — claimed by medusalocker (CH) | — | Organization with 1 emails extracted. Domain: rueegseggerag.ch |
| 🟠 high | Saskatoon Tribal Council — claimed by thegentlemen | — | sktc.sk.ca zoominfo.com/c/saskatoon-tribal-council-inc/215335121 Saskatoon Tribal Council (STC) is a non-profit tribal c |
| 🟠 high | Sheppard, Mullin, Richter & Hampton — claimed by leakeddata | — | They offered $4.900.000 to keep the data from being published. |
| 🟠 high | Sheppard, Mullin, Richter & Hampton — claimed by silentransomgroup (US) | — | They offered $4.900.000 to keep the data from being published. |
| 🟠 high | Sims Vibration Laboratory — claimed by vypr (US) | — | At Sims Vibration Laboratory, we pride ourselves on being industry leaders in providing the ultimate shock and vibration |
| 🟠 high | Standpointe / Trinite Solutions — claimed by byod | — | [PSA] Finished Financial Statements, Tenant documents & files, Customer Bank Accounts, Deposit Slips, Payment/Cheque Reg |
| 🟠 high | sterrer.net — claimed by safepay | — | The company has operated since 1979 and combines agricultural production with technical services for commercial poultry  |
| | _+163 more…_ | | |

---
Sources: NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, URLhaus, MalwareBazaar, ThreatFox, AI Honeypot Observatory, LLM ThreatIntel
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W41)*