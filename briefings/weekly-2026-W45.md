# Weekly Threat Briefing — 2026-11-02 – 2026-11-08

> **weekly** · 2026-11-02 – 2026-11-08 · Generated 2026-11-09 00:45 UTC

## Executive Summary

This week (2026-11-02 – 2026-11-08), CISA added 3 new KEV entries and 1127 additional high/critical CVEs were published (NVD, cvefeed.io, MyThreatIntel), including 221 critical-severity affecting Apache Software Foundation, Qihoo 360, Linksys. Active threat indicators across URLhaus, MalwareBazaar, ThreatFox — 14,942 unique after cross-source dedup; all 14942 indicators (2945 malware-distribution URLs, 3038 malicious domains, 1753 suspicious IPs, 7206 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 1602 |
| CVEs | 1130 |
| KEVs | 3 |
| IOCs | 14942 |
| Critical | 221 |
| High | 907 |
| Ransomware victims | 472 |

## Critical Remote Code Execution Vulnerabilities (47)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-86596: The s2Member plugin for WordPress is vulnerable to Remote Code Execution in all version… | `T1190` | The s2Member plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, <= 260927 |
| 🔴 critical | CVE-2026-120534: The Advanced Custom Fields: Extended PRO plugin for WordPress is vulnerable to Limited … | — | The Advanced Custom Fields: Extended PRO plugin for WordPress is vulnerable to Limited Code Injection in all versions up |
| 🔴 critical | CVE-2026-121260: A flaw has been found in Ziroom ZHOME A0101 1.0.1.0 Build 202004151405. | — | A flaw has been found in Ziroom ZHOME A0101 1.0.1.0 Build 202004151405. This issue affects the function loadstring of th |
| 🔴 critical | CVE-2026-44266: Elo is a purely functional expression language for no-code tools. | — | Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, the Ruby backend in src/compilers/ruby |
| 🔴 critical | CVE-2026-44267: Elo is a purely functional expression language for no-code tools. | — | Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, plain Elo strings supplied to defaultF |
| 🔴 critical | CVE-2026-83542: Improper Control of Generation of Code ('Code Injection') in Apache OFBiz 24.09 before … | `T1190` | Improper Control of Generation of Code ('Code Injection') in Apache OFBiz 24.09 before 24.09.08 on all platforms allows  |
| 🔴 critical | CVE-2026-54141: OpenHuman is an open-source agent harness available as a desktop application and Rust l… | — | OpenHuman is an open-source agent harness available as a desktop application and Rust library. Before 0.57.13, a remote  |
| 🔴 critical | CVE-2026-123198: LMFDB before commit 01829bd contains a server-side template injection vulnerability in … | — | LMFDB before commit 01829bd contains a server-side template injection vulnerability in the render_knowl function that al |
| 🔴 critical | CVE-2026-116533: The Static Snapshot WordPress plugin through 0.2.1 does not sanitise shell metacharacte… | — | The Static Snapshot WordPress plugin through 0.2.1 does not sanitise shell metacharacters in a user-supplied value befor |
| 🔴 critical | CVE-2026-118423: The WP Libre Form WordPress plugin 1.5.0.1 does not validate the type of files uploaded… | `T1190` | The WP Libre Form WordPress plugin 1.5.0.1 does not validate the type of files uploaded through its form submissions, al |
| 🔴 critical | CVE-2026-93754: The payever – WooCommerce Gateway plugin for WordPress is vulnerable to arbitrary file … | `T1190` | The payever – WooCommerce Gateway plugin for WordPress is vulnerable to arbitrary file upload leading to remote code exe |
| 🔴 critical | CVE-2026-19803: The Printcart Store – Web to Print Product Designer for WooCommerce plugin for WordPres… | `T1190` | The Printcart Store – Web to Print Product Designer for WooCommerce plugin for WordPress is vulnerable to Arbitrary File |
| 🔴 critical | CVE-2026-17342: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17359: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-121491: The Fiber Admin WordPress plugin before 4.0.1 does not validate or escape a request hea… | `T1190` | The Fiber Admin WordPress plugin before 4.0.1 does not validate or escape a request header before writing it into a PHP  |
| 🔴 critical | CVE-2026-120984: A flaw was found in the Keycloak server's client management component. | `T1190` | A flaw was found in the Keycloak server's client management component. When a client is created or imported with authori |
| 🔴 critical | CVE-2026-114432: The Contact Form 7 WordPress plugin before 6.2.4 does not validate the type or extensio… | `T1190` | The Contact Form 7 WordPress plugin before 6.2.4 does not validate the type or extension of files uploaded through a for |
| 🟠 high | CVE-2026-120348: A vulnerability was identified in dayrui XunRuiCMS up to 4.7.4. | — | A vulnerability was identified in dayrui XunRuiCMS up to 4.7.4. Affected by this vulnerability is the function _get_tpl_ |
| 🟠 high | CVE-2026-120349: A security flaw has been discovered in dayrui XunRuiCMS up to 4.7.4. | — | A security flaw has been discovered in dayrui XunRuiCMS up to 4.7.4. Affected by this issue is the function str_replace  |
| 🟠 high | CVE-2026-119085: Improper neutralization of special elements used in a template engine in the publishing… | `T1190` | Improper neutralization of special elements used in a template engine in the publishing component of Amazon Virtual Engi |
| 🟠 high | CVE-2026-91898: Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Improper … | `T1190`, `T1068` | Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Improper Verification of Cryptographic Sig |
| 🟠 high | CVE-2026-76124: The BuddyBoss App plugin for WordPress is vulnerable to Arbitrary File Upload in all ve… | `T1190` | The BuddyBoss App plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 3.2. |
| 🟠 high | CVE-2026-121428: AzuraCast through 0.23.8 contains a remote code execution vulnerability that allows aut… | `T1190` | AzuraCast through 0.23.8 contains a remote code execution vulnerability that allows authenticated station managers to in |
| 🟠 high | CVE-2026-28335: SolarWinds Dameware was found to be affected by a buffer overflow vulnerability that ca… | `T1190`, `T1203` | SolarWinds Dameware was found to be affected by a buffer overflow vulnerability that can result in remote code execution |
| 🟠 high | CVE-2026-44265: Elo is a purely functional expression language for no-code tools. | `T1190` | Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, Elo's programmatic AST API accepts arb |
| 🟠 high | CVE-2026-39379: GeoNetwork is a catalog application to manage spatially referenced resources. | — | GeoNetwork is a catalog application to manage spatially referenced resources. From 3.0.0 until 4.2.15 and 4.4.10, reques |
| 🟠 high | CVE-2026-115878: Stanza is a Stanford NLP Python library for tokenization, sentence segmentation, NER, a… | `T1190` | Stanza is a Stanford NLP Python library for tokenization, sentence segmentation, NER, and parsing of many human language |
| 🟠 high | CVE-2022-30267: Emerson Ovation 
was found to have no authentication of firmware signing and relies on … | `T1190` | Emerson Ovation 
was found to have no authentication of firmware signing and relies on an insecure checksum for integrit |
| 🟠 high | CVE-2026-13292: IBM MQ Managed File Transfer is affected by an arbitrary code execution vulnerability | `T1190` | [cvefeed.io] IBM MQ Managed File Transfer is affected by an arbitrary code execution vulnerability |
| 🟠 high | CVE-2026-122135: Mistral Vibe before 3.0.3 RCE via Repository-Configured gpg.program | `T1190` | [cvefeed.io] Mistral Vibe before 3.0.3 RCE via Repository-Configured gpg.program |
| 🟠 high | CVE-2026-122133: Mistral Vibe before 2.25.5 on Windows Untrusted Search Path RCE via git.exe | `T1190` | [cvefeed.io] Mistral Vibe before 2.25.5 on Windows Untrusted Search Path RCE via git.exe |
| 🟠 high | CVE-2026-123018: A security flaw has been discovered in eosphoros-ai DB-GPT up to 0.8.2. | — | A security flaw has been discovered in eosphoros-ai DB-GPT up to 0.8.2. This issue affects the function execute_code of  |
| 🟠 high | CVE-2026-82910: Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Tem… | — | Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Template Injection') in MacroScreenR |
| 🟠 high | CVE-2026-82912: Improper Neutralization of Special Elements Used in an Expression Language Statement ('… | — | Improper Neutralization of Special Elements Used in an Expression Language Statement ('Expression Language Injection') i |
| 🟠 high | CVE-2026-82960: Improper Control of Generation of Code ('Code Injection') in ModelFormField in the Apac… | — | Improper Control of Generation of Code ('Code Injection') in ModelFormField in the Apache OFBiz cms plugin before 24.09. |
| 🟠 high | CVE-2026-116786: FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from… | — | FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to  |
| 🟠 high | CVE-2026-87964: The Product Feed Manager for WooCommerce – CTX Feed – Support 220+ Shopping, AI & Socia… | `T1190` | The Product Feed Manager for WooCommerce – CTX Feed – Support 220+ Shopping, AI & Social Channels plugin for WordPress i |
| 🟠 high | CVE-2026-92895: The Live2DWebCanvas plugin for WordPress is vulnerable to Arbitrary File Upload in all … | `T1190` | The Live2DWebCanvas plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2. |
| 🟠 high | CVE-2026-123675: A flaw has been found in OpenBMB Internet of Agents up to 9d78e88e47160eb42ee1ee8538c05… | — | A flaw has been found in OpenBMB Internet of Agents up to 9d78e88e47160eb42ee1ee8538c05e1c2c47877a. This affects the fun |
| 🟠 high | CVE-2026-102530: JupyterLab Desktop: Cross-Site Scripting (XSS) leading to Remote Code Execution on Conn… | `T1190`, `T1059.007` | [cvefeed.io] JupyterLab Desktop: Cross-Site Scripting (XSS) leading to Remote Code Execution on Connect URL |
| 🟠 high | CVE-2026-83844: Windows Paint RCE With Conflicting Fixed-Version Reports | `T1190` | [VulnTracker] A Windows Paint out-of-bounds read can lead to code execution over a network. It scores 8.1 and is not kno |
| 🟠 high | CVE-2026-104913: The Interactive Real Estate – Floor Plan & Building Visualizer plugin for WordPress is … | `T1190` | The Interactive Real Estate – Floor Plan & Building Visualizer plugin for WordPress is vulnerable to Arbitrary File Uplo |
| 🟠 high | CVE-2026-105002: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow ar… | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow arbitrary code to be executed by th |
| 🟠 high | CVE-2026-124328: A vulnerability has been found in FlowCI flow-core-x up to 1.23.49. | — | A vulnerability has been found in FlowCI flow-core-x up to 1.23.49. The affected element is the function ConditionManage |
| 🟠 high | CVE-2026-124430: Craft CMS from 5.10.0 before 5.11.2 contains a remote code execution vulnerability that… | `T1190` | Craft CMS from 5.10.0 before 5.11.2 contains a remote code execution vulnerability that allows non-administrator control |
| 🟠 high | CVE-2026-110273: IBM TRIRIGA Application Platform 5.0.0 through 5.0.9 IBM TRIRIGA could allow a remote a… | `T1190`, `T1059` | IBM TRIRIGA Application Platform 5.0.0 through 5.0.9 IBM TRIRIGA could allow a remote authenticated attacker to execute  |
| 🟠 high | CVE-2026-9764: IBM Bob 1.0.4 through 2.0.1 could allow a remote attacker to inject arbitrary code on t… | `T1190` | IBM Bob 1.0.4 through 2.0.1 could allow a remote attacker to inject arbitrary code on the system, due to the improper co |

## Command Injection (53)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-120276: A weakness has been identified in WAVLINK WN536AX6-A V260507_2.0.0. | `T1059` | A weakness has been identified in WAVLINK WN536AX6-A V260507_2.0.0. This vulnerability affects the function sub_416760 o |
| 🔴 critical | CVE-2026-120277: A security vulnerability has been detected in WAVLINK WN536AX6-A V260507_2.0.0. | `T1059` | A security vulnerability has been detected in WAVLINK WN536AX6-A V260507_2.0.0. This issue affects the function sub_41a1 |
| 🔴 critical | CVE-2026-120279: A flaw has been found in WAVLINK WN536AX6-A V260507. | `T1059` | A flaw has been found in WAVLINK WN536AX6-A V260507. The affected element is an unknown function of the file /protocol.c |
| 🔴 critical | CVE-2026-120280: A vulnerability has been found in WAVLINK WN536AX6-A V260507. | `T1059` | A vulnerability has been found in WAVLINK WN536AX6-A V260507. The impacted element is the function wireguard_cli_group h |
| 🔴 critical | CVE-2026-120282: A vulnerability was determined in WAVLINK WN536AX6-A V260507. | `T1059` | A vulnerability was determined in WAVLINK WN536AX6-A V260507. This impacts the function host_black of the file /protocol |
| 🔴 critical | CVE-2026-120344: A vulnerability has been found in WAVLINK WN551X3-A M51X3_V251020-WO-182e965. | `T1059` | A vulnerability has been found in WAVLINK WN551X3-A M51X3_V251020-WO-182e965. This affects the function system of the fi |
| 🔴 critical | CVE-2026-120345: A vulnerability was found in WAVLINK WN551X3-A M51X3_V251020-WO-182e965. | `T1059` | A vulnerability was found in WAVLINK WN551X3-A M51X3_V251020-WO-182e965. This impacts the function sub_41a430 of the fil |
| 🔴 critical | CVE-2026-77876: Control Web Panel (CWP) before webpanel_version 1.16 contains an OS command injection v… | `T1059` | Control Web Panel (CWP) before webpanel_version 1.16 contains an OS command injection vulnerability in the protected_dir |
| 🔴 critical | CVE-2026-28336: SolarWinds Dameware was found to be affected by a command injection vulnerability that … | `T1059` | SolarWinds Dameware was found to be affected by a command injection vulnerability that could lead to the compromise of t |
| 🔴 critical | CVE-2026-121607: Qihoo 360 D603-2/D600-2/D606-6/D706 iscm testspeed_command os command injection | `T1059` | [VulnTracker digest] Qihoo 360 D603-2 — Qihoo 360 D603-2/D600-2/D606-6/D706 iscm testspeed_command os command injection |
| 🔴 critical | CVE-2026-122051: Edimax BR-6208AC mp command injection | `T1059` | [VulnTracker digest] Edimax BR-6208AC — Edimax BR-6208AC mp command injection |
| 🔴 critical | CVE-2026-54143: OpenHuman is an open-source agent harness available as a desktop application and Rust l… | — | OpenHuman is an open-source agent harness available as a desktop application and Rust library. Before version 0.57.13, a |
| 🔴 critical | CVE-2026-116779: FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from… | — | FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to  |
| 🔴 critical | CVE-2026-122193: OS command injection in the example SSM document provisioning script in Trusted Remote … | `T1059` | OS command injection in the example SSM document provisioning script in Trusted Remote Execution (REX) before 2026-07-28 |
| 🔴 critical | CVE-2026-17402: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1059` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17408: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190`, `T1059` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to execute arbitr |
| 🔴 critical | CVE-2026-17410: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-15266: IBM Concert 1.0 through 3.0.1.1 contains components that allow potentially unsafe comma… | — | IBM Concert 1.0 through 3.0.1.1 contains components that allow potentially unsafe command execution, which could be expl |
| 🔴 critical | CVE-2026-6715: IBM Concert 1.0 through 3.0.1.1 allows an attacker can supply crafted input that is inc… | — | IBM Concert 1.0 through 3.0.1.1 allows an attacker can supply crafted input that is incorporated into an operating syste |
| 🟠 high | CVE-2026-18199: Zohocorp ManageEngine Password Manager Pro versions before 13236 and PAM360 versions be… | `T1190` | Zohocorp ManageEngine Password Manager Pro versions before 13236 and PAM360 versions before 8601 are vulnerable to an au |
| 🟠 high | CVE-2026-8923: Zohocorp ManageEngine Eventlog Analyzer and ManageEngine Log360 versions before 13062 a… | `T1190` | Zohocorp ManageEngine Eventlog Analyzer and ManageEngine Log360 versions before 13062 are vulnerable to Authenticated Re |
| 🟠 high | CVE-2026-94349: Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Neutralizatio… | `T1059` | Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Neutralization of Special Elements used in an  |
| 🟠 high | CVE-2026-73697: Control Web Panel (CWP) before webpanel_version 1.16 contains an arbitrary file write a… | `T1059` | Control Web Panel (CWP) before webpanel_version 1.16 contains an arbitrary file write and OS command injection vulnerabi |
| 🟠 high | CVE-2026-104080: Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection v… | `T1059` | Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection vulnerability in the loopback API  |
| 🟠 high | CVE-2026-77878: Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection v… | `T1059` | Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection vulnerability in the loopback API  |
| 🟠 high | CVE-2026-77880: Control Web Panel (CWP) before webpanel_version 1.16 contains an OS command injection v… | `T1190`, `T1059` | Control Web Panel (CWP) before webpanel_version 1.16 contains an OS command injection vulnerability in the loopback API  |
| 🟠 high | CVE-2026-119737: The pppoe_wrapper vendor daemon from the Amlogic Android SDK, as shipped on Nexbox A95X… | `T1059`, `T1068` | The pppoe_wrapper vendor daemon from the Amlogic Android SDK, as shipped on Nexbox A95X (Amlogic S905/S905X) TV boxes, c |
| 🟠 high | CVE-2026-105978: Improper input validation in management control functions may allow a remote attacker w… | — | Improper input validation in management control functions may allow a remote attacker with high privileges to inject ope |
| 🟠 high | CVE-2026-105979: Improper input validation in the ZeroTier VPN function may allow a remote attacker with… | — | Improper input validation in the ZeroTier VPN function may allow a remote attacker with high privileges to inject system |
| 🟠 high | CVE-2026-105980: Improper input validation in the WireGuard VPN function may allow a remote attacker wit… | — | Improper input validation in the WireGuard VPN function may allow a remote attacker with high privileges to inject syste |
| 🟠 high | CVE-2026-105981: Improper input validation in the Digital I/O function may allow a remote attacker with … | — | Improper input validation in the Digital I/O function may allow a remote attacker with high privileges to inject operati |
| 🟠 high | CVE-2026-105982: Improper input validation in the IPsec VPN function may allow a remote attacker with hi… | — | Improper input validation in the IPsec VPN function may allow a remote attacker with high privileges to inject system co |
| 🟠 high | CVE-2026-77691: ZohoCorp ManageEngine Key Manager Plus versions before 7151 allow authenticated users t… | — | ZohoCorp ManageEngine Key Manager Plus versions before 7151 allow authenticated users to enter malicious input when conf |
| 🟠 high | CVE-2026-119742: Nagios XI before 2026R2 contains an OS command injection vulnerability in the MIB uploa… | `T1059` | Nagios XI before 2026R2 contains an OS command injection vulnerability in the MIB upload feature where the install_mib() |
| 🟠 high | CVE-2026-121429: AzuraCast through 0.23.8 contains a command injection vulnerability that allows station… | `T1059` | AzuraCast through 0.23.8 contains a command injection vulnerability that allows station users with Profile permission to |
| 🟠 high | CVE-2026-121548: Jarun nnn through 5.3 contains an OS command injection vulnerability in plugins/togglex… | `T1059` | Jarun nnn through 5.3 contains an OS command injection vulnerability in plugins/togglex that allows attackers to execute |
| 🟠 high | CVE-2026-54161: Network UPS Tools is a collection of programs which provide a common interface for moni… | — | Network UPS Tools is a collection of programs which provide a common interface for monitoring and administering UPS, PDU |
| 🟠 high | CVE-2026-95725: A command injection vulnerability exists in the VIA client for Linux. | `T1059` | A command injection vulnerability exists in the VIA client for Linux. Successful exploitation could allow a low-privileg |
| 🟠 high | CVE-2026-95727: A command injection vulnerability exists in HPE Networking VIA. | `T1059` | A command injection vulnerability exists in HPE Networking VIA. Successful exploitation could allow an authenticated adm |
| 🟠 high | CVE-2026-121621: A command injection vulnerability was found in Argo CD Image Updater, where a proxy URL… | `T1059` | A command injection vulnerability was found in Argo CD Image Updater, where a proxy URL configured on an SSH Git reposit |
| 🟠 high | CVE-2026-116650: Tanium addressed an unauthorized code execution vulnerability in Threat Response. | — | Tanium addressed an unauthorized code execution vulnerability in Threat Response. |
| 🟠 high | CVE-2026-116651: Tanium addressed an unauthorized code execution vulnerability in Threat Response. | — | Tanium addressed an unauthorized code execution vulnerability in Threat Response. |
| 🟠 high | CVE-2026-118869: An OS command injection vulnerability exists in SHIRASAGI, which may allow an authentic… | `T1059` | An OS command injection vulnerability exists in SHIRASAGI, which may allow an authenticated attacker to execute arbitrar |
| 🟠 high | CVE-2026-123022: A vulnerability was detected in agentscope-ai AgentScope up to 2.0.11. | `T1059` | A vulnerability was detected in agentscope-ai AgentScope up to 2.0.11. The impacted element is the function subprocess.P |
| 🟠 high | CVE-2026-82413: ntopng is a web-based network traffic monitoring application. | `T1059` | ntopng is a web-based network traffic monitoring application. Prior to 6.7.260717, scripts/lua/rest/v2/add/host/to_scan. |
| 🟠 high | CVE-2026-110930: Codex Desktop for Windows does not correctly check quotation marks in project paths fro… | — | Codex Desktop for Windows does not correctly check quotation marks in project paths from Windows Explorer. If a user sel |
| 🟠 high | CVE-2026-113663: AG2 is an open-source AgentOS. | — | AG2 is an open-source AgentOS. From 0.13.2 until ag2 1.1.1, and from autogen 0.13.2 to 0.14.1, SandboxShellTool configur |
| 🟠 high | CVE-2026-123281: In JetBrains Datalore before 2026.4 notebook code could execute commands in the sidecar… | — | In JetBrains Datalore before 2026.4 notebook code could execute commands in the sidecar container via the mount broker |
| 🟠 high | CVE-2026-123620: Usermin through 2.570 contains an OS command injection vulnerability in the Read Mail m… | `T1059` | Usermin through 2.570 contains an OS command injection vulnerability in the Read Mail module that allows authenticated u |
| 🟠 high | CVE-2026-123784: Fluxbox through 1.3.7 contains an OS command injection vulnerability in RootTheme::reco… | `T1059` | Fluxbox through 1.3.7 contains an OS command injection vulnerability in RootTheme::reconfigTheme() that allows attackers |
| | _+3 more…_ | | |

## Authentication & Authorization Bypass (208)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-120442: ape-volo-admin before 3.6.1 contains an authentication bypass vulnerability that allows… | `T1078` | ape-volo-admin before 3.6.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to for |
| 🔴 critical | CVE-2026-120446: madong-admin-saas through 5.1.4 contains a missing authentication vulnerability in the … | `T1078` | madong-admin-saas through 5.1.4 contains a missing authentication vulnerability in the platform tenant management API be |
| 🔴 critical | CVE-2026-4052: This issue only impacts deployments where WSO2 Identity Server is configured as a Resid… | — | This issue only impacts deployments where WSO2 Identity Server is configured as a Resident Key Manager with database sha |
| 🔴 critical | CVE-2026-95732: An authentication bypass vulnerability exists in the underlying operating system of HPE… | `T1190`, `T1078` | An authentication bypass vulnerability exists in the underlying operating system of HPE Networking Fabric Composer. Succ |
| 🔴 critical | CVE-2026-121030: Incorrect authorization in DevTools in Google Chrome prior to 157.0.8103.38 allowed a r… | `T1190` | Incorrect authorization in DevTools in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social  |
| 🔴 critical | CVE-2026-121060: Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a… | `T1190` | Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging socia |
| 🔴 critical | CVE-2026-121071: Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a… | `T1190` | Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging socia |
| 🔴 critical | CVE-2026-121104: Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a… | `T1190` | Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging socia |
| 🔴 critical | CVE-2026-95860: node-opcua is an OPC UA implementation for TypeScript and Node.js. | — | node-opcua is an OPC UA implementation for TypeScript and Node.js. From 2.42.0 until 2.180.0, namespace-level access con |
| 🔴 critical | CVE-2022-29966: Emerson Ovation has several protocols that have no authentication, which could allow an… | — | Emerson Ovation has several protocols that have no authentication, which could allow an attacker to change controller co |
| 🔴 critical | CVE-2026-121933: Linksys E5350 Setup Wizard apply.cgi save_settings missing authentication | `T1078` | [VulnTracker digest] Linksys E5350 — Linksys E5350 Setup Wizard apply.cgi save_settings missing authentication |
| 🔴 critical | CVE-2026-122303: Kyverno from 1.17.0 before 1.19.2 contains an authorization bypass vulnerability that a… | — | Kyverno from 1.17.0 before 1.19.2 contains an authorization bypass vulnerability that allows namespace tenants to overwr |
| 🔴 critical | CVE-2026-122304: Kyverno from 1.17.0 before 1.19.2 contains an authorization bypass vulnerability that a… | — | Kyverno from 1.17.0 before 1.19.2 contains an authorization bypass vulnerability that allows namespace admins to escape  |
| 🔴 critical | CVE-2026-100109: The Security For WooCommerce WordPress plugin from 1.0.10 to 1.0.16 does not perform ca… | — | The Security For WooCommerce WordPress plugin from 1.0.10 to 1.0.16 does not perform capability checks when creating use |
| 🔴 critical | CVE-2026-82907: Authentication Bypass by Capture-replay in ExternalLoginKeysManager in Apache OFBiz 24.… | `T1078` | Authentication Bypass by Capture-replay in ExternalLoginKeysManager in Apache OFBiz 24.09 before 24.09.08 on all platfor |
| 🔴 critical | CVE-2026-102940: OpenEMR is a free and open source electronic health records and medical practice manage… | — | OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.4.0, |
| 🔴 critical | CVE-2026-116790: FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from… | — | FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to  |
| 🔴 critical | CVE-2026-77596: Kubeflow Pipelines enables users to build and deploy portable, scalable machine learnin… | — | Kubeflow Pipelines enables users to build and deploy portable, scalable machine learning workflows. Prior to 2.18.0, the |
| 🔴 critical | CVE-2026-63017: Incorrect authorization in PowerSYSTEM Center allows a low-privileged, authenticated us… | — | Incorrect authorization in PowerSYSTEM Center allows a low-privileged, authenticated user to access resources normally l |
| 🔴 critical | CVE-2026-110955: The Wurdey WordPress plugin through 1.0.0 does not verify a request signature before lo… | — | The Wurdey WordPress plugin through 1.0.0 does not verify a request signature before logging a user in, allowing unauthe |
| 🔴 critical | CVE-2026-88800: The MDJM Event Management and Mobile Events Manager WordPress plugins through 1.7.8.7 a… | — | The MDJM Event Management and Mobile Events Manager WordPress plugins through 1.7.8.7 act on a role deletion request on  |
| 🔴 critical | CVE-2026-123279: In JetBrains Datalore before 2026.4 code execution was possible in a notebook's computa… | — | In JetBrains Datalore before 2026.4 code execution was possible in a notebook's computation by view-only collaborators |
| 🔴 critical | CVE-2026-63438: 2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate the… | — | 2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0 |
| 🔴 critical | CVE-2026-63439: 2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate the… | — | 2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0 |
| 🔴 critical | CVE-2026-59104: UgCS server before 6.2 contains an authentication bypass in the HCI protocol login hand… | `T1078` | UgCS server before 6.2 contains an authentication bypass in the HCI protocol login handler (LoginHandler) exposed on TCP |
| 🔴 critical | CVE-2026-109469: Authorization bypass through user-controlled key in Entra Device Registration allows an… | — | Authorization bypass through user-controlled key in Entra Device Registration allows an unauthorized attacker to elevate |
| 🔴 critical | CVE-2026-123218: IBM Aspera Faspex 5.0.0 through 5.0.19 could allow an authorized user to craft a specif… | — | IBM Aspera Faspex 5.0.0 through 5.0.19 could allow an authorized user to craft a specific message to bypass user authori |
| 🔴 critical | CVE-2026-17362: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to create, modi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to create, modify, or delete tenants due to miss |
| 🔴 critical | CVE-2026-16720: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain valid a |
| 🔴 critical | CVE-2026-17049: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information an |
| 🔴 critical | CVE-2026-17066: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information an |
| 🔴 critical | CVE-2026-17158: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17278: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to gain unautho… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to gain unauthorized access to sensitive API cat |
| 🔴 critical | CVE-2026-17292: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17313: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | `T1078` | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information and take control |
| 🔴 critical | CVE-2026-17338: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🔴 critical | CVE-2026-18838: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information and modify API c |
| 🔴 critical | CVE-2026-104014: The Naimur Email OTP Verification for WooCommerce plugin for WordPress is vulnerable to… | `T1078` | The Naimur Email OTP Verification for WooCommerce plugin for WordPress is vulnerable to authentication bypass in version |
| 🔴 critical | CVE-2026-118066: The Appointment Booking Plugin – LatePoint \| Calendar & Scheduling for WordPress plugin… | `T1078` | The Appointment Booking Plugin – LatePoint \| Calendar & Scheduling for WordPress plugin for WordPress is vulnerable to A |
| 🔴 critical | CVE-2026-122041: The Checkout Field Editor for WooCommerce (Pro) plugin for WordPress is vulnerable to u… | — | The Checkout Field Editor for WooCommerce (Pro) plugin for WordPress is vulnerable to unauthorized deletion of arbitrary |
| 🔴 critical | CVE-2026-123550: OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 s… | `T1078` | OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 service provider that accepts unsi |
| 🔴 critical | CVE-2026-124427: Craft CMS from 5.0.0 before 5.11.2 contains an authorization bypass vulnerability that … | — | Craft CMS from 5.0.0 before 5.11.2 contains an authorization bypass vulnerability that allows anonymous GraphQL clients  |
| 🔴 critical | CVE-2026-114464: IBM Process Mining 2.0.0 through 2.2.1 could allow a remote attacker to obtain sensitiv… | — | IBM Process Mining 2.0.0 through 2.2.1 could allow a remote attacker to obtain sensitive information due to improper acc |
| 🟠 high | CVE-2026-120314: Network-AI from 5.14.0 before 5.15.5 contains a missing authentication vulnerability in… | `T1078` | Network-AI from 5.14.0 before 5.15.5 contains a missing authentication vulnerability in the A2AServer class that allows  |
| 🟠 high | CVE-2026-92886: Missing Authorization vulnerability in TÜBİTAK BİLGEM Software Technologies Research In… | `T1068` | Missing Authorization vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-register allows Privi |
| 🟠 high | CVE-2026-120318: Product Gallery Slider & Additional Variation Images for WooCommerce 2.3.23 before 2.3.… | — | Product Gallery Slider & Additional Variation Images for WooCommerce 2.3.23 before 2.3.26 contains a missing authorizati |
| 🟠 high | CVE-2026-120426: OpenCSG CSGHub through v2.6.0-ce contains an authorization bypass vulnerability in the … | — | OpenCSG CSGHub through v2.6.0-ce contains an authorization bypass vulnerability in the unauthenticated file resolve rout |
| 🟠 high | CVE-2026-120429: Camaleon CMS before 2.9.2 contains a missing authorization vulnerability in Admin::Medi… | — | Camaleon CMS before 2.9.2 contains a missing authorization vulnerability in Admin::MediaController that allows low-privi |
| 🟠 high | CVE-2026-120445: madong-admin-saas through 5.1.4 contains an incorrect authorization vulnerability in Ac… | — | madong-admin-saas through 5.1.4 contains an incorrect authorization vulnerability in AccessTokenMiddleware that allows a |
| 🟠 high | CVE-2026-120447: HotGo 2.8.4 through 2.15.1 contains an authentication bypass vulnerability that allows … | `T1078` | HotGo 2.8.4 through 2.15.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to choo |
| | _+158 more…_ | | |

## Privilege Escalation (44)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-94290: SUSE Rancher Fleet clusters reference a kubeconfig secret that the controller uses to i… | — | SUSE Rancher Fleet clusters reference a kubeconfig secret that the controller uses to install and manage a Fleet agent o |
| 🔴 critical | CVE-2026-121234: Privilege elevation in Contacts in Google Chrome on on Android prior to 157.0.8103.38 a… | `T1190` | Privilege elevation in Contacts in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to poten |
| 🔴 critical | CVE-2026-122302: Kyverno before 1.19.2 contains a privilege escalation vulnerability that allows namespa… | `T1068` | Kyverno before 1.19.2 contains a privilege escalation vulnerability that allows namespace admins to create resources bey |
| 🔴 critical | CVE-2026-122313: Kyverno from 1.17.0 before 1.19.2 contains a privilege escalation vulnerability that al… | `T1068` | Kyverno from 1.17.0 before 1.19.2 contains a privilege escalation vulnerability that allows namespace-scoped tenants to  |
| 🔴 critical | CVE-2026-113584: The placester WordPress plugin through 1.4.3 does not perform any capability, nonce or … | — | The placester WordPress plugin through 1.4.3 does not perform any capability, nonce or ownership check on an AJAX action |
| 🔴 critical | CVE-2026-113615: The GS JWT Authentication for WP REST API WordPress plugin through 1.0.0 does not sanit… | `T1190` | The GS JWT Authentication for WP REST API WordPress plugin through 1.0.0 does not sanitize or parameterize a request val |
| 🔴 critical | CVE-2026-115230: The WHIZZ WordPress plugin through 1.1.8 does not validate the password-reset key befor… | — | The WHIZZ WordPress plugin through 1.1.8 does not validate the password-reset key before updating a user's password, rel |
| 🔴 critical | CVE-2026-120844: Incorrect Privilege Assignment vulnerability in miniOrange OAuth Single Sign On – SSO (… | `T1068` | Incorrect Privilege Assignment vulnerability in miniOrange OAuth Single Sign On – SSO (OAuth Client) miniorange-login-wi |
| 🔴 critical | CVE-2026-123294: In JetBrains Hub before 2026.2.52556 privilege escalation was possible by changing emai… | `T1068` | In JetBrains Hub before 2026.2.52556 privilege escalation was possible by changing email authentication details during t |
| 🔴 critical | CVE-2026-107622: The BuddyForms plugin for WordPress is vulnerable to Privilege Escalation in all versio… | `T1068` | The BuddyForms plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.10.5 v |
| 🔴 critical | CVE-2026-119075: The Registration Form for WooCommerce plugin for WordPress is vulnerable to privilege e… | `T1068` | The Registration Form for WooCommerce plugin for WordPress is vulnerable to privilege escalation due to a missing allow- |
| 🔴 critical | CVE-2026-123549: OpenAM before 16.1.4 fails to enforce the Valid Creation Attributes list during self-re… | — | OpenAM before 16.1.4 fails to enforce the Valid Creation Attributes list during self-registration, allowing anonymous at |
| 🔴 critical | CVE-2026-110963: The Userplace  WordPress plugin through 1.2.0 does not perform authorization checks on … | — | The Userplace  WordPress plugin through 1.2.0 does not perform authorization checks on an AJAX action available to unaut |
| 🔴 critical | CVE-2026-109900: Incorrect Privilege Assignment vulnerability in Melapress Melapress Role Editor melapre… | `T1068` | Incorrect Privilege Assignment vulnerability in Melapress Melapress Role Editor melapress-role-editor allows Privilege E |
| 🟠 high | CVE-2026-91893: Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Improper … | `T1068` | Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Improper Privilege Management vulnerabilit |
| 🟠 high | CVE-2026-105476: Improper link resolution before file access in cPanel allows remote authenticated users… | — | Improper link resolution before file access in cPanel allows remote authenticated users to write arbitrary root-owned fi |
| 🟠 high | CVE-2026-121419: SurrealDB from 3.1.0 before 3.3.0 contains an improper authentication vulnerability whe… | — | SurrealDB from 3.1.0 before 3.3.0 contains an improper authentication vulnerability where the MCP BoundSubject fingerpri |
| 🟠 high | CVE-2026-121559: GLPI 10.0.0 before 10.0.28 and 11.0.0 before 11.0.10 contains a privilege escalation vu… | `T1068` | GLPI 10.0.0 before 10.0.28 and 11.0.0 before 11.0.10 contains a privilege escalation vulnerability that allows authentic |
| 🟠 high | CVE-2026-95722: A local privilege escalation vulnerability has been discovered in the Virtual Intranet … | `T1068` | A local privilege escalation vulnerability has been discovered in the Virtual Intranet Access (VIA) client. Successful e |
| 🟠 high | CVE-2026-95728: An arbitrary file write vulnerability exists in the Virtual Intranet Access (VIA) client. | — | An arbitrary file write vulnerability exists in the Virtual Intranet Access (VIA) client. Successful exploitation could  |
| 🟠 high | CVE-2026-95737: A privilege escalation vulnerability exists in the underlying operating system of HPE N… | `T1068` | A privilege escalation vulnerability exists in the underlying operating system of HPE Networking Fabric Composer. Succes |
| 🟠 high | CVE-2026-95743: Local privilege escalation vulnerabilities exist in the underlying operating system of … | `T1068` | Local privilege escalation vulnerabilities exist in the underlying operating system of HPE Networking Fabric Composer. S |
| 🟠 high | CVE-2026-95747: A privilege escalation vulnerability exists in the SSH interface of HPE Networking Fabr… | `T1068` | A privilege escalation vulnerability exists in the SSH interface of HPE Networking Fabric Composer which could allow an  |
| 🟠 high | CVE-2026-95752: A local privilege escalation vulnerability exists in the API of HPE Networking Fabric C… | `T1068` | A local privilege escalation vulnerability exists in the API of HPE Networking Fabric Composer. Successful exploitation  |
| 🟠 high | CVE-2026-95753: A privilege escalation vulnerability exists in the API of HPE Networking Fabric Composer. | `T1068` | A privilege escalation vulnerability exists in the API of HPE Networking Fabric Composer. Successful exploitation could  |
| 🟠 high | CVE-2026-121090: Improper privilege management in Navigation in Google Chrome on on iOS prior to 157.0.8… | `T1190` | Improper privilege management in Navigation in Google Chrome on on iOS prior to 157.0.8103.38 allowed a remote attacker  |
| 🟠 high | CVE-2026-122312: Kyverno from 1.19.1 before 1.19.2 contains a namespace isolation bypass in APICall Fetc… | — | Kyverno from 1.19.1 before 1.19.2 contains a namespace isolation bypass in APICall Fetch() in pkg/engine/apicall/apiCall |
| 🟠 high | CVE-2026-118193: The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerabl… | `T1068` | The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to Privilege Escalation in all  |
| 🟠 high | CVE-2026-100363: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-85076: Cronicle: Privilege Escalation via Arbitrary Environment Variable Injection through Eve… | `T1068` | [cvefeed.io] Cronicle: Privilege Escalation via Arbitrary Environment Variable Injection through Event Params (Incomplet |
| 🟠 high | CVE-2026-87784: The Cool Media Filter WordPress plugin through 1.0.1 does not perform any capability or… | — | The Cool Media Filter WordPress plugin through 1.0.1 does not perform any capability or nonce check when updating the ca |
| 🟠 high | CVE-2026-103479: The Pubjet \| پاب‌جت plugin for WordPress is vulnerable to Privilege Escalation in all v… | `T1068` | The Pubjet \| پاب‌جت plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 5.4 |
| 🟠 high | CVE-2026-116624: The Advanced Members for ACF plugin for WordPress is vulnerable to Privilege Escalation… | `T1068` | The Advanced Members for ACF plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and inclu |
| 🟠 high | CVE-2026-123490: Craft CMS from 5.8.17 before 5.11.2 contains a privilege escalation vulnerability becau… | `T1068` | Craft CMS from 5.8.17 before 5.11.2 contains a privilege escalation vulnerability because getOwners() applies caller cri |
| 🟠 high | CVE-2026-103985: FreeScout is a self-hosted help desk and shared mailbox. | — | FreeScout is a self-hosted help desk and shared mailbox. Prior to 1.8.231, the profile form exposes the only_assigned_ti |
| 🟠 high | CVE-2026-123974: In all versions of PyTorch's TorchServe, a predictable extraction directory in /tmp let… | `T1068` | In all versions of PyTorch's TorchServe, a predictable extraction directory in /tmp lets a local user swap the model han |
| 🟠 high | CVE-2026-121848: The Magic Link  WordPress plugin before 2.2.6 does not check that the user requesting a… | — | The Magic Link  WordPress plugin before 2.2.6 does not check that the user requesting a login link is authorised to gene |
| 🟠 high | CVE-2026-121866: The iLeads SMS Gateway by Exsile WordPress plugin before 2.0.0 does not check capabilit… | — | The iLeads SMS Gateway by Exsile WordPress plugin before 2.0.0 does not check capabilities or nonces in several AJAX act |
| 🟠 high | CVE-2026-103900: The WPJAM Basic plugin for WordPress is vulnerable to Privilege Escalation in versions … | `T1068` | The WPJAM Basic plugin for WordPress is vulnerable to Privilege Escalation in versions up to, and including, 7.1 This is |
| 🟠 high | CVE-2026-119164: The wpForo Forum plugin for WordPress is vulnerable to Privilege Escalation in all vers… | `T1068` | The wpForo Forum plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.2.2  |
| 🟠 high | CVE-2026-104768: The AutomatorWP – No-Code Workflow Automation, Integration & Webhooks Plugin, now with … | `T1068` | The AutomatorWP – No-Code Workflow Automation, Integration & Webhooks Plugin, now with AI plugin for WordPress is vulner |
| 🟠 high | CVE-2026-123520: Vikunja from 0.18.0 before 2.7.1 contains a privilege escalation vulnerability that all… | `T1068` | Vikunja from 0.18.0 before 2.7.1 contains a privilege escalation vulnerability that allows team owners to gain admin or  |
| 🟠 high | CVE-2026-124429: Craft CMS from 5.0.0 before 5.11.2 contains a privilege escalation vulnerability that a… | `T1068` | Craft CMS from 5.0.0 before 5.11.2 contains a privilege escalation vulnerability that allows unauthenticated public regi |
| 🟠 high | CVE-2026-18893: IBM CockroachDB PostgreSQL for IBM VPC 26.2.0 through 26.2.3, 25.4.0 through 25.4.12, a… | `T1068` | IBM CockroachDB PostgreSQL for IBM VPC 26.2.0 through 26.2.3, 25.4.0 through 25.4.12, and 25.2.0 through 25.2.20 is vuln |

## SQL & NoSQL Injection (65)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-63774: Insufficient input validation in the PowerSYSTEM Center report designer allows an authe… | — | Insufficient input validation in the PowerSYSTEM Center report designer allows an authenticated user to execute unauthor |
| 🔴 critical | CVE-2026-123488: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL i… | `T1190` | Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the ele |
| 🔴 critical | CVE-2026-54349: Chartbrew is an open-source web application that can connect directly to databases and … | — | Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create c |
| 🔴 critical | CVE-2026-17132: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to execute arbitrary SQL commands  |
| 🔴 critical | CVE-2026-17134: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | `T1190` | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to execute arbitrary SQL commands  |
| 🔴 critical | CVE-2026-17336: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to execute arbitrary SQL commands  |
| 🔴 critical | CVE-2026-17396: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-124469: OpenEMR before 8.3.0 contains an SQL injection vulnerability in the Fee Sheet drug-inve… | `T1190` | OpenEMR before 8.3.0 contains an SQL injection vulnerability in the Fee Sheet drug-inventory lookup (DrugSalesService::s |
| 🟠 high | CVE-2026-120342: A vulnerability was detected in mathurvishal CloudClassroom-PHP-Project. | `T1190` | A vulnerability was detected in mathurvishal CloudClassroom-PHP-Project. The affected element is an unknown function of  |
| 🟠 high | CVE-2026-120347: A vulnerability was determined in dayrui XunRuiCMS up to 4.7.4. | `T1190` | A vulnerability was determined in dayrui XunRuiCMS up to 4.7.4. Affected is the function View of the file dayrui/Fcms/Co |
| 🟠 high | CVE-2026-2613: The Admin REST API accepts user-supplied input without adequately sanitizing it, allowi… | `T1190` | The Admin REST API accepts user-supplied input without adequately sanitizing it, allowing it to be included in the struc |
| 🟠 high | CVE-2026-74993: Improper neutralization of special elements used in an SQL command ('SQL injection') vu… | `T1190` | Improper neutralization of special elements used in an SQL command ('SQL injection') vulnerability in Starnet Computer a |
| 🟠 high | CVE-2026-77879: Control Web Panel (CWP) before webpanel_version 1.16 contains a SQL injection vulnerabi… | `T1190` | Control Web Panel (CWP) before webpanel_version 1.16 contains a SQL injection vulnerability in the loopback API authenti |
| 🟠 high | CVE-2026-119301: Improper neutralization of quoting syntax in SQL identifier construction in the Apache … | — | Improper neutralization of quoting syntax in SQL identifier construction in the Apache Iceberg write component in AWS SD |
| 🟠 high | CVE-2026-120062: SQLSpecialColumns in psqlODBC splices the table and schema names it receives into its c… | — | SQLSpecialColumns in psqlODBC splices the table and schema names it receives into its catalog query without escaping the |
| 🟠 high | CVE-2026-120065: For an updatable cursor over a table without OIDs that has an auto-increment int4 colum… | — | For an updatable cursor over a table without OIDs that has an auto-increment int4 column, psqlODBC uses that column to i |
| 🟠 high | CVE-2026-120558: The Advanced Shipment Tracking for WooCommerce plugin for WordPress is vulnerable to SQ… | `T1190` | The Advanced Shipment Tracking for WooCommerce plugin for WordPress is vulnerable to SQL Injection via the `tracking_pro |
| 🟠 high | CVE-2026-45146: Chamilo LMS is an open-source learning management system. | `T1190` | Chamilo LMS is an open-source learning management system. Prior to 1.11.40 and 2.0.1, an authenticated administrator can |
| 🟠 high | CVE-2026-63489: Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intell… | — | Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intelligence platform and pipeline. In  |
| 🟠 high | CVE-2026-95748: A SQL injection vulnerability exists in HPE Networking Fabric Composer. | `T1190` | A SQL injection vulnerability exists in HPE Networking Fabric Composer. Successful exploitation could allow an unauthent |
| 🟠 high | CVE-2026-121502: A vulnerability was identified in mathurvishal CloudClassroom-PHP-Project. | `T1190` | A vulnerability was identified in mathurvishal CloudClassroom-PHP-Project. The impacted element is an unknown function o |
| 🟠 high | CVE-2026-121524: A flaw has been found in sumiie24 School-Management-System up to d946d649c7c95e101fc567… | `T1190` | A flaw has been found in sumiie24 School-Management-System up to d946d649c7c95e101fc5679ecd91999533bb10d7. Affected by t |
| 🟠 high | CVE-2026-121731: RosarioSIS before 12.9 contains a sql injection vulnerability that allows authenticated… | `T1190` | RosarioSIS before 12.9 contains a sql injection vulnerability that allows authenticated non-student users, including par |
| 🟠 high | CVE-2026-122050: A vulnerability was found in Campcodes Complete Sales and Inventory System with Credit … | `T1190` | A vulnerability was found in Campcodes Complete Sales and Inventory System with Credit Management 1.0. This issue affect |
| 🟠 high | CVE-2026-105321: Improper neutralization of special elements used in an SQL command ('SQL injection') vu… | `T1190` | Improper neutralization of special elements used in an SQL command ('SQL injection') vulnerability in Kobikom Telecommun |
| 🟠 high | CVE-2026-123028: A vulnerability was identified in itsourcecode Online Book Store 1.0. | `T1190` | A vulnerability was identified in itsourcecode Online Book Store 1.0. Affected by this issue is some unknown functionali |
| 🟠 high | CVE-2026-100365: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-61648: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190`, `T1059.007` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-61651: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-61653: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190`, `T1059.007` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-63214: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-63215: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69134: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69135: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69136: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69140: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1059.007` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69141: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190`, `T1059.007` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69142: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-71548: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-97377: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | `T1190` | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-33944: Dolibarr is an open-source enterprise resource planning and customer relationship manag… | `T1190` | Dolibarr is an open-source enterprise resource planning and customer relationship management application. Prior to 22.0. |
| 🟠 high | CVE-2026-111492: SQL injection in the push notification handler of the MatchPoint Android app | `T1190` | [cvefeed.io] SQL injection in the push notification handler of the MatchPoint Android app |
| 🟠 high | CVE-2025-71458: FTS3 Web Monitoring (fts-monitoring) versions 3.12.0 through 3.13.2 and 3.14.0 contain … | `T1190` | FTS3 Web Monitoring (fts-monitoring) versions 3.12.0 through 3.13.2 and 3.14.0 contain an unauthenticated sql injection  |
| 🟠 high | CVE-2026-110532: The Mail Mage WordPress plugin through 0.0.25 does not properly sanitise and escape a u… | `T1190` | The Mail Mage WordPress plugin through 0.0.25 does not properly sanitise and escape a user-supplied value before using i |
| 🟠 high | CVE-2026-123489: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains a blind SQL injection vu… | `T1190` | Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains a blind SQL injection vulnerability because the sandbox-e |
| 🟠 high | CVE-2026-123491: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an SQL injection vulnera… | `T1190` | Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an SQL injection vulnerability in GraphQL eager-loading:  |
| 🟠 high | CVE-2026-123859: When identifier escaping is disabled through a non-default configuration, the write_pan… | `T1190` | When identifier escaping is disabled through a non-default configuration, the write_pandas() data-loading functionality  |
| 🟠 high | CVE-2026-85726: Chartbrew is an open-source web application that can connect directly to databases and … | — | Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create c |
| 🟠 high | CVE-2026-123791: A vulnerability was detected in OpenBMB Internet of Agents up to 9d78e88e47160eb42ee1ee… | — | A vulnerability was detected in OpenBMB Internet of Agents up to 9d78e88e47160eb42ee1ee8538c05e1c2c47877a. This affects  |
| 🟠 high | CVE-2026-120043: The Affiliate Program Suite — SliceWP Affiliates plugin for WordPress is vulnerable to … | `T1190` | The Affiliate Program Suite — SliceWP Affiliates plugin for WordPress is vulnerable to generic SQL Injection via the 'em |
| | _+15 more…_ | | |

## Cross-Site Scripting (67)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-82158: Dell Wyse Management Suite, versions prior to 2609.0.0.155, contain an Improper Neutral… | `T1059.007` | Dell Wyse Management Suite, versions prior to 2609.0.0.155, contain an Improper Neutralization of Input During Web Page  |
| 🔴 critical | CVE-2026-96677: Apache Juneau: Cross-site scripting via unescaped request variables in HTML-doc chrome | `T1059.007` | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Cross-site scripting via unescaped reques |
| 🔴 critical | CVE-2026-17146: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-63197: traQ is a messenger application built for Digital Creators Club traP. | — | traQ is a messenger application built for Digital Creators Club traP. Prior to 3.28.3, instances configured with TRAQ_ST |
| 🟠 high | CVE-2026-82159: Dell Wyse Management Suite, versions prior to 2609.0.0.155, contain an Improper Neutral… | `T1059.007` | Dell Wyse Management Suite, versions prior to 2609.0.0.155, contain an Improper Neutralization of Input During Web Page  |
| 🟠 high | CVE-2026-102615: HeyForm is an open-source form builder. | — | HeyForm is an open-source form builder. Prior to 3.0.1, /api/upload accepts a file according to the client-controlled mu |
| 🟠 high | CVE-2026-105607: Joomla Extension - balbooa.com - Unauthenticated stored XSS in the "Recent Comments / R… | `T1059.007` | Joomla Extension - balbooa.com - Unauthenticated stored XSS in the "Recent Comments / Recent Reviews" widget in Gridbox  |
| 🟠 high | CVE-2026-107903: Joomla Extension - balbooa.com - Stored XSS in reviews via inconsistent sanitization in… | `T1059.007` | Joomla Extension - balbooa.com - Stored XSS in reviews via inconsistent sanitization in Gridbox < 2.20.5.0 |
| 🟠 high | CVE-2026-103935: OpenEMR is a free and open source electronic health records and medical practice manage… | — | OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.3.0, |
| 🟠 high | CVE-2026-119432: A stored cross-site scripting (XSS) vulnerability exists in the Foxit Workspace's file … | `T1059.007` | A stored cross-site scripting (XSS) vulnerability exists in the Foxit Workspace's file share preview functionality. An a |
| 🟠 high | CVE-2026-110525: The MCB  WordPress plugin through 1.0.0 does not sanitise or escape request header valu… | — | The MCB  WordPress plugin through 1.0.0 does not sanitise or escape request header values before storing them and later  |
| 🟠 high | CVE-2026-110813: The Advanced Custom Fields (ACF®) WordPress plugin before 6.8.11 does not properly sani… | — | The Advanced Custom Fields (ACF®) WordPress plugin before 6.8.11 does not properly sanitize a stored field definition th |
| 🟠 high | CVE-2026-115673: The Anti-Spam, Spam FireWall by CleanTalk WordPress plugin before 6.91 does not escape … | — | The Anti-Spam, Spam FireWall by CleanTalk WordPress plugin before 6.91 does not escape a commenter-supplied value before |
| 🟠 high | CVE-2026-120408: The All-in-One Video Gallery  WordPress plugin before 5.1.0 does not escape a video's s… | `T1059.007` | The All-in-One Video Gallery  WordPress plugin before 5.1.0 does not escape a video's stored thumbnail URL before output |
| 🟠 high | CVE-2026-86606: The iubenda \| All-in-one Compliance for GDPR / CCPA Cookie Consent + more WordPress plu… | — | The iubenda \| All-in-one Compliance for GDPR / CCPA Cookie Consent + more WordPress plugin before 3.13.7 does not proper |
| 🟠 high | CVE-2026-119488: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Shamim Rajani Pie  |
| 🟠 high | CVE-2026-39744: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WC Lovers WCFM Mem |
| 🟠 high | CVE-2026-88801: The MDJM Event Management and Mobile Events Manager WordPress plugins through 1.7.8.7 d… | — | The MDJM Event Management and Mobile Events Manager WordPress plugins through 1.7.8.7 do not check a capability or a non |
| 🟠 high | CVE-2026-110291: The Graphina – Charts and Graphs For Elementor plugin for WordPress is vulnerable to St… | `T1059.007` | The Graphina – Charts and Graphs For Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the |
| 🟠 high | CVE-2026-110776: The MDTF – Meta Data and Taxonomies Filter plugin for WordPress is vulnerable to Stored… | `T1059.007` | The MDTF – Meta Data and Taxonomies Filter plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'va |
| 🟠 high | CVE-2026-123301: In JetBrains IntelliJ IDEA before 2026.3 dOM-based XSS in the OpenAPI preview error vie… | `T1059.007` | In JetBrains IntelliJ IDEA before 2026.3 dOM-based XSS in the OpenAPI preview error view was possible |
| 🟠 high | CVE-2026-109883: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Elementor Elemento |
| 🟠 high | CVE-2026-109884: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Elementor Elemento |
| 🟠 high | CVE-2026-104656: Improper neutralization of input in the sessions grid in Progress Telerik Fiddler Every… | — | Improper neutralization of input in the sessions grid in Progress Telerik Fiddler Everywhere 8.3.0 and earlier allows an |
| 🟠 high | CVE-2026-62854: FreeScout is a self-hosted help desk and shared mailbox. | — | FreeScout is a self-hosted help desk and shared mailbox. Prior to 1.8.225, a user who can edit a mailbox signature can c |
| 🟠 high | CVE-2026-118670: OHIF Viewers is a zero-footprint DICOM viewer with shared extension packages. | — | OHIF Viewers is a zero-footprint DICOM viewer with shared extension packages. From 3.5.0-beta.0 until 3.12.15, 3.13.7, a |
| 🟠 high | CVE-2026-85742: FreeScout is a self-hosted help desk and shared mailbox. | — | FreeScout is a self-hosted help desk and shared mailbox. Prior to 1.8.230, a pre-authenticated attacker can place HTML i |
| 🟠 high | CVE-2026-62345: Wanderer is a self-hosted trail database for saving and sharing adventures. | — | Wanderer is a self-hosted trail database for saving and sharing adventures. Prior to 0.19.3, an authenticated user can s |
| 🟠 high | CVE-2026-62346: Wanderer is a self-hosted trail database for saving and sharing adventures. | — | Wanderer is a self-hosted trail database for saving and sharing adventures. Prior to 0.19.3, an authenticated local user |
| 🟠 high | CVE-2026-119070: The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimiza… | `T1059.007` | The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimization plugin for WordPress is vuln |
| 🟠 high | CVE-2026-119175: The Flying Images: Optimize and Lazy Load Images for Faster Page Speed plugin for WordP… | `T1059.007` | The Flying Images: Optimize and Lazy Load Images for Faster Page Speed plugin for WordPress is vulnerable to Stored Cros |
| 🟠 high | CVE-2026-120082: The GeoDirectory – WP Business Directory Plugin and Classified Listings Directory plugi… | `T1059.007` | The GeoDirectory – WP Business Directory Plugin and Classified Listings Directory plugin for WordPress is vulnerable to  |
| 🟠 high | CVE-2026-120512: The Form Maker by 10Web – Mobile-Friendly Drag & Drop Contact Form Builder plugin for W… | `T1059.007` | The Form Maker by 10Web – Mobile-Friendly Drag & Drop Contact Form Builder plugin for WordPress is vulnerable to Stored  |
| 🟠 high | CVE-2026-120540: The iubenda \| All-in-one Compliance for GDPR / CCPA Cookie Consent + more plugin for Wo… | `T1059.007` | The iubenda \| All-in-one Compliance for GDPR / CCPA Cookie Consent + more plugin for WordPress is vulnerable to Stored C |
| 🟠 high | CVE-2026-119158: The Pie Register – User Registration, Profiles & Content Restriction plugin for WordPre… | `T1059.007` | The Pie Register – User Registration, Profiles & Content Restriction plugin for WordPress is vulnerable to Stored Cross- |
| 🟠 high | CVE-2026-120677: The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimiza… | `T1059.007` | The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimization plugin for WordPress is vuln |
| 🟠 high | CVE-2026-120739: The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimiza… | `T1059.007` | The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimization plugin for WordPress is vuln |
| 🟠 high | CVE-2026-119167: The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPr… | `T1059.007` | The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross |
| 🟠 high | CVE-2026-16709: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1059.007` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17190: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1059.007` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-117525: The FV Flowplayer Video Player WordPress plugin before 7.5.57.7212 does not escape shor… | — | The FV Flowplayer Video Player WordPress plugin before 7.5.57.7212 does not escape shortcode attribute values embedded i |
| 🟠 high | CVE-2026-115811: The Strong Testimonials plugin for WordPress is vulnerable to Stored Cross-Site Scripti… | `T1059.007` | The Strong Testimonials plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'star_rating' paramete |
| 🟠 high | CVE-2026-116558: The Unlimited Elements for Elementor plugin for WordPress is vulnerable to Stored Cross… | `T1059.007` | The Unlimited Elements for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the '<title>/ |
| 🟠 high | CVE-2026-120537: The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPr… | `T1059.007` | The TranslatePress – Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross |
| 🟠 high | CVE-2026-122037: The AgenWebsite Shipping – Plugin Ongkos Kirim & Generate Resi Otomatis Semua Kurir Ind… | `T1059.007` | The AgenWebsite Shipping – Plugin Ongkos Kirim & Generate Resi Otomatis Semua Kurir Indonesia plugin for WordPress is vu |
| 🟠 high | CVE-2026-109214: The User Frontend – Membership, User Registration, User Profile, User Directory & Conte… | `T1059.007` | The User Frontend – Membership, User Registration, User Profile, User Directory & Content Restriction with Frontend Post |
| 🟠 high | CVE-2026-109230: The WP Visitor Statistics (Real Time Traffic) plugin for WordPress is vulnerable to Sto… | `T1059.007` | The WP Visitor Statistics (Real Time Traffic) plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the  |
| 🟠 high | CVE-2026-111317: The JetFormBuilder — Dynamic Blocks Form Builder plugin for WordPress is vulnerable to … | `T1059.007` | The JetFormBuilder — Dynamic Blocks Form Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via t |
| 🟠 high | CVE-2026-111370: The WP Visitor Statistics (Real Time Traffic) plugin for WordPress is vulnerable to Sto… | `T1059.007` | The WP Visitor Statistics (Real Time Traffic) plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the  |
| 🟠 high | CVE-2026-115548: The Quttera ThreatSign – Web Malware Scanner for WordPress plugin for WordPress is vuln… | `T1059.007` | The Quttera ThreatSign – Web Malware Scanner for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scrip |
| | _+17 more…_ | | |

## Memory Corruption (194)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-120281: A vulnerability was found in WAVLINK WN536AX6-A V260507. | `T1203` | A vulnerability was found in WAVLINK WN536AX6-A V260507. This affects the function strcpy of the file /protocol.csp of t |
| 🔴 critical | CVE-2026-120283: A vulnerability was identified in Linksys E8450 1.2.00.360516. | `T1203` | A vulnerability was identified in Linksys E8450 1.2.00.360516. Affected is the function strcpy of the file /www/cgi-bin/ |
| 🔴 critical | CVE-2026-121034: Use after free in Views in Google Chrome on on Windows prior to 157.0.8103.38 allowed a… | `T1190` | Use after free in Views in Google Chrome on on Windows prior to 157.0.8103.38 allowed a remote attacker leveraging socia |
| 🔴 critical | CVE-2026-121035: Use after free in Prerender in Google Chrome prior to 157.0.8103.38 allowed a remote at… | `T1190` | Use after free in Prerender in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code  |
| 🔴 critical | CVE-2026-121037: Out of bounds write in ANGLE in Google Chrome on on Windows prior to 157.0.8103.38 allo… | `T1190` | Out of bounds write in ANGLE in Google Chrome on on Windows prior to 157.0.8103.38 allowed a remote attacker to potentia |
| 🔴 critical | CVE-2026-121074: Memory corruption in GPU in Google Chrome on on Android prior to 157.0.8103.38 allowed … | `T1190`, `T1203` | Memory corruption in GPU in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentially  |
| 🔴 critical | CVE-2026-121076: Use after free in WebXR in Google Chrome prior to 157.0.8103.38 allowed a remote attack… | `T1190` | Use after free in WebXR in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering  |
| 🔴 critical | CVE-2026-121077: Use after free in Mobile in Google Chrome prior to 157.0.8103.38 allowed a remote attac… | `T1190` | Use after free in Mobile in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering |
| 🔴 critical | CVE-2026-121086: Buffer overflow in Skia in Google Chrome prior to 157.0.8103.38 allowed a remote attack… | `T1190`, `T1203` | Buffer overflow in Skia in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code outs |
| 🔴 critical | CVE-2026-121089: Use after free in WebGPU in Google Chrome prior to 157.0.8103.38 allowed a remote attac… | `T1190` | Use after free in WebGPU in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitr |
| 🔴 critical | CVE-2026-121114: Use after free in TabStrip in Google Chrome prior to 157.0.8103.38 allowed a remote att… | `T1190` | Use after free in TabStrip in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code o |
| 🔴 critical | CVE-2026-121126: Use after free in Core in Google Chrome prior to 157.0.8103.38 allowed a remote attacke… | `T1190` | Use after free in Core in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitrar |
| 🔴 critical | CVE-2026-121148: Use after free in ANGLE in Google Chrome prior to 157.0.8103.38 allowed a remote attack… | `T1190` | Use after free in ANGLE in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code outs |
| 🔴 critical | CVE-2026-121156: Buffer overflow in Dawn in Google Chrome prior to 157.0.8103.38 allowed a remote attack… | `T1190`, `T1203` | Buffer overflow in Dawn in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitra |
| 🔴 critical | CVE-2026-121185: Use after free in PictureInPicture in Google Chrome prior to 157.0.8103.38 allowed a re… | `T1190` | Use after free in PictureInPicture in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social e |
| 🔴 critical | CVE-2026-121189: Use after free in Browser in Google Chrome prior to 157.0.8103.38 allowed a remote atta… | `T1190` | Use after free in Browser in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code ou |
| 🔴 critical | CVE-2026-121202: Use after free in Autofill in Google Chrome prior to 157.0.8103.38 allowed a remote att… | `T1190` | Use after free in Autofill in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineeri |
| 🔴 critical | CVE-2026-121214: Use after free in Passwords in Google Chrome prior to 157.0.8103.38 allowed a remote at… | `T1190` | Use after free in Passwords in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute arb |
| 🔴 critical | CVE-2026-121229: Memory corruption in ANGLE in Google Chrome on on Android prior to 157.0.8103.38 allowe… | `T1190`, `T1203` | Memory corruption in ANGLE in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentiall |
| 🔴 critical | CVE-2026-121241: Use after free in Navigation in Google Chrome on on Android prior to 157.0.8103.38 allo… | `T1190` | Use after free in Navigation in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentia |
| 🔴 critical | CVE-2026-121246: Use after free in WebGL in Google Chrome on on Android prior to 157.0.8103.38 allowed a… | `T1190` | Use after free in WebGL in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentially e |
| 🔴 critical | CVE-2026-121247: Buffer overflow in Dawn in Google Chrome on on Android prior to 157.0.8103.38 allowed a… | `T1190`, `T1203` | Buffer overflow in Dawn in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentially e |
| 🔴 critical | CVE-2026-121249: Buffer overflow in ANGLE in Google Chrome prior to 157.0.8103.38 allowed a remote attac… | `T1190`, `T1203` | Buffer overflow in ANGLE in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code out |
| 🔴 critical | CVE-2026-120931: Out of bounds write in WebGL in Google Chrome on on Android prior to 156.0.8078.47 allo… | `T1190` | Out of bounds write in WebGL in Google Chrome on on Android prior to 156.0.8078.47 allowed a remote attacker to execute  |
| 🔴 critical | CVE-2026-116785: FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from… | `T1190` | FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to  |
| 🔴 critical | CVE-2026-119923: A heap-based buffer overflow in the TDS prelogin parser in the Babelfish for PostgreSQL… | `T1203` | A heap-based buffer overflow in the TDS prelogin parser in the Babelfish for PostgreSQL extension versions 1.0-1.5, 2.1- |
| 🔴 critical | CVE-2026-123957: A vulnerability was determined in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A vulnerability was determined in TOTOLINK CA300-PoE 6.2c.884. Impacted is the function setIpQosRules of the file /cgi-b |
| 🔴 critical | CVE-2026-123958: A vulnerability was identified in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A vulnerability was identified in TOTOLINK CA300-PoE 6.2c.884. The affected element is the function setLanConfig of the  |
| 🔴 critical | CVE-2026-123959: A security flaw has been discovered in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A security flaw has been discovered in TOTOLINK CA300-PoE 6.2c.884. The impacted element is the function setLanguageCfg  |
| 🔴 critical | CVE-2026-123960: A weakness has been identified in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A weakness has been identified in TOTOLINK CA300-PoE 6.2c.884. This affects the function setWanConfig of the file /cgi-b |
| 🔴 critical | CVE-2026-123961: A security vulnerability has been detected in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A security vulnerability has been detected in TOTOLINK CA300-PoE 6.2c.884. This impacts the function setWiFiBasicConfig  |
| 🔴 critical | CVE-2026-123966: A vulnerability was determined in Tenda AC19 16.03.10.07. | `T1203` | A vulnerability was determined in Tenda AC19 16.03.10.07. Affected by this issue is the function saveParentControlInfo o |
| 🔴 critical | CVE-2026-124057: A security flaw has been discovered in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A security flaw has been discovered in TOTOLINK CA300-PoE 6.2c.884. This impacts the function setWiFiMultipleConfig of t |
| 🔴 critical | CVE-2026-124058: A weakness has been identified in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A weakness has been identified in TOTOLINK CA300-PoE 6.2c.884. Affected is the function setWiFiRepeaterConfig of the fil |
| 🔴 critical | CVE-2026-124059: A security vulnerability has been detected in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A security vulnerability has been detected in TOTOLINK CA300-PoE 6.2c.884. Affected by this vulnerability is the functio |
| 🔴 critical | CVE-2026-124060: A vulnerability was detected in TOTOLINK CA300-PoE 6.2c.884. | `T1203` | A vulnerability was detected in TOTOLINK CA300-PoE 6.2c.884. Affected by this issue is the function UploadCustomModule o |
| 🔴 critical | CVE-2026-123614: imgproxy from 4.0.0 before 4.0.16 contains an integer overflow in the ICO loader that a… | `T1203` | imgproxy from 4.0.0 before 4.0.16 contains an integer overflow in the ICO loader that allows remote attackers to trigger |
| 🟠 high | CVE-2026-20499: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20545: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20546: In Modem, there is a possible out of bounds write due to an incorrect bounds check. | — | In Modem, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation |
| 🟠 high | CVE-2026-20547: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20548: In Modem, there is a possible out of bounds write due to an integer overflow. | — | In Modem, there is a possible out of bounds write due to an integer overflow. This could lead to remote escalation of pr |
| 🟠 high | CVE-2026-20549: In Modem, there is a possible out of bounds write due to improper input validation. | — | In Modem, there is a possible out of bounds write due to improper input validation. This could lead to remote escalation |
| 🟠 high | CVE-2026-20554: In Modem, there is a possible system crash due to a missing bounds check. | — | In Modem, there is a possible system crash due to a missing bounds check. This could lead to remote escalation of privil |
| 🟠 high | CVE-2026-20556: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20557: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| 🟠 high | CVE-2026-20558: In GPU pdma, there is a possible escalation of privilege due to use after free. | — | In GPU pdma, there is a possible escalation of privilege due to use after free. This could lead to local escalation of p |
| 🟠 high | CVE-2026-20559: In GPU pdma, there is a possible memory corruption due to use after free. | `T1203` | In GPU pdma, there is a possible memory corruption due to use after free. This could lead to local escalation of privile |
| 🟠 high | CVE-2026-20565: In Modem, there is a possible out of bounds write due to an incorrect bounds check. | — | In Modem, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation  |
| 🟠 high | CVE-2026-20585: In Modem, there is a possible out of bounds write due to a missing bounds check. | — | In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote escalation of |
| | _+144 more…_ | | |

## Insecure Deserialization (12)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-102435: The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to arbitrary fil… | `T1190` | The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient fi |
| 🔴 critical | CVE-2026-119516: Deserialization of Untrusted Data vulnerability in Mamunur Rashid Radius Booking — Book… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Mamunur Rashid Radius Booking — Booking Calendar for Appointments &am |
| 🟠 high | CVE-2026-120833: labbench before 0.46.1 contains a deserialization of untrusted data vulnerability in re… | `T1190`, `T1059.007` | labbench before 0.46.1 contains a deserialization of untrusted data vulnerability in read() and read_relational() that p |
| 🟠 high | CVE-2026-109408: vault-java-driver, a Java client for HashiCorp Vault, silently disables TLS certificate… | `T1059.007` | vault-java-driver, a Java client for HashiCorp Vault, silently disables TLS certificate and hostname verification in thr |
| 🟠 high | CVE-2026-102739: ESPectre is a Wi-Fi motion sensing platform for ESP32. | — | ESPectre is a Wi-Fi motion sensing platform for ESP32. Prior to 3.0.0-rc1, Micro-ESPectre analysis tools, including tool |
| 🟠 high | CVE-2026-120499: h5io before 0.2.6 contains a code injection vulnerability in read_hdf5() that allows at… | `T1190` | h5io before 0.2.6 contains a code injection vulnerability in read_hdf5() that allows attackers to execute arbitrary code |
| 🟠 high | CVE-2026-120859: PyMoDAQ before 4.4.13, and pymodaq_data, pymodaq_gui, and pymodaq_utils before 5.1.15, … | `T1190`, `T1059.007` | PyMoDAQ before 4.4.13, and pymodaq_data, pymodaq_gui, and pymodaq_utils before 5.1.15, 5.2.x before 5.2.14, and 5.3.x be |
| 🟠 high | CVE-2026-104010: The WPSyncSheets For Contact Form 7 – CF7 Google Sheets Connector & Save to Database pl… | `T1190` | The WPSyncSheets For Contact Form 7 – CF7 Google Sheets Connector & Save to Database plugin for WordPress is vulnerable  |
| 🟠 high | CVE-2026-87112: The QA Assistants – Driven by data plugin for WordPress is vulnerable to PHP Object Inj… | `T1190`, `T1059.007` | The QA Assistants – Driven by data plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and |
| 🟠 high | CVE-2026-104738: The Advanced Form Integration — Connect Forms to 300+ Apps plugin for WordPress is vuln… | `T1059.007` | The Advanced Form Integration — Connect Forms to 300+ Apps plugin for WordPress is vulnerable to PHP Object Injection in |
| 🟠 high | CVE-2026-124318: Treeio through 2.0 contains an insecure deserialization vulnerability in UpdateRecord.g… | `T1059.007` | Treeio through 2.0 contains an insecure deserialization vulnerability in UpdateRecord.get_format_strings and ModuleSetti |
| 🟠 high | CVE-2026-116499: IBM Qiskit SDK 1.4.2 through 2.6.2 could allow a local attacker to execute arbitrary co… | `T1190`, `T1059.007` | IBM Qiskit SDK 1.4.2 through 2.6.2 could allow a local attacker to execute arbitrary code due to deserialization of untr |

## Path Traversal & File Disclosure (67)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-120322: A vulnerability was identified in Termix-SSH Termix up to 2.9.2. | — | A vulnerability was identified in Termix-SSH Termix up to 2.9.2. This issue affects some unknown processing of the file  |
| 🔴 critical | CVE-2026-120213: @fastify/http-proxy is a Fastify plugin that proxies HTTP requests to an upstream serve… | — | @fastify/http-proxy is a Fastify plugin that proxies HTTP requests to an upstream server under a configured prefix. In v |
| 🔴 critical | CVE-2026-120518: The BuddyPress XProfile Image Field plugin for WordPress is vulnerable to arbitrary fil… | `T1190` | The BuddyPress XProfile Image Field plugin for WordPress is vulnerable to arbitrary file deletion in all versions up to, |
| 🔴 critical | CVE-2026-38600: A Zip Slip vulnerability in the /upload endpoint of codeskyblue gohttpserver through v1… | — | A Zip Slip vulnerability in the /upload endpoint of codeskyblue gohttpserver through v1.3.0 allows attackers to write ar |
| 🔴 critical | CVE-2026-122013: Comfast CF-WR632AX Multipart webmgnt path traversal | — | [VulnTracker digest] Comfast CF-WR632AX — Comfast CF-WR632AX Multipart webmgnt path traversal |
| 🔴 critical | CVE-2026-122311: Kyverno from 1.16.0 before 1.19.2 fails to validate path segments in the resource argum… | — | Kyverno from 1.16.0 before 1.19.2 fails to validate path segments in the resource argument of resource.get() and resourc |
| 🔴 critical | CVE-2026-71550: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🔴 critical | CVE-2026-121489: Apache Juneau: Path traversal in DirectoryResource allows reading files outside the con… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Path traversal in DirectoryResource allow |
| 🔴 critical | CVE-2026-114630: The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnera… | `T1190` | The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to arbitrary file deletion du |
| 🔴 critical | CVE-2026-17147: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17239: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | `T1190` | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to execute arbitrary code due to a |
| 🔴 critical | CVE-2026-17339: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to access or delete resources belo |
| 🔴 critical | CVE-2026-17340: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to execute arbi… | `T1190` | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to execute arbitrary code due to a path traversa |
| 🔴 critical | CVE-2026-17354: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to perform arbitrary file writes d |
| 🔴 critical | CVE-2026-121379: The Tournamatch WordPress plugin before 4.7.1 does not validate or restrict the path of… | — | The Tournamatch WordPress plugin before 4.7.1 does not validate or restrict the path of a previously stored profile or t |
| 🔴 critical | CVE-2026-124450: OpenEMR before 8.3.0 contains a broken access control and path traversal vulnerability … | `T1190` | OpenEMR before 8.3.0 contains a broken access control and path traversal vulnerability in the fax/sms module disposeDocu |
| 🔴 critical | CVE-2026-124490: OpenEMR before 8.3.0 contains a path traversal vulnerability in the RingCentral RCFaxCl… | — | OpenEMR before 8.3.0 contains a path traversal vulnerability in the RingCentral RCFaxClient disposeDocument() method of  |
| 🔴 critical | CVE-2026-107331: IBM DataStage on Cloud Pak for Data 5.4.0.0 could allow a remote authenticated attacker… | — | IBM DataStage on Cloud Pak for Data 5.4.0.0 could allow a remote authenticated attacker to obtain sensitive information  |
| 🔴 critical | CVE-2026-17466: IBM Optim 1.0.0, 1.1.0, and 1.2.0 could allow a remote authenticated attacker to obtain… | — | IBM Optim 1.0.0, 1.1.0, and 1.2.0 could allow a remote authenticated attacker to obtain sensitive information due to pat |
| 🟠 high | CVE-2026-120311: Network-AI from 5.13.4 before 5.15.5 contains a path traversal vulnerability in FileJob… | — | Network-AI from 5.13.4 before 5.15.5 contains a path traversal vulnerability in FileJobStore that allows attackers to re |
| 🟠 high | CVE-2026-120312: Network-AI from 5.13.4 before 5.15.5 contains a path traversal vulnerability in AgentVC… | — | Network-AI from 5.13.4 before 5.15.5 contains a path traversal vulnerability in AgentVCR that allows attackers controlli |
| 🟠 high | CVE-2026-120313: Network-AI before 5.15.5 contains a path traversal vulnerability in InputSanitizer.sani… | — | Network-AI before 5.15.5 contains a path traversal vulnerability in InputSanitizer.sanitizePath() that allows attackers  |
| 🟠 high | CVE-2026-120315: LobeHub Chat from 1.84.26 before 2.1.49 contains a path traversal vulnerability that al… | — | LobeHub Chat from 1.84.26 before 2.1.49 contains a path traversal vulnerability that allows authenticated users to write |
| 🟠 high | CVE-2026-120324: A weakness has been identified in Aklivity Zilla up to 1.3.4/2.4.7/2.5.0-rc2. | — | A weakness has been identified in Aklivity Zilla up to 1.3.4/2.4.7/2.5.0-rc2. The affected element is the function Path. |
| 🟠 high | CVE-2026-117518: @fastify/reply-from is a Fastify plugin that forwards requests to an upstream HTTP server. | — | @fastify/reply-from is a Fastify plugin that forwards requests to an upstream HTTP server. In versions up to and includi |
| 🟠 high | CVE-2026-120444: GoFound through 1.4.1 contains a path traversal vulnerability that allows unauthenticat… | — | GoFound through 1.4.1 contains a path traversal vulnerability that allows unauthenticated attackers to delete arbitrary  |
| 🟠 high | CVE-2026-73695: Control Web Panel (CWP) before webpanel_version 1.16 contains a path traversal vulnerab… | — | Control Web Panel (CWP) before webpanel_version 1.16 contains a path traversal vulnerability in services/users/index.php |
| 🟠 high | CVE-2026-81938: Grafana Mimir's Alertmanager rejects tenant-supplied receiver configurations that refer… | — | Grafana Mimir's Alertmanager rejects tenant-supplied receiver configurations that reference local files, but the check d |
| 🟠 high | CVE-2026-120559: The Contact Form Extender for Divi Builder plugin for WordPress is vulnerable to Arbitr… | `T1190` | The Contact Form Extender for Divi Builder plugin for WordPress is vulnerable to Arbitrary File Deletion due to insuffic |
| 🟠 high | CVE-2026-120577: The FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler plugin for WordPre… | `T1190` | The FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler plugin for WordPress is vulnerable to arbitrary fil |
| 🟠 high | CVE-2026-121448: Dockhand before 1.0.54 contains a path traversal vulnerability that allows authenticate… | — | Dockhand before 1.0.54 contains a path traversal vulnerability that allows authenticated users to read, overwrite, and d |
| 🟠 high | CVE-2026-115294: Improper Limitation of a Pathname to a Restricted Directory (CWE-22) in the Kibana Flee… | — | Improper Limitation of a Pathname to a Restricted Directory (CWE-22) in the Kibana Fleet feature can lead to unauthorize |
| 🟠 high | CVE-2026-63395: isomorphic-git is a pure JavaScript implementation of Git for Node.js and browsers. | — | isomorphic-git is a pure JavaScript implementation of Git for Node.js and browsers. Prior to 1.38.6, isomorphic-git's gi |
| 🟠 high | CVE-2026-63500: Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intell… | — | Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intelligence platform and pipeline. Pri |
| 🟠 high | CVE-2026-63502: Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intell… | — | Yeti bridges the gap between CTI and DFIR practitioners by providing a Forensics Intelligence platform and pipeline. Pri |
| 🟠 high | CVE-2026-95742: An arbitrary file write vulnerability exists in the underlying operating system of HPE … | — | An arbitrary file write vulnerability exists in the underlying operating system of HPE Networking Fabric Composer. Succe |
| 🟠 high | CVE-2026-116617: The Motors – Car Dealership & Classified Listings Plugin plugin for WordPress is vulner… | — | The Motors – Car Dealership & Classified Listings Plugin plugin for WordPress is vulnerable to File Deletion in all vers |
| 🟠 high | CVE-2026-104720: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerab… | — | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Kobikom Telecommunicatio |
| 🟠 high | CVE-2026-102523: MariaDB server is a community developed fork of MySQL server. | — | MariaDB server is a community developed fork of MySQL server. From 10.11.1 until 10.11.19, 11.4.13, 11.8.9, 12.3.3, and  |
| 🟠 high | CVE-2026-119083: Path traversal in the archive extraction utility in GluonTS before 0.17.0 might allow a… | — | Path traversal in the archive extraction utility in GluonTS before 0.17.0 might allow an actor who supplies a crafted ta |
| 🟠 high | CVE-2026-63213: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-77604: Code Graph RAG is an AI-powered knowledge graph and retrieval system for querying, unde… | — | Code Graph RAG is an AI-powered knowledge graph and retrieval system for querying, understanding, and editing multi-lang |
| 🟠 high | CVE-2026-87008: Code Graph RAG is an AI-powered knowledge graph and retrieval system for querying, unde… | — | Code Graph RAG is an AI-powered knowledge graph and retrieval system for querying, understanding, and editing multi-lang |
| 🟠 high | CVE-2026-118045: The Ever Accounting  WordPress plugin before 2.3.3 does not restrict the file path supp… | — | The Ever Accounting  WordPress plugin before 2.3.3 does not restrict the file path supplied to its CSV import routine to |
| 🟠 high | CVE-2026-123305: In JetBrains IntelliJ IDEA before 2026.3 path traversal was possible via unpacking Dev … | — | In JetBrains IntelliJ IDEA before 2026.3 path traversal was possible via unpacking Dev Container archives from a remote  |
| 🟠 high | CVE-2026-123621: Usermin through 2.570 contains a path traversal vulnerability in mailbox/detachall.cgi … | — | Usermin through 2.570 contains a path traversal vulnerability in mailbox/detachall.cgi that allows remote unauthenticate |
| 🟠 high | CVE-2026-53980: Charmbracelet wish before 2.0.5 contains a path traversal vulnerability in the git midd… | — | Charmbracelet wish before 2.0.5 contains a path traversal vulnerability in the git middleware (charm.land/wish/v2) that  |
| 🟠 high | CVE-2026-123842: In JetBrains IntelliJ IDEA before 2026.3 arbitrary file write was possible via symlinks… | — | In JetBrains IntelliJ IDEA before 2026.3 arbitrary file write was possible via symlinks when extracting plugin archives |
| 🟠 high | CVE-2026-102359: Kroki creates diagrams from textual descriptions. | — | Kroki creates diagrams from textual descriptions. Prior to 0.31.2, the TikZ backend's tikz/tikz2svg guard used when KROK |
| 🟠 high | CVE-2026-102657: esm.sh is a no-build content delivery network (CDN) for web development. | — | esm.sh is a no-build content delivery network (CDN) for web development. Prior to server version 137_7, the documented w |
| | _+17 more…_ | | |

## SSRF, CSRF & Open Redirect (67)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-73117: Apache Juneau: Response header CRLF injection and open redirect when applications set h… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Response header CRLF injection and open r |
| 🔴 critical | CVE-2026-73099: Apache Juneau: Cross-site request forgery via default-enabled content query-parameter b… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Cross-site request forgery via default-en |
| 🔴 critical | CVE-2026-71495: Wanderer is a self-hosted trail database for saving and sharing adventures. | — | Wanderer is a self-hosted trail database for saving and sharing adventures. Prior to 0.20.0, when PUBLIC_PRIVATE_INSTANC |
| 🔴 critical | CVE-2026-86044: JupyterLab Desktop is the cross-platform desktop application for JupyterLab. | `T1190` | JupyterLab Desktop is the cross-platform desktop application for JupyterLab. Prior to 4.6.2-1, JupyterLab Desktop expose |
| 🔴 critical | CVE-2026-68935: Chartbrew is an open-source web application for creating charts from databases and APIs. | — | Chartbrew is an open-source web application for creating charts from databases and APIs. In versions 4.8.5 through 5.2.2 |
| 🔴 critical | CVE-2026-16918: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to access interna |
| 🔴 critical | CVE-2026-17131: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to server-si |
| 🔴 critical | CVE-2026-17296: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17297: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to perform an acc |
| 🔴 critical | CVE-2026-17298: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17299: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17329: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to improper  |
| 🔴 critical | CVE-2026-17344: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to server-si |
| 🔴 critical | CVE-2026-17353: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information an |
| 🔴 critical | CVE-2026-18836: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensiti |
| 🟠 high | CVE-2026-88809: A security vulnerability exists in the SUSE Rancher Manager meta proxy endpoint (/meta/… | — | A security vulnerability exists in the SUSE Rancher Manager meta proxy endpoint (/meta/proxy). This endpoint is intended |
| 🟠 high | CVE-2026-97718: CSRF in Secure Access Server v14.60 | — | [cvefeed.io] CSRF in Secure Access Server v14.60 |
| 🟠 high | CVE-2026-121451: AB Download Manager before 1.11.2 contains a cross-site request forgery vulnerability i… | — | AB Download Manager before 1.11.2 contains a cross-site request forgery vulnerability in its unauthenticated browser-int |
| 🟠 high | CVE-2026-121561: Label Studio before 1.23.2 (label-studio-sdk before 2.1.2) contains a server-side reque… | — | Label Studio before 1.23.2 (label-studio-sdk before 2.1.2) contains a server-side request forgery vulnerability that all |
| 🟠 high | CVE-2026-57566: Readest: Unauthenticated SSRF / open request proxy in /api/opds/proxy | — | [cvefeed.io] Readest: Unauthenticated SSRF / open request proxy in /api/opds/proxy |
| 🟠 high | CVE-2026-61649: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-69137: SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) sof… | — | SuiteCRM is an open-source, enterprise-ready Customer Relationship Management (CRM) software application. Prior to 7.15. |
| 🟠 high | CVE-2026-103938: OpenEMR is a free and open source electronic health records and medical practice manage… | — | OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.3.0, |
| 🟠 high | CVE-2026-88980: Kubeflow Pipelines enables users to build and deploy portable, scalable machine learnin… | — | Kubeflow Pipelines enables users to build and deploy portable, scalable machine learning workflows. Prior to 2.18.0, the |
| 🟠 high | CVE-2026-88981: Kubeflow Pipelines enables users to build and deploy portable, scalable machine learnin… | — | Kubeflow Pipelines enables users to build and deploy portable, scalable machine learning workflows. Prior to 2.18.0, the |
| 🟠 high | CVE-2026-119431: A server-side request forgery (SSRF) vulnerability exists in Foxit Workspace's file-upl… | — | A server-side request forgery (SSRF) vulnerability exists in Foxit Workspace's file-upload functionality. Insufficient v |
| 🟠 high | CVE-2026-119433: A server-side request forgery (SSRF) vulnerability exists in an undocumented API endpoi… | — | A server-side request forgery (SSRF) vulnerability exists in an undocumented API endpoint of Foxit Workspace due to insu |
| 🟠 high | CVE-2026-123786: Agenta before 0.122.5 contains a server-side request forgery vulnerability that allows … | — | Agenta before 0.122.5 contains a server-side request forgery vulnerability that allows workspace members with workflow e |
| 🟠 high | CVE-2026-58141: Dify before 1.15.0 contains a server-side request forgery vulnerability that allows any… | — | Dify before 1.15.0 contains a server-side request forgery vulnerability that allows any authenticated console user to by |
| 🟠 high | CVE-2026-85743: FreeScout is a self-hosted help desk and shared mailbox. | — | FreeScout is a self-hosted help desk and shared mailbox. Prior to 1.8.230, multiple outbound paths in Helper::downloadRe |
| 🟠 high | CVE-2026-16912: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17108: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17187: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17188: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17228: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17281: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17285: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17287: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17288: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17289: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17291: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17294: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-17316: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to perform serv… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to perform server-side request forgery due to im |
| 🟠 high | CVE-2026-17325: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17327: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17328: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17330: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17341: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to perform serv… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to perform server-side request forgery and relay |
| 🟠 high | CVE-2026-17352: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information du |
| 🟠 high | CVE-2026-17355: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information fr |
| | _+17 more…_ | | |

## Cryptographic Weaknesses (6)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-95731: Hardcoded password vulnerabilities in the command-line interface of HPE Networking Fabr… | — | Hardcoded password vulnerabilities in the command-line interface of HPE Networking Fabric Composer could allow an unauth |
| 🔴 critical | CVE-2026-17360: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to gain full ad… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to gain full administrative control due to the u |
| 🔴 critical | CVE-2026-17403: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to gain full admi |
| 🟠 high | CVE-2026-54374: VitaFit Android &lt; 2.8.1.0 Hardcoded Credentials Disclosure | — | [cvefeed.io] VitaFit Android &lt; 2.8.1.0 Hardcoded Credentials Disclosure |
| 🟠 high | CVE-2026-19877: INFINITT ULite 5.0.2.1_BN48_20260528 and earlier protects image-share links with a low-… | — | INFINITT ULite 5.0.2.1_BN48_20260528 and earlier protects image-share links with a low-entropy password and does not res |
| 🟠 high | CVE-2026-17356: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a local attacker to obtain sensit… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a local attacker to obtain sensitive information due to the use of |

## Information Disclosure (10)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-88811: Missing filtering in the SUSE Rancher Manager meta proxy could cause passed in rancher … | — | Missing filtering in the SUSE Rancher Manager meta proxy could cause passed in rancher credentials to be leaked to cloud |
| 🔴 critical | CVE-2026-119757: BTCPay Server before 2.4.2, including 2.4.2 release candidates, contains an information… | — | BTCPay Server before 2.4.2, including 2.4.2 release candidates, contains an information disclosure vulnerability that al |
| 🔴 critical | CVE-2026-123551: OpenAM from 14.0.0 before 16.1.4 contains an information disclosure vulnerability that … | — | OpenAM from 14.0.0 before 16.1.4 contains an information disclosure vulnerability that allows unauthenticated attackers  |
| 🟠 high | CVE-2026-105475: cPanel NUL Byte Injection Information Disclosure | — | [cvefeed.io] cPanel NUL Byte Injection Information Disclosure |
| 🟠 high | CVE-2026-82976: A flaw was found in the image-customization-controller used in OpenShift's bare metal p… | — | A flaw was found in the image-customization-controller used in OpenShift's bare metal provisioning stack. The controller |
| 🟠 high | CVE-2026-95734: A sensitive information disclosure vulnerability in the API of HPE Networking Fabric Co… | — | A sensitive information disclosure vulnerability in the API of HPE Networking Fabric Composer could allow an authenticat |
| 🟠 high | CVE-2026-95744: A sensitive information disclosure vulnerability in the affected interface of HPE Netwo… | — | A sensitive information disclosure vulnerability in the affected interface of HPE Networking Fabric Composer could allow |
| 🟠 high | CVE-2026-54381: VitaFit Cloud API Storage Bucket Unauthenticated Access Information Disclosure | — | [cvefeed.io] VitaFit Cloud API Storage Bucket Unauthenticated Access Information Disclosure |
| 🟠 high | CVE-2026-119499: Insertion of Sensitive Information Into Sent Data vulnerability in BAKKBONE Australia F… | — | Insertion of Sensitive Information Into Sent Data vulnerability in BAKKBONE Australia FloristPress bakkbone-florist-comp |
| 🟠 high | CVE-2026-17322: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a local attacker to obtain sensitiv |

## Denial of Service (60)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-18535: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable… | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to a Regular Expression Denial o |
| 🟠 high | CVE-2026-101186: DoS vulnerability in the window module. | — | DoS vulnerability in the window module.
Impact: Successful exploitation of this vulnerability may affect availability. |
| 🟠 high | CVE-2026-120596: A remotely exploitable denial-of-service vulnerability exists in the TCP options parser… | — | A remotely exploitable denial-of-service vulnerability exists in the TCP options parser of the Nut/Net TCP/IP stack incl |
| 🟠 high | CVE-2026-121386: FreeRDP before 3.32.2 contains a denial of service vulnerability in WinPR's winpr_read_… | — | FreeRDP before 3.32.2 contains a denial of service vulnerability in WinPR's winpr_read_png_from_buffer() and winpr_conve |
| 🟠 high | CVE-2026-121437: Mistune from 3.3.0 before 3.3.4 contains a denial of service vulnerability that allows … | — | Mistune from 3.3.0 before 3.3.4 contains a denial of service vulnerability that allows remote attackers to exhaust CPU t |
| 🟠 high | CVE-2026-121444: svg-sanitizer from 0.11.0 before 1.1.0 contains an algorithmic complexity denial of ser… | — | svg-sanitizer from 0.11.0 before 1.1.0 contains an algorithmic complexity denial of service vulnerability in hasInfinite |
| 🟠 high | CVE-2026-121512: Memory Leak with Amplification in µD3TN BPv6 EID Reference Handling allows Unauthentica… | — | Memory Leak with Amplification in µD3TN BPv6 EID Reference Handling allows Unauthenticated Remote Attacker to Cause DoS |
| 🟠 high | CVE-2026-118487: In Eclipse Vert.x versions [4.0.0, 4.5.35] or [5.0.0, 5.2.2], the `FrameParser` in vert… | — | In Eclipse Vert.x versions [4.0.0, 4.5.35] or [5.0.0, 5.2.2], the `FrameParser` in vertx-stomp creates a `RecordParser`  |
| 🟠 high | CVE-2026-119741: rsync through 3.5.1 contains a denial of service vulnerability in the delta-transfer se… | — | rsync through 3.5.1 contains a denial of service vulnerability in the delta-transfer sender's hash_search() in match.c t |
| 🟠 high | CVE-2026-115290: Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to denial of service via Ser… | — | Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to denial of service via Serialized Data with Nested Payloads |
| 🟠 high | CVE-2026-120678: A memory management flaw in the MongoDB C Driver's handling of compressed responses may… | — | A memory management flaw in the MongoDB C Driver's handling of compressed responses may cause the client library to hold |
| 🟠 high | CVE-2026-57154: OPNsense is a FreeBSD based firewall and routing platform. | — | OPNsense is a FreeBSD based firewall and routing platform. Prior to 26.1.11 and 26.4.1p1, authenticated Web UI or API us |
| 🟠 high | CVE-2026-63501: ag-psd is a JavaScript library for reading and writing Photoshop Document files. | — | ag-psd is a JavaScript library for reading and writing Photoshop Document files. Prior to 31.0.3, readPsd() accepts a to |
| 🟠 high | CVE-2026-95745: A vulnerability in the API of HPE Networking Fabric Composer could allow an unauthentic… | — | A vulnerability in the API of HPE Networking Fabric Composer could allow an unauthenticated remote attacker to conduct a |
| 🟠 high | CVE-2026-121092: Uncontrolled recursion in SVG in Google Chrome prior to 157.0.8103.38 allowed a remote … | `T1190` | Uncontrolled recursion in SVG in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute a |
| 🟠 high | CVE-2026-13271: IBM MQ Managed File Transfer is affected by a denial of service vulnerability | — | [cvefeed.io] IBM MQ Managed File Transfer is affected by a denial of service vulnerability |
| 🟠 high | CVE-2026-122305: Kyverno before 1.19.2 contains a denial of service vulnerability in substituteVariables… | — | Kyverno before 1.19.2 contains a denial of service vulnerability in substituteVariablesIfAny that allows low-privileged  |
| 🟠 high | CVE-2026-122306: Kyverno before 1.19.2 contains a denial of service vulnerability that allows namespaced… | — | Kyverno before 1.19.2 contains a denial of service vulnerability that allows namespaced policy authors to exhaust admiss |
| 🟠 high | CVE-2026-122314: Kyverno before 1.19.2 contains an unchecked type assertion in its variable-substitution… | — | Kyverno before 1.19.2 contains an unchecked type assertion in its variable-substitution engine that allows users who can |
| 🟠 high | CVE-2026-122322: Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability in … | — | Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability in extractStatement that allows remo |
| 🟠 high | CVE-2026-122323: Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability in … | — | Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability in FetchSignatureBlob that allows at |
| 🟠 high | CVE-2026-107123: A flaw was found in the SAML XML processing component of Keycloak, an open-source ident… | — | A flaw was found in the SAML XML processing component of Keycloak, an open-source identity and access management solutio |
| 🟠 high | CVE-2026-107602: A flaw was found in the SAML 1.1 XML parsing logic of Keycloak, an open-source identity… | — | A flaw was found in the SAML 1.1 XML parsing logic of Keycloak, an open-source identity and access management solution.  |
| 🟠 high | CVE-2026-110931: A flaw was found in the SAML 1.1 assertion parser of Keycloak, a tool used for identity… | — | A flaw was found in the SAML 1.1 assertion parser of Keycloak, a tool used for identity and access management. The issue |
| 🟠 high | CVE-2026-110932: A flaw was found in the theme resource endpoint of Keycloak, an open-source identity an… | — | A flaw was found in the theme resource endpoint of Keycloak, an open-source identity and access management solution. The |
| 🟠 high | CVE-2026-121996: A length validation flaw in gdbserver's agent-expression parser allows an unauthenticat… | — | A length validation flaw in gdbserver's agent-expression parser allows an unauthenticated remote attacker to read uninit |
| 🟠 high | CVE-2026-82965: A flaw was found in the SAML implementation of Keycloak, an open-source identity and ac… | — | A flaw was found in the SAML implementation of Keycloak, an open-source identity and access management solution. The SAM |
| 🟠 high | CVE-2026-111768: The Model Context Protocol TypeScript SDK provides TypeScript client and server impleme… | — | The Model Context Protocol TypeScript SDK provides TypeScript client and server implementations of the Model Context Pro |
| 🟠 high | CVE-2026-77622: Sliver: Unauthenticated Memory Exhaustion Denial of Service in Sliver HTTP(S) Listener … | — | [cvefeed.io] Sliver: Unauthenticated Memory Exhaustion Denial of Service in Sliver HTTP(S) Listener PNG Decoder |
| 🟠 high | CVE-2026-77299: Regexp2 is a feature-rich RegExp engine for Go. | — | Regexp2 is a feature-rich RegExp engine for Go. Prior to version 2.3.0, when regexp2 compiles and matches a pattern cont |
| 🟠 high | CVE-2026-102650: Nuxt Content is the file-based CMS for Nuxt applications, powered by Markdown and Vue c… | — | Nuxt Content is the file-based CMS for Nuxt applications, powered by Markdown and Vue components. From 3.0.0 until 3.15. |
| 🟠 high | CVE-2026-123356: GROBID is machine learning software for extracting information from scholarly documents. | — | GROBID is machine learning software for extracting information from scholarly documents. Prior to 0.9.1, the unauthentic |
| 🟠 high | CVE-2026-124078: plist.js (npm package 'plist') before 5.0.1 contains an uncontrolled resource consumpti… | — | plist.js (npm package 'plist') before 5.0.1 contains an uncontrolled resource consumption vulnerability in the binary pr |
| 🟠 high | CVE-2026-17279: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🟠 high | CVE-2026-123531: Vikunja from 1.0.0 before 2.7.1 contains an uncontrolled resource consumption vulnerabi… | — | Vikunja from 1.0.0 before 2.7.1 contains an uncontrolled resource consumption vulnerability that allows authenticated us |
| 🟠 high | CVE-2026-123543: OpenAM before 16.1.4 contains a denial of service vulnerability that allows unauthentic… | — | OpenAM before 16.1.4 contains a denial of service vulnerability that allows unauthenticated attackers to exhaust server  |
| 🟠 high | CVE-2026-123555: Zebra from 2.3.0 before 7.0.0 contains a denial of service vulnerability that allows un… | — | Zebra from 2.3.0 before 7.0.0 contains a denial of service vulnerability that allows unauthenticated peers to evade misb |
| 🟠 high | CVE-2026-123558: Zebra zebrad before 7.0.0 contains a denial of service vulnerability that allows a mali… | — | Zebra zebrad before 7.0.0 contains a denial of service vulnerability that allows a malicious peer to stall checkpoint sy |
| 🟠 high | CVE-2026-123563: Devalue before 5.9.3 contains a validation bypass vulnerability that allows custom Arra… | — | Devalue before 5.9.3 contains a validation bypass vulnerability that allows custom ArrayBuffer revivers to skip typed-ar |
| 🟠 high | CVE-2026-123564: Sveltejs devalue from 1.0.0 before 5.9.3 contains a memory exhaustion flaw in uneval, w… | — | Sveltejs devalue from 1.0.0 before 5.9.3 contains a memory exhaustion flaw in uneval, whose generated code for sparse ar |
| 🟠 high | CVE-2026-123565: Sveltejs devalue before 5.9.3 contains a resource exhaustion vulnerability where repeat… | — | Sveltejs devalue before 5.9.3 contains a resource exhaustion vulnerability where repeated primitive strings cause quadra |
| 🟠 high | CVE-2026-123566: Sveltejs devalue before 5.9.3 contains a denial of service vulnerability that allows at… | — | Sveltejs devalue before 5.9.3 contains a denial of service vulnerability that allows attackers to cause CPU amplificatio |
| 🟠 high | CVE-2026-123569: The devalue package for npm before 5.6.3 can consume excessive CPU and memory when seri… | — | The devalue package for npm before 5.6.3 can consume excessive CPU and memory when serializing sparse arrays with uneval |
| 🟠 high | CVE-2026-123570: The DNS wire-format message parser in hickory-proto (Hickory DNS) 0.18 before 0.26.2 pr… | — | The DNS wire-format message parser in hickory-proto (Hickory DNS) 0.18 before 0.26.2 preallocates record vectors sized b |
| 🟠 high | CVE-2026-123572: Hickory-dns from 0.20.1 before 0.26.2 contains a denial of service vulnerability in the… | — | Hickory-dns from 0.20.1 before 0.26.2 contains a denial of service vulnerability in the hickory-proto SVCB and HTTPS rec |
| 🟠 high | CVE-2026-123573: hickory-dns from 0.20.1 before 0.26.2 contains a denial of service vulnerability in the… | — | hickory-dns from 0.20.1 before 0.26.2 contains a denial of service vulnerability in the hickory-proto SVCB and HTTPS rec |
| 🟠 high | CVE-2026-123574: The zone file parser in the hickory-proto crate of Hickory DNS 0.24.0 before 0.26.2 pan… | — | The zone file parser in the hickory-proto crate of Hickory DNS 0.24.0 before 0.26.2 panics when a single token in a zone |
| 🟠 high | CVE-2026-123575: Hickory DNS before 0.26.2 contains a resource exhaustion vulnerability in its DNS-over-… | — | Hickory DNS before 0.26.2 contains a resource exhaustion vulnerability in its DNS-over-HTTPS HTTP/2 server that lacks su |
| 🟠 high | CVE-2026-123576: Hickory DNS 0.24.0 through 0.26.1 contains a memory exhaustion vulnerability that allow… | — | Hickory DNS 0.24.0 through 0.26.1 contains a memory exhaustion vulnerability that allows remote attackers to consume ser |
| 🟠 high | CVE-2026-123577: Hickory DNS from 0.24.0 before 0.26.2 contains a resource exhaustion vulnerability that… | — | Hickory DNS from 0.24.0 before 0.26.2 contains a resource exhaustion vulnerability that allows remote attackers to consu |
| | _+10 more…_ | | |

## Network Infrastructure & IoT Device Vulnerabilities (7)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-109593: An unauthenticated attacker with network access to the SonicWall GMS 9.5.2 and earlier … | — | An unauthenticated attacker with network access to the SonicWall GMS 9.5.2 and earlier versions may be able to read inte |
| 🔴 critical | CVE-2026-112354: Etrel INCH AC charging station management web interface prior to firmware versions 7.1.… | — | Etrel INCH AC charging station management web interface prior to firmware versions 7.1.2 and 8.0.1 contains a hard-coded |
| 🔴 critical | CVE-2026-121609: Qihoo 360 Whole Home Router M5 Boot Script mpt start hard-coded credentials | — | [VulnTracker digest] Qihoo 360 Whole Home Router M5 — Qihoo 360 Whole Home Router M5 Boot Script mpt start hard-coded cr |
| 🔴 critical | CVE-2026-121606: Qihoo 360 D621-2/D603-2/D600-2/D619/D606-6/D706 Firmware Signature Verification iscm ve… | — | [VulnTracker digest] Qihoo 360 D621-2 — Qihoo 360 D621-2/D603-2/D600-2/D619/D606-6/D706 Firmware Signature Verification  |
| 🟠 high | CVE-2026-104269: ModSecurity is an open source, cross platform web application firewall (WAF) engine for… | — | ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx. From 3.0. |
| 🟠 high | CVE-2026-73856: ModSecurity is an open source, cross platform web application firewall (WAF) engine for… | — | ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx. From 3.0. |
| 🟠 high | CVE-2026-19868: SonicWall SonicOS SSLVPN — SonicWall SonicOS SSLVPN Use of Single-factor Authentication Vulnerability | — | An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alt |

## Social Engineering & Phishing (2)

_Active phishing campaigns, lures, and social-engineering tradecraft._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-121200: Incorrect reference resolution in DevTools in Google Chrome prior to 157.0.8103.38 allo… | `T1190` | Incorrect reference resolution in DevTools in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging  |
| 🟠 high | CVE-2026-121168: Improper resource exposure in DevTools in Google Chrome prior to 157.0.8103.38 allowed … | `T1190` | Improper resource exposure in DevTools in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging soci |

## Critical-Severity Vulnerabilities (32)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2025-11969: The System REST APIs do not correctly enforce access control mechanisms, allowing users… | — | The System REST APIs do not correctly enforce access control mechanisms, allowing users with lower privilege roles to ex |
| 🔴 critical | CVE-2026-73696: Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redire… | — | Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redirect vulnerability in the user pane |
| 🔴 critical | CVE-2026-105769: kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure R… | — | kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure Resource Manager to an attacker-co |
| 🔴 critical | CVE-2026-13594: Zoho Corporation's ManageEngine Log360 and EventLog Analyzer versions 13062 and below a… | — | Zoho Corporation's ManageEngine Log360 and EventLog Analyzer versions 13062 and below are vulnerable to an issue that co |
| 🔴 critical | CVE-2026-95733: A vulnerability exists in a component of HPE Networking Fabric Composer. | `T1190` | A vulnerability exists in a component of HPE Networking Fabric Composer. Successful exploitation could allow an unauthen |
| 🔴 critical | CVE-2026-121615: Linksys E5600 Login mesh_login.cgi improper authentication | — | [VulnTracker digest] Linksys E5600 — Linksys E5600 Login mesh_login.cgi improper authentication |
| 🔴 critical | CVE-2026-122310: Kyverno from 1.19.1 before 1.19.2 validates a Policy's context.apiCall urlPath after cl… | — | Kyverno from 1.19.1 before 1.19.2 validates a Policy's context.apiCall urlPath after cleaning it but executes the raw pa |
| 🔴 critical | CVE-2026-122321: Kyverno 1.18.0 before 1.19.2 contains a signature verification bypass in verifyImages b… | — | Kyverno 1.18.0 before 1.19.2 contains a signature verification bypass in verifyImages because cached verification result |
| 🔴 critical | CVE-2026-117691: A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak. | — | A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak. The issue occurs because the server proce |
| 🔴 critical | CVE-2026-46350: dcmjs is a JavaScript implementation of DICOM manipulation. | — | dcmjs is a JavaScript implementation of DICOM manipulation. Prior to 0.52.0, the DecimalString and IntegerString impleme |
| 🔴 critical | CVE-2026-48705: MONAI (Medical Open Network for AI) is an AI toolkit for health care imaging. | — | MONAI (Medical Open Network for AI) is an AI toolkit for health care imaging. Prior to 1.6.1, PydicomReader._get_affine( |
| 🔴 critical | CVE-2026-73116: Apache Juneau: REST client forwards credentials to a different origin when following HT… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: REST client forwards credentials to a dif |
| 🔴 critical | CVE-2026-73101: Apache Juneau: Internal exception class and message disclosed via error response header… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Internal exception class and message disc |
| 🔴 critical | CVE-2026-73100: Apache Juneau: Sensitive request headers logged in cleartext by the default request log… | — | [VulnTracker digest] Apache Software Foundation Apache Juneau — Apache Juneau: Sensitive request headers logged in clear |
| 🔴 critical | CVE-2026-83493: A flaw was found in distributed-workloads. | — | A flaw was found in distributed-workloads. A remote attacker could exploit a vulnerability in the pull_request_target wo |
| 🔴 critical | CVE-2026-59105: Jumis (formerly Tildes Jumis) creates and uses a Microsoft SQL Server login named ##Til… | — | Jumis (formerly Tildes Jumis) creates and uses a Microsoft SQL Server login named ##Tilde_JumisAdmin## whose password is |
| 🔴 critical | CVE-2026-123831: In JetBrains CLion before 2026.2, 
2026.1.4 code execution was possible in Safe Mode vi… | — | In JetBrains CLion before 2026.2, 
2026.1.4 code execution was possible in Safe Mode via Meson project settings |
| 🔴 critical | CVE-2026-123832: In JetBrains CLion before 2026.2 code execution was possible in Safe Mode via JSON comp… | — | In JetBrains CLion before 2026.2 code execution was possible in Safe Mode via JSON compilation database |
| 🔴 critical | CVE-2026-58490: Tracecat is an open-source security automation platform for teams and AI agents. | — | Tracecat is an open-source security automation platform for teams and AI agents. From version 0.37.0 until 1.0.0-beta.49 |
| 🔴 critical | CVE-2026-85295: Chartbrew is an open-source web application that can connect directly to databases and … | — | Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create c |
| 🔴 critical | CVE-2026-16884: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensi… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to an XML ex |
| 🔴 critical | CVE-2026-16920: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker t… | — | IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to bypass security restrictions du |
| 🔴 critical | CVE-2026-17117: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17150: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17301: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow an… | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow an unauthenticated attacker to bypa |
| 🔴 critical | CVE-2026-17392: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17394: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17399: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | `T1190` | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to  |
| 🔴 critical | CVE-2026-17409: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a … | — | IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to execute unauth |
| 🔴 critical | CVE-2026-124440: Kyverno from 1.19.1 before 1.19.2 contains an authorization bypass vulnerability in the… | — | Kyverno from 1.19.1 before 1.19.2 contains an authorization bypass vulnerability in the apiCall namespace clamp that all |
| 🔴 critical | CVE-2026-124445: OpenEMR from 7.0.1 before 8.4.0 contains a flaw in src/Common/Auth/OneTimeAuth.php that… | — | OpenEMR from 7.0.1 before 8.4.0 contains a flaw in src/Common/Auth/OneTimeAuth.php that ignores the enforce_onetime_use  |
| 🔴 critical | CVE-2026-101117: IBM WebSphere Extreme Scale 8.6.1.0 through 8.6.2.2 could allow a remote attacker to by… | — | IBM WebSphere Extreme Scale 8.6.1.0 through 8.6.2.2 could allow a remote attacker to bypass security restrictions due to |

## High-Severity Vulnerabilities (187)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-120341: A security vulnerability has been detected in mathurvishal CloudClassroom-PHP-Project. | — | A security vulnerability has been detected in mathurvishal CloudClassroom-PHP-Project. Impacted is an unknown function o |
| 🟠 high | CVE-2026-101176: Permission control vulnerability in the event notification management module. | — | Permission control vulnerability in the event notification management module.
Impact: Successful exploitation of this vu |
| 🟠 high | CVE-2026-120448: DoraCMS through 3.1.0 contains a mass assignment vulnerability in the PUT /api/v1/user/… | — | DoraCMS through 3.1.0 contains a mass assignment vulnerability in the PUT /api/v1/user/api-keys/:id endpoint that allows |
| 🟠 high | CVE-2026-109140: The vulnerability is that Krill encrypts every login-session token with a nonce built f… | — | The vulnerability is that Krill encrypts every login-session token with a nonce built from a counter that is reset to 0  |
| 🟠 high | CVE-2026-99218: In the Linux kernel, the following vulnerability has been resolved:

coredump: hold RCU… | — | In the Linux kernel, the following vulnerability has been resolved:

coredump: hold RCU while releasing parked threads

 |
| 🟠 high | CVE-2026-99224: In the Linux kernel, the following vulnerability has been resolved:

keys: Protect the … | — | In the Linux kernel, the following vulnerability has been resolved:

keys: Protect the type name while describing a key
 |
| 🟠 high | CVE-2026-99227: In the Linux kernel, the following vulnerability has been resolved:

io_uring/waitid: p… | — | In the Linux kernel, the following vulnerability has been resolved:

io_uring/waitid: prevent cancel reference wrap

io_ |
| 🟠 high | CVE-2026-99233: In the Linux kernel, the following vulnerability has been resolved:

tracing/histograms… | — | In the Linux kernel, the following vulnerability has been resolved:

tracing/histograms: Verify event_call identity when |
| 🟠 high | CVE-2026-99236: In the Linux kernel, the following vulnerability has been resolved:

tracing: Reject in… | — | In the Linux kernel, the following vulnerability has been resolved:

tracing: Reject incomplete event filter expressions |
| 🟠 high | CVE-2026-99237: In the Linux kernel, the following vulnerability has been resolved:

tracing: Hold trac… | — | In the Linux kernel, the following vulnerability has been resolved:

tracing: Hold trace_types_lock when resetting last  |
| 🟠 high | CVE-2026-99238: In the Linux kernel, the following vulnerability has been resolved:

tracing: Hold trac… | — | In the Linux kernel, the following vulnerability has been resolved:

tracing: Hold trace_types_lock when updating module |
| 🟠 high | CVE-2026-99239: In the Linux kernel, the following vulnerability has been resolved:

Bluetooth: L2CAP: … | — | In the Linux kernel, the following vulnerability has been resolved:

Bluetooth: L2CAP: refuse __l2cap_chan_add if chan a |
| 🟠 high | CVE-2026-119736: Attendo (formerly Petpooja Payroll) Admin Android application version 3.0.13 and earlie… | — | Attendo (formerly Petpooja Payroll) Admin Android application version 3.0.13 and earlier contains a hard-coded credentia |
| 🟠 high | CVE-2026-28588: In shouldBlockDirectoryFromTree of ExternalStorageProvider.java, there is a possible wa… | — | In shouldBlockDirectoryFromTree of ExternalStorageProvider.java, there is a possible way to access protected data due to |
| 🟠 high | CVE-2026-28597: In writeGrantedUriPermissions of UriGrantsManagerService.java, there is a possible perm… | — | In writeGrantedUriPermissions of UriGrantsManagerService.java, there is a possible permission bypass due to improper inp |
| 🟠 high | CVE-2026-45514: In multiple functions of SaveUi.java, there is a possible bypass of package installatio… | — | In multiple functions of SaveUi.java, there is a possible bypass of package installation requirements due to a logic err |
| 🟠 high | CVE-2026-49922: In queryRemoteConnectionServices of ConnectionServiceWrapper.java, there is a possible … | — | In queryRemoteConnectionServices of ConnectionServiceWrapper.java, there is a possible permission bypass due to a confus |
| 🟠 high | CVE-2026-49923: In onResult of AccountManagerService.java, there is a possible untrusted/misleading UI … | — | In onResult of AccountManagerService.java, there is a possible untrusted/misleading UI issue due to a logic error in the |
| 🟠 high | CVE-2026-49931: In onActivityResult in multiple locations, there is a possible contact leak from protec… | — | In onActivityResult in multiple locations, there is a possible contact leak from protected profile due to a confused dep |
| 🟠 high | CVE-2026-55257: In UsbDialogHelper of UsbDialogHelper.java, there is a possible UI confusion due to mis… | — | In UsbDialogHelper of UsbDialogHelper.java, there is a possible UI confusion due to misleading or insufficient UI. This  |
| 🟠 high | CVE-2026-55262: In setNotificationListenerAccessGrantedForUserInternal of NotificationManagerService.ja… | — | In setNotificationListenerAccessGrantedForUserInternal of NotificationManagerService.java, there is a possible  policy d |
| 🟠 high | CVE-2026-55271: In forwardToPreferredActionPickHandler of ContactsPickerActivity.kt, there is a possibl… | — | In forwardToPreferredActionPickHandler of ContactsPickerActivity.kt, there is a possible intent redirection due to a con |
| 🟠 high | CVE-2026-55287: In onCreate of GrantCredentialsPermissionActivity.java, there is a possible way to tric… | — | In onCreate of GrantCredentialsPermissionActivity.java, there is a possible way to trick the user into granting account  |
| 🟠 high | CVE-2026-55289: In multiple functions in multiple locations, there is a possible execution of sensitive… | — | In multiple functions in multiple locations, there is a possible execution of sensitive USSD codes due to a confused dep |
| 🟠 high | CVE-2026-58836: In handlePackagePostInstall of InstallPackageHelper.java, there is a possible Enhanced … | — | In handlePackagePostInstall of InstallPackageHelper.java, there is a possible Enhanced Confirmation Mode (ECM) bypass vu |
| 🟠 high | CVE-2026-58837: In multiple locations, there is a possible background activity launch due to a logic er… | — | In multiple locations, there is a possible background activity launch due to a logic error in the code. This could lead  |
| 🟠 high | CVE-2026-58884: In startTetheredHotspotRequest of WifiServiceImpl.java, there is a possible permission … | — | In startTetheredHotspotRequest of WifiServiceImpl.java, there is a possible permission bypass due to a confused deputy.  |
| 🟠 high | CVE-2026-58885: In multiple locations, there is a possible permission bypass due to a confused deputy. | — | In multiple locations, there is a possible permission bypass due to a confused deputy. This could lead to local escalati |
| 🟠 high | CVE-2026-58934: In prepareWindowToDisplayDuringRelayout of WindowState.java, there is a possible permis… | — | In prepareWindowToDisplayDuringRelayout of WindowState.java, there is a possible permission bypass due to a logic error  |
| 🟠 high | CVE-2026-58943: In run of AddAccountSettings.java, there is a possible background activity launch due t… | — | In run of AddAccountSettings.java, there is a possible background activity launch due to a confused deputy. This could l |
| 🟠 high | CVE-2026-58944: In moveTaskToFrontLocked of ActivityTaskManagerService.java, there is a possible backgr… | — | In moveTaskToFrontLocked of ActivityTaskManagerService.java, there is a possible background application launch (bal) iss |
| 🟠 high | CVE-2026-58946: In navigateUpTo of ActivityClientController.java, there is a possible permission bypass… | — | In navigateUpTo of ActivityClientController.java, there is a possible permission bypass due to a logic error in the code |
| 🟠 high | CVE-2026-58957: In resolveToHeavyWeightSwitcherIfNeeded of ActivityStarter.java, there is a possible ba… | — | In resolveToHeavyWeightSwitcherIfNeeded of ActivityStarter.java, there is a possible background activity launch due to a |
| 🟠 high | CVE-2026-58965: In handleAudioEffectBroadcast of MusicFxHelper.java, there is a possible permission byp… | — | In handleAudioEffectBroadcast of MusicFxHelper.java, there is a possible permission bypass due to a confused deputy. Thi |
| 🟠 high | CVE-2026-58970: In deliverResult of AppTimeTracker.java, there is a possible background activity launch… | — | In deliverResult of AppTimeTracker.java, there is a possible background activity launch due to a confused deputy. This c |
| 🟠 high | CVE-2026-59000: In multiple locations, there is a possible permission bypass due to a confused deputy. | — | In multiple locations, there is a possible permission bypass due to a confused deputy. This could lead to local escalati |
| 🟠 high | CVE-2026-59028: In resolveAidConflictLocked of RegisteredAidCache.java, there is a possible permission … | — | In resolveAidConflictLocked of RegisteredAidCache.java, there is a possible permission bypass due to a confused deputy.  |
| 🟠 high | CVE-2026-91895: Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Incorrect… | — | Dell Alienware Command Center (AWCC), versions prior to 6.14.54.0, contain an Incorrect Default Permissions vulnerabilit |
| 🟠 high | CVE-2026-120091: Temporal Server Kubernetes compute provider builds a client from caller-supplied config… | — | [cvefeed.io] Temporal Server Kubernetes compute provider builds a client from caller-supplied configuration and runs a c |
| 🟠 high | CVE-2026-115215: NetX Secure DTLS server allocates a session for each new source before the cookie excha… | — | [cvefeed.io] NetX Secure DTLS server allocates a session for each new source before the cookie exchange and never reclai |
| 🟠 high | CVE-2026-116766: Improper input handling in Secure Access server | — | [cvefeed.io] Improper input handling in Secure Access server |
| 🟠 high | pyprig (pypi) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-11-02. Review versio |
| 🟠 high | CVE-2026-121022: Use of Default Password (CWE-1393) in the web client in AxxonSoft Axxon One before 3.0.… | — | Use of Default Password (CWE-1393) in the web client in AxxonSoft Axxon One before 3.0.0 on Windows and Linux allows a r |
| 🟠 high | CVE-2026-77778: ZohoCorp ManageEngine Key Manager Plus versions up to 7150 allow authenticated users to… | — | ZohoCorp ManageEngine Key Manager Plus versions up to 7150 allow authenticated users to export certificates belonging to |
| 🟠 high | CVE-2026-99264: In the Linux kernel, the following vulnerability has been resolved:

io_uring/net: don'… | — | In the Linux kernel, the following vulnerability has been resolved:

io_uring/net: don't retry recv on uncommitted buffe |
| 🟠 high | CVE-2026-99269: In the Linux kernel, the following vulnerability has been resolved:

sched_ext: Wait fo… | — | In the Linux kernel, the following vulnerability has been resolved:

sched_ext: Wait for SCX_OPSS_DISPATCHING before mov |
| 🟠 high | CVE-2026-99270: In the Linux kernel, the following vulnerability has been resolved:

tcp: Fix potential… | — | In the Linux kernel, the following vulnerability has been resolved:

tcp: Fix potential UAF in reqsk_timer_handler().

W |
| 🟠 high | CVE-2026-119179: A flaw in the connection management layer of the MongoDB Node.js driver can leave a poo… | — | A flaw in the connection management layer of the MongoDB Node.js driver can leave a pooled network connection in the poo |
| 🟠 high | CVE-2026-106991: hustoj >=24.09.10 and <=26.08.19 is vulnerable to Incorrect Access Control. | — | hustoj >=24.09.10 and <=26.08.19 is vulnerable to Incorrect Access Control. Any registered user can delete, lock, or sti |
| 🟠 high | CVE-2026-121392: FreeRDP before 3.32.2 contains an improper certificate validation vulnerability in tls_… | — | FreeRDP before 3.32.2 contains an improper certificate validation vulnerability in tls_verify_certificate() that accepts |
| | _+137 more…_ | | |

## Other Vulnerabilities (2)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-119977: WordPress WordPress Core — WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability | — | WordPress WordPress Core contains a time-of-check time-of-use (TOCTOU) race condition vulnerability that could allow una |
| ⚪ unknown | CVE-2024-27834: Apple Multiple Products — Apple Multiple Products Improper Authentication Vulnerability | — | Apple iOS, iPadOS, macOS, Safari, tvOS and watchOS 10.5 contain an improper authentication vulnerability which could all |

## Ransomware activity (ransomware.live + peers) (472)

_Victim claims rolled up from the 7 daily briefings covering this window. Most active groups: thegentlemen (50), n0n (49), akira (39)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | [DISCLOSED]Namibian Defence Force — claimed by ransomhouse | — | [DISCLOSED]Namibian Defence Force listed by ransomhouse. |
| 🟠 high | [DISCLOSED]Pertamina — claimed by ransomhouse | — | [DISCLOSED]Pertamina listed by ransomhouse. |
| 🟠 high | Academy of the Sacred Heart — claimed by thegentlemen | — | ashrosary.org Academy of the Sacred Heart is a private Catholic all-girls school in New Orleans founded in 1867, educati |
| 🟠 high | Airdrie Christian Academy — claimed by thegentlemen | — | airdriechristian.com Airdrie Christian Academy is a private K-12 Christian school founded in 1987 in Airdrie, Alberta, w |
| 🟠 high | Antwerp House Dental — claimed by thegentlemen | — | antwerphousedentistry.co.uk Antwerp House Dental Practice is a premium private dental clinic in Cambridge, England, foun |
| 🟠 high | Astino Berhad — claimed by qilin | — | Building Materials |
| 🟠 high | Ateşsan Ambalaj — claimed by hyflock (TR) | — | Ateşsan Ambalaj A.Ş. (Ateşsan Oluklu Mukavva) is a long-established, industry-leading manufacturer of corrugated boxes a |
| 🟠 high | Ateşsan Ambalaj leaks — claimed by hyflock | — | Ateşsan Ambalaj A.Ş. (Ateşsan Oluklu Mukavva) is a long-established, industry-leading manufacturer of corrugated boxes a |
| 🟠 high | Barking Shopfronts — claimed by thegentlemen | — | bsfgroup.co.uk Barkingshopfronts Limited is a London-based shop front manufacturer and installer founded in 2018 in Bark |
| 🟠 high | Coemi Imóveis — claimed by thegentlemen | — | coemi.com.br Coemi Imóveis is a Brazilian real estate agency founded in 1985 in Brasília with 41 years of experience in  |
| 🟠 high | Company #113 — claimed by n0n | — | storage and organization retail · United States |
| 🟠 high | Company #114 — claimed by n0n | — | biopharmaceutical · United States |
| 🟠 high | Company #115 — claimed by n0n | — | digital sports entertainment and gaming · United States |
| 🟠 high | Company #116 — claimed by n0n | — | data collaboration and identity resolution · United States |
| 🟠 high | Company #117 — claimed by n0n | — | dental insurance · United States |
| 🟠 high | Customs Support — claimed by thegentlemen | — | customssupport.com Revenue $389.4 Million IZD GmbH Europe's largest customs brokerage network, founded with headquarters |
| 🟠 high | da***t.com — claimed by everstake | — | Category: Logistics \| Size: 473.05 Gb \| Release: 2026-11-12T15:23:00+00:00 \| Status: Scheduled |
| 🟠 high | daHidden namet.com — claimed by everstake | — | daHidden namet.com listed by everstake. |
| 🟠 high | deom.be — claimed by safepay | — | The company specializes in the distribution, installation, customization and maintenance of lifting equipment, truck-mou |
| 🟠 high | European Motorcars — claimed by thegentlemen | — | european-motorcars.com European Motorcars is a multi-brand premium European car dealership founded in 1972 in Dayton, Oh |
| 🟠 high | Five Star Plating — claimed by thegentlemen | — | fivestarplating.com Five Star Plating LLC is an American electroplating and metal finishing company founded in 2007 in L |
| 🟠 high | Grupo Lorrio — claimed by thegentlemen | — | grupolorrio.es Grupo Lorrio is a Spanish industrial engineering and construction group founded in 1989 in San Fernando d |
| 🟠 high | Harry's International — claimed by orova | — | Harry’s is Singapore’s largest collection of everyday bars and kitchens - a homegrown destination where people from all  |
| 🟠 high | Hausarztpraxis Ries — claimed by thegentlemen | — | hausarzt-praxis-ries.de Hausarztpraxis Ries is a family general practice in Frickenhausen, Baden-Württemberg, Germany, r |
| 🟠 high | HighTec — claimed by thegentlemen | — | hightec.ch HighTec AG is a Swiss industrial engineering company founded in 1988 in Winterthur, specializing in turnkey s |
| 🟠 high | Holland & Knight — claimed by redact | — | Revenue: $2B USD \| Sector: Law Firm \| Data Size: 29.7 GB \| Files: 11,156 |
| 🟠 high | Howells Motor Freight — claimed by akira | — | Howell's Motor Freight, established in 1957, specializes in refrigerated, frozen, and dry transport and distribution ser |
| 🟠 high | Hydrogel Vision Corporation — claimed by orova | — | Hydrogel Vision Corp. based in Sarasota, Florida was founded in May 2002 as an independent subsidiary of Benz Research a |
| 🟠 high | Indiana Area School District — claimed by interlock | — | https://www.iasd.cc/
									A school district in Indiana, Pennsylvania (approximately 2,800 students) is required to p |
| 🟠 high | insurancehouse.com — claimed by settra (GB) | — | Inside: quarterly and annual operational reports from the claims division (Claims Operations, QCS, S… |
| 🟠 high | Isapre Consalud — claimed by qilin | — | Insurance |
| 🟠 high | Jerome School District — claimed by interlock | — | https://www.jeromeschools.org/
									Jerome School District 261 is a public school district located in Jerome, Idaho  |
| 🟠 high | KABS Pharmaceutical Services — claimed by thegentlemen | — | kabs.com Revenue $27.2 Million KABS Laboratories is a Canadian pharmaceutical CDMO founded in 1997 in Saint-Hubert, Queb |
| 🟠 high | kingdomtitle.net — claimed by settra (GB) | — | 1. 06/26/2026: an incoming book transfer of &#036;15,319,440 and an outgoing wire on file 20260084C of &#036;1… |
| 🟠 high | Labatec — claimed by thegentlemen | — | labatecpharma.com Revenue $19 Million Labatec S.A. is a Swiss laboratory instruments company founded in 1965 in Meyrin,  |
| 🟠 high | Lighting Direct — claimed by thegentlemen | — | lightingdirect.co.nz Lighting Direct is New Zealand's largest lighting specialist, founded in 1974 in Auckland by Bill a |
| 🟠 high | Logsytech Group — claimed by thegentlemen | — | logsytech.fr Logsytech Group is a French logistics holding company based in Émerainville near Paris, founded in 2001 and |
| 🟠 high | mackinengineering.com — claimed by settra (US) | — | In March 2025, Mackin Engineering recorded journal entry JE3767 for &#036;2,373,675.44 — roughly 90% of t… |
| 🟠 high | MARDEC Berhad — claimed by orova | — | MARDEC Berhad (formerly known as the Malaysian Rubber Development Corporation or MRDC) was established on 20th September |
| 🟠 high | McEwan Fraser Legal — claimed by thegentlemen | — | mcewanfraserlegal.co.uk McEwan Fraser Legal is Scotland's largest property law firm and award-winning estate agency, fou |
| 🟠 high | MegChem — claimed by thegentlemen | — | megchem.com MegChem is a South African engineering consultancy founded in 1985 in Secunda, Mpumalanga, providing process |
| 🟠 high | Michigan State University — claimed by byod | — | [PSA] Full Personal Identifiable Information for 1.03 million current and ex students as well as the full team in relati |
| 🟠 high | Mitsubishi Motors Ukraine — claimed by thegentlemen | — | itsubishi-motors.com.ua Mitsubishi Motors Ukraine is the official importer and distributor of Mitsubishi Motors vehicles |
| 🟠 high | Neighborhood House Association — claimed by thegentlemen | — | neighborhoodhouse.org Revenue $238.7 Million Neighborhood House is Portland's oldest nonprofit social services organizat |
| 🟠 high | Neiman & Company, Inc. — claimed by pear | — | Architectural signage for clients including hotels, corporate offices, universities, hospitals, and museums in Southern  |
| 🟠 high | Pages Asociados — claimed by thegentlemen | — | pages.com.ve Pages Asociados C.A. is a Venezuelan engineering and consulting firm founded in 1972 in Caracas with over 5 |
| 🟠 high | Princeton Management — claimed by akira | — | Princeton Management offers a range of residential and commercial properties, emphasizing quality and competitive pricin |
| 🟠 high | ra***g.com — claimed by everstake | — | Category: Manufacturing \| Size: 582.69 Gb \| Release: 2026-11-10T15:10:00+00:00 \| Status: Scheduled |
| 🟠 high | Raffles United Holdings Pte Ltd — claimed by orova | — | Kian Ho Singapore(“KHS”), is a wholly-owned subsidiary of Raffles United Holdings Pte Ltd (“RUH”) formerly known as Kian |
| 🟠 high | RedBlink Technologies — claimed by thegentlemen | — | redblink.com RedBlink Technologies is an AI and software development company founded in 2008 in Danville, California, wi |
| | _+422 more…_ | | |

---
Sources: CISA KEV, NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, URLhaus, MalwareBazaar, ThreatFox
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203, T1566

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W45)*