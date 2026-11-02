# Weekly Threat Briefing — 2026-10-26 – 2026-11-01

> **weekly** · 2026-10-26 – 2026-11-01 · Generated 2026-11-02 00:45 UTC

## Executive Summary

This week (2026-10-26 – 2026-11-01), CISA added 9 new KEV entries and 993 additional high/critical CVEs were published (NVD, cvefeed.io, MyThreatIntel), including 204 critical-severity affecting PHP Group, Ivanti, WAVLINK. Active threat indicators across AI Honeypot Observatory, URLhaus, MalwareBazaar, and ThreatFox — 18,833 unique after cross-source dedup; all 18833 indicators (8101 malware-distribution URLs, 4378 malicious domains, 1606 suspicious IPs, 4748 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 1369 |
| CVEs | 1002 |
| KEVs | 9 |
| IOCs | 18833 |
| Critical | 204 |
| High | 789 |
| Ransomware victims | 367 |

## Critical Remote Code Execution Vulnerabilities (76)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-115188: An unrestricted file upload vulnerability exists in the campaign import feature of Maut… | `T1190` | An unrestricted file upload vulnerability exists in the campaign import feature of Mautic 7. When processing an uploaded |
| 🔴 critical | CVE-2026-112346: OpenHands Software Agent SDK before 1.52.0 contains an unauthenticated remote code exec… | `T1190` | OpenHands Software Agent SDK before 1.52.0 contains an unauthenticated remote code execution vulnerability where the Doc |
| 🔴 critical | CVE-2026-104351: Adobe Campaign Classic (ACC) is affected by an Improper Control of Generation of Code (… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability t |
| 🔴 critical | CVE-2026-48360: Adobe Connect is affected by an Improper Control of Generation of Code ('Code Injection… | `T1190` | Adobe Connect is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability that could resul |
| 🔴 critical | CVE-2026-116692: MLflow is an open source AI engineering platform for agents, large language models, and… | `T1059.007` | MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. From 3. |
| 🔴 critical | CVE-2026-58256: GRR is a resource management and reservation application. | `T1190` | GRR is a resource management and reservation application. Prior to the advisory-reported fixed version 4.5.0, an adminis |
| 🔴 critical | CVE-2026-84999: The Pie Register Premium plugin for WordPress is vulnerable to Unrestricted File Type U… | `T1190` | The Pie Register Premium plugin for WordPress is vulnerable to Unrestricted File Type Upload in all versions up to, and  |
| 🔴 critical | CVE-2026-103688: The Checkout Files Upload for WooCommerce WordPress plugin before 2.4.0 does not valida… | `T1190` | The Checkout Files Upload for WooCommerce WordPress plugin before 2.4.0 does not validate uploaded file types when its a |
| 🔴 critical | CVE-2026-109218: The Contact Manager plugin for WordPress is vulnerable to Arbitrary File Upload in all … | `T1190` | The Contact Manager plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 9. |
| 🔴 critical | CVE-2026-67074: HCL BigFix AEX is affected by a Remote Code Execution Vulnerability . | `T1190` | HCL BigFix AEX is affected by a Remote Code Execution Vulnerability . It may allow attackers to execute code with the pr |
| 🔴 critical | CVE-2026-44179: XWiki Remote Macros provides XWiki rendering macros that are useful when migrating cont… | `T1190` | XWiki Remote Macros provides XWiki rendering macros that are useful when migrating content from Confluence. From 1.13 un |
| 🔴 critical | CVE-2026-61564: AVideo is a video-sharing Platform. | — | AVideo is a video-sharing Platform. Prior to 8.1.0, the unauthenticated installer endpoint `install/checkConfiguration.p |
| 🔴 critical | CVE-2026-42922: A authorization bypass vulnerability exists in the /nodered functionality of FUXA (vers… | `T1190` | A authorization bypass vulnerability exists in the /nodered functionality of FUXA (version(s): 1.3.2-2809). A specially  |
| 🔴 critical | CVE-2026-115245: The Chat AI with Dispatcher WordPress plugin before 2.4 does not properly validate uplo… | `T1190` | The Chat AI with Dispatcher WordPress plugin before 2.4 does not properly validate uploaded files, relying only on a spo |
| 🔴 critical | CVE-2026-104339: IBM Langflow OSS 1.0.0 through 1.12.3 could allow a remote attacker to execute arbitrar… | `T1190`, `T1059` | IBM Langflow OSS 1.0.0 through 1.12.3 could allow a remote attacker to execute arbitrary code due to improper neutraliza |
| 🔴 critical | CVE-2026-107328: IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to ex… | `T1190` | IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to impro |
| 🔴 critical | CVE-2026-107329: IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to ex… | `T1190` | IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to impro |
| 🔴 critical | CVE-2026-110186: IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to execute arbitrar… | `T1190` | IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to execute arbitrary code due to improper control of |
| 🔴 critical | CVE-2026-61991: Unauthenticated Remote Code Execution (RCE) in AjaxLoadMore Cache <= 3.1.1 versions. | `T1190` | Unauthenticated Remote Code Execution (RCE) in AjaxLoadMore Cache <= 3.1.1 versions. |
| 🔴 critical | CVE-2026-61645: Docat is a tool for hosting versioned static documentation. | `T1190`, `T1059.007` | Docat is a tool for hosting versioned static documentation. In the affected implementation, an arbitrary file upload vul |
| 🔴 critical | CVE-2026-61707: SOCFortress CoPilot focuses on providing a single pane of glass for all your security o… | — | SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. Prior to 0.1.76, |
| 🔴 critical | CVE-2026-116852: Author Remote Code Execution (RCE) in Widget Options <= 4.2.5 versions. | `T1190` | Author Remote Code Execution (RCE) in Widget Options <= 4.2.5 versions. |
| 🔴 critical | CVE-2026-62853: ThingLinks is an enterprise IoT platform. | — | ThingLinks is an enterprise IoT platform. Prior to 1.4.0, the `/groovyScriptTest/registerScript` endpoint accepts user-s |
| 🔴 critical | CVE-2026-116512: The Project Manager – AI Powered Project Management, Task Management, Kanban Board & Ti… | `T1190` | The Project Manager – AI Powered Project Management, Task Management, Kanban Board & Time Tracker plugin for WordPress i |
| 🔴 critical | CVE-2026-118235: The SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications p… | `T1190` | The SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications plugin for WordPress is vulnerable |
| 🔴 critical | CVE-2026-120338: Prefab UI's Generative UI sandbox runs caller-supplied Python inside Pyodide, Python co… | — | Prefab UI's Generative UI sandbox runs caller-supplied Python inside Pyodide, Python compiled to WebAssembly, in a Deno  |
| 🟠 high | CVE-2026-113345: Electronic delivery item Inspection Support System provided by Japan's Ministry of Land… | `T1190` | Electronic delivery item Inspection Support System provided by Japan's Ministry of Land, Infrastructure, Transport and T |
| 🟠 high | CVE-2026-116253: A vulnerability was determined in DedeCMS 5.7.118. | — | A vulnerability was determined in DedeCMS 5.7.118. This vulnerability affects the function common.inc.php::_RunMagicQuot |
| 🟠 high | CVE-2026-115189: A server-side template injection vulnerability exists in the Twig theme rendering sandb… | `T1190` | A server-side template injection vulnerability exists in the Twig theme rendering sandbox of Mautic. The sandbox introdu |
| 🟠 high | CVE-2026-116612: A flaw was found in GStreamer Editing Services (gst-editing-services). | — | A flaw was found in GStreamer Editing Services (gst-editing-services). A GES project file can embed an arbitrary GStream |
| 🟠 high | CVE-2026-116811: OpenPanel before 3.0.0 contains a sandbox escape vulnerability in the js-runtime valida… | `T1190` | OpenPanel before 3.0.0 contains a sandbox escape vulnerability in the js-runtime validator that allows a project member  |
| 🟠 high | CVE-2026-116843: Mistral Vibe before 3.0.3 contains a remote code execution vulnerability that allows at… | `T1190` | Mistral Vibe before 3.0.3 contains a remote code execution vulnerability that allows attackers to run commands by defini |
| 🟠 high | CVE-2026-117602: Electrum 4.6.0 before 4.7.2 contains an authorization bypass in the external plugin loa… | `T1190` | Electrum 4.6.0 before 4.7.2 contains an authorization bypass in the external plugin loader, which executes a plugin's __ |
| 🟠 high | CVE-2026-92377: Improper access control in the Patch
Management update mechanism of TeamViewer Full Cli… | `T1190` | Improper access control in the Patch
Management update mechanism of TeamViewer Full Client and Host for Windows
prior to |
| 🟠 high | CVE-2026-104349: Creative Cloud Desktop is affected by an Uncontrolled Search Path Element vulnerability… | `T1190` | Creative Cloud Desktop is affected by an Uncontrolled Search Path Element vulnerability that could result in arbitrary c |
| 🟠 high | CVE-2026-117607: Xerte Online Toolkits through 3.15.5 contains a remote code execution vulnerability tha… | `T1190` | Xerte Online Toolkits through 3.15.5 contains a remote code execution vulnerability that allows authenticated users with |
| 🟠 high | CVE-2026-111255: The affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display plugin for Wor… | `T1190` | The affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display plugin for WordPress is vulnerable to Arbitrary |
| 🟠 high | CVE-2026-109384: The The Innovative Form Builder – IvyForms plugin for WordPress is vulnerable to Arbitr… | `T1190` | The The Innovative Form Builder – IvyForms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions u |
| 🟠 high | CVE-2026-118606: Alpine iLX-F511 Framework Service Exposed Dangerous Function Remote Code Execution Vuln… | `T1190` | Alpine iLX-F511 Framework Service Exposed Dangerous Function Remote Code Execution Vulnerability. This vulnerability all |
| 🟠 high | CVE-2026-118614: Ultralytics check_det_dataset Code Injection Remote Code Execution Vulnerability. | `T1190` | Ultralytics check_det_dataset Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attac |
| 🟠 high | CVE-2026-118616: Ultralytics parse_model Code Injection Remote Code Execution Vulnerability. | `T1190` | Ultralytics parse_model Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers t |
| 🟠 high | CVE-2026-118618: Ultralytics parse_model Code Injection Remote Code Execution Vulnerability. | `T1190` | Ultralytics parse_model Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers t |
| 🟠 high | CVE-2026-118683: MONAI from 1.2.0 before 1.6.1 contains a remote code execution vulnerability in ConfigW… | `T1190` | MONAI from 1.2.0 before 1.6.1 contains a remote code execution vulnerability in ConfigWorkflow.__init__, which passes a  |
| 🟠 high | CVE-2026-118803: Bricks Theme 2.4.3 and before contains an unauthenticated dynamic-data tag injection vu… | — | Bricks Theme 2.4.3 and before contains an unauthenticated dynamic-data tag injection vulnerability that allows anonymous |
| 🟠 high | CVE-2026-54453: OpenCATS is an open-source applicant tracking system and recruitment CRM for staffing a… | — | OpenCATS is an open-source applicant tracking system and recruitment CRM for staffing agencies and hiring teams. Prior t |
| 🟠 high | CVE-2026-115301: The Contact Form by Supsystic  WordPress plugin before 1.11.1 does not sandbox the temp… | `T1190` | The Contact Form by Supsystic  WordPress plugin before 1.11.1 does not sandbox the template engine used to render its fo |
| 🟠 high | CVE-2026-118905: Node Version Manager (nvm) is a POSIX-compliant shell function for managing multiple no… | — | Node Version Manager (nvm) is a POSIX-compliant shell function for managing multiple node.js versions. In versions 0.31. |
| 🟠 high | CVE-2026-103665: The installer for Yamaha LAN Monitor for Windows provided by Yamaha Corporation may ins… | `T1190` | The installer for Yamaha LAN Monitor for Windows provided by Yamaha Corporation may insecurely load Dynamic Link Librari |
| 🟠 high | CVE-2026-119027: oapi-codegen 2.5.0 before 2.8.1 contains a code injection vulnerability that allows att… | — | oapi-codegen 2.5.0 before 2.8.1 contains a code injection vulnerability that allows attackers to inject Go code by suppl |
| 🟠 high | CVE-2026-119028: oapi-codegen 2.0.0 before 2.8.1 contains a code injection vulnerability that allows att… | — | oapi-codegen 2.0.0 before 2.8.1 contains a code injection vulnerability that allows attackers to inject Go code by suppl |
| | _+26 more…_ | | |

## Command Injection (80)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-59106: A security vulnerability has been identified in the WolfProt interface implementation. | — | A security vulnerability has been identified in the WolfProt interface implementation. Insufficient neutralization of us |
| 🔴 critical | CVE-2026-65184: The root-privileged `wsserver` terminal-bridge daemon builds a shell command from clien… | — | The root-privileged `wsserver` terminal-bridge daemon builds a shell command from client-supplied WebSocket fields and p |
| 🔴 critical | CVE-2026-116504: A vulnerability has been found in TOTOLINK A950RG 4.1.2cu.5268_B20221104. | `T1059` | A vulnerability has been found in TOTOLINK A950RG 4.1.2cu.5268_B20221104. This affects the function setCloudUpgradeFW of |
| 🔴 critical | CVE-2026-116505: A vulnerability was found in TOTOLINK A950RG 4.1.2cu.5268_B20221104. | `T1059` | A vulnerability was found in TOTOLINK A950RG 4.1.2cu.5268_B20221104. This impacts the function getDeviceInfo of the file |
| 🔴 critical | CVE-2026-116506: A vulnerability was determined in TOTOLINK A950RG 4.1.2cu.5268_B20221104. | `T1059` | A vulnerability was determined in TOTOLINK A950RG 4.1.2cu.5268_B20221104. Affected is the function apmib_set of the file |
| 🔴 critical | CVE-2026-82119: OS Command Injection Vulnerability in HiRDB. | `T1059` | OS Command Injection Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-12-01; H |
| 🔴 critical | CVE-2026-104353: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Eleme… | `T1190`, `T1059` | Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an OS Command ('OS Co |
| 🔴 critical | CVE-2026-114278: The che-machine-exec service constructs a shell command by concatenating user-controlle… | `T1190` | The che-machine-exec service constructs a shell command by concatenating user-controlled input (the username and namespa |
| 🔴 critical | CVE-2026-118477: The ei_git_repo_url parameter in the Git remote configuration endpoint of KaliFast is v… | `T1059` | The ei_git_repo_url parameter in the Git remote configuration endpoint of KaliFast is vulnerable to OS Command Injection |
| 🔴 critical | CVE-2026-115904: Topluyo is a social networking platform. | `T1059` | Topluyo is a social networking platform. A vulnerability exists in Topluyo Desktop for Linux prior to version 2026.9.241 |
| 🔴 critical | CVE-2026-103406: An Improper Neutralization of Special Elements used in an OS Command vulnerability in t… | `T1059` | An Improper Neutralization of Special Elements used in an OS Command vulnerability in the AutomatedProvisioner in Junipe |
| 🔴 critical | CVE-2026-61567: AVideo is a video-sharing Platform. | — | AVideo is a video-sharing Platform. Prior to 8.1.0, the live-streaming endpoint `view/videosListToLive.php` accepts an a |
| 🔴 critical | CVE-2026-97854: Yamaha wireless LAN router NWR100 provided by Yamaha Corporation contains an OS command… | `T1059` | Yamaha wireless LAN router NWR100 provided by Yamaha Corporation contains an OS command injection vulnerability. Arbitra |
| 🔴 critical | CVE-2026-90865: An OS command injection vulnerability in Progress Software WS_FTP Server versions prior… | `T1059` | An OS command injection vulnerability in Progress Software WS_FTP Server versions prior to 2024.0.7 and 2025.0.4 on Wind |
| 🔴 critical | CVE-2026-90868: An OS command injection vulnerability in Progress Software WS_FTP Server versions prior… | `T1059` | An OS command injection vulnerability in Progress Software WS_FTP Server versions prior to 2024.0.7 and 2025.0.4 on Wind |
| 🔴 critical | CVE-2025-31704: A vulnerability has been found in the Dahua Intelligent Connection Center. | `T1190` | A vulnerability has been found in the Dahua Intelligent Connection Center. A remote attacker could send a specially craf |
| 🔴 critical | CVE-2026-116241: pgAdmin 4's Import/Export Data tool wraps a user's query export in a psql \copy (...) T… | — | pgAdmin 4's Import/Export Data tool wraps a user's query export in a psql \copy (...) TO command and checks that the que |
| 🔴 critical | CVE-2026-120195: A security vulnerability has been detected in WAVLINK WL-WN579A3-A 2026-03-10-94f93d4. | `T1059` | A security vulnerability has been detected in WAVLINK WL-WN579A3-A 2026-03-10-94f93d4. The impacted element is the funct |
| 🔴 critical | CVE-2026-120196: A vulnerability was detected in WAVLINK WN579X3-D V250402. | `T1059` | A vulnerability was detected in WAVLINK WN579X3-D V250402. This affects the function port_forward of the file /cgi-bin/w |
| 🔴 critical | CVE-2026-120197: A flaw has been found in WAVLINK WL-WN530HG4B M_V260724. | `T1059` | A flaw has been found in WAVLINK WL-WN530HG4B M_V260724. This impacts the function port_forward of the file /cgi-bin/wap |
| 🔴 critical | CVE-2026-120198: A vulnerability has been found in WAVLINK WL-WN530BE1-A V251117. | `T1059` | A vulnerability has been found in WAVLINK WL-WN530BE1-A V251117. Affected is the function con_check_read_finish of the f |
| 🔴 critical | CVE-2026-120227: A vulnerability was detected in WAVLINK WN701AE M01AE_V260105. | `T1059` | A vulnerability was detected in WAVLINK WN701AE M01AE_V260105. This affects the function del_staticrule of the file stat |
| 🔴 critical | CVE-2026-120228: A flaw has been found in WAVLINK WN553X1-B V260403_2.0.0. | `T1059` | A flaw has been found in WAVLINK WN553X1-B V260403_2.0.0. This vulnerability affects the function sub_416D88 of the file |
| 🔴 critical | CVE-2026-120229: A vulnerability has been found in WAVLINK WN553X1-B 260403_2.0.0. | `T1059` | A vulnerability has been found in WAVLINK WN553X1-B 260403_2.0.0. This issue affects the function sub_416B50 of the file |
| 🔴 critical | CVE-2026-120230: A vulnerability was found in WAVLINK WN701AE 260105. | `T1059` | A vulnerability was found in WAVLINK WN701AE 260105. Impacted is the function del_vlan_group of the component ioos Web B |
| 🔴 critical | CVE-2026-120231: A vulnerability was determined in WAVLINK WN553X1-B V260403_2.0.0. | `T1059` | A vulnerability was determined in WAVLINK WN553X1-B V260403_2.0.0. The affected element is the function sub_416568 of th |
| 🔴 critical | CVE-2026-120238: A vulnerability has been found in WAVLINK WN553X1-B 260403_2.0.0. | `T1059` | A vulnerability has been found in WAVLINK WN553X1-B 260403_2.0.0. This affects the function sub_4162A8 of the file /bin/ |
| 🔴 critical | CVE-2026-120239: A vulnerability was found in WAVLINK WN553X1-B V260403_2.0.0. | `T1059` | A vulnerability was found in WAVLINK WN553X1-B V260403_2.0.0. This vulnerability affects the function sub_419DA8 of the  |
| 🔴 critical | CVE-2026-120240: A vulnerability was determined in WAVLINK WN553X1-B V260403_2.0.0. | `T1059` | A vulnerability was determined in WAVLINK WN553X1-B V260403_2.0.0. This issue affects the function sub_41A748 of the fil |
| 🔴 critical | CVE-2026-120277: WAVLINK WN536AX6-A WireGuard CLI Group ioos sub_41a1d8 os command injection | `T1059` | [VulnTracker digest] WAVLINK WN536AX6-A — WAVLINK WN536AX6-A WireGuard CLI Group ioos sub_41a1d8 os command injection |
| 🔴 critical | CVE-2026-120276: WAVLINK WN536AX6-A Web Management ioos sub_416760 os command injection | `T1059` | [VulnTracker digest] WAVLINK WN536AX6-A — WAVLINK WN536AX6-A Web Management ioos sub_416760 os command injection |
| 🟠 high | CVE-2026-116219: Dolibarr ERP CRM before 24.0.0 contains an OS command injection vulnerability in htdocs… | `T1059` | Dolibarr ERP CRM before 24.0.0 contains an OS command injection vulnerability in htdocs/admin/tools/export.php that lets |
| 🟠 high | CVE-2026-116576: systeminformation is a System and OS information library for node.js. | — | systeminformation is a System and OS information library for node.js. Prior to 5.33.16, services() in lib/processes.js i |
| 🟠 high | CVE-2026-16521: An OS command injection vulnerability exists because of insufficient input filtering. | `T1059` | An OS command injection vulnerability exists because of insufficient input filtering. An attacker can inject a command p |
| 🟠 high | CVE-2026-117558: The ai-sdlc plugin MCP server through 0.31.2 contains an OS command injection vulnerabi… | `T1059` | The ai-sdlc plugin MCP server through 0.31.2 contains an OS command injection vulnerability that allows attackers to exe |
| 🟠 high | CVE-2026-117559: DroidMind through 0.4.0 contains a command injection vulnerability that allows MCP clie… | `T1059` | DroidMind through 0.4.0 contains a command injection vulnerability that allows MCP clients to bypass the shell command a |
| 🟠 high | CVE-2026-117560: ATXP Gemini CLI extension through 1.0.0 contains an OS command injection vulnerability … | `T1059` | ATXP Gemini CLI extension through 1.0.0 contains an OS command injection vulnerability in runAtxp() that allows attacker |
| 🟠 high | CVE-2026-117561: Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability that allo… | `T1059` | Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability that allows attackers to execute shell com |
| 🟠 high | CVE-2026-117567: esp-mcp through commit 28afddf contains an OS command injection vulnerability that allo… | `T1059` | esp-mcp through commit 28afddf contains an OS command injection vulnerability that allows attackers to run arbitrary com |
| 🟠 high | CVE-2026-117568: mcp-ffmpeg through 1.0.5 contains an OS command injection vulnerability that allows att… | `T1059` | mcp-ffmpeg through 1.0.5 contains an OS command injection vulnerability that allows attackers to run shell commands by s |
| 🟠 high | CVE-2026-117569: Kali-GPT through commit a608c74 contains an OS command injection vulnerability in execu… | `T1059` | Kali-GPT through commit a608c74 contains an OS command injection vulnerability in execute_tool() in kali_gpt/tools/mcp_s |
| 🟠 high | CVE-2026-117573: hagent through commit 761eec6 contains an OS command injection vulnerability that allow… | `T1059` | hagent through commit 761eec6 contains an OS command injection vulnerability that allows MCP clients to execute shell co |
| 🟠 high | CVE-2026-107672: A maliciously crafted .stack.json file can trigger a trusted Markdown injection vulnera… | — | A maliciously crafted .stack.json file can trigger a trusted Markdown injection vulnerability in Autodesk Fusion Post Pr |
| 🟠 high | CVE-2026-117511: A vulnerability has been found in desmondmorris node-tesseract up to 0.2.7. | `T1059` | A vulnerability has been found in desmondmorris node-tesseract up to 0.2.7. Affected by this issue is the function proce |
| 🟠 high | CVE-2026-108303: Tanium addressed an unauthorized code execution vulnerability in Certificate Manager. | — | Tanium addressed an unauthorized code execution vulnerability in Certificate Manager. |
| 🟠 high | CVE-2026-108329: Tanium addressed an unauthorized code execution vulnerability in Threat Response. | — | Tanium addressed an unauthorized code execution vulnerability in Threat Response. |
| 🟠 high | CVE-2026-116676: Atlantis is a self-hosted golang application that listens for Terraform pull request ev… | — | Atlantis is a self-hosted golang application that listens for Terraform pull request events via webhooks. From version 0 |
| 🟠 high | CVE-2026-112351: Sunhillo SureLine before 9.1.5 contains an OS command injection vulnerability in the ne… | `T1059` | Sunhillo SureLine before 9.1.5 contains an OS command injection vulnerability in the networkDiag.cgi endpoint that allow |
| 🟠 high | CVE-2013-20007: Linksys WAG200G through 1.01.06 contains an OS command injection vulnerability that all… | `T1059` | Linksys WAG200G through 1.01.06 contains an OS command injection vulnerability that allows authenticated attackers to ex |
| 🟠 high | CVE-2026-86395: Dell PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through… | `T1059` | Dell PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7. |
| | _+30 more…_ | | |

## Authentication & Authorization Bypass (134)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-107656: An authentication bypass using an alternate path or channel vulnerability in Fortinet F… | `T1078` | An authentication bypass using an alternate path or channel vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.6,  |
| 🔴 critical | CVE-2026-116214: MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability that a… | `T1078` | MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability that allows unauthenticated attackers t |
| 🔴 critical | CVE-2026-116485: danmu_api before 1.21.7 contains an authentication bypass vulnerability that allows una… | `T1078` | danmu_api before 1.21.7 contains an authentication bypass vulnerability that allows unauthenticated attackers to modify  |
| 🔴 critical | CVE-2026-102649: Burrito is a Terraform Automation Collaboration Software (TACoS) Kubernetes operator. | — | Burrito is a Terraform Automation Collaboration Software (TACoS) Kubernetes operator. Prior to 0.13.0, `POST /api/webhoo |
| 🔴 critical | CVE-2026-110720: Consul-k8s versions 0.42.0 and later are vulnerable to a cross-namespace authorization … | — | Consul-k8s versions 0.42.0 and later are vulnerable to a cross-namespace authorization bypass in component ACL binding r |
| 🔴 critical | CVE-2026-18450: The BMC does not correctly enforce integrity and encryption requirements for IPMI comma… | — | The BMC does not correctly enforce integrity and encryption requirements for IPMI commands. An attacker may be able to c |
| 🔴 critical | CVE-2026-92885: The Qode Membership plugin for WordPress is vulnerable to Authentication Bypass leading… | `T1078` | The Qode Membership plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeover in all versi |
| 🔴 critical | CVE-2026-76938: Authentication Bypass Vulnerability in JP1/Automatic Job Management System 3. | `T1078` | Authentication Bypass Vulnerability in JP1/Automatic Job Management System 3.


This issue affects JP1/Automatic Job Man |
| 🔴 critical | CVE-2026-82116: Missing Authentication for Critical Function Vulnerability in HiRDB. | `T1078` | Missing Authentication for Critical Function Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from  |
| 🔴 critical | CVE-2026-82117: Authentication Bypass by Spoofing Vulnerability in HiRDB. | `T1078` | Authentication Bypass by Spoofing Vulnerability in HiRDB.

This issue affects HiRDB Server Version 10: from 10-00 before |
| 🔴 critical | CVE-2026-117532: REDAXO core from 5.3.0 before 5.21.4 contains an authentication bypass vulnerability in… | `T1078` | REDAXO core from 5.3.0 before 5.21.4 contains an authentication bypass vulnerability in the structure/history plugin tha |
| 🔴 critical | CVE-2026-65145: NVIDIA NeMo Agent Toolkit contains a vulnerability where a attacker could cause a missi… | `T1078` | NVIDIA NeMo Agent Toolkit contains a vulnerability where a attacker could cause a missing authentication issue. This vul |
| 🔴 critical | CVE-2026-105780: Adobe Campaign Classic (ACC) is affected by an Incorrect Authorization vulnerability th… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Incorrect Authorization vulnerability that could result in arbitrary code |
| 🔴 critical | CVE-2026-112352: Sunhillo SureLine before 9.1.5 contains an authentication bypass vulnerability that all… | `T1078` | Sunhillo SureLine before 9.1.5 contains an authentication bypass vulnerability that allows an unauthenticated remote att |
| 🔴 critical | CVE-2026-106013: The Jupiter X Core plugin for WordPress is vulnerable to Authentication Bypass via the … | `T1078` | The Jupiter X Core plugin for WordPress is vulnerable to Authentication Bypass via the Twitter/X Social Login handler in |
| 🔴 critical | CVE-2026-86397: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🔴 critical | CVE-2026-86400: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🔴 critical | CVE-2026-90717: Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 throu… | `T1078` | Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions  |
| 🔴 critical | CVE-2026-103799: Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 throu… | — | Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions  |
| 🔴 critical | CVE-2026-103409: A Missing authentication for critical function vulnerability in Juniper Networks Sessio… | `T1078` | A Missing authentication for critical function vulnerability in Juniper Networks Session Smart Router allows an unauthen |
| 🔴 critical | CVE-2026-117574: A flaw was found in ai-gateway-payload-processing. | — | A flaw was found in ai-gateway-payload-processing. An authenticated remote attacker can exploit this vulnerability by su |
| 🔴 critical | CVE-2026-63190: FearlessCMS is a flat-file `content` management system centered on simplicity and open … | `T1059.007` | FearlessCMS is a flat-file `content` management system centered on simplicity and open source. Prior to version 0.1.4, f |
| 🔴 critical | CVE-2026-118690: Signal K Server before 2.33.0 contains a missing authentication vulnerability that allo… | `T1078` | Signal K Server before 2.33.0 contains a missing authentication vulnerability that allows unauthenticated remote attacke |
| 🔴 critical | CVE-2026-109516: The Bot for Telegram on WooCommerce plugin for WordPress is vulnerable to Authenticatio… | `T1078` | The Bot for Telegram on WooCommerce plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeo |
| 🔴 critical | CVE-2026-107327: IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to ex… | `T1190` | IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to missi |
| 🔴 critical | CVE-2026-84295: Improper authentication in Progress Software WS_FTP Server versions prior to 2024.0.6 a… | — | Improper authentication in Progress Software WS_FTP Server versions prior to 2024.0.6 and 2025.0.3 on Windows could allo |
| 🔴 critical | CVE-2026-90863: Missing authorization in the administrative interface of Progress Software WS_FTP Serve… | — | Missing authorization in the administrative interface of Progress Software WS_FTP Server versions prior to 2024.0.7 and  |
| 🔴 critical | CVE-2026-93680: IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to bypass security … | — | IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to bypass security restrictions due to improper auth |
| 🔴 critical | CVE-2026-107058: An issue in Shelter versionCode 445 allows attackers to register their own auth_key and… | — | An issue in Shelter versionCode 445 allows attackers to register their own auth_key and execute a takeover of another us |
| 🔴 critical | CVE-2026-110799: Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or e… | `T1078` | Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or ecommerce stores. Prior to version |
| 🔴 critical | CVE-2026-112905: Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or e… | — | Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or ecommerce stores. Prior to version |
| 🔴 critical | CVE-2026-119660: MuseBot before 2.0.0 contains an authentication bypass vulnerability that allows unauth… | `T1078` | MuseBot before 2.0.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge admi |
| 🔴 critical | CVE-2026-61729: SOCFortress CoPilot focuses on providing a single pane of glass for all your security o… | — | SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. Prior to 0.1.76, |
| 🔴 critical | CVE-2026-61730: SOCFortress CoPilot focuses on providing a single pane of glass for all your security o… | — | SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. In affected depl |
| 🔴 critical | CVE-2026-61826: Bazarr is a companion application to Sonarr and Radarr. | — | Bazarr is a companion application to Sonarr and Radarr. Prior to 1.5.7-beta.14, the `api_ns_plex` namespace in `bazarr/a |
| 🔴 critical | CVE-2026-78403: Stack-based buffer overflow and missing
authorization vulnerability in Thales Sentinel … | `T1190`, `T1203` | Stack-based buffer overflow and missing
authorization vulnerability in Thales Sentinel Keys Server on Windows allows
Ove |
| 🔴 critical | CVE-2026-62863: MoLing is a computer-use and browser-use based MCP server. | — | MoLing is a computer-use and browser-use based MCP server. Prior to 0.5.0, when MoLing runs in SSE mode using `-l`, its  |
| 🔴 critical | CVE-2026-63377: TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query t… | — | TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language |
| 🔴 critical | CVE-2026-116557: The WP Booking System - Booking Calendar plugin for WordPress is vulnerable to unauthor… | — | The WP Booking System - Booking Calendar plugin for WordPress is vulnerable to unauthorized modification of data due to  |
| 🔴 critical | CVE-2026-89270: The Popup Builder – Create highly converting, mobile friendly marketing popups. | — | The Popup Builder – Create highly converting, mobile friendly marketing popups. plugin for WordPress is vulnerable to au |
| 🔴 critical | CVE-2026-119096: The Uncanny Toolkit for LearnDash plugin for WordPress is vulnerable to Authentication … | `T1078` | The Uncanny Toolkit for LearnDash plugin for WordPress is vulnerable to Authentication Bypass in versions up to, and inc |
| 🟠 high | CVE-2026-116110: A vulnerability was found in GiantappMan LiveWallPaper 2.6.8.0 on Windows. | `T1078` | A vulnerability was found in GiantappMan LiveWallPaper 2.6.8.0 on Windows. This issue affects some unknown processing of |
| 🟠 high | CVE-2026-116257: A vulnerability was determined in BillaBear up to 2025.01.03. | `T1078` | A vulnerability was determined in BillaBear up to 2025.01.03. Affected by this issue is the function processInstall of t |
| 🟠 high | CVE-2026-115748: **UNSUPPORTED WHEN ASSIGNED**  Authorization bypass in Apache Vysper, all versions. | — | **UNSUPPORTED WHEN ASSIGNED**  Authorization bypass in Apache Vysper, all versions.




Apache Vysper is an XMPP (Jabber |
| 🟠 high | CVE-2026-105765: HashiCorp Consul and Consul Enterprise 1.17.0 up to 2.0.4 are vulnerable to an authoriz… | — | HashiCorp Consul and Consul Enterprise 1.17.0 up to 2.0.4 are vulnerable to an authorization bypass in the agent's servi |
| 🟠 high | CVE-2026-112427: An authentication issue was addressed with improved state management. | `T1190` | An authentication issue was addressed with improved state management. This issue is fixed in macOS Golden Gate 27.2. A r |
| 🟠 high | CVE-2026-116623: A vulnerability was detected in code-projects Simple Content Management System 1.0. | — | A vulnerability was detected in code-projects Simple Content Management System 1.0. Impacted is an unknown function of t |
| 🟠 high | CVE-2026-65211: This issue may allow an authenticated IPMI Administrator to read and write arbitrary BM… | — | This issue may allow an authenticated IPMI Administrator to read and write arbitrary BMC physical memory and thereby exe |
| 🟠 high | CVE-2026-116873: Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerabili… | — | Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerability in the smwtask API module that |
| 🟠 high | CVE-2026-116876: Semantic MediaWiki from 2.5.0 before 7.3.1 contains an improper authorization vulnerabi… | — | Semantic MediaWiki from 2.5.0 before 7.3.1 contains an improper authorization vulnerability that allows ordinary editors |
| | _+84 more…_ | | |

## Privilege Escalation (38)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-113616: The LogixFast Auth WordPress plugin before 1.0.4 does not deliver its password-reset on… | — | The LogixFast Auth WordPress plugin before 1.0.4 does not deliver its password-reset one-time code to the resolved accou |
| 🔴 critical | CVE-2026-116386: Unauthenticated Privilege Escalation in SMS Alert Order Notifications <= 4.0.2 versions. | `T1068` | Unauthenticated Privilege Escalation in SMS Alert Order Notifications <= 4.0.2 versions. |
| 🔴 critical | CVE-2026-120306: Beta9 turns each shell command in a tenant image definition into a Dockerfile RUN line … | — | Beta9 turns each shell command in a tenant image definition into a Dockerfile RUN line and executes it with Buildah on t |
| 🟠 high | CVE-2026-113947: This issue was addressed with improved access restrictions. | `T1190` | This issue was addressed with improved access restrictions. This issue is fixed in macOS Golden Gate 27.2. Unpacking a m |
| 🟠 high | CVE-2026-65220: A logic flaw in the BMC IPMI implementation may allow an attacker to send specially cra… | — | A logic flaw in the BMC IPMI implementation may allow an attacker to send specially crafted RAKP+ messages and escalate  |
| 🟠 high | CVE-2026-118008: Privilege escalation in the DOM: Navigation component. | `T1068` | Privilege escalation in the DOM: Navigation component. This vulnerability was fixed in Firefox 159 and Thunderbird 159. |
| 🟠 high | CVE-2026-111582: A DLL loading vulnerability in the
TeamViewer Remote Management Monitoring installer fo… | — | A DLL loading vulnerability in the
TeamViewer Remote Management Monitoring installer for Windows prior to version 26.10. |
| 🟠 high | CVE-2026-111583: Improper access control in the installer
staging directory used by TeamViewer Full Clie… | — | Improper access control in the installer
staging directory used by TeamViewer Full Client and Host prior to version
15.8 |
| 🟠 high | CVE-2026-111584: A race condition in the installation
process of TeamViewer Remote Management - Patch Ma… | `T1190` | A race condition in the installation
process of TeamViewer Remote Management - Patch Management for Windows prior to
ver |
| 🟠 high | CVE-2026-92374: A time-of-check time-of-use (TOCTOU) race condition combined with improper symbolic lin… | `T1068` | A time-of-check time-of-use (TOCTOU) race condition combined with improper symbolic link handling in the privileged help |
| 🟠 high | CVE-2026-108304: Tanium addressed a local privilege escalation vulnerability in End-User Notifications. | `T1068` | Tanium addressed a local privilege escalation vulnerability in End-User Notifications. |
| 🟠 high | CVE-2026-108305: Tanium addressed a local privilege escalation vulnerability in End-User Notifications. | `T1068` | Tanium addressed a local privilege escalation vulnerability in End-User Notifications. |
| 🟠 high | CVE-2026-108306: Tanium addressed a local privilege escalation vulnerability in End-User Notifications. | `T1068` | Tanium addressed a local privilege escalation vulnerability in End-User Notifications. |
| 🟠 high | CVE-2026-111577: The GoSMTP  WordPress plugin before 1.2.5 does not perform a settings-management author… | — | The GoSMTP  WordPress plugin before 1.2.5 does not perform a settings-management authorization check on its SMTP configu |
| 🟠 high | CVE-2026-109381: The Mage Eventpress plugin for WordPress is vulnerable to privilege escalation in versi… | `T1068` | The Mage Eventpress plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.7.8 T |
| 🟠 high | CVE-2026-86385: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, contain an… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, contain an Improper Check for Dropped Privi |
| 🟠 high | CVE-2026-86393: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🟠 high | CVE-2025-30414: Local privilege escalation due to improper authentication. | `T1068` | Local privilege escalation due to improper authentication. The following products are affected: Acronis Cyber Protect Cl |
| 🟠 high | CVE-2026-6064: Link following vulnerability in Data Shredder components in Norton Antivirus, Avast Ant… | — | Link following vulnerability in Data Shredder components in Norton Antivirus, Avast Antivirus, and AVG Internet Security |
| 🟠 high | CVE-2026-112357: GFI KerioConnect (Kerio Connect) Outlook Connector (Offline Edition), 'KOFF', before 10… | `T1190`, `T1068` | GFI KerioConnect (Kerio Connect) Outlook Connector (Offline Edition), 'KOFF', before 10.0.9 Patch 2 contains a local pri |
| 🟠 high | CVE-2026-103402: An Insufficient Verification of Data Authenticity vulnerability in PCLI in Juniper Netw… | `T1190` | An Insufficient Verification of Data Authenticity vulnerability in PCLI in Juniper Networks Session Smart Router and Ses |
| 🟠 high | CVE-2026-118602: Alpine iLX-F511 Fiv.System Exposed Dangerous Method Local Privilege Escalation Vulnerab… | `T1190`, `T1068` | Alpine iLX-F511 Fiv.System Exposed Dangerous Method Local Privilege Escalation Vulnerability. This vulnerability allows  |
| 🟠 high | CVE-2026-118082: Subscriber Privilege Escalation in Buddyboss Platform <= 3.5.0 versions. | `T1068` | Subscriber Privilege Escalation in Buddyboss Platform <= 3.5.0 versions. |
| 🟠 high | CVE-2026-119168: HashiCorp Nomad and Nomad Enterprise are vulnerable to symlink following during same-cl… | `T1068` | HashiCorp Nomad and Nomad Enterprise are vulnerable to symlink following during same-client allocation data migration th |
| 🟠 high | CVE-2026-104368: The Export and Import Users and Customers plugin for WordPress is vulnerable to Privile… | `T1068` | The Export and Import Users and Customers plugin for WordPress is vulnerable to Privilege Escalation in all versions up  |
| 🟠 high | CVE-2026-59387: The Nginx routing configuration for Cloud Controller blocks unauthenticated access to /… | `T1068` | The Nginx routing configuration for Cloud Controller blocks unauthenticated access to /internal/v4/ and /internal/v5/ en |
| 🟠 high | CVE-2026-101213: Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Privilege Man… | — | Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Privilege Management vulnerability. A low priv |
| 🟠 high | CVE-2026-105894: The Ak Framework plugin for WordPress, included in the Newsy - Viral News & Magazine Wo… | `T1068` | The Ak Framework plugin for WordPress, included in the Newsy - Viral News & Magazine WordPress Theme, is vulnerable to P |
| 🟠 high | CVE-2026-118205: The Essential Addons for Elementor – Popular Elementor Templates & Widgets plugin for W… | `T1068` | The Essential Addons for Elementor – Popular Elementor Templates & Widgets plugin for WordPress is vulnerable to Privile |
| 🟠 high | CVE-2026-118086: Subscriber Privilege Escalation in WP BASE Booking <= 6.5.2 versions. | `T1068` | Subscriber Privilege Escalation in WP BASE Booking <= 6.5.2 versions. |
| 🟠 high | CVE-2026-40573: NovumOS is a custom 32-bit operating system written in Zig and x86 Assembly. | — | NovumOS is a custom 32-bit operating system written in Zig and x86 Assembly. Prior to version 0.25-beta.1, the `Nova` in |
| 🟠 high | CVE-2026-62847: Metalama is a Roslyn-based open-source patterns and architecture toolkit for C#. | `T1068` | Metalama is a Roslyn-based open-source patterns and architecture toolkit for C#. Prior to 2025.1.18, 2026.0.25 and 2026. |
| 🟠 high | CVE-2026-62990: Shopper is a Headless e-commerce Admin Panel. | — | Shopper is a Headless e-commerce Admin Panel. In versions from 2.0.0 prior to 2.10.1 and in the 3.0.0 prereleases beta.1 |
| 🟠 high | CVE-2026-63339: IXP Manager is a full-stack web application for managing Internet Exchange Points. | — | IXP Manager is a full-stack web application for managing Internet Exchange Points. Prior to version 7.3.0, an authentica |
| 🟠 high | CVE-2026-120040: The Mail logging & Catcher plugin for WordPress is vulnerable to Sensitive Information … | — | The Mail logging & Catcher plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, a |
| 🟠 high | CVE-2026-104012: The Rox Appointment Booking – Appointment Booking Scheduling Solution plugin for WordPr… | `T1068` | The Rox Appointment Booking – Appointment Booking Scheduling Solution plugin for WordPress is vulnerable to Privilege Es |
| 🟠 high | CVE-2026-120070: The User Frontend – Membership, User Registration, User Profile, User Directory & Conte… | `T1068` | The User Frontend – Membership, User Registration, User Profile, User Directory & Content Restriction with Frontend Post |
| 🟠 high | CVE-2026-117681: A flaw was found in konflux-ci. | `T1068` | A flaw was found in konflux-ci. This vulnerability allows privilege escalation when the user interface proxy automatical |

## SQL & NoSQL Injection (52)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-10757: There is a SQL injection vulnerability in Esri ArcGIS Server versions 12.1 and earlier … | `T1190` | There is a SQL injection vulnerability in Esri ArcGIS Server versions 12.1 and earlier on Windows and Linux that may all |
| 🔴 critical | CVE-2026-104354: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Eleme… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL  |
| 🔴 critical | CVE-2026-105489: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Eleme… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL  |
| 🔴 critical | CVE-2026-105779: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Eleme… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL  |
| 🔴 critical | CVE-2026-105781: Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Eleme… | `T1190` | Adobe Campaign Classic (ACC) is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL  |
| 🔴 critical | CVE-2026-103792: Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 throu… | `T1190` | Dell PowerProtect Data Domain Management Center, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions  |
| 🔴 critical | CVE-2026-111411: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Aman FunnelKit Aut |
| 🔴 critical | CVE-2026-115607: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Crowd Favorite DXP |
| 🔴 critical | CVE-2026-115964: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in StylemixThemes Mot |
| 🔴 critical | CVE-2026-39732: Unauthenticated SQL Injection in Transliterator <= 2.5.13 versions. | `T1190` | Unauthenticated SQL Injection in Transliterator <= 2.5.13 versions. |
| 🔴 critical | CVE-2026-61620: HoneySQL turns Clojure data structures into SQL. | `T1190` | HoneySQL turns Clojure data structures into SQL. From 2.0.0 until 2.7.1392, applications that pass user input or other a |
| 🔴 critical | CVE-2026-62849: ThingLinks is an enterprise IoT platform. | `T1190` | ThingLinks is an enterprise IoT platform. Prior to 1.4.0, an unauthenticated SQL injection vulnerability in the `TDengin |
| 🔴 critical | CVE-2026-120201: Jpom 2.10.0 through 2.11.12 contains an authentication bypass vulnerability that allows… | `T1078` | Jpom 2.10.0 through 2.11.12 contains an authentication bypass vulnerability that allows unauthenticated attackers to gai |
| 🔴 critical | CVE-2026-62048: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Liquid Web / Stell |
| 🟠 high | CVE-2026-116112: A vulnerability was identified in HashenUdara edoc-doctor-appointment-system up to cc25… | `T1190` | A vulnerability was identified in HashenUdara edoc-doctor-appointment-system up to cc258425b915d1af9e298777ccd26d160493e |
| 🟠 high | CVE-2026-115608: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Crocoblock JetEngi |
| 🟠 high | CVE-2026-115948: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in David Lingren Medi |
| 🟠 high | CVE-2026-115191: A SQL injection vulnerability exists in a contact lookup AJAX endpoint of the Mautic ad… | `T1190` | A SQL injection vulnerability exists in a contact lookup AJAX endpoint of the Mautic administration interface (/s/ajax). |
| 🟠 high | CVE-2026-115192: An SQL Injection vulnerability exists in the dashboard widget data API endpoint (/api/d… | `T1190` | An SQL Injection vulnerability exists in the dashboard widget data API endpoint (/api/data/{type}). Chart filter paramet |
| 🟠 high | CVE-2026-116218: Dolibarr ERP CRM 19.0.0 before 23.0.4 contains an SQL injection vulnerability that allo… | `T1190` | Dolibarr ERP CRM 19.0.0 before 23.0.4 contains an SQL injection vulnerability that allows authenticated API users to inj |
| 🟠 high | CVE-2026-115418: SQL injection in the database-query custom resource handlers in the Amazon Web Services… | `T1190` | SQL injection in the database-query custom resource handlers in the Amazon Web Services (AWS) Cloud Development Kit (CDK |
| 🟠 high | CVE-2026-116818: OpenPanel before 3.0.0 contains an unauthenticated ClickHouse sql injection vulnerabili… | `T1190` | OpenPanel before 3.0.0 contains an unauthenticated ClickHouse sql injection vulnerability that allows remote attackers t |
| 🟠 high | CVE-2026-116808: OpenPanel before 3.0.0 contains an sql injection vulnerability that allows authenticate… | `T1190` | OpenPanel before 3.0.0 contains an sql injection vulnerability that allows authenticated users to read cross-tenant data |
| 🟠 high | CVE-2026-65151: NVIDIA NeMo Agent Toolkit contains vulnerability where an attacker could cause a SQL in… | `T1190` | NVIDIA NeMo Agent Toolkit contains vulnerability where an attacker could cause a SQL injection issue. A successful explo |
| 🟠 high | CVE-2026-117513: A vulnerability was determined in oretnom23 php-travel-agency-system. | `T1190` | A vulnerability was determined in oretnom23 php-travel-agency-system. This vulnerability affects unknown code of the fil |
| 🟠 high | CVE-2026-117514: A vulnerability was identified in oretnom23 php-travel-agency-system. | `T1190` | A vulnerability was identified in oretnom23 php-travel-agency-system. This issue affects some unknown processing of the  |
| 🟠 high | CVE-2026-117515: A security flaw has been discovered in oretnom23 php-travel-agency-system 4e28b8f84d724… | `T1190` | A security flaw has been discovered in oretnom23 php-travel-agency-system 4e28b8f84d72420373dd15c3ae32900beb7e0635. Impa |
| 🟠 high | CVE-2026-117516: A weakness has been identified in oretnom23 php-travel-agency-system. | `T1190` | A weakness has been identified in oretnom23 php-travel-agency-system. The affected element is an unknown function of the |
| 🟠 high | CVE-2026-118378: Tabularis before 0.28.0 contains an SQL injection vulnerability in its SQLite driver th… | `T1190` | Tabularis before 0.28.0 contains an SQL injection vulnerability in its SQLite driver that allows MCP clients to execute  |
| 🟠 high | CVE-2026-111850: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in BuddyPress BuddyPr |
| 🟠 high | CVE-2026-115603: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Advanced Ads GmbH  |
| 🟠 high | CVE-2026-118641: n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains an OData $fil… | — | n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains an OData $filter injection vulnerability in th |
| 🟠 high | CVE-2026-118645: n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains a filter inje… | — | n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains a filter injection vulnerability in the Quick  |
| 🟠 high | CVE-2026-54455: OpenCATS is an open-source applicant tracking system and recruitment CRM for staffing a… | — | OpenCATS is an open-source applicant tracking system and recruitment CRM for staffing agencies and hiring teams. Prior t |
| 🟠 high | CVE-2026-61569: AVideo is a video-sharing Platform. | — | AVideo is a video-sharing Platform. Prior to 8.1.0, the unauthenticated streamer login at `objects/login.json.php` passe |
| 🟠 high | CVE-2026-93855: The SendPress Newsletters plugin for WordPress is vulnerable to time-based SQL Injectio… | `T1190` | The SendPress Newsletters plugin for WordPress is vulnerable to time-based SQL Injection via the 'subscriberid' paramete |
| 🟠 high | CVE-2026-93904: The Social Web Suite – Social Media Auto Post, Social Media Auto Publish plugin for Wor… | `T1190` | The Social Web Suite – Social Media Auto Post, Social Media Auto Publish plugin for WordPress is vulnerable to generic S |
| 🟠 high | CVE-2026-89216: The vTables  WordPress plugin before 0.3 does not properly sanitise and escape a parame… | `T1190` | The vTables  WordPress plugin before 0.3 does not properly sanitise and escape a parameter before using it in a SQL stat |
| 🟠 high | CVE-2026-115965: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in BuddyPress BuddyPr |
| 🟠 high | CVE-2026-110184: The Newsmatic theme for WordPress is vulnerable to blind SQL Injection via the 'slug' p… | `T1190` | The Newsmatic theme for WordPress is vulnerable to blind SQL Injection via the 'slug' parameter in all versions up to, a |
| 🟠 high | CVE-2026-49142: OpenEMR before 8.5.0 contains an authenticated SQL injection vulnerability in the Syndr… | `T1190` | OpenEMR before 8.5.0 contains an authenticated SQL injection vulnerability in the Syndromic Surveillance module that all |
| 🟠 high | CVE-2026-39736: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Crocoblock JetEngi |
| 🟠 high | CVE-2026-61996: Subscriber SQL Injection in MLS On The Fly <= 1.8.1.5 versions. | `T1190` | Subscriber SQL Injection in MLS On The Fly <= 1.8.1.5 versions. |
| 🟠 high | CVE-2026-11587: SQL injection allowing an authenticated user with access to ACL management to read and … | `T1190` | SQL injection allowing an authenticated user with access to ACL management to read and modify the Centreon database |
| 🟠 high | CVE-2026-119418: CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to … | `T1190` | CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to inject SQL by supplying unvalidat |
| 🟠 high | CVE-2026-119419: CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to … | `T1190` | CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to inject SQL by supplying unvalidat |
| 🟠 high | CVE-2026-111503: Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Neutralizatio… | `T1190` | Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Improper Neutralization of Special Elements used in an  |
| 🟠 high | CVE-2026-119655: CoreShop through 1.5.5 contains an unauthenticated sql injection vulnerability in the a… | `T1190` | CoreShop through 1.5.5 contains an unauthenticated sql injection vulnerability in the api/Good/GetGoodsPageList endpoint |
| 🟠 high | CVE-2026-119656: CoreShop by CoreUnion through 1.5.5 contains an unauthenticated sql injection vulnerabi… | `T1190` | CoreShop by CoreUnion through 1.5.5 contains an unauthenticated sql injection vulnerability in the api/Agent/GetGoodsPag |
| 🟠 high | CVE-2026-119619: A vulnerability was found in 37954679 cak-filemanagement-system up to 5e6433246475e6646… | `T1190` | A vulnerability was found in 37954679 cak-filemanagement-system up to 5e6433246475e66462e1fea980688de96a049297. This aff |
| | _+2 more…_ | | |

## Cross-Site Scripting (88)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-104350: Adobe Campaign Classic (ACC) is affected by a reflected Cross-Site Scripting (XSS) vuln… | `T1059.007` | Adobe Campaign Classic (ACC) is affected by a reflected Cross-Site Scripting (XSS) vulnerability. An attacker could expl |
| 🔴 critical | CVE-2026-61728: SOCFortress CoPilot focuses on providing a single pane of glass for all your security o… | — | SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. In affected snap |
| 🟠 high | CVE-2026-115193: A stored Cross-Site Scripting (XSS) vulnerability exists in the contact detail view of … | `T1059.007` | A stored Cross-Site Scripting (XSS) vulnerability exists in the contact detail view of Mautic 7. Values of HTML-type cus |
| 🟠 high | CVE-2026-116836: A malicious actor with access to the adjacent network and under certain conditions coul… | `T1059.007` | A malicious actor with access to the adjacent network and under certain conditions could exploit a Stored Cross-Site Scr |
| 🟠 high | CVE-2026-111820: The Analytics Insights – Google Analytics Dashboard for WordPress plugin for WordPress … | `T1059.007` | The Analytics Insights – Google Analytics Dashboard for WordPress plugin for WordPress is vulnerable to Stored Cross-Sit |
| 🟠 high | CVE-2026-109995: The Advanced Views – Display Framework for Gutenberg & Elementor plugin for WordPress i… | `T1059.007` | The Advanced Views – Display Framework for Gutenberg & Elementor plugin for WordPress is vulnerable to Stored Cross-Site |
| 🟠 high | CVE-2026-102636: A maliciously crafted HTML payload in a design name, when displayed after another user … | `T1190`, `T1059.007` | A maliciously crafted HTML payload in a design name, when displayed after another user opens the manipulated design, can |
| 🟠 high | CVE-2026-102637: A maliciously crafted HTML payload in the documentName parameter of a Fusion protocol U… | `T1190`, `T1059.007` | A maliciously crafted HTML payload in the documentName parameter of a Fusion protocol URL, when the protocol URL is invo |
| 🟠 high | CVE-2026-102638: A maliciously crafted HTML payload in the description of an electronic library (.lbr) f… | `T1190`, `T1059.007` | A maliciously crafted HTML payload in the description of an electronic library (.lbr) file, when displayed in the Librar |
| 🟠 high | CVE-2026-112353: GFI KerioConnect (Kerio Connect) before 10.0.8 Patch 2 contains a stored cross-site scr… | `T1059.007` | GFI KerioConnect (Kerio Connect) before 10.0.8 Patch 2 contains a stored cross-site scripting vulnerability in the Webma |
| 🟠 high | CVE-2026-116688: CKEditor 5 is a modern JavaScript rich-text editor with an MVC architecture. | — | CKEditor 5 is a modern JavaScript rich-text editor with an MVC architecture. From 45.0.0 until 47.7.4 and 48.5.1, the en |
| 🟠 high | CVE-2026-58205: GRR is a resource management and reservation application. | `T1059.007`, `T1566` | GRR is a resource management and reservation application. Prior to version 4.5.0, `maj.php` reflects the `forcemaj` para |
| 🟠 high | CVE-2026-116675: TinyMCE Cross-Site Scripting (XSS) vulnerability using media plugin `data-mce-object` s… | `T1059.007` | [cvefeed.io] TinyMCE Cross-Site Scripting (XSS) vulnerability using media plugin `data-mce-object` serialization |
| 🟠 high | CVE-2026-109999: The AI Marketing Expert — AI Email Marketing, AI Content Generator, SEO Analyzer, AI Wo… | `T1059.007` | The AI Marketing Expert — AI Email Marketing, AI Content Generator, SEO Analyzer, AI Workflow Automation, Social Media & |
| 🟠 high | CVE-2026-111314: The affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display plugin for Wor… | `T1059.007` | The affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display plugin for WordPress is vulnerable to Stored Cr |
| 🟠 high | CVE-2026-97019: The AMP for WP – Accelerated Mobile Pages plugin for WordPress is vulnerable to Stored … | `T1059.007` | The AMP for WP – Accelerated Mobile Pages plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'headlin |
| 🟠 high | CVE-2026-105972: The Menu Cart for WooCommerce WordPress plugin before 3.2.1 does not sanitise and escap… | `T1059.007` | The Menu Cart for WooCommerce WordPress plugin before 3.2.1 does not sanitise and escape cart item variation data before |
| 🟠 high | CVE-2026-111021: The افزونه پیامک ووکامرس \| Persian WooCommerce SMS WordPress plugin before 7.3.2 does n… | `T1059.007` | The افزونه پیامک ووکامرس \| Persian WooCommerce SMS WordPress plugin before 7.3.2 does not sanitise and escape a paramete |
| 🟠 high | CVE-2026-110662: The MxChat – AI Chatbot & Content Generation for WordPress plugin for WordPress is vuln… | `T1059.007` | The MxChat – AI Chatbot & Content Generation for WordPress plugin for WordPress is vulnerable to Stored DOM-Based Cross- |
| 🟠 high | CVE-2026-111111: The Prime Slider – Hero Slider, Carousel, WooCommerce & Post Slider Elementor Addons pl… | `T1059.007` | The Prime Slider – Hero Slider, Carousel, WooCommerce & Post Slider Elementor Addons plugin for WordPress is vulnerable  |
| 🟠 high | CVE-2026-115593: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Unlimited Elements |
| 🟠 high | CVE-2026-115596: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in impleCode eCommerc |
| 🟠 high | CVE-2026-115606: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Crowd Favorite DXP |
| 🟠 high | CVE-2026-115609: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Stiofan GetPaid in |
| 🟠 high | CVE-2026-115612: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in iova.mihai SliceWP |
| 🟠 high | CVE-2026-67073: HCL BigFix AEX is affected by an Unrestricted File Upload and Improper Access Control v… | — | HCL BigFix AEX is affected by an Unrestricted File Upload and Improper Access Control vulnerability. This could allow an |
| 🟠 high | CVE-2026-118257: Vue I18n is the internationalization plugin for Vue.js. | — | Vue I18n is the internationalization plugin for Vue.js. From 11.1.10 until 11.4.14 and from 12.0.0-alpha.4 until 12.0.0- |
| 🟠 high | CVE-2026-118648: n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains a stored cros… | `T1059.007` | n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 contains a stored cross-site scripting vulnerability be |
| 🟠 high | CVE-2026-96666: The Schema App Structured Data plugin for WordPress is vulnerable to Stored Cross-Site … | `T1059.007` | The Schema App Structured Data plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via |
| 🟠 high | CVE-2026-96669: The Food Store – Online Food Delivery & Pickup plugin for WordPress is vulnerable to St… | `T1059.007` | The Food Store – Online Food Delivery & Pickup plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'se |
| 🟠 high | CVE-2026-96741: The DSGVO All in one for WP plugin for WordPress is vulnerable to Stored Cross-Site Scr… | `T1059.007` | The DSGVO All in one for WP plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via Ou |
| 🟠 high | CVE-2026-86794: The Community Events WordPress plugin before 1.6.0 does not have authorisation or nonce… | — | The Community Events WordPress plugin before 1.6.0 does not have authorisation or nonce checks when processing public ev |
| 🟠 high | CVE-2026-107743: The Mapster WP Maps plugin for WordPress is vulnerable to Stored Cross-Site Scripting i… | `T1059.007` | The Mapster WP Maps plugin for WordPress is vulnerable to Stored Cross-Site Scripting in versions up to, and including,  |
| 🟠 high | CVE-2026-115592: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in OceanWP OceanWP oc |
| 🟠 high | CVE-2026-115611: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in PluginUs.Net Table |
| 🟠 high | CVE-2026-116409: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Swings Upsell O |
| 🟠 high | CVE-2026-115821: The NewsmanApp plugin for WordPress is vulnerable to Stored Cross-Site Scripting via th… | `T1059.007` | The NewsmanApp plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'billing_first_name, billing_la |
| 🟠 high | CVE-2026-96767: The NEX-Forms – Ultimate Forms Plugin for WordPress plugin for WordPress is vulnerable … | `T1059.007` | The NEX-Forms – Ultimate Forms Plugin for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting vi |
| 🟠 high | CVE-2026-108494: Unauthenticated Cross Site Scripting (XSS) in Chained Quiz <= 1.4.1 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Chained Quiz <= 1.4.1 versions. |
| 🟠 high | CVE-2026-118085: Unauthenticated Cross Site Scripting (XSS) in GlobalPayments WooCommerce <= 1.23.3 vers… | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in GlobalPayments WooCommerce <= 1.23.3 versions. |
| 🟠 high | CVE-2026-27394: Unauthenticated Cross Site Scripting (XSS) in Eventer <= 0.1.1 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Eventer <= 0.1.1 versions. |
| 🟠 high | CVE-2026-42692: Unauthenticated Cross Site Scripting (XSS) in WP Crowdfunding <= 2.2.2 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in WP Crowdfunding <= 2.2.2 versions. |
| 🟠 high | CVE-2026-54864: Unauthenticated Cross Site Scripting (XSS) in Post Video Players <= 1.165 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Post Video Players <= 1.165 versions. |
| 🟠 high | CVE-2026-54866: Unauthenticated Cross Site Scripting (XSS) in Razorpay Payment Button Elementor Plugin … | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Razorpay Payment Button Elementor Plugin <= 1.2.8 versions. |
| 🟠 high | CVE-2026-61988: Unauthenticated Cross Site Scripting (XSS) in Auction Nudge – Your eBay on Your Site <=… | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Auction Nudge – Your eBay on Your Site <= 8.4.0 versions. |
| 🟠 high | CVE-2026-61989: Unauthenticated Cross Site Scripting (XSS) in Easy Property Listings <= 3.5.25 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Easy Property Listings <= 3.5.25 versions. |
| 🟠 high | CVE-2026-61993: Unauthenticated Cross Site Scripting (XSS) in Blockonomics 3.11.0 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in Blockonomics 3.11.0 versions. |
| 🟠 high | CVE-2026-61995: Unauthenticated Cross Site Scripting (XSS) in YouTube Showcase <= 4.1.0 versions. | `T1059.007` | Unauthenticated Cross Site Scripting (XSS) in YouTube Showcase <= 4.1.0 versions. |
| 🟠 high | CVE-2026-61719: WeGIA is a web manager for charitable institutions. | `T1059.007` | WeGIA is a web manager for charitable institutions. Prior to 3.8.7, a stored cross-site scripting vulnerability in `saud |
| 🟠 high | CVE-2026-117571: The WP Visitor Statistics (Real Time Traffic) WordPress plugin before 8.8 does not sani… | — | The WP Visitor Statistics (Real Time Traffic) WordPress plugin before 8.8 does not sanitize and escape tracking data der |
| | _+38 more…_ | | |

## Memory Corruption (149)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-116508: A security flaw has been discovered in TOTOLINK A950RG 4.1.2cu.5268_B20221104. | `T1203` | A security flaw has been discovered in TOTOLINK A950RG 4.1.2cu.5268_B20221104. Affected by this issue is the function su |
| 🔴 critical | CVE-2026-76932: Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.

This issue affects JP1/Automatic Jo |
| 🔴 critical | CVE-2026-76933: Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.

This issue affects JP1/Automatic Job |
| 🔴 critical | CVE-2026-76934: Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.

This issue affects JP1/Automatic Jo |
| 🔴 critical | CVE-2026-76935: Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.


This issue affects JP1/Automatic J |
| 🔴 critical | CVE-2026-76936: Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Stack-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.


This issue affects JP1/Automatic J |
| 🔴 critical | CVE-2026-76937: Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.


This issue affects JP1/Automatic Jo |
| 🔴 critical | CVE-2026-76939: Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3. | `T1203` | Heap-based Buffer Overflow Vulnerability in JP1/Automatic Job Management System 3.

This issue affects JP1/Automatic Job |
| 🔴 critical | CVE-2026-82118: Stack-based Buffer Overflow Vulnerability in HiRDB. | `T1203` | Stack-based Buffer Overflow Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-1 |
| 🔴 critical | CVE-2026-82120: Heap-based Buffer Overflow Vulnerability in HiRDB. | `T1203` | Heap-based Buffer Overflow Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-12 |
| 🔴 critical | CVE-2026-82122: Stack-based Buffer Overflow Vulnerability in HiRDB. | `T1203` | Stack-based Buffer Overflow Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-1 |
| 🔴 critical | CVE-2026-86574: Heap-based Buffer Overflow Vulnerability in JP1/Base. | `T1203` | Heap-based Buffer Overflow Vulnerability in JP1/Base.

This issue affects JP1/Base: from 11-00 before 12-50-54. |
| 🔴 critical | CVE-2026-86575: Stack-based Buffer Overflow Vulnerability in JP1 Products. | `T1203` | Stack-based Buffer Overflow Vulnerability in JP1 Products.

This issue affects JP1/Integrated Management 3 - Manager: fr |
| 🔴 critical | CVE-2026-86576: Heap-based Buffer Overflow Vulnerability in JP1 Products. | `T1203` | Heap-based Buffer Overflow Vulnerability in JP1 Products.

This issue affects JP1/Integrated Management 3 - Manager: fro |
| 🔴 critical | CVE-2026-86577: Out-of-bounds Write Vulnerability in JP1 Products. | — | Out-of-bounds Write Vulnerability in JP1 Products.

This issue affects JP1/Integrated Management 3 - Manager: from 13-00 |
| 🔴 critical | CVE-2026-114595: In EPICS Base release 7.0.10 and prior, an integer overflow in network request processi… | `T1190`, `T1203` | In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocat |
| 🔴 critical | CVE-2026-103780: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | `T1203` | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🔴 critical | CVE-2026-119263: Memory corruption in GarbageCollection in Google Chrome prior to 156.0.8078.79 allowed … | `T1190`, `T1203` | Memory corruption in GarbageCollection in Google Chrome prior to 156.0.8078.79 allowed a remote attacker to potentially  |
| 🔴 critical | CVE-2026-120189: A vulnerability was identified in D-Link DIR-505 1.10B02. | `T1203` | A vulnerability was identified in D-Link DIR-505 1.10B02. Affected is the function save_upload_file/mp_upload_file of th |
| 🟠 high | CVE-2026-107894: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190`, `T1203` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains a stack-based buffer overflow vulnerability. Opening a crafted V7 fil |
| 🟠 high | CVE-2026-107895: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds write vulnerability. Opening a crafted V7 file may l |
| 🟠 high | CVE-2026-107896: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds read vulnerability in VS6ComFile!load_gr_item. Openi |
| 🟠 high | CVE-2026-107897: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds read vulnerability in VS6MemInIF!set_temp_type_defau |
| 🟠 high | CVE-2026-107898: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds read vulnerability in VS6EditData!CDataRomErrorCheck |
| 🟠 high | CVE-2026-107899: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds read vulnerability in VS6EditData!CDataRomErrorCheck |
| 🟠 high | CVE-2026-107900: V-SFT provided by FUJI ELECTRIC CO., LTD. | `T1190` | V-SFT provided by FUJI ELECTRIC CO., LTD. contains an out-of-bounds read vulnerability in VS6ComFile!CCheck::ItemCheck.  |
| 🟠 high | CVE-2026-70388: SOEM version 2.0.0 and earlier contains vulnerabilities where a malicious device on the… | `T1190` | SOEM version 2.0.0 and earlier contains vulnerabilities where a malicious device on the network can send specially craft |
| 🟠 high | CVE-2026-82944: SOEM version 2.0.0 and earlier contains a vulnerability in multi-segment data transfers… | — | SOEM version 2.0.0 and earlier contains a vulnerability in multi-segment data transfers where a malicious device can ove |
| 🟠 high | CVE-2026-82947: SOEM version 2.0.0 and earlier contains multiple vulnerabilities in frame processing wh… | — | SOEM version 2.0.0 and earlier contains multiple vulnerabilities in frame processing where a malicious device can cause  |
| 🟠 high | CVE-2026-116260: A weakness has been identified in libimobiledevice up to 1.4.0. | — | A weakness has been identified in libimobiledevice up to 1.4.0. This issue affects the function service_receive of the f |
| 🟠 high | CVE-2026-116489: Timescale pgvectorscale before 0.9.1 contains a type confusion vulnerability that allow… | — | Timescale pgvectorscale before 0.9.1 contains a type confusion vulnerability that allows low-privileged database users t |
| 🟠 high | CVE-2026-116543: Open5GS 1.3.0 through 2.8.0 contains a heap out-of-bounds write vulnerability in parse_… | — | Open5GS 1.3.0 through 2.8.0 contains a heap out-of-bounds write vulnerability in parse_multipart() that allows unauthent |
| 🟠 high | CVE-2026-112623: A use-after-free issue was addressed with improved memory management. | `T1190` | A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 27.2, iOS 26.7.2 and |
| 🟠 high | CVE-2026-112626: A use-after-free issue was addressed with improved memory management. | `T1190` | A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 27.2, iOS 26.7.2 and |
| 🟠 high | CVE-2026-112637: A use-after-free issue was addressed with improved memory management. | `T1190` | A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 27.2, iOS 27.2 and i |
| 🟠 high | CVE-2026-112651: A use-after-free issue was addressed with improved memory management. | `T1190` | A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 27.2, iOS 26.7.2 and |
| 🟠 high | CVE-2026-112655: A use-after-free issue was addressed with improved memory management. | `T1190` | A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 27.2, iOS 26.7.2 and |
| 🟠 high | CVE-2026-112659: A type confusion issue was addressed with improved memory handling. | `T1190` | A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 27.2, iOS 26.7.2 and i |
| 🟠 high | CVE-2026-112688: A memory corruption issue was addressed with improved memory handling. | `T1190`, `T1203` | A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 26.7 and iPadOS 26.7,  |
| 🟠 high | CVE-2026-64759: An integer overflow was addressed with improved input validation. | `T1190` | An integer overflow was addressed with improved input validation. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, i |
| 🟠 high | CVE-2026-86916: A use after free issue was addressed with improved memory management. | `T1190` | A use after free issue was addressed with improved memory management. This issue is fixed in iOS 26.7 and iPadOS 26.7, i |
| 🟠 high | CVE-2026-86929: An out-of-bounds write issue was addressed with improved bounds checking. | `T1190` | An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Golden Gate 27, m |
| 🟠 high | CVE-2026-116723: FLTK through 1.4.5 contains a stack-based buffer overflow vulnerability in Fl_BMP_Image… | `T1203` | FLTK through 1.4.5 contains a stack-based buffer overflow vulnerability in Fl_BMP_Image::load_bmp_() that allows attacke |
| 🟠 high | CVE-2026-116724: FLTK through 1.4.5 contains an integer overflow vulnerability in Fl_BMP_Image::load_bmp… | — | FLTK through 1.4.5 contains an integer overflow vulnerability in Fl_BMP_Image::load_bmp_() that causes undersized pixel  |
| 🟠 high | CVE-2026-116738: VMime through 0.9.2 contains an integer underflow in the uuEncoder::decode function tha… | `T1203` | VMime through 0.9.2 contains an integer underflow in the uuEncoder::decode function that allows remote attackers to trig |
| 🟠 high | CVE-2026-116741: Speex through 1.2.1 Out-of-Bounds Write via speex_bits_read_whole_bytes | — | [cvefeed.io] Speex through 1.2.1 Out-of-Bounds Write via speex_bits_read_whole_bytes |
| 🟠 high | CVE-2026-116819: OpenPanel before 3.0.0 contains an information disclosure vulnerability that allows rea… | — | OpenPanel before 3.0.0 contains an information disclosure vulnerability that allows read-level project members to obtain |
| 🟠 high | CVE-2024-58400: llama.cpp before b3701 contains an out-of-bounds read vulnerability in llama_decode_int… | — | llama.cpp before b3701 contains an out-of-bounds read vulnerability in llama_decode_internal and llama_encode_internal t |
| 🟠 high | CVE-2026-116620: A security vulnerability has been detected in Tencent RapidJSON up to 1.1.0. | — | A security vulnerability has been detected in Tencent RapidJSON up to 1.1.0. This issue affects the function GenericStri |
| 🟠 high | CVE-2026-116816: llama.cpp b5899 before b10261 contains a heap out-of-bounds write vulnerability in llm_… | — | llama.cpp b5899 before b10261 contains a heap out-of-bounds write vulnerability in llm_tokenizer_plamo2::build that allo |
| | _+99 more…_ | | |

## Insecure Deserialization (77)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-110879: jackson-databind validates the outer class of a class-name type ID but accepts attacker… | — | jackson-databind validates the outer class of a class-name type ID but accepts attacker-selected classes inside its gene |
| 🔴 critical | CVE-2026-115968: Deserialization of Untrusted Data vulnerability in Ultimate Member Ultimate Member ulti… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Ultimate Member Ultimate Member ultimate-member allows Object Injecti |
| 🔴 critical | CVE-2026-103693: The Frontend Dashboard WordPress plugin before 3.0.5, ProfileGrid  WordPress plugin bef… | `T1190` | The Frontend Dashboard WordPress plugin before 3.0.5, ProfileGrid  WordPress plugin before 6.0.0.5 do not prevent an una |
| 🔴 critical | CVE-2026-54856: Unauthenticated PHP Object Injection in RexCoin <= 1.2.6 versions. | — | Unauthenticated PHP Object Injection in RexCoin <= 1.2.6 versions. |
| 🔴 critical | CVE-2026-54857: Unauthenticated PHP Object Injection in Quirky <= 1.23 versions. | — | Unauthenticated PHP Object Injection in Quirky <= 1.23 versions. |
| 🔴 critical | CVE-2026-54858: Unauthenticated PHP Object Injection in Printy <= 1.13.0 versions. | — | Unauthenticated PHP Object Injection in Printy <= 1.13.0 versions. |
| 🔴 critical | CVE-2026-54859: Unauthenticated PHP Object Injection in Preservation <= 1.15 versions. | — | Unauthenticated PHP Object Injection in Preservation <= 1.15 versions. |
| 🔴 critical | CVE-2026-54860: Unauthenticated PHP Object Injection in Ozisti <= 1.1.10 versions. | — | Unauthenticated PHP Object Injection in Ozisti <= 1.1.10 versions. |
| 🔴 critical | CVE-2026-61992: Unauthenticated PHP Object Injection in GEO my WordPress <= 4.5.5.3 versions. | — | Unauthenticated PHP Object Injection in GEO my WordPress <= 4.5.5.3 versions. |
| 🔴 critical | CVE-2026-61997: Unauthenticated PHP Object Injection in Legal Stone <= 1.2.11 versions. | — | Unauthenticated PHP Object Injection in Legal Stone <= 1.2.11 versions. |
| 🔴 critical | CVE-2026-61998: Unauthenticated PHP Object Injection in Le Truffe <= 1.1.7 versions. | — | Unauthenticated PHP Object Injection in Le Truffe <= 1.1.7 versions. |
| 🔴 critical | CVE-2026-62001: Unauthenticated PHP Object Injection in Marcell <= 1.2.14 versions. | — | Unauthenticated PHP Object Injection in Marcell <= 1.2.14 versions. |
| 🔴 critical | CVE-2026-62002: Unauthenticated PHP Object Injection in Meals & Wheels <= 1.1.13 versions. | — | Unauthenticated PHP Object Injection in Meals & Wheels <= 1.1.13 versions. |
| 🔴 critical | CVE-2026-62003: Unauthenticated PHP Object Injection in Mission <= 1.22 versions. | — | Unauthenticated PHP Object Injection in Mission <= 1.22 versions. |
| 🔴 critical | CVE-2026-62004: Unauthenticated PHP Object Injection in Motorix <= 1.11 versions. | — | Unauthenticated PHP Object Injection in Motorix <= 1.11 versions. |
| 🔴 critical | CVE-2026-62005: Unauthenticated PHP Object Injection in Muzicon <= 1.15 versions. | — | Unauthenticated PHP Object Injection in Muzicon <= 1.15 versions. |
| 🔴 critical | CVE-2026-62006: Unauthenticated PHP Object Injection in Nuts <= 1.12 versions. | — | Unauthenticated PHP Object Injection in Nuts <= 1.12 versions. |
| 🔴 critical | CVE-2026-62008: Unauthenticated PHP Object Injection in Orpheus <= 1.8 versions. | — | Unauthenticated PHP Object Injection in Orpheus <= 1.8 versions. |
| 🔴 critical | CVE-2026-62009: Unauthenticated PHP Object Injection in Filmax <= 1.1.11 versions. | — | Unauthenticated PHP Object Injection in Filmax <= 1.1.11 versions. |
| 🔴 critical | CVE-2026-62010: Unauthenticated PHP Object Injection in Avventure <= 1.1.12 versions. | — | Unauthenticated PHP Object Injection in Avventure <= 1.1.12 versions. |
| 🔴 critical | CVE-2026-62011: Unauthenticated PHP Object Injection in Bonbon <= 1.11 versions. | — | Unauthenticated PHP Object Injection in Bonbon <= 1.11 versions. |
| 🔴 critical | CVE-2026-62012: Unauthenticated PHP Object Injection in Coinpress <= 1.0.15 versions. | — | Unauthenticated PHP Object Injection in Coinpress <= 1.0.15 versions. |
| 🔴 critical | CVE-2026-62013: Unauthenticated PHP Object Injection in Edge Decor <= 2.9 versions. | — | Unauthenticated PHP Object Injection in Edge Decor <= 2.9 versions. |
| 🔴 critical | CVE-2026-62014: Unauthenticated PHP Object Injection in EmojiNation <= 1.0.12 versions. | — | Unauthenticated PHP Object Injection in EmojiNation <= 1.0.12 versions. |
| 🔴 critical | CVE-2026-62015: Unauthenticated PHP Object Injection in Gamezone <= 1.1.11 versions. | — | Unauthenticated PHP Object Injection in Gamezone <= 1.1.11 versions. |
| 🔴 critical | CVE-2026-62016: Unauthenticated PHP Object Injection in Gamic <= 1.19 versions. | — | Unauthenticated PHP Object Injection in Gamic <= 1.19 versions. |
| 🔴 critical | CVE-2026-62017: Unauthenticated PHP Object Injection in Good Homes <= 1.3.13 versions. | — | Unauthenticated PHP Object Injection in Good Homes <= 1.3.13 versions. |
| 🔴 critical | CVE-2026-62018: Unauthenticated PHP Object Injection in Gunslinger <= 1.11 versions. | — | Unauthenticated PHP Object Injection in Gunslinger <= 1.11 versions. |
| 🔴 critical | CVE-2026-62131: Unauthenticated PHP Object Injection in Zoho Flow <= 2.14.5 versions. | — | Unauthenticated PHP Object Injection in Zoho Flow <= 2.14.5 versions. |
| 🔴 critical | CVE-2026-103039: The Gravity Forms plugin for WordPress is vulnerable to PHP Object Injection in all ver… | `T1190` | The Gravity Forms plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.1.2 |
| 🔴 critical | CVE-2026-119706: InternLM LMDeploy 0.9.0 through 0.18.0 contains an unauthenticated remote code executio… | `T1190` | InternLM LMDeploy 0.9.0 through 0.18.0 contains an unauthenticated remote code execution vulnerability that allows remot |
| 🔴 critical | CVE-2026-119526: Deserialization of Untrusted Data vulnerability in ThemeREX Royal Event allows Object I… | `T1059.007` | Deserialization of Untrusted Data vulnerability in ThemeREX Royal Event allows Object Injection.

This issue affects Roy |
| 🔴 critical | CVE-2026-39738: Unauthenticated PHP Object Injection in FunnelKit Automations <= 3.8.6.1 versions. | — | Unauthenticated PHP Object Injection in FunnelKit Automations <= 3.8.6.1 versions. |
| 🔴 critical | CVE-2026-90888: Unauthenticated PHP Object Injection in LeadSnap <= 1.25 versions. | — | Unauthenticated PHP Object Injection in LeadSnap <= 1.25 versions. |
| 🔴 critical | CVE-2026-109220: The PDF Invoice for WooCommerce + Drag and Drop Template Builder plugin for WordPress i… | — | The PDF Invoice for WooCommerce + Drag and Drop Template Builder plugin for WordPress is vulnerable to PHP Object Inject |
| 🔴 critical | CVE-2026-118636: **UNSUPPORTED WHEN ASSIGNED** 

JavaNativeMessageDecoder in the MINA 3.0 codec module c… | `T1190` | **UNSUPPORTED WHEN ASSIGNED** 

JavaNativeMessageDecoder in the MINA 3.0 codec module calls ObjectInputStream.readObject |
| 🟠 high | CVE-2026-115190: An insecure deserialization (PHP object injection) vulnerability exists in Mautic's han… | `T1190`, `T1059.007` | An insecure deserialization (PHP object injection) vulnerability exists in Mautic's handling of segment filters and cust |
| 🟠 high | CVE-2026-115912: vLLM is an inference and serving engine for large language models. | — | vLLM is an inference and serving engine for large language models. Prior to 0.32.0, an authenticated caller can place fo |
| 🟠 high | CVE-2026-116580: Seroval facilitates JavaScript value stringification, including complex structures beyo… | — | Seroval facilitates JavaScript value stringification, including complex structures beyond JSON.stringify capabilities. P |
| 🟠 high | CVE-2026-75891: The Kirki plugin for WordPress is vulnerable to Privilege Escalation via PHP Object Inj… | `T1068`, `T1059.007` | The Kirki plugin for WordPress is vulnerable to Privilege Escalation via PHP Object Injection in all versions up to, and |
| 🟠 high | CVE-2026-1928: The Rank Math SEO – AI SEO Tools to Dominate SEO Rankings plugin for WordPress is vulne… | `T1190`, `T1059.007` | The Rank Math SEO – AI SEO Tools to Dominate SEO Rankings plugin for WordPress is vulnerable to PHP Object Injection in  |
| 🟠 high | CVE-2026-116391: Deserialization of Untrusted Data vulnerability in GS Plugins GS Logo Slider gs-logo-sl… | `T1059.007` | Deserialization of Untrusted Data vulnerability in GS Plugins GS Logo Slider gs-logo-slider allows Object Injection.This |
| 🟠 high | CVE-2026-116392: Deserialization of Untrusted Data vulnerability in PickPlugins Accordion accordions all… | `T1059.007` | Deserialization of Untrusted Data vulnerability in PickPlugins Accordion accordions allows Object Injection.This issue a |
| 🟠 high | CVE-2026-115590: Deserialization of Untrusted Data vulnerability in weDevs Dokan dokan-lite allows Objec… | `T1059.007` | Deserialization of Untrusted Data vulnerability in weDevs Dokan dokan-lite allows Object Injection.This issue affects Do |
| 🟠 high | CVE-2026-116389: Deserialization of Untrusted Data vulnerability in crossi72 Phoenix Media Rename phoeni… | `T1059.007` | Deserialization of Untrusted Data vulnerability in crossi72 Phoenix Media Rename phoenix-media-rename allows Object Inje |
| 🟠 high | CVE-2026-116390: Deserialization of Untrusted Data vulnerability in stepasyuk Filter Everything&nbsp;— W… | `T1059.007` | Deserialization of Untrusted Data vulnerability in stepasyuk Filter Everything&nbsp;— WordPress &amp; WooCommerce Filter |
| 🟠 high | CVE-2026-118613: Ultralytics torch_load Deserialization of Untrusted Data Remote Code Execution Vulnerab… | `T1190`, `T1059.007` | Ultralytics torch_load Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows  |
| 🟠 high | CVE-2026-118617: Ultralytics load_dataset_cache_file Deserialization of Untrusted Data Remote Code Execu… | `T1190`, `T1059.007` | Ultralytics load_dataset_cache_file Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerab |
| 🟠 high | CVE-2026-15564: Wildfly's IIOP listener may permit deserialization of input streams before authenticati… | `T1059.007` | Wildfly's IIOP listener may permit deserialization of input streams before authentication is performed. An attacker who  |
| 🟠 high | CVE-2026-104317: IBM Langflow OSS 1.0.0 through 1.12.3 could allow a remote attacker who could reach the… | `T1190`, `T1059.007` | IBM Langflow OSS 1.0.0 through 1.12.3 could allow a remote attacker who could reach the message broker to execute arbitr |
| | _+27 more…_ | | |

## Path Traversal & File Disclosure (38)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-107092: NexoPOS v6.2.4 is vulnerable to Directory Traversal via the api/update endpoint. | — | NexoPOS v6.2.4 is vulnerable to Directory Traversal via the api/update endpoint. |
| 🔴 critical | CVE-2026-113617: The Automated Import Products to Cart WordPress plugin before 1.0.4 does not sanitize a… | — | The Automated Import Products to Cart WordPress plugin before 1.0.4 does not sanitize a user-supplied file path before u |
| 🔴 critical | CVE-2026-119145: Frappe before 15.121.0 and 16.x before 16.34.0 contains a path traversal vulnerability … | `T1190` | Frappe before 15.121.0 and 16.x before 16.34.0 contains a path traversal vulnerability because certain file-upload handl |
| 🔴 critical | CVE-2026-90864: A path traversal vulnerability in Progress Software WS_FTP Server versions prior to 202… | — | A path traversal vulnerability in Progress Software WS_FTP Server versions prior to 2024.0.7 and 2025.0.4 on Windows cou |
| 🔴 critical | CVE-2026-90866: A path traversal vulnerability in Progress Software WS_FTP Server versions prior to 202… | `T1190` | A path traversal vulnerability in Progress Software WS_FTP Server versions prior to 2024.0.7 and 2025.0.4 on Windows cou |
| 🔴 critical | CVE-2026-61738: SOCFortress CoPilot focuses on providing a single pane of glass for all your security o… | — | SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. Prior to 0.1.77, |
| 🔴 critical | CVE-2026-103882: The Acadlix LMS – AI Quiz Maker, Online Exam & Course Plugin for WordPress plugin for W… | `T1190` | The Acadlix LMS – AI Quiz Maker, Online Exam & Course Plugin for WordPress plugin for WordPress is vulnerable to arbitra |
| 🔴 critical | CVE-2026-120225: A weakness has been identified in Oray Pugongying X5 Pro up to 7.6.1. | — | A weakness has been identified in Oray Pugongying X5 Pro up to 7.6.1. Affected by this vulnerability is the function con |
| 🔴 critical | CVE-2026-120307: The Beta9 worker serves the sandbox file API from outside the container. | — | The Beta9 worker serves the sandbox file API from outside the container. getHostPathFromContainerPath turns the tenant's |
| 🔴 critical | CVE-2026-120308: A Beta9 tenant can attach a volume when deploying a function, endpoint, or task queue. | — | A Beta9 tenant can attach a volume when deploying a function, endpoint, or task queue. The gateway builds the host path  |
| 🟠 high | CVE-2026-116117: A flaw has been found in halo-dev halo up to 2.27.0-beta.1. | — | A flaw has been found in halo-dev halo up to 2.27.0-beta.1. Affected by this vulnerability is the function run.halo.app. |
| 🟠 high | CVE-2026-112343: Syncplify Server! | — | Syncplify Server! before 8.8.0 contains an access control bypass vulnerability that allows authenticated SFTP users to e |
| 🟠 high | CVE-2026-115908: zip is a zip library for Rust that supports reading and writing simple ZIP files. | — | zip is a zip library for Rust that supports reading and writing simple ZIP files. From 7.2.0 until 9.0.0, ZipArchive::ex |
| 🟠 high | CVE-2026-115924: Rembg is a tool to remove images background. | — | Rembg is a tool to remove images background. Prior to 2.0.82, the public /api/remove endpoint passes attacker-controlled |
| 🟠 high | CVE-2026-94346: PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through 8.7,… | — | PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through 8.7, LTS2024 release versions 7.13.1. |
| 🟠 high | CVE-2026-116682: FileBrowser Quantum is a free, self-hosted, web-based file manager. | — | FileBrowser Quantum is a free, self-hosted, web-based file manager. Prior to 1.5.2-stable and 2.0.1-beta, file read hand |
| 🟠 high | CVE-2026-112350: Sunhillo SureLine before 9.1.5 contains a path traversal vulnerability in the radarUpda… | `T1078` | Sunhillo SureLine before 9.1.5 contains a path traversal vulnerability in the radarUpdater.cgi endpoint that allows unau |
| 🟠 high | CVE-2026-116690: MLflow is an open source AI engineering platform for agents, large language models, and… | — | MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. From 3. |
| 🟠 high | CVE-2026-58257: GRR is a resource management and reservation application. | — | GRR is a resource management and reservation application. Prior to the advisory-reported fixed version 4.5.0, the databa |
| 🟠 high | CVE-2026-15323: The Product Designer for WooCommerce WordPress \| Lumise plugin for WordPress is vulnera… | — | The Product Designer for WooCommerce WordPress \| Lumise plugin for WordPress is vulnerable to Directory Traversal in all |
| 🟠 high | CVE-2026-86398: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🟠 high | CVE-2026-118485: Axel Download Accelerator 2.17.14 and earlier performs URL percent-decoding (http_decod… | — | Axel Download Accelerator 2.17.14 and earlier performs URL percent-decoding (http_decode()) on the output filename after |
| 🟠 high | CVE-2026-118038: In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, a pat… | — | In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, a path traversal vulnerability in the  |
| 🟠 high | CVE-2026-59179: OpenHop is a tool for creating interactive data-flow diagrams. | — | OpenHop is a tool for creating interactive data-flow diagrams. Prior to 0.3.7, `@openhop/server` passes unauthenticated  |
| 🟠 high | CVE-2026-103407: An Improper Limitation of a Pathname to a Restricted Directory vulnerability in ConfigD… | — | An Improper Limitation of a Pathname to a Restricted Directory vulnerability in ConfigDirector in Juniper Networks Sessi |
| 🟠 high | CVE-2026-118619: Ultralytics Google Drive Download Path Traversal Remote Code Execution Vulnerability. | `T1190` | Ultralytics Google Drive Download Path Traversal Remote Code Execution Vulnerability. This vulnerability allows remote a |
| 🟠 high | CVE-2026-118633: A path traversal vulnerability allows a remote unauthenticated attacker to execute arbi… | `T1190` | A path traversal vulnerability allows a remote unauthenticated attacker to execute arbitrary code as root in Sophos UTM  |
| 🟠 high | CVE-2026-93851: Mattermost versions 11.9.x <= 11.9.1, 11.8.x <= 11.8.5, 11.7.x <= 11.7.10 fail to valid… | — | Mattermost versions 11.9.x <= 11.9.1, 11.8.x <= 11.8.5, 11.7.x <= 11.7.10 fail to validate the target post ID in the Age |
| 🟠 high | CVE-2026-110244: IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to ob… | — | IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to obtain sensitive information due to |
| 🟠 high | CVE-2026-84294: Improper limitation of pathname in the Ad Hoc Transfer component of Progress Software W… | — | Improper limitation of pathname in the Ad Hoc Transfer component of Progress Software WS_FTP Server versions prior to 20 |
| 🟠 high | CVE-2026-118758: Kubeflow Pipelines enables users to build and deploy portable, scalable machine learnin… | — | Kubeflow Pipelines enables users to build and deploy portable, scalable machine learning workflows. Prior to 2.18.0, the |
| 🟠 high | CVE-2026-119250: A malicious actor with local access and low privileges could exploit an External Contro… | — | A malicious actor with local access and low privileges could exploit an External Control of File Name or Path vulnerabil |
| 🟠 high | CVE-2010-20125: DedeCMS before 5.7 contains a file inclusion vulnerability in plus/carbuyaction.php tha… | — | DedeCMS before 5.7 contains a file inclusion vulnerability in plus/carbuyaction.php that allows remote unauthenticated a |
| 🟠 high | CVE-2026-119979: LM Studio before 0.4.22+1 contains a path traversal vulnerability in the model download… | — | LM Studio before 0.4.22+1 contains a path traversal vulnerability in the model downloader's resolveDownloadRequest that  |
| 🟠 high | CVE-2026-84243: The gettext family of functions in the GNU C Library version 2.0 and later accept LANGU… | `T1190` | The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE environment variable entries  |
| 🟠 high | CVE-2026-39734: Unauthenticated Path Traversal in WP EasyPay <= 4.5.4 versions. | — | Unauthenticated Path Traversal in WP EasyPay <= 4.5.4 versions. |
| 🟠 high | CVE-2026-62331: praktor is a multi-agent Claude Code orchestrator with Telegram input and output, Docke… | — | praktor is a multi-agent Claude Code orchestrator with Telegram input and output, Docker isolation, and a Mission Contro |
| 🟠 high | CVE-2026-116249: In server mode pgAdmin 4 resolves a server's password file, SSL certificate, key, CRL a… | — | In server mode pgAdmin 4 resolves a server's password file, SSL certificate, key, CRL and SSH tunnel identity file relat |

## SSRF, CSRF & Open Redirect (34)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-116863: Cross-Site Request Forgery (CSRF) vulnerability in Tribulant Software Newsletters newsl… | — | Cross-Site Request Forgery (CSRF) vulnerability in Tribulant Software Newsletters newsletters-lite allows Cross Site Req |
| 🔴 critical | CVE-2026-55598: PinePods is a complete, self-hosted podcast management system written in Rust. | — | PinePods is a complete, self-hosted podcast management system written in Rust. Prior to 0.9.0, an authenticated user can |
| 🟠 high | CVE-2026-111841: Cross-Site Request Forgery (CSRF) vulnerability in Aman FunnelKit Automations wp-market… | — | Cross-Site Request Forgery (CSRF) vulnerability in Aman FunnelKit Automations wp-marketing-automations allows Cross Site |
| 🟠 high | CVE-2026-116256: A vulnerability was found in geesondog RhaPHP up to 7ae639ccf8dcb627faace096d030bd4cb4c… | — | A vulnerability was found in geesondog RhaPHP up to 7ae639ccf8dcb627faace096d030bd4cb4cfb905. Affected by this vulnerabi |
| 🟠 high | CVE-2026-115717: Frappe Builder versions before 1.36.1 contain a server-side request forgery vulnerabili… | — | Frappe Builder versions before 1.36.1 contain a server-side request forgery vulnerability in the convert_to_webp API end |
| 🟠 high | CVE-2026-116748: Transmission 4.0.0 before 4.1.3 contains a permissive CORS vulnerability in handle_requ… | — | Transmission 4.0.0 before 4.1.3 contains a permissive CORS vulnerability in handle_request() in rpc-server.cc that expos |
| 🟠 high | CVE-2026-116838: A malicious actor who lures an authenticated user to a malicious page could exploit a C… | `T1059` | A malicious actor who lures an authenticated user to a malicious page could exploit a Cross-Site Request Forgery (CSRF)  |
| 🟠 high | CVE-2026-116839: A malicious actor who lures an authenticated user to a malicious page could exploit a C… | — | A malicious actor who lures an authenticated user to a malicious page could exploit a Cross-Site Request Forgery (CSRF)  |
| 🟠 high | CVE-2026-116880: Semantic MediaWiki from 3.0.0 before 7.3.1 contains a cross-site request forgery vulner… | — | Semantic MediaWiki from 3.0.0 before 7.3.1 contains a cross-site request forgery vulnerability in Special:SMWAdmin becau |
| 🟠 high | CVE-2026-117536: REDAXO before 5.21.3 contains a cross-site request forgery vulnerability in the backend… | — | REDAXO before 5.21.3 contains a cross-site request forgery vulnerability in the backend user administration page (users/ |
| 🟠 high | CVE-2026-24269: NVIDIA TensorRT-LLM contains a vulnerability where an attacker could cause a server-sid… | — | NVIDIA TensorRT-LLM contains a vulnerability where an attacker could cause a server-side request forgery. A successful e |
| 🟠 high | CVE-2026-65120: NVIDIA TensorRT-LLM contains a vulnerability where an attacker could cause a server-sid… | — | NVIDIA TensorRT-LLM contains a vulnerability where an attacker could cause a server-side request forgery. A successful e |
| 🟠 high | CVE-2026-117553: Umbraco CMS before 17.7.2 and 18.2.2 contains an authentication bypass vulnerability th… | `T1078` | Umbraco CMS before 17.7.2 and 18.2.2 contains an authentication bypass vulnerability that allows unauthenticated attacke |
| 🟠 high | CVE-2015-20129: CrushFTP before 7.3.0 contains a cross-site request forgery vulnerability that allows a… | — | CrushFTP before 7.3.0 contains a cross-site request forgery vulnerability that allows attackers to perform administrativ |
| 🟠 high | CVE-2026-111120: The VikRentCar Car Rental Management System plugin for WordPress is vulnerable to Cross… | `T1190` | The VikRentCar Car Rental Management System plugin for WordPress is vulnerable to Cross-Site Request Forgery in all vers |
| 🟠 high | CVE-2026-92797: The MemberPress plugin for WordPress is vulnerable to Cross-Site Request Forgery in ver… | — | The MemberPress plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 1.14. |
| 🟠 high | CVE-2026-88967: A user with query access to an Azure Monitor data source in Grafana can cause server-si… | — | A user with query access to an Azure Monitor data source in Grafana can cause server-side requests to an attacker-contro |
| 🟠 high | CVE-2026-118679: n8n before 1.123.83, 2.41.4, and 2.42.1 contains a server-side request forgery vulnerab… | — | n8n before 1.123.83, 2.41.4, and 2.42.1 contains a server-side request forgery vulnerability in the Slack Trigger webhoo |
| 🟠 high | CVE-2025-14260: Due to the improper implementation of access control rules, the WSO2 product accepts us… | — | Due to the improper implementation of access control rules, the WSO2 product accepts user-supplied input related to reso |
| 🟠 high | CVE-2026-13451: A flaw was found in KServe. | — | A flaw was found in KServe. A namespace-scoped user with create/update permissions on InferenceService custom resources  |
| 🟠 high | CVE-2026-118659: Happy DOM is a JavaScript implementation of a web browser without its graphical user in… | — | Happy DOM is a JavaScript implementation of a web browser without its graphical user interface. Prior to 21.0.2, the Hap |
| 🟠 high | CVE-2026-118660: Happy DOM is a JavaScript implementation of a web browser without its graphical user in… | — | Happy DOM is a JavaScript implementation of a web browser without its graphical user interface. Prior to 21.0.0, Happy D |
| 🟠 high | CVE-2026-61572: AVideo is a video-sharing Platform. | — | AVideo is a video-sharing Platform. Before the initial remediation attempt in 8.1.0, `url_get_contents` in `objects/func |
| 🟠 high | CVE-2026-111418: A server-side request forgery (SSRF) vulnerability exists in the Foxit official website… | — | A server-side request forgery (SSRF) vulnerability exists in the Foxit official website’s HTML-to-PDF conversion service |
| 🟠 high | CVE-2026-116399: Cross-Site Request Forgery (CSRF) vulnerability in InstaWP InstaWP Connect instawp-conn… | — | Cross-Site Request Forgery (CSRF) vulnerability in InstaWP InstaWP Connect instawp-connect allows Cross Site Request For |
| 🟠 high | CVE-2026-107020: An issue in the activity.LoadLinkLaterActivity component of FeedEx / Handy News Reader … | — | An issue in the activity.LoadLinkLaterActivity component of FeedEx / Handy News Reader versionCode 116 allows attackers  |
| 🟠 high | CVE-2026-13303: HashiCorp Boundary and Boundary Enterprise are vulnerable to a server-side request forg… | — | HashiCorp Boundary and Boundary Enterprise are vulnerable to a server-side request forgery in the Vault credential store |
| 🟠 high | CVE-2026-119407: Element Web and Element Desktop before 1.12.32 accept guest credentials from URL fragme… | — | Element Web and Element Desktop before 1.12.32 accept guest credentials from URL fragment parameters in loadSession, all |
| 🟠 high | CVE-2026-119426: phpMyAdmin through 5.2.3 contains a cross-site request forgery vulnerability that allow… | — | phpMyAdmin through 5.2.3 contains a cross-site request forgery vulnerability that allows remote attackers to execute arb |
| 🟠 high | CVE-2026-119549: Jellyfin through 12.4 contains a server-side request forgery vulnerability that lets au… | — | Jellyfin through 12.4 contains a server-side request forgery vulnerability that lets authenticated users bypass SvgSecur |
| 🟠 high | CVE-2026-65566: Cross-Site Request Forgery (CSRF) vulnerability in Meow Apps AI Engine ai-engine allows… | — | Cross-Site Request Forgery (CSRF) vulnerability in Meow Apps AI Engine ai-engine allows Cross Site Request Forgery.This  |
| 🟠 high | CVE-2026-59978: AdminNeo is a full-featured database management tool written in PHP. | — | AdminNeo is a full-featured database management tool written in PHP. From 4.6.2 until 5.5.0, the unauthenticated `?scrip |
| 🟠 high | CVE-2026-63184: Refitter is a tool for generating a C# REST API client using the Refit library. | — | Refitter is a tool for generating a C# REST API client using the Refit library. Prior to 2.1.1, the `refitter` dotnet to |
| 🟠 high | CVE-2026-120207: Thelia Page Module before 2.0.4 contains a cross-site request forgery vulnerability tha… | — | Thelia Page Module before 2.0.4 contains a cross-site request forgery vulnerability that allows remote attackers to dele |

## Cryptographic Weaknesses (11)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-117564: nest-admin before 1.0.1 contains an authentication bypass vulnerability that allows una… | `T1078` | nest-admin before 1.0.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge a |
| 🔴 critical | CVE-2026-86384: Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 re… | — | Dell PowerProtect Data Domain, Feature Release versions 7.7.1.0 through 8.8, LTS2024 release versions 7.13.1.0 through 7 |
| 🔴 critical | CVE-2026-119597: OpenDeepWiki through 2.0.6 contains a hard-coded JWT signing key vulnerability that all… | — | OpenDeepWiki through 2.0.6 contains a hard-coded JWT signing key vulnerability that allows unauthenticated attackers to  |
| 🔴 critical | CVE-2026-61737: ng-antd-admin is an Angular and NestJS administration system template. | — | ng-antd-admin is an Angular and NestJS administration system template. Prior to 22.0, a hardcoded default `JWT` secret p |
| 🔴 critical | CVE-2026-120209: AJ-Report through 1.7.1 signs share tokens with a hard-coded JWT secret, allowing attac… | `T1190` | AJ-Report through 1.7.1 signs share tokens with a hard-coded JWT secret, allowing attackers to forge valid Share-Tokens  |
| 🟠 high | CVE-2026-112345: TTLock Android application before v9.8.260718 and associated smart-lock firmware contai… | — | TTLock Android application before v9.8.260718 and associated smart-lock firmware contain a hardcoded static AES key vuln |
| 🟠 high | CVE-2014-125135: A security vulnerability has been detected in OctoPrint 1.0.0/1.1.0. | — | A security vulnerability has been detected in OctoPrint 1.0.0/1.1.0. Affected is an unknown function of the component Fl |
| 🟠 high | CVE-2026-116747: Kener 3.0.0 before 4.1.10 contains an authentication bypass vulnerability that allows u… | `T1078` | Kener 3.0.0 before 4.1.10 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge |
| 🟠 high | CVE-2026-63286: Database backups are vulnerable to offline attacks. | — | Database backups are vulnerable to offline attacks. Backups created using a version prior to the patched version are sti |
| 🟠 high | CVE-2026-91912: Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Use of Hard-coded Cryp… | — | Dell OpenManage Enterprise, versions prior to 4.8.0, contains an Use of Hard-coded Cryptographic Key vulnerability. A lo |
| 🟠 high | CVE-2026-119662: Songloft 2.9.0 before 2.13.6 contains a hardcoded credentials vulnerability that allows… | — | Songloft 2.9.0 before 2.13.6 contains a hardcoded credentials vulnerability that allows adjacent network attackers to au |

## Information Disclosure (11)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-65119: NVIDIA TensorRT-LLM for any platform contains a vulnerability in KvCacheAwareRouter tok… | — | NVIDIA TensorRT-LLM for any platform contains a vulnerability in KvCacheAwareRouter tokenizer loading, where an attacker |
| 🟠 high | CVE-2026-87102: Sensitive information disclosure and manipulation due to improper token validation. | — | Sensitive information disclosure and manipulation due to improper token validation. The following products are affected: |
| 🟠 high | CVE-2026-87103: Sensitive information disclosure and manipulation due to improper token validation. | — | Sensitive information disclosure and manipulation due to improper token validation. The following products are affected: |
| 🟠 high | CVE-2026-115591: Insertion of Sensitive Information Into Sent Data vulnerability in Supsystic Contact Fo… | — | Insertion of Sensitive Information Into Sent Data vulnerability in Supsystic Contact Form by Supsystic contact-form-by-s |
| 🟠 high | CVE-2026-118643: n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 stores credential secr… | — | n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 stores credential secrets in execution error data when  |
| 🟠 high | CVE-2026-118647: n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 saves the SeaTable Tri… | — | n8n before 1.123.85, 2.x before 2.43.5, and 2.44.x before 2.44.1 saves the SeaTable Trigger node's API token in error ex |
| 🟠 high | CVE-2026-111419: A sensitive information exposure vulnerability exists on the Foxit official website bec… | — | A sensitive information exposure vulnerability exists on the Foxit official website because JavaScript code contains thi |
| 🟠 high | CVE-2026-118083: Unauthenticated Sensitive Data Exposure in WP Crowdfunding <= 2.2.2 versions. | — | Unauthenticated Sensitive Data Exposure in WP Crowdfunding <= 2.2.2 versions. |
| 🟠 high | CVE-2026-45049: Open Access Management (OpenAM) is an access management solution. | — | Open Access Management (OpenAM) is an access management solution. Prior to 16.1.1, the `Cross-Domain Single Sign-On` (`C |
| 🟠 high | CVE-2026-119290: Zuke is a code-first, strongly typed build automation system for Deno. | — | Zuke is a code-first, strongly typed build automation system for Deno. Prior to 1.51.0, @zuke/core writes rendered repor |
| 🟠 high | CVE-2026-116861: Unauthenticated Sensitive Data Exposure in Flexible Chat <= 1.1.0 versions. | — | Unauthenticated Sensitive Data Exposure in Flexible Chat <= 1.1.0 versions. |

## Denial of Service (42)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-115907: zip is a zip library for Rust that supports reading and writing simple ZIP files. | — | zip is a zip library for Rust that supports reading and writing simple ZIP files. From 5.1.0 until 9.0.0, applications b |
| 🟠 high | CVE-2026-115909: zip is a zip library for Rust that supports reading and writing simple ZIP files. | — | zip is a zip library for Rust that supports reading and writing simple ZIP files. From 1.3.0 until 9.0.0, ZipArchive::ex |
| 🟠 high | CVE-2026-81038: The Object Transfer Service server builds its Object Action Control Point (OACP) respon… | `T1203` | The Object Transfer Service server builds its Object Action Control Point (OACP) response indication in oacp_ind_send()  |
| 🟠 high | CVE-2026-105626: HashiCorp Consul and Consul Enterprise are vulnerable to a denial of service in the HTT… | — | HashiCorp Consul and Consul Enterprise are vulnerable to a denial of service in the HTTP API that may allow an unauthent |
| 🟠 high | CVE-2026-33521: There is s denial of service vulnerability in Esri ArcGIS Server versions 12.0 and prio… | — | There is s denial of service vulnerability in Esri ArcGIS Server versions 12.0 and prior that may allow a remote, unauth |
| 🟠 high | CVE-2026-116581: Seroval facilitates JavaScript value stringification, including complex structures beyo… | — | Seroval facilitates JavaScript value stringification, including complex structures beyond JSON.stringify capabilities. P |
| 🟠 high | CVE-2026-116584: Seroval facilitates JavaScript value stringification, including complex structures beyo… | — | Seroval facilitates JavaScript value stringification, including complex structures beyond JSON.stringify capabilities. F |
| 🟠 high | CVE-2026-116587: Go JOSE provides an implementation of the Javascript Object Signing and Encryption set … | — | Go JOSE provides an implementation of the Javascript Object Signing and Encryption set of standards in Go, including sup |
| 🟠 high | CVE-2026-116589: Datadog dd-trace-py: IAST instrumentation can lead to application DOS | — | [cvefeed.io] Datadog dd-trace-py: IAST instrumentation can lead to application DOS |
| 🟠 high | CVE-2026-106174: A improper locking vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.4 through 7.6.6… | — | A improper locking vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.4 through 7.6.6 may allow an unauthenticated att |
| 🟠 high | CVE-2026-116871: Semantic MediaWiki 3.0.0 before 7.3.1 contains an uncontrolled recursion vulnerability … | — | Semantic MediaWiki 3.0.0 before 7.3.1 contains an uncontrolled recursion vulnerability in LegacyParser::getSubqueryDescr |
| 🟠 high | CVE-2026-116878: Semantic MediaWiki from 2.5.0 before 7.3.1 contains an uncontrolled resource consumptio… | — | Semantic MediaWiki from 2.5.0 before 7.3.1 contains an uncontrolled resource consumption vulnerability that allows anony |
| 🟠 high | CVE-2026-117540: svg-sanitizer from 0.5.3 before 1.1.0 contains a denial of service vulnerability in San… | — | svg-sanitizer from 0.5.3 before 1.1.0 contains a denial of service vulnerability in Sanitizer::sanitize() that repeatedl |
| 🟠 high | CVE-2026-114597: In EPICS Base release 7.0.10 and prior, an insufficient validation of element or length… | — | In EPICS Base release 7.0.10 and prior, an insufficient validation of element or length values in a network message can  |
| 🟠 high | CVE-2026-77167: Abusing the federated share endpoint, an attacker can write arbitrary rows into the oc_… | — | Abusing the federated share endpoint, an attacker can write arbitrary rows into the oc_share_external database table. Th |
| 🟠 high | CVE-2026-116656: Tanium addressed an uncontrolled resource consumption vulnerability in Enforce. | — | Tanium addressed an uncontrolled resource consumption vulnerability in Enforce. |
| 🟠 high | CVE-2026-87086: Tanium addressed a denial of service vulnerability in Provision. | — | Tanium addressed a denial of service vulnerability in Provision. |
| 🟠 high | CVE-2026-118035: In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncon… | — | In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncontrolled recursion, inefficient al |
| 🟠 high | CVE-2026-118036: In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncon… | — | In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncontrolled recursion, infinite loop, |
| 🟠 high | CVE-2026-118037: In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncon… | — | In Progress® Telerik® Document Processing Libraries prior to version 2026.3.1027, uncontrolled recursion, infinite loop, |
| 🟠 high | CVE-2026-118686: EspoCRM before 9.3.11 and 10.x before 10.0.8 contains a denial of service vulnerability… | — | EspoCRM before 9.3.11 and 10.x before 10.0.8 contains a denial of service vulnerability in which the password-redaction  |
| 🟠 high | CVE-2026-76418: A vulnerability in the Remote Access SSL VPN service of Cisco Secure Firewall Adaptive … | — | A vulnerability in the Remote Access SSL VPN service of Cisco Secure Firewall Adaptive Security Appliance (ASA) Software |
| 🟠 high | CVE-2026-118689: OvenMediaEngine through 0.21.0 contains a denial of service vulnerability in OvtPacket:… | — | OvenMediaEngine through 0.21.0 contains a denial of service vulnerability in OvtPacket::LoadHeader() that allows unauthe |
| 🟠 high | CVE-2026-118694: python-markdown2 through 2.5.5 contains a denial of service vulnerability that allows r… | — | python-markdown2 through 2.5.5 contains a denial of service vulnerability that allows remote users to exhaust CPU by sub |
| 🟠 high | CVE-2026-118664: decode-uri-component: Denial of service via quadratic replacement of percent-encoded runs | — | [cvefeed.io] decode-uri-component: Denial of service via quadratic replacement of percent-encoded runs |
| 🟠 high | CVE-2026-119119: Crawl4AI before 0.9.5 contains a denial of service vulnerability in the Docker API serv… | — | Crawl4AI before 0.9.5 contains a denial of service vulnerability in the Docker API server where _clamp_untrusted() fails |
| 🟠 high | CVE-2026-118779: Forge (also called node-forge) is a native implementation of Transport Layer Security i… | — | Forge (also called node-forge) is a native implementation of Transport Layer Security in JavaScript. Prior to 1.4.1, the |
| 🟠 high | CVE-2026-41216: An invalid pointer dereference vulnerability exists in the vtkPNGReader::ExecuteInforma… | — | An invalid pointer dereference vulnerability exists in the vtkPNGReader::ExecuteInformation functionality of vtk 9.6. A  |
| 🟠 high | CVE-2026-42057: An invalid pointer dereference vulnerability exists in the vtkPNGReader::vtkPNGReaderUp… | — | An invalid pointer dereference vulnerability exists in the vtkPNGReader::vtkPNGReaderUpdate2 functionality of vtk 9.6. A |
| 🟠 high | CVE-2026-119187: Forge (also called node-forge) is a native implementation of Transport Layer Security i… | — | Forge (also called node-forge) is a native implementation of Transport Layer Security in JavaScript. Prior to 1.4.1, the |
| 🟠 high | CVE-2026-119191: Forge (also called node-forge) is a native implementation of Transport Layer Security i… | — | Forge (also called node-forge) is a native implementation of Transport Layer Security in JavaScript. Prior to 1.4.1, the |
| 🟠 high | CVE-2026-119283: joserfc is a Python library that provides an implementation of several JSON Object Sign… | — | joserfc is a Python library that provides an implementation of several JSON Object Signing and Encryption (JOSE) standar |
| 🟠 high | CVE-2026-119286: GraphQL-core is a Python port of the GraphQL.js reference implementation. | — | GraphQL-core is a Python port of the GraphQL.js reference implementation. From 3.3.0a3 until 3.3.1, validate() reuses a  |
| 🟠 high | CVE-2026-118764: minimatch: potential denial of service via globparts amplification | — | [cvefeed.io] minimatch: potential denial of service via globparts amplification |
| 🟠 high | CVE-2026-103963: A flaw was found in glib-networking. | — | A flaw was found in glib-networking. When establishing connections using Transport Layer Security (TLS) version 1.3, the |
| 🟠 high | CVE-2026-119762: Axigen Mail Server before 10.5.69, 10.6.x before 10.6.40, and 10.7.x before 10.7.2 cont… | — | Axigen Mail Server before 10.5.69, 10.6.x before 10.6.40, and 10.7.x before 10.7.2 contains an unauthenticated denial of |
| 🟠 high | CVE-2026-61854: VoiceSentinel is a real-time voice moderation system for Minecraft servers. | — | VoiceSentinel is a real-time voice moderation system for Minecraft servers. From 2.2.1 until 3.3.1, the optional report  |
| 🟠 high | CVE-2026-62297: ag-psd is a JavaScript library for reading and writing Photoshop Document files. | — | ag-psd is a JavaScript library for reading and writing Photoshop Document files. Before the allocation-limit remediation |
| 🟠 high | CVE-2026-62864: Ring is a Clojure web applications library inspired by Python's WSGI and Ruby's Rack. | — | Ring is a Clojure web applications library inspired by Python's WSGI and Ruby's Rack. Prior to 1.15.5, `wrap-nested-para |
| 🟠 high | CVE-2026-63341: Aedes is an MQTT broker that can run on any stream server. | — | Aedes is an MQTT broker that can run on any stream server. Prior to 1.1.1, the MQTT broker does not bound topic depth or |
| 🟠 high | CVE-2026-120194: A flaw was found in json-glib. | — | A flaw was found in json-glib. The JSONPath slice evaluator used by json_path_query() can enter an infinite loop when gi |
| ⚪ unknown | CVE-2026-111497: Google Brotli — Google Brotli Unchecked Return Value Vulnerability | `T1190` | Google Brotli contains an unchecked return value vulnerability that allows a remote unauthenticated attacker to corrupt  |

## Network Infrastructure & IoT Device Vulnerabilities (4)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-112362: @fastify/express is a Fastify plugin that runs Express middleware inside Fastify. | — | @fastify/express is a Fastify plugin that runs Express middleware inside Fastify. In versions 4.0.5 through 4.0.8, when  |
| 🔴 critical | CVE-2026-118579: A weakness has been identified in D-Link DIR-505 1.10B02. | — | A weakness has been identified in D-Link DIR-505 1.10B02. The impacted element is the function main of the file /secmark |
| 🟠 high | CVE-2026-102814: Improper Authentication in TP-Link TDDP v2 Allows Root Command Execution in TP-Link RE305 | — | [cvefeed.io] Improper Authentication in TP-Link TDDP v2 Allows Root Command Execution in TP-Link RE305 |
| 🟠 high | CVE-2026-103401: An Improper Link Resolution Before File Access ('Link Following') vulnerability in the … | — | An Improper Link Resolution Before File Access ('Link Following') vulnerability in the unauthenticated web server handle |

## Critical-Severity Vulnerabilities (13)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-116231: A security flaw has been discovered in Oray Pugongying X5 Pro 7.6.1. | — | A security flaw has been discovered in Oray Pugongying X5 Pro 7.6.1. The impacted element is an unknown function of the  |
| 🔴 critical | CVE-2026-116232: A weakness has been identified in Oray Pugongying X5 Pro 7.6.1. | — | A weakness has been identified in Oray Pugongying X5 Pro 7.6.1. This affects the function snmp_set of the component SNMP |
| 🔴 critical | CVE-2026-116233: A security vulnerability has been detected in Oray Pugongying X5 Pro 7.6.1. | — | A security vulnerability has been detected in Oray Pugongying X5 Pro 7.6.1. This impacts an unknown function of the comp |
| 🔴 critical | CVE-2026-116234: A vulnerability was detected in Oray Pugongying X5 Pro 7.6.1. | — | A vulnerability was detected in Oray Pugongying X5 Pro 7.6.1. Affected is an unknown function of the file /etc/ipsec.con |
| 🔴 critical | CVE-2026-116235: A flaw has been found in Oray Pugongying X5 Pro 7.6.1. | — | A flaw has been found in Oray Pugongying X5 Pro 7.6.1. Affected by this vulnerability is an unknown functionality of the |
| 🔴 critical | CVE-2026-59107: A security vulnerability has been identified in the vSolution Matrix file sharing feature. | — | A security vulnerability has been identified in the vSolution Matrix file sharing feature. A shared cryptographic trust  |
| 🔴 critical | CVE-2026-107015: Insecure permissions in Simple Contacts Pro versionCode 107 allow unauthorized attacker… | — | Insecure permissions in Simple Contacts Pro versionCode 107 allow unauthorized attackers to write and read notes in anot |
| 🔴 critical | CVE-2026-107032: Insecure permissions in Bulk Share : Location Sender v2.1.0 (versionCode 5) allows unau… | — | Insecure permissions in Bulk Share : Location Sender v2.1.0 (versionCode 5) allows unauthorized attackers to invoke an e |
| 🔴 critical | CVE-2026-118762: Monkeytype is a minimalistic and customizable typing test. | `T1190` | Monkeytype is a minimalistic and customizable typing test. Prior to 26.43.0, the .github/workflows/fix-formatting.yml wo |
| 🔴 critical | CVE-2026-119261: Improper input validation in Skia in Google Chrome prior to 156.0.8078.79 allowed a rem… | `T1190` | Improper input validation in Skia in Google Chrome prior to 156.0.8078.79 allowed a remote attacker to potentially execu |
| 🔴 critical | CVE-2026-107249: Improperly Controlled Modification of Dynamically-Determined Object Attributes vulnerab… | — | Improperly Controlled Modification of Dynamically-Determined Object Attributes vulnerability in Drupal Block AJAX allows |
| 🔴 critical | CVE-2026-118697: In JetBrains Toolbox App before 3.9.1 and 3.8.2; IntelliJ IDEA before 2026.3 and 2026.2… | — | In JetBrains Toolbox App before 3.9.1 and 3.8.2; IntelliJ IDEA before 2026.3 and 2026.2.4, the jetbrainsd daemon trusted |
| 🔴 critical | CVE-2026-120224: A security flaw has been discovered in Oray Pugongying X5 Pro up to 7.6.1. | — | A security flaw has been discovered in Oray Pugongying X5 Pro up to 7.6.1. Affected is the function run_apis_by_json/run |

## High-Severity Vulnerabilities (152)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-116106: A security vulnerability has been detected in HeyCyan App 1.0.103 on Android. | — | A security vulnerability has been detected in HeyCyan App 1.0.103 on Android. Affected by this vulnerability is an unkno |
| 🟠 high | CVE-2026-116116: A vulnerability was detected in Yoosee GM8135S Camera 21.00.01.36. | — | A vulnerability was detected in Yoosee GM8135S Camera 21.00.01.36. Affected is an unknown function of the component Secu |
| 🟠 high | CVE-2026-116236: A vulnerability has been found in Oray Pugongying X5 Pro 7.6.1. | — | A vulnerability has been found in Oray Pugongying X5 Pro 7.6.1. Affected by this issue is the function plugin_init of th |
| 🟠 high | CVE-2026-116237: A vulnerability was found in Oray Pugongying X5 Pro 7.6.1. | — | A vulnerability was found in Oray Pugongying X5 Pro 7.6.1. This affects an unknown part of the component Dnsmasq. Perfor |
| 🟠 high | CVE-2026-94380: Weak Password Recovery Mechanism for Forgotten Password vulnerability in HAVELSAN Inc. | — | Weak Password Recovery Mechanism for Forgotten Password vulnerability in HAVELSAN Inc. Liman MYS allows Password Recover |
| 🟠 high | CVE-2026-116339: A vulnerability was determined in iFlytek astron-agent up to 1.1.2. | — | A vulnerability was determined in iFlytek astron-agent up to 1.1.2. This affects an unknown function of the file core/me |
| 🟠 high | CVE-2026-90885: Improper Restriction of XML External Entity Reference vulnerability in Apache Camel Sax… | — | Improper Restriction of XML External Entity Reference vulnerability in Apache Camel Saxon component.



This issue affec |
| 🟠 high | CVE-2026-115721: **UNSUPPORTED WHEN ASSIGNED**  Unbounded allocation in XML parsing in Apache Vysper; al… | — | **UNSUPPORTED WHEN ASSIGNED**  Unbounded allocation in XML parsing in Apache Vysper; all versions, may lead to an out of |
| 🟠 high | CVE-2026-116368: A vulnerability was determined in DeepSeek Harness up to 0.2.0-rc.2. | — | A vulnerability was determined in DeepSeek Harness up to 0.2.0-rc.2. This issue affects some unknown processing of the f |
| 🟠 high | CVE-2026-105608: HashiCorp Consul and Consul Enterprise are vulnerable to an authorization bypass in ser… | — | HashiCorp Consul and Consul Enterprise are vulnerable to an authorization bypass in service mesh proxy registration. Thi |
| 🟠 high | CVE-2026-115915: vLLM is an inference and serving engine for large language models. | — | vLLM is an inference and serving engine for large language models. Prior to 0.32.0, ImageMediaIO passes attacker-control |
| 🟠 high | CVE-2026-72753: When Routinator encounters an RRDP notification file with gaps in the delta entries, it… | — | When Routinator encounters an RRDP notification file with gaps in the delta entries, it is still accepted and parsed, po |
| 🟠 high | CVE-2026-72754: When Routinator encounters a CRL with many entries, it may hang or run out of memory. | — | When Routinator encounters a CRL with many entries, it may hang or run out of memory. If Routinator encounters a CRL fil |
| 🟠 high | CVE-2026-72756: Routinator exits when an rsync URI for a file obtained over RRDP contains a path that c… | — | Routinator exits when an rsync URI for a file obtained over RRDP contains a path that cannot be stored on disk, such as  |
| 🟠 high | CVE-2026-72758: When parsing an AS range in Routinator, if the maximum value of the range is smaller th… | — | When parsing an AS range in Routinator, if the maximum value of the range is smaller than the minimum value of the range |
| 🟠 high | CVE-2026-112438: A logic issue was addressed with improved state management. | `T1190` | A logic issue was addressed with improved state management. This issue is fixed in macOS Golden Gate 27.2, macOS Sequoia |
| 🟠 high | CVE-2026-112484: This issue was addressed with improved file handling. | `T1190` | This issue was addressed with improved file handling. This issue is fixed in macOS Golden Gate 27.2, macOS Sequoia 15.8. |
| 🟠 high | CVE-2026-65327: A logic issue was addressed with improved checks. | — | A logic issue was addressed with improved checks. This issue is fixed in macOS Golden Gate 27.2, macOS Sequoia 15.8.2, m |
| 🟠 high | CVE-2026-116591: compress zstd: Panic on two-block frames | — | [cvefeed.io] compress zstd: Panic on two-block frames |
| 🟠 high | CVE-2026-116588: Datadog dd-trace-py: ReDOS in URL query string obfuscation | — | [cvefeed.io] Datadog dd-trace-py: ReDOS in URL query string obfuscation |
| 🟠 high | CVE-2026-18449: The BMC does not correctly enforce integrity and encryption requirements for IPMI comma… | — | The BMC does not correctly enforce integrity and encryption requirements for IPMI commands. An attacker may be able to c |
| 🟠 high | CVE-2026-65219: A flaw in the BMC RAKP+ implementation may allow an attacker to send a request followed… | — | A flaw in the BMC RAKP+ implementation may allow an attacker to send a request followed by a specially crafted RAKP mess |
| 🟠 high | CVE-2026-82121: Origin Validation Error Vulnerability in HiRDB. | — | Origin Validation Error Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-12-01 |
| 🟠 high | CVE-2026-116872: Semantic MediaWiki from 3.0.0 before 7.3.1 contains an algorithmic complexity vulnerabi… | — | Semantic MediaWiki from 3.0.0 before 7.3.1 contains an algorithmic complexity vulnerability in TermParser::normalize_com |
| 🟠 high | CVE-2026-41021: Eaton easyE4 uses an insufficiently strong password policy. | — | Eaton easyE4 uses an insufficiently strong password policy. An attacker who obtains a password hash, including through C |
| 🟠 high | CVE-2026-100164: Observable response discrepancy vulnerability in Rolantis Information Technologies Tour… | — | Observable response discrepancy vulnerability in Rolantis Information Technologies Tourism Industry and Trade Co. Ltd. A |
| 🟠 high | CVE-2026-117601: Electrum before 4.8.3 fails to verify signatures of wallet-owned inputs in unconfirmed … | — | Electrum before 4.8.3 fails to verify signatures of wallet-owned inputs in unconfirmed mempool transactions, allowing ma |
| 🟠 high | CVE-2026-94347: PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through 8.7,… | — | PowerProtect Data Domain Virtual Edition, Feature Release versions 7.7.1.0 through 8.7, LTS2024 release versions 7.13.1. |
| 🟠 high | CVE-2026-113775: A maliciously crafted dynamic library, when loaded from an arbitrary path through the T… | `T1190` | A maliciously crafted dynamic library, when loaded from an arbitrary path through the TextCommands.LoadDll command expos |
| 🟠 high | CVE-2026-117512: A vulnerability was found in oretnom23 php-travel-agency-system. | — | A vulnerability was found in oretnom23 php-travel-agency-system. This affects an unknown part of the file admin/employee |
| 🟠 high | CVE-2026-116647: Tanium addressed an improper output sanitization vulnerability in Comply. | — | Tanium addressed an improper output sanitization vulnerability in Comply. |
| 🟠 high | CVE-2026-116649: Tanium addressed an improper output sanitization vulnerability in Enforce. | — | Tanium addressed an improper output sanitization vulnerability in Enforce. |
| 🟠 high | CVE-2026-116662: Tanium addressed a compression bomb vulnerability in Enforce. | — | Tanium addressed a compression bomb vulnerability in Enforce. |
| 🟠 high | CVE-2026-57202: Asterisk is an open source private branch exchange and telephony toolkit. | — | Asterisk is an open source private branch exchange and telephony toolkit. Prior to Asterisk 20.20.1, 21.12.3, 22.10.1, 2 |
| 🟠 high | CVE-2026-115413: Missing token audience validation in the OAuth authentication mode of AWS API MCP Serve… | — | Missing token audience validation in the OAuth authentication mode of AWS API MCP Server before version 1.6.0 might allo |
| 🟠 high | CVE-2026-57186: Asterisk is an open source private branch exchange and telephony toolkit. | — | Asterisk is an open source private branch exchange and telephony toolkit. From 21.0.0-pre1 until Asterisk 21.12.3, 22.10 |
| 🟠 high | CVE-2026-59158: Nuxt Ollama integrates the official Ollama JavaScript library into Nuxt applications. | — | Nuxt Ollama integrates the official Ollama JavaScript library into Nuxt applications. Prior to 1.3.1, `src/module.ts` un |
| 🟠 high | CVE-2026-116693: dd-trace: ReDOS in URL query string obfuscation | — | [cvefeed.io] dd-trace: ReDOS in URL query string obfuscation |
| 🟠 high | CVE-2026-108142: CDP Coordinator Service Authorization Bypass | — | [cvefeed.io] CDP Coordinator Service Authorization Bypass |
| 🟠 high | ccsec-crypto-toolkit (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | ccsec-form-validator (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | ccsseecc-crypto-toolkit (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | ccsseecc-form-validator (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | csec-crypto-toolkit (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | csec-form-validator (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | csec-form-validatorr (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | agentenact (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-10-27. Review versio |
| 🟠 high | CVE-2026-104895: The asynchronous Smile parser (NonBlockingByteArrayParser) uses a raw-binary length pre… | — | The asynchronous Smile parser (NonBlockingByteArrayParser) uses a raw-binary length prefix taken from untrusted input to |
| 🟠 high | CVE-2014-125138: C97net qEngine CMS through 6.0.0, Kemana Directory through 1.5.6, and Cart Engine throu… | — | C97net qEngine CMS through 6.0.0, Kemana Directory through 1.5.6, and Cart Engine through 3.0.0 contain an unrestricted  |
| 🟠 high | CVE-2026-118377: mews/pos through 2.0.0 contains an insufficient verification of data authenticity vulne… | — | mews/pos through 2.0.0 contains an insufficient verification of data authenticity vulnerability that allows unauthentica |
| | _+102 more…_ | | |

## Other Vulnerabilities (3)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-41709: Broadcom VMware ESX — Broadcom VMWare ESX Insufficient Logging Vulnerability | — | Broadcom VMWare ESX contains an insufficient logging vulnerability that could allow a malicious actor with admin access  |
| ⚪ unknown | CVE-2026-46300: Linux Kernel — Linux Kernel Missing Initialization of a Variable Vulnerability | — | Linux Kernel contains a missing initialization of a variable vulnerability that could allow for unintended modification  |
| ⚪ unknown | CVE-2026-118527: Ivanti Connect Secure — Ivanti Connect Secure Generation of Predictable Numbers or Identifiers Vulnerability | — | Ivanti Connect Secure contains a generation of predictable numbers or identifiers vulnerability that allows a remote aut |

## Ransomware activity (ransomware.live + peers) (367)

_Victim claims rolled up from the 7 daily briefings covering this window. Most active groups: thegentlemen (62), qilin (47), safepay (18)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | Afflelou — claimed by emperador | — | Afflelou listed by emperador. |
| 🟠 high | Bangor Wholesale Laminates — claimed by qilin (GB) | — | N/A |
| 🟠 high | Beasley Allen Law Firm — claimed by falcon (US) | — | Plaintiff litigation law firm - Our 214 GB extraction includes executed agreements, final settlement… |
| 🟠 high | Bi-silque — claimed by majinahanashi (US) | — | A Portuguese manufacturing company that produces equipment for offices, schools, and presentations. Its product line inc |
| 🟠 high | Burnaby Schools - School District 41 — claimed by qilin (CA) | — | N/A |
| 🟠 high | Delta Electric Power Association — claimed by qilin (US) | — | N/A |
| 🟠 high | Edelstahl-Mechanik GmbH — claimed by payload (DE) | — | Edelstahl-Mechanik GmbH is a German manufacturing company based in Göppingen. The company specializes in laser metal pro |
| 🟠 high | Ernesto Malvestiti S.p.A. — claimed by aurora | — | Ernesto Malvestiti S.p.A. listed by aurora. |
| 🟠 high | everon.com.ar — claimed by safepay | — | The company is headquartered in Resistencia, in Chaco Province, and specializes in providing fiber-optic internet connec |
| 🟠 high | FIRMENGRUPPE APPL Holding GmbH — claimed by qilin (DE) | — | N/A |
| 🟠 high | Five Star Sheets — claimed by qilin (US) | — | N/A |
| 🟠 high | Gamdom — claimed by whitearmor | — | Gamdom is an unregulated crypto casino and sportsbook founded in 2016. It recently suffered a hot-wa… |
| 🟠 high | Glückauf-Vermessung GmbH — claimed by payload (DE) | — | Glückauf-Vermessung GmbH (glueckauf-vermessung.de) is a German engineering and technical company based in Sondershausen, |
| 🟠 high | goldencrops.com.tw — claimed by safepay | — | The company specializes in grain-based foods, nutritional products, plant-based foods and customized food manufacturing  |
| 🟠 high | grifosespinoza.com — claimed by safepay | — | Headquartered in Lima, the company manages fuel stations that serve individual motorists, commercial customers and other |
| 🟠 high | Hochschule Worms — claimed by qilin (DE) | — | N/A |
| 🟠 high | i. — claimed by payoutsking | — | i. listed by payoutsking. |
| 🟠 high | ImmoVia Hausverwaltung — claimed by thegentlemen | — | immovia-hausverwaltung.de ImmoVia Hausverwaltung GmbH is a German property management company registered in November 202 |
| 🟠 high | Ingelectus Innovative Electrical Solutions S.L. — claimed by n0n (ES) | — | smart grid engineering firm · Spain \| Live electrical telemetry sampled from the plant control netwo… |
| 🟠 high | Inside Passage Electric Cooperative, Inc — claimed by dragonforce | — | Inside Passage Electric Cooperative, Inc listed by dragonforce. |
| 🟠 high | J.B Hunt — claimed by whitearmor | — | J.B Hunt listed by whitearmor. |
| 🟠 high | jumonji-u.ac.jp — claimed by safepay | — | The institution is operated by Jumonji Gakuen Educational Corporation and focuses on providing undergraduate and postgra |
| 🟠 high | layam.com — claimed by safepay | — | Its product portfolio includes food and provisions, beverages, tobacco products, perfumes, cosmetics, electronics, confe |
| 🟠 high | LoveSac — claimed by whitearmor | — | LoveSac listed by whitearmor. |
| 🟠 high | Lydenburg Toyota — claimed by thegentlemen | — | lydenburg.toyota.co.za Lydenburg Toyota is a Toyota dealership in Lydenburg (Mashishing), Mpumalanga, South Africa, part |
| 🟠 high | mahsing.com.my — claimed by scarlettgroup (MY) | — | Mah Sing Group is a leading Malaysian property developer specializing in affordable residential and commercial propertie |
| 🟠 high | mars-semi.com.tw — claimed by safepay | — | Established in 2001 and headquartered in Hsinchu Science Park, the company develops long-range, high-bandwidth wireless  |
| 🟠 high | Miletic GmbH — claimed by payload (DE) | — | Miletic GmbH is a German specialized contractor headquartered in Bad Schönborn that has been operating in the constructi |
| 🟠 high | Miller Stratvert — claimed by qilin (US) | — | N/A |
| 🟠 high | MISC Group — claimed by rhysida | — | MISC Group
Incorporated in 1968, MISC Group is a world leading provider of international energy-related maritime solutio |
| 🟠 high | Montship — claimed by qilin (CA) | — | N/A |
| 🟠 high | Morrison Cohen — claimed by silentransomgroup (US) | — | [AI generated] Morrison Cohen LLP is a United States law firm headquartered in New York City. It provides legal services |
| 🟠 high | Mountain Rheumatology — claimed by qilin (US) | — | N/A |
| 🟠 high | Natural Energy Laboratory of Hawaii Authority — claimed by qilin (US) | — | N/A |
| 🟠 high | Power Funding — claimed by qilin (GB) | — | N/A |
| 🟠 high | Premier Medical Group — claimed by qilin (US) | — | N/A |
| 🟠 high | quevedo-ponce.com — claimed by safepay | — | Headquartered in Quito, the firm serves domestic and international clients, including businesses, investors, entrepreneu |
| 🟠 high | RaceTrakka — claimed by qilin | — | RaceTrakka listed by qilin. |
| 🟠 high | Referans Lab Ref-Lab — claimed by doommageddon (TR) | — | Status: leaked \| Data size: 3.07 GB \| Files: 2 files \| Deadline: 2026-10-26T00:00:00Z |
| 🟠 high | Rood Trucking — claimed by safepay | — | Established in 1962 by George and Diane Rood Sr., the company developed from a single-truck operation into a regional ca |
| 🟠 high | Safe Data Storage — claimed by auditteam (GB) | — | Safe Data Storage Ltd is an active UK-based SME IT services company founded in 2004, headquartered in Orpington, Kent, a |
| 🟠 high | sequoiadental.com — claimed by threeam | — | sequoiadental.com listed by threeam. |
| 🟠 high | Seufert Construction — claimed by qilin (US) | — | N/A |
| 🟠 high | Smith Feddeler & Smith — claimed by qilin | — | Smith Feddeler & Smith listed by qilin. |
| 🟠 high | SOME — claimed by thegentlemen | — | some.it SOME Srl is an Italian ERP and financial systems consulting company founded in 2001 in Milan, delivering end-to- |
| 🟠 high | ST Engineering — claimed by metaencryptor | — | Singapore Technologies Engineering or ST Engineering (ST Engg.) is a Singapore-based multinational technology, defence a |
| 🟠 high | Taubensee Steel & Wire — claimed by qilin (DE) | — | N/A |
| 🟠 high | TeleTronic — claimed by qilin (ES) | — | N/A |
| 🟠 high | THOMAS JORDAN, P.A — claimed by qilin (US) | — | N/A |
| 🟠 high | townofnorwell.net — claimed by threeam | — | townofnorwell.net listed by threeam. |
| | _+317 more…_ | | |

---
Sources: CISA KEV, NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, AI Honeypot Observatory, URLhaus, MalwareBazaar, ThreatFox
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203, T1566

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W44)*