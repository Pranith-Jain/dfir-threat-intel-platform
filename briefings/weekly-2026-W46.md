# Weekly Threat Briefing — 2026-11-09 – 2026-11-15

> **weekly** · 2026-11-09 – 2026-11-15 · Generated 2026-11-16 00:45 UTC

## Executive Summary

This week (2026-11-09 – 2026-11-15), CISA added 11 new KEV entries and 2133 additional high/critical CVEs were published (NVD, cvefeed.io, MyThreatIntel), including 206 critical-severity affecting Fundacja Widzialni, Barracuda Networks, SignalWire. Active threat indicators across URLhaus, MalwareBazaar, ThreatFox — 17,331 unique after cross-source dedup; all 17331 indicators (5663 malware-distribution URLs, 3967 malicious domains, 796 suspicious IPs, 6905 malware sample hashes) are included in the IOC dump. Reference only — verify all indicators in your own environment and apply vendor patches per CISA KEV due-date guidance.

## Stats

| Metric | Count |
|--------|-------|
| Findings | 2976 |
| CVEs | 2144 |
| KEVs | 11 |
| IOCs | 17331 |
| Critical | 206 |
| High | 1928 |
| Ransomware victims | 832 |

## Critical Remote Code Execution Vulnerabilities (70)

_Vulnerabilities allowing arbitrary code execution on affected systems — patch immediately._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-123751: The WP Duplicate  WordPress plugin through 1.1.11 does not properly verify a request au… | `T1190` | The WP Duplicate  WordPress plugin through 1.1.11 does not properly verify a request authentication value and does not v |
| 🔴 critical | CVE-2026-115252: The Confection WordPress Cable WordPress plugin from 0.4.0 to 0.4.7 does not perform an… | — | The Confection WordPress Cable WordPress plugin from 0.4.0 to 0.4.7 does not perform any capability or nonce checks befo |
| 🔴 critical | CVE-2026-110469: Remote Code Execution via Unrestricted File Upload in WidzialniCMS | `T1190` | [VulnTracker digest] Fundacja Widzialni WidzialniCMS — Remote Code Execution via Unrestricted File Upload in WidzialniCM |
| 🔴 critical | CVE-2026-110468: Remote Code Execution via Unrestricted File Upload in WidzialniCMS | `T1190` | [VulnTracker digest] Fundacja Widzialni WidzialniCMS — Remote Code Execution via Unrestricted File Upload in WidzialniCM |
| 🔴 critical | CVE-2026-109795: SAP NetWeaver does not perform necessary authorization checks and lacks sufficient inpu… | `T1190` | SAP NetWeaver does not perform necessary authorization checks and lacks sufficient input validation in certain remote-en |
| 🔴 critical | CVE-2026-109803: SAP NetWeaver Knowledge Management (XML Forms) does not sufficiently restrict the selec… | `T1190` | SAP NetWeaver Knowledge Management (XML Forms) does not sufficiently restrict the selection of XSL transformations proce |
| 🔴 critical | CVE-2026-125757: mailcow: dockerized before 2026-11 contains a server-side template injection vulnerabil… | — | mailcow: dockerized before 2026-11 contains a server-side template injection vulnerability that allows domain administra |
| 🔴 critical | CVE-2026-120779: Improper control of generation of code ('code injection') in Visual Studio Code allows … | — | Improper control of generation of code ('code injection') in Visual Studio Code allows an unauthorized attacker to execu |
| 🔴 critical | CVE-2026-126082: Active Storage makes it simple to upload and reference files in cloud services and atta… | `T1190` | Active Storage makes it simple to upload and reference files in cloud services and attach those files to Active Record o |
| 🔴 critical | CVE-2026-113579: Adobe Experience Manager is affected by an Improper Control of Generation of Code ('Cod… | `T1190` | Adobe Experience Manager is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability that  |
| 🔴 critical | CVE-2026-113580: Adobe Experience Manager is affected by an Improper Control of Generation of Code ('Cod… | `T1190` | Adobe Experience Manager is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability that  |
| 🔴 critical | CVE-2026-121353: Adobe Connect is affected by an Improper Neutralization of CRLF Sequences ('CRLF Inject… | `T1190` | Adobe Connect is affected by an Improper Neutralization of CRLF Sequences ('CRLF Injection') vulnerability that could re |
| 🔴 critical | CVE-2026-121887: Adobe Connect is affected by an Improper Restriction of XML External Entity Reference (… | `T1190` | Adobe Connect is affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could r |
| 🔴 critical | CVE-2026-121892: Adobe Connect is affected by an Improper Control of Generation of Code ('Code Injection… | `T1190` | Adobe Connect is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability that could resul |
| 🔴 critical | CVE-2026-78287: Improper Control of Generation of Code ('Code Injection') vulnerability in Staggs STAGG… | — | Improper Control of Generation of Code ('Code Injection') vulnerability in Staggs STAGGS staggs allows Remote Code Inclu |
| 🔴 critical | CVE-2026-124814: The Ultimate Addons for Elementor Forms WordPress plugin before 1.0.8 does not properly… | `T1190` | The Ultimate Addons for Elementor Forms WordPress plugin before 1.0.8 does not properly validate the extension of upload |
| 🔴 critical | CVE-2026-117551: Joomla Extension - jdownloads.com - RCE through file upload in jDownloads < 4.1.8 | `T1190` | [VulnTracker digest] jdownloads.com jDownloads extension for Joomla — Joomla Extension - jdownloads.com - RCE through fi |
| 🔴 critical | CVE-2026-118063: The Advance Guest Post WordPress plugin through 1.9 does not properly validate uploaded… | `T1190` | The Advance Guest Post WordPress plugin through 1.9 does not properly validate uploaded files, relying on a case-sensiti |
| 🔴 critical | CVE-2026-126119: The Streamit WordPress plugin before 1.3.10 does not perform any authorization or nonce… | `T1190`, `T1068` | The Streamit WordPress plugin before 1.3.10 does not perform any authorization or nonce verification on one of its unaut |
| 🔴 critical | CVE-2026-125055: The Chatterbug Forms – Fast, Flexible WordPress Form Builder plugin for WordPress is vu… | `T1190` | The Chatterbug Forms – Fast, Flexible WordPress Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload |
| 🔴 critical | CVE-2026-126378: Vvveb through 1.0.8.6 contains a file upload vulnerability in the theme installer valid… | `T1190` | Vvveb through 1.0.8.6 contains a file upload vulnerability in the theme installer validFile() function that uses strpos( |
| 🟠 high | CVE-2026-115204: The AZEXO Store Locator WordPress plugin through 1.4 does not perform capability or non… | `T1190` | The AZEXO Store Locator WordPress plugin through 1.4 does not perform capability or nonce checks on its AJAX actions and |
| 🟠 high | CVE-2026-115212: The mView 豆瓣电影 WordPress plugin through 1.0.3 does not validate the type, name, or sour… | `T1190` | The mView 豆瓣电影 WordPress plugin through 1.0.3 does not validate the type, name, or source of a remotely fetched file, no |
| 🟠 high | CVE-2026-95778: A remote code execution vulnerability exists in HPE Morpheus Software. | `T1190` | A remote code execution vulnerability exists in HPE Morpheus Software. |
| 🟠 high | CVE-2026-120009: SAP ABAP Developer Tools (AMDP Data Preview) does not perform sufficient validation and… | `T1190` | SAP ABAP Developer Tools (AMDP Data Preview) does not perform sufficient validation and authorization checks within cert |
| 🟠 high | CVE-2026-109097: A vulnerability has been identified in ROS# (All versions < V2.3.1). | `T1190` | A vulnerability has been identified in ROS# (All versions < V2.3.1). Affected systems do not properly escape text of mes |
| 🟠 high | CVE-2026-118112: Improper control of generation of code ('code injection') in SQL Server allows an autho… | — | Improper control of generation of code ('code injection') in SQL Server allows an authorized attacker to elevate privile |
| 🟠 high | CVE-2026-118149: Improper control of generation of code ('code injection') in Microsoft Exchange Server … | — | Improper control of generation of code ('code injection') in Microsoft Exchange Server allows an authorized attacker to  |
| 🟠 high | CVE-2026-119904: Improper control of generation of code ('code injection') in Microsoft Windows Speech a… | — | Improper control of generation of code ('code injection') in Microsoft Windows Speech allows an authorized attacker to e |
| 🟠 high | CVE-2026-120782: Improper control of generation of code ('code injection') in Visual Studio Code allows … | — | Improper control of generation of code ('code injection') in Visual Studio Code allows an unauthorized attacker to bypas |
| 🟠 high | CVE-2026-122979: Improper control of generation of code ('code injection') in Microsoft Teams for Androi… | — | Improper control of generation of code ('code injection') in Microsoft Teams for Android allows an unauthorized attacker |
| 🟠 high | CVE-2026-124225: Improper control of generation of code ('code injection') in Windows PowerShell allows … | — | Improper control of generation of code ('code injection') in Windows PowerShell allows an unauthorized attacker to execu |
| 🟠 high | CVE-2026-110089: Premiere Pro is affected by a Buffer Underwrite ('Buffer Underflow') vulnerability that… | `T1190` | Premiere Pro is affected by a Buffer Underwrite ('Buffer Underflow') vulnerability that could result in arbitrary code e |
| 🟠 high | CVE-2026-113526: After Effects is affected by a Violation of Secure Design Principles vulnerability that… | `T1190` | After Effects is affected by a Violation of Secure Design Principles vulnerability that could result in arbitrary code e |
| 🟠 high | CVE-2026-113534: After Effects is affected by an Improper Input Validation vulnerability that could resu… | `T1190` | After Effects is affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in |
| 🟠 high | CVE-2026-113557: Audition is affected by an Improper Input Validation vulnerability that could result in… | `T1190` | Audition is affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the  |
| 🟠 high | CVE-2026-113558: Audition is affected by an Improper Input Validation vulnerability that could result in… | `T1190` | Audition is affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the  |
| 🟠 high | CVE-2026-113562: Audition is affected by an Improper Input Validation vulnerability that could result in… | `T1190` | Audition is affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the  |
| 🟠 high | CVE-2026-113563: Audition is affected by a Violation of Secure Design Principles vulnerability that coul… | `T1190` | Audition is affected by a Violation of Secure Design Principles vulnerability that could result in arbitrary code execut |
| 🟠 high | CVE-2026-48402: Premiere Pro is affected by an Untrusted Search Path vulnerability that could result in… | `T1190` | Premiere Pro is affected by an Untrusted Search Path vulnerability that could result in arbitrary code execution in the  |
| 🟠 high | CVE-2026-118483: Dimension is affected by an Improper Input Validation vulnerability that could result i… | `T1190` | Dimension is affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the |
| 🟠 high | CVE-2026-126186: Active Storage makes it simple to upload and reference files in cloud services and atta… | `T1190` | Active Storage makes it simple to upload and reference files in cloud services and attach those files to Active Record o |
| 🟠 high | CVE-2026-125882: RCE via file repository upload path traversal | `T1190` | [cvefeed.io] RCE via file repository upload path traversal |
| 🟠 high | CVE-2026-118041: The Contest Gallery  WordPress plugin before 34.0.3 does not sanitise the name of files… | `T1190` | The Contest Gallery  WordPress plugin before 34.0.3 does not sanitise the name of files uploaded through its e-commerce  |
| 🟠 high | CVE-2026-111190: The ARForms plugin for WordPress is vulnerable to arbitrary file upload in all versions… | `T1190` | The ARForms plugin for WordPress is vulnerable to arbitrary file upload in all versions up to, and including, 7.2.4 via  |
| 🟠 high | CVE-2026-62971: The OWASP core rule set (CRS) is a set of generic attack detection rules for use with c… | `T1190`, `T1059.007` | The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewal |
| 🟠 high | CVE-2026-126774: @tinacms/mdx before 2.4.2 contains a code injection vulnerability in its MDX serializer… | — | @tinacms/mdx before 2.4.2 contains a code injection vulnerability in its MDX serializer, which writes rich-text values i |
| 🟠 high | CVE-2026-126180: A improper neutralization of special elements used in a template engine vulnerability i… | — | A improper neutralization of special elements used in a template engine vulnerability in Fortinet FortiManager 8.0.0 thr |
| 🟠 high | CVE-2026-126182: A improper control of generation of code ('code injection') vulnerability in Fortinet F… | — | A improper control of generation of code ('code injection') vulnerability in Fortinet FortiManager 8.0.0 through 8.0.1,  |
| 🟠 high | CVE-2026-126185: A improper control of generation of code ('code injection') vulnerability in Fortinet F… | — | A improper control of generation of code ('code injection') vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, |
| | _+20 more…_ | | |

## Command Injection (75)

_OS / shell command injection enabling attacker-controlled execution._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-124580: A vulnerability was found in Chengdu Feiyuxing Technology VW2100 and VEC10GP 1.0 B-MB3W… | `T1059` | A vulnerability was found in Chengdu Feiyuxing Technology VW2100 and VEC10GP 1.0 B-MB3W202-210825-r11775. This impacts t |
| 🔴 critical | CVE-2026-124585: A vulnerability was found in Chengdu Feiyuxing Technology VW2100 and VEC10GP 1.0 B-MB3W… | `T1059` | A vulnerability was found in Chengdu Feiyuxing Technology VW2100 and VEC10GP 1.0 B-MB3W202-210825-r11775. This issue aff |
| 🔴 critical | CVE-2026-126148: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🔴 critical | CVE-2026-124002: XWEB EVO versions 5.2.3 through before 5.7.0 contains a pre-authentication OS command i… | `T1059` | XWEB EVO versions 5.2.3 through before 5.7.0 contains a pre-authentication OS command injection vulnerability that allow |
| 🔴 critical | CVE-2026-124010: XWEB EVO before 5.6.2 contains a command injection vulnerability that allows unauthenti… | `T1059` | XWEB EVO before 5.6.2 contains a command injection vulnerability that allows unauthenticated remote attackers to execute |
| 🔴 critical | CVE-2026-103813: Dell PowerStore contains an OS Command Injection vulnerability. | `T1059`, `T1068` | Dell PowerStore contains an OS Command Injection vulnerability. An authenticated user with limited privileges could pote |
| 🔴 critical | CVE-2026-129433: Dokploy before 0.31.1 contains an OS command injection vulnerability in getComposeConta… | `T1059` | Dokploy before 0.31.1 contains an OS command injection vulnerability in getComposeContainerCommand() that allows authent |
| 🔴 critical | CVE-2026-129449: A security vulnerability has been detected in DrayTek Vigor2960 up to 1.5.1.6. | `T1059` | A security vulnerability has been detected in DrayTek Vigor2960 up to 1.5.1.6. Affected by this vulnerability is the fun |
| 🔴 critical | CVE-2026-129452: A vulnerability has been found in DrayTek Vigor2960 1.5.1.6. | `T1059` | A vulnerability has been found in DrayTek Vigor2960 1.5.1.6. This vulnerability affects the function set_table of the fi |
| 🟠 high | CVE-2026-94434: Improper neutralization of special elements used in an OS command ('OS command injectio… | `T1059` | Improper neutralization of special elements used in an OS command ('OS command injection') vulnerability in TÜBİTAK BİLG |
| 🟠 high | CVE-2026-16283: Improper neutralization of special elements used in an OS command ('OS command injectio… | `T1059` | Improper neutralization of special elements used in an OS command ('OS command injection') vulnerability in Osbil Techno |
| 🟠 high | CVE-2026-63496: augment-vir is a collection of helper functions. | `T1059` | augment-vir is a collection of helper functions. Prior to version 31.73.5, the grep() function exported by @augment-vir/ |
| 🟠 high | CVE-2026-63644: bird-lg-go is a BIRD looking glass in Go. | — | bird-lg-go is a BIRD looking glass in Go. Prior to version 1.4.7, unsanitized input path enables arbitrary local file re |
| 🟠 high | CVE-2026-125399: Fluxion before 6.39 contains an OS command injection vulnerability in the fluxion.sh ta… | `T1059` | Fluxion before 6.39 contains an OS command injection vulnerability in the fluxion.sh target scanner, which decodes acces |
| 🟠 high | CVE-2026-125391: Webmin through 2.670 contains an OS command injection vulnerability in samba/save_euser… | `T1059` | Webmin through 2.670 contains an OS command injection vulnerability in samba/save_euser.cgi that allows authenticated Sa |
| 🟠 high | CVE-2026-107240: The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero To… | — | The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero Touch Provisioning (ZTP) of the VOS |
| 🟠 high | CVE-2026-91756: OS Command Injection Vulnerability in Hitachi Dynamic Link Manager for VMware. | `T1059` | OS Command Injection Vulnerability in Hitachi Dynamic Link Manager for VMware.

This issue affects Hitachi Dynamic Link  |
| 🟠 high | CVE-2026-91757: OS Command Injection Vulnerability in Hitachi Dynamic Link Manager for VMware. | `T1059` | OS Command Injection Vulnerability in Hitachi Dynamic Link Manager for VMware.

This issue affects Hitachi Dynamic Link  |
| 🟠 high | CVE-2026-60035: A high privileged remote attacker can perform a code injection in the backends network … | — | A high privileged remote attacker can perform a code injection in the backends network auth function leading to code exe |
| 🟠 high | CVE-2026-60036: A high privileged remote attacker can perform a code injection in the backends patch ac… | — | A high privileged remote attacker can perform a code injection in the backends patch activate function leading to code e |
| 🟠 high | CVE-2026-60037: A high privileged remote attacker can perform an OpenSSL code injection in the frontend… | — | A high privileged remote attacker can perform an OpenSSL code injection in the frontends device importer function leadin |
| 🟠 high | CVE-2026-60038: A high privileged remote attacker can perform an OpenSSL code injection in the backends… | — | A high privileged remote attacker can perform an OpenSSL code injection in the backends ImportPKCS12 function leading to |
| 🟠 high | CVE-2026-60039: A high privileged remote attacker can perform a code injection in the backends backup r… | — | A high privileged remote attacker can perform a code injection in the backends backup restore function leading to code e |
| 🟠 high | CVE-2026-95646: Zoho Corporation ManageEngine DDI Central versions 6500 and below are vulnerable to a U… | `T1059` | Zoho Corporation ManageEngine DDI Central versions 6500 and below are vulnerable to a Unicode-based command injection vu |
| 🟠 high | CVE-2026-109830: A vulnerability has been identified in meta-iot2050 (All versions >= V01.03.01). | `T1190` | A vulnerability has been identified in meta-iot2050 (All versions >= V01.03.01). Affected devices take parts from a conf |
| 🟠 high | CVE-2026-12573: Zoho Corporation ManageEngine DDI Central versions 6200 and below are vulnerable to Cis… | `T1059` | Zoho Corporation ManageEngine DDI Central versions 6200 and below are vulnerable to Cisco IOS command injection via DHCP |
| 🟠 high | CVE-2026-105425: OS command injection in Ivanti Sentry before versions 11.0.0, 10.8.3, and 10.7.4 as wel… | `T1190`, `T1059` | OS command injection in Ivanti Sentry before versions 11.0.0, 10.8.3, and 10.7.4 as well as in Ivanti EPMM before versio |
| 🟠 high | CVE-2026-126042: VNote 3.11.0 before 4.12.0 contains an OS command injection vulnerability in its Tasks … | `T1059` | VNote 3.11.0 before 4.12.0 contains an OS command injection vulnerability in its Tasks feature: magic variables such as  |
| 🟠 high | CVE-2026-102224: Improper neutralization of special elements used in an os command ('os command injectio… | `T1059` | Improper neutralization of special elements used in an os command ('os command injection') in Azure CycleCloud allows an |
| 🟠 high | CVE-2026-109457: Improper neutralization of special elements used in an os command ('os command injectio… | `T1059` | Improper neutralization of special elements used in an os command ('os command injection') in Azure CLI allows an author |
| 🟠 high | CVE-2026-116930: Improper neutralization of special elements used in a command ('command injection') in … | `T1059` | Improper neutralization of special elements used in a command ('command injection') in SQL Server allows an unauthorized |
| 🟠 high | CVE-2026-119906: Improper neutralization of special elements used in an os command ('os command injectio… | `T1059` | Improper neutralization of special elements used in an os command ('os command injection') in Windows Sandbox allows an  |
| 🟠 high | CVE-2026-119989: Improper neutralization of special elements used in a command ('command injection') in … | `T1059` | Improper neutralization of special elements used in a command ('command injection') in Azure Pipelines allows an authori |
| 🟠 high | CVE-2026-121662: Improper neutralization of special elements used in a command ('command injection') in … | `T1059` | Improper neutralization of special elements used in a command ('command injection') in Visual Studio Code allows an unau |
| 🟠 high | CVE-2026-122988: Improper authorization in Windows Admin Center allows an authorized attacker to elevate… | — | Improper authorization in Windows Admin Center allows an authorized attacker to elevate privileges over a network. |
| 🟠 high | CVE-2026-123387: Improper neutralization of special elements used in a command ('command injection') in … | `T1059` | Improper neutralization of special elements used in a command ('command injection') in Windows Active Directory allows a |
| 🟠 high | CVE-2026-96053: Improper neutralization of special elements used in a command ('command injection') in … | `T1059` | Improper neutralization of special elements used in a command ('command injection') in Windows Task Scheduler allows an  |
| 🟠 high | CVE-2026-108472: A flaw was found in the xfs_admin utility in xfsprogs. | `T1059`, `T1068` | A flaw was found in the xfs_admin utility in xfsprogs. The tool does not properly validate user-supplied parameters, all |
| 🟠 high | CVE-2026-126144: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126145: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126146: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126158: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126166: A improper neutralization of argument delimiters in a command ('argument injection') vu… | `T1190` | A improper neutralization of argument delimiters in a command ('argument injection') vulnerability in Fortinet FortiMail |
| 🟠 high | CVE-2026-126167: A improper neutralization of special elements used in a command ('command injection') v… | `T1190`, `T1059` | A improper neutralization of special elements used in a command ('command injection') vulnerability in Fortinet FortiMai |
| 🟠 high | CVE-2026-126168: A improper neutralization of argument delimiters in a command ('argument injection') vu… | `T1190` | A improper neutralization of argument delimiters in a command ('argument injection') vulnerability in Fortinet FortiMail |
| 🟠 high | CVE-2026-126169: A improper neutralization of argument delimiters in a command ('argument injection') vu… | `T1190` | A improper neutralization of argument delimiters in a command ('argument injection') vulnerability in Fortinet FortiMail |
| 🟠 high | CVE-2026-126179: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126224: A improper neutralization of argument delimiters in a command ('argument injection') vu… | — | A improper neutralization of argument delimiters in a command ('argument injection') vulnerability in Fortinet FortiAnal |
| 🟠 high | CVE-2026-126226: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| 🟠 high | CVE-2026-126231: A improper neutralization of special elements used in an os command ('os command inject… | `T1059` | A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet F |
| | _+25 more…_ | | |

## Authentication & Authorization Bypass (267)

_Missing or broken authentication / authorisation enabling unauthorised actions._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-115213: The EASY-JS-WPAPI Client HANDLE for the WordPress REST-API WordPress plugin through 2.0… | — | The EASY-JS-WPAPI Client HANDLE for the WordPress REST-API WordPress plugin through 2.0 does not prevent the administrat |
| 🔴 critical | CVE-2026-115237: The Grand Job WordPress plugin through 1.2.1 does not correctly verify the password res… | — | The Grand Job WordPress plugin through 1.2.1 does not correctly verify the password reset code before updating a user's  |
| 🔴 critical | CVE-2026-124577: A weakness has been identified in Intelbras SG 2404 PoE L2+ 1.00.70/1.00.72. | — | A weakness has been identified in Intelbras SG 2404 PoE L2+ 1.00.70/1.00.72. The affected element is an unknown function |
| 🔴 critical | CVE-2026-123270: Redpanda Connect versions 4.39 to 4.110 contain a missing authentication vulnerability … | `T1190`, `T1078` | Redpanda Connect versions 4.39 to 4.110 contain a missing authentication vulnerability that enables unauthenticated remo |
| 🔴 critical | CVE-2026-123800: SuperTokens Core is an open source authentication server. | — | SuperTokens Core is an open source authentication server. From 6.0.0 until 6.0.24, 7.0.23, 8.0.7, 9.0.6, 9.1.6, 9.2.7, 9 |
| 🔴 critical | CVE-2026-89103: SAP Gateway activates the default Access Control List with high privileges allowing cat… | — | SAP Gateway activates the default Access Control List with high privileges allowing categorization of external attacker  |
| 🔴 critical | CVE-2026-121683: Missing authentication in Ivanti Cloud Services Application version 5.0.8 allows a remo… | `T1078` | Missing authentication in Ivanti Cloud Services Application version 5.0.8 allows a remote unauthenticated attacker to ad |
| 🔴 critical | CVE-2026-125347: Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.50 allowed a… | `T1190` | Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.50 allowed a remote attacker leveraging socia |
| 🔴 critical | CVE-2026-109467: Improper authentication in Azure DevOps allows an authorized attacker to execute code o… | — | Improper authentication in Azure DevOps allows an authorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-114146: Incorrect authorization in ASP.NET Core allows an authorized attacker to elevate privil… | — | Incorrect authorization in ASP.NET Core allows an authorized attacker to elevate privileges over a network. |
| 🔴 critical | CVE-2026-114162: Incorrect authorization in Microsoft Graph allows an authorized attacker to elevate pri… | — | Incorrect authorization in Microsoft Graph allows an authorized attacker to elevate privileges over a network. |
| 🔴 critical | CVE-2026-118740: Missing authorization in Aspire allows an unauthorized attacker to bypass a security fe… | — | Missing authorization in Aspire allows an unauthorized attacker to bypass a security feature over a network. |
| 🔴 critical | CVE-2026-119990: Missing authentication for critical function in Azure OpenAI allows an unauthorized att… | `T1078` | Missing authentication for critical function in Azure OpenAI allows an unauthorized attacker to elevate privileges over  |
| 🔴 critical | CVE-2026-120002: Incorrect authorization in Microsoft Office SharePoint allows an authorized attacker to… | — | Incorrect authorization in Microsoft Office SharePoint allows an authorized attacker to elevate privileges over a networ |
| 🔴 critical | CVE-2026-125331: HarnessRouter is a self-hosted unified API for running agent harnesses with sessions, s… | — | HarnessRouter is a self-hosted unified API for running agent harnesses with sessions, streaming, files, cancellation, an |
| 🔴 critical | CVE-2026-85844: Authentication bypass using an alternate path or channel in Windows Kerberos allows an … | `T1078` | Authentication bypass using an alternate path or channel in Windows Kerberos allows an unauthorized attacker to elevate  |
| 🔴 critical | CVE-2026-126065: OpenObserve is a cloud-native observability platform. | `T1190` | OpenObserve is a cloud-native observability platform. Prior to 1.1.0, the shared authentication validator in src/api/com |
| 🔴 critical | CVE-2026-114371: Adobe Experience Manager is affected by an Incorrect Authorization vulnerability that c… | `T1190` | Adobe Experience Manager is affected by an Incorrect Authorization vulnerability that could result in arbitrary code exe |
| 🔴 critical | CVE-2026-119017: Adobe Experience Manager is affected by an Incorrect Authorization vulnerability that c… | `T1190` | Adobe Experience Manager is affected by an Incorrect Authorization vulnerability that could result in arbitrary code exe |
| 🔴 critical | CVE-2026-121352: Adobe Connect is affected by an Incorrect Authorization vulnerability that could result… | `T1068` | Adobe Connect is affected by an Incorrect Authorization vulnerability that could result in privilege escalation. An atta |
| 🔴 critical | CVE-2026-121355: Adobe Connect is affected by an Incorrect Authorization vulnerability that could result… | `T1068` | Adobe Connect is affected by an Incorrect Authorization vulnerability that could result in privilege escalation. An atta |
| 🔴 critical | CVE-2026-125297: AsiaInfo Business Support System (BSS) 9.2.0 through 9.2.40 accepts unauthenticated req… | — | AsiaInfo Business Support System (BSS) 9.2.0 through 9.2.40 accepts unauthenticated requests via the management API '/bs |
| 🔴 critical | CVE-2026-89324: The Basel Post Types plugin for WordPress is vulnerable to Authentication Bypass in all… | `T1078` | The Basel Post Types plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1 |
| 🔴 critical | CVE-2026-126542: WWBN AVideo 6.5 through 29.7.1 contains an authentication bypass vulnerability that all… | `T1078` | WWBN AVideo 6.5 through 29.7.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to  |
| 🔴 critical | CVE-2026-115733: The Printaura-Woocommerce WordPress plugin through 4.0.2 does not properly restrict acc… | — | The Printaura-Woocommerce WordPress plugin through 4.0.2 does not properly restrict access to the WooCommerce REST API,  |
| 🔴 critical | CVE-2026-85632: Missing authentication for critical function and Improper validation of integrity check… | `T1078` | Missing authentication for critical function and Improper validation of integrity check value vulnerability in Sipay Ele |
| 🔴 critical | CVE-2026-126768: OpsTree REMS through 1.0.0 contains an authentication bypass vulnerability that allows … | `T1078` | OpsTree REMS through 1.0.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obta |
| 🔴 critical | CVE-2026-65840: Fider is a feedback portal for feature requests and suggestions. | — | Fider is a feedback portal for feature requests and suggestions. Prior to version 0.36.0, in multi-tenant mode (HOST_MOD |
| 🔴 critical | CVE-2026-126155: A incorrect authorization vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, Fort… | — | A incorrect authorization vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiM |
| 🔴 critical | CVE-2026-126156: A authorization bypass through user-controlled key vulnerability in Fortinet FortiMail … | — | A authorization bypass through user-controlled key vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7. |
| 🔴 critical | CVE-2026-126157: A improper authentication vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, Fort… | — | A improper authentication vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiM |
| 🔴 critical | CVE-2026-126229: A authorization bypass through user-controlled key vulnerability in Fortinet FortiAnaly… | — | A authorization bypass through user-controlled key vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAna |
| 🔴 critical | CVE-2026-126251: A incorrect authorization vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.… | — | A incorrect authorization vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6.0 thr |
| 🔴 critical | CVE-2026-126253: A authentication bypass by primary weakness vulnerability in Fortinet FortiOS 8.0.0 thr… | `T1078` | A authentication bypass by primary weakness vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through |
| 🔴 critical | CVE-2026-126259: A missing authentication for critical function vulnerability in Fortinet FortiOS 8.0.0,… | `T1078` | A missing authentication for critical function vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.0 through 7.6.7, For |
| 🔴 critical | CVE-2026-67449: Portabase is a database backup and restore tool for PostgreSQL, MySQL, MsSQL, MariaDB, … | — | Portabase is a database backup and restore tool for PostgreSQL, MySQL, MsSQL, MariaDB, Firebird SQL, SQLite, MongoDB, Re |
| 🔴 critical | CVE-2026-110959: The Descope WordPress plugin before 1.2.0 does not validate the authentication token it… | — | The Descope WordPress plugin before 1.2.0 does not validate the authentication token it receives before creating a WordP |
| 🔴 critical | CVE-2026-12591: Zohocorp ManageEngine M365 Manager Plus versions below 4818 is affected by an authentic… | `T1190` | Zohocorp ManageEngine M365 Manager Plus versions below 4818 is affected by an authenticated technician may exploit insuf |
| 🔴 critical | CVE-2026-19422: Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authentication … | `T1078` | Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authentication bypass vulnerability in Windows D |
| 🔴 critical | CVE-2026-124014: XWEB EVO 4.3.0 through 5.8.8 contains an unauthenticated arbitrary file write vulnerabi… | — | XWEB EVO 4.3.0 through 5.8.8 contains an unauthenticated arbitrary file write vulnerability that allows remote attackers |
| 🔴 critical | CVE-2026-68548: Algernon is a small self-contained pure-Go web server. | — | Algernon is a small self-contained pure-Go web server. Prior to version 1.17.10, Algernon's URL-prefix authorization gat |
| 🔴 critical | CVE-2026-127275: Linksys EA8100 JNAP API ui_server.lua SetUnsecuredWiFiWarning missing authentication | `T1078` | [VulnTracker digest] Linksys EA8100 — Linksys EA8100 JNAP API ui_server.lua SetUnsecuredWiFiWarning missing authenticati |
| 🔴 critical | CVE-2026-124763: The Woocommerce Wishlist WordPress plugin through 1.1.0 does not have authorisation and… | — | The Woocommerce Wishlist WordPress plugin through 1.1.0 does not have authorisation and CSRF checks in one of its unauth |
| 🔴 critical | CVE-2026-126473: OpenEMR before 8.4.0 contains OAuth scope canonicalization and containment flaws that a… | — | OpenEMR before 8.4.0 contains OAuth scope canonicalization and containment flaws that allow unauthenticated attackers to |
| 🔴 critical | CVE-2026-129110: sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allow… | `T1078` | sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allows unauthenticated attackers to re |
| 🔴 critical | CVE-2026-82504: VITEC EZ TV Platform Server before 8.5.0 contains an unrestricted file upload vulnerabi… | `T1190` | VITEC EZ TV Platform Server before 8.5.0 contains an unrestricted file upload vulnerability in the upload handler that a |
| 🔴 critical | CVE-2026-126173: The AutomatorWP Pro plugin for WordPress' webhook addon is vulnerable to authorization … | — | The AutomatorWP Pro plugin for WordPress' webhook addon is vulnerable to authorization bypass in all versions up to, and |
| 🔴 critical | CVE-2026-19907: The Shipo plugin for WordPress is vulnerable to Authentication Bypass in versions 1.6 t… | `T1078` | The Shipo plugin for WordPress is vulnerable to Authentication Bypass in versions 1.6 through 1.8.0. This is due to the  |
| 🔴 critical | CVE-2026-129483: Cyrus SASL through 2.1.28 contains an authentication bypass vulnerability in the SRP se… | `T1078` | Cyrus SASL through 2.1.28 contains an authentication bypass vulnerability in the SRP server mechanism because srp_server |
| 🟠 high | CVE-2026-118201: The Limit Login Attempts Security  WordPress plugin before 3.4.1 does not enforce its t… | — | The Limit Login Attempts Security  WordPress plugin before 3.4.1 does not enforce its two-factor authentication on every |
| | _+217 more…_ | | |

## Privilege Escalation (53)

_Vulnerabilities enabling escalation to higher privileges._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-119506: Incorrect Privilege Assignment vulnerability in DynamiApps Frontend Admin by DynamiApps… | `T1068` | Incorrect Privilege Assignment vulnerability in DynamiApps Frontend Admin by DynamiApps acf-frontend-form-element allows |
| 🔴 critical | CVE-2026-123695: The Security For WooCommerce WordPress plugin through 1.0.16 does not restrict access t… | — | The Security For WooCommerce WordPress plugin through 1.0.16 does not restrict access to several of its REST API routes, |
| 🔴 critical | CVE-2026-127073: OpsTree BuildPiper before 2.7.0 contains a privilege escalation vulnerability that allo… | `T1068` | OpsTree BuildPiper before 2.7.0 contains a privilege escalation vulnerability that allows project users to gain Kubernet |
| 🔴 critical | CVE-2026-127080: OpsTree BuildPiper before 2.7.0 contains an improper authorization vulnerability that a… | — | OpsTree BuildPiper before 2.7.0 contains an improper authorization vulnerability that allows authenticated deploy users  |
| 🔴 critical | CVE-2026-125769: Incorrect Privilege Assignment vulnerability in Nasir Ahmed Advanced Form Integration a… | `T1068` | Incorrect Privilege Assignment vulnerability in Nasir Ahmed Advanced Form Integration advanced-form-integration allows P |
| 🟠 high | CVE-2026-124501: A weakness has been identified in Tidelift moto up to 5.2.4. | — | A weakness has been identified in Tidelift moto up to 5.2.4. Affected is an unknown function of the file moto/batch/mode |
| 🟠 high | CVE-2026-121875: The Post Duplicator WordPress plugin before 3.0.18 does not validate the capabilities a… | — | The Post Duplicator WordPress plugin before 3.0.18 does not validate the capabilities assigned to roles through its perm |
| 🟠 high | CVE-2026-123064: The WP BASE Booking of Appointments, Services and Events WordPress plugin before 6.5.1 … | — | The WP BASE Booking of Appointments, Services and Events WordPress plugin before 6.5.1 does not properly restrict access |
| 🟠 high | CVE-2026-95648: Improperly controlled modification of Dynamically-Determined object attributes vulnerab… | `T1068` | Improperly controlled modification of Dynamically-Determined object attributes vulnerability in C-Prot Inc. C-Prot AppDe |
| 🟠 high | CVE-2026-121842: Privilege escalation in the Reader View component in Firefox for iOS. | `T1068` | Privilege escalation in the Reader View component in Firefox for iOS. This vulnerability was fixed in Firefox for iOS 16 |
| 🟠 high | CVE-2026-121843: Privilege escalation in Firefox for iOS. | `T1068` | Privilege escalation in Firefox for iOS. This vulnerability was fixed in Firefox for iOS 160.0. |
| 🟠 high | CVE-2026-119474: Incorrect Permission Assignment for Critical Resource vulnerability in HAVELSAN Inc. | `T1068` | Incorrect Permission Assignment for Critical Resource vulnerability in HAVELSAN Inc. Liman Render Engine allows Privileg |
| 🟠 high | CVE-2026-121576: Incorrect Privilege Assignment vulnerability in AtlasAiDev MCP Server for WordPress ai-… | `T1068` | Incorrect Privilege Assignment vulnerability in AtlasAiDev MCP Server for WordPress ai-workflow-automation-ai-agent-hub  |
| 🟠 high | CVE-2026-120834: Incorrect Privilege Assignment vulnerability in Tobias WP2LEADS wp2leads allows Privile… | `T1068` | Incorrect Privilege Assignment vulnerability in Tobias WP2LEADS wp2leads allows Privilege Escalation.This issue affects  |
| 🟠 high | CVE-2026-114031: Incorrect permission assignment allows local privilege escalation to SYSTEM on affected… | `T1068` | Incorrect permission assignment allows local privilege escalation to SYSTEM on affected releases of the Illumio VEN for  |
| 🟠 high | CVE-2026-125382: Map-OS 5.0.0 to before 5.2.2 contains a privilege escalation vulnerability in the REST … | `T1068` | Map-OS 5.0.0 to before 5.2.2 contains a privilege escalation vulnerability in the REST users API that allows non-adminis |
| 🟠 high | CVE-2026-125364: frab through 0.9.1 contains a privilege escalation vulnerability that allows authentica… | `T1068` | frab through 0.9.1 contains a privilege escalation vulnerability that allows authenticated crew users to grant themselve |
| 🟠 high | CVE-2026-125360: Storyden through 1.26.16 contains a privilege escalation vulnerability that allows user… | `T1068` | Storyden through 1.26.16 contains a privilege escalation vulnerability that allows users holding MANAGE_ROLES to grant t |
| 🟠 high | CVE-2026-4762: A vulnerability to perform a privilege escalation attack on the server as a non-admin u… | `T1068` | A vulnerability to perform a privilege escalation attack on the server as a non-admin user. |
| 🟠 high | CVE-2026-104619: Untrusted users could roll back security updates when using the PackageKit Zypp Backend… | `T1068` | Untrusted users could roll back security updates when using the PackageKit Zypp Backend before 1.4.1, allowing privilege |
| 🟠 high | CVE-2026-16478: Permissive list of allowed inputs vulnerability in TÜBİTAK BİLGEM Software Technologies… | `T1068` | Permissive list of allowed inputs vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute pardus-nvidia |
| 🟠 high | CVE-2026-105513: An elevation of privilege vulnerability exists in the way that the Windows Kernel handl… | `T1068` | An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory. An attacker |
| 🟠 high | CVE-2026-116929: Execution with unnecessary privileges in SQL Server allows an authorized attacker to el… | — | Execution with unnecessary privileges in SQL Server allows an authorized attacker to elevate privileges over a network. |
| 🟠 high | CVE-2026-122986: Improper privilege management in Microsoft Azure Kubernetes Service allows an authorize… | — | Improper privilege management in Microsoft Azure Kubernetes Service allows an authorized attacker to elevate privileges  |
| 🟠 high | CVE-2026-124226: Execution with unnecessary privileges in Windows PowerShell allows an authorized attack… | — | Execution with unnecessary privileges in Windows PowerShell allows an authorized attacker to bypass a security feature l |
| 🟠 high | CVE-2026-94525: An elevation of privilege vulnerability exists in Windows Error Reporting (WER) when WE… | `T1068` | An elevation of privilege vulnerability exists in Windows Error Reporting (WER) when WER handles and executes files. The |
| 🟠 high | CVE-2026-120814: An improper privilege management issue in the sharding subsystem of MongoDB Server may … | — | An improper privilege management issue in the sharding subsystem of MongoDB Server may allow a user holding certain shar |
| 🟠 high | CVE-2026-113551: Audition is affected by a Violation of Secure Design Principles vulnerability that coul… | `T1068` | Audition is affected by a Violation of Secure Design Principles vulnerability that could result in privilege escalation. |
| 🟠 high | CVE-2026-91000: Insecure IPC Channels lead to local privilege escalation | `T1068` | [cvefeed.io] Insecure IPC Channels lead to local privilege escalation |
| 🟠 high | CVE-2026-125879: Local privilege escalation to root via nable-writable syslog-ng config | `T1068` | [cvefeed.io] Local privilege escalation to root via nable-writable syslog-ng config |
| 🟠 high | CVE-2026-109870: The User Registration & Membership  WordPress plugin before 5.3.2 does not verify that … | `T1068` | The User Registration & Membership  WordPress plugin before 5.3.2 does not verify that a discount coupon applied to a pa |
| 🟠 high | CVE-2026-111579: The Forminator Forms  WordPress plugin before 1.58.4 does not enforce payment on the se… | — | The Forminator Forms  WordPress plugin before 1.58.4 does not enforce payment on the server side when a form's configure |
| 🟠 high | CVE-2026-121870: The Simpler Checkout WordPress plugin before 1.5.4 does not properly restrict who can c… | — | The Simpler Checkout WordPress plugin before 1.5.4 does not properly restrict who can create orders and checks its autom |
| 🟠 high | CVE-2026-119615: The Reset Database plugin for WordPress is vulnerable to privilege escalation in versio… | `T1068` | The Reset Database plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 1.1.3. T |
| 🟠 high | CVE-2026-89061: During an internal security assessment, a potential vulnerability was discovered in Len… | — | During an internal security assessment, a potential vulnerability was discovered in Lenovo PC Manager, distributed exclu |
| 🟠 high | CVE-2026-126780: Webmin through 2.670 contains a privilege escalation vulnerability in acl/save_group.cg… | `T1068` | Webmin through 2.670 contains a privilege escalation vulnerability in acl/save_group.cgi that allows delegated administr |
| 🟠 high | CVE-2026-91151: A flaw was found in Cockpit. | `T1068` | A flaw was found in Cockpit. A local authenticated user with control over a target account's home directory can exploit  |
| 🟠 high | CVE-2026-126803: Rote through 2.6.0 contains a privilege escalation vulnerability that allows authentica… | `T1068` | Rote through 2.6.0 contains a privilege escalation vulnerability that allows authenticated admins to obtain super_admin  |
| 🟠 high | CVE-2026-126211: A improper privilege management vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8… | — | A improper privilege management vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer 7.6.1 through |
| 🟠 high | CVE-2026-126249: A improper privilege management vulnerability in Fortinet FortiAuthenticator 8.0.0 thro… | — | A improper privilege management vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6 |
| 🟠 high | CVE-2026-123092: The WP Remote Users Sync WordPress plugin before 2.3.0 does not restrict which user met… | — | The WP Remote Users Sync WordPress plugin before 2.3.0 does not restrict which user metadata keys may be written through |
| 🟠 high | CVE-2026-15309: The CourseCure Courses plugin for WordPress is vulnerable to Privilege Escalation in ve… | `T1068` | The CourseCure Courses plugin for WordPress is vulnerable to Privilege Escalation in versions up to, and including, 1.5. |
| 🟠 high | CVE-2026-16135: The VibeBP plugin for WordPress is vulnerable to Privilege Escalation in all versions u… | `T1068` | The VibeBP plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 1.9.9.8.1. T |
| 🟠 high | CVE-2026-107484: An input and authorization validation vulnerability in Gaia Portal backend handlers cou… | — | An input and authorization validation vulnerability in Gaia Portal backend handlers could allow an authenticated, non-ad |
| 🟠 high | CVE-2026-124003: XWEB EVO before 5.6.2 contains a command injection vulnerability where the setuid-root … | `T1059` | XWEB EVO before 5.6.2 contains a command injection vulnerability where the setuid-root Lua CGI interpreter wlua executes |
| 🟠 high | CVE-2026-126793: An untrusted search path issue in Aurora PostgreSQL dialect detection in the AWS Advanc… | — | An untrusted search path issue in Aurora PostgreSQL dialect detection in the AWS Advanced Go Wrapper from release 2026-0 |
| 🟠 high | CVE-2026-123097: The WP Remote Users Sync WordPress plugin before 2.2.1 does not restrict which account … | — | The WP Remote Users Sync WordPress plugin before 2.2.1 does not restrict which account fields a synchronised site may se |
| 🟠 high | CVE-2026-123769: The SureDash – Community, Courses & Member Dashboard plugin for WordPress is vulnerable… | `T1068` | The SureDash – Community, Courses & Member Dashboard plugin for WordPress is vulnerable to Privilege Escalation in all v |
| 🟠 high | CVE-2026-126273: NocoDB before 2026.09.0 contains a privilege escalation vulnerability in initAdminFromE… | `T1068` | NocoDB before 2026.09.0 contains a privilege escalation vulnerability in initAdminFromEnv.ts that silently skips super-a |
| 🟠 high | CVE-2026-126282: NocoDB from 2026.04.0 before 2026.08.0 contains an improper privilege management vulner… | — | NocoDB from 2026.04.0 before 2026.08.0 contains an improper privilege management vulnerability in org-users.service.ts w |
| | _+3 more…_ | | |

## SQL & NoSQL Injection (79)

_Database injection vulnerabilities exposing or modifying stored data._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-115934: An unauthenticated SQL injection can occur on the front end of any site that uses craft… | `T1068`, `T1190` | An unauthenticated SQL injection can occur on the front end of any site that uses craft.search to perform a search, allo |
| 🔴 critical | CVE-2026-125120: Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environm… | — | Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment. Prior to 6.13.11, 7.8.12, 8. |
| 🔴 critical | CVE-2026-121653: SQL injection in the Core of Ivanti Endpoint Manager before version 2024 SU8 allows a r… | `T1190` | SQL injection in the Core of Ivanti Endpoint Manager before version 2024 SU8 allows a remote unauthenticated attacker to |
| 🔴 critical | CVE-2026-121894: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🔴 critical | CVE-2026-121896: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🔴 critical | CVE-2026-121898: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🔴 critical | CVE-2026-121902: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🔴 critical | CVE-2026-121908: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🔴 critical | CVE-2026-110697: A flaw was found in Quay where the robot account listing function constructs a SQL LIKE… | — | A flaw was found in Quay where the robot account listing function constructs a SQL LIKE pattern from user-controlled nam |
| 🔴 critical | CVE-2026-126164: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiMa |
| 🔴 critical | CVE-2026-126262: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAn |
| 🔴 critical | CVE-2026-126263: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiMa |
| 🔴 critical | CVE-2026-76954: An improper neutralization of special elements used in an SQL command vulnerability in … | — | An improper neutralization of special elements used in an SQL command vulnerability in the Auth API in Synology DiskStat |
| 🔴 critical | CVE-2026-124815: The Clockinator Lite WordPress plugin before 1.1.0 does not restrict access to several … | `T1190` | The Clockinator Lite WordPress plugin before 1.1.0 does not restrict access to several of its record deletion actions, a |
| 🔴 critical | CVE-2026-12507: Zohocorp ManageEngine AssetExplorer versions below 7860, ServiceDesk Plus versions belo… | `T1190` | Zohocorp ManageEngine AssetExplorer versions below 7860, ServiceDesk Plus versions below 15290, ServiceDesk Plus MSP ver |
| 🔴 critical | CVE-2026-124415: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Alejandro Alex Res |
| 🔴 critical | CVE-2026-124970: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WP BASE WP BASE Bo |
| 🔴 critical | CVE-2026-129171: NginxPulse 1.5.0 before 1.6.26 contains an unauthenticated sql injection vulnerability … | `T1190` | NginxPulse 1.5.0 before 1.6.26 contains an unauthenticated sql injection vulnerability that allows remote attackers to a |
| 🟠 high | CVE-2026-124554: A security flaw has been discovered in JeecgBoot 3.9.5. | `T1190` | A security flaw has been discovered in JeecgBoot 3.9.5. This affects an unknown part of the file /jeecg-boot/drag/onlDra |
| 🟠 high | CVE-2026-124581: A vulnerability was determined in itsourcecode Airline Reservation System 1.0. | `T1190` | A vulnerability was determined in itsourcecode Airline Reservation System 1.0. Affected is an unknown function of the fi |
| 🟠 high | CVE-2026-121769: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vu… | `T1190` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in axew3.com WP w3all |
| 🟠 high | CVE-2026-125119: Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environm… | — | Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment. From 6.0.0 until 6.13.12, 7. |
| 🟠 high | CVE-2026-125612: Improper neutralization of special elements used in an SQL command ('SQL injection') vu… | `T1190` | Improper neutralization of special elements used in an SQL command ('SQL injection') vulnerability in Deltaww DIAEnergie |
| 🟠 high | CVE-2026-12572: Zoho Corporation ManageEngine DDI Central version below 6201 is vulnerable to SQL injec… | `T1190` | Zoho Corporation ManageEngine DDI Central version below 6201 is vulnerable to SQL injection in HA replication username h |
| 🟠 high | CVE-2026-125759: Nango before 0.71.3 contains an sql injection vulnerability that allows unauthenticated… | `T1190` | Nango before 0.71.3 contains an sql injection vulnerability that allows unauthenticated attackers to execute arbitrary S |
| 🟠 high | CVE-2026-118105: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118109: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118110: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118113: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118114: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118115: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118116: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118117: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118118: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118119: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-118120: Improper neutralization of special elements used in an sql command ('sql injection') in… | `T1190` | Improper neutralization of special elements used in an sql command ('sql injection') in SQL Server allows an authorized  |
| 🟠 high | CVE-2026-121350: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🟠 high | CVE-2026-121900: Adobe Connect is affected by an Improper Neutralization of Special Elements used in an … | `T1190` | Adobe Connect is affected by an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vul |
| 🟠 high | CVE-2026-12062: Zoho Corporation ManageEngine ADAudit Plus versions below 8703 are vulnerable to an aut… | `T1190` | Zoho Corporation ManageEngine ADAudit Plus versions below 8703 are vulnerable to an authenticated SQL injection vulnerab |
| 🟠 high | CVE-2026-76981: Zoho Corporation ManageEngine ADAudit Plus versions below 8711 are vulnerable to an aut… | `T1190` | Zoho Corporation ManageEngine ADAudit Plus versions below 8711 are vulnerable to an authenticated second order SQL injec |
| 🟠 high | CVE-2026-126617: SQL injection in the database layer of Progressive Robot hMailServer 6.0.0-B1 through 6… | `T1190` | SQL injection in the database layer of Progressive Robot hMailServer 6.0.0-B1 through 6.2.18, when the server uses MySQL |
| 🟠 high | CVE-2026-107662: Blind SQL injection in Revive Adserver 6.0.8 and earlier allows an authenticated manage… | `T1190` | Blind SQL injection in Revive Adserver 6.0.8 and earlier allows an authenticated manager restricted to one agency to ext |
| 🟠 high | CVE-2026-91877: Dell OpenManage Ansible Modules, versions 2.0.2 through 10.0.3, contains an Improper Ne… | — | Dell OpenManage Ansible Modules, versions 2.0.2 through 10.0.3, contains an Improper Neutralization of Special Elements  |
| 🟠 high | CVE-2026-126175: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAn |
| 🟠 high | CVE-2026-126213: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAn |
| 🟠 high | CVE-2026-126241: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAu |
| 🟠 high | CVE-2026-126252: A improper neutralization of special elements used in an sql command ('sql injection') … | `T1190` | A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAu |
| 🟠 high | CVE-2026-65971: Livewire PowerGrid creates data tables based on Laravel Livewire library. | `T1190` | Livewire PowerGrid creates data tables based on Laravel Livewire library. From version 6.0.0 to before version 6.10.4, t |
| 🟠 high | CVE-2026-118632: Philips Hue Bridge Pro SQL Injection Remote Code Execution Vulnerability. | `T1190` | Philips Hue Bridge Pro SQL Injection Remote Code Execution Vulnerability. This vulnerability allows network-adjacent att |
| 🟠 high | CVE-2026-81584: An improper neutralization of special elements used in an SQL command vulnerability in … | — | An improper neutralization of special elements used in an SQL command vulnerability in the User API in Synology DiskStat |
| | _+29 more…_ | | |

## Cross-Site Scripting (112)

_Reflected, stored, or DOM-based XSS in web applications._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-60043: An unauthenticated remote attacker can perform a XSS attack on a logged in backend user… | `T1059.007` | An unauthenticated remote attacker can perform a XSS attack on a logged in backend user allowing for execution of multip |
| 🔴 critical | CVE-2026-109454: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🔴 critical | CVE-2026-80095: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🔴 critical | CVE-2026-121904: Adobe Connect is affected by a stored Cross-Site Scripting (XSS) vulnerability that cou… | `T1059.007` | Adobe Connect is affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by a low-privileged  |
| 🔴 critical | CVE-2026-64670: Waline is a comment system with backend support. | `T1059.007` | Waline is a comment system with backend support. In versions 3.15.2 and prior, @waline/client renders the comment editor |
| 🟠 high | CVE-2026-111403: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Inventory WP In |
| 🟠 high | CVE-2026-119483: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in 10Web Form Maker b |
| 🟠 high | CVE-2026-119504: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in DynamiApps Fronten |
| 🟠 high | CVE-2026-119505: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Welcart Welcart e- |
| 🟠 high | CVE-2026-121764: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in FolioVision FV Flo |
| 🟠 high | CVE-2026-121780: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Gijo Varghese Flyi |
| 🟠 high | CVE-2026-123463: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Wham Checkout F |
| 🟠 high | CVE-2026-123484: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Crocoblock JetForm |
| 🟠 high | CVE-2026-54863: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Mamunur Rashid Rev |
| 🟠 high | CVE-2026-121570: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Chill RSVP and  |
| 🟠 high | CVE-2026-121782: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in If-So Dynamic Cont |
| 🟠 high | CVE-2026-122666: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Kitae Park Mang Bo |
| 🟠 high | CVE-2026-123460: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Nickboss WordPress |
| 🟠 high | CVE-2026-123476: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in fifu.app Featured  |
| 🟠 high | CVE-2026-120856: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Rymera Web Co Invo |
| 🟠 high | CVE-2026-122664: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in VideoWhisper.com B |
| 🟠 high | CVE-2026-123482: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Crocoblock JetForm |
| 🟠 high | CVE-2026-84938: The Avada (Fusion) Builder plugin for WordPress is vulnerable to Stored Cross-Site Scri… | `T1059.007` | The Avada (Fusion) Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Form Notification Dynam |
| 🟠 high | CVE-2026-93427: The ARMember Premium – Membership Plugin, Content Restriction, Member Levels, User Prof… | `T1059.007` | The ARMember Premium – Membership Plugin, Content Restriction, Member Levels, User Profile & User signup plugin for Word |
| 🟠 high | CVE-2026-12574: Zoho Corporation ManageEngine DDI Central versions 6200 and below are vulnerable to Ser… | — | Zoho Corporation ManageEngine DDI Central versions 6200 and below are vulnerable to Server-side HTML/JavaScript injectio |
| 🟠 high | CVE-2026-109497: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-109504: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-110045: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-110065: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-111297: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-111300: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-111303: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Office SharePoint allo |
| 🟠 high | CVE-2026-116926: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Microsoft Teams allows an unauth |
| 🟠 high | CVE-2026-119975: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Visual Studio Code allows an una |
| 🟠 high | CVE-2026-121664: Improper neutralization of input during web page generation ('cross-site scripting') in… | `T1059.007` | Improper neutralization of input during web page generation ('cross-site scripting') in Visual Studio Code allows an una |
| 🟠 high | CVE-2026-26248: A improper neutralization of input during web page generation ('cross-site scripting') … | `T1059.007` | A improper neutralization of input during web page generation ('cross-site scripting') vulnerability in Fortinet FortiSa |
| 🟠 high | CVE-2026-122102: Adobe Connect is affected by a stored Cross-Site Scripting (XSS) vulnerability that cou… | `T1059.007` | Adobe Connect is affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by a low-privileged  |
| 🟠 high | CVE-2026-125880: Stored XSS via MMS3 patch metadata (admin context) | `T1059.007` | [cvefeed.io] Stored XSS via MMS3 patch metadata (admin context) |
| 🟠 high | CVE-2026-64671: Waline is a comment system with backend support. | `T1059.007` | Waline is a comment system with backend support. In versions 3.15.2 and prior, the @waline/client UserList widget builds |
| 🟠 high | CVE-2026-121862: The Knowledge Building WordPress plugin before 0.7.3 does not sanitise and escape comme… | `T1059.007` | The Knowledge Building WordPress plugin before 0.7.3 does not sanitise and escape comments submitted through its reply f |
| 🟠 high | CVE-2026-121863: The Knowledge Building WordPress plugin before 0.7.3 does not escape several user-suppl… | `T1059.007` | The Knowledge Building WordPress plugin before 0.7.3 does not escape several user-supplied values before echoing them ba |
| 🟠 high | CVE-2026-123134: The Smoove abandoned cart trigger for WooCommerce WordPress plugin before 4.3.6 does no… | `T1059.007` | The Smoove abandoned cart trigger for WooCommerce WordPress plugin before 4.3.6 does not sanitise and escape abandoned-c |
| 🟠 high | CVE-2026-12424: The ARforms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Refer… | `T1059.007` | The ARforms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Referer Header in all versions up to,  |
| 🟠 high | CVE-2026-12427: The ARforms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the '… | `T1059.007` | The ARforms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'description' parameter in all ver |
| 🟠 high | CVE-2026-124250: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in AyeCode Ltd GeoDir |
| 🟠 high | CVE-2026-123478: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Meow Apps AI Engin |
| 🟠 high | CVE-2026-124253: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vu… | `T1059.007` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in codepeople Calcula |
| 🟠 high | CVE-2026-124687: In Progress® Kendo® UI for jQuery versions from 2022.2.621 prior to 2026.4.1111 the Dro… | — | In Progress® Kendo® UI for jQuery versions from 2022.2.621 prior to 2026.4.1111 the DropDownButton and SplitButton allow |
| 🟠 high | CVE-2026-124688: In Progress® Kendo® UI for jQuery prior to 2026.4.1111 the TabStrip, PanelBar, and Menu… | — | In Progress® Kendo® UI for jQuery prior to 2026.4.1111 the TabStrip, PanelBar, and Menu widgets support mapping a dataSo |
| 🟠 high | CVE-2026-124689: In Progress Kendo UI for jQuery versions 2026.3.1014 up to, but not including, 2026.4.1… | — | In Progress Kendo UI for jQuery versions 2026.3.1014 up to, but not including, 2026.4.1110, ActionSheet does not encode  |
| | _+62 more…_ | | |

## Memory Corruption (882)

_Buffer overflows, use-after-free, type confusion enabling crashes or RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-124560: A vulnerability was found in D-Link DIR-878 1.20B05. | `T1203` | A vulnerability was found in D-Link DIR-878 1.20B05. This affects the function GetCAPTCHAsetting of the file bin/prog.cg |
| 🔴 critical | CVE-2026-119756: Tasmota through 16.0.0, fixed in commit e97e1e4, contains a heap out-of-bounds write vu… | — | Tasmota through 16.0.0, fixed in commit e97e1e4, contains a heap out-of-bounds write vulnerability in SendReceiveDeviceG |
| 🔴 critical | CVE-2026-89126: SAP Web Dispatcher does not sufficiently validate certain network input processed by an… | `T1190`, `T1203` | SAP Web Dispatcher does not sufficiently validate certain network input processed by an internal component. An unauthent |
| 🔴 critical | CVE-2026-124859: Sandbox escape due to incorrect boundary conditions in the Storage: Cache API component. | — | Sandbox escape due to incorrect boundary conditions in the Storage: Cache API component. This vulnerability was fixed in |
| 🔴 critical | CVE-2026-124861: Sandbox escape due to use-after-free in the Audio/Video: cubeb component. | — | Sandbox escape due to use-after-free in the Audio/Video: cubeb component. This vulnerability was fixed in Firefox 160, F |
| 🔴 critical | CVE-2026-124864: Sandbox escape due to use-after-free in the DOM: Service Workers component. | — | Sandbox escape due to use-after-free in the DOM: Service Workers component. This vulnerability was fixed in Firefox 160, |
| 🔴 critical | CVE-2026-124900: Sandbox escape due to use-after-free in the DOM: Service Workers component. | — | Sandbox escape due to use-after-free in the DOM: Service Workers component. This vulnerability was fixed in Firefox 160  |
| 🔴 critical | CVE-2026-124903: Sandbox escape due to use-after-free in the IPC component. | — | Sandbox escape due to use-after-free in the IPC component. This vulnerability was fixed in Firefox 160, Firefox ESR 115. |
| 🔴 critical | CVE-2026-124917: Sandbox escape due to use-after-free in the Widget: Gtk component. | — | Sandbox escape due to use-after-free in the Widget: Gtk component. This vulnerability was fixed in Firefox 160, Firefox  |
| 🔴 critical | CVE-2026-61547: rabbitmq-c is a C-language AMQP client library for RabbitMQ. | `T1203` | rabbitmq-c is a C-language AMQP client library for RabbitMQ. Prior to version 0.17.0, a heap buffer overflow exists in r |
| 🔴 critical | CVE-2026-112967: Heap-based buffer overflow in Windows Xbox Live Networking Service allows an unauthoriz… | `T1203` | Heap-based buffer overflow in Windows Xbox Live Networking Service allows an unauthorized attacker to execute code over  |
| 🔴 critical | CVE-2026-116928: Out-of-bounds write in Microsoft Windows Search Component allows an unauthorized attack… | — | Out-of-bounds write in Microsoft Windows Search Component allows an unauthorized attacker to execute code over a network |
| 🔴 critical | CVE-2026-116945: Heap-based buffer overflow in SQL Server allows an unauthorized attacker to execute cod… | `T1203` | Heap-based buffer overflow in SQL Server allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-119958: Out-of-bounds write in Windows LDAP - Lightweight Directory Access Protocol allows an u… | — | Out-of-bounds write in Windows LDAP - Lightweight Directory Access Protocol allows an unauthorized attacker to execute c |
| 🔴 critical | CVE-2026-66801: Heap-based buffer overflow in Xbox allows an unauthorized attacker to execute code over… | `T1203` | Heap-based buffer overflow in Xbox allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-88218: Double free in Windows DNS allows an unauthorized attacker to execute code over a network. | — | Double free in Windows DNS allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-88243: Out-of-bounds read in Windows DHCP Server allows an unauthorized attacker to execute co… | — | Out-of-bounds read in Windows DHCP Server allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-95882: Stack-based buffer overflow in Windows Microsoft DirectMusic allows an unauthorized att… | `T1203` | Stack-based buffer overflow in Windows Microsoft DirectMusic allows an unauthorized attacker to execute code over a netw |
| 🔴 critical | CVE-2026-95901: Double free in Windows Microsoft DirectMusic allows an unauthorized attacker to execute… | — | Double free in Windows Microsoft DirectMusic allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-95962: Use after free in Windows Virtual Filtering Platform (VFP) allows an unauthorized attac… | — | Use after free in Windows Virtual Filtering Platform (VFP) allows an unauthorized attacker to execute code over a networ |
| 🔴 critical | CVE-2026-96067: Integer overflow or wraparound in Microsoft Color Management allows an unauthorized att… | — | Integer overflow or wraparound in Microsoft Color Management allows an unauthorized attacker to execute code over a netw |
| 🔴 critical | CVE-2026-96078: Heap-based buffer overflow in Microsoft Color Management allows an unauthorized attacke… | `T1203` | Heap-based buffer overflow in Microsoft Color Management allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-96157: Heap-based buffer overflow in Microsoft Windows Media Foundation allows an unauthorized… | `T1203` | Heap-based buffer overflow in Microsoft Windows Media Foundation allows an unauthorized attacker to execute code over a  |
| 🔴 critical | CVE-2026-121289: On affected platforms running Arista EOS with BGP configured, a specially crafted packe… | `T1190` | On affected platforms running Arista EOS with BGP configured, a specially crafted packet can cause the BGP agent to cras |
| 🔴 critical | CVE-2026-118383: A use-after-free in the replication component of MongoDB Server can occur when a newly … | `T1190` | A use-after-free in the replication component of MongoDB Server can occur when a newly elected replica set primary compl |
| 🔴 critical | CVE-2026-82391: The HTTP/2 front-end of the Zephyr HTTP server aliased connection receive state as a sc… | `T1203` | The HTTP/2 front-end of the Zephyr HTTP server aliased connection receive state as a scratch output. In subsys/net/lib/h |
| 🔴 critical | CVE-2026-109445: PLANET GS-5220-8P2T2S (hardware version 3.0) firmware versions before 3.2412b261008 con… | `T1203` | PLANET GS-5220-8P2T2S (hardware version 3.0) firmware versions before 3.2412b261008 contains a stack-based buffer overfl |
| 🔴 critical | CVE-2026-123965: A prompt injection vulnerability in all versions of Jet Admin Cloud Platform allows a r… | — | A prompt injection vulnerability in all versions of Jet Admin Cloud Platform allows a remote attacker with a free accoun |
| 🔴 critical | CVE-2026-129250: A security vulnerability has been detected in Edimax BR6478ACV2 1.23. | `T1203` | A security vulnerability has been detected in Edimax BR6478ACV2 1.23. The impacted element is the function formPPTPSetup |
| 🔴 critical | CVE-2026-129351: A security vulnerability has been detected in TRENDnet TEW-657BRM 1.00.1. | — | A security vulnerability has been detected in TRENDnet TEW-657BRM 1.00.1. This vulnerability affects the function sprint |
| 🔴 critical | CVE-2026-129352: A vulnerability was detected in TRENDnet TEW-657BRM 1.00.1. | `T1203` | A vulnerability was detected in TRENDnet TEW-657BRM 1.00.1. This issue affects some unknown processing of the file /usr/ |
| 🔴 critical | CVE-2026-129354: A flaw has been found in D-Link DIR-600L 2.17b02. | `T1203` | A flaw has been found in D-Link DIR-600L 2.17b02. Affected by this issue is the function hnap_main of the file htdocs/cg |
| 🔴 critical | CVE-2026-129453: A vulnerability was found in DrayTek Vigor2960 1.5.1.6. | `T1203` | A vulnerability was found in DrayTek Vigor2960 1.5.1.6. This issue affects the function check_file_exist of the file /cg |
| 🟠 high | CVE-2026-124561: A vulnerability was determined in D-Link DIR-878 1.20B05. | `T1203` | A vulnerability was determined in D-Link DIR-878 1.20B05. This impacts the function SetVLANSettings of the file prog.cgi |
| 🟠 high | CVE-2026-124562: A vulnerability was identified in D-Link DIR-878 1.20B05. | `T1203` | A vulnerability was identified in D-Link DIR-878 1.20B05. Affected is the function SetWanSettings of the component HNAP  |
| 🟠 high | CVE-2026-124563: A security flaw has been discovered in D-Link DIR-878 1.20B05. | `T1203` | A security flaw has been discovered in D-Link DIR-878 1.20B05. Affected by this vulnerability is the function SetWanSett |
| 🟠 high | CVE-2026-115256: The Mail Debug for WooCommerce WordPress plugin through 1.3.0 does not perform any capa… | — | The Mail Debug for WooCommerce WordPress plugin through 1.3.0 does not perform any capability, authentication, or nonce  |
| 🟠 high | CVE-2026-124586: A vulnerability was determined in Tencent RapidJSON 1.1.0. | — | A vulnerability was determined in Tencent RapidJSON 1.1.0. Impacted is the function GetCachedPowerByIndex in the library |
| 🟠 high | CVE-2026-119610: A flaw was found in GStreamer's gst-plugins-good, specifically in the H.264 RTP depaylo… | — | A flaw was found in GStreamer's gst-plugins-good, specifically in the H.264 RTP depayloader element. When processing MTA |
| 🟠 high | CVE-2026-95779: An exposure of the appliance’s confidential certificate  information 
vulnerability exi… | — | An exposure of the appliance’s confidential certificate  information 
vulnerability exists in HPE Morpheus manager softw |
| 🟠 high | CVE-2026-123367: Thor Vector Graphics (ThorVG) is a production-ready vector graphics engine. | `T1203` | Thor Vector Graphics (ThorVG) is a production-ready vector graphics engine. Prior to 1.1.2, the bundled jpgd JPEG decode |
| 🟠 high | CVE-2026-123999: NASA JPL ION-DTN 3.6.2 through 4.2.0 contains a heap-based buffer overflow in the Netwo… | `T1203` | NASA JPL ION-DTN 3.6.2 through 4.2.0 contains a heap-based buffer overflow in the Network Management daemon (nm_mgr) str |
| 🟠 high | CVE-2026-124001: NASA JPL ION-DTN 2.2.1b through 4.2.0 contains an integer overflow vulnerability in the… | `T1190` | NASA JPL ION-DTN 2.2.1b through 4.2.0 contains an integer overflow vulnerability in the Datagram Retransmission (DGR) co |
| 🟠 high | CVE-2026-125181: FFmpeg through 9.0.2 contains an out-of-bounds write vulnerability in flic_decode_frame… | — | FFmpeg through 9.0.2 contains an out-of-bounds write vulnerability in flic_decode_frame_15_16BPP() in libavcodec/flicvid |
| 🟠 high | CVE-2026-125196: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in liboapve_encode()… | `T1203` | FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in liboapve_encode() in libavcodec/liboapvenc.c that  |
| 🟠 high | CVE-2026-125201: FFmpeg 7.0 before 8.1.3 and 9.x before 9.0.2 contains a heap out-of-bounds write vulner… | — | FFmpeg 7.0 before 8.1.3 and 9.x before 9.0.2 contains a heap out-of-bounds write vulnerability in vk_av1_decode_slice()  |
| 🟠 high | CVE-2026-125202: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in vaapi_hevc_start_… | `T1203` | FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in vaapi_hevc_start_frame() in libavcodec/vaapi_hevc. |
| 🟠 high | CVE-2026-125203: FFmpeg before 8.1.3 and 9.x before 9.0.2 contains a heap buffer overflow vulnerability … | `T1203` | FFmpeg before 8.1.3 and 9.x before 9.0.2 contains a heap buffer overflow vulnerability in the Cook multichannel decoder  |
| 🟠 high | CVE-2026-125204: FFmpeg through 9.0.2 contains a heap buffer overflow in ff_libwebp_get_frame() in libwe… | `T1203` | FFmpeg through 9.0.2 contains a heap buffer overflow in ff_libwebp_get_frame() in libwebpenc_common.c that lets attacker |
| 🟠 high | CVE-2026-125208: FFmpeg through 9.0.2 contains an out-of-bounds write vulnerability in v4l2_buffer_swfra… | — | FFmpeg through 9.0.2 contains an out-of-bounds write vulnerability in v4l2_buffer_swframe_to_buf() in libavcodec/v4l2_bu |
| | _+832 more…_ | | |

## Insecure Deserialization (26)

_Unsafe deserialization of attacker-controlled data leading to RCE._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-124079: rConfig Core 8.0.0 before 8.2.19 and rConfig Pro before 8.4.1 contain a deserialization… | `T1190`, `T1059.007` | rConfig Core 8.0.0 before 8.2.19 and rConfig Pro before 8.4.1 contain a deserialization of untrusted data vulnerability  |
| 🔴 critical | CVE-2026-64678: NOsql Object (NO2 a.k.a Nitrite) database is an open source nosql embedded document store. | `T1190` | NOsql Object (NO2 a.k.a Nitrite) database is an open source nosql embedded document store. Prior to version 4.4.1, when  |
| 🔴 critical | CVE-2026-126325: A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill… | `T1190`, `T1059.007` | A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill and PTC FlexPLM. The vulnerabili |
| 🔴 critical | CVE-2026-119077: The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnera… | `T1059.007` | The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to PHP Object Injection in al |
| 🔴 critical | CVE-2026-125855: Deserialization of Untrusted Data vulnerability in Elextensions ELEX WordPress HelpDesk… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Elextensions ELEX WordPress HelpDesk & Customer Ticketing System elex |
| 🔴 critical | CVE-2026-63079: RBH Access Technologies Integra32 Security Management System 5.1.11 R5.0 contains an un… | `T1190`, `T1059.007` | RBH Access Technologies Integra32 Security Management System 5.1.11 R5.0 contains an unauthenticated deserialization vul |
| 🔴 critical | CVE-2026-122662: Deserialization of Untrusted Data vulnerability in Barn2 Plugins Document Library Pro d… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Barn2 Plugins Document Library Pro document-library-pro allows Object |
| 🟠 high | CVE-2026-111421: Apache Airflow's Task Execution API stored XCom values written by a task without the re… | `T1059.007` | Apache Airflow's Task Execution API stored XCom values written by a task without the reserved-key check applied elsewher |
| 🟠 high | CVE-2026-12389: A vulnerability that could lead to a high privileged authenticated user performing a re… | `T1190` | A vulnerability that could lead to a high privileged authenticated user performing a remote code execution attack. |
| 🟠 high | CVE-2026-109463: Deserialization of untrusted data in Windows DNS allows an unauthorized attacker to exe… | `T1059.007` | Deserialization of untrusted data in Windows DNS allows an unauthorized attacker to execute code over a network. |
| 🟠 high | CVE-2026-109464: Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized a… | `T1059.007` | Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a ne |
| 🟠 high | CVE-2026-109472: Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized a… | `T1059.007` | Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a ne |
| 🟠 high | CVE-2026-110044: Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized a… | `T1059.007` | Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a ne |
| 🟠 high | CVE-2026-120000: Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized a… | `T1059.007` | Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a ne |
| 🟠 high | CVE-2026-123390: Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized a… | `T1059.007` | Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a ne |
| 🟠 high | CVE-2026-77882: A deserialization of untrusted data vulnerability was discovered in Lenovo System Updat… | `T1059.007` | A deserialization of untrusted data vulnerability was discovered in Lenovo System Update that could allow a local authen |
| 🟠 high | CVE-2026-106140: In Progress® Telerik® Reporting prior to version 20.3.26.1110, a deserialization of unt… | `T1190`, `T1059.007` | In Progress® Telerik® Reporting prior to version 20.3.26.1110, a deserialization of untrusted data vulnerability in the  |
| 🟠 high | CVE-2026-124701: In Telerik UI for WinForms, versions prior to 2026.4.1111, a deserialization of untrust… | `T1059.007` | In Telerik UI for WinForms, versions prior to 2026.4.1111, a deserialization of untrusted data vulnerability exists that |
| 🟠 high | CVE-2026-124704: In Telerik UI for WPF, versions prior to 2026.4.1110, a deserialization of untrusted da… | `T1059.007` | In Telerik UI for WPF, versions prior to 2026.4.1110, a deserialization of untrusted data vulnerability exists that allo |
| 🟠 high | CVE-2026-126982: A type allow-list bypass in the BSON serialization library of the MongoDB C# Driver all… | `T1190` | A type allow-list bypass in the BSON serialization library of the MongoDB C# Driver allows a type-restriction check to b |
| 🟠 high | CVE-2026-126322: OpenEMR before 8.3.0 contains an unsanitized deserialization vulnerability that allows … | `T1059.007` | OpenEMR before 8.3.0 contains an unsanitized deserialization vulnerability that allows authenticated attackers to contro |
| 🟠 high | CVE-2026-103769: Deserialization of Untrusted Data vulnerability in Acowebs PDF Invoices and Packing Sli… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Acowebs PDF Invoices and Packing Slips For WooCommerce pdf-invoices-a |
| 🟠 high | CVE-2026-119512: Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsl… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsletters-lite allows Object Injecti |
| 🟠 high | CVE-2026-120835: Deserialization of Untrusted Data vulnerability in VillaTheme AFFI – Affiliate Marketin… | `T1059.007` | Deserialization of Untrusted Data vulnerability in VillaTheme AFFI – Affiliate Marketing for WooCommerce affi-affiliate- |
| 🟠 high | CVE-2026-124969: The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimiza… | `T1190` | The Optimole – Optimize Images \| Convert WebP & AVIF \| CDN & Lazy Load \| Image Optimization plugin for WordPress is vuln |
| 🟠 high | CVE-2026-125449: Deserialization of Untrusted Data vulnerability in Mamunur Rashid Testimonial Slider te… | `T1059.007` | Deserialization of Untrusted Data vulnerability in Mamunur Rashid Testimonial Slider testimonial-slider-and-showcase all |

## Path Traversal & File Disclosure (67)

_Directory traversal and arbitrary file read/write vulnerabilities._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-123807: Signal K Server is a server application that runs on a central hub in a boat. | — | Signal K Server is a server application that runs on a central hub in a boat. From 2.0.0 until 2.34.0 for Signal K Serve |
| 🔴 critical | CVE-2026-121349: Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Direc… | `T1190` | Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabi |
| 🔴 critical | CVE-2026-121351: Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Direc… | — | Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabi |
| 🔴 critical | CVE-2026-121354: Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Direc… | — | Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabi |
| 🔴 critical | CVE-2026-121906: Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Direc… | — | Adobe Connect is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabi |
| 🔴 critical | CVE-2026-115734: The Pay with a tweet WordPress plugin through 1.0.5 does not validate a file path befor… | — | The Pay with a tweet WordPress plugin through 1.0.5 does not validate a file path before deleting it, nor does it restri |
| 🔴 critical | CVE-2026-115735: The Somatic Framework WordPress plugin through 1.8.14 does not perform an authorization… | — | The Somatic Framework WordPress plugin through 1.8.14 does not perform an authorization check or validate a user-supplie |
| 🔴 critical | CVE-2026-126537: The Ninja Forms - File Uploads add-on for WordPress is vulnerable to Arbitrary File Del… | `T1190` | The Ninja Forms - File Uploads add-on for WordPress is vulnerable to Arbitrary File Deletion (and arbitrary file read vi |
| 🔴 critical | CVE-2026-126147: A improper limitation of a pathname to a restricted directory ('path traversal') vulner… | — | A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0 |
| 🔴 critical | CVE-2026-124822: The Easy DragDrop File Uploader WordPress plugin before 1.1.10 does not validate a user… | — | The Easy DragDrop File Uploader WordPress plugin before 1.1.10 does not validate a user-supplied path before deleting it |
| 🔴 critical | CVE-2026-129165: Tactical RMM 0.17.0 through 1.6.1 contains an arbitrary file read in the /reporting/tem… | — | Tactical RMM 0.17.0 through 1.6.1 contains an arbitrary file read in the /reporting/templates/preview/ endpoint because  |
| 🔴 critical | CVE-2026-120522: The Cloud Storage Manager for Fluent Forms – Google Drive, Dropbox, OneDrive, S3 Upload… | `T1190` | The Cloud Storage Manager for Fluent Forms – Google Drive, Dropbox, OneDrive, S3 Uploads plugin for WordPress is vulnera |
| 🔴 critical | CVE-2026-129450: A vulnerability was detected in DrayTek Vigor2960 1.5.1.6. | — | A vulnerability was detected in DrayTek Vigor2960 1.5.1.6. Affected by this issue is the function sub_1E084 of the file  |
| 🔴 critical | CVE-2026-129451: A flaw has been found in DrayTek Vigor2960 up to 1.5.1.6. | — | A flaw has been found in DrayTek Vigor2960 up to 1.5.1.6. This affects the function app_guest_export of the file /cgi-bi |
| 🔴 critical | CVE-2026-125795: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote … | — | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in |
| 🟠 high | CVE-2026-124509: A vulnerability was identified in floci-io Floci up to 2.1.0. | — | A vulnerability was identified in floci-io Floci up to 2.1.0. The affected element is the function S3Destination.bucketN |
| 🟠 high | CVE-2026-124557: A vulnerability was detected in OtterMind Chat2DB up to 5.3.8. | — | A vulnerability was detected in OtterMind Chat2DB up to 5.3.8. Impacted is the function DbMybatisGenerateServiceImpl.gen |
| 🟠 high | CVE-2026-121629: A flaw was found in GStreamer's adaptive streaming demuxers (HLS, DASH, MSS). | — | A flaw was found in GStreamer's adaptive streaming demuxers (HLS, DASH, MSS). When processing a media playlist or manife |
| 🟠 high | CVE-2026-102643: AsyncSSH is a Python package which provides an asynchronous client and server implement… | — | AsyncSSH is a Python package which provides an asynchronous client and server implementation of the SSHv2 protocol on to |
| 🟠 high | CVE-2026-100386: The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Directory Tra… | — | The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and |
| 🟠 high | CVE-2026-120513: The Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder with… | — | The Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder with AI plugin for WordPress is vulne |
| 🟠 high | CVE-2026-120013: The agent_memory module accepts a caller-supplied tenant parameter in create_client(ten… | — | The agent_memory module accepts a caller-supplied tenant parameter in create_client(tenant=...). Prior to version 0.50.0 |
| 🟠 high | CVE-2026-105505: Relative path traversal in Microsoft Input Method Editor (IME) allows an authorized att… | — | Relative path traversal in Microsoft Input Method Editor (IME) allows an authorized attacker to elevate privileges local |
| 🟠 high | CVE-2026-112762: Relative path traversal in Windows Print Spooler Components allows an unauthorized atta… | — | Relative path traversal in Windows Print Spooler Components allows an unauthorized attacker to elevate privileges over a |
| 🟠 high | CVE-2026-113823: Improper limitation of a pathname to a restricted directory ('path traversal') in Azure… | — | Improper limitation of a pathname to a restricted directory ('path traversal') in Azure CycleCloud allows an unauthorize |
| 🟠 high | CVE-2026-114161: Improper limitation of a pathname to a restricted directory ('path traversal') in Azure… | — | Improper limitation of a pathname to a restricted directory ('path traversal') in Azure CycleCloud allows an authorized  |
| 🟠 high | CVE-2026-118151: External control of file name or path in Microsoft Exchange Server allows an authorized… | — | External control of file name or path in Microsoft Exchange Server allows an authorized attacker to elevate privileges o |
| 🟠 high | CVE-2026-119903: Improper access control in Windows Installer allows an authorized attacker to elevate p… | — | Improper access control in Windows Installer allows an authorized attacker to elevate privileges locally. |
| 🟠 high | CVE-2026-119939: Improper privilege management in Windows Print Spooler Components allows an authorized … | — | Improper privilege management in Windows Print Spooler Components allows an authorized attacker to elevate privileges lo |
| 🟠 high | CVE-2026-124228: Improper limitation of a pathname to a restricted directory ('path traversal') in Micro… | — | Improper limitation of a pathname to a restricted directory ('path traversal') in Microsoft Office Outlook allows an aut |
| 🟠 high | CVE-2025-61625: An improper limitation of a pathname to a restricted directory ('path traversal') vulne… | — | An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiAnalyze |
| 🟠 high | CVE-2026-115483: The Everest Forms plugin for WordPress is vulnerable to Arbitrary File Read in all vers… | — | The Everest Forms plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 3.6.3  |
| 🟠 high | CVE-2026-121371: On affected EOS versions with the eAPI service enabled, a specially crafted HTTP reques… | — | On affected EOS versions with the eAPI service enabled, a specially crafted HTTP request can allow an unauthenticated, r |
| 🟠 high | CVE-2026-110090: Premiere Pro is affected by an Improper Limitation of a Pathname to a Restricted Direct… | — | Premiere Pro is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabil |
| 🟠 high | CVE-2026-113532: After Effects is affected by an Improper Limitation of a Pathname to a Restricted Direc… | — | After Effects is affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerabi |
| 🟠 high | CVE-2026-126499: Jellyfin before 12.0 contains a path traversal vulnerability in the DELETE /Library/Vir… | — | Jellyfin before 12.0 contains a path traversal vulnerability in the DELETE /Library/VirtualFolders and POST /Library/Vir |
| 🟠 high | CVE-2026-116633: A potential vulnerability was reported in some Lenovo Tablets that could allow a third-… | — | A potential vulnerability was reported in some Lenovo Tablets that could allow a third-party application to perform an a |
| 🟠 high | CVE-2026-123747: A flaw was found in pappl-retrofit. | — | A flaw was found in pappl-retrofit. The application fails to properly sanitize user-supplied filenames when handling the |
| 🟠 high | CVE-2026-126779: Spatie Browsershot 2.2.0 before 5.5.0 contains a local file read vulnerability that all… | — | Spatie Browsershot 2.2.0 before 5.5.0 contains a local file read vulnerability that allows attackers to read server file |
| 🟠 high | CVE-2026-126804: WWBN AVideo 12.4 through 29.7.1 contains a path traversal vulnerability in the ADs plug… | — | WWBN AVideo 12.4 through 29.7.1 contains a path traversal vulnerability in the ADs plugin deleteImage.json.php that allo |
| 🟠 high | CVE-2026-126153: A improper limitation of a pathname to a restricted directory ('path traversal') vulner… | — | A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0 |
| 🟠 high | CVE-2026-126219: A improper limitation of a pathname to a restricted directory ('path traversal') vulner… | — | A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiAnalyzer |
| 🟠 high | CVE-2026-126222: A improper limitation of a pathname to a restricted directory ('path traversal') vulner… | — | A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiAnalyzer |
| 🟠 high | CVE-2026-126235: A improper limitation of a pathname to a restricted directory ('path traversal') vulner… | — | A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiAnalyzer |
| 🟠 high | CVE-2026-126255: A path traversal: '../filedir' vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, F… | — | A path traversal: '../filedir' vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, Forti |
| 🟠 high | CVE-2026-114556: MailEnable Save Directory Traversal Arbitrary File Creation Vulnerability. | — | MailEnable Save Directory Traversal Arbitrary File Creation Vulnerability. This vulnerability allows remote attackers to |
| 🟠 high | CVE-2026-111435: Relative path traversal vulnerability in openEuler iSulad on Linux. | — | Relative path traversal vulnerability in openEuler iSulad on Linux.

This vulnerability is associated with program file  |
| 🟠 high | CVE-2026-18792: An improper limitation of a pathname to a restricted directory vulnerability in the Sha… | — | An improper limitation of a pathname to a restricted directory vulnerability in the Sharing API in Synology DiskStation  |
| 🟠 high | CVE-2026-14661: External control of file name in PostgreSQL dblink and CREATE/ALTER SUBSCRIPTION allows… | — | External control of file name in PostgreSQL dblink and CREATE/ALTER SUBSCRIPTION allows a user to achieve persistent den |
| 🟠 high | CVE-2026-18379: A flaw was found in yggdrasil-worker-package-manager. | `T1068` | A flaw was found in yggdrasil-worker-package-manager. An authenticated attacker can exploit this issue to achieve arbitr |
| | _+17 more…_ | | |

## SSRF, CSRF & Open Redirect (52)

_Server-side request forgery, cross-site request forgery, and redirect issues._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-89119: SAP Web Dispatcher and SAP NetWeaver Application Server ABAP (Internet Communication Ma… | — | SAP Web Dispatcher and SAP NetWeaver Application Server ABAP (Internet Communication Manager) do not perform sufficient  |
| 🔴 critical | CVE-2026-114160: Server-side request forgery (ssrf) in Azure Managed Grafana allows an unauthorized atta… | — | Server-side request forgery (ssrf) in Azure Managed Grafana allows an unauthorized attacker to elevate privileges over a |
| 🔴 critical | CVE-2026-121356: Adobe Connect is affected by a Server-Side Request Forgery (SSRF) vulnerability that co… | `T1068` | Adobe Connect is affected by a Server-Side Request Forgery (SSRF) vulnerability that could result in privilege escalatio |
| 🔴 critical | CVE-2026-121889: Adobe Connect is affected by a Server-Side Request Forgery (SSRF) vulnerability that co… | `T1068` | Adobe Connect is affected by a Server-Side Request Forgery (SSRF) vulnerability that could result in privilege escalatio |
| 🔴 critical | CVE-2026-128049: OpenMage Magento LTS before 20.18.2 and 21.0.0-beta1 before 21.0.0-beta3 contains a cro… | — | OpenMage Magento LTS before 20.18.2 and 21.0.0-beta1 before 21.0.0-beta3 contains a cross-site request forgery vulnerabi |
| 🟠 high | CVE-2026-124558: A vulnerability has been found in DataLinkDC Dinky up to 1.2.5. | — | A vulnerability has been found in DataLinkDC Dinky up to 1.2.5. The impacted element is the function SqlGateway.onOpen o |
| 🟠 high | CVE-2026-119755: Tasmota through 16.0.0, fixed in commit 1cb7ebc, contains a cross-site request forgery … | — | Tasmota through 16.0.0, fixed in commit 1cb7ebc, contains a cross-site request forgery vulnerability that allows unauthe |
| 🟠 high | CVE-2026-123818: LMDeploy is a toolkit for compressing, deploying, and serving large language models. | — | LMDeploy is a toolkit for compressing, deploying, and serving large language models. From 0.12.3 until 0.15.0, _is_safe_ |
| 🟠 high | CVE-2026-56712: Replicate Cog through 0.23.1 contains a server-side request forgery vulnerability that … | — | Replicate Cog through 0.23.1 contains a server-side request forgery vulnerability that allows attackers to cause the Cog |
| 🟠 high | CVE-2026-125114: Novu: SSRF via conditions filter webhook bypasses validateUrlSsrf() protection | — | [cvefeed.io] Novu: SSRF via conditions filter webhook bypasses validateUrlSsrf() protection |
| 🟠 high | CVE-2026-120014: SAP HANA XSA Web Dispatcher does not perform sufficient request validation in certain a… | — | SAP HANA XSA Web Dispatcher does not perform sufficient request validation in certain administrative functionality. In t |
| 🟠 high | CVE-2026-12964: A vulnerability allowing for privileged escalation of the viewer account to gain admini… | — | A vulnerability allowing for privileged escalation of the viewer account to gain administrator privileges. |
| 🟠 high | CVE-2026-60041: An unauthenticated remote attacker can perform a CSRF attack on a logged in backend use… | — | An unauthenticated remote attacker can perform a CSRF attack on a logged in backend user allowing for execution of multi |
| 🟠 high | CVE-2026-124251: Cross-Site Request Forgery (CSRF) vulnerability in XplodedThemes WPIDE – File Manager &… | — | Cross-Site Request Forgery (CSRF) vulnerability in XplodedThemes WPIDE – File Manager & Code Editor wpide allows Cross S |
| 🟠 high | CVE-2026-109481: Cross-site request forgery (csrf) in ASP.NET Core allows an unauthorized attacker to el… | — | Cross-site request forgery (csrf) in ASP.NET Core allows an unauthorized attacker to elevate privileges over a network. |
| 🟠 high | CVE-2026-109502: Server-side request forgery (ssrf) in Microsoft Office SharePoint allows an authorized … | — | Server-side request forgery (ssrf) in Microsoft Office SharePoint allows an authorized attacker to elevate privileges ov |
| 🟠 high | CVE-2026-111296: Server-side request forgery (ssrf) in Microsoft Office SharePoint allows an authorized … | — | Server-side request forgery (ssrf) in Microsoft Office SharePoint allows an authorized attacker to elevate privileges ov |
| 🟠 high | CVE-2026-119983: Server-side request forgery (ssrf) in Visual Studio Code allows an unauthorized attacke… | — | Server-side request forgery (ssrf) in Visual Studio Code allows an unauthorized attacker to bypass a security feature ov |
| 🟠 high | CVE-2026-125881: Schema-hint SSRF via service import schema validation | — | [cvefeed.io] Schema-hint SSRF via service import schema validation |
| 🟠 high | CVE-2026-125784: Cross-Site Request Forgery (CSRF) vulnerability in Magnigenie RestroPress restropress a… | — | Cross-Site Request Forgery (CSRF) vulnerability in Magnigenie RestroPress restropress allows Cross Site Request Forgery. |
| 🟠 high | CVE-2026-118411: Cross-Site Request Forgery (CSRF) in Apache Roller 5.0.1 through 6.1.6 allows an unauth… | — | Cross-Site Request Forgery (CSRF) in Apache Roller 5.0.1 through 6.1.6 allows an unauthenticated attacker to create an a |
| 🟠 high | CVE-2026-125446: Cross-Site Request Forgery (CSRF) vulnerability in WisdmLabs Edwiser Bridge edwiser-bri… | — | Cross-Site Request Forgery (CSRF) vulnerability in WisdmLabs Edwiser Bridge edwiser-bridge allows Cross Site Request For |
| 🟠 high | CVE-2026-125838: Cross-Site Request Forgery (CSRF) vulnerability in webriti Quality quality allows Cross… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Quality quality allows Cross Site Request Forgery.This issue  |
| 🟠 high | CVE-2026-125839: Cross-Site Request Forgery (CSRF) vulnerability in webriti ElitePress elitepress allows… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti ElitePress elitepress allows Cross Site Request Forgery.This  |
| 🟠 high | CVE-2026-125840: Cross-Site Request Forgery (CSRF) vulnerability in webriti Rambo rambo allows Cross Sit… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Rambo rambo allows Cross Site Request Forgery.This issue affe |
| 🟠 high | CVE-2026-125841: Cross-Site Request Forgery (CSRF) vulnerability in webriti Heroic heroic allows Cross S… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Heroic heroic allows Cross Site Request Forgery.This issue af |
| 🟠 high | CVE-2026-125842: Cross-Site Request Forgery (CSRF) vulnerability in webriti Wallstreet Agency wallstreet… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Wallstreet Agency wallstreet-agency allows Cross Site Request |
| 🟠 high | CVE-2026-125843: Cross-Site Request Forgery (CSRF) vulnerability in webriti Spasalon spasalon allows Cro… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Spasalon spasalon allows Cross Site Request Forgery.This issu |
| 🟠 high | CVE-2026-125844: Cross-Site Request Forgery (CSRF) vulnerability in webriti vice vice allows Cross Site … | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti vice vice allows Cross Site Request Forgery.This issue affect |
| 🟠 high | CVE-2026-125845: Cross-Site Request Forgery (CSRF) vulnerability in webriti vdequator vdequator allows C… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti vdequator vdequator allows Cross Site Request Forgery.This is |
| 🟠 high | CVE-2026-125846: Cross-Site Request Forgery (CSRF) vulnerability in webriti Mazino mazino allows Cross S… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Mazino mazino allows Cross Site Request Forgery.This issue af |
| 🟠 high | CVE-2026-125847: Cross-Site Request Forgery (CSRF) vulnerability in webriti vdperanto vdperanto allows C… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti vdperanto vdperanto allows Cross Site Request Forgery.This is |
| 🟠 high | CVE-2026-125848: Cross-Site Request Forgery (CSRF) vulnerability in webriti Leo leo allows Cross Site Re… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Leo leo allows Cross Site Request Forgery.This issue affects  |
| 🟠 high | CVE-2026-125849: Cross-Site Request Forgery (CSRF) vulnerability in webriti Shk Corporate shk-corporate … | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Shk Corporate shk-corporate allows Cross Site Request Forgery |
| 🟠 high | CVE-2026-125850: Cross-Site Request Forgery (CSRF) vulnerability in webriti Appointment Dark appointment… | — | Cross-Site Request Forgery (CSRF) vulnerability in webriti Appointment Dark appointment-dark allows Cross Site Request F |
| 🟠 high | CVE-2026-65967: Fider is a feedback portal for feature requests and suggestions. | — | Fider is a feedback portal for feature requests and suggestions. Prior to version 0.34.0, a Server-Side Request Forgery  |
| 🟠 high | CVE-2026-125926: Server-side request forgery (SSRF) in the server registration and update API in Amazon … | — | Server-side request forgery (SSRF) in the server registration and update API in Amazon mcp-gateway-registry before 1.35. |
| 🟠 high | CVE-2026-126799: Gotenberg 8.31.0 before 8.38.0 contains a server-side request forgery vulnerability in … | — | Gotenberg 8.31.0 before 8.38.0 contains a server-side request forgery vulnerability in IsPublicIP() that allows unauthen |
| 🟠 high | CVE-2026-67542: Heym builds and runs agentic systems and business-process automations on self-hosted in… | — | Heym builds and runs agentic systems and business-process automations on self-hosted infrastructure. Prior to version 0. |
| 🟠 high | CVE-2026-67545: Heym builds and runs agentic systems and business-process automations on self-hosted in… | — | Heym builds and runs agentic systems and business-process automations on self-hosted infrastructure. Prior to version 0. |
| 🟠 high | CVE-2026-122003: The Abilities Bridge WordPress plugin before 1.4.2 does not require a valid nonce befor… | — | The Abilities Bridge WordPress plugin before 1.4.2 does not require a valid nonce before re-authenticating a REST API re |
| 🟠 high | CVE-2026-125836: Cross-Site Request Forgery (CSRF) vulnerability in Nicu Micle Simple JWT Login simple-j… | — | Cross-Site Request Forgery (CSRF) vulnerability in Nicu Micle Simple JWT Login simple-jwt-login allows Cross Site Reques |
| 🟠 high | CVE-2026-124705: In Progress® Telerik® UI for .NET MAUI prior to version 16.0.0, an untrusted URL redire… | — | In Progress® Telerik® UI for .NET MAUI prior to version 16.0.0, an untrusted URL redirection vulnerability in the RadRic |
| 🟠 high | CVE-2026-126997: A vulnerability was identified in JeecgBoot up to 3.9.6. | — | A vulnerability was identified in JeecgBoot up to 3.9.6. This affects the function RestTemplate.exchange of the file org |
| 🟠 high | CVE-2026-126998: A security flaw has been discovered in JeecgBoot up to 3.9.5. | — | A security flaw has been discovered in JeecgBoot up to 3.9.5. This vulnerability affects the function OpenApiController. |
| 🟠 high | CVE-2026-124700: In Telerik UI for WinForms, versions prior to 2026.4.1111, an untrusted URL redirection… | — | In Telerik UI for WinForms, versions prior to 2026.4.1111, an untrusted URL redirection vulnerability exists that allows |
| 🟠 high | CVE-2026-124702: In Telerik UI for WPF, versions prior to 2026.4.1110, an untrusted URL redirection vuln… | — | In Telerik UI for WPF, versions prior to 2026.4.1110, an untrusted URL redirection vulnerability exists that allows an a |
| 🟠 high | CVE-2026-126379: Vvveb 1.0.8.6 contains an incomplete server-side request forgery fix that allows authen… | — | Vvveb 1.0.8.6 contains an incomplete server-side request forgery fix that allows authenticated admin users to bypass DNS |
| 🟠 high | CVE-2026-126416: OpenEMR before 8.5.0 contains an improper authorization vulnerability in patient_tracke… | — | OpenEMR before 8.5.0 contains an improper authorization vulnerability in patient_tracker_status.php that allows low-priv |
| 🟠 high | CVE-2026-116411: Dell PowerStore contains a Server-Side Request Forgery (SSRF) vulnerability. | — | Dell PowerStore contains a Server-Side Request Forgery (SSRF) vulnerability. An authenticated user with limited privileg |
| | _+2 more…_ | | |

## Cryptographic Weaknesses (11)

_Broken cryptography, weak hashes, or insecure key management._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-125383: INDOTALENT WHMS (Asp.Net-Core-Inventory-Order-Management-System) before 10.20261109 con… | `T1078` | INDOTALENT WHMS (Asp.Net-Core-Inventory-Order-Management-System) before 10.20261109 contains an authentication bypass vu |
| 🔴 critical | CVE-2026-125370: Kubero 3.0.0 through 3.1.1 contains an authentication bypass vulnerability that allows … | `T1078` | Kubero 3.0.0 through 3.1.1 contains an authentication bypass vulnerability that allows unauthenticated remote attackers  |
| 🔴 critical | CVE-2026-64682: AstroBlocks is a block-first CMS for Astro projects. | — | AstroBlocks is a block-first CMS for Astro projects. Prior to version 3.4.0, admin session tokens can be forged due to a |
| 🔴 critical | CVE-2026-126797: NextScan 1.1.0 through 1.2.0 contains an authentication bypass vulnerability in ns-admi… | `T1078` | NextScan 1.1.0 through 1.2.0 contains an authentication bypass vulnerability in ns-admin that allows unauthenticated att |
| 🟠 high | CVE-2026-124598: An
API key is hardcoded and retrievable from the GV-Face package. | — | An
API key is hardcoded and retrievable from the GV-Face package. Since
Android applications can be reverse engineered,  |
| 🟠 high | CVE-2026-102219: Inadequate encryption strength in Windows Modern Device Management (MDM) allows an unau… | — | Inadequate encryption strength in Windows Modern Device Management (MDM) allows an unauthorized attacker to execute code |
| 🟠 high | CVE-2026-126181: A use of hard-coded credentials vulnerability in Fortinet FortiManager 8.0.0 through 8.… | — | A use of hard-coded credentials vulnerability in Fortinet FortiManager 8.0.0 through 8.0.1, FortiManager 7.6.0 through 7 |
| 🟠 high | CVE-2026-124005: XWEB EVO 4.3.0 through 5.8.8 contains a weak password generation vulnerability that all… | — | XWEB EVO 4.3.0 through 5.8.8 contains a weak password generation vulnerability that allows remote attackers to derive th |
| 🟠 high | CVE-2026-128047: OpenMage magento-lts before 20.18.2 and 21.0.0-beta pre-releases before 21.0.0-beta3 ge… | — | OpenMage magento-lts before 20.18.2 and 21.0.0-beta pre-releases before 21.0.0-beta3 generate customer email-confirmatio |
| 🟠 high | CVE-2026-116413: Dell PowerStore contains a use-of-broken-cryptography vulnerability. | — | Dell PowerStore contains a use-of-broken-cryptography vulnerability. A low-privileged attacker could exploit it to imper |
| 🟠 high | CVE-2026-63151: Omnispace Agora Project through 26.10.0 contains a predictable token generation vulnera… | — | Omnispace Agora Project through 26.10.0 contains a predictable token generation vulnerability that allows unauthenticate |

## Information Disclosure (18)

_Exposure of sensitive information through error messages, logs, or responses._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-120012: SAP Cloud SDK for AI (Node.js) could inadvertently include sensitive authentication cre… | — | SAP Cloud SDK for AI (Node.js) could inadvertently include sensitive authentication credentials in error messages genera |
| 🟠 high | CVE-2026-120006: Insertion of sensitive information into sent data in .NET Aspire allows an authorized a… | — | Insertion of sensitive information into sent data in .NET Aspire allows an authorized attacker to elevate privileges loc |
| 🟠 high | CVE-2026-120792: Insertion of sensitive information into log file in .NET Aspire allows an authorized at… | — | Insertion of sensitive information into log file in .NET Aspire allows an authorized attacker to disclose information lo |
| 🟠 high | CVE-2026-91870: Dell Ansible Storage for PowerFlex, versions prior to 3.2.0, contains an Improper Certi… | — | Dell Ansible Storage for PowerFlex, versions prior to 3.2.0, contains an Improper Certificate Validation vulnerability i |
| 🟠 high | CVE-2026-91871: Dell Ansible Storage for PowerStore, versions prior to 3.9.0, contains an Improper Cert… | — | Dell Ansible Storage for PowerStore, versions prior to 3.9.0, contains an Improper Certificate Validation vulnerability  |
| 🟠 high | CVE-2026-91879: Dell Terraform for ObjectScale and Powerstore, versions prior to 1.1.1 (ObjectScale) an… | — | Dell Terraform for ObjectScale and Powerstore, versions prior to 1.1.1 (ObjectScale) and versions 1.2.1 through 1.3.0 (P |
| 🟠 high | CVE-2026-91890: Dell Ansible Storage for Unity , versions prior to 1.2.13 contains an Improper Certific… | — | Dell Ansible Storage for Unity , versions prior to 1.2.13 contains an Improper Certificate Validation vulnerability in t |
| 🟠 high | CVE-2026-91873: Dell OpenManage Ansible Modules, versions 2.1.2 through 10.0.3, contains an Improper Ce… | — | Dell OpenManage Ansible Modules, versions 2.1.2 through 10.0.3, contains an Improper Certificate Validation vulnerabilit |
| 🟠 high | CVE-2026-91874: Dell OpenManage Ansible Modules, versions 5.0.0 through 10.0.3, contains an Improper Ce… | — | Dell OpenManage Ansible Modules, versions 5.0.0 through 10.0.3, contains an Improper Certificate Validation vulnerabilit |
| 🟠 high | CVE-2026-91875: Dell OpenManage Ansible Modules, versions 9.2.0 through 10.0.3, contains an Improper Ce… | — | Dell OpenManage Ansible Modules, versions 9.2.0 through 10.0.3, contains an Improper Certificate Validation vulnerabilit |
| 🟠 high | CVE-2026-91891: Dell Terraform Provider for PowerStore, versions prior to 1.3.1 , contains a  vulnerabi… | — | Dell Terraform Provider for PowerStore, versions prior to 1.3.1 , contains a  vulnerability that may cause sensitive aut |
| 🟠 high | CVE-2026-116417: Dell PowerScale InsightIQ, versions 6.3.0 through 6.4.0, contains a Weak Password Requi… | — | Dell PowerScale InsightIQ, versions 6.3.0 through 6.4.0, contains a Weak Password Requirements vulnerability. An unauthe |
| 🟠 high | CVE-2026-126271: NocoDB before 2026.09.0 contains an information disclosure vulnerability that allows au… | — | NocoDB before 2026.09.0 contains an information disclosure vulnerability that allows authenticated base Viewers to obtai |
| 🟠 high | CVE-2026-126308: The web dashboard in Coder 2.24.0 before 2.29.23, 2.30.0 before 2.34.14, 2.35.0 before … | — | The web dashboard in Coder 2.24.0 before 2.29.23, 2.30.0 before 2.34.14, 2.35.0 before 2.36.9, 2.37.0 before 2.37.6, and |
| 🟠 high | CVE-2026-127082: Huginn before 2026.11.09 contains an information exposure vulnerability in JqAgent that… | — | Huginn before 2026.11.09 contains an information exposure vulnerability in JqAgent that allows authenticated users to re |
| 🟠 high | CVE-2026-126091: Dental practice sites hosted with iDentalSoft send a JSON response to any user who load… | — | Dental practice sites hosted with iDentalSoft send a JSON response to any user who loads certain pages containing sensit |
| 🟠 high | CVE-2026-109158: IBM App Connect Operator and IBM App Connect Enterprise Certified Containers Operands m… | — | IBM App Connect Operator and IBM App Connect Enterprise Certified Containers Operands may allow the AI Agent to log sens |
| 🟠 high | CVE-2026-125799: Insertion of Sensitive Information into Externally-Accessible File or Directory vulnera… | — | Insertion of Sensitive Information into Externally-Accessible File or Directory vulnerability in Looks Awesome Flow-Flow |

## Denial of Service (67)

_Vulnerabilities causing service disruption, resource exhaustion, or crashes._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-120367: Allocation of Resources Without Limits or Throttling vulnerability in Apache Axis2/Java. | — | Allocation of Resources Without Limits or Throttling vulnerability in Apache Axis2/Java. The JSON message builders, incl |
| 🟠 high | CVE-2026-120854: Allocation of Resources Without Limits or Throttling vulnerability in iubenda iubenda i… | — | Allocation of Resources Without Limits or Throttling vulnerability in iubenda iubenda iubenda-cookie-law-solution allows |
| 🟠 high | CVE-2026-115339: Insufficient resource limits in Progress Software WS_FTP Server releases prior to 2025.… | — | Insufficient resource limits in Progress Software WS_FTP Server releases prior to 2025.0.5 on Windows could allow an una |
| 🟠 high | CVE-2026-112314: clnttcp_call() in lib/rpc/clnt_tcp.c in MIT Kerberos 5 (aka krb5) does not free the RPC… | — | clnttcp_call() in lib/rpc/clnt_tcp.c in MIT Kerberos 5 (aka krb5) does not free the RPC reply verifier between retries,  |
| 🟠 high | CVE-2026-112320: The GSS-RPC transport layer in MIT Kerberos 5 (aka krb5) 1.4 and later does not release… | — | The GSS-RPC transport layer in MIT Kerberos 5 (aka krb5) 1.4 and later does not release the previous authentication cont |
| 🟠 high | CVE-2026-112321: The AUTH_GSSAPI handler in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) does … | — | The AUTH_GSSAPI handler in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) does not free decoded arguments on cer |
| 🟠 high | CVE-2026-112322: clean_client() in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) restarts its s… | — | clean_client() in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) restarts its scan from the head of the client l |
| 🟠 high | CVE-2026-112323: The AUTH_GSSAPI handler in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) 1.5.2… | — | The AUTH_GSSAPI handler in lib/rpc/svc_auth_gssapi.c in MIT Kerberos 5 (aka krb5) 1.5.2 and later allows remote attacker |
| 🟠 high | CVE-2026-119079: decode_sequence_of() in lib/krb5/asn.1/asn1_encode.c in MIT Kerberos 5 (aka krb5) 1.11 … | — | decode_sequence_of() in lib/krb5/asn.1/asn1_encode.c in MIT Kerberos 5 (aka krb5) 1.11 and later grows the decoded eleme |
| 🟠 high | CVE-2026-125111: Rack is a modular Ruby web server interface. | — | Rack is a modular Ruby web server interface. Prior to 2.2.25, 3.1.23, and 3.2.8, Rack::Multipart::Parser can retain pars |
| 🟠 high | CVE-2026-109794: SAP NetWeaver Application Server ABAP, ABAP Platform, and SAP Web Dispatcher do not suf… | — | SAP NetWeaver Application Server ABAP, ABAP Platform, and SAP Web Dispatcher do not sufficiently handle resource consump |
| 🟠 high | CVE-2026-60040: An unauthenticated remote attacker can perform a DoS in the backends backup creation fu… | — | An unauthenticated remote attacker can perform a DoS in the backends backup creation function. This can result in a tota |
| 🟠 high | CVE-2026-105561: Uncontrolled resource consumption in Windows Secure Socket Tunneling Protocol (SSTP) al… | — | Uncontrolled resource consumption in Windows Secure Socket Tunneling Protocol (SSTP) allows an unauthorized attacker to  |
| 🟠 high | CVE-2026-114147: Missing release of memory after effective lifetime in ASP.NET Core allows an unauthoriz… | — | Missing release of memory after effective lifetime in ASP.NET Core allows an unauthorized attacker to deny service over  |
| 🟠 high | CVE-2026-114149: Uncontrolled resource consumption in ASP.NET Core allows an unauthorized attacker to de… | — | Uncontrolled resource consumption in ASP.NET Core allows an unauthorized attacker to deny service over a network. |
| 🟠 high | CVE-2026-114154: Uncontrolled resource consumption in ASP.NET Core allows an unauthorized attacker to de… | — | Uncontrolled resource consumption in ASP.NET Core allows an unauthorized attacker to deny service over a network. |
| 🟠 high | CVE-2026-118748: Allocation of resources without limits or throttling in ASP.NET Core allows an unauthor… | — | Allocation of resources without limits or throttling in ASP.NET Core allows an unauthorized attacker to deny service ove |
| 🟠 high | CVE-2026-118750: Allocation of resources without limits or throttling in ASP.NET Core allows an unauthor… | — | Allocation of resources without limits or throttling in ASP.NET Core allows an unauthorized attacker to deny service ove |
| 🟠 high | CVE-2026-125327: pgEdge RAG Server is an API server for retrieval-augmented generation over PostgreSQL c… | — | pgEdge RAG Server is an API server for retrieval-augmented generation over PostgreSQL content using pgvector. Prior to 2 |
| 🟠 high | CVE-2026-70240: Missing release of memory after effective lifetime in Windows Kerberos allows an unauth… | — | Missing release of memory after effective lifetime in Windows Kerberos allows an unauthorized attacker to deny service o |
| 🟠 high | CVE-2026-96176: Missing release of memory after effective lifetime in Windows DNS allows an unauthorize… | — | Missing release of memory after effective lifetime in Windows DNS allows an unauthorized attacker to deny service over a |
| 🟠 high | CVE-2026-121370: On affected platforms running Arista EOS with Precision Time Protocol (PTP) configured,… | — | On affected platforms running Arista EOS with Precision Time Protocol (PTP) configured, an unauthenticated attacker with |
| 🟠 high | CVE-2026-120828: A replica-set database server node does not limit or reclaim internal wait records crea… | — | A replica-set database server node does not limit or reclaim internal wait records created while handling a client-suppl |
| 🟠 high | CVE-2026-126613: Allocation of resources without limits in the JSON reader of Progressive Robot hMailSer… | — | Allocation of resources without limits in the JSON reader of Progressive Robot hMailServer 6.3.2 through 6.3.7 allows a  |
| 🟠 high | CVE-2026-126659: BlueprintUE Self-Hosted Edition 1.0.0 before 4.3.5 contains a resource exhaustion vulne… | — | BlueprintUE Self-Hosted Edition 1.0.0 before 4.3.5 contains a resource exhaustion vulnerability that allows unauthentica |
| 🟠 high | CVE-2026-106137: In affected versions of Progress® Telerik® UI for ASP.NET MVC `2012.2.710` through `202… | — | In affected versions of Progress® Telerik® UI for ASP.NET MVC `2012.2.710` through `2026.3.811`, ClassFactory updates a  |
| 🟠 high | CVE-2026-106156: In Progress® Telerik® UI for ASP.NET Core versions `2015.1.318` through `2026.3.811`, r… | — | In Progress® Telerik® UI for ASP.NET Core versions `2015.1.318` through `2026.3.811`, repeated server-side aggregation r |
| 🟠 high | CVE-2026-123865: An unauthenticated HTTP/2 client can permanently leak Node.js server memory and file de… | — | An unauthenticated HTTP/2 client can permanently leak Node.js server memory and file descriptors. If a peer triggers a p |
| 🟠 high | CVE-2026-58505: geojson-vt is a JavaScript library for slicing GeoJSON data into vector tiles on the fl… | — | geojson-vt is a JavaScript library for slicing GeoJSON data into vector tiles on the fly, primarily designed to enable r |
| 🟠 high | CVE-2026-91150: A flaw was found in Cockpit. | — | A flaw was found in Cockpit. This vulnerability allows a remote attacker, without prior authentication, to send speciall |
| 🟠 high | CVE-2026-126161: A uncontrolled resource consumption vulnerability in Fortinet FortiMail 8.0.0 through 8… | — | A uncontrolled resource consumption vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6 |
| 🟠 high | CVE-2026-126165: A memory allocation with excessive size value vulnerability in Fortinet FortiMail 8.0.0… | — | A memory allocation with excessive size value vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 t |
| 🟠 high | CVE-2026-126230: A use of externally-controlled format string vulnerability in Fortinet FortiAnalyzer 8.… | — | A use of externally-controlled format string vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer  |
| 🟠 high | CVE-2026-126237: A loop with unreachable exit condition ('infinite loop') vulnerability in Fortinet Fort… | — | A loop with unreachable exit condition ('infinite loop') vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0. |
| 🟠 high | CVE-2026-126244: A allocation of resources without limits or throttling vulnerability in Fortinet FortiA… | — | A allocation of resources without limits or throttling vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, |
| 🟠 high | CVE-2026-68538: fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input … | — | fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input supplied by many tenants. From ve |
| 🟠 high | CVE-2026-68539: fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input … | — | fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input supplied by many tenants. From ve |
| 🟠 high | CVE-2026-68540: fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input … | — | fulgur converts untrusted HTML/CSS into PDF, commonly on a server that processes input supplied by many tenants. From ve |
| 🟠 high | CVE-2026-127056: PapaParse before 5.7.1 contains an inefficient algorithmic complexity vulnerability tha… | — | PapaParse before 5.7.1 contains an inefficient algorithmic complexity vulnerability that allows remote unauthenticated a |
| 🟠 high | CVE-2026-106154: In Progress® Telerik® UI for ASP.NET Core versions `2015.1.318` through `2026.3.1015`, … | — | In Progress® Telerik® UI for ASP.NET Core versions `2015.1.318` through `2026.3.1015`, the server-side FilterParser proc |
| 🟠 high | CVE-2026-47217: BACnet Stack is a BACnet open source protocol stack C library for embedded systems. | — | BACnet Stack is a BACnet open source protocol stack C library for embedded systems. Prior to versions 1.4.4 and 1.5.1, a |
| 🟠 high | CVE-2026-126366: MessagePack for Ruby is an implementation of the MessagePack binary serialization format. | — | MessagePack for Ruby is an implementation of the MessagePack binary serialization format. Prior to 1.8.7, the Java-platf |
| 🟠 high | CVE-2026-126277: NocoDB before 2026.08.1 contains an uncontrolled resource consumption vulnerability tha… | — | NocoDB before 2026.08.1 contains an uncontrolled resource consumption vulnerability that allows unauthenticated attacker |
| 🟠 high | CVE-2026-126297: NLTK before 3.10.4 contains a quadratic-time denial of service vulnerability in ConllCo… | — | NLTK before 3.10.4 contains a quadratic-time denial of service vulnerability in ConllCorpusReader._get_srl_instances tha |
| 🟠 high | CVE-2026-126298: NLTK before 3.10.4 contains a denial of service vulnerability in Tree.chomsky_normal_fo… | — | NLTK before 3.10.4 contains a denial of service vulnerability in Tree.chomsky_normal_form that allows remote attackers t |
| 🟠 high | CVE-2026-126299: NLTK before 3.10.4 contains a denial of service vulnerability in the CCG lexicon parser… | — | NLTK before 3.10.4 contains a denial of service vulnerability in the CCG lexicon parser fromstring that allows remote at |
| 🟠 high | CVE-2026-126303: NLTK before 3.10.4 contains an uncontrolled resource consumption vulnerability in Stepp… | — | NLTK before 3.10.4 contains an uncontrolled resource consumption vulnerability in SteppingRecursiveDescentParser.parse() |
| 🟠 high | CVE-2026-126397: vLLM from 0.10.1 before 0.31.0 forwards a request-controlled mm_processor_kwargs.max_pa… | — | vLLM from 0.10.1 before 0.31.0 forwards a request-controlled mm_processor_kwargs.max_patches value to the Hugging Face p |
| 🟠 high | CVE-2026-126401: Fleet before 4.86.2 contains a denial of service vulnerability that allows unauthentica… | — | Fleet before 4.86.2 contains a denial of service vulnerability that allows unauthenticated attackers to exhaust server m |
| 🟠 high | CVE-2026-126938: Zipline before 4.6.4 contains a resource allocation vulnerability that allows authentic… | — | Zipline before 4.6.4 contains a resource allocation vulnerability that allows authenticated users to bypass chunked-uplo |
| | _+17 more…_ | | |

## Network Infrastructure & IoT Device Vulnerabilities (29)

_Vulnerabilities in routers, firewalls, and IoT devices on the network edge._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-125086: A vulnerability has been found in D-Link M60 1.12.B01. | — | A vulnerability has been found in D-Link M60 1.12.B01. Impacted is the function system of the file /etc/emDaemon/mosquit |
| 🔴 critical | CVE-2026-121529: A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7,… | — | A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through |
| 🔴 critical | CVE-2026-126261: A improper authorization vulnerability in Fortinet FortiManager 8.0.0, FortiManager 7.6… | — | A improper authorization vulnerability in Fortinet FortiManager 8.0.0, FortiManager 7.6.0 through 7.6.7, FortiManager 7. |
| 🔴 critical | CVE-2026-126150: A weak password recovery mechanism for forgotten password vulnerability in Fortinet For… | — | A weak password recovery mechanism for forgotten password vulnerability in Fortinet FortiMail 8.0.0, FortiMail 7.6.0 thr |
| 🔴 critical | CVE-2026-126170: A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0… | — | A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6 |
| 🔴 critical | CVE-2026-126254: A numeric truncation error vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, Forti… | — | A numeric truncation error vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7 |
| 🔴 critical | CVE-2026-126257: A use of hard-coded password vulnerability in Fortinet FortiAuthenticator 8.0.0 through… | — | A use of hard-coded password vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6.0  |
| 🔴 critical | CVE-2026-129258: A vulnerability was identified in Tenda AC18 15.03.05.05_multi/15.03.05.19 Build 6318. | — | A vulnerability was identified in Tenda AC18 15.03.05.05_multi/15.03.05.19 Build 6318. Affected by this vulnerability is |
| 🔴 critical | CVE-2026-129353: D-Link DIR-600L authentication.cgi authenticationcgi_main stack-based overflow | — | [VulnTracker digest] D-Link DIR-600L — D-Link DIR-600L authentication.cgi authenticationcgi_main stack-based overflow |
| 🔴 critical | CVE-2026-129444: A vulnerability was identified in D-Link DSL-6740C 20131126. | — | A vulnerability was identified in D-Link DSL-6740C 20131126. This affects an unknown function of the file /etc/templates |
| 🟠 high | CVE-2026-90586: The Xtensa MMU userspace port never initialized the per-thread page-table pointer threa… | — | The Xtensa MMU userspace port never initialized the per-thread page-table pointer thread->arch.ptables during thread set |
| 🟠 high | CVE-2026-102166: Arista C-260 and C-250 access points ship with fleet-wide static cryptographic keys use… | — | Arista C-260 and C-250 access points ship with fleet-wide static cryptographic keys used for firmware image verification |
| 🟠 high | CVE-2026-121528: A improper certificate validation vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4… | — | A improper certificate validation vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4.0 through 7.4.9, Fo |
| 🟠 high | CVE-2026-126162: A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiMail 8.0.0 t… | — | A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 thr |
| 🟠 high | CVE-2026-126163: A use of externally-controlled format string vulnerability in Fortinet FortiMail 8.0.0 … | — | A use of externally-controlled format string vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1 may allow a remote  |
| 🟠 high | CVE-2026-126171: A use of externally-controlled format string vulnerability in Fortinet FortiAnalyzer 8.… | — | A use of externally-controlled format string vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer  |
| 🟠 high | CVE-2026-126176: A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiAnalyzer 8.0… | — | A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiAnalyzer 8.0.0, FortiAnalyzer 7.6.0 through 7 |
| 🟠 high | CVE-2026-126177: A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiAnalyzer 8.0… | — | A xml injection (aka blind xpath injection) vulnerability in Fortinet FortiAnalyzer 8.0.0, FortiAnalyzer 7.6.0 through 7 |
| 🟠 high | CVE-2026-126220: A improper neutralization of special elements in output used by a downstream component … | — | A improper neutralization of special elements in output used by a downstream component ('injection') vulnerability in Fo |
| 🟠 high | CVE-2026-126221: A improper neutralization of special elements in output used by a downstream component … | — | A improper neutralization of special elements in output used by a downstream component ('injection') vulnerability in Fo |
| 🟠 high | CVE-2026-126227: A unintended proxy or intermediary ('confused deputy') vulnerability in Fortinet FortiA… | — | A unintended proxy or intermediary ('confused deputy') vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, Fort |
| 🟠 high | CVE-2026-126232: A improper certificate validation vulnerability in Fortinet FortiAnalyzer 8.0.0 through… | — | A improper certificate validation vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer 7.6.0 throu |
| 🟠 high | CVE-2026-126233: A unrestricted upload of file with dangerous type vulnerability in Fortinet FortiAnalyz… | — | A unrestricted upload of file with dangerous type vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnal |
| 🟠 high | CVE-2026-126240: A improper neutralization of special elements used in an ldap query ('ldap injection') … | — | A improper neutralization of special elements used in an ldap query ('ldap injection') vulnerability in Fortinet FortiAu |
| 🟠 high | CVE-2026-126247: A use of externally-controlled format string vulnerability in Fortinet FortiAuthenticat… | — | A use of externally-controlled format string vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuth |
| 🟠 high | CVE-2026-126248: A insufficiently protected credentials vulnerability in Fortinet FortiAuthenticator 8.0… | — | A insufficiently protected credentials vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthentica |
| 🟠 high | CVE-2026-128909: Improper verification of cryptographic signature (CWE-347) in the firmware update handl… | — | Improper verification of cryptographic signature (CWE-347) in the firmware update handler of the management service (uav |
| 🟠 high | CVE-2026-129445: A security flaw has been discovered in D-Link DIR-850L FW1.20WWb03. | — | A security flaw has been discovered in D-Link DIR-850L FW1.20WWb03. This impacts an unknown function of the file /usr/sb |
| ⚪ unknown | CVE-2026-20320: Cisco BroadWorks — Cisco BroadWorks Improper Restriction of XML External Entity Reference Vulnerability | — | Cisco BroadWorks contains an improper restriction of XML external entity reference vulnerability that could allow an una |

## Critical-Severity Vulnerabilities (25)

_Critical-severity issues that did not fit a more specific category — review urgently._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🔴 critical | CVE-2026-125384: INDOTALENT WHMS before 10.20261109 contains a default credentials vulnerability that al… | — | INDOTALENT WHMS before 10.20261109 contains a default credentials vulnerability that allows unauthenticated attackers to |
| 🔴 critical | CVE-2026-109798: SAP BusinessObjects Business Intelligence Platform (Web Intelligence) does not properly… | — | SAP BusinessObjects Business Intelligence Platform (Web Intelligence) does not properly restrict external entity resolut |
| 🔴 critical | CVE-2026-120017: SAP NetWeaver AS ABAP and ABAP Platform does not perform sufficient verification of inc… | — | SAP NetWeaver AS ABAP and ABAP Platform does not perform sufficient verification of incoming authentication assertions u |
| 🔴 critical | CVE-2026-76964: SAP NetWeaver Application Server ABAP does not sufficiently validate certain network in… | `T1190`, `T1203` | SAP NetWeaver Application Server ABAP does not sufficiently validate certain network input processed by an internal comp |
| 🔴 critical | CVE-2026-76965: SAP NetWeaver Application Server ABAP and ABAP Platform does not perform necessary auth… | — | SAP NetWeaver Application Server ABAP and ABAP Platform does not perform necessary authorization checks for certain inte |
| 🔴 critical | CVE-2026-115646: Partial String Comparison Vulnerability in HiRDB. | — | Partial String Comparison Vulnerability in HiRDB.


This issue affects HiRDB Server Version 10: from 10-00 before 10-12- |
| 🔴 critical | CVE-2026-13312: A vulnerability that could allow an attacker to compromise a system. | — | A vulnerability that could allow an attacker to compromise a system. |
| 🔴 critical | CVE-2026-124853: Sandbox escape due to incorrect boundary conditions in the Graphics: Text component. | — | Sandbox escape due to incorrect boundary conditions in the Graphics: Text component. This vulnerability was fixed in Fir |
| 🔴 critical | CVE-2026-108186: Improper Input Validation in Zoom Workplace for Windows may allow an unauthenticated us… | — | Improper Input Validation in Zoom Workplace for Windows may allow an unauthenticated user to conduct an escalation of pr |
| 🔴 critical | CVE-2026-88234: Release of invalid pointer or reference in Windows iSCSI allows an unauthorized attacke… | — | Release of invalid pointer or reference in Windows iSCSI allows an unauthorized attacker to execute code over a network. |
| 🔴 critical | CVE-2026-121367: On affected Arista EOS platforms with Routing Information Protocol version 2 (RIPv2) co… | — | On affected Arista EOS platforms with Routing Information Protocol version 2 (RIPv2) configured, under certain condition |
| 🔴 critical | CVE-2026-125298: AsiaInfo Business Support System (BSS) 9.2.0 through 9.2.40 does not correctly verify c… | — | AsiaInfo Business Support System (BSS) 9.2.0 through 9.2.40 does not correctly verify cryptographic signatures for JSON  |
| 🔴 critical | CVE-2026-124600: Unencrypted HTTP Traffic Exposing Sensitive User Credentials in GV-Face Android Applica… | — | [VulnTracker digest] GeoVision Inc. GV-Face — Unencrypted HTTP Traffic Exposing Sensitive User Credentials in GV-Face An |
| 🔴 critical | CVE-2026-121497: The AskAny  WordPress plugin before 2.2.0 does not validate the extension or content of… | `T1190` | The AskAny  WordPress plugin before 2.2.0 does not validate the extension or content of files attached to chat messages, |
| 🔴 critical | CVE-2026-123710: A flaw was found in Red Hat Quay. | — | A flaw was found in Red Hat Quay. An unauthenticated client can obtain an anonymous registry token with an audience it c |
| 🔴 critical | CVE-2026-126812: blueprintUE Self-Hosted Edition before 4.3.7 contains an insecure default configuration… | — | blueprintUE Self-Hosted Edition before 4.3.7 contains an insecure default configuration in its Docker Compose examples t |
| 🔴 critical | CVE-2026-107360: A flaw was found in rubygem-safemode. | — | A flaw was found in rubygem-safemode. Compound assignment expressions in sandboxed code are evaluated without mediating  |
| 🔴 critical | CVE-2026-124004: XWEB EVO before 5.6.2 contains a hardcoded backdoor password vulnerability that allows … | — | XWEB EVO before 5.6.2 contains a hardcoded backdoor password vulnerability that allows unauthenticated remote attackers  |
| 🔴 critical | CVE-2026-127277: A security flaw has been discovered in Linksys EA8100 1.0.3.216940. | — | A security flaw has been discovered in Linksys EA8100 1.0.3.216940. The affected element is an unknown function of the f |
| 🔴 critical | CVE-2026-118064: The Advance Guest Post WordPress plugin through 1.9 does not properly restrict or valid… | — | The Advance Guest Post WordPress plugin through 1.9 does not properly restrict or validate file uploads, authorizing an  |
| 🔴 critical | CVE-2026-124833: The Ahime Image Printer WordPress plugin through 1.0.0 does not validate the name, exte… | — | The Ahime Image Printer WordPress plugin through 1.0.0 does not validate the name, extension or type of uploaded files b |
| 🔴 critical | CVE-2026-126315: Frappe HRMS 16.14.0 before 16.20.1 sends product usage events on certain HR transaction… | — | Frappe HRMS 16.14.0 before 16.20.1 sends product usage events on certain HR transactions without checking the site's tel |
| 🔴 critical | CVE-2026-126380: Vvveb before 1.0.9.0 contains a denylist bypass in system/traits/media.php where '.phar… | — | Vvveb before 1.0.9.0 contains a denylist bypass in system/traits/media.php where '.phar' is misconfigured with a leading |
| 🔴 critical | CVE-2026-128027: FrankenPHP Docker images before 1.1.11 were rebuilt only when new base image tags were … | — | FrankenPHP Docker images before 1.1.11 were rebuilt only when new base image tags were created, so security fixes that A |
| 🔴 critical | CVE-2026-125851: Unrestricted Upload of File with Dangerous Type vulnerability in themagnifico52 Hotel B… | — | Unrestricted Upload of File with Dangerous Type vulnerability in themagnifico52 Hotel Booking Lite hotel-booking-lite al |

## High-Severity Vulnerabilities (306)

_High-severity vulnerabilities across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | CVE-2026-124576: A security flaw has been discovered in BeikeShop up to 2.0.0.31. | — | A security flaw has been discovered in BeikeShop up to 2.0.0.31. Impacted is the function OrderRepo::getOrderByNumber of |
| 🟠 high | CVE-2026-124579: A vulnerability was determined in aaPanel BillionMail up to 4.9. | — | A vulnerability was determined in aaPanel BillionMail up to 4.9. Affected by this issue is some unknown functionality of |
| 🟠 high | CVE-2026-123465: Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerabilit… | — | Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerability in myCred myCred mycred allows  |
| 🟠 high | CVE-2026-106466: The JWT Auth WordPress plugin through 3.0.2 does not invalidate previously issued refre… | — | The JWT Auth WordPress plugin through 3.0.2 does not invalidate previously issued refresh tokens when a user changes or  |
| 🟠 high | CVE-2026-124590: A security vulnerability has been detected in zhangbw409 library_manager_system f6c9d9c… | — | A security vulnerability has been detected in zhangbw409 library_manager_system f6c9d9c96bf5d2a32ef741daeaa29d80e6db166b |
| 🟠 high | CVE-2026-124621: A vulnerability was determined in kongxin-github Java_Library_Management_System up to 7… | — | A vulnerability was determined in kongxin-github Java_Library_Management_System up to 70a6eb6b96fe64575d8051f1a59055bfc5 |
| 🟠 high | CVE-2026-115338: Insufficient protection of communications in Progress WS_FTP Server versions prior to 2… | — | Insufficient protection of communications in Progress WS_FTP Server versions prior to 2025.0.5 could allow a network att |
| 🟠 high | CVE-2026-115340: Progress Software WS_FTP Server versions prior to 2025.0.5 on Windows may write sensiti… | — | Progress Software WS_FTP Server versions prior to 2025.0.5 on Windows may write sensitive user credential and session da |
| 🟠 high | CVE-2026-123799: SuperTokens Core is an open source authentication server. | — | SuperTokens Core is an open source authentication server. From 11.0.0 until 11.0.9, 11.1.4, 11.2.4, 11.3.8, 11.4.8, 12.0 |
| 🟠 high | CVE-2026-12977: A flaw was found in the deployment-operation family of WildFly Core. | — | A flaw was found in the deployment-operation family of WildFly Core. Certain handlers, such as upload-deployment-url, la |
| 🟠 high | CVE-2026-114032: The OpenSSL library bundled with the Illumio VEN for Windows is affected by an uncontro… | `T1190` | The OpenSSL library bundled with the Illumio VEN for Windows is affected by an uncontrolled search path vulnerability. A |
| 🟠 high | CVE-2026-123813: pyLoad is a free and open-source download manager written in Python. | — | pyLoad is a free and open-source download manager written in Python. Prior to 0.5.0b3.dev102, pyLoad does not invalidate |
| 🟠 high | CVE-2026-124035: Unsafe reflection in the error mitigation schema validation in Amazon Braket Schemas be… | `T1190` | Unsafe reflection in the error mitigation schema validation in Amazon Braket Schemas before 1.32.2 might allow a remote  |
| 🟠 high | CVE-2026-125074: A flaw has been found in SourceCodester Smart Attendance System with QR Code Scanner 1.0. | — | A flaw has been found in SourceCodester Smart Attendance System with QR Code Scanner 1.0. This affects an unknown functi |
| 🟠 high | CVE-2026-125117: Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environm… | — | Mongoose is a MongoDB object modeling tool designed to work in an asynchronous environment. Prior to 6.13.12, 7.8.13, 8. |
| 🟠 high | CVE-2026-125406: Ettercap through 0.8.4.1 contains a stack buffer underwrite vulnerability in the telnet… | — | Ettercap through 0.8.4.1 contains a stack buffer underwrite vulnerability in the telnet dissector in src/dissectors/ec_t |
| 🟠 high | CVE-2026-125358: Universal-modder before commit e88f6876745427321eb755ebc98276063a962d8a contains a miss… | — | Universal-modder before commit e88f6876745427321eb755ebc98276063a962d8a contains a missing WebSocket Origin validation v |
| 🟠 high | CVE-2026-123817: AIOHTTP WebSocket frame reassembly permits excessive memory consumption from tiny reads | — | [cvefeed.io] AIOHTTP WebSocket frame reassembly permits excessive memory consumption from tiny reads |
| 🟠 high | CVE-2026-123815: pyLoad: Tar extraction creates device nodes and FIFOs (member types not filtered; tarfi… | — | [cvefeed.io] pyLoad: Tar extraction creates device nodes and FIFOs (member types not filtered; tarfile extractall withou |
| 🟠 high | @vanzky (npm) | — | Newly disclosed malicious package in the OpenSSF malicious-packages directory. First disclosed 2026-11-09. Review versio |
| 🟠 high | CVE-2026-125368: OmniAgent through commit 12b98c5 contains an approval bypass vulnerability in Reflexion… | — | OmniAgent through commit 12b98c5 contains an approval bypass vulnerability in ReflexionAgent._is_safe_bash_command that  |
| 🟠 high | CVE-2026-107241: The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero To… | — | The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero Touch Provisioning (ZTP) of the VOS |
| 🟠 high | CVE-2026-107243: The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero To… | — | The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero Touch Provisioning (ZTP) of the VOS |
| 🟠 high | CVE-2026-107244: The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero To… | — | The Node.js web service on VOS (previously Versa FlexVNF) is used for URL-based Zero Touch Provisioning (ZTP) of the VOS |
| 🟠 high | CVE-2026-109797: In SAP/astonish, an authenticated user could potentially identify and operate on anothe… | — | In SAP/astonish, an authenticated user could potentially identify and operate on another team�s sandbox containers becau |
| 🟠 high | CVE-2026-109799: The SAP Cloud SDK for Python contains an improper cryptographic signature verification … | — | The SAP Cloud SDK for Python contains an improper cryptographic signature verification vulnerability (CWE-347) in IASCon |
| 🟠 high | CVE-2026-109804: SAP Message Server does not properly handle certain malformed requests, which could be … | — | SAP Message Server does not properly handle certain malformed requests, which could be leveraged by an unauthenticated a |
| 🟠 high | CVE-2026-120015: SAP Host Agent does not sufficiently validate certain inputs. | — | SAP Host Agent does not sufficiently validate certain inputs. Under certain condition, an attacker with low privileges c |
| 🟠 high | CVE-2026-112125: Incorrect Permission Assignment for Critical Resource Vulnerability in HA Monitor. | — | Incorrect Permission Assignment for Critical Resource Vulnerability in HA Monitor.

This issue affects HA Monitor: from  |
| 🟠 high | CVE-2026-86578: Link Following Vulnerability in Hitachi Dynamic Link Manager for Windows. | — | Link Following Vulnerability in Hitachi Dynamic Link Manager for Windows.

This issue affects Hitachi Dynamic Link Manag |
| 🟠 high | CVE-2026-86579: Binary Planting Vulnerability in Hitachi Dynamic Link Manager for Windows. | — | Binary Planting Vulnerability in Hitachi Dynamic Link Manager for Windows.

This issue affects Hitachi Dynamic Link Mana |
| 🟠 high | CVE-2026-91761: UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager fo… | — | UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager for Linux.

This issue affects Hita |
| 🟠 high | CVE-2026-91762: UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager fo… | — | UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager for Linux.


This issue affects Hit |
| 🟠 high | CVE-2026-91763: UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager fo… | — | UNIX Symbolic Link (Symlink) Following Vulnerability in Hitachi Dynamic Link Manager for Linux.
This issue affects Hitac |
| 🟠 high | CVE-2026-91764: Improper Link Resolution Before File Access Vulnerability in Hitachi Dynamic Link Manag… | — | Improper Link Resolution Before File Access Vulnerability in Hitachi Dynamic Link Manager for Linux.


This issue affect |
| 🟠 high | CVE-2026-92864: Insecure Temporary File Vulnerability in Hitachi Dynamic Link Manager for AIX (for mark… | — | Insecure Temporary File Vulnerability in Hitachi Dynamic Link Manager for AIX (for markets outside Japan) and Hitachi Dy |
| 🟠 high | CVE-2026-12963: A vulnerability that could allow a viewer account to gain unauthorized access to networ… | — | A vulnerability that could allow a viewer account to gain unauthorized access to network attached storage devices on the |
| 🟠 high | CVE-2026-60044: The backups created by the application use a weak static password allowing an unauthent… | — | The backups created by the application use a weak static password allowing an unauthenticated remote attacker to access  |
| 🟠 high | CVE-2026-60046: An unauthenticated remote attacker can perform password resets for any user with known … | — | An unauthenticated remote attacker can perform password resets for any user with known username and email without rate l |
| 🟠 high | CVE-2026-112136: A vulnerability has been identified in Mendix Studio Pro 11 (All versions >= V11.15.0 <… | — | A vulnerability has been identified in Mendix Studio Pro 11 (All versions >= V11.15.0 < V11.16.0), Mendix Studio Pro 11. |
| 🟠 high | CVE-2026-58114: A vulnerability has been identified in SIMATIC BATCH V9.1 (All versions), SIMATIC Infor… | — | A vulnerability has been identified in SIMATIC BATCH V9.1 (All versions), SIMATIC Information Server 2020 (All versions) |
| 🟠 high | CVE-2026-59082: A vulnerability has been identified in SIMATIC WinCC V7.5 (All versions), SIMATIC WinCC… | `T1190` | A vulnerability has been identified in SIMATIC WinCC V7.5 (All versions), SIMATIC WinCC V8.0 (All versions), SIMATIC Win |
| 🟠 high | CVE-2026-121267: Incorrect default permissions vulnerability in TÜBİTAK BİLGEM Software Technologies Res… | — | Incorrect default permissions vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute eta-remote allows |
| 🟠 high | CVE-2026-120399: A flaw was found in flightctl. | — | A flaw was found in flightctl. A TLS handshake is performed synchronously in the HTTP server’s connection-context callba |
| 🟠 high | CVE-2026-82509: V programming language standard library net.http through version 0.5.2 prior to commit … | — | V programming language standard library net.http through version 0.5.2 prior to commit 4077484 contains a TLS certificat |
| 🟠 high | CVE-2026-108187: Origin Validation Error in Zoom Workplace for Windows may allow an unauthenticated user… | — | Origin Validation Error in Zoom Workplace for Windows may allow an unauthenticated user to conduct an escalation of priv |
| 🟠 high | CVE-2026-102236: Improper restriction of rendered ui layers or frames in Visual Studio Code allows an un… | — | Improper restriction of rendered ui layers or frames in Visual Studio Code allows an unauthorized attacker to bypass a s |
| 🟠 high | CVE-2026-105017: Concurrent execution using shared resource with improper synchronization ('race conditi… | — | Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Volume Shadow Cop |
| 🟠 high | CVE-2026-105494: Untrusted search path in Azure NFS mount helper (aznfs) allows an authorized attacker t… | — | Untrusted search path in Azure NFS mount helper (aznfs) allows an authorized attacker to elevate privileges locally. |
| 🟠 high | CVE-2026-105511: Concurrent execution using shared resource with improper synchronization ('race conditi… | — | Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Point-to-Point Pr |
| | _+256 more…_ | | |

## Medium-Severity Vulnerabilities (1)

_Medium-severity issues across miscellaneous products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟡 medium | CVE-2026-124194: Microsoft Office — Microsoft Office Outlook Missing User Interaction for Potentially Unsafe Action Vulnerability | — | Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform s |

## Other Vulnerabilities (4)

_Additional vulnerabilities observed across products and services._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| ⚪ unknown | CVE-2026-102895: GPUStack GPUStack — GPUStack Improper Authentication Vulnerability | — | GPUStack contains an improper authentication vulnerability which could allow unauthenticated administrative access, incl |
| ⚪ unknown | CVE-2026-123218: IBM Aspera Faspex — IBM Aspera Faspex Incorrect Authorization Vulnerability | — | IBM Aspera Faspex contains an incorrect authorization vulnerability that could allow an authenticated user to craft a sp |
| ⚪ unknown | CVE-2026-111793: Openwave Messaging Limited Webtop Media Transcoder — Openwave Messaging Limited Webtop Media Transcoder Incorrect Resource Transfer Between Spheres Vulnerability | — | Openwave Messaging Limited Webtop Media Transcoder contains an incorrect resource transfer between spheres vulnerability |
| ⚪ unknown | CVE-2026-114713: UnrealIRCd UnrealIRCd — UnrealIRCd Improper Neutralization of Delimiters Vulnerability | — | UnrealIRCd UnrealIRCd contains an improper neutralization of delimiters vulnerability that allows any user on a network  |

## Ransomware activity (ransomware.live + peers) (832)

_Victim claims rolled up from the 7 daily briefings covering this window. Most active groups: incransom (111), n0n (108), pixelleaks (78)._

| Severity | Finding | MITRE | Description |
|----------|---------|-------|-------------|
| 🟠 high | 159 Solutions, Inc. — claimed by n0n | — | specialty pharma data analytics · United States |
| 🟠 high | Air Communities — claimed by vortex | — | accounts payable/receivable, audited financials FY2006–FY2013, TRS restructuring, total ownership summaries, disposition |
| 🟠 high | Albion Online Data Project — claimed by vexy | — | A community-driven data platform that collects and distributes real-time market prices, gold prices, market orders and h |
| 🟠 high | Albion Online Data Project — claimed by vexyransomware | — | Albion Online Data Project listed by vexyransomware. |
| 🟠 high | Allegis Advisor Group — claimed by climax | — | Climax lists this organization on its leak site. Site date: 2026-10-21. Site status: Published. Listed sector: Financial |
| 🟠 high | althus.be — claimed by boobaproject | — | althus.be listed by boobaproject. |
| 🟠 high | Andersen Construction - 200+ GB — claimed by vortex | — | ════════════════════════════════════════════════════════════════
ANDERSEN CONSTRUCTION — CONSOLIDATED FINANCIALS
Sourc |
| 🟠 high | ARTHREX - 700+ GB — claimed by vortex | — | MORE TIERS WILL RELEASE |
| 🟠 high | asc-psd.com — claimed by boobaproject | — | asc-psd.com listed by boobaproject. |
| 🟠 high | assocgastro.com — claimed by boobaproject | — | assocgastro.com listed by boobaproject. |
| 🟠 high | atlasoceanvoyages.com — claimed by boobaproject | — | atlasoceanvoyages.com listed by boobaproject. |
| 🟠 high | AUDIT ENTITY: hnopvm.org — claimed by auditteam | — | AUDIT ID: 2AE3CE243E823521 / DISCOVERY DATE: 2026-10-31 |
| 🟠 high | AUDIT ENTITY: jltrust.com — claimed by auditteam | — | AUDIT ID: 1E2CF5D71F581238 / DISCOVERY DATE: 2026-10-31 |
| 🟠 high | AUDIT ENTITY: Pelican ICT — claimed by auditteam | — | AUDIT ID: 17BACA24A3932895 / DISCOVERY DATE: 2026-10-31 |
| 🟠 high | AUDIT ENTITY: roycegroup — claimed by auditteam | — | AUDIT ID: 57FD7689754A6F21 / DISCOVERY DATE: 2026-10-31 |
| 🟠 high | B... W... — claimed by leakeddata | — | To be announced... |
| 🟠 high | B... W... — claimed by silentransomgroup | — | Redacted entry - full company name pending disclosure (FULL DATA TIMER active). |
| 🟠 high | bassmedicalgroup.com — claimed by boobaproject | — | bassmedicalgroup.com listed by boobaproject. |
| 🟠 high | bigspringtx.gov — claimed by boobaproject | — | bigspringtx.gov listed by boobaproject. |
| 🟠 high | boardmanpark.com — claimed by boobaproject | — | boardmanpark.com listed by boobaproject. |
| 🟠 high | BOZZUTO — claimed by vortex | — | BOZZUTO listed by vortex. |
| 🟠 high | Calmont Wire & Cable — claimed by akira | — | Calmont Wire & Cable listed by akira. |
| 🟠 high | Cameroon government troops leaked — claimed by hyflock | — | The core conclusion has already completed an analysis of the entire database's data volume sorted by table. It can be co |
| 🟠 high | carrollins.com — claimed by everstake | — | Category: Insurance Agency \| Size: 370.73 Gb \| Status: Published |
| 🟠 high | Cascade Flooring Ame rica — claimed by akira | — | Cascade Flooring Ame rica listed by akira. |
| 🟠 high | chernyy-law.com — claimed by boobaproject | — | chernyy-law.com listed by boobaproject. |
| 🟠 high | citicpacific.com — claimed by krybit | — | citicpacific.com listed by krybit. |
| 🟠 high | cityofedgewater.org — claimed by boobaproject | — | cityofedgewater.org listed by boobaproject. |
| 🟠 high | commercetwp.com — claimed by boobaproject | — | commercetwp.com listed by boobaproject. |
| 🟠 high | Company #148 — claimed by n0n | — | Company #148 listed by n0n. |
| 🟠 high | Company #149 — claimed by n0n | — | Company #149 listed by n0n. |
| 🟠 high | Company #150 — claimed by n0n | — | Company #150 listed by n0n. |
| 🟠 high | Company #151 — claimed by n0n | — | Company #151 listed by n0n. |
| 🟠 high | Company #152 — claimed by n0n | — | Company #152 listed by n0n. |
| 🟠 high | Company #153 — claimed by n0n | — | Company #153 listed by n0n. |
| 🟠 high | Company #154 — claimed by n0n | — | Company #154 listed by n0n. |
| 🟠 high | Company #155 — claimed by n0n | — | Company #155 listed by n0n. |
| 🟠 high | Company #156 — claimed by n0n | — | Company #156 listed by n0n. |
| 🟠 high | Company #157 — claimed by n0n | — | Company #157 listed by n0n. |
| 🟠 high | Company #158 — claimed by n0n | — | Company #158 listed by n0n. |
| 🟠 high | Company #159 — claimed by n0n | — | medical supplies manufacture and distribution · United States |
| 🟠 high | Company #160 — claimed by n0n | — | financial planning · Canada |
| 🟠 high | Company #161 — claimed by n0n | — | industrial property management · Canada |
| 🟠 high | Company #162 — claimed by n0n | — | insurance and financial services · Canada |
| 🟠 high | Company #163 — claimed by n0n | — | online education · Saudi Arabia |
| 🟠 high | Company #164 — claimed by n0n | — | health and beauty retail · Hong Kong |
| 🟠 high | Company #165 — claimed by n0n | — | licensed pop culture retail · United States |
| 🟠 high | Company #166 — claimed by n0n | — | virtual addiction treatment and telehealth · United States |
| 🟠 high | Company #167 — claimed by n0n | — | office supply retail · United States |
| 🟠 high | Company #168 — claimed by n0n | — | email deliverability and sender reputation platform · United States |
| | _+782 more…_ | | |

---
Sources: CISA KEV, NVD, cvefeed.io, ransomware.live, ossf/malicious-packages, URLhaus, MalwareBazaar, ThreatFox
MITRE ATT&CK: T1059, T1059.007, T1068, T1078, T1190, T1203

---
*[PANOPTICON](https://pranithjain.qzz.io/threatintel/briefings) · [Full brief](https://pranithjain.qzz.io/threatintel/briefings/weekly-2026-W46)*