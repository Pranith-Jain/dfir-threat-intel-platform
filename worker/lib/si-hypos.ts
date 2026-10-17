/* eslint-disable @typescript-eslint/no-unused-vars */
/**
 * HYPOS — Hypothesis engine for threat hunting.
 *
 * Edge-native hypothesis generator replicated from
 * https://h3ad-sec.github.io/HYPOS/ — "Hunt smarter. Miss nothing."
 *
 * Given an observed anomaly (free-text description of an alert, a
 * noisy metric, a suspicious host, or a cluster of IOCs), HYPOS
 * returns:
 *   - ranked hypotheses (each: title, narrative, what-to-look-for,
 *     kill-chain phase, MITRE techniques, evidence signals, expected
 *     false-positive scenarios, sample KQL)
 *   - the SI skills (from our /public/data/si/skills/ corpus) that
 *     best match the anomaly, so the LLM client can pull them with
 *     `si_get_skill` and follow the analyst playbook
 *
 * The hypothesis catalogue is hand-curated from the platform's
 * common SOC scenarios. The retrieval layer scores free-text
 * observations against each hypothesis via simple token overlap +
 * keyword weighting, then surfaces the top N with a confidence %.
 *
 * Exposed as:
 *   - MCP tool `si_hypos_generate`  (Worker)
 *   - REST  `POST /api/v1/si/hypos`  (api)
 *
 * No external API calls — pure scorer + corpus. Edge-native.
 */

import { loadSiIndex, getSiSkill, type SiSkillIndexEntry } from './si-manifest';
import { errMessage } from './err';

export interface HypoObservation {
  /** Free-text description of the anomaly: alert name, observed behaviour, etc. */
  text: string;
  /** Optional IOC list to bias scoring toward network/host hypotheses. */
  iocs?: string[];
  /** Optional platform / environment to narrow the hypothesis space. */
  environment?: 'endpoint' | 'identity' | 'cloud' | 'network' | 'email' | 'saas' | 'unknown';
  /** Cap the number of returned hypotheses. Default: 5. Max: 10. */
  topN?: number;
  /** If true, also return matched SI skill slugs. Default: true. */
  includeSkills?: boolean;
}

export interface Hypothesis {
  id: string;
  title: string;
  narrative: string;
  // Union of the original Lockheed kill-chain phases + the MITRE ATT&CK
  // tactic slugs that hypothesis fixtures use for in-attack-stage placement
  // (e.g. 'initial-access', 'execution', 'credential-access'). The runtime
  // renders them straight through; the type just needs to allow both.
  killChainPhase:
    | 'reconnaissance'
    | 'weaponization'
    | 'delivery'
    | 'exploitation'
    | 'installation'
    | 'command-and-control'
    | 'actions-on-objectives'
    | 'initial-access'
    | 'execution'
    | 'persistence'
    | 'privilege-escalation'
    | 'defense-evasion'
    | 'credential-access'
    | 'discovery'
    | 'lateral-movement'
    | 'collection'
    | 'exfiltration'
    | 'impact'
    | 'supply-chain-compromise';
  mitre: string[]; // ATT&CK technique IDs (Txxxx[.yyy])
  signals: string[];
  whatToLookFor: string[];
  falsePositives: string[];
  sampleKql: string;
  score: number; // 0..100, confidence the hypothesis fits the observation
  rationale: string;
}

export interface HyposResult {
  observation: { text: string; iocs: string[]; environment: HypoObservation['environment'] };
  hypotheses: Hypothesis[];
  skills: SiSkillIndexEntry[];
  generatedAt: string;
  source: 'curated-corpus' | 'fallback';
}

// ---------------------------------------------------------------------------
// Curated hypothesis corpus — 25 hand-written entries covering the
// most-common SOC anomaly categories. Kept small enough to be
// readable in one screen, but each is a full hypothesis with signals
// and KQL.
// ---------------------------------------------------------------------------

const CORPUS: Hypothesis[] = [
  {
    id: 'h_bec_aitm',
    title: 'Business Email Compromise via Adversary-in-the-Middle (AiTM) Phishing Proxy',
    narrative:
      'Attacker deploys an AitM phishing kit (e.g., Evilginx, Muraena) between user and a real IdP login page. Captures session cookie in real time, bypassing MFA. User believes they logged in normally; attacker uses the stolen session cookie to access mailbox, OneDrive, and downstream SaaS apps.',
    killChainPhase: 'initial-access',
    mitre: ['T1566.002', 'T1078', 'T1539'],
    signals: [
      "User logs in from an IP / ASN not seen in the user's normal sign-in baseline",
      "Sign-in log shows a session token issued by a non-corporate IP within minutes of the user's real login",
      'Inbox rule "move messages from X to RSS Feeds" or "hide from inbox" created within minutes of the compromise',
      'OAuth consent grant for a high-privilege app within the AiTM session',
    ],
    whatToLookFor: [
      "Newest inbox rules on the user's mailbox (modification timestamp)",
      'MailItemsAccessed events on messages the user did not read interactively',
      'AzureADAuditSignInLogs with isInteractive=true and abnormal network details',
      'OAuthPermissionGrants for Mail.Read, Mail.ReadWrite, Files.ReadWrite.All',
    ],
    falsePositives: ['User travelling with VPN', 'Personal mobile device using cellular data'],
    sampleKql:
      'SigninLogs | where UserPrincipalName == "user@contoso.com" | where CreatedDateTime > ago(7d) | summarize dcount(IPAddress), make_set(IPAddress) by bin(CreatedDateTime, 1h)',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_lolbas_mshta',
    title: 'LOLBAS abuse — mshta.exe loading remote HTA payload',
    narrative:
      "Attacker uses mshta.exe to fetch and execute a remote .hta file. The HTA runs under the user context with no integrity-level elevation but inherits the user's network access and can launch further payloads (PowerShell, .NET assemblies).",
    killChainPhase: 'execution',
    mitre: ['T1218.005', 'T1059.001', 'T1105'],
    signals: [
      'mshta.exe parent is Office (winword.exe, excel.exe, outlook.exe)',
      'mshta.exe command line contains http://, https://, or hxxp-style URL',
      'mshta.exe makes outbound network connection to a low-reputation host',
      'Subsequent child of mshta.exe is powershell.exe, regsvr32.exe, or rundll32.exe',
    ],
    whatToLookFor: [
      'DeviceProcessEvents where ProcessName == "mshta.exe" and InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")',
      'Network connection events from mshta.exe to newly-registered domains (< 30 days old)',
      'Child process tree under mshta.exe — look for "mshta" → "powershell" / "rundll32"',
    ],
    falsePositives: ['Internal IT admin troubleshooting', 'Some legacy enterprise installers use mshta'],
    sampleKql:
      'DeviceProcessEvents | where FileName =~ "mshta.exe" | where ProcessCommandLine has_any ("http://","https://","hxxp","hxxps") | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_credspray',
    title: 'Password-spray against user accounts',
    narrative:
      'Attacker uses a small list of common passwords ("Spray2024!", "Welcome1") against a large list of user accounts from a distributed botnet. Defeats account-lockout policies because each account sees only one attempt.',
    killChainPhase: 'credential-access',
    mitre: ['T1110.003', 'T1078'],
    signals: [
      'Many failed sign-ins across many accounts from a single IP (or IP range) within a short window',
      'Sign-in failure reason: "Invalid username or password" or "Password expired"',
      "Geographic distribution of source IPs that does not match the tenant's normal traffic",
      'Successful sign-in appears for one or more accounts after a long string of failures',
    ],
    whatToLookFor: [
      'SigninLogs aggregate by IP: failure count > 50, distinct UserId > 10, within 1h',
      'Newly observed source IP for the user (look at ConditionalAccess / IdentityProtection)',
      'User flagged for "Anonymous IP address" or "Impossible travel" risk event after the spray',
    ],
    falsePositives: ['Legacy service accounts with expired passwords rotating', 'External federated IdP outage'],
    sampleKql:
      'SigninLogs | where ResultType in ("50126","50053") | summarize Failures=count(), Users=dcount(UserPrincipalName) by IPAddress, bin(CreatedDateTime, 1h) | where Failures > 20 and Users > 5',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_oauth_phish',
    title: 'Illicit OAuth consent grant to attacker-controlled app',
    narrative:
      'Attacker registers a multi-tenant Azure AD application, abuses Verified Publisher / publisher verification, and sends a phishing email with a link to the consent page. User grants Mail.Read, Files.ReadWrite.All, etc. Attacker reads mail exfiltrating data and sends phishing from inside the tenant.',
    killChainPhase: 'initial-access',
    mitre: ['T1528', 'T1078.004'],
    signals: [
      'New OAuth application grant by user to an unknown publisher',
      'Application has high-privilege Microsoft Graph scopes (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All)',
      "Publisher not in the tenant's allowlist (Tenant App Management policy)",
      'Mail activity from the application originating from a non-Microsoft IP',
    ],
    whatToLookFor: [
      'AuditLogs "Consent to application" operation, filter by ApplicationName NOT in allowlist',
      'AuditLogs "Add OAuth2PermissionGrant" with scope containing Mail.Read or Files.ReadWrite.All',
      'MailItemsAccessed operations by the application with isExternalApplication=true',
    ],
    falsePositives: ['IT admin granting consent to known first-party apps', 'Approved SaaS vendor onboarding'],
    sampleKql:
      'AuditLogs | where OperationName in ("Consent to application","Add OAuth2PermissionGrant") | where TargetResources[0].displayName has_any ("Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All") | project TimeGenerated, UserId, TargetResources',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_kc_fileless',
    title: 'Fileless PowerShell post-exploitation (reflection / .NET assemblies)',
    narrative:
      'Attacker loads a .NET assembly into PowerShell via [System.Reflection.Assembly]::Load() or System.Management.Automation to avoid writing a .dll to disk. Often observed with EncodedCommand, AMSI bypass attempts, or amsiInitFailed strings.',
    killChainPhase: 'defense-evasion',
    mitre: ['T1059.001', 'T1027', 'T1620'],
    signals: [
      'powershell.exe with -EncodedCommand base64 blob > 1000 chars',
      'powershell.exe with command containing "amsiInitFailed" or "AmsiUtils" reflection',
      'powershell.exe loading system.management.automation.assembly via reflection',
      'powershell.exe using DownloadString, DownloadFile, or WebClient from non-corporate network',
    ],
    whatToLookFor: [
      'DeviceProcessEvents on PowerShell with command length > 2000 chars',
      'ScriptBlockText (if ScriptBlock logging enabled) containing "Load(", "Reflection.Assembly", "FromBase64String"',
      'Network connection from powershell.exe to new domains',
    ],
    falsePositives: ['IT automation scripts', 'Some RMM tools use encoded PowerShell'],
    sampleKql:
      'DeviceProcessEvents | where FileName =~ "powershell.exe" | where ProcessCommandLine has "EncodedCommand" or ProcessCommandLine has "amsiInitFailed" or ProcessCommandLine has "FromBase64String" | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_ransom_pre',
    title: 'Ransomware precursor — shadow copy deletion + mass file rename',
    narrative:
      'In the 4–24h before encryption, ransomware crews delete shadow copies, clear event logs, and disable recovery. Watch for vssadmin, wbadmin, bcdedit, wevtutil clearing logs, and mass file renames in user-writable directories.',
    killChainPhase: 'impact',
    mitre: ['T1490', 'T1070.001', 'T1486'],
    signals: [
      'vssadmin.exe Delete Shadows /All /Quiet (or wbadmin delete catalog)',
      'wevtutil cl Security / wevtutil cl System (log clear)',
      'bcdedit /set {default} recoveryenabled No',
      'Mass file rename (rename count > 50/min on a single host)',
    ],
    whatToLookFor: [
      'DeviceProcessEvents on vssadmin.exe, wbadmin.exe, bcdedit.exe, wevtutil.exe with delete/clear parameters',
      'DeviceFileEvents on host with rename count > 100 in 5 min',
      'Off-hours activity (00:00–05:00 local) on a workstation or file server',
    ],
    falsePositives: ['IT admin rotating backup catalogues', 'Software uninstall scripts'],
    sampleKql:
      'DeviceProcessEvents | where FileName in~ ("vssadmin.exe","wbadmin.exe","bcdedit.exe","wevtutil.exe") | where ProcessCommandLine has_any ("delete","clear","recoveryenabled No") | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_cloud_token',
    title: 'Cloud token theft from developer workstation',
    narrative:
      'Attacker compromises a developer endpoint (phishing, malvertising) and exfiltrates long-lived cloud credentials (AWS access keys, GitHub PATs, npm tokens, container registry creds) from environment variables, .aws/credentials, or browser session stores.',
    killChainPhase: 'credential-access',
    mitre: ['T1552.001', 'T1217', 'T1078.004'],
    signals: [
      'Outbound traffic to a non-corporate destination from a process that recently read ~/.aws/credentials',
      'Git credential helper process spawned by a non-Git parent',
      'New IAM AccessKey created in AWS CloudTrail from a source IP outside the corporate egress',
      "Docker / kubectl / gh commands run from a host that doesn't normally have those binaries",
    ],
    whatToLookFor: [
      'Process tree: non-dev process (outlook, chrome) → node/python/powershell → curl/wget to suspicious host',
      'CloudTrail events: CreateAccessKey from unusual ASN',
      'Network connection from aws/cli or kubectl binary to a brand-new domain',
    ],
    falsePositives: ['Developer legitimate API usage from a new laptop', 'CI/CD pipeline debug'],
    sampleKql:
      'DeviceProcessEvents | where FileName in~ ("aws","kubectl","gh","docker") | where InitiatingProcessFileName !in~ ("bash.exe","cmd.exe","WindowsTerminal.exe","code.exe","Cursor.exe","pwsh.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_dns_exfil',
    title: 'DNS tunneling / data exfiltration over DNS',
    narrative:
      'Attacker encodes payload into DNS query labels (base32/base64 chunks sent as subdomains of attacker.com). The DNS resolver forwards queries to attacker-controlled authoritative NS, which reassembles data. Common for initial C2 and slow exfil.',
    killChainPhase: 'command-and-control',
    mitre: ['T1071.004', 'T1048.003'],
    signals: [
      'DNS queries for long random-looking subdomains (label length > 30 chars) at high volume',
      'Single hostname sending DNS queries to many subdomains of the same parent',
      'DNS query volume per host > 5x baseline',
      'Newly observed authoritative NS for the parent domain',
    ],
    whatToLookFor: [
      'DnsEvents aggregate: dcount(Name) per DeviceName in 1h, top 1% of population',
      'Name label length distribution: P95 > 25 chars suggests tunneling',
      "Resolving nameserver ASN not matching the parent domain's normal NS",
    ],
    falsePositives: ['Some CDN health checks', 'Anti-spam blocklist lookups'],
    sampleKql:
      'DnsEvents | where TimeGenerated > ago(24h) | summarize Queries=count(), dNames=dcount(Name) by DeviceName | where dNames > 5000',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_supply_chain_npm',
    title: 'Malicious npm / PyPI package installed in build pipeline',
    narrative:
      'Attacker publishes a typosquatted or hijacked package (e.g., event-stream, ua-parser-js, ctx) that runs a postinstall script stealing env vars, SSH keys, and CI tokens.',
    killChainPhase: 'supply-chain-compromise',
    mitre: ['T1195.002', 'T1059.006'],
    signals: [
      'Newly published package (< 30 days) with no dependents appears in a build lockfile diff',
      'Package maintainer account is single-factor and recently added',
      'Postinstall script in package.json contains curl/wget/nc/Python',
      'Build runner makes outbound network call to a low-reputation host within minutes of npm install',
    ],
    whatToLookFor: [
      'Diff of package-lock.json commits with newly added dependencies (low download count, recent publish date)',
      'Egress logs from CI runner: outbound DNS/HTTP from node / npm / pip to new domain',
      'Source of the new package — single maintainer, no GitHub org, no verified publisher',
    ],
    falsePositives: ['Legitimate new internal package', 'A new dev-dependency for testing'],
    sampleKql:
      'union isfuzzy=true (DeviceProcessEvents, DeviceNetworkEvents) | where InitiatingProcessFileName in~ ("npm","node","pip","python","pip3") | where RemoteUrl has_any (".tk",".ml",".ga",".cf",".xyz") or RemoteIP in ("<low-reputation-IPs>")',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_kc_cred_dump',
    title: 'LSASS credential dump (Mimikatz / comsvcs.dll MiniDump)',
    narrative:
      'Attacker with code execution on a host dumps LSASS process memory to harvest NTLM hashes, Kerberos tickets, and cleartext credentials (where WDigest is enabled). Common via Mimikatz, ProcDump, comsvcs.dll MiniDump, or direct handle to lsass.exe.',
    killChainPhase: 'credential-access',
    mitre: ['T1003.001', 'T1003.002'],
    signals: [
      'Process access to lsass.exe with PROCESS_VM_READ (0x0010) and PROCESS_QUERY_INFORMATION',
      'rundll32.exe comsvcs.dll MiniDump <pid> <path> full',
      'procdump.exe -ma lsass.exe',
      'mimikatz, sekurlsa, or wce strings in command lines',
    ],
    whatToLookFor: [
      'DeviceProcessEvents with "MiniDump" in command line, or procdump -ma with lsass',
      'Sysmon Event 10 (ProcessAccess) with SourceImage NOT in AV/EDR and TargetImage ending lsass.exe',
      '.dmp file created in TEMP or PUBLIC directories',
    ],
    falsePositives: ['Crash-dump collection during support', 'Some AV products use lsass handle for protection'],
    sampleKql:
      'DeviceProcessEvents | where FileName in~ ("procdump.exe","rundll32.exe") | where ProcessCommandLine has "lsass" or ProcessCommandLine has "MiniDump" | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_ransomware_c2',
    title: 'Active ransomware C2 — beacons to Tor / known ransomware payment site',
    narrative:
      'Encrypted-workstation or file-server traffic to a known ransomware tracker (.onion gateway egress, payment portal domain, or known I2P endpoint) within hours of mass file rename events.',
    killChainPhase: 'command-and-control',
    mitre: ['T1071.001', 'T1573'],
    signals: [
      'Outbound to a Tor exit-node IP and host in same minute as a vssadmin.exe event',
      'DNS query to a known ransomware payment site / data-leak site (e.g., .onion, alphabay-style)',
      'TLS connection with JA3 matching known C2 framework',
    ],
    whatToLookFor: [
      'DeviceNetworkEvents: RemoteUrl in known-ransomware-feed-blocklist',
      'Temporal correlation: vssadmin.exe + outbound-to-Tor within 30 min',
      'Process ancestry: explorer.exe → rundll32.exe → outbound to low-reputation host',
    ],
    falsePositives: ['Security researchers monitoring leaks', 'Threat-intel team controlled tests'],
    sampleKql:
      'DeviceNetworkEvents | where RemotePort in (443,8443) | where RemoteIP in (TorExitNodeIPs) | join kind=inner DeviceProcessEvents on DeviceName, $left.Timestamp between ($right.Timestamp .. ($right.Timestamp + 30m))',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_data_leak_via_dns',
    title: 'Data exfiltration via DNS TXT queries',
    narrative:
      "Attacker encodes stolen data into DNS TXT record queries. Defender's DNS logs show a flood of TXT queries to attacker.com containing base64-chunked payloads.",
    killChainPhase: 'exfiltration',
    mitre: ['T1048.003', 'T1071.004'],
    signals: [
      'TXT queries to single parent domain at high QPS',
      'Label content includes + / = or other base64 chars',
      'Query count to a single base domain > 1000/hour from one host',
    ],
    whatToLookFor: ['DnsEvents QueryType=TXT, group by Name parent, look for high QPS + high entropy labels'],
    falsePositives: ['SPF/DKIM lookups in mail flow'],
    sampleKql:
      'DnsEvents | where QueryType == 16 | where Name matches regex @"^[A-Za-z0-9+/=]{20,}\\." | summarize count() by Name, bin(TimeGenerated, 5m)',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_dormant_account',
    title: 'Dormant account activation (MFA bypass via password reset)',
    narrative:
      "Attacker obtains a user's account (via leaked password, social engineering) and resets MFA. The account has been dormant for 90+ days; activation triggers a sign-in from an unusual IP. The risk event in Azure AD Identity Protection may have been suppressed.",
    killChainPhase: 'initial-access',
    mitre: ['T1078', 'T1098'],
    signals: [
      'User sign-in risk: "anonymous IP address", "impossible travel", "unfamiliar sign-in properties"',
      'Account lastSignInDateTime > 90 days ago, now suddenly active',
      'MFA method changed within 24h of first new sign-in',
      'Newly observed ASN for the user',
    ],
    whatToLookFor: [
      "SigninLogs where UserPrincipalName's last sign-in was > 90 days ago and a new sign-in appears",
      'AuditLogs "Register Security Information" or "Update Security Information" shortly before sign-in',
      'IdentityProtection risk events: "unfamiliar sign-in properties" with high confidence',
    ],
    falsePositives: ['User returns from long leave'],
    sampleKql:
      'SigninLogs | where ResultType == 0 | extend LastSignIn = coalesce(toscalar(SigninLogs | where UserPrincipalName == UserPrincipalName and TimeGenerated < ago(1d) | summarize max(TimeGenerated)), datetime(1900-01-01)) | extend DaysSince = datetime_diff("day", TimeGenerated, LastSignIn) | where DaysSince > 90',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_idp_log_clear',
    title: 'Identity provider log tampering',
    narrative:
      'Attacker with privileged access to AD or Azure AD connector clears Security event logs to hide their activity. Watch for wevtutil cl, Get-EventLog -Clear, or log-pipeline tampering (omitting event-id 4624, 4720, etc.)',
    killChainPhase: 'defense-evasion',
    mitre: ['T1070.001', 'T1070.002'],
    signals: [
      'wevtutil cl Security',
      'Get-EventLog -LogName Security -Clear',
      'SIEM gap: missing 4624/4720/4732 events during a known active session',
    ],
    whatToLookFor: [
      'DeviceProcessEvents with wevtutil and cl parameter',
      'Event log clear events (1102, 104) on the host',
      'SIEM coverage gap: check event counts per host per hour against baseline',
    ],
    falsePositives: ['IT admin troubleshooting a full log'],
    sampleKql:
      'DeviceProcessEvents | where FileName =~ "wevtutil.exe" | where ProcessCommandLine has "cl " | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_priv_escalation',
    title: 'Privilege escalation via service account abuse',
    narrative:
      'Attacker compromises a low-privilege service account, finds it has GenericAll / WriteDACL / DCSync rights, escalates to Domain Admin. Watch for service accounts with privileged group membership, recent ACL changes, and Kerberos pre-auth disabled.',
    killChainPhase: 'privilege-escalation',
    mitre: ['T1078.002', 'T1003.006', 'T1098'],
    signals: [
      'Service account added to privileged group (Domain Admins, Enterprise Admins, Schema Admins)',
      'UserAccountControl flags changed: 0x1000000 (TRUSTED_FOR_DELEGATION)',
      'ACL change on a privileged object (Gen\.WriteDACL, Gen\.WriteOwner)',
      'Service account running interactive logon (should never be interactive)',
    ],
    whatToLookFor: [
      'AuditLogs 4728/4732/4756 group-membership events targeting service accounts',
      'AuditLogs 5136/4662 ACL changes on privileged objects',
      'SigninLogs where service account has InteractiveLogon type',
    ],
    falsePositives: ['IT scheduled change window'],
    sampleKql:
      'AuditLogs | where OperationName in ("Add member to group","Add member to role") | where TargetResources[0].userPrincipalName has "svc-" or TargetResources[0].userPrincipalName has "sa-" | project TimeGenerated, Actor, TargetResources',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_mac_macro',
    title: 'Office macro execution chain (Word → PowerShell)',
    narrative:
      'User opens a weaponised .docm / .xlsm with a malicious VBA macro. The macro runs on Document_Open, spawns wscript.exe or powershell.exe, fetches a stager, executes in memory. Common initial access vector for ransomware affiliates.',
    killChainPhase: 'execution',
    mitre: ['T1566.001', 'T1204.002', 'T1059.001'],
    signals: [
      'winword.exe child = wscript.exe, cscript.exe, or powershell.exe',
      'Office child process command line contains "http" or "EncodedCommand"',
      'Office process spawning a non-Office process within 5 minutes of file open',
    ],
    whatToLookFor: [
      'DeviceProcessEvents: InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe") and FileName in~ ("wscript.exe","cscript.exe","powershell.exe","mshta.exe")',
      'Parent of child: Office spawning non-Office in 5 min of open',
      'Newly observed domain in outbound network connection from Office',
    ],
    falsePositives: ['User macros in legitimate documents (rare, usually blocked by policy)'],
    sampleKql:
      'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","powerpnt.exe") | where FileName in~ ("powershell.exe","wscript.exe","cscript.exe","mshta.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_cloud_role_escalation',
    title: 'Cloud IAM privilege escalation',
    narrative:
      'Attacker with a low-privilege cloud identity (often an SSO user with weak RBAC) creates a new access key, attaches AdministratorAccess, or modifies a Lambda execution role to gain cross-account access.',
    killChainPhase: 'privilege-escalation',
    mitre: ['T1078.004', 'T1098'],
    signals: [
      'iam:CreateAccessKey called by a human user from a non-corporate IP',
      'iam:AttachUserPolicy attaching AdministratorAccess to a non-admin user',
      'iam:UpdateAssumeRolePolicy on a privileged role',
      'sts:AssumeRole called from a newly-observed account',
    ],
    whatToLookFor: [
      'CloudTrail: AttachUserPolicy, CreateAccessKey, UpdateAssumeRolePolicy',
      'Actor != root and Actor session context issuer != corporate IdP',
      'Resource policy diff for the targeted role',
    ],
    falsePositives: ['IT onboarding offboarding automation'],
    sampleKql:
      'AWSCloudTrail | where EventName in ("AttachUserPolicy","CreateAccessKey","UpdateAssumeRolePolicy") | where UserIdentity.type == "IAMUser" or UserIdentity.type == "AssumedRole" | project TimeGenerated, UserIdentity, EventName, RequestParameters',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_internal_recon',
    title: 'Internal reconnaissance — port scan / SMB enumeration',
    narrative:
      'Attacker with a foothold scans the internal network to discover other hosts, services, and credentials. Common signatures: powershell Test-NetConnection at scale, SMB session enumeration, LDAP queries for service accounts.',
    killChainPhase: 'discovery',
    mitre: ['T1046', 'T1018', 'T1087.002'],
    signals: [
      'Test-NetConnection or nmap.exe run by a non-admin user',
      'Many failed SMB authentications from a single source to many targets',
      'LDAP queries for service accounts (objectClass=user with servicePrincipalName)',
      'ADRecon, BloodHound, SharpHound in command lines or process names',
    ],
    whatToLookFor: [
      'DeviceProcessEvents with Test-NetConnection, nmap, masscan in command line',
      '4625 logon events: many failures from one source to many targets in 5 min',
      'Network connection to many ports on a single host in <1 min',
    ],
    falsePositives: ['NOC scan for asset inventory', 'Vulnerability scanner running on schedule'],
    sampleKql:
      'DeviceProcessEvents | where FileName in~ ("nmap.exe","masscan.exe") or ProcessCommandLine has "Test-NetConnection" | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_saas_abuse_oauth',
    title: 'SaaS abuse via OAuth refresh-token theft',
    narrative:
      'Attacker steals a long-lived OAuth refresh token (from local browser session storage, GitHub repo leak, CI/CD pipeline env var) and uses it offline to query M365 Graph, Google Workspace, Salesforce.',
    killChainPhase: 'credential-access',
    mitre: ['T1528', 'T1552.001'],
    signals: [
      "Sign-in to a SaaS app from a source IP not in the user's baseline",
      'MailItemsAccessed events with isExternalApplication=true at unusual hours',
      'Continuous Graph calls (polling) from a single access token at 2-minute intervals',
    ],
    whatToLookFor: [
      'SigninLogs with ClientApp containing "Microsoft Graph Explorer" or unknown app',
      'MailItemsAccessed: aggregation by ClientAppName, look for high call count to mailbox from one app',
      'OAuthPermissionGrants: app with offline_access scope over Mail.ReadWrite',
    ],
    falsePositives: ['IT automation polling mail', 'Service account background sync'],
    sampleKql:
      'MailItemsAccessed | where ClientAppName != "Outlook Desktop" | summarize Calls=count() by MailboxOwner, ClientAppName, bin(TimeGenerated, 1h) | where Calls > 100',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_dlp_to_cloud',
    title: 'Sensitive data upload to personal cloud storage',
    narrative:
      'Attacker or insider uses a personal Dropbox/Google Drive/MEGA account to upload sensitive files (source code, customer PII, financial models) bypassing corporate DLP.',
    killChainPhase: 'exfiltration',
    mitre: ['T1567.002', 'T1530'],
    signals: [
      'Upload to non-corporate cloud storage domain from corporate device',
      'Process ancestry: explorer.exe → browser.exe with upload in URL',
      'File activity: read of *.csv/*.sql/*.xlsx/*confidential* followed by upload',
    ],
    whatToLookFor: [
      'DeviceFileEvents: file with sensitivity label "Confidential" read by user, then browser upload event within 5 min',
      'DeviceNetworkEvents: RemoteUrl in (dropbox.com, drive.google.com, mega.nz) from corporate device',
      'UserAgent associated with the upload, distinct from corporate web proxy',
    ],
    falsePositives: ['Sales uploading to a CRM', 'Marketing uploading approved assets'],
    sampleKql:
      'DeviceFileEvents | where SensitivityLabel has "Confidential" | where ActionType in ("FileOpened","FileRenamed") | join kind=inner DeviceNetworkEvents on DeviceName, $left.Timestamp between ($right.Timestamp - 5m .. $right.Timestamp + 5m) | where RemoteUrl has_any ("dropbox.com","drive.google.com","mega.nz")',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_dga_dns',
    title: 'DGA / domain-generation algorithm beaconing',
    narrative:
      'Compromised host makes DNS queries to algorithmically-generated domain names (NXDOMAIN-heavy traffic, high-entropy labels) used by malware for resilient C2.',
    killChainPhase: 'command-and-control',
    mitre: ['T1568.002', 'T1071.001'],
    signals: [
      'NXDOMAIN rate from a single host > 10x baseline',
      'High-entropy DNS labels (Shannon entropy > 3.5) at high QPS',
      'No successful HTTP connection to most of the resolved names (NXDOMAIN)',
    ],
    whatToLookFor: [
      'DnsEvents group by DeviceName, count NXDOMAIN, filter top 1% of population',
      'Compute label entropy (Python notebook / KQL with entropy UDF)',
      'Whois registration age for resolved-but-NXDOMAIN names — most are < 30 days old',
    ],
    falsePositives: ['Misconfigured internal services', 'Email misconfig'],
    sampleKql:
      'DnsEvents | where ResponseCode == 3 | summarize NX=count() by DeviceName, bin(TimeGenerated, 1h) | where NX > 100',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_offboard_residual',
    title: 'Residual access after employee offboarding',
    narrative:
      'Former employee / contractor retains access to corporate SaaS via personal OAuth grant, unscoped service account, or unrevoked API key. Used for revenge or data theft.',
    killChainPhase: 'persistence',
    mitre: ['T1078.004', 'T1098'],
    signals: [
      'User account disabled in HR but sign-in logs still show "ResultType=0" within 24h',
      'OAuth grant by user before offboarding still in tenant',
      'Service account created by user, not deleted at offboarding',
    ],
    whatToLookFor: [
      'Cross-reference HR offboarding date with sign-in events (SigninLogs where AccountEnabled = false but result = success)',
      'AuditLogs "Disable account" then later successful sign-in (suspicious unless expected)',
      'OAuthPermissionGrants: filter by user.createdDateTime < offboardingDate and not revoked',
    ],
    falsePositives: ['User on extended leave, not yet offboarded'],
    sampleKql:
      'SigninLogs | where TimeGenerated > ago(30d) | join kind=leftouter (AuditLogs | where OperationName == "Disable account") on UserPrincipalName | where ResultType == 0 and AuditTimeGenerated < TimeGenerated',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_phish_o365_creds',
    title: 'Phished Microsoft 365 credentials',
    narrative:
      'User enters password on a phishing clone of the M365 login page. Attacker uses the credentials in real time, often with IMAP/ActiveSync first (lower bar) before moving to interactive logins.',
    killChainPhase: 'credential-access',
    mitre: ['T1078', 'T1110'],
    signals: [
      'IMAP / ActiveSync sign-in from an IP that has not been seen for this tenant',
      'Sign-in immediately followed by Inbox rule creation',
      'Mail forwarding rule set to an external domain',
      'OAuth consent grant within 5 min of the IMAP sign-in',
    ],
    whatToLookFor: [
      'SigninLogs: ClientApp == "IMAP4" or "ActiveSync" and IP NOT in tenant-allowlist',
      'MailItemsAccessed with ClientApp "ActiveSync" and unusual source IP',
      'AuditLogs "New-InboxRule" or "Set-Mailbox AutoForwardSettings" within 5 min of first phished sign-in',
    ],
    falsePositives: ['User travels and uses ActiveSync on hotel WiFi'],
    sampleKql:
      'SigninLogs | where ClientAppUsed in ("IMAP4","ActiveSync","POP3","SMTP") | where ResultType == 0 | summarize dcount(IPAddress) by UserPrincipalName | where dcount_IPAddress > 3',
    score: 0,
    rationale: '',
  },
  {
    id: 'h_k8s_pod_escape',
    title: 'Kubernetes pod escape / privileged container',
    narrative:
      'Attacker compromises a pod running with privileged: true or hostPath mount, escapes to node, and pivots to the cluster. Watch for kubectl exec from unusual sources, privileged pod creation, and hostPath mounts.',
    killChainPhase: 'privilege-escalation',
    mitre: ['T1611', 'T1078'],
    signals: [
      'kubectl create pod with securityContext.privileged=true',
      'kubectl exec from an IP not on the dev network',
      'Pod with hostPath / mount',
      'Audit log: anonymous-authenticated request to apiserver',
    ],
    whatToLookFor: [
      'K8s Audit: pods created with privileged=true or hostPID/hostNetwork=true',
      'kubectl exec audit events from a user not in dev team',
      'Container spawning another container (docker-in-docker, kube-exec)',
    ],
    falsePositives: ['Dev cluster intentionally running privileged'],
    sampleKql:
      'KubeAudit | where ObjectRef.resource == "pods" and RequestObject.spec.containers[0].securityContext.privileged == true',
    score: 0,
    rationale: '',
  },
];

// ---------------------------------------------------------------------------
// Scorer — token overlap + keyword boost + environment / IOC alignment.
// ---------------------------------------------------------------------------

const STOPWORDS = new Set([
  'the',
  'a',
  'an',
  'and',
  'or',
  'of',
  'to',
  'in',
  'on',
  'for',
  'with',
  'at',
  'by',
  'is',
  'it',
  'this',
  'that',
  'are',
  'be',
  'as',
  'from',
  'user',
  'host',
  'device',
  'process',
  'file',
  'data',
  'event',
  'alert',
  'activity',
  'signs',
  'flag',
  'look',
  'find',
]);

function tokenize(s: string): string[] {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\.\-_@\/ ]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 1 && !STOPWORDS.has(w));
}

function environmentBias(env: HypoObservation['environment'] | undefined, h: Hypothesis): number {
  if (!env) return 0;
  const m = h.mitre.join(' ') + ' ' + h.title + ' ' + h.narrative;
  let boost = 0;
  if (env === 'identity' && /T1078|T1528|T1110|T1098|T1556|T1558|T1550|T1003\.00[16]/i.test(m)) boost = 8;
  if (env === 'endpoint' && /T1059|T1218|T1003|T1543|T1547|T1548|T1569|T1003\.001/i.test(m)) boost = 8;
  if (env === 'cloud' && /T1078\.004|T1528|T1098|T1552|T1195/i.test(m)) boost = 8;
  if (env === 'network' && /T1071|T1046|T1090|T1573/i.test(m)) boost = 8;
  if (env === 'email' && /T1566|T1078|T1539|T1110/i.test(m)) boost = 8;
  if (env === 'saas' && /T1528|T1078\.004/i.test(m)) boost = 6;
  return boost;
}

function iocBias(iocs: string[], h: Hypothesis): number {
  if (!iocs || iocs.length === 0) return 0;
  const text = (h.title + ' ' + h.narrative + ' ' + h.signals.join(' ')).toLowerCase();
  let boost = 0;
  for (const ioc of iocs) {
    const i = ioc.toLowerCase();
    if (i.includes('@') && /mail|phish|o365|inbox|forward|oauth|impersonation/.test(text)) boost += 3;
    if (/^\d+\.\d+\.\d+\.\d+/.test(i) && /c2|beacon|nxdomain|scan|smb|kerb|nltm|rdp|ssh|port/.test(text)) boost += 2;
    if (/^[a-f0-9]{32,128}/.test(i) && /lsass|mimikatz|dump|loader|fileless|reflection/.test(text)) boost += 2;
    if (/\.tor|\.onion|\.ru|\.cn|\.tk|\.ml|\.ga/.test(i) && /c2|exfil|tunnel|dns/.test(text)) boost += 2;
  }
  return Math.min(boost, 12);
}

function scoreHypothesis(h: Hypothesis, obs: HypoObservation): { score: number; rationale: string } {
  const text = obs.text.toLowerCase();
  const obsTokens = new Set(tokenize(obs.text));
  const hTokens = new Set(
    tokenize(h.title + ' ' + h.narrative + ' ' + h.signals.join(' ') + ' ' + h.whatToLookFor.join(' '))
  );
  let overlap = 0;
  for (const t of obsTokens) if (hTokens.has(t)) overlap++;
  // Title-weight: extra boost if any title-token appears in obs.
  const titleTokens = new Set(tokenize(h.title));
  let titleHits = 0;
  for (const t of titleTokens) if (obsTokens.has(t)) titleHits++;
  let s = overlap * 3 + titleHits * 6 + environmentBias(obs.environment, h) + iocBias(obs.iocs ?? [], h);
  // Mitre technique direct match
  for (const t of h.mitre) if (text.includes(t.toLowerCase())) s += 8;
  // Code matches
  if (text.includes(h.id.replace('h_', ''))) s += 10;
  // Cap and normalise to 0-100
  s = Math.min(100, s);
  if (s < 1) s = 1;
  const rationale = `${overlap} token overlap, ${titleHits} title hits${obs.environment ? `, env=${obs.environment}` : ''}${obs.iocs?.length ? `, ${obs.iocs.length} iocs` : ''}`;
  return { score: Math.round(s), rationale };
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

export async function siHyposGenerate(obs: HypoObservation, env: { ASSETS?: Fetcher } = {}): Promise<HyposResult> {
  const topN = Math.min(10, Math.max(1, obs.topN ?? 5));
  const includeSkills = obs.includeSkills !== false;
  // Score all hypotheses.
  const scored = CORPUS.map((h) => {
    const { score, rationale } = scoreHypothesis(h, obs);
    return { ...h, score, rationale };
  });
  scored.sort((a, b) => b.score - a.score);
  const top = scored.slice(0, topN);
  let skills: SiSkillIndexEntry[] = [];
  if (includeSkills && env.ASSETS) {
    try {
      const index = await loadSiIndex(env.ASSETS);
      const obsHaystack = (obs.text + ' ' + (obs.iocs ?? []).join(' ')).toLowerCase();
      const obsTokens = new Set(tokenize(obsHaystack));
      const ranked = index.skills
        .map((s) => {
          const skillTokens = new Set(tokenize(s.name + ' ' + s.description + ' ' + s.triggerKeywords.join(' ')));
          let hits = 0;
          for (const t of obsTokens) if (skillTokens.has(t)) hits++;
          const trigHits = s.triggerKeywords.filter((k) => obsHaystack.includes(k.toLowerCase())).length;
          return { skill: s, score: hits * 2 + trigHits * 5 };
        })
        .filter((r) => r.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 5);
      skills = ranked.map((r) => r.skill);
    } catch (_catchErr) {
      console.error('siHyposGenerate failed:', errMessage(_catchErr));
      skills = [];
    }
  }
  return {
    observation: {
      text: obs.text,
      iocs: obs.iocs ?? [],
      environment: obs.environment,
    },
    hypotheses: top,
    skills,
    generatedAt: new Date().toISOString(),
    source: 'curated-corpus',
  };
}
