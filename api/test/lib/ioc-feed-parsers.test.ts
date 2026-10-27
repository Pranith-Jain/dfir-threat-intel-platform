import { describe, it, expect } from 'vitest';
import {
  parseUrlhaus,
  parseMalwarebazaar,
  parseThreatfox,
  parseThreatfoxJson,
  parseOpenPhish,
  parseCisaKev,
  parseSslblC2,
  parseSwiftioc,
  buildSummary,
} from '../../src/lib/ioc-feed-parsers';

// ─── URLhaus ────────────────────────────────────────────────────────────────
const URLHAUS_FIXTURE = `
################################################################
# abuse.ch URLhaus Database Dump
# Generated at: 2026-05-08 00:00:00 UTC
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
################################################################
"1234567","2026-05-08 12:00:00","http://evil.example.com/payload.exe","online","2026-05-08 12:00:00","malware_download","exe|stealer","https://urlhaus.abuse.ch/url/1234567/","reporter1"
"1234566","2026-05-07 10:00:00","https://phish.bad.net/login","online","","phishing","phishing|banking","https://urlhaus.abuse.ch/url/1234566/","reporter2"
"1234565","2026-05-06 08:00:00","http://botnet.cc/gate.php","offline","2026-05-06","botnet_cc","","https://urlhaus.abuse.ch/url/1234565/","reporter3"
`.trim();

describe('parseUrlhaus', () => {
  it('parses all data rows and skips comment lines', () => {
    const entries = parseUrlhaus(URLHAUS_FIXTURE);
    expect(entries).toHaveLength(3);
  });

  it('extracts correct type, value, context and timestamp', () => {
    const entries = parseUrlhaus(URLHAUS_FIXTURE);
    expect(entries[0]).toMatchObject({
      type: 'url',
      value: 'http://evil.example.com/payload.exe',
      context: 'malware_download | exe|stealer',
      timestamp: '2026-05-08 12:00:00',
    });
  });

  it('handles empty tags field — context only shows threat', () => {
    const entries = parseUrlhaus(URLHAUS_FIXTURE);
    expect(entries[2]!.context).toBe('botnet_cc');
  });

  it('returns empty array for empty input', () => {
    expect(parseUrlhaus('')).toHaveLength(0);
    expect(parseUrlhaus('# just a comment\n')).toHaveLength(0);
  });

  it('caps at 100 entries', () => {
    const rows = Array.from(
      { length: 150 },
      (_, i) => `"${i}","2026-05-08 00:00:00","http://url${i}.example.com/","online","","malware","","","reporter"`
    ).join('\n');
    expect(parseUrlhaus(rows)).toHaveLength(100);
  });
});

// ─── MalwareBazaar ──────────────────────────────────────────────────────────
const MB_FIXTURE = `
################################################################################
# abuse.ch MalwareBazaar Database Dump
################################################################################
# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh
################################################################################
"2026-05-08 12:00:00","aabbccdd1122334455667788aabbccddeeff00112233445566778899aabbccdd","d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","reporter1","malware.exe","exe","application/x-dosexec","LockBit","Win.Ransomware.LockBit","85","","","",
"2026-05-07 10:00:00","ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","abc123","sha1abc","reporter2","dropper.dll","dll","application/x-dosexec","Emotet","Win.Trojan.Emotet","72","","","",
`.trim();

describe('parseMalwarebazaar', () => {
  it('parses hash rows and skips comments', () => {
    const entries = parseMalwarebazaar(MB_FIXTURE);
    expect(entries).toHaveLength(2);
  });

  it('extracts sha256 as value with signature|file_type_guess as context', () => {
    const entries = parseMalwarebazaar(MB_FIXTURE);
    expect(entries[0]).toMatchObject({
      type: 'hash',
      value: 'aabbccdd1122334455667788aabbccddeeff00112233445566778899aabbccdd',
      context: 'LockBit | exe',
      timestamp: '2026-05-08 12:00:00',
    });
  });

  it('returns empty for pure comment block', () => {
    expect(parseMalwarebazaar('# comment\n# another')).toHaveLength(0);
  });
});

// ─── ThreatFox ───────────────────────────────────────────────────────────────
const TF_FIXTURE = `
################################################################
# ThreatFox Recent IOC Export
################################################################
# first_seen,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen,confidence_level,reference,tags,anonymous,reporter
################################################################
"2026-05-08 09:00:00","1001","http://malicious.url/cmd","url","botnet_cc","mal.letsgo","","Mirai","2026-05-08","90","","","0","reporter1"
"2026-05-08 08:00:00","1002","evil-domain.ru","domain","c2","evil.fam","","DarkComet","2026-05-08","75","","","0","reporter2"
"2026-05-08 07:00:00","1003","10.20.30.40:4444","ip:port","c2","bot.fam","","Botnet","2026-05-08","80","","","0","reporter3"
"2026-05-08 06:00:00","1004","deadbeef1234567890abcdef12345678","md5_hash","malware","hash.fam","","AgentTesla","2026-05-08","70","","","0","reporter4"
"2026-05-08 05:00:00","1005","unknown_type_xyz","ftp_store","payload","x","","X","2026-05-08","50","","","0","reporter5"
`.trim();

describe('parseThreatfox', () => {
  it('parses url, domain, ip:port, hash types; skips unknown ioc_type', () => {
    const entries = parseThreatfox(TF_FIXTURE);
    expect(entries).toHaveLength(4);
  });

  it('maps url ioc_type correctly', () => {
    const entries = parseThreatfox(TF_FIXTURE);
    expect(entries[0]).toMatchObject({ type: 'url', value: 'http://malicious.url/cmd' });
  });

  it('maps domain ioc_type correctly', () => {
    const entries = parseThreatfox(TF_FIXTURE);
    expect(entries[1]).toMatchObject({ type: 'domain', value: 'evil-domain.ru' });
  });

  it('strips port for ip:port entries', () => {
    const entries = parseThreatfox(TF_FIXTURE);
    expect(entries[2]).toMatchObject({ type: 'ipv4', value: '10.20.30.40' });
  });

  it('maps md5_hash ioc_type to hash', () => {
    const entries = parseThreatfox(TF_FIXTURE);
    expect(entries[3]).toMatchObject({ type: 'hash' });
  });
});

// ─── ThreatFox JSON (authenticated get_iocs, replacing the retired CSV) ─────
const TF_JSON_FIXTURE = JSON.stringify({
  query_status: 'ok',
  data: [
    {
      id: '1001',
      ioc: 'http://malicious.url/cmd',
      ioc_type: 'url',
      malware: 'win.malware.autoit.020',
      malware_printable: 'AgentTesla',
      confidence_level: 90,
      first_seen: '2026-10-25 09:00:00',
      reporter: 'reporter1',
    },
    {
      id: '1002',
      ioc: 'evil-domain.ru',
      ioc_type: 'domain',
      malware: 'c2',
      malware_printable: 'DarkComet',
      confidence_level: 75,
      first_seen: '2026-10-25 08:00:00',
    },
    {
      id: '1003',
      ioc: '10.20.30.40:4444',
      ioc_type: 'ip:port',
      malware: 'bot.fam',
      confidence_level: 80,
      first_seen: '2026-10-25 07:00:00',
    },
    {
      id: '1004',
      ioc: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
      ioc_type: 'md5_hash',
      malware: 'AgentTesla',
      confidence_level: 70,
      first_seen: '2026-10-25 06:00:00',
    },
    // Unknown type + blank ioc rows must be dropped, not crash.
    { id: '1005', ioc: 'weird', ioc_type: 'ftp_store', first_seen: '2026-10-25' },
    { id: '1006', ioc: '', ioc_type: 'url', first_seen: '2026-10-25' },
  ],
});

describe('parseThreatfoxJson', () => {
  it('maps url/domain/ip:port/hash and skips unknown or empty iocs', () => {
    const entries = parseThreatfoxJson(TF_JSON_FIXTURE);
    expect(entries).toHaveLength(4);
    expect(entries[0]).toMatchObject({ type: 'url', value: 'http://malicious.url/cmd' });
    expect(entries[1]).toMatchObject({ type: 'domain', value: 'evil-domain.ru' });
    expect(entries[2]).toMatchObject({ type: 'ipv4', value: '10.20.30.40' });
    expect(entries[3]).toMatchObject({ type: 'hash', value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90' });
  });

  it('strips the port from ip:port values', () => {
    const entries = parseThreatfoxJson(TF_JSON_FIXTURE);
    expect(entries[2]!.value).toBe('10.20.30.40');
  });

  it('builds context from printable malware + family', () => {
    const entries = parseThreatfoxJson(TF_JSON_FIXTURE);
    expect(entries[0]!.context).toContain('AgentTesla');
    expect(entries[0]!.context).toContain('win.malware.autoit.020');
  });

  it('carries first_seen as the timestamp (normalised by looseDateToIso)', () => {
    const entries = parseThreatfoxJson(TF_JSON_FIXTURE);
    expect(entries[1]!.timestamp).toBe('2026-10-25T08:00:00.000Z');
  });

  it('returns [] for non-ok query_status, bad JSON, or missing data', () => {
    expect(parseThreatfoxJson(JSON.stringify({ query_status: 'no_results' }))).toEqual([]);
    expect(parseThreatfoxJson('not json')).toEqual([]);
    expect(parseThreatfoxJson(JSON.stringify({ query_status: 'ok' }))).toEqual([]);
  });

  it('honours the cap', () => {
    const many = JSON.stringify({
      query_status: 'ok',
      data: Array.from({ length: 12 }, (_, i) => ({
        id: String(i),
        ioc: `10.0.0.${i}:80`,
        ioc_type: 'ip:port',
        first_seen: '2026-10-25',
      })),
    });
    expect(parseThreatfoxJson(many, 5)).toHaveLength(5);
  });
});

describe('buildSummary threatfox JSON sniffing', () => {
  it('routes the authenticated JSON body through the JSON parser', () => {
    const s = buildSummary('threatfox', TF_JSON_FIXTURE);
    expect(s.count).toBe(4);
    expect(s.entries[2]).toMatchObject({ type: 'ipv4', value: '10.20.30.40' });
  });

  it('still parses the legacy CSV fallback shape', () => {
    const s = buildSummary('threatfox', TF_FIXTURE);
    expect(s.count).toBe(4);
    expect(s.entries[0]).toMatchObject({ type: 'url', value: 'http://malicious.url/cmd' });
  });
});

// ─── OpenPhish ───────────────────────────────────────────────────────────────
const OPENPHISH_FIXTURE = `
https://phish1.example.com/login
https://phish2.example.com/secure
http://phish3.example.org/account

https://phish4.example.net/verify
`.trim();

describe('parseOpenPhish', () => {
  it('parses one url per line', () => {
    const entries = parseOpenPhish(OPENPHISH_FIXTURE);
    expect(entries).toHaveLength(4);
    entries.forEach((e) => expect(e.type).toBe('url'));
  });

  it('has no context or timestamp', () => {
    const entries = parseOpenPhish(OPENPHISH_FIXTURE);
    expect(entries[0]!.context).toBeUndefined();
    expect(entries[0]!.timestamp).toBeUndefined();
  });

  it('ignores blank lines', () => {
    expect(parseOpenPhish('\n\nhttps://a.com\n\nhttps://b.com\n')).toHaveLength(2);
  });

  it('caps at 100', () => {
    const lines = Array.from({ length: 150 }, (_, i) => `https://url${i}.example.com`).join('\n');
    expect(parseOpenPhish(lines)).toHaveLength(100);
  });
});

// ─── CISA KEV ────────────────────────────────────────────────────────────────
const CISA_KEV_FIXTURE = JSON.stringify({
  title: 'CISA KEV',
  catalogVersion: '2026.05.08',
  dateReleased: '2026-05-08T00:00:00Z',
  count: 3,
  vulnerabilities: [
    {
      cveID: 'CVE-2024-12345',
      vendorProject: 'Acme Corp',
      product: 'WebServer',
      vulnerabilityName: 'Remote Code Execution',
      dateAdded: '2024-01-15',
      shortDescription: 'An RCE vuln',
      requiredAction: 'Patch immediately',
      dueDate: '2024-02-05',
      knownRansomwareCampaignUse: 'Known',
      notes: '',
    },
    {
      cveID: 'CVE-2025-67890',
      vendorProject: 'BigSoft',
      product: 'Enterprise Suite',
      vulnerabilityName: 'Authentication Bypass',
      dateAdded: '2025-03-10',
      shortDescription: 'Auth bypass',
      requiredAction: 'Patch',
      dueDate: '2025-04-01',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
    },
    {
      cveID: 'CVE-2026-11111',
      vendorProject: 'CloudVend',
      product: 'API Gateway',
      vulnerabilityName: 'SQL Injection',
      dateAdded: '2026-05-01',
      shortDescription: 'SQLi',
      requiredAction: 'Patch',
      dueDate: '2026-05-22',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
    },
  ],
});

describe('parseCisaKev', () => {
  it('parses cve entries from vulnerabilities array', () => {
    const { entries, total } = parseCisaKev(CISA_KEV_FIXTURE);
    expect(entries).toHaveLength(3);
    expect(total).toBe(3);
  });

  it('extracts cveID as value and vendor/product/name as context', () => {
    const { entries } = parseCisaKev(CISA_KEV_FIXTURE);
    // Sorted DESC by dateAdded; newest is CVE-2026-11111
    expect(entries[0]).toMatchObject({
      type: 'cve',
      value: 'CVE-2026-11111',
      context: 'CloudVend | API Gateway | SQL Injection',
      timestamp: '2026-05-01',
    });
  });

  it('returns empty entries on invalid JSON', () => {
    const { entries } = parseCisaKev('not json');
    expect(entries).toHaveLength(0);
  });

  it('returns empty entries on empty vulnerabilities array', () => {
    const { entries } = parseCisaKev(JSON.stringify({ vulnerabilities: [] }));
    expect(entries).toHaveLength(0);
  });

  it('caps at 100 (takes newest)', () => {
    const vulns = Array.from({ length: 150 }, (_, i) => ({
      cveID: `CVE-2025-${String(i).padStart(5, '0')}`,
      vendorProject: 'V',
      product: 'P',
      vulnerabilityName: 'N',
      dateAdded: `2025-01-${String((i % 28) + 1).padStart(2, '0')}`,
    }));
    const { entries } = parseCisaKev(JSON.stringify({ vulnerabilities: vulns }));
    expect(entries).toHaveLength(100);
  });

  it('returns entries sorted DESC by dateAdded', () => {
    const fixture = JSON.stringify({
      vulnerabilities: [
        { cveID: 'CVE-2021-1111', vendorProject: 'A', product: 'B', vulnerabilityName: 'C', dateAdded: '2021-11-03' },
        { cveID: 'CVE-2024-9999', vendorProject: 'D', product: 'E', vulnerabilityName: 'F', dateAdded: '2024-09-15' },
        { cveID: 'CVE-2022-5555', vendorProject: 'G', product: 'H', vulnerabilityName: 'I', dateAdded: '2022-06-01' },
        { cveID: 'CVE-2025-0001', vendorProject: 'J', product: 'K', vulnerabilityName: 'L', dateAdded: '2025-01-10' },
        { cveID: 'CVE-2023-3333', vendorProject: 'M', product: 'N', vulnerabilityName: 'O', dateAdded: '2023-03-20' },
      ],
    });
    const { entries } = parseCisaKev(fixture);
    expect(entries).toHaveLength(5);
    // Newest first
    expect(entries[0]!.value).toBe('CVE-2025-0001');
    expect(entries[1]!.value).toBe('CVE-2024-9999');
    expect(entries[2]!.value).toBe('CVE-2023-3333');
    expect(entries[3]!.value).toBe('CVE-2022-5555');
    expect(entries[4]!.value).toBe('CVE-2021-1111');
    // Timestamps should be in DESC order
    expect(entries[0]!.timestamp! > entries[1]!.timestamp!).toBe(true);
  });
});

// ─── SSLBL botnet C2 ──────────────────────────────────────────────────────────
describe('parseSslblC2', () => {
  it('parses CSV rows, skips comments, carries port + timestamp', () => {
    const fixture = `# SSL Blacklist
# Firstseen,DstIP,DstPort
2026-05-19 10:00:00,203.0.113.9,443
2026-05-18 08:30:00,198.51.100.4,8443
not,an,ip`;
    const e = parseSslblC2(fixture);
    expect(e).toHaveLength(2);
    expect(e[0]!.type).toBe('ipv4');
    expect(e[0]!.value).toBe('203.0.113.9');
    expect(e[0]!.context).toContain('443');
    expect(e[0]!.timestamp).toBe('2026-05-19 10:00:00');
  });
  it('honours the cap', () => {
    const rows = Array.from({ length: 10 }, (_, i) => `2026-05-19,10.0.0.${i},443`).join('\n');
    expect(parseSslblC2(rows, 3)).toHaveLength(3);
  });
});

// ─── buildSummary integration ─────────────────────────────────────────────────
describe('buildSummary', () => {
  it('returns correct shape for urlhaus', () => {
    const s = buildSummary('urlhaus', URLHAUS_FIXTURE);
    expect(s.source).toBe('urlhaus');
    expect(s.source_name).toBe('Abuse.ch URLhaus');
    expect(s.count).toBe(s.entries.length);
    expect(s.cache_control_seconds).toBe(1800);
    expect(typeof s.fetched_at).toBe('string');
  });

  it('returns correct shape for cisa-kev with total_in_feed', () => {
    const s = buildSummary('cisa-kev', CISA_KEV_FIXTURE);
    expect(s.source).toBe('cisa-kev');
    expect(s.total_in_feed).toBe(3);
    expect(s.entries[0]!.type).toBe('cve');
  });

  it('returns correct shape for certpl-warnings', () => {
    const fixture = 'evil.example.com\nphish.bad.net\n# comment';
    const s = buildSummary('certpl-warnings', fixture);
    expect(s.source).toBe('certpl-warnings');
    expect(s.source_name).toBe('CERT.PL Warning List');
    expect(s.count).toBe(2);
    expect(s.entries[0]!.type).toBe('domain');
    expect(s.entries[0]!.value).toBe('evil.example.com');
  });

  it('returns correct shape for phishunt', () => {
    const fixture = 'http://phish1.example.com\nhttps://phish2.example.com\n# comment';
    const s = buildSummary('phishunt', fixture);
    expect(s.source).toBe('phishunt');
    expect(s.source_name).toBe('phishunt');
    expect(s.count).toBe(2);
    expect(s.entries[0]!.type).toBe('url');
    expect(s.entries[0]!.value).toBe('http://phish1.example.com');
  });
});

// ─── SwiftIOC high-confidence ───────────────────────────────────────────
const SWIFTIOC_FIXTURE = [
  'indicator,type,source,first_seen,last_seen,confidence,score,sightings,tlp,tags,reference,context',
  '77[.]239[.]124[.]108,ipv4,"et_compromised,ipsum_level5",2026-08-21T04:32:04Z,2026-09-12T04:45:02Z,high,96,118,CLEAR,"Mirai,ssh",https://example.com/,Blocklist entry',
  'evil[.]example[.]com,domain,"phish",2026-09-01T00:00:00Z,2026-09-12T00:00:00Z,high,90,12,CLEAR,"phishing",https://example.com/,x',
  'nonsense-row-without-enough-columns',
  '10.0.0.1,cve,"x",2026-09-01T00:00:00Z,2026-09-12T00:00:00Z,high,50,1,CLEAR,"t",https://example.com/,x',
].join('\n');

describe('parseSwiftioc', () => {
  it('refangs indicators and keeps score context', () => {
    const entries = parseSwiftioc(SWIFTIOC_FIXTURE);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({
      type: 'ipv4',
      value: '77.239.124.108',
      timestamp: '2026-09-12T04:45:02Z',
    });
    expect(entries[0]!.context).toContain('score 96');
    expect(entries[1]).toMatchObject({ type: 'domain', value: 'evil.example.com' });
  });

  it('returns [] on malformed bodies', () => {
    expect(parseSwiftioc('not a csv at all')).toEqual([]);
  });

  it('buildSummary routes swiftioc correctly', () => {
    const s = buildSummary('swiftioc', SWIFTIOC_FIXTURE);
    expect(s.source).toBe('swiftioc');
    expect(s.source_name).toBe('SwiftIOC High-Confidence');
    expect(s.count).toBe(2);
  });
});
