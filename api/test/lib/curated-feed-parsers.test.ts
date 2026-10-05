/**
 * Parser tests for the newly-adopted feeds, driven by fixtures captured from
 * the real upstreams on 2026-10-05.
 *
 * These exist because every one of these formats has a trap that a
 * "looks like a CSV" assumption gets wrong — the ThreatFox hostfile's
 * all-`127.0.0.1` placeholder column, the tab-separated Carbon Black CSV,
 * Threatview's prose dates, botvrij's CSV header over bare-domain rows. A
 * fixture-shape change is how an upstream format change first becomes visible.
 */
import { describe, it, expect } from 'vitest';
import {
  parseAiHoneypots,
  parseLlmThreatintelIocs,
  parseCobaltStrikeCsv,
  parseCarbonBlackC2,
  parseThreatviewC2,
  parseThreatfoxHostfile,
  parseThreatfoxUrls,
  parseC2IntelDomains,
  parseBotvrijDomains,
  parsePlainDomainList,
  parseSslblJa3,
  toIsoTimestamp,
  looseDateToIso,
} from '../../src/lib/ioc-feed-parsers';

describe('toIsoTimestamp', () => {
  it('canonicalizes a +00:00 offset to Z', () => {
    // The live ai-honeypots feed's actual format. Without this, `+00:00` sorts
    // BEFORE `Z` lexicographically and the freshness filter misjudges it.
    expect(toIsoTimestamp('2026-10-01T07:14:38.806561+00:00')).toBe('2026-10-01T07:14:38.806Z');
  });

  it('canonicalizes a date-only value to UTC midnight', () => {
    expect(toIsoTimestamp('2026-09-23')).toBe('2026-09-23T00:00:00.000Z');
  });

  it('is idempotent', () => {
    const once = toIsoTimestamp('2026-10-01T07:14:38.806561+00:00');
    expect(toIsoTimestamp(once)).toBe(once);
  });

  it('returns undefined for junk rather than emitting a garbage timestamp', () => {
    // A garbage timestamp would fail the lexicographic staleness test and get
    // the item silently dropped as stale.
    expect(toIsoTimestamp('not-a-date')).toBeUndefined();
    expect(toIsoTimestamp('')).toBeUndefined();
    expect(toIsoTimestamp(undefined)).toBeUndefined();
  });

  it('produces strings that sort correctly against a Z cutoff', () => {
    const cutoff = '2026-10-01T00:00:00.000Z';
    const fresh = toIsoTimestamp('2026-10-05T09:01:37.948608+00:00')!;
    const stale = toIsoTimestamp('2026-09-20T09:01:37.948608+00:00')!;
    expect(fresh >= cutoff).toBe(true);
    expect(stale >= cutoff).toBe(false);
  });
});

describe('parseAiHoneypots', () => {
  const body = JSON.stringify({
    indicators: [
      {
        ioc_type: 'ip',
        value: '185.226.197.32',
        actor_category: 'MCP-SCANNER',
        confidence: 'low',
        ttps: ['T1046', 'T1190'],
        first_seen: '2026-10-03T05:14:03.315237+00:00',
        last_seen: '2026-10-03T08:32:13.446106+00:00',
        total_hits: 6,
        distinct_personas: 2,
      },
      {
        ioc_type: 'ip',
        value: '123.160.223.73',
        actor_category: 'SCANNER-ENUM',
        confidence: 'high',
        ttps: ['T1046'],
        first_seen: '2026-10-01T08:56:05.143014+00:00',
        last_seen: '2026-10-05T10:37:36.995708+00:00',
        total_hits: 6,
        distinct_personas: 5,
      },
    ],
  });

  it('maps indicators to ipv4 entries with ATT&CK + hit context', () => {
    const entries = parseAiHoneypots(body);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ type: 'ipv4', value: '185.226.197.32' });
    expect(entries[0]!.context).toContain('MCP-SCANNER');
    expect(entries[0]!.context).toContain('conf:low');
    expect(entries[0]!.context).toContain('hits:6');
    expect(entries[0]!.context).toContain('personas:2');
    expect(entries[0]!.context).toContain('T1046,T1190');
  });

  it('uses last_seen as the observation timestamp, canonicalized', () => {
    const entries = parseAiHoneypots(body);
    expect(entries[0]!.timestamp).toBe('2026-10-03T08:32:13.446Z');
  });

  it('returns [] for malformed JSON and for a doc with no indicators array', () => {
    expect(parseAiHoneypots('not json')).toEqual([]);
    expect(parseAiHoneypots('{}')).toEqual([]);
    expect(parseAiHoneypots('{"indicators": "nope"}')).toEqual([]);
  });

  it('drops non-ip indicator types and non-IP values', () => {
    const mixed = JSON.stringify({
      indicators: [
        { ioc_type: 'domain', value: 'evil.example', last_seen: '2026-10-01T00:00:00Z' },
        { ioc_type: 'ip', value: 'not-an-ip', last_seen: '2026-10-01T00:00:00Z' },
        { ioc_type: 'ip', value: '1.2.3.4', last_seen: '2026-10-01T00:00:00Z' },
      ],
    });
    expect(parseAiHoneypots(mixed).map((e) => e.value)).toEqual(['1.2.3.4']);
  });

  it('honours the cap', () => {
    const many = JSON.stringify({
      indicators: Array.from({ length: 50 }, (_, i) => ({
        ioc_type: 'ip',
        value: `1.1.1.${i}`,
        last_seen: '2026-10-01T00:00:00Z',
      })),
    });
    expect(parseAiHoneypots(many, 10)).toHaveLength(10);
  });
});

describe('parseLlmThreatintelIocs', () => {
  it('maps type and folds campaign + reporter into context', () => {
    const body = JSON.stringify({
      iocs: [
        {
          value: 'third-party.com',
          type: 'domain',
          context: 'Placeholder hostname serving a Windows ClickFix lure.',
          first_seen: '2026-09-23',
          source: 'Manifold Security',
          campaign: '2026-09-30-third-party-com-clickfix-skills-mcp',
          status: 'active',
        },
      ],
    });
    const entries = parseLlmThreatintelIocs(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ type: 'domain', value: 'third-party.com' });
    expect(entries[0]!.context).toContain('Manifold Security');
    expect(entries[0]!.context).toContain('2026-09-30-third-party-com-clickfix-skills-mcp');
    expect(entries[0]!.timestamp).toBe('2026-09-23T00:00:00.000Z');
  });

  it('drops stood-down indicators so the stream does not serve retired IOCs', () => {
    const body = JSON.stringify({
      iocs: [
        { value: 'a.example', type: 'domain', status: 'retired' },
        { value: 'b.example', type: 'domain', status: 'active' },
        { value: 'c.example', type: 'domain' },
      ],
    });
    expect(parseLlmThreatintelIocs(body).map((e) => e.value)).toEqual(['b.example', 'c.example']);
  });

  it('drops unknown types and malformed rows', () => {
    const body = JSON.stringify({
      iocs: [
        { value: 'x', type: 'email' },
        { value: '', type: 'domain' },
        { type: 'domain' },
        { value: 'ok.example', type: 'domain' },
      ],
    });
    expect(parseLlmThreatintelIocs(body).map((e) => e.value)).toEqual(['ok.example']);
  });

  it('returns [] for malformed JSON', () => {
    expect(parseLlmThreatintelIocs('<html>502</html>')).toEqual([]);
    expect(parseLlmThreatintelIocs('{}')).toEqual([]);
  });
});

describe('parseCobaltStrikeCsv (Fox-IT)', () => {
  it('parses ip,port,first_seen,last_seen and skips the header', () => {
    const body = ['ip,port,first_seen,last_seen', '1.122.234.70,443,2017-06-20,2017-06-20'].join('\n');
    const entries = parseCobaltStrikeCsv(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      type: 'ipv4',
      value: '1.122.234.70',
      context: 'Cobalt Strike team server :443',
    });
    expect(entries[0]!.timestamp).toBe('2017-06-20T00:00:00.000Z');
  });

  it('falls back to first_seen when last_seen is empty', () => {
    const body = 'ip,port,first_seen,last_seen\n1.1.1.1,80,2020-01-02,';
    expect(parseCobaltStrikeCsv(body)[0]!.timestamp).toBe('2020-01-02T00:00:00.000Z');
  });
});

describe('parseCarbonBlackC2', () => {
  it('parses the TAB-separated layout despite the .csv extension', () => {
    const body =
      'c2_ip\tfirst_seen\tlast_seen\tprotocol\tport\tversion\twatermark\tpubkey_md5\tdomains\thost_header\n' +
      '31.14.40.134\t2020/09/04 23:32:24\t2020/09/04 23:32:24\tHTTPS\t443\t4.0\t305419896 (leaked)\t8ac540617dddcdf575f6dc207abb7344\t31.14.40.134,/jquery-3.3.1.min.js\tNone';
    const entries = parseCarbonBlackC2(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.value).toBe('31.14.40.134');
    expect(entries[0]!.context).toContain('HTTPS:443');
    expect(entries[0]!.context).toContain('CS 4.0');
    expect(entries[0]!.timestamp).toBe('2020-09-04T23:32:24.000Z');
  });

  it('skips the header row', () => {
    const body = 'c2_ip\tfirst_seen\n1.2.3.4\t2021/01/01 00:00:00';
    expect(parseCarbonBlackC2(body).map((e) => e.value)).toEqual(['1.2.3.4']);
  });
});

describe('parseThreatviewC2', () => {
  it("parses the prose detection date ('08 February 2026 03:26 PM UTC')", () => {
    const body =
      '#IP,Date of Detection,Host,Protocol,Beacon Config,Comment\n' +
      '106.12.219.245,08 February 2026 03:26 PM UTC,106.12.219.245,https,"106.12.219.245,/fwlink",Generated by Threatview[.]io';
    const entries = parseThreatviewC2(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.value).toBe('106.12.219.245');
    expect(entries[0]!.timestamp).toBe('2026-02-08T15:26:00.000Z');
    expect(entries[0]!.context).toContain('https');
    expect(entries[0]!.context).toContain('/fwlink');
  });

  it('handles 12-hour noon and midnight correctly', () => {
    const noon = '1.1.1.1,08 February 2026 12:00 PM UTC,1.1.1.1,https,"x",c';
    const midnight = '1.1.1.1,08 February 2026 12:00 AM UTC,1.1.1.1,https,"x",c';
    expect(parseThreatviewC2(noon)[0]!.timestamp).toBe('2026-02-08T12:00:00.000Z');
    expect(parseThreatviewC2(midnight)[0]!.timestamp).toBe('2026-02-08T00:00:00.000Z');
  });
});

describe('parseThreatfoxHostfile', () => {
  // The trap: the address column is the literal placeholder `127.0.0.1` on all
  // 38,123 live rows. A naive split would emit 38k copies of loopback.
  it('takes the domain and never the 127.0.0.1 placeholder', () => {
    const body = ['# comment', '127.0.0.1\tclouddelivry.com', '127.0.0.1\t5r35llx8.deamobros.com'].join('\n');
    const entries = parseThreatfoxHostfile(body);
    expect(entries.map((e) => e.value)).toEqual(['clouddelivry.com', '5r35llx8.deamobros.com']);
    expect(entries.every((e) => e.value !== '127.0.0.1')).toBe(true);
    expect(entries.every((e) => e.type === 'domain')).toBe(true);
  });

  it('still emits an IP when a row carries a real address', () => {
    const body = '203.0.113.5\tc2.example.com';
    const entries = parseThreatfoxHostfile(body);
    expect(entries.map((e) => `${e.type}:${e.value}`).sort()).toEqual(['domain:c2.example.com', 'ipv4:203.0.113.5']);
  });

  it('deduplicates repeated hosts', () => {
    const body = '127.0.0.1\tdup.example\n127.0.0.1\tdup.example\n127.0.0.1\tother.example';
    expect(parseThreatfoxHostfile(body).map((e) => e.value)).toEqual(['dup.example', 'other.example']);
  });
});

describe('parseThreatfoxUrls', () => {
  it('parses the quoted recent-URLs CSV with family attribution', () => {
    const body =
      '# banner\n' +
      '"2026-10-05 13:45:47", "1952830", "https://cdn.example/a.js", "url", "payload_delivery", "js.clearfake", "None", "ClearFake", "", "100", "False", "None", "ClearFake"';
    const entries = parseThreatfoxUrls(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ type: 'url', value: 'https://cdn.example/a.js' });
    expect(entries[0]!.context).toContain('ClearFake');
    expect(entries[0]!.timestamp).toBe('2026-10-05T13:45:47.000Z');
  });

  it('drops rows whose URL column is not http', () => {
    const body = '"2026-10-05 13:45:47", "1", "not-a-url", "url", "x", "y"';
    expect(parseThreatfoxUrls(body)).toEqual([]);
  });

  it('never attributes a row to the "None" placeholder', () => {
    // Column 6 is the malware name and upstream fills it with the literal
    // "None"; the family is column 7. Reading column 6 first labelled every
    // unnamed row "ThreatFox payload delivery — None".
    const body =
      '"2026-10-05 13:45:47", "1", "https://cdn.example/a.js", "url", "payload_delivery", "js.clearfake", "None", "ClearFake", "", "100"';
    const entries = parseThreatfoxUrls(body);
    expect(entries[0]!.context).toContain('ClearFake');
    expect(entries[0]!.context).not.toContain('None');
  });

  it('falls back to the tag when family and malware are both "None"', () => {
    const body =
      '"2026-10-05 13:45:47", "1", "https://cdn.example/b.js", "url", "payload_delivery", "js.emotet", "None", "None"';
    expect(parseThreatfoxUrls(body)[0]!.context).toContain('js.emotet');
  });

  it('falls back to the bare descriptor when every attribution column is empty', () => {
    const body =
      '"2026-10-05 13:45:47", "1", "https://cdn.example/c.js", "url", "payload_delivery", "None", "None", "None"';
    expect(parseThreatfoxUrls(body)[0]!.context).toBe('ThreatFox payload delivery');
  });
});

describe('parseC2IntelDomains', () => {
  it('parses the #domain,ioc,uri_path layout and skips the header', () => {
    const body = '#domain,ioc,uri_path\n1309673150-86ymvxmhrm.example.com,Possible Cobalt Strike C2 Domain,/g.pixel';
    const entries = parseC2IntelDomains(body);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.value).toBe('1309673150-86ymvxmhrm.example.com');
    expect(entries[0]!.context).toContain('Possible Cobalt Strike C2 Domain');
    expect(entries[0]!.context).toContain('/g.pixel');
  });

  it('lowercases hosts', () => {
    expect(parseC2IntelDomains('Mixed.Case.Example,/x')[0]!.value).toBe('mixed.case.example');
  });
});

describe('parseBotvrijDomains', () => {
  // The trap: upstream emits a CSV header then BARE domains, so the rows are
  // not CSV records and must not be split on commas.
  it('skips the CSV header and parses bare domain rows', () => {
    const body = ['value,decay_sore,value_type,event_id,event_info', 'getcoronavirusalert.com', 'coronaviruss.ir'].join(
      '\n'
    );
    expect(parseBotvrijDomains(body).map((e) => e.value)).toEqual(['getcoronavirusalert.com', 'coronaviruss.ir']);
  });

  it('does not mis-split a domain containing a comma', () => {
    const body = 'value,decay_sore\nfoo.example\nbar.example';
    expect(parseBotvrijDomains(body).every((e) => !e.value.includes(','))).toBe(true);
  });
});

describe('parseSslblJa3', () => {
  it('parses ja3,first_seen,last_seen,family and skips the banner', () => {
    const body =
      '################################################################\n' +
      '# abuse.ch Suricata JA3 Fingerprint Blacklist (CSV)            #\n' +
      '#\n' +
      'b386946a5a44d1ddcc843bc75336dfce,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex';
    const entries = parseSslblJa3(body);
    expect(entries).toHaveLength(1);
    // A JA3 fingerprint is an MD5, so `hash` is the correct kind.
    expect(entries[0]).toMatchObject({ type: 'hash', value: 'b386946a5a44d1ddcc843bc75336dfce' });
    expect(entries[0]!.context).toContain('Dridex');
    expect(entries[0]!.timestamp).toBe('2019-07-27T20:42:54.000Z');
  });

  it('rejects non-32-hex rows', () => {
    expect(parseSslblJa3('zzzz,2017-07-14,2019-07-27,Dridex')).toEqual([]);
  });
});

describe('parsePlainDomainList', () => {
  it('parses bare domain lists and drops comments', () => {
    const body = ['# comment', '007systems.com', '0108.dk', '', 'not a domain!'].join('\n');
    expect(parsePlainDomainList(body).map((e) => e.value)).toEqual(['007systems.com', '0108.dk']);
  });
});

describe('looseDateToIso', () => {
  it('handles every format present in the adopted feeds', () => {
    expect(looseDateToIso('2017-06-20')).toBe('2017-06-20T00:00:00.000Z');
    expect(looseDateToIso('2020/09/04 23:32:24')).toBe('2020-09-04T23:32:24.000Z');
    expect(looseDateToIso('08 February 2026 03:26 PM UTC')).toBe('2026-02-08T15:26:00.000Z');
    expect(looseDateToIso('2026-10-05 13:45:47')).toBe('2026-10-05T13:45:47.000Z');
  });

  it('rejects every month abbreviation at its boundary', () => {
    const months = [
      'January',
      'February',
      'March',
      'April',
      'May',
      'June',
      'July',
      'August',
      'September',
      'October',
      'November',
      'December',
    ];
    months.forEach((mon, i) => {
      expect(looseDateToIso(`08 ${mon} 2026 03:26 PM UTC`), mon).toBe(
        `2026-${String(i + 1).padStart(2, '0')}-08T15:26:00.000Z`
      );
    });
  });

  it('returns undefined for junk', () => {
    expect(looseDateToIso('sometime')).toBeUndefined();
    expect(looseDateToIso('')).toBeUndefined();
  });
});
