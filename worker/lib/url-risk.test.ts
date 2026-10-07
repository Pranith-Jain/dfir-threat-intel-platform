/**
 * Tests for the URL risk engine — TS port of the IntelX Phishing
 * Intelligence Framework. Run via:
 *   npx vitest run worker/lib/url-risk.test.ts
 *
 * The risk-engine expectations are hand-computed against the upstream
 * `Risk_Engine/risk_engine.py` weight tables so a port drift shows up as
 * a failing assertion.
 */
import { describe, it, expect } from 'vitest';
// Was ./url-risk — a byte-identical duplicate nothing imported. Production uses
// the api/src module; test that one instead.
import { analyzeUrlSignals, calculateUrlRisk, computeAgeInDays } from '../../api/src/lib/url-risk';

describe('analyzeUrlSignals — static heuristics (signals.py port)', () => {
  it('clean https URL produces no flags', () => {
    const s = analyzeUrlSignals('https://example.com/path');
    expect(s.flags).toEqual([]);
    expect(s.static_score).toBe(0);
    expect(s.long_url).toBe(false);
    expect(s.has_at_symbol).toBe(false);
    expect(s.punycode).toBe(false);
    expect(s.shortener).toBe(false);
    expect(s.ip_hostname).toBe(false);
    expect(s.non_standard_port).toBe(false);
    expect(s.scheme).toBe('https');
    expect(s.hostname).toBe('example.com');
  });

  it('flags long URLs over 75 chars', () => {
    const long = 'https://example.com/' + 'a'.repeat(80);
    expect(analyzeUrlSignals(long).long_url).toBe(true);
    expect(analyzeUrlSignals(long).flags).toContain('long-url');
  });

  it('detects the @ symbol trick', () => {
    const s = analyzeUrlSignals('https://www.example.com@evil.com/login');
    expect(s.has_at_symbol).toBe(true);
    expect(s.flags).toContain('at-symbol');
  });

  it('flags punycode (IDN) hostnames', () => {
    const s = analyzeUrlSignals('https://xn--80ak6aa92e.com/verify');
    expect(s.punycode).toBe(true);
    expect(s.flags).toContain('punycode-host');
  });

  it('detects known URL shorteners', () => {
    for (const short of ['bit.ly', 't.co', 'goo.gl', 'cutt.ly']) {
      const s = analyzeUrlSignals(`https://${short}/abc123`);
      expect(s.shortener).toBe(true);
      expect(s.shortener_name).toBe(short);
      expect(s.flags).toContain('url-shortener');
    }
  });

  it('does not flag a domain merely containing a shortener string', () => {
    const s = analyzeUrlSignals('https://bitly.com/not-a-shortener');
    expect(s.shortener).toBe(false);
  });

  it('flags IP-literal hostnames', () => {
    const s = analyzeUrlSignals('http://192.168.1.1:8080/admin');
    expect(s.ip_hostname).toBe(true);
    expect(s.non_standard_port).toBe(true);
    expect(s.port).toBe(8080);
    expect(s.scheme).toBe('http');
    expect(s.flags).toContain('ip-hostname');
    expect(s.flags).toContain('nonstandard-port');
  });

  it('treats 80/443 as standard ports', () => {
    expect(analyzeUrlSignals('https://example.com:443/x').non_standard_port).toBe(false);
    expect(analyzeUrlSignals('http://example.com:80/x').non_standard_port).toBe(false);
  });

  it('flags subdomain bloat (4+ labels)', () => {
    const s = analyzeUrlSignals('https://a.b.c.d.example.com/login');
    expect(s.many_subdomains).toBe(true);
    expect(s.subdomain_count).toBe(6);
  });

  it('collects suspicious keywords', () => {
    const s = analyzeUrlSignals('https://example.com/verify/password/login');
    expect(s.suspicious_keywords).toEqual(expect.arrayContaining(['verify', 'password', 'login']));
    expect(s.flags).toContain('suspicious-keywords');
  });

  it('does not count ipv6 hextets as subdomains', () => {
    const s = analyzeUrlSignals('http://[2001:db8::1]:8080/x');
    expect(s.ip_hostname).toBe(true);
    expect(s.subdomain_count).toBe(0);
    expect(s.many_subdomains).toBe(false);
  });

  it('caps static_score at 10', () => {
    const worst = `http://${'a'.repeat(90)}@xn--80ak6aa92e.com:8443/login/verify/password/payment/account`;
    const s = analyzeUrlSignals(worst);
    expect(s.static_score).toBeLessThanOrEqual(10);
    expect(s.flags.length).toBeGreaterThanOrEqual(6);
  });
});

describe('calculateUrlRisk — engine (risk_engine.py port)', () => {
  it('returns a zero-risk verdict when no provider contributed', () => {
    const r = calculateUrlRisk({});
    expect(r.risk_score).toBe(0);
    expect(r.verdict).toBe('No Strong Threat Evidence');
    expect(r.confidence).toBe(0);
    expect(r.evidence).toEqual(['No provider contributed a positive risk-scoring indicator.']);
    expect(r.provider_status).toEqual({
      virustotal: false,
      urlscan: false,
      abuseipdb: false,
      whois: false,
      google_safe_browsing: false,
    });
  });

  it('scores VT malicious >= 20 as 35 points (Suspicious band, conf 62)', () => {
    const r = calculateUrlRisk({
      virustotal: { malicious: 21, suspicious: 3, total_vendors: 70 },
    });
    expect(r.risk_score).toBe(35);
    expect(r.score_breakdown.virustotal).toBe(35);
    expect(r.verdict).toBe('Suspicious'); // 35–59 band
    expect(r.confidence).toBe(62); // coverage 8 + agreement 50 + strength 3.5
    expect(r.evidence[0]).toContain('+35 VirusTotal');
    expect(r.evidence[0]).toContain('24/70');
    expect(r.positive_findings[0]).toContain('21 malicious');
  });

  it('scores VT malicious bands 30/22/12 and suspicious-only 7', () => {
    expect(calculateUrlRisk({ virustotal: { malicious: 12 } }).risk_score).toBe(30);
    expect(calculateUrlRisk({ virustotal: { malicious: 5 } }).risk_score).toBe(22);
    expect(calculateUrlRisk({ virustotal: { malicious: 1 } }).risk_score).toBe(12);
    expect(calculateUrlRisk({ virustotal: { suspicious: 1 } }).risk_score).toBe(7);
    expect(calculateUrlRisk({ virustotal: { malicious: 0, suspicious: 0 } }).risk_score).toBe(0);
  });

  it('adds Google Safe Browsing 30 points with threat types', () => {
    const r = calculateUrlRisk({
      google_safe_browsing: {
        detected: true,
        matches: [{ threatType: 'MALWARE' }, { threatType: 'SOCIAL_ENGINEERING' }],
      },
    });
    expect(r.risk_score).toBe(30);
    expect(r.verdict).toBe('Low Risk');
    expect(r.evidence[0]).toContain('MALWARE, SOCIAL_ENGINEERING');
  });

  it('urlscan malicious verdict adds 22 points; brand impersonation +5', () => {
    const base = calculateUrlRisk({ urlscan: { verdict: 'malicious' } });
    expect(base.risk_score).toBe(22);

    const imp = calculateUrlRisk({
      urlscan: { verdict: 'malicious', brand: 'PayPal', page_domain: 'evil-verify.com' },
    });
    expect(imp.risk_score).toBe(27);
    expect(imp.evidence.some((e) => e.includes('brand impersonation'))).toBe(true);

    // Brand matching the investigated domain → informational, not +5.
    const legit = calculateUrlRisk({
      urlscan: { brand: 'example', page_domain: 'www.example.com' },
    });
    expect(legit.risk_score).toBe(0);
  });

  it('urlscan domain age <= 30 days adds 5; redirects >= 4 add 3', () => {
    const age = calculateUrlRisk({ urlscan: { domain_age_days: 12 } });
    expect(age.risk_score).toBe(5);

    const redir = calculateUrlRisk({ urlscan: { redirects: ['a', 'b', 'c', 'd'] } });
    expect(redir.risk_score).toBe(3);

    const old = calculateUrlRisk({ urlscan: { domain_age_days: 90 } });
    expect(old.risk_score).toBe(0);
  });

  it('AbuseIPDB confidence bands 18/13/8/3 and tor +2', () => {
    expect(calculateUrlRisk({ abuseipdb: { abuse_confidence: 80 } }).risk_score).toBe(18);
    expect(calculateUrlRisk({ abuseipdb: { abuse_confidence: 60 } }).risk_score).toBe(13);
    expect(calculateUrlRisk({ abuseipdb: { abuse_confidence: 30 } }).risk_score).toBe(8);
    expect(calculateUrlRisk({ abuseipdb: { abuse_confidence: 5 } }).risk_score).toBe(3);
    const tor = calculateUrlRisk({ abuseipdb: { abuse_confidence: 0, is_tor: true } });
    expect(tor.risk_score).toBe(2);
  });

  it('WHOIS domain age bands 20/15/10/5', () => {
    const fresh = calculateUrlRisk({ whois: { creation_date: isoDaysAgo(3) } });
    expect(fresh.risk_score).toBe(20);
    expect(fresh.domain_age_days).toBe(3);
    expect(fresh.evidence[0]).toContain('3 days old');

    expect(calculateUrlRisk({ whois: { creation_date: isoDaysAgo(20) } }).risk_score).toBe(15);
    expect(calculateUrlRisk({ whois: { creation_date: isoDaysAgo(60) } }).risk_score).toBe(10);
    expect(calculateUrlRisk({ whois: { creation_date: isoDaysAgo(120) } }).risk_score).toBe(5);

    const old = calculateUrlRisk({ whois: { creation_date: '2010-01-01T00:00:00Z' } });
    expect(old.risk_score).toBe(0);
    expect(old.informational_findings.some((f) => f.includes('domain age'))).toBe(true);
  });

  it('parses WHOIS date formats: ISO, dotted, named-month, bare date', () => {
    expect(computeAgeInDays('2010-01-01T00:00:00Z')).not.toBeNull();
    expect(computeAgeInDays('2010-01-01')).not.toBeNull();
    expect(computeAgeInDays('2010.01.01')).not.toBeNull();
    expect(computeAgeInDays('01-Jan-2010')).not.toBeNull();
    expect(computeAgeInDays('not-a-date')).toBeNull();
    expect(computeAgeInDays(undefined)).toBeNull();
  });

  it('full critical profile caps at 100 and flags Critical Risk', () => {
    const r = calculateUrlRisk({
      virustotal: { malicious: 25, suspicious: 5, total_vendors: 80 },
      google_safe_browsing: { detected: true, matches: [{ threatType: 'SOCIAL_ENGINEERING' }] },
      urlscan: { verdict: 'malicious' },
      abuseipdb: { abuse_confidence: 90, total_reports: 12 },
      whois: { creation_date: isoDaysAgo(2), registrar: 'Namecheap' },
    });
    expect(r.risk_score).toBe(100); // 35+30+22+18+20 = 125 → capped
    expect(r.verdict).toBe('Critical Risk');
    expect(r.confidence).toBe(100);
    expect(r.evidence.length).toBe(5);
    expect(r.score_breakdown).toEqual({
      virustotal: 35,
      urlscan: 22,
      abuseipdb: 18,
      whois: 20,
      google_safe_browsing: 30,
    });
    expect(r.recommendation).toContain('Block the URL immediately');
  });

  it('verdict bands: High >= 60, Suspicious >= 35, Low >= 15', () => {
    const high = calculateUrlRisk({
      virustotal: { malicious: 20 },
      google_safe_browsing: { detected: true },
      abuseipdb: { abuse_confidence: 80 },
    });
    expect(high.risk_score).toBe(83);
    expect(high.verdict).toBe('Critical Risk');

    const susp = calculateUrlRisk({ virustotal: { malicious: 10 } }); // 30 → Low
    expect(susp.verdict).toBe('Low Risk');
    expect(calculateUrlRisk({ virustotal: { malicious: 20 } }).verdict).toBe('Suspicious'); // 35
    expect(
      calculateUrlRisk({
        virustotal: { malicious: 20 },
        google_safe_browsing: { detected: true },
      }).verdict
    ).toBe('High Risk'); // 65

    const highRisk = calculateUrlRisk({
      virustotal: { malicious: 20 },
      google_safe_browsing: { detected: true },
    });
    expect(highRisk.risk_score).toBe(65);
    expect(highRisk.verdict).toBe('High Risk');
  });

  it('confidence reflects coverage + agreement + strength', () => {
    // All 5 providers available, only VT positive: 40 + 10 + 3.5 → 54 (round)
    const r = calculateUrlRisk({
      virustotal: { malicious: 5, suspicious: 0 },
      google_safe_browsing: { detected: false },
      urlscan: { result_count: 0 },
      abuseipdb: { abuse_confidence: 0, total_reports: 0 },
      whois: { creation_date: '2010-01-01T00:00:00Z', registrar: 'Namecheap' },
    });
    expect(r.provider_status).toEqual({
      virustotal: true,
      urlscan: true,
      abuseipdb: true,
      whois: true,
      google_safe_browsing: true,
    });
    expect(r.risk_score).toBe(22);
    expect(r.confidence).toBe(52); // 40 coverage + 10 agreement + 2.2 strength
  });

  it('treats explicit error-status payloads as unavailable', () => {
    const r = calculateUrlRisk({
      virustotal: { status: 'no api key' },
      whois: { status: 'error' },
    });
    expect(r.provider_status.virustotal).toBe(false);
    expect(r.provider_status.whois).toBe(false);
    expect(r.verdict).toBe('No Strong Threat Evidence');
  });
});

function isoDaysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}
