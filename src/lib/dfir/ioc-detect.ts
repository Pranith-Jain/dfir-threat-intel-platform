/**
 * Cheap "does this blob look like it contains IOCs?" check.
 *
 * Used by sister-tool pipes (PowerShell Deobfuscator, Decoder, Phishing
 * Analyzer) to decide whether to surface the "send to IOC Extractor"
 * button. Intentionally permissive - false positives are cheap (the
 * button shows but the extractor finds nothing, no harm done), false
 * negatives are expensive (analyst misses a usable pivot).
 *
 * The actual extraction lives in IocExtractor - this is just a yes/no
 * gate for showing the CTA.
 */
export function hasIocCandidates(text: string): boolean {
  if (!text) return false;
  if (/\bhttps?:\/\//i.test(text)) return true; // URLs
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text)) return true; // IPv4
  if (/\b[a-f0-9]{32,64}\b/i.test(text)) return true; // MD5/SHA-1/SHA-256
  if (/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:[a-z]{2,63})\b/i.test(text)) return true; // domains
  return false;
}

/**
 * Single-indicator type detection - strict, returns one canonical IocType
 * or null. Used by the Cmd+K palette and the /dfir landing's paste-to-
 * dispatch input. Regex order is precedence (more specific first).
 */

export type IocType =
  | 'cve'
  | 'mitre-technique'
  | 'mitre-group'
  | 'asn'
  | 'url'
  | 'hash-md5'
  | 'hash-sha1'
  | 'hash-sha256'
  | 'email'
  | 'btc'
  | 'ip'
  | 'ipv6'
  | 'domain';

export interface DetectedIoc {
  type: IocType;
  value: string;
}

export function detectIoc(raw: string): DetectedIoc | null {
  const v = raw.trim();
  if (!v) return null;
  if (/^CVE-\d{4}-\d{4,7}$/i.test(v)) return { type: 'cve', value: v.toUpperCase() };
  if (/^T\d{4}(?:\.\d{3})?$/i.test(v)) return { type: 'mitre-technique', value: v.toUpperCase() };
  if (/^G\d{4}$/i.test(v)) return { type: 'mitre-group', value: v.toUpperCase() };
  if (/^AS\d{1,7}$/i.test(v)) return { type: 'asn', value: v.toUpperCase() };
  if (/^https?:\/\/\S+$/i.test(v)) return { type: 'url', value: v };
  if (/^[a-fA-F0-9]{32}$/.test(v)) return { type: 'hash-md5', value: v.toLowerCase() };
  if (/^[a-fA-F0-9]{40}$/.test(v)) return { type: 'hash-sha1', value: v.toLowerCase() };
  if (/^[a-fA-F0-9]{64}$/.test(v)) return { type: 'hash-sha256', value: v.toLowerCase() };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) return { type: 'email', value: v.toLowerCase() };
  if (/^(?:1|3)[a-zA-HJ-NP-Z0-9]{25,34}$|^bc1[a-z0-9]{25,87}$/.test(v)) return { type: 'btc', value: v };
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    const octets = v.split('.').map(Number);
    if (octets.every((n) => n >= 0 && n <= 255)) return { type: 'ip', value: v };
  }
  if (/^[0-9a-fA-F:]+$/.test(v) && (v.match(/:/g)?.length ?? 0) >= 2) return { type: 'ipv6', value: v.toLowerCase() };
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(v)) {
    return { type: 'domain', value: v.toLowerCase() };
  }
  return null;
}

export const IOC_TYPE_LABEL: Record<IocType, string> = {
  cve: 'CVE',
  'mitre-technique': 'MITRE technique',
  'mitre-group': 'MITRE group',
  asn: 'ASN',
  url: 'URL',
  'hash-md5': 'MD5 hash',
  'hash-sha1': 'SHA-1 hash',
  'hash-sha256': 'SHA-256 hash',
  email: 'Email',
  btc: 'BTC address',
  ip: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
};

export interface Pivot {
  label: string;
  desc: string;
  path: string;
  external?: true;
}

/**
 * Pivot tools for a detected IOC - the 2-3 most useful destinations
 * per IOC type. The Cmd+K palette has the long tail; this is the
 * landing's quick-paste dispatcher.
 */
export function getIocPivots(ioc: DetectedIoc): Pivot[] {
  const enc = encodeURIComponent(ioc.value);
  const pivots: Pivot[] = [];

  if (ioc.type === 'cve') {
    pivots.push({
      label: 'CVE Lookup',
      desc: 'NVD + CISA KEV + heuristic actor scanning',
      path: `/dfir/cve?id=${enc}`,
    });
    pivots.push({
      label: 'CVE list',
      desc: 'Filter the platform CVE list - actor pills + KEV flags inline',
      path: `/threatintel/cve-list?q=${enc}`,
    });
    return pivots;
  }
  if (ioc.type === 'mitre-technique') {
    pivots.push({
      label: 'MITRE technique',
      desc: 'ATT&CK matrix scoped to this technique',
      path: `/threatintel/mitre?id=${enc}`,
    });
    return pivots;
  }
  if (ioc.type === 'mitre-group') {
    pivots.push({
      label: 'MITRE Group profile',
      desc: 'Open ATT&CK Group page - techniques, software, references',
      path: `https://attack.mitre.org/groups/${enc}/`,
      external: true,
    });
    return pivots;
  }
  if (ioc.type === 'asn') {
    pivots.push({
      label: 'ASN Lookup',
      desc: 'Routes + prefixes + neighbours',
      path: `/dfir/asn?asn=${enc}`,
    });
    return pivots;
  }
  if (ioc.type === 'email') {
    pivots.push({
      label: 'Breach check',
      desc: 'Have-I-Been-Pwned exposure for this address',
      path: `/dfir/breach?email=${enc}`,
    });
    return pivots;
  }
  // Network indicators + hashes - IOC Checker is universal primary pivot.
  pivots.push({
    label: 'IOC Checker',
    desc: `Run ${IOC_TYPE_LABEL[ioc.type]} through 20+ providers (VT, AbuseIPDB, OTX, GreyNoise, threatfox, urlhaus, …)`,
    path: `/dfir/ioc-check?indicator=${enc}`,
  });

  if (ioc.type === 'ip' || ioc.type === 'ipv6' || ioc.type === 'domain' || ioc.type === 'url') {
    pivots.push({
      label: 'Correlation lookup',
      desc: 'Cross-source: is this in 2+ feeds? Confidence + per-feed attribution',
      // IocCorrelation owns the ?q= indicator filter; /threatintel/correlation
      // is a different page (sector cross-correlate) with no query box.
      path: `/threatintel/iocs/correlation?q=${enc}`,
    });
  }

  if (ioc.type === 'ip' || ioc.type === 'ipv6') {
    pivots.push({
      label: 'IP Geolocation',
      desc: 'Country / city / ISP / org',
      path: `/dfir/ioc-investigate?indicator=${enc}`,
    });
  } else if (ioc.type === 'domain') {
    pivots.push({
      label: 'Domain Lookup',
      desc: 'WHOIS + DNS records + subdomains + cert transparency',
      path: `/dfir/domain-investigator?domain=${enc}`,
    });
    pivots.push({
      label: 'Cert Search',
      desc: 'crt.sh certificate transparency log lookup',
      path: `/dfir/cert-search?q=${enc}`,
    });
  } else if (ioc.type === 'url') {
    pivots.push({
      label: 'URL Preview',
      desc: 'Server-side fetch + screenshot + headers - safe to inspect',
      path: `/dfir/url-preview?url=${enc}`,
    });
    pivots.push({
      label: 'Wayback CDX',
      desc: 'Archive.org historical captures of this URL',
      path: `/dfir/wayback?url=${enc}`,
    });
  } else if (ioc.type.startsWith('hash-')) {
    pivots.push({
      label: 'File Analysis',
      desc: 'Hash lookup across malware-sample sources',
      // IOC Investigator's checker consumes ?indicator= for every type incl. hashes.
      path: `/dfir/ioc-investigate?indicator=${enc}`,
    });
  }

  return pivots;
}
