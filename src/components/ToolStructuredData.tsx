/**
 * Structured data (JSON-LD) for CRUCIBLE (DFIR toolkit), PANOPTICON
 * (Threat Intel platform), and the Domain Recon Scanner. Helps search
 * engines understand the page structure and content.
 */

export function DfirStructuredData(): JSX.Element {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'CRUCIBLE',
    alternateName: 'DFIR & Security Toolkit',
    description:
      'CRUCIBLE (DFIR & Security Toolkit) is a free, browser-side collection of 125+ utilities for incident response, digital forensics, and detection engineering. IOC checks, CVE triage, rule conversion, and more.',
    url: 'https://pranithjain.qzz.io/dfir',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web Browser',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
    featureList: [
      'IOC & Hash Checker - 60+ sources',
      'Phishing Analysis',
      'CVE Prioritizer - CVSS + EPSS + KEV',
      'Detection Rule Converter - Sigma ↔ KQL ↔ SPL ↔ YARA',
      'Email Defense - SPF/DKIM/DMARC audit',
      'YARA Workbench',
      'Malware Analyzer',
      'STIX 2.1 Viewer',
      'MITRE ATT&CK Matrix',
    ],
    author: {
      '@type': 'Person',
      '@id': 'https://pranithjain.qzz.io/#person',
      name: 'Pranith Jain',
      url: 'https://pranithjain.qzz.io',
      sameAs: ['https://github.com/Pranith-Jain', 'https://x.com/Npj8448'],
    },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema).replace(/</g, '\\u003c') }}
    />
  );
}

export function ThreatIntelStructuredData(): JSX.Element {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'PANOPTICON',
    alternateName: 'Threat Intelligence Platform',
    description:
      'PANOPTICON (Threat Intelligence Platform) is a free, live CTI surface covering ransomware activity, threat actors, IOCs, CVEs, dark-web monitoring, and social-media signals from 30-plus feeds.',
    url: 'https://pranithjain.qzz.io/threatintel',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web Browser',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
    featureList: [
      'Live ransomware leak monitoring',
      'Threat actor knowledge base',
      'IOC enrichment and cross-correlation',
      'CVE tracking with CISA KEV',
      'Dark web monitoring',
      'Social media intelligence',
      'Global threat pulse - 3D globe',
      'Daily threat briefings',
    ],
    author: {
      '@type': 'Person',
      '@id': 'https://pranithjain.qzz.io/#person',
      name: 'Pranith Jain',
      url: 'https://pranithjain.qzz.io',
      sameAs: ['https://github.com/Pranith-Jain', 'https://x.com/Npj8448'],
    },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema).replace(/</g, '\\u003c') }}
    />
  );
}

export function RadarStructuredData(): JSX.Element {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'Domain Recon Scanner',
    description:
      'Free, browser-driven recon: HTTP headers, redirect chains, DNS, JavaScript inventory, exposed endpoints, security headers, and a 0-100 security score.',
    url: 'https://pranithjain.qzz.io/radar',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web Browser',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
    featureList: [
      'HTTP header and redirect chain capture',
      'Server fingerprint and content-type detection',
      'JavaScript file inventory with endpoint extraction',
      'Security header scoring (HSTS, CSP, X-Frame-Options)',
      'Per-colo scan result cache for fast revisits',
      'Shareable scan report URL',
    ],
    author: {
      '@type': 'Person',
      name: 'Pranith Jain',
    },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema).replace(/</g, '\\u003c') }}
    />
  );
}
