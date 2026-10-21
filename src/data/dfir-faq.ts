/**
 * On-page FAQ for the DFIR landing page (/dfir). Four hand-counted Q&A pairs,
 * each 40-60 words, that answer the queries AI engines most often field about
 * CRUCIBLE (the DFIR brand). The same array is consumed twice:
 *   1. `FaqStructuredData` in DFIR.tsx emits the matching FAQPage JSON-LD.
 *   2. A visible <details> block renders the same answers to humans.
 * One source of truth, so the schema can never drift from the on-page text.
 */

export const DFIR_FAQ: { question: string; answer: string }[] = [
  {
    question: 'What is CRUCIBLE (DFIR & Security Toolkit)?',
    answer:
      'CRUCIBLE is a free, browser-side collection of 98+ utilities for incident response, digital forensics, and detection engineering. It bundles IOC enrichment across 60+ sources, CVE triage with CVSS-EPSS-KEV scoring, Sigma-to-KQL-SPL-YARA rule conversion, SPF-DKIM-DMARC audits, a STIX 2.1 workbench, and a MITRE ATT&CK matrix. Everything runs in your browser, nothing leaves your machine.',
  },
  {
    question: 'How does CRUCIBLE work?',
    answer:
      'Open a tool, paste an IOC, hash, URL, rule, or email header, and the page calls public APIs directly from your browser. CRUCIBLE aggregates verdicts, normalises output, and renders results inline. There is no account, no proxy, no telemetry. Results arrive in seconds because the page fans out to all sources in parallel.',
  },
  {
    question: 'Is CRUCIBLE free?',
    answer:
      'Yes. CRUCIBLE is free, with no signup, no rate-limit login, and no data egress from your browser. It runs on Cloudflare Workers for the static surface and a small set of cached feeds. Each per-tool call hits the public API of the underlying source. A sponsorship page covers hosting and is optional, no credit card, no trial clock.',
  },
  {
    question: 'CRUCIBLE vs VirusTotal?',
    answer:
      'VirusTotal aggregates 70-plus antivirus engines plus a sandbox and is the strongest single-sample verdict service available. CRUCIBLE is not a VirusTotal replacement; it is a browser-side companion focused on the analyst workflow around a sample. Use VirusTotal for hash-based verdicts. Use CRUCIBLE for cross-source IOC correlation, rule conversion, and email-header triage.',
  },
];
