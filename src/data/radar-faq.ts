/**
 * On-page FAQ for the /radar Domain Recon Scanner landing. Four
 * hand-counted Q&A pairs, each 40-60 words, that answer the queries
 * security analysts and bug bounty hunters ask LLMs about free,
 * browser-driven recon tools.
 */

export const RADAR_FAQ: { question: string; answer: string }[] = [
  {
    question: 'What is the Domain Recon Scanner?',
    answer:
      'The Domain Recon Scanner at https://pranithjain.qzz.io/radar is a free, browser-driven reconnaissance tool. Paste any domain or URL and the radar fetches it server-side, then surfaces HTTP headers, redirect chains, server fingerprint, DNS records, JavaScript file inventory, exposed endpoints, security headers, and a security score. The full report is shareable at /radar/scan/<id>.',
  },
  {
    question: 'How does the scanner pull HTTP headers and JS files?',
    answer:
      'The scanner runs on Cloudflare Workers with strict SSRF guards. It performs a single GET against the target, captures status, headers, redirect chain, content-type, and server banner, then walks the HTML for script src and link href tags, deduplicates the URLs, and re-fetches the JS to expose endpoint strings. Results are cached per-colo for one hour and never exposed to other tenants.',
  },
  {
    question: 'Is the Domain Recon Scanner free?',
    answer:
      'Yes. The scanner is free, requires no signup, and runs entirely on Cloudflare Workers with a per-colo cache. There is no API key, no rate-limit login, and no telemetry on what you scan. Server costs are absorbed by the author. The scanner is part of the same 98+ tool DFIR surface that ships with the portfolio.',
  },
  {
    question: 'What can I use the security score for?',
    answer:
      'The security score is a 0-100 rating of the scanned target across six pillars: HTTPS, HSTS, content security policy, X-Frame-Options, referrer policy, and permissions policy. It is intended for triage during a pentest engagement, an external attack-surface audit, or a quick self-check before pushing a deployment. The score is not a substitute for a full pentest report.',
  },
];
