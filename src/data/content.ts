import { PORTFOLIO_ORIGIN } from '../lib/surface';

/**
 * Canonical URL of the platform repo (formerly `Pranith-Jain.github.io`).
 * The project cards below, the tool-app chrome, and the README all need this
 * string; keeping it in one const means a future rename is a one-line change
 * instead of a grep across `src/`, `api/`, and `scripts/`.
 */
export const PLATFORM_REPO_URL = 'https://github.com/Pranith-Jain/dfir-threat-intel-platform';

export const personalInfo = {
  name: 'Pranith Jain',
  // Long form, used in headlines, SEO, and structured-data schema.
  title:
    'Associate Cyber Security Analyst: CERT Threat and Vulnerability Intelligence Group, AI Threats & Security Automation',
  // Short form, used in tight UI like the profile card to avoid overflow.
  shortTitle: 'Associate Cyber Security Analyst · Capgemini CERT',
  headline: 'Building at the intersection of AI, threat intelligence, and edge-native security tooling.',
  // Plain-text bio. Used as-is by StructuredData (SEO schema). The Hero
  // renders this same string. Keep it short enough to read: this is the
  // hero's only prose block, and the previous 62-word single-sentence
  // version set as 7 lines on desktop and 9 on mobile, started mid-sentence
  // in lowercase, and stacked two clauses behind a colon splice. It also
  // restated "60+ tools" and "free to use", both of which the stat block
  // directly above and the toolkit section directly below already carry.
  // Three short sentences, no em dashes, no numbers to repeat.
  description:
    'Cyber security analyst on the Capgemini CERT Threat and Vulnerability Intelligence group. I research AI-driven threats: the models, the agents, and the infrastructure that carries them. The rest of my time goes into the tooling I wished I had on shift.',
  currentFocus: 'AI threats, AI threat intelligence, and autonomous SOC workflows',
  currentlyLearning: 'AI red-teaming & autonomous threat hunting',
  availability: 'Open for Consultations & Strategy Calls',
  email: 'hello@pranithjain.qzz.io',
  phone: '+91 8310386578',
  calendlyUrl: 'https://calendly.com/pranithjain84/30min',
  linkedInUrl: 'https://www.linkedin.com/in/pranithjain',
  githubUrl: 'https://github.com/Pranith-Jain',
  resumeUrl: 'https://pranithjain.qzz.io/resume.docx',
  featuredUrl: 'https://featured.com/p/pranith-jain',
};

/**
 * Hero stats strip. Three numbers, each anchored to a hardened past
 * result rather than a target metric. The "Response Time <75min" entry
 * used to live here too; dropped because (a) it's a moving target
 * rather than a fixed achievement, and (b) the platform's live
 * /threatintel surface now carries the up-to-the-minute response
 * signal in the LiveSignalStrip below the hero, which does the same
 * job with real numbers.
 *
 * Type is explicit (not inferred) so consumers that branch on the
 * optional `suffix` / `progress` fields still typecheck - those fields
 * were only used by the dropped Response Time stat, but the conditional
 * rendering code stays in place for future stats that might want them.
 */
export interface StatItem {
  label: string;
  value: string;
  /** Used by the old Response Time stat ("<75" + suffix "min"). Kept
   *  optional so a future stat can re-use the pattern. */
  suffix?: string;
  target?: number;
  description: string;
  badge?: string;
  /** Animated progress bar percentage; only used when `progress` is set. */
  progress?: number;
  /** Link to verify this stat (e.g., /dfir/dashboard). */
  source?: string;
  /** Label for the source link. */
  sourceLabel?: string;
}
export const stats: StatItem[] = [
  {
    label: 'Incidents Investigated',
    value: '250+',
    target: 250,
    description: 'Phishing, BEC, and malware incidents investigated and resolved.',
    badge: '90%+ Remediation Success',
    source: '/dfir/ioc-check',
    sourceLabel: 'verified via IOC checker',
  },
  {
    label: 'Domains Secured',
    value: '1300+',
    target: 1300,
    description: 'Across 150+ startup portfolios',
    badge: '98%+ Auth Alignment',
    source: '/dfir/email-defense',
    sourceLabel: 'verified via Email Defense',
  },
  {
    label: 'Inboxes Monitored',
    value: '2700+',
    target: 2700,
    description: 'Real-time email infrastructure visibility',
    badge: 'Automated Dashboard',
    source: '/dfir',
    sourceLabel: 'live count',
  },
];

export const skills = [
  {
    title: 'Email Security & Deliverability',
    icon: 'Mail',
    items: [
      'SPF / DKIM / DMARC / BIMI',
      'Phishing & spoofing defense',
      'BEC (Business Email Compromise) detection',
      'Email header & forensic analysis',
      'Sender reputation monitoring & response',
      'Proofpoint & Google Workspace',
    ],
  },
  {
    title: 'Threat Intelligence',
    icon: 'Search',
    items: [
      'Threat hunting & intel operations',
      'MITRE ATT&CK framework mapping',
      'IoC enrichment & correlation',
      'CVE correlation & threat actor tracking',
      'Dark web monitoring & OSINT',
      'Email-borne threat analysis',
    ],
  },
  {
    title: 'Cyber Criminology & OSINT',
    icon: 'Users',
    items: [
      'Advanced Digital Footprinting',
      'Fraud, abuse, and actor profiling',
      'Social engineering risk analysis',
      'Case & entity investigations',
    ],
  },
  {
    title: 'Email Threat Response',
    icon: 'Shield',
    items: [
      'Phishing triage & abuse response',
      'Malware payload analysis & sandboxing',
      'Alert correlation & incident workflows',
      'SOC investigations & escalation',
      'Domain abuse prevention & takedowns',
    ],
  },
  {
    title: 'Cloud Identity Security',
    icon: 'Cloud',
    items: [
      'IAM design & Zero Trust',
      'Identity governance & access reviews',
      'SSO, MFA, and conditional access',
      'NHI security & threat detection',
      'Cloud directory hardening (GCP/AWS/Azure)',
    ],
  },
  {
    title: 'AI for Security & Automation',
    icon: 'Zap',
    items: [
      'n8n workflow automation & MCP frameworks',
      'AI for security detection & analysis',
      'AI security & prompt injection defense',
      'Security automation playbooks',
      'NHI security testing & integration',
    ],
  },
];

export const companies = [
  'Alphasearch',
  'BlendHealth',
  'Axolotl Biosciences',
  'Blue Vision Capital',
  'MoneyVerse',
  'Doctor Assistant',
  'HealthSpectra AI',
  'Query Health',
  'Carbon Neutral Homes',
  'VoltPath',
  'Sentient Trader',
  'SwyftFin',
];

export const experiences = [
  {
    title: 'Associate Cyber Security Analyst, CERT Threat and Vulnerability Intelligence Group',
    company: 'Capgemini',
    location: 'India',
    period: 'Sep 2026 - Present',
    badge: 'AI Automation • AI Threat Intel • Autonomous Workflows',
    sections: [
      {
        title: 'AI Automation & Autonomous Workflows',
        icon: 'Zap',
        items: [
          'Building AI automation and autonomous agentic workflows for the Computer Emergency Response Team: tooling and technology implementations that take repeatable triage, enrichment, and reporting work off the analyst critical path.',
        ],
      },
      {
        title: 'AI Threat Intelligence & Hunting',
        icon: 'Search',
        items: [
          'Hunting and researching AI-driven threats: AI-enabled attack tooling, LLM abuse, and agent containment failures. Mapping the emerging AI attack surface and feeding findings back into detection and threat intelligence.',
        ],
      },
      {
        title: 'AI Security',
        icon: 'Shield',
        items: [
          'Working AI security for the Threat and Vulnerability Intelligence group: vulnerability triage in an enterprise CERT context, AI-assisted detection engineering, and threat intel pipelines covering both traditional and AI-specific threat vectors.',
        ],
      },
    ],
  },
  {
    title: 'IT Support Specialist',
    company: 'Qubit Capital',
    location: 'Remote',
    period: 'Jul 2024 - Jul 2026',
    badge: '250+ Incidents • <75min Response',
    sections: [
      {
        title: 'Email Security Operations',
        icon: 'Mail',
        items: [
          'Hardened email authentication (SPF, DKIM, DMARC) across 1,300+ domains for 150+ portfolio startups, achieving 98%+ authentication alignment and reducing spoofing incidents by 60% within six months.',
        ],
      },
      {
        title: 'Infrastructure Monitoring Dashboard',
        icon: 'Monitor',
        items: [
          'Developed a real-time infrastructure monitoring dashboard delivering live visibility across 1,300+ domains and 2,700+ inboxes, replacing a two-hour manual daily health-check process.',
        ],
      },
      {
        title: 'IOC Hunting & Detection Engineering',
        icon: 'Search',
        items: [
          'Conducted IOC/IOA indicator hunting across 250+ phishing, BEC, and malware incidents triaging with VirusTotal, tri.ge, Hunt.io, SOCRadar, and IBM X-Force; extracting indicators across sender IPs, domains, and file hashes; and writing YARA/Sigma rules sustaining a 90%+ remediation rate and reducing false positives by 25%.',
        ],
      },
      {
        title: 'SOC Automation',
        icon: 'Zap',
        items: [
          'Built n8n SOAR pipelines automating phishing triage, IOC enrichment, and email blocking, cutting mean incident response time from 4 hours to under 75 minutes across high-volume alert queues.',
        ],
      },
      {
        title: 'Threat Intelligence Pipelines',
        icon: 'FileText',
        items: [
          'Engineered MCP-based threat intelligence pipelines correlating CVEs, adversary TTPs, and OSINT indicators, and mapped campaign techniques to MITRE ATT&CK to shift team posture from reactive ticket-closing to proactive threat profiling.',
        ],
      },
      {
        title: 'Domain Abuse Monitoring',
        icon: 'Shield',
        items: [
          'Hunted and dismantled 30+ lookalike-domain and phishing URL campaigns, shrinking the portfolio attack surface by 40%, by conducting domain threat hunting with Webamon, WHOIS, and Cloudflare RDAP to trace attacker infrastructure and identify malicious patterns before user impact.',
        ],
      },
    ],
  },
  {
    title: 'Junior Support Engineer',
    company: 'UnifyCX',
    location: 'Mysore',
    period: 'Sep 2023 - Jul 2024',
    items: [
      'Pulled 200+ enterprise domains back to 95% inbox placement after IP blacklisting and weak SMTP auth had tanked delivery. Failures dropped 40%+ once the auth posture was clean.',
      'Cleaned 60+ web assets: malware removal, WAF tuning, XSS hardening. 98% of the cases closed first-pass with no regression.',
      'Automated SSL/TLS renewals for 300+ domains. The renewal-day outages we used to firefight stopped happening.',
    ],
  },
  {
    title: 'Associate Software Developer',
    company: 'TekWorks',
    location: 'Vijayawada, India',
    period: 'Mar 2023 - Sep 2023',
    items: [
      'Built "Arogya", a hospital management system. The administrative team had been on paper-and-Excel for years, so patient-record lookup time was the headline metric.',
      'Wrote the responsive front-end and the REST APIs underneath it. Appointment scheduling and billing were the modules I owned end-to-end.',
    ],
  },
  {
    title: 'AIML Intern',
    company: 'AiROBOSOFT',
    location: 'Remote',
    period: 'Jul 2022 - Aug 2022',
    items: [
      'Trained predictive-analytics models in Python with Scikit-learn and Pandas. First exposure to the gap between a notebook that works and a model that ships.',
    ],
  },
];

export const certifications = {
  core: [
    { title: 'Proofpoint Certified AI Agent Security Specialist', issuer: 'Proofpoint', year: '2026', featured: true },
    { title: 'SOC Summit 2026', issuer: 'SOC Summit', year: '2026', featured: true },
    { title: 'Certified Cyber Criminologist', issuer: 'Virtual Cyber Labs', year: '2025', featured: true },
    { title: 'Proofpoint AI Email Security Specialist', issuer: 'Proofpoint', year: '2025', featured: true },
    { title: 'DSPM Fundamentals', issuer: 'Securiti AI', year: '2025', featured: true },
    { title: 'Antisyphon Training', issuer: 'Antisyphon', year: '2026', featured: true },
    { title: 'Data Loss Prevention (DLP) Survival Guide', issuer: 'Fortra', year: '2026', featured: true },
    { title: 'Social Media Intelligence (SOCMINT)', issuer: 'CyberSudo', year: 'Mar 2026', featured: true },
    { title: 'Certified AI Security Expert', issuer: 'Virtual Cyber Labs', year: 'Mar 2026', featured: true },
  ],
  training: [
    { title: 'IntelVan 2025 Threat Intelligence & OSINT Masterclass', issuer: 'The OSINTion', year: '2025' },
    { title: 'CTRL. ALT. ACT. (Advanced OSINT Training)', issuer: 'Cyber Secured India', year: '2025' },
    { title: 'OpSec – Privacy for Security Professionals', issuer: 'Just Hacking', year: '2025' },
    { title: 'Cyber Threat Intelligence 101', issuer: 'arcX', year: '2025' },
  ],
  bootcamps: [
    { title: 'MindStudio AI Agent Developer 3 Bootcamp', issuer: 'MindStudio', year: '2025' },
    { title: '7-Day Offensive Bootcamp', issuer: 'ZeroRisk Labs', year: '2025' },
  ],
  additional: [
    { title: 'Proofpoint AI Data Security Specialist', issuer: 'Proofpoint', year: '2025' },
    { title: 'Google Cloud Cybersecurity Certificate', issuer: 'Google', year: '2025' },
    { title: 'Multi-Cloud Blue Team Analyst (MCBTA)', issuer: 'CyberWarFare Labs', year: '2025' },
  ],
  internships: [
    { title: 'SOC Analyst Intern', issuer: 'Tracelay', year: '2024' },
    { title: 'Cloud Identity Security Intern', issuer: 'ZeroRisk Labs', year: '2025' },
  ],
  simulations: [
    { title: 'Mastercard - Cybersecurity', issuer: 'Forage', year: '2024' },
    { title: 'AIG - Shields Up: Cybersecurity', issuer: 'Forage', year: '2024' },
  ],
};

export const education = [
  {
    degree: 'Bachelor of Engineering, Computer Science Engineering',
    school: 'Visvesvaraya Technological University (VTU)',
  },
];

interface Project {
  title: string;
  description: string;
  tags: string[];
  github?: string;
  badge?: string;
  /** Internal SPA route (rendered as <Link>), e.g. "/dfir". */
  href?: string;
  /** External URL (rendered as <a target=_blank>), e.g. "https://example.com". */
  externalUrl?: string;
}

export const projects: Project[] = [
  {
    title: 'Threat Intel Platform',
    description:
      "Live CTI surface at /threatintel. It correlates indicators across 18 free IOC feeds so I can tell whether a flagged IP is consensus-malicious or one source crying wolf. The live stream gives each indicator a reporter handle and a freshness badge, so I know which feeds are actually publishing today. There's a Gantt of which ransomware groups are posting right now, with MITRE Group profiles linked inline. Victim re-leak detection catches the cases where one company shows up under two different groups in the same year, which usually means a failed double-extortion or an affiliate moving shop. Everything that can be exported is exported as STIX 2.1 so it drops straight into MISP or a SIEM.",
    tags: ['Cloudflare Workers', 'STIX 2.1', 'MITRE ATT&CK', 'IOC Correlation', 'CTI', 'May 2026 - Present'],
    github: PLATFORM_REPO_URL,
    href: '/threatintel',
  },
  {
    title: 'DFIR Toolkit',
    description:
      'The interactive side of the same site, at /dfir. The piece I use the most is the IOC checker. Paste anything (IP, domain, URL, hash, CVE), and it fans out to about two dozen providers over SSE so the verdicts stream back as they arrive. VirusTotal, AbuseIPDB, OTX, GreyNoise, the abuse.ch trio, and a long tail of free reputation lists. Around that sits a Diamond Model builder that auto-fills its corners from whatever indicator you hand it, a STIX 2.1 viewer with an interactive relationship graph, subdomain-takeover fingerprinting, JWT inspection, IDN homograph detection, the MITRE ATT&CK matrix, and a small knowledge base I write to whenever I learn something the hard way. Edge-hosted, free, no signup.',
    tags: ['Cloudflare Workers', 'Hono', 'SSE', 'TypeScript', 'May 2026 - Present'],
    github: PLATFORM_REPO_URL,
    href: '/dfir',
  },
  {
    title: 'Autonomous DFIR Agent',
    description:
      'An autonomous investigator agent at /dfir/agent. Describe what to investigate in natural language - the agent classifies the query type, plans which of 30+ intelligence tools to call, executes them in parallel, observes results, and repeats for up to 8 reasoning steps before synthesizing a structured intelligence report. Built on a Cloudflare Durable Object for stateful multi-step execution with alarm-driven scheduling, the same pattern used by the report builder. LLM planning via Groq (primary) with Workers AI fallback. Real-time progress streamed to the frontend via SSE.',
    tags: ['Cloudflare Workers', 'Durable Objects', 'LLM', 'Groq', 'TypeScript', 'Jun 2026'],
    github: PLATFORM_REPO_URL,
    href: '/dfir/agent',
  },
  {
    title: 'CTI STIX Connector',
    description:
      'A small Python CLI that takes the messy stuff (JSON campaign blobs, CSV IOC dumps from wherever) and emits a clean STIX 2.1 bundle on the other side. Containerized, runs as non-root (UID 1000), strict-mode entrypoint, 38 pytest tests because I got bitten once by a silent parse failure that made it through review. Plugs into this site at /threatintel/actors and /api/v1/cti/parse.',
    tags: ['Python', 'STIX 2.1', 'Docker', 'CTI', 'Apr 2026 - Present'],
    github: 'https://github.com/Pranith-Jain/cti-stix-connector',
  },
  {
    title: 'DFIR MCP Server',
    description:
      'MCP server exposing 20 DFIR and threat intelligence tools for AI agents - IOC checking, CVE lookup, threat actor enrichment, phishing analysis, and more. Built on Cloudflare Workers with streaming SSE support. Works with Claude Desktop, Cursor, and any MCP-compatible client.',
    tags: ['MCP', 'Cloudflare Workers', 'AI Agents', 'DFIR', 'TypeScript', 'Jun 2026'],
    github: 'https://github.com/Pranith-Jain/dfir-mcp-server',
  },
  {
    title: 'DFIR AI Skills',
    description:
      'AI coding assistant skills for Digital Forensics and Incident Response - investigation workflows, threat report generation, detection rule authoring. Compatible with Claude Code, Cursor, and GitHub Copilot/Codex. Source lives locally at /agent/dfir-ai-skills.',
    tags: ['AI', 'DFIR', 'Skills', 'Claude Code', 'Jun 2026'],
    github: 'https://github.com/Pranith-Jain/dfir-ai-skills',
  },
  {
    title: 'CTI AI Skills',
    description:
      'AI coding assistant skills for Cyber Threat Intelligence - IOC extraction, OCR analysis, threat intel, dark web monitoring, and feed management. Compatible with Claude Code, Cursor, and GitHub Copilot/Codex. Source lives locally at /agent/cti-ai-skills.',
    tags: ['AI', 'CTI', 'Skills', 'Claude Code', 'Jun 2026'],
    github: 'https://github.com/Pranith-Jain/cti-ai-skills',
  },
  {
    title: 'DFIR CLI',
    description:
      'Command-line DFIR toolkit - IOC extraction, encoding, file analysis, PE triage. Powered by the pranithjain.qzz.io API.',
    tags: ['CLI', 'DFIR', 'Python', 'Jun 2026'],
    github: 'https://github.com/Pranith-Jain/dfir-cli',
  },
  {
    title: 'CTI CLI',
    description:
      'Command-line threat intelligence - AI copilot, IOC checker, 13+ feeds. Powered by the pranithjain.qzz.io API.',
    tags: ['CLI', 'CTI', 'Python', 'Jun 2026'],
    github: 'https://github.com/Pranith-Jain/cti-cli',
  },
  {
    title: 'Email Infrastructure Automation Platform',
    description:
      'Built when onboarding a new client domain was taking the team most of an afternoon. End-to-end domain setup across 1,300+ domains, now down to under 10 minutes per domain. The Smartlead MCP server on top of it bundles 23 analytics tools so warmup health, deliverability, and campaign metrics for 2,700+ inboxes all live in one place instead of three tabs.',
    tags: ['n8n', 'MCP', 'Smartlead', 'Automation', 'Analytics', 'Jan 2026 - Present'],
  },
  {
    title: 'Portfolio (Personal)',
    description:
      'This site. React + Vite, hosted on Cloudflare Pages, mail routed through Cloudflare too. The DFIR toolkit and threat-intel platform run as Workers next to it.',
    tags: ['React', 'Vite', 'Tailwind', 'Cloudflare Pages', 'Nov 2025 - Present'],
  },
  {
    title: 'MindStudio AI Agents',
    description:
      'Workshop for the AI agent patterns I was experimenting with at the time. A few of them got useful enough to keep around.',
    tags: ['AI', 'Agents', 'MindStudio', 'Aug 2025 - Sep 2025'],
    github: 'https://github.com/Pranith-Jain/AI-Agent-Portfolio',
  },
  {
    title: 'Secure Patient Data Platform on Google Cloud (Capstone)',
    description:
      'Final capstone. Zero Trust on GCP with HIPAA-aligned controls for a patient-data platform. Got a 93/100. Spent more time thinking about audit-log retention than I expected to.',
    tags: ['GCP', 'Zero Trust', 'HIPAA', 'Capstone', 'Jul 2025 - Aug 2025'],
    github: 'https://github.com/Pranith-Jain/Secure-Patient-Data-Platform-on-Google-Cloud-Capstone-',
  },
  {
    title: 'Cloud-Based Ransomware Detection and Recovery System (GCP)',
    description:
      "A cloud-security capstone scoped around what a small team would actually do post-incident. Detection signals from Cloud Logging, a recovery workflow that doesn't assume the SOC has 24/7 staff, and network hardening that survives a key-rotation event.",
    tags: ['GCP', 'Detection Engineering', 'Cloud Logging', 'Recovery', 'Jun 2025 - Jul 2025'],
  },
  {
    title: 'Detection Playbooks',
    description:
      'Triage and response runbooks I wrote up after enough phishing, spoofing, and domain-abuse cases that the steps were starting to look the same every time. Written so the next analyst on shift can pick one up without a 30-minute briefing first.',
    tags: ['IR', 'Playbooks', 'Detection', 'Feb 2025'],
  },
  {
    title: 'Tracelay Internship',
    description:
      'First real SOC seat. Tier-1 monitoring and a lot of "what does this alert actually mean" pattern-matching. The foundation for almost everything I built after.',
    tags: ['SOC', 'Internship', 'Monitoring', 'Jul 2024 - Oct 2024'],
  },
  {
    title: 'Detecting Bots on Twitter Using Machine Learning',
    description:
      'Final-year project. Engineered features off behavioural metadata: posting cadence, follower-to-following ratios, content entropy, then trained classifiers to call out automated accounts. Mostly useful for learning where signal hides in noisy social data.',
    tags: ['ML', 'Python', 'NLP', 'Twitter', 'Dec 2022 - Apr 2023'],
  },
  {
    title: 'CTF Writeups',
    description:
      "Notes from CTFs I've worked through. I keep them around because the techniques recur in real investigations more often than they should.",
    tags: ['CTF', 'Writeups', 'Cybersecurity'],
  },
  {
    title: 'SOC Automation',
    description:
      "n8n workflows that took the boring half of triage off my plate. Enrichment, IOC pivots, ticket-comment automation. Some of the lessons from this work fed into the DFIR toolkit's API design.",
    tags: ['n8n', 'SOC', 'Automation', 'Workflows'],
  },
  {
    title: 'UrlScanner Bot',
    description:
      'Small chatbot. Paste a URL, it runs through urlscan and a couple of reputation feeds, then posts the verdict back in the channel. Built when I got tired of manually pivoting on every link a client forwarded.',
    tags: ['Bot', 'Security', 'URL Analysis'],
  },
];

export const featuredArticles = [
  {
    title: 'Cybersecurity Compliance Lessons: Insights From Industry Experts',
    description:
      'Quoted as an expert contributor. My piece argues compliance is a milestone, not the mission. Risk-based security controls aligned with the business context come first; the certification follows.',
    source: 'BlockTelegraph',
    category: 'Security Engineering',
    url: 'https://blocktelegraph.io/cybersecurity-compliance-lessons-insights-from-industry-experts/',
  },
  {
    title: 'How to Ensure Data Privacy in Cybersecurity',
    description:
      'Concrete data-protection moves for teams that have to make tradeoffs. Encryption choices, threat-modelling the data flow first, and avoiding policies nobody actually follows.',
    source: 'DevX.com',
    category: 'Cybersecurity Insights',
    url: 'https://www.devx.com/cybersecurity/how-to-ensure-data-privacy-in-cybersecurity-key-protection-tips/',
  },
  {
    title: '15 Initiatives to Build a Strong Cybersecurity Culture',
    description:
      "Security culture is mostly downstream of incident-response habits. A breakdown of the initiatives I've seen actually shift behaviour, and the ones that just produce posters.",
    source: 'DevX.com',
    category: 'Cybersecurity Culture',
    url: 'https://www.devx.com/cybersecurity/15-initiatives-to-build-a-strong-cybersecurity-culture/',
  },
  {
    title: 'Featured Expert: OSINT & Threat Intelligence',
    description:
      'Q&A on how I work the OSINT-to-actioned-intel pipeline, the tools I lean on, and what I think most enterprises get wrong about email-threat tradecraft.',
    source: 'Featured.com',
    category: 'Security Specialist',
    url: 'https://featured.com/p/pranith-jain',
  },
];

export const memberships = [
  {
    name: 'UK OSINT Community',
    abbreviation: 'UK',
    period: 'Jan 2026 - Present · 5 mos',
    description:
      'Working alongside investigators and researchers in one of the more active OSINT communities. The discussions sharpen tradecraft faster than anything I do alone.',
    details: [
      {
        label: 'Technical Development',
        text: 'CTF challenges and workshops on SOCMINT, GEOINT, and IMINT. Good for staying current with what techniques actually work this quarter.',
      },
      {
        label: 'Tradecraft Exchange',
        text: 'Validate digital-footprinting tools against real targets so OPSEC stays clean. Hands-on, with peer review.',
      },
      {
        label: 'Knowledge Sharing',
        text: 'Roundtables on privacy frameworks, breach-data handling, and attribution. The conversations are where most of my "ah, I had been doing this wrong" moments happen.',
      },
    ],
    color: 'brand',
  },
  {
    name: 'Messaging, Malware, Mobile Anti-Abuse Working Group',
    abbreviation: 'M3',
    period: 'Feb 2026 - Present · 4 mos',
    description:
      'M3AAWG. Global working group focused on the practical defence side of messaging abuse, malware, and mobile threats. Standards conversations that actually ship.',
    color: 'emerald',
  },
  {
    name: 'emailexpert',
    abbreviation: 'E',
    period: 'May 2026 - Present · 1 mo',
    description:
      'Email-deliverability and authentication community. Where I go to sanity-check a DMARC posture decision before rolling it across a fleet.',
    color: 'cyan',
  },
  {
    name: 'Valinor Intelligence',
    abbreviation: 'VI',
    period: 'Jun 2026 - Present · <1 mo',
    description:
      'Professional OSINT community and marketplace connecting analysts with intelligence buyers. Collaborative platform for tradecraft development, training, and client work.',
    details: [
      {
        label: 'Community Hub',
        text: 'Dedicated channels for OSINT tradecraft, tooling discussions, and collaborative investigations across SOCMINT, GEOINT, and IMINT domains.',
      },
      {
        label: 'Marketplace',
        text: 'Two-sided platform connecting OSINT analysts with buyers in industry and government. RFI-based engagement model with scoped deliverables.',
      },
    ],
    color: 'violet',
  },
  {
    name: 'Webamon',
    abbreviation: 'WA',
    period: 'Jun 2026 - Present · <1 mo',
    description:
      'Community Threat Researcher contributing to web infrastructure intelligence. Collaborative threat research and IOC enrichment across the community platform.',
    color: 'emerald',
  },
  {
    name: 'OSMOSIS - An Association for OSINT Professionals',
    abbreviation: 'OSMOSIS',
    period: 'Jul 2026 - Present',
    description:
      'Professional association dedicated to advancing the OSINT discipline through standards, training, and peer collaboration across government, industry, and research.',
    color: 'brand',
  },
];

interface NavLinkChild {
  label: string;
  href: string;
}

interface NavLink {
  label: string;
  href: string;
  children?: NavLinkChild[];
}

/**
 * Header navigation. Grouped to keep the desktop bar compact - 4 visible
 * top-level items + the Contact CTA - while preserving every destination
 * via dropdown children. The `Home` entry is kept first so the mobile
 * drawer can still surface it; it is filtered out in the desktop bar
 * (the logo already routes home).
 *
 * The Contact route renders as a CTA pill on the right of the header,
 * not as a regular nav link - set `cta: true` so the Header component
 * knows to pull it out of the inline list.
 */
interface NavLinkExt extends NavLink {
  /** When true, the link is rendered as a CTA pill outside the inline nav. */
  cta?: boolean;
}

/** Portfolio surface nav — served on the apex host. Person + work only. */
export const portfolioNavLinks: NavLinkExt[] = [
  { label: 'Home', href: '/' },
  {
    label: 'Work',
    // Parent link points at the first child so mobile + middle-click users
    // get a sensible default destination if they click the group label.
    href: '/about',
    children: [
      { label: 'About', href: '/about' },
      { label: 'Skills', href: '/skills' },
      { label: 'Experience', href: '/experience' },
      { label: 'Projects', href: '/projects' },
    ],
  },
  { label: 'Blog', href: '/blog' },
  { label: 'Contact', href: '/#contact', cta: true },
];

/**
 * Tools-surface nav, keyed by the host that owns it.
 *
 * Every tools host is a front door for ONE product, so its nav lists that
 * product's pages and nothing else. A single shared array was the reason
 * `scout.` advertised PANOPTICON's eight-page threat-intel dropdown while
 * showing the recon scanner underneath — the nav and the landing disagreed.
 *
 * Cross-host destinations (the brand switcher, Portfolio) are absolute URLs
 * rather than paths, because each host serves the SAME route table: a
 * relative `/threatintel` on `crucible.` would render the threat-intel pages
 * under the CRUCIBLE chrome instead of navigating to panopticon.
 */

/** PANOPTICON — threat intel. */
const PANOPTICON_NAV: NavLinkExt = {
  label: 'PANOPTICON',
  href: '/threatintel',
  children: [
    { label: 'Catalog', href: '/threatintel/catalog' },
    { label: 'Briefings', href: '/threatintel/briefings' },
    { label: 'Live IOCs', href: '/threatintel/iocs/live' },
    { label: 'Global Pulse', href: '/threatintel/predictive/global-pulse' },
    { label: 'Intel Dashboard', href: '/threatintel/predictive/dashboard' },
    { label: 'Most Wanted', href: '/threatintel/most-wanted' },
    { label: 'Actor KB', href: '/threatintel/actors/hub' },
    { label: 'CVE & KEV Catalog', href: '/threat-intel' },
  ],
};

/** CRUCIBLE — DFIR toolkit. */
const CRUCIBLE_NAV: NavLinkExt = {
  label: 'CRUCIBLE',
  href: '/dfir',
  children: [
    { label: 'Catalog', href: '/dfir/catalog' },
    { label: 'IOC Check', href: '/dfir/ioc-check' },
    { label: 'CVE Lookup', href: '/dfir/cve' },
    { label: 'Domain Rep', href: '/dfir/domain-rep' },
    { label: 'Full Spectrum', href: '/dfir/full-spectrum' },
    { label: 'Decode', href: '/dfir/decode' },
    { label: 'Encoder', href: '/dfir/encoder' },
    { label: 'DNSCOPE', href: '/dfir/dnscope' },
    { label: 'Rule Converter', href: '/dfir/rule-converter' },
    { label: 'Blocklists', href: '/dfir/blocklists' },
    { label: 'Threat Graph', href: '/dfir/threat-graph' },
  ],
};

/**
 * Other-tool switcher, appended to every tools host.
 *
 * Links are ABSOLUTE and point at the owning host, because every tools host
 * serves the same route table: a relative `/threatintel` clicked on `crucible.`
 * would render the threat-intel pages under CRUCIBLE's chrome and read as a
 * broken CRUCIBLE sub-page rather than as a trip to PANOPTICON. An absolute
 * URL makes the navigation actually cross hosts.
 *
 * Kept as a dropdown rather than a flat row so the nav reads as "this product,
 * plus somewhere else to go" instead of putting PANOPTICON next to CRUCIBLE on
 * the CRUCIBLE host.
 */
function otherToolsNav(selfHref: string): NavLinkExt {
  const HOST_OF: ReadonlyArray<[string, NavLinkExt]> = [
    ['panopticon.pranithjain.qzz.io', PANOPTICON_NAV],
    ['crucible.pranithjain.qzz.io', CRUCIBLE_NAV],
    ['scout.pranithjain.qzz.io', { label: 'SCOUT', href: '/radar' }],
    ['argus.pranithjain.qzz.io', { label: 'ARGUS', href: '/argus' }],
    ['brief.pranithjain.qzz.io', { label: 'Daily Briefs', href: '/daily-briefs' }],
    ['agent.pranithjain.qzz.io', { label: 'Agent', href: '/dfir/agent-suite' }],
    ['copilot.pranithjain.qzz.io', { label: 'Copilot', href: '/threatintel/tools/copilot' }],
  ];

  const others: NavLinkExt[] = HOST_OF.filter(([, link]) => link.href !== selfHref).map(([host, link]) => ({
    label: link.label,
    // Land on the target host's ROOT, which is where that host renders its own
    // product. Using the apex path instead would ask a different host to serve
    // a page whose canonical owner is this one.
    href: `https://${host}/`,
  }));

  return { label: 'Other tools', href: others[0]!.href, children: others };
}

/**
 * Build the nav for one tools host.
 *
 * `self` stays as the host's own (relative — same host) nav item; everything
 * else moves into the cross-host "Other tools" switcher.
 */
function navForHost(self: NavLinkExt, selfHref: string): NavLinkExt[] {
  return [
    { label: 'Home', href: '/' },
    self,
    otherToolsNav(selfHref),
    // The tools surface has no Contact section of its own, so the CTA returns
    // to the portfolio apex.
    { label: 'Portfolio', href: `${PORTFOLIO_ORIGIN}/`, cta: true },
  ];
}

/**
 * Hostname → nav. Mirrors `TOOL_HOSTS_BY_PATH`; a host missing here falls
 * back to `toolsNavLinks` so an unrecognised tools hostname still gets a
 * usable nav rather than a broken header.
 */
export const TOOLS_NAV_BY_HOST: Readonly<Record<string, NavLinkExt[]>> = {
  'panopticon.pranithjain.qzz.io': navForHost(PANOPTICON_NAV, '/threatintel'),
  'crucible.pranithjain.qzz.io': navForHost(CRUCIBLE_NAV, '/dfir'),
  'scout.pranithjain.qzz.io': navForHost({ label: 'SCOUT', href: '/radar' }, '/radar'),
  'argus.pranithjain.qzz.io': navForHost({ label: 'ARGUS', href: '/argus' }, '/argus'),
  'agent.pranithjain.qzz.io': navForHost({ label: 'Agent', href: '/' }, '/dfir/agent-suite'),
  'copilot.pranithjain.qzz.io': navForHost({ label: 'Copilot', href: '/' }, '/threatintel/tools/copilot'),
  'brief.pranithjain.qzz.io': navForHost({ label: 'Daily Briefs', href: '/' }, '/daily-briefs'),
};

/**
 * Fallback nav for a tools host with no entry above: every product listed, so
 * nothing becomes unreachable. Prefer `TOOLS_NAV_BY_HOST`.
 */
export const toolsNavLinks: NavLinkExt[] = [
  { label: 'Home', href: '/' },
  PANOPTICON_NAV,
  CRUCIBLE_NAV,
  { label: 'SCOUT', href: '/radar' },
  { label: 'ARGUS', href: '/argus' },
  { label: 'Daily Briefs', href: '/daily-briefs' },
  // Prefixes here must match TOOL_HOSTS_BY_PATH: a path owned by no host
  // resolves to nothing. Asserted by data/__tests__/tools-nav.test.ts.
  { label: 'Agent', href: '/dfir/agent-suite' },
  { label: 'Copilot', href: '/threatintel/tools/copilot' },
  // Cross-host: the tools surface has no Contact section of its own, so the
  // CTA sends people back to the portfolio apex.
  { label: 'Portfolio', href: `${PORTFOLIO_ORIGIN}/`, cta: true },
];

/**
 * Back-compat alias for the portfolio surface's nav.
 *
 * The surface split renamed the single array into `portfolioNavLinks` +
 * `toolsNavLinks`; `navLinks` still resolves to the portfolio set so existing
 * imports and the `content.test.ts` contract keep working unchanged.
 */
export const navLinks: NavLinkExt[] = portfolioNavLinks;
