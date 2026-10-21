import { Link } from 'react-router-dom';
import { Shield, Eye, Radar, Globe, ArrowUpRight } from 'lucide-react';

const apps = [
  {
    id: 'crucible',
    icon: Shield,
    title: 'CRUCIBLE',
    subtitle: 'DFIR Toolkit',
    description:
      'Check if an indicator is malicious, investigate phishing, triage CVEs, convert detection rules, and more - 98+ tools that run in your browser.',
    rows: [
      ['IOC checker', 'Paste an IP, domain, or hash → verdict from 60+ sources'],
      ['Common tasks', 'Phishing analysis · CVE triage · rule conversion'],
      ['How it works', 'Runs entirely in your browser - no data leaves your machine'],
    ],
    builtWith: ['Free', 'No signup', 'Client-side'],
    href: '/dfir',
    stat: '125+',
    statLabel: 'tools',
    cta: 'Open CRUCIBLE',
  },
  {
    id: 'panopticon',
    icon: Eye,
    title: 'PANOPTICON',
    subtitle: 'Threat Intel Platform',
    description:
      'Monitor ransomware activity, track threat actors, and stay ahead of campaigns - live intelligence from 30+ public feeds.',
    rows: [
      ['Live feeds', 'Ransomware leaks · CVEs · dark web · social media'],
      ['Common tasks', 'Actor research · IOC enrichment · campaign tracking'],
      ['How it works', 'Aggregates 30+ feeds so you see the full picture, not noise'],
    ],
    builtWith: ['Free', 'No login', 'Edge-hosted'],
    href: '/threatintel',
    stat: '30+',
    statLabel: 'feeds',
    cta: 'Open PANOPTICON',
  },
  {
    id: 'scout',
    icon: Radar,
    title: 'SCOUT',
    subtitle: 'Recon Scanner',
    description:
      'Deep crawl, JS analysis, API endpoint discovery, secret detection, and security scoring - full reconnaissance in one scan.',
    rows: [
      ['Deep crawl', 'Multi-page crawl with JS bundle analysis'],
      ['Common tasks', 'API discovery · secret detection · domain enumeration'],
      ['How it works', 'Crawls up to 50 pages and analyzes every JS file for endpoints'],
    ],
    builtWith: ['Free', 'No signup', 'Edge-hosted'],
    href: '/radar',
    stat: '30+',
    statLabel: 'checks',
    cta: 'Open SCOUT',
  },
  {
    id: 'argus',
    icon: Globe,
    title: 'ARGUS',
    subtitle: 'Threat Nexus',
    description:
      'Nation-state threat intelligence dashboard with 3D globe visualization, actor dossiers, relationship graphs, and live threat feeds.',
    rows: [
      ['6 views', 'Globe · Cluster · Diamond · Landscape · Feed · Hunt'],
      ['Common tasks', 'Actor profiling · TTP mapping · campaign analysis'],
      ['How it works', 'Interactive D3 + three.js visualizations backed by curated APT data'],
    ],
    builtWith: ['Free', 'Standalone', 'Visual'],
    href: '/argus',
    stat: '6',
    statLabel: 'views',
    cta: 'Open ARGUS',
  },
];

export function Toolkits() {
  return (
    <section id="toolkits" className="scroll-mt-24">
      <div className="mb-8 max-w-3xl">
        <div className="mb-3 text-eyebrow font-mono uppercase tracking-[0.2em] text-muted">Tooling</div>
        <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight text-heading">
          Security tools I built
        </h2>
        <p className="mt-3 text-base sm:text-lg text-muted leading-relaxed">
          Free, no signup, runs in your browser. Check indicators, investigate threats, and stay ahead of attackers.
        </p>
      </div>

      <div className="stagger grid gap-4 grid-cols-1 md:grid-cols-2">
        {apps.map((app) => {
          const Icon = app.icon;
          return (
            <Link key={app.id} to={app.href} className="group card-hover surface-card flex flex-col p-6 h-full">
              <div className="flex items-start justify-between mb-4">
                <div className="grid h-10 w-10 place-items-center rounded bg-brand-50 text-brand-600 dark:bg-brand-900/30 dark:text-brand-300">
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </div>
                <div className="flex items-baseline gap-1 tabular-nums">
                  <span className="font-display text-2xl font-bold text-heading">{app.stat}</span>
                  <span className="text-mini font-mono text-muted">{app.statLabel}</span>
                </div>
              </div>
              <h3 className="font-display text-xl font-semibold tracking-[-0.96px] text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                {app.title}
              </h3>
              <p className="mt-0.5 text-xs font-medium text-muted">{app.subtitle}</p>
              <p className="mt-2 text-sm text-muted leading-relaxed flex-1">{app.description}</p>

              <dl className="mt-4 -mx-1 divide-y divide-line-1/70 border-y border-line-1/70">
                {app.rows.map(([k, v]) => (
                  <div key={k} className="grid grid-cols-[7.5rem_1fr] items-baseline gap-3 px-1 py-2 text-sm">
                    <dt className="text-eyebrow font-mono uppercase text-muted">{k}</dt>
                    <dd className="text-body font-mono text-meta leading-snug">{v}</dd>
                  </div>
                ))}
              </dl>

              <div className="mt-4 flex flex-wrap gap-1.5">
                {app.builtWith.map((tech) => (
                  <span
                    key={tech}
                    className="rounded border border-black/10 bg-black/[0.02] px-2 py-0.5 text-mini font-mono text-muted dark:border-white/10 dark:bg-white/[0.03]"
                  >
                    {tech}
                  </span>
                ))}
              </div>
              <div className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-brand-600 group-hover:text-brand-700 dark:text-brand-400 dark:group-hover:text-brand-300 transition-colors">
                <span>{app.cta}</span>
                <ArrowUpRight
                  className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                  aria-hidden="true"
                />
              </div>
            </Link>
          );
        })}
      </div>
    </section>
  );
}
