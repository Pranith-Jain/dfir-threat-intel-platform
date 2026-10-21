import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Compass, ArrowRight, Star } from 'lucide-react';
import { preloadRoute } from '../lib/route-preloaders';

const PAGES = [
  {
    path: '/dfir',
    name: 'DFIR Toolkit',
    desc: '98+ browser-side security tools for incident response and forensics.',
  },
  {
    path: '/threatintel',
    name: 'Threat Intel Platform',
    desc: 'Live CTI from 30+ feeds - ransomware, CVEs, dark web, and social.',
  },
  {
    path: '/threatintel/predictive/global-pulse',
    name: 'Global Pulse',
    desc: 'Interactive 3D globe showing global threat activity in real-time.',
  },
  {
    path: '/threatintel/ransomware-live',
    name: 'Ransomware Live',
    desc: 'Live ransomware leak site monitoring and victim tracking.',
  },
  { path: '/dfir/catalog', name: 'DFIR Tool Catalog', desc: 'Browse all 98+ tools organized by category.' },
  {
    path: '/threatintel/catalog',
    name: 'Threat Intel Catalog',
    desc: 'Browse all threat intelligence pages and dashboards.',
  },
  { path: '/dfir/ioc-check', name: 'IOC Checker', desc: 'Check any indicator across 60+ sources instantly.' },
  {
    path: '/threatintel/actors/hub',
    name: 'Threat Actor Database',
    desc: 'Research APT groups, criminal orgs, and threat actors.',
  },
];

function getPageToCheckOut(): (typeof PAGES)[0] {
  const today = new Date();
  const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
  return PAGES[seed % PAGES.length]!;
}

export function PageToCheckOut(): JSX.Element | null {
  const [page] = useState(getPageToCheckOut);

  if (!page) return null;

  return (
    <section className="group relative overflow-hidden rounded-xl border border-line-1/70 p-5 transition-all duration-200 hover:border-brand-300/50 dark:hover:border-brand-500/30 hover:shadow-e1 dark:hover:shadow-brand-500/5">
      {/* Geist: tonal surface wash, no multi-stop decorative gradient
          (Geist hierarchy comes from borders + fills, not gradients). */}
      <div aria-hidden className="absolute inset-0 bg-wash" />
      <div className="relative">
        <div className="flex items-center gap-2 mb-3">
          <div className="grid h-6 w-6 place-items-center rounded bg-brand-500/10 text-brand-600 dark:text-brand-400">
            <Star size={12} />
          </div>
          <h3 className="text-xs font-mono uppercase tracking-wider text-muted">Page to Check Out</h3>
        </div>
        <Link
          to={page.path}
          className="group block"
          onMouseEnter={() => preloadRoute(page.path)}
          onFocus={() => preloadRoute(page.path)}
        >
          <div className="flex items-start gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-xl bg-brand-500/10 dark:bg-brand-500/15 text-brand-600 dark:text-brand-400 shrink-0">
              <Compass size={16} />
            </div>
            <div className="min-w-0 flex-1">
              <h4 className="text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                {page.name}
              </h4>
              <p className="text-xs text-muted mt-0.5 leading-relaxed">{page.desc}</p>
            </div>
            <ArrowRight size={14} className="text-muted group-hover:text-brand-500 transition-colors shrink-0 mt-1" />
          </div>
        </Link>
      </div>
    </section>
  );
}
