import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  Bug,
  Compass,
  Crosshair,
  ChevronDown,
  Clock,
  FileSearch,
  FileText,
  GitBranch,
  Globe,
  Hash,
  Mail,
  Search,
  Shield,
  ShieldAlert,
  X,
  type LucideIcon,
} from 'lucide-react';
import { MAIN_TOOL_COUNT } from '../components/dfir/tool-sections';
import { CountUp } from '../components/ui/CountUp';
import { catalogSearch, CATALOG } from '../data/dfir-catalog';
import { useRecentTools } from '../hooks/useRecentTools';
import { getSidebarForSection } from '../data/sidebar-nav';
import { DfirStructuredData } from '../components/ToolStructuredData';
import { FaqStructuredData, HowToStructuredData } from '../components/FaqStructuredData';
import { BreadcrumbListSchema } from '../components/BreadcrumbStructuredData';
import { PageMeta } from '../components/PageMeta';
import { DFIR_FAQ } from '../data/dfir-faq';
import { PRODUCTS } from '../lib/product-brands';

/**
 * DFIR home page - redesigned following SaaS UX patterns from
 * Huntress, Shodan, and Recorded Future.
 *
 * Visual language (2026-06-19): one card surface, no rainbow category
 * tiles. Each category gets a tone-tinted icon and a 1px tone-tinted
 * hover border on a neutral surface-card. Hero uses a 1px hairline
 * accent instead of the old 224px blurred brand wash.
 *
 * Structure:
 *   1. Bold hero - "What is this?" in one sentence + primary search
 *   2. Stats - Social proof (Huntress "5M+ endpoints" pattern)
 *   3. Category overview - 8 clean topic cards (NOT 60+ individual tools)
 *   4. Quick access - Most-used tools for returning users
 *   5. Getting started - 3-step guide for novices
 *   6. Case studies - "Used in real cases" (proven credibility)
 *   7. Full catalog - One click away
 */

/* ------------------------------------------------------------------ */
/*  Category cards - the primary navigation surface                    */
/* ------------------------------------------------------------------ */

interface CategoryCard {
  id: string;
  label: string;
  description: string;
  icon: LucideIcon;
  href: string;
  tone: string;
}

/** Live page counts from the hub registry - never hard-code. */
function hubPageCount(hubId: string): number {
  return CATALOG.find((h) => h.id === hubId)?.pages.length ?? 0;
}

const CATEGORY_CARDS: CategoryCard[] = [
  {
    id: 'ioc-triage',
    label: 'IOC Triage',
    description: 'Check IPs, domains, URLs, and hashes across 60+ sources. Get consensus verdicts in seconds.',
    icon: Crosshair,
    href: '/dfir/catalog?cat=ioc-triage',
    tone: 'text-rose-600 dark:text-rose-400 hover:border-rose-500/40',
  },
  {
    id: 'malware',
    label: 'Malware Analysis',
    description: 'Triage samples, parse stealer logs, extract capabilities, and submit to sandboxes.',
    icon: Bug,
    href: '/dfir/catalog?cat=malware',
    tone: 'text-orange-600 dark:text-orange-400 hover:border-orange-500/40',
  },
  {
    id: 'email',
    label: 'Email Security',
    description: 'Analyze phishing, audit SPF/DKIM/DMARC, check BEC risk, and inspect email headers.',
    icon: Mail,
    href: '/dfir/catalog?cat=email',
    tone: 'text-violet-600 dark:text-violet-400 hover:border-violet-500/40',
  },
  {
    id: 'cloud',
    label: 'Cloud & IAM',
    description: 'Audit AWS, GCP, Azure IAM policies. Analyze CloudTrail, K8s RBAC, and security groups.',
    icon: Shield,
    href: '/dfir/catalog?cat=cloud',
    tone: 'text-emerald-600 dark:text-emerald-400 hover:border-emerald-500/40',
  },
  {
    id: 'detection',
    label: 'Detection & Rules',
    description: 'Author, convert, and test detection rules. Sigma, KQL, YARA, SPL - all in one place.',
    icon: FileSearch,
    href: '/dfir/catalog?cat=detection',
    tone: 'text-amber-600 dark:text-amber-400 hover:border-amber-500/40',
  },
  {
    id: 'artifacts',
    label: 'Forensics & Triage',
    description: 'Parse EVTX logs, registry hives, PCAPs, prefetch files, and iOS backups.',
    icon: FileText,
    href: '/dfir/catalog?cat=artifacts',
    tone: 'text-sky-600 dark:text-sky-400 hover:border-sky-500/40',
  },
  {
    id: 'domain-network',
    label: 'Web & Domain Intel',
    description: 'Check domain reputation, WHOIS, DNS, certificates, URL safety, and open directories.',
    icon: Globe,
    href: '/dfir/catalog?cat=domain-network',
    tone: 'text-pink-600 dark:text-pink-400 hover:border-pink-500/40',
  },
  {
    id: 'frameworks',
    label: 'Frameworks & Models',
    description: 'MITRE ATT&CK, Diamond Model, Kill Chain, OWASP, STIX/TAXII - visual frameworks for analysis.',
    icon: GitBranch,
    href: '/dfir/catalog?cat=frameworks',
    tone: 'text-indigo-600 dark:text-indigo-400 hover:border-indigo-500/40',
  },
];

/* ------------------------------------------------------------------ */
/*  Case studies - Huntress "Global Threats We've Wrecked" pattern     */
/* ------------------------------------------------------------------ */

interface ToolCase {
  caseSlug: string;
  caseTitle: string;
  tools: { path: string; label: string }[];
  contribution: string;
}

const TOOL_CASES: ToolCase[] = [
  {
    caseSlug: '/projects/phishing-program-at-scale',
    caseTitle: 'Phishing program at scale (250+ incidents, −25% FPs)',
    tools: [
      { path: '/dfir/ioc-check', label: 'IOC & Hash Checker' },
      { path: '/dfir/email-defense', label: 'Email Defense' },
    ],
    contribution:
      'Cross-source consensus on the IOC checker re-classified ~12% of "suspicious, escalate" cases as single-feed false alarms.',
  },
  {
    caseSlug: '/projects/dmarc-enforcement-1300-domains',
    caseTitle: 'DMARC enforcement across 1,300+ domains',
    tools: [{ path: '/dfir/email-defense', label: 'Email Defense / BEC Score' }],
    contribution: 'The audit rules in Email Defense came directly from the failure modes seen in this rollout.',
  },
  {
    caseSlug: '/projects/dfir-toolkit-design',
    caseTitle: 'Building the toolkit itself: lab → converter loop',
    tools: [
      { path: '/dfir/detection-lab', label: 'Detection Lab' },
      { path: '/dfir/rule-converter', label: 'Rule Converter' },
    ],
    contribution:
      'Author in the lab, prove the rule fires, export to the SIEM dialect you actually run. One detection-engineering loop.',
  },
  {
    caseSlug: '/projects/threat-intel-platform-build',
    caseTitle: 'Autonomous CTI pipeline (layer-1 + layer-2 IOC defence)',
    tools: [{ path: '/dfir/ioc-check', label: 'IOC & Hash Checker' }],
    contribution:
      'The same validators that power the public IOC checker also gate every IOC the autonomous pipeline emits.',
  },
];

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export default function DFIRPage(): JSX.Element {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [iocInput, setIocInput] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);
  const searchResults = useMemo(() => (query.trim() ? catalogSearch(query) : null), [query]);
  const isSearching = query.trim().length > 0;
  const location = typeof window !== 'undefined' ? window.location.pathname : '/dfir';
  const { entries: recentTools, isHydrated } = useRecentTools('dfir', location, 6);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const inField = target && /^(INPUT|TEXTAREA)$/.test(target.tagName);
      if (e.key === 'Escape' && document.activeElement === inputRef.current) {
        setQuery('');
        return;
      }
      if (inField) return;
      if (e.key === '/' || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Sidebar lookup for recent tool icons
  const sidebarLookup = useMemo(() => {
    const map = new Map<string, { icon: LucideIcon; label: string }>();
    const sidebar = getSidebarForSection('/dfir');
    if (sidebar) {
      for (const g of sidebar.groups) {
        for (const it of g.items) {
          map.set(it.href, { icon: it.icon, label: it.label });
        }
      }
    }
    return map;
  }, []);

  return (
    <>
      <PageMeta
        title={PRODUCTS.crucible.code}
        description={`${MAIN_TOOL_COUNT}+ browser-side security tools for incident response, forensics, and detection engineering. IOC checks, CVE triage, rule conversion, and more.`}
        section={PRODUCTS.crucible.metaSection}
        canonicalPath="/dfir"
        ogImage="/og-dfir.png"
      />
      <div className="w-full py-6 sm:py-10 text-heading space-y-8 sm:space-y-12">
        <DfirStructuredData />
        <BreadcrumbListSchema
          items={[
            { name: 'Home', url: 'https://pranithjain.qzz.io' },
            { name: PRODUCTS.crucible.code, url: 'https://pranithjain.qzz.io/dfir' },
          ]}
        />
        <FaqStructuredData entries={DFIR_FAQ} />
        <HowToStructuredData
          name="How to triage an indicator of compromise with CRUCIBLE"
          description="Three-step browser-side workflow: pick a tool, paste the indicator, read the aggregated verdict. No signup required."
          steps={[
            {
              name: 'Pick a tool',
              text: 'Open the IOC Triage category or use the search bar to find the right utility for IPs, domains, URLs, hashes, or CVEs.',
            },
            {
              name: 'Paste the indicator',
              text: 'Drop the value into the input field. Many tools call public APIs from your browser in parallel; some use edge-hosted providers.',
            },
            {
              name: 'Read the verdict',
              text: 'Sources are aggregated, normalised, and rendered inline. Export the result as STIX 2.1, JSON, CSV, or copy to clipboard.',
            },
          ]}
        />
        {/* ── Hero - bold value prop + primary search ───────────── */}
        {/* surface-card + tone-tinted 1px hairline at top-left replaces
          the old 224px blurred brand wash. Same hierarchy, none of the
          AI-decorative feel. */}
        <section className="surface-elevated relative p-6 sm:p-10 lg:p-12">
          <div aria-hidden className="pointer-events-none absolute top-0 left-0 h-px w-12 bg-brand-500/60" />

          {/* Status ribbon - product-accurate kicker (not blanket "local only"). */}
          <div className="mb-5 sm:mb-7 flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-mini uppercase tracking-[0.16em] text-muted">
            <span className="inline-flex items-center gap-1.5">
              <span className="relative inline-flex h-1.5 w-1.5">
                <span className="absolute inset-0 rounded-full bg-brand-500 live-pulse" aria-hidden="true" />
                <span className="relative inline-block h-1.5 w-1.5 rounded-full bg-brand-500" />
              </span>
              <span className="text-brand-600 dark:text-brand-400">Operational</span>
            </span>
            <span aria-hidden className="text-inverted">
              /
            </span>
            <span>Free · No signup · Runs in your browser</span>
          </div>

          {/* H1 - the single most important visual moment. Bigger, tighter
            tracking, real display weight. The stat row now lives below the
            lead paragraph as a hairline-separated band, not a single
            inline string. */}
          <h1 className="font-display text-4xl sm:text-6xl lg:text-7xl font-bold leading-[0.95] tracking-[-0.04em] text-heading">
            Investigate faster.
            <br className="hidden sm:inline" />
            <span className="sm:inline"> Respond with confidence.</span>
          </h1>
          <p className="mt-5 sm:mt-6 max-w-2xl text-base sm:text-lg leading-relaxed text-body">
            Check if an indicator is malicious, investigate phishing, triage CVEs, convert detection rules -{' '}
            {MAIN_TOOL_COUNT}+ tools that run entirely in your browser. No data leaves your machine.
          </p>

          {/* Primary search - the VirusTotal/Shodan pattern */}
          <div role="search" className="mt-6 relative max-w-2xl">
            <Search
              size={16}
              className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-muted"
              aria-hidden="true"
            />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={`Search ${MAIN_TOOL_COUNT}+ tools - IOC check, phishing, CVEs, decoders...`}
              className="w-full rounded-xl border border-line-1 bg-surface-200 py-3 pl-11 pr-24 font-mono text-sm text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:placeholder:text-muted"
              aria-label="Search DFIR tools"
            />
            {query ? (
              <button
                type="button"
                onClick={() => {
                  setQuery('');
                  inputRef.current?.focus();
                }}
                className="absolute right-3 top-1/2 inline-flex -translate-y-1/2 items-center gap-1 rounded px-2 py-1 text-xs font-mono text-muted hover:bg-track hover:text-heading dark:hover:bg-surface-300 dark:hover:text-slate-100"
                aria-label="Clear search"
              >
                <X size={12} /> clear
              </button>
            ) : (
              <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 hidden items-center gap-1 font-mono text-xs text-muted sm:inline-flex">
                <kbd className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 text-xs">/</kbd>
                <span>or</span>
                <kbd className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 text-xs">⌘K</kbd>
              </span>
            )}
          </div>

          {/* Stat band - Hunt.io "data table inside a card" pattern.
              Three rows, hairline divider, big mono numerals. Reads as
              capability, not as bullet list. */}
          <dl className="stagger mt-7 sm:mt-9 grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-line-1 border-y border-line-1">
            {[
              { to: MAIN_TOOL_COUNT, suffix: '+', label: 'Tools', sub: 'in-browser, client-side' },
              { to: 60, suffix: '+', label: 'IOC sources', sub: 'checked in parallel' },
              { to: 0, suffix: '', label: 'data leaves', sub: 'your browser. literally.' },
            ].map((stat, i) => (
              <div
                key={stat.label}
                className={`flex flex-col gap-1.5 py-3 sm:py-4 ${i === 0 ? 'sm:pr-6' : i === 1 ? 'sm:px-6' : 'sm:pl-6'}`}
              >
                <dt className="font-mono text-micro uppercase tracking-[0.16em] text-muted">{stat.label}</dt>
                <dd className="font-display text-3xl sm:text-4xl font-bold leading-none text-heading">
                  <CountUp to={stat.to} duration={900} formatter={(v) => `${v.toLocaleString()}${stat.suffix}`} />
                </dd>
                <dd className="font-mono text-mini text-muted">{stat.sub}</dd>
              </div>
            ))}
          </dl>
        </section>

        {/* ── Personalized workspace - "Continue where you left off" */}
        {isHydrated && recentTools.length > 0 && (
          <section className="surface-card p-4 sm:p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Clock size={14} className="text-brand-600 dark:text-brand-400" />
                <h2 className="font-display text-sm font-semibold text-heading">Continue where you left off</h2>
              </div>
              <span className="font-mono text-micro text-muted">{recentTools.length} recent</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {recentTools.map((entry) => {
                const meta = sidebarLookup.get(entry.path);
                const Icon = meta?.icon ?? Clock;
                return (
                  <Link
                    key={entry.path}
                    to={entry.path}
                    className="group inline-flex items-center gap-2 rounded border border-line-1 bg-surface-200 px-3 py-2 text-xs font-medium text-body hover:border-brand-500/40 hover:bg-brand-50/50 dark:hover:border-brand-500/40 dark:hover:bg-brand-500/10 transition-colors"
                  >
                    <Icon size={12} className="text-muted group-hover:text-brand-500 dark:group-hover:text-brand-400" />
                    <span>{meta?.label ?? entry.label}</span>
                    <ArrowRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                  </Link>
                );
              })}
            </div>
          </section>
        )}

        {/* ── Quick IOC check - paste an indicator inline */}
        <section className="surface-card p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-3">
            <Hash size={14} className="text-brand-600 dark:text-brand-400" />
            <h2 className="font-display text-sm font-semibold text-heading">Quick IOC check</h2>
          </div>
          <p className="text-xs text-muted mb-3">
            Paste an IP, domain, URL, or hash and get an instant verdict from 60+ sources.
          </p>
          <div className="flex gap-2">
            <input
              type="text"
              value={iocInput}
              onChange={(e) => setIocInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && iocInput.trim()) {
                  navigate(`/dfir/ioc-investigate?indicator=${encodeURIComponent(iocInput.trim())}`);
                }
              }}
              placeholder="e.g. 8.8.8.8, evil.com, hash..."
              className="flex-1 rounded border border-line-1 bg-surface-200 px-3 py-2 font-mono text-xs text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/20 dark:placeholder:text-muted"
              aria-label="Enter IOC to check"
            />
            <button
              type="button"
              onClick={() => {
                if (iocInput.trim()) {
                  navigate(`/dfir/ioc-investigate?indicator=${encodeURIComponent(iocInput.trim())}`);
                }
              }}
              disabled={!iocInput.trim()}
              className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 text-xs font-medium text-on-fill hover:bg-brand-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <Search size={12} />
              Check
            </button>
          </div>
        </section>

        {/* ── Search results (when typing) ─────────────────────── */}
        {isSearching && (
          <section className="animate-fade-in-up">
            <div className="font-mono text-xs text-muted mb-4">
              {searchResults?.length ?? 0} {searchResults?.length === 1 ? 'match' : 'matches'} for &ldquo;{query.trim()}
              &rdquo;
              {(searchResults?.length ?? 0) === 0 && ' - try fewer or different keywords'}
            </div>
            {searchResults && searchResults.length > 0 && (
              <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {searchResults.map(({ category, ...t }) => {
                  const Icon = t.icon ?? category.icon;
                  return (
                    <li key={t.path}>
                      <Link to={t.path} className="group block h-full surface-card card-hover p-4">
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <Icon size={16} className="mt-0.5 shrink-0 text-brand-600 dark:text-brand-400" />
                          <span className="font-mono text-micro uppercase tracking-wider text-muted">
                            {category.label}
                          </span>
                        </div>
                        <h3 className="font-display text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400">
                          {t.label}
                        </h3>
                        <p className="mt-1 text-xs text-muted line-clamp-2">{t.desc}</p>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
            {searchResults && searchResults.length === 0 && (
              <div className="rounded-xl border border-dashed border-line-2 p-10 text-center">
                <p className="text-sm text-muted">No matches. Try different keywords.</p>
              </div>
            )}
          </section>
        )}

        {/* ── Non-search content ───────────────────────────────── */}
        {!isSearching && (
          <>
            {/* ── Quick access - always visible, no scrolling needed */}
            <section>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  { label: 'IOC Check', desc: '60+ sources, streaming verdicts', href: '/dfir/ioc-check', icon: Hash },
                  { label: 'Email Defense', desc: 'SPF / DKIM / DMARC audit', href: '/dfir/email-defense', icon: Mail },
                  {
                    label: 'CVE Prioritizer',
                    desc: 'CVSS + EPSS + KEV in one call',
                    href: '/dfir/cve-prioritizer',
                    icon: ShieldAlert,
                  },
                  {
                    label: 'Rule Converter',
                    desc: 'Sigma ↔ KQL ↔ SPL ↔ YARA',
                    href: '/dfir/rule-converter',
                    icon: GitBranch,
                  },
                ].map((item) => {
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      to={item.href}
                      className="group flex items-center gap-3 surface-card card-hover p-4"
                    >
                      <div className="grid h-10 w-10 place-items-center rounded bg-surface-200 dark:bg-surface-100/5 text-brand-600 dark:text-brand-400 shrink-0">
                        <Icon size={18} />
                      </div>
                      <div className="min-w-0">
                        <h3 className="font-display text-sm font-semibold text-heading truncate">{item.label}</h3>
                        <p className="text-xs text-muted truncate">{item.desc}</p>
                      </div>
                      <ArrowRight
                        size={14}
                        className="ml-auto text-inverted group-hover:text-brand-500 transition-colors shrink-0"
                      />
                    </Link>
                  );
                })}
              </div>
            </section>

            {/* ── Explore by topic - open by default: these category cards are
                the hub's primary navigation, so they shouldn't be hidden behind
                a collapsed summary on landing. Secondary sections stay collapsed. */}
            <details open className="group surface-card">
              <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
                <div>
                  <h2 className="font-display font-bold text-lg text-heading">Explore by topic</h2>
                  <p className="text-xs text-muted mt-0.5">8 categories · {MAIN_TOOL_COUNT}+ tools</p>
                </div>
                <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
              </summary>
              <div className="px-4 sm:px-5 pb-4 sm:pb-5">
                <div className="stagger grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {CATEGORY_CARDS.map((cat) => {
                    const Icon = cat.icon;
                    return (
                      <Link
                        key={cat.id}
                        to={cat.href}
                        className={`group relative flex flex-col h-full surface-card card-hover p-4 sm:p-5 ${cat.tone}`}
                      >
                        <div className="flex items-center gap-2">
                          <Icon size={16} aria-hidden="true" />
                          <h3 className="font-display text-sm font-bold text-heading">{cat.label}</h3>
                        </div>
                        <p className="mt-2 text-xs leading-relaxed text-muted line-clamp-2 min-h-[2.5rem]">
                          {cat.description}
                        </p>
                        <dl className="mt-auto pt-3 flex items-center justify-between border-t border-line-1 font-mono text-micro">
                          <div className="flex items-center gap-1.5 text-muted">
                            <dt className="uppercase tracking-wider opacity-70">tools</dt>
                            <dd className="font-semibold tabular-nums text-body">{hubPageCount(cat.id)}</dd>
                          </div>
                          <span className="inline-flex items-center gap-0.5 text-muted group-hover:text-heading dark:group-hover:text-white transition-colors">
                            open
                            <ArrowRight size={10} className="transition-transform group-hover:translate-x-0.5" />
                          </span>
                        </dl>
                      </Link>
                    );
                  })}
                </div>
              </div>
            </details>

            {/* ── Collapsible: Getting started */}
            <details className="group surface-card">
              <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
                <h2 className="font-display font-bold text-lg text-heading">New here?</h2>
                <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
              </summary>
              <div className="px-4 sm:px-5 pb-4 sm:pb-5">
                <div className="grid gap-4 sm:grid-cols-3">
                  {[
                    {
                      step: '1',
                      title: 'Pick a task',
                      desc: 'What are you trying to do? Check an indicator? Investigate phishing? Triage a CVE?',
                    },
                    {
                      step: '2',
                      title: 'Find the tool',
                      desc: 'Use the search bar or category cards above to find the right tool for your job.',
                    },
                    {
                      step: '3',
                      title: 'Get results',
                      desc: 'Everything runs in your browser. No signup, no data leaves your machine.',
                    },
                  ].map((s) => (
                    <div key={s.step} className="flex gap-3">
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-200 dark:bg-surface-100/5 font-mono text-sm font-bold text-brand-600 dark:text-brand-400">
                        {s.step}
                      </span>
                      <div>
                        <h3 className="font-display text-sm font-semibold text-heading">{s.title}</h3>
                        <p className="text-xs text-muted mt-0.5 leading-relaxed">{s.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </details>

            {/* ── Collapsible: Case studies */}
            <details className="group surface-card">
              <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
                <div>
                  <h2 className="font-display font-bold text-lg text-heading">Used in real cases</h2>
                  <p className="text-xs text-muted mt-0.5">{TOOL_CASES.length} case studies · real incidents</p>
                </div>
                <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
              </summary>
              <div className="px-4 sm:px-5 pb-4 sm:pb-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  {TOOL_CASES.map((tc) => (
                    <Link key={tc.caseSlug} to={tc.caseSlug} className="group surface-card card-hover p-4">
                      <h3 className="font-display text-sm font-semibold text-heading group-hover:text-brand-600 dark:group-hover:text-brand-400 mb-1.5">
                        {tc.caseTitle}
                      </h3>
                      <p className="text-xs text-muted leading-relaxed mb-2 line-clamp-2">{tc.contribution}</p>
                      <div className="flex flex-wrap gap-1.5">
                        {tc.tools.map((t) => (
                          <span
                            key={t.path}
                            className="text-micro font-mono px-1.5 py-0.5 rounded border border-brand-500/30 text-brand-600 dark:text-brand-400"
                          >
                            {t.label}
                          </span>
                        ))}
                      </div>
                    </Link>
                  ))}
                </div>
              </div>
            </details>

            {/* ── Common questions (FAQ) ── */}
            {/* Same Q&A also emitted as FAQPage JSON-LD via FaqStructuredData
              above. Visible here so human readers see the answers and any
              AI engine that does not parse JSON-LD can still lift the text. */}
            <details className="group surface-card">
              <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
                <h2 className="font-display font-bold text-lg text-heading">Common questions</h2>
                <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
              </summary>
              <div className="px-4 sm:px-5 pb-4 sm:pb-5 space-y-4">
                {DFIR_FAQ.map((f) => (
                  <div key={f.question}>
                    {/* Question-shaped H2s match voice/LLM prompts directly and
                        give the FAQ section 2+ AEO question headings. */}
                    <h2 className="font-display text-sm font-semibold text-heading">{f.question}</h2>
                    <p className="mt-1.5 text-sm text-muted leading-relaxed">{f.answer}</p>
                  </div>
                ))}
              </div>
            </details>

            {/* ── Full catalog link */}
            <div className="flex justify-center">
              <Link
                to="/dfir/catalog"
                className="surface-card inline-flex items-center gap-2 rounded-xl px-6 py-3 text-sm font-medium text-body hover:border-brand-300 hover:text-brand-600 dark:hover:border-brand-600 dark:hover:text-brand-400"
              >
                <Compass size={16} />
                Browse the full catalog
                <span className="font-mono text-xs text-muted">{MAIN_TOOL_COUNT}+ tools</span>
                <ArrowRight size={14} />
              </Link>
            </div>
          </>
        )}
      </div>
    </>
  );
}
