import { useEffect, useMemo, useRef, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Link } from 'react-router-dom';
import { ArrowRight, ChevronDown, Compass, Flame, Globe, Radio, Search, Shield, Users, X } from 'lucide-react';
import { LiveSnapshotPanel } from '../../components/dfir/LiveSnapshotPanel';
import { WhatsNewBanner } from '../../components/threatintel/WhatsNewBanner';
import { LatestBriefingCard } from '../../components/threatintel/LatestBriefingCard';
import { LivePulse } from '../../components/threatintel/LivePulse';
import { HubTabs } from '../../components/threatintel/HubTabs';
import { CATALOG, catalogSearch } from '../../data/threatintel-catalog';
import { ThreatIntelStructuredData } from '../../components/ToolStructuredData';
import { FaqStructuredData } from '../../components/FaqStructuredData';
import { BreadcrumbListSchema } from '../../components/BreadcrumbStructuredData';
import { THREATINTEL_FAQ } from '../../data/threatintel-faq';
import { FaqSection } from '../../components/FaqSection';

/**
 * Threat-Intel home page - redesigned following SaaS UX patterns from
 * Recorded Future, Huntress, Shodan, and VirusTotal.
 *
 * Visual language (2026-06-19): one card surface, no rainbow category
 * tiles. Each category gets a tone-tinted icon and a 1px tone-tinted
 * hover border on a neutral surface-card. Hero uses a 1px rose-tinted
 * hairline accent instead of the old 224px blurred brand wash.
 *
 * Structure:
 *   1. Bold hero - "What is this?" in one sentence + primary search
 *   2. Live intelligence pulse - Real-time proof the platform works
 *   3. Quick access - Most-used tools for returning users
 *   4. Explore by topic - tabbed hub directory (<HubTabs />), one tab per
 *      registry hub, deep-linked via ?hub=<id>
 *   5. Getting started - 3-step guide for novices
 *   6. Full catalog - One click away
 *
 * The key insight from competitor research: don't dump 100+ tools on
 * the landing page. Show categories, each leading to a focused sub-page.
 * Users think in problems ("ransomware", "phishing"), not in tool names.
 * Categories were previously a hand-maintained 8-card grid; they are now
 * generated from `data/threatintel-hubs.ts` so the tab list can never drift
 * out of sync with the routes that actually exist.
 */

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export default function ThreatIntelHome(): JSX.Element {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);
  const searchResults = useMemo(() => (query.trim() ? catalogSearch(query) : null), [query]);
  const isSearching = query.trim().length > 0;

  // Keyboard: '/' or 'Cmd/Ctrl+K' focuses the search; 'Esc' clears.
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

  return (
    <DataPageLayout
      backTo="/"
      hideBack
      icon={<Shield size={28} />}
      title="Threat Intel"
      description="Live threat intelligence - ransomware activity, threat actors, IOCs, CVEs, dark web monitoring, and social media feeds."
      maxWidthClass="max-w-7xl"
    >
      <ThreatIntelStructuredData />
      <BreadcrumbListSchema
        items={[
          { name: 'Home', url: 'https://pranithjain.qzz.io' },
          { name: 'Threat Intel', url: 'https://pranithjain.qzz.io/threatintel' },
        ]}
      />
      <FaqStructuredData entries={THREATINTEL_FAQ} />
      <WhatsNewBanner />
      <LatestBriefingCard />
      <LivePulse />

      {/* ── Hero - bold value prop + primary search ───────────── */}
      {/* surface-card + tone-tinted 1px hairline replaces the old
          224px blurred brand wash. Same hierarchy, none of the
          AI-decorative feel. */}
      <section className="surface-elevated relative mt-8 p-6 sm:mt-10 sm:p-10 lg:p-12">
        <div aria-hidden className="pointer-events-none absolute top-0 left-0 h-px w-12 bg-rose-500/60" />

        {/* Status ribbon - pulse + uptime + feed scope. The .live-pulse
            utility handles the breathe animation in one place. */}
        <div className="mb-5 sm:mb-7 flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-mini uppercase tracking-[0.16em] text-muted">
          <span className="inline-flex items-center gap-1.5">
            <span className="relative inline-flex h-1.5 w-1.5">
              <span className="absolute inset-0 rounded-full bg-rose-500 live-pulse" aria-hidden="true" />
              <span className="relative inline-block h-1.5 w-1.5 rounded-full bg-rose-500" />
            </span>
            <span className="text-rose-600 dark:text-rose-400">Live</span>
          </span>
          <span aria-hidden="true" className="text-inverted">
            /
          </span>
          <span>30+ feeds · 90s refresh · no login</span>
          <span aria-hidden="true" className="text-inverted">
            /
          </span>
          <span>edge-hosted on Cloudflare</span>
        </div>

        {/* H1 - same treatment as the DFIR home: bigger, tighter, real
            display weight. The visual rule is the same on both landings
            so visitors who switch between them read it as one product. */}
        <h1 className="font-display text-3xl sm:text-5xl lg:text-6xl font-bold leading-[0.95] tracking-[-0.04em] text-heading">
          See the threats.
          <br className="hidden sm:inline" />
          <span className="sm:inline"> Stop them before they strike.</span>
        </h1>
        <p className="mt-5 sm:mt-6 max-w-2xl text-base sm:text-lg leading-relaxed text-body">
          Monitor ransomware activity, track threat actors, enrich IOCs, stay ahead of campaigns - live intelligence
          from 30+ public feeds, all in one place.
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
            placeholder="Search actors, CVEs, campaigns, feeds, tools..."
            className="w-full rounded-xl border border-line-1 bg-surface-200 py-3 pl-11 pr-24 font-mono text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/40 dark:placeholder:text-muted"
            aria-label="Search threat intelligence"
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

        {/* Popular shortcuts - only tools NOT already in the Quick access grid below */}
        <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-muted">
          <span>Popular:</span>
          {[
            { label: 'CVE Intel', href: '/threatintel/cves/cves' },
            { label: 'Live IOCs', href: '/threatintel/iocs/live' },
          ].map((link) => (
            <Link
              key={link.href}
              to={link.href}
              className="inline-flex items-center gap-1 surface-card rounded-full px-2.5 py-1 text-xs font-medium text-muted hover:border-rose-300 hover:text-rose-600 dark:hover:border-rose-600 dark:hover:text-rose-400"
            >
              {link.label}
            </Link>
          ))}
        </div>

        {/* Stat band - same hairline-divided treatment as the DFIR home so
              the two landings read as one product (big mono numerals + a
              sub-label per stat), not two differently-styled pages. */}
        <dl className="mt-7 sm:mt-9 grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-line-1 border-y border-line-1">
          {[
            { value: '30+', label: 'Live feeds', sub: 'refreshed every 90s' },
            { value: '100+', label: 'Intel pages', sub: `across ${CATALOG.length} categories` },
            { value: '60+', label: 'IOC sources', sub: 'cross-correlated' },
          ].map((stat, i) => (
            <div
              key={stat.label}
              className={`flex flex-col gap-1.5 py-3 sm:py-4 ${i === 0 ? 'sm:pr-6' : i === 1 ? 'sm:px-6' : 'sm:pl-6'}`}
            >
              <dt className="font-mono text-micro uppercase tracking-[0.16em] text-muted">{stat.label}</dt>
              <dd className="font-display text-3xl sm:text-4xl font-bold leading-none tabular-nums text-heading">
                {stat.value}
              </dd>
              <dd className="font-mono text-mini text-muted">{stat.sub}</dd>
            </div>
          ))}
        </dl>
      </section>

      {/* ── Search results (when typing) ─────────────────────── */}
      {isSearching && (
        <section className="mt-8 animate-fade-in-up sm:mt-10">
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
                        <Icon size={16} className="mt-0.5 shrink-0 text-rose-600 dark:text-rose-400" />
                        <span className="font-mono text-micro uppercase tracking-wider text-muted">
                          {category.label}
                        </span>
                      </div>
                      <h3 className="font-display text-sm font-semibold text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400">
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

      {/* ── Live intelligence + content ───────────────────────── */}
      {!isSearching && (
        <>
          {/* ── Quick access - always visible, no scrolling needed */}
          <section className="mt-8 sm:mt-10">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                {
                  label: 'Live Threat Feed',
                  desc: 'Unified 30+ sources, threatintel.dk style',
                  href: '/threatintel/live-feed',
                  icon: Radio,
                  badge: 'live',
                },
                {
                  label: 'Global Pulse',
                  desc: 'Live 3D threat map',
                  href: '/threatintel/predictive/global-pulse',
                  icon: Globe,
                  badge: 'live',
                },
                {
                  label: 'Ransomware Live',
                  desc: 'Active leak sites',
                  href: '/threatintel/ransomware-live',
                  icon: Flame,
                  badge: 'live',
                },
                {
                  label: 'Actor KB',
                  desc: 'Threat actor profiles',
                  href: '/threatintel/actors/hub',
                  icon: Users,
                },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    className="group flex items-center gap-3 surface-card card-hover p-4"
                  >
                    <div className="grid h-10 w-10 place-items-center rounded bg-surface-200 dark:bg-surface-100/5 text-rose-600 dark:text-rose-400 shrink-0">
                      <Icon size={18} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-display text-sm font-semibold text-heading truncate">{item.label}</h3>
                        {item.badge === 'live' && (
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shrink-0" />
                        )}
                      </div>
                      <p className="text-xs text-muted truncate">{item.desc}</p>
                    </div>
                    <ArrowRight
                      size={14}
                      className="ml-auto text-inverted group-hover:text-rose-500 transition-colors shrink-0"
                    />
                  </Link>
                );
              })}
            </div>
          </section>

          {/* ── Live Intelligence - open by default: live proof the platform
                is working belongs above the fold on the threat-intel hub. */}
          <details open className="group surface-card mt-8 sm:mt-10">
            <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
              <div className="flex items-center gap-2">
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <h2 className="font-display font-bold text-lg text-heading">Live Intelligence</h2>
              </div>
              <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
            </summary>
            <div className="px-4 sm:px-5 pb-4 sm:pb-5">
              <LiveSnapshotPanel
                tone="brand"
                compact
                subtitle="real-time feed health across the platform"
                mbClass="mb-0"
              />
            </div>
          </details>

          {/* ── Explore by topic - tabbed hub directory ───────────────
                Replaces the previous 8-card grid. Every hub in the registry
                gets its own tab (there are 19, not 8), and the active hub is
                mirrored to ?hub=<id> so it is deep-linkable and
                reload-stable. Structure follows the novasky.io
                /threat-intelligence reference: sticky tab rail, then a
                panel with a section header and a widget grid. */}
          <HubTabs />

          {/* ── Collapsible: Getting started */}
          <details className="group surface-card mt-8 sm:mt-10">
            <summary className="flex items-center justify-between cursor-pointer p-4 sm:p-5 select-none">
              <h2 className="font-display font-bold text-lg text-heading">New here?</h2>
              <ChevronDown size={16} aria-hidden="true" className="shrink-0 text-muted" />
            </summary>
            <div className="px-4 sm:px-5 pb-4 sm:pb-5">
              <div className="grid gap-4 sm:grid-cols-3">
                {[
                  {
                    step: '1',
                    title: 'Pick a topic',
                    desc: "Choose one of the categories above that matches what you're investigating.",
                  },
                  {
                    step: '2',
                    title: 'Explore the tools',
                    desc: 'Each category has focused dashboards and tools - no need to search through everything.',
                  },
                  {
                    step: '3',
                    title: 'Go deep',
                    desc: 'Drill into specific actors, campaigns, or IOCs. Cross-reference across sources.',
                  },
                ].map((s) => (
                  <div key={s.step} className="flex gap-3">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-200 dark:bg-surface-100/5 font-mono text-sm font-bold text-rose-600 dark:text-rose-400">
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

          {/* Visible Q&A matching THREATINTEL_FAQ JSON-LD above — required for
              FAQ rich results and gives answer engines question-shaped H2s. */}
          <FaqSection entries={THREATINTEL_FAQ} className="mt-8 sm:mt-10" />

          {/* ── Full catalog link */}
          <div className="mt-8 flex justify-center sm:mt-10">
            <Link
              to="/threatintel/catalog"
              className="surface-card inline-flex items-center gap-2 rounded-xl px-6 py-3 text-sm font-medium text-body hover:border-rose-300 hover:text-rose-600 dark:hover:border-rose-600 dark:hover:text-rose-400"
            >
              <Compass size={16} />
              Browse the full catalog
              <span className="font-mono text-xs text-muted">
                {CATALOG.reduce((sum, h) => sum + h.pages.length, 0)} pages
              </span>
              <ArrowRight size={14} />
            </Link>
          </div>
        </>
      )}
    </DataPageLayout>
  );
}
