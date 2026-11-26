import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, Moon, Sun, Shield, Radar, Menu, X, Globe2 } from 'lucide-react';

interface TopBarProps {
  sectionLabel: string;
  sectionHref: string;
  accentClass: string;
  isDark: boolean;
  onToggleTheme: () => void;
  /**
   * 'dfir' = shield (DFIR toolkit). 'threatintel' = radar (live threat platform).
   * Drives the small mark beside the section name. Kept as a string prop so
   * the TopBar doesn't need to know the section's URL structure.
   */
  mark?: 'dfir' | 'threatintel' | 'radar' | 'argus';
  /**
   * Mobile-only: when set, renders a hamburger button on the left edge
   * (visible <md) that toggles the sidebar drawer. The AppShell wires
   * this to its `MobileSidebarDrawer` open state.
   */
  onOpenMobileNav?: () => void;
  /**
   * Whether a mobile nav drawer is open - drives the hamburger
   * → X transition. When undefined, always render the hamburger.
   */
  mobileNavOpen?: boolean;
  /**
   * Optional extra slot rendered just to the left of the theme toggle.
   * Used by the threatintel shell to mount the MCP connection pill
   * (visible on every page; popover holds the key input).
   */
  topBarExtra?: ReactNode;
}

const SEARCH_PLACEHOLDERS: Record<string, string> = {
  dfir: 'Search CRUCIBLE forensics tools…',
  threatintel: 'Search PANOPTICON threat intelligence…',
  radar: 'Scan a domain with SCOUT…',
  argus: 'Search ARGUS nation-state actors…',
};

// Geist mark chip: surface-200 wash + accent-tinted icon. No ring -
// Geist leans on borders and tonal surfaces, not decorative rings.
const MARK_ACCENT: Record<'dfir' | 'threatintel' | 'radar' | 'argus', string> = {
  dfir: 'bg-brand-500/10 text-brand-600 dark:text-brand-300',
  threatintel: 'bg-brand-500/10 text-brand-600 dark:text-brand-300',
  radar: 'bg-brand-500/10 text-brand-600 dark:text-brand-300',
  argus: 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
};

const TAGLINE: Record<'dfir' | 'threatintel' | 'radar' | 'argus', string> = {
  dfir: 'forensics',
  threatintel: 'intelligence',
  radar: 'recon',
  argus: 'threat nexus',
};

export function TopBar({
  sectionLabel,
  sectionHref,
  accentClass,
  isDark,
  onToggleTheme,
  mark = 'dfir',
  onOpenMobileNav,
  mobileNavOpen,
  topBarExtra,
}: TopBarProps): JSX.Element {
  const [isMac, setIsMac] = useState<boolean | null>(null);
  const searchKey = sectionHref.replace(/^\//, '');

  useEffect(() => {
    if (typeof navigator === 'undefined') return;
    setIsMac(/Mac|iPhone|iPad/.test(navigator.platform));
  }, []);

  const openPalette = () => {
    const ev = new KeyboardEvent('keydown', {
      key: 'k',
      metaKey: isMac ?? false,
      ctrlKey: !(isMac ?? false),
      bubbles: true,
    });
    window.dispatchEvent(ev);
  };

  const MarkIcon = mark === 'dfir' ? Shield : mark === 'argus' ? Globe2 : Radar;

  return (
    // Geist chrome: surface-100 fill (white/80) + gray-alpha-400 border.
    // Frosted via backdrop-blur; chrome-glass utility is reused from
    // the design system so the header matches the footer.
    <header className="sticky top-0 z-40 chrome-glass border-b border-line-1 pt-[env(safe-area-inset-top)]">
      <div className="max-w-[1500px] mx-auto px-3 sm:px-6 h-14 sm:h-16 flex items-center gap-2 sm:gap-4">
        {onOpenMobileNav && (
          <button
            type="button"
            onClick={onOpenMobileNav}
            className="md:hidden -ml-1 grid h-11 w-11 sm:h-9 sm:w-9 place-items-center rounded border border-line-1 bg-surface-100 text-body transition-colors hover:bg-wash hover:border-line-2 dark:bg-transparent dark:hover:bg-wash focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
            aria-label={mobileNavOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={mobileNavOpen ?? false}
            // Only while open: Drawer returns null when closed, so the target
            // id is absent in the collapsed state and referencing it there
            // would be a dangling aria-controls. aria-expanded alone already
            // conveys the collapsed state correctly.
            aria-controls={mobileNavOpen ? 'mobile-sidebar-drawer' : undefined}
          >
            {mobileNavOpen ? (
              <X className="h-4 w-4" aria-hidden="true" />
            ) : (
              <Menu className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        )}
        <Link
          to={sectionHref}
          className="flex items-center gap-2 sm:gap-2.5 shrink-0 group min-h-[44px] sm:min-h-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
          aria-label={`${sectionLabel} home`}
        >
          <span className={`grid h-8 w-8 place-items-center ${MARK_ACCENT[mark]} transition group-hover:scale-105`}>
            <MarkIcon className="h-4 w-4" aria-hidden="true" />
          </span>
          <span className="flex flex-col leading-tight min-w-0">
            <span className={`font-display font-bold text-sm sm:text-base ${accentClass} truncate`}>
              {sectionLabel}
            </span>
            <span className="hidden sm:inline text-micro font-mono uppercase tracking-[0.18em] text-muted truncate">
              {TAGLINE[mark]}
            </span>
          </span>
        </Link>

        <button
          type="button"
          onClick={openPalette}
          className="group flex-1 flex items-center gap-2 sm:gap-2.5 min-w-10 min-[360px]:min-w-11 sm:min-w-0 rounded border border-line-1 bg-surface-200 px-3 py-2 sm:px-3 sm:py-1.5 min-h-[44px] sm:min-h-0 text-left text-sm text-muted transition-colors hover:border-line-2 hover:bg-surface-100 dark:hover:bg-surface-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2"
          aria-label="Open search (press Cmd+K or Ctrl+K)"
        >
          <Search
            className="h-4 w-4 flex-shrink-0 text-muted group-hover:text-muted dark:group-hover:text-muted"
            aria-hidden="true"
          />
          <span className="truncate flex-1 text-tool sm:text-sm">
            {SEARCH_PLACEHOLDERS[searchKey] ?? `Search ${sectionLabel}…`}
          </span>
          {isMac !== null && (
            <kbd className="hidden md:inline-flex items-center gap-0.5 rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 text-mini font-mono text-muted">
              {isMac ? '⌘' : 'Ctrl'} K
            </kbd>
          )}
        </button>

        {topBarExtra}
        <button
          type="button"
          onClick={onToggleTheme}
          className="grid h-11 w-11 sm:h-9 sm:w-9 place-items-center rounded border border-line-1 bg-surface-100 text-body transition-colors hover:bg-wash hover:border-line-2 dark:bg-transparent dark:hover:bg-wash focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
          aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
          title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
        >
          {isDark ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
        </button>
      </div>
    </header>
  );
}
