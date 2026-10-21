import { memo, useMemo, useState, useEffect, useRef, useCallback, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Menu, X, ChevronDown, Command } from 'lucide-react';
import type { NavLink } from '../core/entities';
import { ThemeToggle } from './ui/ThemeToggle';
import { useFocusTrap } from '../hooks/useFocusTrap';
import { preloadRoute } from '../lib/route-preloaders';
import { PjMark } from './PjMark';

interface HeaderProps {
  isDark: boolean;
  onToggleTheme: () => void;
  navLinks: NavLink[];
  /** Optional extra slot rendered just before the theme toggle. */
  topBarExtra?: ReactNode;
}

export const Header = memo(function Header({ isDark, onToggleTheme, navLinks, topBarExtra }: HeaderProps) {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [isMac, setIsMac] = useState<boolean | null>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const scrollRafRef = useRef<number>(0);
  const location = useLocation();

  useEffect(() => {
    if (typeof navigator === 'undefined') return;
    setIsMac(/Mac|iPhone|iPad/.test(navigator.platform));
  }, []);

  // Track scroll position for header styling - throttled via rAF
  useEffect(() => {
    const handleScroll = () => {
      if (scrollRafRef.current) return;
      scrollRafRef.current = requestAnimationFrame(() => {
        scrollRafRef.current = 0;
        setIsScrolled(window.scrollY > 10);
      });
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', handleScroll);
      if (scrollRafRef.current) cancelAnimationFrame(scrollRafRef.current);
    };
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [location.pathname]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (openDropdown) {
        const dropdownEl = document.querySelector<HTMLElement>(`[data-nav-href="${CSS.escape(openDropdown)}"]`);
        if (dropdownEl && !dropdownEl.contains(e.target as Node)) {
          setOpenDropdown(null);
        }
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [openDropdown]);

  // Handle mobile menu close and return focus to button
  const closeMobileMenu = useCallback(() => {
    setIsMobileMenuOpen(false);
    setTimeout(() => {
      mobileMenuButtonRef.current?.focus();
    }, 0);
  }, []);

  // Handle escape key for mobile menu and dropdowns
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (isMobileMenuOpen) {
          closeMobileMenu();
        } else if (openDropdown) {
          setOpenDropdown(null);
        }
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isMobileMenuOpen, openDropdown, closeMobileMenu]);

  // Prevent body scroll when mobile menu is open, compensating for
  // scrollbar width to avoid content reflow.
  useEffect(() => {
    if (isMobileMenuOpen) {
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.overflow = 'hidden';
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    } else {
      document.body.style.overflow = '';
      document.body.style.paddingRight = '';
    }

    return () => {
      document.body.style.overflow = '';
      document.body.style.paddingRight = '';
    };
  }, [isMobileMenuOpen]);

  // Focus trap for mobile menu
  const mobileMenuRef = useFocusTrap({
    isActive: isMobileMenuOpen,
    onEscape: closeMobileMenu,
  });

  // Toggle dropdown with keyboard support
  const toggleDropdown = useCallback((href: string) => {
    setOpenDropdown((prev) => (prev === href ? null : href));
  }, []);

  const isActive = (href: string) => location.pathname === href;

  // Arrow-key navigation within dropdown menus
  const handleDropdownKeyDown = useCallback(
    (e: React.KeyboardEvent, href: string) => {
      const link = navLinks.find((l) => l.href === href);
      if (!link || !('children' in link) || !link.children) return;
      const items = link.children;
      const currentEl = e.target as HTMLElement;
      const menuLinks = Array.from(
        document.querySelectorAll(`#dropdown-${href.replace('/', '')} a[role="menuitem"]`)
      ) as HTMLElement[];
      const currentIndex = menuLinks.indexOf(currentEl);

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const next = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
        menuLinks[next]?.focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        const prev = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
        menuLinks[prev]?.focus();
      }
    },
    [navLinks]
  );

  const mainLinks = useMemo(() => navLinks.filter((link) => link.label !== 'Home' && !link.cta), [navLinks]);
  const ctaLinks = useMemo(() => navLinks.filter((link) => link.cta), [navLinks]);

  return (
    <>
      <header
        className={`sticky top-0 z-50 transition-all duration-200 ${
          isScrolled ? 'border-b border-line-1 bg-surface-100 ' : 'border-b border-transparent bg-surface-100'
        }`}
      >
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-2.5 sm:py-3 sm:px-6">
          {/* Logo */}
          <Link
            to="/"
            className="group inline-flex items-center gap-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
            aria-label="PJ - Pranith Jain Portfolio, back to home"
          >
            <PjMark className="h-11 w-11" />
            <span className="hidden text-sm font-semibold tracking-tight sm:inline text-heading">Pranith Jain</span>
          </Link>

          {/* Desktop Navigation - Home is skipped (logo already routes home)
              and CTA-tagged links (Contact) are pulled out so they render
              as a button on the right, not as an inline pill. */}
          <nav className="hidden items-center gap-1 md:flex" aria-label="Main navigation">
            {mainLinks.map((link) => (
              <div key={link.href} data-nav-href={link.href} className="relative">
                {'children' in link && link.children ? (
                  <>
                    <button
                      onClick={() => toggleDropdown(link.href)}
                      onMouseEnter={() => setOpenDropdown(link.href)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleDropdown(link.href);
                        } else if (e.key === 'ArrowDown') {
                          e.preventDefault();
                          setOpenDropdown(link.href);
                          // Focus first menuitem after render
                          setTimeout(() => {
                            const first = document.querySelector<HTMLElement>(
                              `#dropdown-${link.href.replace('/', '')} a[role="menuitem"]`
                            );
                            first?.focus();
                          }, 0);
                        }
                      }}
                      className={`flex items-center gap-1 rounded-full px-3 py-2 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 ${
                        isActive(link.href)
                          ? 'text-brand-600 dark:text-brand-400 bg-brand-500/10'
                          : 'text-slate-700 hover:bg-slate-900/5 hover:text-slate-900 dark:text-slate-200 dark:hover:bg-white/10 dark:hover:text-white'
                      }`}
                      aria-expanded={openDropdown === link.href}
                      aria-haspopup="true"
                      aria-controls={`dropdown-${link.href.replace('/', '')}`}
                    >
                      {link.label}
                      <ChevronDown
                        className={`h-4 w-4 transition-transform ${openDropdown === link.href ? 'rotate-180' : ''}`}
                        aria-hidden="true"
                      />
                    </button>
                    <div
                      id={`dropdown-${link.href.replace('/', '')}`}
                      role="menu"
                      tabIndex={-1}
                      className={`absolute left-0 top-full mt-1 min-w-[200px] rounded-xl border border-line-1 bg-surface-100 py-2 shadow-e3 dark:border-line-1 dark:bg-surface-200 transition-all duration-200 ${
                        openDropdown === link.href
                          ? 'visible opacity-100 translate-y-0'
                          : 'invisible opacity-0 -translate-y-2'
                      }`}
                      onMouseLeave={() => setOpenDropdown(null)}
                      onKeyDown={(e) => handleDropdownKeyDown(e, link.href)}
                    >
                      {link.children.map((child) => (
                        <Link
                          key={child.href}
                          to={child.href}
                          aria-current={isActive(child.href) ? 'page' : undefined}
                          className="block px-4 py-2 text-sm font-medium text-body transition hover:bg-surface-300 dark:hover:bg-surface-100/10 focus:outline-none focus:bg-surface-300 dark:focus:bg-surface-100/10"
                          onClick={() => setOpenDropdown(null)}
                          onMouseEnter={() => preloadRoute(child.href)}
                          onFocus={() => preloadRoute(child.href)}
                          role="menuitem"
                        >
                          {child.label}
                        </Link>
                      ))}
                    </div>
                  </>
                ) : (
                  <Link
                    to={link.href}
                    aria-current={isActive(link.href) ? 'page' : undefined}
                    onMouseEnter={() => preloadRoute(link.href)}
                    onFocus={() => preloadRoute(link.href)}
                    className={`rounded-full px-3 py-2 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 ${
                      isActive(link.href)
                        ? 'text-brand-600 dark:text-brand-400 bg-brand-500/10'
                        : 'text-slate-700 hover:bg-slate-900/5 hover:text-slate-900 dark:text-slate-200 dark:hover:bg-white/10 dark:hover:text-white'
                    }`}
                  >
                    {link.label}
                  </Link>
                )}
              </div>
            ))}
          </nav>

          {/* Actions */}
          <div className="flex items-center gap-2">
            {/* CTA pill - sits to the left of the theme toggle on desktop;
                hidden on mobile (the drawer surfaces Contact as its own
                row). The arrow nudges the user toward action without being
                shouty. */}
            {ctaLinks.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                className="hidden md:inline-flex items-center gap-1.5 rounded-full bg-brand-600 px-4 py-2 text-sm font-semibold text-on-fill shadow-e1 transition hover:bg-brand-500 hover:shadow-e1 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
              >
                {link.label}
                <span aria-hidden="true">→</span>
              </Link>
            ))}

            {isMac !== null && (
              <button
                type="button"
                onClick={() => {
                  const ev = new KeyboardEvent('keydown', {
                    key: 'k',
                    metaKey: isMac,
                    ctrlKey: !isMac,
                    bubbles: true,
                  });
                  window.dispatchEvent(ev);
                }}
                className="hidden md:inline-flex items-center gap-1 text-mini font-mono px-2 py-1 rounded border border-line-1 text-body hover:text-heading dark:hover:text-slate-100 hover:border-brand-500/40 hover:bg-surface-200 dark:hover:bg-surface-200"
                aria-label="Search across tools, wiki, actors, CVEs, and Telegram channels"
                title="Command palette"
              >
                <Command size={11} />
                <kbd className="px-1 py-0.5 rounded bg-surface-300 text-micro font-mono text-body border border-line-1">
                  {isMac ? '⌘' : 'Ctrl'}K
                </kbd>
              </button>
            )}

            {topBarExtra}
            <ThemeToggle isDark={isDark} onToggle={onToggleTheme} />

            <button
              ref={mobileMenuButtonRef}
              type="button"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="grid h-11 w-11 sm:h-10 sm:w-10 place-items-center rounded-full border border-line-1/60 bg-white/70 text-body shadow-e1 transition hover:shadow-e1 dark:bg-surface-200/60 md:hidden focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
              aria-label={isMobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={isMobileMenuOpen}
              aria-controls="mobile-menu"
            >
              {isMobileMenuOpen ? (
                <X className="h-6 w-6" aria-hidden="true" />
              ) : (
                <Menu className="h-6 w-6" aria-hidden="true" />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Menu Overlay */}
      <div
        className={`fixed inset-0 z-40 md:hidden transition-all duration-200 ${
          isMobileMenuOpen ? 'visible opacity-100' : 'invisible opacity-0'
        }`}
        id="mobile-menu"
        aria-hidden={!isMobileMenuOpen}
      >
        {/* Backdrop */}
        <div
          className={`absolute inset-0 bg-slate-950/20 backdrop-blur-sm dark:bg-black/50 transition-opacity duration-200 ${
            isMobileMenuOpen ? 'opacity-100' : 'opacity-0'
          }`}
          onClick={closeMobileMenu}
          aria-hidden="true"
        />

        {/* Menu - focus trap attached to the nav panel, not the backdrop overlay,
            so Tab cycling stays within the interactive links. */}
        <nav
          ref={mobileMenuRef as React.RefObject<HTMLElement>}
          role="dialog"
          aria-modal="true"
          aria-label="Mobile navigation"
          className={`absolute top-[env(safe-area-inset-top,0px)] left-0 right-0 border-t border-line-1 bg-surface-100 dark:border-line-1 dark:bg-surface-100 max-h-[calc(100dvh-env(safe-area-inset-top,0px)-env(safe-area-inset-bottom,0px))] overflow-y-auto overscroll-contain transition-all duration-200 ${
            isMobileMenuOpen ? 'translate-y-0 opacity-100' : '-translate-y-3 opacity-0'
          }`}
          style={{ WebkitOverflowScrolling: 'touch' }}
        >
          <div className="flex flex-col p-4 space-y-1 pt-[env(safe-area-inset-top,0px)]">
            {/* In-panel close button - the header hamburger sits OUTSIDE this
                focus-trapped nav, so keyboard users need a reachable control
                to dismiss the menu without relying on Escape alone. */}
            <button
              type="button"
              onClick={closeMobileMenu}
              className="mb-1 inline-flex items-center justify-end gap-1.5 rounded-xl px-4 py-2 text-sm font-medium text-muted hover:bg-surface-300 dark:hover:bg-surface-100/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 transition-colors"
              aria-label="Close navigation menu"
            >
              Close
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
            {navLinks.map((link) => {
              if ('children' in link && link.children) {
                return (
                  <div key={link.label} className="pt-2 first:pt-0">
                    <div className="px-4 pb-1 text-eyebrow font-mono uppercase text-muted">{link.label}</div>
                    {link.children.map((child) => (
                      <Link
                        key={child.href}
                        to={child.href}
                        aria-current={isActive(child.href) ? 'page' : undefined}
                        onClick={closeMobileMenu}
                        className={`block rounded-xl px-4 py-3.5 sm:py-3 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 ${
                          isActive(child.href)
                            ? 'text-brand-600 dark:text-brand-400 bg-brand-500/10'
                            : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-white/10'
                        }`}
                      >
                        {child.label}
                      </Link>
                    ))}
                  </div>
                );
              }
              return (
                <Link
                  key={link.href}
                  to={link.href}
                  aria-current={!link.cta && isActive(link.href) ? 'page' : undefined}
                  onClick={closeMobileMenu}
                  className={`rounded-xl px-4 py-3.5 sm:py-3 text-sm font-medium block focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 ${
                    link.cta
                      ? 'bg-brand-600 text-white hover:bg-brand-500 mt-2'
                      : isActive(link.href)
                        ? 'text-brand-600 dark:text-brand-400 bg-brand-500/10'
                        : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-white/10'
                  }`}
                >
                  {link.label}
                  {link.cta && <span aria-hidden="true"> →</span>}
                </Link>
              );
            })}
          </div>
          {/* Safe area spacer for notched devices */}
          <div className="h-[env(safe-area-inset-bottom,0px)]" />
        </nav>
      </div>
    </>
  );
});
