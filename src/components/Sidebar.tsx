import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronLeft, ChevronRight, ChevronDown } from 'lucide-react';
import type { SidebarConfig } from '../data/sidebar-nav';

interface SidebarProps {
  config: SidebarConfig;
}

const STORAGE_KEY = 'sidebar-collapsed';
const GROUPS_KEY = 'sidebar-expanded-groups';

/**
 * DOM id for a collapsible group's `<ul>`.
 *
 * Was previously an inline `sidebar-group-${title.replace(...)}` expression
 * duplicated at both the button's `aria-controls` and the list's `id`. Two
 * copies of a string-building rule is exactly the kind of thing that drifts;
 * one function keeps the two ends from ever disagreeing.
 */
function groupDomId(title: string): string {
  return `sidebar-group-${title.replace(/\s+/g, '-').toLowerCase()}`;
}

function isActive(pathname: string, href: string): boolean {
  if (href === pathname) return true;
  if (href === '/threatintel') return false;
  if (href === '/dfir') return false;
  return pathname.startsWith(href + '/') || pathname.startsWith(href + '?');
}

function toneClasses(tone: 'brand' | 'rose' = 'brand') {
  if (tone === 'rose') {
    return {
      // Geist active: surface-200 wash (subtle), tone-tinted icon, and
      // a tone-tinted dot at the trailing edge. The label itself stays
      // slate-900 so the text colour always reads at WCAG AA.
      activeBg: 'bg-rose-500/10 text-slate-900 dark:text-white',
      activeIcon: 'text-rose-600 dark:text-rose-400',
      activeDot: 'bg-rose-500',
      activeBorder: 'border-rose-500',
      focusRing: 'focus-visible:ring-rose-500',
    };
  }
  return {
    activeBg: 'bg-brand-500/10 text-slate-900 dark:text-white',
    activeIcon: 'text-brand-600 dark:text-brand-400',
    activeDot: 'bg-brand-500',
    activeBorder: 'border-brand-500',
    focusRing: 'focus-visible:ring-brand-500',
  };
}

function useExpandedGroups(
  pathname: string,
  groups: { title: string; items: { href: string }[] }[]
): [Set<string>, (title: string) => void] {
  const [expanded, setExpanded] = useState<Set<string>>(() => {
    // Compute initial state from localStorage (client) or route match (SSR)
    if (typeof window !== 'undefined') {
      try {
        const raw = window.localStorage.getItem(GROUPS_KEY);
        if (raw) return new Set(JSON.parse(raw));
      } catch {
        /* ignore */
      }
    }
    // Auto-expand the group containing the active page
    const active = new Set<string>();
    for (const group of groups) {
      if (group.items.some((item) => isActive(pathname, item.href))) {
        active.add(group.title);
      }
    }
    return active;
  });

  const toggle = (title: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(title)) next.delete(title);
      else next.add(title);
      try {
        window.localStorage.setItem(GROUPS_KEY, JSON.stringify([...next]));
      } catch {
        /* ignore */
      }
      return next;
    });
  };

  return [expanded, toggle];
}

/**
 * Sidebar with collapsible groups. Each group has a toggle at the top
 * so users don't have to scroll to the bottom to find controls.
 */
export function SidebarContent({ config }: { config: SidebarConfig }): JSX.Element {
  const location = useLocation();
  const totalItems = useMemo(() => config.groups.reduce((n, g) => n + g.items.length, 0), [config]);
  // Footer count. Prefers an explicit `config.toolCount` so a surface can
  // publish its own headline figure, and falls back to counting the nav items
  // so this stays generic for surfaces that have no separate headline number.
  //
  // DFIR supplies `toolCount` because its nav list (149 entries) and its hub
  // headline (115, excluding `utility: true` routes) are different
  // quantities; printing both under one label made one look broken.
  const toolCountLabel = config.toolCount ?? `${totalItems} tools`;
  const { activeBg, activeIcon, activeDot, focusRing } = toneClasses(config.tone);
  const [expanded, toggle] = useExpandedGroups(location.pathname, config.groups);

  // Auto-expand group containing active page. Intentionally runs only on
  // pathname change: `expanded`/`toggle` are excluded so the user's manual
  // expand/collapse isn't fought by re-runs, and `config.groups` is static.
  /* eslint-disable react-hooks/exhaustive-deps */
  useEffect(() => {
    for (const group of config.groups) {
      if (group.items.some((item) => isActive(location.pathname, item.href))) {
        if (!expanded.has(group.title)) {
          toggle(group.title);
        }
      }
    }
  }, [location.pathname]);
  /* eslint-enable react-hooks/exhaustive-deps */

  return (
    <>
      <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label={`${config.sectionLabel} categories`}>
        {config.groups.map((group) => {
          const isExpanded = expanded.has(group.title);
          const hasActive = group.items.some((item) => isActive(location.pathname, item.href));
          return (
            <div key={group.title} className="mb-1 last:mb-0">
              {/* Pillar band label. `pillarBlurb` is set only on the first
                  group of a band, so the heading is printed exactly once
                  while every group in the band still carries `pillar` for
                  ordering. Decorative wrapper — the heading is a plain
                  label, and the hub button beneath keeps its own
                  aria-expanded/controls pairing untouched. */}
              {group.pillar && group.pillarBlurb && (
                <div className="px-2 pt-3 pb-1 first:pt-0">
                  <div className="text-[11px] font-display font-semibold uppercase tracking-[0.16em] text-body">
                    {group.pillar}
                  </div>
                  <div className="text-micro text-muted mt-0.5 leading-snug">{group.pillarBlurb}</div>
                </div>
              )}
              <button
                type="button"
                onClick={() => toggle(group.title)}
                className={`w-full flex items-center justify-between gap-1 px-2 py-1.5 text-micro font-mono font-semibold uppercase tracking-[0.12em] transition-colors rounded ${
                  hasActive
                    ? 'text-brand-600 dark:text-brand-400'
                    : 'text-muted hover:text-slate-700 dark:hover:text-slate-200'
                }`}
                aria-expanded={isExpanded}
                // Only reference the list when it is actually in the DOM.
                // The group body renders conditionally (`{isExpanded && ...}`),
                // so an unconditional aria-controls left ~20 collapsed groups
                // pointing at IDs that do not exist - a dangling reference
                // assistive tech reports as a broken control. Pairing the two
                // keeps the relationship honest in both states.
                aria-controls={isExpanded ? groupDomId(group.title) : undefined}
              >
                <span className="truncate">{group.title}</span>
                <ChevronDown
                  size={12}
                  className={`shrink-0 transition-transform duration-150 ${isExpanded ? 'rotate-0' : '-rotate-90'}`}
                  aria-hidden="true"
                />
              </button>
              {isExpanded && (
                <ul id={groupDomId(group.title)} className="space-y-0.5 pb-2">
                  {group.items.map((item) => {
                    const active = isActive(location.pathname, item.href);
                    const Icon = item.icon;
                    return (
                      <li key={item.href}>
                        <Link
                          to={item.href}
                          aria-current={active ? 'page' : undefined}
                          // `py-1.5` made the drawer links 32px tall —
                          // under the 44px touch minimum. The drawer is
                          // the primary navigation on a phone, so its
                          // targets get the full height.
                          className={`group flex min-h-[44px] items-center gap-2 px-2 py-1.5 text-tool transition focus:outline-none focus-visible:ring-2 ${focusRing} ${
                            active
                              ? `${activeBg} font-medium`
                              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-muted dark:hover:bg-wash dark:hover:text-slate-200'
                          }`}
                        >
                          <Icon
                            size={14}
                            className={`flex-shrink-0 ${
                              active
                                ? activeIcon
                                : 'text-muted group-hover:text-slate-600 dark:group-hover:text-slate-300'
                            }`}
                            aria-hidden="true"
                          />
                          <span className="truncate">{item.label}</span>
                          {item.badge && (
                            <span
                              className={`shrink-0 rounded px-1 py-px text-micro font-mono font-bold uppercase leading-none ${
                                item.badge === 'live'
                                  ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                                  : item.badge === 'beta'
                                    ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
                                    : 'bg-brand-500/15 text-brand-600 dark:text-brand-400'
                              }`}
                            >
                              {item.badge}
                            </span>
                          )}
                          {active && (
                            <span
                              aria-hidden="true"
                              className={`h-1.5 w-1.5 rounded-full ${activeDot} shrink-0 ml-auto`}
                            />
                          )}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </nav>

      <div className="border-t border-line-1 px-3 py-2">
        <span className="text-micro font-mono text-muted">{toolCountLabel}</span>
      </div>
    </>
  );
}

export function Sidebar({ config }: SidebarProps): JSX.Element {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    try {
      return window.localStorage.getItem(STORAGE_KEY) === 'true';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, String(collapsed));
    } catch {
      /* private mode / quota */
    }
  }, [collapsed]);

  const width = collapsed ? 'w-12' : 'w-56';

  return (
    <aside
      className={`hidden md:flex flex-col ${width} flex-shrink-0 transition-[width] duration-200 ease-out`}
      aria-label={`${config.sectionLabel} navigation`}
    >
      <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] flex flex-col border-r border-line-1 bg-surface-100">
        {collapsed ? <SidebarContentCollapsed config={config} /> : <SidebarContent config={config} />}
        <div className="flex items-center justify-end border-t border-line-1 px-2 py-1.5">
          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            className="grid h-6 w-6 place-items-center text-muted transition hover:text-muted dark:hover:text-inverted focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={14} aria-hidden="true" /> : <ChevronLeft size={14} aria-hidden="true" />}
          </button>
        </div>
      </div>
    </aside>
  );
}

function SidebarContentCollapsed({ config }: { config: SidebarConfig }): JSX.Element {
  const location = useLocation();
  const { activeBg, activeIcon, activeBorder, focusRing } = toneClasses(config.tone);
  return (
    <nav className="flex-1 overflow-y-auto px-1.5 py-3" aria-label={`${config.sectionLabel} categories`}>
      {config.groups.map((group) => (
        <div key={group.title} className="mb-1 last:mb-0 space-y-0.5">
          {group.items.map((item) => {
            const active = isActive(location.pathname, item.href);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                to={item.href}
                aria-current={active ? 'page' : undefined}
                aria-label={item.label}
                title={item.label}
                className={`grid h-8 w-8 mx-auto place-items-center transition focus:outline-none focus-visible:ring-2 ${focusRing} ${
                  active
                    ? `${activeBg} border-l-2 ${activeBorder}`
                    : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-muted dark:hover:bg-wash dark:hover:text-slate-200'
                }`}
              >
                <Icon size={14} className={active ? activeIcon : ''} aria-hidden="true" />
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
