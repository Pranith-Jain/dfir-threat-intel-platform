import { useCallback, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Tab state for a hub page, seeded from `?tab=` so deep links land on the
 * tab the caller meant instead of the hub's default.
 *
 * Why this exists: the DFIR surface is organised as tab-hubs (one route,
 * several tools behind tabs). Each sub-tool used to keep its own route,
 * which meant two catalogs (`dfir-hubs` + `pages-index`) plus a redirect row
 * in App.tsx for every single tab. Those routes collapsed into `?tab=`
 * redirects, but the hubs hardcoded their initial tab, so
 * `/dfir/domain-rep` redirected to `/dfir/domain-investigator` and opened
 * the **DNS** tab - the deep link silently lost its meaning.
 *
 * Validating against the hub's own TABS array (rather than casting) means a
 * stale or hand-edited `?tab=` falls back to the default instead of
 * rendering a blank panel.
 *
 * @example
 *   const TABS = [{ id: 'dns', label: 'DNS' }, { id: 'web', label: 'Web' }];
 *   const [active, setActive] = useHubTab(TABS, 'dns');
 */
export function useHubTab<T extends string>(tabs: ReadonlyArray<{ id: T }>, defaultTab: T): [T, (id: T) => void] {
  const [searchParams, setSearchParams] = useSearchParams();

  const requested = searchParams.get('tab') as T | null;
  const initial = requested && tabs.some((t) => t.id === requested) ? requested : defaultTab;
  const [active, setActiveState] = useState<T>(initial);

  const setActive = useCallback(
    (id: T) => {
      setActiveState(id);
      // Keep the URL in sync so the tab is shareable and survives a reload.
      // `replace` avoids stacking a history entry per tab click.
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (id === defaultTab) next.delete('tab');
          else next.set('tab', id);
          return next;
        },
        { replace: true }
      );
    },
    [defaultTab, setSearchParams]
  );

  return [active, setActive];
}
