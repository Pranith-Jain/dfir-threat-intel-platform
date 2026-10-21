import { useEffect, useState, type ComponentType } from 'react';

/**
 * Load a component on the client only.
 *
 * `React.lazy` is not enough for a module that touches `window` at
 * evaluation time. The SSR entry uses `renderToReadableStream` and awaits
 * `stream.allReady`, which resolves every Suspense boundary — so a lazily
 * imported browser-only module *is* evaluated on the server, and Leaflet
 * throws `ReferenceError: window is not defined` there. The ErrorBoundary
 * catches it and the page still renders, but it renders the error fallback
 * instead of the page, which is a worse first paint than a skeleton.
 *
 * A `useEffect` runs only in the browser, so the module is never evaluated
 * on the server. Until it has loaded, the caller gets `null` and renders
 * its own placeholder.
 *
 * `loader` must be a stable reference (a module-level function), or the
 * effect re-runs on every render and the import restarts each time.
 */
export function useClientComponent<P extends object>(
  loader: () => Promise<{ default: ComponentType<P> }>
): ComponentType<P> | null {
  const [Component, setComponent] = useState<ComponentType<P> | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loader().then(
      (mod) => {
        if (!cancelled) setComponent(() => mod.default);
      },
      () => {
        // A failed import (offline, chunk 404) leaves the placeholder in
        // place rather than crashing the page.
      }
    );
    return () => {
      cancelled = true;
    };
  }, [loader]);

  return Component;
}
