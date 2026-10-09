/**
 * Route chunk preloaders.
 *
 * Each entry is a dynamic import that points at the SAME module path used in
 * App.tsx's `React.lazy(() => import(...))` call. Vite assigns each module a
 * stable chunk identity by path, so calling these preloaders kicks the chunk
 * fetch and parse early - the lazy() in App.tsx then resolves instantly when
 * the user actually navigates.
 *
 * Wire-up: attach `onMouseEnter` + `onFocus` handlers on internal nav links
 * (Header, AppShell, in-app nav menus) that look up the preloader by path and
 * call it. Repeated calls are cheap - the module is cached after first load.
 */

type Preloader = () => Promise<unknown>;

export const routePreloaders: Record<string, Preloader> = {
  // Portfolio nav. NOTE: no entry for '/' - Home is eagerly imported by
  // App.tsx (measured decision, see the comment there), so a preloader for
  // it is a no-op that also trips rolldown's INEFFECTIVE_DYNAMIC_IMPORT
  // warning at build time.
  '/about': () => import('../pages/About'),
  '/skills': () => import('../pages/Skills'),
  '/experience': () => import('../pages/Experience'),
  '/projects': () => import('../pages/Projects'),
  '/dfir': () => import('../pages/DFIR'),

  // DFIR app nav (keys are real route paths; redirect sources like the old
  // /dfir/ioc-check are intentionally absent — warming follows the target).
  '/dfir/ioc-investigate': () => import('../pages/dfir/IocInvestigate'),
  '/dfir/url-preview': () => import('../pages/dfir/UrlPreview'),
  '/dfir/domain-investigator': () => import('../pages/dfir/DomainInvestigator'),
  '/dfir/cve': () => import('../pages/dfir/Cve'),
  '/dfir/diamond': () => import('../pages/dfir/Diamond'),
  '/dfir/host-graph': () => import('../pages/dfir/HostGraph'),

  // Threat-intel app nav
  '/threatintel': () => import('../pages/threatintel/Home'),
  '/threatintel/iocs/live': () => import('../pages/threatintel/LiveIocs'),
  '/threatintel/iocs/correlation': () => import('../pages/threatintel/IocCorrelation'),
  '/threatintel/actors/hub': () => import('../pages/threatintel/ActorHub'),
  '/threatintel/writeups': () => import('../pages/threatintel/Writeups'),
  '/threatintel/metrics': () => import('../pages/threatintel/Metrics'),
  '/threatintel/catalog': () => import('../pages/threatintel/Catalog'),
  '/threatintel/c2-tracker': () => import('../pages/threatintel/C2Tracker'),
  '/threatintel/domain-monitor': () => import('../pages/threatintel/DomainMonitor'),
  '/threatintel/iocs/map': () => {
    // Threat-map's bottleneck is the 190KB world-110m.json topojson on top of
    // the react-simple-maps chunk. Warm both concurrently so the first render
    // doesn't sit on a sequential 250-400ms wait.
    void fetch('/world-110m.json', { credentials: 'omit' }).catch(() => {});
    return import('../pages/dfir/ThreatMap');
  },
  '/threatintel/ransomware-hub': () => import('../pages/threatintel/RansomwareHub'),
  '/threatintel/predictive/certstream': () => import('../pages/threatintel/CertStreamLive'),

  // Live-snap cards on the portfolio home (highest-traffic entry points).
  // Warming these on hover/focus removes the chunk-load round-trip the user
  // would otherwise see between click and first paint.
  '/threatintel/predictive/global-pulse': () => import('../pages/threatintel/GlobalPulse'),
  '/threatintel/detections/detections': () => import('../pages/threatintel/Detections'),
  // /threatintel/briefings reuses the DFIR Briefings component, so its
  // lazy chunk lives in pages/dfir/. Warm that chunk on hover.
  '/threatintel/briefings': () => import('../pages/dfir/Briefings'),

  // Cross-cuts the user reaches from the live-snap tiles above.
  '/threatintel/predictive/dashboard': () => import('../pages/threatintel/IntelDashboard'),

  // Blog.
  '/blog': () => import('../pages/Blog'),

  // New DFIR tools (inbound links from EmailDefense / Dnscope panels).
  '/dfir/sec-headers-live': () => import('../pages/dfir/SecHeadersLive'),
};

/**
 * Preload a route's chunk. No-op if the path isn't mapped or already loaded.
 */
export function preloadRoute(path: string): void {
  // Strip query/hash: callers pass hrefs like /threatintel/catalog?cat=tools.
  const key = path.split(/[?#]/)[0];
  const fn = routePreloaders[key ?? ''];
  if (fn) void fn().catch(() => {});
}
