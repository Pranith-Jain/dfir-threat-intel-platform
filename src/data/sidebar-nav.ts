/**
 * Sidebar navigation for the threat-intel area.
 *
 * Auto-generated from `data/threatintel-hubs.ts` so every page in the
 * catalog has a sidebar entry. Adding a new page to the registry
 * automatically adds a sidebar item - no manual upkeep.
 *
 * The sidebar is the primary wayfinding surface for /threatintel/* pages.
 * It's grouped by hub and shows all direct page URLs (no nested tabs).
 */

import {
  Activity,
  Activity as ActivityIcon,
  AlertTriangle,
  Award,
  BarChart as BarChartIcon,
  Beaker as BeakerIcon,
  Bell,
  BookOpen,
  Brain,
  Bug,
  Camera as CameraIcon,
  Cloud,
  Code as CodeIcon,
  Compass,
  Database,
  ExternalLink,
  Eye,
  FileSearch,
  FileText,
  Flame,
  FolderTree,
  Globe,
  Grid3x3 as GridIcon,
  KeyRound,
  Layers,
  LayoutDashboard,
  List,
  Lock as LockIcon,
  Map,
  MapPin as MapPinIcon,
  MessageSquare,
  Network as NetworkIcon,
  Newspaper,
  Package,
  Radar,
  Radio,
  Rss,
  Scale,
  Search,
  Settings,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShoppingBag as ShoppingBagIcon,
  Sparkles,
  Star as StarIcon,
  Store as StoreIcon,
  Sword as SwordIcon,
  Tag as TagIcon,
  Telescope,
  Terminal,
  TrendingUp,
  UserSearch,
  Users,
  Wallet,
  Wifi,
  Wrench,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { HUB_META } from './threatintel-hubs';
import { HUB_META as DFIR_HUB_META } from './dfir-hubs';
import { pillarFor, pillarOrder, type Surface } from './pillars';
import { MAIN_TOOL_COUNT } from '../components/dfir/tool-count';

export interface SidebarItem {
  label: string;
  href: string;
  icon: LucideIcon;
  description?: string;
  /** Optional live/new/beta badge pip (from the hub registry). */
  badge?: 'live' | 'new' | 'beta';
}
export interface SidebarGroup {
  title: string;
  items: SidebarItem[];
  /**
   * Band this group sits under, e.g. "IOCs & Enrichment".
   *
   * The registries declare 40 hubs; emitted flat, the sidebar reads as a
   * tool dump. `pillar` is what `Sidebar.tsx` uses to draw the band label.
   * Presentation-only — see `data/pillars.ts`.
   */
  pillar?: string;
  /** Pillar blurb, shown as the band's subtitle on the first group only. */
  pillarBlurb?: string;
}
export interface SidebarConfig {
  sectionLabel: string;
  groups: SidebarGroup[];
  /** Accent tone for active states. Defaults to "brand" (blue, for DFIR).
   *  Pass "rose" for threat-intel so the active sidebar item matches the
   *  page accent. */
  tone?: 'brand' | 'rose';
  /**
   * Footer count label, e.g. "115+ tools". Omit it to fall back to the raw
   * number of nav items.
   *
   * Exists because the nav-item count and a surface's headline figure are
   * different quantities: the nav list holds every routable entry, while the
   * DFIR headline (`MAIN_TOOL_COUNT`) deliberately excludes `utility: true`
   * entries so the front door does not read as padded. Rendering both under
   * one label put "149 tools" beside "115+ tools" on a single screen.
   *
   * DFIR sets this from `tool-count.ts`, an import-free mirror of the value
   * derived in `tool-sections.ts`. Import `tool-sections` here instead and the
   * eager entry chunk grows ~34KB (it pulls ~40 lucide icons and is reachable
   * from `AppShell`), failing three `check:budgets` limits. See
   * `tool-count.ts` and `tool-count.test.ts`.
   */
  toolCount?: string;
}

/* ------------------------------------------------------------------ */
/*  Per-page icon override                                            */
/* ------------------------------------------------------------------ */

/**
 * Map page path -> custom icon. Pages not in this map fall back to the
 * hub's icon. The override is needed because not every page has a
 * distinct visual from its hub.
 */
const PAGE_ICON_OVERRIDES: Record<string, LucideIcon> = {
  // Actors
  '/threatintel/actors/hub': Users,
  '/threatintel/actors/attribution': Telescope,
  // Campaigns
  // IOCs
  '/threatintel/iocs/live': Radar,
  '/threatintel/iocs/enrichment': Search,
  '/threatintel/iocs/feeds': Rss,
  '/threatintel/iocs/entity': Layers,
  '/threatintel/iocs/c2': Wifi,
  '/threatintel/iocs/map': Map,
  '/threatintel/iocs/correlation': Share2,
  // CVEs
  '/threatintel/cves/cves': AlertTriangle,
  '/threatintel/cves/advisories': CodeIcon,
  '/threatintel/cves/resources': Wrench,
  '/threatintel/cves/k8s': Package,
  '/threatintel/cves/exploitable': Bug,
  '/threatintel/cves/list': List,
  // Malware
  '/threatintel/malware/iocs': Bug,
  '/threatintel/malware/sandbox': BeakerIcon,
  '/threatintel/malware/packages': Package,
  '/threatintel/malware/malpedia': BookOpen,
  '/threatintel/malware/maltrail': Map,
  // Feeds
  '/threatintel/feeds/threatfeeds': Rss,
  '/threatintel/feeds/mythreatintel': TagIcon,
  '/threatintel/feeds/threatcluster': Globe,
  '/threatintel/feeds/threatcluster/entities': NetworkIcon,
  // Social
  '/threatintel/social/firehose': Radio,
  '/threatintel/social/news': Newspaper,
  '/threatintel/social/crypto-scam': Wallet,
  // Dark web
  '/threatintel/darkweb/watch': Globe,
  '/threatintel/darkweb/markets': StoreIcon,
  '/threatintel/darkweb/darknetlist': Globe,
  '/threatintel/breach-hub': MessageSquare,
  '/threatintel/darkweb/deepdark': NetworkIcon,
  '/threatintel/darkweb/crime': ShoppingBagIcon,
  '/threatintel/darkweb/infostealer': KeyRound,
  '/threatintel/darkweb/leaks': LockIcon,
  '/threatintel/darkweb/playbook': BookOpen,
  '/threatintel/darkweb/ransom-report': FileText,
  '/threatintel/darkweb/ransom-activity': Flame,
  '/threatintel/darkweb/ransom-map': MapPinIcon,
  '/threatintel/darkweb/ransomwhere': Wallet,
  // Phishing
  '/threatintel/phishing/phish': ShieldAlert,
  '/threatintel/phishing/urls': FileText,
  '/threatintel/phishing/scam': Eye,
  // Infra
  '/threatintel/infra/cloud': Cloud,
  '/threatintel/infra/infra': NetworkIcon,
  '/threatintel/infra/webamon': CameraIcon,
  '/threatintel/infra/domain': Globe,
  // Detections
  '/threatintel/detections/detections': Shield,
  '/threatintel/detections/disarm': SwordIcon,
  '/threatintel/detections/yara': FileSearch,
  '/threatintel/detections/signal': Rss,
  '/threatintel/detection-wiki': Database,
  // Research
  '/threatintel/research-hub/reports': FileText,
  '/threatintel/research-hub/ai': Sparkles,
  '/threatintel/research-hub/writeups': BookOpen,
  '/threatintel/research-hub/signal': TrendingUp,
  '/threatintel/research-hub/redhunt': Telescope,
  '/threatintel/research-hub/redhunt-labs': Telescope,
  '/threatintel/research-hub/volexity': Telescope,
  '/threatintel/research-hub/post': FileText,
  '/threatintel/research-hub/attack-flow': NetworkIcon,
  '/threatintel/research-hub/campaign-gen': Sparkles,
  '/threatintel/research-hub/knowledge': Share2,
  '/threatintel/research-hub/ach': Scale,
  // Knowledge
  '/threatintel/wiki/wiki': BookOpen,
  '/threatintel/wiki/mitre': GridIcon,
  '/threatintel/wiki/f3ead': Compass,
  '/threatintel/wiki/f2t2ea': Compass,
  '/threatintel/wiki/ooda': Compass,
  '/threatintel/wiki/kill-chain-v2': Compass,
  '/threatintel/wiki/unified-kill-chain': Compass,
  '/threatintel/wiki/insider': UserSearch,
  '/threatintel/wiki/owasp': Sparkles,
  '/threatintel/wiki/llm': Brain,
  // OSINT
  '/threatintel/osint/framework': Search,
  '/threatintel/osint/cli': Terminal,
  '/threatintel/osint/map': Map,
  '/threatintel/osint/toolbox': Wrench,
  '/threatintel/osint/certs': Award,
  '/threatintel/osint/secops': Settings,
  '/threatintel/osint/threat-actor-monitor': Shield,
  // Tools
  '/threatintel/tools/copilot': Sparkles,
  '/threatintel/mcp-search': Zap,
  // '/threatintel/tools/mcp' now redirects to /threatintel/mcp-search
  '/threatintel/tools/stix': FileText,
  '/threatintel/tools/stix-ip-export': FileText,
  '/threatintel/tools/kev-catalog': Shield,
  '/threatintel/tools/graph': Share2,
  '/threatintel/tools/investigations': FolderTree,
  '/threatintel/tools/watches': Eye,
  '/threatintel/tools/unified-search': Search,
  '/threatintel/tools/darknet-intel': Shield,
  // External
  '/threatintel/external/external': ExternalLink,
  '/threatintel/supply-chain': Package,
  '/threatintel/external/awesome': StarIcon,
  // Predictive
  '/threatintel/predictive/dashboard': LayoutDashboard,
  '/threatintel/predictive/global-pulse': Globe,
  '/threatintel/cyberpulse': ShieldAlert,
  '/threatintel/predictive/threat-pulse': ActivityIcon,
  '/threatintel/predictive/certstream': ShieldCheck,
  '/threatintel/predictive/metrics': BarChartIcon,
  '/threatintel/predictive/predictions': TrendingUp,
  '/threatintel/predictive/predictive': Sparkles,
  '/threatintel/briefings': Newspaper,
  '/threatintel/telegram': Radio,
  '/threatintel/source-health': Activity,
  '/threatintel/ransomware-live': Flame,
  '/threatintel/alerts': Bell,

  '/threatintel/about': Scale,
  '/threatintel/live-center': Globe,
  '/threatintel/soc-dashboard': LayoutDashboard,
  '/threatintel/ti-dashboard': ShieldAlert,
};

/* ------------------------------------------------------------------ */
/*  Build the threat-intel sidebar from the registry                  */
/* ------------------------------------------------------------------ */

/**
 * Attach pillar metadata to hub groups and order them so each pillar's hubs
 * are adjacent. `withBandHead` marks the first group of every pillar so the
 * sidebar can print the band label + blurb exactly once.
 */
function bandGroups(
  surface: Surface,
  hubs: ReadonlyArray<{
    id: string;
    label: string;
    icon: LucideIcon;
    pages: ReadonlyArray<{ label: string; path: string; desc?: string; badge?: SidebarItem['badge'] }>;
  }>,
  iconFor: (path: string, fallback: LucideIcon) => LucideIcon
): SidebarGroup[] {
  const decorated = hubs.map((hub) => {
    const pillar = pillarFor(surface, hub.id);
    return {
      hub,
      group: {
        title: hub.label,
        items: hub.pages.map((p) => ({
          label: p.label,
          href: p.path,
          icon: iconFor(p.path, hub.icon),
          description: p.desc,
          badge: p.badge,
        })),
        pillar: pillar.label,
        pillarBlurb: pillar.blurb,
      } satisfies SidebarGroup,
    };
  });

  // Stable sort on pillar order keeps each registry's own hub ordering
  // inside a pillar, so the band reads top-to-bottom as authored.
  decorated.sort((a, b) => pillarOrder(surface, a.hub.id) - pillarOrder(surface, b.hub.id));

  let lastPillar: string | undefined;
  return decorated.map(({ group }) => {
    const head = group.pillar !== lastPillar;
    lastPillar = group.pillar;
    return head ? { ...group, pillarBlurb: group.pillarBlurb } : { ...group, pillarBlurb: undefined };
  });
}

function buildThreatIntelSidebar(): SidebarConfig {
  // Top-level entry: Home + Catalog + a few key standalone pages
  const home: SidebarGroup = {
    title: 'Overview',
    items: [
      {
        label: 'Home',
        href: '/threatintel',
        icon: Compass,
        description: 'Landing page - quick actions and recent tools',
      },
      {
        label: 'Page Catalog',
        href: '/threatintel/catalog',
        icon: List,
        description: 'Every page in the threat-intel area',
      },
      { label: 'About', href: '/threatintel/about', icon: Scale, description: 'About the platform' },
    ],
  };

  // Per-hub groups - list direct page URLs only (no hub landing page; the
  // catalog at /threatintel/catalog?cat=<id> is the single navigation
  // surface for browsing a category).
  const hubGroups = bandGroups('threatintel', HUB_META, (path, fallback) => PAGE_ICON_OVERRIDES[path] ?? fallback);

  return {
    sectionLabel: 'PANOPTICON',
    groups: [home, ...hubGroups],
    tone: 'rose',
  };
}

/* ------------------------------------------------------------------ */
/*  DFIR sidebar - auto-generated from dfir-hubs (zero manual upkeep)  */
/* ------------------------------------------------------------------ */

function buildDfirSidebar(): SidebarConfig {
  // Per-hub groups, generated from the dfir-hubs registry so every catalog
  // page gets a sidebar entry automatically (mirrors buildThreatIntelSidebar).
  const hubGroups = bandGroups('dfir', DFIR_HUB_META, (_path, fallback) => fallback);

  // Prepend a Home entry to the first group (the registry's Overview hub) so
  // the sidebar opens with the landing page without a redundant extra group.
  const homeItem: SidebarItem = {
    label: 'Home',
    href: '/dfir',
    icon: LayoutDashboard,
    description: 'Search every tool, quick IOC triage.',
  };
  const first = hubGroups[0];
  if (first) first.items = [homeItem, ...first.items];

  return {
    sectionLabel: 'CRUCIBLE',
    groups: hubGroups,
    tone: 'brand',
    // Match the hub headline so the sidebar does not print a second, larger
    // "tools" figure on a screen whose hero already says "115+ tools".
    //
    // Imported from `tool-count`, NOT from `tool-sections` where the value is
    // derived: `tool-sections` pulls in ~40 lucide icons and this module is
    // reachable from `AppShell` on the eager path, so importing it directly
    // added ~34KB to the entry chunk and failed three `check:budgets` limits.
    // `tool-count.test.ts` pins the mirror against SECTIONS so it cannot drift.
    toolCount: `${MAIN_TOOL_COUNT}+ tools`,
  };
}

const SIDEBARS: Record<string, SidebarConfig> = {
  '/threatintel': buildThreatIntelSidebar(),
  '/dfir': buildDfirSidebar(),
  '/radar': {
    sectionLabel: 'SCOUT',
    groups: [
      {
        title: 'Tools',
        items: [{ label: 'Scan', href: '/radar', icon: Radar }],
      },
    ],
  },
};

export function getSidebarForSection(pathname: string): SidebarConfig | null {
  for (const [prefix, config] of Object.entries(SIDEBARS)) {
    if (pathname.startsWith(prefix)) return config;
  }
  return null;
}

export const PAGE_TITLES: Record<string, string> = (() => {
  const out: Record<string, string> = {};
  out['/threatintel'] = 'Threat Intel';
  out['/threatintel/catalog'] = 'Page Catalog';
  out['/threatintel/about'] = 'About';
  // Per-page titles only - no bare hub paths in PAGE_TITLES since
  // hub landing pages are gone. The catalog is the single navigation
  // surface for browsing a category.
  for (const hub of HUB_META) {
    for (const p of hub.pages) {
      out[p.path] = p.label;
    }
  }
  // DFIR catalog + per-page titles (driven by dfir-hubs)
  out['/dfir/catalog'] = 'DFIR Catalog';
  for (const hub of DFIR_HUB_META) {
    for (const p of hub.pages) {
      out[p.path] = p.label;
    }
  }
  return out;
})();
