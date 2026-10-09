import { describe, it, expect } from 'vitest';
import { backCategoryFor } from './back-link';
import { HUB_META, hubIdForSlug } from '../data/threatintel-hubs';

describe('backCategoryFor', () => {
  describe('threat-intel 2-segment paths (flat tool pages)', () => {
    // The 2-segment shapes that the resolver should recognise as
    // registered flat tool pages (every flat page has a direct
    // /threatintel/<slug> URL - see HUB_META).

    it('returns null for /threatintel/detections (a redirect target, not a flat page)', () => {
      // /threatintel/detections → /threatintel/detections/detections
      // is a legacy 2-segment alias. The 3-segment case below is the
      // one the user actually lands on after the redirect.
      expect(backCategoryFor('/threatintel/detections')).toBeNull();
    });

    it('maps /threatintel/briefings to the campaigns hub', () => {
      // /threatintel/briefings is a registered flat page under `campaigns`.
      expect(backCategoryFor('/threatintel/briefings')).toBe('/threatintel/catalog?cat=campaigns');
    });

    it('returns null for /threatintel/metrics (a redirect target)', () => {
      // /threatintel/metrics is a legacy alias → /threatintel/predictive/dashboard.
      expect(backCategoryFor('/threatintel/metrics')).toBeNull();
    });

    // /threatintel/most-wanted and /threatintel/apt-tracker were dropped as
    // duplicates of the Actor Hub and now redirect to /threatintel/actors/hub.
    // A redirect target has no hub of its own, so backCategoryFor returns null
    // and the page falls back to the surface root — same as /threatintel/metrics
    // above.
    it('returns null for retired actor pages that now redirect to the hub', () => {
      expect(backCategoryFor('/threatintel/most-wanted')).toBeNull();
      expect(backCategoryFor('/threatintel/apt-tracker')).toBeNull();
    });

    it('returns null for paths that are not registered tools', () => {
      // /threatintel/about IS a registered flat page (wiki hub) - see
      // HUB_META - so the resolver correctly back-links to the wiki
      // catalog. The unrecognised path below is the real negative case.
      expect(backCategoryFor('/threatintel/unknown-tool')).toBeNull();
      expect(backCategoryFor('/threatintel/about')).toBe('/threatintel/catalog?cat=wiki');
    });
  });

  describe('threat-intel 3-segment paths (hub/tab routes)', () => {
    it('maps /threatintel/iocs/cross to the iocs hub', () => {
      // Previously broken: 'iocs' was missing from the legacy map so
      // the back link fell through to the surface root.
      expect(backCategoryFor('/threatintel/iocs/cross')).toBe('/threatintel/catalog?cat=iocs');
    });

    it('maps /threatintel/detections/detections to the detections hub', () => {
      expect(backCategoryFor('/threatintel/detections/detections')).toBe('/threatintel/catalog?cat=detections');
    });

    it('still back-links to the social hub from retired telegram tabs', () => {
      // The 4 telegram tab pages collapsed into the TelegramMonitor
      // tab container. They 301-redirect, so users land on the
      // canonical page; the back-link uses the hub segment directly
      // and still resolves to the social catalog.
      expect(backCategoryFor('/threatintel/social/telegram-leaks')).toBe('/threatintel/catalog?cat=social');
      expect(backCategoryFor('/threatintel/social/telegram-stats')).toBe('/threatintel/catalog?cat=social');
      expect(backCategoryFor('/threatintel/social/telegram-channels')).toBe('/threatintel/catalog?cat=social');
      expect(backCategoryFor('/threatintel/social/telegram-settings')).toBe('/threatintel/catalog?cat=social');
    });

    it('maps /threatintel/darkweb/ransom-activity to the darkweb hub', () => {
      // Previously routed to 'darkweb-breach' (legacy id, no longer
      // exists in HUB_META).
      expect(backCategoryFor('/threatintel/darkweb/ransom-activity')).toBe('/threatintel/catalog?cat=darkweb');
    });

    it('maps /threatintel/feeds/threatfeeds to the feeds hub', () => {
      // Previously routed to 'feeds-news' (legacy id).
      expect(backCategoryFor('/threatintel/feeds/threatfeeds')).toBe('/threatintel/catalog?cat=feeds');
    });

    it('maps /threatintel/phishing/scam to the phishing hub', () => {
      // Previously broken: 'phishing' was missing from the legacy map.
      expect(backCategoryFor('/threatintel/phishing/scam')).toBe('/threatintel/catalog?cat=phishing');
    });

    it('disambiguates slug collisions using the hub part of the path', () => {
      // `cross` is a tab slug under both `iocs` and `campaigns`. The
      // resolver must use the hub part of the path, not the slug.
      expect(backCategoryFor('/threatintel/iocs/cross')).toBe('/threatintel/catalog?cat=iocs');
      expect(backCategoryFor('/threatintel/campaigns/cross')).toBe('/threatintel/catalog?cat=campaigns');
    });

    it('returns null when the hub part is not a registered hub', () => {
      expect(backCategoryFor('/threatintel/unknown-hub/tab')).toBeNull();
    });
  });

  describe('dfir paths', () => {
    it('maps /dfir/ioc-investigate to the ioc-triage catalog hub', () => {
      expect(backCategoryFor('/dfir/ioc-investigate')).toBe('/dfir/catalog?cat=ioc-triage');
    });

    it('maps /dfir/domain-investigator to the domain-network catalog hub', () => {
      expect(backCategoryFor('/dfir/domain-investigator')).toBe('/dfir/catalog?cat=domain-network');
    });

    it('returns null for unknown dfir tools', () => {
      expect(backCategoryFor('/dfir/unknown-tool')).toBeNull();
    });

    it('returns null for retired alias paths (use canonical)', () => {
      // /dfir/ioc-check and /dfir/domain were collapsed to hub pages.
      // They still 301-redirect, so users land on the canonical path
      // and the back-link lookup uses that.
      expect(backCategoryFor('/dfir/ioc-check')).toBeNull();
      expect(backCategoryFor('/dfir/domain')).toBeNull();
    });
  });

  describe('off-surface paths', () => {
    it('returns null for the root', () => {
      expect(backCategoryFor('/threatintel')).toBeNull();
    });

    it('returns null for blog posts and other unrelated paths', () => {
      expect(backCategoryFor('/blog/some-post')).toBeNull();
      expect(backCategoryFor('/')).toBeNull();
    });
  });
});

describe('hubIdForSlug (drift guard)', () => {
  it('returns the hub id for every 2-segment slug registered in HUB_META', () => {
    // 2-segment pages: every hub has a flat page that maps to its own id.
    for (const hub of HUB_META) {
      expect(hubIdForSlug(hub.id), `hub ${hub.id} should resolve to itself`).toBe(hub.id);
    }
  });

  it('returns a real hub id for every page tab in HUB_META', () => {
    const HUB_IDS = new Set(HUB_META.map((h) => h.id));
    for (const hub of HUB_META) {
      for (const page of hub.pages) {
        const rel = page.path.replace(/^\/threatintel\//, '');
        const parts = rel.split('/');
        // For 2-segment paths the slug is the hub id (covered above).
        if (parts.length === 2) {
          const slug = parts[1]!;
          const resolved = hubIdForSlug(slug);
          expect(resolved, `slug "${slug}" from ${page.path}`).toBeDefined();
          expect(HUB_IDS.has(resolved!), `slug "${slug}" resolved to unknown hub "${resolved}"`).toBe(true);
        }
      }
    }
  });
});
