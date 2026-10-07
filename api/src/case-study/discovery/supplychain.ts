import type { Candidate, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { parseRssItems, isValidHttpUrl, type RssRunnerDeps } from './rss-util';
import { dayOfYear } from './rotation';

/**
 * Supply chain and third-party risk.
 *
 * Covers the links between organisations rather than the endpoints: package
 * registries, CI/CD and build pipelines, update channels, SaaS and OAuth
 * applications, managed service providers whose compromise propagates to
 * every client, and the concentration risk in the vendors many organisations
 * all depend on.
 *
 * The distinction from the plain `cve` runner matters: a vulnerable
 * dependency nobody uses is a scan finding, while a compromised dependency
 * at build time reaches every downstream artefact. Sources skew CERT alerts
 * and vendor research rather than exploit feeds.
 */

const FEEDS = [
  'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  'https://www.bleepingcomputer.com/feed/',
  'https://www.darkreading.com/rss.xml',
  'https://unit42.paloaltonetworks.com/feed/',
  'https://blog.talosintelligence.com/rss/',
  'https://www.wiz.io/blog/rss.xml',
  'https://feeds.feedburner.com/TheHackersNews',
  'https://www.crowdstrike.com/blog/feed/',
];

/** Content that is genuinely about a link in the chain, not a local bug. */
const RELEVANT =
  /\b(supply chain|third.party|third party|dependency|dependencies|package (registry|manager)|npm|pypi|maven|nuget|container image|docker|kubernetes|ci\/cd|pipeline|build system|update (channel|mechanism)|compromised (package|library|account|dependency)|oauth (app|application)|saas|managed service|msp\b|vendor (risk|compromise)|typosquat|dependency confusion|code signing|signed (build|binary)|open source maintainer)\b/i;

const TYPE_MAP: Array<[RegExp, CaseStudyType]> = [
  [/\b(pipeline|ci\/cd|build system|code signing|dependency confusion|typosquat)\b/i, 'supplychain'],
  [/\b(container|kubernetes|docker|registry|artifact)\b/i, 'supplychain'],
  [/\b(saas|oauth (app|application)|managed service|msp\b)\b/i, 'supplychain'],
  [/\b(vulnerability|cve-|patch|advisory)\b/i, 'supplychain'],
];

function classify(title: string): CaseStudyType {
  for (const [re, type] of TYPE_MAP) if (re.test(title)) return type;
  return 'supplychain';
}

export type DiscoverDeps = RssRunnerDeps;

export const discoverSupplyChain = async (deps: DiscoverDeps): Promise<Candidate[]> => {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - 12 * 24 * 3600 * 1000;

  for (const feed of FEEDS) {
    try {
      const res = await deps.fetch(feed, {
        headers: {
          Accept: 'application/rss+xml, application/xml, */*',
          'User-Agent': 'pranithjain.qzz.io case-study-discovery',
        },
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) continue;
      const xml = await res.text();
      const feedHost = new URL(feed).hostname.replace(/^www\./, '');

      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        if (!isValidHttpUrl(item.link)) continue;
        if (!RELEVANT.test(item.title)) continue;

        const key = topicKey('supplychain', item.link);
        const dedup = await deps.getDedup(key);

        out.push({
          key,
          type: classify(item.title),
          title: item.title.slice(0, 200),
          rationale: `A link in the software supply chain, published by ${feedHost} on ${item.date
            .toISOString()
            .slice(0, 10)}.`,
          score: Number(
            finalScore({
              recency: recencyScore(item.date.toISOString(), deps.now),
              severity: severityScore({}),
              novelty: noveltyScore(dedup, deps.now),
              sourceWeight: 0.65,
            }).toFixed(4)
          ),
          evidence: {
            url: item.link,
            sources: [item.link],
            publisher: feedHost,
            publishedAt: item.date.toISOString(),
            provenance: `rss · ${feedHost} · day ${dayOfYear(deps.now)}`,
          },
          discoveredAt: deps.now.toISOString(),
          status: 'pending',
        });
      }
    } catch {
      // One dead feed never fails the runner.
    }
  }
  return out;
};
