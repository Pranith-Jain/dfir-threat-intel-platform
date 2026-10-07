import type { Candidate, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { parseRssItems, isValidHttpUrl, type RssRunnerDeps } from './rss-util';
import { dayOfYear } from './rotation';

/**
 * AI SecOps — AI inside the security function.
 *
 * Distinct from `aisec` (attacks ON AI systems) and `llm` (model-level
 * security: injection, jailbreak, tool poisoning). This one covers the
 * operator side: triage copilots, alert reduction, AI-assisted detection
 * authoring, autonomous response, and honest evaluations of whether any of
 * it works.
 *
 * Sources are vendor research desks and industry analysis rather than CERT
 * advisories, because this topic moves at the speed of product releases and
 * research posts, not vulnerability disclosures.
 */

const FEEDS = [
  'https://www.microsoft.com/en-us/security/blog/feed/',
  'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
  'https://www.sentinelone.com/labs/feed/',
  'https://www.wiz.io/blog/rss.xml',
  'https://therecord.media/feed/',
  'https://feeds.feedburner.com/TheHackersNews',
];

/** Material that is genuinely about AI in a security workflow. */
const RELEVANT =
  /\b(ai|artificial intelligence|machine learning|\bml\b|llm|genai|agentic|copilot|automated triage|ai-assisted|ai-generated|soc analyst|security operations|siem|soar)\b/i;

/** A hunting write-up is more useful as a hunt than as an AI-SecOps post. */
function classify(title: string): CaseStudyType {
  return /\b(detection rule|sigma|yara|hunting|hunt\b|kql|spl query)\b/i.test(title) ? 'hunting' : 'aisecops';
}

export type DiscoverDeps = RssRunnerDeps;

export const discoverAiSecOps = async (deps: DiscoverDeps): Promise<Candidate[]> => {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - 10 * 24 * 3600 * 1000;

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

        const key = topicKey('aisecops', item.link);
        const dedup = await deps.getDedup(key);
        const score = finalScore({
          recency: recencyScore(item.date.toISOString(), deps.now),
          severity: severityScore({}),
          novelty: noveltyScore(dedup, deps.now),
          sourceWeight: 0.6,
        });

        out.push({
          key,
          type: classify(item.title),
          title: item.title.slice(0, 200),
          rationale: `AI in a security operations workflow, published by ${feedHost} on ${item.date
            .toISOString()
            .slice(0, 10)}.`,
          score: Number(score.toFixed(4)),
          evidence: {
            url: item.link,
            sources: [item.link],
            source: feed,
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
