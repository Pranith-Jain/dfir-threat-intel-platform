import type { Candidate, DedupRecord } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityFromText, noveltyScore, finalScore } from '../scoring';
import { parseRssItems } from './rss-util';

const WINDOW_MS = 7 * 24 * 3600 * 1000;

export interface DiscoverAdvisoriesDeps {
  fetch: typeof globalThis.fetch;
  now: Date;
  getDedup: (stableKey: string) => Promise<DedupRecord | null>;
  feeds: string[];
}

/** Government/regional advisory + state-actor research feeds → `intel`
 *  candidates. Mirrors discoverIntel; a real UA avoids CISA bot 403s. */
export async function discoverAdvisories(deps: DiscoverAdvisoriesDeps): Promise<Candidate[]> {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - WINDOW_MS;
  for (const feed of deps.feeds) {
    try {
      const r = await deps.fetch(feed, {
        headers: {
          Accept: 'application/rss+xml, application/atom+xml, application/xml, */*',
          'User-Agent': 'pranithjain.qzz.io case-study-discovery',
        },
      });
      if (!r.ok) continue;
      const xml = await r.text();
      const feedHost = new URL(feed).hostname.replace(/^www\./, '');
      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        const key = topicKey('intel', item.link || item.title);
        const dedup = await deps.getDedup(key);
        const score = finalScore({
          recency: recencyScore(item.date.toISOString(), deps.now),
          severity: severityFromText(item.title),
          novelty: noveltyScore(dedup, deps.now),
          sourceWeight: 0.7,
        });
        out.push({
          key,
          type: 'intel',
          title: item.title,
          rationale: `Advisory · ${feedHost} · ${item.date.toISOString().slice(0, 10)}`,
          score,
          evidence: { url: item.link, published: item.date.toISOString(), source: feed },
          discoveredAt: deps.now.toISOString(),
          status: 'pending',
        });
      }
    } catch {}
  }
  return out;
}
