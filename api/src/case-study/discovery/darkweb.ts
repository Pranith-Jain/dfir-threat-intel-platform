import type { Candidate, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { parseRssItems, isValidHttpUrl, type RssRunnerDeps } from './rss-util';
import { dayOfYear } from './rotation';

/**
 * Darkweb and deepweb monitoring.
 *
 * Replaces the ransomware-victim runner in the content mix. Where that runner
 * produced a post per group per month ("Akira: 12 new victims this week"),
 * this one surfaces the underground signal that actually changes what a
 * defender does: what access is being offered, at what price, for which
 * targets, and what the infostealer logs show.
 *
 * Sources are the platform's own monitored surfaces. Leak-site and broker
 * content is not published by RSS, and we do not want to link to a live
 * criminal marketplace in a published post anyway — the reader gets the
 * finding and the defensive read, not a shopping link.
 */

const TYPE_MAP: Array<[RegExp, CaseStudyType]> = [
  // A specific product being offered is a supply-chain / third-party story.
  [
    /\b(vpn|firewall|forti|citrix|ivanti|cisco|palo alto|sap|exchange|sharepoint|citrix|manageengine|atlassian)\b/i,
    'supplychain',
  ],
  // Infostealer log dumps and credential sales are breach material.
  [/\b(stealer|redline|raccoon|lumma|amadey|vidar|credential dump|password dump|combo)\b/i, 'breach'],
  // A CVE for sale or a stated RCE is an exploitation story.
  [/\b(poc|exploit|rce|zero.day|weaponiz)\b/i, 'exploit'],
];

function classify(title: string, body: string): CaseStudyType {
  for (const [re, type] of TYPE_MAP) if (re.test(`${title} ${body}`)) return type;
  return 'darkweb';
}

export interface DarkwebDeps extends RssRunnerDeps {
  /** Query the platform's own darkweb monitor. Falls back to RSS-only. */
  fetchHits?: (limit: number) => Promise<Array<Record<string, unknown>>>;
}

/** Sources that report ON the underground rather than hosting it. */
const FEEDS = [
  'https://krebsonsecurity.com/feed/',
  'https://therecord.media/feed/',
  'https://www.bleepingcomputer.com/feed/',
  'https://www.darkreading.com/rss.xml',
  'https://www.securityweek.com/feed/',
  'https://securelist.com/feed/',
  'https://www.sentinelone.com/labs/feed/',
];

export const discoverDarkweb = async (deps: DarkwebDeps): Promise<Candidate[]> => {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - 7 * 24 * 3600 * 1000;

  // ── Platform's own monitored surfaces ────────────────────────────
  if (deps.fetchHits) {
    try {
      const hits = await deps.fetchHits(25);
      for (const hit of hits) {
        const title = String(hit.title ?? hit.name ?? '').trim();
        if (!title) continue;
        const detected = String(hit.detected_at ?? hit.date ?? hit.first_seen ?? '');
        const ts = Date.parse(detected);
        if (detected && !Number.isNaN(ts) && ts < cutoff) continue;

        const source = String(hit.source ?? hit.source_name ?? 'darkweb monitor');
        const key = topicKey('darkweb', String(hit.id ?? title).slice(0, 50));
        const dedup = await deps.getDedup(key);

        out.push({
          key,
          type: classify(title, JSON.stringify(hit).slice(0, 600)),
          title: title.slice(0, 200),
          rationale: `Observed on ${source}${detected ? ` on ${detected.slice(0, 10)}` : ''}. ${
            hit.summary ? String(hit.summary).slice(0, 200) : 'Underground telemetry on this topic.'
          }`,
          score: Number(
            finalScore({
              recency: 1,
              severity: severityScore({}),
              novelty: noveltyScore(dedup, deps.now),
              sourceWeight: 0.7,
            }).toFixed(4)
          ),
          evidence: {
            title,
            source,
            detectedAt: detected,
            summary: String(hit.summary ?? '').slice(0, 800),
            url: typeof hit.url === 'string' && hit.url.startsWith('http') ? hit.url : undefined,
            sources: typeof hit.url === 'string' && hit.url.startsWith('http') ? [hit.url] : [],
            provenance: `platform darkweb monitor · ${source}`,
          },
          discoveredAt: deps.now.toISOString(),
          status: 'pending',
        });
      }
    } catch {
      // Monitor unavailable — RSS path below still produces candidates.
    }
  }

  // ── Reporting on the underground ─────────────────────────────────
  const RELEVANT =
    /\b(dark ?web|deep ?web|initial access broker|\biab\b|access broker|infostealer|stealer|credential (sale|dump|market)|leak site|forum|marketplace|monero|xmr|onion|exploit broker|vulnerability broker|ransomware site)\b/i;

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

        const key = topicKey('darkweb-news', item.link);
        const dedup = await deps.getDedup(key);

        out.push({
          key,
          type: classify(item.title, xml.slice(0, 0)),
          title: item.title.slice(0, 200),
          rationale: `Reporting on underground activity, published by ${feedHost} on ${item.date
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
