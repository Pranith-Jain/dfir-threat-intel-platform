import type { Candidate, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { parseRssItems, isValidHttpUrl, type RssRunnerDeps } from './rss-util';
import { dayOfYear } from './rotation';

/**
 * Infostealer and ClickFix telemetry.
 *
 * Two related themes that read as one to a defender and were being covered
 * as neither:
 *
 *  - **Infostealers.** Hudson Rock's infostealers.com publishes weekly
 *    reports with hard numbers that almost nothing else carries: infected
 *    machine counts, the specific domains and corporate tenants whose
 *    employees are compromised, which stealer families are active, and
 *    geography breakdowns. That is a genuinely different signal from a CVE
 *    feed — it measures where credentials are actually leaking right now,
 *    which is the question that determines whether an MFA rollout or an
 *    edge-device patch is the higher priority this quarter.
 *
 *  - **ClickFix.** The copy-paste-run social engineering family (fake
 *    CAPTCHA, fake browser update, fake Windows Update splash, the FileFix
 *    and ConsentFix variants). It needs no vulnerability at all, which is
 *    exactly why it keeps succeeding: there is no patch, so CVE feeds never
 *    mention it. Its artefacts are well documented and stable though — the
 *    RunMRU registry key, `mshta.exe` lineage, explorer-spawned shells,
 *    command-line length outliers — which makes it excellent hunting
 *    material and exactly the kind of thing this platform can write about
 *    with authority.
 *
 * Both classify into the existing type system: a stealer family with
 * technical detail is `malware`, a campaign/takedown story is `darkweb` or
 * `news`, and a weekly telemetry report is a `trend` or `briefing`.
 */

const FEEDS = [
  'https://www.infostealers.com/feed/',
  'https://www.proofpoint.com/us/blog/threat-insight/feed',
  'https://www.malwarebytes.com/blog/feed/',
  'https://www.splunk.com/en_us/blog/security/index.xml',
];

/** ClickFix and its named variants. */
const CLICKFIX_RE =
  /\b(clickfix|filefix|consentfix|fake ?captcha|fakecaptcha|clearfake|paste ?to ?run|copy.?and.?paste.?run)\b/i;

/** Infostealer families worth writing about by name. */
const STEALER_RE =
  /\b(redline|lumma|raccoon|vidar|amos|atomic stealer|amadey|stealc|rhadamanthys|smokeloader|phemedrone|metastealer|warden (stealer|infostealer)|arkei|earlybird|aurora stealer|luca stealer)\b/i;

/** Generic infostealer/ClickFix reporting language, used when neither a family
 *  nor the technique name appears in the title. */
const TOPIC_RE =
  /\b(infostealer|info.?stealer|stealer log|credential (dump|market|sale)|session (cookie|token)s?|browser (credential|password)s?|token theft|click.?fix|social engineering|malvertising|lure page|clipboard)\b/i;

function classify(title: string): CaseStudyType {
  const t = title.toLowerCase();
  if (CLICKFIX_RE.test(t)) return 'malware';
  if (STEALER_RE.test(t)) return 'malware';
  // Weekly telemetry reports are trend-shaped: the numbers are the story.
  if (/\b(weekly report|threat feeds report|monthly|statistics|totals|recap)\b/i.test(t)) return 'trend';
  if (/\b(takedown|disruption|indictment|arrest|seizure)\b/i.test(t)) return 'news';
  return 'darkweb';
}

export type DiscoverDeps = RssRunnerDeps;

export const discoverInfostealers = async (deps: DiscoverDeps): Promise<Candidate[]> => {
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
      const isHudsonRock = feedHost.includes('infostealers.com');

      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        if (!isValidHttpUrl(item.link)) continue;

        const haystack = `${item.title} ${item.link}`;
        if (!(CLICKFIX_RE.test(haystack) || STEALER_RE.test(haystack) || TOPIC_RE.test(haystack))) continue;

        const type = classify(item.title);
        const key = topicKey(type === 'trend' ? 'stealertrend' : 'infostealer', item.link);
        const dedup = await deps.getDedup(key);

        out.push({
          key,
          type,
          title: item.title.slice(0, 200),
          rationale: isHudsonRock
            ? `Infostealer telemetry with current infection counts and named compromised corporate tenants, published by ${feedHost} on ${item.date
                .toISOString()
                .slice(0, 10)}.`
            : `Infostealer or ClickFix delivery chain, published by ${feedHost} on ${item.date
                .toISOString()
                .slice(0, 10)}.`,
          score: Number(
            finalScore({
              recency: recencyScore(item.date.toISOString(), deps.now),
              severity: severityScore({}),
              novelty: noveltyScore(dedup, deps.now),
              // Hudson Rock publishes primary infostealer measurements;
              // the rest is vendor analysis of the same ecosystem.
              sourceWeight: isHudsonRock ? 0.8 : 0.7,
            }).toFixed(4)
          ),
          evidence: {
            url: item.link,
            sources: [item.link],
            publisher: feedHost,
            publishedAt: item.date.toISOString(),
            clickfix: CLICKFIX_RE.test(haystack),
            stealerFamily: (item.title.match(STEALER_RE)?.[0] ?? '').trim() || undefined,
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
