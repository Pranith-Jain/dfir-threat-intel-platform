import type { Candidate, CaseStudyType } from '../types';
import { topicKey } from '../stable-keys';
import { recencyScore, severityScore, noveltyScore, finalScore } from '../scoring';
import { parseRssItems, isValidHttpUrl, type RssRunnerDeps } from './rss-util';
import { dayOfYear } from './rotation';

/**
 * LLM and AI-model security.
 *
 * Covers attacks and weaknesses in the model layer itself: prompt injection,
 * jailbreaks, indirect injection through retrieved content, tool and MCP
 * server compromise, agent hijacking, model theft, training-data poisoning,
 * and the supply chain of model weights and adapters.
 *
 * Sources skew academic and standards bodies rather than breach-disclosure
 * feeds, because the interesting material here is published as research
 * (arXiv, OWASP GenAI, vendor AI security desks) months before it appears in
 * a CVE record.
 */

const FEEDS = [
  'https://genai.owasp.org/feed/',
  'https://owasp.org/feed/',
  'https://arxiv.org/rss/cs.CR',
  'https://arxiv.org/rss/cs.AI',
  'https://unit42.paloaltonetworks.com/feed/',
  'https://www.wiz.io/blog/rss.xml',
  'https://blog.talosintelligence.com/rss/',
  'https://www.horizon3.ai/feed/',
];

/** Terms that indicate genuinely model-level security content. */
const LLM_RELEVANT =
  /\b(llm|large language model|prompt injection|jailbreak|mcp|model context protocol|agent|ai agent|tool (use|call|poisoning)|rag\b|retrieval.augmented|model (theft|poisoning|extraction|inversion)|adversarial (example|input|prompt)|guardrail|system prompt|ai security|model security|prompt)\b/i;

const TYPE_MAP: Array<[RegExp, CaseStudyType]> = [
  [/\b(agent|tool call|mcp|autonomous)\b/i, 'agentic'],
  [/\b(prompt injection|jailbreak|rag\b|guardrail|context poisoning)\b/i, 'llm'],
];

/** Research papers are 'llm'; everything else stays 'llm' unless it is
 *  specifically about agent architectures. */
function classify(title: string): CaseStudyType {
  for (const [re, type] of TYPE_MAP) if (re.test(title)) return type;
  return 'llm';
}

export type DiscoverDeps = RssRunnerDeps;

export const discoverLlmSec = async (deps: DiscoverDeps): Promise<Candidate[]> => {
  const out: Candidate[] = [];
  const cutoff = deps.now.getTime() - 14 * 24 * 3600 * 1000;

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
      const isArxiv = feedHost.includes('arxiv');

      for (const item of parseRssItems(xml, deps.now)) {
        if (item.date.getTime() < cutoff) continue;
        if (!isValidHttpUrl(item.link)) continue;
        if (!LLM_RELEVANT.test(item.title)) continue;

        const key = topicKey('llm', item.link);
        const dedup = await deps.getDedup(key);
        const score = finalScore({
          recency: recencyScore(item.date.toISOString(), deps.now),
          severity: severityScore({}),
          novelty: noveltyScore(dedup, deps.now),
          // Research desks and preprints are the primary sources for this
          // topic; arXiv in particular is where new attack classes appear
          // first.
          sourceWeight: isArxiv ? 0.75 : 0.65,
        });

        out.push({
          key,
          type: classify(item.title),
          title: item.title.slice(0, 200),
          rationale: `Model-level security research published by ${feedHost} on ${item.date
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
