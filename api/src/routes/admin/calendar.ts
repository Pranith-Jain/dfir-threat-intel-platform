/**
 * Content calendar + funnel-mix route.
 *
 * The content-engine skill calls for "posting order only if it helps
 * execution" and the research docs describe a TOFU/MOFU/BOFU funnel mix
 * (60/30/10). The planner already does per-week type diversity, but
 * there's no operator-facing view of the content mix over time — no way
 * to see "this week is all ransomware posts, no CVE/actor/breach
 * diversity."
 *
 * This route aggregates:
 *   - Scheduled slots (from the planner — what's queued for the week)
 *   - Recently published posts (from the post index)
 *   - Pending candidates (from the discovery queue)
 *
 * Into a calendar view grouped by day, with a funnel-mix breakdown showing
 * how the scheduled + published content maps to awareness (TOFU) /
 * consideration (MOFU) / decision (BOFU) categories.
 *
 * The funnel mapping:
 *   TOFU (awareness): cve, ransom, breach, scam, news, trend, briefing
 *   MOFU (consideration): actor, malware, intel, aisec, agentic, hunting, report
 *   BOFU (decision): methodology, tool, osint
 *
 * This is advisory — the planner doesn't enforce the mix, it just reports
 * it so the operator can manually approve/skip candidates to rebalance.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { getSchedule } from '../../case-study/storage/schedule';
import { listPostIndex } from '../../case-study/storage/posts';
import { listApproved } from '../../case-study/storage/approved';
import type { CaseStudyType, PostIndexEntry, Slot, Candidate } from '../../case-study/types';

export const calendarRouter = new Hono<{ Bindings: Env }>();

/** Map a CaseStudyType to a funnel stage. */
const FUNNEL_MAP: Record<CaseStudyType, 'tofu' | 'mofu' | 'bofu'> = {
  // Awareness — things that just happened and someone needs to act on
  cve: 'tofu',
  vulnfaq: 'tofu',
  exploit: 'tofu',
  breach: 'tofu',
  scam: 'tofu',
  news: 'tofu',
  trend: 'tofu',
  darkweb: 'tofu',
  supplychain: 'tofu',
  briefing: 'tofu',
  // Consideration — deep-dives, tradecraft, AI security analysis
  actor: 'mofu',
  malware: 'mofu',
  intel: 'mofu',
  aisec: 'mofu',
  llm: 'mofu',
  aisecops: 'mofu',
  agentic: 'mofu',
  hunting: 'mofu',
  report: 'mofu',
  analysis: 'mofu', // thought leadership sits in consideration
  // Decision — methodology, tools, how-to
  methodology: 'bofu',
  tool: 'bofu',
  osint: 'bofu',
};

/** Target funnel mix (60/30/10) per the research docs. */
const TARGET_MIX = { tofu: 0.6, mofu: 0.3, bofu: 0.1 };

interface CalendarDay {
  date: string; // YYYY-MM-DD
  label: string; // Mon, Tue, etc.
  slots: Array<{
    slotAt: string;
    candidateId: string;
    status: Slot['status'];
    publishedSlug?: string;
    type?: CaseStudyType;
    title?: string;
    funnel: 'tofu' | 'mofu' | 'bofu';
  }>;
  published: Array<{
    slug: string;
    title: string;
    type: CaseStudyType;
    funnel: 'tofu' | 'mofu' | 'bofu';
  }>;
}

interface FunnelMix {
  tofu: number;
  mofu: number;
  bofu: number;
  total: number;
  /** How far the actual mix is from the 60/30/10 target (0 = perfect, 1 = worst). */
  divergence: number;
  /** Per-type breakdown. */
  byType: Record<string, number>;
}

interface CalendarResponse {
  days: CalendarDay[];
  funnelMix: FunnelMix;
  /** Target mix for comparison. */
  target: { tofu: number; mofu: number; bofu: number };
  /** Pending candidates count (available to schedule). */
  pendingCount: number;
  /** Approved candidates count (queued for scheduling). */
  approvedCount: number;
  /** Scheduled but not yet published. */
  scheduledCount: number;
  /** Published in the window. */
  publishedCount: number;
}

function funnelFor(type: CaseStudyType): 'tofu' | 'mofu' | 'bofu' {
  return FUNNEL_MAP[type] ?? 'mofu';
}

function dayKey(iso: string): string {
  return iso.slice(0, 10); // YYYY-MM-DD
}

function dayLabel(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { weekday: 'short' });
  } catch {
    return '???';
  }
}

/** Compute funnel mix divergence from target (0 = perfect, 1 = worst). */
function mixDivergence(mix: { tofu: number; mofu: number; bofu: number }): number {
  const total = mix.tofu + mix.mofu + mix.bofu;
  if (total === 0) return 0;
  const actual = { tofu: mix.tofu / total, mofu: mix.mofu / total, bofu: mix.bofu / total };
  // L1 distance from target, normalized to 0-1
  const diff =
    Math.abs(actual.tofu - TARGET_MIX.tofu) +
    Math.abs(actual.mofu - TARGET_MIX.mofu) +
    Math.abs(actual.bofu - TARGET_MIX.bofu);
  return Number((diff / 2).toFixed(3)); // max divergence = 2 (all in one stage, target in another)
}

calendarRouter.get('/calendar', async (c) => {
  const now = new Date();
  // Window: today + 14 days forward (the planner schedules ~1 week ahead)
  const windowStart = new Date(now);
  windowStart.setUTCHours(0, 0, 0, 0);
  const windowEnd = new Date(windowStart.getTime() + 14 * 24 * 3600 * 1000);

  const [schedule, postIndex, approved] = await Promise.all([
    getSchedule(c.env.CASE_STUDIES),
    listPostIndex(c.env.CASE_STUDIES),
    listApproved(c.env.CASE_STUDIES),
  ]);

  // Build a lookup of approved candidates by key (for title/type on slots)
  const approvedMap = new Map<string, Candidate>();
  for (const cand of approved) approvedMap.set(cand.key, cand);

  // Build a lookup of published posts by slug (for type on published slots)
  const postMap = new Map<string, PostIndexEntry>();
  for (const p of postIndex) postMap.set(p.slug, p);

  // Group scheduled slots by day
  const days: CalendarDay[] = [];
  const dayMap = new Map<string, CalendarDay>();
  for (let i = 0; i < 14; i++) {
    const d = new Date(windowStart.getTime() + i * 24 * 3600 * 1000);
    const key = d.toISOString().slice(0, 10);
    const day: CalendarDay = { date: key, label: dayLabel(d.toISOString()), slots: [], published: [] };
    days.push(day);
    dayMap.set(key, day);
  }

  // Assign scheduled slots to days
  for (const slot of schedule) {
    const slotDate = new Date(slot.slotAt);
    if (slotDate < windowStart || slotDate > windowEnd) continue;
    const key = dayKey(slot.slotAt);
    const day = dayMap.get(key);
    if (!day) continue;

    // Resolve the candidate for type/title
    const cand = approvedMap.get(slot.candidateId);
    const publishedPost = slot.publishedSlug ? postMap.get(slot.publishedSlug) : undefined;
    const type = publishedPost?.type ?? cand?.type;
    const title = publishedPost?.title ?? cand?.title;

    day.slots.push({
      slotAt: slot.slotAt,
      candidateId: slot.candidateId,
      status: slot.status,
      publishedSlug: slot.publishedSlug,
      type,
      title,
      funnel: type ? funnelFor(type) : 'mofu',
    });
  }

  // Assign published posts to days (within the window)
  for (const post of postIndex) {
    const pubDate = new Date(post.publishedAt);
    if (pubDate < windowStart || pubDate > windowEnd) continue;
    const key = dayKey(post.publishedAt);
    const day = dayMap.get(key);
    if (!day) continue;
    day.published.push({
      slug: post.slug,
      title: post.title,
      type: post.type,
      funnel: funnelFor(post.type),
    });
  }

  // Compute funnel mix across scheduled + published in the window
  const mix = { tofu: 0, mofu: 0, bofu: 0 };
  const byType: Record<string, number> = {};
  for (const day of days) {
    for (const slot of day.slots) {
      if (slot.status === 'published' || slot.status === 'pending' || slot.status === 'draft') {
        mix[slot.funnel]++;
        if (slot.type) byType[slot.type] = (byType[slot.type] ?? 0) + 1;
      }
    }
    for (const pub of day.published) {
      // Avoid double-counting: if the published post has a slot, it's
      // already counted above. Check by matching publishedSlug.
      const hasSlot = day.slots.some((s) => s.publishedSlug === pub.slug);
      if (!hasSlot) {
        mix[pub.funnel]++;
        byType[pub.type] = (byType[pub.type] ?? 0) + 1;
      }
    }
  }

  const total = mix.tofu + mix.mofu + mix.bofu;
  const scheduledCount = schedule.filter(
    (s) => s.status === 'pending' || s.status === 'draft' || s.status === 'publishing'
  ).length;
  const publishedCount = postIndex.filter((p) => {
    const d = new Date(p.publishedAt);
    return d >= windowStart && d <= windowEnd;
  }).length;

  const response: CalendarResponse = {
    days,
    funnelMix: {
      ...mix,
      total,
      divergence: mixDivergence(mix),
      byType,
    },
    target: TARGET_MIX,
    pendingCount: 0, // filled below (separate KV read)
    approvedCount: approved.length,
    scheduledCount,
    publishedCount,
  };

  // Pending count requires a separate read — best-effort, non-blocking
  try {
    const { countAllCandidates } = await import('../../case-study/storage/candidates');
    response.pendingCount = await countAllCandidates(c.env.CASE_STUDIES);
  } catch {
    // non-critical
  }

  return c.json(response);
});
