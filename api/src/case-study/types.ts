// api/src/case-study/types.ts
import type { CarouselSpec } from './social/slide-spec';

/**
 * Content-engine topic types. Every type maps 1:1 to a discovery runner and
 * to a writing shape in `generation/templates.ts`.
 *
 * `ransom` was removed — the platform still tracks ransomware as an intel
 * SIGNAL (KEV `known_ransomware_campaign_use`, leak trackers, negotiation
 * data, graph ingest), but it is no longer a content topic. Its place in the
 * daily mix is taken by `darkweb` (leak sites, IAB listings, infostealer
 * logs), which covers the same ground with more signal per post.
 *
 * The 2026 additions cluster around what practitioners actually search for:
 *   - `vulnfaq`     answer-first vulnerability deep-dives
 *   - `exploit`     weaponisation timelines, PoC drops, exploit chains
 *   - `darkweb`     darkweb / deepweb / IAB / infostealer telemetry
 *   - `llm`         LLM + AI-model security (injection, MCP, jailbreaks)
 *   - `aisecops`    AI inside the SOC / SecOps (triage, copilots, AI-SOC)
 *   - `supplychain` dependency, CI/CD, registry and third-party risk
 */
export type CaseStudyType =
  // Vulnerability & exploitation
  | 'cve'
  | 'vulnfaq'
  | 'exploit'
  // Adversary & malware
  | 'actor'
  | 'malware'
  // Underground & data exposure
  | 'darkweb'
  | 'breach'
  // AI security (target = the AI system)
  | 'aisec'
  | 'llm'
  // AI security (tool = AI in the security function)
  | 'aisecops'
  | 'agentic'
  // Ecosystem
  | 'supplychain'
  | 'scam'
  // Analysis & craft
  | 'intel'
  | 'osint'
  | 'methodology'
  | 'trend'
  | 'briefing'
  | 'analysis'
  | 'tool'
  | 'news'
  | 'hunting'
  | 'report';

export type CandidateStatus = 'pending' | 'approved' | 'skipped' | 'published';

export interface Candidate {
  key: string; // stable key, e.g. "cve-2026-1234"
  type: CaseStudyType;
  title: string;
  rationale: string; // one-line why-this-matters
  score: number; // 0..1
  evidence: Record<string, unknown>; // type-specific snapshot
  discoveredAt: string; // ISO 8601
  status: CandidateStatus;
}

export interface Slot {
  slotAt: string; // ISO 8601
  candidateId: string; // stable key
  /**
   * `draft` is the new terminal state for the approval-gate flow: the
   * publisher generated the post but it's awaiting an admin click before
   * it goes public. Once approved it moves to `published`; once rejected
   * the slot stays at `draft` until the admin explicitly clears it.
   */
  status: 'pending' | 'publishing' | 'published' | 'failed' | 'draft';
  publishedSlug?: string;
  error?: string;
}

export interface PostIOC {
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256' | 'sha1' | 'md5' | 'email';
  value: string;
}

export interface PostSource {
  url: string;
  title: string;
}

/**
 * Factual measurements of a generated post, recorded for the admin to see.
 *
 * This is NOT a quality score and nothing gates publish on it. The previous
 * design scored output on length / section count / filler density and then
 * blocked the publish below a threshold. That machinery (plus its slop
 * detectors) reliably rejected good drafts and let mediocre ones through,
 * because the model was being trained against a checklist instead of being
 * given better facts. Editorial judgement now lives with the human reviewing
 * the draft in `/admin/drafts`; these counters exist so that human has the
 * numbers in front of them.
 */
export interface PostAudit {
  words: number;
  sections: number;
  /** Clickable markdown links in the body. */
  references: number;
  iocs: number;
  /**
   * Factual grounding notes raised while normalising the draft, e.g. a CVE
   * cited that does not appear in the research dossier. Informational only.
   */
  warnings: string[];
}

/**
 * Outcome of the generation-time reference HEAD-check. Surfaced in the
 * admin so an operator can tell verified citations from ones kept on the
 * benefit of the doubt ('unchecked' — a WAF block / 5xx / timeout that is
 * NOT proof the page is gone) and from confirmed-broken links that were
 * pruned before publish.
 */
export interface LinkVerification {
  /** Total distinct reference URLs probed. */
  checked: number;
  /** Resolved live (2xx, not a soft-404). */
  verified: number;
  /** Could not be confirmed dead (403/429/5xx/timeout) — kept, not pruned. */
  unchecked: number;
  /** Confirmed dead (404/410/soft-404/NXDOMAIN) — pruned before publish. */
  broken: number;
  /** The pruned URLs (first few), for the admin tooltip. */
  brokenUrls?: string[];
}

export interface Post {
  slug: string;
  type: CaseStudyType;
  title: string;
  excerpt: string;
  publishedAt: string; // ISO 8601
  candidateId: string;
  body: string; // markdown
  hero: string; // inline SVG (typographic banner; fallback when no AI hero)
  /** Public URL of the AI-generated hero illustration, when one was produced.
   *  The blog page prefers this over the SVG `hero`. */
  heroImageUrl?: string;
  iocs: PostIOC[];
  tags: string[];
  sources: PostSource[];
  /** Factual counters for the admin reviewer. Never a publish gate. */
  audit?: PostAudit;
  /** Reference-link HEAD-check outcome, for the admin verification badge. */
  linkVerification?: LinkVerification;
  /**
   * Optional snapshot of the original candidate's evidence, persisted
   * at generation time so the admin `/drafts/:slug/regenerate` (rewrite
   * mode) can re-run `generatePost` with the same facts even after the
   * candidate itself has been deleted (the publisher clears the
   * candidate blob on success). Unset for legacy posts.
   */
  evidence?: Record<string, unknown>;
  /**
   * Optional approval gate metadata. Absent for legacy auto-published
   * posts (treated as `published`). New posts go through `draft` first
   * when `BLOG_APPROVAL_REQUIRED=true` is set on the worker.
   */
  status?: 'draft' | 'published';
  /** ISO 8601 timestamp set when an admin approves a draft. */
  approvedAt?: string;
}

export interface PostIndexEntry {
  slug: string;
  title: string;
  type: CaseStudyType;
  excerpt: string;
  publishedAt: string;
  tags: string[];
  /** Stable key of the originating candidate. Set for drafts; may be absent
   *  for legacy published posts. Used by the Drafts tab to generate social
   *  copy from the candidate path when BLOG_APPROVAL_REQUIRED is on. */
  candidateId?: string;
}

export interface DedupRecord {
  lastSeenAt: string;
  publishedSlug?: string;
  /** ISO 8601. When in the future, discovery hard-suppresses this key
   *  (set by admin Skip / Clear-all). Distinct from the 60-day published
   *  republish-block, which is keyed off `publishedSlug`. */
  suppressedUntil?: string;
}

export interface FailureRecord {
  slotId: string;
  candidateId: string;
  error: string;
  rawOutput?: string;
  failedAt: string;
  retries: number;
}

export interface SocialContent {
  slug: string;
  twitter: string;
  linkedin: string;
  instagram?: string;
  carousel?: CarouselSpec;
  /** Alternative opening hooks (different angles) for A/B / manual selection. */
  hooks?: string[];
  generatedAt: string;
  /**
   * Factual per-platform checks (character limits, CVE grounding, link
   * allowlist) recorded for the admin. Purely descriptive: the copy is never
   * regenerated or withheld because of a score. Underscore-prefixed because
   * it's metadata, not copy.
   */
  _validation?: {
    twitter_check?: SocialCheck;
    linkedin_check?: SocialCheck;
    instagram_check?: SocialCheck;
  };
}

/**
 * Factual, checkable properties of one platform's generated copy. Every
 * field here is either a measurement (counts, lengths) or a ground-truth
 * lookup (does this CVE exist in the dossier, is this host on the
 * allowlist). Nothing here encodes an opinion about how good the copy is.
 *
 * Lives here rather than in `generation/social.ts` so the route layer can
 * type the KV blob without importing from the generation module (which would
 * be a circular dependency).
 */
export interface SocialCheck {
  /** Longest single post (X) or the body before FIRST COMMENT (LinkedIn/IG). */
  char_count: number;
  /** True when that exceeds the platform's hard limit. */
  over_limit: boolean;
  /** CVEs in the copy with no match in the research dossier. */
  ungrounded_cves: string[];
  /** Links to hosts outside the allowlist, stripped before publishing. */
  untrusted_urls: number;
}

/** Per-platform posting state for the social scheduling queue.
 *
 *  Lifecycle: 'pending' (generated, awaiting human approval) → 'approved'
 *  (human OK'd the copy; the drip cron may auto-post once `scheduledAt` is
 *  due) → 'posted' (live, auto or manual) | 'failed' (an auto-post attempt
 *  errored). Instagram never auto-posts (personal-account API limit) — it
 *  only moves to 'posted' via the admin "mark posted". */
export interface SocialScheduleEntry {
  /** ISO 8601 — planned post time. The drip cron auto-posts an 'approved'
   *  entry only once this is in the past. */
  scheduledAt?: string;
  status: 'pending' | 'approved' | 'posted' | 'failed';
  /** ISO 8601 — set when posted (auto or manual). */
  postedAt?: string;
  /** Permalink returned by the platform on a successful auto-post. */
  postUrl?: string;
  /** Last auto-post error (when status is 'failed'). */
  error?: string;
  /** Count of auto-post attempts; the cron gives up past a cap. */
  attempts?: number;
}

/** Tracks each platform's generated copy through the approval/posting
 *  lifecycle. Auto-posting (X/LinkedIn only) is gated by approval + a due
 *  time + the SOCIAL_AUTOPOST_ENABLED master switch. */
export interface SocialSchedule {
  slug: string;
  twitter?: SocialScheduleEntry;
  linkedin?: SocialScheduleEntry;
  instagram?: SocialScheduleEntry;
  updatedAt: string;
}
