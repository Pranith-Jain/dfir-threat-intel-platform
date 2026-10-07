/**
 * Content Utilities
 *
 * Shared utilities for blog, research, and social media content:
 *   - Reading time estimation
 *   - Table of contents extraction
 *   - Hashtag generation
 *   - Social sharing URLs
 *   - Content quality scoring
 */

// ── Reading Time ─────────────────────────────────────────────────

/**
 * Estimate reading time for content.
 * Average reading speed: 200-250 words per minute for technical content.
 * Accounts for code blocks (slower) and images (pauses).
 *
 * @param content - Markdown or plain text content
 * @returns Reading time in minutes (minimum 1)
 */
export function estimateReadingTime(content: string): number {
  if (!content) return 1;

  // Remove code blocks and count them separately
  const codeBlocks = content.match(/```[\s\S]*?```/g) ?? [];
  const codeTime = codeBlocks.length * 0.5; // 30 seconds per code block

  // Remove code, HTML, markdown syntax for word count
  const plainText = content
    .replace(/```[\s\S]*?```/g, '')
    .replace(/<[^>]+>/g, '')
    .replace(/[#*_~`\[\]()]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  const wordCount = plainText.split(/\s+/).filter(Boolean).length;
  const wordsPerMinute = 220; // Technical content reading speed
  const readingMinutes = wordCount / wordsPerMinute;

  // Add time for images (average 5 seconds each)
  const imageCount = (content.match(/!\[.*?\]\(.*?\)/g) ?? []).length;
  const imageTime = imageCount * (5 / 60);

  return Math.max(1, Math.ceil(readingMinutes + codeTime + imageTime));
}

// ── Table of Contents ────────────────────────────────────────────

interface TocEntry {
  id: string;
  text: string;
  level: number; // 2 = h2, 3 = h3
}

/**
 * Extract table of contents from markdown content.
 * Returns an array of headings with IDs for anchor links.
 *
 * @param content - Markdown content
 * @returns Array of TOC entries
 */
export function extractTableOfContents(content: string): TocEntry[] {
  const headings: TocEntry[] = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const match = /^(#{2,3})\s+(.+)$/.exec(line);
    if (match) {
      const level = match[1]!.length;
      const text = match[2]!.trim();
      // Generate ID from heading text
      const id = text
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .slice(0, 80);

      headings.push({ id, text, level });
    }
  }

  return headings;
}

/**
 * Add IDs to headings in HTML content for anchor links.
 *
 * @param html - HTML content
 * @returns HTML with IDs added to headings
 */
export function addHeadingIds(html: string): string {
  return html.replace(/<h([23])(.*?)>(.*?)<\/h\1>/gi, (_match, level, attrs, text) => {
    const id = text
      .toLowerCase()
      .replace(/<[^>]+>/g, '')
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .slice(0, 80);
    return `<h${level}${attrs} id="${id}">${text}</h${level}>`;
  });
}

// ── Hashtag Generation ───────────────────────────────────────────

interface HashtagOptions {
  /** Maximum number of hashtags to return */
  max?: number;
  /** Platform-specific constraints */
  platform?: 'twitter' | 'linkedin';
  /** Include trending/seasonal tags */
  includeTrending?: boolean;
}

/**
 * Generate relevant hashtags from content.
 * Uses keyword extraction and maps to common CTI hashtags.
 *
 * @param title - Content title
 * @param body - Content body
 * @param tags - Existing content tags
 * @param options - Hashtag generation options
 * @returns Array of hashtags (without #)
 */
export function generateHashtags(
  title: string,
  body: string,
  tags: string[] = [],
  options: HashtagOptions = {}
): string[] {
  const { max = 5, platform = 'twitter' } = options;
  const content = `${title} ${body}`.toLowerCase();

  const hashtags = new Set<string>();

  // Always include platform-specific defaults
  if (platform === 'twitter') {
    hashtags.add('cybersecurity');
  } else {
    hashtags.add('cybersecurity');
    hashtags.add('infosec');
  }

  // Map keywords to hashtags
  const keywordMap: Record<string, string> = {
    ransomware: 'ransomware',
    apt: 'apt',
    malware: 'malware',
    phishing: 'phishing',
    vulnerability: 'vulnerability',
    cve: 'cve',
    'zero-day': 'zeroday',
    'zero day': 'zeroday',
    'threat actor': 'threatactor',
    'threat intelligence': 'threatintel',
    dfir: 'dfir',
    'incident response': 'incidentresponse',
    forensics: 'forensics',
    osint: 'osint',
    'dark web': 'darkweb',
    breach: 'databreach',
    'data breach': 'databreach',
    'cloud security': 'cloudsecurity',
    'api security': 'apisecurity',
    'supply chain': 'supplychain',
    iot: 'iot',
    'ai security': 'aisecurity',
    'machine learning': 'machinelearning',
    detection: 'detection',
    hunting: 'threathunting',
    mitre: 'mitre',
    'att&ck': 'mitreattack',
    sigma: 'sigma',
    yara: 'yara',
    suricata: 'suricata',
  };

  // Check content for keyword matches
  for (const [keyword, hashtag] of Object.entries(keywordMap)) {
    if (content.includes(keyword)) {
      hashtags.add(hashtag);
    }
  }

  // Add from existing tags
  for (const tag of tags) {
    const normalized = tag.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (normalized.length >= 3 && normalized.length <= 20) {
      hashtags.add(normalized);
    }
  }

  // Platform-specific limits
  const limit = platform === 'twitter' ? Math.min(max, 3) : Math.min(max, 5);

  return Array.from(hashtags).slice(0, limit);
}

// ── Social Sharing URLs ──────────────────────────────────────────

interface ShareUrls {
  twitter: string;
  linkedin: string;
  reddit: string;
  hackernews: string;
  email: string;
}

/**
 * Generate social sharing URLs for content.
 *
 * @param title - Content title
 * @param url - Content URL
 * @param hashtags - Optional hashtags for Twitter
 * @returns Object with sharing URLs for each platform
 */
export function generateShareUrls(title: string, url: string, hashtags: string[] = []): ShareUrls {
  const encodedTitle = encodeURIComponent(title);
  const encodedUrl = encodeURIComponent(url);
  const twitterHashtags = hashtags.length > 0 ? `&hashtags=${hashtags.join(',')}` : '';

  return {
    twitter: `https://twitter.com/intent/tweet?text=${encodedTitle}&url=${encodedUrl}${twitterHashtags}`,
    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`,
    reddit: `https://reddit.com/submit?url=${encodedUrl}&title=${encodedTitle}`,
    hackernews: `https://news.ycombinator.com/submitlink?u=${encodedUrl}&t=${encodedTitle}`,
    email: `mailto:?subject=${encodedTitle}&body=Check out this article: ${encodedUrl}`,
  };
}

// ── Related Posts ────────────────────────────────────────────────

interface PostMeta {
  slug: string;
  title: string;
  tags: string[];
  type: string;
}

/**
 * Find related posts based on tag overlap and type similarity.
 *
 * @param current - Current post metadata
 * @param allPosts - All available posts
 * @param limit - Maximum related posts to return
 * @returns Array of related posts sorted by relevance
 */
export function findRelatedPosts(current: PostMeta, allPosts: PostMeta[], limit: number = 3): PostMeta[] {
  const scored = allPosts
    .filter((p) => p.slug !== current.slug)
    .map((post) => {
      let score = 0;

      // Tag overlap (highest weight)
      const tagOverlap = current.tags.filter((t) => post.tags.includes(t)).length;
      score += tagOverlap * 3;

      // Same type bonus
      if (post.type === current.type) score += 2;

      // Title word overlap
      const currentWords = new Set(current.title.toLowerCase().split(/\s+/));
      const postWords = post.title.toLowerCase().split(/\s+/);
      const wordOverlap = postWords.filter((w) => currentWords.has(w) && w.length > 3).length;
      score += wordOverlap;

      return { post, score };
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);

  return scored.map((item) => item.post);
}

// ── Optimal Posting Time ─────────────────────────────────────────

interface PostingTimeSuggestion {
  platform: 'twitter' | 'linkedin';
  day: string;
  time: string;
  reason: string;
}

/**
 * Suggest optimal posting times based on platform and content type.
 * Based on industry research for cybersecurity content.
 *
 * @param platform - Target platform
 * @param contentType - Type of content being posted
 * @returns Posting time suggestion with reasoning
 */
export function suggestPostingTime(
  platform: 'twitter' | 'linkedin',
  contentType: string = 'general'
): PostingTimeSuggestion {
  const suggestions: Record<string, Record<string, PostingTimeSuggestion>> = {
    twitter: {
      general: {
        platform: 'twitter',
        day: 'Tuesday-Thursday',
        time: '9:00-11:00 AM EST',
        reason: 'Peak engagement for professional content. Avoid Mondays (inbox catchup) and Fridays (weekend mode).',
      },
      breaking: {
        platform: 'twitter',
        day: 'Any',
        time: 'Immediately',
        reason: 'Breaking news gets 3x more engagement when posted within 1 hour of the event.',
      },
      technical: {
        platform: 'twitter',
        day: 'Tuesday-Wednesday',
        time: '10:00 AM - 12:00 PM EST',
        reason: 'Technical content performs best mid-week when practitioners are in deep-work mode.',
      },
    },
    linkedin: {
      general: {
        platform: 'linkedin',
        day: 'Tuesday-Thursday',
        time: '8:00-10:00 AM EST',
        reason: 'LinkedIn engagement peaks early in the workday. Tuesday-Thursday avoids weekend drop-off.',
      },
      technical: {
        platform: 'linkedin',
        day: 'Wednesday',
        time: '9:00-11:00 AM EST',
        reason: 'Wednesday is the peak day for technical content engagement on LinkedIn.',
      },
      career: {
        platform: 'linkedin',
        day: 'Tuesday-Thursday',
        time: '7:30-8:30 AM EST',
        reason: 'Career content performs best when professionals are planning their day.',
      },
    },
  };

  const platformSuggestions = (suggestions[platform] ?? suggestions.twitter)!;
  return platformSuggestions[contentType] ?? platformSuggestions.general!;
}
