import { describe, it, expect } from 'vitest';
import {
  estimateReadingTime,
  extractTableOfContents,
  generateHashtags,
  generateShareUrls,
  findRelatedPosts,
  suggestPostingTime,
} from '../lib/content-utils';

describe('Content Utilities', () => {
  describe('estimateReadingTime', () => {
    it('returns 1 for empty content', () => {
      expect(estimateReadingTime('')).toBe(1);
    });

    it('calculates reading time for short content', () => {
      const content = 'This is a short paragraph with about ten words in it.';
      const time = estimateReadingTime(content);
      expect(time).toBe(1);
    });

    it('calculates reading time for long content', () => {
      // ~500 words at 220 wpm = ~2.3 minutes
      const content = 'word '.repeat(500);
      const time = estimateReadingTime(content);
      expect(time).toBeGreaterThanOrEqual(2);
      expect(time).toBeLessThanOrEqual(4);
    });

    it('adds time for code blocks', () => {
      const content = 'Some text\n```javascript\nconsole.log("hello");\n```\nMore text';
      const time = estimateReadingTime(content);
      expect(time).toBeGreaterThanOrEqual(1);
    });

    it('adds time for images', () => {
      const content = 'Text ![alt](image.png) more text ![alt2](image2.png)';
      const time = estimateReadingTime(content);
      expect(time).toBeGreaterThanOrEqual(1);
    });
  });

  describe('extractTableOfContents', () => {
    it('returns empty array for content without headings', () => {
      expect(extractTableOfContents('No headings here')).toEqual([]);
    });

    it('extracts h2 and h3 headings', () => {
      const content = '# Title\n## Section 1\n### Subsection\n## Section 2';
      const toc = extractTableOfContents(content);
      expect(toc).toHaveLength(3);
      expect(toc[0]!.level).toBe(2);
      expect(toc[0]!.text).toBe('Section 1');
      expect(toc[1]!.level).toBe(3);
      expect(toc[2]!.level).toBe(2);
    });

    it('generates IDs from heading text', () => {
      const content = '## My Section Title';
      const toc = extractTableOfContents(content);
      expect(toc[0]!.id).toBe('my-section-title');
    });
  });

  describe('generateHashtags', () => {
    it('returns default cybersecurity hashtag', () => {
      const tags = generateHashtags('Test title', 'Test body');
      expect(tags).toContain('cybersecurity');
    });

    it('detects ransomware keyword', () => {
      const tags = generateHashtags('Ransomware attack', 'LockBit ransomware group');
      expect(tags).toContain('ransomware');
    });

    it('detects multiple keywords', () => {
      const tags = generateHashtags('APT28 phishing attack', 'APT28 used phishing');
      expect(tags.length).toBeGreaterThan(1);
    });

    it('respects max parameter', () => {
      const tags = generateHashtags('Test', 'Test', [], { max: 2 });
      expect(tags.length).toBeLessThanOrEqual(2);
    });

    it('respects platform limits', () => {
      const twitterTags = generateHashtags('Test', 'Test', [], { platform: 'twitter', max: 10 });
      expect(twitterTags.length).toBeLessThanOrEqual(3);
    });
  });

  describe('generateShareUrls', () => {
    it('generates Twitter share URL', () => {
      const urls = generateShareUrls('Test Title', 'https://example.com');
      expect(urls.twitter).toContain('twitter.com');
      expect(urls.twitter).toContain(encodeURIComponent('Test Title'));
    });

    it('generates LinkedIn share URL', () => {
      const urls = generateShareUrls('Test', 'https://example.com');
      expect(urls.linkedin).toContain('linkedin.com');
    });

    it('includes hashtags in Twitter URL', () => {
      const urls = generateShareUrls('Test', 'https://example.com', ['cyber', 'infosec']);
      expect(urls.twitter).toContain('cyber');
    });
  });

  describe('findRelatedPosts', () => {
    const posts = [
      { slug: 'a', title: 'Ransomware Attack Analysis', tags: ['ransomware', 'lockbit'], type: 'ransom' },
      { slug: 'b', title: 'Phishing Campaign Detection', tags: ['phishing', 'email'], type: 'intel' },
      {
        slug: 'c',
        title: 'LockBit Ransomware Update',
        tags: ['ransomware', 'lockbit', 'threat-intel'],
        type: 'ransom',
      },
      { slug: 'd', title: 'Cloud Security Best Practices', tags: ['cloud', 'aws'], type: 'methodology' },
    ];

    it('finds related posts by tag overlap', () => {
      const current = { slug: 'x', title: 'LockBit Analysis', tags: ['ransomware', 'lockbit'], type: 'ransom' };
      const related = findRelatedPosts(current, posts, 2);
      expect(related.length).toBeGreaterThan(0);
      // Posts with 'ransomware' and 'lockbit' tags should rank highest
      expect(related[0]!.slug).toBe('a');
    });

    it('excludes current post', () => {
      const current = posts[0]!;
      const related = findRelatedPosts(current, posts);
      expect(related.every((p) => p.slug !== current.slug)).toBe(true);
    });

    it('respects limit parameter', () => {
      const current = { slug: 'x', title: 'Test', tags: ['ransomware'], type: 'ransom' };
      const related = findRelatedPosts(current, posts, 1);
      expect(related).toHaveLength(1);
    });
  });

  describe('suggestPostingTime', () => {
    it('returns suggestion for Twitter', () => {
      const suggestion = suggestPostingTime('twitter');
      expect(suggestion.platform).toBe('twitter');
      expect(suggestion.day).toBeDefined();
      expect(suggestion.time).toBeDefined();
      expect(suggestion.reason).toBeDefined();
    });

    it('returns suggestion for LinkedIn', () => {
      const suggestion = suggestPostingTime('linkedin');
      expect(suggestion.platform).toBe('linkedin');
    });

    it('returns different suggestions for different content types', () => {
      const general = suggestPostingTime('twitter', 'general');
      const breaking = suggestPostingTime('twitter', 'breaking');
      expect(general.day).toBeDefined();
      expect(breaking.day).toBeDefined();
    });
  });
});
