-- Migration 0049: cs_posts.quality_total -> word_count
--
-- The column held `Post.quality.total`: a 0-100 composite built from word
-- count, section count, sentences-per-section, a keyword match against a
-- "technical terms" list, and a filler-phrase penalty.
--
-- That score no longer exists. The content pipeline no longer computes a
-- quality score at all — the research stage supplies verified facts upstream
-- of the writer, and a human approves the draft in /admin/drafts. What the
-- pipeline records now is factual counters (`Post.audit`).
--
-- Renaming rather than reusing the old name matters: `quality_total` holding
-- a word count would mislead anyone querying the table, and a future "top
-- quality posts" query would silently rank by length.
--
-- Old values are NOT comparable across the rename (0-100 scores vs word
-- counts), so existing rows are cleared to NULL and repopulated on the next
-- publish. Leaving them in place would report a meaningless number.
--
-- SQLite supports RENAME COLUMN from 3.25; D1 ships well past it.

ALTER TABLE cs_posts RENAME COLUMN quality_total TO word_count;

-- Invalidate rows written under the old semantics.
UPDATE cs_posts SET word_count = NULL WHERE word_count IS NOT NULL;
