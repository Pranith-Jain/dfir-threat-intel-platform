import type { D1Database } from '@cloudflare/workers-types';
import type { Post } from '../types';

/** Upsert a published post into the D1 `cs_posts` table — mirror of KV storage. */
export async function upsertCsPostD1(db: D1Database, post: Post): Promise<void> {
  await db
    .prepare(
      `INSERT INTO cs_posts (slug, title, type, excerpt, body, published_at, tags, candidate_id, ioc_count, source_count, word_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(slug) DO UPDATE SET
         title = excluded.title,
         excerpt = excluded.excerpt,
         body = excluded.body,
         tags = excluded.tags,
         ioc_count = excluded.ioc_count,
         source_count = excluded.source_count,
         word_count = excluded.word_count,
         updated_at = datetime('now')`
    )
    .bind(
      post.slug,
      post.title,
      post.type,
      post.excerpt ?? '',
      post.body,
      post.publishedAt ?? new Date().toISOString(),
      JSON.stringify(post.tags ?? []),
      post.candidateId ?? null,
      post.iocs?.length ?? 0,
      post.sources?.length ?? 0,
      post.audit?.words ?? null
    )
    .run();
}

/** Remove a post from D1 by slug. */
export async function deleteCsPostD1(db: D1Database, slug: string): Promise<void> {
  await db.prepare('DELETE FROM cs_posts WHERE slug = ?').bind(slug).run();
}

/** Search posts by keyword (title/body/excerpt) with optional type filter. */
export async function searchCsPostsD1(
  db: D1Database,
  q: string,
  type?: string,
  limit = 50,
  offset = 0
): Promise<{ slug: string; title: string; type: string; publishedAt: string }[]> {
  let sql = `SELECT slug, title, type, published_at as publishedAt FROM cs_posts WHERE (title LIKE ? OR body LIKE ? OR excerpt LIKE ?)`;
  const params: unknown[] = [`%${q}%`, `%${q}%`, `%${q}%`];
  if (type) {
    sql += ` AND type = ?`;
    params.push(type);
  }
  sql += ` ORDER BY published_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);
  const { results } = await db
    .prepare(sql)
    .bind(...params)
    .all<{ slug: string; title: string; type: string; publishedAt: string }>();
  return results ?? [];
}
