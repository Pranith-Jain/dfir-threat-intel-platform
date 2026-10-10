import { describe, it, expect, beforeEach } from 'vitest';
import { env as testEnv } from 'cloudflare:test';
import {
  listAllCandidates,
  countAllCandidates,
  putCandidate,
  CANDIDATE_TYPES,
} from '../../src/case-study/storage/candidates';
import { buildVoiceProfileFromIndex } from '../../src/case-study/generation/voice-profile';
import { putPost, listPostIndex } from '../../src/case-study/storage/posts';
import { kv } from '../../src/case-study/kv-keys';
import type { Env } from '../../src/env';
import type { Candidate, CaseStudyType, Post } from '../../src/case-study/types';

const env = testEnv as unknown as Env;
const ns = env.CASE_STUDIES;

/**
 * Counts the subrequests a namespace consumes, by wrapping `get`/`put`.
 *
 * The regression these tests guard is invisible to a correctness assertion —
 * reading 23 keys individually and reading them in one bulk both return the
 * same data. Only the op count differs, and op count is the thing that runs
 * the Worker out of its 50-subrequest free-plan budget. So we measure it.
 */
function countingNs(): { ns: KVNamespace; gets: () => number } {
  let n = 0;
  const wrapped = {
    get: ((key: unknown, ...rest: unknown[]) => {
      n++;
      return (ns.get as (...a: unknown[]) => Promise<unknown>)(key, ...rest);
    }) as KVNamespace['get'],
    put: ns.put.bind(ns),
    delete: ns.delete.bind(ns),
    list: ns.list.bind(ns),
  };
  return { ns: wrapped as unknown as KVNamespace, gets: () => n };
}

function candidate(type: CaseStudyType, key: string): Candidate {
  return { key, type } as Candidate;
}

describe('listAllCandidates / countAllCandidates', () => {
  beforeEach(async () => {
    for (const t of CANDIDATE_TYPES) await ns.delete(`candidates:${t}:all`);
  });

  it('returns candidates across many types', async () => {
    await putCandidate(ns, candidate('cve', 'cve-1'));
    await putCandidate(ns, candidate('actor', 'actor-1'));
    await putCandidate(ns, candidate('malware', 'malware-1'));

    const all = await listAllCandidates(ns);
    expect(all.map((c) => c.key).sort()).toEqual(['actor-1', 'cve-1', 'malware-1']);
    expect(await countAllCandidates(ns)).toBe(3);
  });

  // 23 types -> 23 individual gets before, 1 bulk get now.
  it('reads every type blob in a single subrequest, not one per type', async () => {
    // Populate every type so nothing falls into the per-key migration path.
    for (const t of CANDIDATE_TYPES) await putCandidate(ns, candidate(t, `${t}-key`));

    const counter = countingNs();
    const all = await listAllCandidates(counter.ns);

    expect(all).toHaveLength(CANDIDATE_TYPES.length);
    expect(counter.gets()).toBe(1);
  });

  it('counts from the same single bulk read', async () => {
    for (const t of CANDIDATE_TYPES) await putCandidate(ns, candidate(t, `${t}-key`));

    const counter = countingNs();
    expect(await countAllCandidates(counter.ns)).toBe(CANDIDATE_TYPES.length);
    expect(counter.gets()).toBe(1);
  });

  it('returns empty rather than throwing when no candidates exist', async () => {
    expect(await listAllCandidates(ns)).toEqual([]);
    expect(await countAllCandidates(ns)).toBe(0);
  });

  // One corrupt blob must not take down the whole admin candidates list.
  it('skips a malformed blob and still returns the other types', async () => {
    await putCandidate(ns, candidate('cve', 'cve-1'));
    await ns.put('candidates:actor:all', '{not json');

    const all = await listAllCandidates(ns);
    expect(all.map((c) => c.key)).toEqual(['cve-1']);
  });
});

function post(slug: string, body: string, publishedAt = '2026-10-01T00:00:00Z'): Post {
  return {
    slug,
    title: slug,
    body,
    type: 'methodology',
    excerpt: '',
    tags: [],
    publishedAt,
  } as unknown as Post;
}

describe('buildVoiceProfileFromIndex', () => {
  beforeEach(async () => {
    await ns.delete(kv.postsIndex);
    await ns.delete('meta:voice-profile');
  });

  // Regression: the body read used the key `post:<slug>` while every writer
  // uses `posts:<slug>`. Every read missed, so the profile was always built
  // from zero real posts.
  it('finds post bodies under the canonical posts:<slug> key', async () => {
    await putPost(ns, post('alpha', 'The quick brown fox jumps over the lazy dog. '.repeat(6)));
    await putPost(ns, post('beta', 'Pack my box with five dozen liquor jugs today. '.repeat(6)));

    const profile = await buildVoiceProfileFromIndex(ns);
    expect(profile).toBeTruthy();

    // The cache entry records how many real posts the profile was built from.
    // Before the key fix this was always 0.
    const entry = (await ns.get('meta:voice-profile', 'json')) as { postCount: number } | null;
    expect(entry?.postCount).toBe(2);
  });

  it('reads the post bodies in one bulk subrequest regardless of count', async () => {
    for (let i = 0; i < 20; i++) await putPost(ns, post(`p${i}`, `Body number ${i}. `.repeat(8)));

    const counter = countingNs();
    await buildVoiceProfileFromIndex(counter.ns);

    // Exactly three reads: the cached-profile check, `posts:index`, and ONE
    // bulk read of all 20 bodies. The old loop cost 1 + 1 + 20 = 22, which on
    // the free plan (50 subrequests/invocation) burned nearly half the
    // request budget rebuilding the voice profile.
    expect(counter.gets()).toBe(3);
  });

  it('does not grow its subrequest count as the post count grows', async () => {
    const readsFor = async (n: number): Promise<number> => {
      for (const key of await ns.list({ prefix: 'posts:' }).then((r) => r.keys.map((k) => k.name)))
        await ns.delete(key);
      await ns.delete('meta:voice-profile');
      for (let i = 0; i < n; i++) await putPost(ns, post(`q${i}`, `Body ${i}. `.repeat(8)));
      const counter = countingNs();
      await buildVoiceProfileFromIndex(counter.ns);
      return counter.gets();
    };

    // 5 posts and 40 posts must cost the same, because the body read is a
    // single bulk op rather than one op per key.
    expect(await readsFor(5)).toBe(await readsFor(40));
  });

  it('does not rebuild when the cached profile is still fresh', async () => {
    await putPost(ns, post('alpha', 'Original body text here. '.repeat(10)));
    await buildVoiceProfileFromIndex(ns);

    const first = (await ns.get('meta:voice-profile', 'json')) as { builtAt: string };
    await buildVoiceProfileFromIndex(ns);
    const second = (await ns.get('meta:voice-profile', 'json')) as { builtAt: string };

    expect(second.builtAt).toBe(first.builtAt);
  });

  it('tolerates an empty index', async () => {
    expect(await listPostIndex(ns)).toEqual([]);
    await expect(buildVoiceProfileFromIndex(ns)).resolves.toBeTruthy();
  });
});
