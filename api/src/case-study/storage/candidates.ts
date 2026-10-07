import type { KVNamespace } from '@cloudflare/workers-types';
import type { Candidate, CaseStudyType } from '../types';
import { logError } from '../../lib/logger';

const THIRTY_DAYS_SECONDS = 30 * 24 * 3600;

/**
 * Canonical list of content types a candidate can have — the SINGLE source of
 * truth, imported by the admin routes too so the lookup list can never drift
 * from this storage/list list again. Every runner output type MUST be here, or
 * candidates of that type become invisible (not listed) and un-actionable
 * ("candidate not found" on approve/generate). That drift is exactly what hid
 * `analysis` candidates (from agentic-trends) from the approve/generate route
 * and `tool`/`news` from the pending list.
 */
export const CANDIDATE_TYPES: CaseStudyType[] = [
  'cve',
  'vulnfaq',
  'exploit',
  'actor',
  'malware',
  'darkweb',
  'breach',
  'scam',
  'aisec',
  'llm',
  'aisecops',
  'supplychain',
  'intel',
  'osint',
  'methodology',
  'trend',
  'briefing',
  'analysis',
  'tool',
  'news',
  'agentic',
  'hunting',
  'report',
];

/** Used by `listAllCandidates` to read per-type blobs without an unbounded
 *  `.list()` call. Aliased to the canonical list to prevent drift. */
const ALL_TYPES = CANDIDATE_TYPES;

function blobKey(type: CaseStudyType): string {
  return `candidates:${type}:all`;
}

function oldPrefix(type: CaseStudyType): string {
  return `candidates:${type}:`;
}

async function readTypeBlob(ns: KVNamespace, type: CaseStudyType): Promise<Candidate[]> {
  const key = blobKey(type);
  const blob = (await ns.get(key, 'json')) as Candidate[] | null;
  if (blob) return blob;

  // One-time migration: read old per-key format and promote to blob.
  const { keys } = await ns.list({ prefix: oldPrefix(type) });
  const oldKeys = keys.filter((k) => k.name !== key);
  if (oldKeys.length === 0) return [];
  const migrated = (await Promise.all(oldKeys.map((k) => ns.get(k.name, 'json') as Promise<Candidate | null>))).filter(
    (x): x is Candidate => x !== null
  );
  if (migrated.length > 0) {
    await ns.put(key, JSON.stringify(migrated), { expirationTtl: THIRTY_DAYS_SECONDS });
    for (const k of oldKeys) ns.delete(k.name).catch((err) => logError('delete old candidate key failed', err));
  }
  return migrated;
}

async function writeTypeBlob(ns: KVNamespace, type: CaseStudyType, list: Candidate[]): Promise<void> {
  await ns.put(blobKey(type), JSON.stringify(list), { expirationTtl: THIRTY_DAYS_SECONDS });
}

export async function putCandidate(ns: KVNamespace, c: Candidate): Promise<void> {
  // readTypeBlob triggers migration on first access if blob doesn't exist yet.
  const list = await readTypeBlob(ns, c.type);
  const idx = list.findIndex((x) => x.key === c.key);
  if (idx >= 0) list[idx] = c;
  else list.push(c);
  await writeTypeBlob(ns, c.type, list);
}

export async function getCandidate(ns: KVNamespace, type: CaseStudyType, stableKey: string): Promise<Candidate | null> {
  const list = await readTypeBlob(ns, type);
  return list.find((x) => x.key === stableKey) ?? null;
}

export async function listCandidates(ns: KVNamespace, type: CaseStudyType): Promise<Candidate[]> {
  return readTypeBlob(ns, type);
}

/**
 * All pending candidates across every type — reads each type's blob
 * in parallel (13 reads) instead of the old unbounded `.list()` + N gets.
 */
export async function listAllCandidates(ns: KVNamespace): Promise<Candidate[]> {
  const perType = await Promise.all(ALL_TYPES.map((t) => readTypeBlob(ns, t)));
  return perType.flat();
}

export async function deleteCandidate(ns: KVNamespace, type: CaseStudyType, stableKey: string): Promise<void> {
  const list = await readTypeBlob(ns, type);
  await writeTypeBlob(
    ns,
    type,
    list.filter((x) => x.key !== stableKey)
  );
}

/** Count all candidates across every type — reads all type blobs in parallel. */
export async function countAllCandidates(ns: KVNamespace): Promise<number> {
  const perType = await Promise.all(ALL_TYPES.map((t) => readTypeBlob(ns, t)));
  return perType.reduce((sum, arr) => sum + arr.length, 0);
}
