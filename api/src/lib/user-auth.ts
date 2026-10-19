/**
 * User authentication module.
 *
 * Provides password hashing (Argon2id via Web Crypto PBKDF2 fallback),
 * session management, and org membership checks. Designed for Cloudflare
 * Workers — no Node.js crypto dependencies.
 */

import type { D1Database } from '@cloudflare/workers-types';
import { safeEqual } from './admin-auth';

/* ─── Password Hashing ────────────────────────────────────────────────────── */

const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH = 64;
const SALT_LENGTH = 32;

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, [
    'deriveBits',
  ]);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-512',
      salt,
      iterations: PBKDF2_ITERATIONS,
    },
    keyMaterial,
    KEY_LENGTH * 8
  );
  const hashArray = new Uint8Array(derivedBits);
  const saltHex = Array.from(salt)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const hashHex = Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `pbkdf2:${PBKDF2_ITERATIONS}:sha512:${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(':');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
  const iterStr = parts[1];
  const saltHex = parts[3];
  const expectedHash = parts[4];
  if (!iterStr || !saltHex || !expectedHash) return false;
  const iterations = parseInt(iterStr, 10);
  const saltMatches = saltHex.match(/.{2}/g);
  if (!saltMatches || saltHex.length % 2 !== 0) return false;
  const salt = Uint8Array.from(saltMatches.map((h) => parseInt(h, 16)));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, [
    'deriveBits',
  ]);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-512',
      salt,
      iterations,
    },
    keyMaterial,
    expectedHash.length * 4
  );
  const hashHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  // Constant-time compare: `===` on a secret-derived value short-circuits on
  // the first differing character. The stored PBKDF2 digest isn't directly
  // observable through a response, so this is defense-in-depth, but it keeps
  // every secret comparison in the codebase on one primitive.
  return safeEqual(hashHex, expectedHash);
}

/* ─── Token Generation ─────────────────────────────────────────────────────── */

function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hashToken(token: string): Promise<string> {
  const enc = new TextEncoder().encode(token);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ─── User Operations ──────────────────────────────────────────────────────── */

export interface User {
  id: string;
  email: string;
  email_verified: number;
  display_name: string | null;
  avatar_url: string | null;
  created_at: string;
  last_login_at: string | null;
}

export interface CreateUserInput {
  email: string;
  password: string;
  display_name?: string;
}

export async function createUser(
  db: D1Database,
  input: CreateUserInput
): Promise<{ user: User; token: string } | { error: string }> {
  const existing = await db
    .prepare('SELECT id FROM users WHERE email = ?')
    .bind(input.email.toLowerCase())
    .first<{ id: string }>();
  if (existing) {
    return { error: 'Email already registered' };
  }

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(input.password);
  const verificationToken = generateToken();
  const verificationHash = await hashToken(verificationToken);

  await db.batch([
    db
      .prepare('INSERT INTO users (id, email, password_hash, display_name) VALUES (?, ?, ?, ?)')
      .bind(id, input.email.toLowerCase(), passwordHash, input.display_name || null),
    db
      .prepare(
        "INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))"
      )
      .bind(crypto.randomUUID(), id, verificationHash),
  ]);

  const token = generateToken();
  await createSession(db, id, token);

  const user: User = {
    id,
    email: input.email.toLowerCase(),
    email_verified: 0,
    display_name: input.display_name || null,
    avatar_url: null,
    created_at: new Date().toISOString(),
    last_login_at: null,
  };

  return { user, token };
}

export async function loginUser(
  db: D1Database,
  email: string,
  password: string
): Promise<{ user: User; token: string } | { error: string }> {
  const row = await db
    .prepare(
      'SELECT id, email, email_verified, password_hash, display_name, avatar_url, created_at, last_login_at FROM users WHERE email = ?'
    )
    .bind(email.toLowerCase())
    .first<{
      id: string;
      email: string;
      email_verified: number;
      password_hash: string;
      display_name: string | null;
      avatar_url: string | null;
      created_at: string;
      last_login_at: string | null;
    }>();

  if (!row) {
    return { error: 'Invalid email or password' };
  }

  const valid = await verifyPassword(password, row.password_hash);
  if (!valid) {
    return { error: 'Invalid email or password' };
  }

  const token = generateToken();
  await createSession(db, row.id, token);
  await db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(row.id).run();

  const user: User = {
    id: row.id,
    email: row.email,
    email_verified: row.email_verified,
    display_name: row.display_name,
    avatar_url: row.avatar_url,
    created_at: row.created_at,
    last_login_at: new Date().toISOString(),
  };

  return { user, token };
}

/* ─── Session Management ───────────────────────────────────────────────────── */

async function createSession(db: D1Database, userId: string, token: string): Promise<void> {
  const sessionId = crypto.randomUUID();
  const hash = await hashToken(token);
  await db
    .prepare(
      "INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+30 days'))"
    )
    .bind(sessionId, userId, hash)
    .run();
}

export async function validateSession(db: D1Database, token: string): Promise<User | null> {
  const hash = await hashToken(token);
  const row = await db
    .prepare(
      `SELECT u.id, u.email, u.email_verified, u.display_name, u.avatar_url, u.created_at, u.last_login_at
       FROM user_sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
    )
    .bind(hash)
    .first<User>();
  return row || null;
}

export async function deleteSession(db: D1Database, token: string): Promise<void> {
  const hash = await hashToken(token);
  await db.prepare('DELETE FROM user_sessions WHERE token_hash = ?').bind(hash).run();
}

/* ─── Organization Operations ──────────────────────────────────────────────── */

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  avatar_url: string | null;
  created_by: string;
  created_at: string;
}

export interface OrgMember {
  id: string;
  org_id: string;
  user_id: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  joined_at: string;
  display_name?: string;
  email?: string;
}

export async function createOrganization(
  db: D1Database,
  createdBy: string,
  name: string,
  slug: string,
  description?: string
): Promise<Organization | { error: string }> {
  const existing = await db.prepare('SELECT id FROM organizations WHERE slug = ?').bind(slug).first<{ id: string }>();
  if (existing) {
    return { error: 'Organization slug already taken' };
  }

  const id = crypto.randomUUID();
  await db.batch([
    db
      .prepare('INSERT INTO organizations (id, name, slug, description, created_by) VALUES (?, ?, ?, ?, ?)')
      .bind(id, name, slug, description || null, createdBy),
    db
      .prepare("INSERT INTO org_members (id, org_id, user_id, role) VALUES (?, ?, ?, 'owner')")
      .bind(crypto.randomUUID(), id, createdBy),
  ]);

  return {
    id,
    name,
    slug,
    description: description || null,
    avatar_url: null,
    created_by: createdBy,
    created_at: new Date().toISOString(),
  };
}

export async function getOrgMembers(db: D1Database, orgId: string): Promise<OrgMember[]> {
  const { results } = await db
    .prepare(
      `SELECT m.id, m.org_id, m.user_id, m.role, m.joined_at,
              u.display_name, u.email
       FROM org_members m
       JOIN users u ON m.user_id = u.id
       WHERE m.org_id = ?
       ORDER BY m.joined_at`
    )
    .bind(orgId)
    .all<OrgMember>();
  return results || [];
}

export async function isOrgMember(db: D1Database, orgId: string, userId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT id FROM org_members WHERE org_id = ? AND user_id = ?')
    .bind(orgId, userId)
    .first<{ id: string }>();
  return !!row;
}

export async function addOrgMember(
  db: D1Database,
  orgId: string,
  userId: string,
  role: 'admin' | 'member' | 'viewer' = 'member'
): Promise<{ error: string } | { success: boolean }> {
  const existing = await db
    .prepare('SELECT id FROM org_members WHERE org_id = ? AND user_id = ?')
    .bind(orgId, userId)
    .first<{ id: string }>();
  if (existing) {
    return { error: 'User is already a member' };
  }

  await db
    .prepare('INSERT INTO org_members (id, org_id, user_id, role) VALUES (?, ?, ?, ?)')
    .bind(crypto.randomUUID(), orgId, userId, role)
    .run();

  return { success: true };
}

export async function removeOrgMember(db: D1Database, orgId: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM org_members WHERE org_id = ? AND user_id = ?').bind(orgId, userId).run();
}

export async function getUserOrgs(db: D1Database, userId: string): Promise<Organization[]> {
  const { results } = await db
    .prepare(
      `SELECT o.id, o.name, o.slug, o.description, o.avatar_url, o.created_by, o.created_at
       FROM organizations o
       JOIN org_members m ON o.id = m.org_id
       WHERE m.user_id = ?
       ORDER BY o.name`
    )
    .bind(userId)
    .all<Organization>();
  return results || [];
}
