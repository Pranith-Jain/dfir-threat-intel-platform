/**
 * Standardized API error helpers. Every route should use these instead
 * of ad-hoc `c.json(...)` so clients always see the same shape:
 *
 *   { error: "error_code", message: "human readable" }
 *
 * Optionally with a `fields` map for validation errors:
 *
 *   { error: "validation_error", message: "...", fields: { email: "invalid" } }
 *
 * Migration note: ~500 ad-hoc `c.json({ error: 'code' }, status)` call
 * sites predate the helpers and are intentionally left in place — each
 * one shows up as just an `error` field (no `message`) to the frontend,
 * which falls back to the `error` code in api-client.ts. New routes
 * should reach for the helpers below; for the common 4xx-with-code
 * pattern the `respondError()` shorthand is the drop-in replacement.
 */

import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { Env } from '../env';
import { safeErrorMessage } from './error';

function safeMsg(env: Env, err: unknown): string {
  return safeErrorMessage(env, err);
}

export interface ApiErrorBody {
  error: string;
  message: string;
  fields?: Record<string, string>;
}

function headers(extra?: Record<string, string>): Record<string, string> {
  return { 'Cache-Control': 'no-store, max-age=0', ...extra };
}

/**
 * Generic error responder. Replaces the most common ad-hoc pattern:
 *   return c.json({ error: 'rate_limited' }, 429);
 * with the standardized shape including a human-readable `message`:
 *   return respondError(c, 'rate_limited', 'try again in a minute', 429);
 *
 * Use this for custom error codes that don't have a dedicated helper
 * below. The four-argument form mirrors the existing `c.json` call
 * sites so the migration is a one-line search-and-replace.
 */
export function respondError(
  c: Context,
  code: string,
  message: string,
  status: ContentfulStatusCode,
  extraHeaders?: Record<string, string>
): Response {
  return c.json({ error: code, message } as ApiErrorBody, status, headers(extraHeaders));
}

/** 400 Bad Request — malformed input */
export function badRequest(c: Context, message = 'bad request'): Response {
  return c.json({ error: 'bad_request', message } as ApiErrorBody, 400, headers());
}

/** 400 with per-field error map */
export function validationError(c: Context, fields: Record<string, string>, message = 'validation failed'): Response {
  return c.json({ error: 'validation_error', message, fields } as ApiErrorBody, 400, headers());
}

/** 401 Unauthorized — missing or invalid credentials */
export function unauthorized(c: Context, message = 'unauthorized'): Response {
  return c.json({ error: 'unauthorized', message } as ApiErrorBody, 401, headers());
}

/** 403 Forbidden — authenticated but not permitted */
export function forbidden(c: Context, message = 'forbidden'): Response {
  return c.json({ error: 'forbidden', message } as ApiErrorBody, 403, headers());
}

/** 404 Not Found */
export function notFound(c: Context, message = 'not found'): Response {
  return c.json({ error: 'not_found', message } as ApiErrorBody, 404, headers());
}

/** 409 Conflict */
export function conflict(c: Context, message = 'conflict'): Response {
  return c.json({ error: 'conflict', message } as ApiErrorBody, 409, headers());
}

/** 413 Payload Too Large */
export function payloadTooLarge(
  c: Context,
  message = 'payload too large',
  meta?: { size_bytes?: number; max_bytes?: number }
): Response {
  return c.json({ error: 'payload_too_large', message, ...meta } as ApiErrorBody, 413, headers());
}

/** 429 Too Many Requests */
export function tooManyRequests(
  c: Context,
  message = 'rate limited',
  meta?: { limit?: number; windowSeconds?: number }
): Response {
  return c.json(
    { error: 'rate_limited', message, ...meta } as ApiErrorBody & typeof meta,
    429,
    headers({ 'retry-after': String(meta?.windowSeconds ?? 60) })
  );
}

/** 500 Internal Server Error — masks real error in production */
export function internalError(c: Context, err: unknown): Response {
  const message = safeMsg(c.env, err);
  return c.json({ error: 'internal_error', message } as ApiErrorBody, 500, headers());
}

/**
 * 502 Bad Gateway — upstream returned an error.
 *
 * `message` is **client-visible**. Routes that echo `err.message` here are
 * echoing whatever the runtime produced, which for a Workers `fetch` failure
 * is a generic string ("fetch failed") — fine to show, and useful for users
 * deciding whether to retry. Anything richer than that (a raw upstream
 * response body, a URL, credentials in a query string) belongs in `logError`
 * instead; `safeErrorMessage` exists for the cases where even the generic
 * text should be withheld outside development.
 */
export function badGateway(c: Context, message = 'upstream error'): Response {
  return c.json({ error: 'bad_gateway', message } as ApiErrorBody, 502, headers());
}

/** 503 Service Unavailable — upstream dependency failed. `message` is client-visible; see `badGateway`. */
export function serviceUnavailable(c: Context, message = 'service unavailable'): Response {
  return c.json({ error: 'service_unavailable', message } as ApiErrorBody, 503, headers());
}

/**
 * Convenience guard for the most common 503 case: a required binding
 * is missing in the deployed env. Returns the response if missing, or
 * `null` if the binding is present (caller can short-circuit on null).
 *
 *   const db = requireDb(c, 'BRIEFINGS_DB');
 *   if (!db) return db; // 503 with standardized shape already returned
 *   // db is typed as the binding, not optional
 *
 * The `name` argument is the human-readable feature name (e.g.
 * 'briefings database') surfaced in the response message so operators
 * can debug from the response body alone.
 */
export function requireDb(c: Context, name = 'database'): D1Database | null | Response {
  const db = c.env.BRIEFINGS_DB;
  if (!db) {
    return serviceUnavailable(c, `${name} is not configured on this deployment`);
  }
  return db;
}

export function requireKv(c: Context, name = 'cache'): KVNamespace | null | Response {
  const kv = c.env.KV_CACHE;
  if (!kv) {
    return serviceUnavailable(c, `${name} is not configured on this deployment`);
  }
  return kv;
}
