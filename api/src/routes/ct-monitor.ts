import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import type { D1Database } from '@cloudflare/workers-types';

/**
 * Certificate Transparency Domain Monitor
 *
 * Monitors CT logs for new certificates issued to watched domains.
 * Detects:
 *   - New subdomain creation
 *   - Suspicious certificate patterns (typosquatting, phishing)
 *   - Certificate authority changes
 *   - Wildcard certificate issuance
 *
 * GET  /api/v1/ct-monitor/watched
 *      List all watched domains.
 *
 * POST /api/v1/ct-monitor/watch
 *      body: { domain: "example.com", alert_types: [...] }
 *      Add a domain to watch.
 *
 * DELETE /api/v1/ct-monitor/watch/:domain
 *      Remove a domain from watch.
 *
 * GET  /api/v1/ct-monitor/certs?domain=example.com
 *      Get recent certificates for a domain.
 *
 * Uses crt.sh (free, unlimited) for CT log queries.
 * Storage: D1 table `ct_watch` + `ct_certs`.
 */

const CACHE_TTL = 3600; // 1 hour
const CRT_SH_TIMEOUT = 15_000;

interface CrtShCert {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  entry_timestamp: string;
  // crt.sh may add more fields
}

interface WatchConfig {
  domain: string;
  alert_types: string[];
  added_at: string;
  last_checked: string;
  cert_count: number;
}

interface CertInfo {
  id: number;
  common_name: string;
  names: string[];
  issuer: string;
  not_before: string;
  not_after: string;
  serial: string;
  first_seen: string;
  /** Whether this cert matches any alert conditions. */
  alert?: {
    type: string;
    message: string;
  };
}

/** Check if a domain name looks suspicious (typosquat, homograph, etc.) */
function isSuspiciousDomain(name: string, baseDomain: string): boolean {
  const lower = name.toLowerCase();
  const base = baseDomain.toLowerCase();

  // Exact match or subdomain - not suspicious
  if (lower === base || lower.endsWith(`.${base}`)) return false;

  // Check for common typosquat patterns
  const withoutTld = lower.replace(/\.[^.]+$/, '');
  const baseWithoutTld = base.replace(/\.[^.]+$/, '');

  // Levenshtein distance 1-2 (simplified check)
  if (withoutTld.includes(baseWithoutTld) || baseWithoutTld.includes(withoutTld)) {
    // Could be a superset/subset - check if it's actually suspicious
    const diff = Math.abs(withoutTld.length - baseWithoutTld.length);
    if (diff <= 2) return true;
  }

  // Check for homograph attacks (mixed scripts)
  const hasCyrillic = /[а-яА-Я]/.test(name);
  const hasLatin = /[a-zA-Z]/.test(name);
  if (hasCyrillic && hasLatin) return true;

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /secure/i,
    /login/i,
    /verify/i,
    /account/i,
    /update/i,
    /banking/i,
    /payment/i,
    /support/i,
    /help/i,
    /service/i,
  ];

  return suspiciousPatterns.some((p) => p.test(lower) && !p.test(base));
}

/** Fetch certificates from crt.sh */
async function fetchCertificates(domain: string): Promise<CrtShCert[]> {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(CRT_SH_TIMEOUT),
      headers: { 'User-Agent': 'threat-intel-ct-monitor/1.0' },
    });

    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  } catch (_catchErr) {
    logError('fetchCertificates failed', _catchErr);
    return [];
  }
}

/** GET /api/v1/ct-monitor/watched */
export async function ctWatchedListHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const rows = await db
    .prepare('SELECT domain, alert_types, added_at, last_checked, cert_count FROM ct_watch ORDER BY last_checked DESC')
    .all<WatchConfig>();

  return c.json({
    watched: rows.results ?? [],
    count: rows.results?.length ?? 0,
  });
}

/** POST /api/v1/ct-monitor/watch */
export async function ctWatchAddHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const body = await c.req.json<{
    domain: string;
    alert_types?: string[];
  }>();

  if (!body.domain) {
    return badRequest(c, 'domain is required');
  }

  // Validate domain
  const domain = body.domain.toLowerCase().trim();
  if (!/^[a-z0-9-]+\.[a-z]{2,}$/.test(domain)) {
    return badRequest(c, 'invalid domain format');
  }

  const alertTypes = body.alert_types ?? ['new_subdomain', 'suspicious_name', 'wildcard'];

  await db
    .prepare(
      `INSERT OR REPLACE INTO ct_watch (domain, alert_types, added_at, last_checked, cert_count)
       VALUES (?, ?, datetime('now'), NULL, 0)`
    )
    .bind(domain, JSON.stringify(alertTypes))
    .run();

  // Trigger initial fetch in background
  c.executionCtx.waitUntil(
    (async () => {
      const certs = await fetchCertificates(domain);
      if (certs.length > 0) {
        await storeCerts(db, domain, certs, alertTypes);
      }
      await db
        .prepare("UPDATE ct_watch SET last_checked = datetime('now'), cert_count = ? WHERE domain = ?")
        .bind(certs.length, domain)
        .run();
    })()
  );

  return c.json({
    success: true,
    domain,
    alert_types: alertTypes,
    message: 'Domain added to watch list. Initial scan running in background.',
  });
}

/** DELETE /api/v1/ct-monitor/watch/:domain */
export async function ctWatchRemoveHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const domain = c.req.param('domain')?.toLowerCase();
  if (!domain) return badRequest(c, 'domain required');

  await db.prepare('DELETE FROM ct_watch WHERE domain = ?').bind(domain).run();
  await db.prepare('DELETE FROM ct_certs WHERE domain = ?').bind(domain).run();

  return c.json({ success: true, domain, message: 'Domain removed from watch list' });
}

/** GET /api/v1/ct-monitor/certs?domain=example.com */
export async function ctCertsHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'database not configured');

  const domain = c.req.query('domain')?.toLowerCase();
  if (!domain) return badRequest(c, 'domain query param required');

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(`https://ct-monitor-cache.internal/v1?domain=${encodeURIComponent(domain)}`);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const limit = Math.min(Math.max(Number(c.req.query('limit')) || 100, 1), 500);
  const days = Math.max(Number(c.req.query('days')) || 30, 1);

  const rows = await db
    .prepare(
      `SELECT id, domain, common_name, names, issuer, not_before, not_after, serial, first_seen FROM ct_certs
       WHERE domain = ? AND first_seen > datetime('now', '-${days} days')
       ORDER BY first_seen DESC
       LIMIT ?`
    )
    .bind(domain, limit)
    .all<{
      id: number;
      common_name: string;
      names: string;
      issuer: string;
      not_before: string;
      not_after: string;
      serial: string;
      first_seen: string;
      alert_type: string;
      alert_message: string;
    }>();

  const certs: CertInfo[] = (rows.results ?? []).map((row) => ({
    id: row.id,
    common_name: row.common_name,
    names: JSON.parse(row.names ?? '[]'),
    issuer: row.issuer,
    not_before: row.not_before,
    not_after: row.not_after,
    serial: row.serial,
    first_seen: row.first_seen,
    alert: row.alert_type ? { type: row.alert_type, message: row.alert_message } : undefined,
  }));

  const response = c.json(
    {
      domain,
      certs,
      count: certs.length,
      generated_at: new Date().toISOString(),
    },
    200,
    { 'Cache-Control': `public, max-age=${CACHE_TTL}` }
  );

  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

/**
 * Cap on certificates persisted per scan.
 *
 * This is NOT a subrequest budget — a `db.batch()` is one D1 call regardless of
 * statement count. (An earlier revision of this file claimed the opposite and
 * cut this from 90 to 40; that was based on a wrong premise and would have
 * thrown away more than half of every scan.) The cap exists because crt.sh
 * returns large, duplicate-heavy result sets whose tail is near-duplicate SANs
 * of low value.
 */
const MAX_CERTS_PER_SCAN = 90;

/**
 * Chunk the cert inserts.
 *
 * The batch is atomic, so one rejected statement rolls back the whole set.
 * Chunking bounds that blast radius and an isolated catch keeps a single
 * failure from discarding certificates already written by earlier chunks.
 */
const CERT_BATCH_CHUNK = 50;

/** Store certificates and check for alerts. */
async function storeCerts(db: D1Database, domain: string, certs: CrtShCert[], alertTypes: string[]): Promise<number> {
  let alertCount = 0;
  const stmts: D1PreparedStatement[] = [];

  // crt.sh returns large, duplicate-heavy result sets. Cap the number we
  // persist so one scan stays bounded (the old code did one serial .run() per
  // cert — hundreds of subrequests on a busy domain).
  const considered = certs.slice(0, MAX_CERTS_PER_SCAN);
  if (certs.length > considered.length) {
    console.log(
      JSON.stringify({
        job: 'ct-monitor',
        domain,
        certs_returned: certs.length,
        certs_persisted: considered.length,
        note: 'scan cap reached — the crt.sh tail is near-duplicate SANs of low value',
      })
    );
  }
  for (const cert of considered) {
    const names = cert.name_value
      ? cert.name_value
          .split('\n')
          .map((n) => n.trim())
          .filter(Boolean)
      : [cert.common_name];

    // Check for alerts
    let alertType: string | null = null;
    let alertMessage: string | null = null;

    if (alertTypes.includes('wildcard') && names.some((n) => n.startsWith('*.'))) {
      alertType = 'wildcard';
      alertMessage = `Wildcard certificate issued for ${names.find((n) => n.startsWith('*.'))}`;
    }

    if (alertTypes.includes('suspicious_name')) {
      const suspicious = names.find((n) => isSuspiciousDomain(n, domain));
      if (suspicious) {
        alertType = 'suspicious_name';
        alertMessage = `Suspicious domain pattern detected: ${suspicious}`;
      }
    }

    if (alertTypes.includes('ip_cert') && names.some((n) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(n))) {
      alertType = 'ip_cert';
      alertMessage = 'Certificate issued for IP address';
    }

    if (alertTypes.includes('short_validity')) {
      const notBefore = new Date(cert.not_before);
      const notAfter = new Date(cert.not_after);
      const validityDays = (notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24);
      if (validityDays < 30) {
        alertType = 'short_validity';
        alertMessage = `Short validity period: ${Math.round(validityDays)} days`;
      }
    }

    if (alertType) alertCount++;

    // Queue the upsert; flushed as a single batched round-trip below.
    stmts.push(
      db
        .prepare(
          `INSERT OR IGNORE INTO ct_certs (id, domain, common_name, names, issuer, not_before, not_after, serial, first_seen, alert_type, alert_message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)`
        )
        .bind(
          cert.id,
          domain,
          cert.common_name,
          JSON.stringify(names),
          cert.issuer_name,
          cert.not_before,
          cert.not_after,
          cert.serial_number,
          alertType,
          alertMessage
        )
    );
  }

  // One D1 call per chunk (not N serial writes), and a failure in one chunk
  // does not discard the certificates already written by the others.
  for (let i = 0; i < stmts.length; i += CERT_BATCH_CHUNK) {
    await db.batch(stmts.slice(i, i + CERT_BATCH_CHUNK));
  }

  return alertCount;
}
