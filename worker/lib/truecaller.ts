/**
 * Truecaller reverse phone lookup — typed wrapper around the Truecaller API.
 *
 * Requires `TRUECALLER_API_KEY`. Truecaller offers a REST API for looking up
 * phone numbers to get caller name, carrier, spam score, and location data.
 *
 * API: https://api.truecaller.com/
 * Auth: Bearer token in Authorization header.
 */

import { errMessage } from './err';

const TRUECALLER_BASE = 'https://api.truecaller.com';
const TIMEOUT_MS = 10_000;

interface TruecallerEnv {
  TRUECALLER_API_KEY?: string;
}

// ─── Types ──────────────────────────────────────────────────────────────

export interface TruecallerPhoneResult {
  /** Phone number (E.164 format). */
  phone_number: string;
  /** Country code (ISO 3166-1 alpha-2). */
  country_code?: string;
  /** Carrier / telecom provider name. */
  carrier?: string;
  /** Whether the number is a mobile, fixed-line, VoIP, etc. */
  number_type?: string;
  /** Caller name (from Truecaller's crowd-sourced database). */
  name?: string;
  /** Alternate name / company. */
  alt_name?: string;
  /** Spam score (0 = not spam, higher = more spam reports). */
  spam_score?: number;
  /** Number of spam reports. */
  spam_reports?: number;
  /** Whether the number is a known spammer. */
  is_spam?: boolean;
  /** City / region. */
  city?: string;
  /** Country name. */
  country?: string;
  /** Timezone. */
  timezone?: string;
  /** Whether the number is on Truecaller. */
  is_truecaller?: boolean;
  /** Last updated timestamp. */
  last_updated?: string;
  /** Provider source. */
  source?: string;
  /** Raw fields from the API response. */
  [key: string]: unknown;
}

export interface TruecallerResponse {
  success: boolean;
  phone_number: string;
  result?: TruecallerPhoneResult;
  elapsed_ms: number;
  diagnostics: Array<{
    provider: string;
    status: 'ok' | 'skipped' | 'failed';
    ms: number;
    error?: string;
  }>;
}

// ─── Helpers ────────────────────────────────────────────────────────────

function requireKey(env: TruecallerEnv): string {
  const key = env.TRUECALLER_API_KEY;
  if (!key) {
    throw new Error('TRUECALLER_API_KEY not set — register at truecaller.com');
  }
  return key;
}

/** Strip all non-digit characters and ensure E.164-ish format. */
function normalizePhone(phone: string): string {
  const digits = phone.replace(/\D/g, '');
  // If it starts with 0, assume US (country code 1) — common for local formats
  if (digits.startsWith('0') && digits.length <= 10) {
    return `1${digits}`;
  }
  return digits;
}

// ─── Public API ─────────────────────────────────────────────────────────

/**
 * Reverse phone lookup via Truecaller. Returns caller name, carrier,
 * spam score, and location data for a phone number.
 */
export async function truecallerLookup(env: TruecallerEnv, phone: string): Promise<TruecallerResponse> {
  const result: TruecallerResponse = {
    success: false,
    phone_number: phone,
    elapsed_ms: 0,
    diagnostics: [],
  };

  if (!phone || !phone.trim()) {
    result.diagnostics.push({ provider: 'validator', status: 'failed', ms: 0, error: 'empty phone number' });
    return result;
  }

  const normalized = normalizePhone(phone.trim());
  result.phone_number = normalized;

  const t0 = Date.now();
  try {
    const key = requireKey(env);

    const res = await fetch(`${TRUECALLER_BASE}/v2/phone/${normalized}`, {
      headers: {
        Authorization: `Bearer ${key}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      result.diagnostics.push({
        provider: 'truecaller',
        status: 'failed',
        ms: Date.now() - t0,
        error: `Truecaller returned ${res.status}: ${body.slice(0, 200)}`,
      });
      return result;
    }

    const data = (await res.json()) as Record<string, unknown>;

    // Truecaller returns the phone data in the top-level object
    const r: TruecallerPhoneResult = {
      phone_number: normalized,
      country_code: data.countryCode as string | undefined,
      carrier: data.carrier as string | undefined,
      number_type: data.numberType as string | undefined,
      name: data.name as string | undefined,
      alt_name: data.altName as string | undefined,
      spam_score: data.spamScore as number | undefined,
      spam_reports: data.spamReports as number | undefined,
      is_spam: data.isSpam as boolean | undefined,
      city: data.city as string | undefined,
      country: data.country as string | undefined,
      timezone: data.timezone as string | undefined,
      is_truecaller: data.isPresentOnTruecaller as boolean | undefined,
      last_updated: data.lastUpdated as string | undefined,
      source: 'truecaller',
      ...data,
    };

    result.result = r;
    result.success = true;
    result.diagnostics.push({ provider: 'truecaller', status: 'ok', ms: Date.now() - t0 });
  } catch (e) {
    result.diagnostics.push({
      provider: 'truecaller',
      status: 'failed',
      ms: Date.now() - t0,
      error: errMessage(e),
    });
  }

  result.elapsed_ms = Date.now() - t0;
  return result;
}
