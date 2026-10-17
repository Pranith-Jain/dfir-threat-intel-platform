import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest } from '../lib/api-error';
import { cachedJson } from '../lib/route-cache';
import { fetchResilient } from '../lib/fetch-resilient';

interface CertEntry {
  name_value: string;
  issuer_ca_id: number;
  issuer_name: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

interface CertTransparencyResult {
  domain: string;
  subdomains: string[];
  total_certs: number;
  entries: CertEntry[];
  source: string;
  fetched_at: string;
}

/**
 * Cert Transparency lookup via crt.sh — free, no API key.
 * Equivalent to metabigor's `cert` command.
 */
export async function certTransparencyHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const domain = c.req.query('domain');
  if (!domain) return badRequest(c, 'missing domain');

  const clean = domain
    .replace(/^(https?:\/\/)/, '')
    .replace(/\/.*$/, '')
    .trim();
  if (!clean || clean.includes(' ')) return badRequest(c, 'invalid domain');

  return cachedJson(c, `cert-transparency:${clean}`, 3600, async () => {
    const url = `https://crt.sh/?q=${encodeURIComponent(clean)}&output=json`;
    const res = await fetchResilient(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DFIR-Portfolio/1.0)' } },
      { attempts: 3, timeoutMs: 15000 }
    );
    if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);

    const data = (await res.json()) as CertEntry[];
    const subdomains = new Set<string>();
    for (const entry of data) {
      const names = entry.name_value.split('\n').map((n) => n.trim().toLowerCase());
      for (const n of names) {
        if (n === clean || n === `*.${clean}`) continue;
        if (n.endsWith(`.${clean}`) || n === clean) {
          subdomains.add(n.replace(/^\*\./, ''));
        }
      }
    }

    return {
      domain: clean,
      subdomains: [...subdomains].sort(),
      total_certs: data.length,
      entries: data.slice(0, 50),
      source: 'crt.sh',
      fetched_at: new Date().toISOString(),
    } as CertTransparencyResult;
  });
}
