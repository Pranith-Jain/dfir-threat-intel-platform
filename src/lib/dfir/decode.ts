import { errMessage } from '../log';
export type DecodeFormat = 'base64' | 'url' | 'unknown';

export function detectEncoding(input: string): DecodeFormat {
  const trimmed = input.trim();
  if (!trimmed) return 'unknown';
  if (/%[0-9a-fA-F]{2}/.test(trimmed)) return 'url';
  // base64: only A-Z a-z 0-9 + / = (and url-safe - _), length % 4 === 0 (or padded)
  if (
    /^[A-Za-z0-9+/_-]*={0,2}$/.test(trimmed) &&
    trimmed.length >= 4 &&
    (trimmed.length % 4 === 0 || trimmed.includes('='))
  ) {
    return 'base64';
  }
  return 'unknown';
}

export function decodeBase64(input: string): { ok: true; result: string } | { ok: false; error: string } {
  try {
    // url-safe → standard
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(normalized);
    // try to interpret as utf-8
    const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    const result = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: errMessage(err, 'invalid base64') };
  }
}

export function decodeUrl(input: string): { ok: true; result: string } | { ok: false; error: string } {
  try {
    return { ok: true, result: decodeURIComponent(input) };
  } catch (err) {
    return { ok: false, error: errMessage(err, 'invalid url encoding') };
  }
}

export interface DecodeStep {
  format: DecodeFormat;
  input: string;
  output: string;
}

export function decodeChain(input: string, maxPasses = 5): DecodeStep[] {
  const steps: DecodeStep[] = [];
  let current = input.trim();
  for (let i = 0; i < maxPasses; i++) {
    const fmt = detectEncoding(current);
    if (fmt === 'unknown') break;
    const result = fmt === 'base64' ? decodeBase64(current) : decodeUrl(current);
    if (!result.ok) break;
    if (result.result === current) break; // no change, stop
    steps.push({ format: fmt, input: current, output: result.result });
    current = result.result;
  }
  return steps;
}
