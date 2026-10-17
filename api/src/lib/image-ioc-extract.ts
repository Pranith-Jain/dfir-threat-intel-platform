/**
 * Image IOC extraction — OCR-ish step that finds IOCs embedded in
 * screenshots, diagrams, and report images.
 *
 * Pipeline:
 *   1. Caller fetches an image (URL or POSTed body) and passes a
 *      Uint8Array of image bytes.
 *   2. We hand the bytes to Workers AI's @cf/meta/llama-3.2-11b-vision-instruct
 *      (the first-party vision model — the previous captioner,
 *      @cf/unum/uform-gen2-qwen-500m, was retired and 404s in the model
 *      catalog). The model returns any visible text it can read — the classic
 *      "I see a phishing email header with these IPs in the From: line" output.
 *   3. We re-run the IOC normalizer on the extracted text to find
 *      IOCs, score them, and apply the allowlist.
 *
 * The model is best-effort. If the captioning call fails, we return
 * an empty array — the analyst can still see the original image and
 * do it by hand.
 */

import type { Env } from '../env';
import { isBenign, refang, scoreConfidence } from './ioc-normalize';
import { pinnedFetchFollow } from './ssrf-guard';

export interface ImageIocHit {
  value: string;
  kind: 'ipv4' | 'domain' | 'url' | 'hash' | 'cve' | 'email' | 'unknown';
  confidence: number;
  confidence_band: 'high' | 'medium' | 'low' | 'rejected';
  source: 'image-ocr';
  evidence: string; // the snippet of OCR text that contained the IOC
}

interface AIBindings {
  run: (model: string, inputs: unknown) => Promise<unknown>;
}

const VISION_MODEL = '@cf/meta/llama-3.2-11b-vision-instruct';
const VISION_PROMPT = 'Transcribe all text visible in this image verbatim. Output only the transcribed text.';
const VISION_TIMEOUT_MS = 20_000;

/** Both generations of vision model have shipped here: uform answered with
 *  `description`, llama-3.2-vision answers with `response`. Accept either so a
 *  future swap doesn't silently zero the caption again. */
function visionText(v: unknown): string | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as Record<string, unknown>;
  if (typeof r.description === 'string' && r.description) return r.description;
  if (typeof r.response === 'string' && r.response) return r.response;
  return null;
}

function detectKind(s: string): ImageIocHit['kind'] {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'ipv4';
  if (/^CVE-\d{4}-\d{4,}$/i.test(s)) return 'cve';
  if (/^[a-f0-9]{32,128}$/i.test(s) && s.length % 2 === 0) return 'hash';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s)) return 'email';
  if (/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) return 'domain';
  return 'unknown';
}

const IOC_REGEXES: Array<{ kind: ImageIocHit['kind']; re: RegExp }> = [
  { kind: 'ipv4', re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
  { kind: 'cve', re: /\bCVE-\d{4}-\d{4,}\b/gi },
  { kind: 'hash', re: /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g },
  { kind: 'url', re: /https?:\/\/[^\s<>"']{4,}/g },
  { kind: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // Domain: require a TLD, exclude 'localhost' / 'example' TLDs and IP-shaped values
  {
    kind: 'domain',
    re: /\b(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,}\b/gi,
  },
];

export async function extractIocsFromImageBytes(
  bytes: Uint8Array,
  env: { AI?: AIBindings }
): Promise<{ text: string; hits: ImageIocHit[]; error?: string }> {
  if (!env.AI) return { text: '', hits: [], error: 'AI binding unavailable' };
  if (bytes.byteLength === 0) return { text: '', hits: [], error: 'empty image' };
  if (bytes.byteLength > 5 * 1024 * 1024) {
    return { text: '', hits: [], error: 'image exceeds 5MB' };
  }

  let caption = '';
  try {
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('vision timeout')), VISION_TIMEOUT_MS)
    );
    const callPromise = env.AI.run(VISION_MODEL, { image: Array.from(bytes), prompt: VISION_PROMPT });
    const res = await Promise.race([callPromise, timeout]);
    caption = visionText(res) ?? '';
  } catch (e) {
    return { text: '', hits: [], error: e instanceof Error ? e.message : String(e) };
  }

  if (!caption) return { text: '', hits: [] };

  // Pull candidate IOCs out of the OCR text, then run through the same
  // normalizer + allowlist + scorer the live feed uses. Same false-positive
  // surface area, same confidence model — the only new thing is the source
  // label in the output.
  const candidates = new Set<string>();
  for (const { re } of IOC_REGEXES) {
    const matches = caption.match(re);
    if (matches) for (const m of matches) candidates.add(refang(m));
  }
  const hits: ImageIocHit[] = [];
  for (const c of candidates) {
    const kind = detectKind(c);
    if (isBenign(c, kind).allow === false) continue;
    const s = scoreConfidence(c, kind, caption);
    if (s.band === 'rejected') continue;
    hits.push({
      value: c,
      kind,
      confidence: s.score,
      confidence_band: s.band,
      source: 'image-ocr',
      evidence: caption.slice(0, 200),
    });
  }
  return { text: caption, hits };
}

export async function extractIocsFromImageUrl(
  url: string,
  env: { AI?: AIBindings } & Pick<Env, never>
): Promise<{ text: string; hits: ImageIocHit[]; error?: string }> {
  try {
    // Image OCR fetch — 15s ceiling. The URL is user-supplied and this
    // route IS publicly reachable (POST /api/v1/image-ioc), so the fetch
    // MUST be SSRF-safe: pinnedFetchFollow re-validates + IP-pins every
    // hop, blocking a public URL that 302s/rebinds to a private/metadata
    // host. Do NOT downgrade to a raw fetch() — that was a read-SSRF.
    const res = await pinnedFetchFollow(url, {
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; portfolio-ocr/1.0)' },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { text: '', hits: [], error: `fetch ${res.status}` };
    const ab = await res.arrayBuffer();
    return extractIocsFromImageBytes(new Uint8Array(ab), env);
  } catch (e) {
    return { text: '', hits: [], error: e instanceof Error ? e.message : String(e) };
  }
}
