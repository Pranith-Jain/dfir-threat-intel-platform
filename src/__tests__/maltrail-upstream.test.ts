import { describe, it, expect } from 'vitest';

/**
 * Regression guard for the `/threatintel/malware/maltrail` 502.
 *
 * The handler fetched `trails/static/malware` from stamparm/maltrail, a path
 * that has never existed upstream, so every list request 404'd and surfaced
 * as a 502 for every visitor. Nothing tested the URLs, so it rotted silently.
 *
 * The raw-path check is the actual regression guard and uses a long-standing
 * file in upstream `data/`. The contents-API check is supplementary: GitHub
 * rate-limits anonymous CI IPs (403/429), so that case degrades to a warning
 * rather than failing a deploy for a reason unrelated to the handler.
 */
const RAW = 'https://raw.githubusercontent.com/stamparm/maltrail/master/data';
const API = 'https://api.github.com/repos/stamparm/maltrail/contents/data';
const KNOWN_TXT = 'bogon_ranges.txt';

const GH = { 'User-Agent': 'pranithjain.maltrail-test', Accept: 'application/vnd.github.v3+json' };

describe('maltrail upstream paths', () => {
  it('a long-standing .txt list file is fetchable from the raw data path', async () => {
    const raw = await fetch(`${RAW}/${KNOWN_TXT}`, { headers: { 'User-Agent': GH['User-Agent'] } });
    expect(raw.status, `${RAW}/${KNOWN_TXT} returned ${raw.status}`).toBe(200);
    const body = await raw.text();
    expect(body.length, 'list file should not be empty').toBeGreaterThan(0);
    // Content is IOC lines with `#` comments — the classifier relies on that.
    expect(body).toMatch(/^#/m);
  }, 30_000);

  it('the contents API lists .txt list files (skipped when rate-limited)', async () => {
    const res = await fetch(API, { headers: GH });
    if (res.status === 403 || res.status === 429) {
      console.warn(`[maltrail] GitHub contents API rate-limited (${res.status}); skipping listing assertion.`);
      return;
    }
    expect(res.status, `${API} returned ${res.status}`).toBe(200);
    const files = (await res.json()) as Array<{ type: string; name: string }>;
    expect(Array.isArray(files), 'contents API should return an array').toBe(true);
    const txt = files.filter((f) => f.type === 'file' && f.name.endsWith('.txt'));
    expect(txt.length, 'expected at least one .txt list file').toBeGreaterThan(0);
  }, 30_000);
});
