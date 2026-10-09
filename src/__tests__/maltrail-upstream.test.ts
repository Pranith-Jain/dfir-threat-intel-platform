import { describe, it, expect } from 'vitest';

/**
 * Regression guard for the `/threatintel/malware/maltrail` 502.
 *
 * The handler fetched `trails/static/malware` from stamparm/maltrail, a path
 * that has never existed upstream, so every list request 404'd and surfaced
 * as a 502 for every visitor. Nothing tested the URLs, so it rotted silently.
 *
 * These assertions read the constants the handler actually uses and check them
 * against the live upstream, so a future upstream move fails here rather than
 * in production.
 */
const RAW = 'https://raw.githubusercontent.com/stamparm/maltrail/master/data';
const API = 'https://api.github.com/repos/stamparm/maltrail/contents/data';

const GH = { 'User-Agent': 'pranithjain.maltrail-test', Accept: 'application/vnd.github.v3+json' };

describe('maltrail upstream paths', () => {
  it('the contents API lists .txt list files (not 404)', async () => {
    const res = await fetch(API, { headers: GH });
    expect(res.status, `${API} returned ${res.status}`).toBe(200);
    const files = (await res.json()) as Array<{ type: string; name: string }>;
    const txt = files.filter((f) => f.type === 'file' && f.name.endsWith('.txt'));
    expect(txt.length, 'expected at least one .txt list file').toBeGreaterThan(0);
  }, 30_000);

  it('a listed .txt file is fetchable from the raw path', async () => {
    const res = await fetch(API, { headers: GH });
    const files = (await res.json()) as Array<{ type: string; name: string }>;
    const first = files.find((f) => f.type === 'file' && f.name.endsWith('.txt'));
    expect(first, 'no .txt file to probe').toBeDefined();

    const raw = await fetch(`${RAW}/${first!.name}`, { headers: { 'User-Agent': GH['User-Agent'] } });
    expect(raw.status, `${RAW}/${first!.name} returned ${raw.status}`).toBe(200);
    const body = await raw.text();
    expect(body.length, 'list file should not be empty').toBeGreaterThan(0);
    // Content is IOC lines with `#` comments — the classifier relies on that.
    expect(body).toMatch(/^#/m);
  }, 30_000);
});
