/**
 * Tests for the SSRF dataflow scanner (scripts/scan-ssrf.mjs).
 *
 * The scanner is a gate, so its failure modes matter more than its hit rate:
 *   - a FALSE NEGATIVE lets an SSRF ship (the #298 regression),
 *   - a FALSE POSITIVE re-files the same noise daily and trains everyone to
 *     ignore the scan.
 *
 * Each case below is a shape that actually appears in this repo, not a synthetic
 * one. The critical assertion is the negative direction: the safe shapes that
 * the OLD grep-based check used to flag must stay silent.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, 'scan-ssrf.mjs');

/**
 * Materialise a throwaway api/src/routes/<name>.ts and run the scanner over it.
 * The scanner walks a fixed relative path, so each case runs in its own cwd.
 */
function scan(source) {
  const root = mkdtempSync(join(tmpdir(), 'scan-ssrf-'));
  const dir = join(root, 'api/src/routes');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'probe.ts'), source);
  try {
    const out = execFileSync(process.execPath, [SCANNER], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status, out: err.stdout ?? '' };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ── Must flag: the user value IS the fetch target ────────────────────────

test('flags a bare request value used as the fetch host (#298 shape)', () => {
  const { code, out } = scan(`
    export const r = new Hono();
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 1);
  assert.match(out, /probe\.ts/);
  assert.match(out, /fetch\(url\)/);
});

test('flags a param-sourced value, not just query', () => {
  const { code } = scan(`
    r.get('/x/:target', async (c) => {
      const target = c.req.param('target');
      const res = await fetch(target);
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 1);
});

test('flags when the value passes through .trim() first', () => {
  const { code, out } = scan(`
    r.get('/x', async (c) => {
      const url = (c.req.query('url') ?? '').trim();
      const res = await fetch(url);
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 1);
  assert.match(out, /line 4/);
});

// ── Must stay silent: shapes the old grep check used to flag ─────────────

test('silent when the value is a query param of a fixed upstream', () => {
  // mozilla-tls: `?host=<user>` against a constant Observatory host.
  const { code } = scan(`
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await fetch(
        \`https://http-observatory.security.mozilla.org/api/v1/analyze?host=\${encodeURIComponent(url)}\`
      );
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

test('silent when the value is a JSON body field to a fixed upstream', () => {
  // darknet-intel-tools urlhaus: POST body, constant host.
  const { code } = scan(`
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        body: JSON.stringify({ url }),
      });
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

test('silent when the fetch goes through a guard fetcher', () => {
  const { code } = scan(`
    import { pinnedFetchFollow } from '../lib/ssrf-guard';
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await pinnedFetchFollow(url);
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

test('silent for an accept-reason annotated file', () => {
  const { code } = scan(`
    // ssrf-audit: accept-reason .onion-only input, fixed tor2web gateway
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await fetch(url);
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

test('silent when the file reads no request values at all', () => {
  const { code } = scan(`
    r.get('/x', async (c) => {
      const res = await fetch('https://example.com/feed');
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

test('silent when fetch is called on a non-identifier expression', () => {
  // A template literal is already a specific URL, not the raw user value.
  const { code } = scan(`
    r.get('/x', async (c) => {
      const slug = c.req.query('slug');
      const res = await fetch(\`https://api.example.com/\${slug}\`);
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 0);
});

// ── Parser robustness ────────────────────────────────────────────────────

test('does not split the argument on a comma inside a string literal', () => {
  // The first-arg walker must not stop at the comma inside "a,b" and then see
  // a bare identifier that isn't the URL.
  const { code } = scan(`
    r.get('/x', async (c) => {
      const other = c.req.query('other');
      const res = await fetch(url, { headers: { accept: 'text/html,application/xml' } });
      return new Response(other);
    });
  `);
  assert.equal(code, 0, 'a comma in an init string must not be read as the arg boundary');
});

test('handles a nested call in the init object', () => {
  const { code, out } = scan(`
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      return new Response(await res.text());
    });
  `);
  assert.equal(code, 1);
  assert.match(out, /fetch\(url\)/);
});

test('ignores fetch as a property or method name', () => {
  const { code } = scan(`
    r.get('/x', async (c) => {
      const url = c.req.query('url');
      const res = await self.caches.default.fetch(url);
      return new Response(res.status);
    });
  `);
  assert.equal(code, 0, 'a .fetch method call is not the global fetcher');
});

test('ignores test files', () => {
  const root = mkdtempSync(join(tmpdir(), 'scan-ssrf-t-'));
  const dir = join(root, 'api/src/routes');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'thing.test.ts'),
    `r.get('/x', async (c) => { const url = c.req.query('url'); return fetch(url); });`
  );
  try {
    execFileSync(process.execPath, [SCANNER], { cwd: root, encoding: 'utf8' });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});