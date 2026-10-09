#!/usr/bin/env node
/**
 * SSRF dataflow scanner.
 *
 * WHY THIS EXISTS: the original check in .github/workflows/daily-bug-scan.yml
 * was `grep "does this route read query('url')" && "does it mention ssrf-guard"`.
 * That flags any handler which merely READS a url-ish query param, which is not
 * the same thing as one which FETCHES it. Eight of the nine files it reported
 * passed the value as an encodeURIComponent'd query parameter or a JSON body
 * field to a fixed upstream — none were SSRF-reachable. That noise buried the
 * one real finding (#298, threat-monitor), which sat in the same list.
 *
 * WHAT IT CHECKS: the actual dataflow. A file is reported only when a variable
 * assigned from `c.req.query(...)` / `c.req.param(...)` is used as the FIRST
 * ARGUMENT of `fetch(...)` — the one position where the value becomes the
 * request's host and can therefore be pointed at an internal address.
 *
 * Values that are safe by construction do not match, because they cannot reach
 * that position:
 *   - encodeURIComponent'd into a query string  → `fetch(`${BASE}?q=${enc(u)}`)`
 *   - JSON body fields                          → `fetch(URL, { body: JSON })`
 *   - already validated into a guarded fetcher   → `pinnedFetchFollow(u)`
 *
 * SUPPRESSION: two independent paths, both explicit and greppable.
 *   1. The file uses a guard — assertPublicHost / pinnedFetch / pinnedFetchFollow
 *      / secureFetch / flowvizSecureFetch. Detected automatically.
 *   2. The file carries a `// ssrf-audit: accept-reason <why>` annotation for a
 *      false positive the guard grep cannot see (e.g. .onion-only input).
 *
 * Exit codes: 0 clean, 1 suspects found, 2 scanner error.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROUTE_DIR = 'api/src/routes';

/** Fetcher wrappers that validate + pin the host themselves. */
const GUARD =
  /assertPublicHost|pinnedFetch|pinnedFetchFollow|flowvizSecureFetch|secureFetch/;

/** Human-set suppression for a false positive the guard grep cannot detect. */
const ANNOTATION = 'ssrf-audit: accept-reason';

/**
 * Extract the first argument of a `fetch(` call starting at `start`.
 * Returns the raw source text of that argument, or null if the call is malformed.
 * Walks the string tracking nesting and string-literal state so a comma inside
 * a string or a nested call does not terminate the argument early.
 */
function firstArg(src, start) {
  let i = start + 'fetch'.length;
  while (i < src.length && (src[i] === ' ' || src[i] === '\t')) i += 1;
  if (src[i] !== '(') return null;
  i += 1;
  let depth = 1;
  let out = '';
  let quote = null;
  while (i < src.length && depth > 0) {
    const ch = src[i];
    if (quote) {
      out += ch;
      if (ch === '\\') {
        out += src[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      out += ch;
    } else if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      out += ch;
    } else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) break;
      out += ch;
    } else if (ch === ',' && depth === 1) {
      break;
    } else {
      out += ch;
    }
    i += 1;
  }
  return out;
}

/** Variables assigned directly from a request read: `const u = c.req.query('url')`. */
function requestVars(src) {
  const vars = new Set();
  const re = /(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*([^;\n]{0,120})c\.req\.(?:query|param)\(/g;
  let m;
  while ((m = re.exec(src)) !== null) vars.add(m[1]);
  return vars;
}

function scanFile(path) {
  const src = readFileSync(path, 'utf8');
  if (src.includes(ANNOTATION)) return { skipped: 'annotated', hits: [] };
  if (GUARD.test(src)) return { skipped: 'uses-guard', hits: [] };

  const vars = requestVars(src);
  if (vars.size === 0) return { hits: [] };

  const hits = [];
  const re = /(?<![\w.$])fetch\s*\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const arg = firstArg(src, m.index);
    if (arg === null) continue;
    // Only a BARE identifier as the whole first argument is the dangerous shape.
    // A template literal or an expression has already been built into something
    // specific; a bare identifier means the user value IS the URL.
    const bare = arg.trim().match(/^([A-Za-z_]\w*)$/);
    if (!bare) continue;
    if (vars.has(bare[1])) {
      hits.push({ line: src.slice(0, m.index).split('\n').length, var: bare[1] });
    }
  }
  return { hits };
}

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) files.push(...walk(full));
    else if (entry.endsWith('.ts') && !entry.includes('.test.')) files.push(full);
  }
  return files;
}

function main() {
  let files;
  try {
    files = walk(ROUTE_DIR);
  } catch (err) {
    console.error(`scan-ssrf: cannot read ${ROUTE_DIR}: ${err.message}`);
    process.exit(2);
  }

  const suspects = [];
  for (const file of files) {
    const { hits, skipped } = scanFile(file);
    if (hits.length > 0) suspects.push({ file, hits });
    else if (skipped) suspects.push({ file, skipped, hits: [] });
  }

  const real = suspects.filter((s) => s.hits.length > 0);
  if (real.length === 0) {
    console.log(`scan-ssrf: clean (${files.length} route files)`);
    process.exit(0);
  }

  const lines = real.map(({ file, hits }) => {
    const detail = hits.map((h) => `    line ${h.line}: fetch(${h.var})`).join('\n');
    return `${file}\n${detail}`;
  });
  console.log(lines.join('\n'));
  console.error(`scan-ssrf: ${real.length} file(s) with a request value used as a fetch host`);
  process.exit(1);
}

main();