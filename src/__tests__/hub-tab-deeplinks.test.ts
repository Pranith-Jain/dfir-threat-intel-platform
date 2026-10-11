import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Every DFIR sub-tool now lives as a tab inside a hub page. The old
 * one-route-per-tool paths survive only as redirects, and those redirects
 * MUST carry `?tab=<id>` — otherwise the hub opens its default tab and the
 * deep link silently means something else.
 *
 * The bug this guards: `/dfir/domain-rep` redirected to
 * `/dfir/domain-investigator`, whose initial state was hardcoded to the
 * `dns` tab. A user following that link landed on DNS instead of Reputation
 * with no error anywhere. `useHubTab` fixed the mechanism; this test makes
 * sure every redirect keeps pointing at a tab that actually exists.
 */

const ROOT = resolve(__dirname, '../..');
const read = (p: string) => readFileSync(resolve(ROOT, p), 'utf8');
const appSrc = read('src/App.tsx');

/** Routes served by a hub component, mapped to that hub's valid tab ids. */
function hubTabs(): Map<string, Set<string>> {
  const routeToComponent = new Map<string, string>(
    [...appSrc.matchAll(/\{ path: '(\/dfir\/[a-z0-9-]+)', Component: (\w+) \}/g)].map((m) => [m[1], m[2]!])
  );

  const out = new Map<string, Set<string>>();
  for (const file of readdirSync(resolve(ROOT, 'src/pages/dfir'))) {
    if (!file.endsWith('.tsx')) continue;
    const src = readFileSync(resolve(ROOT, 'src/pages/dfir', file), 'utf8');
    // A hub lazily imports at least one sibling component as a tab.
    if (!/import\('\.\//.test(src)) continue;
    const tabs = new Set([...src.matchAll(/active === '([a-z0-9-]+)'/g)].map((m) => m[1]!));
    for (const [route, component] of routeToComponent) {
      if (component === file.replace(/\.tsx$/, '')) out.set(route, tabs);
    }
  }
  return out;
}

const HUBS = hubTabs();

describe('DFIR tab-hub deep links', () => {
  it('maps at least the expected hubs', () => {
    // Guards against the extraction silently matching nothing.
    expect(HUBS.size).toBeGreaterThanOrEqual(10);
  });

  it('every ?tab= redirect names a tab the hub actually has', () => {
    const bad: string[] = [];
    for (const m of appSrc.matchAll(/to: '(\/dfir\/[a-z0-9-]+)\?tab=([a-z0-9-]+)'/g)) {
      const [, route, tab] = m as unknown as [string, string, string];
      const tabs = HUBS.get(route);
      if (!tabs) bad.push(`${route} -> no hub component at that route`);
      else if (!tabs.has(tab)) bad.push(`${route} has no tab '${tab}' (has: ${[...tabs].sort().join(', ')})`);
    }
    expect(bad, `redirects pointing at non-existent tabs:\n  ${bad.join('\n  ')}`).toEqual([]);
  });

  it('no redirect lands on a hub without pinning the tab it means', () => {
    // Every redirect whose target is a hub MUST carry ?tab=, otherwise the
    // hub opens its default tab and the deep link quietly means something
    // else (/dfir/domain-rep landing on the DNS tab).
    const bad: string[] = [];
    for (const m of appSrc.matchAll(
      /\{ path: '(\/dfir\/[a-z0-9-]+)', to: '(\/dfir\/[a-z0-9-]+)'(, preserveQuery: true)? \}/g
    )) {
      const [, from, to] = m as unknown as [string, string, string, string?];
      if (!HUBS.has(to)) continue;
      // The `to` in this match has no query string by construction, so any
      // redirect that omits it is a tab-dropping one.
      bad.push(`${from} -> ${to}`);
    }
    expect(
      bad,
      `these redirects land on a hub's default tab instead of the intended one:\n  ${bad.join('\n  ')}`
    ).toEqual([]);
  });

  it('multi-tab hubs read ?tab= via useHubTab rather than hardcoding', () => {
    // A hub that still uses `useState<TabId>('default')` cannot be deep-linked.
    const notWired: string[] = [];
    const hubsDir = resolve(ROOT, 'src/pages/dfir');
    for (const file of readdirSync(hubsDir)) {
      if (!file.endsWith('.tsx')) continue;
      const src = readFileSync(resolve(hubsDir, file), 'utf8');
      if (!/import\('\.\//.test(src)) continue; // not a hub
      if ([...src.matchAll(/active === '([a-z0-9-]+)'/g)].length < 2) continue; // single tab
      if (/useState<TabId>/.test(src) && !/useHubTab/.test(src)) notWired.push(file);
    }
    expect(notWired, `multi-tab hubs not using useHubTab: ${notWired.join(', ')}`).toEqual([]);
  });
});
