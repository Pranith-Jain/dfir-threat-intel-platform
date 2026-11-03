/**
 * Lockfile / manifest parsers for the browser-only OSV dependency scanner.
 *
 * Kept out of the page component so the formats can be unit-tested without a
 * DOM. The scanner sends only {name, ecosystem, version} tuples to the OSV
 * proxy; everything here runs in the browser.
 */

export interface Pkg {
  name: string;
  ecosystem: string;
  version?: string;
}

export interface ParsedManifest {
  packages: Pkg[];
  kind: string;
}

const ECOSYSTEM = {
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go',
  cargo: 'crates.io',
  rubygems: 'RubyGems',
  packagist: 'Packagist',
} as const;

const stripRange = (v: string) =>
  v
    .replace(/^[\^~>=<\s]+/, '')
    .replace(/\s.*$/, '')
    .trim();

const stripComposerV = (v: string) => v.replace(/^v(?=\d)/i, '');

function dedupe(p: Pkg[]): Pkg[] {
  const seen = new Set<string>();
  return p.filter((x) => {
    const k = `${x.ecosystem}:${x.name}@${x.version ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/* ─── JSON formats ────────────────────────────────────────────────────────── */

function parseComposer(j: Record<string, unknown>): ParsedManifest | null {
  const packages = [...asArray(j.packages), ...asArray(j['packages-dev'])];
  const composerLock = packages.length > 0 || typeof j['content-hash'] === 'string';
  if (!composerLock) return null;
  const out: Pkg[] = [];
  for (const raw of packages) {
    const p = asRecord(raw);
    const name = str(p?.name).toLowerCase();
    const version = str(p?.version);
    if (name && version) out.push({ name, ecosystem: ECOSYSTEM.packagist, version: stripComposerV(version) });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'composer.lock (Packagist)' } : null;
}

function parsePipfileLock(j: Record<string, unknown>): ParsedManifest | null {
  const hasMeta = asRecord(j._meta) !== null;
  const groups = ['default', 'develop'].filter((g) => asRecord(j[g]) !== null);
  if (!hasMeta && groups.length === 0) return null;
  const out: Pkg[] = [];
  for (const group of groups) {
    const entries = asRecord(j[group]) ?? {};
    for (const [name, raw] of Object.entries(entries)) {
      const entry = asRecord(raw);
      const version = stripRange(str(entry?.version));
      if (name && version) out.push({ name: name.toLowerCase(), ecosystem: ECOSYSTEM.pypi, version });
    }
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'Pipfile.lock (PyPI)' } : null;
}

function parseNpmLock(j: Record<string, unknown>): ParsedManifest | null {
  const packages = asRecord(j.packages);
  const hasNodeModules = packages ? Object.keys(packages).some((k) => k.startsWith('node_modules/')) : false;
  if (j.lockfileVersion === undefined && !hasNodeModules) return null;
  const out: Pkg[] = [];
  for (const [k, raw] of Object.entries(packages ?? {})) {
    const v = asRecord(raw);
    if (!k.startsWith('node_modules/') || !v?.version) continue;
    out.push({
      name: k.replace(/^.*node_modules\//, ''),
      ecosystem: ECOSYSTEM.npm,
      version: str(v.version),
    });
  }
  const deps = asRecord(j.dependencies) ?? {};
  for (const [name, raw] of Object.entries(deps)) {
    const v = asRecord(raw);
    if (v?.version) out.push({ name, ecosystem: ECOSYSTEM.npm, version: str(v.version) });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'npm package-lock.json' } : null;
}

function parsePackageJson(j: Record<string, unknown>): ParsedManifest | null {
  const out: Pkg[] = [];
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = asRecord(j[field]) ?? {};
    for (const [name, raw] of Object.entries(deps)) {
      const version = stripRange(String(raw));
      out.push({ name, ecosystem: ECOSYSTEM.npm, ...(version ? { version } : {}) });
    }
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'npm package.json' } : null;
}

function parseJsonManifest(j: Record<string, unknown>): ParsedManifest | null {
  return parseComposer(j) ?? parsePipfileLock(j) ?? parseNpmLock(j) ?? parsePackageJson(j);
}

/* ─── Yarn / pnpm ─────────────────────────────────────────────────────────── */

function yarnPackageName(key: string): string {
  let k = key
    .trim()
    .replace(/^"(.*)"$/, '$1')
    .replace(/\([^)]*\)$/, '');
  const npmProtocol = k.indexOf('@npm:');
  if (npmProtocol > 0) k = k.slice(0, npmProtocol);
  const at = k.startsWith('@') ? k.indexOf('@', 1) : k.indexOf('@');
  return (at > 0 ? k.slice(0, at) : k).trim();
}

function parseYarnLock(text: string): ParsedManifest | null {
  if (!/^# yarn lockfile v1/m.test(text) && !/^__metadata:/m.test(text)) return null;
  const out: Pkg[] = [];
  let current: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (!/^\s/.test(line) && line.trim().endsWith(':')) {
      const raw = line.trim().slice(0, -1);
      const first = raw.split(',')[0]?.trim() ?? '';
      const name = yarnPackageName(first);
      current = name && !name.startsWith('__') ? name : null;
      continue;
    }
    if (!current) continue;
    const m = /^\s+version(?::|\s)\s*"?([^"\s]+)"?/.exec(line);
    if (m) {
      out.push({ name: current, ecosystem: ECOSYSTEM.npm, version: m[1]! });
      current = null;
    }
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'yarn.lock (npm)' } : null;
}

function pnpmNameVersion(key: string): [string, string] | null {
  let k = key.trim().replace(/^['"]|['"]$/g, '');
  k = k.replace(/\([^)]*\)$/, '');
  if (k.startsWith('/')) k = k.slice(1);

  if (k.startsWith('@')) {
    const slash = k.lastIndexOf('/');
    const slashVersion = slash > 0 ? k.slice(slash + 1) : '';
    if (/^\d/.test(slashVersion)) return [k.slice(0, slash), slashVersion];
    const at = k.indexOf('@', 1);
    if (at > 0 && /^\d/.test(k.slice(at + 1))) return [k.slice(0, at), k.slice(at + 1)];
    return null;
  }

  const at = k.lastIndexOf('@');
  if (at > 0 && /^\d/.test(k.slice(at + 1))) return [k.slice(0, at), k.slice(at + 1)];
  const slash = k.lastIndexOf('/');
  if (slash > 0 && /^\d/.test(k.slice(slash + 1))) return [k.slice(0, slash), k.slice(slash + 1)];
  return null;
}

function parsePnpmLock(text: string): ParsedManifest | null {
  if (!/^lockfileVersion:/m.test(text) || !/^packages:/m.test(text)) return null;
  const out: Pkg[] = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const indent = /^\s*/.exec(line)?.[0].length ?? 0;
    if (indent === 0) {
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages || indent !== 2 || !line.trim().endsWith(':')) continue;
    const parsed = pnpmNameVersion(line.trim().slice(0, -1));
    if (parsed) out.push({ name: parsed[0], ecosystem: ECOSYSTEM.npm, version: parsed[1] });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'pnpm-lock.yaml (npm)' } : null;
}

/* ─── TOML formats ────────────────────────────────────────────────────────── */

function parseTomlPackages(text: string, kind: string, ecosystem: string): ParsedManifest {
  const out: Pkg[] = [];
  for (const block of text.split('[[package]]')) {
    const n = /name\s*=\s*"([^"]+)"/.exec(block);
    const v = /version\s*=\s*"([^"]+)"/.exec(block);
    if (n && v) out.push({ name: n[1]!, ecosystem, version: v[1] });
  }
  return { packages: dedupe(out), kind };
}

function parsePoetryLock(text: string): ParsedManifest | null {
  if (!/\[\[package\]\]/.test(text) || !/\[metadata\]/.test(text)) return null;
  if (!/lock-version|python-versions|content-hash/.test(text)) return null;
  const parsed = parseTomlPackages(text, 'poetry.lock (PyPI)', ECOSYSTEM.pypi);
  return parsed.packages.length > 0 ? parsed : null;
}

function parseCargoLock(text: string): ParsedManifest | null {
  if (!/\[\[package\]\]/.test(text)) return null;
  const parsed = parseTomlPackages(text, 'Cargo.lock (crates.io)', ECOSYSTEM.cargo);
  return parsed.packages.length > 0 ? parsed : null;
}

/* ─── Requirements / Go / Gemfile ─────────────────────────────────────────── */

function parseRequirements(text: string): ParsedManifest | null {
  if (!/(^|\n)\s*[A-Za-z0-9._-]+(\[[^\]]*\])?\s*==\s*[\w.]+/.test(text)) return null;
  const out: Pkg[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([\w.]+)/.exec(line);
    if (m) out.push({ name: m[1]!.toLowerCase(), ecosystem: ECOSYSTEM.pypi, version: m[2] });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'requirements.txt (PyPI)' } : null;
}

function parseGoMod(text: string): ParsedManifest | null {
  if (!/^module\s+\S+/m.test(text) && !/^\s*require\s/m.test(text)) return null;
  const out: Pkg[] = [];
  for (const m of text.matchAll(/(?:^|\n)\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v([\w.\-+]+)/g)) {
    out.push({ name: m[1]!, ecosystem: ECOSYSTEM.go, version: `v${m[2]}` });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'go.mod (Go)' } : null;
}

function parseGemfileLock(text: string): ParsedManifest | null {
  if (!/^GEM\b/m.test(text) || !/specs:/.test(text)) return null;
  const out: Pkg[] = [];
  for (const m of text.matchAll(/^\s{4}([a-z0-9._-]+) \(([^)]+)\)/gim)) {
    out.push({ name: m[1]!, ecosystem: ECOSYSTEM.rubygems, version: m[2]! });
  }
  return out.length > 0 ? { packages: dedupe(out), kind: 'Gemfile.lock (RubyGems)' } : null;
}

/* ─── Entry point ─────────────────────────────────────────────────────────── */

export function parseManifest(text: string): ParsedManifest {
  const t = text.trim();
  if (t.startsWith('{')) {
    try {
      const parsed = parseJsonManifest(JSON.parse(t) as Record<string, unknown>);
      if (parsed) return parsed;
    } catch {
      /* fall through to text parsers */
    }
  }
  return (
    parsePoetryLock(t) ??
    parseCargoLock(t) ??
    parseGemfileLock(t) ??
    parseYarnLock(t) ??
    parsePnpmLock(t) ??
    parseRequirements(t) ??
    parseGoMod(t) ?? { packages: [], kind: '' }
  );
}
