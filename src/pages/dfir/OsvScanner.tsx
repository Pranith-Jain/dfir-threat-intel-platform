import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef } from 'react';
import { BackLink } from '../../components/BackLink';
import { ShieldAlert, ShieldCheck, Loader2, ExternalLink } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';

/**
 * OSV Dependency Scanner - paste a lockfile/manifest → known
 * vulnerabilities via OSV.dev (proxied server-side; OSV has no browser
 * CORS). Parsing is 100% client-side; only the {name,ecosystem,version}
 * list is sent. Supports npm (package-lock/package.json), PyPI
 * (requirements.txt), Go (go.mod), crates.io (Cargo.lock), RubyGems
 * (Gemfile.lock).
 */

interface Pkg {
  name: string;
  ecosystem: string;
  version?: string;
}
interface VulnRow {
  package: string;
  version: string;
  ecosystem: string;
  vulns: { id: string; summary?: string; severity?: string; aliases?: string[]; fixed?: string }[];
}

const stripRange = (v: string) =>
  v
    .replace(/^[\^~>=<\s]+/, '')
    .replace(/\s.*$/, '')
    .trim();

function parseManifest(text: string): { packages: Pkg[]; kind: string } {
  const t = text.trim();
  // JSON → npm lockfile or package.json
  if (t.startsWith('{')) {
    try {
      const j = JSON.parse(t) as Record<string, unknown>;
      if (j.lockfileVersion || j.packages) {
        const out: Pkg[] = [];
        const pkgs = (j.packages as Record<string, { version?: string }>) ?? {};
        for (const [k, v] of Object.entries(pkgs)) {
          if (!k.startsWith('node_modules/') || !v?.version) continue;
          out.push({ name: k.replace(/^.*node_modules\//, ''), ecosystem: 'npm', version: v.version });
        }
        const deps = (j.dependencies as Record<string, { version?: string }>) ?? {};
        for (const [k, v] of Object.entries(deps))
          if (v?.version) out.push({ name: k, ecosystem: 'npm', version: v.version });
        return { packages: dedupe(out), kind: 'npm package-lock.json' };
      }
      const out: Pkg[] = [];
      for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
        const d = (j[field] as Record<string, string>) ?? {};
        for (const [name, ver] of Object.entries(d))
          out.push({ name, ecosystem: 'npm', version: stripRange(String(ver)) || undefined });
      }
      return { packages: dedupe(out), kind: 'npm package.json' };
    } catch (_catchErr) {
      console.error('parseManifest failed:', errMessage(_catchErr));
      /* fall through to text parsers */
    }
  }
  // requirements.txt (PyPI)
  if (/^[\w.-]+\s*==\s*[\w.]+/m.test(t) || /(^|\n)[\w.-]+\s*[<>=!~]=/.test(t)) {
    const out: Pkg[] = [];
    for (const line of t.split('\n')) {
      const m = /^\s*([A-Za-z0-9._-]+)\s*==\s*([\w.]+)/.exec(line);
      if (m) out.push({ name: m[1]!.toLowerCase(), ecosystem: 'PyPI', version: m[2] });
    }
    if (out.length) return { packages: dedupe(out), kind: 'requirements.txt (PyPI)' };
  }
  // go.mod
  if (/^module\s+\S+/m.test(t) || /^\s*require\s/m.test(t)) {
    const out: Pkg[] = [];
    for (const m of t.matchAll(/(?:^|\n)\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v([\w.\-+]+)/g))
      out.push({ name: m[1]!, ecosystem: 'Go', version: `v${m[2]}` });
    if (out.length) return { packages: dedupe(out), kind: 'go.mod (Go)' };
  }
  // Cargo.lock
  if (/\[\[package\]\]/.test(t)) {
    const out: Pkg[] = [];
    for (const block of t.split('[[package]]')) {
      const n = /name\s*=\s*"([^"]+)"/.exec(block);
      const v = /version\s*=\s*"([^"]+)"/.exec(block);
      if (n && v) out.push({ name: n[1]!, ecosystem: 'crates.io', version: v[1] });
    }
    if (out.length) return { packages: dedupe(out), kind: 'Cargo.lock (crates.io)' };
  }
  // Gemfile.lock
  if (/^GEM\b/m.test(t) && /specs:/.test(t)) {
    const out: Pkg[] = [];
    for (const m of t.matchAll(/^\s{4}([a-z0-9._-]+) \(([\w.]+)\)/gim))
      out.push({ name: m[1]!, ecosystem: 'RubyGems', version: m[2] });
    if (out.length) return { packages: dedupe(out), kind: 'Gemfile.lock (RubyGems)' };
  }
  return { packages: [], kind: '' };
}

function dedupe(p: Pkg[]): Pkg[] {
  const seen = new Set<string>();
  return p.filter((x) => {
    const k = `${x.ecosystem}:${x.name}@${x.version ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export default function OsvScanner(): JSX.Element {
  const [input, setInput] = useState('');
  const [rows, setRows] = useState<VulnRow[] | null>(null);
  const [meta, setMeta] = useState<{ kind: string; total: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const runRef = useRef<AbortController | null>(null);

  const run = async () => {
    setErr(null);
    const { packages, kind } = parseManifest(input);
    if (packages.length === 0) {
      setErr(
        'No packages parsed. Supported: package-lock.json / package.json, requirements.txt, go.mod, Cargo.lock, Gemfile.lock.'
      );
      setRows(null);
      setMeta(null);
      return;
    }
    runRef.current?.abort();
    const ctrl = new AbortController();
    runRef.current = ctrl;
    setRunning(true);
    setRows(null);
    try {
      const r = await fetch('/api/v1/osv/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ packages: packages.slice(0, 250) }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) throw new Error(`scan failed (HTTP ${r.status})`);
      const d = (await r.json()) as { results: VulnRow[]; total_packages: number };
      const sorted = [...d.results].sort((a, b) => b.vulns.length - a.vulns.length);
      setRows(sorted);
      setMeta({ kind, total: d.total_packages });
    } catch (e) {
      logCatch(e);
      if (ctrl.signal.aborted) return;
      setErr((e as Error).message);
    } finally {
      if (!ctrl.signal.aborted) setRunning(false);
    }
  };

  const vulnerable = rows?.filter((r) => r.vulns.length > 0) ?? [];

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">OSV Dependency Scanner</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste a lockfile/manifest - <span className="font-mono text-tool">package-lock.json</span> / package.json,
          requirements.txt, go.mod, Cargo.lock, Gemfile.lock. Parsed in your browser; only the name/version list is
          checked against{' '}
          <a
            href="https://osv.dev"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            OSV.dev
          </a>{' '}
          (proxied - OSV has no browser CORS).
        </p>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            type="button"
            onClick={() =>
              setInput(
                '{\n  "dependencies": {\n    "lodash": "4.17.19",\n    "log4js": "0.6.0",\n    "minimist": "1.2.0"\n  }\n}'
              )
            }
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load example
          </button>
          {input && (
            <button
              type="button"
              onClick={() => {
                setInput('');
                setRows(null);
                setMeta(null);
                setErr(null);
              }}
              className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
            >
              clear
            </button>
          )}
        </div>
      </div>
      <label htmlFor="osv-input" className="sr-only">
        Lockfile / manifest
      </label>
      <Textarea
        id="osv-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Paste package-lock.json / requirements.txt / go.mod / Cargo.lock / Gemfile.lock"
        rows={12}
        spellCheck={false}
        aria-label="Lockfile / manifest"
      />
      <button
        type="button"
        onClick={() => void run()}
        disabled={running || !input.trim()}
        className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono text-sm font-semibold rounded-xl disabled:opacity-40 hover:bg-brand-700 dark:hover:bg-brand-400"
      >
        {running && <Loader2 size={14} className="animate-spin" />} {running ? 'scanning OSV…' : 'scan dependencies'}
      </button>

      {err && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{err}</p>}

      {rows && meta && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Parsed:</span> <span className="font-mono">{meta.kind}</span>
              </span>
              <span>
                <span className="text-muted">Packages:</span> <span className="font-mono">{meta.total}</span>
              </span>
              <span
                className={`text-mini font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${vulnerable.length ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'}`}
              >
                {vulnerable.length} vulnerable
              </span>
            </div>
          </section>

          {vulnerable.length === 0 && (
            <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
              <ShieldCheck size={16} className="mt-0.5 flex-shrink-0" />
              <span>
                No known OSV advisories for the parsed packages. (Exact-version matching - transitive ranges may still
                warrant a full SCA in CI.)
              </span>
            </section>
          )}

          {vulnerable.map((r) => (
            <section key={`${r.ecosystem}:${r.package}@${r.version}`} className="surface-card p-4">
              <div className="flex items-center gap-2 flex-wrap">
                <ShieldAlert size={15} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
                <span className="font-display font-semibold">{r.package}</span>
                <span className="text-meta font-mono text-muted">
                  {r.version} · {r.ecosystem}
                </span>
                <span className="text-mini font-mono px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/5 text-rose-600 dark:text-rose-400">
                  {r.vulns.length} advisor{r.vulns.length === 1 ? 'y' : 'ies'}
                </span>
              </div>
              <ul className="mt-2 space-y-2">
                {r.vulns.map((v) => (
                  <li key={v.id} className="text-sm">
                    <a
                      href={`https://osv.dev/vulnerability/${v.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                    >
                      {v.id} <ExternalLink size={11} />
                    </a>
                    {v.aliases && v.aliases.length > 0 && (
                      <span className="text-mini font-mono text-muted">
                        {' '}
                        · {v.aliases.filter((a) => a.startsWith('CVE')).join(', ')}
                      </span>
                    )}
                    {v.fixed && (
                      <span className="text-mini font-mono text-emerald-700 dark:text-emerald-400">
                        {' '}
                        · fixed in {v.fixed}
                      </span>
                    )}
                    {v.summary && <p className="text-muted mt-0.5 leading-relaxed">{v.summary}</p>}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
