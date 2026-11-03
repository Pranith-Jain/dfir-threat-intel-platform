import { describe, it, expect } from 'vitest';
import { parseManifest } from './lockfile-parsers';

function names(text: string): string[] {
  return parseManifest(text).packages.map((p) => `${p.name}@${p.version ?? ''}`);
}

describe('parseManifest', () => {
  it('parses npm package-lock and package.json', () => {
    const lock = parseManifest(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/lodash': { version: '4.17.20' },
          'node_modules/@scope/pkg': { version: '1.2.3' },
        },
      })
    );
    expect(lock.kind).toBe('npm package-lock.json');
    expect(lock.packages).toEqual([
      { name: 'lodash', ecosystem: 'npm', version: '4.17.20' },
      { name: '@scope/pkg', ecosystem: 'npm', version: '1.2.3' },
    ]);

    const pkg = parseManifest(JSON.stringify({ dependencies: { lodash: '^4.17.21' } }));
    expect(pkg.kind).toBe('npm package.json');
    expect(pkg.packages[0]).toEqual({ name: 'lodash', ecosystem: 'npm', version: '4.17.21' });
  });

  it('parses yarn v1 and berry locks', () => {
    const v1 = `# yarn lockfile v1\n\n"lodash@^4.17.0", "lodash@^4.17.4":\n  version "4.17.21"\n`;
    expect(parseManifest(v1).kind).toBe('yarn.lock (npm)');
    expect(names(v1)).toEqual(['lodash@4.17.21']);

    const berry = `__metadata:\n  version: 8\n\n"@babel/core@npm:^7.0.0":\n  version: 7.24.0\n`;
    expect(names(berry)).toEqual(['@babel/core@7.24.0']);
  });

  it('parses pnpm v9 and v6 locks', () => {
    const v9 = `lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n  '@scope/pkg@1.2.3':\n    resolution: {integrity: sha512-y}\n`;
    expect(parseManifest(v9).kind).toBe('pnpm-lock.yaml (npm)');
    expect(names(v9)).toEqual(['lodash@4.17.21', '@scope/pkg@1.2.3']);

    const v6 = `lockfileVersion: '6.0'\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n  /@scope/pkg/1.2.3:\n    resolution: {integrity: sha512-y}\n`;
    expect(names(v6)).toEqual(['lodash@4.17.21', '@scope/pkg@1.2.3']);
  });

  it('parses Pipfile.lock and poetry.lock', () => {
    const pipfile = parseManifest(
      JSON.stringify({
        _meta: { hash: { sha256: 'x' } },
        default: { requests: { version: '==2.31.0' }, flask: { version: '==3.0.0' } },
        develop: { pytest: { version: '==8.0.0' } },
      })
    );
    expect(pipfile.kind).toBe('Pipfile.lock (PyPI)');
    expect(pipfile.packages.map((p) => p.name)).toEqual(['requests', 'flask', 'pytest']);

    const poetry = `[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[metadata]\nlock-version = "2.0"\npython-versions = "^3.11"\ncontent-hash = "abc"\n`;
    const parsed = parseManifest(poetry);
    expect(parsed.kind).toBe('poetry.lock (PyPI)');
    expect(parsed.packages).toEqual([{ name: 'requests', ecosystem: 'PyPI', version: '2.31.0' }]);
  });

  it('keeps Cargo.lock and Gemfile.lock distinct', () => {
    const cargo = `[[package]]\nname = "serde"\nversion = "1.0.197"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
    expect(parseManifest(cargo).kind).toBe('Cargo.lock (crates.io)');
    expect(parseManifest(cargo).packages).toEqual([{ name: 'serde', ecosystem: 'crates.io', version: '1.0.197' }]);

    const gemfile = `GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.3)\n    nokogiri (1.16.0-x86_64-linux)\n`;
    const parsed = parseManifest(gemfile);
    expect(parsed.kind).toBe('Gemfile.lock (RubyGems)');
    expect(parsed.packages.map((p) => p.name)).toEqual(['rails', 'nokogiri']);
  });

  it('parses composer.lock before the npm JSON path', () => {
    const parsed = parseManifest(
      JSON.stringify({
        'content-hash': 'abc',
        packages: [{ name: 'laravel/framework', version: 'v10.0.0' }],
        'packages-dev': [{ name: 'phpunit/phpunit', version: '10.0.0' }],
      })
    );
    expect(parsed.kind).toBe('composer.lock (Packagist)');
    expect(parsed.packages).toEqual([
      { name: 'laravel/framework', ecosystem: 'Packagist', version: '10.0.0' },
      { name: 'phpunit/phpunit', ecosystem: 'Packagist', version: '10.0.0' },
    ]);
  });

  it('parses requirements.txt and go.mod', () => {
    const req = parseManifest('requests[socks]==2.31.0\nflask==3.0.0\n');
    expect(req.kind).toBe('requirements.txt (PyPI)');
    expect(req.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['requests@2.31.0', 'flask@3.0.0']);

    const go = `module example.com/app\n\ngo 1.22\n\nrequire (\n  github.com/gin-gonic/gin v1.9.1\n  golang.org/x/text v0.14.0\n)\n`;
    expect(parseManifest(go).kind).toBe('go.mod (Go)');
    expect(names(go)).toEqual(['github.com/gin-gonic/gin@v1.9.1', 'golang.org/x/text@v0.14.0']);
  });

  it('returns an empty result for unknown input', () => {
    expect(parseManifest('hello world')).toEqual({ packages: [], kind: '' });
  });
});
