import { describe, expect, it } from 'vitest';
import { PURL_TYPES, buildPurl, parsePurl, purlFromCpe, purlBareName, purlIdentity } from '../../src/lib/purl';

describe('parsePurl', () => {
  it('parses the canonical npm form', () => {
    const p = parsePurl('pkg:npm/lodash@4.17.21');
    expect(p).not.toBeNull();
    expect(p!.type).toBe('npm');
    expect(p!.name).toBe('lodash');
    expect(p!.namespace).toEqual([]);
    expect(p!.version).toBe('4.17.21');
  });

  it('parses a scoped npm package into namespace + name', () => {
    const p = parsePurl('pkg:npm/%40angular/core@17.0.0');
    expect(p!.type).toBe('npm');
    expect(p!.namespace).toEqual(['@angular']);
    expect(p!.name).toBe('core');
    expect(p!.version).toBe('17.0.0');
  });

  it('treats the whole remainder as the name for unnamespaced types', () => {
    // pkg:deb/debian/curl/amd64 is ONE name, not a namespace path.
    const p = parsePurl('pkg:deb/debian/curl/amd64');
    expect(p!.type).toBe('deb');
    expect(p!.namespace).toEqual([]);
    expect(p!.name).toBe('debian/curl/amd64');
  });

  it('splits maven groupId:artifactId into namespace + name', () => {
    const p = parsePurl('pkg:maven/org.apache.commons/commons-lang3@3.12.0');
    expect(p!.type).toBe('maven');
    expect(p!.namespace).toEqual(['org.apache.commons']);
    expect(p!.name).toBe('commons-lang3');
  });

  it('parses qualifiers and lowercases their keys', () => {
    const p = parsePurl('pkg:npm/foo@1.0.0?arch=x86&repository_url=https%3A%2F%2Fexample.com');
    expect(p!.qualifiers.arch).toBe('x86');
    expect(p!.qualifiers.repository_url).toBe('https://example.com');
  });

  it('parses a subpath', () => {
    const p = parsePurl('pkg:generic/bitwarderl?vcs_url=git%2Bhttps://x/y#src/main');
    expect(p!.subpath).toBe('src/main');
  });

  it('lowercases the type', () => {
    expect(parsePurl('pkg:NPM/lodash')!.type).toBe('npm');
  });

  it('round-trips through buildPurl', () => {
    for (const raw of [
      'pkg:npm/lodash@4.17.21',
      'pkg:maven/org.apache.commons/commons-lang3@3.12.0',
      'pkg:pypi/django@5.0',
      'pkg:golang/github.com/gin-gonic/gin@v1.9.1',
    ]) {
      expect(parsePurl(raw)!.canonical).toBe(raw);
    }
  });

  it('rejects a non-purl string', () => {
    expect(parsePurl('lodash')).toBeNull();
    expect(parsePurl('https://registry.npmjs.org/lodash')).toBeNull();
    expect(parsePurl('')).toBeNull();
    expect(parsePurl(null)).toBeNull();
  });

  it('rejects an unknown type rather than accepting it silently', () => {
    // Accepting pkg:nmp/lodash would produce a Purl that misses every lookup
    // and looks valid, which is worse than an explicit null.
    expect(parsePurl('pkg:nmp/lodash')).toBeNull();
    expect(parsePurl('pkg:/lodash')).toBeNull();
  });

  it('rejects a missing name', () => {
    expect(parsePurl('pkg:npm/')).toBeNull();
    expect(parsePurl('pkg:npm')).toBeNull();
  });

  it('does not treat a leading @ as a version separator', () => {
    const p = parsePurl('pkg:npm/%40scope/name@1.0.0');
    expect(p!.name).toBe('name');
    expect(p!.namespace).toEqual(['@scope']);
    expect(p!.version).toBe('1.0.0');
  });

  it('survives a malformed percent-escape instead of throwing', () => {
    // One bad byte in a scraped package name must not abort a lockfile scan.
    expect(() => parsePurl('pkg:npm/bad%ZZname')).not.toThrow();
  });

  it('accepts every declared type as a type', () => {
    for (const t of PURL_TYPES) {
      expect(parsePurl(`pkg:${t}/something`)!.type).toBe(t);
    }
  });
});

describe('buildPurl', () => {
  it('sorts qualifiers for a stable string', () => {
    const a = buildPurl({ type: 'npm', name: 'x', qualifiers: { b: '2', a: '1' } });
    expect(a).toBe('pkg:npm/x?a=1&b=2');
  });

  it('drops spec-reserved qualifier keys', () => {
    // The spec reserves these; emitting them produces invalid purl.
    const s = buildPurl({ type: 'npm', name: 'x', qualifiers: { checksum: 'sha256:abc', arch: 'x64' } });
    expect(s).not.toContain('checksum');
    expect(s).toContain('arch=x64');
  });
});

describe('purlIdentity and purlBareName', () => {
  it('ignores version, so a patch bump still matches', () => {
    expect(purlIdentity('pkg:npm/lodash@4.17.20')).toBe(purlIdentity('pkg:npm/lodash@4.17.21'));
  });

  it('keeps type and namespace, so different ecosystems do not collide', () => {
    expect(purlIdentity('pkg:npm/lodash')).not.toBe(purlIdentity('pkg:cargo/lodash'));
    expect(purlIdentity('pkg:npm/%40scope/a')).not.toBe(purlIdentity('pkg:npm/b'));
  });

  it('returns null for a non-purl', () => {
    expect(purlIdentity('lodash')).toBeNull();
    expect(purlBareName('lodash')).toBeNull();
  });
});

describe('purlFromCpe', () => {
  it('maps a registry vendor to an ecosystem', () => {
    const p = purlFromCpe('cpe:2.3:a:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*');
    // canonical is not a registry name, so this is the documented null.
    expect(p).toBeNull();

    const n = purlFromCpe('cpe:2.3:a:npm:lodash:4.17.21:*:*:*:*:*:*:*');
    expect(n?.type).toBe('npm');
    expect(n?.name).toBe('lodash');
  });

  it('rejects a CPE whose vendor is a product vendor, not a registry', () => {
    // This is most of CPE. Returning null is the honest answer rather than
    // inventing an ecosystem the CPE never stated.
    expect(purlFromCpe('cpe:2.3:a:citrix:netscaler_gateway:13.0:*:*:*:*:*:*:*')).toBeNull();
  });

  it('ignores a wildcard or empty version', () => {
    expect(purlFromCpe('cpe:2.3:a:npm:lodash:*:*:*:*:*:*:*:*')?.version).toBeNull();
    expect(purlFromCpe('cpe:2.3:a:npm:lodash:-:*:*:*:*:*:*:*')?.version).toBeNull();
  });

  it('rejects non-2.3 CPE and junk', () => {
    expect(purlFromCpe('cpe:/a:npm:lodash')).toBeNull();
    expect(purlFromCpe(null)).toBeNull();
    expect(purlFromCpe('')).toBeNull();
  });
});
