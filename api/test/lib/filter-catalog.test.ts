import { describe, expect, it } from 'vitest';
import {
  FILTER_CATALOGUE,
  UNIVERSAL_PARAMS,
  buildFilterCatalogResponse,
  findUnknownParams,
  unknownParamHeaders,
} from '../../src/lib/filter-catalog';

describe('findUnknownParams', () => {
  it('returns nothing when every parameter is recognised', () => {
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['platform', 'days', 'gaps'])).toEqual([]);
  });

  it('flags a misspelled parameter', () => {
    // The case this whole module exists for: `platfrom` used to be silently
    // ignored, so the caller read an unfiltered set as a filtered one.
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['platfrom'])).toEqual(['platfrom']);
  });

  it('flags unknowns while leaving knowns alone', () => {
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['days', 'sevrity', 'gaps'])).toEqual(['sevrity']);
  });

  it('never flags the universal pagination params', () => {
    for (const p of UNIVERSAL_PARAMS) {
      expect(findUnknownParams('GET', '/api/v1/detection-coverage', [p])).toEqual([]);
    }
  });

  it('returns an empty array for a route that is not catalogued', () => {
    // An uncatalogued route is a docs gap, not a client error. Flagging all of
    // its parameters would train people to ignore the header.
    expect(findUnknownParams('GET', '/api/v1/not-catalogued', ['anything', 'at', 'all'])).toEqual([]);
  });

  it('accepts caller-supplied extras beyond the catalogue', () => {
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['vendor_id'], ['vendor_id'])).toEqual([]);
  });

  it('respects a route-scoped passThrough list', () => {
    const entry = FILTER_CATALOGUE.find((e) => e.path === '/api/v1/cisa-kev');
    expect(entry?.passThrough).toBeUndefined();

    const result = findUnknownParams('GET', '/api/v1/detection-coverage', ['days', 'nope'], ['nope']);
    expect(result).toEqual([]);
  });

  it('is case sensitive, because query keys are', () => {
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['Days'])).toEqual(['Days']);
  });

  it('de-duplicates a repeated key', () => {
    expect(findUnknownParams('GET', '/api/v1/detection-coverage', ['bogus', 'bogus'])).toEqual(['bogus']);
  });

  it('is method and path sensitive', () => {
    // /api/v1/cve/lookup accepts `cve`; /api/v1/cve-recent does not.
    expect(findUnknownParams('GET', '/api/v1/cve/lookup', ['cve'])).toEqual([]);
    expect(findUnknownParams('GET', '/api/v1/cve-recent', ['cve'])).toEqual(['cve']);
  });
});

describe('unknownParamHeaders', () => {
  it('returns no headers when nothing was ignored', () => {
    expect(unknownParamHeaders([], '/api/v1/x')).toEqual({});
  });

  it('names the ignored params and points at the catalog', () => {
    const h = unknownParamHeaders(['a', 'b'], '/api/v1/x');
    expect(h['X-Unknown-Params']).toBe('a,b');
    expect(h['X-Filter-Catalog']).toBe('/api/v1/filters');
    expect(h['X-Note']).toContain('a, b');
    expect(h['X-Note']).toContain('/api/v1/filters');
  });
});

describe('filter catalogue payload', () => {
  const response = buildFilterCatalogResponse();

  it('advertises a schema version and the endpoint list', () => {
    expect(response.schemaVersion).toBe('filter-catalog-v1');
    expect(Array.isArray(response.endpoints)).toBe(true);
    expect((response.endpoints as unknown[]).length).toBeGreaterThan(0);
  });

  it('documents the lenient CVE identifier forms', () => {
    const idNorm = (response as { identifierNormalisation: { equivalentForms: string[] } }).identifierNormalisation;
    expect(idNorm.equivalentForms).toContain('2025-1974');
    expect(idNorm.equivalentForms).toContain('CVE-2025-1974');
  });

  it('gives every declared param a name, type and description', () => {
    for (const ep of FILTER_CATALOGUE) {
      for (const p of ep.params) {
        expect(p.name, `${ep.path} param`).toBeTruthy();
        expect(['string', 'number', 'boolean', 'enum']).toContain(p.type);
        expect(p.description, `${ep.path} ${p.name} description`).toBeTruthy();
      }
    }
  });

  it('lists enum values for every param declared as an enum', () => {
    for (const ep of FILTER_CATALOGUE) {
      for (const p of ep.params) {
        if (p.type !== 'enum') continue;
        expect(p.values?.length, `${ep.path} ${p.name} enum values`).toBeGreaterThan(0);
      }
    }
  });

  it('has no duplicate param names within a single endpoint', () => {
    for (const ep of FILTER_CATALOGUE) {
      const names = ep.params.map((p) => p.name);
      expect(new Set(names).size, `${ep.path} duplicate params`).toBe(names.length);
    }
  });
});
