import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadPromptIntelIndex,
  filterPromptIntelEntries,
  filterPromptIntelMappings,
  getPromptIntelEntry,
  normalizeIopcId,
  canonicalFrameworkName,
  translateFrameworkRef,
  promptIntelCacheStats,
  _resetPromptIntelCacheForTests,
  type PromptIntelIndex,
  type PromptIntelEntryBody,
  type PromptIntelEntrySlim,
} from './promptintel-manifest';

function mockAssets(files: Record<string, unknown>): Fetcher {
  return {
    fetch: async (req: Request) => {
      const url = new URL(req.url);
      const data = files[url.pathname];
      if (data === undefined) return new Response(null, { status: 404 });
      return new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
    },
  } as unknown as Fetcher;
}

function row(overrides: Partial<PromptIntelEntrySlim>): PromptIntelEntrySlim {
  return {
    id: 'IOPC-T1.001',
    name: 'Direct Prompt Injection',
    domain: 'T1',
    domainName: 'Instruction & Input Injection',
    summary: 'Attacker-authored instructions supplied directly in the user-controlled input channel.',
    url: 'https://promptintel.securitybreak.io/taxonomy/IOPC-T1.001/',
    maturity: 'active',
    evidence: 'mixed',
    reviewed: '2026-11-12',
    frameworks: ['OWASP Top 10 for LLM Applications', 'MITRE ATLAS'],
    mappingCount: 9,
    ...overrides,
  };
}

function body(overrides: Partial<PromptIntelEntryBody>): PromptIntelEntryBody {
  return {
    id: 'IOPC-T1.001',
    name: 'Direct Prompt Injection',
    description: 'Attacker-authored instructions supplied directly.',
    differs: 'Canonical form of registry entry IOPC-R001.',
    maturity: 'active',
    evidence: 'mixed',
    reviewed: '2026-11-12',
    statusLine: 'active, evidence: mixed, reviewed 2026-11-12.',
    mappings: [
      {
        framework: 'OWASP Top 10 for LLM Applications',
        ref: 'LLM01',
        name: 'Prompt Injection',
        relationship: 'narrower than',
      },
    ],
    url: 'https://promptintel.securitybreak.io/taxonomy/IOPC-T1.001/',
    ...overrides,
  };
}

const INDEX: PromptIntelIndex = {
  source: 'PromptIntel',
  sourceUrl: 'https://promptintel.securitybreak.io/taxonomy/',
  license: 'mirrored metadata',
  syncedAt: '2026-11-26T00:00:00.000Z',
  taxonomyVersion: '2.2.0',
  counts: { domains: 9, techniques: 2, frameworks: 6, mappings: 12 },
  frameworks: [
    { name: 'OWASP Top 10 for LLM Applications', version: '2026', url: 'https://genai.owasp.org/llm-top-10/' },
    { name: 'MITRE ATLAS', version: '2026.10', url: 'https://atlas.mitre.org/' },
  ],
  domains: [
    {
      id: 'T1',
      name: 'Instruction & Input Injection',
      description: 'Injection techniques.',
      techniques: ['IOPC-T1.001'],
    },
    {
      id: 'T5',
      name: 'Disclosure & Output Integrity',
      description: 'Disclosure techniques.',
      techniques: ['IOPC-T5.001'],
    },
  ],
  entries: [
    row({}),
    row({
      id: 'IOPC-T5.001',
      name: 'System Prompt & Configuration Disclosure',
      domain: 'T5',
      maturity: 'experimental',
      frameworks: ['MITRE ATLAS'],
      mappingCount: 3,
    }),
  ],
  mappings: [
    {
      entry: 'IOPC-T1.001',
      name: 'Direct Prompt Injection',
      domain: 'T1',
      framework: 'OWASP Top 10 for LLM Applications',
      ref: 'LLM01',
      item: 'Prompt Injection',
      relationship: 'narrower than',
    },
    {
      entry: 'IOPC-T1.001',
      name: 'Direct Prompt Injection',
      domain: 'T1',
      framework: 'MITRE ATLAS',
      ref: 'AML.T0051',
      item: 'LLM Prompt Injection',
      relationship: 'narrower than',
    },
    {
      entry: 'IOPC-T1.002',
      name: 'Indirect Prompt Injection',
      domain: 'T1',
      framework: 'OWASP Top 10 for LLM Applications',
      ref: 'LLM01',
      item: 'Prompt Injection',
      relationship: 'equivalent',
    },
    {
      entry: 'IOPC-T5.001',
      name: 'System Prompt & Configuration Disclosure',
      domain: 'T5',
      framework: 'OWASP Top 10 for LLM Applications',
      ref: 'LLM07',
      item: 'System Prompt Leakage',
      relationship: 'related',
    },
  ],
};

beforeEach(() => _resetPromptIntelCacheForTests());

describe('loadPromptIntelIndex', () => {
  it('loads and caches the mirrored taxonomy', async () => {
    const assets = mockAssets({ '/data/promptintel/index.json': INDEX });
    const first = await loadPromptIntelIndex(assets);
    expect(first.taxonomyVersion).toBe('2.2.0');
    expect(first.entries).toHaveLength(2);
    expect(promptIntelCacheStats().indexLoaded).toBe(true);
    // Second call is served from memory (no fetch).
    const second = await loadPromptIntelIndex({
      fetch: async () => {
        throw new Error('should not fetch');
      },
    } as unknown as Fetcher);
    expect(second).toBe(first);
  });

  it('names the build script when the manifest is missing', async () => {
    await expect(loadPromptIntelIndex(mockAssets({}))).rejects.toThrow(/sync-promptintel\.mjs/);
  });
});

describe('getPromptIntelEntry', () => {
  it('reads one technique body by id', async () => {
    const assets = mockAssets({ '/data/promptintel/entries/IOPC-T1.001.json': body({}) });
    const entry = await getPromptIntelEntry(assets, 'iopc-t1.001');
    expect(entry?.name).toBe('Direct Prompt Injection');
    expect(entry?.mappings[0]?.ref).toBe('LLM01');
  });

  it('rejects a non-canonical id before it reaches the asset path', async () => {
    const assets = mockAssets({});
    expect(await getPromptIntelEntry(assets, '../../etc/passwd')).toBeNull();
    expect(await getPromptIntelEntry(assets, 'IOPC-XX')).toBeNull();
  });

  it('returns null for a technique that is not mirrored', async () => {
    expect(await getPromptIntelEntry(mockAssets({}), 'IOPC-T9.999')).toBeNull();
  });
});

describe('normalizeIopcId', () => {
  it('accepts registry and technique ids', () => {
    expect(normalizeIopcId('IOPC-T1.001')).toBe('IOPC-T1.001');
    expect(normalizeIopcId(' iopc-r012 ')).toBe('IOPC-R012');
    expect(normalizeIopcId('IOPC-T10.004')).toBe('IOPC-T10.004');
  });

  it('rejects anything else', () => {
    expect(normalizeIopcId('')).toBeNull();
    expect(normalizeIopcId('CVE-2026-1234')).toBeNull();
    expect(normalizeIopcId('IOPC-T1.1')).toBeNull();
    expect(normalizeIopcId('/data/promptintel/index.json')).toBeNull();
  });
});

describe('filterPromptIntelEntries', () => {
  it('filters by domain', () => {
    expect(filterPromptIntelEntries(INDEX.entries, { domain: 't5' }).map((e) => e.id)).toEqual(['IOPC-T5.001']);
  });

  it('filters by mapped framework', () => {
    expect(
      filterPromptIntelEntries(INDEX.entries, { framework: 'OWASP Top 10 for LLM Applications' }).map((e) => e.id)
    ).toEqual(['IOPC-T1.001']);
  });

  it('filters by maturity and keyword', () => {
    expect(filterPromptIntelEntries(INDEX.entries, { maturity: 'experimental' }).map((e) => e.id)).toEqual([
      'IOPC-T5.001',
    ]);
    expect(filterPromptIntelEntries(INDEX.entries, { keyword: 'system prompt' }).map((e) => e.id)).toEqual([
      'IOPC-T5.001',
    ]);
  });

  it('honours the limit and defaults to everything', () => {
    expect(filterPromptIntelEntries(INDEX.entries, { limit: 1 })).toHaveLength(1);
    expect(filterPromptIntelEntries(INDEX.entries)).toHaveLength(2);
  });
});

describe('translateFrameworkRef', () => {
  it('inverts a mapping row into the IoPC techniques behind it', () => {
    const hit = translateFrameworkRef(INDEX, 'owasp top 10 for llm applications', 'llm01');
    expect(hit?.item).toBe('Prompt Injection');
    expect(hit?.entries.map((e) => e.id)).toEqual(['IOPC-T1.001', 'IOPC-T1.002']);
  });

  it('returns null when nothing maps', () => {
    expect(translateFrameworkRef(INDEX, 'MITRE ATLAS', 'AML.T9999')).toBeNull();
    expect(translateFrameworkRef({ ...INDEX, mappings: [] }, 'OWASP Top 10 for LLM Applications', 'LLM01')).toBeNull();
    expect(translateFrameworkRef(INDEX, '', 'LLM01')).toBeNull();
  });

  it('accepts upstream framework ids as well as the mirror names', () => {
    expect(translateFrameworkRef(INDEX, 'OWASP_LLM', 'LLM01')?.entries).toHaveLength(2);
    expect(translateFrameworkRef(INDEX, 'mitre_atlas', 'aml.t0051')?.entries).toHaveLength(1);
    expect(canonicalFrameworkName('OWASP_LLM')).toBe('owasp top 10 for llm applications');
  });
});

describe('filterPromptIntelMappings', () => {
  it('filters the flat table by framework, ref and relationship', () => {
    expect(filterPromptIntelMappings(INDEX, { framework: 'MITRE ATLAS' }).map((r) => r.ref)).toEqual(['AML.T0051']);
    expect(filterPromptIntelMappings(INDEX, { relationship: 'equivalent' }).map((r) => r.entry)).toEqual([
      'IOPC-T1.002',
    ]);
    expect(filterPromptIntelMappings(INDEX, { entry: 'iopc-t1.001' })).toHaveLength(2);
  });
});
