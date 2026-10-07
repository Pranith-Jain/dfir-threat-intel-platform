/**
 * Tests for the AI Security hub manifest helpers (filter + cache reset).
 */
import { describe, expect, it } from 'vitest';
import {
  filterAdvisories,
  filterIncidentReports,
  filterMatrixTools,
  filterResearch,
  filterVulns,
  _resetAiSecurityCacheForTests,
  type AdvisoriesIndex,
  type IncidentsIndex,
  type MatrixIndex,
  type ResearchIndex,
  type VulnsIndex,
} from '../../api/src/lib/ai-security-manifest';

const MATRIX: MatrixIndex = {
  updatedAt: '2026-09-18T00:00:00.000Z',
  total: 3,
  byCategory: { agent: 1, scanner: 2 },
  tools: [
    {
      slug: 'a__x',
      repo: 'a/x',
      category: 'agent',
      scope: ['webapp'],
      stars: 100,
      description: 'pentest swarm',
      homepage: null,
      added: null,
      checkedAt: null,
      pushedAt: null,
      daysIdle: 0,
      archived: false,
      license: 'MIT',
    },
    {
      slug: 'b__y',
      repo: 'b/y',
      category: 'scanner',
      scope: ['llm'],
      stars: 5000,
      description: 'llm vuln scanner',
      homepage: null,
      added: null,
      checkedAt: null,
      pushedAt: null,
      daysIdle: 1,
      archived: false,
      license: 'Apache-2.0',
    },
    {
      slug: 'c__z',
      repo: 'c/z',
      category: 'scanner',
      scope: ['agentic'],
      stars: 50,
      description: 'old tool',
      homepage: null,
      added: null,
      checkedAt: null,
      pushedAt: null,
      daysIdle: 90,
      archived: true,
      license: null,
    },
  ],
};

const INCIDENTS: IncidentsIndex = {
  updatedAt: '2026-09-18T00:00:00.000Z',
  source: 'https://incidentdatabase.ai/rss.xml',
  total: 2,
  reports: [
    {
      id: '1',
      guid: 'g1',
      title: 'Flock camera misuse',
      link: 'https://example.invalid/1',
      pubDate: '2026-09-16T00:00:00.000Z',
      citeId: '1689',
      reportNum: '7954',
    },
    {
      id: '2',
      guid: 'g2',
      title: 'Agentic data breach reported',
      link: 'https://example.invalid/2',
      pubDate: '2026-09-15T00:00:00.000Z',
      citeId: '1693',
      reportNum: '7971',
    },
  ],
};

describe('ai-security manifest filters', () => {
  it('filters matrix tools by category + query + minStars + limit', () => {
    _resetAiSecurityCacheForTests();
    expect(filterMatrixTools(MATRIX, { category: 'scanner' }).map((t) => t.repo)).toEqual(['b/y', 'c/z']);
    expect(filterMatrixTools(MATRIX, { q: 'swarm' }).map((t) => t.repo)).toEqual(['a/x']);
    expect(filterMatrixTools(MATRIX, { minStars: 1000 }).map((t) => t.repo)).toEqual(['b/y']);
    expect(filterMatrixTools(MATRIX, { limit: 1 })).toHaveLength(1);
  });

  it('filters incident reports by query + cite + limit', () => {
    expect(filterIncidentReports(INCIDENTS, { q: 'flock' }).map((r) => r.id)).toEqual(['1']);
    expect(filterIncidentReports(INCIDENTS, { citeId: '1693' }).map((r) => r.id)).toEqual(['2']);
    expect(filterIncidentReports(INCIDENTS, { limit: 1 })).toHaveLength(1);
  });
});

const VULNS: VulnsIndex = {
  updatedAt: '2026-09-18T00:00:00.000Z',
  total: 3,
  kev: 1,
  vulns: [
    {
      id: 'CVE-2026-42271',
      title: 'LiteLLM RCE chain',
      sources: ['euvd', 'nvd', 'osv', 'kev'],
      severity: '8.7',
      cvssBase: 8.7,
      epss: 0.8359,
      kev: true,
      kevSources: ['cisa_kev'],
      published: '2026-06-08',
      link: 'https://example.invalid/1',
      aliases: [],
      packages: ['PyPI:litellm'],
      vendor: 'berriai',
      product: 'LiteLLM',
    },
    {
      id: 'CVE-2026-33626',
      title: 'LMDeploy SSRF',
      sources: ['nvd'],
      severity: '7.5',
      cvssBase: 7.5,
      epss: 0.5,
      kev: false,
      kevSources: [],
      published: '2026-04-21',
      link: 'https://example.invalid/2',
      aliases: [],
      packages: [],
      vendor: null,
      product: 'LMDeploy',
    },
    {
      id: 'GHSA-xxxx-yyyy-zzzz',
      title: 'libheif heap overflow',
      sources: ['euvd'],
      severity: '9.8',
      cvssBase: 9.8,
      epss: null,
      kev: false,
      kevSources: [],
      published: '2026-09-01',
      link: 'https://example.invalid/3',
      aliases: [],
      packages: [],
      vendor: null,
      product: 'libheif',
    },
  ],
};

const ADVISORIES: AdvisoriesIndex = {
  updatedAt: '2026-09-18T00:00:00.000Z',
  total: 2,
  bySource: { garak: 1, exploitdb: 1 },
  items: [
    {
      id: 'a1',
      title: 'garak v0.12 release',
      link: 'https://example.invalid/g',
      updated: '2026-09-17',
      source: 'garak',
      kind: 'release',
      cves: [],
      description: '',
    },
    {
      id: 'a2',
      title: 'LLM inference SSRF exploit',
      link: 'https://example.invalid/e',
      updated: '2026-09-16',
      source: 'exploitdb',
      kind: 'exploit',
      cves: ['CVE-2026-33626'],
      description: '',
    },
  ],
};

const RESEARCH: ResearchIndex = {
  updatedAt: '2026-09-18T00:00:00.000Z',
  total: 2,
  bySource: { hacktron: 1, unit42: 1 },
  items: [
    {
      id: 'r1',
      title: 'HEIF Heist: image parsers to RCE',
      link: 'https://example.invalid/h',
      pubDate: '2026-09-15',
      source: 'hacktron',
      description: '',
    },
    {
      id: 'r2',
      title: 'Cloud threat report',
      link: 'https://example.invalid/u',
      pubDate: '2026-09-14',
      source: 'unit42',
      description: '',
    },
  ],
};

describe('ai-security tier-1 filters', () => {
  it('filters vulns by kev + epss + source + query', () => {
    expect(filterVulns(VULNS, { kevOnly: true }).map((v) => v.id)).toEqual(['CVE-2026-42271']);
    expect(filterVulns(VULNS, { minEpss: 0.8 }).map((v) => v.id)).toEqual(['CVE-2026-42271']);
    expect(filterVulns(VULNS, { source: 'osv' }).map((v) => v.id)).toEqual(['CVE-2026-42271']);
    expect(filterVulns(VULNS, { q: 'libheif' }).map((v) => v.id)).toEqual(['GHSA-xxxx-yyyy-zzzz']);
    expect(filterVulns(VULNS, { limit: 2 })).toHaveLength(2);
  });

  it('filters advisories by source + kind + query', () => {
    expect(filterAdvisories(ADVISORIES, { source: 'garak' }).map((a) => a.id)).toEqual(['a1']);
    expect(filterAdvisories(ADVISORIES, { kind: 'exploit' }).map((a) => a.id)).toEqual(['a2']);
    expect(filterAdvisories(ADVISORIES, { q: '33626' }).map((a) => a.id)).toEqual(['a2']);
  });

  it('filters research by source + query', () => {
    expect(filterResearch(RESEARCH, { source: 'hacktron' }).map((r) => r.id)).toEqual(['r1']);
    expect(filterResearch(RESEARCH, { q: 'heist' }).map((r) => r.id)).toEqual(['r1']);
  });
});
