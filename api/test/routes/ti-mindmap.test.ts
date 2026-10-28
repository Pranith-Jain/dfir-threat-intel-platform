/**
 * Tests for the TI Mindmap Studio port: pure pipeline helpers
 * (Mermind sanitizer, tree, ordering, timeline, Navigator layer, tweet
 * parser) plus the Hono route 400 paths. No LLM calls anywhere — the
 * route's happy path is exercised in production only.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { tiMindmapRouter, normalizeTiMindmapModel } from '../../src/routes/ti-mindmap';
import {
  TIMINDMAP_HARD_BRANCH_CAP,
  buildMermaidTimeline,
  buildNavigatorLayer,
  cleanNodeText,
  navigatorFileName,
  orderTtpsByExecution,
  parseTweetResponse,
  sanitizeMermaidMindmap,
  mermaidTreeToText,
} from '../../src/lib/ti-mindmap';
import type { TtpHit } from '../../src/lib/ttp-extract';

function setup() {
  const app = new Hono<{ Bindings: Env }>();
  app.route('/api/v1', tiMindmapRouter);
  return app;
}

function mockCtx() {
  return { waitUntil: (_p: Promise<unknown>) => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
}

function req(app: ReturnType<typeof setup>, path: string, env: Env, init?: RequestInit) {
  return app.request(path, init ?? {}, env, mockCtx());
}

const env = {} as Env;

beforeEach(() => vi.restoreAllMocks());

const GOOD_MAP = `mindmap
root((YoroTrooper Espionage))
  (Origin and Attribution)
    (Kazakhstan linked)
    (Disguises origin as Azerbaijan)
  (Targets)
    (CIS government entities)
    (Embassies and NGOs)
  (TTPs)
    (Spear phishing sites)
    (Credential harvesting)`;

describe('sanitizeMermaidMindmap', () => {
  it('accepts a well-formed map and parses the tree', () => {
    const s = sanitizeMermaidMindmap(GOOD_MAP);
    expect(s.ok).toBe(true);
    expect(s.nodes).toBe(9);
    expect(s.tree?.label).toContain('YoroTrooper');
    expect(s.tree?.children.length).toBe(3);
    expect(s.text).toMatch(/^mindmap\nroot\(/);
  });

  it('strips a mermaid code fence and preamble', () => {
    const s = sanitizeMermaidMindmap(`Here is your mindmap:\n\n\`\`\`mermaid\n${GOOD_MAP}\n\`\`\`\nEnjoy!`);
    expect(s.ok).toBe(true);
    expect(s.text.startsWith('mindmap\n')).toBe(true);
    expect(s.nodes).toBe(9);
  });

  it('fails cleanly without a mindmap header', () => {
    const s = sanitizeMermaidMindmap('no diagram here at all');
    expect(s.ok).toBe(false);
    expect(s.tree).toBeNull();
  });

  it('warns above the 4-branch methodology cap', () => {
    const many = `mindmap\nroot((T))\n${['a', 'b', 'c', 'd', 'e', 'f'].map((x) => `  (branch ${x})`).join('\n')}`;
    const s = sanitizeMermaidMindmap(many);
    expect(s.ok).toBe(true);
    expect(s.tree?.children.length).toBeLessThanOrEqual(TIMINDMAP_HARD_BRANCH_CAP);
    expect(s.warnings.join('|')).toMatch('primary branches');
  });

  it('sanitises nested parentheses, emoji, and trailing dots in labels', () => {
    const s = sanitizeMermaidMindmap('mindmap\nroot((Title))\n  (Uses C2 \u{1F525} infra (doc.example.com).)');
    expect(s.ok).toBe(true);
    const label = s.tree?.children[0]?.label ?? '';
    expect(label).not.toMatch(/[()]/);
    expect(label.trimEnd()).not.toMatch(/\.$/);
  });

  it('round-trips text through the tree deterministically', () => {
    const s = sanitizeMermaidMindmap(GOOD_MAP);
    const s2 = sanitizeMermaidMindmap(s.text);
    expect(s2.text).toBe(s.text);
  });
});

describe('mermaidTreeToText', () => {
  it('emits a syntax-valid block from a tree', () => {
    const s = sanitizeMermaidMindmap(GOOD_MAP);
    expect(s.tree).not.toBeNull();
    const text = mermaidTreeToText(s.tree);
    expect(text.startsWith('mindmap\nroot(')).toBe(true);
    expect(text.split('\n').every((l) => !/\s$/.test(l))).toBe(true);
  });
});

describe('orderTtpsByExecution', () => {
  const mk = (tactic: string, id: string): TtpHit => ({
    id,
    name: id,
    tactic,
    confidence: 'medium',
    evidence: 'e',
  });
  it('sorts by kill-chain order and keeps unknowns last, stable', () => {
    const out = orderTtpsByExecution(
      [mk('Command and Control', 'T1071'), mk('Initial Access', 'T1566'), mk('Exotic', 'T9999'), mk('Impact', 'T1486')],
      ['initial access', 'impact', 'command and control']
    );
    expect(out.map((t) => t.id)).toEqual(['T1566', 'T1486', 'T1071', 'T9999']);
  });
});

describe('buildMermaidTimeline', () => {
  it('groups by tactic and cleans syntax-breaking characters', () => {
    const out = buildMermaidTimeline(
      [
        { id: 'T1566', name: 'Phishing: spear #tail', tactic: 'Initial Access', confidence: 'high', evidence: 'e' },
        { id: 'T1486', name: 'Data Encrypted', tactic: 'Impact', confidence: 'medium', evidence: 'e' },
      ],
      'Attack, TTP Execution'
    );
    expect(out.startsWith('timeline\n')).toBe(true);
    expect(out).toContain('title Attack, TTP Execution');
    expect(out).toContain('section Initial Access');
    expect(out).toContain('Phishing spear tail : T1566');
    expect(out).not.toMatch(/["';#{}]/);
  });
  it('returns empty when there are no TTPs', () => {
    expect(buildMermaidTimeline([])).toBe('');
  });
});

describe('buildNavigatorLayer', () => {
  it('dedupes ids keeping the best score and drops malformed ids', () => {
    const layer = buildNavigatorLayer({
      name: 'Test',
      ttps: [
        { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', confidence: 'low', evidence: 'first' },
        { id: 'T1566.001', name: 'Spearphishing', tactic: 'Initial Access', confidence: 'high', evidence: 'later' },
        { id: 'T99999', name: 'Bogus', tactic: 'X', confidence: 'high', evidence: 'bogus' },
        { id: 'N/A', name: 'Bogus2', tactic: 'X', confidence: 'high', evidence: 'bogus' },
      ],
    });
    const ids = layer.techniques.map((t) => t.techniqueID);
    expect(ids).toContain('T1566.001');
    expect(layer.techniques.find((t) => t.techniqueID === 'T1566.001')?.score).toBe(100);
    expect(ids).not.toContain('T99999');
    expect(ids).not.toContain('N/A');
  });
});

describe('helpers', () => {
  it('navigatorFileName slugs the title', () => {
    expect(navigatorFileName('APT 28 Targets: NATO!')).toBe('apt-28-targets-nato.navigator.json');
    expect(navigatorFileName('')).toBe('ti-mindmap.navigator.json');
  });
  it('cleanNodeText neutralises syntax glyphs', () => {
    expect(cleanNodeText('C2 (beacon) [host]')).toBe('C2 /beacon/ /host/');
    expect(cleanNodeText('Success.')).toBe('Success');
    expect(cleanNodeText('\u{1F9A0} Germs')).toBe('Germs');
  });
  it('parses a fenced tweet JSON and caps arrays', () => {
    const r = parseTweetResponse(
      'final answer:\n```json\n{"tweet_summary":"Ransomware hits hospitals.","actor":"LockBit-ish", "malware":["A","B","C","D","E","F","G","H","I"], "sectors":["health"],"headline":"H"}\n```'
    );
    expect(r.tweet_summary).toContain('Ransomware');
    expect(r.malware.length).toBeLessThanOrEqual(8);
    expect(r.headline).toBe('H');
  });
  it('falls back to plain text when JSON parsing fails', () => {
    const r = parseTweetResponse('not json at all');
    expect(r.tweet_summary).toContain('not json');
    expect(r.actor).toBeNull();
  });
  it('normalizes the model selector', () => {
    expect(normalizeTiMindmapModel('oss')).toBe('oss');
    expect(normalizeTiMindmapModel(undefined)).toBe('auto');
    expect(normalizeTiMindmapModel('auto')).toBe('auto');
  });
});

describe('routes', () => {
  it('GET /ti-mindmap/ returns the index', async () => {
    const app = setup();
    const r = await req(app, '/api/v1/ti-mindmap/', env);
    expect(r.status).toBe(200);
    const j = (await r.json()) as { artifacts?: string[] };
    expect(j.artifacts).toContain('mermaid_mindmap');
  });

  it('POST analyze rejects a request with no usable input', async () => {
    const app = setup();
    const r = await req(app, '/api/v1/ti-mindmap/analyze', env, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(400);
  });

  it('POST analyze rejects too-short text', async () => {
    const app = setup();
    const r = await req(app, '/api/v1/ti-mindmap/analyze', env, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: 'tiny' }),
    });
    expect(r.status).toBe(400);
    expect(((await r.json()) as { message?: string }).message ?? '').toMatch(/200 chars/);
  });

  it('POST assistant rejects a missing question and short text', async () => {
    const app = setup();
    const r1 = await req(app, '/api/v1/ti-mindmap/assistant', env, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: 'x'.repeat(300) }),
    });
    expect(r1.status).toBe(400);
    const r2 = await req(app, '/api/v1/ti-mindmap/assistant', env, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ question: 'What pretexts were used for phishing attempts?' }),
    });
    expect(r2.status).toBe(400);
  });
});
