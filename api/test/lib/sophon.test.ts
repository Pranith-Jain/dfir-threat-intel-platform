import { describe, it, expect } from 'vitest';
import {
  SOPHON_PROFILES,
  SOPHON_PROFILE_IDS,
  buildSophonContext,
  filterSophonToolCalls,
  getSophonProfile,
  parseMissionScope,
  sophonLoop,
  suggestSophonProfile,
} from '../../src/lib/agent/sophon';
import type { AgentToolCall } from '../../src/lib/agent/types';

const call = (tool: string, args: Record<string, unknown>): AgentToolCall => ({ tool, args, reasoning: 'test' });

describe('task profiles', () => {
  it('exposes ten original method profiles, not upstream prompts', () => {
    expect(SOPHON_PROFILE_IDS).toHaveLength(10);
    for (const p of Object.values(SOPHON_PROFILES)) {
      expect(p.id).toBeTruthy();
      expect(p.methodHint.length).toBeGreaterThan(20);
      expect(p.specialists.length).toBeGreaterThan(0);
      expect(p.description).not.toMatch(/[一-龥]/); // no vendored Chinese prose
    }
  });

  it('resolves ids, labels and aliases', () => {
    expect(getSophonProfile('java-code-audit')?.id).toBe('java-code-audit');
    expect(getSophonProfile(' Java Source Review ')?.id).toBe('java-code-audit');
    expect(getSophonProfile('nope')).toBeNull();
    expect(getSophonProfile(null)).toBeNull();
  });

  it('suggests a profile deterministically from the query', () => {
    expect(suggestSophonProfile('review CVE-2026-1 in a Spring app')).toBe('java-code-audit');
    expect(suggestSophonProfile('check this APK')).toBe('mobile-reverse');
    expect(suggestSophonProfile('scan example.com')).toBe('web-pentest');
    expect(suggestSophonProfile('anything else')).toBe('default');
  });
});

describe('mission scope', () => {
  it('parses domains, IPs, CIDRs and wildcard suffixes', () => {
    const scope = parseMissionScope('Authorized: example.com, *.corp.test, 10.0.0.0/8, 192.168.1.5');
    expect(scope.targets).toContain('example.com');
    expect(scope.targets).toContain('192.168.1.5');
    expect(scope.suffixes).toContain('.corp.test');
    expect(scope.networks).toContain('10.0.0.0/8');
  });

  it('blocks an out-of-scope host but keeps CVE-only intel calls', () => {
    const scope = parseMissionScope('Authorized: example.com, 10.0.0.0/8');
    const calls = [
      call('lookup_domain', { domain: 'evil.test' }),
      call('lookup_domain', { domain: 'sub.example.com' }),
      call('lookup_ip', { ip: '10.4.5.6' }),
      call('lookup_cve', { cve: 'CVE-2026-1234' }),
      call('check_ioc', { value: 'unknown-value-that-is-not-a-host' }),
    ];
    const kept = filterSophonToolCalls(calls, scope);
    expect(kept.map((c) => c.tool)).toEqual(['lookup_domain', 'lookup_ip', 'lookup_cve', 'check_ioc']);
    expect(kept[0]!.args.domain).toBe('sub.example.com');
  });

  it('checks URL-shaped arguments and wildcard suffixes', () => {
    const scope = parseMissionScope('*.corp.test');
    const kept = filterSophonToolCalls(
      [
        call('analyze_url', { url: 'https://portal.corp.test/login' }),
        call('analyze_url', { url: 'https://elsewhere.io' }),
      ],
      scope
    );
    expect(kept).toHaveLength(1);
    expect(String(kept[0]!.args.url)).toContain('corp.test');
  });

  it('is a no-op without explicit targets', () => {
    const calls = [call('lookup_domain', { domain: 'anything.test' })];
    expect(filterSophonToolCalls(calls, parseMissionScope(''))).toEqual(calls);
  });
});

describe('sophon context', () => {
  it('states the scope, read-only boundary and evidence standard', () => {
    const ctx = buildSophonContext(SOPHON_PROFILES['web-pentest'], parseMissionScope('example.com'));
    expect(ctx).toContain('Authorized scope: example.com');
    expect(ctx).toContain('no exploitation');
    expect(ctx).toContain('cite the tool result');
    expect(ctx).toContain(SOPHON_PROFILES['web-pentest'].methodHint);
  });
});

describe('sophon loop', () => {
  const state = (over: Partial<Parameters<typeof sophonLoop.evaluateExit>[0]> = {}) => ({
    stepNum: 1,
    maxSteps: 6,
    okResults: 0,
    evidenceCandidates: 0,
    allCallsBlocked: false,
    ...over,
  });

  it('stops first when every proposed target was out of scope', () => {
    expect(sophonLoop.evaluateExit(state({ allCallsBlocked: true, stepNum: 6, okResults: 9 }))?.name).toBe(
      'scope-exhausted'
    );
  });

  it('exits on corroborated evidence before the step ceiling', () => {
    expect(sophonLoop.evaluateExit(state({ okResults: 3, evidenceCandidates: 2 }))?.name).toBe('enough-evidence');
  });

  it('falls back to the step ceiling and otherwise continues', () => {
    expect(sophonLoop.evaluateExit(state({ stepNum: 6 }))?.name).toBe('max-steps');
    expect(sophonLoop.evaluateExit(state())).toBeNull();
    expect(sophonLoop.maxIterations(state())).toBe(6);
  });
});
