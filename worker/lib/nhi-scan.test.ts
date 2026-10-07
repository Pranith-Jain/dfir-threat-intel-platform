/**
 * Port of the upstream nhi-scan pytest suite (github.com/rpmsft9/nhi-scan,
 * MIT) to vitest: tiering rules, OWASP checks, scan orchestration, ingest.
 */
import { describe, expect, it } from 'vitest';
// The worker copy of this module was a byte-identical duplicate that nothing
// imported — production has always used the api/src one. Point the suite at the
// live module so it stops passing against dead code.
import {
  Nhi,
  assess,
  parseFleet,
  runChecks,
  scan,
  reportToJson,
  reportToMarkdown,
  type NhiRecord,
} from '../../api/src/lib/nhi-scan';

function nhi(kw: Partial<NhiRecord> & { id?: string; name?: string } = {}): Nhi {
  const base: NhiRecord = { id: 'x', name: 'x', owner: 'o@example' };
  return new Nhi({ ...base, ...kw });
}

function codes(n: Nhi): Set<string> {
  return new Set(runChecks(n).map((f) => f.owaspId));
}

/** Mirrors examples/sample-inventory.json from the upstream repo. */
const SAMPLE_INVENTORY = [
  {
    id: 'svc-payments-prod',
    name: 'payments-batch-runner',
    type: 'service_account',
    owner: 'payments-platform@bank.example',
    environment: 'prod',
    privilege: 'admin',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 410,
    last_used_days: 1,
    exposure: 'internal',
    scopes: ['payments:*'],
  },
  {
    id: 'key-legacy-etl',
    name: 'legacy-etl-api-key',
    type: 'api_key',
    owner: null,
    environment: 'prod',
    privilege: 'privileged',
    credential: 'api_key',
    secret_storage: 'plaintext',
    last_rotated_days: null,
    last_used_days: 220,
    exposure: 'internet',
    scopes: ['data:read', 'data:write'],
  },
  {
    id: 'agent-collections',
    name: 'collections-ai-agent',
    type: 'ai_agent',
    owner: 'cx-automation@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'env',
    last_rotated_days: 30,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['accounts:read', 'accounts:update', 'ledger:*'],
    autonomous: true,
  },
  {
    id: 'sp-analytics-vendor',
    name: 'analytics-vendor-connector',
    type: 'service_principal',
    owner: 'data-eng@bank.example',
    environment: 'prod',
    privilege: 'scoped',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 45,
    last_used_days: 3,
    exposure: 'external_partner',
    scopes: ['reports:read'],
    third_party: true,
  },
  {
    id: 'ci-deploy-token',
    name: 'github-actions-deployer',
    type: 'ci_cd_token',
    owner: 'devsecops@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'vault',
    last_rotated_days: 15,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['deploy:prod', 'deploy:nonprod'],
    shared_across_env: true,
    used_by: ['web-app', 'batch', 'mobile-bff'],
  },
  {
    id: 'wl-fraud-scoring',
    name: 'fraud-scoring-workload',
    type: 'workload_identity',
    owner: 'fraud-ml@bank.example',
    environment: 'prod',
    privilege: 'scoped',
    credential: 'federated',
    secret_storage: 'none',
    last_rotated_days: null,
    last_used_days: 0,
    exposure: 'internal',
    scopes: ['features:read'],
  },
  {
    id: 'pat-oncall-shared',
    name: 'oncall-shared-pat',
    type: 'pat',
    owner: 'sre@bank.example',
    environment: 'prod',
    privilege: 'privileged',
    credential: 'static_secret',
    secret_storage: 'env',
    last_rotated_days: 200,
    last_used_days: 2,
    exposure: 'internal',
    scopes: ['repo', 'admin:org'],
    human_used: true,
  },
  {
    id: 'hook-sandbox-test',
    name: 'sandbox-webhook',
    type: 'webhook',
    owner: 'qa@bank.example',
    environment: 'sandbox',
    privilege: 'read_only',
    credential: 'short_lived_token',
    secret_storage: 'none',
    last_rotated_days: 5,
    last_used_days: 400,
    exposure: 'internal',
    scopes: ['events:read'],
  },
];

// ── Tiering (port of tests/test_tiering.py) ────────────────────────────────

describe('tiering', () => {
  it('baseline identity is tier 4', () => {
    const n = nhi({
      type: 'workload_identity',
      environment: 'sandbox',
      privilege: 'read_only',
      credential: 'federated',
    });
    expect(assess(n).tier).toBe(4);
  });

  it('admin + static secret is critical (tier 1)', () => {
    const n = nhi({ privilege: 'admin', credential: 'static_secret' });
    const res = assess(n);
    expect(res.tier).toBe(1);
    expect(res.reasons.some((r) => r.ruleId === 'ADMIN_STATIC_SECRET')).toBe(true);
  });

  it('privileged orphan is critical (tier 1)', () => {
    const n = nhi({ owner: null, privilege: 'privileged', credential: 'federated' });
    expect(assess(n).tier).toBe(1);
  });

  it('autonomous privileged agent is critical (tier 1)', () => {
    const n = nhi({
      type: 'ai_agent',
      autonomous: true,
      privilege: 'privileged',
      credential: 'federated',
    });
    expect(assess(n).tier).toBe(1);
  });

  it('internet-exposed privileged identity is critical (tier 1)', () => {
    const n = nhi({ exposure: 'internet', privilege: 'privileged', credential: 'federated' });
    expect(assess(n).tier).toBe(1);
  });

  it('autonomous scoped agent (non-prod) is high (tier 2)', () => {
    const n = nhi({
      type: 'ai_agent',
      autonomous: true,
      privilege: 'scoped',
      credential: 'federated',
      environment: 'nonprod',
    });
    expect(assess(n).tier).toBe(2);
  });

  it('tier is the most severe floor', () => {
    // prod (tier 3) + admin (tier 2 via OVERPRIVILEGED, not ADMIN_STATIC_SECRET) -> tier 2
    const n = nhi({ environment: 'prod', privilege: 'admin', credential: 'federated' });
    expect(assess(n).tier).toBe(2);
  });

  it('assessment is reproducible (pure function)', () => {
    const n = nhi({ privilege: 'admin', credential: 'static_secret' });
    const a = assess(n);
    expect(a.tier).toBe(assess(n).tier);
    expect(a.reasons).toEqual(assess(n).reasons);
  });

  it('reasons are sorted most-severe first', () => {
    const n = nhi({ privilege: 'admin', credential: 'static_secret', environment: 'prod' });
    const floors = assess(n).reasons.map((r) => r.floor);
    expect(floors).toEqual([...floors].sort((x, y) => x - y));
  });
});

// ── Checks (port of tests/test_checks.py) ───────────────────────────────────

describe('OWASP NHI Top 10 checks', () => {
  it('plaintext secret is critical leakage (NHI2)', () => {
    const n = nhi({ credential: 'static_secret', secret_storage: 'plaintext' });
    const leak = runChecks(n).find((f) => f.owaspId === 'NHI2:2025');
    expect(leak?.severity).toBe('critical');
  });

  it('long-lived secret is flagged (NHI7)', () => {
    const n = nhi({ credential: 'api_key', secret_storage: 'vault', last_rotated_days: null });
    expect(codes(n).has('NHI7:2025')).toBe(true);
  });

  it('recently rotated secret is not long-lived (NHI7)', () => {
    const n = nhi({ credential: 'api_key', secret_storage: 'vault', last_rotated_days: 10 });
    expect(codes(n).has('NHI7:2025')).toBe(false);
  });

  it('admin privilege is overprivileged (NHI5)', () => {
    expect(codes(nhi({ privilege: 'admin' })).has('NHI5:2025')).toBe(true);
  });

  it('wildcard scope is overprivileged (NHI5)', () => {
    expect(codes(nhi({ scopes: ['ledger:*'] })).has('NHI5:2025')).toBe(true);
  });

  it('internet exposure is a deployment-config finding (NHI6)', () => {
    expect(codes(nhi({ exposure: 'internet' })).has('NHI6:2025')).toBe(true);
  });

  it('stale identity is an offboarding finding (NHI1)', () => {
    expect(codes(nhi({ last_used_days: 365 })).has('NHI1:2025')).toBe(true);
  });

  it('shared across environments is flagged (NHI8)', () => {
    expect(codes(nhi({ shared_across_env: true })).has('NHI8:2025')).toBe(true);
  });

  it('reuse across workloads is flagged (NHI9)', () => {
    expect(codes(nhi({ used_by: ['a', 'b'] })).has('NHI9:2025')).toBe(true);
  });

  it('human use is flagged (NHI10)', () => {
    expect(codes(nhi({ human_used: true })).has('NHI10:2025')).toBe(true);
  });

  it('third-party identity is flagged (NHI3)', () => {
    expect(codes(nhi({ third_party: true })).has('NHI3:2025')).toBe(true);
  });

  it('clean identity has no findings', () => {
    const n = nhi({
      type: 'workload_identity',
      environment: 'prod',
      privilege: 'scoped',
      credential: 'federated',
      secret_storage: 'none',
      last_used_days: 1,
      scopes: ['features:read'],
    });
    expect(runChecks(n)).toEqual([]);
  });

  it('findings are sorted by severity weight', () => {
    const n = nhi({
      credential: 'static_secret',
      secret_storage: 'plaintext',
      privilege: 'admin',
      exposure: 'internet',
      last_rotated_days: null,
    });
    const weights = runChecks(n).map((f) => f.severity);
    expect(weights).toEqual([...weights].sort((a, b) => weight(b) - weight(a)));
  });
});

function weight(sev: string): number {
  return { info: 1, low: 2, medium: 4, high: 8, critical: 12 }[sev] ?? 0;
}

// ── Scan + report (port of tests/test_scan.py) ───────────────────────────────

describe('scan + report', () => {
  function result() {
    return scan(parseFleet(SAMPLE_INVENTORY));
  }

  it('example loads all 8 identities', () => {
    expect(result().total).toBe(8);
  });

  it('example has critical (tier 1) and sums to 8', () => {
    const counts = result().tierCounts;
    expect(counts[1]).toBeGreaterThanOrEqual(1);
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(8);
  });

  it('example detects the single orphaned identity', () => {
    expect(result().orphaned).toBe(1);
  });

  it('byRisk is descending risk score', () => {
    const scores = result().byRisk.map((a) => a.riskScore);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
  });

  it('highest-risk identity is a crown jewel (tier 1)', () => {
    expect(result().byRisk[0]?.tier.tier).toBe(1);
  });

  it('owasp counts are present and prefixed with NHI', () => {
    const counts = result().owaspCounts;
    expect(Object.keys(counts).length).toBeGreaterThan(0);
    for (const code of Object.keys(counts)) {
      expect(code.startsWith('NHI')).toBe(true);
    }
  });

  it('markdown report renders', () => {
    const md = reportToMarkdown(result());
    expect(md).toContain('# Non-Human Identity Risk Report');
    expect(md).toContain('OWASP NHI Top 10');
  });

  it('json report has the expected shape', () => {
    const data = reportToJson(result());
    expect(data.summary.total_identities).toBe(8);
    expect(data.identities.length).toBe(8);
    expect('tier' in (data.identities[0] ?? {})).toBe(true);
  });
});

// ── Ingest (port of tests/test_ingest.py) ─────────────────────────────────────

describe('ingest', () => {
  it('partial record gets safe defaults', () => {
    const n = parseFleet([{ id: 'a', name: 'a' }]).identities[0]!;
    expect(n.type).toBe('service_account');
    expect(n.environment).toBe('prod');
    expect(n.privilege).toBe('scoped');
    expect(n.isOrphaned).toBe(true); // no owner supplied
  });

  it('unknown enum value falls back to safe default', () => {
    const n = parseFleet([{ id: 'a', name: 'a', privilege: 'wizard' }]).identities[0]!;
    expect(n.privilege).toBe('scoped');
  });

  it('scopes string is coerced to a list', () => {
    const n = parseFleet([{ id: 'a', name: 'a', scopes: 'repo:*' }]).identities[0]!;
    expect(n.scopes).toEqual(['repo:*']);
    expect(n.hasWildcardScope).toBe(true);
  });

  it('accepts an object with an identities key', () => {
    expect(parseFleet({ identities: [{ id: 'a', name: 'a' }] }).size).toBe(1);
  });

  it('federated credential is not static', () => {
    const n = parseFleet([{ id: 'a', name: 'a', credential: 'federated' }]).identities[0]!;
    expect(n.credential).toBe('federated');
    expect(n.hasStaticSecret).toBe(false);
  });

  it('rejects non-list, non-identities input', () => {
    expect(() => parseFleet({ notAnInventory: true })).toThrow();
  });
});
