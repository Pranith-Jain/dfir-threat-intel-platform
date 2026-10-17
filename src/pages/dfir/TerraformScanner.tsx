import { useMemo, useState } from 'react';
import { useDebounce } from '../../hooks/useDebounce';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * Terraform / IaC Plan Scanner - 100% client-side.
 *
 * Paste `terraform show -json <planfile>` (or `terraform plan -json`
 * piped, or `terraform show -json` of state). Planned resource
 * attributes are statically checked for the misconfigurations that
 * become cloud incidents - public S3 / RDS, security groups open to the
 * world, unencrypted storage, IMDSv1, wildcard IAM, public resource
 * policies, and hardcoded secrets. Nothing leaves your browser.
 */

interface Finding {
  sev: Sev;
  title: string;
  detail: string;
  where: string;
  fix: string;
}

interface Analysis {
  error?: string;
  resources: number;
  findings: Finding[];
}

const SEV_ORDER: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEV_STYLE: Record<Sev, { text: string; chip: string; Icon: typeof ShieldAlert }> = {
  critical: {
    text: 'text-rose-700 dark:text-rose-300',
    chip: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    Icon: ShieldX,
  },
  high: {
    text: 'text-rose-600 dark:text-rose-400',
    chip: 'border-rose-500/30 bg-rose-500/5 text-rose-600 dark:text-rose-400',
    Icon: ShieldAlert,
  },
  medium: {
    text: 'text-amber-700 dark:text-amber-400',
    chip: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400',
    Icon: AlertTriangle,
  },
  low: {
    text: 'text-sky-700 dark:text-sky-400',
    chip: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400',
    Icon: Info,
  },
  info: {
    text: 'text-muted',
    chip: 'border-slate-400/30 bg-slate-400/10 text-muted',
    Icon: Info,
  },
};

interface Res {
  type: string;
  address: string;
  values: Record<string, unknown>;
  actions: string[];
}

const WORLD = (v: unknown) => Array.isArray(v) && (v as string[]).some((c) => c === '0.0.0.0/0' || c === '::/0');

const PORT_SEV: Record<number, Sev> = {
  22: 'critical',
  23: 'critical',
  3389: 'critical',
  3306: 'critical',
  5432: 'critical',
  1433: 'critical',
  6379: 'critical',
  27017: 'critical',
  9200: 'critical',
  5985: 'critical',
  445: 'critical',
  2375: 'critical',
  6443: 'critical',
};

function asArr<T>(x: unknown): T[] {
  if (x == null) return [];
  return (Array.isArray(x) ? x : [x]) as T[];
}

/** Pull resources from any terraform-json shape. */
function collect(doc: Record<string, unknown>): Res[] {
  const out: Res[] = [];

  // `terraform show -json <plan>` → resource_changes[]
  if (Array.isArray(doc.resource_changes)) {
    for (const rc of doc.resource_changes as Record<string, unknown>[]) {
      const change = (rc.change ?? {}) as Record<string, unknown>;
      out.push({
        type: String(rc.type ?? ''),
        address: String(rc.address ?? rc.name ?? ''),
        values: (change.after as Record<string, unknown>) ?? {},
        actions: asArr<string>(change.actions),
      });
    }
    return out;
  }

  // `terraform show -json` of state / planned_values → recurse modules
  const walk = (mod: Record<string, unknown> | undefined) => {
    if (!mod) return;
    for (const r of asArr<Record<string, unknown>>(mod.resources)) {
      out.push({
        type: String(r.type ?? ''),
        address: String(r.address ?? r.name ?? ''),
        values: (r.values as Record<string, unknown>) ?? {},
        actions: ['create'],
      });
    }
    for (const cm of asArr<Record<string, unknown>>(mod.child_modules)) walk(cm);
  };
  const pv = (doc.planned_values ?? doc.values) as Record<string, unknown> | undefined;
  if (pv?.root_module) {
    walk(pv.root_module as Record<string, unknown>);
    return out;
  }

  // Raw array of resources
  if (Array.isArray(doc)) {
    for (const r of doc as Record<string, unknown>[]) {
      out.push({
        type: String(r.type ?? ''),
        address: String(r.address ?? r.name ?? ''),
        values: (r.values ?? r.after ?? r) as Record<string, unknown>,
        actions: ['create'],
      });
    }
  }
  return out;
}

/** Light IAM/resource-policy check on a stringified or object policy. */
function policyIssues(policy: unknown): string[] {
  let doc: Record<string, unknown>;
  try {
    doc = typeof policy === 'string' ? JSON.parse(policy) : (policy as Record<string, unknown>);
  } catch (_catchErr) {
    console.error('policyIssues failed:', errMessage(_catchErr));
    return [];
  }
  if (!doc || typeof doc !== 'object') return [];
  const stmts = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  const issues: string[] = [];
  for (const s of stmts as Record<string, unknown>[]) {
    if (String(s.Effect) !== 'Allow') continue;
    const act = asArr<string>(s.Action).map(String);
    const res = asArr<string>(s.Resource).map(String);
    if (act.includes('*') && res.includes('*')) issues.push('Action "*" on Resource "*" (full admin)');
    else if (act.includes('*')) issues.push('wildcard Action "*"');
    const pr = s.Principal;
    const anon =
      pr === '*' ||
      (pr &&
        typeof pr === 'object' &&
        Object.values(pr as object).some((v) => v === '*' || (Array.isArray(v) && v.includes('*'))));
    if (anon) issues.push('public Principal "*"');
  }
  return issues;
}

const SECRETY = /(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)/i;

function analyzeRes(r: Res, findings: Finding[]): void {
  const v = r.values;
  const where = r.address || r.type;
  const t = r.type;

  // Destructive change to stateful infra
  if (
    r.actions.includes('delete') &&
    /aws_(db_instance|rds_cluster|s3_bucket|dynamodb_table|ebs_volume|efs_file_system)/.test(t)
  ) {
    findings.push({
      sev: 'medium',
      title: `Destructive change: ${r.actions.join('+')} ${t}`,
      detail: 'The plan destroys a stateful resource - confirm data is backed up / this is intentional.',
      where,
      fix: 'Add prevent_destroy lifecycle or verify the migration plan before apply.',
    });
  }

  // S3 public access block
  if (t === 'aws_s3_bucket_public_access_block') {
    const offs = ['block_public_acls', 'ignore_public_acls', 'block_public_policy', 'restrict_public_buckets'].filter(
      (k) => v[k] === false
    );
    if (offs.length > 0)
      findings.push({
        sev: 'high',
        title: 'S3 Block Public Access weakened',
        detail: `Disabled: ${offs.join(', ')}. The bucket can become public via ACL/policy.`,
        where,
        fix: 'Set all four block-public settings to true unless the bucket is intentionally a public website.',
      });
  }
  if (t === 'aws_s3_bucket_acl' && /public-read/.test(String(v.acl ?? ''))) {
    findings.push({
      sev: 'critical',
      title: `S3 ACL "${String(v.acl)}"`,
      detail: 'Canned ACL grants public read/write to bucket objects.',
      where,
      fix: 'Use private ACL + CloudFront/OAC for public delivery.',
    });
  }
  if (
    (t === 'aws_s3_bucket_policy' ||
      t === 'aws_sqs_queue_policy' ||
      t === 'aws_sns_topic_policy' ||
      t === 'aws_lambda_permission') &&
    v.policy
  ) {
    for (const i of policyIssues(v.policy))
      findings.push({
        sev: 'critical',
        title: `Public/over-broad resource policy (${i})`,
        detail: `${t} attaches a policy with ${i} - anonymous access to the resource.`,
        where,
        fix: 'Scope Principal to specific accounts/ARNs; never "*" without a strict Condition.',
      });
  }

  // Security groups
  if (t === 'aws_security_group') {
    for (const ing of asArr<Record<string, unknown>>(v.ingress)) {
      if (WORLD(ing.cidr_blocks) || WORLD(ing.ipv6_cidr_blocks)) {
        const from = Number(ing.from_port ?? 0);
        const to = Number(ing.to_port ?? 65535);
        const allPorts = from <= 0 && to >= 65535;
        const hit = Object.keys(PORT_SEV)
          .map(Number)
          .find((p) => p >= from && p <= to);
        findings.push({
          sev: allPorts ? 'critical' : hit ? PORT_SEV[hit]! : 'medium',
          title: allPorts
            ? 'Security group: ALL ports open to 0.0.0.0/0'
            : `Security group ingress ${from}-${to} open to 0.0.0.0/0`,
          detail: allPorts
            ? 'Every port reachable from the internet.'
            : `Inbound ${from}-${to} from anywhere${hit ? ` (covers sensitive port ${hit})` : ''}.`,
          where,
          fix: 'Restrict cidr_blocks to specific ranges / SG references; open only required ports.',
        });
      }
    }
  }
  if (
    (t === 'aws_security_group_rule' || t === 'aws_vpc_security_group_ingress_rule') &&
    String(v.type ?? 'ingress') === 'ingress'
  ) {
    const cidr = v.cidr_ipv4 ?? v.cidr_blocks;
    if (WORLD(Array.isArray(cidr) ? cidr : [cidr]) || cidr === '0.0.0.0/0') {
      const from = Number(v.from_port ?? 0);
      findings.push({
        sev: PORT_SEV[from] ?? 'medium',
        title: `SG rule open to the world (port ${v.from_port ?? '?'})`,
        detail: 'Standalone ingress rule allows the entire internet.',
        where,
        fix: 'Restrict the source CIDR / reference a security group.',
      });
    }
  }

  // RDS
  if (/aws_(db_instance|rds_cluster|rds_cluster_instance|redshift_cluster)/.test(t)) {
    if (v.publicly_accessible === true)
      findings.push({
        sev: 'critical',
        title: 'Database is publicly accessible',
        detail: `${t} has publicly_accessible = true - the DB gets a public endpoint.`,
        where,
        fix: 'Set publicly_accessible = false; place it in private subnets.',
      });
    if (v.storage_encrypted === false || v.encrypted === false)
      findings.push({
        sev: 'high',
        title: 'Database storage not encrypted',
        detail: `${t} storage_encrypted is false.`,
        where,
        fix: 'Enable storage_encrypted (KMS).',
      });
  }

  // EC2 / EBS
  if (t === 'aws_instance') {
    const md = (v.metadata_options as Record<string, unknown> | undefined) ?? undefined;
    if (md && md.http_tokens && md.http_tokens !== 'required')
      findings.push({
        sev: 'high',
        title: 'IMDSv1 enabled (http_tokens != "required")',
        detail: 'Instance metadata v1 is exploitable via SSRF to steal the instance role credentials.',
        where,
        fix: 'Set metadata_options { http_tokens = "required" } (enforce IMDSv2).',
      });
    if (v.associate_public_ip_address === true)
      findings.push({
        sev: 'medium',
        title: 'Instance gets a public IP',
        detail: 'associate_public_ip_address = true exposes the instance directly.',
        where,
        fix: 'Use private subnets + NAT / SSM; drop the public IP unless required.',
      });
  }
  if (t === 'aws_ebs_volume' && v.encrypted === false)
    findings.push({
      sev: 'medium',
      title: 'EBS volume not encrypted',
      detail: 'encrypted = false - data at rest is unprotected.',
      where,
      fix: 'Set encrypted = true (account-level EBS encryption by default is better).',
    });

  // IAM
  if (/aws_iam_(policy|role_policy|user_policy|group_policy)/.test(t) && (v.policy || v.assume_role_policy)) {
    for (const i of policyIssues(v.policy ?? v.assume_role_policy))
      findings.push({
        sev: 'critical',
        title: `Over-broad IAM policy (${i})`,
        detail: `${t} grants ${i}.`,
        where,
        fix: 'Scope Action/Resource to least privilege.',
      });
  }

  // Search / KMS / logging
  if (/aws_(elasticsearch|opensearch)_domain/.test(t)) {
    const e2r = v.encrypt_at_rest as Record<string, unknown> | undefined;
    if (!e2r || e2r.enabled === false)
      findings.push({
        sev: 'high',
        title: 'OpenSearch/ES domain without encryption at rest',
        detail: 'encrypt_at_rest is absent or disabled.',
        where,
        fix: 'Add encrypt_at_rest { enabled = true } and node_to_node_encryption.',
      });
  }
  if (t === 'aws_kms_key' && v.enable_key_rotation === false)
    findings.push({
      sev: 'low',
      title: 'KMS key rotation disabled',
      detail: 'enable_key_rotation = false.',
      where,
      fix: 'Set enable_key_rotation = true for CMKs.',
    });
  if (t === 'aws_cloudtrail') {
    if (v.is_multi_region_trail === false)
      findings.push({
        sev: 'medium',
        title: 'CloudTrail is single-region',
        detail: 'is_multi_region_trail = false - activity in other regions is not captured.',
        where,
        fix: 'Set is_multi_region_trail = true.',
      });
    if (v.enable_log_file_validation === false)
      findings.push({
        sev: 'low',
        title: 'CloudTrail log-file validation off',
        detail: 'enable_log_file_validation = false - tampering is harder to detect.',
        where,
        fix: 'Set enable_log_file_validation = true.',
      });
  }

  // Hardcoded secrets in the plan
  for (const [k, val] of Object.entries(v)) {
    if (
      SECRETY.test(k) &&
      typeof val === 'string' &&
      val.length >= 6 &&
      !/^\$\{|^arn:|^var\.|^data\.|^aws_/.test(val) &&
      !/^\s*$/.test(val)
    ) {
      findings.push({
        sev: 'high',
        title: `Possible hardcoded secret (${k})`,
        detail: `Attribute "${k}" is a literal string in the plan - secrets in IaC/state leak to anyone with plan/state access.`,
        where,
        fix: 'Source from a secrets manager / variable marked sensitive; rotate if already applied.',
      });
      break; // one per resource is enough signal
    }
  }
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return {
      error: `${(e as Error).message}. Tip: this expects JSON - run \`terraform show -json <planfile>\` (not the human-readable plan).`,
      resources: 0,
      findings: [],
    };
  }
  const resources = collect(doc);
  if (resources.length === 0)
    return {
      error:
        'No resources found. Expected resource_changes[] / planned_values / values.root_module from terraform-json.',
      resources: 0,
      findings: [],
    };
  const findings: Finding[] = [];
  for (const r of resources) {
    try {
      analyzeRes(r, findings);
    } catch (_catchErr) {
      console.error('analyze failed:', errMessage(_catchErr));
      /* never let one odd resource break the scan */
    }
  }
  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { resources: resources.length, findings };
}

const SAMPLE = JSON.stringify(
  {
    format_version: '1.2',
    resource_changes: [
      {
        address: 'aws_s3_bucket_public_access_block.data',
        type: 'aws_s3_bucket_public_access_block',
        change: {
          actions: ['create'],
          after: {
            block_public_acls: false,
            ignore_public_acls: false,
            block_public_policy: false,
            restrict_public_buckets: false,
          },
        },
      },
      {
        address: 'aws_security_group.web',
        type: 'aws_security_group',
        change: {
          actions: ['create'],
          after: { ingress: [{ from_port: 22, to_port: 22, cidr_blocks: ['0.0.0.0/0'] }] },
        },
      },
      {
        address: 'aws_db_instance.prod',
        type: 'aws_db_instance',
        change: {
          actions: ['create'],
          after: { publicly_accessible: true, storage_encrypted: false, password: 'Sup3rSecret!' },
        },
      },
    ],
  },
  null,
  2
);

export default function TerraformScanner(): JSX.Element {
  const [input, setInput] = useState('');
  // Parse + walk the whole plan JSON only after typing/pasting settles
  // (~220ms); the textarea stays bound to `input` so editing feels instant.
  const debouncedInput = useDebounce(input, 220);
  const analysis = useMemo(() => analyze(debouncedInput), [debouncedInput]);
  const counts = useMemo(() => {
    const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    analysis?.findings.forEach((f) => (c[f.sev] += 1));
    return c;
  }, [analysis]);

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Terraform / IaC Plan Scanner</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste <span className="font-mono text-tool">terraform show -json &lt;planfile&gt;</span> (or plan/state JSON).
          Planned attributes are checked for public S3/RDS, world-open security groups, unencrypted storage, IMDSv1,
          wildcard IAM, public resource policies, and hardcoded secrets. Nothing leaves your browser.
        </p>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            type="button"
            onClick={() => setInput(SAMPLE)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load example
          </button>
          {input && (
            <button
              type="button"
              onClick={() => setInput('')}
              className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
            >
              clear
            </button>
          )}
        </div>
      </div>

      <label htmlFor="tf-input" className="sr-only">
        terraform-json
      </label>
      <Textarea
        id="tf-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "resource_changes": [ { "type": "aws_s3_bucket_public_access_block", "change": { "actions": ["create"], "after": { "block_public_acls": false } } } ] }'
        rows={12}
        spellCheck={false}
        aria-label="terraform-json"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Resources scanned:</span>{' '}
                <span className="font-mono">{analysis.resources}</span>
              </span>
              <span className="flex flex-wrap gap-1.5">
                {(['critical', 'high', 'medium', 'low', 'info'] as Sev[])
                  .filter((s) => counts[s] > 0)
                  .map((s) => (
                    <span
                      key={s}
                      className={`text-mini font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEV_STYLE[s].chip}`}
                    >
                      {counts[s]} {s}
                    </span>
                  ))}
              </span>
            </div>
          </section>

          {analysis.findings.length === 0 && (
            <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
              <ShieldCheck size={16} className="mt-0.5 flex-shrink-0" />
              <span>
                No misconfigurations matched the ruleset. This is not a full policy engine - pair with tfsec / Checkov
                in CI.
              </span>
            </section>
          )}

          {analysis.findings.length > 0 && (
            <section className="space-y-3">
              {analysis.findings.map((f, idx) => {
                const st = SEV_STYLE[f.sev];
                return (
                  <div key={`${f.where}-${f.title}-${idx}`} className="surface-card p-4">
                    <div className="flex items-start gap-2.5">
                      <st.Icon size={16} className={`mt-0.5 flex-shrink-0 ${st.text}`} />
                      <div className="min-w-0 flex-1">
                        <span
                          className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${st.chip}`}
                        >
                          {f.sev}
                        </span>
                        <h3 className={`font-display font-semibold mt-1.5 ${st.text}`}>{f.title}</h3>
                        <p className="text-sm text-muted mt-1 leading-relaxed">{f.detail}</p>
                        <p className="text-meta font-mono text-muted mt-2 break-all">{f.where}</p>
                        <p className="text-tool text-body mt-2">
                          <span className="text-muted font-mono text-mini uppercase tracking-wider">fix</span> {f.fix}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
