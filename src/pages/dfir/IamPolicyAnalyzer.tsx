import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * AWS IAM / Cloud Policy Analyzer - 100% client-side.
 *
 * Paste an AWS policy JSON (identity, resource-based, S3 bucket, or role
 * trust policy). It is parsed and statically analysed for the
 * least-privilege / misconfiguration patterns that show up in real cloud
 * incidents: wildcard admin, public principals, NotAction/NotResource
 * allows, privilege-escalation actions, broad secret/data access, and
 * confused-deputy trust relationships. Nothing leaves the browser.
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
  policyType: string;
  statementCount: number;
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

/** AWS string-or-array fields → always an array of strings. */
function toStrArray(x: unknown): string[] {
  if (x == null) return [];
  if (Array.isArray(x)) return x.map((v) => String(v));
  return [String(x)];
}

const hasFullWildcard = (vals: string[]) => vals.some((v) => v === '*');
const serviceWildcards = (actions: string[]) =>
  actions.filter((a) => /^[a-z0-9-]+:\*$/i.test(a)).map((a) => a.split(':')[0]!);

/**
 * Actions that, granted broadly, let a principal escalate its own
 * privileges (the well-known IAM priv-esc set) or pivot via a passed role.
 */
const PRIV_ESC = [
  'iam:createpolicyversion',
  'iam:setdefaultpolicyversion',
  'iam:attachuserpolicy',
  'iam:attachrolepolicy',
  'iam:attachgrouppolicy',
  'iam:putuserpolicy',
  'iam:putrolepolicy',
  'iam:putgrouppolicy',
  'iam:createaccesskey',
  'iam:createloginprofile',
  'iam:updateloginprofile',
  'iam:updateassumerolepolicy',
  'iam:passrole',
  'sts:assumerole',
  'lambda:createfunction',
  'lambda:updatefunctioncode',
  'glue:createdevendpoint',
  'cloudformation:createstack',
  'datapipeline:createpipeline',
  'sagemaker:createnotebookinstance',
  'ec2:runinstances',
];

/** Broad access to secrets / data - exfil-relevant when paired with *. */
const SENSITIVE_DATA = [
  'secretsmanager:getsecretvalue',
  'kms:decrypt',
  'ssm:getparameter',
  'ssm:getparameters',
  'ssm:getparametersbypath',
  's3:getobject',
  'dynamodb:getitem',
  'dynamodb:scan',
  'rds:downloaddblogfileportion',
];

function actionMatches(actions: string[], needle: string): boolean {
  const lc = actions.map((a) => a.toLowerCase());
  if (lc.includes('*')) return true;
  if (lc.includes(needle)) return true;
  const svc = needle.split(':')[0];
  return lc.includes(`${svc}:*`);
}

function isAnonymousPrincipal(principal: unknown): boolean {
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') {
    const p = principal as Record<string, unknown>;
    return Object.values(p).some((v) => v === '*' || (Array.isArray(v) && v.includes('*')));
  }
  return false;
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return { error: (e as Error).message, policyType: '', statementCount: 0, findings: [] };
  }

  const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  const findings: Finding[] = [];

  const version = doc.Version;
  if (version !== '2012-10-17') {
    findings.push({
      sev: 'low',
      title: 'Policy version is not 2012-10-17',
      detail: `Version is ${version ? `"${String(version)}"` : 'missing'}. Older/absent versions disable policy variables and some condition keys.`,
      where: 'Document',
      fix: 'Set "Version": "2012-10-17".',
    });
  }

  if (statements.length === 0) {
    findings.push({
      sev: 'info',
      title: 'No statements found',
      detail: 'The policy has no Statement array - nothing to evaluate.',
      where: 'Document',
      fix: 'Add at least one statement, or verify you pasted the right document.',
    });
  }

  let anyPrincipal = false;
  let trustLike = false;

  statements.forEach((raw, i) => {
    const s = (raw ?? {}) as Record<string, unknown>;
    const sid = typeof s.Sid === 'string' && s.Sid ? ` (${s.Sid})` : '';
    const where = `Statement ${i + 1}${sid}`;
    const effect = String(s.Effect ?? '');
    const actions = toStrArray(s.Action);
    const notActions = toStrArray(s.NotAction);
    const resources = toStrArray(s.Resource);
    const notResources = toStrArray(s.NotResource);
    const hasCondition = !!s.Condition && Object.keys(s.Condition as object).length > 0;
    const principalPresent = 'Principal' in s || 'NotPrincipal' in s;
    if (principalPresent) anyPrincipal = true;

    if (effect !== 'Allow' && effect !== 'Deny') {
      findings.push({
        sev: 'info',
        title: 'Invalid or missing Effect',
        detail: `Effect is "${effect}". AWS only accepts exactly "Allow" or "Deny" (case-sensitive).`,
        where,
        fix: 'Set Effect to "Allow" or "Deny".',
      });
      return;
    }

    // Deny statements with wildcards are generally safe (and often good) -
    // only Allow statements grant risk. Keep Deny noise out.
    if (effect === 'Deny') return;

    const actionWildcard = hasFullWildcard(actions);
    const resourceWildcard = hasFullWildcard(resources);

    if (actionWildcard && resourceWildcard) {
      findings.push({
        sev: 'critical',
        title: 'Full administrative access (Action "*" on Resource "*")',
        detail: 'This statement allows every action on every resource - equivalent to AdministratorAccess.',
        where,
        fix: 'Scope Action and Resource to exactly what the principal needs.',
      });
    } else {
      if (actionWildcard) {
        findings.push({
          sev: 'high',
          title: 'Wildcard Action ("*")',
          detail: 'Every action across every AWS service is allowed by this statement.',
          where,
          fix: 'Replace "*" with the specific actions required.',
        });
      }
      if (resourceWildcard) {
        findings.push({
          sev: 'high',
          title: 'Wildcard Resource ("*")',
          detail: 'The allowed actions apply to every resource in the account.',
          where,
          fix: 'Restrict Resource to specific ARNs.',
        });
      }
    }

    const svcWild = serviceWildcards(actions);
    if (svcWild.length > 0 && !actionWildcard) {
      findings.push({
        sev: 'medium',
        title: `Service-wide wildcard action (${[...new Set(svcWild)].join(', ')})`,
        detail: `"${svcWild[0]}:*" grants every action in that service, including destructive and IAM-adjacent ones.`,
        where,
        fix: 'Enumerate the specific actions instead of "<service>:*".',
      });
    }

    if (notActions.length > 0) {
      findings.push({
        sev: 'high',
        title: 'NotAction with Allow',
        detail:
          'Allow + NotAction grants EVERY action except the listed ones - an allow-list inversion that almost always grants far more than intended.',
        where,
        fix: 'Rewrite as an explicit Allow of the required Action list.',
      });
    }
    if (notResources.length > 0) {
      findings.push({
        sev: 'high',
        title: 'NotResource with Allow',
        detail: 'Allow + NotResource grants the actions on every resource except the listed ones.',
        where,
        fix: 'Rewrite as an explicit Allow on specific resource ARNs.',
      });
    }

    // Principal analysis (resource-based / bucket / trust policies)
    if ('Principal' in s && isAnonymousPrincipal(s.Principal)) {
      findings.push({
        sev: hasCondition ? 'high' : 'critical',
        title: hasCondition ? 'Wildcard Principal gated only by Condition' : 'Public / anonymous Principal ("*")',
        detail: hasCondition
          ? 'The resource is exposed to every AWS account / anonymous caller and only restricted by a Condition block - verify the condition is actually restrictive (e.g. aws:SourceArn / aws:PrincipalOrgID), not just aws:SecureTransport.'
          : 'This grants access to ANY AWS principal - effectively public. A classic source of S3 / SNS / SQS / KMS data exposure.',
        where,
        fix: 'Set Principal to specific account/role ARNs, or add a strict Condition (aws:PrincipalOrgID, aws:SourceArn).',
      });
    }

    // Trust-policy confused-deputy: cross-account/3rd-party assume-role
    const isAssume = actionMatches(actions, 'sts:assumerole');
    if ('Principal' in s && isAssume) {
      trustLike = true;
      const principal = s.Principal as Record<string, unknown> | string;
      const awsP = typeof principal === 'object' && principal ? toStrArray(principal.AWS) : [];
      const external = awsP.some((p) => /^arn:aws:iam::\d{12}:/.test(p) || p === '*');
      const condStr = JSON.stringify(s.Condition ?? {}).toLowerCase();
      const guarded =
        condStr.includes('sts:externalid') ||
        condStr.includes('aws:sourcearn') ||
        condStr.includes('aws:sourceaccount') ||
        condStr.includes('aws:principalorgid');
      if (external && !guarded) {
        findings.push({
          sev: 'high',
          title: 'Cross-account trust without ExternalId / SourceArn (confused deputy)',
          detail:
            'This role can be assumed by another account with no sts:ExternalId, aws:SourceArn, aws:SourceAccount or aws:PrincipalOrgID condition - the confused-deputy pattern third parties exploit.',
          where,
          fix: 'Add a Condition requiring sts:ExternalId (third-party) or aws:SourceArn/aws:PrincipalOrgID (internal).',
        });
      }
    }

    // Privilege escalation
    const escHits = PRIV_ESC.filter((a) => actionMatches(actions, a));
    if (escHits.length > 0) {
      findings.push({
        sev: resourceWildcard || actionWildcard ? 'critical' : 'high',
        title: 'Privilege-escalation actions granted',
        detail: `Grants ${escHits
          .slice(0, 6)
          .join(
            ', '
          )}${escHits.length > 6 ? ` +${escHits.length - 6} more` : ''} - these let a principal grant itself more access or pivot through a passed role.`,
        where,
        fix: 'Remove these unless strictly required; if iam:PassRole is needed, scope Resource to the exact role ARN and add an iam:PassedToService condition.',
      });
    }

    // Broad secret / data access
    const dataHits = SENSITIVE_DATA.filter((a) => actionMatches(actions, a));
    if (dataHits.length > 0 && resourceWildcard) {
      findings.push({
        sev: 'high',
        title: 'Broad access to secrets / data',
        detail: `${dataHits.slice(0, 5).join(', ')} on Resource "*" - account-wide read access to secrets, KMS plaintext, parameters or object data.`,
        where,
        fix: 'Scope Resource to specific secret/key/bucket ARNs.',
      });
    }
  });

  const policyType = trustLike
    ? 'Role trust policy'
    : anyPrincipal
      ? 'Resource-based policy (S3 / SNS / SQS / KMS / …)'
      : 'Identity-based policy';

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { policyType, statementCount: statements.length, findings };
}

const SAMPLE_RISKY = JSON.stringify(
  {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'GodMode', Effect: 'Allow', Action: '*', Resource: '*' },
      {
        Sid: 'PublicBucket',
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::my-bucket/*',
      },
      { Sid: 'PassAnyRole', Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: '*' },
    ],
  },
  null,
  2
);

const SAMPLE_CLEAN = JSON.stringify(
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadOneBucketPrefix',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::reports-prod', 'arn:aws:s3:::reports-prod/finance/*'],
        Condition: { Bool: { 'aws:SecureTransport': 'true' } },
      },
    ],
  },
  null,
  2
);

export default function IamPolicyAnalyzer(): JSX.Element {
  const [input, setInput] = useState('');
  const analysis = useMemo(() => analyze(input), [input]);

  const counts = useMemo(() => {
    const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    analysis?.findings.forEach((f) => (c[f.sev] += 1));
    return c;
  }, [analysis]);

  const clean = analysis && !analysis.error && analysis.findings.every((f) => f.sev === 'info' || f.sev === 'low');

  return (
    <DataPageLayout
      backTo="/dfir"
      maxWidthClass="max-w-4xl"
      icon={<ShieldAlert size={28} />}
      title="IAM Policy Analyzer"
      description="Paste an AWS policy (identity, resource-based, S3 bucket, or role trust policy). It is analysed locally for least-privilege and misconfiguration risks - wildcard admin, public principals, NotAction/NotResource allows, privilege-escalation actions, broad secret access, and confused-deputy trust. Nothing leaves your browser."
      headerExtra={
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setInput(SAMPLE_RISKY)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load risky example
          </button>
          <button
            type="button"
            onClick={() => setInput(SAMPLE_CLEAN)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load least-privilege example
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
      }
    >
      <label htmlFor="policy-input" className="sr-only">
        AWS policy JSON
      </label>
      <Textarea
        id="policy-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*" } ] }'
        rows={12}
        spellCheck={false}
        aria-label="AWS policy JSON"
      />

      {analysis?.error && (
        <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">JSON parse error: {analysis.error}</p>
      )}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Type:</span> <span className="font-mono">{analysis.policyType}</span>
              </span>
              <span>
                <span className="text-muted">Statements:</span>{' '}
                <span className="font-mono">{analysis.statementCount}</span>
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

          {clean && counts.critical + counts.high + counts.medium === 0 && (
            <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
              <ShieldCheck size={16} className="mt-0.5 flex-shrink-0" />
              <span>
                No high-risk patterns detected. Still review against your environment’s least-privilege baseline.
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
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${st.chip}`}
                          >
                            {f.sev}
                          </span>
                          <span className="text-mini font-mono text-muted">{f.where}</span>
                        </div>
                        <h3 className={`font-display font-semibold mt-1.5 ${st.text}`}>{f.title}</h3>
                        <p className="text-sm text-muted mt-1 leading-relaxed">{f.detail}</p>
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
    </DataPageLayout>
  );
}
