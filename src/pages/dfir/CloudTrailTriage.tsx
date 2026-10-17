import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * CloudTrail Triage - 100% client-side.
 *
 * Paste CloudTrail JSON: a log file ({ Records: [...] }), `aws cloudtrail
 * lookup-events` output ({ Events: [{ CloudTrailEvent: "<json>" }] }), a
 * raw array, or a single event. Management-plane events are scored for
 * the patterns that show up in cloud intrusions - no-MFA console logins,
 * root usage, log/guardrail tampering, IAM changes, public exposure,
 * snapshot/AMI sharing, and access-denied recon bursts.
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
  events: number;
  principals: number;
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

interface CTEvent {
  eventName?: string;
  eventSource?: string;
  eventTime?: string;
  awsRegion?: string;
  sourceIPAddress?: string;
  errorCode?: string;
  readOnly?: boolean;
  userIdentity?: {
    type?: string;
    arn?: string;
    userName?: string;
    accessKeyId?: string;
    invokedBy?: string;
    sessionContext?: { attributes?: { mfaAuthenticated?: string } };
  };
  additionalEventData?: { MFAUsed?: string };
  responseElements?: Record<string, unknown> | null;
  requestParameters?: Record<string, unknown> | null;
}

const LOG_TAMPER = new Set([
  'StopLogging',
  'DeleteTrail',
  'UpdateTrail',
  'PutEventSelectors',
  'DeleteDetector',
  'UpdateDetector',
  'DisassociateFromMasterAccount',
  'DeleteConfigurationRecorder',
  'StopConfigurationRecorder',
  'DisableSecurityHub',
  'DeleteFlowLogs',
]);

const IAM_SENSITIVE = new Set([
  'CreateUser',
  'CreateAccessKey',
  'AttachUserPolicy',
  'AttachRolePolicy',
  'AttachGroupPolicy',
  'PutUserPolicy',
  'PutRolePolicy',
  'PutGroupPolicy',
  'CreateLoginProfile',
  'UpdateLoginProfile',
  'CreatePolicyVersion',
  'SetDefaultPolicyVersion',
  'UpdateAssumeRolePolicy',
  'DeactivateMFADevice',
  'DeleteVirtualMFADevice',
  'CreateRole',
]);

const SNAPSHOT_SHARE = new Set(['ModifySnapshotAttribute', 'ModifyImageAttribute', 'ModifyDBSnapshotAttribute']);

function principalOf(e: CTEvent): string {
  const u = e.userIdentity ?? {};
  return u.arn || u.userName || u.accessKeyId || u.type || 'unknown-principal';
}

function flatten(doc: unknown): CTEvent[] {
  const out: CTEvent[] = [];
  const pushMaybe = (v: unknown) => {
    if (v && typeof v === 'object') out.push(v as CTEvent);
  };
  if (Array.isArray(doc)) {
    doc.forEach(pushMaybe);
    return out;
  }
  const d = doc as Record<string, unknown>;
  if (Array.isArray(d.Records)) {
    d.Records.forEach(pushMaybe);
    return out;
  }
  if (Array.isArray(d.Events)) {
    for (const ev of d.Events) {
      const cte = (ev as Record<string, unknown>)?.CloudTrailEvent;
      if (typeof cte === 'string') {
        try {
          out.push(JSON.parse(cte) as CTEvent);
        } catch (_catchErr) {
          console.error('flatten failed:', errMessage(_catchErr));
          /* skip unparseable embedded event */
        }
      } else pushMaybe(ev);
    }
    return out;
  }
  if (d.eventName || d.eventSource) out.push(d as CTEvent);
  return out;
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(trimmed);
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return { error: (e as Error).message, events: 0, principals: 0, findings: [] };
  }

  const events = flatten(doc);
  if (events.length === 0) {
    return {
      error: 'No events found. Expected { Records: [...] }, { Events: [...] }, an array, or a single event.',
      events: 0,
      principals: 0,
      findings: [],
    };
  }

  const findings: Finding[] = [];
  const deniedByPrincipal = new Map<string, number>();
  const secretPullByPrincipal = new Map<string, number>();
  const principals = new Set<string>();

  for (const e of events) {
    const name = e.eventName ?? '';
    const src = (e.eventSource ?? '').replace('.amazonaws.com', '');
    const who = principalOf(e);
    principals.add(who);
    const ip = e.sourceIPAddress ?? '?';
    const when = e.eventTime ?? '';
    const where = `${name || src} · ${who} · ${ip}${when ? ` · ${when}` : ''}`;
    const uType = e.userIdentity?.type ?? '';
    const isRoot = uType === 'Root';
    const isService = !!e.userIdentity?.invokedBy || uType === 'AWSService';

    // Console login without MFA
    if (name === 'ConsoleLogin') {
      const success = String((e.responseElements as Record<string, unknown> | null)?.ConsoleLogin ?? '') === 'Success';
      const mfa =
        e.additionalEventData?.MFAUsed ?? e.userIdentity?.sessionContext?.attributes?.mfaAuthenticated ?? 'Unknown';
      const noMfa = mfa === 'No' || mfa === 'false';
      if (success && noMfa) {
        findings.push({
          sev: isRoot ? 'critical' : 'high',
          title: `${isRoot ? 'ROOT ' : ''}console login WITHOUT MFA`,
          detail: `Successful console sign-in for ${who} from ${ip} with no MFA. ${isRoot ? 'Root with no MFA is the highest-risk identity in the account.' : ''}`,
          where,
          fix: 'Enforce MFA for all human principals (SCP / IAM). Investigate this session.',
        });
      }
    }

    // Root usage (non-service)
    if (isRoot && !isService && name !== 'ConsoleLogin') {
      findings.push({
        sev: 'high',
        title: `Root account API activity (${name})`,
        detail: `The account root identity performed ${name}. Root should be used only for the handful of tasks that require it.`,
        where,
        fix: 'Stop using root for day-to-day operations; lock root credentials + MFA.',
      });
    }

    // Log / guardrail tampering
    if (LOG_TAMPER.has(name)) {
      findings.push({
        sev: 'critical',
        title: `Security telemetry tampering (${name})`,
        detail: `${name} on ${src} disables or weakens detection (CloudTrail / GuardDuty / Config / SecurityHub / VPC flow logs). Classic anti-forensics step.`,
        where,
        fix: 'Treat as an incident. Re-enable logging, review surrounding activity by this principal.',
      });
    }

    // IAM changes
    if (src === 'iam' && IAM_SENSITIVE.has(name)) {
      findings.push({
        sev: 'high',
        title: `IAM modification (${name})`,
        detail: `${who} changed identity/permissions via ${name}. Persistence + privilege-escalation primitive.`,
        where,
        fix: 'Confirm this was an authorized change-management action; review the new permissions.',
      });
    }

    // Security group opened to the world
    if (name === 'AuthorizeSecurityGroupIngress') {
      const rp = JSON.stringify(e.requestParameters ?? {});
      if (rp.includes('0.0.0.0/0') || rp.includes('::/0')) {
        findings.push({
          sev: 'high',
          title: 'Security group opened to 0.0.0.0/0',
          detail: `${who} authorized inbound access from the entire internet. Pair with the Security Group Analyzer to see which ports.`,
          where,
          fix: 'Restrict the rule to specific CIDRs; verify intent.',
        });
      }
    }

    // S3 public-exposure changes
    if (
      src === 's3' &&
      /PutBucketAcl|PutBucketPolicy|DeleteBucketPublicAccessBlock|PutAccountPublicAccessBlock/.test(name)
    ) {
      findings.push({
        sev: 'high',
        title: `S3 exposure-relevant change (${name})`,
        detail: `${who} modified bucket ACL/policy or public-access-block settings. A frequent data-exposure path.`,
        where,
        fix: 'Verify the bucket is not now public; re-enable Block Public Access if unintended.',
      });
    }

    // Snapshot / AMI shared publicly
    if (SNAPSHOT_SHARE.has(name)) {
      const rp = JSON.stringify(e.requestParameters ?? {}).toLowerCase();
      // CloudTrail emits group "all" specifically for a PUBLIC snapshot/AMI
      // share. The old bare `"all"` substring false-positived on any value
      // literally equal to "all" anywhere in requestParameters.
      if (/"group"\s*:\s*"all"/.test(rp) || rp.includes('groupall') || rp.includes('"userid":"all"')) {
        findings.push({
          sev: 'critical',
          title: `Snapshot / AMI shared publicly (${name})`,
          detail: `${who} added "all" to a snapshot/AMI/DB-snapshot share permission - public data exfiltration vector.`,
          where,
          fix: 'Remove the public share immediately; audit what data the snapshot contained.',
        });
      }
    }

    // KMS destruction
    if (src === 'kms' && /ScheduleKeyDeletion|DisableKey/.test(name)) {
      findings.push({
        sev: 'high',
        title: `KMS key disable/deletion (${name})`,
        detail: `${who} scheduled deletion of / disabled a KMS key - potential ransom / destruction or break-glass.`,
        where,
        fix: 'Cancel deletion if unintended; KMS key loss is unrecoverable.',
      });
    }

    // Aggregation: access-denied recon + bulk secret pulls
    if (e.errorCode && /AccessDenied|UnauthorizedOperation|Forbidden/i.test(e.errorCode)) {
      deniedByPrincipal.set(who, (deniedByPrincipal.get(who) ?? 0) + 1);
    }
    if (/GetSecretValue|GetParameter|Decrypt|GetParameters/.test(name) && !e.errorCode) {
      secretPullByPrincipal.set(who, (secretPullByPrincipal.get(who) ?? 0) + 1);
    }
  }

  for (const [who, n] of deniedByPrincipal) {
    if (n >= 15) {
      findings.push({
        sev: 'medium',
        title: `Access-denied burst (${n}) from one principal`,
        detail: `${who} generated ${n} AccessDenied/Unauthorized errors - permission enumeration / recon signature.`,
        where: who,
        fix: 'Review what the principal was probing; consider whether the credential is compromised.',
      });
    }
  }
  for (const [who, n] of secretPullByPrincipal) {
    if (n >= 25) {
      findings.push({
        sev: 'high',
        title: `Bulk secret / parameter / decrypt access (${n})`,
        detail: `${who} pulled secrets/SSM params or called KMS Decrypt ${n} times - possible mass credential harvesting.`,
        where: who,
        fix: 'Confirm the workload legitimately needs this volume; rotate exposed secrets if not.',
      });
    }
  }

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { events: events.length, principals: principals.size, findings };
}

const SAMPLE = JSON.stringify(
  {
    Records: [
      {
        eventTime: '2026-05-18T03:11:02Z',
        eventName: 'ConsoleLogin',
        eventSource: 'signin.amazonaws.com',
        awsRegion: 'us-east-1',
        sourceIPAddress: '203.0.113.9',
        userIdentity: { type: 'IAMUser', userName: 'deploy', arn: 'arn:aws:iam::111122223333:user/deploy' },
        additionalEventData: { MFAUsed: 'No' },
        responseElements: { ConsoleLogin: 'Success' },
      },
      {
        eventTime: '2026-05-18T03:12:40Z',
        eventName: 'StopLogging',
        eventSource: 'cloudtrail.amazonaws.com',
        sourceIPAddress: '203.0.113.9',
        userIdentity: { type: 'IAMUser', userName: 'deploy', arn: 'arn:aws:iam::111122223333:user/deploy' },
      },
      {
        eventTime: '2026-05-18T03:14:05Z',
        eventName: 'AuthorizeSecurityGroupIngress',
        eventSource: 'ec2.amazonaws.com',
        sourceIPAddress: '203.0.113.9',
        userIdentity: { type: 'IAMUser', userName: 'deploy' },
        requestParameters: { ipPermissions: { items: [{ ipRanges: { items: [{ cidrIp: '0.0.0.0/0' }] } }] } },
      },
    ],
  },
  null,
  2
);

export default function CloudTrailTriage(): JSX.Element {
  const [input, setInput] = useState('');
  const analysis = useMemo(() => analyze(input), [input]);
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">CloudTrail Triage</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste CloudTrail JSON - a log file, <span className="font-mono text-tool">lookup-events</span> output, an
          array, or one event. Management activity is scored for intrusion patterns: no-MFA / root logins, log &
          guardrail tampering, IAM changes, public exposure, snapshot sharing, and recon bursts. Nothing leaves your
          browser.
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

      <label htmlFor="ct-input" className="sr-only">
        CloudTrail JSON
      </label>
      <Textarea
        id="ct-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "Records": [ { "eventName": "ConsoleLogin", "userIdentity": { "type": "Root" }, "additionalEventData": { "MFAUsed": "No" }, "responseElements": { "ConsoleLogin": "Success" } } ] }'
        rows={12}
        spellCheck={false}
        aria-label="CloudTrail JSON"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Events:</span> <span className="font-mono">{analysis.events}</span>
              </span>
              <span>
                <span className="text-muted">Principals:</span> <span className="font-mono">{analysis.principals}</span>
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
                No high-risk management events matched. Note: data events (S3 object reads) aren’t in management trails.
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
                        </div>
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
