import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * GCP IAM Policy Analyzer - 100% client-side.
 *
 * Paste a GCP IAM allow policy (`gcloud … get-iam-policy --format=json`,
 * i.e. { bindings: [...] }) or a custom role
 * (`gcloud iam roles describe --format=json`, i.e.
 * { includedPermissions: [...] }). Bindings and permissions are scored
 * for the over-grant / privilege-escalation patterns specific to GCP -
 * allUsers/allAuthenticatedUsers, primitive owner/editor roles, service-
 * account impersonation & key creation, setIamPolicy, and wildcard
 * custom-role permissions. Nothing leaves the browser.
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
  bindings: number;
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

interface Binding {
  role?: string;
  members?: string[];
  condition?: { title?: string; expression?: string };
}

/** Roles whose grant is itself a privilege-escalation / takeover primitive. */
const DANGEROUS_ROLES: Record<string, { sev: Sev; why: string }> = {
  'roles/owner': {
    sev: 'critical',
    why: 'full control of the project incl. IAM - anyone with it can grant themselves anything.',
  },
  'roles/editor': {
    sev: 'high',
    why: 'broad write across almost all services (primitive role) - not least-privilege.',
  },
  'roles/iam.securityAdmin': { sev: 'high', why: 'can read & set IAM policy across the project.' },
  'roles/iam.roleAdmin': { sev: 'high', why: 'can edit custom roles → grant itself extra permissions.' },
  'roles/iam.organizationRoleAdmin': { sev: 'critical', why: 'org-wide custom-role control.' },
  'roles/resourcemanager.organizationAdmin': { sev: 'critical', why: 'organization-level admin.' },
  'roles/iam.serviceAccountTokenCreator': {
    sev: 'critical',
    why: 'can mint access tokens / sign as ANY service account it is granted on - direct impersonation & escalation.',
  },
  'roles/iam.serviceAccountUser': {
    sev: 'high',
    why: 'can deploy resources that run AS a service account (actAs) - pivot to the SA’s privileges.',
  },
  'roles/iam.serviceAccountKeyAdmin': {
    sev: 'high',
    why: 'can create long-lived SA keys - persistence & credential exfil.',
  },
  'roles/iam.workloadIdentityUser': { sev: 'medium', why: 'external workload can impersonate the service account.' },
  'roles/storage.admin': { sev: 'high', why: 'full control of all buckets/objects in scope.' },
  'roles/cloudfunctions.admin': { sev: 'high', why: 'deploy code that runs as a service account (actAs path).' },
  'roles/run.admin': { sev: 'high', why: 'deploy Cloud Run services as a service account (actAs path).' },
  'roles/compute.admin': { sev: 'high', why: 'create VMs with attached service accounts → token theft.' },
  'roles/cloudbuild.builds.editor': {
    sev: 'high',
    why: 'trigger builds that run as the Cloud Build SA - well-known escalation.',
  },
  'roles/deploymentmanager.editor': {
    sev: 'high',
    why: 'Deployment Manager runs as a Google-managed SA - escalation path.',
  },
};

const ESC_PERMS = [
  'resourcemanager.projects.setiampolicy',
  'iam.serviceaccounts.actas',
  'iam.serviceaccounts.getaccesstoken',
  'iam.serviceaccounts.getopenidtoken',
  'iam.serviceaccounts.implicitdelegation',
  'iam.serviceaccounts.signblob',
  'iam.serviceaccounts.signjwt',
  'iam.serviceaccountkeys.create',
  'iam.roles.update',
  'iam.roles.create',
  'serviceusage.services.use',
];

function bindingsOf(doc: Record<string, unknown>): Binding[] | null {
  if (Array.isArray(doc.bindings)) return doc.bindings as Binding[];
  if (Array.isArray(doc)) return doc as Binding[];
  if (doc.role && doc.members) return [doc as Binding];
  return null;
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return { error: (e as Error).message, policyType: '', bindings: 0, findings: [] };
  }

  const findings: Finding[] = [];

  // ---- Custom role ----
  if (Array.isArray(doc.includedPermissions)) {
    const perms = (doc.includedPermissions as string[]).map((p) => String(p).toLowerCase());
    const where = `role ${String(doc.name ?? doc.title ?? 'custom-role')}`;
    if (perms.includes('*'))
      findings.push({
        sev: 'critical',
        title: 'Custom role grants "*" (all permissions)',
        detail: 'Equivalent to project owner.',
        where,
        fix: 'Enumerate only the permissions the role’s purpose requires.',
      });
    const hitEsc = perms.filter((p) => ESC_PERMS.includes(p) || p.endsWith('.setiampolicy'));
    if (hitEsc.length > 0)
      findings.push({
        sev: 'critical',
        title: 'Privilege-escalation permissions in custom role',
        detail: `Includes ${[...new Set(hitEsc)].slice(0, 6).join(', ')} - setIamPolicy / actAs / token & key minting let the holder escalate or impersonate.`,
        where,
        fix: 'Remove escalation permissions; if actAs is required, scope the role to a single service account.',
      });
    const wildSvc = perms.filter((p) => /\.\*$/.test(p));
    if (wildSvc.length > 0)
      findings.push({
        sev: 'high',
        title: `Wildcard service permissions (${[...new Set(wildSvc)].slice(0, 4).join(', ')})`,
        detail: 'Service-wide "<svc>.*" grants every current and future permission in that service.',
        where,
        fix: 'List explicit permissions instead of "<service>.*".',
      });
    if (String(doc.stage ?? '') === 'DISABLED')
      findings.push({
        sev: 'info',
        title: 'Custom role is DISABLED',
        detail: 'Role stage is DISABLED - bindings to it are inert (context only).',
        where,
        fix: 'No action; noted for completeness.',
      });
    findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
    return { policyType: 'Custom IAM role', bindings: 0, findings };
  }

  // ---- Allow policy ----
  const bindings = bindingsOf(doc);
  if (!bindings) {
    return {
      error:
        'Unrecognised shape. Expected an allow policy ({ bindings: [...] }) or a custom role ({ includedPermissions: [...] }).',
      policyType: '',
      bindings: 0,
      findings: [],
    };
  }

  const version = Number(doc.version ?? 1);

  bindings.forEach((b, i) => {
    const role = String(b.role ?? '');
    const members = (b.members ?? []).map(String);
    const where = `binding ${i + 1} · ${role || '(no role)'}`;
    const hasCond = !!b.condition && !!b.condition.expression;

    if (members.includes('allUsers')) {
      findings.push({
        sev: 'critical',
        title: `Public access - allUsers on ${role}`,
        detail: `Anyone on the internet (unauthenticated) holds ${role}. The classic GCP public-bucket / public-API exposure.`,
        where,
        fix: 'Remove allUsers; expose public content via a CDN/load balancer, not an IAM binding.',
      });
    }
    if (members.includes('allAuthenticatedUsers')) {
      findings.push({
        sev: 'high',
        title: `Any Google account - allAuthenticatedUsers on ${role}`,
        detail: `Every Google/Workspace account anywhere holds ${role} - not "your org", literally any Google identity.`,
        where,
        fix: 'Replace with specific principals or your org/group; never use allAuthenticatedUsers for non-public data.',
      });
    }

    const dr = DANGEROUS_ROLES[role];
    if (dr) {
      // allUsers/allAuthenticated already covered above with critical; this
      // is about the role being broad even for a named principal.
      const saMembers = members.filter((m) => m.startsWith('serviceAccount:'));
      const baseSev = dr.sev;
      findings.push({
        sev: saMembers.length && (role === 'roles/owner' || role === 'roles/editor') ? 'critical' : baseSev,
        title: `Sensitive role: ${role}`,
        detail: `${dr.why}${saMembers.length ? ` Bound to a service account (${saMembers.length}) - a compromised workload token then has this.` : ''}${hasCond ? ' (an IAM Condition is attached - verify it is genuinely restrictive.)' : ''}`,
        where,
        fix:
          role === 'roles/owner' || role === 'roles/editor' || role === 'roles/viewer'
            ? 'Replace the primitive role with a predefined or custom least-privilege role.'
            : 'Confirm each member needs this; prefer a narrower predefined role and add an IAM Condition.',
      });
    } else if (role === 'roles/viewer') {
      findings.push({
        sev: 'medium',
        title: 'Primitive role: roles/viewer',
        detail: 'Project-wide read of nearly every resource - broad data exposure even though it is "read only".',
        where,
        fix: 'Use service-specific viewer roles scoped to what the principal needs.',
      });
    }

    // Primitive role granted directly to individual users (prefer groups)
    if (role === 'roles/owner' || role === 'roles/editor') {
      const userMembers = members.filter((m) => m.startsWith('user:'));
      if (userMembers.length > 0)
        findings.push({
          sev: 'high',
          title: 'Primitive role granted to individual user accounts',
          detail: `${userMembers.slice(0, 3).join(', ')} hold ${role} directly - bind to groups and use least-privilege roles instead.`,
          where,
          fix: 'Grant roles to Google Groups, not individuals; replace owner/editor with predefined roles.',
        });
    }

    const deleted = members.filter((m) => m.startsWith('deleted:'));
    if (deleted.length > 0)
      findings.push({
        sev: 'low',
        title: 'Binding references deleted principals',
        detail: `${deleted.length} member(s) are "deleted:" - stale bindings; if the principal id is recycled they could regain access.`,
        where,
        fix: 'Remove deleted: members from the policy.',
      });

    if (hasCond && version < 3)
      findings.push({
        sev: 'info',
        title: 'Conditional binding with policy version < 3',
        detail: `Binding has a Condition but policy version is ${version}; IAM Conditions require version 3 to evaluate.`,
        where,
        fix: 'Set the policy version to 3 when using conditional bindings.',
      });
  });

  // Audit logging posture (only if auditConfigs present)
  if (Array.isArray(doc.auditConfigs)) {
    const allSvc = (doc.auditConfigs as Record<string, unknown>[]).find((a) => a.service === 'allServices');
    const logs = (allSvc?.auditLogConfigs as { logType?: string }[] | undefined)?.map((l) => l.logType) ?? [];
    if (!allSvc || !logs.includes('DATA_READ') || !logs.includes('DATA_WRITE'))
      findings.push({
        sev: 'low',
        title: 'Data-access audit logging not fully enabled',
        detail:
          'allServices DATA_READ/DATA_WRITE audit logs are not both enabled - data-plane actions may be invisible during IR.',
        where: 'auditConfigs',
        fix: 'Enable DATA_READ + DATA_WRITE audit logs for allServices (mind log volume/cost).',
      });
  }

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { policyType: 'IAM allow policy', bindings: bindings.length, findings };
}

const SAMPLE_POLICY = JSON.stringify(
  {
    version: 1,
    bindings: [
      { role: 'roles/owner', members: ['user:alice@example.com', 'serviceAccount:ci@proj.iam.gserviceaccount.com'] },
      { role: 'roles/storage.objectViewer', members: ['allUsers'] },
      { role: 'roles/iam.serviceAccountTokenCreator', members: ['user:contractor@gmail.com'] },
    ],
    etag: 'BwX...',
  },
  null,
  2
);

const SAMPLE_ROLE = JSON.stringify(
  {
    name: 'projects/p/roles/deployer',
    title: 'Deployer',
    stage: 'GA',
    includedPermissions: [
      'storage.objects.get',
      'iam.serviceAccounts.actAs',
      'resourcemanager.projects.setIamPolicy',
      'compute.*',
    ],
  },
  null,
  2
);

export default function GcpIamAnalyzer(): JSX.Element {
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">GCP IAM Policy Analyzer</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste a GCP IAM allow policy (<span className="font-mono text-tool">get-iam-policy --format=json</span>) or a
          custom role (<span className="font-mono text-tool">iam roles describe --format=json</span>). Bindings &amp;
          permissions are scored for GCP-specific risks - allUsers/allAuthenticatedUsers, primitive owner/editor,
          service-account impersonation &amp; key creation, setIamPolicy, wildcard custom-role permissions. Nothing
          leaves your browser.
        </p>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            type="button"
            onClick={() => setInput(SAMPLE_POLICY)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load allow-policy example
          </button>
          <button
            type="button"
            onClick={() => setInput(SAMPLE_ROLE)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load custom-role example
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

      <label htmlFor="gcp-input" className="sr-only">
        GCP IAM policy JSON
      </label>
      <Textarea
        id="gcp-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "bindings": [ { "role": "roles/owner", "members": ["user:alice@example.com"] } ] }'
        rows={12}
        spellCheck={false}
        aria-label="GCP IAM policy JSON"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Type:</span> <span className="font-mono">{analysis.policyType}</span>
              </span>
              {analysis.policyType === 'IAM allow policy' && (
                <span>
                  <span className="text-muted">Bindings:</span> <span className="font-mono">{analysis.bindings}</span>
                </span>
              )}
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
                No high-risk bindings/permissions matched. Still review against your org’s least-privilege baseline.
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
