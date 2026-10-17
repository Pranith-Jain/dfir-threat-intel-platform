import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * Azure RBAC Analyzer - 100% client-side.
 *
 * Paste `az role assignment list -o json` (role assignments) or
 * `az role definition list --custom-role-only -o json` (role
 * definitions). Assignments are scored for privileged built-in roles at
 * broad scope (root / management-group / subscription), service-
 * principal & guest grants, and legacy co-admins; custom definitions
 * for wildcard actions, role-assignment / elevateAccess escalation, VM
 * run-command, and storage-key / Key Vault data access. Nothing leaves
 * the browser.
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
  inputType: string;
  count: number;
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

/** Built-in roles whose grant is itself broad / an escalation primitive. */
const PRIV_ROLES: Record<string, { sev: Sev; why: string }> = {
  owner: { sev: 'critical', why: 'full control INCLUDING role assignment - a holder can grant itself anything.' },
  'user access administrator': {
    sev: 'critical',
    why: 'can assign ANY role (incl. Owner) - pure privilege-escalation role.',
  },
  'role based access control administrator': {
    sev: 'critical',
    why: 'manages role assignments - escalation primitive.',
  },
  contributor: { sev: 'high', why: 'create/modify/delete almost everything (cannot assign roles, but very broad).' },
  'global administrator': { sev: 'critical', why: 'Entra ID tenant-wide superuser.' },
  'privileged role administrator': { sev: 'critical', why: 'can grant Entra admin roles - escalation.' },
  'security administrator': { sev: 'high', why: 'broad security-config control.' },
  'key vault administrator': { sev: 'high', why: 'full Key Vault data + management access (secrets/keys/certs).' },
  'key vault secrets officer': { sev: 'high', why: 'read/write all Key Vault secrets in scope.' },
  'storage blob data owner': { sev: 'high', why: 'full data-plane access to all blobs in scope.' },
  'storage account contributor': { sev: 'high', why: 'can list keys → full storage data access.' },
  'virtual machine contributor': { sev: 'high', why: 'can run commands / extensions on VMs (code exec).' },
  reader: { sev: 'medium', why: 'broad read of (almost) every resource in scope - wide data exposure.' },
};

function scopeBreadth(scope: string): { label: string; broad: boolean } {
  const s = (scope || '').trim();
  if (s === '/' || s === '') return { label: 'tenant root "/"', broad: true };
  if (/\/providers\/Microsoft\.Management\/managementGroups\//i.test(s))
    return { label: 'management group', broad: true };
  if (/^\/subscriptions\/[^/]+$/i.test(s)) return { label: 'subscription', broad: true };
  if (/\/resourceGroups\/[^/]+$/i.test(s)) return { label: 'resource group', broad: false };
  return { label: 'resource', broad: false };
}

const bump = (s: Sev): Sev => (s === 'high' ? 'critical' : s === 'medium' ? 'high' : s);

function asArr<T>(x: unknown): T[] {
  if (x == null) return [];
  return (Array.isArray(x) ? x : [x]) as T[];
}

interface Assignment {
  roleDefinitionName?: string;
  roleDefinitionId?: string;
  principalId?: string;
  principalName?: string;
  principalType?: string;
  scope?: string;
  properties?: Record<string, unknown>;
}

function roleNameFromId(id: string): string {
  // .../roleDefinitions/<guid> - name unknown; surface the guid tail.
  const m = id.match(/roleDefinitions\/([^/]+)/i);
  return m ? `roleDefinitionId ${m[1]}` : id;
}

function analyzeAssignments(items: Assignment[], findings: Finding[]): void {
  for (let i = 0; i < items.length; i++) {
    const a = items[i]!;
    const p = (a.properties ?? {}) as Record<string, unknown>;
    const roleName = String(a.roleDefinitionName ?? p.roleDefinitionName ?? '').trim();
    const roleId = String(a.roleDefinitionId ?? p.roleDefinitionId ?? '');
    const pType = String(a.principalType ?? p.principalType ?? '').toLowerCase();
    const pName = String(a.principalName ?? p.principalName ?? a.principalId ?? p.principalId ?? 'principal');
    const scope = String(a.scope ?? p.scope ?? '');
    const sb = scopeBreadth(scope);
    const where = `${roleName || roleNameFromId(roleId)} → ${pName}${pType ? ` (${pType})` : ''} @ ${sb.label}`;

    const pr = PRIV_ROLES[roleName.toLowerCase()];
    if (pr) {
      let sev = pr.sev;
      if (sb.broad && (pr.sev === 'high' || pr.sev === 'medium')) sev = bump(pr.sev);
      findings.push({
        sev,
        title: `${roleName} at ${sb.label} scope`,
        detail: `${pr.why}${sb.broad ? ` Scope is ${sb.label} - this applies tenant/subscription-wide.` : ''}`,
        where,
        fix:
          roleName.toLowerCase() === 'owner' || roleName.toLowerCase() === 'contributor'
            ? 'Replace with a least-privilege built-in or custom role scoped to a resource group / resource.'
            : 'Confirm the principal must hold this; narrow the scope and prefer a purpose-built role.',
      });
    }

    if (pType === 'serviceprincipal' && /^(owner|contributor|user access administrator)$/i.test(roleName) && sb.broad) {
      findings.push({
        sev: 'critical',
        title: 'Service principal holds a privileged role at broad scope',
        detail: `A workload/app identity (${pName}) has ${roleName} over a ${sb.label} - a leaked client secret/cert = tenant-wide compromise.`,
        where,
        fix: 'Scope SP access to the exact resources it automates; rotate creds; consider workload identity federation.',
      });
    }

    if (/#ext#|guest/i.test(pName) || pType === 'guest') {
      findings.push({
        sev: pr ? 'high' : 'medium',
        title: 'External / guest principal has a role assignment',
        detail: `${pName} appears to be a B2B guest / external identity${pr ? ` holding ${roleName}` : ''}.`,
        where,
        fix: 'Verify the guest must have this; prefer entitlement management with expiry + access reviews.',
      });
    }

    if (/classic|co-?admin|service administrator|account administrator/i.test(roleName)) {
      findings.push({
        sev: 'high',
        title: 'Legacy classic administrator',
        detail: 'Classic Co-Administrator / Service Administrator is equivalent to Owner and bypasses modern RBAC.',
        where,
        fix: 'Remove classic administrators; use Azure RBAC role assignments instead.',
      });
    }
  }
}

const DANGER_ACTIONS: { re: RegExp; sev: Sev; title: string; detail: string }[] = [
  {
    re: /^microsoft\.authorization\/elevateaccess\/action$/i,
    sev: 'critical',
    title: 'elevateAccess action',
    detail:
      'Microsoft.Authorization/elevateAccess/action lets the principal grant itself User Access Administrator at tenant root - full takeover.',
  },
  {
    re: /^microsoft\.authorization\/roleassignments\/write$|^microsoft\.authorization\/\*$|^\*$/i,
    sev: 'critical',
    title: 'Can create role assignments (escalation)',
    detail: 'roleAssignments/write (or Microsoft.Authorization/* or *) lets the holder grant itself any role.',
  },
  {
    re: /^microsoft\.authorization\/roledefinitions\/write$/i,
    sev: 'high',
    title: 'Can edit role definitions',
    detail: 'roleDefinitions/write lets the holder add permissions to a custom role it can use.',
  },
  {
    re: /^microsoft\.compute\/virtualmachines\/runcommand\/action$|^microsoft\.compute\/virtualmachines\/extensions\/write$/i,
    sev: 'high',
    title: 'VM run-command / extension write (code exec)',
    detail:
      'Run-command / VM extensions execute arbitrary code as SYSTEM/root on the VM - and inherit its managed identity.',
  },
  {
    re: /^microsoft\.storage\/storageaccounts\/listkeys\/action$/i,
    sev: 'high',
    title: 'Storage account listKeys',
    detail: 'listKeys returns the account access keys → full data-plane access bypassing RBAC.',
  },
  {
    re: /^microsoft\.keyvault\/vaults\/\*$|^microsoft\.keyvault\/\*$/i,
    sev: 'high',
    title: 'Key Vault wildcard',
    detail: 'Wildcard Key Vault management access (and often the path to its data plane).',
  },
];

interface RoleDef {
  roleName?: string;
  roleType?: string;
  type?: string;
  assignableScopes?: string[];
  permissions?: { actions?: string[]; notActions?: string[]; dataActions?: string[]; notDataActions?: string[] }[];
  properties?: Record<string, unknown>;
}

function analyzeDefs(items: RoleDef[], findings: Finding[]): void {
  for (const d0 of items) {
    const d = (d0.properties ? { ...d0, ...(d0.properties as object) } : d0) as RoleDef;
    const name = String(d.roleName ?? 'custom-role');
    if (String(d.roleType ?? d.type ?? '').toLowerCase() === 'builtinrole') continue;
    const where = `role "${name}"`;
    const perms = asArr<Record<string, string[]>>(d.permissions);
    const actions: string[] = [];
    const dataActions: string[] = [];
    for (const pm of perms) {
      actions.push(...asArr<string>(pm.actions).map(String));
      dataActions.push(...asArr<string>(pm.dataActions).map(String));
    }

    if (actions.includes('*'))
      findings.push({
        sev: 'critical',
        title: 'Custom role grants "*" (all actions)',
        detail: 'Equivalent to Owner (minus data-plane) - not least-privilege.',
        where,
        fix: 'Enumerate only the action strings the role needs.',
      });

    for (const act of actions) {
      for (const da of DANGER_ACTIONS) {
        if (da.re.test(act)) {
          findings.push({
            sev: da.sev,
            title: `${da.title} (${act})`,
            detail: da.detail,
            where,
            fix: 'Remove unless essential; if needed, pair with a narrow assignableScope and an ABAC condition.',
          });
        }
      }
    }

    const wildSvc = actions.filter((a) => /\/\*$/.test(a) && a !== '*');
    if (wildSvc.length > 0)
      findings.push({
        sev: 'high',
        title: `Wildcard action scopes (${[...new Set(wildSvc)].slice(0, 4).join(', ')})`,
        detail: '"<provider>/.../*" grants every operation under that path, including future ones.',
        where,
        fix: 'List explicit operations instead of trailing "/*".',
      });

    if (dataActions.includes('*') || dataActions.some((a) => /microsoft\.keyvault\/vaults\/secrets\//i.test(a)))
      findings.push({
        sev: 'high',
        title: 'Broad data-plane actions',
        detail: 'dataActions includes "*" or Key Vault secret access - direct access to stored data/secrets.',
        where,
        fix: 'Scope dataActions to the specific data operations required.',
      });

    const scopes = asArr<string>(d.assignableScopes).map(String);
    if (scopes.some((s) => s === '/' || /\/providers\/Microsoft\.Management\/managementGroups\//i.test(s)))
      findings.push({
        sev: 'high',
        title: 'Custom role assignable at root / management-group scope',
        detail: `assignableScopes includes ${scopes.find((s) => s === '/' || /managementGroups/i.test(s))} - the role can be granted very broadly.`,
        where,
        fix: 'Limit assignableScopes to specific subscriptions / resource groups.',
      });
  }
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(trimmed);
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return { error: (e as Error).message, inputType: '', count: 0, findings: [] };
  }
  const root = doc as Record<string, unknown>;
  // ARM list wrapper { value: [...] }
  const list: unknown[] = Array.isArray(doc)
    ? (doc as unknown[])
    : Array.isArray(root.value)
      ? (root.value as unknown[])
      : root.roleName || root.permissions || root.principalId || root.roleDefinitionId || root.properties
        ? [root]
        : [];
  if (list.length === 0)
    return {
      error:
        'No assignments or role definitions found. Expected `az role assignment list` / `az role definition list` JSON (array, {value:[]}, or single object).',
      inputType: '',
      count: 0,
      findings: [],
    };

  const isDef = (o: unknown) => {
    const r = o as Record<string, unknown>;
    const p = (r.properties as Record<string, unknown>) ?? r;
    return Array.isArray(p.permissions) || !!p.roleName;
  };
  const findings: Finding[] = [];
  const defs = list.filter(isDef);
  const assigns = list.filter((o) => !isDef(o));

  if (defs.length) analyzeDefs(defs as RoleDef[], findings);
  if (assigns.length) analyzeAssignments(assigns as Assignment[], findings);

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const inputType =
    defs.length && assigns.length
      ? 'Mixed (assignments + role definitions)'
      : defs.length
        ? 'Custom role definition(s)'
        : 'Role assignment(s)';
  return { inputType, count: list.length, findings };
}

const SAMPLE_ASSIGN = JSON.stringify(
  [
    {
      roleDefinitionName: 'Owner',
      principalName: 'app-deployer',
      principalType: 'ServicePrincipal',
      scope: '/subscriptions/00000000-0000-0000-0000-000000000000',
    },
    {
      roleDefinitionName: 'User Access Administrator',
      principalName: 'contractor#EXT#@partner.com',
      principalType: 'User',
      scope: '/providers/Microsoft.Management/managementGroups/root',
    },
    {
      roleDefinitionName: 'Reader',
      principalName: 'audit-group',
      principalType: 'Group',
      scope: '/subscriptions/0000/resourceGroups/rg-logs',
    },
  ],
  null,
  2
);

const SAMPLE_DEF = JSON.stringify(
  {
    roleName: 'Deployer',
    roleType: 'CustomRole',
    assignableScopes: ['/'],
    permissions: [
      {
        actions: [
          'Microsoft.Authorization/roleAssignments/write',
          'Microsoft.Compute/virtualMachines/runCommand/action',
          'Microsoft.Storage/*',
        ],
        notActions: [],
        dataActions: [],
        notDataActions: [],
      },
    ],
  },
  null,
  2
);

export default function AzureRbacAnalyzer(): JSX.Element {
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Azure RBAC Analyzer</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste <span className="font-mono text-tool">az role assignment list -o json</span> or{' '}
          <span className="font-mono text-tool">az role definition list --custom-role-only -o json</span>. Scored for
          privileged roles at root/management-group/subscription scope, service-principal &amp; guest grants, legacy
          co-admins, and custom-role escalation (roleAssignments/write, elevateAccess, VM run-command, listKeys).
          Nothing leaves your browser.
        </p>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            type="button"
            onClick={() => setInput(SAMPLE_ASSIGN)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load assignments example
          </button>
          <button
            type="button"
            onClick={() => setInput(SAMPLE_DEF)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load role-definition example
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

      <label htmlFor="az-input" className="sr-only">
        Azure RBAC JSON
      </label>
      <Textarea
        id="az-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='[ { "roleDefinitionName": "Owner", "principalType": "ServicePrincipal", "scope": "/subscriptions/…" } ]'
        rows={12}
        spellCheck={false}
        aria-label="Azure RBAC JSON"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Input:</span> <span className="font-mono">{analysis.inputType}</span>
              </span>
              <span>
                <span className="text-muted">Items:</span> <span className="font-mono">{analysis.count}</span>
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
                No high-risk assignments / role definitions matched. Still review against your least-privilege baseline
                + PIM.
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
