import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * Kubernetes RBAC Analyzer - 100% client-side.
 *
 * Paste `kubectl get clusterroles,roles,clusterrolebindings,rolebindings
 * -o json` (a List with items[]) or a single Role / ClusterRole /
 * RoleBinding / ClusterRoleBinding object. Rules and bindings are scored
 * for the privilege-escalation and over-grant patterns attackers abuse:
 * wildcard verbs/resources, escalate/bind/impersonate, cluster-wide
 * secret read, pod exec, cluster-admin bindings, anonymous subjects.
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
  objects: number;
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

interface K8sObj {
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  rules?: { apiGroups?: string[]; resources?: string[]; verbs?: string[]; resourceNames?: string[] }[];
  roleRef?: { kind?: string; name?: string };
  subjects?: { kind?: string; name?: string; namespace?: string }[];
}

const has = (arr: unknown, v: string) => Array.isArray(arr) && (arr as string[]).map(String).includes(v);
const wildcards = (arr: unknown) => Array.isArray(arr) && (arr as string[]).includes('*');

function analyzeRole(o: K8sObj, findings: Finding[]): void {
  const ns = o.metadata?.namespace;
  const scope = o.kind === 'ClusterRole' ? 'cluster-wide' : `namespace ${ns ?? '?'}`;
  const where = `${o.kind}/${o.metadata?.name ?? '?'} (${scope})`;

  for (const r of o.rules ?? []) {
    const verbs = (r.verbs ?? []).map(String);
    const resources = (r.resources ?? []).map(String);
    const verbWild = wildcards(verbs);
    const resWild = wildcards(resources);

    if (verbWild && resWild) {
      findings.push({
        sev: o.kind === 'ClusterRole' ? 'critical' : 'high',
        title: 'Wildcard verbs on wildcard resources',
        detail: `Rule grants verbs:["*"] on resources:["*"]${o.kind === 'ClusterRole' ? ' cluster-wide - effectively cluster-admin.' : ' in this namespace - namespace-admin.'}`,
        where,
        fix: 'Enumerate the exact verbs and resources required; never "*" on "*".',
      });
    } else {
      if (verbWild)
        findings.push({
          sev: 'high',
          title: 'Wildcard verbs ("*")',
          detail: `All verbs (get/list/create/update/delete/…) allowed on ${resources.join(', ') || 'the listed resources'}.`,
          where,
          fix: 'List only the verbs needed (e.g. ["get","list"]).',
        });
      if (resWild)
        findings.push({
          sev: 'high',
          title: 'Wildcard resources ("*")',
          detail: `Verbs ${verbs.join(', ')} apply to every resource type${wildcards(r.apiGroups) ? ' across every API group' : ''}.`,
          where,
          fix: 'Restrict to specific resources (and apiGroups).',
        });
    }

    if (has(verbs, 'escalate'))
      findings.push({
        sev: 'critical',
        title: 'verb: escalate on RBAC',
        detail:
          'The "escalate" verb lets the holder grant itself permissions beyond its own - direct privilege escalation.',
        where,
        fix: 'Remove "escalate" unless this is a controller that genuinely needs it; scope to specific roles.',
      });
    if (has(verbs, 'bind'))
      findings.push({
        sev: 'critical',
        title: 'verb: bind on RBAC',
        detail: '"bind" lets the holder create bindings to roles it does not itself hold - privilege escalation.',
        where,
        fix: 'Remove "bind" or constrain with resourceNames to specific safe roles.',
      });
    if (has(verbs, 'impersonate'))
      findings.push({
        sev: 'critical',
        title: 'verb: impersonate',
        detail: 'Allows acting as any user / group / service account - full identity takeover within scope.',
        where,
        fix: 'Remove impersonate, or restrict with resourceNames to a specific principal.',
      });

    const isSecret = has(resources, 'secrets') || resWild;
    const canRead = verbWild || verbs.some((v) => ['get', 'list', 'watch'].includes(v));
    if (isSecret && canRead) {
      findings.push({
        sev: o.kind === 'ClusterRole' ? 'critical' : 'high',
        title: 'Secret read access',
        detail: `Can read Secrets${o.kind === 'ClusterRole' ? ' cluster-wide (every namespace)' : ' in this namespace'} - service-account tokens, credentials, TLS keys.`,
        where,
        fix: 'Scope to specific secrets via resourceNames; avoid cluster-wide secret read.',
      });
    }

    const subres = resources.join(',');
    if (/pods\/exec|pods\/attach|pods\/portforward/.test(subres)) {
      findings.push({
        sev: 'high',
        title: 'pods/exec | attach | portforward',
        detail: 'Shell/console into running pods - code execution on workloads, a common lateral-movement primitive.',
        where,
        fix: 'Restrict to break-glass roles; audit who is bound.',
      });
    }
    if (has(resources, 'pods') && (verbWild || verbs.includes('create'))) {
      findings.push({
        sev: 'high',
        title: 'pods: create',
        detail:
          'Creating pods can be abused to mount the host filesystem / hostPath or run privileged containers → node takeover.',
        where,
        fix: 'Gate pod creation behind admission policy (PSA/Kyverno/OPA); limit who can create pods.',
      });
    }
    if (has(resources, 'nodes/proxy') || has(resources, 'nodes')) {
      findings.push({
        sev: 'high',
        title: 'nodes / nodes/proxy access',
        detail: 'Node/kubelet API access can expose all pods’ secrets and enable container breakout.',
        where,
        fix: 'Remove unless this is a node-level controller.',
      });
    }
    if (
      (has(r.apiGroups, 'certificates.k8s.io') &&
        /certificatesigningrequests/.test(subres) &&
        (verbWild || verbs.includes('create'))) ||
      has(resources, 'tokenrequests') ||
      /serviceaccounts\/token/.test(subres)
    ) {
      findings.push({
        sev: 'high',
        title: 'CSR signing / SA token request',
        detail:
          'Issuing certificates or service-account tokens lets the holder mint new identities - persistence & escalation.',
        where,
        fix: 'Restrict to the controllers that require it.',
      });
    }
  }
}

function analyzeBinding(o: K8sObj, findings: Finding[]): void {
  const where = `${o.kind}/${o.metadata?.name ?? '?'}`;
  const roleName = o.roleRef?.name ?? '';
  const adminRoles = ['cluster-admin', 'admin', 'edit'];
  for (const s of o.subjects ?? []) {
    const sName = s.name ?? '';
    const anon = sName === 'system:anonymous' || sName === 'system:unauthenticated';
    const allAuthed = sName === 'system:authenticated';
    if (anon) {
      findings.push({
        sev: 'critical',
        title: `RBAC granted to anonymous (${o.kind} → ${roleName})`,
        detail: `Subject ${sName} binds the cluster's unauthenticated identity to ${roleName} - any unauthenticated API call gets these rights.`,
        where,
        fix: 'Delete this binding immediately; never bind roles to system:anonymous/unauthenticated.',
      });
    } else if (allAuthed && adminRoles.includes(roleName)) {
      findings.push({
        sev: 'critical',
        title: `Powerful role bound to ALL authenticated users (${roleName})`,
        detail: 'Every authenticated principal (including every service account) gets this role.',
        where,
        fix: 'Bind to specific users/groups/service accounts, not system:authenticated.',
      });
    }
    if (roleName === 'cluster-admin' && o.kind === 'ClusterRoleBinding') {
      findings.push({
        sev: 'critical',
        title: `cluster-admin ClusterRoleBinding → ${s.kind}/${sName}`,
        detail: 'Full, unrestricted control of the entire cluster granted to this subject.',
        where,
        fix: 'Confirm this subject must be cluster-admin; prefer narrowly-scoped roles.',
      });
    } else if (adminRoles.includes(roleName)) {
      findings.push({
        sev: 'high',
        title: `Built-in "${roleName}" role bound → ${s.kind}/${sName}`,
        detail: `The aggregated built-in "${roleName}" role is broad. Verify the subject needs it.`,
        where,
        fix: 'Prefer a least-privilege custom Role over the built-in admin/edit roles.',
      });
    }
    if (s.kind === 'ServiceAccount' && roleName === 'cluster-admin') {
      findings.push({
        sev: 'critical',
        title: 'Service account is cluster-admin',
        detail: `SA ${s.namespace ?? ''}/${sName} is cluster-admin - a compromised pod with this SA token owns the cluster.`,
        where,
        fix: 'Never give workloads cluster-admin; scope SA permissions to the workload’s needs.',
      });
    }
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
    return {
      error: `${(e as Error).message}. Tip: paste \`kubectl get … -o json\` (JSON, not YAML).`,
      objects: 0,
      findings: [],
    };
  }

  const root = doc as Record<string, unknown>;
  const items: K8sObj[] = Array.isArray(root.items)
    ? (root.items as K8sObj[])
    : Array.isArray(doc)
      ? (doc as K8sObj[])
      : root.kind
        ? [root as K8sObj]
        : [];

  if (items.length === 0) {
    return {
      error:
        'No RBAC objects found. Expected a List ({ items: [...] }) or a single Role/ClusterRole/(Cluster)RoleBinding.',
      objects: 0,
      findings: [],
    };
  }

  const findings: Finding[] = [];
  let analysed = 0;
  for (const o of items) {
    const kind = o.kind ?? '';
    if (kind === 'Role' || kind === 'ClusterRole') {
      analyzeRole(o, findings);
      analysed++;
    } else if (kind === 'RoleBinding' || kind === 'ClusterRoleBinding') {
      analyzeBinding(o, findings);
      analysed++;
    }
  }
  if (analysed === 0) {
    return {
      error: 'No Role/ClusterRole/RoleBinding/ClusterRoleBinding objects recognised (check the `kind` fields).',
      objects: items.length,
      findings: [],
    };
  }

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { objects: analysed, findings };
}

const SAMPLE = JSON.stringify(
  {
    apiVersion: 'v1',
    kind: 'List',
    items: [
      {
        kind: 'ClusterRole',
        metadata: { name: 'app-reader' },
        rules: [{ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }],
      },
      {
        kind: 'ClusterRoleBinding',
        metadata: { name: 'ci-admin' },
        roleRef: { kind: 'ClusterRole', name: 'cluster-admin' },
        subjects: [{ kind: 'ServiceAccount', name: 'ci-runner', namespace: 'ci' }],
      },
      {
        kind: 'Role',
        metadata: { name: 'reader', namespace: 'prod' },
        rules: [{ apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list'] }],
      },
    ],
  },
  null,
  2
);

export default function K8sRbacAnalyzer(): JSX.Element {
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Kubernetes RBAC Analyzer</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste{' '}
          <span className="font-mono text-tool">
            kubectl get clusterroles,roles,clusterrolebindings,rolebindings -o json
          </span>{' '}
          (or a single object). Rules &amp; bindings are scored for the escalation patterns attackers abuse - wildcard
          verbs/resources, escalate/bind/impersonate, cluster-wide secret read, pod exec, cluster-admin &amp; anonymous
          bindings. Nothing leaves your browser.
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

      <label htmlFor="rbac-input" className="sr-only">
        Kubernetes RBAC JSON
      </label>
      <Textarea
        id="rbac-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "kind": "ClusterRole", "metadata": { "name": "x" }, "rules": [ { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] } ] }'
        rows={12}
        spellCheck={false}
        aria-label="Kubernetes RBAC JSON"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">RBAC objects analysed:</span>{' '}
                <span className="font-mono">{analysis.objects}</span>
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
              <span>No high-risk RBAC patterns detected in the supplied objects.</span>
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
