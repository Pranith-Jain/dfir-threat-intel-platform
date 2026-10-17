import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * GraphQL Security Analyzer - 100% client-side.
 *
 * Paste an introspection result (`{ "data": { "__schema": … } }`) or
 * SDL. Flags introspection exposure, sensitive/PII fields, auth-less
 * mutations/subscriptions, and recursive types that enable depth/
 * complexity DoS - the GraphQL-specific slice of the OWASP API Top 10
 * (API4 resource consumption, API3 excessive data exposure, API5 BFLA).
 * Nothing leaves the browser.
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
  mode: string;
  types: number;
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

const SENSITIVE =
  /\b(password|passwd|pwd|pass_?hash|secret|api_?key|access_?token|refresh_?token|priv(ate)?_?key|ssn|social_?security|credit_?card|card_?number|cvv|pin|otp|mfa_?secret|session_?token|bank_?account|routing_?number|salt|seed_?phrase|mnemonic)\b/i;

type TypeMap = Record<string, { fields: { name: string; type: string }[]; kind: string }>;

/** Strip GraphQL type wrappers ([X!]! → X). */
function baseType(t: string): string {
  return t.replace(/[[\]!]/g, '').trim();
}

function fromIntrospection(schema: Record<string, unknown>): {
  types: TypeMap;
  query?: string;
  mutation?: string;
  subscription?: string;
} {
  const types: TypeMap = {};
  const arr = (schema.types as Record<string, unknown>[]) ?? [];
  for (const t of arr) {
    const name = String(t.name ?? '');
    if (!name || name.startsWith('__')) continue;
    const fields = [
      ...((t.fields as Record<string, unknown>[]) ?? []),
      ...((t.inputFields as Record<string, unknown>[]) ?? []),
    ].map((fd) => {
      // Resolve nested ofType chain to a base name.
      let ty = fd.type as Record<string, unknown> | undefined;
      let nm = '';
      let depth = 0;
      while (ty && depth++ < 8) {
        if (ty.name) nm = String(ty.name);
        ty = ty.ofType as Record<string, unknown> | undefined;
      }
      return { name: String(fd.name ?? ''), type: nm };
    });
    types[name] = { fields, kind: String(t.kind ?? 'OBJECT') };
  }
  return {
    types,
    query: (schema.queryType as { name?: string })?.name,
    mutation: (schema.mutationType as { name?: string })?.name,
    subscription: (schema.subscriptionType as { name?: string })?.name,
  };
}

function fromSdl(sdl: string): { types: TypeMap; query?: string; mutation?: string; subscription?: string } {
  const types: TypeMap = {};
  const re = /\b(type|input|interface)\s+([A-Za-z_]\w*)[^{]*\{([^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sdl)) !== null) {
    const kind = m[1]!.toUpperCase();
    const name = m[2]!;
    const body = m[3]!;
    const fields = body
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .map((l) => {
        const fm = /^([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:\s*([[\]!\w]+)/.exec(l);
        return fm ? { name: fm[1]!, type: baseType(fm[2]!) } : null;
      })
      .filter((x): x is { name: string; type: string } => !!x);
    types[name] = { fields, kind };
  }
  const sm = /\bschema\s*\{([^}]*)\}/.exec(sdl);
  let query = types.Query ? 'Query' : undefined;
  let mutation = types.Mutation ? 'Mutation' : undefined;
  let subscription = types.Subscription ? 'Subscription' : undefined;
  if (sm) {
    const map = sm[1]!;
    query = /query\s*:\s*(\w+)/.exec(map)?.[1] ?? query;
    mutation = /mutation\s*:\s*(\w+)/.exec(map)?.[1] ?? mutation;
    subscription = /subscription\s*:\s*(\w+)/.exec(map)?.[1] ?? subscription;
  }
  return { types, query, mutation, subscription };
}

/** Detect a reference cycle among object types (recursive query DoS surface). */
function hasCycle(types: TypeMap): string | null {
  const state: Record<string, number> = {};
  let found: string | null = null;
  const visit = (name: string, path: string[]) => {
    if (found) return;
    if (state[name] === 1) {
      found = [...path.slice(path.indexOf(name)), name].join(' → ');
      return;
    }
    if (state[name] === 2 || !types[name]) return;
    state[name] = 1;
    for (const f of types[name]!.fields) {
      const b = baseType(f.type);
      if (types[b] && types[b]!.kind === 'OBJECT') visit(b, [...path, name]);
    }
    state[name] = 2;
  };
  for (const n of Object.keys(types)) {
    if (types[n]!.kind === 'OBJECT') visit(n, []);
    if (found) break;
  }
  return found;
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  let parsed: ReturnType<typeof fromIntrospection> | null = null;
  let mode = '';
  if (trimmed.startsWith('{')) {
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(trimmed) as Record<string, unknown>;
    } catch (e) {
      console.error('analyze failed:', errMessage(e));
      return { error: `JSON parse error: ${(e as Error).message}`, mode: '', types: 0, findings: [] };
    }
    const schema = ((doc.data as Record<string, unknown>)?.__schema ??
      doc.__schema ??
      (doc as Record<string, unknown>).schema) as Record<string, unknown> | undefined;
    if (!schema || !Array.isArray(schema.types))
      return {
        error: 'No __schema.types - expected an introspection result ({ "data": { "__schema": … } }).',
        mode: '',
        types: 0,
        findings: [],
      };
    parsed = fromIntrospection(schema);
    mode = 'Introspection JSON';
  } else if (/\b(type|schema|input|interface)\b/.test(trimmed)) {
    parsed = fromSdl(trimmed);
    mode = 'SDL';
  } else {
    return {
      error: 'Unrecognised input - paste an introspection JSON or GraphQL SDL.',
      mode: '',
      types: 0,
      findings: [],
    };
  }

  const findings: Finding[] = [];
  const { types, query, mutation, subscription } = parsed;

  if (mode === 'Introspection JSON')
    findings.push({
      sev: 'high',
      title: 'Introspection is enabled',
      detail:
        'You obtained a full introspection result from the server - in production this hands attackers the entire schema for free enumeration (OWASP API exposure).',
      where: '__schema',
      fix: 'Disable introspection in production (e.g. NODE_ENV gate / apollo introspection:false); allow it only in non-prod.',
    });

  // Sensitive fields on OBJECT output types
  for (const [tn, t] of Object.entries(types)) {
    if (t.kind !== 'OBJECT') continue;
    for (const fld of t.fields) {
      if (SENSITIVE.test(fld.name))
        findings.push({
          sev: 'high',
          title: `Sensitive field exposed: ${tn}.${fld.name}`,
          detail:
            'A credential/PII-looking field is queryable in the schema - excessive data exposure (OWASP API3); also a BOLA amplifier.',
          where: `${tn}.${fld.name}`,
          fix: 'Remove from the GraphQL type, or gate it behind field-level authorization and never return it by default.',
        });
    }
  }

  // Mutations / subscriptions - authz cannot be seen in the schema
  const mut = mutation && types[mutation];
  if (mut && mut.fields.length > 0)
    findings.push({
      sev: 'medium',
      title: `${mut.fields.length} mutation(s) exposed`,
      detail: `Mutations are state-changing and the schema carries no visible authorization. Each must enforce function-level authz server-side (OWASP API5 BFLA). e.g. ${mut.fields
        .slice(0, 5)
        .map((x) => x.name)
        .join(', ')}${mut.fields.length > 5 ? ' …' : ''}`,
      where: mutation,
      fix: 'Apply per-resolver auth (directive/middleware); verify object & function-level checks on every mutation.',
    });
  if (subscription && types[subscription] && types[subscription]!.fields.length > 0)
    findings.push({
      sev: 'low',
      title: 'Subscriptions exposed',
      detail:
        'Real-time subscriptions run over a long-lived transport (WS/SSE) - auth on the upgrade/connection is frequently missed.',
      where: subscription,
      fix: 'Authenticate the connection on connect and re-check authz per published event.',
    });

  // Recursive/cyclic types → unbounded query depth
  const cycle = hasCycle(types);
  if (cycle)
    findings.push({
      sev: 'medium',
      title: 'Recursive type relationship (query-depth DoS surface)',
      detail: `Cyclic object references (${cycle}) let a client nest a query arbitrarily deep and explode resolver/DB work - OWASP API4 unrestricted resource consumption.`,
      where: cycle,
      fix: 'Enforce a max query depth + cost/complexity limit and pagination; consider persisted queries.',
    });

  // Query breadth
  const q = query && types[query];
  if (q && q.fields.length > 40)
    findings.push({
      sev: 'info',
      title: `Large root Query surface (${q.fields.length} fields)`,
      detail: 'A very wide root query increases attack surface and makes per-field authz easy to miss.',
      where: query,
      fix: 'Review that every root field enforces authorization; split internal vs public schemas.',
    });

  if (mode === 'SDL' && !/@auth|@authenticated|@hasRole|@requires|@policy|@scope/i.test(trimmed))
    findings.push({
      sev: 'info',
      title: 'No auth directives visible in SDL',
      detail:
        'No @auth/@hasRole/@requires-style directives - authorization may be enforced in resolvers (not visible here). Cannot verify least-privilege from the schema alone.',
      where: 'schema',
      fix: 'Confirm resolver-level authorization exists for every query/mutation; consider schema directives for auditability.',
    });

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return { mode, types: Object.keys(types).length, findings };
}

const SAMPLE = `type Query { me: User, users: [User!]! }
type Mutation { deleteUser(id: ID!): Boolean, resetPassword(token: String!): Boolean }
type User {
  id: ID!
  email: String!
  passwordHash: String
  apiKey: String
  posts: [Post!]!
}
type Post { id: ID!, author: User!, title: String! }`;

export default function GraphqlAuditor(): JSX.Element {
  const [input, setInput] = useState('');
  const analysis = useMemo(() => analyze(input), [input]);
  const counts = useMemo(() => {
    const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    analysis?.findings.forEach((f) => (c[f.sev] += 1));
    return c;
  }, [analysis]);

  return (
    <DataPageLayout
      backTo="/dfir"
      maxWidthClass="max-w-4xl"
      icon={<ShieldAlert size={28} />}
      title="GraphQL Security Analyzer"
      description={
        <>
          Paste a GraphQL introspection result (<span className="font-mono text-tool">{'{ data: { __schema } }'}</span>)
          or SDL. Flags introspection exposure, sensitive/PII fields, auth-less mutations/subscriptions, and recursive
          types that enable query-depth DoS. Nothing leaves your browser.
        </>
      }
      headerExtra={
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setInput(SAMPLE)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load SDL example
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
      <label htmlFor="gql-input" className="sr-only">
        GraphQL introspection JSON or SDL
      </label>
      <Textarea
        id="gql-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "data": { "__schema": { "types": [ … ] } } }   - or paste SDL (type Query { … })'
        rows={12}
        spellCheck={false}
        aria-label="GraphQL introspection JSON or SDL"
      />
      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}
      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Source:</span> <span className="font-mono">{analysis.mode}</span>
              </span>
              <span>
                <span className="text-muted">Types:</span> <span className="font-mono">{analysis.types}</span>
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
                No schema-level issues matched. Authorization can’t be fully judged from a schema - verify resolver
                authz at runtime.
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
    </DataPageLayout>
  );
}
