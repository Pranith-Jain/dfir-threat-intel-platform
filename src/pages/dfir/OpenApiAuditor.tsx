import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * OpenAPI / Swagger Security Auditor - 100% client-side.
 *
 * Paste an OpenAPI 3.x or Swagger 2.0 spec (JSON; YAML is best-effort).
 * Operations are checked against the patterns behind the OWASP API
 * Security Top 10: unauthenticated endpoints, no global security,
 * BOLA/IDOR-prone object ids, API keys in the query string, weak/Basic
 * auth, plaintext HTTP servers, missing 401/403/429, mass-assignment,
 * unbounded params, and exposed debug/admin paths. Nothing leaves the
 * browser.
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
  spec: string;
  operations: number;
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

/* Best-effort indentation YAML → object (handles the common OpenAPI subset:
   maps, "- " lists, list-of-maps, [inline] arrays, quoted scalars). JSON is
   exact; YAML is a convenience fallback. */
function parseYaml(src: string): unknown {
  const lines = src
    .split('\n')
    .map((l) => l.replace(/\t/g, '  '))
    .filter((l) => l.trim() !== '' && !/^\s*#/.test(l))
    .map((l) => ({ indent: l.length - l.trimStart().length, text: l.trimEnd() }));
  let pos = 0;
  const scalar = (v: string): unknown => {
    const t = v.trim();
    if (!t) return null;
    if ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'"))) return t.slice(1, -1);
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null' || t === '~') return null;
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    if (t.startsWith('[') && t.endsWith(']'))
      return t
        .slice(1, -1)
        .split(',')
        .map((s) => scalar(s))
        .filter((s) => s !== null);
    return t;
  };
  function block(minIndent: number): unknown {
    const first = lines[pos];
    if (!first) return null;
    const lvl = first.indent;
    if (first.text.trim().startsWith('- ')) {
      const arr: unknown[] = [];
      while (pos < lines.length && lines[pos]!.indent === lvl && lines[pos]!.text.trim().startsWith('- ')) {
        const rest = lines[pos]!.text.trim().slice(2);
        if (rest.includes(':') && !/^["']/.test(rest)) {
          lines[pos] = { indent: lvl + 2, text: ' '.repeat(lvl + 2) + rest };
          arr.push(block(lvl + 2));
        } else {
          arr.push(scalar(rest));
          pos++;
        }
      }
      return arr;
    }
    const obj: Record<string, unknown> = {};
    while (pos < lines.length && lines[pos]!.indent === lvl && lines[pos]!.indent >= minIndent) {
      const txt = lines[pos]!.text.trim();
      const ci = txt.indexOf(':');
      if (ci === -1) {
        pos++;
        continue;
      }
      const key = txt
        .slice(0, ci)
        .trim()
        .replace(/^["']|["']$/g, '');
      const val = txt.slice(ci + 1).trim();
      pos++;
      if (val === '') {
        obj[key] = pos < lines.length && lines[pos]!.indent > lvl ? block(lvl + 1) : null;
      } else {
        obj[key] = scalar(val);
      }
    }
    return obj;
  }
  return block(0);
}

const DEBUG_PATH = /\/(debug|actuator|swagger|api-docs|graphiql|internal|__|metrics|health\/detail|trace|admin)\b/i;
const ID_PARAM = /\{[^}]*\b(id|uuid|guid|user[_-]?id|account|customer|order|email)\b[^}]*\}/i;

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (_catchErr) {
    console.error('analyze failed:', errMessage(_catchErr));
    try {
      doc = parseYaml(trimmed) as Record<string, unknown>;
      if (!doc || typeof doc !== 'object') throw new Error('not an object');
    } catch (e) {
      console.error('analyze failed:', errMessage(e));
      return {
        error: `Could not parse as JSON or YAML (${(e as Error).message}). Tip: export the spec as JSON.`,
        spec: '',
        operations: 0,
        findings: [],
      };
    }
  }

  const isV3 = typeof doc.openapi === 'string';
  const isV2 = String(doc.swagger ?? '') === '2.0';
  if (!isV3 && !isV2 && !doc.paths)
    return {
      error: 'No `openapi`/`swagger` version or `paths` - does not look like an OpenAPI/Swagger document.',
      spec: '',
      operations: 0,
      findings: [],
    };

  const findings: Finding[] = [];
  const globalSecurity = Array.isArray(doc.security) ? (doc.security as unknown[]) : null;
  const comp = (doc.components as Record<string, unknown>) ?? {};
  const schemes =
    (isV3
      ? (comp.securitySchemes as Record<string, Record<string, unknown>>)
      : (doc.securityDefinitions as Record<string, Record<string, unknown>>)) ?? {};

  if (!globalSecurity || globalSecurity.length === 0)
    findings.push({
      sev: 'high',
      title: 'No global security requirement',
      detail:
        'The spec sets no top-level `security`. Every operation is unauthenticated unless it declares its own - fail-open by default (OWASP API2/API5).',
      where: 'document root',
      fix: 'Declare a global `security` and explicitly opt specific public endpoints out with `security: []`.',
    });
  if (Object.keys(schemes).length === 0)
    findings.push({
      sev: 'high',
      title: 'No security schemes defined',
      detail: 'No securitySchemes/securityDefinitions - the API documents no way to authenticate at all.',
      where: 'components.securitySchemes',
      fix: 'Define an OAuth2/OIDC (or at minimum bearer) scheme and require it.',
    });

  for (const [name, s] of Object.entries(schemes)) {
    const typ = String(s.type ?? '').toLowerCase();
    if ((isV2 && typ === 'apikey' && s.in === 'query') || (isV3 && typ === 'apikey' && s.in === 'query'))
      findings.push({
        sev: 'high',
        title: `API key passed in query string (${name})`,
        detail:
          'Query strings are logged by proxies, gateways, and browser history - an API key there is effectively logged plaintext.',
        where: `securityScheme ${name}`,
        fix: 'Move the API key to a header (or use OAuth2 bearer).',
      });
    if (typ === 'basic' || (isV3 && typ === 'http' && String(s.scheme).toLowerCase() === 'basic'))
      findings.push({
        sev: 'medium',
        title: `HTTP Basic auth scheme (${name})`,
        detail: 'Basic auth sends reusable base64 credentials on every request - no rotation, no scoping.',
        where: `securityScheme ${name}`,
        fix: 'Prefer OAuth2/OIDC bearer tokens with short expiry and scopes.',
      });
    if (typ === 'oauth2') {
      const flows = (s.flows ?? s) as Record<string, Record<string, unknown>>;
      const anyScopes = Object.values(flows).some(
        (f) => f && typeof f === 'object' && Object.keys((f.scopes as object) ?? {}).length > 0
      );
      if (!anyScopes)
        findings.push({
          sev: 'medium',
          title: `OAuth2 scheme without scopes (${name})`,
          detail: 'No scopes defined - tokens are all-or-nothing, defeating least-privilege (OWASP API5 BFLA).',
          where: `securityScheme ${name}`,
          fix: 'Define granular scopes and require them per-operation.',
        });
    }
  }

  // Servers / schemes over plaintext HTTP
  const servers = (doc.servers as { url?: string }[]) ?? [];
  if (servers.some((sv) => /^http:\/\//i.test(String(sv.url ?? ''))))
    findings.push({
      sev: 'high',
      title: 'Server served over plaintext HTTP',
      detail: 'A `servers` entry uses http:// - tokens & data are interceptable.',
      where: 'servers',
      fix: 'Serve the API exclusively over HTTPS.',
    });
  if (isV2 && Array.isArray(doc.schemes) && (doc.schemes as string[]).map(String).includes('http'))
    findings.push({
      sev: 'high',
      title: 'API allows plaintext HTTP scheme',
      detail: '`schemes` includes "http".',
      where: 'schemes',
      fix: 'Restrict to ["https"].',
    });

  const paths = (doc.paths as Record<string, Record<string, unknown>>) ?? {};
  const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];
  let opCount = 0;

  for (const [p, item] of Object.entries(paths)) {
    if (!item || typeof item !== 'object') continue;
    for (const m of METHODS) {
      const op = item[m] as Record<string, unknown> | undefined;
      if (!op || typeof op !== 'object') continue;
      opCount++;
      const where = `${m.toUpperCase()} ${p}`;
      const opSec = op.security as unknown[] | undefined;
      const effectivelyOpen =
        (opSec && opSec.length === 0) || (!opSec && (!globalSecurity || globalSecurity.length === 0));
      const explicitlyDisabled = Array.isArray(opSec) && opSec.length === 0 && !!globalSecurity?.length;

      if (explicitlyDisabled)
        findings.push({
          sev: 'critical',
          title: 'Authentication explicitly disabled',
          detail: `\`security: []\` overrides the global requirement - this endpoint is public.`,
          where,
          fix: 'Remove the empty security override unless this is intentionally a public endpoint.',
        });
      else if (effectivelyOpen)
        findings.push({
          sev: m === 'get' ? 'high' : 'critical',
          title: 'Unauthenticated endpoint',
          detail: `No operation or global \`security\` applies - anyone can call this ${m.toUpperCase()}${m !== 'get' ? ' (state-changing!)' : ''} (OWASP API2).`,
          where,
          fix: 'Require an auth scheme on this operation (or globally).',
        });

      if (!effectivelyOpen && ID_PARAM.test(p) && /get|put|patch|delete/.test(m))
        findings.push({
          sev: 'medium',
          title: 'Possible BOLA / IDOR (object id in path)',
          detail: `Path takes an object identifier. Authentication ≠ authorization - confirm the handler checks the caller OWNS this object (OWASP API1, the #1 API risk).`,
          where,
          fix: 'Enforce object-level authorization server-side; never trust the id alone.',
        });

      const responses = (op.responses as Record<string, unknown>) ?? {};
      const codes = Object.keys(responses);
      if (!effectivelyOpen && !codes.includes('401') && !codes.includes('403'))
        findings.push({
          sev: 'low',
          title: 'No 401/403 response documented',
          detail:
            'A secured operation should document its auth-failure responses (contract clarity + client handling).',
          where,
          fix: 'Add 401 and 403 responses.',
        });
      if (!codes.includes('429'))
        findings.push({
          sev: 'low',
          title: 'No 429 (rate limiting) documented',
          detail:
            'No 429 anywhere suggests no documented rate limiting - OWASP API4 (unrestricted resource consumption).',
          where,
          fix: 'Add 429 responses and enforce rate limits at the gateway.',
        });

      if (DEBUG_PATH.test(p))
        findings.push({
          sev: effectivelyOpen ? 'critical' : 'high',
          title: 'Debug / admin / docs path exposed',
          detail: `\`${p}\` looks like a debug, actuator, internal, metrics, or admin surface${effectivelyOpen ? ' AND it is unauthenticated' : ''}.`,
          where,
          fix: 'Remove from the public API or strongly authenticate + network-restrict it.',
        });

      // Mass assignment: request body schema allows arbitrary properties
      const rb = (op.requestBody as Record<string, unknown>) ?? null;
      const content = rb ? ((rb.content as Record<string, Record<string, unknown>>) ?? {}) : {};
      for (const ct of Object.values(content)) {
        const sch = (ct.schema as Record<string, unknown>) ?? {};
        if (sch.type === 'object' && sch.additionalProperties !== false && !sch.$ref && !sch.properties)
          findings.push({
            sev: 'medium',
            title: 'Mass-assignment risk (free-form request body)',
            detail: `Request body is an object with no \`properties\` and additionalProperties not false - clients can submit arbitrary fields (OWASP API6 / API3).`,
            where,
            fix: 'Define an explicit allow-list schema and set additionalProperties: false.',
          });
      }

      // Unbounded array params (resource consumption)
      const params = (op.parameters as Record<string, unknown>[]) ?? [];
      for (const pr of params) {
        const sch = (pr.schema as Record<string, unknown>) ?? pr;
        if ((sch.type === 'array' || pr.type === 'array') && sch.maxItems == null)
          findings.push({
            sev: 'low',
            title: `Unbounded array parameter "${String(pr.name ?? '?')}"`,
            detail: 'Array parameter with no maxItems - a caller can send an enormous list (OWASP API4).',
            where,
            fix: 'Set maxItems on array parameters.',
          });
      }

      if (op.deprecated === true)
        findings.push({
          sev: 'info',
          title: 'Deprecated operation still served',
          detail: 'Deprecated endpoints are often unmaintained and unmonitored - a soft target.',
          where,
          fix: 'Plan removal; monitor usage and sunset.',
        });
    }
  }

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  return {
    spec: isV3 ? `OpenAPI ${String(doc.openapi)}` : isV2 ? 'Swagger 2.0' : 'OpenAPI-like',
    operations: opCount,
    findings,
  };
}

const SAMPLE = JSON.stringify(
  {
    openapi: '3.0.3',
    info: { title: 'Demo', version: '1.0' },
    servers: [{ url: 'http://api.example.com' }],
    components: { securitySchemes: { ApiKeyQuery: { type: 'apiKey', in: 'query', name: 'api_key' } } },
    paths: {
      '/users/{id}': {
        get: { responses: { '200': {} } },
        delete: { security: [], responses: { '200': {} } },
      },
      '/actuator/env': { get: { responses: { '200': {} } } },
    },
  },
  null,
  2
);

export default function OpenApiAuditor(): JSX.Element {
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">OpenAPI / Swagger Auditor</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste an OpenAPI 3.x / Swagger 2.0 spec (JSON; YAML best-effort). Checked against the OWASP API Security Top
          10 - unauthenticated &amp; BOLA-prone endpoints, query-string API keys, Basic/no-scope auth, plaintext HTTP,
          mass assignment, unbounded params, debug paths. Nothing leaves your browser.
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
      <label htmlFor="oas-input" className="sr-only">
        OpenAPI / Swagger spec
      </label>
      <Textarea
        id="oas-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "openapi": "3.0.0", "paths": { "/users/{id}": { "get": { "responses": { "200": {} } } } } }'
        rows={12}
        spellCheck={false}
        aria-label="OpenAPI / Swagger spec"
      />
      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}
      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Spec:</span> <span className="font-mono">{analysis.spec}</span>
              </span>
              <span>
                <span className="text-muted">Operations:</span> <span className="font-mono">{analysis.operations}</span>
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
                No issues matched the ruleset. Spec-level checks ≠ a pentest - verify object-level authz at runtime.
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
