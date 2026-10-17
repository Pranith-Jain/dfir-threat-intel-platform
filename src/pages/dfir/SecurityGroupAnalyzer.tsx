import { useMemo, useState } from 'react';
import type { Severity as Sev } from '../../components/severity';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldAlert, ShieldX, ShieldCheck, Info } from 'lucide-react';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

/**
 * Security Group / NSG Exposure Analyzer - 100% client-side.
 *
 * Paste AWS `aws ec2 describe-security-groups` JSON or an Azure NSG
 * (securityRules / ARM shape). Inbound rules open to the internet
 * (0.0.0.0/0, ::/0, "*", "Internet", "Any") are flagged, severity-ranked
 * by the service behind the port - SSH/RDP/databases/admin planes that
 * should never face the public internet. Nothing leaves the browser.
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
  cloud: string;
  groups: number;
  rulesChecked: number;
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

/** Port → {service, severity when exposed to the internet}. */
const PORT_RISK: Record<number, { svc: string; sev: Sev }> = {
  22: { svc: 'SSH', sev: 'critical' },
  23: { svc: 'Telnet', sev: 'critical' },
  135: { svc: 'MSRPC', sev: 'high' },
  139: { svc: 'NetBIOS', sev: 'high' },
  445: { svc: 'SMB', sev: 'critical' },
  161: { svc: 'SNMP', sev: 'high' },
  389: { svc: 'LDAP', sev: 'high' },
  636: { svc: 'LDAPS', sev: 'medium' },
  1433: { svc: 'MSSQL', sev: 'critical' },
  1521: { svc: 'Oracle DB', sev: 'critical' },
  2375: { svc: 'Docker API (plaintext)', sev: 'critical' },
  2376: { svc: 'Docker API (TLS)', sev: 'high' },
  2379: { svc: 'etcd', sev: 'critical' },
  3000: { svc: 'app / admin (3000)', sev: 'medium' },
  3306: { svc: 'MySQL', sev: 'critical' },
  3389: { svc: 'RDP', sev: 'critical' },
  5432: { svc: 'PostgreSQL', sev: 'critical' },
  5601: { svc: 'Kibana', sev: 'high' },
  5900: { svc: 'VNC', sev: 'critical' },
  5984: { svc: 'CouchDB', sev: 'critical' },
  5985: { svc: 'WinRM', sev: 'critical' },
  5986: { svc: 'WinRM (TLS)', sev: 'high' },
  6379: { svc: 'Redis', sev: 'critical' },
  6443: { svc: 'Kubernetes API', sev: 'critical' },
  7001: { svc: 'WebLogic', sev: 'high' },
  8020: { svc: 'Hadoop NameNode', sev: 'high' },
  8080: { svc: 'HTTP-alt / admin', sev: 'medium' },
  8443: { svc: 'HTTPS-alt / admin', sev: 'medium' },
  8888: { svc: 'Jupyter / admin', sev: 'high' },
  9000: { svc: 'app / admin (9000)', sev: 'medium' },
  9200: { svc: 'Elasticsearch', sev: 'critical' },
  9300: { svc: 'Elasticsearch transport', sev: 'critical' },
  10250: { svc: 'kubelet', sev: 'critical' },
  11211: { svc: 'memcached', sev: 'critical' },
  27017: { svc: 'MongoDB', sev: 'critical' },
  50070: { svc: 'Hadoop NameNode UI', sev: 'high' },
};

const WEB_PORTS = new Set([80, 443]);
const WORLD_V4 = new Set(['0.0.0.0/0', '0.0.0.0', '*', 'any', 'internet', 'all']);
const WORLD_V6 = new Set(['::/0', '::', '*', 'any', 'internet', 'all']);

function isWorld(cidr: string): 'v4' | 'v6' | null {
  const c = cidr.trim().toLowerCase();
  if (WORLD_V4.has(c)) return 'v4';
  if (WORLD_V6.has(c)) return 'v6';
  return null;
}

function toArray<T>(x: unknown): T[] {
  if (x == null) return [];
  return (Array.isArray(x) ? x : [x]) as T[];
}

/** Sensitive ports inside [from,to]; `allPorts` if the span covers everything. */
function classifySpan(
  from: number,
  to: number
): { allPorts: boolean; hits: { port: number; svc: string; sev: Sev }[] } {
  const allPorts = from <= 0 && to >= 65535;
  const hits: { port: number; svc: string; sev: Sev }[] = [];
  if (allPorts) return { allPorts, hits };
  for (const [p, meta] of Object.entries(PORT_RISK)) {
    const port = Number(p);
    if (port >= from && port <= to) hits.push({ port, svc: meta.svc, sev: meta.sev });
  }
  return { allPorts, hits };
}

function pushExposure(
  findings: Finding[],
  where: string,
  proto: string,
  from: number,
  to: number,
  fam: 'v4' | 'v6'
): void {
  const src = fam === 'v6' ? '::/0' : '0.0.0.0/0';
  const { allPorts, hits } = classifySpan(from, to);

  if (allPorts) {
    findings.push({
      sev: 'critical',
      title: `ALL ports open to the internet (${src})`,
      detail: `${proto.toUpperCase()} all ports are reachable from anywhere - every service on these hosts is internet-exposed.`,
      where,
      fix: 'Replace the source with specific CIDRs / a bastion / SG reference and open only the ports you serve.',
    });
    return;
  }

  if (hits.length === 0) {
    const onlyWeb = from === to && WEB_PORTS.has(from);
    if (onlyWeb) {
      findings.push({
        sev: 'info',
        title: `Port ${from} open to the internet (${src})`,
        detail:
          'Standard web port exposed publicly - expected for a public endpoint; confirm it is meant to be public.',
        where,
        fix: 'If this is not a public web endpoint, restrict the source range.',
      });
    } else {
      findings.push({
        sev: 'medium',
        title: `Port range ${from}-${to} open to the internet (${src})`,
        detail: `${proto.toUpperCase()} ${from}-${to} is reachable from anywhere. No well-known sensitive service in range, but a public range is rarely intended.`,
        where,
        fix: 'Narrow the source to specific CIDRs and the port span to exactly what is served.',
      });
    }
    return;
  }

  for (const h of hits) {
    findings.push({
      sev: h.sev,
      title: `${h.svc} (port ${h.port}) open to the internet (${src})`,
      detail: `${proto.toUpperCase()} ${h.port} (${h.svc}) is reachable from anywhere. Internet-facing ${h.svc} is a top initial-access / data-exposure vector.`,
      where,
      fix: `Restrict port ${h.port} to specific CIDRs, a bastion host, or a security-group reference - never 0.0.0.0/0.`,
    });
  }
}

function analyzeAws(doc: Record<string, unknown>): { groups: number; rules: number; findings: Finding[] } | null {
  let sgs: Record<string, unknown>[] | null = null;
  if (Array.isArray(doc.SecurityGroups)) sgs = doc.SecurityGroups as Record<string, unknown>[];
  else if (Array.isArray(doc)) sgs = doc as unknown as Record<string, unknown>[];
  else if (doc.GroupId || doc.IpPermissions) sgs = [doc];
  if (!sgs) return null;

  const findings: Finding[] = [];
  let rules = 0;
  for (const sg of sgs) {
    const gid = String(sg.GroupId ?? sg.GroupName ?? 'security-group');
    for (const perm of toArray<Record<string, unknown>>(sg.IpPermissions)) {
      rules++;
      const proto = String(perm.IpProtocol ?? '-1');
      // -1 / "all" means every protocol & port; FromPort/ToPort absent => all.
      const allProto = proto === '-1' || proto.toLowerCase() === 'all';
      const from = allProto ? 0 : Number(perm.FromPort ?? 0);
      const to = allProto ? 65535 : Number(perm.ToPort ?? 65535);
      for (const r of toArray<Record<string, unknown>>(perm.IpRanges)) {
        if (isWorld(String(r.CidrIp ?? '')) === 'v4')
          pushExposure(findings, gid, allProto ? 'any' : proto, from, to, 'v4');
      }
      for (const r of toArray<Record<string, unknown>>(perm.Ipv6Ranges)) {
        if (isWorld(String(r.CidrIpv6 ?? '')) === 'v6')
          pushExposure(findings, gid, allProto ? 'any' : proto, from, to, 'v6');
      }
    }
  }
  return { groups: sgs.length, rules, findings };
}

function analyzeAzure(doc: Record<string, unknown>): { groups: number; rules: number; findings: Finding[] } | null {
  const props = (doc.properties as Record<string, unknown> | undefined) ?? doc;
  const rulesRaw = toArray<Record<string, unknown>>((props.securityRules as unknown) ?? (doc.securityRules as unknown));
  if (rulesRaw.length === 0 && !('securityRules' in (props as object)) && !('securityRules' in doc)) return null;

  const findings: Finding[] = [];
  let rules = 0;
  for (const rule of rulesRaw) {
    const p = (rule.properties as Record<string, unknown> | undefined) ?? rule;
    const name = String(rule.name ?? p.name ?? 'rule');
    const direction = String(p.direction ?? '').toLowerCase();
    const access = String(p.access ?? '').toLowerCase();
    if (direction !== 'inbound' || access !== 'allow') continue;
    rules++;
    const proto = String(p.protocol ?? '*');
    const srcs = [
      ...(p.sourceAddressPrefix ? [String(p.sourceAddressPrefix)] : []),
      ...toArray<string>(p.sourceAddressPrefixes).map(String),
    ];
    const fam = srcs.map(isWorld).find((x): x is 'v4' | 'v6' => x !== null);
    if (!fam) continue;

    const portFields = [
      ...(p.destinationPortRange ? [String(p.destinationPortRange)] : []),
      ...toArray<string>(p.destinationPortRanges).map(String),
    ];
    for (const pr of portFields) {
      let from: number;
      let to: number;
      if (pr === '*') {
        from = 0;
        to = 65535;
      } else if (pr.includes('-')) {
        const [a, b] = pr.split('-');
        from = Number(a);
        to = Number(b);
      } else {
        from = Number(pr);
        to = from;
      }
      if (Number.isFinite(from) && Number.isFinite(to)) {
        pushExposure(findings, name, proto === '*' ? 'any' : proto, from, to, fam);
      }
    }
  }
  return { groups: 1, rules, findings };
}

function analyze(text: string): Analysis | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(trimmed) as Record<string, unknown>;
  } catch (e) {
    console.error('analyze failed:', errMessage(e));
    return { error: (e as Error).message, cloud: '', groups: 0, rulesChecked: 0, findings: [] };
  }

  const aws = analyzeAws(doc);
  if (aws) {
    aws.findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
    return { cloud: 'AWS EC2 Security Group', groups: aws.groups, rulesChecked: aws.rules, findings: aws.findings };
  }
  const az = analyzeAzure(doc);
  if (az) {
    az.findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
    return { cloud: 'Azure Network Security Group', groups: az.groups, rulesChecked: az.rules, findings: az.findings };
  }
  return {
    error:
      'Unrecognised shape. Expected AWS `describe-security-groups` JSON (SecurityGroups[].IpPermissions) or an Azure NSG (securityRules[] / properties.securityRules).',
    cloud: '',
    groups: 0,
    rulesChecked: 0,
    findings: [],
  };
}

const SAMPLE_AWS = JSON.stringify(
  {
    SecurityGroups: [
      {
        GroupId: 'sg-0a1b2c3d',
        GroupName: 'web-prod',
        IpPermissions: [
          { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          { IpProtocol: 'tcp', FromPort: 3306, ToPort: 3306, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
          { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
        ],
      },
    ],
  },
  null,
  2
);

const SAMPLE_AZURE = JSON.stringify(
  {
    securityRules: [
      {
        name: 'allow-rdp',
        properties: {
          direction: 'Inbound',
          access: 'Allow',
          protocol: 'Tcp',
          sourceAddressPrefix: 'Internet',
          destinationPortRange: '3389',
          priority: 100,
        },
      },
      {
        name: 'allow-https',
        properties: {
          direction: 'Inbound',
          access: 'Allow',
          protocol: 'Tcp',
          sourceAddressPrefix: '*',
          destinationPortRange: '443',
          priority: 110,
        },
      },
    ],
  },
  null,
  2
);

export default function SecurityGroupAnalyzer(): JSX.Element {
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
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Security Group / NSG Analyzer</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Paste AWS <span className="font-mono text-tool">aws ec2 describe-security-groups</span> JSON or an Azure NSG
          (securityRules / ARM shape). Inbound rules open to the internet (0.0.0.0/0, ::/0, “*”, “Internet”) are flagged
          and ranked by the service behind the port. Nothing leaves your browser.
        </p>
        <div className="flex flex-wrap gap-2 mb-4">
          <button
            type="button"
            onClick={() => setInput(SAMPLE_AWS)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load AWS example
          </button>
          <button
            type="button"
            onClick={() => setInput(SAMPLE_AZURE)}
            className="text-meta font-mono px-2.5 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
          >
            load Azure NSG example
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

      <label htmlFor="sg-input" className="sr-only">
        Security group / NSG JSON
      </label>
      <Textarea
        id="sg-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder='{ "SecurityGroups": [ { "GroupId": "sg-…", "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ] }'
        rows={12}
        spellCheck={false}
        aria-label="Security group / NSG JSON"
      />

      {analysis?.error && <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">{analysis.error}</p>}

      {analysis && !analysis.error && (
        <div className="mt-8 space-y-6">
          <section className="surface-card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>
                <span className="text-muted">Detected:</span> <span className="font-mono">{analysis.cloud}</span>
              </span>
              <span>
                <span className="text-muted">Groups:</span> <span className="font-mono">{analysis.groups}</span>
              </span>
              <span>
                <span className="text-muted">Inbound rules checked:</span>{' '}
                <span className="font-mono">{analysis.rulesChecked}</span>
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
                No internet-open inbound rules detected. Still confirm source ranges match your intended exposure.
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
    </div>
  );
}
