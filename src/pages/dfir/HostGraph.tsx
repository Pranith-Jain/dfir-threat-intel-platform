import { logCatch } from '../../lib/log';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Search, Network, Building2, Globe, Mail, Database, AlertTriangle, Clock, ExternalLink } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';

const API = '/api/v1';

type InputKind = 'ip' | 'asn' | 'cidr' | 'unknown';

interface IpData {
  ip: string;
  prefix?: string;
  asn?: number;
  asn_name?: string;
  asn_country?: string;
  rir?: string;
  abuse_contact?: string;
  sources: string[];
}
interface AsData {
  asn: number;
  name?: string;
  descr?: string;
  country?: string;
  prefix_count?: number;
  peer_count?: number;
  abuse_contact?: string;
  rir?: string;
  sources: string[];
}
interface PrefixData {
  prefix: string;
  rir?: string;
  registry_handle?: string;
  parent?: string;
  abuse_contact?: string;
  rdap_links: string[];
  asn?: number;
  sources: string[];
}

type GraphResponse =
  | { kind: 'ip'; input: { ip: string }; data: IpData; generated_at: string }
  | { kind: 'asn'; input: { asn: number }; data: AsData; generated_at: string }
  | { kind: 'cidr'; input: { cidr: string }; data: PrefixData; generated_at: string };

function classifyInput(s: string): InputKind {
  const v = s.trim();
  if (!v) return 'unknown';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((o) => Number(o) <= 255)) return 'ip';
  if (/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v) && v.split('.')[3]?.includes('/')) return 'cidr';
  if (/^(?:AS)?\d+$/i.test(v)) return 'asn';
  return 'unknown';
}

function exampleFor(kind: InputKind): string {
  if (kind === 'ip') return '8.8.8.8';
  if (kind === 'asn') return '13335';
  if (kind === 'cidr') return '198.51.100.0/24';
  return 'IP (1.2.3.4), ASN (13335 or AS13335), or CIDR (198.51.100.0/24)';
}

const KIND_LABEL: Record<InputKind, string> = {
  ip: 'IP',
  asn: 'ASN',
  cidr: 'CIDR',
  unknown: '?',
};

const KIND_TONE: Record<InputKind, string> = {
  ip: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
  asn: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300',
  cidr: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
  unknown: 'bg-slate-100 dark:bg-surface-300 text-slate-500',
};

export default function HostGraphView(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const initial = params.get('q') ?? '';
  const [query, setQuery] = useState(initial);
  const [error, setError] = useState('');
  const [result, setResult] = useState<GraphResponse | null>(null);
  const [submitted, setSubmitted] = useState(initial);

  const inputKind = classifyInput(query);

  const ctrlRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      ctrlRef.current?.abort();
    };
  }, []);

  const fetchGraph = useCallback(
    async (q: string) => {
      ctrlRef.current?.abort();
      const ctrl = new AbortController();
      ctrlRef.current = ctrl;

      setError('');
      setResult(null);
      setSubmitted(q);
      setParams((p) => {
        const next = new URLSearchParams(p);
        if (q) next.set('q', q);
        else next.delete('q');
        return next;
      });
      const kind = classifyInput(q);
      if (kind === 'unknown') {
        setError('Enter an IPv4 address, ASN (e.g. 13335 or AS13335), or CIDR (e.g. 198.51.100.0/24).');
        return;
      }
      const param =
        kind === 'ip'
          ? `ip=${encodeURIComponent(q.trim())}`
          : kind === 'asn'
            ? `asn=${encodeURIComponent(q.trim())}`
            : `cidr=${encodeURIComponent(q.trim())}`;
      try {
        const res = await fetch(`${API}/asn-graph?${param}`, { signal: ctrl.signal });
        const body = (await res.json().catch(() => ({}))) as Partial<GraphResponse> & { message?: string };
        if (!mountedRef.current || ctrl.signal.aborted) return;
        if (!res.ok) throw new Error(body.message || `HTTP ${res.status}`);
        setResult(body as GraphResponse);
      } catch (e) {
        logCatch(e);
        if (e instanceof DOMException && e.name === 'AbortError') return;
        if (!mountedRef.current) return;
        setError(e instanceof Error ? e.message : 'Lookup failed');
      }
    },
    [setParams]
  );

  // Honour ?q=… on first render so the page is shareable.
  useEffect(() => {
    if (initial && !result && !error) {
      void fetchGraph(initial);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) void fetchGraph(query.trim());
  };

  return (
    <div className="max-w-6xl">

      <h1 className="text-3xl font-display font-semibold mb-2">Host Graph Pivot</h1>
      <p className="text-muted mb-6">
        Network-intel pivot: paste an IP, ASN, or CIDR and get the announcing prefix, holder, registry, and abuse
        contact - fused from bgp.tools, RIPE Stat, and the RDAP bootstrap registry. Keyless, no signup.
      </p>

      <form onSubmit={onSubmit} className="flex gap-2 mb-3">
        <div className="relative flex-1">
          <Network size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={exampleFor(inputKind)}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            className="w-full pl-10 pr-24 py-2.5 surface-card text-sm font-mono focus-visible:ring-2 focus-visible:ring-brand-500 focus:border-transparent"
          />
          {query && (
            <span
              className={`absolute right-3 top-1/2 -translate-y-1/2 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded ${KIND_TONE[inputKind]}`}
            >
              {KIND_LABEL[inputKind]}
            </span>
          )}
        </div>
        <button
          type="submit"
          disabled={!query.trim() || inputKind === 'unknown'}
          className="px-4 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-on-fill text-sm font-medium disabled:opacity-50 inline-flex items-center gap-2 transition-colors"
        >
          <Search size={14} />
          Pivot
        </button>
      </form>

      <p className="text-xs font-mono text-muted mb-8">Tip: {exampleFor(inputKind === 'unknown' ? 'ip' : inputKind)}</p>

      {error && (
        <div className="mb-6 p-3 rounded-xl bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/50 text-rose-700 dark:text-rose-300 text-sm font-mono">
          <AlertTriangle size={14} className="inline mr-2" />
          {error}
        </div>
      )}

      {!result && !error && submitted && (
        <div className="p-6 rounded-xl border border-dashed border-line-2 text-center text-sm text-muted">
          <Clock size={20} className="inline-block mr-2 mb-1 animate-spin" />
          Resolving <span className="font-mono">{submitted}</span> across bgp.tools, RIPE Stat, and RDAP…
        </div>
      )}

      {result && result.kind === 'ip' && <IpView data={result.data} input={result.input.ip} />}
      {result && result.kind === 'asn' && <AsnView data={result.data} input={result.input.asn} />}
      {result && result.kind === 'cidr' && <PrefixView data={result.data} input={result.input.cidr} />}

      {result && (
        <p className="mt-6 text-mini font-mono text-muted flex items-center gap-2">
          <Clock size={11} />
          generated {new Date(result.generated_at).toLocaleString()} · sources: {result.data.sources.join(', ') || '-'}
        </p>
      )}
    </div>
  );
}

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: typeof Search;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <section className="mb-6 p-4 surface-card">
      <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted mb-3">
        <Icon size={14} />
        {title}
      </h2>
      {children}
    </section>
  );
}

function Row({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }): JSX.Element {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[8rem_1fr] gap-y-1 gap-x-4 py-1.5 text-sm">
      <span className="text-xs font-mono uppercase tracking-wider text-muted">{label}</span>
      <span className={mono ? 'font-mono' : ''}>{value || <span className="text-muted">-</span>}</span>
    </div>
  );
}

function IpView({ data, input }: { data: IpData; input: string }): JSX.Element {
  return (
    <>
      <Section title="Identity" icon={Network}>
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-xl font-mono font-bold">{data.ip || input}</h2>
              <CopyButton value={data.ip || input} />
            </div>
            <div className="text-sm text-muted flex flex-wrap gap-x-3">
              {data.asn && (
                <Link
                  to={`/dfir/host-graph?q=${data.asn}`}
                  className="font-mono text-brand-600 dark:text-brand-400 hover:underline"
                >
                  AS{data.asn}
                </Link>
              )}
              {data.prefix && (
                <Link
                  to={`/dfir/host-graph?q=${encodeURIComponent(data.prefix)}`}
                  className="font-mono text-brand-600 dark:text-brand-400 hover:underline"
                >
                  {data.prefix}
                </Link>
              )}
            </div>
          </div>
        </div>
        <Row label="ASN" value={data.asn !== undefined ? `AS${data.asn}` : undefined} />
        <Row label="Holder" value={data.asn_name} mono={false} />
        <Row label="Country" value={data.asn_country} />
        <Row label="RIR" value={data.rir} />
        <Row label="Prefix" value={data.prefix} />
        <Row
          label="Abuse"
          value={
            data.abuse_contact ? (
              <a
                className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                href={`mailto:${data.abuse_contact}`}
              >
                <Mail size={12} />
                {data.abuse_contact}
              </a>
            ) : undefined
          }
          mono={false}
        />
      </Section>
    </>
  );
}

function AsnView({ data, input }: { data: AsData; input: number }): JSX.Element {
  return (
    <>
      <Section title="Autonomous System" icon={Building2}>
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-xl font-mono font-bold">AS{data.asn || input}</h2>
              <CopyButton value={`AS${data.asn || input}`} />
            </div>
            <div className="text-sm text-muted">
              {data.name && <span>{data.name}</span>}
              {data.descr && data.descr !== data.name && <span className="ml-2 text-muted">· {data.descr}</span>}
            </div>
          </div>
        </div>
        <Row label="Holder" value={data.name} mono={false} />
        <Row label="Description" value={data.descr} mono={false} />
        <Row label="Country" value={data.country} />
        <Row label="RIR" value={data.rir} />
        <Row label="Prefixes" value={data.prefix_count?.toLocaleString()} />
        <Row label="Peers" value={data.peer_count?.toLocaleString()} />
        <Row
          label="Abuse"
          value={
            data.abuse_contact ? (
              <a
                className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                href={`mailto:${data.abuse_contact}`}
              >
                <Mail size={12} />
                {data.abuse_contact}
              </a>
            ) : undefined
          }
          mono={false}
        />
      </Section>
    </>
  );
}

function PrefixView({ data, input }: { data: PrefixData; input: string }): JSX.Element {
  return (
    <>
      <Section title="Prefix allocation" icon={Globe}>
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-xl font-mono font-bold">{data.prefix || input}</h2>
              <CopyButton value={data.prefix || input} />
            </div>
            {data.asn !== undefined && (
              <div className="text-sm text-muted">
                <Link
                  to={`/dfir/host-graph?q=${data.asn}`}
                  className="font-mono text-brand-600 dark:text-brand-400 hover:underline"
                >
                  AS{data.asn}
                </Link>
              </div>
            )}
          </div>
        </div>
        <Row label="RIR" value={data.rir} />
        <Row label="Registry handle" value={data.registry_handle} />
        <Row label="Parent" value={data.parent} />
        <Row
          label="Abuse"
          value={
            data.abuse_contact ? (
              <a
                className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                href={`mailto:${data.abuse_contact}`}
              >
                <Mail size={12} />
                {data.abuse_contact}
              </a>
            ) : undefined
          }
          mono={false}
        />
        {data.rdap_links.length > 0 && (
          <div className="mt-3 pt-3 border-t border-line-1">
            <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1.5">
              <Database size={10} className="inline mr-1" />
              RDAP links
            </p>
            <ul className="space-y-1">
              {data.rdap_links.slice(0, 6).map((href) => (
                <li key={href} className="text-xs break-all">
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
                  >
                    <ExternalLink size={10} />
                    {href}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Section>
    </>
  );
}
