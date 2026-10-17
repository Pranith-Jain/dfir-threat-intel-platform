import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useRef } from 'react';
import { BackLink } from '../../components/BackLink';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { Search, Loader2, Bug, FileText, Shield, Globe, Wallet, Monitor, AlertTriangle } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';

interface StealerResult {
  parse_id: string;
  detected_stealer: string | null;
  credentials: Array<{ domain: string; username: string; password_length: number; source: string }>;
  emails: string[];
  domains: string[];
  ips: string[];
  crypto_wallets: Array<{ currency: string; address: string }>;
  system_info: { hostname?: string; username?: string; os?: string; hwid?: string; ip?: string; country?: string };
  installed_software: string[];
  stats: { total_credentials: number; unique_domains: number; unique_emails: number; crypto_wallets: number };
  meta: { parsed_at: string; warnings: string[] };
}

const SUPPORTED_STEALERS = ['RedLine', 'Raccoon', 'Vidar', 'Lumma', 'StealC', 'Mystic', 'AzorUlt'];

type Credential = StealerResult['credentials'][number];

const CREDENTIAL_COLUMNS: DataTableColumn<Credential>[] = [
  {
    key: 'domain',
    header: 'Domain',
    render: (c) => c.domain,
    sortValue: (c) => c.domain,
    className: 'font-mono text-xs',
  },
  {
    key: 'username',
    header: 'Username',
    render: (c) => c.username,
    sortValue: (c) => c.username,
    className: 'font-mono text-xs',
  },
  {
    key: 'password_length',
    header: 'Pass Len',
    render: (c) => <span className="text-muted">{c.password_length}</span>,
    sortValue: (c) => c.password_length,
    align: 'right',
    className: 'text-xs',
  },
  {
    key: 'source',
    header: 'Source',
    render: (c) => <span className="text-muted">{c.source}</span>,
    sortValue: (c) => c.source,
    className: 'text-xs',
  },
];

export default function StealerParser(): JSX.Element {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<StealerResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const parseRef = useRef<AbortController | null>(null);

  const handleParse = useCallback(async () => {
    if (!input.trim()) return;
    parseRef.current?.abort();
    const ctrl = new AbortController();
    parseRef.current = ctrl;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/v1/stealer/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: input }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(30_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(errBody) as { error?: string };
          msg = p.error ?? msg;
        } catch (_catchErr) {
          console.error('StealerParser failed:', errMessage(_catchErr));
          /* ok */
        }
        throw new Error(msg);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      setResult(await res.json());
    } catch (err) {
      logCatch(err);
      if (ctrl.signal.aborted) return;
      setError(errMessage(err));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, [input]);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Bug size={28} className="text-brand-600 dark:text-brand-400" /> Infostealer Log Parser
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Extract credentials, IOCs, crypto wallets, and system info from stealer log dumps. Auto-detects format and
          parses client-side where possible.
        </p>
      </div>

      {/* Supported stealers */}
      <div className="flex flex-wrap gap-1.5 mb-6">
        {SUPPORTED_STEALERS.map((s) => (
          <span key={s} className="px-2.5 py-1 rounded-xl text-xs font-mono border border-line-1 text-muted">
            {s}
          </span>
        ))}
      </div>

      {/* Input */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paste stealer log content here…"
          aria-label="Stealer log content to parse"
          className="w-full h-48 bg-surface-200 border border-line-1 rounded-xl p-4 text-sm text-heading placeholder-slate-400 focus:outline-none focus:border-brand-500 focus-visible:ring-2 focus-visible:ring-brand-500/40 dark:focus:border-brand-400 resize-y font-mono"
        />
        <div className="flex items-center justify-between mt-3">
          <span className="text-xs text-muted font-mono">
            {input.length > 0 ? `${(input.length / 1024).toFixed(1)} KB` : 'Max 500 KB'}
          </span>
          <button
            onClick={handleParse}
            disabled={loading || !input.trim()}
            className="px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled disabled:cursor-not-allowed rounded-xl text-sm font-semibold text-on-fill transition-colors flex items-center gap-2"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            {loading ? 'Parsing…' : 'Parse Log'}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 mb-6 flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0" />
          <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-5 animate-fade-in-up">
          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard
              label="Credentials"
              value={result.stats.total_credentials}
              icon={<Shield size={16} />}
              color="text-rose-600 dark:text-rose-400"
            />
            <StatCard
              label="Domains"
              value={result.stats.unique_domains}
              icon={<Globe size={16} />}
              color="text-brand-600 dark:text-brand-400"
            />
            <StatCard
              label="Emails"
              value={result.stats.unique_emails}
              icon={<FileText size={16} />}
              color="text-emerald-600 dark:text-emerald-400"
            />
            <StatCard
              label="Crypto Wallets"
              value={result.stats.crypto_wallets}
              icon={<Wallet size={16} />}
              color="text-amber-600 dark:text-amber-400"
            />
          </div>

          {/* Detected Stealer */}
          {result.detected_stealer && (
            <div className="rounded-xl border border-amber-300/50 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 p-4 flex items-center gap-3">
              <Bug size={16} className="text-amber-600 dark:text-amber-400" />
              <span className="text-sm text-amber-800 dark:text-amber-200">
                Detected stealer: <strong className="font-mono">{result.detected_stealer}</strong>
              </span>
            </div>
          )}

          {/* System Info */}
          {Object.keys(result.system_info).length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
                <Monitor size={14} className="text-brand-600 dark:text-brand-400" /> System Information
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {result.system_info.hostname && <InfoField label="Hostname" value={result.system_info.hostname} />}
                {result.system_info.username && <InfoField label="Username" value={result.system_info.username} />}
                {result.system_info.os && <InfoField label="OS" value={result.system_info.os} />}
                {result.system_info.ip && <InfoField label="IP" value={result.system_info.ip} />}
                {result.system_info.hwid && <InfoField label="HWID" value={result.system_info.hwid} />}
                {result.system_info.country && <InfoField label="Country" value={result.system_info.country} />}
              </div>
            </div>
          )}

          {/* Credentials */}
          {result.credentials.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <div className="flex items-center justify-between mb-3">
                <h2 className="font-display font-bold text-sm text-rose-600 dark:text-rose-400">
                  Stolen Credentials ({result.credentials.length})
                </h2>
                <CopyButton value={result.credentials.map((c) => `${c.domain}:${c.username}`).join('\n')} />
              </div>
              <div className="max-h-64 overflow-auto">
                <DataTable
                  rows={result.credentials.slice(0, 50)}
                  rowKey={(c, i) => `${c.domain}-${c.username}-${i}`}
                  columns={CREDENTIAL_COLUMNS}
                />
              </div>
            </div>
          )}

          {/* Crypto Wallets */}
          {result.crypto_wallets.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3">Crypto Wallets ({result.crypto_wallets.length})</h2>
              <div className="space-y-1.5">
                {result.crypto_wallets.map((w) => (
                  <div
                    key={w.address}
                    className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-200 px-3 py-2"
                  >
                    <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300">
                      {w.currency}
                    </span>
                    <code className="text-xs text-body flex-1 truncate">{w.address}</code>
                    <CopyButton value={w.address} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Emails */}
          {result.emails.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3">Emails ({result.emails.length})</h2>
              <div className="max-h-32 overflow-y-auto flex flex-wrap gap-1">
                {result.emails.map((e) => (
                  <span key={e} className="px-2 py-0.5 rounded border border-line-1 text-xs font-mono text-muted">
                    {e}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Installed Software */}
          {result.installed_software.length > 0 && (
            <div className="surface-card/40 shadow-e1 p-5">
              <h2 className="font-display font-bold text-sm mb-3">Installed Software</h2>
              <div className="flex flex-wrap gap-1.5">
                {result.installed_software.map((s) => (
                  <span key={s} className="px-2 py-1 rounded border border-line-1 text-xs text-muted">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: number;
  icon?: React.ReactNode;
  color?: string;
}) {
  return (
    <div className="surface-card/40 shadow-e1 p-4">
      <div className="flex items-center gap-2 mb-1.5">
        {icon && <span className={color ?? 'text-muted'}>{icon}</span>}
        <span className="text-micro font-mono uppercase tracking-wider text-muted">{label}</span>
      </div>
      <div className={`text-2xl font-display font-bold ${color ?? 'text-slate-900 dark:text-white'}`}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

function InfoField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-sm font-mono text-body">{value}</div>
    </div>
  );
}
