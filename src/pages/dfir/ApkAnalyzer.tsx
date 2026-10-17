import { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Upload,
  ShieldAlert,
  Hash,
  Loader2,
  Globe,
  ExternalLink,
  Smartphone,
  AlertTriangle,
  ShieldCheck,
  Search,
  Cpu,
  Database,
  Layers,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { CopyChip } from '../../components/dfir/CopyButton';
import { analyzeApk, type ApkAnalysis } from '../../lib/dfir/apk-analysis';
import { SEVERITY_TONE } from '../../components/severity';
import { errMessage } from '../../lib/log';

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export default function ApkAnalyzer(): JSX.Element {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    analysis: ApkAnalysis;
    sha256: string;
    sha1: string;
    md5: string;
    size: number;
    entropy: number;
    fileName: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const onFile = async (file: File) => {
    if (!file.name.endsWith('.apk')) {
      setError('Only .apk files are supported.');
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      setError('File exceeds 100 MB limit.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await analyzeApk(file);
      setResult(r);
    } catch (e) {
      console.error('ApkAnalyzer failed:', errMessage(e));
      setError(errMessage(e, 'analysis failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Smartphone size={28} />}
      title="APK Analyzer"
      description="Static analysis for Android APKs. Parses binary AndroidManifest.xml, DEX headers, and ZIP structure. Detects
          dangerous permissions, suspicious API usage, packed code, and potential malware behaviors. 100% client-side,
          max 100 MB."
    >
      <section className="surface-card p-4 mb-6">
        <button
          type="button"
          onDrop={(e) => {
            e.preventDefault();
            const f = e.dataTransfer.files?.[0];
            if (f) void onFile(f);
          }}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => fileRef.current?.click()}
          className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
          aria-label="Drop an APK file or click to choose"
        >
          <Upload size={32} className="mx-auto mb-2 text-muted" />
          <p className="text-sm font-mono text-body">Drop an APK here, or click to choose</p>
          <p className="text-mini font-mono text-muted mt-1">100% client-side. Max 100 MB.</p>
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".apk"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
          }}
        />
      </section>

      {loading && (
        <p className="text-sm font-mono text-muted mb-4 inline-flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Parsing APK, extracting DEX headers, scanning strings...
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4">
          {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          {/* Summary */}
          <section className="surface-card p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
              <h2 className="font-display font-bold text-lg">{result.fileName}</h2>
              <span className="text-xs font-mono text-muted">{fmtBytes(result.size)}</span>
            </div>
            <dl className="grid sm:grid-cols-[140px_1fr] gap-x-4 gap-y-1 text-meta font-mono">
              <dt className="text-muted">Package</dt>
              <dd className="text-heading break-all">{result.analysis.packageName || 'unknown'}</dd>
              {result.analysis.appName && (
                <>
                  <dt className="text-muted">App name</dt>
                  <dd className="text-heading">{result.analysis.appName}</dd>
                </>
              )}
              {result.analysis.versionName && (
                <>
                  <dt className="text-muted">Version</dt>
                  <dd className="text-heading">
                    {result.analysis.versionName} ({result.analysis.versionCode})
                  </dd>
                </>
              )}
              {result.analysis.minSdk && (
                <>
                  <dt className="text-muted">Min SDK</dt>
                  <dd className="text-heading">{result.analysis.minSdk}</dd>
                </>
              )}
              {result.analysis.targetSdk && (
                <>
                  <dt className="text-muted">Target SDK</dt>
                  <dd className="text-heading">{result.analysis.targetSdk}</dd>
                </>
              )}
              <dt className="text-muted">Entropy</dt>
              <dd className="text-heading">
                {result.entropy.toFixed(3)} / 8{' '}
                {result.entropy > 7.5 && <span className="text-rose-600 dark:text-rose-400">(likely packed)</span>}
              </dd>
              <dt className="text-muted">DEX files</dt>
              <dd className="text-heading">{result.analysis.dexFiles.length}</dd>
              <dt className="text-muted">Native libs</dt>
              <dd className="text-heading">{result.analysis.nativeLibs.length}</dd>
              <dt className="text-muted">Files</dt>
              <dd className="text-heading">{result.analysis.fileCount} entries</dd>
              <dt className="text-muted">Suspicious</dt>
              <dd
                className={`font-semibold ${result.analysis.suspicious.length > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}
              >
                {result.analysis.suspicious.length > 0 ? `${result.analysis.suspicious.length} flags` : 'none detected'}
              </dd>
            </dl>
          </section>

          {/* Hashes */}
          <section className="surface-card p-4">
            <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
              <Hash size={12} /> File hashes
            </h3>
            <div className="space-y-1.5 text-meta font-mono mb-3">
              {(
                [
                  ['SHA-256', result.sha256],
                  ['SHA-1', result.sha1],
                  ['MD5', result.md5],
                ] as const
              ).map(([label, val]) => (
                <div key={label} className="flex items-center gap-2">
                  <span className="text-muted w-20 shrink-0">{label}</span>
                  <code className="text-heading break-all flex-1">{val}</code>
                  <CopyChip value={val} label="copy" />
                </div>
              ))}
            </div>
            <div className="flex gap-2 flex-wrap">
              <Link
                to={`/dfir/ioc-check?indicator=${result.sha256}`}
                className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20"
              >
                <Search size={11} /> Check hash in IOC Checker (60+ sources)
              </Link>
              <Link
                to={`/dfir/malware-scan?hash=${result.sha256}`}
                className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
              >
                <ExternalLink size={10} /> Malware Scanner
              </Link>
            </div>
          </section>

          {/* Suspicious findings */}
          {result.analysis.suspicious.length > 0 && (
            <section className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4">
              <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-rose-600 dark:text-rose-400 font-mono mb-3 inline-flex items-center gap-2">
                <AlertTriangle size={12} /> Suspicious indicators ({result.analysis.suspicious.length})
              </h3>
              <div className="space-y-2">
                {result.analysis.suspicious.map((s, i) => (
                  <div key={i} className="rounded border border-rose-500/20 bg-rose-500/5 p-2.5">
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEVERITY_TONE[s.severity]}`}
                      >
                        {s.severity}
                      </span>
                      <span className="text-xs font-mono font-semibold text-rose-800 dark:text-rose-200">{s.rule}</span>
                    </div>
                    <p className="text-mini font-mono text-rose-700 dark:text-rose-300">{s.detail}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Permissions */}
          {result.analysis.permissions.length > 0 && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <ShieldAlert size={12} /> Permissions ({result.analysis.permissions.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {result.analysis.permissions.map((p) => (
                  <span
                    key={p.name}
                    className={`inline-flex items-center gap-1 text-micro font-mono px-2 py-0.5 rounded border ${p.dangerous ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300' : 'border-line-1 text-muted'}`}
                  >
                    {p.dangerous ? (
                      <AlertTriangle size={10} aria-hidden="true" />
                    ) : (
                      <ShieldCheck size={10} aria-hidden="true" />
                    )}
                    {p.name.split('.').pop()}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* DEX Files */}
          {result.analysis.dexFiles.length > 0 && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Cpu size={12} /> DEX Analysis ({result.analysis.dexFiles.length} files)
              </h3>
              <div className="grid gap-2 sm:grid-cols-2">
                {result.analysis.dexFiles.map((dex) => (
                  <div key={dex.name} className="rounded border border-line-1 bg-surface-200 p-2.5">
                    <div className="font-semibold text-sm text-heading mb-1">{dex.name}</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-3 gap-y-0.5 text-micro font-mono text-muted">
                      <span>DEX v{dex.version}</span>
                      <span>{fmtBytes(dex.size)}</span>
                      <span>{dex.classCount} classes</span>
                      <span>{dex.methodCount} methods</span>
                      <span>{dex.fieldCount} fields</span>
                      <span>
                        entropy {dex.entropy.toFixed(2)}
                        {dex.entropy > 7.5 ? ' (packed)' : ''}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* IOCs */}
          {(result.analysis.urls.length > 0 ||
            result.analysis.ips.length > 0 ||
            result.analysis.domains.length > 0 ||
            result.analysis.apiKeys.length > 0) && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Globe size={12} /> Extracted IOCs
              </h3>
              {result.analysis.urls.length > 0 && (
                <div className="mb-2">
                  <div className="text-micro font-mono text-muted mb-1">URLs ({result.analysis.urls.length})</div>
                  <div className="flex flex-wrap gap-1">
                    {result.analysis.urls.map((u) => (
                      <span
                        key={u}
                        className="text-micro font-mono px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-700 dark:text-sky-300 border border-sky-500/30 break-all max-w-[300px] truncate"
                      >
                        {u}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {result.analysis.ips.length > 0 && (
                <div className="mb-2">
                  <div className="text-micro font-mono text-muted mb-1">IPs ({result.analysis.ips.length})</div>
                  <div className="flex flex-wrap gap-1">
                    {result.analysis.ips.map((ip) => (
                      <span
                        key={ip}
                        className="text-micro font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/30"
                      >
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* Components */}
          {(result.analysis.activities.length > 0 ||
            result.analysis.services.length > 0 ||
            result.analysis.receivers.length > 0) && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Layers size={12} /> Components
              </h3>
              {result.analysis.activities.length > 0 && (
                <div className="mb-2">
                  <div className="text-micro font-mono text-muted mb-1">
                    Activities ({result.analysis.activities.length})
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {result.analysis.activities.map((a) => (
                      <span key={a} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                        {a.split('.').pop()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {result.analysis.services.length > 0 && (
                <div className="mb-2">
                  <div className="text-micro font-mono text-muted mb-1">
                    Services ({result.analysis.services.length})
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {result.analysis.services.map((s) => (
                      <span key={s} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                        {s.split('.').pop()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {result.analysis.receivers.length > 0 && (
                <div className="mb-2">
                  <div className="text-micro font-mono text-muted mb-1">
                    Receivers ({result.analysis.receivers.length})
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {result.analysis.receivers.map((r) => (
                      <span key={r} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                        {r.split('.').pop()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* Native libs */}
          {result.analysis.nativeLibs.length > 0 && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Database size={12} /> Native Libraries ({result.analysis.nativeLibs.length})
              </h3>
              <div className="flex flex-wrap gap-1">
                {result.analysis.nativeLibs.map((lib) => (
                  <span key={lib} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                    {lib.split('/').pop()}
                  </span>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </DataPageLayout>
  );
}
