import { useState, useCallback, type ReactNode } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Radar, Phone, Trash2, Scan, Loader2, ExternalLink, Shield } from 'lucide-react';
import { errMessage } from '../../lib/log';

interface StealerEntry {
  stealer_family?: string;
  date_compromised?: string;
  operating_system?: string;
  ip?: string;
}

interface MalwareScanResult {
  malware_family?: string;
  verdict?: 'malicious' | 'suspicious' | 'clean' | string;
  first_seen?: string;
  tags?: string[];
  error?: string;
  [key: string]: unknown;
}

interface PhoneResult {
  phone: { e164: string; digits: string; country_code: string; country_name: string; national_number: string };
  carrier: { type: string; carrier: string; confidence: string };
  numverify: {
    valid?: boolean;
    local_format: string;
    international_format: string;
    country_prefix: string;
    country_name: string;
    location: string;
    carrier: string;
    line_type: string;
  } | null;
  lookups: Array<{ service: string; url: string; category: string; free: boolean }>;
  dorks: Array<{ engine: string; query: string; url: string }>;
  breach: { checked: boolean; reason: string; stealerStats?: { data?: StealerEntry[] } } | null;
}

// Category values match the API (buildLookups) - keep in sync.
const CATEGORY_ICONS: Record<string, string> = {
  messaging: 'Msg',
  lookup: 'Search',
  directory: 'Globe',
  'caller-id': 'Phone',
  'people-search': 'Users',
  osint: 'Radar',
  regulatory: 'Scale',
};
const CATEGORY_LABELS: Record<string, string> = {
  messaging: 'Messaging',
  lookup: 'Reverse Lookup',
  directory: 'Directory',
  'caller-id': 'Caller ID',
  'people-search': 'People Search',
  osint: 'OSINT',
  regulatory: 'Regulatory',
};

function Field({
  label,
  value,
  mono,
  valueColor,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  valueColor?: string;
}) {
  return (
    <div className="min-w-0">
      <div className="text-micro uppercase tracking-wider mb-1 text-muted">{label}</div>
      <div
        className={`text-sm font-medium truncate ${mono ? 'font-mono' : ''} ${valueColor || 'text-heading'}`}
        title={typeof value === 'string' ? value : undefined}
      >
        {value || '-'}
      </div>
    </div>
  );
}

export default function PhoneOsintNew() {
  const [activeTab, setActiveTab] = useState<'phone' | 'malware'>('phone');
  const [input, setInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<PhoneResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<Array<{ id: string; number: string; timestamp: string }>>([]);

  // Malware state
  const [hashInput, setHashInput] = useState('');
  const [malwareResult, setMalwareResult] = useState<MalwareScanResult | null>(null);
  const [malwareScanning, setMalwareScanning] = useState(false);

  const handlePhoneScan = useCallback(async () => {
    if (!input.trim()) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`/api/v1/phone-osint?phone=${encodeURIComponent(input.trim())}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Request failed' }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
      setHistory((prev) => [
        { id: Date.now().toString(), number: input, timestamp: new Date().toISOString() },
        ...prev,
      ]);
    } catch (e: unknown) {
      setError(errMessage(e, 'Scan failed'));
    } finally {
      setScanning(false);
    }
  }, [input]);

  const handleMalwareScan = useCallback(async () => {
    if (!hashInput.trim()) return;
    setMalwareScanning(true);
    setMalwareResult(null);
    try {
      const res = await fetch(`/api/v1/malware-samples?hash=${encodeURIComponent(hashInput.trim())}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as MalwareScanResult;
      setMalwareResult(data);
    } catch (e: unknown) {
      setMalwareResult({ error: errMessage(e, 'Scan failed') });
    } finally {
      setMalwareScanning(false);
    }
  }, [hashInput]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Radar size={28} />}
      title="AI Phone Intel Dashboard"
      description="AI-powered OSINT dashboard - phone number intelligence with risk scoring, carrier detection, breach checks, and malware hash analysis."
      maxWidthClass="max-w-5xl"
    >
      {/* Main Dashboard Card */}
      <div className="relative rounded-xl p-6 md:p-8 overflow-hidden border border-line-1 bg-surface-200 shadow-e3">
        {/* Header */}
        <div className="flex items-center gap-3 mb-2">
          <Radar size={32} className="text-brand-600 dark:text-brand-400" />
          <h2 className="text-2xl font-bold text-heading">AI Phone Intel Dashboard</h2>
        </div>

        {/* Status bar */}
        <div className="flex items-center justify-between text-tool pb-3.5 mb-5 border-b border-line-1 gap-3 flex-wrap">
          <span className="text-muted">AI-Powered OSINT</span>
          <div className="flex items-center gap-2">
            <span className="text-mini font-semibold px-2.5 py-1 rounded-full bg-surface-100 text-brand-600 dark:text-brand-400 border border-line-1">
              Remaining: 100 of 100
            </span>
            <span className="text-micro font-bold tracking-wider px-3 py-1 rounded-full animate-pulse bg-emerald-500 text-slate-950">
              LIVE
            </span>
          </div>
        </div>

        {/* Tab buttons */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => setActiveTab('phone')}
            className={`flex-1 px-4 py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition border ${
              activeTab === 'phone'
                ? 'bg-brand-600 text-white border-transparent'
                : 'bg-surface-100 text-muted border-line-1'
            }`}
          >
            <Phone size={16} /> Phone Intel
          </button>
          <button
            onClick={() => setActiveTab('malware')}
            className={`flex-1 px-4 py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition border ${
              activeTab === 'malware'
                ? 'bg-brand-600 text-white border-transparent'
                : 'bg-surface-100 text-muted border-line-1'
            }`}
          >
            <Shield size={16} /> Malware Hash
          </button>
        </div>

        {/* Phone Intel Tab */}
        {activeTab === 'phone' && (
          <>
            <div className="flex flex-wrap gap-3 mb-6">
              <input
                type="tel"
                placeholder="Enter number e.g. 14155552671"
                maxLength={20}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handlePhoneScan()}
                className="flex-1 min-w-[200px] px-5 py-4 rounded-xl text-base font-medium outline-none transition bg-surface-100 text-heading border border-line-1"
              />
              <button
                onClick={handlePhoneScan}
                disabled={!input.trim() || scanning}
                className="px-7 py-4 rounded-xl font-bold text-on-fill flex items-center gap-2.5 transition disabled:opacity-50 disabled:cursor-not-allowed bg-brand-600 hover:bg-brand-700 shadow-e2"
              >
                {scanning ? <Loader2 size={16} className="animate-spin" /> : <Scan size={16} />}
                {scanning ? 'Scanning...' : 'Deep Scan'}
              </button>
            </div>

            {error && (
              <div className="mb-4 p-3 rounded-xl text-sm bg-red-900/20 text-red-300 border border-red-900/40">
                {error}
              </div>
            )}

            {/* Results */}
            {result && (
              <div className="space-y-4 relative">
                {/* Phone Info Card */}
                <div className="p-5 rounded-xl bg-surface-100 border border-line-1">
                  <h3 className="text-sm font-bold mb-3 flex items-center gap-2 text-brand-600 dark:text-brand-400">
                    <Phone size={14} /> Phone Information
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-4">
                    <Field label="E.164" value={result.phone.e164} mono />
                    <Field label="National Number" value={result.phone.national_number} mono />
                    <Field label="Country" value={result.phone.country_name || result.phone.country_code} />
                    <Field label="Country Code" value={result.phone.country_code} />
                    <Field label="Carrier" value={result.carrier.carrier || 'Unknown'} />
                    <Field label="Line Type" value={result.carrier.type || 'Unknown'} />
                    <Field
                      label="Confidence"
                      value={result.carrier.confidence || 'low'}
                      valueColor={
                        result.carrier.confidence === 'api-verified' || result.carrier.confidence === 'high'
                          ? 'text-emerald-500'
                          : result.carrier.confidence === 'medium'
                            ? 'text-amber-500'
                            : 'text-muted'
                      }
                    />
                    {result.numverify && <Field label="Valid" value="Verified" valueColor="text-emerald-500" />}
                  </div>
                  {result.numverify && (
                    <div className="mt-4 pt-4 grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-4 border-t border-line-1">
                      <Field label="International" value={result.numverify.international_format} mono />
                      <Field label="Local Format" value={result.numverify.local_format} mono />
                      <Field label="Dial Prefix" value={result.numverify.country_prefix} mono />
                      <Field label="Location" value={result.numverify.location} />
                      <Field label="Carrier (NumVerify)" value={result.numverify.carrier} />
                      <Field label="Line Type (NumVerify)" value={result.numverify.line_type} />
                    </div>
                  )}
                </div>

                {/* Breach Check */}
                {result.breach &&
                  (() => {
                    const entries = result.breach.stealerStats?.data ?? [];
                    const found = result.breach.checked && entries.length > 0;
                    const families = Array.from(
                      new Set(entries.map((e) => e.stealer_family).filter(Boolean))
                    ) as string[];
                    return (
                      <div
                        className={`p-4 rounded-xl border ${
                          found ? 'bg-red-900/10 border-red-900/40' : 'bg-surface-100 border-line-1'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <Shield
                            size={14}
                            className={
                              found ? 'text-red-500' : result.breach.checked ? 'text-emerald-500' : 'text-muted'
                            }
                          />
                          <span
                            className={`text-sm font-bold ${
                              found ? 'text-red-300' : result.breach.checked ? 'text-emerald-300' : 'text-muted'
                            }`}
                          >
                            Breach Check:{' '}
                            {result.breach.checked ? (found ? `EXPOSED (${entries.length})` : 'CLEAN') : 'NOT CHECKED'}
                          </span>
                        </div>
                        {!result.breach.checked && <div className="text-mini text-muted">{result.breach.reason}</div>}
                        {found && families.length > 0 && (
                          <div className="text-xs mt-1 text-muted">Stealer families: {families.join(', ')}</div>
                        )}
                      </div>
                    );
                  })()}

                {/* Lookup Links */}
                {result.lookups.length > 0 && (
                  <div className="p-5 rounded-xl bg-surface-100 border border-line-1">
                    <h3 className="text-sm font-bold mb-3 text-muted">Lookup Services</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {result.lookups.map((l, i) => (
                        <a
                          key={i}
                          href={l.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2.5 p-2.5 rounded-xl transition hover:bg-wash bg-surface-100 border border-line-1"
                        >
                          <span className="text-sm shrink-0">{CATEGORY_ICONS[l.category] || 'Link'}</span>
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-medium truncate text-heading">{l.service}</div>
                            <div className="text-micro truncate text-muted">
                              {CATEGORY_LABELS[l.category] || l.category}
                            </div>
                          </div>
                          {l.free && (
                            <span className="text-micro px-1.5 py-0.5 rounded-full shrink-0 bg-emerald-500/20 text-emerald-500">
                              FREE
                            </span>
                          )}
                          <ExternalLink size={12} className="shrink-0 text-muted" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Dorks */}
                {result.dorks.length > 0 && (
                  <div className="p-5 rounded-xl bg-surface-100 border border-line-1">
                    <h3 className="text-sm font-bold mb-3 text-muted">Search Engine Dorks</h3>
                    <div className="space-y-1.5">
                      {result.dorks.map((d, i) => (
                        <a
                          key={i}
                          href={d.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center justify-between gap-3 p-2.5 rounded-xl transition hover:bg-wash bg-surface-100 border border-line-1"
                        >
                          <span className="text-micro font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-surface-300 text-brand-600 dark:text-brand-400">
                            {d.engine}
                          </span>
                          <span className="text-xs font-mono truncate flex-1 text-muted">{d.query}</span>
                          <ExternalLink size={10} className="shrink-0 text-muted" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Malware Hash Tab */}
        {activeTab === 'malware' && (
          <>
            <div className="flex flex-wrap gap-3 mb-6">
              <input
                type="text"
                placeholder="Enter hash (MD5, SHA-1, SHA-256)"
                maxLength={128}
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleMalwareScan()}
                className="flex-1 min-w-[200px] px-5 py-4 rounded-xl text-base font-medium font-mono outline-none transition bg-surface-100 text-heading border border-line-1"
              />
              <button
                onClick={handleMalwareScan}
                disabled={!hashInput.trim() || malwareScanning}
                className="px-7 py-4 rounded-xl font-bold text-white flex items-center gap-2.5 transition disabled:opacity-50 disabled:cursor-not-allowed bg-severity-critical hover:bg-red-700 shadow-e2"
              >
                {malwareScanning ? <Loader2 size={16} className="animate-spin" /> : <Scan size={16} />}
                {malwareScanning ? 'Analyzing...' : 'Analyze Hash'}
              </button>
            </div>

            {malwareResult && !malwareResult.error && (
              <div className="space-y-4 relative">
                {/* Family / Verdict */}
                <div className="p-5 rounded-xl bg-surface-100 border border-line-1">
                  <h3 className="text-sm font-bold mb-3 flex items-center gap-2 text-red-400">
                    <Shield size={14} /> Malware Intelligence
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <div className="text-micro uppercase tracking-wider mb-1 text-muted">Family</div>
                      <div className="text-sm font-bold text-heading">{malwareResult.malware_family || 'Unknown'}</div>
                    </div>
                    <div>
                      <div className="text-micro uppercase tracking-wider mb-1 text-muted">Verdict</div>
                      <div
                        className={`text-sm font-bold ${
                          malwareResult.verdict === 'malicious'
                            ? 'text-red-500'
                            : malwareResult.verdict === 'suspicious'
                              ? 'text-amber-500'
                              : 'text-emerald-500'
                        }`}
                      >
                        {malwareResult.verdict || 'Unknown'}
                      </div>
                    </div>
                    <div>
                      <div className="text-micro uppercase tracking-wider mb-1 text-muted">First Seen</div>
                      <div className="text-sm text-heading">{malwareResult.first_seen || 'N/A'}</div>
                    </div>
                    <div>
                      <div className="text-micro uppercase tracking-wider mb-1 text-muted">Tags</div>
                      <div className="text-xs flex flex-wrap gap-1">
                        {(malwareResult.tags || []).slice(0, 5).map((tag: string, i: number) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Quick Links */}
                <div className="p-5 rounded-xl bg-surface-100 border border-line-1">
                  <h3 className="text-sm font-bold mb-3 text-muted">Analysis Links</h3>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {[
                      { name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${hashInput.trim()}` },
                      {
                        name: 'MalwareBazaar',
                        url: `https://bazaar.abuse.ch/browse.php?search=sha256:${hashInput.trim()}`,
                      },
                      {
                        name: 'Hybrid Analysis',
                        url: `https://www.hybrid-analysis.com/search?query=${hashInput.trim()}`,
                      },
                      { name: 'ANY.RUN', url: `https://any.run/report/${hashInput.trim()}` },
                      { name: 'URLhaus', url: `https://urlhaus.abuse.ch/browse.php?search=sha256:${hashInput.trim()}` },
                      { name: 'Triage', url: `https://tria.ge/s?q=${hashInput.trim()}` },
                    ].map((link, i) => (
                      <a
                        key={i}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 p-2.5 rounded-xl transition hover:bg-wash bg-surface-100 border border-line-1"
                      >
                        <span className="text-xs font-medium flex-1 truncate text-heading">{link.name}</span>
                        <ExternalLink size={10} className="text-muted" />
                      </a>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {malwareResult?.error && (
              <div className="p-3 rounded-xl text-sm bg-red-900/20 text-red-300 border border-red-900/40">
                {malwareResult.error}
              </div>
            )}
          </>
        )}
      </div>

      {/* Scan History */}
      {history.length > 0 && (
        <div className="mt-4 p-5 rounded-xl bg-surface-200 border border-line-1">
          <div className="text-tool font-semibold mb-3 flex items-center justify-between text-muted">
            <span>Scan History ({history.length})</span>
            <button onClick={() => setHistory([])} className="text-mini hover:text-white transition text-muted">
              <Trash2 size={12} /> Clear
            </button>
          </div>
          <div className="space-y-1.5">
            {history.slice(0, 5).map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-2.5 rounded-xl bg-surface-100 border border-line-1"
              >
                <div>
                  <div className="text-xs font-medium font-mono text-heading">{scan.number}</div>
                  <div className="text-micro text-muted">{new Date(scan.timestamp).toLocaleTimeString()}</div>
                </div>
                <span className="text-micro font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-500">
                  done
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="mt-6 pt-4 text-center text-meta text-muted">
        <a href="/dfir/phone-hub" className="text-muted">
          Legal Policy · Privacy · Terms
        </a>
      </div>
    </DataPageLayout>
  );
}
