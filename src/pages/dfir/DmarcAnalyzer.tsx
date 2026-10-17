import { errMessage, logCatch } from '../../lib/log';
import { useState, useRef, useCallback, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { Upload, Shield, Download, AlertTriangle, CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { downloadBlob } from '../../lib/download';

interface IpEnrichment {
  org?: string;
  country?: string;
  country_code?: string;
  asn?: string;
  asname?: string;
  isp?: string;
}

interface DmarcRecord {
  sourceIp: string;
  count: number;
  disposition: string;
  spf: string;
  dkim: string;
  headerFrom: string;
  enrichment?: IpEnrichment;
}

interface DmarcReport {
  orgName: string;
  email: string;
  domain: string;
  policy: string;
  subdomainPolicy: string;
  pct: string;
  beginDate: string;
  endDate: string;
  records: DmarcRecord[];
}

const MAX_DECOMPRESSED = 60 * 1024 * 1024;

async function unzip(buf: ArrayBuffer): Promise<ArrayBuffer> {
  const ds = new DecompressionStream('gzip');
  const blob = new Blob([buf]);
  const reader = blob.stream().pipeThrough(ds).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_DECOMPRESSED) {
      reader.cancel();
      throw new Error('Decompressed report exceeds size limit.');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out.buffer;
}

function parseDmarcXml(xml: string): DmarcReport {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'text/xml');

  const parseError = doc.querySelector('parsererror');
  if (parseError) throw new Error('Invalid XML: ' + (parseError.textContent ?? '').slice(0, 200));

  const gte = (parent: Element | Document, tag: string): Element | null =>
    parent.getElementsByTagName(tag).length > 0 ? parent.getElementsByTagName(tag)[0]! : null;

  const text = (parent: Element | Document, tag: string): string => gte(parent, tag)?.textContent?.trim() ?? '';

  const metadata = gte(doc, 'report_metadata');
  const policy = gte(doc, 'policy_published');
  const records = doc.getElementsByTagName('record');

  if (!metadata)
    throw new Error('Could not find <report_metadata> in XML - invalid or unsupported DMARC report format.');
  if (!policy)
    throw new Error('Could not find <policy_published> in XML - invalid or unsupported DMARC report format.');
  if (records.length === 0) throw new Error('No <record> elements found in XML - report may be empty.');

  const ipMap = new Map<string, DmarcRecord>();
  for (let i = 0; i < records.length; i++) {
    const rec = records[i]!;
    const row = gte(rec, 'row');
    if (!row) continue;
    const ip = text(row, 'source_ip');
    const count = parseInt(text(row, 'count'), 10) || 0;
    const evaluated = gte(row, 'policy_evaluated');
    if (!evaluated) continue;
    const disposition = text(evaluated, 'disposition');
    const spf = text(evaluated, 'spf');
    const dkim = text(evaluated, 'dkim');
    const headerFrom = text(rec, 'header_from');
    if (!ip) continue;

    const existing = ipMap.get(ip);
    if (existing) {
      existing.count += count;
      if (spf === 'pass' && existing.spf !== 'fail') existing.spf = 'pass';
      if (spf === 'fail') existing.spf = 'fail';
      if (dkim === 'pass' && existing.dkim !== 'fail') existing.dkim = 'pass';
      if (dkim === 'fail') existing.dkim = 'fail';
      if (disposition === 'reject' || disposition === 'quarantine') existing.disposition = disposition;
    } else {
      ipMap.set(ip, { sourceIp: ip, count, disposition, spf, dkim, headerFrom });
    }
  }

  const begin = parseInt(text(metadata, 'begin'), 10);
  const end = parseInt(text(metadata, 'end'), 10);

  return {
    orgName: text(metadata, 'org_name'),
    email: text(metadata, 'email'),
    domain: text(policy, 'domain'),
    policy: text(policy, 'p'),
    subdomainPolicy: text(policy, 'sp'),
    pct: text(policy, 'pct'),
    beginDate: begin ? new Date(begin * 1000).toISOString().slice(0, 10) : 'unknown',
    endDate: end ? new Date(end * 1000).toISOString().slice(0, 10) : 'unknown',
    records: Array.from(ipMap.values()).sort((a, b) => b.count - a.count),
  };
}

const RE_IP = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

async function enrichIp(ip: string, signal: AbortSignal): Promise<IpEnrichment | null> {
  try {
    const res = await fetch(`/api/v1/ip-geo?ip=${encodeURIComponent(ip)}`, { signal });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      geo?: { org?: string; country?: string; country_code?: string; asn?: string; asname?: string; isp?: string };
    };
    if (!data.geo || Object.keys(data.geo).length === 0) return null;
    return {
      org: data.geo?.org,
      country: data.geo?.country,
      country_code: data.geo?.country_code,
      asn: data.geo?.asn,
      asname: data.geo?.asname,
      isp: data.geo?.isp,
    };
  } catch (_catchErr) {
    console.error('enrichIp failed:', errMessage(_catchErr));
    return null;
  }
}

export default function DmarcAnalyzer(): JSX.Element {
  const [report, setReport] = useState<DmarcReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  const enrichAll = useCallback(async (records: DmarcRecord[]) => {
    const ips = records
      .map((r) => r.sourceIp)
      .filter((ip) => RE_IP.test(ip))
      .filter((ip, i, a) => a.indexOf(ip) === i);

    if (ips.length === 0) return;

    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setEnriching(true);

    const results = new Map<string, IpEnrichment>();
    const BATCH = 5;
    for (let i = 0; i < ips.length; i += BATCH) {
      if (ctrl.signal.aborted) break;
      const batch = ips.slice(i, i + BATCH);
      const enriched = await Promise.all(batch.map((ip) => enrichIp(ip, ctrl.signal)));
      for (let j = 0; j < batch.length; j++) {
        if (enriched[j]!) results.set(batch[j]!, enriched[j]!);
      }
    }

    if (!ctrl.signal.aborted) {
      setReport((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          records: prev.records.map((r) => ({
            ...r,
            enrichment: results.get(r.sourceIp),
          })),
        };
      });
    }
    setEnriching(false);
  }, []);

  const processFile = useCallback(
    async (file: File) => {
      setLoading(true);
      setEnriching(false);
      setError(null);
      setReport(null);
      setFileName(file.name);

      try {
        if (file.size > 25 * 1024 * 1024) throw new Error('File too large (max 25 MB compressed).');
        const buf = await file.arrayBuffer();
        let xml: string;

        if (file.name.endsWith('.gz')) {
          const decompressed = await unzip(buf);
          xml = new TextDecoder().decode(decompressed);
        } else if (file.name.endsWith('.zip')) {
          const { default: JSZip } = await import('jszip');
          const zip = await JSZip.loadAsync(buf);
          const firstXml = Object.keys(zip.files).find((n) => n.endsWith('.xml'));
          if (!firstXml) throw new Error('No XML file found in zip archive');
          const entry = zip.files[firstXml];
          const uncompressed = (entry as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize;
          if (uncompressed && uncompressed > MAX_DECOMPRESSED) throw new Error('Decompressed XML exceeds size limit.');
          xml = await entry!.async('text');
        } else {
          xml = new TextDecoder().decode(buf);
        }

        const parsed = parseDmarcXml(xml);
        if (parsed.records.length === 0) throw new Error('No DMARC records found in the XML');
        setReport(parsed);
        enrichAll(parsed.records);
      } catch (e) {
        logCatch(e);
        setError(errMessage(e, 'Failed to parse DMARC report'));
      } finally {
        setLoading(false);
      }
    },
    [enrichAll]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const handleFile = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) processFile(file);
    },
    [processFile]
  );

  const exportCsv = () => {
    if (!report) return;
    const header = 'Source IP,Count,SPF,DKIM,Disposition,Header From,DMARC Pass,Organization,Country,ASN,ISP\n';
    const rows = report.records
      .map((r) => {
        const dmarcPass = r.spf === 'pass' || r.dkim === 'pass' ? 'PASS' : 'FAIL';
        const org = r.enrichment?.org?.replace(/,/g, ' ') ?? '';
        const country = r.enrichment?.country ?? '';
        const asn = r.enrichment?.asn ?? '';
        const isp = r.enrichment?.isp?.replace(/,/g, ' ') ?? '';
        return `${r.sourceIp},${r.count},${r.spf},${r.dkim},${r.disposition},${r.headerFrom},${dmarcPass},"${org}","${country}","${asn}","${isp}"`;
      })
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    downloadBlob(blob, `dmarc-${report.domain}-${report.beginDate}-${report.endDate}.csv`);
  };

  const totalEmails = report?.records.reduce((s, r) => s + r.count, 0) ?? 0;
  const passCount =
    report?.records.filter((r) => r.spf === 'pass' || r.dkim === 'pass').reduce((s, r) => s + r.count, 0) ?? 0;
  const passRate = totalEmails ? ((passCount / totalEmails) * 100).toFixed(1) : '0';
  const failRecords = report?.records.filter((r) => r.spf === 'fail' && r.dkim === 'fail') ?? [];
  const enrichedCount = report?.records.filter((r) => r.enrichment).length ?? 0;

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Shield size={28} />}
      title="DMARC RUA Analyzer"
      description="Parse & analyze your DMARC aggregate (RUA) XML reports - XML parsed in-browser, IPs enriched via real-time WHOIS/GeoIP."
      headerExtra={
        <p className="text-xs text-muted font-mono">
          Inspired by{' '}
          <a
            href="https://www.dmarclabsds1.xyz/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            DMARC Labs
          </a>
          .
        </p>
      }
      maxWidthClass="max-w-7xl"
    >
      <div className="flex flex-wrap gap-4 mb-6">
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-full px-3 py-1">
          <CheckCircle2 size={12} /> No signup
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-sky-700 dark:text-sky-300 bg-sky-500/10 border border-sky-500/30 rounded-full px-3 py-1">
          <CheckCircle2 size={12} /> Files never stored
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-amber-700 dark:text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-full px-3 py-1">
          <Loader2 size={12} /> Up to 25 MB
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-fuchsia-700 dark:text-fuchsia-300 bg-fuchsia-500/10 border border-fuchsia-500/30 rounded-full px-3 py-1">
          <CheckCircle2 size={12} /> .xml .gz .zip
        </div>
      </div>

      <div
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative rounded-xl border-2 border-dashed p-12 text-center cursor-pointer transition-colors mb-8 ${
          dragOver
            ? 'border-brand-500 bg-brand-500/5'
            : 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200/50 hover:border-brand-400 hover:bg-brand-500/5'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".xml,.gz,.zip"
          onChange={handleFile}
          className="hidden"
          aria-label="Upload DMARC XML report"
        />
        <Upload size={36} className="mx-auto mb-3 text-muted" />
        <p className="text-sm font-mono text-muted mb-1">Drag &amp; drop your DMARC XML report here</p>
        <p className="text-xs text-muted font-mono">or click to browse - .xml, .gz, .zip up to 25 MB</p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 mb-8 flex items-start gap-3">
          <AlertTriangle size={18} className="text-rose-600 dark:text-rose-400 mt-0.5 shrink-0" />
          <div>
            <p className="font-mono text-sm text-rose-700 dark:text-rose-300">{error}</p>
          </div>
        </div>
      )}

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 size={24} className="animate-spin text-brand-600 dark:text-brand-400" />
          <span className="ml-3 font-mono text-sm text-muted">Parsing DMARC report...</span>
        </div>
      )}

      {report && (
        <div className="animate-fade-in-up space-y-6">
          <div className="surface-card p-6">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <h2 className="text-lg font-display font-bold">{report.domain}</h2>
              <button
                onClick={exportCsv}
                className="inline-flex items-center gap-2 text-xs font-mono border border-line-2 rounded-xl px-3 py-1.5 hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
              >
                <Download size={14} /> Export CSV
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
              <div className="rounded-xl bg-surface-200 p-3">
                <p className="text-xs text-muted font-mono">Total Emails</p>
                <p className="text-2xl font-bold">{totalEmails.toLocaleString()}</p>
              </div>
              <div className="rounded-xl bg-surface-200 p-3">
                <p className="text-xs text-muted font-mono">DMARC Pass Rate</p>
                <p className="text-2xl font-bold">{passRate}%</p>
              </div>
              <div className="rounded-xl bg-surface-200 p-3">
                <p className="text-xs text-muted font-mono">Unique IPs</p>
                <p className="text-2xl font-bold">{report.records.length}</p>
              </div>
              <div className="rounded-xl bg-surface-200 p-3">
                <p className="text-xs text-muted font-mono">Report Period</p>
                <p className="text-sm font-bold">
                  {report.beginDate} - {report.endDate}
                </p>
              </div>
            </div>

            <div className="text-xs text-muted font-mono space-y-1">
              <p>
                Report from: <span className="text-body">{report.orgName}</span>
              </p>
              <p>
                Policy:{' '}
                <span className="text-body">
                  p={report.policy || 'none'} sp={report.subdomainPolicy || 'none'} pct={report.pct || 100}%
                </span>
              </p>
              <p>
                File: <span className="text-body">{fileName}</span>
              </p>
            </div>
          </div>

          {failRecords.length > 0 && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
              <AlertTriangle size={18} className="text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
              <div>
                <p className="font-semibold text-sm text-amber-800 dark:text-amber-200">
                  {failRecords.length} IP{failRecords.length > 1 ? 's' : ''} with both SPF and DKIM failing
                </p>
                <p className="text-xs text-amber-700 dark:text-amber-300 font-mono mt-1">
                  These senders are not authorized to send email for {report.domain}. Total failing volume:{' '}
                  {failRecords.reduce((s, r) => s + r.count, 0).toLocaleString()} emails.
                </p>
              </div>
            </div>
          )}

          {enriching && (
            <div className="flex items-center gap-2 text-xs font-mono text-sky-700 dark:text-sky-300">
              <Loader2 size={12} className="animate-spin" />
              Enriching IPs with WHOIS/GeoIP data ({enrichedCount}/{report.records.length})...
            </div>
          )}

          <div className="surface-card overflow-hidden">
            <div className="overflow-x-auto">
              <DataTable
                columns={
                  [
                    {
                      key: 'sourceIp',
                      header: 'Source IP',
                      sortValue: (r: (typeof report.records)[number]) => r.sourceIp,
                      render: (r) => <span className="text-xs">{r.sourceIp}</span>,
                    },
                    {
                      key: 'org',
                      header: 'Organization',
                      sortValue: (r: (typeof report.records)[number]) => r.enrichment?.org ?? '',
                      render: (r) => (
                        <span className="text-xs max-w-[200px] truncate" title={r.enrichment?.org}>
                          {r.enrichment?.org ?? '-'}
                        </span>
                      ),
                    },
                    {
                      key: 'country',
                      header: 'Country',
                      sortValue: (r: (typeof report.records)[number]) => r.enrichment?.country ?? '',
                      render: (r) => <span className="text-xs">{r.enrichment?.country ?? '-'}</span>,
                    },
                    {
                      key: 'count',
                      header: 'Volume',
                      align: 'right',
                      sortValue: (r: (typeof report.records)[number]) => r.count,
                      render: (r) => <span className="text-xs">{r.count.toLocaleString()}</span>,
                    },
                    {
                      key: 'spf',
                      header: 'SPF',
                      align: 'center',
                      sortValue: (r: (typeof report.records)[number]) => r.spf,
                      render: (r) =>
                        r.spf === 'pass' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 text-xs">
                            <CheckCircle2 size={12} /> pass
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400 text-xs">
                            <XCircle size={12} /> {r.spf}
                          </span>
                        ),
                    },
                    {
                      key: 'dkim',
                      header: 'DKIM',
                      align: 'center',
                      sortValue: (r: (typeof report.records)[number]) => r.dkim,
                      render: (r) =>
                        r.dkim === 'pass' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 text-xs">
                            <CheckCircle2 size={12} /> pass
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400 text-xs">
                            <XCircle size={12} /> {r.dkim}
                          </span>
                        ),
                    },
                    {
                      key: 'dmarc',
                      header: 'DMARC',
                      align: 'center',
                      render: (r) => {
                        const dmarcPass = r.spf === 'pass' || r.dkim === 'pass';
                        return (
                          <span
                            className={`inline-flex items-center gap-1 text-xs font-medium ${dmarcPass ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}
                          >
                            {dmarcPass ? 'PASS' : 'FAIL'}
                          </span>
                        );
                      },
                    },
                    {
                      key: 'headerFrom',
                      header: 'Header From',
                      sortValue: (r: (typeof report.records)[number]) => r.headerFrom,
                      render: (r) => (
                        <span className="text-xs max-w-[160px] truncate" title={r.headerFrom}>
                          {r.headerFrom}
                        </span>
                      ),
                    },
                  ] as DataTableColumn<(typeof report.records)[number]>[]
                }
                rows={report.records}
                rowKey={(r) => r.sourceIp}
                rowClassName={(r) => (r.spf !== 'pass' && r.dkim !== 'pass' ? 'bg-rose-50/30 dark:bg-rose-950/10' : '')}
              />
            </div>
          </div>

          <div className="rounded-xl border border-line-1 bg-surface-200 p-4">
            <h3 className="text-sm font-display font-semibold mb-2">Privacy</h3>
            <p className="text-xs text-muted font-mono">
              DMARC XML is parsed entirely in your browser. IPs are enriched server-side via the same edge API used by
              the{' '}
              <Link to="/dfir/ioc-investigate" className="text-brand-600 dark:text-brand-400 hover:underline">
                IP Geo
              </Link>{' '}
              tool - no file content is uploaded. Results are ephemeral and disappear on page refresh.
            </p>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
