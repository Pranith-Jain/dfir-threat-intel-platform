import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Paperclip, Loader2, AlertTriangle, FileText, ShieldAlert, ScanText, FileSearch } from 'lucide-react';
import { parseEml, type ParsedEml, type EmlAttachment } from '../../lib/dfir/eml-parser';
import { CopyChip } from '../../components/dfir/CopyButton';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { errMessage } from '../../lib/log';

const SAMPLE_EML = `MIME-Version: 1.0
From: "Test Sender" <sender@example.com>
To: recipient@example.org
Subject: =?UTF-8?B?VGVzdCBhdHRhY2htZW50IGV4dHJhY3Rpb24=?=
Date: Fri, 10 May 2024 09:00:00 +0000
Content-Type: multipart/mixed; boundary="boundary-demo"

--boundary-demo
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi,

Please find attached the report.

Regards
--boundary-demo
Content-Type: text/plain; charset="utf-8"; name="report.txt"
Content-Disposition: attachment; filename="report.txt"
Content-Transfer-Encoding: base64

VGhpcyBpcyB0aGUgY29udGVudHMgb2YgdGhlIGZpcnN0IGF0dGFjaG1lbnQu
TWFsd2FyZSBoYXNoIGV4YW1wbGUgZm9yIHRlc3RpbmcgcHVycG9zZXMu
--boundary-demo
Content-Type: image/png; name="logo.png"
Content-Disposition: inline; filename="logo.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgAAIAAAUAAeImBZsAAAAASUVORK5CYII=
--boundary-demo--
`;

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export default function EmlExtractor(): JSX.Element {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const [parsed, setParsed] = useState<ParsedEml | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function pipeToExtractor() {
    sessionStorage.setItem('ioc-extractor-pipe', input);
    navigate('/dfir/extract?from=eml');
  }

  const onFile = async (file: File) => {
    if (file.size > 10 * 1024 * 1024) {
      setError(`File too large: ${fmtBytes(file.size)} > 10 MB max`);
      return;
    }
    const text = await file.text();
    setInput(text);
    void run(text);
  };

  const run = async (eml: string) => {
    if (!eml.trim()) return;
    setLoading(true);
    setError(null);
    setParsed(null);
    try {
      const r = await parseEml(eml);
      setParsed(r);
    } catch (e) {
      console.error('pipeToExtractor failed:', errMessage(e));
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Paperclip size={28} />}
      title="EML Attachment Extractor"
      description={
        <>
          Drop or paste a raw <code>.eml</code> file. Each attachment is decoded (base64 / quoted-printable), hashed
          (SHA-256 + SHA-1 + MD5), and gets a one-click pivot to{' '}
          <Link to="/dfir/ioc-investigate" className="text-brand-600 dark:text-brand-400 hover:underline">
            IOC Investigator
          </Link>{' '}
          for multi-engine reputation. Pure client-side - nothing leaves your browser.
          <p className="text-xs text-muted font-mono mt-2">
            Pairs with{' '}
            <Link to="/dfir/phishing" className="text-brand-600 dark:text-brand-400 hover:underline">
              Phishing analyzer
            </Link>{' '}
            (header / URL / risk-flag analysis) and{' '}
            <Link to="/dfir/extract" className="text-brand-600 dark:text-brand-400 hover:underline">
              IOC Extractor
            </Link>{' '}
            (pull URLs, IPs, domains, hashes from raw text). 10 MB max input; 5 MB per part.
          </p>
        </>
      }
    >
      {/* Input */}
      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">Input</h2>
          <div className="flex flex-wrap gap-1.5">
            <label className="text-mini font-mono px-2 py-1 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 cursor-pointer">
              upload .eml
              <input
                type="file"
                accept=".eml,message/rfc822,text/plain"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void onFile(f);
                  // Reset so re-selecting the SAME file still fires onChange.
                  e.target.value = '';
                }}
                className="hidden"
              />
            </label>
            <button
              type="button"
              onClick={() => {
                setInput(SAMPLE_EML);
                void run(SAMPLE_EML);
              }}
              className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
            >
              load sample
            </button>
            {input && (
              <button
                type="button"
                onClick={() => {
                  setInput('');
                  setParsed(null);
                  setError(null);
                }}
                className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
              >
                clear
              </button>
            )}
          </div>
        </div>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paste the raw .eml content here, or use the upload button. Headers + multipart body are parsed; attachments are decoded + hashed locally."
          rows={12}
          className="w-full px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-mini text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          spellCheck={false}
        />
        <div className="flex items-center justify-end gap-2 mt-3">
          <button
            type="button"
            onClick={pipeToExtractor}
            disabled={!input.trim()}
            className="px-3 py-2 rounded border border-line-1 hover:border-brand-500/40 font-mono text-sm disabled:opacity-50 inline-flex items-center gap-2 text-body transition-colors"
          >
            <FileSearch size={14} />
            Extract IOCs →
          </button>
          <button
            type="button"
            onClick={() => void run(input)}
            disabled={loading || !input.trim()}
            className="px-4 py-2 rounded bg-brand-600 hover:bg-brand-700 text-on-fill font-mono text-sm disabled:opacity-50 inline-flex items-center gap-2"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <ScanText size={14} />}
            {loading ? 'parsing…' : 'parse + hash'}
          </button>
        </div>
      </section>

      {error && (
        <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4 inline-flex items-center gap-2">
          <AlertTriangle size={14} /> {error}
        </p>
      )}

      {parsed && (
        <>
          {/* Header summary */}
          <section className="surface-card p-4 mb-6">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
              Header summary
            </h2>
            <dl className="grid sm:grid-cols-[140px_1fr] gap-x-4 gap-y-1 text-meta font-mono">
              <dt className="text-muted">Subject</dt>
              <dd className="text-heading break-words">{parsed.subject ?? '-'}</dd>
              <dt className="text-muted">From</dt>
              <dd className="text-heading break-words">{parsed.from ?? '-'}</dd>
              <dt className="text-muted">To</dt>
              <dd className="text-heading break-words">{parsed.to ?? '-'}</dd>
              <dt className="text-muted">Date</dt>
              <dd className="text-heading">{parsed.date ?? '-'}</dd>
              <dt className="text-muted">Content-Type</dt>
              <dd className="text-heading break-all">{parsed.contentType ?? '-'}</dd>
            </dl>
          </section>

          {/* Attachments */}
          <section className="surface-card p-4 mb-6">
            <div className="flex items-baseline justify-between gap-2 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono inline-flex items-center gap-2">
                <Paperclip size={12} /> Attachments ({parsed.attachments.length})
              </h2>
            </div>
            {parsed.attachments.length === 0 ? (
              <p className="text-sm font-mono text-muted">
                No attachments detected. (Multipart bodies without filenames or non-attachment dispositions are
                ignored.)
              </p>
            ) : (
              <ul className="space-y-3">
                {parsed.attachments.map((a, i) => (
                  <Attachment key={`${a.sha256}-${i}`} att={a} />
                ))}
              </ul>
            )}
          </section>

          {parsed.warnings.length > 0 && (
            <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 mb-6">
              <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-amber-700 dark:text-amber-300 font-mono mb-2">
                Warnings
              </h3>
              <ul className="text-meta font-mono text-amber-800 dark:text-amber-200 space-y-1">
                {parsed.warnings.map((w, i) => (
                  <li key={i}>• {w}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Raw headers (collapsible) */}
          <section className="surface-card p-4 mb-6">
            <details>
              <summary className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono cursor-pointer inline-flex items-center gap-2">
                <FileText size={12} /> All headers ({parsed.headers.length}) - click to expand
              </summary>
              <dl className="grid sm:grid-cols-[180px_1fr] gap-x-4 gap-y-1 text-mini font-mono mt-3 max-h-96 overflow-auto">
                {parsed.headers.map((h, i) => (
                  <div key={`${h.name}-${i}`} className="contents">
                    <dt className="text-muted break-words">{h.name}</dt>
                    <dd className="text-heading break-all border-b border-line-1 pb-1">{h.value}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </section>
        </>
      )}

      <RelatedWikiArticles />
    </DataPageLayout>
  );
}

function Attachment({ att }: { att: EmlAttachment }): JSX.Element {
  const dispoCls =
    att.disposition === 'attachment'
      ? 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
      : att.disposition === 'inline'
        ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
        : 'border-slate-300 dark:border-line-1 text-slate-500';

  return (
    <li className="rounded border border-line-1 bg-surface-200 p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2 mb-2">
        <span className="font-display font-semibold text-sm text-heading break-all">{att.filename}</span>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${dispoCls}`}>
            {att.disposition}
          </span>
          <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300">
            {att.contentType}
          </span>
          <span className="text-micro font-mono text-muted">{fmtBytes(att.size)}</span>
          {att.truncated && (
            <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300">
              truncated @ 5MB
            </span>
          )}
        </div>
      </div>
      <ul className="space-y-1 text-mini font-mono">
        <HashRow label="SHA-256" value={att.sha256} />
        <HashRow label="SHA-1" value={att.sha1} />
        <HashRow label="MD5" value={att.md5} />
      </ul>
    </li>
  );
}

function HashRow({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <li className="flex items-center gap-2">
      <span className="text-muted w-16 shrink-0">{label}</span>
      <span className="text-heading break-all flex-1">{value}</span>
      <CopyChip value={value} label="copy" />
      <Link
        to={`/dfir/ioc-check?indicator=${value}`}
        className="text-micro font-mono inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/5 text-rose-700 dark:text-rose-300 hover:bg-rose-500/10"
        title="Multi-engine hash reputation lookup"
      >
        <ShieldAlert size={9} /> file lookup
      </Link>
    </li>
  );
}
