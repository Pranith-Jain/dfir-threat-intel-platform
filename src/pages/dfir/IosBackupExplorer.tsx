import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Smartphone, Upload } from 'lucide-react';
import { loadSql } from '../../lib/loadSql';
import { fileTooLarge } from '../../lib/dfir/file-guard';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { BackLink } from '../../components/BackLink';
import { useDebounce } from '../../hooks/useDebounce';
import { errMessage } from '../../lib/log';

interface FileRow {
  domain: string;
  path: string;
  fileID: string;
  flags: number;
}

export default function IosBackupExplorer(): JSX.Element {
  const [files, setFiles] = useState<FileRow[] | null>(null);
  const [domains, setDomains] = useState<Array<[string, number]>>([]);
  const [q, setQ] = useState('');
  // The input stays bound to `q` for instant feedback; the 20k-row filter
  // below only runs ~120ms after typing settles, off the debounced value.
  const debouncedQ = useDebounce(q, 120);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function open(file: File) {
    setBusy(true);
    setErr('');
    const tooBig = fileTooLarge(file.size);
    if (tooBig) {
      setErr(tooBig);
      setBusy(false);
      return;
    }
    let db: { close?: () => void } | null = null;
    try {
      const SQL = await loadSql();
      const d = new SQL.Database(new Uint8Array(await file.arrayBuffer()));
      db = d;
      // Manifest.db: Files(fileID, domain, relativePath, flags, file)
      const res = d.exec('SELECT domain, relativePath, fileID, flags FROM Files ORDER BY domain LIMIT 20000');
      if (res.length === 0) throw new Error('No Files table - is this an iOS Manifest.db?');
      const rows: FileRow[] = res[0]!.values.map((r: unknown[]) => ({
        domain: String(r[0] ?? ''),
        path: String(r[1] ?? ''),
        fileID: String(r[2] ?? ''),
        flags: Number(r[3] ?? 0),
      }));
      const dc = new Map<string, number>();
      for (const f of rows) dc.set(f.domain, (dc.get(f.domain) ?? 0) + 1);
      setFiles(rows);
      setDomains([...dc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40));
    } catch (e) {
      console.error('open failed:', errMessage(e));
      setErr(errMessage(e));
      setFiles(null);
    } finally {
      // Free the WASM-backed handle - rows/domains are already materialized
      // into plain JS, so the sql.js Database is no longer needed.
      db?.close?.();
      setBusy(false);
    }
  }

  const shown = useMemo(() => {
    if (!files) return [];
    const t = debouncedQ.trim().toLowerCase();
    return (t ? files.filter((f) => `${f.domain} ${f.path}`.toLowerCase().includes(t)) : files).slice(0, 1000);
  }, [files, debouncedQ]);

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-6 text-heading">
      <BackLink to="/dfir">back</BackLink>
      <Link
        to="/dfir/catalog?cat=artifacts"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        DFIR tools
      </Link>
      <h1 className="font-display font-bold text-2xl flex items-center gap-2">
        <Smartphone size={22} className="text-brand-600 dark:text-brand-400" />
        iOS Backup Explorer
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop an iOS backup <code>Manifest.db</code> - enumerates the backed-up file inventory by domain and path (Files
        table). sql.js runs as a lazy WASM chunk; nothing is uploaded.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('iosbackup-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop a Manifest.db file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">
          {busy ? 'Loading...' : 'Drop Manifest.db here, or click to choose'}
        </p>
        <p className="text-mini font-mono text-muted mt-1">iOS backup SQLite database. 100% client-side.</p>
      </button>
      <input
        id="iosbackup-input"
        type="file"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void open(f);
        }}
      />
      {err && <p className="mt-3 font-mono text-sm text-rose-600 dark:text-rose-400">{err}</p>}

      {files && (
        <div className="mt-6 space-y-4">
          <div className="surface-card p-3">
            <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">
              Top domains · {files.length.toLocaleString()} files total
            </div>
            <div className="flex flex-wrap gap-1.5">
              {domains.map(([dn, c]) => (
                <button
                  key={dn}
                  type="button"
                  onClick={() => setQ(dn)}
                  className="font-mono text-mini px-1.5 py-0.5 rounded border border-line-1 text-body hover:border-brand-500/40"
                >
                  {dn || '(none)'} · {c}
                </button>
              ))}
            </div>
          </div>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter by domain / path - e.g. CameraRollDomain, sms.db, WhatsApp…"
            className="w-full surface-card px-3 py-2 font-mono text-sm focus:border-brand-500 focus:outline-none"
          />
          <div className="rounded-xl border border-line-1 overflow-auto max-h-[60vh]">
            <DataTable
              columns={
                [
                  {
                    key: 'domain',
                    header: 'domain',
                    sortValue: (f: (typeof shown)[number]) => f.domain,
                    render: (f) => f.domain,
                  },
                  {
                    key: 'relativePath',
                    header: 'relativePath',
                    sortValue: (f: (typeof shown)[number]) => f.path,
                    render: (f) => <span className="break-all">{f.path}</span>,
                  },
                  {
                    key: 'fileID',
                    header: 'fileID',
                    sortValue: (f: (typeof shown)[number]) => f.fileID,
                    render: (f) => <span className="text-muted">{f.fileID.slice(0, 12)}…</span>,
                  },
                ] as DataTableColumn<(typeof shown)[number]>[]
              }
              rows={shown}
              rowKey={(f, i) => `${f.fileID}-${i}`}
              rowClassName={() => '[&:nth-child(even)]:bg-slate-50/50 dark:[&:nth-child(even)]:bg-surface-200/50'}
            />
          </div>
          <p className="font-mono text-mini text-muted">showing {shown.length} (filtered, capped 1000)</p>
        </div>
      )}
    </div>
  );
}
