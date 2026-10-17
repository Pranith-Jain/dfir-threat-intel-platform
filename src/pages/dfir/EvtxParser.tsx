import { errMessage, logCatch } from '../../lib/log';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ScrollText, Upload, Loader2 } from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { fileTooLarge, yieldToPaint } from '../../lib/dfir/file-guard';

/**
 * EVTX Parser (Lite). A full Windows BinXML template engine is enormous;
 * for IR triage what matters is: which records exist, when, and the
 * readable strings (provider, channel, computer, EventData). This walks
 * the real EVTX structure (ElfFile → ElfChnk → event records) and pulls
 * the record FileTime + decoded UTF-16 strings from each record's BinXML.
 * Honest scope: structural + string extraction, not full XML render.
 */
interface Rec {
  id: number;
  time: string;
  strings: string[];
}

const CHUNK = 0x10000;
const MAX = 20000;

function ft(lo: number, hi: number): string {
  const ms = (hi * 2 ** 32 + lo) / 1e4 - 11644473600000;
  return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : '';
}

/** Pull printable UTF-16LE runs (≥3 chars) from a byte range. */
function strings(u8: Uint8Array, start: number, end: number): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = start; i + 1 < end; i += 2) {
    const c = u8[i]! | (u8[i + 1]! << 8);
    if (c >= 0x20 && c < 0xfffd && u8[i + 1]! < 0x20) {
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= 3) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 3) out.push(cur);
  // De-dupe consecutive repeats, drop pure-whitespace.
  return out.filter((s, i) => s.trim() && s !== out[i - 1]);
}

function parse(buf: ArrayBuffer): { records: Rec[]; chunks: number } {
  const d = new DataView(buf);
  const u8 = new Uint8Array(buf);
  if (String.fromCharCode(...u8.subarray(0, 7)) !== 'ElfFile') throw new Error('not an EVTX file (bad ElfFile magic)');
  const records: Rec[] = [];
  let chunks = 0;
  for (let base = 0x1000; base + 512 < buf.byteLength && records.length < MAX; base += CHUNK) {
    if (String.fromCharCode(...u8.subarray(base, base + 7)) !== 'ElfChnk') continue;
    chunks++;
    let p = base + 512; // chunk header is 512 bytes; records follow
    const chunkEnd = Math.min(base + CHUNK, buf.byteLength);
    while (p + 24 < chunkEnd && records.length < MAX) {
      if (d.getUint32(p, true) !== 0x00002a2a) break; // record magic "**\0\0"
      const size = d.getUint32(p + 4, true);
      if (size < 24 || p + size > chunkEnd) break;
      const recId = Number(d.getBigUint64(p + 8, true));
      const time = ft(d.getUint32(p + 16, true), d.getUint32(p + 20, true));
      records.push({ id: recId, time, strings: strings(u8, p + 24, p + size - 4).slice(0, 24) });
      p += size;
    }
  }
  return { records, chunks };
}

export default function EvtxParser(): JSX.Element {
  const [data, setData] = useState<{ records: Rec[]; chunks: number } | null>(null);
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);

  const shown = useMemo(() => {
    if (!data) return [];
    const t = q.trim().toLowerCase();
    return (t ? data.records.filter((r) => r.strings.some((s) => s.toLowerCase().includes(t))) : data.records).slice(
      0,
      2000
    );
  }, [data, q]);

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
        <ScrollText size={22} className="text-brand-600 dark:text-brand-400" />
        EVTX Parser <span className="text-sm font-mono text-muted">Lite</span>
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop a Windows <code>.evtx</code> log. Walks the real ElfFile → ElfChnk → record structure and extracts each
        record's timestamp + readable BinXML strings (provider, channel, computer, EventData). Lightweight triage view,
        not a full XML render. 100% client-side.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('evtxparser-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop a .evtx file file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">Drop a .evtx file file here, or click to choose</p>
        <p className="text-mini font-mono text-muted mt-1">100% client-side. No upload.</p>
      </button>
      <input
        id="evtxparser-input"
        type="file"
        accept=".evtx"
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const tooBig = fileTooLarge(f.size);
          if (tooBig) {
            setData(null);
            setErr(tooBig);
            return;
          }
          setErr('');
          setBusy(true);
          try {
            await yieldToPaint();
            setData(parse(await f.arrayBuffer()));
          } catch (ex) {
            logCatch(ex);
            setData(null);
            setErr(errMessage(ex));
          } finally {
            setBusy(false);
          }
        }}
      />

      {busy && (
        <p className="mt-4 inline-flex items-center gap-2 font-mono text-sm text-muted">
          <Loader2 size={14} className="animate-spin" /> parsing…
        </p>
      )}
      {err && <p className="mt-4 font-mono text-sm text-rose-600 dark:text-rose-400">{err}</p>}

      {data && (
        <div className="mt-6 space-y-3">
          <div className="font-mono text-meta text-muted">
            {data.records.length.toLocaleString()} records · {data.chunks} chunks
            {data.records.length >= MAX ? ` (capped at ${MAX})` : ''}
          </div>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter strings - e.g. 4624, powershell, lateral host…"
            aria-label="Filter parsed events by string"
            className="w-full surface-card px-3 py-2 font-mono text-sm focus:border-brand-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40"
          />
          <ul className="space-y-2">
            {shown.map((r) => (
              <li key={r.id} className="surface-card p-3">
                <div className="font-mono text-mini text-muted mb-1">
                  record #{r.id} · {r.time}
                </div>
                <div className="font-mono text-mini text-body break-all">{r.strings.join('  ·  ')}</div>
              </li>
            ))}
          </ul>
          {shown.length === 0 && <p className="font-mono text-meta text-muted">No records match the filter.</p>}
        </div>
      )}
    </div>
  );
}
