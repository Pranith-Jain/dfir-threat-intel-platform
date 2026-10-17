import { errMessage, logCatch } from '../../lib/log';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, Upload, Loader2 } from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { fileTooLarge, yieldToPaint, MAX_PARSE_BYTES } from '../../lib/dfir/file-guard';

/* ── LZXPRESS Huffman decompression ([MS-XCA] 2.2) - for Win8+/Win10+ ──
   prefetch, which is wrapped in a MAM\x04 container. */
function decompressLzxpressHuffman(src: Uint8Array, outSize: number): Uint8Array {
  if (!Number.isFinite(outSize) || outSize < 0 || outSize > MAX_PARSE_BYTES)
    throw new Error('MAM declared output size out of range');
  const out = new Uint8Array(outSize);
  let op = 0;
  let ip = 0;

  while (op < outSize) {
    if (ip >= src.length) throw new Error('truncated MAM stream');
    // 256-byte Huffman table → 512 four-bit code lengths.
    const lengths = new Uint8Array(512);
    for (let i = 0; i < 256; i++) {
      const b = src[ip + i]!;
      lengths[i * 2] = b & 0x0f;
      lengths[i * 2 + 1] = b >> 4;
    }
    ip += 256;

    // Canonical Huffman → flat 2^15 lookup (symbol + code length).
    const symTab = new Int16Array(1 << 15);
    const lenTab = new Uint8Array(1 << 15);
    let code = 0;
    for (let bits = 1; bits <= 15; bits++) {
      for (let sym = 0; sym < 512; sym++) {
        if (lengths[sym] !== bits) continue;
        const start = code << (15 - bits);
        const cnt = 1 << (15 - bits);
        for (let j = 0; j < cnt; j++) {
          symTab[start + j] = sym;
          lenTab[start + j] = bits;
        }
        code++;
      }
      code <<= 1;
    }

    const rd16 = () => {
      const v = src[ip]! | (src[ip + 1]! << 8);
      ip += 2;
      return v;
    };
    let bitbuf = ((rd16() << 16) | rd16()) >>> 0;
    let avail = 16;
    const readBits = (n: number): number => {
      if (n === 0) return 0;
      const r = (bitbuf >>> (32 - n)) & ((1 << n) - 1);
      bitbuf = (bitbuf << n) >>> 0;
      avail -= n;
      if (avail <= 16) {
        bitbuf = (bitbuf | (rd16() << (16 - avail))) >>> 0;
        avail += 16;
      }
      return r;
    };

    const blockEnd = Math.min(op + 65536, outSize);
    while (op < blockEnd) {
      const peek = bitbuf >>> 17; // top 15 bits
      const sym = symTab[peek]!;
      readBits(lenTab[peek]!);
      if (sym < 256) {
        out[op++] = sym;
      } else {
        const s = sym - 256;
        let len = s & 15;
        const distBits = s >> 4;
        if (len === 15) {
          len = src[ip++]! + 15;
          if (len === 270) {
            len = src[ip]! | (src[ip + 1]! << 8);
            ip += 2;
          }
        }
        len += 3;
        const dist = (1 << distBits) + readBits(distBits);
        for (let k = 0; k < len && op < outSize; k++) {
          out[op] = out[op - dist]!;
          op++;
        }
      }
    }
  }
  return out;
}

function utf16(u8: Uint8Array, off: number, maxBytes: number): string {
  let s = '';
  for (let i = off; i < off + maxBytes && i + 1 < u8.length; i += 2) {
    const c = u8[i]! | (u8[i + 1]! << 8);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function filetime(d: DataView, o: number): string {
  try {
    const lo = d.getUint32(o, true);
    const hi = d.getUint32(o + 4, true);
    const ms = (hi * 2 ** 32 + lo) / 1e4 - 11644473600000;
    return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : '';
  } catch (_catchErr) {
    console.error('filetime failed:', errMessage(_catchErr));
    return '';
  }
}

interface PF {
  version: string;
  exe: string;
  hash: string;
  runCount: number;
  lastRuns: string[];
  files: string[];
  note: string;
}

function parsePrefetch(buf: ArrayBuffer): PF {
  let u8: Uint8Array = new Uint8Array(buf);
  let note = '';
  // MAM\x04 → compressed (Win8+/Win10+).
  if (u8[0] === 0x4d && u8[1] === 0x41 && u8[2] === 0x4d) {
    const outSize = new DataView(buf).getUint32(4, true);
    u8 = decompressLzxpressHuffman(u8.subarray(8), outSize);
    note = 'MAM-compressed (Win8+/Win10+) - LZXPRESS-Huffman decompressed in-browser.';
  }
  const d = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const ver = d.getUint32(0, true);
  if (String.fromCharCode(u8[4]!, u8[5]!, u8[6]!, u8[7]!) !== 'SCCA') throw new Error('not a prefetch file (no SCCA)');
  const verLabel =
    (
      { 17: 'Windows XP', 23: 'Windows 7/Vista', 26: 'Windows 8', 30: 'Windows 10/11', 31: 'Windows 11' } as Record<
        number,
        string
      >
    )[ver] ?? `version ${ver}`;
  const exe = utf16(u8, 0x10, 60);
  const hash = '0x' + d.getUint32(0x4c, true).toString(16);

  const FI = 84; // File Information section offset (v17/23/26/30)
  const fnOff = d.getUint32(FI + 0x10, true);
  const fnSize = d.getUint32(FI + 0x14, true);
  const files: string[] = [];
  if (fnOff > 0 && fnOff + fnSize <= u8.length && fnSize < 5_000_000) {
    let cur = '';
    for (let i = fnOff; i + 1 < fnOff + fnSize; i += 2) {
      const c = u8[i]! | (u8[i + 1]! << 8);
      if (c === 0) {
        if (cur) files.push(cur);
        cur = '';
      } else cur += String.fromCharCode(c);
      if (files.length > 4000) break;
    }
    if (cur) files.push(cur);
  }

  let runCount = 0;
  const lastRuns: string[] = [];
  if (ver === 17) {
    lastRuns.push(filetime(d, FI + 0x78));
    runCount = d.getUint32(FI + 0x90, true);
  } else if (ver === 23) {
    lastRuns.push(filetime(d, FI + 0x80));
    runCount = d.getUint32(FI + 0x98, true);
  } else {
    // v26 / v30 / v31 - 8 FILETIME slots, run count later in the section.
    for (let i = 0; i < 8; i++) {
      const t = filetime(d, FI + 0x80 + i * 8);
      if (t) lastRuns.push(t);
    }
    runCount = d.getUint32(FI + 0xd0, true);
    if (!Number.isFinite(runCount) || runCount > 1e7) runCount = d.getUint32(FI + 0xc8, true);
  }

  return { version: verLabel, exe, hash, runCount: runCount >>> 0, lastRuns: lastRuns.filter(Boolean), files, note };
}

/** Cap on rendered file rows — a prefetch list can be very large. */
const MAX_RENDERED_FILES = 3000;
/** Stable empty array so the memo below keeps a constant identity. */
const EMPTY_FILES: string[] = [];

export default function PrefetchAnalyzer(): JSX.Element {
  const [pf, setPf] = useState<PF | null>(null);
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);

  // Memoized: a prefetch file can list tens of thousands of paths, so
  // re-filtering on every render (including on each keystroke in the input
  // below) was a multi-hundred-ms main-thread stall.
  const shown = useMemo(() => {
    if (!pf) return EMPTY_FILES;
    if (!q) return pf.files;
    const needle = q.toLowerCase();
    return pf.files.filter((f) => f.toLowerCase().includes(needle));
  }, [pf, q]);

  // Cap what we actually render so a huge result set doesn't reconcile
  // thousands of DOM nodes on every keystroke.
  const visibleFiles = useMemo(() => shown.slice(0, MAX_RENDERED_FILES), [shown]);

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
        <Activity size={22} className="text-brand-600 dark:text-brand-400" />
        Prefetch Analyzer <span className="text-sm font-mono text-muted">Lite</span>
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop a Windows <code>.pf</code> prefetch file. Decompresses Win8+/Win10+ MAM containers (LZXPRESS-Huffman) in
        the browser, then extracts the executable, run count, last-run times and every referenced file/DLL path - 100%
        client-side.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('prefetchanalyzer-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop a .pf file file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">Drop a .pf file file here, or click to choose</p>
        <p className="text-mini font-mono text-muted mt-1">100% client-side. No upload.</p>
      </button>
      <input
        id="prefetchanalyzer-input"
        type="file"
        accept=".pf"
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const tooBig = fileTooLarge(f.size);
          if (tooBig) {
            setPf(null);
            setErr(tooBig);
            return;
          }
          setErr('');
          setQ('');
          setBusy(true);
          try {
            await yieldToPaint();
            setPf(parsePrefetch(await f.arrayBuffer()));
          } catch (ex) {
            logCatch(ex);
            setPf(null);
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

      {pf && (
        <div className="mt-6 space-y-4">
          {pf.note && <p className="font-mono text-mini text-emerald-600 dark:text-emerald-400">{pf.note}</p>}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              ['Executable', pf.exe],
              ['Version', pf.version],
              ['Prefetch hash', pf.hash],
              ['Run count', String(pf.runCount)],
            ].map(([k, v]) => (
              <div key={k} className="surface-card p-3">
                <div className="text-micro font-mono uppercase tracking-wider text-muted">{k}</div>
                <div className="font-mono text-meta break-all">{v}</div>
              </div>
            ))}
          </div>
          {pf.lastRuns.length > 0 && (
            <div className="surface-card p-3">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
                Last run times ({pf.lastRuns.length})
              </div>
              <div className="font-mono text-mini text-body">{pf.lastRuns.join('  ·  ')}</div>
            </div>
          )}
          <div>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={`filter ${pf.files.length} referenced files…`}
              className="w-full surface-card px-3 py-2 font-mono text-sm focus:border-brand-500 focus:outline-none mb-2"
            />
            <div className="surface-card p-3 overflow-auto max-h-[55vh]">
              {visibleFiles.map((f, i) => (
                <div key={i} className="font-mono text-mini text-muted break-all">
                  {f}
                </div>
              ))}
              {shown.length === 0 && <p className="font-mono text-meta text-muted">No matching file paths.</p>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
