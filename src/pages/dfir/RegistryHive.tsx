import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { FolderTree, Upload, Loader2 } from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { fileTooLarge, yieldToPaint } from '../../lib/dfir/file-guard';

/* Windows registry hive (regf). Cells live in hbins starting at 0x1000;
   stored offsets are relative to that; each cell has a 4-byte size prefix. */
interface RKey {
  name: string;
  modified: string;
  values: RVal[];
  subkeys: RKey[];
}
interface RVal {
  name: string;
  type: string;
  value: string;
}

const TYPES: Record<number, string> = {
  0: 'REG_NONE',
  1: 'REG_SZ',
  2: 'REG_EXPAND_SZ',
  3: 'REG_BINARY',
  4: 'REG_DWORD',
  5: 'REG_DWORD_BE',
  7: 'REG_MULTI_SZ',
  11: 'REG_QWORD',
};
const MAX_NODES = 8000;

function parseHive(buf: ArrayBuffer): RKey {
  const d = new DataView(buf);
  const u8 = new Uint8Array(buf);
  if (d.getUint32(0, false) !== 0x72656766) throw new Error('not a regf hive (bad signature)');
  const BASE = 0x1000;
  const rootOff = d.getUint32(0x24, true);
  let nodes = 0;

  const cell = (off: number) => BASE + off + 4; // skip 4-byte cell size
  const ascii = (o: number, n: number) => String.fromCharCode(...u8.subarray(o, o + n)).replace(/\0+$/, '');
  const utf16 = (o: number, n: number) => new TextDecoder('utf-16le').decode(u8.subarray(o, o + n)).replace(/\0+$/, '');
  const filetime = (o: number) => {
    const lo = d.getUint32(o, true);
    const hi = d.getUint32(o + 4, true);
    const ms = (hi * 2 ** 32 + lo) / 1e4 - 11644473600000;
    return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : '';
  };

  function readVal(off: number): RVal {
    const c = cell(off);
    const nameLen = d.getUint16(c + 0x02, true);
    let dataSize = d.getUint32(c + 0x04, true);
    const dataOff = d.getUint32(c + 0x08, true);
    const type = d.getUint32(c + 0x0c, true);
    const flags = d.getUint16(c + 0x10, true);
    const name = nameLen === 0 ? '(Default)' : flags & 1 ? ascii(c + 0x14, nameLen) : utf16(c + 0x14, nameLen);
    const inline = (dataSize & 0x80000000) !== 0;
    dataSize &= 0x7fffffff;
    const dpos = inline ? c + 0x08 : cell(dataOff);
    let value = '';
    try {
      if (type === 1 || type === 2 || type === 7) {
        value = utf16(dpos, Math.min(dataSize, 4096));
        if (type === 7) value = value.replace(/\0/g, ' · ');
      } else if (type === 4) value = String(d.getUint32(dpos, true));
      else if (type === 5) value = String(d.getUint32(dpos, false));
      else if (type === 11) value = String(d.getUint32(dpos, true) + d.getUint32(dpos + 4, true) * 2 ** 32);
      else
        value =
          [...u8.subarray(dpos, dpos + Math.min(dataSize, 64))].map((b) => b.toString(16).padStart(2, '0')).join(' ') +
          (dataSize > 64 ? ' …' : '');
    } catch (_catchErr) {
      console.error('readVal failed:', errMessage(_catchErr));
      value = '<unreadable>';
    }
    return { name, type: TYPES[type] ?? `0x${type.toString(16)}`, value };
  }

  function listOffsets(off: number): number[] {
    const c = cell(off);
    const sig = ascii(c, 2);
    const cnt = d.getUint16(c + 0x02, true);
    const out: number[] = [];
    if (sig === 'lf' || sig === 'lh') for (let i = 0; i < cnt; i++) out.push(d.getUint32(c + 0x04 + i * 8, true));
    else if (sig === 'li') for (let i = 0; i < cnt; i++) out.push(d.getUint32(c + 0x04 + i * 4, true));
    else if (sig === 'ri') for (let i = 0; i < cnt; i++) out.push(...listOffsets(d.getUint32(c + 0x04 + i * 4, true)));
    return out;
  }

  function readKey(off: number, depth: number): RKey {
    nodes++;
    const c = cell(off);
    if (ascii(c, 2) !== 'nk') return { name: '<bad nk>', modified: '', values: [], subkeys: [] };
    const flags = d.getUint16(c + 0x02, true);
    const nSub = d.getUint32(c + 0x18, true);
    const subOff = d.getUint32(c + 0x20, true);
    const nVal = d.getUint32(c + 0x28, true);
    const valListOff = d.getUint32(c + 0x2c, true);
    const nameLen = d.getUint16(c + 0x4c, true);
    const name = flags & 0x20 ? ascii(c + 0x50, nameLen) : utf16(c + 0x50, nameLen);
    const key: RKey = { name: name || '(root)', modified: filetime(c + 0x04), values: [], subkeys: [] };

    if (nVal > 0 && nVal < 4096 && valListOff !== 0xffffffff) {
      const vl = cell(valListOff);
      for (let i = 0; i < nVal && nodes < MAX_NODES; i++) {
        try {
          key.values.push(readVal(d.getUint32(vl + i * 4, true)));
        } catch (_catchErr) {
          console.error('readKey failed:', errMessage(_catchErr));
          /* skip */
        }
      }
    }
    if (nSub > 0 && depth < 14 && subOff !== 0xffffffff && nodes < MAX_NODES) {
      try {
        for (const so of listOffsets(subOff)) {
          if (nodes >= MAX_NODES) break;
          key.subkeys.push(readKey(so, depth + 1));
        }
      } catch (_catchErr) {
        console.error('readKey failed:', errMessage(_catchErr));
        /* skip */
      }
    }
    return key;
  }

  return readKey(rootOff, 0);
}

function Node({ k, depth }: { k: RKey; depth: number }): JSX.Element {
  const [open, setOpen] = useState(depth < 1);
  const has = k.subkeys.length > 0 || k.values.length > 0;
  return (
    <div className="ml-3 border-l border-line-1 pl-3">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-left font-mono text-meta text-heading hover:text-brand-600 dark:hover:text-brand-400"
      >
        {has ? (open ? '▾ ' : '▸ ') : '· '}
        {k.name}{' '}
        <span className="text-muted">
          ({k.subkeys.length} keys, {k.values.length} vals{k.modified ? ` · ${k.modified.slice(0, 19)}Z` : ''})
        </span>
      </button>
      {open && (
        <div>
          {k.values.map((v, i) => (
            <div key={i} className="ml-4 font-mono text-mini text-muted break-all">
              <span className="text-emerald-600 dark:text-emerald-400">{v.name}</span> [{v.type}] = {v.value}
            </div>
          ))}
          {k.subkeys.map((s, i) => (
            <Node key={i} k={s} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function RegistryHive(): JSX.Element {
  const [root, setRoot] = useState<RKey | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

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
        <FolderTree size={22} className="text-brand-600 dark:text-brand-400" />
        Registry Hive Explorer
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop a raw Windows registry hive (<code>SYSTEM</code>, <code>SOFTWARE</code>, <code>NTUSER.DAT</code>, etc.).
        Hand-rolled <code>regf</code> parser walks keys + values entirely in your browser. Capped at {MAX_NODES} nodes
        for responsiveness.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('registryhive-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop a hive file file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">Drop a hive file file here, or click to choose</p>
        <p className="text-mini font-mono text-muted mt-1">100% client-side. No upload.</p>
      </button>
      <input
        id="registryhive-input"
        type="file"
        accept=""
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const tooBig = fileTooLarge(f.size);
          if (tooBig) {
            setRoot(null);
            setErr(tooBig);
            return;
          }
          setErr('');
          setBusy(true);
          try {
            await yieldToPaint();
            setRoot(parseHive(await f.arrayBuffer()));
          } catch (ex) {
            logCatch(ex);
            setRoot(null);
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

      {root && (
        <div className="mt-6 surface-card p-3 overflow-auto max-h-[70vh]">
          <Node k={root} depth={0} />
        </div>
      )}
    </div>
  );
}
