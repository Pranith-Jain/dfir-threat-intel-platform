import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { FileCode } from 'lucide-react';

/* ───────────────────────── binary plist (bplist00) ─────────────────────── */
function parseBplist(buf: Uint8Array): unknown {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (new TextDecoder().decode(buf.slice(0, 6)) !== 'bplist') throw new Error('not a binary plist');
  const tEnd = buf.length;
  const offSize = buf[tEnd - 26]!;
  const refSize = buf[tEnd - 25]!;
  const numObj = Number(dv.getBigUint64(tEnd - 24));
  const topObj = Number(dv.getBigUint64(tEnd - 16));
  const offTableOff = Number(dv.getBigUint64(tEnd - 8));

  const readSized = (pos: number, size: number) => {
    let v = 0;
    for (let i = 0; i < size; i++) v = v * 256 + buf[pos + i]!;
    return v;
  };
  const offsets: number[] = [];
  for (let i = 0; i < numObj; i++) offsets.push(readSized(offTableOff + i * offSize, offSize));

  const parseObj = (idx: number, depth = 0): unknown => {
    if (depth > 256) throw new Error('plist too deeply nested');
    if (idx < 0 || idx >= numObj) throw new Error('object ref out of range');
    let p = offsets[idx]!;
    const marker = buf[p]!;
    const hi = marker >> 4;
    const lo = marker & 0x0f;
    p += 1;
    const extLen = (): number => {
      if (lo !== 0x0f) return lo;
      const im = buf[p]!;
      const cnt = 1 << (im & 0x0f);
      p += 1;
      const n = readSized(p, cnt);
      p += cnt;
      return n;
    };
    switch (hi) {
      case 0x0:
        return lo === 0 ? null : lo === 8 ? false : lo === 9 ? true : null;
      case 0x1: {
        const n = 1 << lo;
        let v = 0;
        for (let i = 0; i < n; i++) v = v * 256 + buf[p + i]!;
        return v;
      }
      case 0x2:
        return lo === 2 ? dv.getFloat32(p) : dv.getFloat64(p);
      case 0x3:
        return new Date(978307200000 + dv.getFloat64(p) * 1000).toISOString();
      case 0x4: {
        const n = extLen();
        return `<data ${n} bytes: ${[...buf.slice(p, p + Math.min(n, 16))].map((b) => b.toString(16).padStart(2, '0')).join('')}${n > 16 ? '…' : ''}>`;
      }
      case 0x5: {
        const n = extLen();
        return new TextDecoder('ascii').decode(buf.slice(p, p + n));
      }
      case 0x6: {
        const n = extLen();
        return new TextDecoder('utf-16be').decode(buf.slice(p, p + n * 2));
      }
      case 0x8:
        return `UID(${readSized(p, lo + 1)})`;
      case 0xa: {
        const n = extLen();
        const arr: unknown[] = [];
        for (let i = 0; i < n; i++) arr.push(parseObj(readSized(p + i * refSize, refSize), depth + 1));
        return arr;
      }
      case 0xd: {
        const n = extLen();
        const o: Record<string, unknown> = {};
        for (let i = 0; i < n; i++) {
          const k = parseObj(readSized(p + i * refSize, refSize), depth + 1);
          const v = parseObj(readSized(p + (n + i) * refSize, refSize), depth + 1);
          o[String(k)] = v;
        }
        return o;
      }
      default:
        return `<unknown marker 0x${marker.toString(16)}>`;
    }
  };
  return parseObj(topObj);
}

/* ───────────────────────── raw protobuf (schema-less) ──────────────────── */
function parseProtobuf(buf: Uint8Array, depth = 0): unknown {
  const out: Record<string, unknown> = {};
  let p = 0;
  const varint = (): number => {
    let shift = 0,
      v = 0;
    while (p < buf.length) {
      const b = buf[p++]!;
      v += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) break;
      shift += 7;
    }
    return v;
  };
  try {
    while (p < buf.length) {
      const tag = varint();
      const field = tag >> 3;
      const wire = tag & 7;
      const key = `#${field} (wire ${wire})`;
      if (wire === 0) out[key] = varint();
      else if (wire === 1) {
        out[key] = `0x${[...buf.slice(p, p + 8)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
        p += 8;
      } else if (wire === 5) {
        out[key] = `0x${[...buf.slice(p, p + 4)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
        p += 4;
      } else if (wire === 2) {
        const len = varint();
        const sub = buf.slice(p, p + len);
        p += len;
        const txt = new TextDecoder('utf-8', { fatal: true });
        let val: unknown;
        try {
          if (depth < 6 && sub.length > 1 && (sub[0]! & 0x07) <= 5) val = parseProtobuf(sub, depth + 1);
          else throw 0;
        } catch (_catchErr) {
          logCatch(_catchErr);
          try {
            val = txt.decode(sub);
          } catch (_catchErr) {
            logCatch(_catchErr);
            val = `<${len} bytes>`;
          }
        }
        out[key] = val;
      } else break;
    }
  } catch (_catchErr) {
    logCatch(_catchErr);
    /* best-effort */
  }
  return out;
}

function bytesFrom(s: string): Uint8Array | null {
  const t = s.trim();
  if (/^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g, '').length % 2 === 0) {
    const h = t.replace(/\s/g, '');
    return new Uint8Array(h.match(/.{2}/g)!.map((x) => parseInt(x, 16)));
  }
  try {
    return new Uint8Array([...atob(t.replace(/\s/g, ''))].map((c) => c.charCodeAt(0)));
  } catch (_catchErr) {
    console.error('bytesFrom failed:', errMessage(_catchErr));
    return null;
  }
}

export default function PlistProtobuf(): JSX.Element {
  const [out, setOut] = useState<string>('');
  const [kind, setKind] = useState('');
  const [paste, setPaste] = useState('');

  function decode(bytes: Uint8Array) {
    try {
      const head = new TextDecoder().decode(bytes.slice(0, 8));
      if (head.startsWith('bplist')) {
        setKind('binary plist');
        setOut(JSON.stringify(parseBplist(bytes), null, 2));
      } else if (/^\s*<\?xml|^\s*<plist/.test(new TextDecoder().decode(bytes.slice(0, 64)))) {
        setKind('XML plist');
        const doc = new DOMParser().parseFromString(new TextDecoder().decode(bytes), 'text/xml');
        const walk = (n: Element): unknown => {
          const c = Array.from(n.children);
          if (n.tagName === 'dict') {
            const o: Record<string, unknown> = {};
            for (let i = 0; i < c.length; i += 2) o[c[i]!.textContent ?? ''] = walk(c[i + 1] as Element);
            return o;
          }
          if (n.tagName === 'array') return c.map((e) => walk(e));
          if (n.tagName === 'true') return true;
          if (n.tagName === 'false') return false;
          if (n.tagName === 'integer' || n.tagName === 'real') return Number(n.textContent);
          return n.textContent;
        };
        const root = doc.querySelector('plist > *');
        setOut(JSON.stringify(root ? walk(root) : null, null, 2));
      } else {
        setKind('protobuf (schema-less)');
        setOut(JSON.stringify(parseProtobuf(bytes), null, 2));
      }
    } catch (e) {
      console.error('decode failed:', errMessage(e));
      setKind('error');
      setOut(errMessage(e));
    }
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-6 text-heading">
      <BackLink to="/dfir">back</BackLink>
      <Link
        to="/dfir/catalog?cat=file-analysis"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        DFIR tools
      </Link>
      <h1 className="font-display font-bold text-2xl flex items-center gap-2">
        <FileCode size={22} className="text-brand-600 dark:text-brand-400" />
        Plist & Protobuf Decoder
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Decodes Apple binary plists (<code>bplist00</code>), XML plists, and schema-less protobuf blobs. Hand-rolled
        parsers - no upload, fully client-side.
      </p>

      <div className="flex flex-wrap gap-2 mb-3 text-meta font-mono">
        <label className="px-3 py-1.5 rounded border border-line-1 hover:border-brand-500/40 cursor-pointer">
          Drop a file…
          <input
            type="file"
            className="hidden"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) decode(new Uint8Array(await f.arrayBuffer()));
            }}
          />
        </label>
        <button
          type="button"
          onClick={() => {
            const b = bytesFrom(paste);
            if (b) decode(b);
            else {
              setKind('error');
              setOut('Paste must be hex or base64.');
            }
          }}
          className="px-3 py-1.5 rounded border border-line-1 hover:border-brand-500/40"
        >
          Decode pasted hex/base64
        </button>
        {kind && <span className="self-center text-muted">detected: {kind}</span>}
      </div>

      <textarea
        value={paste}
        onChange={(e) => setPaste(e.target.value)}
        rows={3}
        placeholder="Paste hex or base64 of a plist / protobuf blob…"
        className="w-full surface-card px-3 py-2 font-mono text-meta focus:border-brand-500 focus:outline-none"
      />

      {out && (
        <pre className="mt-4 rounded-xl border border-line-1 bg-surface-200 p-3 overflow-auto font-mono text-mini text-heading max-h-[60vh]">
          {out}
        </pre>
      )}
    </div>
  );
}
