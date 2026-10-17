import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Network, Upload } from 'lucide-react';

interface Summary {
  format: string;
  linkType: number;
  packets: number;
  bytes: number;
  span: string;
  proto: Record<string, number>;
  talkers: Array<[string, number]>;
  conversations: Array<[string, number]>;
  dns: string[];
  http: string[];
}

const MAX = 200_000;
// File-size cap so a 500 MB capture doesn't OOM the browser tab before the
// per-packet `MAX` limit kicks in. The packet cap only stops the parser
// loop - the full `arrayBuffer()` has already been read into memory by then.
const MAX_FILE_BYTES = 50 * 1024 * 1024;

function ipv4(d: DataView, o: number): string {
  return `${d.getUint8(o)}.${d.getUint8(o + 1)}.${d.getUint8(o + 2)}.${d.getUint8(o + 3)}`;
}

function parsePacket(
  d: DataView,
  off: number,
  len: number,
  linkType: number,
  acc: {
    proto: Record<string, number>;
    talk: Map<string, number>;
    conv: Map<string, number>;
    dns: Set<string>;
    http: Set<string>;
  }
) {
  try {
    let p = off;
    let etherType: number;
    if (linkType === 1) {
      // Ethernet II
      etherType = d.getUint16(p + 12);
      p += 14;
      if (etherType === 0x8100) {
        etherType = d.getUint16(p + 2);
        p += 4;
      } // VLAN
    } else if (linkType === 101) {
      etherType = 0x0800; // raw IP
    } else {
      acc.proto['non-ethernet'] = (acc.proto['non-ethernet'] ?? 0) + 1;
      return;
    }
    if (etherType === 0x0806) {
      acc.proto['ARP'] = (acc.proto['ARP'] ?? 0) + 1;
      return;
    }
    if (etherType === 0x86dd) {
      acc.proto['IPv6'] = (acc.proto['IPv6'] ?? 0) + 1;
      return;
    }
    if (etherType !== 0x0800) {
      acc.proto[`ether 0x${etherType.toString(16)}`] = (acc.proto[`ether 0x${etherType.toString(16)}`] ?? 0) + 1;
      return;
    }
    const ihl = (d.getUint8(p) & 0x0f) * 4;
    const proto = d.getUint8(p + 9);
    const src = ipv4(d, p + 12);
    const dst = ipv4(d, p + 16);
    acc.talk.set(src, (acc.talk.get(src) ?? 0) + 1);
    acc.talk.set(dst, (acc.talk.get(dst) ?? 0) + 1);
    const tp = p + ihl;
    const note = (name: string) => (acc.proto[name] = (acc.proto[name] ?? 0) + 1);
    if (proto === 6 || proto === 17) {
      const sp = d.getUint16(tp);
      const dp = d.getUint16(tp + 2);
      const l4 = proto === 6 ? 'TCP' : 'UDP';
      note(l4);
      acc.conv.set(`${src}:${sp} → ${dst}:${dp} ${l4}`, (acc.conv.get(`${src}:${sp} → ${dst}:${dp} ${l4}`) ?? 0) + 1);
      const payOff = proto === 6 ? tp + (d.getUint8(tp + 12) >> 4) * 4 : tp + 8;
      // DNS
      if ((sp === 53 || dp === 53) && proto === 17) {
        note('DNS');
        try {
          let q = payOff + 12;
          const labels: string[] = [];
          while (q < off + len) {
            const ln = d.getUint8(q);
            if (ln === 0 || ln > 63) break;
            labels.push(
              String.fromCharCode(...new Uint8Array(d.buffer, d.byteOffset + q + 1, ln)).replace(/[^\x20-\x7e]/g, '')
            );
            q += ln + 1;
          }
          if (labels.length) acc.dns.add(labels.join('.'));
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* skip */
        }
      }
      // HTTP request line
      if (proto === 6 && (dp === 80 || sp === 80)) {
        note('HTTP');
        try {
          const slice = new Uint8Array(d.buffer, d.byteOffset + payOff, Math.min(len + off - payOff, 256));
          const txt = String.fromCharCode(...slice);
          const m = txt.match(/^(GET|POST|PUT|HEAD|DELETE|OPTIONS) (\S+) HTTP/);
          const host = txt.match(/[Hh]ost:\s*([^\r\n]+)/);
          if (m) acc.http.add(`${m[1]} ${host ? host[1]!.trim() : ''}${m[2]}`.slice(0, 120));
        } catch (_catchErr) {
          logCatch(_catchErr);
          /* skip */
        }
      }
      if (proto === 6 && (dp === 443 || sp === 443)) note('TLS/443');
    } else if (proto === 1) note('ICMP');
    else note(`IP proto ${proto}`);
  } catch (_catchErr) {
    logCatch(_catchErr);
    /* malformed packet - skip */
  }
}

function parse(buf: ArrayBuffer): Summary {
  const d = new DataView(buf);
  const m = d.getUint32(0, false);
  const acc = {
    proto: {} as Record<string, number>,
    talk: new Map<string, number>(),
    conv: new Map<string, number>(),
    dns: new Set<string>(),
    http: new Set<string>(),
  };
  let packets = 0,
    bytes = 0,
    tMin = Infinity,
    tMax = -Infinity,
    format = 'unknown',
    linkType = 1;

  if (m === 0x0a0d0d0a) {
    // pcapng - walk blocks, parse SHB/IDB/EPB
    format = 'pcapng';
    let le = true;
    let o = 0;
    while (o + 12 <= buf.byteLength && packets < MAX) {
      const btype = new DataView(buf, o, 4).getUint32(0, true);
      if (btype === 0x0a0d0d0a) le = new DataView(buf, o + 8, 4).getUint32(0, true) === 0x1a2b3c4d;
      const blen = new DataView(buf, o + 4, 4).getUint32(0, le);
      if (blen < 12 || o + blen > buf.byteLength) break;
      if (btype === 0x00000001) linkType = new DataView(buf, o + 8, 2).getUint16(0, le);
      if (btype === 0x00000006) {
        const cap = new DataView(buf, o + 20, 4).getUint32(0, le);
        parsePacket(new DataView(buf), o + 28, cap, linkType, acc);
        packets++;
        bytes += cap;
      }
      o += blen;
    }
  } else {
    const le = m === 0xd4c3b2a1 || m === 0x4d3cb2a1;
    if (m === 0xa1b2c3d4 || m === 0xd4c3b2a1) format = 'pcap (µs)';
    else if (m === 0xa1b23c4d || m === 0x4d3cb2a1) format = 'pcap (ns)';
    else throw new Error('Not a pcap/pcapng file (bad magic)');
    linkType = d.getUint32(20, le);
    let o = 24;
    while (o + 16 <= buf.byteLength && packets < MAX) {
      const ts = d.getUint32(o, le);
      const incl = d.getUint32(o + 8, le);
      if (o + 16 + incl > buf.byteLength) break;
      tMin = Math.min(tMin, ts);
      tMax = Math.max(tMax, ts);
      parsePacket(d, o + 16, incl, linkType, acc);
      packets++;
      bytes += incl;
      o += 16 + incl;
    }
  }

  const top = (mp: Map<string, number>, n: number) =>
    [...mp.entries()].sort((a, b) => b[1] - a[1]).slice(0, n) as Array<[string, number]>;
  return {
    format,
    linkType,
    packets,
    bytes,
    span: tMin !== Infinity ? `${new Date(tMin * 1000).toISOString()} → ${new Date(tMax * 1000).toISOString()}` : 'n/a',
    proto: acc.proto,
    talkers: top(acc.talk, 15),
    conversations: top(acc.conv, 15),
    dns: [...acc.dns].slice(0, 100),
    http: [...acc.http].slice(0, 50),
  };
}

export default function PcapTriage(): JSX.Element {
  const [s, setS] = useState<Summary | null>(null);
  const [err, setErr] = useState('');

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
        <Network size={22} className="text-brand-600 dark:text-brand-400" />
        PCAP Triage
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop a <code>.pcap</code> / <code>.pcapng</code> - extracts protocol mix, top talkers, conversations, DNS
        queries and HTTP request lines. Parsed entirely in your browser; nothing is uploaded.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('pcaptriage-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop a capture file file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">Drop a capture file file here, or click to choose</p>
        <p className="text-mini font-mono text-muted mt-1">100% client-side. No upload.</p>
      </button>
      <input
        id="pcaptriage-input"
        type="file"
        accept=""
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          if (f.size > MAX_FILE_BYTES) {
            setS(null);
            setErr(
              `File exceeds ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB limit (${(f.size / 1024 / 1024).toFixed(1)} MB).`
            );
            return;
          }
          try {
            setErr('');
            setS(parse(await f.arrayBuffer()));
          } catch (ex) {
            logCatch(ex);
            setS(null);
            setErr(errMessage(ex));
          }
        }}
      />

      {err && <p className="mt-4 font-mono text-sm text-rose-600 dark:text-rose-400">{err}</p>}

      {s && (
        <div className="mt-6 space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              ['Format', s.format],
              ['Packets', s.packets.toLocaleString()],
              ['Bytes', s.bytes.toLocaleString()],
              ['Link type', String(s.linkType)],
            ].map(([k, v]) => (
              <div key={k} className="surface-card p-3">
                <div className="text-micro font-mono uppercase tracking-wider text-muted">{k}</div>
                <div className="font-mono text-sm">{v}</div>
              </div>
            ))}
          </div>
          <div className="font-mono text-mini text-muted">span: {s.span}</div>

          <Block title="Protocols" rows={Object.entries(s.proto).sort((a, b) => b[1] - a[1])} />
          <Block title="Top talkers (IP · packets)" rows={s.talkers} />
          <Block title="Conversations" rows={s.conversations} />
          {s.dns.length > 0 && <List title={`DNS queries (${s.dns.length})`} items={s.dns} />}
          {s.http.length > 0 && <List title={`HTTP requests (${s.http.length})`} items={s.http} />}
        </div>
      )}
    </div>
  );
}

function Block({ title, rows }: { title: string; rows: Array<[string, number]> }) {
  if (rows.length === 0) return null;
  return (
    <div className="surface-card p-3">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">{title}</div>
      <ul className="font-mono text-meta space-y-0.5">
        {rows.map(([k, v]) => (
          <li key={k} className="flex justify-between gap-4">
            <span className="truncate text-body">{k}</span>
            <span className="text-muted">{v}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function List({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="surface-card p-3">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">{title}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((i) => (
          <span key={i} className="font-mono text-mini px-1.5 py-0.5 rounded border border-line-1 text-body break-all">
            {i}
          </span>
        ))}
      </div>
    </div>
  );
}
