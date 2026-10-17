import { useState, useEffect, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Hash as HashIcon, Loader2 } from 'lucide-react';
import { CopyButton } from '../../components/ui/CopyButton';
import { BackLink } from '../../components/BackLink';
import { fileTooLarge, yieldToPaint } from '../../lib/dfir/file-guard';
import { errMessage } from '../../lib/log';

/** Compact MD5 (RFC 1321). Web Crypto has no MD5; DFIR still needs it for
 *  cross-referencing legacy hash sets. */
function md5(bytes: Uint8Array): string {
  function rl(x: number, c: number) {
    return (x << c) | (x >>> (32 - c));
  }
  const n = bytes.length;
  const words: number[] = [];
  for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (bytes[i]! << ((i % 4) * 8));
  words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) * 8));
  const bits = n * 8;
  const len = (((n + 8) >> 6) + 1) * 16;
  while (words.length < len) words.push(0);
  words[len - 2] = bits & 0xffffffff;
  words[len - 1] = Math.floor(bits / 0x100000000);
  let a = 1732584193,
    b = -271733879,
    c = -1732584194,
    d = 271733878;
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K: number[] = [];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  const add = (x: number, y: number) => (x + y) & 0xffffffff;
  for (let i = 0; i < words.length; i += 16) {
    let [A, B, C, D] = [a, b, c, d];
    for (let j = 0; j < 64; j++) {
      let f: number, g: number;
      if (j < 16) {
        f = (B & C) | (~B & D);
        g = j;
      } else if (j < 32) {
        f = (D & B) | (~D & C);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        f = B ^ C ^ D;
        g = (3 * j + 5) % 16;
      } else {
        f = C ^ (B | ~D);
        g = (7 * j) % 16;
      }
      const tmp = D;
      D = C;
      C = B;
      B = add(B, rl(add(add(A, f), add(K[j]!, words[i + g] || 0)), S[(Math.floor(j / 16) % 4) * 4 + (j % 4)]!));
      A = tmp;
    }
    a = add(a, A);
    b = add(b, B);
    c = add(c, C);
    d = add(d, D);
  }
  return [a, b, c, d]
    .map((x) => Array.from({ length: 4 }, (_, i) => ((x >>> (i * 8)) & 0xff).toString(16).padStart(2, '0')).join(''))
    .join('');
}

async function subtle(algo: string, bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest(algo, bytes as BufferSource);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export default function HashCalculator(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = searchParams.get('q') ?? '';
  const [text, setText] = useState(initial);
  const [out, setOut] = useState<Record<string, string>>({});
  const [src, setSrc] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const autoFired = useRef(false);

  // Auto-fire from URL param
  useEffect(() => {
    if (initial && !autoFired.current) {
      autoFired.current = true;
      void run(new TextEncoder().encode(initial), 'text');
    }
  }, [initial]);

  // Sync text to URL
  useEffect(() => {
    if (text) setSearchParams({ q: text }, { replace: true });
    else setSearchParams({}, { replace: true });
  }, [text, setSearchParams]);

  async function run(bytes: Uint8Array, label: string) {
    setSrc(label);
    setErr('');
    setBusy(true);
    try {
      // Yield a frame so the spinner paints before the synchronous MD5 (pure JS)
      // blocks the main thread on large inputs.
      await yieldToPaint();
      const [s1, s256, s384, s512] = await Promise.all([
        subtle('SHA-1', bytes),
        subtle('SHA-256', bytes),
        subtle('SHA-384', bytes),
        subtle('SHA-512', bytes),
      ]);
      setOut({ MD5: md5(bytes), 'SHA-1': s1, 'SHA-256': s256, 'SHA-384': s384, 'SHA-512': s512 });
    } catch (ex) {
      console.error('run failed:', errMessage(ex));
      setOut({});
      setErr(errMessage(ex));
    } finally {
      setBusy(false);
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
        <HashIcon size={22} className="text-brand-600 dark:text-brand-400" />
        Hash Calculator
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        MD5, SHA-1, SHA-256, SHA-384, SHA-512 for text or a dropped file. Fully client-side - nothing is uploaded.
      </p>

      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={4}
        placeholder="Type or paste text to hash…"
        className="w-full surface-card px-3 py-2 font-mono text-sm focus:border-brand-500 focus:outline-none"
      />
      <div className="mt-2 flex flex-wrap gap-2 text-meta font-mono">
        <button
          type="button"
          onClick={() => void run(new TextEncoder().encode(text), 'text')}
          className="px-3 py-1.5 rounded border border-line-1 hover:border-brand-500/40"
        >
          Hash text
        </button>
        <label className="px-3 py-1.5 rounded border border-line-1 hover:border-brand-500/40 cursor-pointer">
          Hash a file…
          <input
            type="file"
            className="hidden"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              const tooBig = fileTooLarge(f.size);
              if (tooBig) {
                setOut({});
                setErr(tooBig);
                return;
              }
              void run(new Uint8Array(await f.arrayBuffer()), `${f.name} (${f.size} B)`);
            }}
          />
        </label>
        {src && <span className="self-center text-muted">source: {src}</span>}
      </div>
      {busy && (
        <p className="mt-3 inline-flex items-center gap-2 font-mono text-sm text-muted">
          <Loader2 size={14} className="animate-spin" /> hashing…
        </p>
      )}
      {err && <p className="mt-3 font-mono text-sm text-rose-600 dark:text-rose-400">{err}</p>}

      <ul className="mt-6 space-y-2">
        {Object.entries(out).map(([k, v]) => (
          <li key={k} className="surface-card p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-micro font-mono uppercase tracking-wider text-muted">{k}</span>
              <CopyButton text={v} variant="ghost" size="sm" label={`Copy ${k}`} />
            </div>
            <code className="font-mono text-meta break-all text-heading">{v}</code>
          </li>
        ))}
      </ul>
    </div>
  );
}
