import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { ScanLine, Upload } from 'lucide-react';

const ENTITY: Array<[string, RegExp]> = [
  ['URLs', /\bhttps?:\/\/[^\s"'<>]+/gi],
  ['Domains', /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi],
  ['IPv4', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  ['Emails', /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/gi],
  ['BTC', /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g],
  ['ETH', /\b0x[a-fA-F0-9]{40}\b/g],
  ['Hashes', /\b[a-fA-F0-9]{32,64}\b/g],
];

function entities(text: string): Array<[string, string[]]> {
  const out: Array<[string, string[]]> = [];
  for (const [name, re] of ENTITY) {
    const m = [...new Set(text.match(re) ?? [])];
    if (m.length) out.push([name, m.slice(0, 50)]);
  }
  return out;
}

export default function ScreenshotIntel(): JSX.Element {
  const [qr, setQr] = useState<string | null>(null);
  const [meta, setMeta] = useState<Record<string, unknown> | null>(null);
  const [ents, setEnts] = useState<Array<[string, string[]]>>([]);
  const [ocr, setOcr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState('');
  const [note, setNote] = useState('');

  async function analyze(file: File) {
    setBusy(true);
    setQr(null);
    setMeta(null);
    setEnts([]);
    setOcr(null);
    setNote('');
    // Reject oversized uploads before decoding - a small compressed image can
    // decompress to a huge canvas allocation (decompression-bomb DoS).
    if (file.size > 25 * 1024 * 1024) {
      setNote('Image too large (max 25 MB).');
      setBusy(false);
      return;
    }
    try {
      // EXIF / metadata (exifr - already a dependency)
      try {
        const exifr = (await import('exifr')).default;
        const m = await exifr.parse(file, { gps: true });
        if (m) setMeta(m as Record<string, unknown>);
      } catch (_catchErr) {
        console.error('analyze failed:', errMessage(_catchErr));
        /* no exif */
      }
      // QR decode (jsQR - lazy chunk, tiny pure-JS, no wasm)
      const bmp = await createImageBitmap(file);
      // Guard against pixel-dimension bombs: a 25 MB file can still decode to
      // hundreds of megapixels, allocating gigabytes for the canvas/ImageData.
      if (bmp.width * bmp.height > 40_000_000) {
        bmp.close();
        setNote('Image dimensions too large to analyze (max ~40 MP).');
        setBusy(false);
        return;
      }
      const cv = document.createElement('canvas');
      cv.width = bmp.width;
      cv.height = bmp.height;
      const ctx = cv.getContext('2d')!;
      ctx.drawImage(bmp, 0, 0);
      const img = ctx.getImageData(0, 0, cv.width, cv.height);
      bmp.close();
      const jsQR = (await import('jsqr')).default;
      const code = jsQR(img.data, img.width, img.height);
      const qrText = code?.data ?? '';
      setQr(qrText || '');

      // OCR - tesseract.js, fully self-hosted (worker + core + traineddata
      // served same-origin; workerBlobURL:false keeps the CSP tight).
      let ocrText = '';
      try {
        setStage('loading OCR engine (~11 MB language model)…');
        const { createWorker } = await import('tesseract.js');
        const worker = await createWorker('eng', 1, {
          workerPath: '/tesseract/worker.min.js',
          corePath: '/tesseract/',
          langPath: '/tesseract/',
          workerBlobURL: false,
        });
        const { data } = await worker.recognize(file);
        await worker.terminate();
        ocrText = (data.text || '').trim();
        setOcr(ocrText);
      } catch (oe) {
        logCatch(oe);
        setNote(`OCR unavailable: ${errMessage(oe)}`);
      } finally {
        setStage('');
      }

      setEnts(entities(`${qrText} ${ocrText} ${file.name}`));
    } catch (e) {
      logCatch(e);
      setNote(errMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-6 text-heading">
      <BackLink to="/dfir">back</BackLink>
      <Link
        to="/dfir/catalog?cat=identity-osint"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        OSINT tools
      </Link>
      <h1 className="font-display font-bold text-2xl flex items-center gap-2">
        <ScanLine size={22} className="text-brand-600 dark:text-brand-400" />
        Screenshot Intelligence
      </h1>
      <p className="text-sm font-mono text-muted mt-1 mb-6">
        Drop a screenshot/photo - runs OCR (self-hosted Tesseract), decodes embedded QR codes, reads EXIF/GPS metadata,
        and pulls OSINT entities (URLs, domains, IPs, emails, crypto addresses, hashes) from the recognised text. 100%
        client-side; the language model is served same-origin.
      </p>

      <button
        type="button"
        onClick={() => document.getElementById('screenshot-input')?.click()}
        className="w-full border-2 border-dashed border-line-2 rounded-xl p-8 text-center cursor-pointer hover:border-brand-500/40 focus-visible:outline-none focus-visible:border-brand-500/60"
        aria-label="Drop an image file or click to choose"
      >
        <Upload size={24} className="mx-auto mb-2 text-muted" />
        <p className="text-sm font-mono text-body">
          {busy ? 'Analyzing...' : 'Drop an image here, or click to choose'}
        </p>
        <p className="text-mini font-mono text-muted mt-1">OCR, QR decode, EXIF/GPS extraction. 100% client-side.</p>
      </button>
      <input
        id="screenshot-input"
        type="file"
        accept="image/*"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void analyze(f);
        }}
      />
      {stage && <p className="mt-3 font-mono text-meta text-muted">{stage}</p>}
      {note && <p className="mt-3 font-mono text-meta text-amber-600 dark:text-amber-400">{note}</p>}

      {qr ? (
        <div className="mt-6 surface-card p-3">
          <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">QR / barcode payload</div>
          <code className="font-mono text-meta break-all text-heading">{qr}</code>
        </div>
      ) : null}

      {ocr !== null && ocr !== '' && (
        <div className="mt-4 surface-card p-3">
          <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">OCR text</div>
          <pre className="font-mono text-mini whitespace-pre-wrap break-words text-body max-h-[40vh] overflow-auto">
            {ocr}
          </pre>
        </div>
      )}

      {ents.length > 0 && (
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {ents.map(([k, vs]) => (
            <div key={k} className="surface-card p-3">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
                {k} · {vs.length}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {vs.map((v) => (
                  <span key={v} className="font-mono text-mini px-1.5 py-0.5 rounded border border-line-1 break-all">
                    {v}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {meta && (
        <div className="mt-4 surface-card p-3">
          <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">EXIF / metadata</div>
          <pre className="font-mono text-mini overflow-auto max-h-[40vh] text-body">
            {JSON.stringify(meta, (_k, v) => (v instanceof Date ? v.toISOString() : v), 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
