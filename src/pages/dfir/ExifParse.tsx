import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useRef } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Upload, MapPin, Camera, Image, FileText, ShieldCheck } from 'lucide-react';
import { fileTooLarge } from '../../lib/dfir/file-guard';

// exifr is ~76KB. Lazy-load on first file drop so the route's initial chunk
// only ships the drop-zone UI, not the parser library.
type ExifrModule = typeof import('exifr');

interface ExifData {
  // GPS
  latitude?: number;
  longitude?: number;
  altitude?: number;
  // Camera
  Make?: string;
  Model?: string;
  LensModel?: string;
  // Software
  Software?: string;
  // Capture
  DateTimeOriginal?: Date | string;
  ExposureTime?: number;
  FNumber?: number;
  ISO?: number;
  FocalLength?: number;
  // Image
  ImageWidth?: number;
  ImageHeight?: number;
  Orientation?: number | string;
  ColorSpace?: number | string;
  // IPTC
  Copyright?: string;
  Caption?: string;
  Keywords?: string | string[];
  [key: string]: unknown;
}

function gpsLink(lat: number, lon: number): string {
  return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=14/${lat}/${lon}`;
}

function formatExposure(et: number): string {
  if (et >= 1) return `${et}s`;
  const denom = Math.round(1 / et);
  return `1/${denom}s`;
}

function formatFocalLength(fl: number): string {
  return `${fl}mm`;
}

interface RowProps {
  label: string;
  value?: string | number | null;
}

function Row({ label, value }: RowProps) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div className="flex items-baseline justify-between py-1.5 border-t border-line-1 first:border-t-0">
      <span className="text-xs uppercase tracking-wider text-muted font-mono">{label}</span>
      <span className="text-sm font-mono text-heading text-right break-all max-w-[60%]">{String(value)}</span>
    </div>
  );
}

export default function ExifParse(): JSX.Element {
  const [metadata, setMetadata] = useState<ExifData | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const exifrRef = useRef<ExifrModule | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setLoading(true);
    setError(null);
    setMetadata(null);
    setFileName(file.name);
    try {
      const tooBig = fileTooLarge(file.size);
      if (tooBig) {
        setError(tooBig);
        setLoading(false);
        return;
      }
      const arrayBuf = await file.arrayBuffer();
      const exifr = exifrRef.current ?? (exifrRef.current = await import('exifr'));
      const parseOptions = { gps: true, exif: true, ifd0: true, iptc: true } as unknown as Parameters<
        typeof exifr.default.parse
      >[1];
      const data = (await exifr.default.parse(arrayBuf, parseOptions)) as ExifData | null;

      if (!data || Object.keys(data).length === 0) {
        setError('No EXIF metadata found in this file. Try a JPEG taken by a camera or phone.');
        setMetadata(null);
      } else {
        setMetadata(data);
      }
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'Failed to parse file'));
    } finally {
      setLoading(false);
    }
  }, []);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void handleFile(file);
    // Reset input so same file can be re-selected
    e.target.value = '';
  };

  const onDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) void handleFile(file);
    },
    [handleFile]
  );

  const lat = typeof metadata?.latitude === 'number' ? metadata.latitude : undefined;
  const lon = typeof metadata?.longitude === 'number' ? metadata.longitude : undefined;

  const formatDateTime = (dt: Date | string | undefined): string | undefined => {
    if (!dt) return undefined;
    if (dt instanceof Date) return dt.toISOString().replace('T', ' ').slice(0, 19);
    return String(dt);
  };

  const keywords = metadata?.Keywords;
  const keywordsStr = Array.isArray(keywords) ? keywords.join(', ') : (keywords as string | undefined);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Image size={28} />}
      title="EXIF Parser"
      maxWidthClass="max-w-3xl"
      description="Extract metadata from images. Includes GPS coordinates, camera make and model, capture settings, and more."
    >
      {/* Privacy notice */}
      <div className="mb-8 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-900/10 p-4">
        <div className="flex gap-3">
          <ShieldCheck size={18} className="text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
          <div className="text-sm text-emerald-800 dark:text-emerald-300">
            <strong className="font-semibold">100% client-side:</strong> Your image file is processed entirely in the
            browser. It is never uploaded to any server.
          </div>
        </div>
      </div>

      {/* Drop zone */}
      <button
        type="button"
        onDragOver={(e: React.DragEvent) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop as (e: React.DragEvent) => void}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click();
        }}
        aria-label="Upload image file"
        className={`mb-8 rounded-xl border-2 border-dashed p-12 text-center cursor-pointer transition-colors w-full ${
          dragging
            ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/10'
            : 'border-slate-300 dark:border-line-1 hover:border-brand-400 dark:hover:border-brand-600'
        }`}
      >
        <Upload
          size={32}
          className={`mx-auto mb-3 transition-colors ${dragging ? 'text-brand-600 dark:text-brand-400' : 'text-muted'}`}
        />
        <p className="font-mono text-sm text-muted">
          Drop an image here or{' '}
          <span className="text-brand-600 dark:text-brand-400 hover:underline">click to browse</span>
        </p>
        <p className="mt-1 text-xs font-mono text-muted">JPEG · PNG · HEIC · TIFF</p>
        <input ref={inputRef} type="file" accept="image/*" className="hidden" onChange={onFileChange} />
      </button>

      {loading && <p className="font-mono text-muted">Parsing EXIF data…</p>}
      {error && (
        <p role="alert" className="font-mono text-sm text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {metadata && (
        <div className="animate-fade-in-up space-y-6">
          {/* File name */}
          <div className="font-mono text-xs text-muted">
            Parsed: <span className="text-body">{fileName}</span>
          </div>

          {/* GPS */}
          {lat !== undefined && lon !== undefined && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-lg mb-3 flex items-center gap-2">
                <MapPin size={16} className="text-brand-600 dark:text-brand-400" />
                GPS Location
              </h2>
              <Row label="latitude" value={lat.toFixed(6)} />
              <Row label="longitude" value={lon.toFixed(6)} />
              {metadata.altitude !== undefined && (
                <Row label="altitude" value={`${Number(metadata.altitude).toFixed(1)} m`} />
              )}
              <div className="mt-3">
                <a
                  href={gpsLink(lat, lon)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-sm font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                >
                  <MapPin size={12} />
                  View on OpenStreetMap
                </a>
              </div>
            </section>
          )}

          {/* Camera */}
          {(metadata.Make || metadata.Model || metadata.LensModel) && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-lg mb-3 flex items-center gap-2">
                <Camera size={16} className="text-brand-600 dark:text-brand-400" />
                Camera
              </h2>
              <Row label="make" value={metadata.Make as string | undefined} />
              <Row label="model" value={metadata.Model as string | undefined} />
              <Row label="lens" value={metadata.LensModel as string | undefined} />
              {metadata.Software && <Row label="software" value={metadata.Software as string} />}
            </section>
          )}

          {/* Capture settings */}
          {(metadata.DateTimeOriginal ||
            metadata.ExposureTime !== undefined ||
            metadata.FNumber !== undefined ||
            metadata.ISO !== undefined ||
            metadata.FocalLength !== undefined) && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-lg mb-3 flex items-center gap-2">
                <Camera size={16} className="text-brand-600 dark:text-brand-400" />
                Capture Settings
              </h2>
              <Row label="date / time" value={formatDateTime(metadata.DateTimeOriginal)} />
              {metadata.ExposureTime !== undefined && (
                <Row label="exposure" value={formatExposure(metadata.ExposureTime as number)} />
              )}
              {metadata.FNumber !== undefined && <Row label="aperture" value={`f/${metadata.FNumber}`} />}
              {metadata.ISO !== undefined && <Row label="ISO" value={metadata.ISO as number} />}
              {metadata.FocalLength !== undefined && (
                <Row label="focal length" value={formatFocalLength(metadata.FocalLength as number)} />
              )}
            </section>
          )}

          {/* Image info */}
          {(metadata.ImageWidth || metadata.ImageHeight || metadata.Orientation || metadata.ColorSpace) && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-lg mb-3 flex items-center gap-2">
                <Image size={16} className="text-brand-600 dark:text-brand-400" />
                Image
              </h2>
              {metadata.ImageWidth !== undefined && metadata.ImageHeight !== undefined && (
                <Row label="dimensions" value={`${metadata.ImageWidth} × ${metadata.ImageHeight}`} />
              )}
              {metadata.Orientation !== undefined && <Row label="orientation" value={String(metadata.Orientation)} />}
              {metadata.ColorSpace !== undefined && <Row label="color space" value={String(metadata.ColorSpace)} />}
            </section>
          )}

          {/* IPTC */}
          {(metadata.Copyright || metadata.Caption || keywordsStr) && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-lg mb-3 flex items-center gap-2">
                <FileText size={16} className="text-brand-600 dark:text-brand-400" />
                IPTC Metadata
              </h2>
              <Row label="copyright" value={metadata.Copyright as string | undefined} />
              <Row label="caption" value={metadata.Caption as string | undefined} />
              <Row label="keywords" value={keywordsStr} />
            </section>
          )}
        </div>
      )}
    </DataPageLayout>
  );
}
