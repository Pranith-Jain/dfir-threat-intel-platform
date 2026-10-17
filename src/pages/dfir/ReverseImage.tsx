import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Image as ImageIcon, Search, ExternalLink, Star, AlertTriangle, Clipboard, Check } from 'lucide-react';
import { ENGINES } from '../../data/dfir/reverse-image-engines';
import { errMessage } from '../../lib/log';

const SAMPLES: { label: string; url: string }[] = [
  {
    label: 'Wikimedia (cat)',
    url: 'https://upload.wikimedia.org/wikipedia/commons/thumb/3/3a/Cat03.jpg/640px-Cat03.jpg',
  },
  {
    label: 'Stock logo (Apple)',
    url: 'https://upload.wikimedia.org/wikipedia/commons/thumb/f/fa/Apple_logo_black.svg/200px-Apple_logo_black.svg.png',
  },
];

function isValidImageUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_catchErr) {
    console.error('isValidImageUrl failed:', errMessage(_catchErr));
    return false;
  }
}

export default function ReverseImage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = searchParams.get('url') ?? searchParams.get('q') ?? '';
  const [imageUrl, setImageUrl] = useState(initial);
  const [copiedAll, setCopiedAll] = useState(false);
  const lastValid = useRef<string | null>(null);

  const trimmed = imageUrl.trim();
  const valid = trimmed ? isValidImageUrl(trimmed) : false;

  // Persist into URL once we have something valid.
  useEffect(() => {
    if (!valid) return;
    if (trimmed === lastValid.current) return;
    lastValid.current = trimmed;
    setSearchParams({ url: trimmed }, { replace: true });
  }, [trimmed, valid, setSearchParams]);

  const links = useMemo(() => {
    if (!valid) return [];
    return ENGINES.map((e) => ({ engine: e, url: e.build(trimmed) }));
  }, [trimmed, valid]);

  const copyAll = async () => {
    if (links.length === 0) return;
    const blob = links.map((l) => l.url).join('\n');
    await navigator.clipboard.writeText(blob);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 1500);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <ImageIcon size={28} className="text-brand-600 dark:text-brand-400" /> Reverse Image Search
        </h1>
        <p className="text-muted mb-2 max-w-3xl leading-relaxed">
          Paste an image URL - get one-click links to Google Lens, Bing Visual, Yandex (best for faces), TinEye (best
          for first-seen), Baidu, Sogou, and Karma Decay (Reddit). Pure URL generation; the image stays on its original
          host.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Pairs with{' '}
          <Link to="/dfir/phishing" className="text-brand-600 dark:text-brand-400 hover:underline">
            Phishing analyzer
          </Link>{' '}
          (logo theft, brand impersonation, signature-image reuse) and{' '}
          <Link to="/dfir/exif" className="text-brand-600 dark:text-brand-400 hover:underline">
            EXIF parser
          </Link>{' '}
          (provenance from metadata). Run multiple engines in parallel - none has full coverage on its own.
        </p>
      </div>

      {/* Input */}
      <section className="surface-card p-4 mb-6">
        <div className="relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input
            type="url"
            value={imageUrl}
            onChange={(e) => setImageUrl(e.target.value)}
            placeholder="https://example.com/path/to/image.jpg"
            className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        {trimmed && !valid && (
          <p className="mt-2 text-meta font-mono text-amber-600 dark:text-amber-400 inline-flex items-center gap-1.5">
            <AlertTriangle size={12} /> Not a valid http/https URL
          </p>
        )}
        <div className="flex flex-wrap gap-1.5 mt-3">
          <span className="text-micro font-mono text-muted self-center mr-1">samples:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => setImageUrl(s.url)}
              className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
            >
              {s.label}
            </button>
          ))}
        </div>
      </section>

      {valid && (
        <>
          {/* Image preview */}
          <section className="surface-card p-4 mb-6">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">Preview</h2>
            <div className="flex flex-col sm:flex-row gap-4">
              <img
                loading="lazy"
                src={trimmed}
                alt="reverse-search target"
                className="rounded border border-line-1 max-h-48 max-w-xs object-contain bg-surface-200"
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
              <div className="flex-1 min-w-0">
                <code className="block text-mini font-mono text-body break-all bg-surface-200 rounded border border-line-1 p-2 mb-2">
                  {trimmed}
                </code>
                <p className="text-mini font-mono text-muted">
                  If the preview doesn't load, the image host may block hot-linking. The reverse-search engines fetch
                  the image server-side regardless, so the lookups still work.
                </p>
              </div>
            </div>
          </section>

          {/* Engine links */}
          <section className="surface-card p-4 mb-6">
            <div className="flex items-baseline justify-between gap-2 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">
                Engines ({links.length})
              </h2>
              <button
                type="button"
                onClick={() => void copyAll()}
                className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1"
              >
                {copiedAll ? <Check size={11} /> : <Clipboard size={11} />}
                {copiedAll ? 'copied' : 'copy all URLs'}
              </button>
            </div>
            <ul className="grid sm:grid-cols-2 gap-2">
              {links.map(({ engine, url }) => (
                <li key={engine.id}>
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`block rounded border px-3 py-2 hover:border-brand-500/60 transition-colors ${
                      engine.recommended
                        ? 'border-brand-500/30 bg-brand-500/5'
                        : 'border-line-1 bg-slate-50 dark:bg-input-200'
                    }`}
                  >
                    <div className="flex items-baseline justify-between gap-2 mb-0.5">
                      <span className="font-display font-semibold text-sm text-heading inline-flex items-center gap-1.5">
                        {engine.recommended && <Star size={10} className="text-brand-600 dark:text-brand-400" />}
                        {engine.name}
                      </span>
                      <ExternalLink size={11} className="text-muted shrink-0" />
                    </div>
                    <p className="text-mini font-mono text-muted">{engine.blurb}</p>
                    {engine.coverage && (
                      <p className="text-micro font-mono text-muted mt-1 italic">{engine.coverage}</p>
                    )}
                  </a>
                </li>
              ))}
            </ul>
            <p className="text-micro font-mono text-muted mt-3">
              <Star size={9} className="inline text-brand-600 dark:text-brand-400" /> = recommended starting set. Run
              all four (Lens / Bing / Yandex / TinEye) - coverage barely overlaps.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
