import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { errMessage } from '../../lib/log';
// Common Unicode characters used in homograph attacks → ASCII fold.
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  х: 'x',
  у: 'y',
  і: 'i',
  ѕ: 's',
  ӏ: 'l',
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  // Greek
  α: 'a',
  ο: 'o',
  ν: 'v',
  ι: 'i',
  κ: 'k',
  ρ: 'p',
  υ: 'u',
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Ζ: 'Z',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Υ: 'Y',
  Χ: 'X',
  // Latin lookalikes
  ʟ: 'L',
  '𝟏': '1',
  '𝟎': '0',
};

const BRANDS = [
  'google',
  'apple',
  'microsoft',
  'amazon',
  'paypal',
  'facebook',
  'twitter',
  'instagram',
  'linkedin',
  'github',
  'netflix',
  'dropbox',
  'adobe',
  'ebay',
  'alibaba',
  'walmart',
  'reddit',
  'youtube',
  'whatsapp',
  'telegram',
  'binance',
  'coinbase',
  'wellsfargo',
  'chase',
  'hsbc',
  'barclays',
  'bank',
];

interface CharInfo {
  char: string;
  codePoint: number;
  script: string;
  ascii: boolean;
}

function classifyChar(c: string): CharInfo {
  const cp = c.codePointAt(0) ?? 0;
  let script = 'Other';
  if (cp < 0x80) script = 'ASCII';
  else if (cp >= 0x0400 && cp <= 0x04ff) script = 'Cyrillic';
  else if (cp >= 0x0370 && cp <= 0x03ff) script = 'Greek';
  else if (cp >= 0x0590 && cp <= 0x05ff) script = 'Hebrew';
  else if (cp >= 0x0600 && cp <= 0x06ff) script = 'Arabic';
  else if (cp >= 0x4e00 && cp <= 0x9fff) script = 'CJK';
  else if (cp >= 0x0080 && cp <= 0x024f) script = 'Latin Extended';
  return { char: c, codePoint: cp, script, ascii: cp < 0x80 };
}

function fold(s: string): string {
  return [...s]
    .map((c) => CONFUSABLES[c] ?? c)
    .join('')
    .toLowerCase();
}

function asciiForm(domain: string): { ascii: string; ok: boolean } {
  try {
    const u = new URL(`http://${domain.toLowerCase()}`);
    return { ascii: u.hostname, ok: true };
  } catch (_catchErr) {
    console.error('asciiForm failed:', errMessage(_catchErr));
    return { ascii: domain, ok: false };
  }
}

interface AnalysisResult {
  input: string;
  ascii: string;
  hasUnicode: boolean;
  hasMixedScript: boolean;
  scripts: Set<string>;
  charInfo: CharInfo[];
  brandMatch: string | null;
  errors: string[];
}

function analyze(input: string): AnalysisResult {
  const trimmed = input
    .trim()
    .replace(/^https?:\/\//i, '')
    .split('/')[0];
  const result: AnalysisResult = {
    input: trimmed!,
    ascii: trimmed!,
    hasUnicode: false,
    hasMixedScript: false,
    scripts: new Set(),
    charInfo: [],
    brandMatch: null,
    errors: [],
  };

  if (!trimmed) return result;

  const { ascii, ok } = asciiForm(trimmed);
  if (!ok) result.errors.push('Could not parse as a hostname.');
  result.ascii = ascii;

  // Per-character classification (only over the visible/Unicode form, ignoring TLD breakdown)
  for (const c of trimmed) {
    if (c === '.') continue;
    const info = classifyChar(c);
    result.charInfo.push(info);
    result.scripts.add(info.script);
    if (!info.ascii) result.hasUnicode = true;
  }

  const nonAsciiScripts = [...result.scripts].filter((s) => s !== 'ASCII' && s !== 'Other');
  if (nonAsciiScripts.length > 0 && result.scripts.has('ASCII')) {
    result.hasMixedScript = true;
  }
  if (nonAsciiScripts.length > 1) result.hasMixedScript = true;

  if (result.hasUnicode) {
    const folded = fold(trimmed.split('.').slice(0, -1).join('.'));
    for (const brand of BRANDS) {
      if (folded.includes(brand)) {
        result.brandMatch = brand;
        break;
      }
    }
  }

  return result;
}

export default function Punycode(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = searchParams.get('q') ?? '';
  const [input, setInput] = useState(initial);
  const result = useMemo(() => analyze(input), [input]);

  useEffect(() => {
    if (input) setSearchParams({ q: input }, { replace: true });
    else setSearchParams({}, { replace: true });
  }, [input, setSearchParams]);

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Punycode / Homograph Detector</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Paste a domain. Detects internationalized (IDN) tricks: mixed scripts, Cyrillic / Greek lookalikes, and
          confusables that mimic well-known brand names.
        </p>
      </div>

      <label htmlFor="punycode-input" className="sr-only">
        Domain to check for homograph attacks
      </label>
      <input
        id="punycode-input"
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="example.com or аpple.com"
        aria-label="Domain to check for homograph attacks"
        className="mb-8"
      />

      {input.trim() && (
        <div className="space-y-6">
          <section className="surface-card p-5">
            <h3 className="font-display font-semibold mb-3">Forms</h3>
            <dl className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 text-sm font-mono">
              <dt className="text-muted">As entered</dt>
              <dd className="break-all">{result.input}</dd>
              <dt className="text-muted">ASCII / Punycode</dt>
              <dd className="break-all">{result.ascii}</dd>
              <dt className="text-muted">Scripts detected</dt>
              <dd>{[...result.scripts].sort().join(', ') || 'none'}</dd>
            </dl>
          </section>

          <section className="surface-card p-5 space-y-2">
            {result.hasMixedScript && (
              <Flag
                tone="warn"
                text={`Mixed scripts (${[...result.scripts].sort().join(' + ')}). Common in homograph attacks.`}
              />
            )}
            {result.brandMatch && (
              <Flag
                tone="warn"
                text={`Resembles "${result.brandMatch}" after folding lookalikes, which is a possible brand impersonation.`}
              />
            )}
            {result.hasUnicode && !result.hasMixedScript && !result.brandMatch && (
              <Flag
                tone="info"
                text="Domain contains non-ASCII characters but no mixed-script or brand match was found."
              />
            )}
            {!result.hasUnicode && <Flag tone="ok" text="Pure ASCII. No IDN homograph risk from this string alone." />}
          </section>

          {result.charInfo.length > 0 && (
            <section className="surface-card p-5">
              <h3 className="font-display font-semibold mb-3">Per-character breakdown</h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                {result.charInfo.map((c, i) => (
                  <div
                    key={i}
                    className={`rounded border px-2 py-1 ${c.ascii ? 'border-line-1 text-muted' : 'border-amber-400 bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300'}`}
                  >
                    <span className="text-base">{c.char}</span> · U+
                    {c.codePoint.toString(16).toUpperCase().padStart(4, '0')} · {c.script}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

function Flag({ tone, text }: { tone: 'warn' | 'ok' | 'info'; text: string }): JSX.Element {
  const cls =
    tone === 'warn'
      ? 'text-rose-700 dark:text-rose-400'
      : tone === 'ok'
        ? 'text-emerald-700 dark:text-emerald-400'
        : 'text-muted';
  const Icon = tone === 'ok' ? ShieldCheck : AlertTriangle;
  return (
    <div className={`flex items-start gap-2 text-sm ${cls}`}>
      <Icon size={14} className="mt-0.5 flex-shrink-0" />
      <span>{text}</span>
    </div>
  );
}
