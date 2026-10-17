import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ChevronRight, KeyRound, Search } from 'lucide-react';
import { detectEncoding, decodeBase64, decodeUrl, decodeChain, type DecodeStep } from '../../lib/dfir/decode';
import { hasIocCandidates } from '../../lib/dfir/ioc-detect';
import { CopyButton } from '../../components/dfir/CopyButton';
import { Textarea } from '../../components/ui/Input';
import { errMessage } from '../../lib/log';

const FORMAT_BADGE: Record<string, string> = {
  base64: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300',
  url: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300',
  unknown: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted',
};

export default function Decode(): JSX.Element {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQ = searchParams.get('q') ?? '';
  const initialMode = (searchParams.get('mode') as 'auto' | 'base64' | 'url' | null) ?? 'auto';
  const [input, setInput] = useState(initialQ);
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [format, setFormat] = useState<string>('');
  const [steps, setSteps] = useState<DecodeStep[]>([]);
  const [mode, setMode] = useState<'auto' | 'base64' | 'url'>(initialMode);
  const autoRan = useRef(false);

  const sendToExtractor = () => {
    if (!output) return;
    try {
      sessionStorage.setItem('ioc-extractor-pipe', output);
    } catch (_catchErr) {
      console.error('Decode failed:', errMessage(_catchErr));
      /* sessionStorage unavailable - silent */
    }
    navigate('/dfir/extract?from=decoder');
  };

  const runDecode = (inputStr: string, selectedMode: 'auto' | 'base64' | 'url') => {
    const trimmed = inputStr.trim();
    if (!trimmed) {
      setOutput('');
      setError(null);
      setFormat('');
      setSteps([]);
      return;
    }

    setError(null);

    if (selectedMode === 'auto') {
      const chain = decodeChain(trimmed);
      if (chain.length === 0) {
        setSteps([]);
        setFormat('unknown');
        setOutput(trimmed);
        setError('Could not detect encoding format.');
        return;
      }
      setSteps(chain);
      setFormat(chain.length > 1 ? 'nested' : chain[0]!.format);
      setOutput(chain[chain.length - 1]!.output);
    } else if (selectedMode === 'base64') {
      const result = decodeBase64(trimmed);
      setSteps([]);
      setFormat('base64');
      if (result.ok) {
        setOutput(result.result);
      } else {
        setOutput('');
        setError(result.error);
      }
    } else {
      const result = decodeUrl(trimmed);
      setSteps([]);
      setFormat('url');
      if (result.ok) {
        setOutput(result.result);
      } else {
        setOutput('');
        setError(result.error);
      }
    }
  };

  // Sync the current input + mode into the URL so a decode result is
  // shareable. Only writes when the input is non-empty so an empty page
  // doesn't drop a stray ?q= behind it.
  const pushUrl = (val: string, m: 'auto' | 'base64' | 'url') => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (val.trim()) out.set('q', val.trim());
        else out.delete('q');
        if (m !== 'auto') out.set('mode', m);
        else out.delete('mode');
        return out;
      },
      { replace: true }
    );
  };

  const handleInput = (val: string) => {
    setInput(val);
    runDecode(val, mode);
    pushUrl(val, mode);
  };

  const handleMode = (m: 'auto' | 'base64' | 'url') => {
    setMode(m);
    runDecode(input, m);
    pushUrl(input, m);
  };

  // Auto-decode when the page loads with ?q=<encoded>.
  useEffect(() => {
    if (autoRan.current) return;
    if (initialQ) {
      autoRan.current = true;
      runDecode(initialQ, initialMode);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const detectedOnLoad = input ? detectEncoding(input) : 'unknown';

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<KeyRound size={28} />}
      title="Decoder"
      description="Base64 and URL decode with auto-detect and multi-pass chaining for nested encodings."
    >
      {/* Mode buttons */}
      <div className="flex gap-2 mb-6">
        {(['auto', 'base64', 'url'] as const).map((m) => (
          <button
            key={m}
            onClick={() => handleMode(m)}
            className={`px-4 py-2 rounded-xl font-mono text-sm font-semibold transition-colors border ${
              mode === m
                ? 'bg-brand-600 dark:bg-brand-500 text-white border-brand-600 dark:border-brand-500'
                : 'bg-white dark:bg-surface-200 text-body border-line-1 hover:border-brand-400'
            }`}
          >
            {m === 'auto' ? 'Auto-Detect' : m === 'base64' ? 'Base64 Decode' : 'URL Decode'}
          </button>
        ))}
      </div>

      {/* Two-pane layout */}
      <div className="grid md:grid-cols-2 gap-4 mb-6">
        {/* Input */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="decode-input" className="text-xs font-mono text-muted uppercase tracking-wider">
              Input
            </label>
            {input && mode === 'auto' && detectedOnLoad !== 'unknown' && (
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${FORMAT_BADGE[detectedOnLoad]}`}>
                Detected: {detectedOnLoad.toUpperCase()}
              </span>
            )}
          </div>
          <Textarea
            id="decode-input"
            value={input}
            onChange={(e) => handleInput(e.target.value)}
            placeholder="Paste encoded string here..."
            rows={12}
            className="resize-none"
          />
        </div>

        {/* Output */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="decode-output" className="text-xs font-mono text-muted uppercase tracking-wider">
              Output
            </label>
            <div className="flex items-center gap-2">
              {format && format !== 'unknown' && (
                <span
                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${FORMAT_BADGE[format] ?? FORMAT_BADGE.unknown}`}
                >
                  {format === 'nested' ? 'NESTED' : format.toUpperCase()}
                </span>
              )}
              {output && hasIocCandidates(output) && (
                <button
                  type="button"
                  onClick={sendToExtractor}
                  className="inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 transition-colors"
                  title="Send decoded output to IOC Extractor"
                >
                  <Search size={11} /> extract IOCs →
                </button>
              )}
              {output && <CopyButton value={output} />}
            </div>
          </div>
          <div className="relative h-full">
            <Textarea
              id="decode-output"
              readOnly
              value={output}
              rows={12}
              className="w-full px-4 py-3 bg-surface-200/50 border border-line-1 rounded-xl font-mono text-sm text-heading resize-none focus:outline-none"
              placeholder="Decoded output will appear here..."
            />
          </div>
        </div>
      </div>

      {error && (
        <p role="alert" className="mb-4 text-sm font-mono text-amber-600 dark:text-amber-400">
          {error}
        </p>
      )}

      {/* Multi-pass steps */}
      {steps.length > 1 && (
        <section className="surface-card p-6">
          <h3 className="font-display font-semibold text-lg mb-4">Decode chain: {steps.length} passes</h3>
          <div className="space-y-3">
            {steps.map((step, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className="flex items-center gap-1 shrink-0">
                  <span className="text-xs font-mono text-muted">#{i + 1}</span>
                  <span
                    className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${FORMAT_BADGE[step.format] ?? FORMAT_BADGE.unknown}`}
                  >
                    {step.format.toUpperCase()}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-xs text-muted truncate">
                    {step.input.slice(0, 80)}
                    {step.input.length > 80 ? '…' : ''}
                  </div>
                  <ChevronRight size={12} className="text-muted my-0.5" />
                  <div className="font-mono text-xs text-body break-all">
                    {step.output.slice(0, 200)}
                    {step.output.length > 200 ? '…' : ''}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </DataPageLayout>
  );
}
