import { useState } from 'react';
import { postJsonWithBody } from './adminApi';

/**
 * Content types offered for manual generation.
 *
 * Ordered the way an operator thinks about it — "what do I want to write
 * about" — rather than by the internal union order. Mirrors
 * `CaseStudyType` in api/src/case-study/types.ts; the new vulnerability and
 * AI types are the ones this list was missing before.
 */
const CASE_TYPES = [
  { value: 'vulnfaq', label: 'Vulnerability explainer (FAQ)' },
  { value: 'exploit', label: 'Exploit / weaponisation' },
  { value: 'cve', label: 'CVE' },
  { value: 'actor', label: 'Threat Actor' },
  { value: 'malware', label: 'Malware' },
  { value: 'darkweb', label: 'Darkweb / underground' },
  { value: 'breach', label: 'Breach' },
  { value: 'scam', label: 'Scam' },
  { value: 'llm', label: 'LLM / model security' },
  { value: 'aisec', label: 'AI Security' },
  { value: 'aisecops', label: 'AI SecOps' },
  { value: 'supplychain', label: 'Supply chain' },
  { value: 'intel', label: 'Threat Intel' },
  { value: 'osint', label: 'OSINT' },
  { value: 'methodology', label: 'Methodology' },
  { value: 'hunting', label: 'Threat hunt' },
  { value: 'analysis', label: 'Analysis' },
  { value: 'trend', label: 'Trend' },
];

interface FormatResult {
  slug?: string;
  title?: string;
  final_post?: string;
  status?: string;
  rejected?: boolean;
  reason?: string;
  generatedAt?: string;
}

interface GenerateResponse {
  ok: boolean;
  slug: string;
  dry_run?: boolean;
  result?: Record<string, FormatResult>;
  errors?: string[];
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';
const labelCls = 'block text-xs uppercase tracking-wider text-muted mb-1';

export default function GenerateTab() {
  const [mode, setMode] = useState<'ai' | 'manual'>('ai');

  // ── AI generate state ─────────────────────────────────────────────
  const [topic, setTopic] = useState('');
  const [audience, setAudience] = useState('');
  const [tone, setTone] = useState('professional');
  const [type, setType] = useState('analysis');
  const [notes, setNotes] = useState('');
  const [formats, setFormats] = useState({ blog: true, linkedin: true, twitter: false });
  const [dryRun, setDryRun] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState<GenerateResponse | null>(null);
  const [genError, setGenError] = useState<string | null>(null);

  // ── Manual write state ────────────────────────────────────────────
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [tags, setTags] = useState('');
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<{ ok?: boolean; slug?: string; error?: string } | null>(null);

  function toggleFormat(k: keyof typeof formats) {
    setFormats((prev) => ({ ...prev, [k]: !prev[k] }));
  }

  async function handleGenerate() {
    if (!topic.trim()) return;
    const chosen = Object.entries(formats)
      .filter(([, on]) => on)
      .map(([k]) => k);
    if (chosen.length === 0) return;
    setGenerating(true);
    setGenError(null);
    setGenResult(null);
    try {
      const r = await postJsonWithBody<GenerateResponse>('/generate', {
        topic: topic.trim(),
        audience: audience.trim() || undefined,
        tone: tone.trim() || undefined,
        type,
        notes: notes.trim() || undefined,
        formats: chosen,
        dry_run: dryRun,
      });
      setGenResult(r);
    } catch (e) {
      console.error('handleGenerate failed:', e instanceof Error ? e.message : String(e));
      setGenError(e instanceof Error ? e.message : String(e));
    } finally {
      setGenerating(false);
    }
  }

  async function handlePublishManual() {
    if (!title.trim() || !body.trim()) return;
    setSending(true);
    setResult(null);
    try {
      const tagsArr = tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      const r = await postJsonWithBody<{ ok?: boolean; slug?: string; error?: string }>('/posts/manual', {
        type,
        title: title.trim(),
        body: body.trim(),
        tags: tagsArr.length > 0 ? tagsArr : undefined,
      });
      setResult(r);
    } catch (e) {
      console.error('handlePublish failed:', e instanceof Error ? e.message : String(e));
      setResult({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setSending(false);
    }
  }

  return (
    <div>
      {/* Mode switch */}
      <div className="flex gap-1 mb-5 p-1 rounded-lg bg-surface-300 w-fit">
        {(
          [
            ['ai', 'AI generate'],
            ['manual', 'Write manually'],
          ] as const
        ).map(([m, label]) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              mode === m
                ? 'bg-white dark:bg-surface-300 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-500 hover:text-slate-700 dark:text-muted'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {mode === 'ai' ? (
        <div className="space-y-4 max-w-3xl">
          <p className="text-sm text-muted">
            One topic → blog draft + social posts. Weak or empty output is rejected by the quality gate instead of being
            returned.
          </p>

          <div>
            <label htmlFor="gen-topic" className={labelCls}>
              Topic <span className="text-rose-500">*</span>
            </label>
            <input
              id="gen-topic"
              value={topic}
              onChange={(e) => setTopic(e.target.value)}
              placeholder="e.g. LockBit 3.0 affiliate infrastructure takedown — what changed"
              className={inputCls}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="gen-audience" className={labelCls}>
                Audience
              </label>
              <input
                id="gen-audience"
                value={audience}
                onChange={(e) => setAudience(e.target.value)}
                placeholder="SOC practitioners"
                className={inputCls}
              />
            </div>
            <div>
              <label htmlFor="gen-tone" className={labelCls}>
                Tone
              </label>
              <select id="gen-tone" value={tone} onChange={(e) => setTone(e.target.value)} className={inputCls}>
                <option value="professional">Professional</option>
                <option value="technical">Technical deep-dive</option>
                <option value="advisory">Executive advisory</option>
                <option value="direct">Direct / no-nonsense</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="gen-type" className={labelCls}>
                Content type
              </label>
              <select id="gen-type" value={type} onChange={(e) => setType(e.target.value)} className={inputCls}>
                {CASE_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <span className={labelCls}>Formats</span>
              <div className="flex flex-wrap gap-3 pt-1">
                {(
                  [
                    ['blog', 'Blog draft'],
                    ['linkedin', 'LinkedIn'],
                    ['twitter', 'X thread'],
                  ] as const
                ).map(([k, label]) => (
                  <label key={k} className="inline-flex items-center gap-1.5 text-sm text-body cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formats[k]}
                      onChange={() => toggleFormat(k)}
                      className="accent-brand-600"
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div>
            <label htmlFor="gen-notes" className={labelCls}>
              Notes <span className="normal-case">(optional — facts to include, angle to take)</span>
            </label>
            <textarea
              id="gen-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={4}
              placeholder="Key facts, sources, or the specific angle you want…"
              className={`${inputCls} font-mono`}
            />
          </div>

          <label className="inline-flex items-center gap-2 text-sm text-body cursor-pointer">
            <input
              type="checkbox"
              checked={dryRun}
              onChange={() => setDryRun((p) => !p)}
              className="accent-brand-600"
            />
            Dry run <span className="text-xs text-muted">(compose only — don't create a draft)</span>
          </label>

          <button
            onClick={() => void handleGenerate()}
            disabled={generating || !topic.trim() || Object.values(formats).every((v) => !v)}
            className="px-4 py-2 bg-brand-600 text-on-fill rounded text-sm font-medium hover:bg-brand-500 disabled:opacity-50"
          >
            {generating ? 'Generating…' : 'Generate'}
          </button>

          {genError && (
            <div className="p-3 rounded text-sm font-mono bg-rose-50 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
              Error: {genError}
            </div>
          )}

          {genResult?.errors && genResult.errors.length > 0 && (
            <div className="p-3 rounded text-sm font-mono bg-amber-50 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
              {genResult.errors.join('\n')}
            </div>
          )}

          {/* Per-format results */}
          {genResult?.result &&
            Object.entries(genResult.result).map(([fmt, r]) => (
              <div
                key={fmt}
                className={`p-4 rounded-xl border ${
                  r.rejected
                    ? 'border-amber-300 dark:border-amber-800 bg-amber-50/60 dark:bg-amber-900/20'
                    : 'border-line-1 bg-white dark:bg-surface-200'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
                  <span className="text-xs font-mono uppercase tracking-wider text-muted">
                    {fmt}
                    {r.status ? ` · ${r.status}` : ''}
                  </span>
                  {!r.rejected && r.final_post && (
                    <button
                      type="button"
                      onClick={() => void navigator.clipboard.writeText(r.final_post ?? '')}
                      className="text-xs px-2 py-1 rounded border border-line-1 text-body hover:bg-surface-200 dark:hover:bg-surface-300"
                    >
                      Copy
                    </button>
                  )}
                </div>
                {r.rejected ? (
                  <p className="text-sm text-amber-800 dark:text-amber-300">
                    Rejected by quality gate{r.reason ? ` — ${r.reason}` : ''}. Try adding concrete facts to Notes and
                    regenerate.
                  </p>
                ) : fmt === 'blog' ? (
                  <p className="text-sm text-body">
                    {dryRun ? 'Composed (dry run — not saved).' : 'Draft created.'} A generated post lives in the KV
                    drafts store until approved — it has no public /blog URL yet.{' '}
                    <span className="text-muted">Review it in the Drafts tab.</span>
                  </p>
                ) : (
                  <pre className="whitespace-pre-wrap text-sm font-mono text-body max-h-72 overflow-y-auto">
                    {r.final_post}
                  </pre>
                )}
              </div>
            ))}
        </div>
      ) : (
        <div className="space-y-4 max-w-3xl">
          <p className="text-sm text-muted mb-2">
            Write and publish a case study directly, bypassing the automated pipeline.
          </p>
          <div>
            <label htmlFor="manual-type" className={labelCls}>
              Type
            </label>
            <select id="manual-type" value={type} onChange={(e) => setType(e.target.value)} className={inputCls}>
              {CASE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="manual-title" className={labelCls}>
              Title
            </label>
            <input
              id="manual-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Case study title"
              className={inputCls}
            />
          </div>

          <div>
            <label htmlFor="manual-body" className={labelCls}>
              Body <span className="text-muted normal-case">(Markdown)</span>
            </label>
            <textarea
              id="manual-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Write your case study in Markdown..."
              rows={20}
              className={`${inputCls} font-mono`}
            />
          </div>

          <div>
            <label htmlFor="manual-tags" className={labelCls}>
              Tags <span className="text-muted normal-case">(comma-separated)</span>
            </label>
            <input
              id="manual-tags"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="osint, threat-intel, tools"
              className={inputCls}
            />
          </div>

          <button
            onClick={() => void handlePublishManual()}
            disabled={sending || !title.trim() || !body.trim()}
            className="px-4 py-2 bg-brand-600 text-on-fill rounded text-sm font-medium hover:bg-brand-500 disabled:opacity-50"
          >
            {sending ? 'Publishing…' : 'Publish'}
          </button>

          {result && (
            <div
              className={`mt-4 p-3 rounded text-sm font-mono ${result.ok ? 'bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800' : 'bg-rose-50 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800'}`}
            >
              {result.ok ? (
                <>
                  Published!{' '}
                  <a href={`/blog/${result.slug}`} className="underline" target="_blank" rel="noopener noreferrer">
                    /blog/{result.slug}
                  </a>
                </>
              ) : (
                <>Error: {result.error}</>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
