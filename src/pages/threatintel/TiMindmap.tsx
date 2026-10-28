/**
 * TI Mindmap Studio — LLM threat-report mindmap UI (edge port).
 *
 * Talks to the edge API in api/src/routes/ti-mindmap.ts (GET /api/v1/ti-mindmap/,
 * POST /analyze, POST /assistant) and renders its artifacts: the tweet-length
 * dossier, a parsed Mermaid mindmap tree, the deterministic TTP timeline, and
 * the ATT&CK Navigator layer. Upstream methodology: format81/TI-Mindmap-GPT
 * (GPLv3) and the TI Mindmap HUB research docs (CC BY-NC 4.0), re-implemented
 * independently on the platform runCompletion chain — no BYOK keys.
 *
 * The Mermaid source is deliberately shown as text (copy or download `.mmd`);
 * the interactive view is the parsed tree rendered as nested disclosures, so
 * the page does not need the Mermaid bundle. Composition note: IOCs / STIX /
 * Diamond Model analysis stay on /threatintel/report-analyzer.
 *
 * Route: /threatintel/ti-mindmap
 */
import { useCallback, useState } from 'react';
import { Brain, AlertTriangle, Check, Copy, Download, ExternalLink, Loader2, MessageSquare, X } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { downloadText, downloadJson } from '../../lib/download';
import { errMessage } from '../../lib/log';

// ── API shapes (mirror api/src/lib/ti-mindmap.ts) ─────────────────────

interface MermaidTree {
  label: string;
  depth: number;
  children: MermaidTree[];
}

interface SanitizedMindmap {
  ok: boolean;
  text: string;
  tree: MermaidTree | null;
  warnings: string[];
  nodes: number;
}

interface TweetDossier {
  tweet_summary: string;
  actor: string | null;
  malware: string[];
  sectors: string[];
  headline: string | null;
}

interface TtpHit {
  id: string;
  name: string;
  tactic: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
}

interface NavigatorTechnique {
  techniqueID: string;
  score: number;
  comment?: string;
}

interface NavigatorLayer {
  name: string;
  techniques: NavigatorTechnique[];
}

interface AnalyzeResponse {
  title: string | null;
  textLength: number;
  elapsed_ms: number;
  tweet: TweetDossier | null;
  mindmap: SanitizedMindmap | null;
  ttps: TtpHit[];
  timeline_mermaid: string;
  navigator: NavigatorLayer;
  navigator_file: string;
  branches: { tweet: string | null; mindmap: string | null };
  models: { tweet: string | null; mindmap: string | null };
  warnings: string[];
  source_text?: string;
}

interface ChatTurn {
  q: string;
  a: string;
  model: string;
}

type Tab = 'overview' | 'mindmap' | 'mermaid' | 'timeline' | 'navigator' | 'chat';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'mindmap', label: 'Mindmap' },
  { id: 'mermaid', label: 'Mermaid' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'navigator', label: 'Navigator' },
  { id: 'chat', label: 'Chat' },
];

function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 48) || 'ti-mindmap'
  );
}

function attackUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard
          .writeText(text)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => setCopied(false));
      }}
      disabled={!text}
      className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
      {label}
    </button>
  );
}

/** Interactive mindmap tree (nested disclosures — no Mermaid bundle). */
function TreeView({ node }: { node: MermaidTree }): JSX.Element {
  if (node.children.length === 0) {
    return <p className="py-0.5 font-mono text-xs">{node.label}</p>;
  }
  return (
    <details open={node.depth <= 1} className="py-0.5">
      <summary className="cursor-pointer text-sm select-none">{node.label}</summary>
      <ul className="ml-3 border-l border-line pl-3">
        {node.children.map((c, i) => (
          <li key={i}>
            <TreeView node={c} />
          </li>
        ))}
      </ul>
    </details>
  );
}

function Chip({ children }: { children: string }): JSX.Element {
  return <span className="rounded-full border border-line bg-surface px-2 py-0.5 font-mono text-xs">{children}</span>;
}

function MermaidSource({ code }: { code: string }): JSX.Element {
  return (
    <pre className="max-h-[420px] overflow-auto rounded-xl border border-line bg-surface p-3 font-mono text-xs leading-5 whitespace-pre-wrap">
      {code}
    </pre>
  );
}

function TiMindmapInner(): JSX.Element {
  const [mode, setMode] = useState<'url' | 'text'>('url');
  const [model, setModel] = useState<'auto' | 'oss'>('auto');
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [res, setRes] = useState<AnalyzeResponse | null>(null);
  const [sourceText, setSourceText] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [question, setQuestion] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [chat, setChat] = useState<ChatTurn[]>([]);

  const analyze = useCallback(async () => {
    const v = input.trim();
    if (v.length < 10) {
      setError('Paste an article URL or ≥200 chars of text.');
      return;
    }
    setBusy(true);
    setError(null);
    setStage('analyzing — dossier and mindmap are two LLM passes, hold on…');
    setRes(null);
    setChat([]);
    try {
      const body = mode === 'url' ? { url: v, model } : { text: v, model };
      const r = await fetch('/api/v1/ti-mindmap/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120_000),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const d = (await r.json()) as AnalyzeResponse;
      setRes(d);
      setSourceText(typeof d.source_text === 'string' && d.source_text ? d.source_text : mode === 'text' ? v : null);
      setStage('');
    } catch (e) {
      setError(errMessage(e, 'analysis failed'));
      setStage('');
    } finally {
      setBusy(false);
    }
  }, [input, mode, model]);

  const ask = useCallback(async () => {
    const q = question.trim();
    if (!sourceText || q.length < 3) return;
    setChatBusy(true);
    setChatError(null);
    try {
      const r = await fetch('/api/v1/ti-mindmap/assistant', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: sourceText, question: q, model }),
        signal: AbortSignal.timeout(120_000),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const d = (await r.json()) as { answer: string; modelUsed?: string };
      setChat((c) => [...c, { q, a: d.answer, model: d.modelUsed ?? 'edge-llm' }]);
      setQuestion('');
    } catch (e) {
      setChatError(errMessage(e, 'assistant failed'));
    } finally {
      setChatBusy(false);
    }
  }, [question, sourceText, model]);

  const mindmapText = res?.mindmap?.text ?? '';
  const mmdName = `${slugify(res?.title ?? '')}.mmd`;

  return (
    <DataPageLayout
      title="TI Mindmap Studio"
      description="Paste a threat report URL or text; the edge LLM writes a tweet-length dossier, a Mermaid mindmap, an execution-ordered TTP timeline, and an ATT&CK Navigator layer. Independently ported from format81/TI-Mindmap-GPT (GPLv3) + TI Mindmap HUB research (CC BY-NC) onto the platform's LLM chain."
      icon={<Brain className="h-5 w-5" />}
      backTo="/threatintel"
    >
      {/* Input row (mirrors FlowViz) */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex rounded-lg border border-line overflow-hidden">
          {(['url', 'text'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1.5 text-xs font-mono uppercase ${mode === m ? 'bg-brand-500/20 text-brand-600' : 'text-muted'}`}
            >
              {m === 'url' ? 'URL' : 'Text'}
            </button>
          ))}
        </div>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={mode === 'url' ? 'https://example.com/threat-report…' : 'Paste report text (≥200 chars)…'}
          className="flex-1 min-w-52 rounded-lg border border-line bg-surface px-3 py-2 text-sm"
        />
        <div
          className="flex rounded-lg border border-line overflow-hidden"
          title="Auto = best available model. OSS = open-weights (Groq gpt-oss) only."
        >
          {(['auto', 'oss'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setModel(m)}
              className={`px-3 py-1.5 text-xs font-mono uppercase ${model === m ? 'bg-brand-500/20 text-brand-600' : 'text-muted'}`}
            >
              {m === 'auto' ? 'Auto' : 'OSS'}
            </button>
          ))}
        </div>
        <button
          onClick={analyze}
          disabled={busy}
          className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-on-fill disabled:opacity-50"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Analyze'}
        </button>
      </div>

      {stage && <p className="mb-2 text-xs font-mono text-muted">{stage}</p>}
      {error && (
        <p className="mb-2 flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/5 px-3 py-2 text-sm text-rose-600">
          <AlertTriangle className="h-4 w-4" /> {error}{' '}
          <button onClick={() => setError(null)} className="ml-auto">
            <X className="h-4 w-4" />
          </button>
        </p>
      )}
      {res && (
        <p className="mb-2 text-xs font-mono text-muted">
          {res.title ?? 'untitled'} · {res.textLength.toLocaleString()} chars · {res.elapsed_ms} ms · tweet:{' '}
          {res.models.tweet ?? 'failed'} / mindmap: {res.models.mindmap ?? 'failed'} · {res.mindmap?.nodes ?? 0} nodes ·{' '}
          {res.ttps.length} TTPs
        </p>
      )}

      {res && (
        <>
          <div className="mb-3 flex flex-wrap rounded-lg border border-line overflow-hidden">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-3 py-1.5 text-xs font-mono uppercase ${tab === t.id ? 'bg-brand-500/20 text-brand-600' : 'text-muted'}`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* ── Overview ── */}
          {tab === 'overview' && (
            <div className="rounded-xl border border-line bg-surface p-4">
              <p className="text-lg font-semibold">{res.tweet?.headline ?? res.title ?? 'Untitled report'}</p>
              {res.tweet ? (
                <>
                  <blockquote className="mt-2 border-l-2 border-line pl-3 text-sm italic text-muted">
                    {res.tweet.tweet_summary}
                  </blockquote>
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    {res.tweet.actor && (
                      <span className="rounded-full border border-brand-500/40 bg-brand-500/10 px-2 py-0.5 font-mono text-xs text-brand-600">
                        {res.tweet.actor}
                      </span>
                    )}
                    {res.tweet.malware.map((m) => (
                      <Chip key={m}>{m}</Chip>
                    ))}
                    {res.tweet.sectors.map((s) => (
                      <Chip key={s}>{s}</Chip>
                    ))}
                  </div>
                </>
              ) : (
                <p className="mt-2 text-sm text-muted">Tweet dossier failed (see warnings below).</p>
              )}
              <p className="mt-3 text-xs font-mono text-muted">
                tweet: {res.branches.tweet} · mindmap: {res.branches.mindmap} · IOCs / STIX / Diamond live on{' '}
                <a className="underline" href="/threatintel/report-analyzer">
                  report-analyzer
                </a>
              </p>
              {res.warnings.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-amber-600">
                  {res.warnings.slice(0, 6).map((w, i) => (
                    <li key={i}>· {w}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* ── Mindmap (interactive tree) ── */}
          {tab === 'mindmap' && (
            <div className="rounded-xl border border-line bg-surface p-4">
              {res.mindmap?.tree ? (
                <>
                  <div className="mb-3 flex flex-wrap gap-2">
                    <CopyButton text={mindmapText} label="Copy Mermaid" />
                    <button
                      onClick={() => downloadText(mindmapText, mmdName, 'text/x-mermaid')}
                      className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm"
                    >
                      <Download className="h-3.5 w-3.5" /> {mmdName}
                    </button>
                  </div>
                  <TreeView node={res.mindmap.tree} />
                </>
              ) : (
                <p className="text-sm text-muted">
                  Mindmap unavailable ({res.warnings.filter((w) => w.startsWith('mindmap:')).join('; ') || 'no tree'})
                </p>
              )}
            </div>
          )}

          {/* ── Mermaid source ── */}
          {tab === 'mermaid' && (
            <div>
              <div className="mb-3 flex flex-wrap gap-2">
                <CopyButton text={mindmapText} />
                <button
                  onClick={() => downloadText(mindmapText, mmdName, 'text/x-mermaid')}
                  disabled={!mindmapText}
                  className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
                >
                  <Download className="h-3.5 w-3.5" /> .mmd
                </button>
                <a
                  href="https://mermaid.live/edit#"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm"
                >
                  <ExternalLink className="h-3.5 w-3.5" /> mermaid.live
                </a>
              </div>
              {mindmapText ? (
                <MermaidSource code={mindmapText} />
              ) : (
                <p className="text-sm text-muted">
                  No mindmap text. Paste the downloaded .mmd into mermaid.live to render.
                </p>
              )}
            </div>
          )}

          {/* ── Timeline ── */}
          {tab === 'timeline' && (
            <div>
              {res.ttps.length > 0 ? (
                <>
                  <div className="mb-3 grid grid-cols-1 gap-2">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs font-mono uppercase text-muted">
                          <th className="py-1 pr-2">#</th>
                          <th className="py-1 pr-2">Tactic</th>
                          <th className="py-1 pr-2">Technique</th>
                          <th className="py-1 pr-2">Conf</th>
                          <th className="py-1">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {res.ttps.slice(0, 40).map((t, i) => (
                          <tr key={`${t.id}-${i}`} className="border-t border-line">
                            <td className="py-1 pr-2 font-mono text-xs text-muted">{i + 1}</td>
                            <td className="py-1 pr-2 text-xs">{t.tactic}</td>
                            <td className="py-1 pr-2 font-mono text-xs">
                              <a className="underline" href={attackUrl(t.id)} target="_blank" rel="noreferrer">
                                {t.id}
                              </a>{' '}
                              {t.name}
                            </td>
                            <td className="py-1 pr-2 text-xs">{t.confidence}</td>
                            <td className="py-1 text-xs text-muted">{t.evidence.slice(0, 90)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {res.timeline_mermaid && (
                    <>
                      <div className="mb-2 flex gap-2">
                        <CopyButton text={res.timeline_mermaid} />
                      </div>
                      <MermaidSource code={res.timeline_mermaid} />
                    </>
                  )}
                </>
              ) : (
                <p className="text-sm text-muted">
                  No deterministic TTP keyword hits in this report, so the timeline and Navigator layer are empty.
                </p>
              )}
            </div>
          )}

          {/* ── Navigator ── */}
          {tab === 'navigator' && (
            <div>
              <div className="mb-3 flex flex-wrap gap-2">
                <button
                  onClick={() => downloadJson(res.navigator_file, res.navigator)}
                  className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm"
                >
                  <Download className="h-3.5 w-3.5" /> {res.navigator_file}
                </button>
                <CopyButton text={JSON.stringify(res.navigator, null, 2)} label="Copy JSON" />
                <a
                  href="https://mitre-attack.github.io/attack-navigator/"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm"
                >
                  <ExternalLink className="h-3.5 w-3.5" /> ATT&CK Navigator
                </a>
              </div>
              {res.navigator.techniques.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs font-mono uppercase text-muted">
                      <th className="py-1 pr-2">Technique</th>
                      <th className="py-1 pr-2">Score</th>
                      <th className="py-1">Evidence (comment)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {res.navigator.techniques.map((t) => (
                      <tr key={t.techniqueID} className="border-t border-line">
                        <td className="py-1 pr-2 font-mono text-xs">
                          <a className="underline" href={attackUrl(t.techniqueID)} target="_blank" rel="noreferrer">
                            {t.techniqueID}
                          </a>
                        </td>
                        <td className="py-1 pr-2 font-mono text-xs">{t.score}</td>
                        <td className="py-1 text-xs text-muted">{t.comment ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-sm text-muted">
                  Layer has 0 techniques (no keyword TTP hits). Download it anyway or check the Timeline tab.
                </p>
              )}
              <p className="mt-2 text-xs text-muted">
                Scores encode keyword confidence: high 100 · medium 60 · low 30. Load the JSON via “Open Layer” in the
                Navigator.
              </p>
            </div>
          )}

          {/* ── Chat ── */}
          {tab === 'chat' && (
            <div className="rounded-xl border border-line bg-surface p-4">
              {sourceText ? (
                <>
                  {chat.map((t, i) => (
                    <div key={i} className="mb-3 border-b border-line pb-3 last:border-none">
                      <p className="text-sm font-semibold">Q: {t.q}</p>
                      <p className="mt-1 text-sm whitespace-pre-wrap">{t.a}</p>
                      <p className="mt-1 font-mono text-xs text-muted">{t.model}</p>
                    </div>
                  ))}
                  {chatError && (
                    <p className="mb-2 flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/5 px-3 py-2 text-sm text-rose-600">
                      <AlertTriangle className="h-4 w-4" /> {chatError}
                      <button onClick={() => setChatError(null)} className="ml-auto">
                        <X className="h-4 w-4" />
                      </button>
                    </p>
                  )}
                  <div className="flex gap-2">
                    <input
                      value={question}
                      onChange={(e) => setQuestion(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !chatBusy) void ask();
                      }}
                      placeholder="Ask the report something…"
                      className="flex-1 rounded-lg border border-line bg-background px-3 py-2 text-sm"
                    />
                    <button
                      onClick={ask}
                      disabled={chatBusy || question.trim().length < 3}
                      className="flex items-center gap-1.5 rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-on-fill disabled:opacity-50"
                    >
                      {chatBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <MessageSquare className="h-4 w-4" />}
                      Ask
                    </button>
                  </div>
                </>
              ) : (
                <p className="text-sm text-muted">
                  Chat needs the report text. Use Text mode, or re-run analyze (the response now echoes the extracted
                  article for URL mode).
                </p>
              )}
            </div>
          )}
        </>
      )}

      {!res && !busy && (
        <p className="rounded-xl border border-line bg-surface p-4 text-sm text-muted">
          Artifacts produced per report: tweet-length dossier (actor / malware / sectors / headline), sanitized Mermaid
          mindmap + parsed tree, keyword-extracted TTPs in ATT&CK execution order with a Mermaid timeline, and an ATT&CK
          Navigator layer JSON (confidence → score). Attribution and chat grounded the same way as every other platform
          LLM surface: strictly from the fenced report text.
        </p>
      )}

      <p className="mt-4 text-xs text-muted">
        Upstream methodology:{' '}
        <a className="underline" href="https://github.com/format81/TI-Mindmap-GPT">
          format81/TI-Mindmap-GPT
        </a>{' '}
        (GPLv3) +{' '}
        <a className="underline" href="https://github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-research">
          TI Mindmap HUB research
        </a>{' '}
        (CC BY-NC 4.0) — independent edge reimplementation, no upstream code. ATT&CK® © The MITRE Corporation. OSS mode
        runs open-weights models (Groq gpt-oss) instead of a local Ollama setup.
      </p>
    </DataPageLayout>
  );
}

export default function TiMindmap(): JSX.Element {
  return <TiMindmapInner />;
}
