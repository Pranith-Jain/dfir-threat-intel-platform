/**
 * FlowViz — AI attack-flow visualization (edge port UI).
 *
 * Upstream: davidljohnson/flowviz (MIT). This page talks to the edge-native
 * API in api/src/routes/flowviz.ts (POST /api/v1/flowviz/analyze, SSE
 * /analyze-stream, POST /assistant, GET /techniques) and renders the
 * resulting graph with @xyflow/react + dagre (the platform standard — see
 * KnowledgeGraph.tsx). Exports: PNG (html-to-image, dynamic import like
 * Tracer.tsx), STIX 2.1, .afb, FlowViz JSON (src/lib/flowviz-export.ts).
 * Save/load stays in localStorage (upstream contract); a D1-backed
 * IFlowStorage is future work.
 *
 * Route: /threatintel/flowviz
 */
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from 'react';
import type { Node, Edge } from '@xyflow/react';
import { GitBranch, Loader2, Download, Save, FolderOpen, Trash2, X, AlertTriangle } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { downloadUrl } from '../../lib/download';
import { errMessage } from '../../lib/log';
import {
  exportFlowvizStix,
  exportFlowvizAfb,
  downloadJson,
  listSavedFlows,
  saveFlow,
  deleteSavedFlow,
  type SavedFlow,
} from '../../lib/flowviz-export';

const FlowVizCanvas = lazy(() => import('../../components/flowviz/FlowVizCanvas'));

interface Validation {
  ok: boolean;
  nodeCount: number;
  edgeCount: number;
  errors: string[];
  warnings: string[];
}

interface AnalyzeResponse {
  nodes: Node[];
  edges: Edge[];
  validation: Validation;
  modelUsed?: string;
  title?: string;
}

function FlowVizInner(): JSX.Element {
  const [mode, setMode] = useState<'text' | 'url'>('url');
  const [model, setModel] = useState<'auto' | 'oss'>('auto');
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [modelUsed, setModelUsed] = useState<string | null>(null);
  const [selected, setSelected] = useState<Node | null>(null);
  const [saved, setSaved] = useState<SavedFlow[]>([]);
  const [showSaved, setShowSaved] = useState(false);
  const viewportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setSaved(listSavedFlows());
  }, []);

  const analyze = useCallback(async () => {
    const v = input.trim();
    if (v.length < 10) {
      setError('Paste an article URL or ≥200 chars of text.');
      return;
    }
    setBusy(true);
    setError(null);
    setStage('analyzing…');
    setNodes([]);
    setEdges([]);
    setValidation(null);
    try {
      const body = mode === 'url' ? { url: v, model } : { text: v, model };
      const r = await fetch('/api/v1/flowviz/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120_000),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const d = (await r.json()) as AnalyzeResponse;
      setNodes((d.nodes ?? []) as Node[]);
      setEdges((d.edges ?? []) as Edge[]);
      setValidation(d.validation);
      setModelUsed(d.modelUsed ?? null);
      setStage('');
    } catch (e) {
      setError(errMessage(e, 'analysis failed'));
      setStage('');
    } finally {
      setBusy(false);
    }
  }, [input, mode, model]);

  const exportPng = useCallback(async () => {
    try {
      const { toPng } = await import('html-to-image');
      const el = viewportRef.current?.querySelector('.react-flow__viewport') as HTMLElement | null;
      if (!el) throw new Error('canvas not ready');
      const url = await toPng(el, { pixelRatio: 2, backgroundColor: '#0f172a' });
      downloadUrl(url, 'flowviz.png');
    } catch (e) {
      setError(errMessage(e, 'png export failed'));
    }
  }, []);

  return (
    <DataPageLayout
      title="FlowViz — Attack Flow Visualizer"
      description="Paste a threat report URL or text; the edge LLM extracts an ATT&CK-mapped attack flow you can inspect and export. Port of davidljohnson/flowviz (MIT)."
      icon={<GitBranch className="h-5 w-5" />}
      backTo="/threatintel"
    >
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
          title="Auto = best available model. Open-weights = gpt-oss → Llama, no API key needed beyond the platform."
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
        <button
          onClick={() => setShowSaved((s) => !s)}
          className="rounded-lg border border-line px-3 py-2 text-sm"
          title="Saved flows"
        >
          <FolderOpen className="h-4 w-4" />
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
      {validation && (
        <p className="mb-2 text-xs font-mono text-muted">
          {validation.nodeCount} nodes · {validation.edgeCount} edges · {modelUsed ?? 'edge-llm'}
          {validation.warnings.length > 0 && ` · ${validation.warnings.length} grounding warnings`}
          {!validation.ok && ` · ERRORS: ${validation.errors.slice(0, 3).join('; ')}`}
        </p>
      )}

      {showSaved && (
        <div className="mb-4 rounded-lg border border-line p-3">
          <p className="mb-2 text-xs font-mono uppercase text-muted">Saved flows (this browser)</p>
          {saved.length === 0 && <p className="text-sm text-muted">None yet.</p>}
          {saved.map((f) => (
            <div key={f.id} className="flex items-center gap-2 py-1 text-sm">
              <button
                className="underline"
                onClick={() => {
                  setNodes(f.nodes);
                  setEdges(f.edges);
                  setShowSaved(false);
                }}
              >
                {f.title}
              </button>
              <span className="text-xs text-muted">
                {f.nodes.length}n/{f.edges.length}e
              </span>
              <button
                className="ml-auto text-rose-500"
                onClick={() => {
                  deleteSavedFlow(f.id);
                  setSaved(listSavedFlows());
                }}
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      <div ref={viewportRef} className="h-[520px] rounded-xl border border-line overflow-hidden">
        <Suspense fallback={<p className="p-4 text-sm text-muted">Loading canvas…</p>}>
          <FlowVizCanvas nodes={nodes} edges={edges} onNodeClick={(_, n) => setSelected(n)} />
        </Suspense>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          onClick={exportPng}
          disabled={nodes.length === 0}
          className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
        >
          <Download className="h-4 w-4" /> PNG
        </button>
        <button
          onClick={() => downloadJson('flowviz-stix.json', exportFlowvizStix(nodes, edges))}
          disabled={nodes.length === 0}
          className="rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
        >
          STIX 2.1
        </button>
        <button
          onClick={() => downloadJson('flow.afb', exportFlowvizAfb(nodes, edges))}
          disabled={nodes.length === 0}
          className="rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
        >
          .afb
        </button>
        <button
          onClick={() => downloadJson('flow.flowviz.json', { nodes, edges, validation, modelUsed })}
          disabled={nodes.length === 0}
          className="rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
        >
          JSON
        </button>
        <button
          onClick={() => {
            if (!nodes.length) return;
            const f = saveFlow({ title: `FlowViz ${new Date().toLocaleString()}`, nodes, edges });
            setSaved(listSavedFlows());
            setStage(`saved: ${f.title}`);
            setTimeout(() => setStage(''), 3000);
          }}
          disabled={nodes.length === 0}
          className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm disabled:opacity-40"
        >
          <Save className="h-4 w-4" /> Save
        </button>
        {selected && (
          <div className="w-full rounded-lg border border-line bg-surface p-3 text-sm">
            <div className="flex items-center gap-2">
              <strong>{String((selected.data as Record<string, unknown>)?.name ?? selected.id)}</strong>
              <span className="text-xs font-mono text-muted">
                {String((selected.data as Record<string, unknown>)?.type ?? selected.type)}
              </span>
              <button className="ml-auto" onClick={() => setSelected(null)}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mt-1 text-muted">{String((selected.data as Record<string, unknown>)?.description ?? '')}</p>
            {String((selected.data as Record<string, unknown>)?.technique_id ?? '') && (
              <p className="mt-1 font-mono text-xs">
                {(selected.data as Record<string, unknown>).technique_id as string} ·{' '}
                {(selected.data as Record<string, unknown>).tactic_name as string}
                {' · '}
                <a
                  className="underline"
                  href={`https://attack.mitre.org/techniques/${String((selected.data as Record<string, unknown>).technique_id).replace('.', '/')}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  ATT&CK
                </a>
              </p>
            )}
            {Boolean((selected.data as Record<string, unknown>)?.command_line) && (
              <pre className="mt-1 overflow-x-auto rounded bg-black/30 p-2 font-mono text-xs">
                {String((selected.data as Record<string, unknown>).command_line)}
              </pre>
            )}
            {Boolean((selected.data as Record<string, unknown>)?.source_excerpt) && (
              <blockquote className="mt-1 border-l-2 border-line pl-2 text-xs italic text-muted">
                “{String((selected.data as Record<string, unknown>).source_excerpt).slice(0, 500)}”
              </blockquote>
            )}
          </div>
        )}
      </div>
      <p className="mt-4 text-xs text-muted">
        Upstream:{' '}
        <a className="underline" href="https://github.com/davidljohnson/flowviz">
          davidljohnson/flowviz
        </a>{' '}
        (MIT) · ATT&CK® © The MITRE Corporation · OSS mode runs open-weights models (Groq gpt-oss → Workers AI Llama)
        instead of a local Ollama setup.
      </p>
    </DataPageLayout>
  );
}

export default function FlowViz(): JSX.Element {
  return <FlowVizInner />;
}
