/**
 * Procedure extraction — edge-native queue + review gates UI.
 *
 * Upstream: netandneedle/procedure-extraction-pipeline (Apache-2.0) runs a
 * Kanban queue with four review gates (entities → chunks → procedures →
 * bundle) over a 16-stage LangGraph pipeline. This page implements the same
 * analyst workflow against the edge API (api/src/routes/procedures.ts):
 * submit report → work the gates in order → download the STIX bundle with
 * x-procedure objects + Attack-Flow sequencing.
 *
 * Writes require an admin session (HttpOnly cookie via /admin); reads are
 * key-gated like every other /api/v1/* route.
 *
 * Route: /dfir/procedure-extract
 */
import { useEffect, useState } from 'react';
import { FlaskConical, Loader2, AlertTriangle, X, Download } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface JobRow {
  id: string;
  title: string;
  source_type: string;
  status: string;
  created_at: string;
  updated_at: string;
}

interface JobDetail {
  id: string;
  title: string;
  status: string;
  gates: string;
  extraction: string;
  corrections: string;
  bundle_json: string;
  created_at: string;
  updated_at: string;
}

const GATES = ['entities', 'chunks', 'procedures', 'bundle'] as const;

export default function ProcedureExtract(): JSX.Element {
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [active, setActive] = useState<JobDetail | null>(null);
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState('');

  const refresh = async () => {
    try {
      const r = await fetch('/api/v1/procedures/jobs?limit=30', { signal: AbortSignal.timeout(15_000) });
      if (!r.ok) return;
      const d = (await r.json()) as { jobs: JobRow[] };
      setJobs(d.jobs ?? []);
    } catch {
      /* offline — non-fatal */
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const open = async (id: string) => {
    try {
      const r = await fetch(`/api/v1/procedures/jobs/${id}`, { signal: AbortSignal.timeout(15_000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = (await r.json()) as { job: JobDetail };
      setActive(d.job);
    } catch (e) {
      setError(errMessage(e, 'load failed'));
    }
  };

  const submit = async () => {
    if (!title.trim() || text.trim().length < 600) {
      setError('Title + ≥600 chars of report text required.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/procedures/jobs', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ title: title.trim(), sourceText: text }),
        signal: AbortSignal.timeout(120_000),
      });
      if (r.status === 401 || r.status === 403) throw new Error('Admin session required — log in at /admin first.');
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const d = (await r.json()) as { job: JobDetail };
      setActive(d.job);
      setNote('Extracted — work gate 0 (entities) first.');
      void refresh();
    } catch (e) {
      setError(errMessage(e, 'submit failed'));
    } finally {
      setBusy(false);
    }
  };

  const review = async (gate: string, decision: 'approve' | 'reject') => {
    if (!active) return;
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`/api/v1/procedures/jobs/${active.id}/review`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ gate, decision }),
        signal: AbortSignal.timeout(60_000),
      });
      if (r.status === 401 || r.status === 403) throw new Error('Admin session required — log in at /admin first.');
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const d = (await r.json()) as { job: JobDetail };
      setActive(d.job);
      void refresh();
    } catch (e) {
      setError(errMessage(e, 'review failed'));
    } finally {
      setBusy(false);
    }
  };

  let extraction: {
    entities?: Array<{ kind: string; value: string }>;
    chunks?: Array<{ id: string; text: string; excerpt: string }>;
    techniques?: Array<{ chunkId: string; techniqueId: string; confidence: string; quote: string }>;
    drafts?: Array<{
      chunkId: string;
      name: string;
      description: string;
      techniqueIds: string[];
      commandLines: string[];
      confidence: number;
    }>;
    notes?: string[];
  } = {};
  try {
    extraction = active?.extraction ? (JSON.parse(active.extraction) as typeof extraction) : {};
  } catch {
    extraction = {};
  }

  return (
    <DataPageLayout
      title="Procedure Extraction"
      description="Submit a threat report, review entities → chunks → procedures → bundle, export STIX x-procedures. Edge port of netandneedle/procedure-extraction-pipeline (Apache-2.0)."
      icon={<FlaskConical className="h-5 w-5" />}
      backTo="/dfir"
    >
      {error && (
        <p className="mb-2 flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/5 px-3 py-2 text-sm text-rose-600">
          <AlertTriangle className="h-4 w-4" /> {error}
          <button onClick={() => setError(null)} className="ml-auto">
            <X className="h-4 w-4" />
          </button>
        </p>
      )}
      {note && <p className="mb-2 text-xs font-mono text-muted">{note}</p>}

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <div>
          <div className="rounded-xl border border-line p-3">
            <p className="mb-2 text-xs font-mono uppercase text-muted">Submit report</p>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Report title (e.g. CISA AA23-061A — Royal ransomware)"
              className="mb-2 w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm"
            />
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste report text (≥600 chars)…"
              rows={6}
              className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm"
            />
            <button
              onClick={submit}
              disabled={busy}
              className="mt-2 rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-on-fill disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Extract procedures'}
            </button>
          </div>

          {active && (
            <div className="mt-4 rounded-xl border border-line p-3">
              <div className="flex items-center gap-2">
                <strong className="text-sm">{active.title}</strong>
                <span className="rounded border border-line px-2 py-0.5 font-mono text-xs text-muted">
                  {active.status}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {GATES.map((g) => (
                  <span key={g} className="flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-xs">
                    {g}
                    <button
                      onClick={() => void review(g, 'approve')}
                      disabled={busy}
                      className="text-emerald-600 underline"
                    >
                      approve
                    </button>
                    <button
                      onClick={() => void review(g, 'reject')}
                      disabled={busy}
                      className="text-rose-500 underline"
                    >
                      reject
                    </button>
                  </span>
                ))}
                {active.bundle_json && (
                  <a
                    className="flex items-center gap-1 rounded-lg bg-brand-500/15 px-2 py-1 text-xs text-brand-600"
                    href={`/api/v1/procedures/bundles/${active.id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <Download className="h-3 w-3" /> STIX bundle
                  </a>
                )}
              </div>
              <div className="mt-3 grid gap-3 text-sm md:grid-cols-2">
                <div>
                  <p className="font-mono text-xs uppercase text-muted">
                    Entities ({extraction.entities?.length ?? 0})
                  </p>
                  <ul className="mt-1 max-h-48 overflow-auto text-xs">
                    {(extraction.entities ?? []).slice(0, 50).map((e, i) => (
                      <li key={i} className="font-mono">
                        {e.kind}: {e.value}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <p className="font-mono text-xs uppercase text-muted">
                    Techniques ({extraction.techniques?.length ?? 0})
                  </p>
                  <ul className="mt-1 max-h-48 overflow-auto text-xs">
                    {(extraction.techniques ?? []).slice(0, 50).map((t, i) => (
                      <li key={i} className="font-mono">
                        {t.techniqueId} [{t.confidence}] ← {t.chunkId}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="mt-3">
                <p className="font-mono text-xs uppercase text-muted">
                  Procedure drafts ({extraction.drafts?.length ?? 0})
                </p>
                {(extraction.drafts ?? []).slice(0, 20).map((d, i) => (
                  <div key={i} className="mt-2 rounded-lg border border-line p-2">
                    <p className="text-sm font-semibold">{d.name}</p>
                    <p className="text-xs text-muted">{d.description.slice(0, 400)}</p>
                    <p className="mt-1 font-mono text-xs text-muted">
                      {(d.techniqueIds ?? []).join(' · ')} · conf {d.confidence}
                      {(d.commandLines ?? []).length > 0 && ` · ${(d.commandLines ?? []).length} cmds`}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-line p-3">
          <p className="mb-2 text-xs font-mono uppercase text-muted">Queue ({jobs.length})</p>
          {jobs.map((j) => (
            <button
              key={j.id}
              onClick={() => void open(j.id)}
              className="mb-1 block w-full rounded-lg border border-line px-2 py-1.5 text-left text-sm hover:bg-surface"
            >
              <span className="block truncate">{j.title}</span>
              <span className="font-mono text-xs text-muted">{j.status}</span>
            </button>
          ))}
          {jobs.length === 0 && <p className="text-sm text-muted">Empty — submit the first report.</p>}
        </div>
      </div>
      <p className="mt-4 text-xs text-muted">
        Upstream:{' '}
        <a className="underline" href="https://github.com/netandneedle/procedure-extraction-pipeline">
          netandneedle/procedure-extraction-pipeline
        </a>{' '}
        (Apache-2.0) · Full Docling/Neo4j/SecureBERT pipeline stays self-hosted; this edge port covers extraction +
        gates + x-procedure bundles.
      </p>
    </DataPageLayout>
  );
}
