import { useState, useMemo, useEffect } from 'react';
import {
  FileText,
  FileType2,
  Trash2,
  Plus,
  Star,
  Shield,
  AlertTriangle,
  Eye,
  EyeOff,
  RotateCcw,
  Check,
} from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import { errMessage } from '../../lib/log';
import {
  emptyReport,
  TLP_OPTIONS,
  IOC_TYPES,
  type ReportDoc,
  type Tlp,
  type Finding,
  type IocEntry,
  type Section,
  type Source,
} from '../../lib/dfir/report-composer/schema';

/**
 * /dfir/report-composer - client-side investigation report builder.
 *
 * Edit a multi-section report (cover, summary, findings, IOCs, sources)
 * in the browser; export to PDF (jsPDF) or DOCX (in-house OOXML build
 * via JSZip). No server cost, no API keys, no rate limits. State is
 * persisted to localStorage so a draft survives a refresh.
 *
 * The export functions are imported lazily so the jspdf + jspdf-autotable
 * (~600KB) and JSZip stay out of the page chunk.
 */

const STORAGE_KEY = 'dfir.report-composer.draft:v1';

function loadDraft(): ReportDoc | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as ReportDoc;
  } catch (_catchErr) {
    console.error('loadDraft failed:', errMessage(_catchErr));
    return null;
  }
}

function saveDraft(doc: ReportDoc): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(doc));
  } catch (_catchErr) {
    console.error('saveDraft failed:', errMessage(_catchErr));
    /* quota */
  }
}

const TLP_COLORS: Record<Tlp, string> = {
  CLEAR: 'bg-slate-100 dark:bg-slate-500/10 text-body border-slate-300 dark:border-slate-500/30',
  GREEN:
    'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-500/30',
  AMBER:
    'bg-amber-100 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-500/30',
  RED: 'bg-rose-100 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-500/30',
};

const CONFIDENCE_COLORS: Record<Finding['confidence'], string> = {
  High: 'text-rose-700 dark:text-rose-300',
  Medium: 'text-amber-700 dark:text-amber-300',
  Low: 'text-muted',
};

const IOC_PREVIEW_COLUMNS: DataTableColumn<IocEntry>[] = [
  {
    key: 'type',
    header: 'Type',
    render: (i) => i.type,
    sortValue: (i) => i.type,
    className: 'font-mono',
  },
  {
    key: 'value',
    header: 'Value',
    render: (i) => i.value,
    sortValue: (i) => i.value,
    className: 'font-mono break-all',
  },
  {
    key: 'context',
    header: 'Context',
    render: (i) => i.context,
    sortValue: (i) => i.context,
  },
];

export default function ReportComposer(): JSX.Element {
  const [doc, setDoc] = useState<ReportDoc>(() => loadDraft() ?? emptyReport());
  const [exporting, setExporting] = useState<'pdf' | 'docx' | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  // Auto-save draft (debounced via setTimeout). On a slow device the
  // cost is negligible (~few KB) but we still space the writes so a
  // fast typist doesn't hammer localStorage.
  useEffect(() => {
    const t = setTimeout(() => {
      saveDraft(doc);
      setSavedAt(new Date().toLocaleTimeString());
    }, 600);
    return () => clearTimeout(t);
  }, [doc]);

  function update<K extends keyof ReportDoc>(key: K, value: ReportDoc[K]): void {
    setDoc((d) => ({ ...d, [key]: value }));
  }

  function updateMeta<K extends keyof ReportDoc['meta']>(key: K, value: ReportDoc['meta'][K]): void {
    setDoc((d) => ({ ...d, meta: { ...d.meta, [key]: value } }));
  }

  // ── Findings CRUD ────────────────────────────────────────────
  const addFinding = (): void => update('findings', [...doc.findings, { text: '', confidence: 'Medium', refs: [] }]);
  const updateFinding = (i: number, patch: Partial<Finding>): void =>
    update(
      'findings',
      doc.findings.map((f, idx) => (idx === i ? { ...f, ...patch } : f))
    );
  const removeFinding = (i: number): void =>
    update(
      'findings',
      doc.findings.filter((_, idx) => idx !== i)
    );

  // ── Sections CRUD ────────────────────────────────────────────
  const addSection = (): void =>
    update('sections', [...doc.sections, { id: crypto.randomUUID(), heading: 'New section', body: '', refs: [] }]);
  const updateSection = (i: number, patch: Partial<Section>): void =>
    update(
      'sections',
      doc.sections.map((s, idx) => (idx === i ? { ...s, ...patch } : s))
    );
  const removeSection = (i: number): void =>
    update(
      'sections',
      doc.sections.filter((_, idx) => idx !== i)
    );
  const moveSection = (i: number, dir: -1 | 1): void => {
    const j = i + dir;
    if (j < 0 || j >= doc.sections.length) return;
    const next = [...doc.sections];
    [next[i]!, next[j]!] = [next[j]!, next[i]!];
    update('sections', next);
  };

  // ── IOCs CRUD ────────────────────────────────────────────────
  const addIoc = (): void => update('iocs', [...doc.iocs, { type: 'ip', value: '', context: '', refs: [] }]);
  const updateIoc = (i: number, patch: Partial<IocEntry>): void =>
    update(
      'iocs',
      doc.iocs.map((x, idx) => (idx === i ? { ...x, ...patch } : x))
    );
  const removeIoc = (i: number): void =>
    update(
      'iocs',
      doc.iocs.filter((_, idx) => idx !== i)
    );

  // ── Sources CRUD ─────────────────────────────────────────────
  const addSource = (): void =>
    update('sources', [
      ...doc.sources,
      { ref: doc.sources.length + 1, name: '', url: '', retrieved: new Date().toISOString().slice(0, 10) },
    ]);
  const updateSource = (i: number, patch: Partial<Source>): void =>
    update(
      'sources',
      doc.sources.map((s, idx) => (idx === i ? { ...s, ...patch } : s))
    );
  const removeSource = (i: number): void =>
    update(
      'sources',
      doc.sources.filter((_, idx) => idx !== i)
    );

  // ── Export ───────────────────────────────────────────────────
  async function handleExport(kind: 'pdf' | 'docx'): Promise<void> {
    setExporting(kind);
    setExportError(null);
    try {
      if (kind === 'pdf') {
        const { exportReportPdf, pdfFilename, downloadBlob } =
          await import('../../lib/dfir/report-composer/export-pdf');
        const blob = await exportReportPdf(doc);
        downloadBlob(blob, pdfFilename(doc));
      } else {
        const [{ exportReportDocx, docxFilename }, { downloadBlob }] = await Promise.all([
          import('../../lib/dfir/report-composer/export-docx'),
          import('../../lib/dfir/report-composer/export-pdf'),
        ]);
        const blob = await exportReportDocx(doc);
        downloadBlob(blob, docxFilename(doc));
      }
    } catch (e) {
      console.error('handleExport failed:', errMessage(e));
      setExportError((e as Error).message);
    } finally {
      setExporting(null);
    }
  }

  // ── Stats ────────────────────────────────────────────────────
  const wordCount = useMemo(() => {
    const text = [
      doc.meta.title,
      doc.meta.subject,
      doc.executiveSummary,
      ...doc.sections.flatMap((s) => [s.heading, s.body]),
      ...doc.findings.map((f) => f.text),
    ].join(' ');
    return text.trim().split(/\s+/).filter(Boolean).length;
  }, [doc]);

  function resetAll(): void {
    if (!confirm('Discard current report and start a fresh empty one?')) return;
    setDoc(emptyReport());
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono transition-colors"
      >
        back to DFIR
      </BackLink>

      <div className="flex flex-wrap items-start justify-between gap-4 mb-2">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <span className="text-brand-600 dark:text-brand-400">
            <FileText size={32} />
          </span>
          Report Composer
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          {savedAt && (
            <span className="text-xs text-muted flex items-center gap-1">
              <Check size={12} /> saved {savedAt}
            </span>
          )}
          <button
            type="button"
            onClick={() => setShowPreview((s) => !s)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 text-xs font-mono"
          >
            {showPreview ? <EyeOff size={14} /> : <Eye size={14} />}
            {showPreview ? 'Hide' : 'Preview'}
          </button>
          <button
            type="button"
            onClick={() => handleExport('pdf')}
            disabled={exporting !== null}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-on-fill text-xs font-medium disabled:opacity-50"
          >
            <FileText size={14} /> {exporting === 'pdf' ? 'Building…' : 'PDF'}
          </button>
          <button
            type="button"
            onClick={() => handleExport('docx')}
            disabled={exporting !== null}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-on-fill text-xs font-medium disabled:opacity-50"
          >
            <FileType2 size={14} /> {exporting === 'docx' ? 'Building…' : 'DOCX'}
          </button>
          <button
            type="button"
            onClick={resetAll}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 text-xs font-mono transition-colors"
            title="Discard and start fresh"
          >
            <RotateCcw size={14} />
          </button>
        </div>
      </div>
      <p className="text-muted max-w-2xl leading-relaxed mb-2">
        Build an investigation report in the browser, then export to PDF or DOCX. No server, no API keys - your draft
        stays in localStorage until you export.
      </p>
      <p className="text-xs text-muted mb-8 font-mono">
        {wordCount} words · {doc.findings.length} finding(s) · {doc.sections.length} section(s) · {doc.iocs.length}{' '}
        IOC(s) · {doc.sources.length} source(s)
      </p>

      {exportError && (
        <div className="rounded-xl border border-rose-300 dark:border-rose-500/30 bg-rose-100 dark:bg-rose-500/10 p-3 mb-6 text-sm text-rose-700 dark:text-rose-300 flex items-center gap-2">
          <AlertTriangle size={14} /> Export failed: {exportError}
        </div>
      )}

      {showPreview && (
        <div className="mb-10 rounded-xl border border-line-2 bg-surface-100 p-6 shadow-e1">
          <PreviewPanel doc={doc} />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Cover / Meta ──────────────────────────────── */}
        <section className="lg:col-span-2 rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <h2 className="text-sm font-semibold uppercase text-muted mb-3 flex items-center gap-2">
            <Shield size={14} /> Cover & TLP
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Field label="Title">
              <input
                type="text"
                value={doc.meta.title}
                onChange={(e) => updateMeta('title', e.target.value)}
                className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm"
              />
            </Field>
            <Field label="Subject">
              <input
                type="text"
                value={doc.meta.subject}
                onChange={(e) => updateMeta('subject', e.target.value)}
                placeholder="e.g. APT29 phishing campaign - 2026-06"
                className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm"
              />
            </Field>
            <Field label="Case ID">
              <input
                type="text"
                value={doc.meta.caseId}
                onChange={(e) => updateMeta('caseId', e.target.value)}
                placeholder="IR-2026-014"
                className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm font-mono"
              />
            </Field>
            <Field label="Author">
              <input
                type="text"
                value={doc.meta.author}
                onChange={(e) => updateMeta('author', e.target.value)}
                placeholder="Your name / handle"
                className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm"
              />
            </Field>
            <Field label="Classification">
              <input
                type="text"
                value={doc.meta.classification}
                onChange={(e) => updateMeta('classification', e.target.value)}
                className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm"
              />
            </Field>
            <Field label="TLP">
              <div className="grid grid-cols-4 gap-1.5">
                {TLP_OPTIONS.map((o) => {
                  const on = doc.meta.tlp === o.value;
                  return (
                    <button
                      key={o.value}
                      type="button"
                      onClick={() => updateMeta('tlp', o.value as Tlp)}
                      className={`px-2 py-1.5 rounded text-xs font-mono border transition-colors ${
                        on
                          ? TLP_COLORS[o.value]
                          : 'border-slate-300 dark:border-line-1 text-slate-500 hover:bg-slate-100 dark:hover:bg-surface-300'
                      }`}
                      title={o.description}
                    >
                      {o.label}
                    </button>
                  );
                })}
              </div>
            </Field>
          </div>
        </section>

        {/* ── Executive summary ──────────────────────────── */}
        <section className="lg:col-span-2 rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <h2 className="text-sm font-semibold uppercase text-muted mb-3">Executive Summary</h2>
          <textarea
            value={doc.executiveSummary}
            onChange={(e) => update('executiveSummary', e.target.value)}
            rows={4}
            placeholder="A 3-5 sentence TL;DR for executives. Supports markdown: # ## **bold** *em* `code` - bullets"
            className="w-full px-3 py-2 rounded border border-line-2 bg-surface-100 text-sm font-mono"
          />
        </section>

        {/* ── Findings ───────────────────────────────────── */}
        <section className="rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase text-muted flex items-center gap-2">
              <Star size={14} /> Key Findings ({doc.findings.length})
            </h2>
            <button
              type="button"
              onClick={addFinding}
              className="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono rounded bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
            >
              <Plus size={12} /> Add
            </button>
          </div>
          <div className="space-y-2">
            {doc.findings.map((f, i) => (
              <div key={i} className="rounded border border-line-1 p-2.5 bg-surface-200/50">
                <div className="flex items-start gap-2">
                  <span className="text-xs font-mono text-muted mt-2 w-5">{i + 1}.</span>
                  <textarea
                    value={f.text}
                    onChange={(e) => updateFinding(i, { text: e.target.value })}
                    rows={2}
                    placeholder="Finding statement…"
                    className="flex-1 px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-sm"
                  />
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <select
                    value={f.confidence}
                    onChange={(e) => updateFinding(i, { confidence: e.target.value as Finding['confidence'] })}
                    className="px-2 py-1 text-xs rounded border border-line-2 bg-surface-100 font-mono"
                  >
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                  <span className={`text-micro font-mono ${CONFIDENCE_COLORS[f.confidence]}`}>
                    {f.confidence} confidence
                  </span>
                  <button
                    type="button"
                    onClick={() => removeFinding(i)}
                    className="ml-auto p-1 text-muted hover:text-rose-400"
                    aria-label="Remove finding"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
            {doc.findings.length === 0 && (
              <p className="text-xs text-muted italic text-center py-4">No findings yet.</p>
            )}
          </div>
        </section>

        {/* ── IOCs ───────────────────────────────────────── */}
        <section className="rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase text-muted">IOCs ({doc.iocs.length})</h2>
            <button
              type="button"
              onClick={addIoc}
              className="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono rounded bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
            >
              <Plus size={12} /> Add
            </button>
          </div>
          <div className="space-y-2">
            {doc.iocs.map((ioc, i) => (
              <div key={i} className="rounded border border-line-1 p-2.5 bg-surface-200/50">
                <div className="grid grid-cols-[100px_1fr] gap-1.5">
                  <select
                    value={ioc.type}
                    onChange={(e) => updateIoc(i, { type: e.target.value as IocEntry['type'] })}
                    className="px-1.5 py-1.5 text-xs rounded border border-line-2 bg-surface-100 font-mono"
                  >
                    {IOC_TYPES.map((t) => (
                      <option key={t.value} value={t.value}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={ioc.value}
                    onChange={(e) => updateIoc(i, { value: e.target.value })}
                    placeholder="Indicator value"
                    className="px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs font-mono"
                  />
                </div>
                <div className="flex items-start gap-1.5 mt-1.5">
                  <input
                    type="text"
                    value={ioc.context}
                    onChange={(e) => updateIoc(i, { context: e.target.value })}
                    placeholder="Context (where it was found, what it does)"
                    className="flex-1 px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => removeIoc(i)}
                    className="p-1.5 text-muted hover:text-rose-400"
                    aria-label="Remove IOC"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
            {doc.iocs.length === 0 && <p className="text-xs text-muted italic text-center py-4">No IOCs yet.</p>}
          </div>
        </section>

        {/* ── Sections ──────────────────────────────────── */}
        <section className="lg:col-span-2 rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase text-muted">Sections ({doc.sections.length})</h2>
            <button
              type="button"
              onClick={addSection}
              className="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono rounded bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
            >
              <Plus size={12} /> Add section
            </button>
          </div>
          <div className="space-y-3">
            {doc.sections.map((s, i) => (
              <div key={s.id} className="rounded border border-line-1 p-3 bg-surface-200/50">
                <div className="flex items-center gap-2 mb-2">
                  <input
                    type="text"
                    value={s.heading}
                    onChange={(e) => updateSection(i, { heading: e.target.value })}
                    placeholder="Section heading"
                    className="flex-1 px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-sm font-semibold"
                  />
                  <button
                    type="button"
                    onClick={() => moveSection(i, -1)}
                    disabled={i === 0}
                    className="p-1 text-muted hover:text-body dark:hover:text-inverted disabled:opacity-30"
                    aria-label="Move up"
                    title="Move up"
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    onClick={() => moveSection(i, 1)}
                    disabled={i === doc.sections.length - 1}
                    className="p-1 text-muted hover:text-body dark:hover:text-inverted disabled:opacity-30"
                    aria-label="Move down"
                    title="Move down"
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    onClick={() => removeSection(i)}
                    className="p-1 text-muted hover:text-rose-400"
                    aria-label="Remove section"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <textarea
                  value={s.body}
                  onChange={(e) => updateSection(i, { body: e.target.value })}
                  rows={5}
                  placeholder="Section body. Markdown: # ## **bold** *em* `code` - bullets"
                  className="w-full px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs font-mono"
                />
              </div>
            ))}
            {doc.sections.length === 0 && (
              <p className="text-xs text-muted italic text-center py-4">No sections yet.</p>
            )}
          </div>
        </section>

        {/* ── Sources ────────────────────────────────────── */}
        <section className="lg:col-span-2 rounded-xl border border-line-1 p-4 bg-surface-100/50 dark:bg-surface-200/30">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase text-muted">Sources ({doc.sources.length})</h2>
            <button
              type="button"
              onClick={addSource}
              className="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono rounded bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
            >
              <Plus size={12} /> Add
            </button>
          </div>
          <div className="space-y-2">
            {doc.sources.map((s, i) => (
              <div key={i} className="rounded border border-line-1 p-2.5 bg-surface-200/50">
                <div className="grid grid-cols-[40px_1fr_1fr_120px_auto] gap-1.5">
                  <span className="text-xs font-mono text-muted text-center py-1.5">[{i + 1}]</span>
                  <input
                    type="text"
                    value={s.name}
                    onChange={(e) => updateSource(i, { name: e.target.value, ref: i + 1 })}
                    placeholder="Source name (e.g. Shodan, VirusTotal)"
                    className="px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs"
                  />
                  <input
                    type="url"
                    value={s.url}
                    onChange={(e) => updateSource(i, { url: e.target.value })}
                    placeholder="https://…"
                    className="px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs font-mono"
                  />
                  <input
                    type="date"
                    value={s.retrieved}
                    onChange={(e) => updateSource(i, { retrieved: e.target.value })}
                    className="px-2 py-1.5 rounded border border-line-2 bg-surface-100 text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => removeSource(i)}
                    className="p-1.5 text-muted hover:text-rose-400"
                    aria-label="Remove source"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
            {doc.sources.length === 0 && <p className="text-xs text-muted italic text-center py-4">No sources yet.</p>}
          </div>
        </section>
      </div>
    </div>
  );
}

/* ── Helpers ──────────────────────────────────────────────────── */

interface FieldProps {
  label: string;
  children: React.ReactNode;
}
function Field({ label, children }: FieldProps): JSX.Element {
  return (
    <label className="block">
      <span className="block text-xs font-mono text-muted mb-1 uppercase tracking-wide">{label}</span>
      {children}
    </label>
  );
}

/* ── Preview panel (lightweight render, not a full export) ───── */

function PreviewPanel({ doc }: { doc: ReportDoc }): JSX.Element {
  return (
    <article className="prose prose-slate dark:prose-invert max-w-none text-sm">
      <div className={`inline-block px-2 py-0.5 rounded text-xs font-mono mb-3 ${TLP_COLORS[doc.meta.tlp]}`}>
        TLP:{doc.meta.tlp}
      </div>
      <h1 className="text-2xl font-bold mb-1">{doc.meta.title || 'Untitled report'}</h1>
      {doc.meta.subject && <p className="text-muted text-sm mb-3">Subject: {doc.meta.subject}</p>}
      {doc.executiveSummary && (
        <>
          <h2 className="text-lg font-semibold mt-4 mb-2">Executive Summary</h2>
          <p className="whitespace-pre-wrap">{doc.executiveSummary}</p>
        </>
      )}
      {doc.findings.length > 0 && (
        <>
          <h2 className="text-lg font-semibold mt-4 mb-2">Key Findings</h2>
          <ol className="list-decimal list-inside space-y-1">
            {doc.findings.map((f, i) => (
              <li key={i}>
                {f.text}{' '}
                <span className={`ml-1 text-xs font-mono ${CONFIDENCE_COLORS[f.confidence]}`}>[{f.confidence}]</span>
              </li>
            ))}
          </ol>
        </>
      )}
      {doc.sections.map((s) => (
        <section key={s.id} className="mt-4">
          <h2 className="text-lg font-semibold mb-2">{s.heading}</h2>
          <p className="whitespace-pre-wrap">{s.body}</p>
        </section>
      ))}
      {doc.iocs.length > 0 && (
        <>
          <h2 className="text-lg font-semibold mt-4 mb-2">IOCs</h2>
          <div className="overflow-x-auto">
            <DataTable rows={doc.iocs} rowKey={(i, idx) => `${i.type}-${idx}`} columns={IOC_PREVIEW_COLUMNS} />
          </div>
        </>
      )}
    </article>
  );
}
