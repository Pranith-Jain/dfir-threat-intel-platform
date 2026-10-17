import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Edit3, CheckCircle2, Archive, FileText } from 'lucide-react';
import { adminAuthHeaders } from '../../lib/admin-token';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface Assessment {
  id: string;
  title: string;
  type: string;
  status: string;
  topic: string;
  body: string;
  sources: string[];
  confidence_score: number;
  confidence_level: string;
  author?: string;
  sector?: string;
  related_pirs?: string[];
  created_at: string;
  updated_at: string;
  published_at?: string;
}

const STATUS_ACTIONS: Record<string, { next: string; label: string; color: string }[]> = {
  draft: [{ next: 'review', label: 'Submit for Review', color: 'bg-amber-600 hover:bg-amber-700' }],
  review: [
    { next: 'published', label: 'Publish', color: 'bg-emerald-600 hover:bg-emerald-700' },
    { next: 'draft', label: 'Send Back to Draft', color: 'bg-slate-500 hover:bg-slate-600' },
  ],
  published: [{ next: 'archived', label: 'Archive', color: 'bg-slate-500 hover:bg-slate-600' }],
  archived: [],
};

export default function AssessmentDetail(): JSX.Element {
  const { id } = useParams<{ id: string }>();
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [transitioning, setTransitioning] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    fetch(`/api/v1/threat-intel/assessments/${id}`, { headers: adminAuthHeaders() })
      .then((r) => {
        if (!r.ok) throw new Error('Not found');
        return r.json() as Promise<Assessment>;
      })
      .then(setAssessment)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  async function transitionStatus(nextStatus: string) {
    if (!assessment) return;
    setTransitioning(true);
    setTransitionError(null);
    try {
      const res = await fetch(`/api/v1/threat-intel/assessments/${assessment.id}`, {
        method: 'PUT',
        headers: { ...adminAuthHeaders(), 'content-type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (!res.ok) throw new Error('Transition failed');
      const data = (await res.json()) as { assessment: Assessment };
      setAssessment(data.assessment);
    } catch (e) {
      console.error('transitionStatus failed:', errMessage(e));
      setTransitionError(errMessage(e, 'Failed to update status'));
    } finally {
      setTransitioning(false);
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel/assessments"
      backLabel="back to assessments"
      icon={<FileText size={28} />}
      title={assessment?.title ?? 'Assessment'}
      maxWidthClass="max-w-4xl"
      loading={loading}
      error={error || (!loading && !assessment ? 'Assessment not found' : null)}
      headerExtra={
        assessment ? (
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`text-micro font-mono px-1.5 py-0.5 rounded border ${
                    assessment.status === 'published'
                      ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 border-emerald-300'
                      : assessment.status === 'review'
                        ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 border-amber-300'
                        : 'bg-slate-100 dark:bg-surface-300 text-slate-600 border-slate-300'
                  }`}
                >
                  {assessment.status}
                </span>
                <span className="text-micro font-mono text-muted">{assessment.type}</span>
              </div>
              <p className="text-sm text-muted">Topic: {assessment.topic}</p>
            </div>
            <div className="text-right shrink-0">
              <div
                className={`text-2xl font-bold font-mono ${assessment.confidence_score >= 70 ? 'text-emerald-500' : assessment.confidence_score >= 40 ? 'text-amber-500' : 'text-rose-500'}`}
              >
                {assessment.confidence_score}%
              </div>
              <div className="text-micro font-mono text-muted">{assessment.confidence_level}</div>
            </div>
          </div>
        ) : undefined
      }
    >
      {assessment && (
        <>
          {/* Meta row */}
          <div className="flex flex-wrap gap-3 mb-6 text-mini font-mono text-muted">
            {assessment.author && <span>Author: {assessment.author}</span>}
            {assessment.sector && <span>Sector: {assessment.sector}</span>}
            <span>Created: {new Date(assessment.created_at).toLocaleString()}</span>
            <span>Updated: {new Date(assessment.updated_at).toLocaleString()}</span>
            {assessment.published_at && <span>Published: {new Date(assessment.published_at).toLocaleString()}</span>}
          </div>

          {/* Sources used */}
          {assessment.sources.length > 0 && (
            <div className="mb-6">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Sources</div>
              <div className="flex flex-wrap gap-1">
                {assessment.sources.map((s, i) => (
                  <span key={i} className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Body */}
          <div className="surface-card p-6 mb-6 text-sm leading-relaxed whitespace-pre-wrap">{assessment.body}</div>

          {/* Status transition actions */}
          {(STATUS_ACTIONS[assessment.status]?.length ?? 0) > 0 && (
            <div className="flex gap-2">
              {STATUS_ACTIONS[assessment.status]!.map((action) => (
                <button
                  key={action.next}
                  type="button"
                  onClick={() => transitionStatus(action.next)}
                  disabled={transitioning}
                  className={`inline-flex items-center gap-1.5 text-xs font-mono px-4 py-2 rounded-xl text-white ${action.color} disabled:opacity-50 transition-colors`}
                >
                  {action.next === 'published' ? (
                    <CheckCircle2 size={12} />
                  ) : action.next === 'archived' ? (
                    <Archive size={12} />
                  ) : (
                    <Edit3 size={12} />
                  )}
                  {action.label}
                </button>
              ))}
            </div>
          )}

          {transitionError && (
            <p
              role="alert"
              className="mt-3 rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/30 px-3 py-2 text-xs text-rose-700 dark:text-rose-300"
            >
              {transitionError}
            </p>
          )}
        </>
      )}
    </DataPageLayout>
  );
}
