import { useCallback, useEffect, useState } from 'react';
import { getJson } from './adminApi';
import { errMessage } from '../../lib/log';

interface CalendarSlot {
  slotAt: string;
  candidateId: string;
  status: 'pending' | 'publishing' | 'published' | 'failed' | 'draft';
  publishedSlug?: string;
  type?: string;
  title?: string;
  funnel: 'tofu' | 'mofu' | 'bofu';
}

interface CalendarDay {
  date: string;
  label: string;
  slots: CalendarSlot[];
  published: Array<{ slug: string; title: string; type: string; funnel: string }>;
}

interface FunnelMix {
  tofu: number;
  mofu: number;
  bofu: number;
  total: number;
  divergence: number;
  byType: Record<string, number>;
}

interface CalendarResponse {
  days: CalendarDay[];
  funnelMix: FunnelMix;
  target: { tofu: number; mofu: number; bofu: number };
  pendingCount: number;
  approvedCount: number;
  scheduledCount: number;
  publishedCount: number;
}

const FUNNEL_COLORS: Record<string, string> = {
  tofu: 'bg-brand-500',
  mofu: 'bg-sky-500',
  bofu: 'bg-emerald-500',
};

const FUNNEL_LABELS: Record<string, string> = {
  tofu: 'Awareness',
  mofu: 'Consideration',
  bofu: 'Decision',
};

const STATUS_BADGE: Record<string, string> = {
  pending: 'text-slate-500',
  publishing: 'text-amber-500',
  published: 'text-emerald-500',
  failed: 'text-rose-500',
  draft: 'text-sky-500',
};

function FunnelBar({ mix, target }: { mix: FunnelMix; target: { tofu: number; mofu: number; bofu: number } }) {
  const total = mix.tofu + mix.mofu + mix.bofu;
  if (total === 0) {
    return <p className="text-xs text-muted">No content scheduled in this window.</p>;
  }
  const pct = (n: number) => `${Math.round((n / total) * 100)}%`;
  const targetPct = (n: number) => `${Math.round(n * 100)}%`;
  const divergenceLabel = mix.divergence < 0.15 ? 'on target' : mix.divergence < 0.35 ? 'slightly off' : 'imbalanced';
  const divergenceTone =
    mix.divergence < 0.15 ? 'text-emerald-500' : mix.divergence < 0.35 ? 'text-amber-500' : 'text-rose-500';

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono text-muted">Funnel mix</span>
        <span className={`text-xs font-mono ${divergenceTone}`}>{divergenceLabel}</span>
        <span className="text-xs font-mono text-muted">
          (target 60/30/10 · actual {pct(mix.tofu)}/{pct(mix.mofu)}/{pct(mix.bofu)})
        </span>
      </div>
      <div className="flex h-3 rounded-full overflow-hidden bg-surface-300">
        <div
          className={FUNNEL_COLORS.tofu}
          style={{ width: pct(mix.tofu) }}
          title={`TOFU: ${pct(mix.tofu)} (target ${targetPct(target.tofu)})`}
        />
        <div
          className={FUNNEL_COLORS.mofu}
          style={{ width: pct(mix.mofu) }}
          title={`MOFU: ${pct(mix.mofu)} (target ${targetPct(target.mofu)})`}
        />
        <div
          className={FUNNEL_COLORS.bofu}
          style={{ width: pct(mix.bofu) }}
          title={`BOFU: ${pct(mix.bofu)} (target ${targetPct(target.bofu)})`}
        />
      </div>
      <div className="flex gap-4 text-xs">
        {(['tofu', 'mofu', 'bofu'] as const).map((f) => (
          <span key={f} className="flex items-center gap-1">
            <span className={`inline-block w-2 h-2 rounded-full ${FUNNEL_COLORS[f]}`} />
            <span className="text-muted">
              {FUNNEL_LABELS[f]}: {mix[f]} ({pct(mix[f])})
            </span>
          </span>
        ))}
      </div>
      {Object.keys(mix.byType).length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {Object.entries(mix.byType)
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => (
              <span key={type} className="px-1.5 py-0.5 rounded text-micro font-mono bg-surface-300 text-muted">
                {type} ×{count}
              </span>
            ))}
        </div>
      )}
    </div>
  );
}

export default function CalendarTab() {
  const [data, setData] = useState<CalendarResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await getJson<CalendarResponse>('/calendar');
      setData(r);
    } catch (e) {
      console.error('CalendarTab failed:', errMessage(e));
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) {
    return <p className="text-sm text-muted">Loading calendar…</p>;
  }
  if (error) {
    return (
      <div>
        <p className="text-sm text-rose-500 mb-2">Failed to load calendar: {error}</p>
        <button onClick={() => void load()} className="text-xs text-brand-500 hover:underline">
          Retry
        </button>
      </div>
    );
  }
  if (!data) return null;

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="flex flex-wrap gap-3 text-xs">
        <span className="px-2 py-1 rounded bg-surface-300 text-muted">
          <span className="font-mono">{data.pendingCount}</span> pending
        </span>
        <span className="px-2 py-1 rounded bg-surface-300 text-muted">
          <span className="font-mono">{data.approvedCount}</span> approved
        </span>
        <span className="px-2 py-1 rounded bg-surface-300 text-muted">
          <span className="font-mono">{data.scheduledCount}</span> scheduled
        </span>
        <span className="px-2 py-1 rounded bg-surface-300 text-muted">
          <span className="font-mono">{data.publishedCount}</span> published (14d)
        </span>
      </div>

      {/* Funnel mix */}
      <div className="rounded-lg border border-line-1 p-3">
        <FunnelBar mix={data.funnelMix} target={data.target} />
      </div>

      {/* Calendar grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-2">
        {data.days.map((day) => {
          const hasContent = day.slots.length > 0 || day.published.length > 0;
          return (
            <div
              key={day.date}
              className={`rounded-lg border p-2 min-h-[80px] ${
                hasContent ? 'border-slate-300 dark:border-line-2' : 'border-line-1 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-muted">{day.label}</span>
                <span className="text-micro font-mono text-muted">{day.date.slice(5)}</span>
              </div>
              {day.slots.map((slot, i) => (
                <div key={i} className="mb-1 last:mb-0">
                  <div className="flex items-center gap-1">
                    <span className={`inline-block w-1.5 h-1.5 rounded-full ${FUNNEL_COLORS[slot.funnel]}`} />
                    <span className={`text-micro font-mono ${STATUS_BADGE[slot.status] ?? 'text-slate-400'}`}>
                      {slot.status}
                    </span>
                  </div>
                  {slot.title && (
                    <p className="text-xs text-body truncate" title={slot.title}>
                      {slot.title}
                    </p>
                  )}
                  {slot.type && <span className="text-micro font-mono text-muted">{slot.type}</span>}
                </div>
              ))}
              {day.published
                .filter((p) => !day.slots.some((s) => s.publishedSlug === p.slug))
                .map((pub, i) => (
                  <div key={`pub-${i}`} className="mb-1 last:mb-0">
                    <div className="flex items-center gap-1">
                      <span
                        className={`inline-block w-1.5 h-1.5 rounded-full ${FUNNEL_COLORS[pub.funnel] ?? 'bg-slate-400'}`}
                      />
                      <span className="text-micro font-mono text-emerald-500">published</span>
                    </div>
                    <p className="text-xs text-body truncate" title={pub.title}>
                      {pub.title}
                    </p>
                    <span className="text-micro font-mono text-muted">{pub.type}</span>
                  </div>
                ))}
              {!hasContent && <p className="text-micro text-inverted">—</p>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
