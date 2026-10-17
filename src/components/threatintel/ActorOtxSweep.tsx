import { useState, useRef, useCallback } from 'react';
import { Radio, Loader2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * Bulk-OTX rotation sweep panel.
 *
 * Hits POST /api/v1/actor-enrich/otx-stream which streams SSE events
 * (started / actor / error / done). Streams the actor list it has
 * locally - server applies fair-queue rotation (never-attempted first,
 * then fewest IOCs, then oldest attempt) and processes up to `limit`
 * actors per click.
 */

interface ActorRef {
  slug: string;
  name: string;
  aliases?: string[];
}

interface OtxPulse {
  id: string;
  name: string;
  ioc_count?: number;
  created?: string;
}

interface ActorResult {
  slug: string;
  name: string;
  pulses: OtxPulse[];
  ioc_count: number;
  status: 'ok' | 'error';
  message?: string;
}

interface Props {
  actors: ActorRef[];
  /** Defaults to 10. Server caps at 50. */
  limit?: number;
}

export default function ActorOtxSweep({ actors, limit = 10 }: Props) {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<ActorResult[]>([]);
  const [done, setDone] = useState<{ processed: number; skipped: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setRunning(false);
  }, []);

  const start = useCallback(async () => {
    if (running) return;
    setRunning(true);
    setResults([]);
    setDone(null);
    setError(null);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const res = await fetch('/api/v1/actor-enrich/otx-stream', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ actors, limit }),
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(60_000)]),
      });
      if (!res.ok || !res.body) {
        const text = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const j = JSON.parse(text) as { error?: string };
          if (j.error) msg = j.error;
        } catch {
          /* keep msg */
        }
        throw new Error(msg);
      }

      // Parse the SSE byte-stream manually - EventSource is GET-only, so
      // a POST+stream has to walk the bytes itself. Standard SSE is:
      //   event: <name>\ndata: <json>\n\n
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done: streamDone, value } = await reader.read();
        if (streamDone) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const lines = chunk.split('\n');
          let eventName = 'message';
          let dataStr = '';
          for (const ln of lines) {
            if (ln.startsWith('event:')) eventName = ln.slice(6).trim();
            else if (ln.startsWith('data:')) dataStr += ln.slice(5).trim();
          }
          if (!dataStr) continue;
          let payload: Record<string, unknown> = {};
          try {
            payload = JSON.parse(dataStr) as Record<string, unknown>;
          } catch {
            continue;
          }
          if (eventName === 'actor') {
            setResults((prev) => [
              ...prev,
              {
                slug: String(payload.slug ?? ''),
                name: String(payload.name ?? ''),
                pulses: Array.isArray(payload.pulses) ? (payload.pulses as OtxPulse[]) : [],
                ioc_count: typeof payload.ioc_count === 'number' ? payload.ioc_count : 0,
                status: 'ok',
              },
            ]);
          } else if (eventName === 'error') {
            setResults((prev) => [
              ...prev,
              {
                slug: String(payload.slug ?? ''),
                name: '',
                pulses: [],
                ioc_count: 0,
                status: 'error',
                message: String(payload.message ?? 'failed'),
              },
            ]);
          } else if (eventName === 'done') {
            setDone({
              processed: typeof payload.processed === 'number' ? payload.processed : 0,
              skipped: typeof payload.skipped === 'number' ? payload.skipped : 0,
            });
          }
        }
      }
    } catch (err) {
      if ((err as { name?: string }).name !== 'AbortError') {
        setError(errMessage(err));
      }
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  }, [actors, limit, running]);

  return (
    <section className="surface-card p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 className="text-sm font-semibold inline-flex items-center gap-2">
            <Radio size={14} className="text-brand-600 dark:text-brand-400" />
            OTX rotation sweep
          </h3>
          <p className="text-xs text-muted mt-0.5">
            Fetch fresh OTX pulses for {limit} actors per sweep. Picks never-attempted first, then fewest IOCs, then
            oldest attempt. Rotation state cached at the edge - no API quota cost.
          </p>
        </div>
        {running ? (
          <button
            onClick={cancel}
            className="text-xs px-3 py-1.5 rounded border border-line-2 hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
          >
            cancel
          </button>
        ) : (
          <button
            onClick={start}
            disabled={actors.length === 0}
            className="text-xs px-3 py-1.5 rounded bg-brand-600 hover:bg-brand-700 dark:bg-brand-500 dark:hover:bg-brand-400 text-on-fill disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            run sweep ({actors.length} candidate{actors.length === 1 ? '' : 's'})
          </button>
        )}
      </div>

      {error && (
        <div className="mt-3 text-xs flex items-center gap-2 text-rose-600 dark:text-rose-400">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {(running || results.length > 0) && (
        <ul className="mt-3 space-y-1.5 max-h-64 overflow-y-auto pr-1">
          {results.map((r, i) => (
            <li key={`${r.slug}-${i}`} className="flex items-center gap-2 text-xs text-body">
              {r.status === 'ok' ? (
                <CheckCircle2 size={12} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle size={12} className="text-rose-600 dark:text-rose-400 shrink-0" />
              )}
              <span className="font-mono truncate">{r.name || r.slug}</span>
              {r.status === 'ok' ? (
                <span className="text-muted">
                  · {r.pulses.length} pulse{r.pulses.length === 1 ? '' : 's'} · {r.ioc_count} IOC
                  {r.ioc_count === 1 ? '' : 's'}
                </span>
              ) : (
                <span className="text-rose-500">· {r.message}</span>
              )}
            </li>
          ))}
          {running && !done && (
            <li className="flex items-center gap-2 text-xs text-muted">
              <Loader2 size={12} className="animate-spin" /> streaming…
            </li>
          )}
        </ul>
      )}

      {done && (
        <div className="mt-3 text-xs text-muted">
          done - {done.processed} processed, {done.skipped} skipped
        </div>
      )}
    </section>
  );
}
