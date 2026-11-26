/**
 * MCP settings pill, rendered top-right in the global TopBar.
 *
 * One source of truth for the user's TI-Mindmap-Hub MCP API key. Clicking
 * the pill opens a small popover with the key input, the re-probe button,
 * and the deep link to ti-mindmap-hub.com/settings. The two pages that
 * need MCP (AI Report showcase, MCP Search) render a READ-ONLY
 * `McpStatusBanner` instead -- the key is only edited here.
 *
 * State, the localStorage persist, and the probe logic live in
 * ./McpContext.tsx -- this component is a pure presentational layer
 * over that context.
 */

import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ChevronDown, Key, Loader2, Plug, PlugZap, RefreshCw, Settings2 } from 'lucide-react';
import { useMcp } from './McpContext';

export function McpKeyBar({ className = '' }: { className?: string }): JSX.Element {
  const { apiKey, status, statusMsg, saveKey, reprobe } = useMcp();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(apiKey);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setDraft(apiKey);
  }, [apiKey]);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('mousedown', onClick);
    return () => window.removeEventListener('mousedown', onClick);
  }, [open]);

  const pillInner = ((): JSX.Element => {
    if (status === 'unconfigured') {
      return (
        <>
          <Plug className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">MCP not configured</span>
          <span className="sm:hidden">MCP</span>
        </>
      );
    }
    if (status === 'probing') {
      return (
        <>
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          <span className="hidden sm:inline">probing MCP…</span>
          <span className="sm:hidden">MCP…</span>
        </>
      );
    }
    if (status === 'connected') {
      return (
        <>
          <PlugZap className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">MCP · 25 tools</span>
          <span className="sm:hidden">MCP</span>
        </>
      );
    }
    if (status === 'error') {
      return (
        <>
          <AlertTriangle className="h-3.5 w-3.5" />
          <span className="hidden sm:inline" title={statusMsg || 'Connection failed'}>
            MCP error
          </span>
          <span className="sm:hidden">MCP</span>
        </>
      );
    }
    return (
      <>
        <Plug className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">MCP idle</span>
        <span className="sm:hidden">MCP</span>
      </>
    );
  })();

  const tone = (() => {
    if (status === 'connected')
      return 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300';
    if (status === 'probing')
      return 'border-sky-300 dark:border-sky-700 bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300';
    if (status === 'error')
      return 'border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300';
    if (status === 'unconfigured')
      return 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-body';
    return 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-body';
  })();

  return (
    <div ref={ref} className={`relative ${className}`}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={`inline-flex min-w-[8ch] sm:min-w-[10ch] items-center justify-center gap-1.5 whitespace-nowrap rounded border ${tone} px-1.5 sm:px-2 py-1 min-h-11 sm:min-h-0 text-xs font-mono transition hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring`}
        aria-expanded={open}
        aria-label="TI-Mindmap-Hub MCP connection settings"
        title={status === 'error' ? statusMsg || 'Connection failed' : 'TI-Mindmap-Hub MCP settings'}
      >
        {pillInner}
        <ChevronDown className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute right-0 mt-1.5 w-80 max-w-[calc(100vw-1rem)] surface-card shadow-e2 p-3 z-50">
          <p className="flex items-center gap-1.5 text-micro font-mono uppercase tracking-wider text-muted mb-2">
            <Settings2 className="h-3 w-3" /> MCP settings
          </p>
          <KeyForm
            draft={draft}
            setDraft={setDraft}
            onSave={(k) => {
              saveKey(k);
              // Keep the popover open so the user can see the
              // probe result (the pill updates in place).
            }}
            onClear={
              apiKey
                ? () => {
                    saveKey('');
                    setDraft('');
                  }
                : undefined
            }
          />
          {status === 'error' && statusMsg && (
            <p className="mt-2 text-micro text-rose-600 dark:text-rose-400 font-mono break-words">
              last probe: {statusMsg}
            </p>
          )}
          <div className="mt-2 flex items-start justify-between gap-2">
            <p className="text-micro text-muted flex-1">
              Keys stay in your browser (localStorage) and never reach our backend. Get one at{' '}
              <a
                href="https://ti-mindmap-hub.com/settings"
                target="_blank"
                rel="noopener noreferrer"
                className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
              >
                ti-mindmap-hub.com/settings ↗
              </a>
            </p>
            <button
              type="button"
              onClick={() => void reprobe()}
              disabled={status === 'probing' || !apiKey}
              className="inline-flex items-center gap-1 rounded border border-line-2 px-1.5 py-0.5 text-micro font-mono text-body hover:border-brand-400 disabled:opacity-50 shrink-0"
              title="Re-run the MCP initialize handshake with the stored key"
            >
              <RefreshCw className={`h-3 w-3 ${status === 'probing' ? 'animate-spin' : ''}`} /> re-probe
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function KeyForm(props: {
  draft: string;
  setDraft: (s: string) => void;
  onSave: (k: string) => void;
  onClear?: () => void;
}): JSX.Element {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        props.onSave(props.draft.trim());
      }}
      className="flex flex-col gap-2"
    >
      <input
        type="password"
        value={props.draft}
        onChange={(e) => props.setDraft(e.target.value)}
        placeholder="tim_xxxxxxxxxxxx"
        className="rounded border border-line-2 bg-surface-100 px-2 py-1 font-mono text-xs text-heading w-full sm:w-56"
        autoComplete="off"
        spellCheck={false}
      />
      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={!props.draft.trim()}
          className="rounded border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-950/40 px-2 py-1 font-mono text-xs text-brand-700 dark:text-brand-300 hover:bg-brand-100 disabled:opacity-50 transition-colors"
        >
          <Key className="inline h-3 w-3 mr-1" /> save &amp; probe
        </button>
        {props.onClear && (
          <button
            type="button"
            onClick={props.onClear}
            className="rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/40 px-2 py-1 font-mono text-xs text-rose-700 dark:text-rose-300"
          >
            clear
          </button>
        )}
      </div>
    </form>
  );
}
