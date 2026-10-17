import { useState, useRef, useEffect, useCallback, type JSX } from 'react';
import { useLocation } from 'react-router-dom';
import { sanitizeAiHtml } from '../../lib/sanitize-html';
import { StepIndicator, ChatNarrative, renderMarkdown, type AgentStep } from '../../components/threatintel/ChatShared';
import {
  Send,
  FileText,
  AlertTriangle,
  Loader2,
  Lightbulb,
  Search,
  Shield,
  Globe,
  Database,
  Cpu,
  Target,
  Brain,
  BarChart3,
  Plus,
  MessageSquare,
  Check,
  Copy,
  Edit3,
  Download,
  PanelLeftClose,
  PanelLeftOpen,
  Clock,
  Trash2,
  Crosshair,
} from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { adminAuthHeaders } from '../../lib/admin-token';
import { buildReport, pollReport, type Report, type Progress } from '../../lib/threatintel/report-client';
import { exportReportPdf } from '../../lib/threatintel/report-pdf';
import { ReportView } from '../../components/threatintel/ReportView';
import { PivotSuggestions } from '../../components/threatintel/PivotSuggestions';
import { SelfEvalScorecard, type SelfEvalResult } from '../../components/threatintel/SelfEvalScorecard';
import { DataGapsPanel, type ToolFailure } from '../../components/threatintel/DataGapsPanel';
import { InvestigationTrace } from '../../components/threatintel/InvestigationTrace';
import { DetectionGenerate } from '../../components/threatintel/DetectionGenerate';
import { BulkIocInput } from '../../components/threatintel/BulkIocInput';
import { useToast } from '../../components/ui/Toast';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

// ── Types ───────────────────────────────────────────────────────────────

interface Source {
  name: string;
  items: number;
  data?: unknown[];
}

interface CopilotResponse {
  query: string;
  query_type: string;
  narrative: string;
  sources: Source[];
  model_used: string;
  processed_at: string;
  _meta?: { total_sources: number; total_items: number };
  confidence?: {
    level: string;
    score: number;
    admiralty?: { reliability: string; credibility: number; label: string };
    sources_contributing: number;
    contradictory_sources: number;
    reasoning: string;
  };
}

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  agent_id?: string;
  query_type?: string;
  model_used?: string;
  processed_at?: string;
  sources?: Source[];
  _meta?: { total_sources: number; total_items: number };
  confidence?: CopilotResponse['confidence'];
}

interface SessionItem {
  id: string;
  title: string;
  messageCount: number;
  created_at: string;
  updated_at: string;
}

// ── Vera modes ──────────────────────────────────────────────────────────

type VeraMode = 'ask' | 'investigate' | 'draft' | 'challenge';

interface VeraModeDef {
  id: VeraMode;
  label: string;
  description: string;
  icon: typeof MessageSquare;
  color: string;
}

const VERA_MODES: VeraModeDef[] = [
  {
    id: 'ask',
    label: 'Ask',
    description: 'Quick, sourced, conversational answers',
    icon: MessageSquare,
    color: 'bg-rose-500',
  },
  {
    id: 'investigate',
    label: 'Investigate',
    description: 'Multi-step agent reasoning with full tool fan-out',
    icon: Search,
    color: 'bg-rose-700',
  },
  {
    id: 'draft',
    label: 'Draft',
    description: 'Produces a TLP-marked report with citations',
    icon: FileText,
    color: 'bg-amber-600',
  },
  {
    id: 'challenge',
    label: 'Challenge',
    description: 'Adversarial stress-test of your read',
    icon: Crosshair,
    color: 'bg-severity-critical',
  },
];

// ── Analyst roles ───────────────────────────────────────────────────────

type AnalystRole = 'ciso' | 'detection' | 'ir' | 'cti';
const ROLES: { id: AnalystRole; label: string; icon: typeof Shield; desc: string; color: string }[] = [
  { id: 'ciso', label: 'CISO', icon: BarChart3, desc: 'Risk posture & strategic trends', color: 'bg-emerald-600' },
  { id: 'detection', label: 'Detection', icon: Search, desc: 'TTPs, detections & rule ideas', color: 'bg-rose-600' },
  {
    id: 'ir',
    label: 'Incident Response',
    icon: Target,
    desc: 'IOCs & behaviors for rapid triage',
    color: 'bg-severity-critical',
  },
  { id: 'cti', label: 'Threat Intel', icon: Brain, desc: 'Contextual analysis & relationships', color: 'bg-rose-700' },
];

// ── Constants ───────────────────────────────────────────────────────────

const QUERY_EXAMPLES = [
  { label: 'CVE-2024-1709', desc: 'CVE investigation', query: 'CVE-2024-1709' },
  { label: 'LockBit', desc: 'Ransomware group', query: 'LockBit' },
  { label: 'Scattered Spider', desc: 'Threat actor', query: 'Scattered Spider' },
  { label: '8.8.8.8', desc: 'IP address', query: '8.8.8.8' },
];

const CHAT_STARTERS = [
  'What are the latest critical CVEs?',
  'Which ransomware groups are most active this month?',
  'Tell me about APT29 tactics and techniques',
  'What IoCs are associated with LockBit?',
  'Summarize recent threat activity in the financial sector',
  'Are there any active exploits for CVE-2025-?',
];

const CAPABILITY_GRID = [
  { icon: Shield, label: 'CVE Lookup', desc: 'Vulnerability context, exploits, patches' },
  { icon: Cpu, label: 'Threat Actors', desc: 'TTPs, campaigns, attribution' },
  { icon: Globe, label: 'IOC Triage', desc: 'IPs, domains, hashes, URLs' },
  { icon: Database, label: 'Ransomware Intel', desc: 'Groups, leaks, negotiations' },
];

// ── Markdown renderer ───────────────────────────────────────────────────

function formatTime(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
}

// ── Main component ──────────────────────────────────────────────────────

export default function VeraChat(): JSX.Element {
  const location = useLocation();
  const toast = useToast();

  const [query, setQuery] = useState('');
  const [loading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CopilotResponse | null>(null);
  const [role, setRole] = useState<AnalystRole>('cti');
  const inputRef = useRef<HTMLInputElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const [veraMode, setVeraMode] = useState<VeraMode>('ask');
  const [template, setTemplate] = useState<string>('auto');
  const [tlp, setTlp] = useState<string>('AMBER');
  const [progress, setProgress] = useState<Progress | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [agentSteps, setAgentSteps] = useState<AgentStep[]>([]);
  const [streamingContent, setStreamingContent] = useState('');
  const [selfEval, setSelfEval] = useState<SelfEvalResult | null>(null);
  const [dataGaps, setDataGaps] = useState<ToolFailure[] | null>(null);
  const [cost, setCost] = useState<{ usd: number; tokens: number; llmCalls: number } | null>(null);
  const [priorIntel, setPriorIntel] = useState<string | null>(null);

  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const submitChatRef = useRef<((q: string) => Promise<void>) | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // ── Session management ──────────────────────────────────────────────

  const fetchSessions = useCallback(async () => {
    setLoadingSessions(true);
    try {
      const res = await fetch('/api/v1/agents/chat/sessions', {
        headers: adminAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        const raw = data.sessions ?? [];
        setSessions(
          raw.map(
            (s: {
              id: string;
              preview?: string;
              message_count?: number;
              title?: string;
              messageCount?: number;
              created_at: string;
              updated_at: string;
            }) => ({
              id: s.id,
              title: s.title ?? s.preview ?? 'Untitled',
              messageCount: s.messageCount ?? s.message_count ?? 0,
              created_at: s.created_at,
              updated_at: s.updated_at,
            })
          )
        );
      }
    } catch {
      /* ignore */
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  const loadSession = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/v1/agents/chat/${encodeURIComponent(id)}`, {
        headers: adminAuthHeaders(),
      });
      if (!res.ok) return;
      const data = await res.json();
      setChatMessages(data.messages ?? []);
      setSessionId(id);
      sessionStorage.setItem('vera_session_id', id);
      setError(null);
      setStreaming(false);
      setAgentSteps([]);
    } catch {
      /* ignore */
    }
  }, []);

  const startNewChat = useCallback(() => {
    setChatMessages([]);
    setSessionId(null);
    setStreaming(false);
    setAgentSteps([]);
    setStreamingContent('');
    setSelfEval(null);
    setDataGaps(null);
    setCost(null);
    setPriorIntel(null);
    setError(null);
    setResult(null);
    setReport(null);
    sessionStorage.removeItem('vera_session_id');
    document.title = 'Vera';
    inputRef.current?.focus();
  }, []);

  const deleteSession = useCallback(
    async (id: string) => {
      try {
        const res = await fetch(`/api/v1/agents/chat/${encodeURIComponent(id)}`, {
          method: 'DELETE',
          headers: adminAuthHeaders(),
        });
        if (res.ok) {
          setSessions((prev) => prev.filter((s) => s.id !== id));
          if (sessionId === id) {
            startNewChat();
          }
        }
      } catch {
        /* ignore */
      }
    },
    [sessionId, startNewChat]
  );

  // ── Report mode ─────────────────────────────────────────────────────

  const runReport = useCallback(
    async (q: string) => {
      if (!q.trim()) return;
      setError(null);
      setReport(null);
      setProgress({ phase: 'queued', pct: 0, detail: 'Queued' });
      try {
        const id = await buildReport(q.trim(), template === 'auto' ? undefined : template, tlp);
        const r = await pollReport(id, setProgress);
        setReport(r);
        setProgress(null);
      } catch (e) {
        setError(errMessage(e));
        setProgress(null);
      }
    },
    [template, tlp]
  );

  // ── Scroll / focus ──────────────────────────────────────────────────

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, agentSteps]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const q = new URLSearchParams(location.search).get('q');
    if (q) setQuery(q);
  }, [location.search]);

  // ── Restore session from sessionStorage ─────────────────────────────

  useEffect(() => {
    const storedId = sessionStorage.getItem('vera_session_id');
    if (storedId) {
      setSessionId(storedId);
      fetch(`/api/v1/agents/chat/${encodeURIComponent(storedId)}`, { headers: adminAuthHeaders() })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (!data?.messages) return;
          setChatMessages(data.messages);
          const hasAgent = data.messages.some((m: ChatMessage) => m.role === 'system' && m.agent_id);
          if (!hasAgent) return;
          const lastAssistant = [...data.messages].reverse().find((m: ChatMessage) => m.role === 'assistant');
          if (lastAssistant && lastAssistant.content) return;
          const agentMsg = data.messages.find((m: ChatMessage) => m.role === 'system' && m.agent_id);
          if (agentMsg?.agent_id) {
            reconnectToStream(storedId);
          }
        })
        .catch(() => {});
    }
    // Mount-only: reconnect to an orphaned stream from a previous session.
    // reconnectToStream is defined below via useCallback; adding it as a dep
    // would re-fire this effect on every render it changes identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reconnectToStream = useCallback(async (sid: string) => {
    setStreaming(true);
    setAgentSteps([]);
    setStreamingContent('');
    const ac = new AbortController();
    abortControllerRef.current = ac;
    try {
      const streamRes = await fetch(`/api/v1/agents/chat/${encodeURIComponent(sid)}/stream`, {
        headers: adminAuthHeaders(),
        signal: ac.signal,
      });
      if (!streamRes.ok || !streamRes.body) {
        setStreaming(false);
        return;
      }
      const reader = streamRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.type === 'heartbeat') continue;
            if (d.type === 'step' && d.step) {
              setAgentSteps((prev) => {
                if (prev.find((s) => s.stepNumber === d.step.stepNumber)) return prev;
                return [...prev, d.step];
              });
            }
            if (d.type === 'token' && typeof d.token === 'string') {
              setStreamingContent((prev) => prev + d.token);
            }
            if (d.type === 'done' && d.report) {
              const assistantMsg: ChatMessage = {
                role: 'assistant',
                content: d.report,
                model_used: d.modelUsed,
                processed_at: new Date().toISOString(),
                sources: d.sources,
                _meta: d._meta,
              };
              if (d.selfEval) setSelfEval(d.selfEval as SelfEvalResult);
              else setSelfEval(null);
              if (d.dataGaps) setDataGaps(d.dataGaps as ToolFailure[]);
              else setDataGaps(null);
              if (d.cost) setCost(d.cost as { usd: number; tokens: number; llmCalls: number });
              else setCost(null);
              if (d.priorIntelligence) setPriorIntel(d.priorIntelligence as string);
              else setPriorIntel(null);
              setChatMessages((prev) => {
                const next = [...prev];
                const last = next[next.length - 1];
                if (last && last.role === 'assistant') {
                  next[next.length - 1] = assistantMsg;
                } else {
                  next.push(assistantMsg);
                }
                return next;
              });
              setStreamingContent('');
            }
            if (d.type === 'error') {
              setStreaming(false);
              setAgentSteps([]);
              return;
            }
          } catch {
            /* skip */
          }
        }
      }
    } catch {
      /* stream failed */
    }
    setStreaming(false);
    setAgentSteps([]);
  }, []);

  useEffect(() => {
    void fetchSessions();
  }, [fetchSessions, sessionId]);

  const updateDocTitle = useCallback((messages: ChatMessage[]) => {
    const firstUser = messages.find((m) => m.role === 'user');
    if (firstUser) {
      const title = firstUser.content.slice(0, 50);
      document.title = `${title}${firstUser.content.length > 50 ? '…' : ''} - Vera`;
    } else {
      document.title = 'Vera';
    }
  }, []);

  useEffect(() => {
    if (chatMessages.length > 0) updateDocTitle(chatMessages);
  }, [chatMessages, updateDocTitle]);

  const [, setNarrativeHtml] = useState('');
  useEffect(() => {
    const md = result?.narrative;
    if (!md) {
      setNarrativeHtml('');
      return;
    }
    let cancelled = false;
    void (async () => {
      const { default: DOMPurify } = await import('isomorphic-dompurify');
      const safeMd = DOMPurify.sanitize(md, { ALLOWED_TAGS: [] });
      const safe = await sanitizeAiHtml(renderMarkdown(safeMd));
      if (!cancelled) setNarrativeHtml(safe);
    })();
    return () => {
      cancelled = true;
    };
  }, [result?.narrative]);

  // ── Chat submission ─────────────────────────────────────────────────

  const submitChat = useCallback(
    async (q: string) => {
      if (!q.trim() || streaming) return;
      setError(null);
      setStreaming(true);
      setAgentSteps([]);
      setStreamingContent('');

      const userMsg: ChatMessage = { role: 'user', content: q.trim() };
      setChatMessages((prev) => [...prev, userMsg]);
      setChatMessages((prev) => [...prev, { role: 'assistant', content: '' }]);

      const ac = new AbortController();
      abortControllerRef.current = ac;

      try {
        const res = await fetch('/api/v1/agents/chat', {
          method: 'POST',
          signal: AbortSignal.timeout(30_000),
          headers: { ...adminAuthHeaders(), 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, mode: veraMode, role, query: q.trim() }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.message ?? err.error ?? 'Chat failed');
        }
        const { sessionId: newId } = await res.json();
        setSessionId(newId);
        sessionStorage.setItem('vera_session_id', newId);

        const streamRes = await fetch(`/api/v1/agents/chat/${encodeURIComponent(newId)}/stream`, {
          headers: adminAuthHeaders(),
          signal: ac.signal,
        });
        if (!streamRes.ok || !streamRes.body) throw new Error('Stream unavailable');

        const reader = streamRes.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? '';

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'heartbeat') continue;
              if (data.type === 'step' && data.step) {
                setAgentSteps((prev) => {
                  const exists = prev.find((s) => s.stepNumber === data.step.stepNumber);
                  if (exists) return prev;
                  return [...prev, data.step];
                });
              }
              if (data.type === 'done' && data.report) {
                const assistantMsg: ChatMessage = {
                  role: 'assistant',
                  content: data.report,
                  model_used: data.modelUsed,
                  processed_at: new Date().toISOString(),
                  sources: data.sources,
                  _meta: data._meta,
                };
                setChatMessages((prev) => {
                  const next = [...prev];
                  next[next.length - 1] = assistantMsg;
                  return next;
                });
                setStreamingContent('');
              }
              if (data.type === 'error') {
                throw new Error(data.error ?? 'Investigation failed');
              }
            } catch {
              /* skip malformed */
            }
          }
        }
      } catch (e) {
        const msg = errMessage(e);
        setError(msg);
        setChatMessages((prev) => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last && last.role === 'assistant' && !last.content) {
            next.pop();
          }
          return next;
        });
      } finally {
        abortControllerRef.current = null;
        setStreaming(false);
        setAgentSteps([]);
      }
    },
    [sessionId, streaming, veraMode, role]
  );
  submitChatRef.current = submitChat;

  // ── Cancel investigation ────────────────────────────────────────────

  const cancelInvestigation = useCallback(async () => {
    if (!sessionId || !streaming) return;
    abortControllerRef.current?.abort();
    try {
      await fetch(`/api/v1/agents/chat/${encodeURIComponent(sessionId)}/cancel`, {
        method: 'POST',
        headers: adminAuthHeaders(),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      /* best-effort */
    }
    setError('Investigation cancelled');
    setStreaming(false);
    setAgentSteps([]);
  }, [sessionId, streaming]);

  // ── Submit dispatcher ───────────────────────────────────────────────

  const submit = useCallback(
    (q: string) => {
      if (veraMode === 'draft') void runReport(q);
      else void submitChat(q);
    },
    [veraMode, submitChat, runReport]
  );

  // ── Edit message ────────────────────────────────────────────────────

  const handleEditMessage = useCallback(
    (index: number) => {
      const msg = chatMessages[index];
      if (!msg || msg.role !== 'user') return;
      setQuery(msg.content);
      setChatMessages((prev) => prev.slice(0, index));
      setTimeout(() => inputRef.current?.focus(), 50);
    },
    [chatMessages]
  );

  // ── Export conversation ─────────────────────────────────────────────

  const exportConversation = useCallback(() => {
    const lines: string[] = [];
    for (const msg of chatMessages) {
      if (msg.role === 'user') lines.push(`## User\n\n${msg.content}\n`);
      else if (msg.role === 'assistant' && msg.content) lines.push(`## Assistant\n\n${msg.content}\n`);
    }
    const markdown = lines.join('---\n\n');
    const blob = new Blob([markdown], { type: 'text/markdown' });
    downloadBlob(blob, `${name}.md`);
  }, [chatMessages]);

  // ── Derived state ───────────────────────────────────────────────────

  const currentSteps = agentSteps;
  const currentStepNum =
    currentSteps.filter((s) => s.status === 'running').length > 0
      ? Math.max(...currentSteps.filter((s) => s.status === 'running').map((s) => s.stepNumber))
      : currentSteps.length;
  const hasResults = !!(result || report || loading || progress || error || chatMessages.length > 0 || streaming);
  const currentTitle = chatMessages.find((m) => m.role === 'user')?.content;
  const hasMessages = chatMessages.length > 0;
  const isReporting = veraMode === 'draft';
  const activeModeDef = VERA_MODES.find((m) => m.id === veraMode) ?? VERA_MODES[0]!;
  const ModeIcon = activeModeDef.icon;

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden text-heading">
      {/* ── Session sidebar ──────────────────────────────────────────── */}
      <SessionSidebar
        open={sidebarOpen}
        sessions={sessions}
        loading={loadingSessions}
        activeId={sessionId}
        onSelect={(id) => {
          loadSession(id);
          setSidebarOpen(false);
        }}
        onDelete={deleteSession}
        onNew={startNewChat}
        onClose={() => setSidebarOpen(false)}
        veraMode={veraMode}
        role={role}
        roles={ROLES}
        veraModes={VERA_MODES}
        onVeraModeChange={setVeraMode}
        onRoleChange={setRole}
        onTemplateChange={setTemplate}
        onTlpChange={setTlp}
        template={template}
        tlp={tlp}
      />

      {/* ── Main content area ────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top bar */}
        <div className="flex items-center gap-3 border-b border-line-1 bg-surface-100/80 px-4 py-2.5 backdrop-blur-lg">
          <button
            type="button"
            onClick={() => setSidebarOpen((p) => !p)}
            className="flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-300 hover:text-rose-600 lg:hidden dark:hover:bg-surface-300"
            aria-label="Toggle sidebar"
          >
            <PanelLeftOpen size={15} />
          </button>
          <BackLink
            to="/threatintel"
            className="flex items-center gap-1 text-xs font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 shrink-0"
          >
            back
          </BackLink>
          <div className="flex min-w-0 flex-1 items-center gap-2">
            {hasMessages ? (
              <>
                <MessageSquare size={14} className="shrink-0 text-rose-500" />
                <span className="truncate text-sm font-medium text-body">{currentTitle ?? 'Vera'}</span>
                <span className="shrink-0 rounded bg-surface-300 px-1.5 py-0.5 font-mono text-micro text-muted">
                  {chatMessages.length} msgs
                </span>
              </>
            ) : (
              <span className="text-sm font-medium text-muted">Vera</span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            {hasMessages && (
              <>
                <button
                  type="button"
                  onClick={exportConversation}
                  className="flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-300 hover:text-rose-600 dark:hover:bg-surface-300 transition-colors"
                  aria-label="Export conversation"
                >
                  <Download size={13} />
                </button>
                <BulkIocInput
                  onSubmit={(q) => {
                    startNewChat();
                    setTimeout(() => submitChatRef.current?.(q), 50);
                  }}
                />
              </>
            )}
          </div>
        </div>

        {/* Scrollable chat area */}
        <div className="flex-1 overflow-y-auto">
          {!isReporting && (
            <div className="mx-auto max-w-4xl px-4 py-6">
              {/* Hero - only show when no messages */}
              {!hasMessages && !streaming && (
                <div className="mb-8 flex flex-col items-center gap-3 text-center">
                  <div
                    className={`flex h-14 w-14 items-center justify-center rounded-xl ${activeModeDef.color} shadow-e3`}
                  >
                    <ModeIcon className="h-7 w-7 text-white" />
                  </div>
                  <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Vera</h1>
                  <p className="max-w-lg text-sm text-muted">
                    Your AI threat-intel analyst. Ask, investigate, draft, or challenge - in plain English.
                  </p>
                  {/* Mode selector */}
                  <div className="flex flex-wrap justify-center gap-2">
                    {VERA_MODES.map((m) => {
                      const MIcon = m.icon;
                      return (
                        <button
                          type="button"
                          key={m.id}
                          onClick={() => setVeraMode(m.id)}
                          aria-pressed={veraMode === m.id}
                          className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-mono transition-all ${
                            veraMode === m.id
                              ? 'border-rose-500 bg-rose-600/10 text-rose-700 dark:text-rose-300'
                              : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-line-1 dark:bg-surface-200 dark:text-slate-300'
                          }`}
                          title={m.description}
                        >
                          <MIcon size={14} />
                          {m.label}
                        </button>
                      );
                    })}
                  </div>
                  <p className="text-xs text-muted italic">{activeModeDef.description}</p>
                  {/* Role selector */}
                  <div className="flex flex-wrap justify-center gap-1.5">
                    <span className="text-micro text-muted self-center mr-1 font-medium uppercase tracking-wider">
                      As:
                    </span>
                    {ROLES.map((r) => {
                      const RIcon = r.icon;
                      return (
                        <button
                          type="button"
                          key={r.id}
                          onClick={() => setRole(r.id)}
                          aria-pressed={role === r.id}
                          className={`flex items-center gap-1 rounded-full px-2.5 py-1 text-micro font-mono transition-all ${
                            role === r.id
                              ? `${r.color} text-white shadow-sm`
                              : 'bg-slate-100 text-slate-500 hover:bg-slate-200 dark:bg-surface-300 dark:text-muted dark:hover:bg-surface-300'
                          }`}
                        >
                          <RIcon size={10} />
                          {r.label}
                        </button>
                      );
                    })}
                  </div>
                  <div className="flex flex-wrap items-center justify-center gap-2">
                    {QUERY_EXAMPLES.map((ex) => (
                      <button
                        type="button"
                        key={ex.label}
                        onClick={() => {
                          setQuery(ex.query);
                          void submitChat(ex.query);
                        }}
                        className="rounded-xl border border-line-1 bg-surface-100 px-3 py-1.5 text-xs font-medium text-body transition-colors hover:bg-surface-200"
                      >
                        <span className="text-muted">{ex.desc}:</span> <span className="font-mono">{ex.label}</span>
                      </button>
                    ))}
                  </div>
                  <div className="flex flex-wrap justify-center gap-1.5">
                    {CHAT_STARTERS.slice(0, 4).map((starter) => (
                      <button
                        type="button"
                        key={starter}
                        onClick={() => {
                          setQuery(starter);
                          void submitChat(starter);
                        }}
                        className="rounded-full border border-line-1 bg-surface-100 px-3 py-1 text-mini font-mono text-muted transition-colors hover:border-rose-400 hover:text-rose-600"
                      >
                        {starter}
                      </button>
                    ))}
                  </div>
                  <div className="mt-1 grid w-full grid-cols-2 gap-3 sm:grid-cols-4">
                    {CAPABILITY_GRID.map(({ icon: Icon, label, desc }) => (
                      <div
                        key={label}
                        className="flex flex-col items-center gap-1.5 rounded-xl border border-line-1 bg-surface-200/50 p-3 text-center"
                      >
                        <Icon className="h-4 w-4 text-rose-500" />
                        <span className="text-xs font-medium">{label}</span>
                        <span className="text-mini text-muted">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Messages */}
              {hasMessages && (
                <div className="space-y-4">
                  {chatMessages.map((msg, i) =>
                    msg.role === 'user' ? (
                      <div key={i} className="flex justify-end group">
                        <div className="relative max-w-[85%] sm:max-w-[70%]">
                          <div className="rounded-2xl bg-rose-600 px-4 py-2.5 text-sm text-on-fill shadow-sm">
                            {msg.content}
                          </div>
                          <button
                            type="button"
                            onClick={() => handleEditMessage(i)}
                            className="absolute -left-7 top-1/2 -translate-y-1/2 opacity-0 transition-opacity group-hover:opacity-100"
                            aria-label="Edit message"
                          >
                            <Edit3 size={12} className="text-muted hover:text-rose-600" />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div key={i} className="flex justify-start">
                        <div className="w-full max-w-[95%] sm:max-w-[85%] rounded-2xl border border-line-1 bg-surface-100 p-4 shadow-sm">
                          {i === chatMessages.length - 1 && streaming && currentSteps.length > 0 && (
                            <StepIndicator steps={currentSteps} currentStep={currentStepNum} />
                          )}
                          {i === chatMessages.length - 1 && !streaming && currentSteps.length > 0 && (
                            <InvestigationTrace steps={currentSteps} />
                          )}
                          {msg.content ? (
                            <div className="animate-[textReveal_0.5s_ease-out]">
                              <ChatNarrative markdown={msg.content} />
                            </div>
                          ) : streaming && i === chatMessages.length - 1 ? (
                            <div>
                              {streamingContent ? (
                                <div className="animate-[textReveal_0.5s_ease-out]">
                                  <ChatNarrative markdown={streamingContent} />
                                </div>
                              ) : (
                                <div className="flex items-center gap-3 py-2">
                                  <div className="flex items-center gap-2">
                                    <div className="flex gap-1">
                                      <span
                                        className="h-2 w-2 animate-bounce rounded-full bg-rose-500"
                                        style={{ animationDelay: '0ms' }}
                                      />
                                      <span
                                        className="h-2 w-2 animate-bounce rounded-full bg-rose-500"
                                        style={{ animationDelay: '150ms' }}
                                      />
                                      <span
                                        className="h-2 w-2 animate-bounce rounded-full bg-rose-500"
                                        style={{ animationDelay: '300ms' }}
                                      />
                                    </div>
                                    <span className="font-mono text-xs text-muted">Investigating</span>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={cancelInvestigation}
                                    className="inline-flex items-center gap-1 rounded-md border border-rose-200 bg-rose-50 px-2 py-1 text-mini font-mono text-rose-600 transition-colors hover:bg-rose-100 dark:border-rose-800/50 dark:bg-rose-950/20 dark:text-rose-400"
                                    aria-label="Cancel investigation"
                                  >
                                    Cancel
                                  </button>
                                </div>
                              )}
                            </div>
                          ) : null}
                          {msg.sources && msg.sources.length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-1.5">
                              {msg.sources.map((s) => (
                                <span
                                  key={s.name}
                                  className="inline-flex items-center gap-1 rounded-full border border-line-1 bg-surface-200 px-2.5 py-0.5 font-mono text-mini text-muted"
                                >
                                  {s.name}
                                  <span className="text-muted">({s.items})</span>
                                </span>
                              ))}
                            </div>
                          )}
                          <div className="mt-2 flex items-center justify-between border-t border-line-1 pt-2">
                            <div className="flex items-center gap-2">
                              {msg.model_used && (
                                <span className="font-mono text-mini text-muted">via {msg.model_used}</span>
                              )}
                              {cost && i === chatMessages.length - 1 && (
                                <span className="font-mono text-mini text-muted">
                                  ${cost.usd.toFixed(4)} · {(cost.tokens / 1000).toFixed(1)}K tok · {cost.llmCalls} LLM
                                </span>
                              )}
                              {priorIntel && i === chatMessages.length - 1 && (
                                <span
                                  className="font-mono text-mini text-violet-600 dark:text-violet-400"
                                  title={priorIntel}
                                >
                                  ↺ built on prior investigations
                                </span>
                              )}
                            </div>
                            {msg.content && (
                              <div className="flex items-center gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => {
                                    navigator.clipboard
                                      .writeText(msg.content)
                                      .then(() => {
                                        setCopiedIndex(i);
                                        setTimeout(() => setCopiedIndex(null), 1500);
                                      })
                                      .catch(() => toast.error('Failed to copy to clipboard'));
                                  }}
                                  className="text-muted hover:text-rose-600 transition-colors"
                                  aria-label="Copy response"
                                >
                                  {copiedIndex === i ? (
                                    <Check size={12} className="text-emerald-500" />
                                  ) : (
                                    <Copy size={12} />
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                          {msg.content && i === chatMessages.length - 1 && !streaming && (
                            <>
                              <FollowUpSuggestions
                                content={msg.content}
                                query={
                                  i > 0 && chatMessages[i - 1]?.role === 'user'
                                    ? chatMessages[i - 1]!.content
                                    : undefined
                                }
                                onSubmit={(q) => {
                                  setQuery(q);
                                  void submitChat(q);
                                }}
                              />
                              {(() => {
                                const userMsg = i > 0 ? chatMessages[i - 1] : null;
                                return userMsg?.role === 'user' ? (
                                  <PivotSuggestions
                                    query={userMsg.content}
                                    responseContent={msg.content ?? ''}
                                    responseSources={msg.sources}
                                    onSubmit={(q) => {
                                      setQuery(q);
                                      void submitChat(q);
                                    }}
                                  />
                                ) : null;
                              })()}
                              <DetectionGenerate context={msg.content ?? ''} />
                              {selfEval && i === chatMessages.length - 1 && <SelfEvalScorecard selfEval={selfEval} />}
                              {dataGaps && dataGaps.length > 0 && i === chatMessages.length - 1 && (
                                <DataGapsPanel dataGaps={dataGaps} />
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    )
                  )}
                  <div ref={chatEndRef} />
                </div>
              )}

              {error && (
                <div
                  role="alert"
                  className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-rose-300 bg-rose-50/50 px-4 py-3 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300"
                >
                  <span className="font-mono">
                    <AlertTriangle size={14} className="mr-1 inline" /> {error}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Draft mode (report) */}
          {isReporting && (
            <div className="mx-auto max-w-4xl px-4 py-8">
              <div className="flex flex-col items-center gap-4 text-center mb-6">
                <h1 className="text-2xl font-bold tracking-tight">Draft Report</h1>
                <p className="text-sm text-muted">Generate a structured CTI report</p>
              </div>
              <div className="flex w-full flex-col gap-3">
                <div className="flex flex-wrap items-center justify-center gap-2 mb-2">
                  <select
                    value={template}
                    onChange={(e) => setTemplate(e.target.value)}
                    aria-label="Report template"
                    className="rounded-xl border border-line-1 bg-surface-100 px-2.5 py-1.5 text-xs font-mono text-muted focus:border-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-500/20"
                  >
                    <option value="auto">Auto template</option>
                    <option value="ransomware-group">Ransomware Group</option>
                    <option value="threat-actor">Threat Actor</option>
                    <option value="cve">CVE / Vulnerability</option>
                    <option value="ioc">IOC Dossier</option>
                  </select>
                  <select
                    value={tlp}
                    onChange={(e) => setTlp(e.target.value)}
                    aria-label="TLP classification"
                    className="rounded-xl border border-line-1 bg-surface-100 px-2.5 py-1.5 text-xs font-mono text-muted focus:border-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-500/20"
                  >
                    <option value="CLEAR">TLP:CLEAR</option>
                    <option value="GREEN">TLP:GREEN</option>
                    <option value="AMBER">TLP:AMBER</option>
                    <option value="RED">TLP:RED</option>
                  </select>
                </div>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted" />
                  <input
                    ref={inputRef}
                    type="text"
                    aria-label="Report subject"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && submit(query)}
                    placeholder="Subject for a full report (group, actor, CVE, or IOC)…"
                    className="h-14 w-full rounded-xl border border-line-1 bg-surface-100 pl-12 pr-14 text-base text-heading shadow-sm transition-colors placeholder:text-muted focus:border-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-500/20 dark:placeholder:text-muted"
                    disabled={loading || !!progress}
                  />
                  <button
                    type="button"
                    onClick={() => submit(query)}
                    aria-label="Submit query"
                    disabled={loading || !!progress || !query.trim()}
                    className="absolute right-2 top-1/2 flex h-10 w-10 -translate-y-1/2 items-center justify-center rounded-xl bg-rose-600 text-on-fill transition-all hover:bg-rose-700 disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    {loading || progress ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                  </button>
                </div>
                {error && (
                  <div
                    role="alert"
                    className="flex items-center justify-between gap-3 rounded-xl border border-rose-300 bg-rose-50/50 px-4 py-3 text-sm text-rose-700 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300"
                  >
                    <span className="font-mono">
                      <AlertTriangle size={14} className="mr-1 inline" /> {error}
                    </span>
                    <button
                      type="button"
                      onClick={() => submit(query)}
                      className="shrink-0 rounded border border-rose-400/60 px-3 py-1 font-mono text-xs text-rose-700 hover:bg-rose-500/10 dark:text-rose-300"
                    >
                      retry
                    </button>
                  </div>
                )}
              </div>

              {!hasResults && !loading && !progress && !report && (
                <div className="mt-6 flex flex-col items-center gap-3">
                  <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
                    <Lightbulb size={12} /> Try an example
                  </p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {QUERY_EXAMPLES.map((ex) => (
                      <button
                        type="button"
                        key={ex.label}
                        onClick={() => {
                          setQuery(ex.query);
                          void submit(ex.query);
                        }}
                        className="rounded-xl border border-line-1 bg-surface-100 px-3 py-1.5 text-xs font-medium text-body transition-colors hover:bg-surface-200"
                      >
                        <span className="text-muted">{ex.desc}:</span> <span className="font-mono">{ex.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-8 space-y-6">
                {progress && !report && (
                  <section
                    role="status"
                    aria-live="polite"
                    className="rounded-xl border border-line-1 bg-surface-100 p-5 shadow-sm"
                  >
                    <div className="mb-2 flex items-center justify-between font-mono text-xs text-muted">
                      <span className="inline-flex items-center gap-2">
                        <Loader2 size={13} className="animate-spin text-rose-500" /> {progress.phase}
                      </span>
                      <span>{progress.pct}%</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded bg-track">
                      <div className="h-full bg-rose-500 transition-all" style={{ width: `${progress.pct}%` }} />
                    </div>
                    <p className="mt-2 font-mono text-xs text-muted">{progress.detail}</p>
                  </section>
                )}

                {report && <ReportView report={report} onExportPdf={() => void exportReportPdf(report)} />}

                {loading && !progress && (
                  <div className="py-16 text-center">
                    <Loader2 size={32} className="mx-auto mb-4 animate-spin text-rose-500" />
                    <p className="font-mono text-sm text-muted">Gathering intelligence…</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Chat input bar - fixed bottom */}
        {!isReporting && (
          <div className="shrink-0 border-t border-line-1 bg-surface-100/80 backdrop-blur-lg">
            <div className="mx-auto flex max-w-4xl items-center gap-2 px-4 py-3">
              <div className="relative flex-1">
                <input
                  ref={inputRef}
                  type="text"
                  aria-label="Ask Vera"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      if (query.trim()) {
                        const q = query;
                        setQuery('');
                        void submitChat(q);
                      }
                    }
                  }}
                  placeholder={
                    streaming
                      ? 'Waiting for response…'
                      : hasMessages
                        ? 'Ask a follow-up question…'
                        : veraMode === 'ask'
                          ? 'Ask about any CVE, threat actor, ransomware group, IP, or domain…'
                          : veraMode === 'investigate'
                            ? 'What should I investigate?'
                            : veraMode === 'challenge'
                              ? 'What read should I challenge?'
                              : 'Ask about any threat…'
                  }
                  className="h-12 w-full rounded-xl border border-line-1 bg-surface-100 pl-4 pr-12 text-sm text-heading shadow-sm transition-colors placeholder:text-muted focus:border-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-500/20 dark:placeholder:text-muted"
                  disabled={streaming}
                />
                <button
                  type="button"
                  onClick={() => {
                    if (query.trim()) {
                      const q = query;
                      setQuery('');
                      void submitChat(q);
                    }
                  }}
                  aria-label="Send message"
                  disabled={streaming || !query.trim()}
                  className="absolute right-1.5 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-xl bg-rose-600 text-on-fill transition-all hover:bg-rose-700 disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  {streaming ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Chat narrative renderer ────────────────────────────────────────────

// ── Follow-up suggestions ──────────────────────────────────────────────

function FollowUpSuggestions({
  content,
  query,
  onSubmit,
}: {
  content: string;
  query?: string;
  onSubmit: (q: string) => void;
}) {
  const [suggestions, setSuggestions] = useState<string[] | null>(null);
  const [loadingFU, setLoadingFU] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSuggestions(null);
    setLoadingFU(true);
    void (async () => {
      try {
        const res = await fetch('/api/v1/copilot/follow-ups', {
          method: 'POST',
          headers: { ...adminAuthHeaders(), 'content-type': 'application/json' },
          body: JSON.stringify({ query: query ?? '', responseContent: content }),
          signal: AbortSignal.timeout(8000),
        });
        if (!res.ok) return;
        const data = (await res.json()) as { suggestions: string[] };
        if (!cancelled && data.suggestions?.length > 0) {
          setSuggestions(data.suggestions);
        }
      } catch {
        /* fall back to nothing */
      } finally {
        if (!cancelled) setLoadingFU(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [content, query]);

  if (loadingFU) {
    return (
      <div className="mt-3 flex items-center gap-2 border-t border-line-1 pt-3">
        <Loader2 size={11} className="animate-spin text-muted" />
        <span className="font-mono text-mini text-muted">Suggesting follow-ups…</span>
      </div>
    );
  }

  if (!suggestions || suggestions.length === 0) return null;

  return (
    <div className="mt-3 flex flex-wrap gap-1.5 border-t border-line-1 pt-3">
      {suggestions.map((s) => (
        <button
          type="button"
          key={s}
          onClick={() => onSubmit(s)}
          className="rounded-full border border-line-1 bg-surface-200 px-2.5 py-1 text-mini font-mono text-muted transition-colors hover:border-rose-400 hover:text-rose-600 dark:hover:border-rose-400 dark:hover:text-rose-400"
        >
          {s}
        </button>
      ))}
    </div>
  );
}

// ── Session sidebar ────────────────────────────────────────────────────

function SessionSidebar({
  open,
  sessions,
  loading,
  activeId,
  onSelect,
  onDelete,
  onNew,
  onClose,
  veraMode,
  role,
  roles,
  veraModes,
  onVeraModeChange,
  onRoleChange,
  onTemplateChange,
  onTlpChange,
  template,
  tlp,
}: {
  open: boolean;
  sessions: SessionItem[];
  loading: boolean;
  activeId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
  onNew: () => void;
  onClose: () => void;
  veraMode?: VeraMode;
  role?: string;
  roles?: { id: string; label: string; icon: typeof Shield; desc: string; color: string }[];
  veraModes?: VeraModeDef[];
  onVeraModeChange?: (m: VeraMode) => void;
  onRoleChange?: (r: AnalystRole) => void;
  onTemplateChange?: (t: string) => void;
  onTlpChange?: (t: string) => void;
  template?: string;
  tlp?: string;
}) {
  return (
    <>
      {open && <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm lg:hidden" onClick={onClose} />}
      <div
        className={`w-80 shrink-0 flex-col border-r border-line-1 bg-surface-100 dark:border-line-1 dark:bg-surface-200 lg:sticky lg:top-0 lg:h-full lg:translate-x-0 lg:z-10 ${
          open
            ? 'fixed inset-y-0 left-0 z-50 translate-x-0 shadow-xl transition-transform duration-200 lg:relative lg:shadow-none'
            : 'fixed -translate-x-full lg:relative lg:translate-x-0'
        }`}
      >
        <div className="flex items-center justify-between border-b border-line-1 px-4 py-3">
          <h2 className="text-sm font-semibold text-body">Conversations</h2>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={onNew}
              className="flex items-center gap-1 rounded-xl px-2 py-1 text-xs font-mono text-muted hover:text-rose-600 transition-colors"
            >
              <Plus size={13} />
              New
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl p-1 text-muted hover:text-muted transition-colors"
              aria-label="Close sidebar"
            >
              <PanelLeftClose size={16} />
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={16} className="animate-spin text-muted" />
            </div>
          )}
          {!loading && sessions.length === 0 && (
            <div className="px-4 py-8 text-center font-mono text-xs text-muted">No conversations yet</div>
          )}
          {!loading &&
            sessions.map((s) => (
              <div
                key={s.id}
                className={`group flex items-center gap-2 border-b border-slate-50 px-4 py-2.5 cursor-pointer transition-colors hover:bg-surface-200 dark:border-line-1 dark:hover:bg-surface-300 ${
                  s.id === activeId ? 'bg-rose-50 dark:bg-rose-900/20' : ''
                }`}
                onClick={() => onSelect(s.id)}
              >
                <MessageSquare size={14} className="shrink-0 text-muted" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-body">{s.title}</div>
                  <div className="flex items-center gap-2 text-mini font-mono text-muted">
                    <Clock size={10} />
                    <span>{formatTime(s.updated_at)}</span>
                    <span>
                      · {s.messageCount} {s.messageCount === 1 ? 'turn' : 'turns'}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(s.id);
                  }}
                  className="shrink-0 rounded p-1 text-inverted opacity-0 transition-opacity hover:text-rose-500 group-hover:opacity-100"
                  aria-label="Delete conversation"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
        </div>

        {/* Settings footer */}
        <div className="border-t border-line-1 p-3">
          {onVeraModeChange && veraMode && veraModes && (
            <div className="mb-2">
              <label className="mb-1 block text-mini font-mono font-medium text-muted">Mode</label>
              <div className="flex gap-1">
                {veraModes.map((m) => (
                  <button
                    type="button"
                    key={m.id}
                    onClick={() => onVeraModeChange(m.id)}
                    className={`flex-1 rounded px-2 py-1 text-xs font-mono transition-colors ${
                      veraMode === m.id
                        ? 'bg-rose-500 text-white'
                        : 'bg-slate-100 text-slate-500 hover:bg-slate-200 dark:bg-surface-300'
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>
          )}
          {role && roles && onRoleChange && (
            <div className="mb-2">
              <label className="mb-1 block text-mini font-mono font-medium text-muted">Role</label>
              <select
                value={role}
                onChange={(e) => onRoleChange(e.target.value as AnalystRole)}
                className="w-full rounded border border-line-1 px-2 py-1 text-xs font-mono bg-surface-100"
              >
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.label}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="flex gap-2">
            {onTemplateChange && (
              <div className="flex-1">
                <label className="mb-1 block text-mini font-mono font-medium text-muted">Template</label>
                <select
                  value={template}
                  onChange={(e) => onTemplateChange(e.target.value)}
                  className="w-full rounded border border-line-1 px-2 py-1 text-xs font-mono bg-surface-100"
                >
                  <option value="auto">Auto</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep Dive</option>
                </select>
              </div>
            )}
            {onTlpChange && (
              <div className="flex-1">
                <label className="mb-1 block text-mini font-mono font-medium text-muted">TLP</label>
                <select
                  value={tlp}
                  onChange={(e) => onTlpChange(e.target.value)}
                  className="w-full rounded border border-line-1 px-2 py-1 text-xs font-mono bg-surface-100"
                >
                  <option value="WHITE">WHITE</option>
                  <option value="GREEN">GREEN</option>
                  <option value="AMBER">AMBER</option>
                  <option value="RED">RED</option>
                </select>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
