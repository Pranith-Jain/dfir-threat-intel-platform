import { useState, useEffect, useCallback } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Plus, Trash2, FileDown, Edit2, X, ExternalLink, ScrollText } from 'lucide-react';
import { CopyButton } from '../../components/ui/CopyButton';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

interface YaraRule {
  id: string;
  name: string;
  author: string;
  description: string;
  category: string;
  rule: string;
  created: string;
  modified: string;
  tags: string[];
}

const STORAGE_KEY = 'dfir-yara-rules:v1';

/**
 * Starter rule. Detects the PowerShell encoded-command flag pattern as a
 * concrete, low-risk example - common in initial-access tradecraft and a
 * good first hit a new analyst will recognise. Replace the rule body
 * before saving; the meta block documents the intent so the rule
 * remains readable in shared rule packs.
 */
const TEMPLATE_RULE = `rule PowerShellEncodedCommand
{
    meta:
        author = "analyst"
        description = "Detects PowerShell launched with -EncodedCommand or -enc - common in initial-access tradecraft. Pair with a parent-process filter in your hunting query."
        date = "${new Date().toISOString().slice(0, 10)}"
        reference = "MITRE T1059.001"
    strings:
        $a1 = "powershell" nocase
        $a2 = "-EncodedCommand" nocase
        $a3 = " -enc " nocase
    condition:
        $a1 and ($a2 or $a3)
}`;

const DEFAULT_CATEGORIES = ['malware', 'phishing', 'ransomware', 'c2', 'suspicious', 'custom'];

function loadRules(): YaraRule[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (_catchErr) {
    console.error('loadRules failed:', errMessage(_catchErr));
    return [];
  }
}

export default function YaraManager(): JSX.Element {
  const [rules, setRules] = useState<YaraRule[]>(() => loadRules());
  const [editingId, setEditingId] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
    } catch (_catchErr) {
      console.error('YaraManager failed:', errMessage(_catchErr));
      /* quota / private mode */
    }
  }, [rules]);

  const createRule = useCallback(() => {
    const id = `yara_${Date.now()}`;
    const newRule: YaraRule = {
      id,
      name: 'untitled_rule',
      author: 'analyst',
      description: '',
      category: 'custom',
      rule: TEMPLATE_RULE,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      tags: [],
    };
    setRules((prev) => [newRule, ...prev]);
    setEditingId(id);
  }, []);

  const updateRule = useCallback((id: string, updates: Partial<YaraRule>) => {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, ...updates, modified: new Date().toISOString() } : r)));
  }, []);

  const deleteRule = useCallback(
    (id: string) => {
      if (!window.confirm('Delete this rule?')) return;
      setRules((prev) => prev.filter((r) => r.id !== id));
      if (editingId === id) setEditingId(null);
    },
    [editingId]
  );

  const exportAll = useCallback(() => {
    const text = rules.map((r) => r.rule).join('\n\n');
    const blob = new Blob([text], { type: 'text/plain' });
    downloadBlob(blob, 'yara-rules-export.yara');
  }, [rules]);

  const filtered = filter
    ? rules.filter(
        (r) =>
          r.name.toLowerCase().includes(filter.toLowerCase()) ||
          r.description.toLowerCase().includes(filter.toLowerCase()) ||
          r.tags.some((t) => t.toLowerCase().includes(filter.toLowerCase()))
      )
    : rules;

  const categories = [...new Set([...DEFAULT_CATEGORIES, ...rules.map((r) => r.category)])];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up flex items-center justify-between mb-8 flex-wrap gap-3">
        <div>
          <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
            <ScrollText size={28} className="text-brand-600 dark:text-brand-400" /> YARA Rule Manager
          </h1>
          <p className="text-muted">{rules.length} rules stored locally</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={createRule}
            className="inline-flex items-center gap-1.5 bg-brand-500 px-3 py-1.5 font-mono text-xs font-medium text-surface-page transition-colors duration-enter hover:brightness-110"
          >
            <Plus className="h-3 w-3" /> new rule
          </button>
          {rules.length > 0 && (
            <button
              type="button"
              onClick={exportAll}
              className="inline-flex items-center gap-1.5 border border-line-1 px-3 py-1.5 font-mono text-xs text-muted transition-colors duration-enter hover:border-brand-500 hover:text-brand-600 dark:hover:text-brand-400"
            >
              <FileDown className="h-3 w-3" /> export all
            </button>
          )}
        </div>
      </div>

      <RansomwareIntelPanels />

      <div className="mb-6">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by name, description, or tag…"
          className="w-full px-3 py-2 bg-surface-100 border border-line-1 font-mono text-sm text-heading placeholder:text-muted focus:outline-none"
        />
      </div>

      {filtered.length === 0 && (
        <div className="border border-line-1 p-8 text-center">
          <p className="font-mono text-sm text-muted">
            {rules.length === 0 ? 'No rules yet. Create one to get started.' : 'No rules match your filter.'}
          </p>
        </div>
      )}

      <div className="space-y-3">
        {filtered.map((rule) => (
          <div key={rule.id} className="border border-line-1 bg-surface-200">
            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-line-1">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-medium text-heading">{rule.name}</span>
                  <span className="font-mono text-micro tracking-[0.1em] text-brand-600 dark:text-brand-400 uppercase border border-brand-500/20 bg-brand-50 dark:bg-brand-950/30 px-1">
                    {rule.category}
                  </span>
                </div>
                {rule.description && <p className="text-xs text-muted mt-0.5">{rule.description}</p>}
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => setEditingId(editingId === rule.id ? null : rule.id)}
                  className="p-1.5 text-muted hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                  aria-label="Edit"
                >
                  {editingId === rule.id ? <X className="h-3.5 w-3.5" /> : <Edit2 className="h-3.5 w-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => deleteRule(rule.id)}
                  className="p-1.5 text-muted hover:text-rose-700 dark:text-rose-400 transition-colors"
                  aria-label="Delete"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {editingId === rule.id && (
              <div className="p-4 space-y-3 border-b border-line-1">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor={`yara-name-${rule.id}`} className="mono-label block mb-1">
                      Name
                    </label>
                    <input
                      id={`yara-name-${rule.id}`}
                      type="text"
                      value={rule.name}
                      onChange={(e) => updateRule(rule.id, { name: e.target.value })}
                      className="w-full px-2 py-1.5 bg-surface-100 border border-line-1 font-mono text-xs text-heading focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor={`yara-cat-${rule.id}`} className="mono-label block mb-1">
                      Category
                    </label>
                    <select
                      id={`yara-cat-${rule.id}`}
                      value={rule.category}
                      onChange={(e) => updateRule(rule.id, { category: e.target.value })}
                      className="w-full px-2 py-1.5 bg-surface-100 border border-line-1 font-mono text-xs text-heading focus:outline-none"
                    >
                      {categories.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div>
                  <label htmlFor={`yara-desc-${rule.id}`} className="mono-label block mb-1">
                    Description
                  </label>
                  <input
                    id={`yara-desc-${rule.id}`}
                    type="text"
                    value={rule.description}
                    onChange={(e) => updateRule(rule.id, { description: e.target.value })}
                    className="w-full px-2 py-1.5 bg-surface-100 border border-line-1 font-mono text-xs text-heading focus:outline-none"
                  />
                </div>
              </div>
            )}

            <details className="group">
              <summary className="px-4 py-2 font-mono text-micro text-muted cursor-pointer hover:text-heading transition-colors select-none">
                rule source ({rule.rule.split('\n').length} lines)
              </summary>
              <pre className="px-4 pb-3 pt-1 overflow-x-auto text-mini font-mono text-muted leading-relaxed whitespace-pre">
                {rule.rule}
              </pre>
            </details>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── ransomware.live attack → detection pivot ─────────────────────────────
 * Two read-only panels backed by the authenticated ransomware.live proxy:
 * recent ransomware cyber-attacks, and per-group YARA. Picking an attack's
 * group loads that group's YARA rules. The local rule manager above is
 * untouched - this is additive context, not a replacement.
 */

interface RlAttack {
  group: string;
  victim: string;
  date?: string;
  url?: string;
}

function rec(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function s(o: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return undefined;
}
function rlList(j: unknown): unknown[] {
  const data = rec(j) ? ((j as { data?: unknown }).data ?? j) : j;
  if (Array.isArray(data)) return data;
  if (rec(data)) {
    for (const k of ['victims', 'attacks', 'results', 'data', 'items']) {
      if (Array.isArray(data[k])) return data[k] as unknown[];
    }
  }
  return [];
}

/** Extract YARA text from the (undocumented) /rl/yara/:group payload. */
function rlYaraText(j: unknown): string {
  const data = rec(j) ? ((j as { data?: unknown }).data ?? j) : j;
  if (typeof data === 'string') return data;
  if (Array.isArray(data)) {
    return data
      .map((x) => (typeof x === 'string' ? x : rec(x) ? (s(x, ['rule', 'yara', 'content', 'raw']) ?? '') : ''))
      .filter(Boolean)
      .join('\n\n');
  }
  if (rec(data)) {
    const t = s(data, ['rule', 'yara', 'content', 'raw']);
    if (t) return t;
  }
  return JSON.stringify(data, null, 2);
}

function RansomwareIntelPanels(): JSX.Element {
  const [attacks, setAttacks] = useState<RlAttack[] | null>(null);
  const [attackErr, setAttackErr] = useState<string | null>(null);
  const [group, setGroup] = useState('');
  const [yara, setYara] = useState<string | null>(null);
  const [yaraLoading, setYaraLoading] = useState(false);
  const [yaraErr, setYaraErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/v1/rl/cyberattacks')
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!alive) return;
        if (!ok) {
          setAttackErr((j as { error?: string }).error ?? 'request failed');
          return;
        }
        const rows = rlList(j)
          .filter(rec)
          .map((o) => ({
            group: s(o, ['group', 'group_name', 'gang']) ?? 'unknown',
            victim: s(o, ['victim', 'title', 'post_title', 'domain', 'company']) ?? '-',
            date: s(o, ['discovered', 'published', 'date', 'added']),
            url: s(o, ['url', 'link', 'source', 'press']),
          }))
          .slice(0, 40);
        setAttacks(rows);
      })
      .catch((e: Error) => alive && setAttackErr(e.message));
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (!group) return;
    let alive = true;
    setYaraLoading(true);
    setYaraErr(null);
    setYara(null);
    fetch(`/api/v1/rl/yara/${encodeURIComponent(group)}`)
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!alive) return;
        if (!ok) {
          setYaraErr((j as { error?: string }).error ?? 'request failed');
          return;
        }
        const text = rlYaraText(j);
        setYara(text.trim() || '(no YARA rules published for this group)');
      })
      .catch((e: Error) => alive && setYaraErr(e.message))
      .finally(() => alive && setYaraLoading(false));
    return () => {
      alive = false;
    };
  }, [group]);

  const groups = [...new Set((attacks ?? []).map((a) => a.group))].filter((g) => g && g !== 'unknown').sort();

  return (
    <section className="mb-8 border border-line-1 rounded-xl overflow-hidden">
      <div className="bg-surface-200 px-4 py-2.5 border-b border-line-1">
        <h2 className="font-mono text-sm font-semibold text-heading">ransomware.live · attack → detection</h2>
        <p className="font-mono text-mini text-muted mt-0.5">
          Recent ransomware cyber-attacks + that group's published YARA. Read-only context; your local rules below are
          separate.
        </p>
      </div>
      <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-line-1">
        {/* Recent attacks */}
        <div className="p-4">
          <h3 className="font-mono text-xs uppercase tracking-wider text-muted mb-2">Recent cyber-attacks</h3>
          {attackErr && (
            <p className="font-mono text-mini text-amber-600 dark:text-amber-400">
              {attackErr === 'not_configured' ? 'ransomware.live PRO key not configured.' : `unavailable: ${attackErr}`}
            </p>
          )}
          {!attackErr && !attacks && <p className="font-mono text-mini text-muted">loading…</p>}
          {attacks && attacks.length > 0 && (
            <ul className="space-y-1.5 max-h-[420px] overflow-y-auto">
              {attacks.map((a, i) => (
                <li key={i} className="font-mono text-mini flex items-baseline gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => setGroup(a.group)}
                    className={`px-1.5 py-0.5 rounded border ${
                      group === a.group
                        ? 'border-brand-500 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                        : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:border-brand-500'
                    }`}
                    title="Load this group's YARA →"
                  >
                    {a.group}
                  </button>
                  <span className="text-muted truncate flex-1 min-w-0" title={a.victim}>
                    {a.victim}
                  </span>
                  {a.date && <span className="text-muted text-micro">{a.date.slice(0, 10)}</span>}
                  {a.url && (
                    <a
                      href={sanitizeUrl(a.url) || undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-0.5 transition-colors"
                    >
                      <ExternalLink size={9} />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
          {attacks && attacks.length === 0 && !attackErr && (
            <p className="font-mono text-mini text-muted">No recent attacks in the feed window.</p>
          )}
        </div>

        {/* Per-group YARA */}
        <div className="p-4">
          <div className="flex items-center justify-between gap-2 mb-2">
            <h3 className="font-mono text-xs uppercase tracking-wider text-muted">Group YARA</h3>
            <div className="flex items-center gap-1.5">
              <select
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                className="font-mono text-mini px-2 py-1 bg-surface-100 border border-line-1"
                aria-label="Select ransomware group"
              >
                <option value="">select group…</option>
                {groups.map((g) => (
                  <option key={g} value={g}>
                    {g}
                  </option>
                ))}
              </select>
              {yara && (
                <CopyButton
                  text={yara}
                  variant="ghost"
                  size="sm"
                  label="Copy YARA"
                  className="shrink-0 border border-line-1"
                />
              )}
            </div>
          </div>
          {!group && <p className="font-mono text-mini text-muted">Pick a group (or click one on the left).</p>}
          {group && yaraLoading && <p className="font-mono text-mini text-muted">loading {group} YARA…</p>}
          {yaraErr && (
            <p className="font-mono text-mini text-amber-600 dark:text-amber-400">
              {yaraErr === 'not_configured' ? 'ransomware.live PRO key not configured.' : `unavailable: ${yaraErr}`}
            </p>
          )}
          {yara && !yaraLoading && (
            <pre className="bg-surface-200 border border-line-1 p-3 overflow-auto font-mono text-mini text-body max-h-[420px]">
              {yara}
            </pre>
          )}
        </div>
      </div>
    </section>
  );
}
