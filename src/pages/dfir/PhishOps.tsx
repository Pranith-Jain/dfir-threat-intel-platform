import { useState, useCallback, useEffect } from 'react';
import { BackLink } from '../../components/BackLink';
import { CopyButton } from '../../components/dfir/CopyButton';
import {
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  Download,
  CheckCircle2,
  Circle,
  Shield,
  Link2,
  FileBox,
  User,
  Lock,
  ListTree,
  FileText,
} from 'lucide-react';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

type StepId = 1 | 2 | 3 | 4 | 5 | 6 | 7;

interface StepDef {
  id: StepId;
  label: string;
  icon: typeof Shield;
  title: string;
  description: string;
}

interface CheckItem {
  id: string;
  label: string;
  done: boolean;
  notes: string;
}

interface InvestigationState {
  currentStep: StepId;
  checklists: Record<StepId, CheckItem[]>;
  notes: Record<StepId, string>;
  startedAt: string;
}

const STEPS: StepDef[] = [
  {
    id: 1,
    label: 'Header Analysis',
    icon: Shield,
    title: 'Header Analysis',
    description: 'Extract and analyze email headers - From, Reply-To, Return-Path, SPF, DKIM, and DMARC verdicts.',
  },
  {
    id: 2,
    label: 'URL Triage',
    icon: Link2,
    title: 'URL Triage',
    description: 'Extract URLs, check reputation via urlscan preview, and evaluate domain age.',
  },
  {
    id: 3,
    label: 'Attachment Sandbox',
    icon: FileBox,
    title: 'Attachment Sandbox',
    description: 'Calculate file hashes, detect file type, and submit to sandbox for detonation.',
  },
  {
    id: 4,
    label: 'Identity Impact',
    icon: User,
    title: 'Identity Impact',
    description: 'Review Okta/M365 sessions, MFA events, and suspicious logins for the recipient.',
  },
  {
    id: 5,
    label: 'Containment',
    icon: Lock,
    title: 'Containment',
    description: 'Block sender, quarantine email, and disable compromised accounts.',
  },
  {
    id: 6,
    label: 'IOC Aggregation',
    icon: ListTree,
    title: 'IOC Aggregation',
    description: 'Consolidate all extracted IOCs - IPs, domains, URLs, hashes, email addresses.',
  },
  {
    id: 7,
    label: 'Closure',
    icon: FileText,
    title: 'Closure',
    description: 'Summarize findings, document notes, and export the investigation report.',
  },
];

const STORAGE_KEY = 'phishops-investigation';

function defaultChecklists(): Record<StepId, CheckItem[]> {
  return {
    1: [
      { id: 'h1', label: 'Extract From address and verify against display name', done: false, notes: '' },
      { id: 'h2', label: 'Check Reply-To and Return-Path for mismatch', done: false, notes: '' },
      { id: 'h3', label: 'Review SPF pass/fail verdict', done: false, notes: '' },
      { id: 'h4', label: 'Review DKIM signature and domain alignment', done: false, notes: '' },
      { id: 'h5', label: 'Review DMARC policy and disposition', done: false, notes: '' },
      { id: 'h6', label: 'Trace Received hop chain for origination IP', done: false, notes: '' },
    ],
    2: [
      { id: 'u1', label: 'Extract all URLs from email body', done: false, notes: '' },
      { id: 'u2', label: 'Submit URL to urlscan.io for reputation', done: false, notes: '' },
      { id: 'u3', label: 'Check domain age via WHOIS', done: false, notes: '' },
      { id: 'u4', label: 'Check domain against known blocklists', done: false, notes: '' },
      { id: 'u5', label: 'Check for URL obfuscation / redirect chains', done: false, notes: '' },
    ],
    3: [
      { id: 'a1', label: 'Calculate MD5 hash of attachment', done: false, notes: '' },
      { id: 'a2', label: 'Calculate SHA-256 hash of attachment', done: false, notes: '' },
      { id: 'a3', label: 'Detect true file type (magic bytes)', done: false, notes: '' },
      { id: 'a4', label: 'Submit hash to VirusTotal', done: false, notes: '' },
      { id: 'a5', label: 'Submit file to sandbox for detonation', done: false, notes: '' },
      { id: 'a6', label: 'Review sandbox behavioral summary', done: false, notes: '' },
    ],
    4: [
      { id: 'i1', label: 'Check Okta sign-in events for recipient', done: false, notes: '' },
      { id: 'i2', label: 'Review MFA acceptance / denial events', done: false, notes: '' },
      { id: 'i3', label: 'Check for suspicious geolocation logins', done: false, notes: '' },
      { id: 'i4', label: 'Review M365 Unified Audit Log for mail access', done: false, notes: '' },
      { id: 'i5', label: 'Check for inbox rule creation', done: false, notes: '' },
    ],
    5: [
      { id: 'c1', label: 'Block sender domain at email gateway', done: false, notes: '' },
      { id: 'c2', label: 'Quarantine phishing email from all recipients', done: false, notes: '' },
      { id: 'c3', label: 'Block malicious URLs at proxy', done: false, notes: '' },
      { id: 'c4', label: 'Disable compromised user accounts', done: false, notes: '' },
      { id: 'c5', label: 'Reset passwords for affected users', done: false, notes: '' },
      { id: 'c6', label: 'Revoke active sessions', done: false, notes: '' },
    ],
    6: [
      { id: 'ioc1', label: 'Collect IP addresses from headers and URLs', done: false, notes: '' },
      { id: 'ioc2', label: 'Collect domains from URLs and Return-Path', done: false, notes: '' },
      { id: 'ioc3', label: 'Collect full URLs with paths', done: false, notes: '' },
      { id: 'ioc4', label: 'Collect file hashes (MD5, SHA-256)', done: false, notes: '' },
      { id: 'ioc5', label: 'Collect email addresses involved', done: false, notes: '' },
      { id: 'ioc6', label: 'Tag IOCs with confidence and kill-chain phase', done: false, notes: '' },
    ],
    7: [
      { id: 'cl1', label: 'Write investigation summary', done: false, notes: '' },
      { id: 'cl2', label: 'Document timeline of events', done: false, notes: '' },
      { id: 'cl3', label: 'Tag incident category and severity', done: false, notes: '' },
      { id: 'cl4', label: 'Note lessons learned', done: false, notes: '' },
      { id: 'cl5', label: 'Export final report', done: false, notes: '' },
    ],
  };
}

function loadState(): InvestigationState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as InvestigationState;
  } catch (_catchErr) {
    console.error('loadState failed:', errMessage(_catchErr));
    /* ignore */
  }
  return null;
}

function saveState(s: InvestigationState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

const EXAMPLE_DATA: Record<StepId, { fields: Array<{ label: string; value: string }> }> = {
  1: {
    fields: [
      { label: 'From', value: '"Microsoft Security" <security@microsoft-verify.com>' },
      { label: 'Reply-To', value: 'phish-actor@evil-domain.xyz' },
      { label: 'Return-Path', value: 'bounce@evil-domain.xyz' },
      { label: 'SPF', value: 'FAIL (domain evil-domain.xyz does not designate 203.0.113.42 as sender)' },
      { label: 'DKIM', value: 'FAIL (signature domain mismatch: d=evil-domain.xyz)' },
      { label: 'DMARC', value: 'none (no policy - fallthrough)' },
    ],
  },
  2: {
    fields: [
      { label: 'URL 1', value: 'https://evil-domain.xyz/login.php?token=abc123' },
      { label: 'URL 2', value: 'https://evil-domain.xyz/collect.php' },
      { label: 'Domain Age', value: '12 days (registered 2026-05-28)' },
      { label: 'urlscan Verdict', value: 'MALICIOUS - flagged by 3 scanners' },
      { label: 'Redirect Chain', value: 'evil-domain.xyz → 203.0.113.42 → parked (sinkhole)' },
    ],
  },
  3: {
    fields: [
      { label: 'Filename', value: 'Invoice_June2026.docm' },
      { label: 'File Size', value: '246 KB' },
      { label: 'MD5', value: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' },
      { label: 'SHA-256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      {
        label: 'True Type',
        value: 'Microsoft Word Macro-Enabled Document (application/vnd.ms-word.document.macroenabled.12)',
      },
      { label: 'Sandbox Verdict', value: 'MALICIOUS - dropped Cobalt Strike beacon via macro' },
    ],
  },
  4: {
    fields: [
      { label: 'Recipient', value: 'john.doe@company.com' },
      { label: 'Okta Sessions', value: '2 active sessions (desktop + mobile) - no unusual IPs' },
      { label: 'MFA Events', value: '1 MFA push accepted at 14:32 UTC from IP 198.51.100.7 (unusual)' },
      { label: 'Suspicious Logins', value: '198.51.100.7 - no previous auth history for this user' },
      {
        label: 'Inbox Rules',
        value:
          '1 new rule created: "move to Junk" disabled; rule "Forward to phish@evil-domain.xyz" created at 14:33 UTC',
      },
    ],
  },
  5: {
    fields: [
      { label: 'Blocklist Action', value: 'evil-domain.xyz added to email gateway blocklist' },
      { label: 'URL Block', value: 'All URLs under evil-domain.xyz blocked at proxy (category: phishing)' },
      { label: 'Quarantine', value: '3 copies of the email quarantined (john.doe@, helpdesk@, admin@)' },
      { label: 'Account Status', value: 'john.doe@company.com - disabled, password reset forced' },
      { label: 'Sessions Revoked', value: 'All Okta sessions revoked; user required to re-authenticate' },
    ],
  },
  6: {
    fields: [
      { label: 'IPs', value: '203.0.113.42 (sending MTA), 198.51.100.7 (auth proxy)' },
      { label: 'Domains', value: 'evil-domain.xyz, microsoft-verify.com (spoofed)' },
      { label: 'URLs', value: 'https://evil-domain.xyz/login.php?token=abc123, https://evil-domain.xyz/collect.php' },
      {
        label: 'File Hashes',
        value:
          'MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6, SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      {
        label: 'Email Addresses',
        value:
          'security@microsoft-verify.com (spoofed sender), phish-actor@evil-domain.xyz (reply-to), john.doe@company.com (target)',
      },
      {
        label: 'Confidence Tags',
        value: 'HIGH - phishing kit detected, credential harvesting confirmed, sandbox detonation produced C2 beacon',
      },
    ],
  },
  7: {
    fields: [
      {
        label: 'Summary',
        value:
          'Targeted spear-phishing campaign impersonating Microsoft Security. Email bypassed SPF/DKIM/DMARC due to lax DMARC policy (none). User clicked link and entered credentials on phishing page. Attached .docm macro dropped Cobalt Strike. Quick containment prevented lateral movement.',
      },
      { label: 'Incident Category', value: 'Phishing → Credential Theft → Malware Dropper' },
      { label: 'Severity', value: 'HIGH (credential compromise + C2 beacon)' },
      {
        label: 'Timeline',
        value:
          '14:30 UTC - Email received. 14:32 UTC - User clicked link and entered credentials. 14:33 UTC - Inbox rule created. 14:35 UTC - Alert triggered. 14:40 UTC - Analyst begins triage. 15:00 UTC - Account disabled, email quarantined. 15:15 UTC - Containment complete.',
      },
      {
        label: 'Lessons Learned',
        value:
          '1. DMARC policy should be p=reject. 2. Users need better phishing awareness. 3. MFA geographic anomaly detection prevented further compromise.',
      },
    ],
  },
};

function buildReport(s: InvestigationState): string {
  const lines: string[] = [];
  const d = new Date(s.startedAt);
  lines.push('# PHISHOPS - Phishing Investigation Report');
  lines.push(`**Started:** ${d.toLocaleString()}`);
  lines.push('');
  for (const step of STEPS) {
    lines.push(`## ${step.id}. ${step.title}`);
    const items = s.checklists[step.id] ?? [];
    const done = items.filter((i) => i.done).length;
    lines.push(`Progress: ${done}/${items.length} checks completed`);
    for (const item of items) {
      lines.push(`- [${item.done ? 'x' : ' '}] ${item.label}${item.notes ? ` - ${item.notes}` : ''}`);
    }
    const note = s.notes[step.id];
    if (note?.trim()) {
      lines.push('');
      lines.push(`**Notes:** ${note.trim()}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export default function PhishOps(): JSX.Element {
  const [state, setState] = useState<InvestigationState>(() => {
    return (
      loadState() ?? {
        currentStep: 1 as StepId,
        checklists: defaultChecklists(),
        notes: {} as Record<StepId, string>,
        startedAt: new Date().toISOString(),
      }
    );
  });

  useEffect(() => {
    saveState(state);
  }, [state]);

  const totalChecklist = (step: StepId) => state.checklists[step] ?? [];
  const doneChecklist = (step: StepId) => totalChecklist(step).filter((i) => i.done).length;
  const totalAll = STEPS.reduce((a, s) => a + totalChecklist(s.id).length, 0);
  const doneAll = STEPS.reduce((a, s) => a + doneChecklist(s.id), 0);
  const pctAll = totalAll > 0 ? Math.round((doneAll / totalAll) * 100) : 0;

  const goStep = useCallback((next: StepId) => {
    setState((prev) => ({ ...prev, currentStep: next }));
  }, []);

  const toggleCheck = useCallback((step: StepId, itemId: string) => {
    setState((prev) => {
      const items = prev.checklists[step]?.map((c) => (c.id === itemId ? { ...c, done: !c.done } : c)) ?? [];
      return { ...prev, checklists: { ...prev.checklists, [step]: items } };
    });
  }, []);

  const updateNote = useCallback((step: StepId, id: string, val: string) => {
    setState((prev) => {
      const items = prev.checklists[step]?.map((c) => (c.id === id ? { ...c, notes: val } : c)) ?? [];
      return { ...prev, checklists: { ...prev.checklists, [step]: items } };
    });
  }, []);

  const updateStepNotes = useCallback((step: StepId, val: string) => {
    setState((prev) => ({
      ...prev,
      notes: { ...prev.notes, [step]: val },
    }));
  }, []);

  const reset = useCallback(() => {
    setState({
      currentStep: 1 as StepId,
      checklists: defaultChecklists(),
      notes: {} as Record<StepId, string>,
      startedAt: new Date().toISOString(),
    });
  }, []);

  const downloadReport = useCallback(() => {
    const blob = new Blob([buildReport(state)], { type: 'text/markdown' });
    downloadBlob(blob, `phishops-report-${Date.now()}.md`);
  }, [state]);

  const step = STEPS.find((s) => s.id === state.currentStep)!;
  const data = EXAMPLE_DATA[state.currentStep];
  const checklist = totalChecklist(state.currentStep);
  const doneCount = doneChecklist(state.currentStep);
  const prevStep = state.currentStep > 1 ? ((state.currentStep - 1) as StepId) : null;
  const nextStep = state.currentStep < 7 ? ((state.currentStep + 1) as StepId) : null;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Shield size={28} className="text-brand-600 dark:text-brand-400" /> PHISHOPS
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Guided Phishing Investigation - 7-step tracker with checklists, IOC aggregation, and export.
        </p>
      </div>

      <div className="surface-card p-6 mb-8">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 text-sm font-mono text-muted">
            <CheckCircle2 size={14} className="text-brand-500" />
            {doneAll} / {totalAll} checks ({pctAll}%)
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={reset}
              className="text-xs font-mono px-3 py-1.5 rounded-xl border border-line-2 text-muted hover:border-rose-400 hover:text-rose-600 dark:hover:text-rose-400 transition-colors inline-flex items-center gap-1.5"
            >
              <RotateCcw size={12} /> New Investigation
            </button>
            <button
              type="button"
              onClick={downloadReport}
              className="text-xs font-mono px-3 py-1.5 rounded-xl bg-brand-600 text-on-fill hover:bg-brand-500 transition-colors inline-flex items-center gap-1.5"
            >
              <Download size={12} /> Export Report
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 overflow-x-auto pb-2" role="tablist" aria-label="Investigation steps">
          {STEPS.map((s) => {
            const sDone = doneChecklist(s.id);
            const sTotal = totalChecklist(s.id).length;
            const active = s.id === state.currentStep;
            const complete = sDone === sTotal && sTotal > 0;
            return (
              <button
                key={s.id}
                type="button"
                onClick={() => goStep(s.id)}
                role="tab"
                aria-selected={active}
                className={`flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-mono font-semibold transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300 border border-brand-300/50 dark:border-brand-700/50'
                    : complete
                      ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 border border-emerald-300/50 dark:border-emerald-800/50'
                      : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-300/50'
                }`}
              >
                {complete ? (
                  <CheckCircle2 size={12} />
                ) : active ? (
                  <Circle size={12} />
                ) : (
                  <Circle size={12} className="opacity-40" />
                )}
                <span>{s.id}</span>
                <span className="hidden sm:inline">{s.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex items-center justify-between mb-6">
        <div>
          <span className="text-xs font-mono text-muted">Step {step.id} of 7</span>
        </div>
        <div className="flex items-center gap-3">
          {prevStep && (
            <button
              type="button"
              onClick={() => goStep(prevStep)}
              className="text-xs font-mono px-3 py-1.5 rounded-xl border border-line-2 text-muted hover:border-brand-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors inline-flex items-center gap-1.5"
            >
              <ChevronLeft size={12} /> Previous Step
            </button>
          )}
          {nextStep && (
            <button
              type="button"
              onClick={() => goStep(nextStep)}
              className="text-xs font-mono px-3 py-1.5 rounded-xl bg-brand-600 text-on-fill hover:bg-brand-500 transition-colors inline-flex items-center gap-1.5"
            >
              Next Step <ChevronRight size={12} />
            </button>
          )}
        </div>
      </div>

      <div className="animate-fade-in-up">
        <div className="surface-card p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <step.icon size={22} className="text-brand-600 dark:text-brand-400" />
            <div>
              <h2 className="text-xl font-display font-bold">{step.title}</h2>
              <p className="text-xs font-mono text-muted mt-1">{step.description}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {data.fields.map((f, i) => (
              <div key={i} className="flex items-start gap-2 p-3 rounded-xl bg-surface-200/30 border border-line-1">
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono font-semibold text-muted mb-0.5">{f.label}</div>
                  <div className="text-xs font-mono text-heading break-all">{f.value}</div>
                </div>
                <CopyButton value={f.value} title={`Copy ${f.label}`} />
              </div>
            ))}
          </div>
        </div>

        <div className="surface-card p-6 mb-6">
          <h3 className="font-display font-bold text-sm mb-4 flex items-center gap-2">
            <CheckCircle2 size={14} className="text-brand-600 dark:text-brand-400" />
            Checklist ({doneCount}/{checklist.length})
          </h3>
          <div className="space-y-3">
            {checklist.map((item) => (
              <div key={item.id} className="flex items-start gap-3">
                <button
                  type="button"
                  onClick={() => toggleCheck(state.currentStep, item.id)}
                  className={`mt-0.5 flex-shrink-0 w-4 h-4 rounded border-2 flex items-center justify-center transition-colors ${
                    item.done
                      ? 'bg-emerald-500 border-emerald-500 text-white'
                      : 'border-slate-300 dark:border-line-1 hover:border-brand-400'
                  }`}
                  aria-label={item.done ? `Uncheck ${item.label}` : `Check ${item.label}`}
                >
                  {item.done && <CheckCircle2 size={12} />}
                </button>
                <div className="flex-1 min-w-0">
                  <span
                    role="button"
                    tabIndex={0}
                    className={`text-sm font-mono cursor-pointer ${item.done ? 'line-through text-muted' : 'text-body'}`}
                    onClick={() => toggleCheck(state.currentStep, item.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleCheck(state.currentStep, item.id);
                      }
                    }}
                  >
                    {item.label}
                  </span>
                  <input
                    type="text"
                    value={item.notes}
                    onChange={(e) => updateNote(state.currentStep, item.id, e.target.value)}
                    placeholder="Add notes..."
                    className="w-full mt-1 text-xs font-mono bg-transparent border-b border-dashed border-line-2 text-muted focus:outline-none focus:border-brand-400 placeholder:text-muted dark:placeholder:text-muted pb-0.5"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="surface-card p-6">
          <h3 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
            <FileText size={14} className="text-brand-600 dark:text-brand-400" />
            Step Notes
          </h3>
          <textarea
            value={state.notes[state.currentStep] ?? ''}
            onChange={(e) => updateStepNotes(state.currentStep, e.target.value)}
            placeholder="Document findings, observations, and next steps for this phase..."
            rows={4}
            className="w-full text-sm font-mono bg-surface-200/30 border border-line-1 rounded-xl p-3 text-body focus:outline-none focus:ring-1 focus:ring-brand-500 placeholder:text-muted dark:placeholder:text-muted"
          />
        </div>
      </div>
    </div>
  );
}
