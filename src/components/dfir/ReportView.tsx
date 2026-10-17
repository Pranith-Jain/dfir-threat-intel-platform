/**
 * ReportView - structured renderer for the DFIR agent / Copilot report.
 *
 * Takes the prose report (markdown) + the structured action card produced
 * by the synthesizer, and renders:
 *   - A severity banner with confidence + posture + TLP
 *   - The headline verdict
 *   - The executive summary
 *   - A stakeholder filter chip row (CTI / SOC / IR / VMGT / RED / AWARE / EXEC)
 *     that hides the prose sections not relevant to the selected team
 *   - Key findings (with severity colour)
 *   - Threat context (markdown body)
 *   - An IOC table (parsed from the action card)
 *   - A MITRE table (tactic → technique → detection)
 *   - A Diamond Model card (if the LLM filled ≥2 vertices)
 *   - An actions checklist (stakeholder-tagged)
 *   - A PIR list with business outcomes
 *   - A "Next Actions" row: Generate Hunt Queries / Generate YARA / Export
 *     MITRE Navigator / Copy STIX. These call the existing agent tools
 *     against the report context.
 *
 * The prose body keeps its full markdown rendering. Code fences (KQL,
 * Splunk, YARA) are highlighted. The "action-card" and "stix" code
 * blocks are stripped - the UI has structured components for those.
 */
import { useMemo, useState, lazy, Suspense } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Bug,
  Clock,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Code2,
  Copy,
  Database,
  Share2,
  Diamond,
  ExternalLink,
  FileText,
  Flag,
  Info,
  Link2,
  Loader2,
  Map as MapIcon,
  MessageSquare,
  Network,
  Shield,
  Sparkles,
  Target,
  Terminal,
  Users,
} from 'lucide-react';
import { extractStixBundle, StixRelationshipGraph, StixObjectTable } from '../StixBundleViewer';
import { Modal } from '../ui/Modal';

// Lazy-loaded: @xyflow/react is ~133KB and only needed when a report has a
// relationship graph. Mirrors the StixGraph lazy pattern.
const RelationshipGraph = lazy(() => import('./RelationshipGraph'));
import type {
  Stakeholder,
  ReportActionCard,
  ReportIoc,
  ReportMitre,
  ReportDiamond,
  ReportPir,
  ReportActionItem,
} from './report-view-types';
import { buildShareMarkdown, renderMarkdown } from './report-view-helpers';
import { SEVERITY_COLORS } from './report-view-types';
import { downloadBlob } from '../../lib/download';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';
export type {
  Severity,
  Stakeholder,
  ReportActionCard,
  ReportIoc,
  ReportMitre,
  ReportDiamond,
  ReportPir,
  ReportActionItem,
} from './report-view-types';
export { SEVERITY_COLORS } from './report-view-types';

interface ReportViewProps {
  report: string;
  actionCard?: ReportActionCard;
  /** Self-correction version history (versions + before/after diff summary). */
  reportVersioning?: {
    versions: Array<{ version: number; qualityScore: number; modelUsed: string; reason: string }>;
    diff?: {
      fromVersion: number;
      toVersion: number;
      fromScore: number;
      toScore: number;
      additions: number;
      deletions: number;
    };
  };
  /** Query that produced the report - used to call the action buttons. */
  query?: string;
  /** Optional: invoked when the user clicks an action button. The parent
   *  wires this to the existing tool endpoints. */
  onGenerateHuntingQueries?: () => Promise<{ tool: string; data: unknown } | null>;
  onGenerateYaraRule?: () => Promise<{ tool: string; data: unknown } | null>;
  /** Optional callback to open the Copilot pre-seeded with a
   *  follow-up question. The DFIR Agent page wires this to navigate to
   *  /threatintel/tools/copilot?q=... */
  onDrillDeeper?: (question: string) => void;
}

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

const TLP_COLORS: Record<string, string> = {
  CLEAR: 'border-emerald-400 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300',
  GREEN: 'border-emerald-400 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300',
  AMBER: 'border-amber-400 bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-300',
  RED: 'border-rose-400 bg-rose-50 text-rose-700 dark:bg-rose-950/30 dark:text-rose-300',
};

const STAKEHOLDER_META: Record<Stakeholder, { label: string; color: string }> = {
  cti: { label: 'CTI', color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' },
  soc: { label: 'SOC', color: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300' },
  ir: { label: 'IR', color: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300' },
  vuln: { label: 'VMGT', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' },
  redteam: { label: 'RED', color: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300' },
  appsec: { label: 'APPSEC', color: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300' },
  awareness: { label: 'AWARE', color: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-300' },
  exec: { label: 'EXEC', color: 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300' },
  legal: { label: 'LEGAL', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300' },
  tprm: { label: 'TPRM', color: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300' },
};

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/** Render simple markdown to HTML (headings, bullets, bold, code, tables, kql/sigma/splunk blocks). */

// ─────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────

/** Renders the structured BLUF header parsed from the synthesizer's
 *  \`\`\`report-header block. Feeds the hero card at the top of the report. */
function BlufPanel({ header }: { header: NonNullable<ReportActionCard['reportHeader']> }): JSX.Element {
  const sev = header.severity;
  const sevColor = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS['medium'];
  const postureColor: Record<string, string> = {
    active: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
    'post-exploit': 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
    reconnaissance: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    informational: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-slate-300',
    unknown: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-slate-300',
  };
  return (
    <div className={`rounded-xl p-4 ring-1 ${sevColor.ring} ${sevColor.bg} mb-4`}>
      <div className="flex flex-wrap items-start gap-2 mb-2">
        <span className={`px-2 py-0.5 rounded font-mono font-bold text-xs ${sevColor.pill}`}>{sev.toUpperCase()}</span>
        <span
          className={`px-1.5 py-0.5 rounded border text-micro font-mono uppercase tracking-wider ${TLP_COLORS[header.tlp] ?? TLP_COLORS['AMBER']}`}
        >
          TLP:{header.tlp}
        </span>
        <span
          className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold uppercase tracking-wider ${postureColor[header.posture] ?? postureColor['unknown']}`}
        >
          {header.posture}
        </span>
        {header.time_to_act && (
          <span className="px-1.5 py-0.5 rounded text-micro font-mono font-bold bg-surface-100 text-white dark:bg-surface-300 dark:text-heading inline-flex items-center gap-1">
            <Clock size={9} /> Time to act: {header.time_to_act}
          </span>
        )}
        {(header.actor || header.campaign) && (
          <span className="px-1.5 py-0.5 rounded text-micro font-mono bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300">
            {header.actor ? `Actor: ${header.actor}` : `Campaign: ${header.campaign}`}
          </span>
        )}
      </div>
      <p className={`text-base font-semibold ${sevColor.text} leading-snug`}>{header.headline}</p>
      <p className={`text-sm mt-2 ${sevColor.text} leading-relaxed`}>
        <span className="font-bold uppercase tracking-wider text-xs mr-1">BLUF:</span>
        {header.bluf}
      </p>
      {header.key_takeaway && (
        <p className="text-xs text-muted mt-2 italic">
          <span className="font-bold not-italic uppercase tracking-wider mr-1">Business impact:</span>
          {header.key_takeaway}
        </p>
      )}
      {header.primary_indicator && (
        <div className="mt-2 flex items-center gap-1.5 text-xs">
          <span className="text-micro font-mono uppercase tracking-wider text-muted">Primary IOC:</span>
          <code className="px-1.5 py-0.5 rounded bg-surface-300 text-heading font-mono text-xs">
            {header.primary_indicator.type}: {header.primary_indicator.value}
          </code>
        </div>
      )}
    </div>
  );
}

/** Renders the CVE metadata block (KEV, CVSS, EPSS, exploit status, actors)
 *  when the synthesizer extracted it from the tool data. Sits right after
 *  the BLUF panel so the analyst sees the at-a-glance risk numbers first. */
function CveMetaCard({ card }: { card: ReportActionCard }): JSX.Element | null {
  const hasAny =
    card.kev ||
    card.cvss?.score != null ||
    card.epss?.score != null ||
    (card.threat_actors && card.threat_actors.length > 0) ||
    card.exploit_status ||
    card.ransomware_use ||
    card.patch_url;
  if (!hasAny) return null;

  const cvssSeverityColor = (sev: string | null | undefined): string => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300';
      case 'HIGH':
        return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300';
      case 'LOW':
        return 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300';
      default:
        return 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted';
    }
  };

  const exploitStatusColor = (s: string | null | undefined): string => {
    switch (s) {
      case 'in-the-wild':
        return 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300';
      case 'weaponized':
        return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300';
      case 'poc-public':
        return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300';
      default:
        return 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted';
    }
  };

  return (
    <div className="rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/30 dark:bg-rose-950/20 p-3 mb-4">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-mini font-mono uppercase tracking-wider text-rose-700 dark:text-rose-300 flex items-center gap-1.5">
          <Bug size={12} /> CVE Intelligence
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {card.cvss?.score != null && (
          <div className="rounded border border-line-1 bg-surface-100 p-2">
            <div className="text-micro font-mono uppercase tracking-wider text-muted">CVSS v3.1</div>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="text-xl font-bold text-heading">{card.cvss.score.toFixed(1)}</span>
              <span
                className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${cvssSeverityColor(card.cvss.severity)}`}
              >
                {card.cvss.severity ?? '-'}
              </span>
            </div>
            {card.cvss.vector && (
              <code className="text-micro font-mono text-muted break-all">
                {card.cvss.vector.slice(0, 60)}
                {card.cvss.vector.length > 60 ? '…' : ''}
              </code>
            )}
          </div>
        )}
        {card.epss?.score != null && (
          <div className="rounded border border-line-1 bg-surface-100 p-2">
            <div className="text-micro font-mono uppercase tracking-wider text-muted">EPSS</div>
            <div className="text-xl font-bold text-heading mt-0.5">{(card.epss.score * 100).toFixed(1)}%</div>
            {card.epss.percentile != null && (
              <div className="text-micro font-mono text-muted">
                P{(card.epss.percentile * 100).toFixed(0)} percentile
              </div>
            )}
          </div>
        )}
        <div className="rounded border border-line-1 bg-surface-100 p-2">
          <div className="text-micro font-mono uppercase tracking-wider text-muted">CISA KEV</div>
          {card.kev ? (
            <>
              <div className="flex items-center gap-1 mt-0.5">
                <AlertOctagon size={14} className="text-rose-600 dark:text-rose-400" />
                <span className="text-sm font-bold text-rose-700 dark:text-rose-300">Listed</span>
              </div>
              {card.kev_date && <div className="text-micro font-mono text-muted">since {card.kev_date}</div>}
            </>
          ) : (
            <div className="text-sm text-muted mt-0.5">Not listed</div>
          )}
        </div>
        <div className="rounded border border-line-1 bg-surface-100 p-2">
          <div className="text-micro font-mono uppercase tracking-wider text-muted">Exploit</div>
          {card.exploit_status ? (
            <span
              className={`inline-block mt-0.5 px-1.5 py-0.5 rounded text-micro font-mono font-bold uppercase ${exploitStatusColor(card.exploit_status)}`}
            >
              {card.exploit_status.replace(/-/g, ' ')}
            </span>
          ) : (
            <div className="text-sm text-muted mt-0.5">No public PoC</div>
          )}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
        {card.threat_actors && card.threat_actors.length > 0 && (
          <div className="flex items-center gap-1.5">
            <Users size={11} className="text-muted" />
            <span className="text-micro font-mono uppercase tracking-wider text-muted">Actors:</span>
            {card.threat_actors.map((a) => (
              <span
                key={a}
                className="px-1.5 py-0.5 rounded text-micro font-mono bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300"
              >
                {a}
              </span>
            ))}
          </div>
        )}
        {card.ransomware_use && (
          <span
            className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${card.ransomware_use === 'Known' ? 'bg-rose-200 text-rose-900 dark:bg-rose-900/60 dark:text-rose-200' : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'}`}
          >
            Ransomware: {card.ransomware_use}
          </span>
        )}
        {card.patch_url && (
          <a
            href={sanitizeUrl(card.patch_url) || undefined}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 rounded text-micro font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            Vendor advisory <ExternalLink size={9} />
          </a>
        )}
      </div>
    </div>
  );
}

function SeverityBanner({ card }: { card: ReportActionCard }): JSX.Element {
  const c = SEVERITY_COLORS[card.severity];
  const sev = card.severity.toUpperCase();
  return (
    <div className={`rounded-xl p-4 ${c.bg} ring-1 ${c.ring} mb-4`}>
      <div className="flex flex-wrap items-start gap-3">
        <span className={`px-2.5 py-1 rounded font-mono font-bold text-sm ${c.pill}`}>{sev}</span>
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold ${c.text} leading-relaxed`}>{card.verdict.headline}</p>
          {card.verdict.confidence_rationale && (
            <p className="text-xs text-muted mt-1">{card.verdict.confidence_rationale}</p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className={`px-1.5 py-0.5 rounded border text-micro font-mono uppercase tracking-wider ${TLP_COLORS[card.verdict.tlp] ?? TLP_COLORS['AMBER']}`}
          >
            TLP:{card.verdict.tlp}
          </span>
          <span className="px-1.5 py-0.5 rounded border border-line-2 text-micro font-mono uppercase tracking-wider text-muted">
            {card.verdict.posture}
          </span>
          <span className="px-1.5 py-0.5 rounded border border-line-2 text-micro font-mono uppercase tracking-wider text-muted">
            {card.verdict.confidence}
          </span>
          {card.kev && (
            <span className="px-1.5 py-0.5 rounded border border-rose-400 bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-300 text-micro font-mono font-bold uppercase tracking-wider">
              KEV
            </span>
          )}
          {card.ransomware && (
            <span className="px-1.5 py-0.5 rounded border border-amber-400 bg-amber-100 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300 text-micro font-mono font-bold uppercase tracking-wider">
              RANSOMWARE
            </span>
          )}
          {card.attributed && (
            <span className="px-1.5 py-0.5 rounded border border-indigo-400 bg-indigo-100 text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-300 text-micro font-mono font-bold uppercase tracking-wider">
              ATTRIBUTED
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function IocTable({ iocs }: { iocs: ReportIoc[] }): JSX.Element | null {
  if (iocs.length === 0) return null;
  const confColor: Record<string, string> = {
    Confirmed: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
    Probable: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    Possible: 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted',
  };
  // Type-color map - gives the "Type" column a quick visual signal that
  // matches the indicator's nature (file hash = rose, domain = cyan, etc.).
  const typeColor: Record<string, string> = {
    ipv4: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300',
    ipv6: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300',
    domain: 'bg-sky-100 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300',
    url: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
    hash: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
    email: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-300',
    cve: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    actor: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
    malware: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
  };
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Database size={12} /> Indicators ({iocs.length})
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left">
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1 w-20">
                Type
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1">
                Value
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1 w-24">
                Confidence
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1 w-32">
                Source
              </th>
              <th className="px-3 py-1.5 w-10 border-b border-line-1"></th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((i, idx) => {
              // The IOCs list can contain duplicate (type, value) pairs from
              // multiple sources (e.g. domain pulled in by both VirusTotal
              // and Webamon). Build a unique key by appending a counter only
              // when we have already seen the same value, so React does not
              // log a key-collision warning and the row can be expanded /
              // edited independently.
              const seen = new Set<string>();
              for (let k = 0; k < idx; k++) {
                const prev = iocs[k];
                if (prev) seen.add(`${prev.type}|${prev.value}`);
              }
              const sig = `${i.type}|${i.value}`;
              let n = 1;
              while (seen.has(sig)) n++;
              const key = n > 1 ? `${i.type}-${i.value}-${n}` : `${i.type}-${i.value}`;
              return (
                <tr key={key} className="border-b border-line-1 hover:bg-surface-200 dark:hover:bg-input-200/40">
                  <td className="px-3 py-1.5">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-micro font-mono font-bold uppercase ${typeColor[i.type] ?? 'bg-slate-100 text-slate-500 dark:bg-surface-300 dark:text-muted'}`}
                    >
                      {i.type}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-sm break-all">{i.value}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${confColor[i.confidence] ?? confColor['Possible']}`}
                    >
                      {i.confidence}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-mini text-muted">{i.source ?? '-'}</td>
                  <td className="px-3 py-1.5">
                    <CopyButton text={i.value} label="Copy" />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1 text-mini font-mono text-muted hover:text-brand-600 dark:hover:text-brand-400"
    >
      {copied ? <CheckCircle2 size={11} /> : <Copy size={11} />} {copied ? 'Copied' : label}
    </button>
  );
}

function MitreTable({ mitre }: { mitre: ReportMitre[] }): JSX.Element | null {
  if (mitre.length === 0) return null;
  // Group by tactic
  const byTactic = new Map<string, ReportMitre[]>();
  for (const m of mitre) {
    const k = m.tactic ?? 'Other';
    if (!byTactic.has(k)) byTactic.set(k, []);
    byTactic.get(k)!.push(m);
  }
  const detColor: Record<string, string> = {
    yara: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
    sigma: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
    kql: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300',
    splunk: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    none: 'bg-slate-100 text-slate-500 dark:bg-surface-300 dark:text-muted',
  };
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Target size={12} /> MITRE ATT&CK ({mitre.length} technique{mitre.length === 1 ? '' : 's'})
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left">
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1">
                Tactic
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1 w-24">
                ID
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1">
                Name
              </th>
              <th className="px-3 py-1.5 font-mono text-micro uppercase tracking-wider text-muted border-b border-line-1 w-20">
                Detection
              </th>
            </tr>
          </thead>
          <tbody>
            {[...byTactic.entries()].map(([tactic, items]) =>
              items.map((m, idx) => (
                <tr key={`${m.id}-${idx}`} className="border-b border-line-1">
                  {idx === 0 && (
                    <td className="px-3 py-1.5 font-mono text-sm text-body align-top" rowSpan={items.length}>
                      {tactic}
                    </td>
                  )}
                  <td className="px-3 py-1.5 font-mono text-mini text-muted">
                    <a
                      href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-0.5 transition-colors"
                    >
                      {m.id} <ExternalLink size={9} />
                    </a>
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="text-sm">{m.name ?? '-'}</div>
                    {m.evidence && <div className="text-xs text-muted mt-0.5">{m.evidence}</div>}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${detColor[m.detection ?? 'none'] ?? detColor['none']}`}
                    >
                      {(m.detection ?? 'none').toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DiamondModelCard({ diamond }: { diamond: ReportDiamond | undefined }): JSX.Element | null {
  if (!diamond) return null;
  const filled = [diamond.adversary, diamond.capability?.length, diamond.infrastructure?.length, diamond.victim].filter(
    Boolean
  ).length;
  if (filled < 2) return null;
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Diamond size={12} /> Diamond Model
      </div>
      <div className="grid grid-cols-2 gap-px bg-track">
        <DiamondQuadrant title="Adversary" value={diamond.adversary} />
        <DiamondQuadrant title="Capability" items={diamond.capability} />
        <DiamondQuadrant title="Infrastructure" items={diamond.infrastructure} />
        <DiamondQuadrant title="Victim" value={diamond.victim} />
      </div>
    </div>
  );
}

function DiamondQuadrant({ title, value, items }: { title: string; value?: string; items?: string[] }): JSX.Element {
  return (
    <div className="bg-surface-100 p-3">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">{title}</div>
      {value && <div className="text-sm text-body">{value}</div>}
      {items && items.length > 0 && (
        <ul className="space-y-0.5">
          {items.map((it, idx) => (
            <li key={idx} className="text-sm font-mono text-body break-all">
              • {it}
            </li>
          ))}
        </ul>
      )}
      {!value && (!items || items.length === 0) && <div className="text-xs text-muted italic">unknown</div>}
    </div>
  );
}

function ActionsList({
  actions,
  filterStakeholder,
}: {
  actions: ReportActionItem[];
  filterStakeholder: Stakeholder | null;
}): JSX.Element | null {
  const filtered = filterStakeholder
    ? actions.filter(
        (a) => !a.stakeholders || a.stakeholders.length === 0 || a.stakeholders.includes(filterStakeholder)
      )
    : actions;
  if (filtered.length === 0) return null;
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Shield size={12} /> Containment &amp; Response ({filtered.length})
      </div>
      <ol className="divide-y divide-line-1 dark:divide-slate-800/50">
        {filtered.map((a, idx) => {
          const c = SEVERITY_COLORS[a.severity];
          return (
            <li key={idx} className="px-3 py-2.5 flex items-start gap-3">
              <span
                className={`shrink-0 inline-block px-1.5 py-0.5 rounded text-micro font-mono font-bold ${c.pill} w-16 text-center`}
              >
                {a.severity.toUpperCase()}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-heading leading-relaxed">{a.action}</p>
                <div className="mt-1 flex flex-wrap items-center gap-1.5 text-micro font-mono text-muted">
                  {a.target && (
                    <span className="inline-flex items-center gap-0.5">
                      <Target size={9} /> {a.target}
                    </span>
                  )}
                  {a.source && (
                    <span className="inline-flex items-center gap-0.5">
                      <FileText size={9} /> {a.source}
                    </span>
                  )}
                  <span className="inline-flex items-center gap-0.5">
                    <Network size={9} /> {a.category}
                  </span>
                </div>
              </div>
              {(a.stakeholders ?? []).length > 0 && (
                <div className="flex flex-wrap gap-1 shrink-0">
                  {a.stakeholders!.map((s) => (
                    <span
                      key={s}
                      className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${STAKEHOLDER_META[s]?.color ?? 'bg-slate-100 text-slate-600'}`}
                    >
                      {STAKEHOLDER_META[s]?.label ?? s}
                    </span>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function PirList({ pirs }: { pirs: ReportPir[] }): JSX.Element | null {
  if (pirs.length === 0) return null;
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Flag size={12} /> Priority Intelligence Requirements
      </div>
      <ul className="divide-y divide-line-1 dark:divide-slate-800/50">
        {pirs.map((p, idx) => (
          <li key={idx} className="px-3 py-2.5 flex items-start gap-3">
            <span
              className={`shrink-0 w-2 h-2 rounded-full mt-1.5 ${p.relevant ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-surface-300'}`}
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm text-heading">{p.pir}</p>
              {p.bluf && <p className="text-xs text-muted mt-1">{p.bluf}</p>}
              {p.businessOutcome && (
                <p className="text-xs text-emerald-700 dark:text-emerald-400 mt-1 inline-flex items-center gap-1">
                  <ArrowRight size={10} /> {p.businessOutcome}
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function TimelineList({ timeline }: { timeline: ReportActionCard['timeline'] }): JSX.Element | null {
  if (!timeline || timeline.length === 0) return null;
  return (
    <div className="surface-card mb-4 overflow-hidden">
      <div className="px-3 py-2 border-b border-line-1 flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
        <Activity size={12} /> Timeline
      </div>
      <ol className="relative pl-6 pr-3 py-2">
        <div className="absolute left-3 top-3 bottom-3 w-px bg-track" />
        {timeline.map((t, idx) => (
          <li key={idx} className="relative py-1.5">
            <div className="absolute -left-3 mt-1.5 w-2 h-2 rounded-full bg-brand-500 ring-2 ring-white dark:ring-slate-900" />
            <div className="text-mini font-mono text-muted">{t.date ?? '-'}</div>
            <div className="text-sm text-heading">{t.event}</div>
            {t.source && <div className="text-micro font-mono text-muted">[{t.source}]</div>}
          </li>
        ))}
      </ol>
    </div>
  );
}

function NextActionsBar({
  report,
  query,
  actionCard,
  onGenerateHuntingQueries,
  onGenerateYaraRule,
  onDrillDeeper,
}: {
  /** Raw report text - used for the Share-as-Markdown export. */
  report?: string;
  query?: string;
  actionCard?: ReportActionCard;
  onGenerateHuntingQueries?: () => Promise<{ tool: string; data: unknown } | null>;
  onGenerateYaraRule?: () => Promise<{ tool: string; data: unknown } | null>;
  /** Optional callback to open the Copilot pre-seeded with a
   *  follow-up question. The DFIR Agent page wires this to navigate to
   *  /threatintel/tools/copilot?q=... */
  onDrillDeeper?: (question: string) => void;
}): JSX.Element {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);
  const [result, setResult] = useState<{ tool: string; data: unknown } | null>(null);
  // Drill-deeper follow-up (replaces a native window.prompt).
  const [drillOpen, setDrillOpen] = useState(false);
  const [drillText, setDrillText] = useState('');

  const runAction = async (name: string, fn: () => Promise<{ tool: string; data: unknown } | null>) => {
    setLoading(name);
    setResult(null);
    try {
      const r = await fn();
      setResult(r);
    } catch (e) {
      setResult({ tool: name, data: { error: errMessage(e) } });
    } finally {
      setLoading(null);
    }
  };

  const downloadNavigatorLayer = () => {
    if (!actionCard?.navigatorLayer) return;
    const layer = {
      name: actionCard.navigatorLayer.name,
      description: actionCard.navigatorLayer.description,
      domain: 'enterprise-attack',
      version: '4',
      techniques: actionCard.navigatorLayer.techniques.map((t) => ({
        techniqueID: t.id,
        score: t.score,
        comment: t.comment ?? '',
        color: '',
      })),
      legend: [],
      meta: { generated_at: new Date().toISOString() },
      gradient: { colors: ['#ffe766', '#ff6666', '#990000'], minValue: 0, maxValue: 100 },
    };
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `mitre-navigator-${actionCard.navigatorLayer.name.replace(/\s+/g, '-').toLowerCase()}.json`);
  };

  const hasNavigator = (actionCard?.navigatorLayer?.techniques?.length ?? 0) > 0;

  return (
    <div className="surface-card mb-4">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full px-3 py-2 flex items-center justify-between text-left hover:bg-surface-200 dark:hover:bg-input-200/40"
      >
        <span className="flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
          <Sparkles size={12} /> Next Actions
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
      {open && (
        <div className="px-3 pb-3 border-t border-line-1">
          <p className="text-xs text-muted mt-2 mb-2">
            Generate follow-up artifacts from this investigation. Analyst approval required before deploying anything to
            live tooling.
          </p>
          <div className="flex flex-wrap gap-2">
            {onGenerateHuntingQueries && (
              <button
                type="button"
                disabled={!!loading || !query}
                onClick={() => runAction('hunting_queries', onGenerateHuntingQueries)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-brand-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-950/40 text-brand-700 dark:text-brand-300 text-mini font-mono hover:bg-blue-100 dark:hover:bg-blue-900/40 disabled:opacity-50"
              >
                {loading === 'hunting_queries' ? (
                  <Loader2 size={11} className="animate-spin" />
                ) : (
                  <Terminal size={11} />
                )}
                Generate Hunt Queries (KQL/Splunk/Sigma)
              </button>
            )}
            {onGenerateYaraRule && (
              <button
                type="button"
                disabled={!!loading || !query}
                onClick={() => runAction('yara_rule', onGenerateYaraRule)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 text-mini font-mono hover:bg-rose-100 dark:hover:bg-rose-900/40 disabled:opacity-50"
              >
                {loading === 'yara_rule' ? <Loader2 size={11} className="animate-spin" /> : <Code2 size={11} />}
                Generate YARA / Sigma Rule
              </button>
            )}
            {hasNavigator && (
              <button
                type="button"
                onClick={downloadNavigatorLayer}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-purple-300 dark:border-purple-700 bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300 text-mini font-mono hover:bg-purple-100 dark:hover:bg-purple-900/40 transition-colors"
              >
                <MapIcon size={11} />
                Export MITRE Navigator Layer
              </button>
            )}
            <button
              type="button"
              onClick={() =>
                actionCard && navigator.clipboard.writeText(JSON.stringify(actionCard, null, 2)).then(() => void 0)
              }
              disabled={!actionCard}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-line-2 text-body text-mini font-mono hover:bg-surface-200 dark:hover:bg-input-200/40 disabled:opacity-50"
            >
              <Copy size={11} />
              Copy Action Card JSON
            </button>
            {actionCard && (
              <button
                type="button"
                onClick={async () => {
                  // Build a self-contained Markdown version of the report
                  // for sharing in Slack, email, or a ticketing system.
                  // Falls back to plain text if clipboard write fails.
                  const md = buildShareMarkdown(report ?? '', actionCard, query);
                  try {
                    await navigator.clipboard.writeText(md);
                  } catch {
                    // Fallback: download as a .md file
                    const blob = new Blob([md], { type: 'text/markdown' });
                    downloadBlob(
                      blob,
                      `dfir-report-${actionCard.verdict.headline
                        .replace(/[^a-z0-9]+/gi, '-')
                        .toLowerCase()
                        .slice(0, 60)}.md`
                    );
                  }
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-line-2 text-body text-mini font-mono hover:bg-surface-200 dark:hover:bg-input-200/40"
              >
                <Share2 size={11} />
                Share as Markdown
              </button>
            )}
            {onDrillDeeper && actionCard && (
              <button
                type="button"
                disabled={!query}
                onClick={() => {
                  // Build a follow-up question grounded in the report so the
                  // copilot has the BLUF + IOCs + actor context to answer.
                  const card = actionCard;
                  const iocList = card.iocs
                    .slice(0, 5)
                    .map((i) => `${i.type}:${i.value}`)
                    .join(', ');
                  const followUp = [
                    `Follow-up on: ${query}`,
                    card.verdict.headline ? `\n\nVerdict: ${card.verdict.headline}` : '',
                    iocList ? `\n\nKey IOCs: ${iocList}` : '',
                    '\n\nQuestion: ',
                  ]
                    .filter(Boolean)
                    .join('');
                  setDrillText(followUp);
                  setDrillOpen(true);
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-950/40 text-brand-700 dark:text-brand-300 text-mini font-mono hover:bg-brand-100 dark:hover:bg-brand-900/40 disabled:opacity-50"
              >
                <MessageSquare size={11} />
                Drill Deeper (Copilot)
              </button>
            )}
          </div>
          {actionCard?.handoff?.next_stages && actionCard.handoff.next_stages.length > 0 && (
            <div className="mt-3 rounded border border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/30 p-2.5">
              <div className="flex items-center gap-1.5 text-mini font-mono uppercase tracking-wider text-amber-700 dark:text-amber-300 mb-1.5">
                <AlertTriangle size={11} /> Suggested Next Investigation Stages
                {actionCard.handoff.analyst_approval_required && (
                  <span className="ml-auto px-1.5 py-0.5 rounded text-micro font-mono font-bold bg-amber-200 text-amber-900 dark:bg-amber-900/60 dark:text-amber-200">
                    Analyst approval required
                  </span>
                )}
              </div>
              <ol className="text-xs text-amber-900 dark:text-amber-200 space-y-1 list-decimal list-inside">
                {actionCard.handoff.next_stages.map((stage, i) => (
                  <li key={i}>
                    <span className="font-mono">{stage}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {result && (
            <pre className="mt-3 rounded bg-surface-100 dark:bg-input-200 text-slate-100 p-3 text-xs overflow-x-auto font-mono leading-relaxed max-h-72">
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
        </div>
      )}

      <Modal open={drillOpen} onClose={() => setDrillOpen(false)} title="Drill deeper (Copilot)">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const q = drillText.trim();
            if (q) onDrillDeeper?.(q);
            setDrillOpen(false);
          }}
          className="space-y-3"
        >
          <textarea
            autoFocus
            value={drillText}
            onChange={(e) => setDrillText(e.target.value)}
            rows={8}
            aria-label="Follow-up question for Copilot"
            className="w-full px-3 py-2 rounded border border-line-1 bg-surface-100 text-sm font-mono focus:outline-none focus:border-brand-500"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setDrillOpen(false)}
              className="px-3 py-1.5 text-tool text-muted hover:text-body dark:hover:text-inverted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!drillText.trim()}
              className="px-3 py-1.5 rounded bg-brand-600 text-on-fill text-tool font-semibold hover:bg-brand-500 disabled:opacity-40 transition-colors"
            >
              Ask Copilot
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────

export function ReportView({
  report,
  actionCard,
  reportVersioning,
  query,
  onGenerateHuntingQueries,
  onGenerateYaraRule,
  onDrillDeeper,
}: ReportViewProps): JSX.Element {
  const [stakeholder, setStakeholder] = useState<Stakeholder | null>(null);
  const [showTechnical, setShowTechnical] = useState(false);
  const proseHtml = useMemo(() => renderMarkdown(report), [report]);
  const bundle = useMemo(() => extractStixBundle(report), [report]);

  // Prefer the structured BLUF header (parsed by the synthesizer from the
  // \`\`\`report-header block) over the legacy regex-based parse. Fall back
  // to regex for older reports that don't emit the structured block.
  const headline = useMemo(() => {
    if (actionCard?.reportHeader?.headline) return actionCard.reportHeader.headline;
    const m = report.match(/##\s*1\.\s*HEADLINE VERDICT\s*\n+\s*([^\n]+)/);
    return m?.[1]?.trim();
  }, [report, actionCard?.reportHeader?.headline]);

  const executiveSummary = useMemo(() => {
    if (actionCard?.reportHeader?.bluf) return actionCard.reportHeader.bluf;
    const m = report.match(/##\s*2\.\s*EXECUTIVE SUMMARY\s*\n+([\s\S]*?)(?=\n## |\n# |$)/);
    return m?.[1]?.trim();
  }, [report, actionCard?.reportHeader?.bluf]);

  // Build stakeholder chip set from the action card.
  const stakeholderChips = useMemo(() => {
    if (!actionCard) return [] as Stakeholder[];
    const set = new Set<Stakeholder>();
    for (const a of actionCard.actions) for (const s of a.stakeholders ?? []) set.add(s);
    return [...set].sort();
  }, [actionCard]);

  if (!actionCard) {
    // Fallback - render the prose only with the STIX bundle inline.
    return (
      <div>
        {headline && (
          <div className="rounded-xl p-3 bg-surface-300 mb-3 flex items-start gap-2">
            <Info size={14} className="mt-0.5 text-muted" />
            <p className="text-sm font-semibold text-heading">{headline}</p>
          </div>
        )}
        <div
          data-stakeholder-filter={stakeholder ?? ''}
          className="prose prose-sm dark:prose-invert max-w-none font-mono text-sm leading-relaxed whitespace-pre-wrap"
          dangerouslySetInnerHTML={{ __html: proseHtml }}
        />
        {stakeholder && (
          <style>{`[data-stakeholder-filter="${stakeholder}"] .dfir-stakeholder-block:not([data-stakeholder="${stakeholder}"]) { display: none; }`}</style>
        )}
        {bundle && (
          <>
            <StixRelationshipGraph bundle={bundle} />
            <StixObjectTable bundle={bundle} />
          </>
        )}
      </div>
    );
  }

  return (
    <div>
      {actionCard.reportHeader ? <BlufPanel header={actionCard.reportHeader} /> : <SeverityBanner card={actionCard} />}

      {/* CVE intelligence card - only renders when KEV/CVSS/EPSS/actor data is present. */}
      <CveMetaCard card={actionCard} />

      {actionCard.reportHeader?.bluf && (
        <div className="surface-card p-3 mb-4">
          <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Executive Summary</div>
          <p className="text-sm text-body leading-relaxed">{actionCard.reportHeader.bluf}</p>
          {actionCard.reportHeader.key_takeaway && (
            <p className="text-xs text-muted mt-2 italic">
              <span className="font-bold not-italic uppercase tracking-wider mr-1">Business impact:</span>
              {actionCard.reportHeader.key_takeaway}
            </p>
          )}
        </div>
      )}

      {!actionCard.reportHeader && headline && (
        <div className="surface-card p-3 mb-4">
          <div className="flex items-start gap-2">
            <AlertOctagon size={14} className="mt-0.5 text-muted shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-0.5">Headline</div>
              <p className="text-sm font-semibold text-heading">{headline}</p>
            </div>
          </div>
          {executiveSummary && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Executive Summary</div>
              <p className="text-sm text-body leading-relaxed whitespace-pre-line">{executiveSummary}</p>
            </div>
          )}
        </div>
      )}

      {stakeholderChips.length > 0 && (
        <div className="mb-4 flex items-center gap-2 flex-wrap">
          <span className="text-micro font-mono uppercase tracking-wider text-muted flex items-center gap-1">
            <Users size={11} /> View for:
          </span>
          <button
            type="button"
            onClick={() => setStakeholder(null)}
            className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${
              stakeholder === null
                ? 'bg-brand-600 text-white'
                : 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted hover:bg-slate-200 dark:hover:bg-surface-300'
            }`}
          >
            ALL
          </button>
          {stakeholderChips.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setStakeholder(s)}
              className={`px-1.5 py-0.5 rounded text-micro font-mono font-bold ${
                stakeholder === s ? 'bg-brand-600 text-white' : STAKEHOLDER_META[s]?.color
              }`}
            >
              {STAKEHOLDER_META[s]?.label ?? s}
            </button>
          ))}
        </div>
      )}

      <ActionsList actions={actionCard.actions} filterStakeholder={stakeholder} />
      <IocTable iocs={actionCard.iocs} />
      <MitreTable mitre={actionCard.mitre} />
      {actionCard.graph && actionCard.graph.nodes.length > 0 && (
        <div className="surface-card mb-4 p-3">
          <h3 className="flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted mb-2">
            Relationship Graph
          </h3>
          <Suspense fallback={<div className="h-[460px] animate-pulse rounded-xl bg-surface-300" />}>
            <RelationshipGraph graph={actionCard.graph} />
          </Suspense>
        </div>
      )}
      <DiamondModelCard diamond={actionCard.diamond} />
      <TimelineList timeline={actionCard.timeline} />
      <PirList pirs={actionCard.pirs ?? []} />
      {reportVersioning && reportVersioning.versions.length > 1 && (
        <div className="surface-card mb-4 p-3">
          <h3 className="flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted mb-2">
            QA Revision History
          </h3>
          <div className="space-y-1">
            {reportVersioning.versions.map((v) => (
              <div key={v.version} className="flex items-center justify-between text-sm">
                <span className="font-mono text-body">
                  v{v.version} · {v.reason}
                </span>
                <span className="tabular-nums font-semibold text-heading">{v.qualityScore}/100</span>
              </div>
            ))}
          </div>
          {reportVersioning.diff && (
            <div className="mt-2 border-t border-line-1 pt-2 text-micro font-mono text-muted">
              Self-correction: {reportVersioning.diff.fromScore}→{reportVersioning.diff.toScore} (
              {reportVersioning.diff.toScore - reportVersioning.diff.fromScore >= 0 ? '+' : ''}
              {reportVersioning.diff.toScore - reportVersioning.diff.fromScore}) · {reportVersioning.diff.additions}{' '}
              additions, {reportVersioning.diff.deletions} deletions
            </div>
          )}
        </div>
      )}

      {/* Technical details - collapsible. Analyst can fold the body and
          just see BLUF + action card + IOCs at a glance. */}
      <div className="surface-card mb-4">
        <button
          type="button"
          onClick={() => setShowTechnical((v) => !v)}
          className="w-full px-3 py-2 flex items-center justify-between text-left hover:bg-surface-200 dark:hover:bg-input-200/40"
        >
          <span className="flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted">
            <FileText size={12} /> Technical Details
          </span>
          {showTechnical ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
        {showTechnical && (
          <div className="px-3 pb-3 border-t border-line-1">
            <div
              data-stakeholder-filter={stakeholder ?? ''}
              className="prose prose-sm dark:prose-invert max-w-none font-mono text-sm leading-relaxed pt-2"
              dangerouslySetInnerHTML={{ __html: proseHtml }}
            />
            {stakeholder && (
              <style>{`[data-stakeholder-filter="${stakeholder}"] .dfir-stakeholder-block:not([data-stakeholder="${stakeholder}"]) { display: none; }`}</style>
            )}
            {bundle && (
              <div className="mt-3 rounded border border-line-1 bg-surface-200/40 p-3">
                <div className="flex items-center gap-2 text-mini font-mono uppercase tracking-wider text-muted mb-2">
                  <Link2 size={12} /> STIX 2.1 Bundle
                </div>
                <StixRelationshipGraph bundle={bundle} />
                <StixObjectTable bundle={bundle} />
              </div>
            )}
          </div>
        )}
      </div>

      <NextActionsBar
        report={report}
        query={query}
        actionCard={actionCard}
        onGenerateHuntingQueries={onGenerateHuntingQueries}
        onGenerateYaraRule={onGenerateYaraRule}
        onDrillDeeper={onDrillDeeper}
      />
    </div>
  );
}
