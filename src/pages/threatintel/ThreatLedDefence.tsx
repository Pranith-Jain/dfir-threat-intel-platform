/**
 * /threatintel/wiki/threat-led-defence -- Threat Led Defence (BS5055).
 *
 * BS5055:2020 "The cyber security toolkit: principles and guidance for
 * cyber security built around the idea of threat led defence", published by
 * BSI in the UK under the National Cyber Security Centre's Cyber Security
 * Toolkit.
 *
 * ## Why it is here
 *
 * The platform carries the operational frameworks (MITRE ATT&CK, Kill Chain,
 * F3EAD, Diamond, OODA) and the governance ones (GRC, TID-CMM, UTIOM). What
 * was missing was BS5055, which is different in kind: it is a *certifiable*
 * cyber-resilience standard with a fixed three-principle spine and a five-pillar
 * defence model. TID-CMM and UTIOM ask how mature your capability is; BS5055
 * asks whether you can evidence that your controls were chosen against
 * threats and then validated against them.
 *
 * Everything here is written to be actionable on this platform rather than to
 * be a summary of the standard: each pillar names the surfaces in this
 * codebase that already produce the artefacts an assessor would ask for.
 *
 * Static, no backend roundtrip. Follows the pattern of F3EAD.tsx, Ooda.tsx and
 * the other framework pages in the wiki catalog group.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Eye,
  ShieldCheck,
  FlaskConical,
  Ban,
  Siren,
  RotateCcw,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  CheckCircle2,
  CircleDot,
  ExternalLink,
  Scale,
  ScrollText,
  BookOpen,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';

// ---------------------------------------------------------------------------
// The three principles
// ---------------------------------------------------------------------------

type PrincipleId = 'understand' | 'design' | 'validate';

interface Principle {
  id: PrincipleId;
  number: number;
  name: string;
  question: string;
  summary: string;
  icon: LucideIcon;
  /** What an assessor asks for under this principle. */
  evidence: string[];
  failure: string;
}

const PRINCIPLES: Principle[] = [
  {
    id: 'understand',
    number: 1,
    name: 'Understand the threats',
    question: 'What is actually trying to get in?',
    summary:
      'Establish the threat model before choosing controls. This means naming the adversaries you face, the assets they would come for, and the routes available to them. A control chosen before the threat model exists is decoration.',
    icon: Eye,
    evidence: [
      'A current threat profile: adversaries, their TTPs, and why they would target you specifically',
      'An asset inventory scoped to the internet-facing estate, with the ASN and technology stack identified',
      'Documented prioritisation: which assets, and which threats, drive the risk decision',
    ],
    failure:
      'Controls selected from a compliance checklist rather than from a threat. The estate still has unmodelled exposure and nobody can say which adversary the control actually addresses.',
  },
  {
    id: 'design',
    number: 2,
    name: 'Design the controls',
    question: 'What stops them, and where does it fail?',
    summary:
      'Select controls that map to the threats you just named, and record the reasoning. Controls are built as a layered defence across five build blocks, not as a single perimeter. The design is a hypothesis you are about to test.',
    icon: ShieldCheck,
    evidence: [
      'A control-to-threat mapping: every control traced to a threat from Principle 1',
      'Coverage across all five build blocks, with gaps declared rather than hidden',
      'Detection logic that can be written down and deployed, not just a policy PDF',
    ],
    failure:
      'A stack of tooling with no traceability to threats. Nobody can say which control covers which technique, so an incident reveals an uncovered gap only after it is exploited.',
  },
  {
    id: 'validate',
    number: 3,
    name: 'Validate the controls',
    question: 'Do they actually work, and can you prove it?',
    summary:
      'Test the design against the threat model rather than against a checklist. Assurance comes from exercises, purple-team validation and red-team testing, with the results kept as evidence. Validation is continuous, because both the threats and the estate change.',
    icon: FlaskConical,
    evidence: [
      'Exercises and purple-team results covering the priority threats',
      'Detection efficacy measured, not assumed: which techniques produced an alert and which did not',
      'A remediation record showing findings were closed and re-tested',
    ],
    failure:
      'Controls certified on documentation alone. Every control looks complete and none has been tested against a real adversary, so the first live intrusion is also the first test.',
  },
];

// ---------------------------------------------------------------------------
// The five build blocks
// ---------------------------------------------------------------------------

type PillarId = 'understand' | 'prevent' | 'detect' | 'respond' | 'recover';

interface Pillar {
  id: PillarId;
  name: string;
  intent: string;
  icon: LucideIcon;
  /** Practices that satisfy this pillar. */
  practices: string[];
  /** Surfaces in this platform that produce the artefacts. */
  platform: Array<{ label: string; to: string }>;
}

const PILLARS: Pillar[] = [
  {
    id: 'understand',
    name: 'Understand',
    intent: 'Know the threats, the estate, and the exposure. Everything downstream depends on this being true.',
    icon: Eye,
    practices: [
      'Maintain a threat profile grounded in observed activity, not in generic reports',
      'Keep the asset inventory and technology fingerprint current',
      'Track exposure and newly-disclosed vulnerabilities against what you actually run',
    ],
    platform: [
      { label: 'Threat Intel Platform', to: '/threatintel' },
      { label: 'Threat Actor Monitor', to: '/threatintel/osint/threat-actor-monitor' },
      { label: 'Asset Intelligence', to: '/dfir/asset-intel' },
      { label: 'CVE Intelligence', to: '/threatintel/cves/cves' },
    ],
  },
  {
    id: 'prevent',
    name: 'Prevent',
    intent: 'Reduce the attack surface and the likelihood of successful entry.',
    icon: Ban,
    practices: [
      'Harden identity and privileged access; remove standing administrative capability',
      'Patch and configure to a declared baseline',
      'Segment to limit what one compromised account can reach',
    ],
    platform: [
      { label: 'Asset & Attack Surface', to: '/dfir/asset-intel' },
      { label: 'Cloud Security', to: '/dfir/iam-hub' },
      { label: 'IAM & RBAC Hub', to: '/dfir/iam-hub' },
    ],
  },
  {
    id: 'detect',
    name: 'Detect',
    intent: 'Know quickly when the controls have been worked around.',
    icon: Siren,
    practices: [
      'Convert known adversary behaviour into deployable detection logic',
      'Baseline the environment so anomalies are visible against your own norms',
      'Ensure alerting reaches someone who can act, with enough context to act',
    ],
    platform: [
      { label: 'Detection Engineering', to: '/dfir/rule-converter' },
      { label: 'Rule Converter', to: '/dfir/yara-workbench' },
      { label: 'MITRE ATT&CK', to: '/threatintel/wiki/mitre' },
      { label: 'Live IOC Stream', to: '/threatintel/iocs/live' },
    ],
  },
  {
    id: 'respond',
    name: 'Respond',
    intent: 'Contain an incident decisively and with a rehearsed decision path.',
    icon: RotateCcw,
    practices: [
      'Pre-agreed containment options with the authority to use them already delegated',
      'Playbooks exercised, not merely documented',
      'Evidence capture and scoping that survives the pressure of a live incident',
    ],
    platform: [
      { label: 'Host Graph', to: '/dfir/ioc-investigate' },
      { label: 'IOC Investigator', to: '/dfir/ioc-investigate' },
      { label: 'PCAP Triage', to: '/dfir/pcap-triage' },
      { label: 'Active Campaigns', to: '/threatintel/campaigns/active' },
    ],
  },
  {
    id: 'recover',
    name: 'Recover',
    intent: 'Return to a known-good state and learn something that improves the design.',
    icon: CheckCircle2,
    practices: [
      'Restore from trusted, tested backups rather than from originals',
      'Rebuild rather than repair where the integrity of the system is in doubt',
      'Feed lessons back into the threat model and the control set',
    ],
    platform: [
      { label: 'IOC Correlation', to: '/threatintel/iocs/correlation' },
      { label: 'Actor Timeline', to: '/threatintel/osint/threat-actor-monitor' },
      { label: 'Reports & Export', to: '/dfir/report-hub' },
      { label: 'STIX Workbench', to: '/dfir/stix-workbench' },
    ],
  },
];

// ---------------------------------------------------------------------------
// Maturity model
// ---------------------------------------------------------------------------

const MATURITY = [
  {
    level: 1,
    name: 'Initial',
    summary: 'Controls exist but are not chosen against a threat model. Evidence is anecdotal.',
  },
  {
    level: 2,
    name: 'Repeatable',
    summary: 'Controls are documented and consistently applied. Threat traceability is partial.',
  },
  {
    level: 3,
    name: 'Threat-informed',
    summary: 'Controls trace to a maintained threat profile. Detection logic is deployable and tested.',
  },
  {
    level: 4,
    name: 'Assured',
    summary: 'Controls are exercised and purple-teamed against the threat model. Gaps are declared and owned.',
  },
  {
    level: 5,
    name: 'Adaptive',
    summary:
      'Validation is continuous. Threat model and controls update together as the estate and adversaries change.',
  },
] as const;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ThreatLedDefence(): JSX.Element {
  const [openPillar, setOpenPillar] = useState<PillarId | null>('understand');

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<ShieldCheck size={28} />}
      title="Threat Led Defence (BS5055)"
      description="The UK National Cyber Security Centre's cyber resilience standard: understand the threats, design the controls, validate the controls. Built for assessment, not for a checklist."
    >
      <div className="space-y-10">
        {/* ── Why ─────────────────────────────────────────────────────── */}
        <section>
          <h2 className="text-lg font-display font-semibold text-body mb-2">What it is</h2>
          <p className="text-sm text-muted leading-relaxed max-w-3xl">
            BS5055 is a UK standard for building cyber security around threat led defence rather than around compliance.
            It has three principles and a five-pillar defence model. What separates it from most frameworks on this page
            is that it is <span className="text-body font-medium">certifiable</span>: an independent assessor asks for
            evidence that your controls were chosen against threats and then tested against them.
          </p>
          <p className="text-sm text-muted leading-relaxed max-w-3xl mt-2">
            Each pillar below names the surfaces in this platform that already produce the artefacts an assessor would
            ask for. The standard is mapped onto what you can already do rather than described in the abstract.
          </p>
          <div className="flex flex-wrap gap-2 mt-4">
            <a
              href="https://www.ncsc.gov.uk/collection/cyber-security-toolkit"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border border-line-1 text-muted hover:text-body transition-colors"
            >
              <BookOpen size={12} className="shrink-0" />
              NCSC Cyber Security Toolkit
              <ExternalLink size={11} className="shrink-0" />
            </a>
            <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border border-line-1 text-muted">
              <ScrollText size={12} className="shrink-0" />
              BS5055:2020
            </span>
          </div>
        </section>

        {/* ── Principles ──────────────────────────────────────────────── */}
        <section>
          <h2 className="text-lg font-display font-semibold text-body mb-1">The three principles</h2>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            Sequential and load-bearing. Skipping principle 1 is the most common failure and it invalidates the other
            two.
          </p>
          <div className="space-y-3">
            {PRINCIPLES.map((p) => {
              const Icon = p.icon;
              return (
                <div key={p.id} className="rounded-xl border border-line-1 overflow-hidden">
                  <div className="flex items-start gap-3 p-4 [background:rgb(var(--surface-200)/0.4)]">
                    <span className="shrink-0 mt-0.5 w-6 h-6 rounded-full border border-line-1 flex items-center justify-center font-mono text-xs text-muted">
                      {p.number}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Icon size={15} className="text-brand-600 dark:text-brand-400 shrink-0" />
                        <h3 className="font-display font-semibold text-body">{p.name}</h3>
                      </div>
                      <p className="text-xs font-mono text-muted mt-0.5">{p.question}</p>
                      <p className="text-sm text-muted leading-relaxed mt-2">{p.summary}</p>
                    </div>
                  </div>
                  <div className="grid gap-0 md:grid-cols-2 border-t border-line-1">
                    <div className="p-4">
                      <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">
                        What an assessor asks for
                      </div>
                      <ul className="space-y-1.5">
                        {p.evidence.map((e) => (
                          <li key={e} className="flex gap-2 text-sm text-muted">
                            <CheckCircle2 size={13} className="text-brand-600 dark:text-brand-400 shrink-0 mt-0.5" />
                            <span>{e}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div className="p-4 border-t md:border-t-0 md:border-l border-line-1">
                      <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">
                        What failure looks like
                      </div>
                      <p className="text-sm text-muted leading-relaxed">{p.failure}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* ── Pillars ─────────────────────────────────────────────────── */}
        <section>
          <h2 className="text-lg font-display font-semibold text-body mb-1">The five build blocks</h2>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            A layered defence. A gap in any one block is a gap, and the blocks do not substitute for each other: a
            strong Prevent posture with no Detect is silent.
          </p>
          <div className="space-y-2">
            {PILLARS.map((p) => {
              const Icon = p.icon;
              const open = openPillar === p.id;
              return (
                <div key={p.id} className="rounded-xl border border-line-1 overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setOpenPillar(open ? null : p.id)}
                    aria-expanded={open}
                    className="w-full flex items-center gap-3 p-4 text-left hover:bg-[rgb(var(--surface-300)/0.4)] transition-colors"
                  >
                    <Icon size={16} className="text-brand-600 dark:text-brand-400 shrink-0" />
                    <span className="font-display font-semibold text-body">{p.name}</span>
                    <span className="text-xs text-muted truncate hidden sm:inline">{p.intent}</span>
                    <ChevronDown
                      size={15}
                      className={`shrink-0 ml-auto text-muted transition-transform ${open ? 'rotate-0' : '-rotate-90'}`}
                      aria-hidden="true"
                    />
                  </button>
                  {open && (
                    <div className="border-t border-line-1 p-4 grid gap-4 md:grid-cols-2 [background:rgb(var(--surface-200)/0.4)]">
                      <div>
                        <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">
                          Practices
                        </div>
                        <ul className="space-y-1.5">
                          {p.practices.map((pr) => (
                            <li key={pr} className="flex gap-2 text-sm text-muted">
                              <CircleDot size={13} className="text-muted shrink-0 mt-0.5" />
                              <span>{pr}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">
                          Evidence sources on this platform
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {p.platform.map((l) => (
                            <Link
                              key={l.to}
                              to={l.to}
                              className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded border border-line-1 text-muted hover:text-body hover:border-brand-500/40 transition-colors"
                            >
                              {l.label}
                              <ArrowRight size={11} />
                            </Link>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* ── Maturity ────────────────────────────────────────────────── */}
        <section>
          <h2 className="text-lg font-display font-semibold text-body mb-1">Maturity</h2>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            How far along the threat-led journey you are. Levels 3 and above are where the standard stops being
            documentation and starts being evidence.
          </p>
          <div className="space-y-2">
            {MATURITY.map((m) => (
              <div key={m.level} className="flex gap-3 p-3 rounded-lg border border-line-1">
                <span className="shrink-0 w-6 h-6 rounded-full border border-line-1 flex items-center justify-center font-mono text-xs text-muted">
                  {m.level}
                </span>
                <div className="min-w-0">
                  <div className="font-medium text-body text-sm">{m.name}</div>
                  <p className="text-sm text-muted leading-relaxed mt-0.5">{m.summary}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Related frameworks ──────────────────────────────────────── */}
        <section>
          <h2 className="text-lg font-display font-semibold text-body mb-3">Alongside</h2>
          <div className="grid gap-2 sm:grid-cols-2">
            <Link
              to="/dfir/frameworks/tid-cmm"
              className="flex items-center gap-3 p-3 rounded-lg border border-line-1 hover:border-brand-500/40 transition-colors"
            >
              <Scale size={15} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <span className="min-w-0">
                <span className="block text-sm font-medium text-body">TID-CMM</span>
                <span className="block text-xs text-muted">
                  Capability maturity per domain. BS5055 asks whether controls are evidenced; TID-CMM asks how mature
                  they are.
                </span>
              </span>
              <ChevronRight size={14} className="ml-auto text-muted shrink-0" />
            </Link>
            <Link
              to="/dfir/frameworks/utiom"
              className="flex items-center gap-3 p-3 rounded-lg border border-line-1 hover:border-brand-500/40 transition-colors"
            >
              <ShieldCheck size={15} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <span className="min-w-0">
                <span className="block text-sm font-medium text-body">UTIOM</span>
                <span className="block text-xs text-muted">
                  Lifecycle, pillars and the self-assessment model. Useful when the question is sequencing rather than
                  assurance.
                </span>
              </span>
              <ChevronRight size={14} className="ml-auto text-muted shrink-0" />
            </Link>
            <Link
              to="/threatintel/wiki/mitre"
              className="flex items-center gap-3 p-3 rounded-lg border border-line-1 hover:border-brand-500/40 transition-colors"
            >
              <Eye size={15} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <span className="min-w-0">
                <span className="block text-sm font-medium text-body">MITRE ATT&CK</span>
                <span className="block text-xs text-muted">
                  The adversary vocabulary the threat profile in principle 1 is written in.
                </span>
              </span>
              <ChevronRight size={14} className="ml-auto text-muted shrink-0" />
            </Link>
            <Link
              to="/dfir/grc"
              className="flex items-center gap-3 p-3 rounded-lg border border-line-1 hover:border-brand-500/40 transition-colors"
            >
              <ScrollText size={15} className="text-brand-600 dark:text-brand-400 shrink-0" />
              <span className="min-w-0">
                <span className="block text-sm font-medium text-body">GRC & Posture</span>
                <span className="block text-xs text-muted">
                  Where the evidence pack and control ownership are tracked.
                </span>
              </span>
              <ChevronRight size={14} className="ml-auto text-muted shrink-0" />
            </Link>
          </div>
        </section>
      </div>
    </DataPageLayout>
  );
}
