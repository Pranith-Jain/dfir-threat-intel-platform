import {
  X,
  ExternalLink,
  Shield,
  Bug,
  Crosshair,
  Calendar,
  Users,
  Building2,
  Network,
  Target,
  FileText,
} from 'lucide-react';
import type { Actor } from '../types';
import { NATION_PALETTE } from '../data/countries';
import { cn } from '../lib';
import HexBrainLink from '../../../components/HexBrainLink';

interface Props {
  actor: Actor | null;
  onClose: () => void;
  onOpen: (a: Actor) => void;
}

export function Dossier({ actor, onClose }: Props) {
  if (!actor) return null;
  const nation = NATION_PALETTE[actor.country] ?? NATION_PALETTE.XX!;

  return (
    <aside
      className="fixed top-14 right-0 bottom-0 w-[min(520px,92vw)] z-40 surface-raised border-l overflow-y-auto animate-fade-in"
      style={{ borderColor: 'var(--edge-strong)' }}
      role="dialog"
      aria-label={`${actor.name} dossier`}
    >
      {/* Header */}
      <div
        className="sticky top-0 z-10 backdrop-blur border-b"
        style={{ background: 'var(--ink-900)', borderColor: 'var(--edge)', opacity: 0.95 }}
      >
        <div className="flex items-start gap-3 p-4">
          <span
            className="h-10 w-10 rounded-lg shrink-0 flex items-center justify-center font-mono text-sm font-semibold"
            style={{ background: `${nation.color}22`, color: nation.color, border: `1px solid ${nation.color}55` }}
          >
            {actor.country}
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-lg font-semibold tracking-tight">{actor.name}</h2>
              {actor.apt && <span className="chip chip-blue">{actor.apt}</span>}
              {actor.mitre_id && <span className="chip">{actor.mitre_id}</span>}
            </div>
            <div className="text-meta text-muted font-mono uppercase tracking-wider mt-0.5">
              {actor.aka.slice(0, 4).join(' · ')}
            </div>
            <div className="mt-2 flex items-center gap-3 text-meta text-muted">
              <span className="flex items-center gap-1.5">
                <Building2 size={12} /> {actor.agency}
              </span>
              <span className="flex items-center gap-1.5">
                <Calendar size={12} /> {actor.active_since}–{actor.last_seen}
              </span>
              <span className="chip chip-gold capitalize">{actor.motivation}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-muted hover:text-heading transition-colors" aria-label="Close">
            <X size={18} />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Description */}
        <section>
          <SectionHeader Icon={FileText}>Profile</SectionHeader>
          <p className="text-[13.5px] text-muted leading-relaxed">{actor.description}</p>
        </section>

        {/* Targets & Sectors */}
        <section>
          <SectionHeader Icon={Target}>Targets & sectors</SectionHeader>
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1.5">
              {actor.sectors.map((s) => (
                <span key={s} className="chip">
                  {s}
                </span>
              ))}
            </div>
            <div className="text-meta text-muted font-mono uppercase tracking-wider mt-2">Countries</div>
            <div className="flex flex-wrap gap-1.5">
              {actor.targets.map((t) => (
                <span key={t} className="chip chip-violet">
                  {t}
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* Sector scores (the differentiator) */}
        {actor.sector_scores.length > 0 && (
          <section>
            <SectionHeader Icon={Target}>Sector heat</SectionHeader>
            <div className="space-y-1.5">
              {actor.sector_scores.map((s) => (
                <div key={s.sector} className="flex items-center gap-2">
                  <span className="w-28 text-meta text-muted capitalize">{s.sector}</span>
                  <div className="flex-1 h-2 rounded-full bg-surface-300 overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${s.score}%`,
                        background: nation.color,
                      }}
                    />
                  </div>
                  <span className="text-mini font-mono text-muted w-8 text-right">{s.score}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* TTPs */}
        <section>
          <SectionHeader Icon={Crosshair}>MITRE ATT&CK ({actor.ttps.length})</SectionHeader>
          <div className="grid grid-cols-1 gap-1">
            {actor.ttps.map((t) => (
              <a
                key={t.id}
                href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 px-2.5 py-1.5 rounded-md hover:bg-surface-300 dark:hover:bg-surface-300 group transition-colors"
              >
                <span className="font-mono text-mini text-brand-600 dark:text-brand-400 w-20 shrink-0">{t.id}</span>
                <span className="text-[12.5px] text-heading flex-1">{t.name}</span>
                <span className="text-micro font-mono uppercase tracking-wider text-muted">{t.tactic}</span>
                <ExternalLink size={11} className="text-muted opacity-0 group-hover:opacity-100" />
              </a>
            ))}
          </div>
        </section>

        {/* Malware */}
        {actor.malware.length > 0 && (
          <section>
            <SectionHeader Icon={Bug}>Malware families ({actor.malware.length})</SectionHeader>
            <div className="grid grid-cols-1 gap-1">
              {actor.malware.map((m) => (
                <div
                  key={m.name}
                  className="flex items-center gap-2 px-2.5 py-1.5 rounded-md hover:bg-surface-200 dark:hover:bg-surface-300"
                >
                  <span className="text-tool text-heading">{m.name}</span>
                  <span className="chip chip-cyan ml-auto">{m.type}</span>
                  <span className="chip">{m.platform}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* CVEs */}
        {actor.cves.length > 0 && (
          <section>
            <SectionHeader Icon={Shield}>Exploited CVEs ({actor.cves.length})</SectionHeader>
            <div className="grid grid-cols-1 gap-1">
              {actor.cves.map((c) => (
                <div
                  key={c.id}
                  className="flex items-center gap-2 px-2.5 py-1.5 rounded-md hover:bg-surface-200 dark:hover:bg-surface-300 group transition-colors"
                >
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-2 flex-1 min-w-0"
                  >
                    <span className="font-mono text-meta text-amber-600 dark:text-amber-400">{c.id}</span>
                    <span className="text-[12.5px] text-heading flex-1">{c.product}</span>
                  </a>
                  <span className={cn('chip', c.cvss >= 9 ? 'chip-red' : c.cvss >= 7 ? 'chip-gold' : '')}>
                    CVSS {c.cvss}
                  </span>
                  <HexBrainLink
                    cve={c.id}
                    label="HB"
                    className="text-[10px] font-mono text-orange-600 dark:text-orange-300 hover:underline shrink-0"
                  />
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Campaigns */}
        {actor.campaigns.length > 0 && (
          <section>
            <SectionHeader Icon={Network}>Campaigns ({actor.campaigns.length})</SectionHeader>
            <div className="space-y-2">
              {actor.campaigns.map((c) => (
                <div key={c.name} className="p-3 rounded-lg bg-surface-200 border border-line-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[13.5px] font-medium text-heading">{c.name}</span>
                    <span className="text-[10.5px] font-mono text-muted ml-auto">
                      {c.start} → {c.end}
                    </span>
                  </div>
                  <p className="text-[12.5px] text-muted leading-relaxed">{c.summary}</p>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {c.sectors.map((s) => (
                      <span key={s} className="chip">
                        {s}
                      </span>
                    ))}
                    <span className="chip chip-green ml-auto">via {c.source}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Hunt queries */}
        {actor.hunt_queries.length > 0 && (
          <section>
            <SectionHeader Icon={Crosshair}>Hunt queries ({actor.hunt_queries.length})</SectionHeader>
            <div className="space-y-1.5">
              {actor.hunt_queries.map((h) => (
                <a
                  key={h.title}
                  href={h.url}
                  target="_blank"
                  rel="noreferrer"
                  className="block p-2.5 rounded-md hover:bg-surface-300 dark:hover:bg-surface-300 border border-transparent hover:border-line-1 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-tool text-heading">{h.title}</span>
                    <span className="chip chip-cyan ml-auto">{h.platform}</span>
                    <ExternalLink size={11} className="text-muted" />
                  </div>
                  <p className="text-meta text-muted mt-0.5">{h.description}</p>
                </a>
              ))}
            </div>
          </section>
        )}

        {/* Members */}
        {actor.members.length > 0 && (
          <section>
            <SectionHeader Icon={Users}>Indictments & sanctions</SectionHeader>
            <div className="space-y-1.5">
              {actor.members.map((m) => (
                <div key={m.name} className="flex items-center gap-2 p-2 rounded-md bg-surface-200">
                  <span className="text-[12.5px] text-heading flex-1">{m.name}</span>
                  <span className="text-[11.5px] text-muted">{m.role}</span>
                  <span className={cn('chip', m.status === 'indicted' ? 'chip-red' : 'chip-gold')}>{m.status}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Sources */}
        <section>
          <SectionHeader Icon={FileText}>Sources</SectionHeader>
          <ul className="space-y-1">
            {actor.sources.map((s) => (
              <li key={s.url}>
                <a
                  href={s.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 text-[12.5px] text-muted hover:text-brand-600 dark:text-brand-400 transition-colors"
                >
                  <ExternalLink size={11} /> {s.label}
                </a>
              </li>
            ))}
          </ul>
        </section>

        <p className="text-[10.5px] text-muted font-mono uppercase tracking-[0.18em] pt-4 border-t border-line-1">
          TLP:CLEAR · public intel · corroborate before operational use
        </p>
      </div>
    </aside>
  );
}

function SectionHeader({ Icon, children }: { Icon: typeof Shield; children: React.ReactNode }) {
  return (
    <h3 className="flex items-center gap-2 text-eyebrow font-mono text-muted mb-2.5">
      <Icon size={12} className="text-muted" /> {children}
    </h3>
  );
}
