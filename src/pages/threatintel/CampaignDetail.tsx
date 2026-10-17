import { logCatch } from '../../lib/log';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Sparkles, AlertTriangle, ExternalLink, Copy, Check, Trash2 } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ShareBar } from '../../components/intel/ShareBar';
import { turnstileHeaders } from '../../lib/turnstile';

interface KillChainStep {
  phase: string;
  description: string;
}
interface MitreTechRef {
  id: string;
  name: string;
  rationale: string;
}
interface CampaignDoc {
  campaign_name: string;
  summary: string;
  actor_context: string;
  kill_chain: KillChainStep[];
  mitre_techniques: MitreTechRef[];
  hunting_hypotheses: string[];
  detection_opportunities: string[];
  iocs_to_pivot: string[];
  confidence: 'low' | 'medium' | 'high';
  caveats: string[];
}
interface SavedCampaign {
  id: string;
  saved_at: string;
  generated_at: string;
  model_used: string;
  input: { actor?: string; sector?: string; ttps?: string; notes?: string; iocs?: string[] };
  campaign: CampaignDoc;
}

const PHASE_LABELS: Record<string, string> = {
  recon: 'Reconnaissance',
  weaponization: 'Weaponization',
  delivery: 'Delivery',
  exploitation: 'Exploitation',
  installation: 'Installation',
  c2: 'Command & Control',
  actions: 'Actions on Objectives',
};
const PHASE_ORDER = ['recon', 'weaponization', 'delivery', 'exploitation', 'installation', 'c2', 'actions'];

const CONFIDENCE_COLOR: Record<CampaignDoc['confidence'], string> = {
  high: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
  medium: 'text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10',
  low: 'text-rose-600 dark:text-rose-400 border-rose-500/40 bg-rose-500/10',
};

function buildMarkdown(d: CampaignDoc, input: SavedCampaign['input'], model: string, ts: string): string {
  const lines: string[] = [];
  lines.push(`# ${d.campaign_name}`);
  lines.push('');
  lines.push(`**Confidence:** ${d.confidence}  ·  **Model:** ${model}  ·  **Generated:** ${ts}`);
  if (input.actor) lines.push(`**Actor:** ${input.actor}`);
  if (input.sector) lines.push(`**Sector:** ${input.sector}`);
  lines.push('');
  if (d.summary) {
    lines.push('## Summary');
    lines.push(d.summary);
    lines.push('');
  }
  if (d.actor_context) {
    lines.push('## Actor context');
    lines.push(d.actor_context);
    lines.push('');
  }
  if (d.kill_chain.length) {
    lines.push('## Kill chain');
    for (const k of d.kill_chain) lines.push(`- **${PHASE_LABELS[k.phase] ?? k.phase}:** ${k.description}`);
    lines.push('');
  }
  if (d.mitre_techniques.length) {
    lines.push('## MITRE ATT&CK');
    for (const m of d.mitre_techniques) lines.push(`- **${m.id} - ${m.name}** - ${m.rationale}`);
    lines.push('');
  }
  if (d.hunting_hypotheses.length) {
    lines.push('## Hunting hypotheses');
    for (const h of d.hunting_hypotheses) lines.push(`- ${h}`);
    lines.push('');
  }
  if (d.detection_opportunities.length) {
    lines.push('## Detection opportunities');
    for (const det of d.detection_opportunities) lines.push(`- ${det}`);
    lines.push('');
  }
  if (input.iocs && input.iocs.length) {
    lines.push('## Attached IOCs');
    for (const i of input.iocs) lines.push(`- ${i}`);
    lines.push('');
  }
  if (d.iocs_to_pivot.length) {
    lines.push('## IOCs to pivot on');
    for (const i of d.iocs_to_pivot) lines.push(`- ${i}`);
    lines.push('');
  }
  if (d.caveats.length) {
    lines.push('## Caveats');
    for (const c of d.caveats) lines.push(`- ${c}`);
  }
  return lines.join('\n');
}

export default function CampaignDetail(): JSX.Element {
  const { id = '' } = useParams<{ id: string }>();
  const [data, setData] = useState<SavedCampaign | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [deleted, setDeleted] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(`/api/v1/campaigns/${id}`)
      .then(async (r) => {
        const body = (await r.json()) as SavedCampaign | { error: string };
        if (cancelled) return;
        if (!r.ok || 'error' in body) {
          setError('error' in body ? body.error : `HTTP ${r.status}`);
        } else {
          setData(body);
        }
      })
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const handleDelete = async () => {
    if (!window.confirm('Delete this campaign? This cannot be undone.')) return;
    try {
      const r = await fetch(`/api/v1/campaigns/${id}`, {
        method: 'DELETE',
        headers: await turnstileHeaders('delete-campaign'),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setDeleted(true);
    } catch (e) {
      logCatch(e);
      setError(`Delete failed: ${(e as Error).message}`);
    }
  };

  const copyMarkdown = async () => {
    if (!data) return;
    try {
      const md = buildMarkdown(data.campaign, data.input, data.model_used, data.generated_at);
      await navigator.clipboard.writeText(md);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* clipboard blocked */
    }
  };

  if (deleted) {
    return (
      <div className="max-w-3xl mx-auto px-4 sm:px-8 py-12 sm:py-20 text-heading text-center">
        <Trash2 size={28} className="mx-auto text-muted mb-2" />
        <p className="text-sm font-mono text-muted mb-3">Campaign deleted.</p>
        <Link
          to="/threatintel/catalog?cat=campaigns"
          className="text-sm font-mono text-rose-600 dark:text-rose-400 hover:underline"
        >
          ← back to campaigns
        </Link>
      </div>
    );
  }

  const orderedKillChain = data
    ? [...data.campaign.kill_chain].sort((a, b) => PHASE_ORDER.indexOf(a.phase) - PHASE_ORDER.indexOf(b.phase))
    : [];

  return (
    <DataPageLayout
      backTo="/threatintel/campaigns"
      backLabel="back to campaigns"
      icon={<Sparkles size={28} />}
      title={data ? data.campaign.campaign_name : 'Campaign'}
      description={
        data && (
          <span className="flex items-center gap-2 flex-wrap text-micro font-mono not-italic">
            <span className={`px-1.5 py-0.5 rounded border ${CONFIDENCE_COLOR[data.campaign.confidence]}`}>
              confidence: {data.campaign.confidence}
            </span>
            <span className="text-muted">model: {data.model_used}</span>
            <span className="text-muted">saved: {new Date(data.saved_at).toLocaleString()}</span>
          </span>
        )
      }
      headerExtra={
        data && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void copyMarkdown()}
              className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2.5 py-1 text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 hover:border-rose-500/40"
            >
              {copied ? (
                <>
                  <Check size={11} /> copied
                </>
              ) : (
                <>
                  <Copy size={11} /> copy as markdown
                </>
              )}
            </button>
            <button
              type="button"
              onClick={() => void handleDelete()}
              className="inline-flex items-center gap-1.5 rounded border border-rose-300 dark:border-rose-700 px-2.5 py-1 text-mini font-mono text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950"
            >
              <Trash2 size={11} /> delete
            </button>
          </div>
        )
      }
      loading={loading}
      error={error}
    >
      {data && (
        <section className="surface-card p-6">
          {(data.input.actor || data.input.sector) && (
            <div className="flex flex-wrap gap-2 mb-4 text-mini font-mono">
              {data.input.actor && (
                <span className="rounded border border-line-1 bg-surface-200 px-2 py-0.5 text-body">
                  actor: {data.input.actor}
                </span>
              )}
              {data.input.sector && (
                <span className="rounded border border-line-1 bg-surface-200 px-2 py-0.5 text-body">
                  sector: {data.input.sector}
                </span>
              )}
            </div>
          )}

          {data.campaign.summary && <p className="text-sm text-body leading-relaxed mb-4">{data.campaign.summary}</p>}

          <div className="mb-5 pt-3 border-t border-line-1">
            <ShareBar
              shareText={
                data.campaign.summary?.split('\n')[0]?.slice(0, 200) || `Campaign: ${data.campaign.campaign_name}`
              }
              title={`Campaign: ${data.campaign.campaign_name}`}
              size="sm"
              label="Share:"
            />
          </div>

          {data.campaign.actor_context && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-1.5">Actor context</h3>
              <p className="text-sm text-body leading-relaxed">{data.campaign.actor_context}</p>
            </div>
          )}

          {orderedKillChain.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Kill chain</h3>
              <ol className="space-y-2">
                {orderedKillChain.map((k, i) => (
                  <li key={`${k.phase}-${i}`} className="rounded-xl border border-line-1 bg-surface-200 p-3">
                    <div className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400 mb-0.5">
                      {PHASE_LABELS[k.phase] ?? k.phase}
                    </div>
                    <div className="text-sm text-body">{k.description}</div>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {data.campaign.mitre_techniques.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">MITRE ATT&amp;CK</h3>
              <ul className="space-y-1.5">
                {data.campaign.mitre_techniques.map((m) => (
                  <li key={m.id} className="text-sm rounded-xl border border-line-1 bg-surface-200 p-2.5">
                    <a
                      href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono font-semibold text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 transition-colors"
                    >
                      {m.id} <ExternalLink size={9} />
                    </a>{' '}
                    <span className="font-semibold text-heading">- {m.name}</span>
                    <div className="text-mini font-mono text-muted mt-0.5">{m.rationale}</div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {data.input.iocs && data.input.iocs.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
                Attached IOCs ({data.input.iocs.length})
              </h3>
              <ul className="space-y-1">
                {data.input.iocs.map((ioc) => (
                  <li
                    key={ioc}
                    className="flex items-center gap-2 rounded border border-line-1 bg-surface-200 p-2 text-sm font-mono"
                  >
                    <span className="flex-1 truncate text-body" title={ioc}>
                      {ioc}
                    </span>
                    <Link
                      to={`/dfir/ioc-check?indicator=${encodeURIComponent(ioc)}`}
                      className="text-micro text-rose-600 dark:text-rose-400 hover:underline shrink-0"
                    >
                      pivot →
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {data.campaign.hunting_hypotheses.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Hunting hypotheses</h3>
              <ul className="space-y-1.5 list-disc list-inside text-sm text-body">
                {data.campaign.hunting_hypotheses.map((h) => (
                  <li key={h}>{h}</li>
                ))}
              </ul>
            </div>
          )}

          {data.campaign.detection_opportunities.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">Detection opportunities</h3>
              <ul className="space-y-1.5">
                {data.campaign.detection_opportunities.map((d) => (
                  <li key={d} className="text-sm font-mono rounded border border-line-1 bg-surface-200 p-2.5 text-body">
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {data.campaign.iocs_to_pivot.length > 0 && (
            <div className="mb-5">
              <h3 className="text-xs font-mono uppercase tracking-wider text-muted mb-2">IOCs to pivot on</h3>
              <ul className="space-y-1">
                {data.campaign.iocs_to_pivot.map((i, idx) => (
                  <li key={idx} className="text-sm rounded border border-line-1 bg-surface-200 p-2 text-body">
                    {i}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {data.campaign.caveats.length > 0 && (
            <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50/60 dark:bg-amber-950/40 p-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-amber-700 dark:text-amber-400 mb-2 inline-flex items-center gap-1">
                <AlertTriangle size={11} /> Caveats
              </h3>
              <ul className="space-y-1 list-disc list-inside text-xs font-mono text-amber-900 dark:text-amber-200">
                {data.campaign.caveats.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </DataPageLayout>
  );
}
