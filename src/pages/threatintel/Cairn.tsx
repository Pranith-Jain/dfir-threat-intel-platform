import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { renderMarkdown } from '../../components/dfir/report-view-helpers';
import { BrainCircuit, ExternalLink, Loader2, ScanSearch, Search } from 'lucide-react';
import { errMessage } from '../../lib/log';

/**
 * CAIRN — Cisco-Talos Cognitive Artifact Intelligence Research Network (MIT).
 *
 * Tiered YARA rules (T1 primitive / T2 behavioral / T3 family attribution)
 * over VT-metadata scan text, 27 acquisition channels, A0–A11 archetypes,
 * and 10 published AI-malware family reports.
 *
 * Reads the replicated manifest through the platform API:
 *   GET  /api/v1/cairn/               → index
 *   GET  /api/v1/cairn/rules/:name    → full rule
 *   GET  /api/v1/cairn/families/:slug → full family report
 *   GET  /api/v1/cairn/archetypes     → taxonomy
 *   POST /api/v1/cairn/scan           → run rules over pasted scan text
 */

interface RuleSlim {
  name: string;
  tier: 'T1' | 'T2' | 'T3';
  confidence: number;
  artifactClass: string;
  description: string;
  family: string | null;
  stringCount: number;
}

interface RuleBody extends RuleSlim {
  artifactType: string;
  archetypes: string | null;
  reference: string | null;
  strings: Array<{ id: string; pattern: string; nocase: boolean }>;
  condition: string;
}

interface FamilySlim {
  slug: string;
  name: string;
  platform: string | null;
  archetype: string | null;
  summary: string;
}

interface FamilyBody extends FamilySlim {
  title: string;
  aliases: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  tlp: string | null;
  body: string;
  sourceUrl: string;
}

interface CairnIndex {
  source: string;
  sourceUrl: string;
  license: string;
  replicatedAt: string;
  counts: {
    rules: number;
    t1: number;
    t2: number;
    t3: number;
    filters: number;
    filtersEnabled: number;
    archetypes: number;
    families: number;
  };
  filterCategories: string[];
  rules: RuleSlim[];
  families: FamilySlim[];
}

interface Archetype {
  id: string;
  name: string;
  description: string;
  families: string[];
}

interface ScanMatch {
  rule: string;
  tier: string;
  artifactClass: string;
  confidence: number;
  description: string;
  family: string | null;
  matchedStrings: Array<{ id: string; pattern: string; excerpt: string }>;
}

interface ScanResult {
  matched: boolean;
  rulesEvaluated: number;
  matchCount: number;
  topTier: string | null;
  families: string[];
  matches: ScanMatch[];
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

const TIER_STYLES: Record<string, string> = {
  T1: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  T2: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  T3: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
};

type Tab = 'rules' | 'families' | 'archetypes' | 'scanner';

export default function Cairn(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<CairnIndex>({ url: '/api/v1/cairn/', ttl: 300_000 });
  const { data: archData } = useDataFetch<{ archetypes: Archetype[] }>({
    url: '/api/v1/cairn/archetypes',
    ttl: 300_000,
  });
  const [tab, setTab] = useState<Tab>('rules');
  const [tier, setTier] = useState('');
  const [q, setQ] = useState('');
  const [ruleBody, setRuleBody] = useState<RuleBody | null>(null);
  const [ruleLoading, setRuleLoading] = useState(false);
  const [familyBody, setFamilyBody] = useState<FamilyBody | null>(null);
  const [familyLoading, setFamilyLoading] = useState(false);
  const [scanText, setScanText] = useState('');
  const [scanTier, setScanTier] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const rules = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.rules ?? []).filter((r) => {
      if (tier && r.tier !== tier) return false;
      if (
        needle &&
        `${r.name} ${r.artifactClass} ${r.description} ${r.family ?? ''}`.toLowerCase().includes(needle) === false
      )
        return false;
      return true;
    });
  }, [data, tier, q]);

  const families = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.families ?? []).filter((f) => {
      if (
        needle &&
        `${f.name} ${f.platform ?? ''} ${f.archetype ?? ''} ${f.summary}`.toLowerCase().includes(needle) === false
      )
        return false;
      return true;
    });
  }, [data, q]);

  async function openRule(name: string) {
    setRuleLoading(true);
    try {
      setRuleBody(await api.get<RuleBody>(`/api/v1/cairn/rules/${encodeURIComponent(name)}`));
    } catch {
      setRuleBody(null);
    } finally {
      setRuleLoading(false);
    }
  }

  async function openFamily(slug: string) {
    setFamilyLoading(true);
    try {
      setFamilyBody(await api.get<FamilyBody>(`/api/v1/cairn/families/${encodeURIComponent(slug)}`));
    } catch {
      setFamilyBody(null);
    } finally {
      setFamilyLoading(false);
    }
  }

  async function runScan() {
    if (!scanText.trim()) return;
    setScanning(true);
    setScanResult(null);
    setScanError(null);
    try {
      setScanResult(await api.post<ScanResult>('/api/v1/cairn/scan', { text: scanText, tier: scanTier || undefined }));
    } catch (e) {
      setScanError(errMessage(e, 'Scan failed'));
    } finally {
      setScanning(false);
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'rules', label: `Rules (${data?.counts.rules ?? '…'})` },
    { id: 'families', label: `Families (${data?.counts.families ?? '…'})` },
    { id: 'archetypes', label: `Archetypes (${data?.counts.archetypes ?? '…'})` },
    { id: 'scanner', label: 'Scanner' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<BrainCircuit size={28} />}
      title="CAIRN"
      description="Cisco-Talos Cognitive Artifact Intelligence Research Network (MIT) — tiered YARA rules (T1 primitive / T2 behavioral / T3 family attribution) that spot AI artifacts in malware from VirusTotal metadata alone. No binary downloads, every hit traceable to a metadata field."
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-white border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab !== 'archetypes' && tab !== 'scanner' && (
        <div className="flex flex-col sm:flex-row gap-2 mb-4">
          {tab === 'rules' && (
            <select value={tier} onChange={(e) => setTier(e.target.value)} className={`${inputCls} sm:w-40`}>
              <option value="">All tiers</option>
              <option value="T1">T1 — Primitive</option>
              <option value="T2">T2 — Behavioral</option>
              <option value="T3">T3 — Family</option>
            </select>
          )}
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={tab === 'rules' ? 'Search rules…' : 'Search families…'}
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>
      )}

      {tab === 'rules' && (
        <div className="grid gap-2">
          {rules.map((r) => (
            <button
              key={r.name}
              onClick={() => openRule(r.name)}
              className="surface-card text-left p-3 hover:border-brand-400 transition-colors"
            >
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${TIER_STYLES[r.tier]}`}>
                  {r.tier}
                </span>
                <span className="font-mono text-sm text-heading">{r.name}</span>
                <span className="text-xs text-muted ml-auto">
                  conf {r.confidence} · {r.stringCount} strings
                </span>
              </div>
              <p className="text-sm text-body mt-1">{r.description}</p>
              {r.family && <p className="text-xs text-muted mt-1">Family: {r.family}</p>}
            </button>
          ))}
          {rules.length === 0 && !loading && <p className="text-sm text-muted">No rules match.</p>}
        </div>
      )}

      {tab === 'families' && (
        <div className="grid gap-2">
          {families.map((f) => (
            <button
              key={f.slug}
              onClick={() => openFamily(f.slug)}
              className="surface-card text-left p-3 hover:border-brand-400 transition-colors"
            >
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold text-heading">{f.name}</span>
                {f.platform && <span className="text-xs text-muted">{f.platform}</span>}
                {f.archetype && (
                  <span className="text-[11px] px-2 py-0.5 rounded border text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800">
                    {f.archetype}
                  </span>
                )}
              </div>
              <p className="text-sm text-body mt-1 line-clamp-2">{f.summary}</p>
            </button>
          ))}
          {families.length === 0 && !loading && <p className="text-sm text-muted">No families match.</p>}
        </div>
      )}

      {tab === 'archetypes' && (
        <div className="grid gap-2">
          {(archData?.archetypes ?? []).map((a) => (
            <div key={a.id} className="surface-card p-3">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-heading">{a.id}</span>
                <span className="font-semibold text-heading">{a.name}</span>
              </div>
              <p className="text-sm text-body mt-1">{a.description}</p>
              {a.families.length > 0 && (
                <p className="text-xs text-muted mt-1">Published families: {a.families.join(', ')}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'scanner' && (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Paste VT-metadata scan text (AV labels, PE resource strings, sandbox DNS/HTTP IOCs, ScriptBlock text) — the
            26 tiered rules run locally on the edge.
          </p>
          <textarea
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
            rows={7}
            placeholder={'e.g. Trojan.Python.LAMEHUG … router.huggingface.co … api.openai.com … target_file_list.log …'}
            className={`${inputCls} font-mono`}
          />
          <div className="flex gap-2">
            <select value={scanTier} onChange={(e) => setScanTier(e.target.value)} className={`${inputCls} sm:w-44`}>
              <option value="">All tiers</option>
              <option value="T1">T1 only</option>
              <option value="T2">T2 only</option>
              <option value="T3">T3 only</option>
            </select>
            <button
              onClick={runScan}
              disabled={scanning || !scanText.trim()}
              className="px-4 py-2 rounded-xl bg-brand-600 text-on-fill text-sm font-medium disabled:opacity-50 flex items-center gap-2"
            >
              {scanning ? <Loader2 size={15} className="animate-spin" /> : <ScanSearch size={15} />}
              Scan
            </button>
          </div>
          {scanError && <p className="text-sm text-rose-600">{scanError}</p>}
          {scanResult && (
            <div className="space-y-2">
              <p className="text-sm text-heading font-medium">
                {scanResult.matched
                  ? `${scanResult.matchCount} match${scanResult.matchCount === 1 ? '' : 'es'} — top tier ${scanResult.topTier}`
                  : 'No matches'}{' '}
                ({scanResult.rulesEvaluated} rules evaluated)
                {scanResult.families.length > 0 && ` · families: ${scanResult.families.join(', ')}`}
              </p>
              {scanResult.matches.map((m) => (
                <div key={m.rule} className="surface-card p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${TIER_STYLES[m.tier]}`}>
                      {m.tier}
                    </span>
                    <span className="font-mono text-sm text-heading">{m.rule}</span>
                    <span className="text-xs text-muted ml-auto">conf {m.confidence}</span>
                  </div>
                  <p className="text-sm text-body mt-1">{m.description}</p>
                  <div className="mt-2 space-y-1">
                    {m.matchedStrings.slice(0, 4).map((s, i) => (
                      <p key={i} className="font-mono text-xs text-muted break-all">
                        <span className="text-brand-600 dark:text-brand-400">{s.id}</span> {s.excerpt}
                      </p>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <Modal
        open={ruleLoading || ruleBody !== null}
        onClose={() => {
          setRuleBody(null);
        }}
        title={ruleBody?.name ?? 'Loading rule…'}
        size="lg"
      >
        {ruleBody && (
          <div className="space-y-4 max-h-[70vh] overflow-y-auto">
            <p className="text-sm text-body">{ruleBody.description}</p>
            <div className="flex gap-2 flex-wrap text-xs">
              <span className={`font-bold px-2 py-0.5 rounded border ${TIER_STYLES[ruleBody.tier]}`}>
                {ruleBody.tier}
              </span>
              <span className="text-muted">conf {ruleBody.confidence}</span>
              <span className="text-muted">{ruleBody.artifactClass}</span>
              {ruleBody.family && <span className="text-muted">family {ruleBody.family}</span>}
            </div>
            <div>
              <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-1">Condition</div>
              <p className="font-mono text-xs text-heading bg-surface-200 border border-line-1 rounded px-3 py-2 break-all">
                {ruleBody.condition}
              </p>
            </div>
            <div>
              <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-1">
                Strings ({ruleBody.strings.length})
              </div>
              <div className="space-y-1">
                {ruleBody.strings.map((s) => (
                  <p key={s.id} className="font-mono text-xs text-body break-all">
                    <span className="text-brand-600 dark:text-brand-400">{s.id}</span> “{s.pattern}”
                    {s.nocase ? ' nocase' : ''}
                  </p>
                ))}
              </div>
            </div>
            {ruleBody.reference && <p className="text-xs text-muted">{ruleBody.reference}</p>}
          </div>
        )}
      </Modal>

      <Modal
        open={familyLoading || familyBody !== null}
        onClose={() => {
          setFamilyBody(null);
        }}
        title={familyBody?.name ?? 'Loading family…'}
        size="lg"
      >
        {familyBody && (
          <div className="space-y-4 max-h-[70vh] overflow-y-auto">
            <div className="flex gap-3 flex-wrap text-xs text-muted">
              {familyBody.platform && <span>Platform: {familyBody.platform}</span>}
              {familyBody.archetype && <span>{familyBody.archetype}</span>}
              {familyBody.firstSeen && <span>First seen: {familyBody.firstSeen}</span>}
              {familyBody.tlp && <span>{familyBody.tlp}</span>}
            </div>
            <div
              className="prose dark:prose-invert prose-sm max-w-none"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(familyBody.body) }}
            />
            <a
              href={familyBody.sourceUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-brand-600 dark:text-brand-400"
            >
              Upstream report <ExternalLink size={12} />
            </a>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
