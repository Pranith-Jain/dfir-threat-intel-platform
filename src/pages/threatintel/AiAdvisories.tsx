import { useEffect, useMemo, useState } from 'react';
import { Rss, Search, ExternalLink } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

interface Advisory {
  id: string;
  title: string;
  link: string;
  updated: string | null;
  source: string;
  kind: string;
  cves: string[];
  description: string;
}

interface Research {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  source: string;
  description: string;
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

const KIND_LABEL: Record<string, string> = {
  cve: 'CVE firehose',
  release: 'Tool release',
  exploit: 'Exploit PoC',
  advisory: 'GHSA advisory',
};

export default function AiAdvisories(): JSX.Element {
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [advSources, setAdvSources] = useState<Record<string, number>>({});
  const [research, setResearch] = useState<Research[]>([]);
  const [resSources, setResSources] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [advSource, setAdvSource] = useState('all');
  const [resSource, setResSource] = useState('all');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [aRes, rRes] = await Promise.all([
        fetch('/api/v1/ai-security/advisories?limit=200'),
        fetch('/api/v1/ai-security/research?limit=200'),
      ]);
      if (!aRes.ok) throw new Error(`advisories HTTP ${aRes.status}`);
      if (!rRes.ok) throw new Error(`research HTTP ${rRes.status}`);
      const a = (await aRes.json()) as { items: Advisory[]; bySource: Record<string, number> };
      const r = (await rRes.json()) as { items: Research[]; bySource: Record<string, number> };
      setAdvisories(a.items ?? []);
      setAdvSources(a.bySource ?? {});
      setResearch(r.items ?? []);
      setResSources(r.bySource ?? {});
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const needle = query.toLowerCase().trim();
  const filteredAdv = useMemo(
    () =>
      advisories.filter((a) => {
        if (advSource !== 'all' && a.source !== advSource) return false;
        if (needle && !`${a.title} ${a.source} ${(a.cves ?? []).join(' ')}`.toLowerCase().includes(needle))
          return false;
        return true;
      }),
    [advisories, advSource, needle]
  );
  const filteredRes = useMemo(
    () =>
      research.filter((r) => {
        if (resSource !== 'all' && r.source !== resSource) return false;
        if (needle && !`${r.title} ${r.source}`.toLowerCase().includes(needle)) return false;
        return true;
      }),
    [research, resSource, needle]
  );

  const chip = (active: boolean) =>
    `px-2 py-1 rounded text-xs font-mono font-medium border transition ${
      active
        ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
        : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
    }`;

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      backLabel="AI Security"
      icon={<Rss size={28} />}
      title="Advisories & Research"
      description="Realtime AI advisory firehose — cvelistV5 CVE commits matched to known AI CVEs, tool release trains (garak, PyRIT, promptfoo, litellm, vllm, ollama, langchain, MCP SDK, MITRE ATLAS, OWASP GenAI), ExploitDB PoCs — plus research from Hacktron, Unit42, CSA, and BleepingComputer. Sync runs daily via the ai-security workflow."
      loading={loading && advisories.length === 0 && research.length === 0}
      error={error}
      onRetry={load}
    >
      <AiSummaryCard
        surface="AI Advisories"
        items={filteredAdv.slice(0, 10).map((a) => ({
          title: a.title,
          body: `${a.source} · ${KIND_LABEL[a.kind] ?? a.kind} · ${fmtDate(a.updated)}`,
          source: a.link,
        }))}
        requireAdmin={false}
      />
      <div className="relative my-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
        <input
          type="text"
          placeholder="Search advisories + research…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
        />
      </div>

      <h2 className="text-lg font-bold text-heading mb-2">
        Advisory firehose <span className="font-mono text-xs text-muted">{filteredAdv.length}</span>
      </h2>
      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        {['all', ...Object.keys(advSources)].map((s) => (
          <button key={s} onClick={() => setAdvSource(s)} className={chip(advSource === s)}>
            {s} · {s === 'all' ? advisories.length : (advSources[s] ?? 0)}
          </button>
        ))}
      </div>
      <div className="grid gap-2 mb-8">
        {filteredAdv.map((a) => (
          <div key={a.id} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                {a.source}
              </span>
              <span className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body">
                {KIND_LABEL[a.kind] ?? a.kind}
              </span>
              <span className="text-micro font-mono text-muted">{fmtDate(a.updated)}</span>
            </div>
            <a
              href={sanitizeUrl(a.link) ?? undefined}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="group"
            >
              <h3 className="text-sm font-bold text-heading mt-1 leading-snug group-hover:text-rose-600 dark:group-hover:text-rose-400">
                {a.title} <ExternalLink className="inline w-2.5 h-2.5 text-muted" />
              </h3>
            </a>
            {a.cves.length > 0 && <p className="text-mini font-mono text-muted mt-1">{a.cves.join(', ')}</p>}
          </div>
        ))}
      </div>

      <h2 className="text-lg font-bold text-heading mb-2">
        Research <span className="font-mono text-xs text-muted">{filteredRes.length}</span>
      </h2>
      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        {['all', ...Object.keys(resSources)].map((s) => (
          <button key={s} onClick={() => setResSource(s)} className={chip(resSource === s)}>
            {s} · {s === 'all' ? research.length : (resSources[s] ?? 0)}
          </button>
        ))}
      </div>
      <div className="grid gap-2">
        {filteredRes.map((r) => (
          <div key={r.id} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                {r.source}
              </span>
              <span className="text-micro font-mono text-muted">{fmtDate(r.pubDate)}</span>
            </div>
            <a
              href={sanitizeUrl(r.link) ?? undefined}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="group"
            >
              <h3 className="text-sm font-bold text-heading mt-1 leading-snug group-hover:text-rose-600 dark:group-hover:text-rose-400">
                {r.title} <ExternalLink className="inline w-2.5 h-2.5 text-muted" />
              </h3>
            </a>
            {r.description && <p className="text-xs text-muted mt-1 leading-relaxed line-clamp-2">{r.description}</p>}
          </div>
        ))}
      </div>
    </DataPageLayout>
  );
}
