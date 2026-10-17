import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, useCallback } from 'react';
import { Server, Database, Shield, Loader2, RefreshCw } from 'lucide-react';
import { CopyButton } from '../../components/dfir/CopyButton';

interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
}

interface TaxiiObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  [key: string]: unknown;
}

const TYPE_BADGE: Record<string, string> = {
  indicator: 'bg-sky-100 text-cyan-800 dark:bg-sky-500/10 dark:text-sky-300',
  'threat-actor': 'bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300',
  malware: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  vulnerability: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
  report: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
};

export default function TaxiiServer(): JSX.Element {
  const [collections, setCollections] = useState<TaxiiCollection[]>([]);
  const [selectedCollection, setSelectedCollection] = useState<string | null>(null);
  const [objects, setObjects] = useState<TaxiiObject[]>([]);
  const [loading, setLoading] = useState(false);
  const [objectsLoading, setObjectsLoading] = useState(false);

  const fetchCollections = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/taxii2/collections/');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON');
      const data = (await res.json()) as { collections?: TaxiiCollection[] };
      setCollections(data.collections ?? []);
    } catch (_catchErr) {
      console.error('TaxiiServer failed:', errMessage(_catchErr));
      /* silent */
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchObjects = useCallback(async (collectionId: string) => {
    setObjectsLoading(true);
    try {
      const res = await fetch(`/api/taxii2/collections/${collectionId}/objects/?limit=50`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON');
      const data = (await res.json()) as { objects?: TaxiiObject[] };
      setObjects(data.objects ?? []);
    } catch (_catchErr) {
      logCatch(_catchErr);
      setObjects([]);
    } finally {
      setObjectsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchCollections();
  }, [fetchCollections]);
  useEffect(() => {
    if (selectedCollection) fetchObjects(selectedCollection);
  }, [selectedCollection, fetchObjects]);

  const baseUrl = typeof window !== 'undefined' ? `${window.location.origin}/api/taxii2/` : '/api/taxii2/';

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up mb-10">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Server size={28} className="text-brand-600 dark:text-brand-400" /> TAXII 2.1 Server
        </h1>
        <p className="text-muted max-w-2xl leading-relaxed">
          Browse and consume STIX 2.1 collections via the TAXII protocol. Compatible with MISP, OpenCTI, Splunk SOAR,
          and any TAXII 2.1 client.
        </p>
      </div>

      {/* Connection Details */}
      <div className="surface-card/40 shadow-e1 p-5 mb-6">
        <h2 className="font-display font-bold text-sm mb-3 flex items-center gap-2">
          <Database size={14} className="text-brand-600 dark:text-brand-400" /> Connection
        </h2>
        <div className="space-y-2">
          <div className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-200 px-3 py-2">
            <span className="text-micro font-mono uppercase tracking-wider text-muted shrink-0">Discovery</span>
            <code className="text-xs text-brand-600 dark:text-brand-400 flex-1 truncate font-mono">{baseUrl}</code>
            <CopyButton value={baseUrl} />
          </div>
          <div className="flex items-center gap-2 rounded-xl border border-line-1 bg-surface-200 px-3 py-2">
            <span className="text-micro font-mono uppercase tracking-wider text-muted shrink-0">Content-Type</span>
            <code className="text-xs text-muted font-mono">application/vnd.oasis.taxii+json; version=2.1</code>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Collections */}
        <div className="surface-card/40 shadow-e1 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display font-bold text-sm flex items-center gap-2">
              <Shield size={14} className="text-brand-600 dark:text-brand-400" /> Collections ({collections.length})
            </h2>
            <button
              aria-label="Refresh"
              onClick={fetchCollections}
              className="p-1.5 rounded-xl hover:bg-surface-300 dark:hover:bg-surface-300 text-muted transition-colors"
            >
              <RefreshCw size={14} />
            </button>
          </div>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="animate-spin text-muted" />
            </div>
          ) : (
            <div className="space-y-1.5">
              {collections.map((col) => (
                <button
                  key={col.id}
                  onClick={() => setSelectedCollection(col.id)}
                  className={`w-full text-left p-3 rounded-xl border transition-colors ${
                    selectedCollection === col.id
                      ? 'border-brand-500/60 bg-brand-500/5'
                      : 'border-line-1 hover:border-brand-500/30'
                  }`}
                >
                  <div className="text-sm font-medium">{col.title}</div>
                  <div className="text-xs text-muted mt-0.5 line-clamp-2">{col.description}</div>
                  <div className="flex gap-1.5 mt-1.5">
                    {col.can_read && (
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300">
                        read
                      </span>
                    )}
                    {col.can_write && (
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-300">
                        write
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Objects */}
        <div className="lg:col-span-2 surface-card/40 shadow-e1 p-5">
          <h2 className="font-display font-bold text-sm mb-4 flex items-center gap-2">
            <Database size={14} className="text-brand-600 dark:text-brand-400" />
            STIX Objects{' '}
            {selectedCollection && <span className="font-mono text-xs text-muted">· {selectedCollection}</span>}
          </h2>
          {!selectedCollection ? (
            <p className="text-sm text-muted py-8 text-center">Select a collection to view objects</p>
          ) : objectsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="animate-spin text-muted" />
            </div>
          ) : objects.length === 0 ? (
            <p className="text-sm text-muted py-8 text-center">No objects in this collection</p>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {objects.map((obj, i) => (
                <ObjectCard key={obj.id || i} obj={obj} />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Usage Examples */}
      <div className="mt-6 surface-card/40 shadow-e1 p-5">
        <h2 className="font-display font-bold text-sm mb-4">Quick Start</h2>
        <div className="space-y-3">
          <CodeBlock
            title="curl - List collections"
            code={`curl -H "Accept: application/vnd.oasis.taxii+json; version=2.1" \\\n  ${baseUrl}collections/`}
          />
          <CodeBlock
            title="curl - Get IOCs"
            code={`curl -H "Accept: application/stix+json; version=2.1" \\\n  "${baseUrl}collections/iocs/objects/?limit=100"`}
          />
        </div>
      </div>
    </div>
  );
}

function ObjectCard({ obj }: { obj: TaxiiObject }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      className="rounded-xl border border-line-1 bg-surface-200 p-3 cursor-pointer hover:border-brand-500/30 transition-colors"
      onClick={() => setExpanded(!expanded)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setExpanded(!expanded);
        }
      }}
    >
      <div className="flex items-center gap-2">
        <span
          className={`text-micro font-mono px-1.5 py-0.5 rounded ${TYPE_BADGE[obj.type] ?? 'bg-slate-100 text-slate-600 dark:bg-surface-300 dark:text-muted'}`}
        >
          {obj.type}
        </span>
        <span className="text-sm font-medium truncate">{obj.name || obj.id}</span>
      </div>
      {obj.description && <p className="text-xs text-muted mt-1 line-clamp-2">{obj.description}</p>}
      {expanded && (
        <div className="mt-3 pt-3 border-t border-line-1 text-xs space-y-1">
          <div>
            <span className="text-muted">ID:</span> <code className="font-mono text-body">{obj.id}</code>
          </div>
          {obj.created && (
            <div>
              <span className="text-muted">Created:</span> {new Date(obj.created).toLocaleString()}
            </div>
          )}
          {obj.modified && (
            <div>
              <span className="text-muted">Modified:</span> {new Date(obj.modified).toLocaleString()}
            </div>
          )}
          <pre className="bg-surface-300 rounded p-2 overflow-x-auto text-micro text-muted font-mono mt-2">
            {JSON.stringify(obj, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function CodeBlock({ title, code }: { title: string; code: string }) {
  return (
    <div>
      <div className="text-xs text-muted mb-1">{title}</div>
      <div className="flex items-start gap-2 rounded-xl border border-line-1 bg-surface-200 p-3">
        <pre className="text-xs text-body flex-1 overflow-x-auto font-mono">{code}</pre>
        <CopyButton value={code} />
      </div>
    </div>
  );
}
