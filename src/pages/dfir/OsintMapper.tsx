import { useEffect, useMemo, useRef, useState, lazy } from 'react';
import { Map as MapIcon, Download, Upload, Plus, FilePlus2 } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { IdentifierGraph } from '../../components/dfir/osint/IdentifierGraph';
const MapPane = lazy(() => import('../../components/dfir/osint/MapPane').then((m) => ({ default: m.MapPane })));
import { IdentifierForm } from '../../components/dfir/osint/IdentifierForm';
import { PinForm } from '../../components/dfir/osint/PinForm';
import {
  emptyProject,
  type Identifier,
  type Link,
  type OsintProject,
  type Pin,
} from '../../lib/dfir/osint/osint-schema';
import { loadState, saveProject, buildExport, parseImport } from '../../lib/dfir/osint/osint-store';
import {
  deleteIdentifier,
  deletePin,
  updateIdentifier,
  updatePin,
  setPosition,
} from '../../lib/dfir/osint/osint-mutations';
import { reverseGeocode } from '../../lib/dfir/osint/geocode';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

const ICONS_KEY = 'dfir-osint-icons:v1';

function loadIcons(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(ICONS_KEY) ?? '{}') as Record<string, string>;
  } catch (_catchErr) {
    console.error('loadIcons failed:', errMessage(_catchErr));
    return {};
  }
}

type Selection = { kind: 'identifier' | 'pin'; id: string } | null;

export default function OsintMapper(): JSX.Element {
  const [project, setProject] = useState<OsintProject>(() => loadState().current ?? emptyProject('Untitled case'));
  const [icons, setIcons] = useState<Record<string, string>>(loadIcons);
  const [tab, setTab] = useState<'graph' | 'map'>('graph');
  const [pending, setPending] = useState<{ lat: number; lng: number; address?: string } | null>(null);
  const [addingId, setAddingId] = useState(false);
  const [editingIdentifier, setEditingIdentifier] = useState<Identifier | null>(null);
  const [editingPin, setEditingPin] = useState<Pin | null>(null);
  const [selection, setSelection] = useState<Selection>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Debounced autosave. Date.now() is fine in the browser (not a workflow script).
  useEffect(() => {
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => saveProject(project, Date.now()), 400);
    return () => clearTimeout(saveTimer.current);
  }, [project]);

  const linkedPinIds = useMemo(() => {
    if (selection?.kind !== 'identifier') return new Set<string>();
    return new Set(project.links.filter((l) => l.identifierId === selection.id).map((l) => l.pinId));
  }, [selection, project.links]);

  // Form submit for identifiers: edit in place when editing, else add new.
  function submitIdentifier(id: Identifier, iconDataUrl?: string) {
    if (editingIdentifier) {
      setProject((p) => updateIdentifier(p, id.id, { type: id.type, fields: id.fields }));
      setEditingIdentifier(null);
      return;
    }
    let withIcon = id;
    if (iconDataUrl) {
      const iconId = crypto.randomUUID();
      const nextIcons = { ...icons, [iconId]: iconDataUrl };
      setIcons(nextIcons);
      try {
        localStorage.setItem(ICONS_KEY, JSON.stringify(nextIcons));
      } catch (_catchErr) {
        console.error('submitIdentifier failed:', errMessage(_catchErr));
        // quota / private-mode: keep icon in memory only
      }
      withIcon = { ...id, customIconId: iconId };
    }
    setProject((p) => ({ ...p, identifiers: [...p.identifiers, withIcon] }));
    setAddingId(false);
  }

  // Form submit for pins: edit attributes when editing (links untouched), else add.
  function submitPin(pin: Pin, linkedIds: string[]) {
    if (editingPin) {
      setProject((p) => updatePin(p, pin));
      setEditingPin(null);
      return;
    }
    const links: Link[] = linkedIds.map((identifierId) => ({ id: crypto.randomUUID(), identifierId, pinId: pin.id }));
    setProject((p) => ({ ...p, pins: [...p.pins, pin], links: [...p.links, ...links] }));
    setPending(null);
  }

  function removeIdentifier(id: string) {
    setProject((p) => deleteIdentifier(p, id));
    setSelection((s) => (s?.kind === 'identifier' && s.id === id ? null : s));
  }

  function removePin(id: string) {
    setProject((p) => deletePin(p, id));
    setSelection((s) => (s?.kind === 'pin' && s.id === id ? null : s));
  }

  function openEditIdentifier(id: string) {
    const found = project.identifiers.find((i) => i.id === id);
    if (found) setEditingIdentifier(found);
  }

  function openEditPin(id: string) {
    const found = project.pins.find((p) => p.id === id);
    if (found) setEditingPin(found);
  }

  function moveNode(id: string, pos: { x: number; y: number }) {
    setProject((p) => setPosition(p, id, pos));
  }

  async function handleMapClick(lat: number, lng: number) {
    const address = (await reverseGeocode(lat, lng)) ?? undefined;
    setPending({ lat, lng, address });
  }

  function doExport() {
    const blob = new Blob([buildExport(project, icons)], { type: 'application/json' });
    downloadBlob(blob, `${project.name.replace(/\s+/g, '-') || 'case'}.osint.json`);
  }

  function doImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    void file.text().then((t) => {
      const imported = parseImport(t);
      if (imported) {
        // Merge any embedded custom icons into the per-browser library so the
        // imported case keeps its icons on this machine.
        if (Object.keys(imported.icons).length) {
          const nextIcons = { ...icons, ...imported.icons };
          setIcons(nextIcons);
          try {
            localStorage.setItem(ICONS_KEY, JSON.stringify(nextIcons));
          } catch (_catchErr) {
            console.error('doImport failed:', errMessage(_catchErr));
            // quota / private-mode: keep icons in memory only
          }
        }
        setProject(imported.project);
        setSelection(null);
        setImportError(null);
      } else {
        setImportError('Invalid .osint.json file - not a recognized OSINT project.');
      }
    });
    e.target.value = '';
  }

  const overlayWrap = 'fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4';
  const overlayCard = 'bg-white dark:bg-surface-200 rounded-xl p-4 w-full max-w-md shadow-e3';

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<MapIcon size={28} />}
      title="OSINT Mapper"
      description="Catalog identifiers, pin locations, and cross-link them. All data stays in your browser."
      maxWidthClass="max-w-7xl"
      error={importError}
      onRetry={importError ? () => setImportError(null) : undefined}
      headerExtra={
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => {
              setProject(emptyProject('Untitled case'));
              setSelection(null);
            }}
            className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded border border-line-2"
          >
            <FilePlus2 size={14} /> New
          </button>
          <button
            onClick={() => setAddingId(true)}
            className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded border border-line-2"
          >
            <Plus size={14} /> Add identifier
          </button>
          <button
            onClick={doExport}
            className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded border border-line-2"
          >
            <Download size={14} /> Export
          </button>
          <label className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded border border-line-2 cursor-pointer">
            <Upload size={14} /> Import
            <input type="file" accept="application/json,.json" className="hidden" onChange={doImport} />
          </label>
        </div>
      }
    >
      <div className="mb-4 flex gap-2">
        <button
          onClick={() => setTab('graph')}
          className={`px-3 py-1.5 text-sm rounded ${tab === 'graph' ? 'bg-brand-600 text-white' : 'border border-slate-300 dark:border-line-1'}`}
        >
          Graph ({project.identifiers.length})
        </button>
        <button
          onClick={() => setTab('map')}
          className={`px-3 py-1.5 text-sm rounded ${tab === 'map' ? 'bg-brand-600 text-white' : 'border border-slate-300 dark:border-line-1'}`}
        >
          Map ({project.pins.length})
        </button>
      </div>

      {tab === 'graph' ? (
        <IdentifierGraph
          identifiers={project.identifiers}
          pins={project.pins}
          links={project.links}
          customIcons={icons}
          positions={project.positions}
          selectedId={selection?.kind === 'identifier' ? selection.id : null}
          onSelect={(id) => setSelection(id ? { kind: 'identifier', id } : null)}
          onDelete={removeIdentifier}
          onEdit={openEditIdentifier}
          onMove={moveNode}
        />
      ) : (
        <MapPane
          pins={project.pins}
          selectedPinId={selection?.kind === 'pin' ? selection.id! : linkedPinIds.size ? [...linkedPinIds][0]! : null}
          onMapClick={handleMapClick}
          onSelectPin={(id) => setSelection({ kind: 'pin', id })}
          onDeletePin={removePin}
          onEditPin={openEditPin}
        />
      )}

      {(addingId || editingIdentifier) && (
        <div className={overlayWrap}>
          <div className={overlayCard}>
            <h2 className="font-medium mb-3">{editingIdentifier ? 'Edit identifier' : 'Add identifier'}</h2>
            <IdentifierForm
              initial={editingIdentifier ?? undefined}
              onSubmit={submitIdentifier}
              onCancel={() => {
                setAddingId(false);
                setEditingIdentifier(null);
              }}
            />
          </div>
        </div>
      )}
      {(pending || editingPin) && (
        <div className={overlayWrap}>
          <div className={overlayCard}>
            <h2 className="font-medium mb-3">{editingPin ? 'Edit pin' : 'Add pin'}</h2>
            <PinForm
              lat={editingPin?.lat ?? pending?.lat ?? 0}
              lng={editingPin?.lng ?? pending?.lng ?? 0}
              address={editingPin?.address ?? pending?.address}
              identifiers={project.identifiers}
              initial={editingPin ?? undefined}
              onSubmit={submitPin}
              onCancel={() => {
                setPending(null);
                setEditingPin(null);
              }}
            />
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
