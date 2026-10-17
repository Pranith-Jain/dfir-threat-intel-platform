/**
 * CtiGlobe - 3D interactive globe using globe.gl
 *
 * Features:
 *  - Smooth mouse/touch rotation and zoom
 *  - Click points to focus and show details
 *  - Auto-rotate after inactivity
 *  - Hover tooltips
 *  - Animated arcs and rings
 */

import { useEffect, useRef, useState, useMemo, type JSX } from 'react';
import Globe, { type GlobeInstance } from 'globe.gl';
import type { CtiArc, CtiPoint } from './geo';
import { severityColor, kindColor } from './geo';
import { useReduceMotion } from '../../../hooks/useMediaQuery';
import { errMessage } from '../../../lib/log';

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ─── Types ─────────────────────────────────────────────────────────────── */

/** Helper: cast the opaque `object` datum that globe.gl passes to its
 *  accessors to a known datum type. Cheap and safe because the corresponding
 *  *Data() setter below is statically typed to the same shape. */
function datum<T>(obj: object): T {
  return obj as T;
}

/** Alias for use as a globe.gl datum type (globe.gl reads `any`-shaped
 *  data, but the props are statically CtiPoint-shaped so this is safe). */
type CtiPointDatum = CtiPoint;

interface RingDatum {
  lat: number;
  lng: number;
  size: number;
  color: string;
}

interface CtiGlobeProps {
  arcs: CtiArc[];
  points: CtiPoint[];
  focus: { lat: number; lng: number } | null;
  onPointClick?: (point: CtiPoint) => void;
  onPointHover?: (point: CtiPoint | null) => void;
  autoRotate?: boolean;
}

/* ─── Component ─────────────────────────────────────────────────────────── */

export default function CtiGlobe({
  arcs,
  points,
  focus,
  onPointClick,
  onPointHover,
  autoRotate = false,
}: CtiGlobeProps): JSX.Element {
  const containerRef = useRef<HTMLDivElement>(null);
  const reduceMotion = useReduceMotion();
  const globeRef = useRef<GlobeInstance | null>(null);
  const rotAngleRef = useRef(0);
  const rafRef = useRef(0);
  const userInteracting = useRef(false);
  const lastInteraction = useRef(Date.now());
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hoveredPoint, setHoveredPoint] = useState<CtiPoint | null>(null);
  const [selectedPoint, setSelectedPoint] = useState<CtiPoint | null>(null);

  // Ring data for critical/high severity points
  const ringData: RingDatum[] = useMemo(
    () =>
      points
        .filter((p) => p.severity === 'critical' || p.severity === 'high')
        .slice(0, 80)
        .map((p) => ({
          lat: p.lat,
          lng: p.lng,
          size: p.severity === 'critical' ? 4.0 : 2.8,
          color: severityColor(p.severity),
        })),
    [points]
  );

  // Initialize globe
  useEffect(() => {
    if (!containerRef.current || globeRef.current) return;

    try {
      const container = containerRef.current;
      const w = container.clientWidth;
      const h = container.clientHeight;

      const globe = new Globe(container, { animateIn: true })
        .width(w)
        .height(h)
        // Globe appearance
        .globeImageUrl('/textures/earth-night.jpg')
        .bumpImageUrl('/textures/earth-topology.png')
        .backgroundImageUrl('')
        .backgroundColor('rgba(0,0,0,0)')
        // Atmosphere
        .showAtmosphere(true)
        .atmosphereColor('#4f8fff')
        .atmosphereAltitude(0.2)
        // Points
        .pointsData(points)
        .pointLat((p: object) => datum<CtiPointDatum>(p).lat)
        .pointLng((p: object) => datum<CtiPointDatum>(p).lng)
        .pointColor((p: object) => {
          const d = datum<CtiPointDatum>(p);
          // Use kind-based color when available (distinguishes CVEs from
          // ransomware from IOCs at a glance), fall back to severity color.
          return d.kind ? kindColor(d.kind) : severityColor(d.severity);
        })
        .pointAltitude((p: object) => {
          const alts: Record<string, number> = {
            critical: 0.15,
            high: 0.09,
            medium: 0.055,
            low: 0.035,
            info: 0.02,
          };
          return alts[datum<CtiPointDatum>(p).severity] ?? 0.035;
        })
        .pointRadius((p: object) => {
          const sizes: Record<string, number> = {
            critical: 2.0,
            high: 1.5,
            medium: 1.0,
            low: 0.6,
            info: 0.4,
          };
          return sizes[datum<CtiPointDatum>(p).severity] ?? 0.7;
        })
        .pointLabel((p: object) => {
          const d = datum<CtiPointDatum>(p);
          const sevColor = severityColor(d.severity);
          const label = escHtml(d.label);
          const kindLabel = d.kind ? escHtml(d.kind.replace(/_/g, ' ')) : '';
          const sourceLabel = d.source ? escHtml(d.source) : '';
          const descLabel = d.description ? escHtml(d.description) : '';
          const cvssBadge =
            d.magnitude != null
              ? `<span style="background:${d.magnitude >= 9 ? '#e11d4825' : d.magnitude >= 7 ? '#f43f5e25' : '#f59e0b25'};color:${d.magnitude >= 9 ? '#e11d48' : d.magnitude >= 7 ? '#f43f5e' : '#f59e0b'};padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;">CVSS ${d.magnitude.toFixed(1)}</span>`
              : '';
          return `
            <div style="
              background: rgba(10,15,26,0.95);
              color: #e2e8f0;
              padding: 14px 18px;
              border-radius: 12px;
              font-size: 12px;
              font-family: 'SF Mono', 'Fira Code', monospace;
              max-width: 320px;
              border: 1px solid ${sevColor}50;
              box-shadow: 0 8px 32px rgba(0,0,0,0.6);
              backdrop-filter: blur(10px);
            ">
              <div style="font-weight: 600; margin-bottom: 8px; color: #f8fafc; font-size: 14px;">${label}</div>
              ${descLabel ? `<div style="font-size: 11px; opacity: 0.7; margin-bottom: 8px; line-height: 1.4;">${descLabel}</div>` : ''}
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="
                  background: ${sevColor}25;
                  color: ${sevColor};
                  padding: 3px 10px;
                  border-radius: 6px;
                  font-size: 11px;
                  font-weight: 600;
                  text-transform: uppercase;
                ">${d.severity}</span>
                ${cvssBadge}
                ${kindLabel ? `<span style="font-size: 11px; opacity: 0.6; text-transform: uppercase;">${kindLabel}</span>` : ''}
              </div>
              ${sourceLabel ? `<div style="margin-top: 6px; font-size: 11px; opacity: 0.5;">Source: ${sourceLabel}</div>` : ''}
              <div style="margin-top: 8px; font-size: 11px; opacity: 0.4;">Click to focus</div>
            </div>
          `;
        })
        .onPointClick((p: object | null) => {
          if (!p) return;
          const point = datum<CtiPoint>(p);
          setSelectedPoint(point);
          onPointClick?.(point);
          lastInteraction.current = Date.now();
        })
        .onPointHover((p: object | null) => {
          const point = p ? datum<CtiPoint>(p) : null;
          setHoveredPoint(point);
          onPointHover?.(point);
          if (typeof document !== 'undefined') {
            document.body.style.cursor = point ? 'pointer' : 'default';
          }
        })
        // Rings
        .ringsData(ringData)
        .ringLat((r: object) => datum<RingDatum>(r).lat)
        .ringLng((r: object) => datum<RingDatum>(r).lng)
        .ringColor((r: object) => datum<RingDatum>(r).color)
        .ringMaxRadius((r: object) => datum<RingDatum>(r).size)
        .ringAltitude(0.005)
        .ringRepeatPeriod(2000)
        // Arcs
        .arcsData(arcs)
        .arcColor((a: object) => datum<CtiArc>(a).color)
        .arcDashLength(0.6)
        .arcDashGap(0.04)
        .arcDashAnimateTime(3000)
        .arcStroke(0.5)
        .arcLabel((a: object) => {
          const label = escHtml(datum<CtiArc>(a).label);
          return `
            <div style="
              background: rgba(10,15,26,0.95);
              color: #e2e8f0;
              padding: 10px 14px;
              border-radius: 8px;
              font-size: 11px;
              font-family: monospace;
              max-width: 280px;
              border: 1px solid ${datum<CtiArc>(a).color}40;
              box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            ">${label}</div>
          `;
        });

      // Enable controls
      globe.controls().enableDamping = true;
      globe.controls().dampingFactor = 0.1;
      globe.controls().rotateSpeed = 0.8;
      globe.controls().zoomSpeed = 1.2;
      globe.controls().minDistance = 150;
      globe.controls().maxDistance = 500;

      // Track user interaction
      const onMouseDown = () => {
        userInteracting.current = true;
        lastInteraction.current = Date.now();
      };
      const onMouseUp = () => {
        setTimeout(() => {
          userInteracting.current = false;
        }, 2000);
      };
      const onWheel = () => {
        lastInteraction.current = Date.now();
      };
      const onTouchStart = () => {
        userInteracting.current = true;
        lastInteraction.current = Date.now();
      };
      const onTouchEnd = () => {
        setTimeout(() => {
          userInteracting.current = false;
        }, 2000);
      };
      container.addEventListener('mousedown', onMouseDown);
      container.addEventListener('mouseup', onMouseUp);
      container.addEventListener('wheel', onWheel);
      container.addEventListener('touchstart', onTouchStart);
      container.addEventListener('touchend', onTouchEnd);

      // Set initial POV
      globe.pointOfView({ lat: 20, lng: 0, altitude: 2.5 }, 0);

      globeRef.current = globe;
      setReady(true);

      // Handle resize
      const resizeObserver = new ResizeObserver(() => {
        if (containerRef.current && globeRef.current) {
          const newW = containerRef.current.clientWidth;
          const newH = containerRef.current.clientHeight;
          globeRef.current.width(newW).height(newH);
        }
      });
      resizeObserver.observe(container);

      return () => {
        resizeObserver.disconnect();
        container.removeEventListener('mousedown', onMouseDown);
        container.removeEventListener('mouseup', onMouseUp);
        container.removeEventListener('wheel', onWheel);
        container.removeEventListener('touchstart', onTouchStart);
        container.removeEventListener('touchend', onTouchEnd);
        globeRef.current?._destructor?.();
        globeRef.current = null;
      };
    } catch (err) {
      setError(errMessage(err, 'Failed to initialize globe'));
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Update data when it changes
  useEffect(() => {
    if (!globeRef.current) return;
    try {
      globeRef.current.pointsData(points);
    } catch {
      /* ignore */
    }
  }, [points]);

  useEffect(() => {
    if (!globeRef.current) return;
    try {
      globeRef.current.ringsData(ringData);
    } catch {
      /* ignore */
    }
  }, [ringData]);

  useEffect(() => {
    if (!globeRef.current) return;
    try {
      globeRef.current.arcsData(arcs);
    } catch {
      /* ignore */
    }
  }, [arcs]);

  // Focus on point
  useEffect(() => {
    if (!focus || !globeRef.current) return;
    userInteracting.current = true;
    globeRef.current.pointOfView({ lat: focus.lat, lng: focus.lng, altitude: 1.8 }, 1500);
    setTimeout(() => {
      userInteracting.current = false;
    }, 5000);
  }, [focus]);

  // Auto-rotation (resume after 10s of inactivity)
  useEffect(() => {
    if (!autoRotate || reduceMotion || !globeRef.current) return;

    const rotate = () => {
      const now = Date.now();
      const timeSinceInteraction = now - lastInteraction.current;

      if (!userInteracting.current && timeSinceInteraction > 10000 && globeRef.current) {
        rotAngleRef.current += 0.15;
        const pov = globeRef.current.pointOfView();
        globeRef.current.pointOfView({ lat: pov.lat, lng: rotAngleRef.current % 360 }, 0);
      }
      rafRef.current = requestAnimationFrame(rotate);
    };
    rafRef.current = requestAnimationFrame(rotate);

    return () => cancelAnimationFrame(rafRef.current);
  }, [autoRotate, reduceMotion]);

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center h-full w-full bg-[#0a0f1a]">
        <div className="text-center p-6 max-w-sm">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-surface-200/50 flex items-center justify-center">
            <svg
              className="w-8 h-8 text-muted"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"
              />
            </svg>
          </div>
          <p className="text-sm font-medium text-inverted mb-1">Globe Unavailable</p>
          <p className="text-xs text-muted mb-4">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 text-xs font-mono rounded-xl bg-surface-200 text-inverted hover:bg-slate-700 border border-slate-700 transition-colors"
          >
            Reload Page
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative w-full h-full bg-[#0a0f1a] overflow-hidden">
      {/* Globe container */}
      <div
        ref={containerRef}
        className="w-full h-full"
        role="img"
        aria-label={`Interactive 3D globe showing ${points.length} threat-intel origin points by severity`}
      />

      {/* Loading state */}
      {!ready && (
        <div className="absolute inset-0 flex items-center justify-center bg-[#0a0f1a]">
          <div className="flex flex-col items-center gap-4">
            <div className="relative">
              <div className="w-16 h-16 rounded-full border-2 border-brand-500/20" />
              <div className="absolute inset-0 w-16 h-16 rounded-full border-2 border-transparent border-t-blue-500 animate-spin" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-inverted">Initializing Globe</p>
              <p className="text-xs text-muted mt-1">Loading 3D renderer…</p>
            </div>
          </div>
        </div>
      )}

      {/* Hovered Point Info */}
      {hoveredPoint && !selectedPoint && (
        <div className="absolute top-4 left-4 bg-[#0f1629]/90 backdrop-blur-sm rounded-xl border border-slate-700/50 px-4 py-3 pointer-events-none max-w-xs">
          <div className="flex items-center gap-3">
            <span
              className="w-3 h-3 rounded-full"
              style={{
                backgroundColor: hoveredPoint.kind
                  ? kindColor(hoveredPoint.kind)
                  : severityColor(hoveredPoint.severity),
              }}
            />
            <div>
              <p className="text-sm font-medium text-inverted">{hoveredPoint.label}</p>
              <p className="text-xs text-muted mt-0.5">
                {hoveredPoint.severity.toUpperCase()}
                {hoveredPoint.kind ? ` · ${hoveredPoint.kind.replace(/_/g, ' ')}` : ''}
                {hoveredPoint.source ? ` · ${hoveredPoint.source}` : ''}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Selected Point Detail */}
      {selectedPoint && (
        <div className="absolute top-4 left-4 bg-[#0f1629]/95 backdrop-blur-md rounded-xl border border-slate-700/50 p-4 max-w-sm shadow-2xl">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{
                    backgroundColor: selectedPoint.kind
                      ? kindColor(selectedPoint.kind)
                      : severityColor(selectedPoint.severity),
                  }}
                />
                <span
                  className="text-micro font-mono uppercase px-2 py-0.5 rounded"
                  style={{
                    backgroundColor: severityColor(selectedPoint.severity) + '25',
                    color: severityColor(selectedPoint.severity),
                  }}
                >
                  {selectedPoint.severity}
                </span>
                {selectedPoint.kind && (
                  <span className="text-micro font-mono uppercase text-muted">
                    {selectedPoint.kind.replace(/_/g, ' ')}
                  </span>
                )}
                {selectedPoint.magnitude != null && (
                  <span
                    className="text-micro font-mono font-bold px-1.5 rounded"
                    style={{
                      backgroundColor:
                        selectedPoint.magnitude >= 9
                          ? '#e11d4825'
                          : selectedPoint.magnitude >= 7
                            ? '#f43f5e25'
                            : '#f59e0b25',
                      color:
                        selectedPoint.magnitude >= 9 ? '#e11d48' : selectedPoint.magnitude >= 7 ? '#f43f5e' : '#f59e0b',
                    }}
                  >
                    CVSS {selectedPoint.magnitude.toFixed(1)}
                  </span>
                )}
              </div>
              <p className="text-sm font-semibold text-white">{selectedPoint.label}</p>
              {selectedPoint.description && (
                <p className="text-xs text-muted mt-1 leading-relaxed">{selectedPoint.description}</p>
              )}
              {selectedPoint.source && <p className="text-xs text-muted mt-2">Source: {selectedPoint.source}</p>}
            </div>
            <button
              onClick={() => setSelectedPoint(null)}
              aria-label="Close details"
              className="text-muted hover:text-inverted transition-colors"
            >
              <svg className="w-4 h-4" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      )}

      {/* Controls Help */}
      {ready && (
        <div className="absolute bottom-4 right-4 bg-[#0f1629]/80 backdrop-blur-sm rounded-xl border border-slate-700/50 px-3 py-2 pointer-events-none">
          <div className="text-micro font-mono text-muted space-y-1">
            <div>Drag to rotate</div>
            <div>Scroll to zoom</div>
            <div>Click point for details</div>
          </div>
        </div>
      )}

      {/* Stats */}
      {ready && (
        <div className="absolute bottom-4 left-4 bg-[#0f1629]/80 backdrop-blur-sm rounded-xl border border-slate-700/50 px-3 py-1.5 pointer-events-none">
          <span className="text-micro font-mono text-muted">
            {points.length} points · {arcs.length} arcs
          </span>
        </div>
      )}
    </div>
  );
}
