import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { WORLD_GEOJSON, geoRingTo3D } from '../pages/argus/data/world-map';
import { loadWorldCountries } from '../pages/argus/data/world-topo';

export interface GlobeMarker {
  id: string;
  lat: number;
  lng: number;
  color: string;
  label: string;
  size?: number;
}

/** One raycast target per clustered location; `ids` holds every marker in it. */
interface PickTarget {
  mesh: THREE.Mesh;
  ids: string[];
  label: string;
}

type HoverInfo = { label: string; extra: number; x: number; y: number };

interface GlobeState {
  camera: THREE.PerspectiveCamera;
  scene: THREE.Scene;
  renderer: THREE.WebGLRenderer;
  globeGroup: THREE.Group;
  pickTargets: PickTarget[];
  markerMeshes: THREE.Object3D[];
  baseLand: THREE.Line[];
}

/** The exact lat/lng -> vec3 mapping used by the ARGUS globe. */
function latLngToVec3(lat: number, lng: number, r: number, out: THREE.Vector3): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  out.set(-r * Math.sin(phi) * Math.cos(theta), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(theta));
  return out;
}

/** ARGUS disposal pattern: free every geometry/material under an object. */
function disposeObj(obj: THREE.Object3D): void {
  obj.traverse((o) => {
    const mesh = o as THREE.Mesh & { material?: THREE.Material | THREE.Material[] };
    if (mesh.geometry) mesh.geometry.dispose();
    const mat = mesh.material;
    if (Array.isArray(mat)) mat.forEach((m) => m.dispose());
    else if (mat) mat.dispose();
  });
}

/** Greedy grouping: markers within ~0.6 degrees of the anchor share a cluster. */
function clusterMarkers(markers: GlobeMarker[]): GlobeMarker[][] {
  const clusters: GlobeMarker[][] = [];
  const anchors: { lat: number; lng: number }[] = [];
  for (const marker of markers) {
    const idx = anchors.findIndex((a) => Math.abs(a.lat - marker.lat) <= 0.6 && Math.abs(a.lng - marker.lng) <= 0.6);
    if (idx === -1) {
      clusters.push([marker]);
      anchors.push({ lat: marker.lat, lng: marker.lng });
    } else {
      clusters[idx]!.push(marker);
    }
  }
  return clusters;
}

export function ThreatGlobe3D({
  markers,
  onSelect,
  className,
  autoRotate = true,
}: {
  markers: GlobeMarker[];
  onSelect?: (id: string) => void;
  className?: string;
  autoRotate?: boolean;
}): JSX.Element {
  const mountRef = useRef<HTMLDivElement>(null);
  const stateRef = useRef<GlobeState | null>(null);
  const autoRotateRef = useRef(autoRotate);
  const onSelectRef = useRef(onSelect);
  const draggingRef = useRef(false);
  const pointerMovedRef = useRef(false);
  const [hovered, setHovered] = useState<HoverInfo | null>(null);

  // Keep mutable callbacks/options fresh without re-running the scene setup.
  useEffect(() => {
    autoRotateRef.current = autoRotate;
    onSelectRef.current = onSelect;
  }, [autoRotate, onSelect]);

  // Scene setup — runs once.
  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const w = mount.clientWidth || 800;
    const h = mount.clientHeight || 600;

    const scene = new THREE.Scene();
    scene.background = null;

    const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
    camera.position.set(0, 0.3, w < 640 ? 3.8 : 3.0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(w, h);
    renderer.setClearColor(0x000000, 0);
    renderer.domElement.style.position = 'absolute';
    renderer.domElement.style.inset = '0';
    renderer.domElement.style.zIndex = '0';
    mount.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.55));
    const sun = new THREE.DirectionalLight(0xffffff, 0.9);
    sun.position.set(5, 3, 5);
    scene.add(sun);
    const rim = new THREE.DirectionalLight(0x435ef1, 0.4);
    rim.position.set(-5, -2, -3);
    scene.add(rim);

    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Starfield — a shell of static points behind the globe for depth.
    const starCount = 900;
    const starPos = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      const r = 14 + Math.random() * 26;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      starPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      starPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      starPos[i * 3 + 2] = r * Math.cos(phi);
    }
    const starGeo = new THREE.BufferGeometry();
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const starMat = new THREE.PointsMaterial({
      color: 0x8fa3d9,
      size: 0.05,
      sizeAttenuation: true,
      transparent: true,
      opacity: 0.7,
      depthWrite: false,
    });
    scene.add(new THREE.Points(starGeo, starMat));

    // Globe body — dark navy sphere.
    const globeGeo = new THREE.SphereGeometry(1, 64, 48);
    const globeMat = new THREE.MeshPhongMaterial({
      color: 0x0c1124,
      emissive: 0x050814,
      specular: 0x233052,
      shininess: 16,
      transparent: true,
      opacity: 0.97,
    });
    globeGroup.add(new THREE.Mesh(globeGeo, globeMat));

    // Graticule — latitude and longitude lines.
    const graticuleMat = new THREE.LineBasicMaterial({ color: 0x233052, transparent: true, opacity: 0.32 });
    const gratGroup = new THREE.Group();
    for (let lat = -75; lat <= 75; lat += 15) {
      const pts: THREE.Vector3[] = [];
      for (let lng = 0; lng <= 360; lng += 4) {
        pts.push(latLngToVec3(lat, lng, 1.002, new THREE.Vector3()));
      }
      gratGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), graticuleMat));
    }
    for (let lng = 0; lng < 360; lng += 15) {
      const pts: THREE.Vector3[] = [];
      for (let lat = -85; lat <= 85; lat += 4) {
        pts.push(latLngToVec3(lat, lng, 1.002, new THREE.Vector3()));
      }
      gratGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), graticuleMat));
    }
    globeGroup.add(gratGroup);

    // Atmosphere — brand-blue limb glow.
    const atmoMat = new THREE.ShaderMaterial({
      vertexShader: `varying vec3 vNormal; void main() { vNormal = normalize(normalMatrix * normal); gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`,
      fragmentShader: `varying vec3 vNormal; void main() { float intensity = pow(0.62 - dot(vNormal, vec3(0,0,1)), 2.2); gl_FragColor = vec4(0.26, 0.37, 0.95, 1.0) * intensity; }`,
      blending: THREE.AdditiveBlending,
      side: THREE.BackSide,
      transparent: true,
      depthWrite: false,
    });
    globeGroup.add(new THREE.Mesh(new THREE.SphereGeometry(1.15, 48, 36), atmoMat));

    // Bundled simplified outlines render immediately; the world effect swaps
    // them for accurate Natural Earth borders once the fetch resolves.
    const outlineMat = new THREE.LineBasicMaterial({ color: 0x2c3e6b, transparent: true, opacity: 0.3 });
    const baseLand: THREE.Line[] = [];
    for (const feature of WORLD_GEOJSON) {
      for (const ring of feature.rings) {
        const vecs = geoRingTo3D(ring, 1.003).map((p) => new THREE.Vector3(p.x, p.y, p.z));
        const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(vecs), outlineMat);
        globeGroup.add(line);
        baseLand.push(line);
      }
    }

    // ResizeObserver keeps camera aspect and renderer size in sync.
    const onResize = () => {
      const W = mount.clientWidth;
      const H = mount.clientHeight;
      if (W === 0 || H === 0) return;
      camera.aspect = W / H;
      camera.updateProjectionMatrix();
      renderer.setSize(W, H);
    };
    const ro = new ResizeObserver(onResize);
    ro.observe(mount);

    let rafId = 0;
    let alive = true;
    let lastX = 0;

    const tick = () => {
      if (!alive) return;
      if (autoRotateRef.current && !draggingRef.current) {
        globeGroup.rotation.y += 0.0012;
      }
      renderer.render(scene, camera);
      rafId = requestAnimationFrame(tick);
    };

    // Drag to rotate.
    const onDown = (e: PointerEvent) => {
      draggingRef.current = true;
      pointerMovedRef.current = false;
      lastX = e.clientX;
    };
    const onMove = (e: PointerEvent) => {
      if (!draggingRef.current) return;
      const delta = e.clientX - lastX;
      if (Math.abs(delta) > 3) pointerMovedRef.current = true;
      globeGroup.rotation.y += delta * 0.005;
      lastX = e.clientX;
    };
    const onUp = () => {
      draggingRef.current = false;
    };
    renderer.domElement.addEventListener('pointerdown', onDown);
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);

    // Wheel zoom.
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      camera.position.z = Math.max(1.8, Math.min(6, camera.position.z + e.deltaY * 0.002));
    };
    renderer.domElement.addEventListener('wheel', onWheel, { passive: false });

    // Two-finger pinch zoom.
    let pinchDist = 0;
    const touchDistance = (e: TouchEvent): number =>
      Math.hypot(e.touches[0]!.clientX - e.touches[1]!.clientX, e.touches[0]!.clientY - e.touches[1]!.clientY);
    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length === 2) pinchDist = touchDistance(e);
    };
    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length !== 2) return;
      e.preventDefault();
      const dist = touchDistance(e);
      camera.position.z = Math.max(1.8, Math.min(6, camera.position.z + (pinchDist - dist) * 0.008));
      pinchDist = dist;
    };
    renderer.domElement.addEventListener('touchstart', onTouchStart, { passive: true });
    renderer.domElement.addEventListener('touchmove', onTouchMove, { passive: false });

    stateRef.current = { camera, scene, renderer, globeGroup, pickTargets: [], markerMeshes: [], baseLand };
    tick();

    return () => {
      alive = false;
      cancelAnimationFrame(rafId);
      ro.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      renderer.domElement.removeEventListener('wheel', onWheel);
      renderer.domElement.removeEventListener('touchstart', onTouchStart);
      renderer.domElement.removeEventListener('touchmove', onTouchMove);
      // Free every GPU buffer before dropping the context. Chrome caps live
      // WebGL contexts (~16); without forceContextLoss the canvas eventually
      // blanks mid-session.
      disposeObj(scene);
      renderer.dispose();
      renderer.forceContextLoss();
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement);
      stateRef.current = null;
    };
  }, []);

  // Load accurate Natural Earth borders. On failure the bundled outlines stay.
  useEffect(() => {
    let cancelled = false;
    loadWorldCountries().then((countries) => {
      if (cancelled || !countries) return;
      const s = stateRef.current;
      if (!s) return;
      for (const line of s.baseLand) {
        s.globeGroup.remove(line);
        disposeObj(line);
      }
      s.baseLand = [];
      const borderMat = new THREE.LineBasicMaterial({ color: 0x33436e, transparent: true, opacity: 0.38 });
      for (const country of countries) {
        for (const ring of country.rings) {
          const vecs = geoRingTo3D(ring, 1.003).map((p) => new THREE.Vector3(p.x, p.y, p.z));
          s.globeGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(vecs), borderMat));
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Rebuild markers whenever the marker list changes, disposing old ones.
  useEffect(() => {
    const s = stateRef.current;
    if (!s) return;
    const created: THREE.Object3D[] = [];
    const targets: PickTarget[] = [];

    for (const group of clusterMarkers(markers)) {
      const primary = group[0]!;
      const v = latLngToVec3(primary.lat, primary.lng, 1.006, new THREE.Vector3());
      const size = primary.size ?? 1;
      const radius = (0.014 + Math.min(0.03, group.length * 0.007)) * size;
      const color = new THREE.Color(primary.color);

      // Soft pulse glow.
      const pulse = new THREE.Mesh(
        new THREE.SphereGeometry(radius * 2.5, 16, 16),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.08 })
      );
      pulse.position.copy(v);
      s.globeGroup.add(pulse);
      created.push(pulse);

      // Main (pickable) marker.
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(radius, 16, 16), new THREE.MeshBasicMaterial({ color }));
      mesh.position.copy(v);
      s.globeGroup.add(mesh);
      created.push(mesh);

      // Cluster ring — subtle visual cue that several markers share a spot.
      if (group.length > 1) {
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(radius * 1.5, radius * 1.9, 32),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.35, side: THREE.DoubleSide })
        );
        ring.position.copy(v);
        ring.lookAt(0, 0, 0);
        s.globeGroup.add(ring);
        created.push(ring);
      }

      const target: PickTarget = { mesh, ids: group.map((m) => m.id), label: primary.label };
      targets.push(target);
      s.pickTargets.push(target);
    }
    s.markerMeshes.push(...created);

    return () => {
      for (const obj of created) {
        s.globeGroup.remove(obj);
        disposeObj(obj);
      }
      s.pickTargets = s.pickTargets.filter((t) => !targets.includes(t));
      s.markerMeshes = s.markerMeshes.filter((m) => !created.includes(m));
    };
  }, [markers]);

  // Hover tooltip + click selection, both via raycaster against marker meshes.
  useEffect(() => {
    const s = stateRef.current;
    if (!s) return;
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const pick = (e: MouseEvent, rect: DOMRect): PickTarget | null => {
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(mouse, s.camera);
      const hits = raycaster.intersectObjects(
        s.pickTargets.map((p) => p.mesh),
        false
      );
      if (hits.length === 0) return null;
      return s.pickTargets.find((p) => p.mesh === hits[0]!.object) ?? null;
    };

    const onMove = (e: PointerEvent) => {
      const rect = s.renderer.domElement.getBoundingClientRect();
      const target = pick(e, rect);
      if (target) {
        s.renderer.domElement.style.cursor = 'pointer';
        setHovered({
          label: target.label,
          extra: target.ids.length - 1,
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        });
        return;
      }
      s.renderer.domElement.style.cursor = draggingRef.current ? 'grabbing' : 'grab';
      setHovered(null);
    };

    const onClick = (e: MouseEvent) => {
      if (pointerMovedRef.current) return;
      const target = pick(e, s.renderer.domElement.getBoundingClientRect());
      if (target) onSelectRef.current?.(target.ids[0]!);
    };

    s.renderer.domElement.addEventListener('pointermove', onMove);
    s.renderer.domElement.addEventListener('click', onClick);
    return () => {
      s.renderer.domElement.removeEventListener('pointermove', onMove);
      s.renderer.domElement.removeEventListener('click', onClick);
    };
  }, []);

  return (
    <div ref={mountRef} className={`absolute inset-0 ${className ?? ''}`} style={{ cursor: 'grab' }}>
      {hovered && (
        <div
          className="globe-card text-tool pointer-events-none absolute z-10 min-w-[160px] px-3 py-2.5"
          style={{
            left: Math.min(hovered.x + 14, (mountRef.current?.clientWidth ?? 600) - 180),
            top: Math.min(hovered.y + 14, (mountRef.current?.clientHeight ?? 600) - 80),
          }}
        >
          <div className="font-semibold text-heading">{hovered.label}</div>
          {hovered.extra > 0 && <div className="text-muted text-mini mt-0.5">+{hovered.extra} more</div>}
        </div>
      )}
    </div>
  );
}
