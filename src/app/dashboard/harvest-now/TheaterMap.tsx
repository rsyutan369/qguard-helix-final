'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';
import type { TheaterAnchor, TheaterMapModel, TheaterRegion } from '@/hooks/use-harvest-now';
import { decodeLandDots } from './world-land-grid';

/**
 * Global Quantum Exposure Theater™ — real 3D world map (three.js).
 *
 * Renders the tenant's cryptographic estate on an accurate dotted world map
 * (Natural-Earth-derived land grid) with a tilted, parallax 3D camera:
 *   • sites   — assets with real region telemetry, glowing by severity;
 *   • anchors — certificate-authority trust origins parsed from real issuer
 *               DNs, plotted at their registered country;
 *   • arcs    — real asset-relationship edges between sites and asset→CA
 *               trust chains, with animated harvest-path pulses;
 *   • assets with no location telemetry rise from the "unlocated" tray —
 *               nothing is ever pinned to a guessed location.
 */

export type TheaterSelection = { kind: 'site'; key: string } | { kind: 'anchor'; key: string } | null;

interface TheaterMapProps {
  map: TheaterMapModel;
  selected: TheaterSelection;
  onSelect: (selection: TheaterSelection) => void;
}

/* Map geometry: world units are degrees; the crop matches world-land-grid. */
const LAT_MAX = 78;
const LAT_MIN = -56;
const Y_CENTER = (LAT_MAX + LAT_MIN) / 2; // 11
const MAP_W = 360;
const MAP_H = LAT_MAX - LAT_MIN; // 134
const TRAY_Y = LAT_MIN - Y_CENTER - 16; // below the visible map edge

const SEVERITY_COLOR: Record<string, number> = {
  Critical: 0xf87171,
  High: 0xfbbf24,
  Medium: 0x22d3ee,
  Low: 0x34d399,
};

function toWorld(lat: number, lon: number, z = 0): THREE.Vector3 {
  return new THREE.Vector3(lon, lat - Y_CENTER, z);
}

function arcCurve(from: THREE.Vector3, to: THREE.Vector3): THREE.QuadraticBezierCurve3 {
  const mid = from.clone().add(to).multiplyScalar(0.5);
  mid.z = Math.min(34, Math.max(7, from.distanceTo(to) * 0.28));
  return new THREE.QuadraticBezierCurve3(from, mid, to);
}

interface HoverInfo {
  kind: 'site' | 'anchor';
  key: string;
}

export function TheaterMap({ map, selected, onSelect }: TheaterMapProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  const mapRef = useRef(map);
  mapRef.current = map;
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  /* ---- Zoom + pan (buttons, mouse wheel, drag-to-pan) --------------- *
   * Zoom scales the map group on top of the auto-fit scale; pan shifts it.
   * Both live in refs the render loop reads each frame, with a small state
   * mirror so the control buttons can reflect / disable at the limits. */
  const ZOOM_MIN = 0.6;
  const ZOOM_MAX = 4.5;
  const zoomRef = useRef(1);
  const panRef = useRef({ x: 0, y: 0 });
  const baseScaleRef = useRef(1);
  const [zoom, setZoom] = useState(1);
  const applyZoom = (next: number) => {
    const z = Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, next));
    zoomRef.current = z;
    setZoom(z);
  };
  const zoomBy = (factor: number) => applyZoom(zoomRef.current * factor);
  const resetView = () => { zoomRef.current = 1; panRef.current = { x: 0, y: 0 }; setZoom(1); };

  // Rebuild the scene only when the map DATA changes (SSE re-emits identical
  // frames every 30s — identical payloads must not tear the scene down).
  const mapSig = useMemo(() => JSON.stringify(map), [map]);

  const siteByKey = useMemo(() => new Map(map.sites.map((s) => [s.key, s])), [map.sites]);
  const anchorById = useMemo(() => new Map(map.anchors.map((a) => [a.id, a])), [map.anchors]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const data = mapRef.current;
    const reducedMotion = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = Math.max(320, mount.clientWidth);
    let height = Math.max(260, mount.clientHeight);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(34, width / height, 1, 2000);
    camera.position.set(0, 0, 250);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    renderer.domElement.className = 'absolute inset-0 h-full w-full';
    mount.appendChild(renderer.domElement);

    const disposables: Array<{ dispose: () => void }> = [];
    const track = <T extends { dispose: () => void }>(obj: T): T => { disposables.push(obj); return obj; };

    const root = new THREE.Group();
    const BASE_TILT = -0.3;
    root.rotation.x = BASE_TILT;
    scene.add(root);

    /* ---- Dotted world (accurate land grid) --------------------------- */
    const dots = decodeLandDots();
    const positions = new Float32Array(dots.length * 3);
    const colors = new Float32Array(dots.length * 3);
    const baseColor = new THREE.Color(0x0e7490);
    const brightColor = new THREE.Color(0x22d3ee);
    for (let i = 0; i < dots.length; i += 1) {
      positions[i * 3] = dots[i].lon;
      positions[i * 3 + 1] = dots[i].lat - Y_CENTER;
      positions[i * 3 + 2] = 0;
      // Deterministic per-dot shimmer seed (no RNG → stable between builds).
      const t = Math.abs(Math.sin(dots[i].lon * 12.9898 + dots[i].lat * 78.233)) * 0.55 + 0.2;
      const c = baseColor.clone().lerp(brightColor, t);
      colors[i * 3] = c.r; colors[i * 3 + 1] = c.g; colors[i * 3 + 2] = c.b;
    }
    const dotGeometry = track(new THREE.BufferGeometry());
    dotGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    dotGeometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    const dotMaterial = track(new THREE.PointsMaterial({ size: 1.5, vertexColors: true, transparent: true, opacity: 0.85, sizeAttenuation: false }));
    root.add(new THREE.Points(dotGeometry, dotMaterial));
    const glowMaterial = track(new THREE.PointsMaterial({ size: 3.4, vertexColors: true, transparent: true, opacity: 0.1, sizeAttenuation: false, blending: THREE.AdditiveBlending, depthWrite: false }));
    root.add(new THREE.Points(dotGeometry, glowMaterial));

    /* ---- Graticule ---------------------------------------------------- */
    const gridPoints: number[] = [];
    for (let lon = -180; lon <= 180; lon += 30) gridPoints.push(lon, LAT_MIN - Y_CENTER, -0.4, lon, LAT_MAX - Y_CENTER, -0.4);
    for (let lat = -50; lat <= 70; lat += 25) gridPoints.push(-180, lat - Y_CENTER, -0.4, 180, lat - Y_CENTER, -0.4);
    const gridGeometry = track(new THREE.BufferGeometry());
    gridGeometry.setAttribute('position', new THREE.BufferAttribute(new Float32Array(gridPoints), 3));
    root.add(new THREE.LineSegments(gridGeometry, track(new THREE.LineBasicMaterial({ color: 0x155e75, transparent: true, opacity: 0.14 }))));

    /* ---- Markers ------------------------------------------------------ */
    const hitMeshes: THREE.Mesh[] = [];
    const pulses: Array<{ mesh: THREE.Mesh; base: number; phase: number; max: number }> = [];
    const spinners: THREE.Mesh[] = [];
    const sphereGeometry = track(new THREE.SphereGeometry(1, 24, 16));
    const ringGeometry = track(new THREE.RingGeometry(1, 1.16, 48));
    const anchorGeometry = track(new THREE.OctahedronGeometry(1, 0));

    const addPulseRing = (position: THREE.Vector3, color: number, base: number, max: number, phase: number) => {
      const ring = new THREE.Mesh(ringGeometry, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.5, side: THREE.DoubleSide, depthWrite: false })));
      ring.position.copy(position).setZ(0.4);
      root.add(ring);
      pulses.push({ mesh: ring, base, phase, max });
    };

    for (const site of data.sites) {
      const color = SEVERITY_COLOR[site.severity] ?? 0x22d3ee;
      const radius = Math.min(4.6, 2.4 + site.assets * 0.45);
      const position = toWorld(site.lat, site.lon, 1.4);
      const core = new THREE.Mesh(sphereGeometry, track(new THREE.MeshBasicMaterial({ color })));
      core.scale.setScalar(radius);
      core.position.copy(position);
      core.userData = { kind: 'site', key: site.key };
      root.add(core);
      hitMeshes.push(core);
      const halo = new THREE.Mesh(sphereGeometry, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, depthWrite: false })));
      halo.scale.setScalar(radius * 2.1);
      halo.position.copy(position);
      root.add(halo);
      if (!reducedMotion) {
        addPulseRing(position, color, radius * 1.1, radius * 3.4, 0);
        addPulseRing(position, color, radius * 1.1, radius * 3.4, 0.5);
        if (site.vulnerableAssets > 0 && (site.internetFacing ?? 0) > 0) {
          // Internet-facing vulnerable site: harvest-capture ripple in red.
          addPulseRing(position, 0xef4444, radius * 1.3, radius * 4.6, 0.25);
        }
      }
    }

    for (const anchor of data.anchors) {
      if (anchor.lat == null || anchor.lon == null) continue;
      const color = anchor.quantumSafe ? 0x34d399 : 0xa78bfa;
      const position = toWorld(anchor.lat, anchor.lon, 2.2);
      const core = new THREE.Mesh(anchorGeometry, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 })));
      core.scale.setScalar(2.4);
      core.position.copy(position);
      core.userData = { kind: 'anchor', key: anchor.id };
      root.add(core);
      hitMeshes.push(core);
      spinners.push(core);
      const halo = new THREE.Mesh(sphereGeometry, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false })));
      halo.scale.setScalar(4.6);
      halo.position.copy(position);
      root.add(halo);
    }

    /* ---- Arcs (real relationships) ------------------------------------ */
    const travellers: Array<{ mesh: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; phase: number; speed: number }> = [];
    const pulseGeometry = track(new THREE.SphereGeometry(0.9, 10, 8));
    const addArc = (from: THREE.Vector3, to: THREE.Vector3, color: number, opacity: number, speed: number, phase: number) => {
      const curve = arcCurve(from, to);
      const geometry = track(new THREE.BufferGeometry().setFromPoints(curve.getPoints(56)));
      root.add(new THREE.Line(geometry, track(new THREE.LineBasicMaterial({ color, transparent: true, opacity, blending: THREE.AdditiveBlending }))));
      if (!reducedMotion) {
        const mesh = new THREE.Mesh(pulseGeometry, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false })));
        root.add(mesh);
        travellers.push({ mesh, curve, phase, speed });
      }
    };

    for (let i = 0; i < data.assetLinks.length; i += 1) {
      const link = data.assetLinks[i];
      const from = data.sites.find((s) => s.key === link.from);
      const to = data.sites.find((s) => s.key === link.to);
      if (!from || !to) continue;
      addArc(toWorld(from.lat, from.lon, 1.4), toWorld(to.lat, to.lon, 1.4), link.vulnerable ? 0xf87171 : 0x22d3ee, 0.55, 0.28, (i % 7) / 7);
    }

    // Trust arcs: located assets arc from their site; unlocated assets rise
    // from the tray band beneath the map toward their certificate authority.
    const unlocatedIndex = new Map<string, number>(data.unlocated.map((u, i) => [u.name, i]));
    const traySlot = (index: number, count: number) => new THREE.Vector3(-140 + ((index + 0.5) * 280) / Math.max(1, count), TRAY_Y, 0.4);
    let trustIndex = 0;
    for (const trust of data.trustLinks) {
      const anchor = data.anchors.find((a) => a.id === trust.anchorId);
      if (!anchor || anchor.lat == null || anchor.lon == null) continue;
      const target = toWorld(anchor.lat, anchor.lon, 2.2);
      let source: THREE.Vector3 | null = null;
      if (trust.siteKey) {
        const site = data.sites.find((s) => s.key === trust.siteKey);
        if (site) source = toWorld(site.lat, site.lon, 1.4);
      } else {
        const index = unlocatedIndex.get(trust.asset);
        if (index !== undefined) source = traySlot(index, data.unlocated.length);
      }
      if (!source) continue;
      addArc(source, target, trust.vulnerable ? 0xfb7185 : 0x38bdf8, 0.4, 0.22, (trustIndex % 9) / 9);
      trustIndex += 1;
    }

    /* ---- Fit, parallax, animate --------------------------------------- */
    const fit = () => {
      width = Math.max(320, mount.clientWidth);
      height = Math.max(260, mount.clientHeight);
      renderer.setSize(width, height);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      const distance = camera.position.z;
      const visibleH = 2 * distance * Math.tan((camera.fov * Math.PI) / 360);
      const visibleW = visibleH * camera.aspect;
      const scale = Math.min(visibleW / (MAP_W * 1.06), visibleH / ((MAP_H + 34) * 1.1));
      baseScaleRef.current = scale;
      root.scale.setScalar(scale * zoomRef.current);
    };
    fit();
    const resizeObserver = new ResizeObserver(fit);
    resizeObserver.observe(mount);

    const pointer = { x: 0, y: 0, targetX: 0, targetY: 0 };
    const raycaster = new THREE.Raycaster();
    const ndc = new THREE.Vector2();
    let hovered: THREE.Mesh | null = null;
    const drag = { active: false, moved: false, startX: 0, startY: 0, panX: 0, panY: 0 };

    const onPointerDown = (event: PointerEvent) => {
      drag.active = true;
      drag.moved = false;
      drag.startX = event.clientX;
      drag.startY = event.clientY;
      drag.panX = panRef.current.x;
      drag.panY = panRef.current.y;
    };
    const onPointerUp = () => {
      drag.active = false;
      mount.style.cursor = hovered ? 'pointer' : 'default';
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12);
    };

    const onPointerMove = (event: PointerEvent) => {
      const rect = mount.getBoundingClientRect();
      // Drag-to-pan: shift the map in world units derived from the visible span.
      if (drag.active) {
        const dxPx = event.clientX - drag.startX;
        const dyPx = event.clientY - drag.startY;
        if (Math.abs(dxPx) + Math.abs(dyPx) > 4) drag.moved = true;
        const visibleH = 2 * camera.position.z * Math.tan((camera.fov * Math.PI) / 360);
        panRef.current.x = drag.panX + (dxPx / height) * visibleH;
        panRef.current.y = drag.panY - (dyPx / height) * visibleH;
        mount.style.cursor = 'grabbing';
        return;
      }
      pointer.targetX = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.targetY = ((event.clientY - rect.top) / rect.height) * 2 - 1;
      ndc.set(pointer.targetX, -pointer.targetY);
      raycaster.setFromCamera(ndc, camera);
      const hits = raycaster.intersectObjects(hitMeshes, false);
      const next = (hits[0]?.object as THREE.Mesh) || null;
      if (next !== hovered) {
        if (hovered) hovered.scale.multiplyScalar(1 / 1.25);
        hovered = next;
        if (hovered) hovered.scale.multiplyScalar(1.25);
        mount.style.cursor = hovered ? 'pointer' : 'default';
        setHover(hovered ? (hovered.userData as HoverInfo) : null);
      }
      const tooltip = tooltipRef.current;
      if (tooltip) {
        const x = Math.min(rect.width - 190, Math.max(8, event.clientX - rect.left + 14));
        const y = Math.max(8, event.clientY - rect.top - 12);
        tooltip.style.transform = `translate3d(${x}px, ${y}px, 0)`;
      }
    };
    const onPointerLeave = () => {
      if (hovered) { hovered.scale.multiplyScalar(1 / 1.25); hovered = null; }
      mount.style.cursor = 'default';
      setHover(null);
      pointer.targetX = 0;
      pointer.targetY = 0;
    };
    const onClick = () => {
      // A drag that panned the map must not also select / deselect a marker.
      if (drag.moved) { drag.moved = false; return; }
      if (hovered) onSelectRef.current(hovered.userData as HoverInfo);
      else onSelectRef.current(null);
    };
    mount.addEventListener('pointermove', onPointerMove);
    mount.addEventListener('pointerleave', onPointerLeave);
    mount.addEventListener('pointerdown', onPointerDown);
    mount.addEventListener('click', onClick);
    mount.addEventListener('wheel', onWheel, { passive: false });
    window.addEventListener('pointerup', onPointerUp);

    /* HTML label projection (site/anchor pills follow their 3D markers). */
    const labelWorld = new Map<string, THREE.Vector3>();
    for (const site of data.sites) labelWorld.set(`site:${site.key}`, toWorld(site.lat, site.lon, 2));
    for (const anchor of data.anchors) {
      if (anchor.lat != null && anchor.lon != null) labelWorld.set(`anchor:${anchor.id}`, toWorld(anchor.lat, anchor.lon, 2.6));
    }
    const projected = new THREE.Vector3();
    const placeLabels = () => {
      for (const [id, world] of labelWorld) {
        const element = labelRefs.current[id];
        if (!element) continue;
        projected.copy(world).applyMatrix4(root.matrixWorld).project(camera);
        const x = (projected.x * 0.5 + 0.5) * width;
        const y = (-projected.y * 0.5 + 0.5) * height;
        element.style.opacity = projected.z > 1 ? '0' : '1';
        element.style.transform = `translate3d(${Math.round(x)}px, ${Math.round(y + 10)}px, 0) translateX(-50%)`;
      }
    };

    let raf = 0;
    const clock = new THREE.Clock();
    const animate = () => {
      raf = window.requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();
      pointer.x += (pointer.targetX - pointer.x) * 0.05;
      pointer.y += (pointer.targetY - pointer.y) * 0.05;
      if (!reducedMotion && !drag.active) {
        root.rotation.x = BASE_TILT + pointer.y * 0.05;
        root.rotation.y = pointer.x * 0.07;
      }
      // Apply live zoom + clamped pan so the map can be explored freely.
      const liveScale = baseScaleRef.current * zoomRef.current;
      root.scale.setScalar(liveScale);
      const extentX = MAP_W * liveScale * 0.5;
      const extentY = MAP_H * liveScale * 0.5;
      panRef.current.x = Math.max(-extentX, Math.min(extentX, panRef.current.x));
      panRef.current.y = Math.max(-extentY, Math.min(extentY, panRef.current.y));
      root.position.set(panRef.current.x, panRef.current.y, 0);
      for (const pulse of pulses) {
        const t = (elapsed * 0.42 + pulse.phase) % 1;
        pulse.mesh.scale.setScalar(pulse.base + (pulse.max - pulse.base) * t);
        (pulse.mesh.material as THREE.MeshBasicMaterial).opacity = (1 - t) * 0.45;
      }
      for (const traveller of travellers) {
        const t = (elapsed * traveller.speed + traveller.phase) % 1;
        traveller.mesh.position.copy(traveller.curve.getPoint(t));
      }
      for (const spinner of spinners) spinner.rotation.y = elapsed * 0.8;
      placeLabels();
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      window.cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      mount.removeEventListener('pointermove', onPointerMove);
      mount.removeEventListener('pointerleave', onPointerLeave);
      mount.removeEventListener('pointerdown', onPointerDown);
      mount.removeEventListener('click', onClick);
      mount.removeEventListener('wheel', onWheel);
      window.removeEventListener('pointerup', onPointerUp);
      for (const disposable of disposables) disposable.dispose();
      renderer.dispose();
      if (renderer.domElement.parentElement === mount) mount.removeChild(renderer.domElement);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mapSig]);

  const hoverSite: TheaterRegion | null = hover?.kind === 'site' ? siteByKey.get(hover.key) ?? null : null;
  const hoverAnchor: TheaterAnchor | null = hover?.kind === 'anchor' ? anchorById.get(hover.key) ?? null : null;

  return (
    <div ref={mountRef} className="relative h-[300px] w-full overflow-hidden rounded-lg border border-cyan-400/20 bg-[#020617] md:h-[380px]" aria-label="Global quantum exposure 3D map">
      {/* Site / anchor label pills (projected onto the 3D scene each frame) */}
      {map.sites.map((site) => (
        <button
          key={`site:${site.key}`}
          ref={(el) => { labelRefs.current[`site:${site.key}`] = el; }}
          type="button"
          onClick={() => onSelect({ kind: 'site', key: site.key })}
          className={`absolute left-0 top-0 z-10 whitespace-nowrap rounded border px-1.5 py-0.5 text-[8px] font-black uppercase tracking-[0.08em] transition-colors ${selected?.kind === 'site' && selected.key === site.key ? 'border-cyan-300/80 bg-cyan-500/25 text-cyan-100' : 'border-cyan-400/25 bg-black/60 text-white/70 hover:border-cyan-400/60'}`}
          style={{ willChange: 'transform' }}
        >
          {site.label.split(' (')[0]} · {site.assets}
        </button>
      ))}
      {map.anchors.filter((a) => a.x != null).map((anchor) => (
        <button
          key={`anchor:${anchor.id}`}
          ref={(el) => { labelRefs.current[`anchor:${anchor.id}`] = el; }}
          type="button"
          onClick={() => onSelect({ kind: 'anchor', key: anchor.id })}
          className={`absolute left-0 top-0 z-10 whitespace-nowrap rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-[0.06em] transition-colors ${selected?.kind === 'anchor' && selected.key === anchor.id ? 'border-violet-300/80 bg-violet-500/25 text-violet-100' : 'border-violet-400/25 bg-black/60 text-violet-200/75 hover:border-violet-400/60'}`}
          style={{ willChange: 'transform' }}
        >
          ⬡ {anchor.name}
        </button>
      ))}

      {/* Hover tooltip */}
      <div ref={tooltipRef} className={`pointer-events-none absolute left-0 top-0 z-20 w-[184px] rounded-md border border-cyan-400/35 bg-black/90 p-2 shadow-xl transition-opacity ${hover ? 'opacity-100' : 'opacity-0'}`} style={{ willChange: 'transform' }}>
        {hoverSite && (
          <>
            <p className="truncate text-[10px] font-black text-cyan-200">{hoverSite.label}</p>
            <p className="text-[9px] font-bold text-white/60">{hoverSite.assets} asset(s) · {hoverSite.vulnerableAssets} vulnerable</p>
            <p className="text-[9px] font-bold text-white/45">Avg risk {hoverSite.avgRisk} · {hoverSite.severity}</p>
            {(hoverSite.topAssets ?? []).slice(0, 3).map((a) => (
              <p key={a.name} className="truncate text-[8px] font-semibold text-white/50">• {a.name} ({a.riskScore})</p>
            ))}
          </>
        )}
        {hoverAnchor && (
          <>
            <p className="truncate text-[10px] font-black text-violet-200">{hoverAnchor.name}</p>
            <p className="text-[9px] font-bold text-white/60">Certificate authority{hoverAnchor.countryLabel ? ` · ${hoverAnchor.countryLabel}` : ''}</p>
            <p className="text-[9px] font-bold text-white/45">Anchors {hoverAnchor.certificates} asset(s)</p>
            <p className={`text-[8px] font-black uppercase ${hoverAnchor.quantumSafe ? 'text-emerald-300' : 'text-red-300'}`}>{hoverAnchor.quantumSafe ? 'Quantum-safe chain' : 'Quantum-vulnerable chain'}</p>
          </>
        )}
      </div>

      {/* Zoom + pan controls */}
      <div className="absolute right-2 top-2 z-20 flex flex-col items-end gap-1.5">
        <div className="flex flex-col overflow-hidden rounded-md border border-cyan-400/25 bg-black/70 backdrop-blur">
          <button
            type="button"
            aria-label="Zoom in"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); zoomBy(1.25); }}
            disabled={zoom >= ZOOM_MAX - 0.001}
            className="grid h-7 w-7 place-items-center text-base font-black text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:text-white/25"
          >
            +
          </button>
          <button
            type="button"
            aria-label="Zoom out"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); zoomBy(1 / 1.25); }}
            disabled={zoom <= ZOOM_MIN + 0.001}
            className="grid h-7 w-7 place-items-center border-t border-cyan-400/15 text-base font-black text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:text-white/25"
          >
            −
          </button>
          <button
            type="button"
            aria-label="Reset view"
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); resetView(); }}
            className="grid h-7 w-7 place-items-center border-t border-cyan-400/15 text-xs font-black text-cyan-200 transition hover:bg-cyan-500/20"
          >
            ⌂
          </button>
        </div>
        <span className="rounded border border-white/10 bg-black/60 px-1.5 py-0.5 font-mono text-[8px] font-black text-white/50">{zoom.toFixed(1)}×</span>
      </div>

      {/* Legend */}
      <div className="pointer-events-none absolute bottom-2 left-2 z-10 flex flex-wrap items-center gap-2 rounded border border-white/10 bg-black/60 px-2 py-1 text-[8px] font-black uppercase tracking-[0.1em] text-white/55">
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-red-400" /> Critical site</span>
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> High</span>
        <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Low</span>
        <span className="flex items-center gap-1 text-violet-300">⬡ Trust anchor (CA)</span>
        <span className="flex items-center gap-1"><span className="inline-block h-px w-4 bg-cyan-300" /> Real dependency / trust link</span>
        <span className="text-cyan-300/60">Scroll to zoom · drag to pan</span>
      </div>

      {map.sites.length === 0 && map.anchors.every((a) => a.x == null) && (
        <div className="pointer-events-none absolute inset-0 z-10 grid place-items-center">
          <p className="max-w-[300px] rounded-md border border-white/10 bg-black/70 px-3 py-2 text-center text-[9px] font-bold uppercase tracking-[0.1em] text-white/55">
            No location telemetry yet — sites and certificate trust anchors plot automatically as scans discover region metadata and issuer origins.
          </p>
        </div>
      )}
    </div>
  );
}
