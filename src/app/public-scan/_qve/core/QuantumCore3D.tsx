/**
 * Quantum Visualization Engine™ — holographic Quantum Core (Three.js / R3F).
 *
 * The centrepiece of the hero: a heraldic shield of refractive glass with a
 * wireframe globe suspended inside it, three counter-rotating orbital rings,
 * an animated hexagonal field behind, orbiting quantum particles, and a radar
 * sweep that fires on a fixed cadence.
 *
 * Everything visible here is driven by engine state, not by a decorative
 * timeline:
 *   • `intensity`  (real scan progress)      → ring speed, emissive gain, particle drift
 *   • `accent`     (grade colour / verdict)  → rim light, ring tint, globe emission
 *   • `quantum`    (hybrid ML-KEM observed)  → violet upgrade of the whole core
 *   • `alertKey`   (a real critical finding)  → red shock pulse + shake
 *
 * Lazy-loaded: this module (and Three.js with it) is only fetched on devices the
 * Performance Manager clears for `core3d`, so the anonymous front door does not
 * pay for WebGL it will not use.
 */
'use client';

import React from 'react';
import * as THREE from 'three';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Sparkles } from '@react-three/drei';
import { Bloom, EffectComposer, GodRays, Vignette } from '@react-three/postprocessing';
import { BlendFunction, KernelSize, Resolution } from 'postprocessing';
import type { QveBudget } from '../performance-manager';
import { QVE_COLOR } from '../types';
import { qveAccentOn, type QvePalette } from '../theme';

export interface QuantumCore3DProps {
  /** 0-1, from real scan progress. */
  intensity: number;
  /** Primary hex accent — grade colour once graded, cyan while scanning. */
  accent: string;
  /** True once hybrid post-quantum key agreement has been observed. */
  quantum: boolean;
  /** Changes when a genuine high/critical finding arrives; triggers the shock. */
  alertKey: number;
  /** Engine run state. */
  active: boolean;
  budget: QveBudget;
  dpr: number;
  /* Passed as a PROP, never read from context: @react-three/fiber renders the
     scene through its own reconciler, so React context from the DOM tree does
     not cross the <Canvas> boundary. */
  palette: QvePalette;
  /**
   * Fired once the WebGL root is live. The stage keeps its SVG core visible
   * until this resolves — R3F only creates its root after a ResizeObserver
   * delivers a non-zero size, which never happens in a laid-out-but-not-
   * compositing context (background tab, hidden pane, print). Without this the
   * core region would sit empty in exactly those cases.
   */
  onReady?: () => void;
}

/* ------------------------------------------------------------------ geometry - */

/**
 * Heraldic shield outline, drawn once and shared. Units are core-space; the
 * silhouette matches the reference hero (flat shoulders, tapered point).
 */
function buildShieldShape(): THREE.Shape {
  const shape = new THREE.Shape();
  shape.moveTo(0, 1.18);
  shape.bezierCurveTo(0.42, 1.16, 0.72, 1.02, 0.86, 0.9);
  shape.lineTo(0.86, 0.06);
  shape.bezierCurveTo(0.86, -0.62, 0.46, -1.08, 0, -1.32);
  shape.bezierCurveTo(-0.46, -1.08, -0.86, -0.62, -0.86, 0.06);
  shape.lineTo(-0.86, 0.9);
  shape.bezierCurveTo(-0.72, 1.02, -0.42, 1.16, 0, 1.18);
  return shape;
}

/** Points scattered on a sphere via the golden-angle spiral — no clustering. */
function sphericalPoints(count: number, radius: number): Float32Array {
  const positions = new Float32Array(count * 3);
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let index = 0; index < count; index += 1) {
    const y = 1 - (index / Math.max(1, count - 1)) * 2;
    const ringRadius = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = golden * index;
    positions[index * 3] = Math.cos(theta) * ringRadius * radius;
    positions[index * 3 + 1] = y * radius;
    positions[index * 3 + 2] = Math.sin(theta) * ringRadius * radius;
  }
  return positions;
}

/* -------------------------------------------------------------------- shader - */

/**
 * Animated hexagonal quantum field rendered behind the shield. A hex-distance
 * function gives crisp cell edges at any resolution (no texture to load), and
 * a travelling ripple makes the lattice read as an energised surface rather
 * than wallpaper.
 */
const HEX_FIELD_VERTEX = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const HEX_FIELD_FRAGMENT = /* glsl */ `
  precision highp float;
  varying vec2 vUv;
  uniform float uTime;
  uniform float uIntensity;
  uniform vec3  uColorA;
  uniform vec3  uColorB;

  // Distance to the nearest edge of a hexagonal cell.
  float hexEdge(vec2 p) {
    p = abs(p);
    return max(dot(p, normalize(vec2(1.0, 1.732))), p.x);
  }

  void main() {
    vec2 uv = (vUv - 0.5) * 2.0;
    float radial = length(uv);

    // Hex lattice in skewed space.
    vec2 grid = uv * 7.0;
    vec2 a = mod(grid, vec2(1.0, 1.732)) - vec2(0.5, 0.866);
    vec2 b = mod(grid + vec2(0.5, 0.866), vec2(1.0, 1.732)) - vec2(0.5, 0.866);
    vec2 cell = dot(a, a) < dot(b, b) ? a : b;
    float edge = 0.5 - hexEdge(cell);
    float lattice = smoothstep(0.0, 0.055, edge) - smoothstep(0.055, 0.12, edge);

    // Travelling ripple, driven by scan intensity.
    float ripple = sin(radial * 9.0 - uTime * 1.7) * 0.5 + 0.5;
    ripple = pow(ripple, 3.0);

    float falloff = smoothstep(1.05, 0.15, radial);
    vec3 tint = mix(uColorA, uColorB, ripple);
    float alpha = lattice * falloff * (0.10 + 0.30 * uIntensity) + ripple * falloff * 0.05 * uIntensity;

    gl_FragColor = vec4(tint, alpha);
  }
`;

function HexField({ intensity, accent, quantum, palette }: { intensity: number; accent: string; quantum: boolean; palette: QvePalette }) {
  const uniforms = React.useMemo(
    () => ({
      uTime: { value: 0 },
      uIntensity: { value: 0 },
      uColorA: { value: new THREE.Color(QVE_COLOR.cyan) },
      uColorB: { value: new THREE.Color(QVE_COLOR.quantum) },
    }),
    [],
  );

  React.useEffect(() => {
    uniforms.uColorA.value.set(accent);
    uniforms.uColorB.value.set(quantum ? QVE_COLOR.quantum : '#1d4ed8');
  }, [accent, quantum, uniforms]);

  useFrame((_state, delta) => {
    uniforms.uTime.value += delta;
    // Ease toward the target so a step change in progress does not pop.
    /* Additive blending ADDS light. On white there is no headroom left, so the
       field that reads as energy on navy reads as a grey haze there instead —
       damped rather than removed, so the core still breathes. */
    const target = intensity * palette.glow;
    uniforms.uIntensity.value += (target - uniforms.uIntensity.value) * Math.min(1, delta * 3);
  });

  return (
    <mesh position={[0, 0, -1.15]}>
      <planeGeometry args={[6.2, 6.2]} />
      <shaderMaterial
        vertexShader={HEX_FIELD_VERTEX}
        fragmentShader={HEX_FIELD_FRAGMENT}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </mesh>
  );
}

/* --------------------------------------------------------------------- globe - */

function HoloGlobe({ intensity, accent, count, palette }: { intensity: number; accent: string; count: number; palette: QvePalette }) {
  const group = React.useRef<THREE.Group>(null);
  const positions = React.useMemo(() => sphericalPoints(Math.max(120, count), 0.585), [count]);
  const color = React.useMemo(() => new THREE.Color(accent), [accent]);

  useFrame((_state, delta) => {
    if (!group.current) return;
    // Base drift keeps the core alive even at rest; scanning spins it faster.
    group.current.rotation.y += delta * (0.12 + intensity * 0.5);
    group.current.rotation.x = Math.sin(_state.clock.elapsedTime * 0.25) * 0.08;
  });

  return (
    <group ref={group}>
      {/* Solid body — deep ocean blue so the wireframe reads against it. */}
      <mesh>
        <sphereGeometry args={[0.55, 40, 40]} />
        <meshStandardMaterial
          color={palette.globeBody}
          emissive={palette.globeEmissive}
          emissiveIntensity={0.28 + intensity * 0.3}
          roughness={0.4}
          metalness={0.2}
          transparent
          opacity={0.96}
        />
      </mesh>

      {/* Latitude / longitude lattice. */}
      <mesh scale={1.008}>
        <icosahedronGeometry args={[0.56, 3]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.34 + intensity * 0.28} />
      </mesh>

      {/* Surface nodes — the "digital globe" read from the reference hero. */}
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        </bufferGeometry>
        <pointsMaterial
          size={0.017}
          color={color}
          transparent
          opacity={0.7}
          sizeAttenuation
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </points>

      {/* Inner emissive heart — the light source the bloom picks up. Kept small
          and semi-transparent: at full opacity it blooms over the wireframe and
          the globe stops reading as a globe. */}
      <mesh scale={0.26}>
        <sphereGeometry args={[0.55, 24, 24]} />
        <meshBasicMaterial color={color} transparent opacity={0.3 + intensity * 0.28} />
      </mesh>
    </group>
  );
}

/* -------------------------------------------------------------------- shield - */

function HoloShield({ accent, intensity, transmission, palette }: { accent: string; intensity: number; transmission: boolean; palette: QvePalette }) {
  const geometry = React.useMemo(() => {
    const shape = buildShieldShape();
    const extruded = new THREE.ExtrudeGeometry(shape, {
      depth: 0.16,
      bevelEnabled: true,
      bevelThickness: 0.035,
      bevelSize: 0.03,
      bevelSegments: 3,
      curveSegments: 24,
    });
    extruded.center();
    return extruded;
  }, []);

  const edges = React.useMemo(() => new THREE.EdgesGeometry(geometry, 24), [geometry]);

  React.useEffect(() => () => {
    geometry.dispose();
    edges.dispose();
  }, [geometry, edges]);

  const group = React.useRef<THREE.Group>(null);
  useFrame((state) => {
    if (!group.current) return;
    // Slight parallax tilt: the shield is a hologram, it should never be dead flat.
    group.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.32) * 0.13;
    group.current.rotation.x = Math.cos(state.clock.elapsedTime * 0.24) * 0.06;
  });

  return (
    <group ref={group} scale={1.06}>
      <mesh geometry={geometry}>
        <meshPhysicalMaterial
          color={palette.globeShell}
          emissive={accent}
          emissiveIntensity={0.08 + intensity * 0.12}
          roughness={0.14}
          metalness={0.18}
          transparent
          opacity={palette.shieldOpacity}
          transmission={transmission ? 0.86 : 0}
          thickness={0.5}
          ior={1.38}
          clearcoat={1}
          clearcoatRoughness={0.08}
          side={THREE.DoubleSide}
        />
      </mesh>
      {/* The silhouette is what makes it read as a shield — keep the edge bright
          even as the fill stays glassy. */}
      <lineSegments geometry={edges}>
        <lineBasicMaterial color={accent} transparent opacity={0.7 + intensity * 0.3} />
      </lineSegments>
    </group>
  );
}

/* --------------------------------------------------------------------- rings - */

interface RingSpec {
  radius: number;
  tube: number;
  arc: number;
  tilt: [number, number, number];
  speed: number;
  color: string;
}

function OrbitalRings({ intensity, accent, quantum, palette }: { intensity: number; accent: string; quantum: boolean; palette: QvePalette }) {
  const specs = React.useMemo<RingSpec[]>(
    () => [
      { radius: 1.34, tube: 0.012, arc: Math.PI * 1.55, tilt: [1.42, 0, 0.28], speed: 0.55, color: accent },
      { radius: 1.58, tube: 0.009, arc: Math.PI * 1.15, tilt: [1.32, 0.42, -0.34], speed: -0.4, color: qveAccentOn(quantum ? QVE_COLOR.quantum : '#e879f9', palette) },
      { radius: 1.82, tube: 0.007, arc: Math.PI * 0.85, tilt: [1.5, -0.3, 0.62], speed: 0.3, color: qveAccentOn('#60a5fa', palette) },
    ],
    [accent, quantum, palette],
  );

  const refs = React.useRef<Array<THREE.Group | null>>([]);

  useFrame((_state, delta) => {
    specs.forEach((spec, index) => {
      const group = refs.current[index];
      if (group) group.rotation.z += delta * spec.speed * (0.45 + intensity * 1.5);
    });
  });

  return (
    <>
      {specs.map((spec, index) => (
        <group
          key={spec.radius}
          ref={(node) => {
            refs.current[index] = node;
          }}
          rotation={spec.tilt}
        >
          {/* Full faint track so the arc has something to travel along. */}
          <mesh>
            <torusGeometry args={[spec.radius, spec.tube * 0.6, 6, 96]} />
            <meshBasicMaterial color={spec.color} transparent opacity={0.1} />
          </mesh>
          <mesh>
            <torusGeometry args={[spec.radius, spec.tube, 8, 96, spec.arc]} />
            <meshBasicMaterial
              color={spec.color}
              transparent
              opacity={0.5 + intensity * 0.4}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>
        </group>
      ))}
    </>
  );
}

/* -------------------------------------------------------------------- radar - */

/** Expanding ring on a fixed 3-second cadence, per the engine spec. */
function RadarSweep({ accent, enabled }: { accent: string; enabled: boolean }) {
  const mesh = React.useRef<THREE.Mesh>(null);
  const material = React.useRef<THREE.MeshBasicMaterial>(null);
  const phase = React.useRef(0);

  useFrame((_state, delta) => {
    if (!enabled || !mesh.current || !material.current) return;
    phase.current = (phase.current + delta / 3) % 1;
    const scale = 0.5 + phase.current * 1.9;
    mesh.current.scale.setScalar(scale);
    material.current.opacity = (1 - phase.current) * 0.36;
  });

  if (!enabled) return null;

  return (
    <mesh ref={mesh} position={[0, 0, -0.4]}>
      <ringGeometry args={[0.94, 1, 96]} />
      <meshBasicMaterial
        ref={material}
        color={accent}
        transparent
        opacity={0}
        side={THREE.DoubleSide}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

/* ------------------------------------------------------------------- orbiters - */

/** Instanced quantum particles on inclined orbits, feeding energy inward. */
function QuantumOrbiters({ count, accent, intensity }: { count: number; accent: string; intensity: number }) {
  const mesh = React.useRef<THREE.InstancedMesh>(null);
  const dummy = React.useMemo(() => new THREE.Object3D(), []);

  const seeds = React.useMemo(
    () =>
      Array.from({ length: count }, () => ({
        radius: 0.85 + Math.random() * 1.15,
        speed: 0.18 + Math.random() * 0.55,
        phase: Math.random() * Math.PI * 2,
        inclination: (Math.random() - 0.5) * 1.5,
        scale: 0.006 + Math.random() * 0.012,
      })),
    [count],
  );

  useFrame((state) => {
    if (!mesh.current) return;
    const time = state.clock.elapsedTime;
    for (let index = 0; index < seeds.length; index += 1) {
      const seed = seeds[index];
      const angle = seed.phase + time * seed.speed * (0.5 + intensity);
      // Gentle inward pull as the scan progresses — energy feeds the core.
      const radius = seed.radius * (1 - intensity * 0.12);
      dummy.position.set(
        Math.cos(angle) * radius,
        Math.sin(angle) * radius * Math.sin(seed.inclination),
        Math.sin(angle) * radius * Math.cos(seed.inclination),
      );
      dummy.scale.setScalar(seed.scale * (1 + intensity * 0.5));
      dummy.updateMatrix();
      mesh.current.setMatrixAt(index, dummy.matrix);
    }
    mesh.current.instanceMatrix.needsUpdate = true;
  });

  if (!count) return null;

  return (
    <instancedMesh ref={mesh} args={[undefined, undefined, count]} frustumCulled={false}>
      <sphereGeometry args={[1, 6, 6]} />
      <meshBasicMaterial
        color={accent}
        transparent
        opacity={0.75}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </instancedMesh>
  );
}

/* -------------------------------------------------------------------- lights - */

function ReactiveLights({ accent, intensity, quantum }: { accent: string; intensity: number; quantum: boolean }) {
  const rim = React.useRef<THREE.PointLight>(null);
  const key = React.useRef<THREE.PointLight>(null);

  useFrame((state) => {
    const pulse = 0.85 + Math.sin(state.clock.elapsedTime * 1.8) * 0.15;
    if (rim.current) rim.current.intensity = (5 + intensity * 9) * pulse;
    if (key.current) key.current.intensity = 3 + intensity * 5;
  });

  return (
    <>
      <ambientLight intensity={0.35} />
      <pointLight ref={key} position={[2.4, 2.1, 3.2]} color={accent} intensity={3} distance={12} />
      <pointLight
        ref={rim}
        position={[-2.2, -1.4, -1.6]}
        color={quantum ? QVE_COLOR.quantum : '#2563eb'}
        intensity={5}
        distance={12}
      />
      <directionalLight position={[0, 4, 2]} intensity={0.5} color="#dbeafe" />
    </>
  );
}

/* --------------------------------------------------------------------- shock - */

/**
 * Camera shake + red flash on a real high/critical finding. Amplitude decays to
 * zero in ~700ms so the alert is felt, not endured.
 */
function AlertShock({ alertKey }: { alertKey: number }) {
  const { camera } = useThree();
  const started = React.useRef(0);
  const base = React.useRef(new THREE.Vector3());

  React.useEffect(() => {
    if (!alertKey) return;
    base.current.copy(camera.position);
    started.current = performance.now();
  }, [alertKey, camera]);

  useFrame(() => {
    if (!started.current) return;
    const elapsed = performance.now() - started.current;
    if (elapsed > 700) {
      camera.position.copy(base.current);
      started.current = 0;
      return;
    }
    const decay = 1 - elapsed / 700;
    const amount = 0.045 * decay * decay;
    camera.position.set(
      base.current.x + (Math.random() - 0.5) * amount * 2,
      base.current.y + (Math.random() - 0.5) * amount * 2,
      base.current.z,
    );
  });

  return null;
}

/* ------------------------------------------------------------------ god rays - */

/**
 * The god-ray source: a small additive sphere at the core's heart. It is also
 * the visible inner glow, so the effect has a real emitter rather than an
 * invisible helper mesh.
 */
function SunCore({ accent, palette }: { accent: string; palette: QvePalette }) {
  const [sun, setSun] = React.useState<THREE.Mesh | null>(null);
  const material = React.useRef<THREE.MeshBasicMaterial>(null);

  return (
    <>
      <mesh ref={setSun} position={[0, 0, -0.55]} scale={0.11}>
        <sphereGeometry args={[1, 20, 20]} />
        <meshBasicMaterial ref={material} color={accent} />
      </mesh>
      {sun && <GodRaysLayer sun={sun} palette={palette} />}
    </>
  );
}

/**
 * POST-FX BUDGET — read before raising any of these numbers.
 *
 * The core is a *readable instrument*, not a light show: a shield silhouette and
 * a wireframe globe have to stay legible, and the score readout sits on top of
 * it. Bloom and god rays are both additive, so they compound; tuned generously
 * they merge every element into one undifferentiated glow blob and destroy the
 * contrast the readout depends on. Hence: a high luminance threshold so only the
 * inner heart blooms, modest intensity, and god rays present but faint —
 * volumetric depth, not a floodlight.
 */
function GodRaysLayer({ sun, palette }: { sun: THREE.Mesh; palette: QvePalette }) {
  return (
    <EffectComposer multisampling={0}>
      <GodRays
        sun={sun}
        blendFunction={BlendFunction.SCREEN}
        samples={24}
        density={0.72}
        decay={0.9}
        weight={0.16 * palette.glow}
        exposure={0.12 * palette.glow}
        clampMax={0.7}
        blur
      />
      <Bloom
        intensity={0.55 * palette.glow}
        luminanceThreshold={0.62}
        luminanceSmoothing={0.28}
        kernelSize={KernelSize.MEDIUM}
        resolutionX={Resolution.AUTO_SIZE}
      />
      {/* The vignette darkens the canvas edges — correct over a navy hero, a
          grey smudge over a white one, where the hero's own light vignette does
          the job instead. */}
      <Vignette offset={0.28} darkness={0.6 * palette.glow} blendFunction={BlendFunction.NORMAL} />
    </EffectComposer>
  );
}

/* ------------------------------------------------------------------- content - */

function CoreScene({ intensity, accent, quantum, alertKey, budget, active, palette }: Omit<QuantumCore3DProps, 'dpr'>) {
  // Smooth every externally-driven value: progress arrives in discrete jumps
  // from the SSE stream and the core must glide, never snap.
  const smoothed = React.useRef(0);
  const [eased, setEased] = React.useState(0);

  useFrame((_state, delta) => {
    const next = smoothed.current + (intensity - smoothed.current) * Math.min(1, delta * 2.4);
    smoothed.current = next;
    // Only re-render React when the change is visible — 1% steps.
    if (Math.abs(next - eased) > 0.01) setEased(next);
  });

  const level = active ? Math.max(0.18, eased) : 0.14;

  return (
    <>
      <ReactiveLights accent={accent} intensity={level} quantum={quantum} />
      <HexField intensity={level} accent={accent} quantum={quantum} palette={palette} />
      <OrbitalRings intensity={level} accent={accent} quantum={quantum} palette={palette} />
      <RadarSweep accent={accent} enabled={budget.radar && active} />
      <HoloShield accent={accent} intensity={level} transmission={budget.tier === 'full'} palette={palette} />
      <HoloGlobe intensity={level} accent={accent} count={Math.min(420, budget.coreParticles)} palette={palette} />
      <QuantumOrbiters count={Math.round(budget.coreParticles / 6)} accent={accent} intensity={level} />
      {budget.coreParticles > 0 && (
        <Sparkles
          count={Math.round(budget.coreParticles / 8)}
          scale={4.2}
          size={2.2}
          speed={0.35 + level}
          opacity={0.5}
          color={quantum ? QVE_COLOR.quantum : accent}
        />
      )}
      <AlertShock alertKey={alertKey} />
      {budget.postFx ? (
        <SunCore accent={accent} palette={palette} />
      ) : (
        <mesh position={[0, 0, -0.55]} scale={0.11}>
          <sphereGeometry args={[1, 16, 16]} />
          <meshBasicMaterial color={accent} />
        </mesh>
      )}
    </>
  );
}

/* -------------------------------------------------------------------- canvas - */

export default function QuantumCore3D(props: QuantumCore3DProps) {
  const { dpr, onReady, ...scene } = props;
  return (
    <Canvas
      dpr={dpr}
      onCreated={() => onReady?.()}
      // No alpha-to-black fill: the core composites over the hero's own field.
      gl={{ antialias: false, alpha: true, powerPreference: 'high-performance' }}
      camera={{ fov: 42, position: [0, 0, 4.7], near: 0.1, far: 40 }}
      style={{ width: '100%', height: '100%' }}
      // The core is decoration over a fully-labelled data layer; screen readers
      // read the node cards and the timeline instead.
      aria-hidden
      frameloop="always"
    >
      <CoreScene {...scene} />
    </Canvas>
  );
}
