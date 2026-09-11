/**
 * Quantum Simulation Range — the WebGL stage.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces drew the attack as five SVG bezier curves with a CSS
 * glow. That is a diagram of an idea. This is an instrument: the geometry moves
 * because the simulation state moved, and two of the things on screen are
 * rendered directly from numbers the engines computed.
 *
 * WHAT IS REAL HERE, NOT DECORATIVE
 * ---------------------------------
 *   • The interference ring is the Born-rule distribution from the state-vector
 *     simulator in `lib/quantum-sim/shor.ts`, downsampled to 96 radial bins.
 *     When the simulator has not run, the ring is visibly noise; when it has,
 *     the comb of peaks at k·2^t/r is the same comb the Shor Laboratory panel
 *     plots in 2D, drawn from the same Float64Array.
 *   • The qubit lattice holds one point per qubit in the current register, so
 *     widening the control register makes the core visibly denser.
 *
 * Everything else — conduits, packets, the archive silo, the shield dome — is
 * staging, and is labelled as such in the UI rather than dressed up as data.
 *
 * PERFORMANCE
 * -----------
 * Budgeted through the platform's existing Performance Manager
 * (`_qve/performance-manager`), the same one /public-scan uses, so a low-end
 * device or a reduced-motion preference never mounts this at all — the caller
 * renders the SVG fallback instead. Particle counts and post-processing come
 * from that budget rather than being chosen here.
 */

import React from 'react';
import * as THREE from 'three';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing';
import { BlendFunction, KernelSize } from 'postprocessing';
import type { QveBudget } from '@/app/public-scan/_qve/performance-manager';
import { QSR } from '../_theme';

/* ═══════════════════════════════════════════════════════════════ scene model */

export interface StageSites {
  client: string;
  transit: string;
  server: string;
  archive: string;
  crqc: string;
}

export interface QuantumStage3DProps {
  /** 1..6 — which stage of the attack chain is active. */
  stage: number;
  /** 0..1 — how far through the current stage. Drives flow speed and emission. */
  progress: number;
  /** Node names from the active scenario. */
  sites: StageSites;
  /**
   * The real control-register distribution from the last Shor run, or null when
   * the simulator has not been run yet. Not decorative — see the file header.
   */
  distribution: Float64Array | null;
  /** Qubits in the current register, for the lattice density. */
  qubits: number;
  /** True once the run recovered a period: the ring locks and turns violet. */
  resolved: boolean;
  /** True when the scenario is on a hybrid (post-quantum) group already. */
  quantumSafe: boolean;
  budget: QveBudget;
  dpr: number;
  onReady?: () => void;
}

const SITE_POSITIONS = {
  client: new THREE.Vector3(-6.4, 0.7, 0.2),
  transit: new THREE.Vector3(-2.2, -0.2, 1.0),
  server: new THREE.Vector3(6.4, 0.7, 0.2),
  archive: new THREE.Vector3(-2.4, -3.4, -1.4),
  crqc: new THREE.Vector3(1.6, 1.9, -1.8),
} as const;

/** Where the camera sits for each stage, and what it looks at. */
const CAMERA_RIG: Array<{ position: [number, number, number]; target: [number, number, number] }> = [
  { position: [-0.6, 1.4, 14.4], target: [-0.6, 0.2, 0] }, // 1 record — the whole wire, both endpoints labelled
  { position: [-2.0, -0.6, 11.6], target: [-2.2, -1.6, 0] }, // 2 archive — look down at the silo
  { position: [2.4, 2.2, 8.2], target: [1.6, 1.6, -1.2] }, // 3 order-finding — into the core
  { position: [3.4, 1.4, 11.2], target: [3.2, 1.0, 0] }, // 4 key recovery — core to target
  { position: [0.0, 0.6, 14.2], target: [0.0, -0.6, 0] }, // 5 exposure — the whole board
  { position: [4.6, 1.0, 11.8], target: [5.0, 0.6, 0] }, // 6 migrate — the shield
];

/* ═══════════════════════════════════════════════════════════════ camera rig */

function StageRig({ stage, animate }: { stage: number; animate: boolean }) {
  const { camera } = useThree();
  const target = React.useRef(new THREE.Vector3(...CAMERA_RIG[0].target));

  React.useEffect(() => {
    if (animate) return;
    // Reduced motion: snap, never glide.
    const rig = CAMERA_RIG[Math.min(stage, CAMERA_RIG.length) - 1];
    camera.position.set(...rig.position);
    target.current.set(...rig.target);
    camera.lookAt(target.current);
  }, [animate, camera, stage]);

  useFrame((_state, delta) => {
    if (!animate) return;
    const rig = CAMERA_RIG[Math.min(stage, CAMERA_RIG.length) - 1];
    const lerp = Math.min(1, delta * 1.4);
    camera.position.lerp(new THREE.Vector3(...rig.position), lerp);
    target.current.lerp(new THREE.Vector3(...rig.target), lerp);
    camera.lookAt(target.current);
  });

  return null;
}

/* ═══════════════════════════════════════════════════════════════ backdrop */

/** A slowly drifting lattice of points: depth cue, not data. */
function LatticeField({ count, animate }: { count: number; animate: boolean }) {
  const points = React.useRef<THREE.Points>(null);
  const positions = React.useMemo(() => {
    const out = new Float32Array(count * 3);
    for (let i = 0; i < count; i += 1) {
      out[i * 3] = (Math.random() - 0.5) * 34;
      out[i * 3 + 1] = (Math.random() - 0.5) * 18;
      out[i * 3 + 2] = -6 - Math.random() * 16;
    }
    return out;
  }, [count]);

  useFrame((state) => {
    if (!points.current || !animate) return;
    points.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.04) * 0.12;
    points.current.rotation.x = Math.cos(state.clock.elapsedTime * 0.03) * 0.05;
  });

  return (
    <points ref={points}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.05} color={QSR.live} transparent opacity={0.22} sizeAttenuation depthWrite={false} />
    </points>
  );
}

/* ═══════════════════════════════════════════════════════════════ site nodes */

function SiteNode({
  position,
  label,
  sublabel,
  accent,
  active,
  compromised,
  animate,
  shape = 'octahedron',
}: {
  position: THREE.Vector3;
  label: string;
  sublabel: string;
  accent: string;
  active: boolean;
  compromised: boolean;
  animate: boolean;
  shape?: 'octahedron' | 'box' | 'cylinder';
}) {
  const group = React.useRef<THREE.Group>(null);
  const ring = React.useRef<THREE.Mesh>(null);
  const colour = React.useMemo(() => new THREE.Color(compromised ? QSR.broken : accent), [accent, compromised]);

  useFrame((state, delta) => {
    if (!group.current || !animate) return;
    group.current.rotation.y += delta * (active ? 0.55 : 0.16);
    const pulse = active ? 1 + Math.sin(state.clock.elapsedTime * 3.2) * 0.06 : 1;
    group.current.scale.setScalar(pulse);
    if (ring.current) {
      ring.current.rotation.z += delta * (active ? 0.9 : 0.25);
    }
  });

  return (
    <group position={position}>
      <group ref={group}>
        <mesh>
          {shape === 'box' ? (
            <boxGeometry args={[0.62, 0.62, 0.62]} />
          ) : shape === 'cylinder' ? (
            <cylinderGeometry args={[0.42, 0.42, 0.7, 6]} />
          ) : (
            <octahedronGeometry args={[0.46, 0]} />
          )}
          <meshStandardMaterial
            color={colour}
            emissive={colour}
            emissiveIntensity={active ? 1.5 : 0.4}
            roughness={0.28}
            metalness={0.55}
          />
        </mesh>
        <mesh scale={1.35}>
          {shape === 'box' ? <boxGeometry args={[0.62, 0.62, 0.62]} /> : <octahedronGeometry args={[0.46, 0]} />}
          <meshBasicMaterial color={colour} wireframe transparent opacity={active ? 0.45 : 0.16} />
        </mesh>
      </group>

      <mesh ref={ring} rotation={[Math.PI / 2.6, 0, 0]}>
        <torusGeometry args={[0.92, 0.012, 8, 64]} />
        <meshBasicMaterial color={colour} transparent opacity={active ? 0.7 : 0.22} />
      </mesh>

      <Html center distanceFactor={11} position={[0, -1.35, 0]} style={{ pointerEvents: 'none', userSelect: 'none' }}>
        <div style={{ textAlign: 'center', whiteSpace: 'nowrap', fontFamily: '"JetBrains Mono", monospace' }}>
          <div
            style={{
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: '0.08em',
              color: compromised ? QSR.broken : active ? '#e2e8f0' : QSR.inkSoft,
              textShadow: '0 2px 12px rgba(0,0,0,0.95)',
            }}
          >
            {label}
          </div>
          <div style={{ fontSize: 9, letterSpacing: '0.18em', textTransform: 'uppercase', color: compromised ? QSR.broken : accent, marginTop: 2 }}>
            {sublabel}
          </div>
        </div>
      </Html>
    </group>
  );
}

/* ═══════════════════════════════════════════════════════════════ conduits */

/**
 * A link between two sites: a static tube plus instanced packets that advance
 * along the curve. `flow` scales packet speed; `intensity` scales emission.
 */
function DataConduit({
  from,
  to,
  bow,
  accent,
  flow,
  intensity,
  packets,
  animate,
  dashed = false,
}: {
  from: THREE.Vector3;
  to: THREE.Vector3;
  bow: THREE.Vector3;
  accent: string;
  flow: number;
  intensity: number;
  packets: number;
  animate: boolean;
  dashed?: boolean;
}) {
  const curve = React.useMemo(() => {
    const mid = from.clone().add(to).multiplyScalar(0.5).add(bow);
    return new THREE.CatmullRomCurve3([from.clone(), mid, to.clone()]);
  }, [from, to, bow]);

  const tube = React.useMemo(() => new THREE.TubeGeometry(curve, 48, dashed ? 0.012 : 0.022, 7, false), [curve, dashed]);
  const instances = React.useRef<THREE.InstancedMesh>(null);
  const dummy = React.useMemo(() => new THREE.Object3D(), []);
  const offsets = React.useMemo(() => Array.from({ length: packets }, (_, i) => i / Math.max(1, packets)), [packets]);
  const clock = React.useRef(0);
  const colour = React.useMemo(() => new THREE.Color(accent), [accent]);

  React.useEffect(() => () => tube.dispose(), [tube]);

  useFrame((_state, delta) => {
    if (!instances.current) return;
    if (animate) clock.current += delta * flow;
    for (let i = 0; i < offsets.length; i += 1) {
      const t = (offsets[i] + clock.current) % 1;
      curve.getPointAt(t, dummy.position);
      // Taper the head so packets read as motion, not as beads.
      const scale = 0.055 * (0.6 + Math.sin(t * Math.PI) * 0.8) * (0.5 + intensity);
      dummy.scale.setScalar(Math.max(0.012, scale));
      dummy.updateMatrix();
      instances.current.setMatrixAt(i, dummy.matrix);
    }
    instances.current.instanceMatrix.needsUpdate = true;
  });

  return (
    <group>
      <mesh geometry={tube}>
        <meshBasicMaterial color={colour} transparent opacity={0.1 + intensity * 0.35} depthWrite={false} />
      </mesh>
      {packets > 0 && (
        <instancedMesh ref={instances} args={[undefined, undefined, packets]}>
          <sphereGeometry args={[1, 8, 8]} />
          <meshBasicMaterial color={colour} transparent opacity={0.5 + intensity * 0.5} blending={THREE.AdditiveBlending} depthWrite={false} />
        </instancedMesh>
      )}
    </group>
  );
}

/* ═══════════════════════════════════════════════════════ the quantum core */

const RING_BINS = 96;

/**
 * The CRQC. Two layers:
 *
 *   • a qubit lattice — one point per qubit in the current register, so the
 *     core's density tracks the actual simulation;
 *   • an interference ring — 96 radial bars whose heights are the REAL
 *     Born-rule distribution from the state-vector simulator. Before a run they
 *     are flat noise; after one, the comb.
 */
function QuantumCore({
  position,
  active,
  spinUp,
  distribution,
  qubits,
  resolved,
  animate,
}: {
  position: THREE.Vector3;
  active: boolean;
  spinUp: number;
  distribution: Float64Array | null;
  qubits: number;
  resolved: boolean;
  animate: boolean;
}) {
  const group = React.useRef<THREE.Group>(null);
  const bars = React.useRef<THREE.InstancedMesh>(null);
  const dummy = React.useMemo(() => new THREE.Object3D(), []);
  const accent = resolved ? QSR.quantum : QSR.live;
  const colour = React.useMemo(() => new THREE.Color(accent), [accent]);

  /** One lattice point per qubit, on a golden-angle sphere. */
  const lattice = React.useMemo(() => {
    const count = Math.max(8, Math.min(qubits, 64));
    const out = new Float32Array(count * 3);
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < count; i += 1) {
      const y = 1 - (i / Math.max(1, count - 1)) * 2;
      const radius = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = golden * i;
      out[i * 3] = Math.cos(theta) * radius * 0.72;
      out[i * 3 + 1] = y * 0.72;
      out[i * 3 + 2] = Math.sin(theta) * radius * 0.72;
    }
    return out;
  }, [qubits]);

  /**
   * Downsample the distribution to the ring's bin count, normalised so the
   * tallest peak reaches full height. Peak SHAPE is preserved — this is the
   * measurement statistics, only re-binned.
   */
  const heights = React.useMemo(() => {
    const out = new Float32Array(RING_BINS);
    if (!distribution || distribution.length === 0) {
      for (let i = 0; i < RING_BINS; i += 1) out[i] = 0.08 + Math.random() * 0.06;
      return out;
    }
    const perBin = distribution.length / RING_BINS;
    let peak = 0;
    for (let i = 0; i < RING_BINS; i += 1) {
      let sum = 0;
      const start = Math.floor(i * perBin);
      const end = Math.max(start + 1, Math.floor((i + 1) * perBin));
      for (let j = start; j < end && j < distribution.length; j += 1) sum += distribution[j];
      out[i] = sum;
      peak = Math.max(peak, sum);
    }
    if (peak > 0) for (let i = 0; i < RING_BINS; i += 1) out[i] = out[i] / peak;
    return out;
  }, [distribution]);

  useFrame((state, delta) => {
    if (group.current && animate) {
      group.current.rotation.y += delta * (0.2 + spinUp * 1.6);
      group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.4) * 0.12;
    }
    if (!bars.current) return;
    const elapsed = state.clock.elapsedTime;
    for (let i = 0; i < RING_BINS; i += 1) {
      const angle = (i / RING_BINS) * Math.PI * 2;
      // Before the register resolves, the bars shimmer: superposition has not
      // collapsed to anything yet.
      const shimmer = resolved ? 1 : 0.55 + Math.sin(elapsed * 5 + i * 0.7) * 0.35;
      const height = Math.max(0.02, heights[i] * shimmer * (0.25 + spinUp * 1.5));
      dummy.position.set(Math.cos(angle) * 1.35, height / 2, Math.sin(angle) * 1.35);
      dummy.scale.set(0.05, height, 0.05);
      dummy.rotation.set(0, -angle, 0);
      dummy.updateMatrix();
      bars.current.setMatrixAt(i, dummy.matrix);
    }
    bars.current.instanceMatrix.needsUpdate = true;
  });

  return (
    <group position={position}>
      <group ref={group}>
        <mesh>
          <icosahedronGeometry args={[0.68, 1]} />
          <meshBasicMaterial color={colour} wireframe transparent opacity={0.25 + spinUp * 0.45} />
        </mesh>
        <mesh scale={0.55}>
          <icosahedronGeometry args={[0.68, 2]} />
          <meshStandardMaterial
            color={colour}
            emissive={colour}
            emissiveIntensity={0.5 + spinUp * 2.6}
            roughness={0.2}
            metalness={0.7}
            transparent
            opacity={0.85}
          />
        </mesh>
        <points>
          <bufferGeometry>
            <bufferAttribute attach="attributes-position" args={[lattice, 3]} />
          </bufferGeometry>
          <pointsMaterial size={0.075} color={colour} transparent opacity={0.5 + spinUp * 0.5} sizeAttenuation depthWrite={false} />
        </points>
      </group>

      {/* The interference ring — real measurement statistics. */}
      <instancedMesh ref={bars} args={[undefined, undefined, RING_BINS]} position={[0, -1.15, 0]}>
        <boxGeometry args={[1, 1, 1]} />
        <meshBasicMaterial color={colour} transparent opacity={active ? 0.9 : 0.3} blending={THREE.AdditiveBlending} depthWrite={false} />
      </instancedMesh>

      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -1.16, 0]}>
        <ringGeometry args={[1.3, 1.4, 96]} />
        <meshBasicMaterial color={colour} transparent opacity={active ? 0.4 : 0.12} side={THREE.DoubleSide} />
      </mesh>
    </group>
  );
}

/* ═══════════════════════════════════════════════════════════════ archive */

/** Cold storage. Plates light up as the archive fills — staging, not data. */
function ArchiveSilo({ position, fill, active, animate }: { position: THREE.Vector3; fill: number; active: boolean; animate: boolean }) {
  const group = React.useRef<THREE.Group>(null);
  const plates = 9;

  useFrame((_state, delta) => {
    if (group.current && animate) group.current.rotation.y += delta * 0.14;
  });

  return (
    <group position={position} ref={group}>
      {Array.from({ length: plates }, (_, i) => {
        const lit = i / plates <= fill;
        return (
          <mesh key={i} position={[0, i * 0.19 - 0.8, 0]}>
            <cylinderGeometry args={[0.78 - i * 0.03, 0.78 - i * 0.03, 0.08, 6]} />
            <meshStandardMaterial
              color={lit ? QSR.broken : '#16203a'}
              emissive={lit ? QSR.broken : '#0a1120'}
              emissiveIntensity={lit ? (active ? 1.1 : 0.5) : 0.05}
              roughness={0.5}
              metalness={0.4}
              transparent
              opacity={0.92}
            />
          </mesh>
        );
      })}
    </group>
  );
}

/* ═══════════════════════════════════════════════════════════════ shield */

/** The post-quantum dome that closes over the target at the migration stage. */
function ShieldDome({ position, strength, animate }: { position: THREE.Vector3; strength: number; animate: boolean }) {
  const mesh = React.useRef<THREE.Mesh>(null);
  const inner = React.useRef<THREE.Mesh>(null);

  useFrame((state, delta) => {
    if (mesh.current && animate) mesh.current.rotation.y += delta * 0.3;
    if (inner.current && animate) {
      inner.current.rotation.y -= delta * 0.42;
      const breathe = 1 + Math.sin(state.clock.elapsedTime * 1.7) * 0.02;
      inner.current.scale.setScalar(breathe);
    }
  });

  if (strength <= 0.01) return null;

  return (
    <group position={position}>
      <mesh ref={mesh}>
        <icosahedronGeometry args={[1.75, 2]} />
        <meshBasicMaterial color={QSR.quantum} wireframe transparent opacity={0.34 * strength} />
      </mesh>
      <mesh ref={inner} scale={0.96}>
        <sphereGeometry args={[1.75, 32, 32]} />
        <meshStandardMaterial
          color={QSR.quantum}
          emissive={QSR.quantum}
          emissiveIntensity={0.7 * strength}
          transparent
          opacity={0.1 * strength}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

/* ═══════════════════════════════════════════════════════════════ the scene */

function StageScene(props: Omit<QuantumStage3DProps, 'dpr' | 'onReady'>) {
  const { stage, progress, sites, distribution, qubits, resolved, quantumSafe, budget } = props;
  const animate = budget.animate;

  // How lit each part of the board is at this stage.
  const wireLive = stage >= 1 ? 1 : 0;
  const tapLive = stage >= 1;
  const archiveFill = stage <= 1 ? progress * 0.2 : Math.min(1, 0.2 + (stage - 1) * 0.25);
  const coreSpin = stage < 3 ? 0 : stage === 3 ? 0.35 + progress * 0.65 : 1;
  const recovered = stage >= 4;
  const exposed = stage === 5;
  const shielded = stage >= 6 ? 1 : 0;

  const linkAccent = quantumSafe || stage >= 6 ? QSR.quantum : exposed || recovered ? QSR.broken : QSR.live;
  const packetBudget = Math.max(4, Math.round(budget.maxPackets / 6));

  return (
    <>
      <ambientLight intensity={0.5} />
      <pointLight position={[0, 6, 8]} intensity={90} distance={40} color="#7dd3fc" />
      <pointLight position={[6, -2, 4]} intensity={45} distance={30} color={recovered ? QSR.broken : QSR.quantum} />

      <StageRig stage={stage} animate={animate} />
      {budget.dust && <LatticeField count={budget.dustCount * 6} animate={animate} />}

      {/* The protected link. This is the thing being attacked. */}
      <DataConduit
        from={SITE_POSITIONS.client}
        to={SITE_POSITIONS.server}
        bow={new THREE.Vector3(0, 1.5, 0)}
        accent={linkAccent}
        flow={0.14 + progress * 0.1}
        intensity={wireLive * (0.5 + progress * 0.4)}
        packets={packetBudget}
        animate={animate}
      />

      {/* The tap: a passive mirror off the main link. */}
      <DataConduit
        from={SITE_POSITIONS.transit}
        to={SITE_POSITIONS.archive}
        bow={new THREE.Vector3(-0.6, 0.2, 0)}
        accent={QSR.broken}
        flow={0.22}
        intensity={tapLive ? 0.7 : 0.1}
        packets={tapLive ? packetBudget : 0}
        animate={animate}
      />

      {/* Archive feeding the quantum computer. Only once a CRQC exists. */}
      <DataConduit
        from={SITE_POSITIONS.archive}
        to={SITE_POSITIONS.crqc}
        bow={new THREE.Vector3(0.8, 1.4, 0)}
        accent={QSR.quantum}
        flow={0.3}
        intensity={stage >= 3 ? 0.8 : 0.04}
        packets={stage >= 3 ? packetBudget : 0}
        animate={animate}
        dashed
      />

      {/* Recovered keys reaching the target. Blocked once the shield is up. */}
      <DataConduit
        from={SITE_POSITIONS.crqc}
        to={SITE_POSITIONS.server}
        bow={new THREE.Vector3(0.4, 0.6, 0)}
        accent={shielded ? QSR.safe : QSR.broken}
        flow={0.36}
        intensity={recovered && !shielded ? 0.95 : 0.05}
        packets={recovered && !shielded ? packetBudget : 0}
        animate={animate}
        dashed
      />

      <SiteNode position={SITE_POSITIONS.client} label={sites.client} sublabel="Initiator" accent={QSR.live} active={stage === 1} compromised={false} animate={animate} />
      <SiteNode position={SITE_POSITIONS.transit} label={sites.transit} sublabel="Passive tap" accent={QSR.broken} active={stage <= 2} compromised animate={animate} shape="cylinder" />
      <SiteNode
        position={SITE_POSITIONS.server}
        label={sites.server}
        sublabel={shielded ? 'ML-KEM protected' : recovered ? 'Keys recovered' : 'Responder'}
        accent={shielded ? QSR.quantum : QSR.live}
        active={stage >= 4}
        compromised={recovered && !shielded}
        animate={animate}
        shape="box"
      />

      <ArchiveSilo position={SITE_POSITIONS.archive} fill={archiveFill} active={stage >= 2} animate={animate} />
      <Html center distanceFactor={11} position={[SITE_POSITIONS.archive.x, SITE_POSITIONS.archive.y - 1.5, SITE_POSITIONS.archive.z]} style={{ pointerEvents: 'none' }}>
        <div style={{ textAlign: 'center', whiteSpace: 'nowrap', fontFamily: '"JetBrains Mono", monospace' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0', textShadow: '0 2px 12px rgba(0,0,0,0.95)' }}>{sites.archive}</div>
          <div style={{ fontSize: 9, letterSpacing: '0.18em', textTransform: 'uppercase', color: QSR.broken, marginTop: 2 }}>Ciphertext archive</div>
        </div>
      </Html>

      <QuantumCore
        position={SITE_POSITIONS.crqc}
        active={stage >= 3}
        spinUp={coreSpin}
        distribution={distribution}
        qubits={qubits}
        resolved={resolved}
        animate={animate}
      />
      <Html center distanceFactor={11} position={[SITE_POSITIONS.crqc.x, SITE_POSITIONS.crqc.y + 1.5, SITE_POSITIONS.crqc.z]} style={{ pointerEvents: 'none' }}>
        <div style={{ textAlign: 'center', whiteSpace: 'nowrap', fontFamily: '"JetBrains Mono", monospace' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0', textShadow: '0 2px 12px rgba(0,0,0,0.95)' }}>{sites.crqc}</div>
          <div style={{ fontSize: 9, letterSpacing: '0.18em', textTransform: 'uppercase', color: resolved ? QSR.quantum : QSR.live, marginTop: 2 }}>
            {distribution ? `${qubits} qubits · live register` : 'Awaiting register'}
          </div>
        </div>
      </Html>

      <ShieldDome position={SITE_POSITIONS.server} strength={shielded} animate={animate} />

      {budget.postFx && (
        <EffectComposer multisampling={0}>
          <Bloom intensity={1.15} luminanceThreshold={0.22} luminanceSmoothing={0.5} kernelSize={KernelSize.LARGE} mipmapBlur />
          <Vignette offset={0.28} darkness={0.7} blendFunction={BlendFunction.NORMAL} />
        </EffectComposer>
      )}
    </>
  );
}

export default function QuantumStage3D(props: QuantumStage3DProps) {
  const { dpr, onReady, ...scene } = props;
  return (
    <Canvas
      dpr={dpr}
      onCreated={() => onReady?.()}
      gl={{ antialias: false, alpha: true, powerPreference: 'high-performance' }}
      camera={{ fov: 46, position: CAMERA_RIG[0].position, near: 0.1, far: 80 }}
      style={{ width: '100%', height: '100%' }}
      /* The stage restates what the evidence panels below already say in text;
         screen readers get the panels. */
      aria-hidden
      frameloop={scene.budget.animate ? 'always' : 'demand'}
    >
      <StageScene {...scene} />
    </Canvas>
  );
}
