import { ThreeCanvas } from '@remotion/three';
import { useEffect, useMemo } from 'react';
import {
  AdditiveBlending,
  BufferAttribute,
  BufferGeometry,
  Color,
  type Vector3Tuple,
} from 'three';

type QuantumCoreProps = {
  width: number;
  height: number;
  frame: number;
  fps: number;
  centerY?: number;
};

const TAU = 2 * Math.PI;
const CAMERA_Z = 10;
const CAMERA_FOV = 38;
const FILAMENTS = 22;
const STEPS = 240;
const SPARKS = 2600;
const ICE = new Color('#74deff');
const VIOLET = new Color('#a17bff');
const CAM_WORLD_HEIGHT = 2 * CAMERA_Z * Math.tan((CAMERA_FOV * Math.PI) / 360);

const lightVertex = `
  attribute float aPhase;
  attribute float aHeat;
  uniform float uTime;
  uniform float uPixelScale;
  varying float vPhase;
  varying float vHeat;

  void main() {
    vec3 p = position;
    float ripple = sin(4.0 * aPhase - 1.4 * uTime + 3.0 * aHeat);
    p.z += 0.075 * ripple;
    p.xy *= 1.0 + 0.018 * ripple;
    vec4 view = modelViewMatrix * vec4(p, 1.0);
    gl_Position = projectionMatrix * view;
    gl_PointSize = max(1.2, uPixelScale * (1.0 + 4.0 * aHeat) * 9.0 / -view.z);
    vPhase = aPhase;
    vHeat = aHeat;
  }
`;

const lightFragment = `
  uniform vec3 uIce;
  uniform vec3 uViolet;
  uniform float uTime;
  uniform float uGain;
  varying float vPhase;
  varying float vHeat;

  void main() {
    float split = 0.5 + 0.5 * sin(vPhase + 3.4 * vHeat - uTime * 0.12);
    float pulse = 0.5 + 0.5 * sin(4.0 * vPhase - uTime * 2.2 + 9.0 * vHeat);
    float alpha = (0.04 + 0.39 * pow(pulse, 4.0)) * uGain;
    vec3 light = mix(uViolet, uIce, smoothstep(0.16, 0.84, split));
    #ifdef PARTICLES
      vec2 point = gl_PointCoord - 0.5;
      float radius = dot(point, point);
      float spot = exp(-18.0 * radius) * (1.0 - smoothstep(0.12, 0.25, radius));
      alpha = alpha * spot * (0.5 + 0.5 * smoothstep(0.27, 0.94, vHeat));
      light = mix(light, vec3(0.85, 0.96, 1.0), 0.34 * vHeat);
    #endif
    gl_FragColor = vec4(light, alpha);
    #include <colorspace_fragment>
  }
`;

function smoothstep(from: number, to: number, value: number) {
  const progress = Math.max(0, Math.min(1, (value - from) / (to - from)));
  return progress * progress * (3 - 2 * progress);
}

function seededRandom(initialSeed: number) {
  let seed = initialSeed;
  return () => {
    seed = (Math.imul(1664525, seed) + 1013904223) >>> 0;
    return seed / 0x100000000;
  };
}

function torusPoint(angle: number, phase: number, radius: number, tube: number): Vector3Tuple {
  const rim = radius + tube * Math.cos(phase);
  return [rim * Math.cos(angle), rim * Math.sin(angle), tube * Math.sin(phase)];
}

function createField() {
  const random = seededRandom(743109);
  const filaments: number[] = [];
  const filamentPhases: number[] = [];
  const filamentHeat: number[] = [];
  const sparks: number[] = [];
  const sparkPhases: number[] = [];
  const sparkHeat: number[] = [];

  for (let index = 0; index < FILAMENTS; index++) {
    const phaseOffset = TAU * index / FILAMENTS;
    const radius = 1.47 + 0.33 * random();
    const tube = 0.10 + 0.28 * random();
    const heat = random();
    const length = TAU * (0.62 + 0.31 * random());
    const start = TAU * random();
    for (let step = 0; step < STEPS; step++) {
      for (const end of [step, step + 1]) {
        const angle = start + length * end / STEPS;
        const twist = 3 * angle + phaseOffset + 0.44 * Math.sin(5 * angle + phaseOffset);
        filaments.push(...torusPoint(angle, twist, radius, tube));
        filamentPhases.push(angle);
        filamentHeat.push(heat);
      }
    }
  }

  for (let index = 0; index < SPARKS; index++) {
    const angle = TAU * random();
    const phase = TAU * random();
    const radius = 1.48 + 0.75 * random() ** 2;
    const tube = 0.10 + 0.56 * random() ** 2;
    sparks.push(...torusPoint(angle, phase, radius, tube));
    sparkPhases.push(angle);
    sparkHeat.push(random() ** 2);
  }

  const boundaries: number[] = [];
  for (const radius of [2.23, 2.39, 2.71]) {
    for (let step = 0; step < STEPS; step++) {
      if (step % 31 < 3) continue;
      const angle = TAU * step / STEPS;
      const nextAngle = TAU * (step + 1) / STEPS;
      boundaries.push(...torusPoint(angle, 0, radius, 0), ...torusPoint(nextAngle, 0, radius, 0));
    }
  }
  for (let step = 0; step < 96; step++) {
    const angle = TAU * step / 96;
    const tick = step % 8 === 0 ? 0.082 : 0.033;
    boundaries.push(...torusPoint(angle, 0, 2.39, 0), ...torusPoint(angle, 0, 2.39 + tick, 0));
  }

  function buffer(positions: number[], phases?: number[], heat?: number[]) {
    const geometry = new BufferGeometry();
    geometry.setAttribute('position', new BufferAttribute(new Float32Array(positions), 3));
    if (phases) geometry.setAttribute('aPhase', new BufferAttribute(new Float32Array(phases), 1));
    if (heat) geometry.setAttribute('aHeat', new BufferAttribute(new Float32Array(heat), 1));
    return geometry;
  }

  return {
    filaments: buffer(filaments, filamentPhases, filamentHeat),
    sparks: buffer(sparks, sparkPhases, sparkHeat),
    boundaries: buffer(boundaries),
  };
}

function EnergyField({ time, gain, vertical, centerY, pixelScale }: {
  time: number;
  gain: number;
  vertical: boolean;
  centerY: number;
  pixelScale: number;
}) {
  const field = useMemo(createField, []);
  useEffect(() => () => {
    for (const geometry of Object.values(field)) geometry.dispose();
  }, [field]);

  const settled = smoothstep(0.2, 3.5, time);
  const roll = -0.33 + 0.16 * settled;
  const pitch = 0.85 - 0.52 * settled + 0.045 * Math.sin(time * 0.58);
  const scale = (vertical ? 0.65 : 0.95) * (1.15 - 0.15 * settled);
  const uniforms = {
    uIce: { value: ICE },
    uViolet: { value: VIOLET },
    uTime: { value: time },
    uGain: { value: gain },
    uPixelScale: { value: pixelScale },
  };

  return (
    <group position={[0, (0.5 - centerY) * CAM_WORLD_HEIGHT, 0]} scale={scale}>
      <group rotation={[pitch + 0.08, 0.14, roll]}>
        <lineSegments geometry={field.boundaries}>
          <lineBasicMaterial
            color="#7190ec"
            opacity={gain * 0.21}
            transparent
            blending={AdditiveBlending}
            depthWrite={false}
            toneMapped={false}
          />
        </lineSegments>
      </group>
      <group rotation={[pitch, -0.16 + 0.21 * settled, roll + time * 0.037]}>
        <lineSegments geometry={field.filaments}>
          <shaderMaterial
            vertexShader={lightVertex}
            fragmentShader={lightFragment}
            uniforms={uniforms}
            transparent
            blending={AdditiveBlending}
            depthWrite={false}
          />
        </lineSegments>
        <points geometry={field.sparks}>
          <shaderMaterial
            vertexShader={lightVertex}
            fragmentShader={lightFragment}
            uniforms={uniforms}
            defines={{ PARTICLES: 1 }}
            transparent
            blending={AdditiveBlending}
            depthWrite={false}
          />
        </points>
      </group>
    </group>
  );
}

export function QuantumCore({ width, height, frame, fps, centerY = 0.45 }: QuantumCoreProps) {
  const time = frame / fps;
  const vertical = height > width;
  const ignition = smoothstep(0, 0.85, time);
  const ember = 1 - smoothstep(2.1, 4.9, time);
  const gain = ignition * (0.42 + 0.60 * ember);
  const lensWidth = vertical ? 48 : 30;
  const lensHeight = vertical ? 25 : 47;
  const gradientCenter = `50% ${centerY * 100}%`;
  const pixelScale = Math.min(width, height) / 1080;
  const backdrop = (
    <div style={{
      position: 'absolute',
      inset: 0,
      background: `radial-gradient(ellipse ${lensWidth}% ${lensHeight}% at ${gradientCenter}, #233b72, #111836 43%, #090d24 65%, #040713 100%)`,
    }} />
  );

  return (
    <div aria-hidden style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}>
      {backdrop}
      <div style={{
        position: 'absolute',
        inset: 0,
        opacity: ignition * (0.33 + 0.53 * ember),
        background: [
          `radial-gradient(ellipse 1.9% 3.8% at ${gradientCenter}, #eefaff 4%, #7fdbff 25%, #4986ea30 75%, #4986ea00)`,
          `radial-gradient(ellipse 36% 0.275% at ${gradientCenter}, #a1c8ff, #7fa7ff65 27%, #456dda0c 90%, #456dda00)`,
          `radial-gradient(ellipse 11% 17% at ${gradientCenter}, #8577f67a, #6659d904 80%, #6659d900)`,
        ].join(','),
      }} />
      <ThreeCanvas
        width={width}
        height={height}
        dpr={width >= 3000 ? 0.65 : 1}
        gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
        camera={{ fov: CAMERA_FOV, position: [0, 0, CAMERA_Z], near: 0.1, far: 30 }}
        style={{ position: 'absolute', top: 0, left: 0 }}
        fallback={<div />}
      >
        <EnergyField time={time} gain={gain} vertical={vertical} centerY={centerY} pixelScale={pixelScale} />
      </ThreeCanvas>
    </div>
  );
}
