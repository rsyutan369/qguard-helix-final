import { ThreeCanvas } from '@remotion/three';
import { useEffect, useMemo } from 'react';
import {
  AdditiveBlending,
  BufferAttribute,
  BufferGeometry,
  Color,
  ExtrudeGeometry,
  Shape,
  type Vector3Tuple,
} from 'three';

type SpatialVariant = 'processor' | 'network' | 'finale';

type SpatialProps = {
  variant: SpatialVariant;
  width: number;
  height: number;
  frame: number;
  fps: number;
  centerX?: number;
  centerY?: number;
  scale?: number;
};

const TAU = Math.PI * 2;
const FOV = 38;
const CAMERA_Z = 9.8;
const WORLD_HEIGHT = 2 * CAMERA_Z * Math.tan(FOV * Math.PI / 360);
const ICE = new Color('#69d9ff');
const VIOLET = new Color('#ad8cff');

const vertex = `
  attribute float phase;
  attribute float strength;
  uniform float time;
  uniform float scalePx;
  varying float vPhase;
  varying float vStrength;

  void main() {
    vec3 p = position;
    float wave = sin(phase * 3.0 + time * 0.9);
    #ifdef FINALE
      p.xy *= 1.0 + wave * 0.017;
      p.z += 0.07 * wave;
    #endif
    vec4 view = modelViewMatrix * vec4(p, 1.0);
    gl_Position = projectionMatrix * view;
    gl_PointSize = max(1.5, scalePx * (2.1 + 5.9 * strength) * 8.0 / -view.z);
    vPhase = phase;
    vStrength = strength;
  }
`;

const fragment = `
  uniform vec3 ice;
  uniform vec3 violet;
  uniform float time;
  uniform float gain;
  varying float vPhase;
  varying float vStrength;

  void main() {
    float swept = sin(4.4 * vPhase - time * 1.74);
    float pulse = pow(0.5 + 0.5 * swept, 4.0);
    vec3 light = mix(ice, violet, smoothstep(-0.35, 0.6, sin(vPhase + 3.2 * vStrength)));
    float alpha = gain * (0.13 + pulse * 0.38) * (0.49 + vStrength * 0.51);
    #ifdef SPARKS
      vec2 offset = (gl_PointCoord - 0.5) * 2.0;
      float radius = length(offset);
      alpha *= exp(-2.9 * radius * radius) * (1.0 - smoothstep(0.60, 1.0, radius));
      alpha *= 1.5;
      light = mix(light, vec3(0.78, 0.93, 1.0), 0.4 * vStrength);
    #endif
    gl_FragColor = vec4(light, alpha);
    #include <colorspace_fragment>
  }
`;

const sparkDefines = { SPARKS: 1 };
const finalDefines = { FINALE: 1 };
const finalSparkDefines = { FINALE: 1, SPARKS: 1 };

function ease(start: number, end: number, value: number) {
  const x = Math.min(1, Math.max(0, (value - start) / (end - start)));
  return x * x * (3 - 2 * x);
}

function randomSeed(seed: number) {
  return () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
}

function geometry(positions: number[], phases?: number[], strengths?: number[]) {
  const result = new BufferGeometry();
  result.setAttribute('position', new BufferAttribute(new Float32Array(positions), 3));
  if (phases && strengths) {
    result.setAttribute('phase', new BufferAttribute(new Float32Array(phases), 1));
    result.setAttribute('strength', new BufferAttribute(new Float32Array(strengths), 1));
  }
  return result;
}

function loopPoint(angle: number, radius: number, z = 0): Vector3Tuple {
  return [radius * Math.cos(angle), radius * Math.sin(angle), z];
}

function orbit(radii: number[], tickLength = 0) {
  const points: number[] = [];
  for (const radius of radii) {
    for (let i = 0; i < 160; i++) {
      if (i % 40 > 36) continue;
      points.push(...loopPoint(TAU * i / 160, radius), ...loopPoint(TAU * (i + 1) / 160, radius));
    }
  }
  if (tickLength > 0) {
    const radius = radii[0];
    for (let i = 0; i < 80; i++) {
      const angle = TAU * i / 80;
      points.push(...loopPoint(angle, radius), ...loopPoint(angle, radius + (i % 10 ? 0.5 : 1) * tickLength));
    }
  }
  return geometry(points);
}

function processorGeometry() {
  const corner = 0.18;
  const size = 1.62;
  const shape = new Shape();
  shape.moveTo(-size + corner, -size);
  shape.lineTo(size - corner, -size);
  shape.lineTo(size, -size + corner);
  shape.lineTo(size, size - corner);
  shape.lineTo(size - corner, size);
  shape.lineTo(-size + corner, size);
  shape.lineTo(-size, size - corner);
  shape.lineTo(-size, -size + corner);
  shape.closePath();
  const slab = new ExtrudeGeometry(shape, { depth: 0.14, bevelEnabled: true, bevelThickness: 0.037, bevelSize: 0.031, bevelSegments: 1 });
  slab.rotateX(-Math.PI / 2);

  const traces: number[] = [];
  for (let side = 0; side < 4; side++) {
    const cos = Math.cos(side * Math.PI / 2);
    const sin = Math.sin(side * Math.PI / 2);
    const add = (x: number, z: number) => traces.push(x * cos - z * sin, 0.189, x * sin + z * cos);
    for (let i = 0; i < 20; i++) {
      const x = (i - 9.5) * 0.141;
      const inner = Math.sign(x) * (0.40 + Math.abs(x) * 0.49);
      add(x, 1.605); add(x, 1.08 - i % 3 * 0.08);
      add(x, 1.08 - i % 3 * 0.08); add(inner, 0.88 - i % 3 * 0.08);
      add(inner, 0.88 - i % 3 * 0.08); add(inner, 0.68);
    }
  }
  return { slab, traces: geometry(traces), rims: orbit([2.54, 2.74], 0.055) };
}

function Processor({ time }: { time: number }) {
  const model = useMemo(processorGeometry, []);
  useEffect(() => () => Object.values(model).forEach((item) => item.dispose()), [model]);
  const opened = ease(0.15, 2.7, time);
  const spacing = 0.095 + opened * 0.32;
  const pulse = 0.68 + 0.25 * Math.sin(time * 1.4);

  return (
    <>
      <ambientLight intensity={1.18} color="#9cb7e9" />
      <directionalLight position={[1.4, 4, 6]} intensity={4.1} color="#c1eaff" />
      <directionalLight position={[-5, -0.4, 4]} intensity={1.95} color="#8476ff" />
      <group rotation={[0.10, 0.55 + time * 0.12, -0.25 + opened * 0.11]}>
        {[0, 1, 2, 3, 4, 5, 6].map((index) => {
          const accent = index % 2 === 1;
          return (
            <group key={index} position={[0, (index - 3.5) * spacing, 0]} scale={1 - index * 0.064}>
              <mesh geometry={model.slab}>
                <meshStandardMaterial color={accent ? '#24446b' : '#1c273b'} metalness={0.66} roughness={0.31} emissive={accent ? '#133561' : '#030817'} emissiveIntensity={pulse} />
              </mesh>
              <lineSegments geometry={model.traces}>
                <lineBasicMaterial color={accent ? '#7cddff' : '#a398ff'} transparent opacity={accent ? 0.85 : 0.40} blending={AdditiveBlending} depthWrite={false} toneMapped={false} />
              </lineSegments>
            </group>
          );
        })}
        <mesh position={[0, 3.5 * spacing + 0.18, 0]}>
          <boxGeometry args={[0.80, 0.16, 0.80]} />
          <meshStandardMaterial color="#a4ddfb" metalness={0.32} roughness={0.25} emissive="#277cce" emissiveIntensity={0.67 + pulse * 0.55} />
        </mesh>
      </group>
      <lineSegments geometry={model.rims} position={[0, -1.32, 0]} rotation={[-Math.PI * 0.39, -0.11, time * 0.05]}>
        <lineBasicMaterial color="#64b3fc" transparent opacity={0.37} depthWrite={false} toneMapped={false} />
      </lineSegments>
    </>
  );
}

function networkGeometry() {
  const random = randomSeed(148693);
  const world: Vector3Tuple[] = [];
  const nodePhases: number[] = [];
  const nodeStrengths: number[] = [];
  const edges: number[] = [];
  const edgePhases: number[] = [];
  const edgeStrengths: number[] = [];
  for (let index = 0; index < 155; index++) {
    const height = 1 - 2 * (index + 0.5) / 155;
    const azimuth = index * Math.PI * (3 - Math.sqrt(5)) + random() * 0.10;
    const disk = Math.sqrt(1 - height * height);
    const radius = 1.86 + random() * 0.39;
    world.push([radius * disk * Math.cos(azimuth), radius * height, radius * disk * Math.sin(azimuth)]);
    nodePhases.push(azimuth % TAU);
    nodeStrengths.push(random() ** 0.6);
  }
  for (let idx = 0; idx < world.length; idx++) {
    const origin = world[idx];
    for (let next = idx + 1; next < world.length; next++) {
      const destination = world[next];
      const distance = Math.hypot(origin[0] - destination[0], origin[1] - destination[1], origin[2] - destination[2]);
      if (distance > 0.86 || random() < 0.20) continue;
      edges.push(...origin, ...destination);
      edgePhases.push(nodePhases[idx], nodePhases[next]);
      edgeStrengths.push(nodeStrengths[idx] * 0.7, nodeStrengths[next] * 0.7);
    }
  }
  return {
    dots: geometry(world.flat(), nodePhases, nodeStrengths),
    edges: geometry(edges, edgePhases, edgeStrengths),
    rims: orbit([2.54, 2.73], 0.063),
  };
}

function finaleGeometry() {
  const random = randomSeed(627129);
  const points: number[] = [];
  const phases: number[] = [];
  const strengths: number[] = [];
  const rays: number[] = [];
  const rayPhases: number[] = [];
  const rayStrengths: number[] = [];
  const path = (angle: number, offset: number, radius: number, tube: number) => {
    const twist = 4.0 * angle + offset;
    return loopPoint(angle, radius + tube * Math.cos(twist), tube * Math.sin(twist));
  };

  for (let strand = 0; strand < 31; strand++) {
    const radius = 1.95 + random() * 0.45;
    const offset = random() * TAU;
    const begin = random() * TAU;
    const length = (0.58 + random() * 0.37) * TAU;
    const tube = 0.065 + random() * 0.36;
    const weight = 0.44 + random() * 0.56;
    for (let step = 0; step < 134; step++) {
      const from = begin + length * step / 134;
      const to = begin + length * (step + 1) / 134;
      rays.push(...path(from, offset, radius, tube), ...path(to, offset, radius, tube));
      rayPhases.push(from, to);
      rayStrengths.push(weight, weight);
    }
  }
  for (let index = 0; index < 1250; index++) {
    const angle = random() * TAU;
    points.push(...loopPoint(angle, 1.85 + random() ** 1.66 * 1.45, (random() - 0.5) * 1.11));
    phases.push(angle);
    strengths.push(random() ** 1.7);
  }
  return {
    dots: geometry(points, phases, strengths),
    edges: geometry(rays, rayPhases, rayStrengths),
    rims: orbit([2.78, 2.94, 3.18], 0.085),
  };
}

function Field({ time, flare, scalePx }: { time: number; flare: boolean; scalePx: number }) {
  const field = useMemo(flare ? finaleGeometry : networkGeometry, [flare]);
  useEffect(() => () => Object.values(field).forEach((item) => item.dispose()), [field]);
  const rise = ease(0, flare ? 1.25 : 1.75, time);
  const halo = flare ? 1 + 0.58 * (1 - ease(1.3, 4.7, time)) : 0.92;
  const shaderProps = {
    vertexShader: vertex,
    fragmentShader: fragment,
    uniforms: {
      ice: { value: ICE },
      violet: { value: VIOLET },
      time: { value: time },
      gain: { value: rise * halo },
      scalePx: { value: scalePx },
    },
    transparent: true,
    depthWrite: false,
    blending: AdditiveBlending,
  };
  const flow = flare ? time * 0.089 : time * 0.24;
  const tilt = flare ? 0.49 - 0.38 * ease(0.40, 3.2, time) : -0.30;

  return (
    <>
      <lineSegments geometry={field.rims} rotation={[tilt + 0.42, -0.30, -0.20 - flow * 0.21]}>
        <lineBasicMaterial color={flare ? '#947aff' : '#78bbef'} transparent opacity={rise * (flare ? 0.41 : 0.33)} depthWrite={false} blending={AdditiveBlending} toneMapped={false} />
      </lineSegments>
      <group rotation={[tilt, flare ? 0.11 : flow, flare ? flow - 0.36 : 0.24]}>
        <lineSegments geometry={field.edges}>
          <shaderMaterial {...shaderProps} defines={flare ? finalDefines : undefined} />
        </lineSegments>
        <points geometry={field.dots}>
          <shaderMaterial {...shaderProps} defines={flare ? finalSparkDefines : sparkDefines} />
        </points>
      </group>
    </>
  );
}

export function Spatial({
  variant, width, height, frame, fps,
  centerX = variant === 'finale' ? 0.5 : 0.70,
  centerY = variant === 'finale' ? 0.48 : 0.49,
  scale = 1,
}: SpatialProps) {
  const time = frame / fps;
  const internalWidth = Math.min(1040, Math.round(width * 0.54));
  const internalHeight = Math.round(internalWidth * height / width);
  const aspect = width / height;
  const rise = ease(0, 0.85, time);
  const intensity = variant === 'finale' ? 0.91 - 0.29 * ease(1.5, 4.7, time) : 0.70;
  const size = scale * (aspect < 1 ? 0.70 : 1) * (0.9 + 0.10 * ease(0, 3.25, time));
  const center = `${centerX * 100}% ${centerY * 100}%`;
  const lens = variant === 'finale'
    ? `radial-gradient(ellipse 4% 6% at ${center}, #f1f4ff59 0%, #9addff3f 27%, transparent 100%), radial-gradient(ellipse 25% 40% at ${center}, #367bf761, #5943e73b 57%, transparent 100%)`
    : `radial-gradient(ellipse 25% 37% at ${center}, #4e90e94a 0%, #443da735 49%, transparent 100%)`;

  return (
    <div aria-hidden style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}>
      <div style={{ position: 'absolute', inset: 0, background: lens, opacity: rise * intensity }} />
      <ThreeCanvas
        width={internalWidth}
        height={internalHeight}
        dpr={1}
        gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
        camera={{ fov: FOV, position: [0, 0, CAMERA_Z], near: 0.1, far: 30 }}
        style={{ position: 'absolute', top: 0, left: 0, transformOrigin: '0 0', transform: `scale(${width / internalWidth}, ${height / internalHeight})`, opacity: rise }}
        fallback={<div />}
      >
        <group position={[(centerX - 0.5) * WORLD_HEIGHT * aspect, (0.5 - centerY) * WORLD_HEIGHT, 0]} scale={size}>
          {variant === 'processor'
            ? <Processor time={time} />
            : <Field time={time} flare={variant === 'finale'} scalePx={internalHeight / 620} />}
        </group>
      </ThreeCanvas>
    </div>
  );
}
