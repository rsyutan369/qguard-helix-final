'use client';

/**
 * QKMS motion layer.
 *
 * Every animation here is bound to a real state, never to the passage of time
 * alone:
 *   - sections reveal once, on first paint, and stay still on every live push;
 *   - the gate field takes its colour from the gate decision and MOVES ONLY
 *     WHILE THE STREAM IS LIVE — a frozen field is the disconnected state, so
 *     motion can never imply activity the page is not receiving;
 *   - gauges and bars animate to the measured value and render nothing for a
 *     value that was not measured.
 * `prefers-reduced-motion` disables all of it.
 */

import { Children, useEffect, useRef, type ReactNode } from 'react';
import { MotionConfig, motion, useReducedMotion } from 'framer-motion';
import { TONE, type Tone } from '../observability/primitives';

const EASE = [0.22, 1, 0.36, 1] as const;

/* ------------------------------------------------------------------ */
/* Section reveal                                                      */
/* ------------------------------------------------------------------ */

export function QkmsReveal({ children }: { children: ReactNode }) {
  const items = Children.toArray(children);
  return (
    <MotionConfig reducedMotion="user">
      <motion.div
        className="space-y-4"
        initial="hidden"
        animate="shown"
        variants={{ hidden: {}, shown: { transition: { staggerChildren: 0.055, delayChildren: 0.02 } } }}
      >
        {items.map((child, index) => (
          <motion.div
            // Children.toArray assigns stable keys, so a live push never re-mounts a section.
            key={(child as { key?: string | null }).key ?? index}
            variants={{
              // Opacity and translate only: a lingering filter or transform would become the
              // containing block for the fixed-position key drawer rendered inside a section.
              hidden: { opacity: 0, y: 14 },
              shown: { opacity: 1, y: 0, transition: { duration: 0.5, ease: EASE } },
            }}
          >
            {child}
          </motion.div>
        ))}
      </motion.div>
    </MotionConfig>
  );
}

/* ------------------------------------------------------------------ */
/* Measured gauge                                                      */
/* ------------------------------------------------------------------ */

/** A radial gauge for a measured percentage; `null` renders as "not evaluated". */
export function MeasuredGauge({ value, tone, label, size = 92 }: { value: number | null; tone: Tone; label: string; size?: number }) {
  const reduce = useReducedMotion();
  const stroke = 7;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const fraction = value === null ? 0 : Math.max(0, Math.min(100, value)) / 100;
  return (
    <figure className="relative shrink-0" style={{ width: size, height: size }} aria-label={`${label}: ${value === null ? 'not evaluated' : `${value}%`}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-white/10" />
        {value !== null ? (
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={TONE[tone].hex}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={reduce ? false : { strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference * (1 - fraction) }}
            transition={{ duration: reduce ? 0 : 1.1, ease: EASE }}
            style={{ filter: `drop-shadow(0 0 6px ${TONE[tone].hex}66)` }}
          />
        ) : null}
      </svg>
      <figcaption className="absolute inset-0 grid place-items-center text-center">
        <span>
          <span className={`block font-mono text-[19px] font-black leading-none tabular-nums ${value === null ? 'text-white/35' : TONE[tone].text}`}>
            {value === null ? '—' : `${value}%`}
          </span>
          <span className="mt-1 block text-[8px] font-black uppercase tracking-[0.14em] text-white/40">{label}</span>
        </span>
      </figcaption>
    </figure>
  );
}

/** A horizontal bar that grows to a measured percentage on first paint. */
export function MeasuredBar({ percent, tone }: { percent: number; tone: Tone }) {
  const reduce = useReducedMotion();
  const width = `${Math.max(2, Math.min(100, percent))}%`;
  return (
    <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
      <motion.span
        className="block h-full rounded-full"
        style={{ backgroundColor: TONE[tone].hex, boxShadow: `0 0 10px ${TONE[tone].hex}55` }}
        initial={reduce ? false : { width: '0%' }}
        animate={{ width }}
        transition={{ duration: reduce ? 0 : 0.9, ease: EASE }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Gate field — WebGL                                                  */
/* ------------------------------------------------------------------ */

const VERTEX = `
attribute vec2 p;
void main() { gl_Position = vec4(p, 0.0, 1.0); }
`;

/* A lattice of interference bands — a nod to lattice-based ML-KEM / ML-DSA —
   tinted by the gate decision. `u_time` only advances while the stream is live. */
const FRAGMENT = `
precision mediump float;
uniform vec2 u_res;
uniform float u_time;
uniform vec3 u_tint;
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p); vec2 f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x), mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
}
void main() {
  vec2 uv = gl_FragCoord.xy / u_res.xy;
  vec2 q = vec2(uv.x * u_res.x / u_res.y, uv.y) * 6.0;
  float t = u_time * 0.12;
  float field = noise(q + vec2(t, -t * 0.6)) * 0.6 + noise(q * 2.1 - vec2(t * 0.8, t)) * 0.4;
  vec2 g = abs(fract(q + field * 0.35) - 0.5);
  float lattice = smoothstep(0.47, 0.5, max(g.x, g.y));
  float nodes = smoothstep(0.09, 0.0, length(g - 0.5)) * 0.9;
  float glow = smoothstep(1.15, 0.0, length(uv - vec2(0.18, 0.5)));
  float intensity = (lattice * 0.22 + nodes * 0.35) * (0.35 + field) + glow * 0.16;
  float fade = smoothstep(1.0, 0.25, uv.x);
  gl_FragColor = vec4(u_tint * intensity * fade, intensity * fade);
}
`;

function hexToRgb(hex: string): [number, number, number] {
  const value = parseInt(hex.replace('#', ''), 16);
  return [((value >> 16) & 255) / 255, ((value >> 8) & 255) / 255, (value & 255) / 255];
}

/**
 * Decorative only (aria-hidden) and strictly behind content. If WebGL is
 * unavailable the canvas stays empty and the panel renders exactly as before.
 */
export function GateField({ tone, live }: { tone: Tone; live: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const liveRef = useRef(live);
  const tintRef = useRef(hexToRgb(TONE[tone].hex));
  const reduce = useReducedMotion();

  liveRef.current = live;
  tintRef.current = hexToRgb(TONE[tone].hex);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const gl = canvas.getContext('webgl', { premultipliedAlpha: false, antialias: false, alpha: true });
    if (!gl) return;

    const compile = (type: number, source: string) => {
      const shader = gl.createShader(type);
      if (!shader) return null;
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      return gl.getShaderParameter(shader, gl.COMPILE_STATUS) ? shader : null;
    };
    const vs = compile(gl.VERTEX_SHADER, VERTEX);
    const fs = compile(gl.FRAGMENT_SHADER, FRAGMENT);
    const program = gl.createProgram();
    if (!vs || !fs || !program) return;
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
    gl.useProgram(program);

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);
    const position = gl.getAttribLocation(program, 'p');
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    const uRes = gl.getUniformLocation(program, 'u_res');
    const uTime = gl.getUniformLocation(program, 'u_time');
    const uTint = gl.getUniformLocation(program, 'u_tint');

    let frame = 0;
    let clock = 0;
    let last = performance.now();
    let visible = true;

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      const width = Math.max(1, Math.floor(canvas.clientWidth * ratio));
      const height = Math.max(1, Math.floor(canvas.clientHeight * ratio));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        gl.viewport(0, 0, width, height);
      }
    };

    const draw = (now: number) => {
      const delta = Math.min(0.1, (now - last) / 1000);
      last = now;
      // Time advances only while live: a disconnected page shows a still field.
      if (liveRef.current && !reduce) clock += delta;
      resize();
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, clock + 7.3);
      gl.uniform3f(uTint, ...tintRef.current);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      frame = visible && !reduce ? requestAnimationFrame(draw) : 0;
    };

    // Off-screen panels stop rendering entirely.
    const observer = new IntersectionObserver(([entry]) => {
      visible = entry?.isIntersecting ?? true;
      if (visible && !frame) {
        last = performance.now();
        frame = requestAnimationFrame(draw);
      }
    });
    observer.observe(canvas);
    frame = requestAnimationFrame(draw);

    return () => {
      observer.disconnect();
      if (frame) cancelAnimationFrame(frame);
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
    };
    // tone: with reduced motion there is no loop, so a gate change redraws here.
  }, [reduce, tone]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="qkms-gate-field pointer-events-none absolute inset-0 h-full w-full opacity-70"
    />
  );
}
