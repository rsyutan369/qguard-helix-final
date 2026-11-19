import gsap from 'gsap';
import * as THREE from 'three';

export type LocalMode = 'xfer' | 'mesh' | 'vault';

/** All geometry describes a sample route. The website never discovers devices. */
export function mountLocalScene(canvas: HTMLCanvasElement, onUnavailable: () => void) {
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: 'low-power' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  const scene = new THREE.Scene();
  const camera = new THREE.OrthographicCamera(-5, 5, 3, -3, 0.1, 40);
  camera.position.set(5, 5, 9);
  camera.lookAt(0, 0, 0);
  scene.add(new THREE.HemisphereLight(0xc1e4ff, 0x304057, 2.2));
  const light = new THREE.DirectionalLight(0xf0fdff, 2.7);
  light.position.set(-3, 6, 5);
  scene.add(light);

  const pivot = new THREE.Group();
  scene.add(pivot);
  const floor = new THREE.GridHelper(11, 22, 0x476780, 0x294359);
  floor.position.y = -1.25;
  const floorMaterial = floor.material as THREE.Material;
  floorMaterial.transparent = true;
  floorMaterial.opacity = 0.4;
  pivot.add(floor);

  const deviceGeometry = new THREE.BoxGeometry(1.22, 1.64, 0.22);
  const deviceEdges = new THREE.EdgesGeometry(deviceGeometry);
  const displayGeometry = new THREE.PlaneGeometry(1.02, 1.34);
  const displayMaterial = new THREE.MeshBasicMaterial({ color: 0x142a41 });
  const signalGeometry = new THREE.OctahedronGeometry(0.2);
  const groups: Record<LocalMode, THREE.Group> = { xfer: new THREE.Group(), mesh: new THREE.Group(), vault: new THREE.Group() };
  const signals: Partial<Record<LocalMode, { node: THREE.Mesh; curve: THREE.CatmullRomCurve3 }>> = {};
  const flowTime = { value: 0 };
  const accents = { xfer: 0x6bd6e7, mesh: 0xa8b9ff, vault: 0xf2ca7b };
  const v = (x: number, y: number, z = 0) => new THREE.Vector3(x, y, z);

  function device(group: THREE.Group, position: THREE.Vector3, color: number, scale = 1) {
    const body = new THREE.Mesh(deviceGeometry, new THREE.MeshStandardMaterial({ color: 0x1b354f, metalness: 0.55, roughness: 0.31 }));
    body.add(new THREE.LineSegments(deviceEdges, new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.9 })));
    const display = new THREE.Mesh(displayGeometry, displayMaterial);
    display.position.set(0, 0.04, 0.12);
    const glyph = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints([
      v(-0.24, 0.05, 0.13), v(0.24, 0.05, 0.13),
      v(-0.24, -0.11, 0.13), v(0.12, -0.11, 0.13),
      v(-0.24, -0.27, 0.13), v(0.19, -0.27, 0.13),
    ]), new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.8 }));
    body.add(display, glyph);
    body.position.copy(position);
    body.scale.setScalar(scale);
    group.add(body);
  }

  function route(mode: LocalMode, start: THREE.Vector3, end: THREE.Vector3, animate = false) {
    const curve = new THREE.CatmullRomCurve3([start, start.clone().lerp(end, 0.5).add(v(0, 0.52)), end]);
    const line = new THREE.Mesh(new THREE.TubeGeometry(curve, 48, 0.027, 6, false), new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      uniforms: { time: flowTime, tint: { value: new THREE.Color(accents[mode]) } },
      vertexShader: `
        varying float routePosition;
        void main() {
          routePosition = uv.x;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        uniform float time;
        uniform vec3 tint;
        varying float routePosition;
        void main() {
          float phase = fract(routePosition * 2.0 - time);
          float glow = smoothstep(0.03, 0.19, phase) * (1.0 - smoothstep(0.19, 0.43, phase));
          gl_FragColor = vec4(mix(tint, vec3(0.92, 0.98, 1.0), glow), 0.42 + glow * 0.58);
        }
      `,
    }));
    groups[mode].add(line);
    if (animate) {
      const node = new THREE.Mesh(signalGeometry, new THREE.MeshBasicMaterial({ color: accents[mode] }));
      groups[mode].add(node);
      signals[mode] = { node, curve };
    }
  }

  device(groups.xfer, v(-2.55, 0), accents.xfer);
  device(groups.xfer, v(2.55, 0), accents.xfer);
  route('xfer', v(-1.9, 0.15), v(1.9, 0.15), true);

  device(groups.mesh, v(-2.35, 0.05, 0.25), accents.mesh, 0.92);
  device(groups.mesh, v(2.1, 0.65, -1.05), accents.mesh, 0.68);
  device(groups.mesh, v(2.15, -0.15, 1.25), accents.mesh, 0.68);
  route('mesh', v(-1.75, 0.2, 0.25), v(1.65, 0.65, -1.05), true);
  route('mesh', v(-1.75, 0.2, 0.25), v(1.7, -0.15, 1.25));

  device(groups.vault, v(-2.5, 0), accents.vault, 0.85);
  route('vault', v(-1.95, 0.15), v(1.0, 0.2), true);
  for (let layer = 0; layer < 3; layer += 1) {
    const geometry = new THREE.BoxGeometry(2.1, 0.36, 1.66);
    const slab = new THREE.Mesh(geometry, new THREE.MeshStandardMaterial({ color: 0x394559, metalness: 0.6, roughness: 0.3 }));
    slab.add(new THREE.LineSegments(new THREE.EdgesGeometry(geometry), new THREE.LineBasicMaterial({ color: accents.vault })));
    slab.position.set(2.0, layer * 0.48 - 0.6, 0);
    groups.vault.add(slab);
  }
  pivot.add(...Object.values(groups));

  let lost = false;
  const render = () => { if (!lost) renderer.render(scene, camera); };
  const flow = gsap.to(flowTime, { value: 1, duration: 1.8, repeat: -1, ease: 'none', paused: true, onUpdate: render });
  const turn = gsap.quickTo(pivot.rotation, 'y', { duration: 0.48, ease: 'power2.out', onUpdate: render });
  const onScroll = () => {
    const rect = canvas.getBoundingClientRect();
    const progress = THREE.MathUtils.clamp((innerHeight - rect.top) / (innerHeight + rect.height), 0, 1);
    turn((progress - 0.5) * 0.55);
  };
  function resize() {
    const { clientWidth: width, clientHeight: height } = canvas;
    if (!width || !height) return;
    const halfWidth = Math.max(3.9, 2.3 * width / height);
    const halfHeight = halfWidth * height / width;
    camera.left = -halfWidth;
    camera.right = halfWidth;
    camera.top = halfHeight;
    camera.bottom = -halfHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
    render();
  }
  function setFrame(mode: LocalMode, position: number | null) {
    for (const key of Object.keys(groups) as LocalMode[]) groups[key].visible = key === mode;
    const signal = signals[mode];
    if (signal) {
      signal.node.visible = position !== null;
      if (position !== null) signal.curve.getPoint(position, signal.node.position);
    }
    render();
  }

  const onLost = (event: Event) => {
    event.preventDefault();
    lost = true;
    flow.kill();
    turn.tween.kill();
    onUnavailable();
  };
  const observer = new ResizeObserver(resize);
  observer.observe(canvas);
  canvas.addEventListener('webglcontextlost', onLost);
  window.addEventListener('scroll', onScroll, { passive: true });
  resize();
  onScroll();
  return {
    setFrame,
    setFlowing(enabled: boolean) {
      if (!lost) flow.paused(!enabled);
    },
    dispose() {
      observer.disconnect();
      window.removeEventListener('scroll', onScroll);
      canvas.removeEventListener('webglcontextlost', onLost);
      flow.kill();
      turn.tween.kill();
      const resources = new Set<THREE.BufferGeometry | THREE.Material>();
      scene.traverse((object) => {
        if (!(object instanceof THREE.Mesh) && !(object instanceof THREE.Line)) return;
        resources.add(object.geometry);
        for (const material of [object.material].flat()) resources.add(material);
      });
      resources.forEach((resource) => resource.dispose());
      renderer.dispose();
      renderer.forceContextLoss();
    },
  };
}
