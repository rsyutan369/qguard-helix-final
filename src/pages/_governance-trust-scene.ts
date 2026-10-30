import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';

export type TrustSceneState = {
  active: number;
  running: boolean;
  reduced: boolean;
  progress: number;
  pointerX: number;
  pointerY: number;
};

export type TrustSceneApi = { invalidate: () => void; pick: (clientX: number, clientY: number) => number | null; dispose: () => void };

/** Original conceptual geometry. No operational state, findings or telemetry. */
export function mountTrustScene(host: HTMLDivElement, read: () => TrustSceneState): TrustSceneApi | null {
  let renderer: THREE.WebGLRenderer;
  try {
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'low-power' });
  } catch {
    host.dataset.renderer = 'fallback';
    return null;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  renderer.setClearColor(0xffffff, 0);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.02;
  renderer.domElement.setAttribute('aria-hidden', 'true');
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const room = new RoomEnvironment();
  const pmrem = new THREE.PMREMGenerator(renderer);
  const environment = pmrem.fromScene(room, .04);
  scene.environment = environment.texture;
  room.dispose();
  pmrem.dispose();
  const camera = new THREE.PerspectiveCamera(33, 1, .1, 80);
  const world = new THREE.Group();
  scene.add(world);
  scene.add(new THREE.HemisphereLight(0xffffff, 0x8494b3, 2.4));
  const key = new THREE.DirectionalLight(0xffffff, 3);
  key.position.set(-3, 8, 5);
  const rim = new THREE.DirectionalLight(0xb5ccff, 2.2);
  rim.position.set(5, 3, -5);
  const fill = new THREE.DirectionalLight(0xf0eaff, 1.6);
  fill.position.set(-5, 2, -3);
  scene.add(key, rim, fill);

  const metal = new THREE.MeshStandardMaterial({ color: 0xe0e6f1, metalness: .72, roughness: .22 });
  const darkMetal = new THREE.MeshStandardMaterial({ color: 0xa4b2c9, metalness: .78, roughness: .28 });
  const champagne = new THREE.MeshStandardMaterial({ color: 0x76649d, metalness: .65, roughness: .23 });
  const glass = new THREE.MeshPhysicalMaterial({ color: 0xe6efff, metalness: .05, roughness: .08, transparent: true, opacity: .42, depthWrite: false, clearcoat: 1, transmission: .24, thickness: .15, ior: 1.45, side: THREE.DoubleSide });
  const ink = new THREE.LineBasicMaterial({ color: 0x8094ba, transparent: true, opacity: .55 });
  const bright = new THREE.MeshStandardMaterial({ color: 0xcbeaff, emissive: 0x38bdf8, emissiveIntensity: .6, metalness: .25, roughness: .2 });
  const interactables: THREE.Object3D[] = [];

  function roundedShape(width: number, depth: number, radius = .12) {
    const x = -width / 2, z = -depth / 2;
    const shape = new THREE.Shape();
    shape.moveTo(x + radius, z);
    shape.lineTo(x + width - radius, z);
    shape.quadraticCurveTo(x + width, z, x + width, z + radius);
    shape.lineTo(x + width, z + depth - radius);
    shape.quadraticCurveTo(x + width, z + depth, x + width - radius, z + depth);
    shape.lineTo(x + radius, z + depth);
    shape.quadraticCurveTo(x, z + depth, x, z + depth - radius);
    shape.lineTo(x, z + radius);
    shape.quadraticCurveTo(x, z, x + radius, z);
    return shape;
  }

  function plate(parent: THREE.Group, width: number, depth: number, thickness: number, y: number, material: THREE.Material) {
    const geometry = new THREE.ExtrudeGeometry(roundedShape(width, depth), { depth: thickness, bevelEnabled: true, bevelSize: .035, bevelThickness: .025, bevelSegments: 2, curveSegments: 5, steps: 1 });
    geometry.rotateX(-Math.PI / 2);
    const mesh = new THREE.Mesh(geometry, material);
    mesh.position.y = y;
    parent.add(mesh);
    return mesh;
  }

  function line(parent: THREE.Group, points: THREE.Vector3[], material: THREE.LineBasicMaterial) {
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const result = new THREE.Line(geometry, material);
    parent.add(result);
    return result;
  }

  function rimLine(parent: THREE.Group, width: number, height: number, y: number, material = ink) {
    const points = roundedShape(width, height, .16).getPoints(10).map(p => new THREE.Vector3(p.x, y, p.y));
    line(parent, points, material);
  }

  plate(world, 5.55, 5.55, .12, -.48, darkMetal);
  plate(world, 5.35, 5.35, .10, -.29, metal);
  plate(world, 5.18, 5.18, .08, -.13, darkMetal);
  rimLine(world, 5.09, 5.09, -.015);
  rimLine(world, 4.6, 4.6, .005, new THREE.LineBasicMaterial({ color: 0x9baed0, transparent: true, opacity: .3 }));

  // Fine etched circuit traces make the base feel machined rather than decorative.
  const etch = new THREE.LineBasicMaterial({ color: 0x7896c4, transparent: true, opacity: .28 });
  for (let i = 0; i < 8; i++) {
    const p = -.9 + i * .255;
    line(world, [new THREE.Vector3(p, .006, 1.38), new THREE.Vector3(p, .006, 2.05), new THREE.Vector3(p + .18, .006, 2.23)], etch);
    line(world, [new THREE.Vector3(-1.38, .006, p), new THREE.Vector3(-2.05, .006, p), new THREE.Vector3(-2.23, .006, p + .18)], etch);
  }

  const core = new THREE.Group();
  core.userData.domainIndex = 0;
  interactables.push(core);
  world.add(core);
  const layers = [
    plate(core, 2.18, 2.18, .13, .15, metal),
    plate(core, 2.08, 2.08, .11, .48, glass),
    plate(core, 2.08, 2.08, .11, .81, glass),
    plate(core, 2.18, 2.18, .13, 1.14, metal),
  ];
  const layerRims = layers.map((_, index) => {
    const group = new THREE.Group();
    rimLine(group, 2.12, 2.12, 0, index === 3 ? new THREE.LineBasicMaterial({ color: 0x9181bd, transparent: true, opacity: .8 }) : ink);
    core.add(group);
    return group;
  });
  const inner = new THREE.Mesh(new THREE.BoxGeometry(1.44, .8, 1.44), new THREE.MeshPhysicalMaterial({ color: 0xd2dff8, roughness: .15, metalness: .22, clearcoat: 1, transparent: true, opacity: .8 }));
  inner.position.y = .71;
  core.add(inner);
  const innerEdges = new THREE.LineSegments(new THREE.EdgesGeometry(inner.geometry), new THREE.LineBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: .45 }));
  innerEdges.position.copy(inner.position);
  core.add(innerEdges);

  const seal = new THREE.Group();
  const shield = new THREE.Shape();
  shield.moveTo(0, .54); shield.lineTo(.47, .34); shield.lineTo(.4, -.17);
  shield.quadraticCurveTo(.32, -.43, 0, -.62); shield.quadraticCurveTo(-.32, -.43, -.4, -.17);
  shield.lineTo(-.47, .34); shield.closePath();
  const shieldGeometry = new THREE.ExtrudeGeometry(shield, { depth: .06, bevelEnabled: true, bevelThickness: .015, bevelSize: .015, bevelSegments: 2, steps: 1 });
  shieldGeometry.rotateX(-Math.PI / 2);
  seal.add(new THREE.Mesh(shieldGeometry, champagne));
  line(seal, [new THREE.Vector3(-.2, .09, .02), new THREE.Vector3(-.04, .09, .18), new THREE.Vector3(.24, .09, -.19)], new THREE.LineBasicMaterial({ color: 0xf8fafc }));
  core.add(seal);

  const corners = new THREE.Group();
  for (const x of [-1, 1]) for (const z of [-1, 1]) {
    const pin = new THREE.Mesh(new THREE.CylinderGeometry(.026, .026, 1.03, 8), champagne);
    pin.position.set(x, .7, z);
    corners.add(pin);
  }
  core.add(corners);

  const locations = [new THREE.Vector3(-2.65, .02, -.55), new THREE.Vector3(.55, .02, -2.65), new THREE.Vector3(2.65, .02, .55), new THREE.Vector3(-.55, .02, 2.65)];
  const satellites: THREE.Group[] = [];
  const routeMaterials: THREE.ShaderMaterial[][] = [];
  const curves: THREE.CatmullRomCurve3[] = [];
  const particles: THREE.Sprite[] = [];
  const streams: THREE.Sprite[][] = [];
  const rings: THREE.Mesh[] = [];
  const nodeMaterials: THREE.MeshStandardMaterial[] = [];
  // A small radial texture gives each moving light a white core and soft halo.
  const glowCanvas = document.createElement('canvas');
  glowCanvas.width = glowCanvas.height = 64;
  const glowContext = glowCanvas.getContext('2d')!;
  const gradient = glowContext.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, 'rgba(255,255,255,1)');
  gradient.addColorStop(.12, 'rgba(255,255,255,1)');
  gradient.addColorStop(.3, 'rgba(255,255,255,.65)');
  gradient.addColorStop(.65, 'rgba(255,255,255,.16)');
  gradient.addColorStop(1, 'rgba(255,255,255,0)');
  glowContext.fillStyle = gradient;
  glowContext.fillRect(0, 0, 64, 64);
  const glowTexture = new THREE.CanvasTexture(glowCanvas);

  function streamMaterial(halo: boolean, index: number) {
    return new THREE.ShaderMaterial({
      transparent: true, depthWrite: false,
      uniforms: { time: { value: 0 }, selected: { value: 0 }, phase: { value: index * 1.7 }, halo: { value: halo ? 1 : 0 } },
      vertexShader: 'varying vec2 vUv; void main(){vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}',
      fragmentShader: `precision highp float;
        varying vec2 vUv; uniform float time; uniform float selected; uniform float phase; uniform float halo;
        void main(){
          float flow=pow(.5+.5*cos(vUv.x*18.84956-time*3.4+phase),10.);
          float pulse=.8+.2*sin(time*2.6+phase);
          vec3 tint=mix(vec3(.015,.57,.94),vec3(.43,.18,.91),selected);
          vec3 color=mix(tint,vec3(.91,.98,1.),flow*.88);
          float alpha=mix(.5+.5*flow,.09+.27*flow,halo)*mix(.7,1.,selected)*pulse;
          gl_FragColor=vec4(color,alpha);
        }`,
    });
  }

  locations.forEach((point, index) => {
    const node = new THREE.Group();
    node.userData.domainIndex = index;
    interactables.push(node);
    node.position.copy(point);
    world.add(node);
    satellites.push(node);
    plate(node, 1.02, 1.02, .12, .04, darkMetal);
    plate(node, .9, .9, .07, .2, metal);
    const nodeMaterial = bright.clone();
    nodeMaterials.push(nodeMaterial);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(.39, .016, 6, 48), nodeMaterial);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = .31;
    node.add(ring); rings.push(ring);

    const glyph = new THREE.Group();
    glyph.position.y = .36;
    node.add(glyph);
    if (index === 0) {
      const keyRing = new THREE.Mesh(new THREE.TorusGeometry(.14, .045, 10, 32), champagne);
      keyRing.rotation.x = -Math.PI / 2;
      keyRing.position.z = -.15;
      glyph.add(keyRing);
      const shaft = new THREE.Mesh(new THREE.BoxGeometry(.07, .07, .38), champagne);
      shaft.position.z = .09; glyph.add(shaft);
      for (const z of [.14, .25]) {
        const tooth = new THREE.Mesh(new THREE.BoxGeometry(.16, .07, .06), champagne);
        tooth.position.set(.05, 0, z); glyph.add(tooth);
      }
    } else if (index === 1) {
      for (let row = 0; row < 3; row++) {
        const tile = new THREE.Mesh(new THREE.BoxGeometry(.44, .04, .065), champagne);
        tile.position.z = -.17 + row * .17; glyph.add(tile);
        const dot = new THREE.Mesh(new THREE.BoxGeometry(.06, .04, .065), nodeMaterial);
        dot.position.set(-.31, 0, tile.position.z); glyph.add(dot);
      }
    } else if (index === 2) {
      for (const z of [-.13, .13]) {
        const chain = new THREE.Mesh(new THREE.TorusGeometry(.16, .037, 10, 32), champagne);
        chain.rotation.x = -Math.PI / 2; chain.position.z = z; glyph.add(chain);
      }
    } else {
      for (let sheet = 0; sheet < 3; sheet++) {
        plate(glyph, .38, .48, .025, sheet * .055, sheet === 2 ? champagne : metal);
      }
    }

    const end = point.clone().multiplyScalar(.37); end.y = .68;
    const mid = point.clone().multiplyScalar(.72); mid.y = .5;
    const curve = new THREE.CatmullRomCurve3([point.clone().setY(.39), mid, end]);
    curves.push(curve);
    const materials = [streamMaterial(false, index), streamMaterial(true, index)];
    routeMaterials.push(materials);
    materials.forEach((material, layer) => {
      const route = new THREE.Mesh(new THREE.TubeGeometry(curve, 40, layer ? .075 : .027, 8, false), material);
      route.userData.domainIndex = index;
      route.renderOrder = layer ? 1 : 2;
      world.add(route);
    });
    // A wider invisible hit area makes the small connecting paths selectable.
    const routeHit = new THREE.Mesh(new THREE.TubeGeometry(curve, 24, .14, 6, false), new THREE.MeshBasicMaterial({ visible: false }));
    routeHit.userData.domainIndex = index;
    world.add(routeHit); interactables.push(routeHit);
    const lights = Array.from({ length: 4 }, () => {
      const light = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTexture, color: 0x38bdf8, transparent: true, depthWrite: false }));
      light.scale.setScalar(.24);
      world.add(light);
      return light;
    });
    streams.push(lights);
    particles.push(lights[0]);
  });

  // Outer corner markers give the object a grounded technical drawing language.
  for (const x of [-1, 1]) for (const z of [-1, 1]) {
    const marker = new THREE.Mesh(new THREE.BoxGeometry(.13, .035, .13), champagne);
    marker.position.set(x * 2.43, .015, z * 2.43);
    world.add(marker);
  }

  let frame = 0, disposed = false, lost = false, visible = true, elapsed = 0, previous = 0, lastPaint = 0;
  let expansion = 0, yaw = 0, pitch = 0;
  const lifts = [0, 0, 0, 0];

  function draw(now: number) {
    frame = 0;
    if (disposed || lost || !visible || document.hidden) { previous = 0; return; }
    const state = read();
    if (state.running && now - lastPaint < 33) { frame = requestAnimationFrame(draw); return; }
    const dt = previous ? Math.min((now - previous) / 1000, .05) : 0;
    previous = now; lastPaint = now;
    if (state.running) elapsed += dt;
    const smoothing = state.running ? 1 - Math.exp(-dt * 7) : 1;
    const targetExpansion = state.reduced ? 0 : state.progress * .3;
    const poseSmoothing = state.running || state.reduced ? smoothing : 0;
    expansion += (targetExpansion - expansion) * poseSmoothing;
    yaw += ((state.reduced ? 0 : state.pointerX * .12) - yaw) * poseSmoothing;
    pitch += ((state.reduced ? 0 : state.pointerY * .045) - pitch) * poseSmoothing;
    world.rotation.y = -.12 + yaw + (state.reduced ? 0 : Math.sin(elapsed * .18) * .055);
    world.rotation.x = pitch;
    const assembly = state.reduced ? 0 : .38 * Math.pow(Math.max(0, 1 - elapsed / 1.4), 3);
    layers.forEach((layer, index) => {
      layer.position.y = .15 + index * (.33 + expansion + assembly);
      layerRims[index].position.y = layer.position.y + (index === 0 || index === 3 ? .15 : .13);
    });
    seal.position.y = layers[3].position.y + .18;
    corners.scale.y = 1 + (expansion + assembly) * 2;
    corners.position.y = (expansion + assembly) * .85;
    satellites.forEach((satellite, index) => {
      lifts[index] += ((index === state.active ? .16 : 0) - lifts[index]) * smoothing;
      satellite.position.y = locations[index].y + lifts[index];
      const selected = index === state.active;
      routeMaterials[index].forEach(material => {
        material.uniforms.time.value = elapsed;
        material.uniforms.selected.value = selected ? 1 : 0;
      });
      const pulse = .5 + .5 * Math.sin(elapsed * 2.6 + index);
      nodeMaterials[index].emissiveIntensity = selected ? .65 + pulse * .4 : .2;
      nodeMaterials[index].emissive.setHex(selected ? 0x8b5cf6 : 0x38bdf8);
      rings[index].scale.setScalar(selected ? 1.045 + pulse * .035 : 1);
      streams[index].forEach((light, lightIndex) => {
        const progress = (elapsed * .18 + lightIndex / 4 + index * .12) % 1;
        light.position.copy(curves[index].getPoint(progress));
        light.material.color.setHex(selected ? 0x8b5cf6 : 0x0ea5e9);
        light.material.opacity = selected ? .9 : .62;
        light.scale.setScalar((selected ? .36 : .25) * (.86 + pulse * .2));
      });
    });
    renderer.render(scene, camera);
    host.dataset.renderer = 'webgl';
    host.dataset.motion = state.reduced ? 'reduced' : state.running ? 'running' : 'paused';
    host.dataset.sceneState = [state.active, world.rotation.y.toFixed(4), expansion.toFixed(4), particles[state.active].position.x.toFixed(3)].join(':');
    if (state.running) frame = requestAnimationFrame(draw);
    else previous = 0;
  }

  function invalidate() {
    if (disposed || lost) return;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(draw);
  }

  function resize() {
    const width = host.clientWidth, height = Math.max(1, host.clientHeight);
    renderer.setSize(width, height);
    camera.aspect = width / height;
    const distance = camera.aspect < 1.1 ? 15.2 : 13.2;
    camera.position.set(8.5, 8, 10.5).normalize().multiplyScalar(distance);
    camera.lookAt(0, .4, 0);
    camera.updateProjectionMatrix();
    invalidate();
  }

  function visibilityChanged() { previous = 0; invalidate(); }
  function contextLost(event: Event) {
    event.preventDefault(); lost = true;
    cancelAnimationFrame(frame); host.dataset.renderer = 'fallback';
  }
  function contextRestored() { lost = false; resize(); }
  const observer = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; previous = 0; if (visible) invalidate(); else cancelAnimationFrame(frame); }, { rootMargin: '80px' });
  const sizeObserver = new ResizeObserver(resize);
  observer.observe(host); sizeObserver.observe(host);
  document.addEventListener('visibilitychange', visibilityChanged);
  renderer.domElement.addEventListener('webglcontextlost', contextLost);
  renderer.domElement.addEventListener('webglcontextrestored', contextRestored);
  resize();

  const raycaster = new THREE.Raycaster();
  raycaster.params.Line.threshold = .025;
  const pointer = new THREE.Vector2();
  function pick(clientX: number, clientY: number) {
    if (disposed || lost) return null;
    const bounds = renderer.domElement.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return null;
    pointer.set((clientX - bounds.left) / bounds.width * 2 - 1, -((clientY - bounds.top) / bounds.height) * 2 + 1);
    raycaster.setFromCamera(pointer, camera);
    const intersections = raycaster.intersectObjects(interactables, true);
    for (const hit of intersections) {
      let object: THREE.Object3D | null = hit.object;
      while (object) {
        if (typeof object.userData.domainIndex === 'number') return object.userData.domainIndex as number;
        object = object.parent;
      }
    }
    return null;
  }

  return {
    invalidate,
    pick,
    dispose() {
      disposed = true; cancelAnimationFrame(frame);
      observer.disconnect(); sizeObserver.disconnect();
      document.removeEventListener('visibilitychange', visibilityChanged);
      renderer.domElement.removeEventListener('webglcontextlost', contextLost);
      renderer.domElement.removeEventListener('webglcontextrestored', contextRestored);
      const geometries = new Set<THREE.BufferGeometry>();
      const materials = new Set<THREE.Material>();
      scene.traverse(object => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Sprite) {
          if (!(object instanceof THREE.Sprite)) geometries.add(object.geometry);
          for (const material of Array.isArray(object.material) ? object.material : [object.material]) materials.add(material);
        }
      });
      geometries.forEach(geometry => geometry.dispose());
      materials.forEach(material => material.dispose());
      bright.dispose();
      glowTexture.dispose(); environment.dispose();
      renderer.dispose(); renderer.domElement.remove();
    },
  };
}
