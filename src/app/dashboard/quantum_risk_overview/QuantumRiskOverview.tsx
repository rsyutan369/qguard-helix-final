import { useEffect, useState, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import * as THREE from 'three';
import {
  Shield, AlertTriangle, Activity, TrendingUp, TrendingDown,
  Eye, Zap, Lock, Unlock, Globe, Server, Database,
  Radio, Wifi, Target, Crosshair
} from 'lucide-react';

const GLASS_PANEL_CLASSES = 'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

type RiskNode = {
  id: string;
  label: string;
  x: number;
  y: number;
  risk: number;
  type: 'server' | 'database' | 'api' | 'network';
  vulnerable: boolean;
};

type AttackPath = {
  from: string;
  to: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
};

const RISK_NODES: RiskNode[] = [
  { id: 'gw-01', label: 'API Gateway', x: 50, y: 20, risk: 82, type: 'api', vulnerable: true },
  { id: 'db-01', label: 'Customer DB', x: 80, y: 45, risk: 94, type: 'database', vulnerable: true },
  { id: 'sv-01', label: 'Auth Server', x: 20, y: 40, risk: 45, type: 'server', vulnerable: false },
  { id: 'sv-02', label: 'Payment Svc', x: 65, y: 70, risk: 88, type: 'server', vulnerable: true },
  { id: 'nw-01', label: 'Edge Router', x: 35, y: 65, risk: 67, type: 'network', vulnerable: true },
  { id: 'db-02', label: 'Session Store', x: 15, y: 80, risk: 31, type: 'database', vulnerable: false },
  { id: 'sv-03', label: 'CDN Origin', x: 85, y: 15, risk: 52, type: 'server', vulnerable: false },
  { id: 'api-02', label: 'GraphQL EP', x: 50, y: 50, risk: 76, type: 'api', vulnerable: true },
];

const ATTACK_PATHS: AttackPath[] = [
  { from: 'gw-01', to: 'api-02', severity: 'critical' },
  { from: 'api-02', to: 'db-01', severity: 'critical' },
  { from: 'api-02', to: 'sv-02', severity: 'high' },
  { from: 'nw-01', to: 'sv-01', severity: 'medium' },
  { from: 'sv-01', to: 'db-02', severity: 'low' },
  { from: 'sv-03', to: 'gw-01', severity: 'medium' },
  { from: 'nw-01', to: 'api-02', severity: 'high' },
];

const THREAT_FEEDS = [
  { time: '14:32:01', source: 'NIST CVE-2026-4821', msg: 'RSA-2048 quantum factoring POC published', severity: 'CRITICAL' },
  { time: '14:28:15', source: 'MITRE ATT&CK', msg: 'New HNDL campaign targeting financial sector', severity: 'HIGH' },
  { time: '14:22:44', source: 'QGuard Intel', msg: 'ML-KEM-768 implementation verified secure', severity: 'INFO' },
  { time: '14:15:02', source: 'CERT Alert', msg: 'OpenSSL 3.4 RSA side-channel vulnerability', severity: 'HIGH' },
  { time: '14:08:33', source: 'QGuard Scanner', msg: 'ECDSA P-256 detected in TLS handshake', severity: 'WARNING' },
  { time: '14:01:18', source: 'Threat Feed', msg: 'IBM Condor 1121-qubit milestone confirmed', severity: 'WARNING' },
];

function getNodeIcon(type: RiskNode['type']) {
  switch (type) {
    case 'server': return Server;
    case 'database': return Database;
    case 'api': return Globe;
    case 'network': return Wifi;
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical':
    case 'CRITICAL': return '#ef4444';
    case 'high':
    case 'HIGH': return '#f97316';
    case 'medium':
    case 'WARNING': return '#eab308';
    case 'low':
    case 'INFO': return '#22c55e';
    default: return '#6b7280';
  }
}

export default function QuantumRiskOverview() {
  const [riskScore, setRiskScore] = useState(687);
  const [activePulse, setActivePulse] = useState(0);
  const [telemetry, setTelemetry] = useState({
    scansPerMin: 142,
    threatsBlocked: 23847,
    keysRotated: 1294,
    assetsMonitored: 847
  });
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedNode, setSelectedNode] = useState<RiskNode | null>(null);
  const graphCanvasRef = useRef<HTMLCanvasElement>(null);

  // Procedural geographic Earth map generator (produces seamless spherical world map)
  const generateEarthTexture = () => {
    const canvas = document.createElement('canvas');
    canvas.width = 1024;
    canvas.height = 512;
    const ctx = canvas.getContext('2d');
    if (!ctx) return canvas;

    ctx.fillStyle = '#061730';
    ctx.fillRect(0, 0, 1024, 512);

    const imgData = ctx.createImageData(1024, 512);
    for (let y = 0; y < 512; y++) {
      const lat = (y / 512) * Math.PI - Math.PI / 2;
      const cosLat = Math.cos(lat);
      for (let x = 0; x < 1024; x++) {
        const lon = (x / 1024) * Math.PI * 2;
        
        // 3D Cartesian mapping to eliminate polar texture pinching/seaming
        const nx = Math.cos(lon) * cosLat * 2.8;
        const ny = Math.sin(lat) * 2.8;
        const nz = Math.sin(lon) * cosLat * 2.8;

        // Spherical sine Brownian motion (multi-octave seamless noise)
        const n = Math.sin(nx) * Math.cos(ny) * 0.42 +
                  Math.sin(nx * 2.5 + 1.0) * Math.cos(ny * 2.2 + 0.5) * 0.22 +
                  Math.sin(nx * 6.0) * Math.cos(ny * 5.8) * 0.12 +
                  Math.sin(nx * 14.0) * Math.cos(ny * 13.0) * 0.06 +
                  Math.sin(nx * 30.0) * Math.cos(ny * 28.0) * 0.03;
        
        const h = (n + 1) / 2;
        
        let r = 8, g = 20, b = 45; // Default deep ocean
        
        if (h < 0.46) {
          // Deep ocean floor
          r = 6;
          g = 18;
          b = 38;
        } else if (h < 0.485) {
          // Shallow coastal water
          r = 12;
          g = 45;
          b = 78;
        } else if (h < 0.505) {
          // Sand beaches
          r = 185;
          g = 160;
          b = 115;
        } else {
          // Landmasses
          const isPolar = Math.abs(ny) > 2.1;
          if (isPolar) {
            // Polar ice caps
            r = 245;
            g = 248;
            b = 252;
          } else {
            // Vegetation & mountain altitude coloring
            const elevation = (h - 0.505) / 0.495;
            if (elevation > 0.42) {
              // High rocky peaks
              r = 95 + Math.floor(elevation * 60);
              g = 70 + Math.floor(elevation * 40);
              b = 55 + Math.floor(elevation * 30);
            } else {
              // Lowland valleys and dense forests
              r = 25 + Math.floor(elevation * 45);
              g = 105 - Math.floor(elevation * 25);
              b = 35 + Math.floor(elevation * 15);
            }
          }
        }
        
        const idx = (y * 1024 + x) * 4;
        imgData.data[idx] = r;
        imgData.data[idx+1] = g;
        imgData.data[idx+2] = b;
        imgData.data[idx+3] = 255;
      }
    }
    ctx.putImageData(imgData, 0, 0);
    return canvas;
  };

  // Procedural cloud map texture generator
  const generateCloudTexture = () => {
    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 256;
    const ctx = canvas.getContext('2d');
    if (!ctx) return canvas;

    const imgData = ctx.createImageData(512, 256);
    for (let y = 0; y < 256; y++) {
      const lat = (y / 256) * Math.PI - Math.PI / 2;
      const cosLat = Math.cos(lat);
      for (let x = 0; x < 512; x++) {
        const lon = (x / 512) * Math.PI * 2;
        
        const nx = Math.cos(lon) * cosLat * 3.5;
        const ny = Math.sin(lat) * 3.5;

        const n = Math.sin(nx) * Math.cos(ny) * 0.45 +
                  Math.sin(nx * 3.2 + 0.8) * Math.cos(ny * 3.0 + 1.2) * 0.25 +
                  Math.sin(nx * 9.0) * Math.cos(ny * 8.5) * 0.15;
        
        const h = (n + 1) / 2;
        
        const idx = (y * 512 + x) * 4;
        imgData.data[idx] = 255;
        imgData.data[idx+1] = 255;
        imgData.data[idx+2] = 255;
        imgData.data[idx+3] = h > 0.58 ? Math.floor((h - 0.58) * 2.38 * 255) : 0;
      }
    }
    ctx.putImageData(imgData, 0, 0);
    return canvas;
  };

  // Setup Threejs realistic interactive 3D Globe
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // 1. Initial Scene Setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
    camera.position.z = 6;

    // 2. WebGL Renderer configuration
    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);

    // 3. Procedural maps
    const earthTex = new THREE.CanvasTexture(generateEarthTexture());
    const cloudTex = new THREE.CanvasTexture(generateCloudTexture());

    // 4. Mesh spheres
    const earthGeo = new THREE.SphereGeometry(2, 64, 64);
    const earthMat = new THREE.MeshStandardMaterial({
      map: earthTex,
      roughness: 0.78,
      metalness: 0.12
    });
    const earthMesh = new THREE.Mesh(earthGeo, earthMat);
    scene.add(earthMesh);

    // Clouds sphere
    const cloudGeo = new THREE.SphereGeometry(2.03, 64, 64);
    const cloudMat = new THREE.MeshStandardMaterial({
      map: cloudTex,
      transparent: true,
      opacity: 0.75,
      depthWrite: false
    });
    const cloudMesh = new THREE.Mesh(cloudGeo, cloudMat);
    scene.add(cloudMesh);

    // Custom atmospheric scattering glow shell (Fresnel effect)
    const atmosphereGeo = new THREE.SphereGeometry(2.15, 32, 32);
    const atmosphereMat = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        void main() {
          float intensity = pow(0.62 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.8);
          gl_FragColor = vec4(0.35, 0.68, 1.0, 1.0) * intensity;
        }
      `,
      blending: THREE.AdditiveBlending,
      side: THREE.BackSide,
      transparent: true
    });
    const atmosphereMesh = new THREE.Mesh(atmosphereGeo, atmosphereMat);
    scene.add(atmosphereMesh);

    // 5. Threat Pinpoints & Beacons (attached as children of earthMesh so they rotate perfectly)
    const activeBeacons: THREE.Mesh[] = [];
    RISK_NODES.forEach((node) => {
      // Map cylindrical screen coordinates (0 to 100) into spherical radians
      const lon = (node.x / 100) * Math.PI * 2;
      const lat = -(node.y / 100) * Math.PI + Math.PI / 2;

      const r = 2.0;
      const px = r * Math.cos(lat) * Math.sin(lon);
      const py = r * Math.sin(lat);
      const pz = r * Math.cos(lat) * Math.cos(lon);

      // Core physical node beacon
      const pinColor = node.vulnerable ? 0xef4444 : 0x22c55e;
      const pinGeo = new THREE.SphereGeometry(0.032, 12, 12);
      const pinMat = new THREE.MeshBasicMaterial({ color: pinColor });
      const pinMesh = new THREE.Mesh(pinGeo, pinMat);
      pinMesh.position.set(px, py, pz);
      earthMesh.add(pinMesh);

      // Outward telemetry cylinder beacon beam
      const normalVector = new THREE.Vector3(px, py, pz).normalize();
      const beamHeight = 0.3 + (node.risk / 100) * 0.4;
      const beamGeo = new THREE.CylinderGeometry(0.005, 0.018, beamHeight, 12);
      beamGeo.translate(0, beamHeight / 2, 0); // Rotate from base
      const beamMat = new THREE.MeshBasicMaterial({
        color: pinColor,
        transparent: true,
        opacity: 0.6
      });
      const beamMesh = new THREE.Mesh(beamGeo, beamMat);
      beamMesh.position.set(px, py, pz);
      
      const defaultUp = new THREE.Vector3(0, 1, 0);
      beamMesh.quaternion.setFromUnitVectors(defaultUp, normalVector);
      earthMesh.add(beamMesh);
      activeBeacons.push(beamMesh);
    });

    // 6. Lighting configuration
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.15);
    scene.add(ambientLight);

    const primarySun = new THREE.DirectionalLight(0xfff4d6, 2.6);
    primarySun.position.set(5, 3.5, 5);
    scene.add(primarySun);

    const darkSideFill = new THREE.DirectionalLight(0x3b82f6, 1.2);
    darkSideFill.position.set(-5, -2, -5);
    scene.add(darkSideFill);

    // 7. Interactive Drag Handlers
    let isDragging = false;
    let prevMousePosition = { x: 0, y: 0 };

    const handleMouseDown = (e: MouseEvent) => {
      isDragging = true;
      prevMousePosition = { x: e.clientX, y: e.clientY };
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaX = e.clientX - prevMousePosition.x;
      const deltaY = e.clientY - prevMousePosition.y;

      earthMesh.rotation.y += deltaX * 0.005;
      earthMesh.rotation.x += deltaY * 0.005;

      // Lock X axis range to prevent upside down flips
      earthMesh.rotation.x = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, earthMesh.rotation.x));
      
      cloudMesh.rotation.x = earthMesh.rotation.x;
      cloudMesh.rotation.y = earthMesh.rotation.y + 0.02;

      prevMousePosition = { x: e.clientX, y: e.clientY };
    };

    const handleMouseUp = () => {
      isDragging = false;
    };

    canvas.addEventListener('mousedown', handleMouseDown);
    canvas.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    // 8. Size Resize Observer
    const sizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height, false);
      }
    });
    sizeObserver.observe(canvas.parentElement || canvas);

    // 9. Frame Animation Loop
    let animId = 0;
    const updateFrame = () => {
      animId = requestAnimationFrame(updateFrame);
      const time = Date.now() * 0.001;

      // Gentle auto-rotation when idle
      if (!isDragging) {
        earthMesh.rotation.y += 0.0012;
        cloudMesh.rotation.y += 0.0018;
      }

      // Animate threat beams with a gentle heartbeat pulse
      activeBeacons.forEach((beam, idx) => {
        const pulseScale = 1.0 + Math.sin(time * 4.0 + idx) * 0.18;
        beam.scale.set(pulseScale, pulseScale, pulseScale);
      });

      renderer.render(scene, camera);
    };
    updateFrame();

    // 10. Clean garbage collections
    return () => {
      cancelAnimationFrame(animId);
      sizeObserver.disconnect();
      canvas.removeEventListener('mousedown', handleMouseDown);
      canvas.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);

      earthGeo.dispose();
      earthMat.dispose();
      earthTex.dispose();
      cloudGeo.dispose();
      cloudMat.dispose();
      cloudTex.dispose();
      atmosphereGeo.dispose();
      atmosphereMat.dispose();
      renderer.dispose();
    };
  }, []);

  // Setup Threejs interactive 3D Attack Graph with Drag-and-Drop capability
  useEffect(() => {
    const canvas = graphCanvasRef.current;
    if (!canvas) return;

    // 1. Scene & Camera Setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, canvas.clientWidth / canvas.clientHeight, 0.1, 100);
    camera.position.set(0, 0, 7.5);

    // 2. WebGL Renderer configuration
    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);

    // 3. Node mapping coordinates in 3D (creates a 3-tier enterprise diagram)
    const nodePositionMap = new Map<string, THREE.Vector3>();
    const nodeMeshes: THREE.Mesh[] = [];
    const nodeMaterials: THREE.Material[] = [];
    const nodeGeometries: THREE.BufferGeometry[] = [];

    // Helper to calculate positions
    const get3DNodePosition = (node: RiskNode) => {
      const px = ((node.x - 50) / 100) * 4.8;
      const py = -((node.y - 50) / 100) * 3.2;
      
      let pz = 0;
      if (node.id === 'gw-01' || node.id === 'sv-03' || node.id === 'nw-01') {
        pz = 1.0;  // Front edge gateway tier
      } else if (node.id === 'db-01' || node.id === 'db-02') {
        pz = -1.0; // Secure storage tier
      } else {
        pz = 0.0;  // Core middleware application tier
      }
      return new THREE.Vector3(px, py, pz);
    };

    // Store calculated positions
    RISK_NODES.forEach(node => {
      nodePositionMap.set(node.id, get3DNodePosition(node));
    });

    // 4. Create Node Objects (Gem-like Dodecahedrons)
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    RISK_NODES.forEach((node) => {
      const pos = nodePositionMap.get(node.id)!;
      const color = node.vulnerable ? 0xef4444 : 0x22c55e;

      const nodeGeo = new THREE.DodecahedronGeometry(0.18);
      nodeGeometries.push(nodeGeo);

      const nodeMat = new THREE.MeshStandardMaterial({
        color: color,
        roughness: 0.15,
        metalness: 0.85,
        emissive: color,
        emissiveIntensity: 0.28
      });
      nodeMaterials.push(nodeMat);

      const mesh = new THREE.Mesh(nodeGeo, nodeMat);
      mesh.position.copy(pos);
      mesh.userData = { id: node.id };
      nodeGroup.add(mesh);
      nodeMeshes.push(mesh);

      // Rotating orbital cyber ring
      const ringGeo = new THREE.RingGeometry(0.24, 0.26, 32);
      nodeGeometries.push(ringGeo);
      const ringMat = new THREE.MeshBasicMaterial({
        color: color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.35
      });
      nodeMaterials.push(ringMat);
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 2;
      mesh.add(ringMesh);
    });

    // 5. Draw Attack Path Connections (Cyber Tubes)
    const connectionGroup = new THREE.Group();
    scene.add(connectionGroup);

    const pathLines: { mesh: THREE.Mesh; fromId: string; toId: string }[] = [];
    const pathParticles: { mesh: THREE.Mesh; fromId: string; toId: string; speed: number; offset: number }[] = [];

    ATTACK_PATHS.forEach((path, idx) => {
      const fromPos = nodePositionMap.get(path.from)!;
      const toPos = nodePositionMap.get(path.to)!;
      
      const distance = fromPos.distanceTo(toPos);
      const tubeColor = path.severity === 'critical' ? 0xef4444 : path.severity === 'high' ? 0xf97316 : 0xeab308;

      // Base tube created with unit height 1.0 to support real-time dynamic scaling
      const tubeGeo = new THREE.CylinderGeometry(0.012, 0.012, 1.0, 8);
      tubeGeo.translate(0, 0.5, 0); // Shift base pivot
      nodeGeometries.push(tubeGeo);

      const tubeMat = new THREE.MeshBasicMaterial({
        color: tubeColor,
        transparent: true,
        opacity: 0.18
      });
      nodeMaterials.push(tubeMat);

      const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
      tubeMesh.position.copy(fromPos);
      tubeMesh.scale.set(1, distance, 1);

      const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
      const defaultUp = new THREE.Vector3(0, 1, 0);
      tubeMesh.quaternion.setFromUnitVectors(defaultUp, direction);
      connectionGroup.add(tubeMesh);

      pathLines.push({
        mesh: tubeMesh,
        fromId: path.from,
        toId: path.to
      });

      // Add floating attack/data signal packets
      const packetCount = 2;
      for (let p = 0; p < packetCount; p++) {
        const particleGeo = new THREE.SphereGeometry(0.038, 8, 8);
        nodeGeometries.push(particleGeo);

        const particleMat = new THREE.MeshBasicMaterial({
          color: tubeColor,
          transparent: true,
          opacity: 0.95
        });
        nodeMaterials.push(particleMat);

        const particleMesh = new THREE.Mesh(particleGeo, particleMat);
        scene.add(particleMesh);

        pathParticles.push({
          mesh: particleMesh,
          fromId: path.from,
          toId: path.to,
          speed: 0.45 + Math.random() * 0.25,
          offset: p * 0.5 + Math.random() * 0.15
        });
      }
    });

    // 6. Lighting configuration
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.18);
    scene.add(ambientLight);

    const leftSun = new THREE.DirectionalLight(0x00f3ff, 2.5); // vibrant futuristic cyan
    leftSun.position.set(-6, 3, 5);
    scene.add(leftSun);

    const rightSun = new THREE.DirectionalLight(0xffd36b, 2.0); // golden fill
    rightSun.position.set(6, -3, 5);
    scene.add(rightSun);

    // 7. Interactive dragging & raycasting state
    const raycaster = new THREE.Raycaster();
    const dragPlane = new THREE.Plane();
    const dragIntersection = new THREE.Vector3();
    let draggedNode: THREE.Mesh | null = null;
    let isDraggingNode = false;

    // Track mouse coordinate helpers
    const getNormalizedMouseCoords = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      return new THREE.Vector2(x, y);
    };

    const handleMouseDown = (e: MouseEvent) => {
      const mouse = getNormalizedMouseCoords(e);
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        draggedNode = intersects[0].object as THREE.Mesh;
        isDraggingNode = true;

        const nodeId = draggedNode.userData.id;
        const nodeData = RISK_NODES.find(n => n.id === nodeId)!;

        // Visual click feed (scale node up momentarily)
        nodeMeshes.forEach(mesh => mesh.scale.set(1, 1, 1));
        draggedNode.scale.set(1.4, 1.4, 1.4);

        setSelectedNode(nodeData);

        // Position mathematical drag plane facing camera at the dragged node's depth
        const nodeWorldPos = new THREE.Vector3();
        draggedNode.getWorldPosition(nodeWorldPos);

        const cameraDir = new THREE.Vector3();
        camera.getWorldDirection(cameraDir);
        // Plane perpendicular to camera direction facing the node
        dragPlane.setFromNormalAndCoplanarPoint(cameraDir.negate(), nodeWorldPos);
      } else {
        // Clear selection if clicking on empty space
        nodeMeshes.forEach(mesh => mesh.scale.set(1, 1, 1));
        setSelectedNode(null);
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingNode || !draggedNode) return;

      const mouse = getNormalizedMouseCoords(e);
      raycaster.setFromCamera(mouse, camera);

      if (raycaster.ray.intersectPlane(dragPlane, dragIntersection)) {
        // Convert world intersection back to parent node group's local coordinates
        const localPos = dragIntersection.clone();
        nodeGroup.worldToLocal(localPos);

        // Clamp positions slightly to prevent dragging off-screen
        localPos.x = Math.max(-3.5, Math.min(3.5, localPos.x));
        localPos.y = Math.max(-2.5, Math.min(2.5, localPos.y));

        draggedNode.position.copy(localPos);

        // Update coordinate map so connectivity lines track instantly
        nodePositionMap.set(draggedNode.userData.id, localPos.clone());
      }
    };

    const handleMouseUp = () => {
      isDraggingNode = false;
      draggedNode = null;
    };

    canvas.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    // ESC key listener to clear detail view
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        nodeMeshes.forEach(mesh => mesh.scale.set(1, 1, 1));
        setSelectedNode(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    // 8. Size Resize Observer
    const sizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height, false);
      }
    });
    sizeObserver.observe(canvas.parentElement || canvas);

    // 9. Frame Render loop
    let animId = 0;
    const renderLoop = () => {
      animId = requestAnimationFrame(renderLoop);
      const time = Date.now() * 0.001;

      // Gentle continuous 3D idle rotation (only rotate when not actively dragging to facilitate user focus)
      if (!isDraggingNode) {
        nodeGroup.rotation.y = Math.sin(time * 0.15) * 0.15;
        nodeGroup.rotation.x = Math.cos(time * 0.15) * 0.12;

        connectionGroup.rotation.y = nodeGroup.rotation.y;
        connectionGroup.rotation.x = nodeGroup.rotation.x;
      }

      // Spin internal node orbital rings
      nodeMeshes.forEach((mesh) => {
        mesh.children.forEach(ring => {
          ring.rotation.z = time * 1.5;
        });
      });

      // Update cyber connection tubes dynamically to track dragged coordinates
      pathLines.forEach((line) => {
        const fromPos = nodePositionMap.get(line.fromId)!;
        const toPos = nodePositionMap.get(line.toId)!;
        
        const distance = fromPos.distanceTo(toPos);
        line.mesh.scale.set(1, distance, 1);
        line.mesh.position.copy(fromPos);
        
        const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
        const defaultUp = new THREE.Vector3(0, 1, 0);
        line.mesh.quaternion.setFromUnitVectors(defaultUp, direction);
      });

      // Drive glowing telemetry attack packets along paths dynamically
      pathParticles.forEach((packet) => {
        const fromPos = nodePositionMap.get(packet.fromId)!;
        const toPos = nodePositionMap.get(packet.toId)!;
        const progress = ((time * packet.speed) + packet.offset) % 1.0;
        
        const currentPos = new THREE.Vector3().lerpVectors(fromPos, toPos, progress);
        
        // Offset particle position to account for parent node group rotation
        currentPos.applyEuler(nodeGroup.rotation);
        packet.mesh.position.copy(currentPos);

        const pScale = 0.8 + Math.sin(time * 6.0 + packet.offset) * 0.2;
        packet.mesh.scale.set(pScale, pScale, pScale);
      });

      renderer.render(scene, camera);
    };
    renderLoop();

    // 10. Memory cleanups
    return () => {
      cancelAnimationFrame(animId);
      sizeObserver.disconnect();
      canvas.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      window.removeEventListener('keydown', handleKeyDown);

      nodeMeshes.forEach(mesh => mesh.scale.set(1, 1, 1));
      nodeGeometries.forEach(geo => geo.dispose());
      nodeMaterials.forEach(mat => mat.dispose());
      renderer.dispose();
    };
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      setTelemetry(prev => ({
        scansPerMin: prev.scansPerMin + Math.floor(Math.random() * 5 - 2),
        threatsBlocked: prev.threatsBlocked + Math.floor(Math.random() * 3),
        keysRotated: prev.keysRotated + (Math.random() > 0.7 ? 1 : 0),
        assetsMonitored: prev.assetsMonitored + (Math.random() > 0.9 ? 1 : 0),
      }));
      setRiskScore(prev => Math.max(0, Math.min(1000, prev + Math.floor(Math.random() * 7 - 3))));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const pulseInterval = setInterval(() => {
      setActivePulse(p => (p + 1) % ATTACK_PATHS.length);
    }, 1800);
    return () => clearInterval(pulseInterval);
  }, []);

  const riskColor = riskScore > 700 ? 'text-green-400' : riskScore > 400 ? 'text-yellow-400' : 'text-red-400';
  const riskLabel = riskScore > 700 ? 'QUANTUM SAFE' : riskScore > 400 ? 'AT RISK' : 'CRITICAL';

  return (
    <div className="p-6 lg:p-8 space-y-6 min-h-screen">
      {/* Header */}
      <header className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black uppercase tracking-tight text-white">
            Quantum Risk <span className="text-gold">Overview</span>
          </h1>
          <p className="text-white/50 mt-1 text-sm">Enterprise-wide quantum threat posture and real-time attack surface analysis.</p>
        </div>
        <div className="flex gap-3 items-center">
          <div className="px-4 py-2 border border-gold/30 bg-gold/5 rounded-lg text-[10px] font-black text-gold uppercase tracking-[0.2em] flex items-center gap-2">
            <Radio className="h-3 w-3 animate-pulse" />
            SSE Live Feed
          </div>
          <div className="px-4 py-2 border border-green-500/30 bg-green-500/5 rounded-lg text-[10px] font-black text-green-400 uppercase tracking-[0.2em] flex items-center gap-2">
            <Activity className="h-3 w-3 animate-pulse" />
            Telemetry Active
          </div>
        </div>
      </header>

      {/* Top KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Q-Risk Score', value: riskScore, icon: Shield, color: riskColor, suffix: '/1000', trend: riskScore > 650 ? '+12' : '-8' },
          { label: 'Scans/min', value: telemetry.scansPerMin, icon: Eye, color: 'text-cyan-400', trend: '+3' },
          { label: 'Threats Blocked', value: telemetry.threatsBlocked.toLocaleString(), icon: Zap, color: 'text-gold', trend: '+47' },
          { label: 'Keys Rotated', value: telemetry.keysRotated.toLocaleString(), icon: Lock, color: 'text-purple-400', trend: '+2' },
        ].map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.08 }}
            className={GLASS_PANEL_CLASSES + " p-5"}
          >
            <div className="absolute inset-0 bg-gradient-to-br from-gold/[0.03] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            <div className="absolute top-3 right-3 opacity-[0.06] group-hover:opacity-[0.12] transition-opacity">
              <card.icon className="h-12 w-12" />
            </div>
            <div className="relative z-10">
              <div className="flex items-center gap-2 mb-3">
                <card.icon className="h-3.5 w-3.5 text-gold/60" />
                <span className="text-[10px] font-black uppercase tracking-[0.18em] text-white/40">{card.label}</span>
              </div>
              <div className={`text-3xl font-black tracking-tight ${card.color}`}>
                {card.value}<span className="text-sm text-white/20 ml-1">{card.suffix || ''}</span>
              </div>
              <div className="mt-2 flex items-center gap-1 text-[10px] font-bold text-green-400/70">
                <TrendingUp className="h-3 w-3" /> {card.trend} this hour
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid lg:grid-cols-5 gap-6">
        {/* 3D Globe */}
        <div className={GLASS_PANEL_CLASSES + " lg:col-span-2 p-6"}>
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(212,175,55,0.06),transparent_60%)]" />
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-4 relative z-10">
            <Globe className="h-3.5 w-3.5 inline mr-2 text-gold/60" />
            Global Threat Surface
          </h2>
          <div className="relative z-10 aspect-square max-h-[340px] mx-auto">
            <canvas ref={canvasRef} className="w-full h-full" />
          </div>
          <div className="relative z-10 mt-4 grid grid-cols-2 gap-2">
            <div className="flex items-center gap-2 text-[10px] text-white/40">
              <span className="h-2 w-2 rounded-full bg-red-500" /> Vulnerable ({RISK_NODES.filter(n => n.vulnerable).length})
            </div>
            <div className="flex items-center gap-2 text-[10px] text-white/40">
              <span className="h-2 w-2 rounded-full bg-green-500" /> Secured ({RISK_NODES.filter(n => !n.vulnerable).length})
            </div>
          </div>
        </div>

        {/* Attack Graph */}
        <div className={GLASS_PANEL_CLASSES + " lg:col-span-3 p-6 flex flex-col justify-between"}>
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(0,243,255,0.04),transparent_50%)]" />
          <div className="flex items-center justify-between mb-4 relative z-10">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60">
              <Target className="h-3.5 w-3.5 inline mr-2 text-gold/60" />
              Animated 3D Attack Graph
            </h2>
            <span className="text-[10px] font-bold text-gold/50 uppercase tracking-wider">
              {ATTACK_PATHS.length} Active Paths | Click Assets to Inspect
            </span>
          </div>
          <div className="relative z-10 h-[340px] rounded-lg border border-gold/10 overflow-hidden bg-[#0f1428]/45 flex">
            {/* The 3D Canvas */}
            <canvas ref={graphCanvasRef} className="w-full h-full cursor-pointer" />
            
            {/* Floating Glassmorphic Node Detail Panel overlay */}
            {selectedNode && (
              <motion.div
                initial={{ opacity: 0, x: 50 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 50 }}
                className="absolute right-3 top-3 bottom-3 w-72 rounded-lg border border-[#FFD36B]/30 bg-[#0f1428]/85 backdrop-blur-md shadow-2xl p-4 flex flex-col justify-between overflow-y-auto text-white z-20"
              >
                <div>
                  <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
                    <span className="text-[10px] font-mono tracking-wider text-gold/60">ASSET METADATA</span>
                    <button
                      onClick={() => setSelectedNode(null)}
                      className="text-white/40 hover:text-white transition-colors text-xs font-bold font-mono px-1.5 py-0.5 rounded hover:bg-white/5"
                    >
                      ✕
                    </button>
                  </div>
                  
                  <h3 className="text-sm font-black uppercase tracking-wider mb-1 flex items-center gap-1.5">
                    <span className="text-[10px] bg-gold/10 border border-gold/30 px-1.5 py-0.5 rounded text-gold/90 font-mono">{selectedNode.id}</span>
                    {selectedNode.label}
                  </h3>
                  
                  <div className="flex items-center gap-2 mb-4">
                    <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                      selectedNode.vulnerable 
                        ? 'border-red-500/30 bg-red-500/10 text-red-400' 
                        : 'border-green-500/30 bg-green-500/10 text-green-400'
                    }`}>
                      {selectedNode.vulnerable ? 'Vulnerable' : 'Quantum Safe'}
                    </span>
                    <span className="text-[10px] font-mono text-white/40 capitalize">{selectedNode.type} Asset</span>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <div className="text-[9px] uppercase tracking-wider text-white/30 font-bold mb-1">Current Risk Score</div>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-white/5 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${selectedNode.vulnerable ? 'bg-red-500' : 'bg-green-500'}`}
                            style={{ width: `${selectedNode.risk}%` }}
                          />
                        </div>
                        <span className={`font-mono text-xs font-black ${selectedNode.vulnerable ? 'text-red-400' : 'text-green-400'}`}>
                          {selectedNode.risk}/100
                        </span>
                      </div>
                    </div>

                    <div>
                      <div className="text-[9px] uppercase tracking-wider text-white/30 font-bold mb-1">Active Vulnerability Status</div>
                      <p className="text-xs text-white/60 leading-relaxed font-semibold">
                        {selectedNode.vulnerable 
                          ? 'Current session authorization utilizes standard ECDSA P-256 / RSA-2048 which lacks safety against Shor-algorithm cryptanalytic factoring models.' 
                          : 'Successfully migrated to ML-KEM-768 and ML-DSA-65 entropic hybrid structures. Confirmed secure against current adversarial harvesting models.'
                        }
                      </p>
                    </div>
                  </div>
                </div>

                <div className="border-t border-white/10 pt-3 mt-4">
                  <div className="text-[9px] uppercase tracking-wider text-white/30 font-bold mb-1">Mitigation Recommendation</div>
                  <p className="text-[11px] text-gold/70 leading-relaxed font-bold">
                    {selectedNode.vulnerable 
                      ? 'Deploy hybrid post-quantum key encapsulation mechanism (ML-KEM) scanner. Re-sign session payloads using Falcon/ML-DSA.' 
                      : 'No further action required. Telemetry collection is active and validating key entropy.'
                    }
                  </p>
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Risk Score Gauge */}
        <div className={GLASS_PANEL_CLASSES + " p-6"}>
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-6">
            <Crosshair className="h-3.5 w-3.5 inline mr-2 text-gold/60" />
            Composite Risk Gauge
          </h2>
          <div className="flex flex-col items-center">
            <div className="relative w-40 h-40">
              <svg className="w-full h-full" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
                <circle
                  cx="50" cy="50" r="42"
                  fill="none"
                  stroke="url(#riskGradient)"
                  strokeWidth="6"
                  strokeLinecap="round"
                  strokeDasharray={`${(riskScore / 1000) * 264} 264`}
                  transform="rotate(-90 50 50)"
                  className="transition-all duration-1000"
                />
                <defs>
                  <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#ef4444" />
                    <stop offset="50%" stopColor="#eab308" />
                    <stop offset="100%" stopColor="#22c55e" />
                  </linearGradient>
                </defs>
                <text x="50" y="46" textAnchor="middle" fill="white" fontSize="16" fontWeight="900" fontFamily="monospace">{riskScore}</text>
                <text x="50" y="58" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="5" fontWeight="700">/1000</text>
              </svg>
            </div>
            <div className={`mt-4 text-xs font-black uppercase tracking-[0.2em] ${riskColor}`}>
              {riskLabel}
            </div>
            <div className="mt-3 grid grid-cols-3 gap-4 w-full text-center">
              {[
                { label: 'RSA', count: 14, color: 'text-red-400' },
                { label: 'ECC', count: 8, color: 'text-yellow-400' },
                { label: 'PQC', count: 23, color: 'text-green-400' },
              ].map(item => (
                <div key={item.label}>
                  <div className={`text-lg font-black ${item.color}`}>{item.count}</div>
                  <div className="text-[9px] uppercase tracking-wider text-white/30 font-bold">{item.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live Threat Intelligence Feed */}
        <div className={GLASS_PANEL_CLASSES + " lg:col-span-2 p-6"}>
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_0%_0%,rgba(212,175,55,0.04),transparent_40%)]" />
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white/60 mb-4 relative z-10">
            <Radio className="h-3.5 w-3.5 inline mr-2 text-gold/60 animate-pulse" />
            Live Threat Intelligence Feed
          </h2>
          <div className="relative z-10 space-y-3 max-h-[280px] overflow-y-auto pr-2">
            {THREAT_FEEDS.map((feed, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1 }}
                className="flex gap-4 p-3 rounded-lg border border-gold/8 bg-white/[0.02] hover:bg-white/[0.04] transition-colors group"
              >
                <div className="flex flex-col items-center gap-1 shrink-0">
                  <span className="font-mono text-[10px] text-white/30">{feed.time}</span>
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: getSeverityColor(feed.severity) }}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="text-[9px] font-black uppercase tracking-wider px-2 py-0.5 rounded border"
                      style={{
                        color: getSeverityColor(feed.severity),
                        borderColor: getSeverityColor(feed.severity) + '40',
                        backgroundColor: getSeverityColor(feed.severity) + '10'
                      }}
                    >
                      {feed.severity}
                    </span>
                    <span className="text-[10px] text-gold/50 font-bold">{feed.source}</span>
                  </div>
                  <p className="text-xs text-white/60 group-hover:text-white/80 transition-colors truncate">{feed.msg}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
