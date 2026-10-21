import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

// Pre-allocated scratch objects to prevent GC in animation loop
const _vec3 = new THREE.Vector3();
const _rotTarget = new THREE.Vector3();

interface CyberThreatCore3DProps {
  currentThreatLevel?: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  onThreatSelect?: (level: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL') => void;
}

export const CyberThreatCore3D: React.FC<CyberThreatCore3DProps> = ({
  currentThreatLevel = 'CRITICAL',
  onThreatSelect
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [explodedRatio, setExplodedRatio] = useState(0.2);
  const [simulatedTier, setSimulatedTier] = useState<'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>(currentThreatLevel);
  const [autoRotateSpeed, setAutoRotateSpeed] = useState(1.0);
  const [wireframeMode, setWireframeMode] = useState(false);
  const [fpsInfo, setFpsInfo] = useState('60 FPS');

  // Mutable refs for Three.js render loop
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const partsRef = useRef<{
    shieldChassis?: THREE.Mesh;
    beveledRim?: THREE.Mesh;
    innerGimbal?: THREE.Group;
    ring1?: THREE.Mesh;
    ring2?: THREE.Mesh;
    coreSphere?: THREE.Mesh;
    sensorNodes?: THREE.InstancedMesh;
    energyBeams?: THREE.LineSegments;
    groundGrid?: THREE.GridHelper;
  }>({});

  const stateRef = useRef({
    explodedRatio: 0.2,
    simulatedTier: currentThreatLevel,
    autoRotateSpeed: 1.0,
    wireframeMode: false,
    isDragging: false,
    prevPointer: { x: 0, y: 0 },
    camTargetAngle: { x: 0.2, y: 0.4 },
    camCurrentAngle: { x: 0.2, y: 0.4 },
    camDistance: 8.5
  });

  // Keep stateRef in sync with state
  useEffect(() => {
    stateRef.current.explodedRatio = explodedRatio;
    stateRef.current.simulatedTier = simulatedTier;
    stateRef.current.autoRotateSpeed = autoRotateSpeed;
    stateRef.current.wireframeMode = wireframeMode;

    // Update material colors dynamically
    const parts = partsRef.current;
    let mainColor = 0x4cd7f6; // cyan
    let emissiveColor = 0x06b6d4;

    if (simulatedTier === 'CRITICAL') {
      mainColor = 0xffb4ab; // crimson
      emissiveColor = 0xef4444;
    } else if (simulatedTier === 'HIGH' || simulatedTier === 'MEDIUM') {
      mainColor = 0xfde047; // yellow
      emissiveColor = 0xeab308;
    } else {
      mainColor = 0x4edea3; // emerald
      emissiveColor = 0x10b981;
    }

    if (parts.coreSphere && parts.coreSphere.material instanceof THREE.MeshPhysicalMaterial) {
      parts.coreSphere.material.emissive.setHex(emissiveColor);
      parts.coreSphere.material.color.setHex(mainColor);
      parts.coreSphere.material.wireframe = wireframeMode;
    }
    if (parts.beveledRim && parts.beveledRim.material instanceof THREE.MeshStandardMaterial) {
      parts.beveledRim.material.emissive.setHex(emissiveColor);
      parts.beveledRim.material.wireframe = wireframeMode;
    }
    if (parts.ring1 && parts.ring1.material instanceof THREE.MeshStandardMaterial) {
      parts.ring1.material.wireframe = wireframeMode;
    }
    if (parts.ring2 && parts.ring2.material instanceof THREE.MeshStandardMaterial) {
      parts.ring2.material.wireframe = wireframeMode;
    }
  }, [explodedRatio, simulatedTier, autoRotateSpeed, wireframeMode]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // Detect software WebGL
    const isSoftwareGl = (() => {
      const gl = document.createElement('canvas').getContext('webgl2');
      if (!gl) return true;
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
      const gpu = String(gl.getParameter(param));
      gl.getExtension('WEBGL_lose_context')?.loseContext();
      return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
    })();

    // 1. Scene Setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0b1326);
    scene.fog = new THREE.FogExp2(0x0b1326, 0.045);
    sceneRef.current = scene;

    // 2. Camera Setup
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;
    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 100);
    camera.position.set(0, 2.5, 8.5);
    cameraRef.current = camera;

    // 3. Renderer Setup
    const renderer = new THREE.WebGLRenderer({
      antialias: !isSoftwareGl,
      powerPreference: 'high-performance',
      alpha: false
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    rendererRef.current = renderer;

    container.appendChild(renderer.domElement);

    // 4. Studio Environment Lighting via PMREMGenerator
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    scene.environment = pmremGenerator.fromScene(new RoomEnvironment(), 0.04).texture;
    pmremGenerator.dispose();

    // Key Light (Warm directional)
    const keyLight = new THREE.DirectionalLight(0xfff0e0, 2.8);
    keyLight.position.set(5, 8, 4);
    keyLight.castShadow = !isSoftwareGl;
    if (keyLight.shadow) {
      keyLight.shadow.mapSize.width = 1024;
      keyLight.shadow.mapSize.height = 1024;
      keyLight.shadow.bias = -0.0005;
      keyLight.shadow.normalBias = 0.02;
    }
    scene.add(keyLight);

    // Fill Light (Cool sky / ground)
    const hemiLight = new THREE.HemisphereLight(0x4cd7f6, 0x131b2e, 1.4);
    scene.add(hemiLight);

    // Rim Light (Backlight for specular rim sheen)
    const rimLight = new THREE.DirectionalLight(0x8b5cf6, 2.0);
    rimLight.position.set(-5, 3, -6);
    scene.add(rimLight);

    // 5. Procedural Textures (Zero external 404 dependencies)
    // Procedural Hex / Circuit texture for core bump
    const bumpCanvas = document.createElement('canvas');
    bumpCanvas.width = 256;
    bumpCanvas.height = 256;
    const ctx = bumpCanvas.getContext('2d')!;
    ctx.fillStyle = '#808080';
    ctx.fillRect(0, 0, 256, 256);
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 4;
    // Draw cyber circuitry lines
    ctx.beginPath();
    for (let i = 0; i < 256; i += 32) {
      ctx.moveTo(i, 0); ctx.lineTo(i, 256);
      ctx.moveTo(0, i); ctx.lineTo(256, i);
    }
    ctx.stroke();
    const proceduralBumpMap = new THREE.CanvasTexture(bumpCanvas);
    proceduralBumpMap.wrapS = THREE.RepeatWrapping;
    proceduralBumpMap.wrapT = THREE.RepeatWrapping;
    proceduralBumpMap.repeat.set(4, 4);

    // Radial contact shadow texture
    const shadowCanvas = document.createElement('canvas');
    shadowCanvas.width = 256;
    shadowCanvas.height = 256;
    const sCtx = shadowCanvas.getContext('2d')!;
    const grad = sCtx.createRadialGradient(128, 128, 10, 128, 128, 120);
    grad.addColorStop(0, 'rgba(0, 0, 0, 0.7)');
    grad.addColorStop(0.5, 'rgba(0, 0, 0, 0.3)');
    grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
    sCtx.fillStyle = grad;
    sCtx.fillRect(0, 0, 256, 256);
    const contactShadowTexture = new THREE.CanvasTexture(shadowCanvas);

    // Contact shadow plane
    const shadowGeo = new THREE.PlaneGeometry(6.5, 6.5);
    const shadowMat = new THREE.MeshBasicMaterial({
      map: contactShadowTexture,
      transparent: true,
      depthWrite: false,
      opacity: 0.8
    });
    const shadowMesh = new THREE.Mesh(shadowGeo, shadowMat);
    shadowMesh.rotation.x = -Math.PI / 2;
    shadowMesh.position.y = -1.6;
    scene.add(shadowMesh);

    // Coordinate Ground Grid
    const groundGrid = new THREE.GridHelper(14, 28, 0x4cd7f6, 0x1e293b);
    groundGrid.position.y = -1.61;
    scene.add(groundGrid);

    // 6. Composite 3-12 Part Procedural Model: Holographic Cyber Shield Core
    const cyberShieldGroup = new THREE.Group();
    cyberShieldGroup.position.y = 0;
    scene.add(cyberShieldGroup);

    // Part 1: Outer Hexagonal Shield Chassis (ExtrudeGeometry with bevels)
    const shieldShape = new THREE.Shape();
    const r = 2.4;
    for (let i = 0; i < 6; i++) {
      const angle = (i * Math.PI) / 3 - Math.PI / 6;
      const x = r * Math.cos(angle);
      const y = r * Math.sin(angle);
      if (i === 0) shieldShape.moveTo(x, y);
      else shieldShape.lineTo(x, y);
    }
    shieldShape.closePath();

    // Hollow out inner aperture
    const holePath = new THREE.Path();
    const rHole = 1.6;
    for (let i = 0; i < 6; i++) {
      const angle = (i * Math.PI) / 3 - Math.PI / 6;
      const x = rHole * Math.cos(angle);
      const y = rHole * Math.sin(angle);
      if (i === 0) holePath.moveTo(x, y);
      else holePath.lineTo(x, y);
    }
    holePath.closePath();
    shieldShape.holes.push(holePath);

    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, {
      depth: 0.28,
      bevelEnabled: true,
      bevelSegments: 4,
      steps: 1,
      bevelSize: 0.08,
      bevelThickness: 0.08
    });
    shieldGeo.center();

    // Dark Titanium Chassis Material
    const shieldMat = new THREE.MeshPhysicalMaterial({
      color: 0x1e293b,
      metalness: 0.9,
      roughness: 0.22,
      clearcoat: 0.8,
      clearcoatRoughness: 0.15
    });
    const shieldChassis = new THREE.Mesh(shieldGeo, shieldMat);
    shieldChassis.castShadow = !isSoftwareGl;
    shieldChassis.receiveShadow = !isSoftwareGl;
    cyberShieldGroup.add(shieldChassis);

    // Part 2: Neon Emissive Bevel Rim (Accent detail)
    const rimGeo = new THREE.TorusGeometry(2.45, 0.04, 16, 6);
    const rimMat = new THREE.MeshStandardMaterial({
      color: 0xffb4ab,
      emissive: 0xef4444,
      emissiveIntensity: 1.5,
      roughness: 0.1,
      metalness: 0.8
    });
    const beveledRim = new THREE.Mesh(rimGeo, rimMat);
    beveledRim.rotation.z = Math.PI / 6;
    cyberShieldGroup.add(beveledRim);

    // Part 3 & 4: Inner Counter-Rotating Gyroscopic Defense Rings
    const innerGimbal = new THREE.Group();
    cyberShieldGroup.add(innerGimbal);

    // Ring 1 (Lathe / Torus)
    const ring1Geo = new THREE.TorusGeometry(1.3, 0.05, 16, 48);
    const ring1Mat = new THREE.MeshStandardMaterial({
      color: 0x64748b,
      metalness: 0.95,
      roughness: 0.18
    });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    innerGimbal.add(ring1);

    // Ring 2 (Orthogonal angle)
    const ring2Geo = new THREE.TorusGeometry(1.05, 0.04, 16, 48);
    const ring2Mat = new THREE.MeshStandardMaterial({
      color: 0x8b5cf6,
      metalness: 0.85,
      roughness: 0.25
    });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    innerGimbal.add(ring2);

    // Part 5: Central Quantum Threat Core (Icosahedron with procedural bump & inner glow)
    const coreGeo = new THREE.IcosahedronGeometry(0.55, 1);
    const coreMat = new THREE.MeshPhysicalMaterial({
      color: 0xffb4ab,
      emissive: 0xef4444,
      emissiveIntensity: 1.2,
      roughness: 0.15,
      metalness: 0.3,
      bumpMap: proceduralBumpMap,
      bumpScale: 0.04
    });
    const coreSphere = new THREE.Mesh(coreGeo, coreMat);
    innerGimbal.add(coreSphere);

    // Part 6: Instanced Mesh for 12 Satellite Firewall Sensor Nodes
    const sensorGeo = new THREE.OctahedronGeometry(0.12);
    const sensorMat = new THREE.MeshStandardMaterial({
      color: 0x4cd7f6,
      emissive: 0x06b6d4,
      emissiveIntensity: 1.4,
      metalness: 0.8,
      roughness: 0.2
    });
    const nodeCount = 12;
    const sensorNodes = new THREE.InstancedMesh(sensorGeo, sensorMat, nodeCount);
    sensorNodes.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    cyberShieldGroup.add(sensorNodes);

    // Part 7: Dynamic Laser Containment Filaments (Energy Beams)
    const beamCoords: number[] = [];
    for (let i = 0; i < nodeCount; i++) {
      beamCoords.push(0, 0, 0); // center
      const angle = (i / nodeCount) * Math.PI * 2;
      beamCoords.push(Math.cos(angle) * 2.1, Math.sin(angle) * 2.1, 0);
    }
    const beamGeo = new THREE.BufferGeometry();
    beamGeo.setAttribute('position', new THREE.Float32BufferAttribute(beamCoords, 3));
    const beamMat = new THREE.LineBasicMaterial({
      color: 0x4cd7f6,
      transparent: true,
      opacity: 0.4
    });
    const energyBeams = new THREE.LineSegments(beamGeo, beamMat);
    cyberShieldGroup.add(energyBeams);

    // Store references
    partsRef.current = {
      shieldChassis,
      beveledRim,
      innerGimbal,
      ring1,
      ring2,
      coreSphere,
      sensorNodes,
      energyBeams,
      groundGrid
    };

    // 7. Interactive Mouse / Touch Drag Rotation
    const handlePointerDown = (e: MouseEvent | TouchEvent) => {
      stateRef.current.isDragging = true;
      const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
      const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
      stateRef.current.prevPointer = { x: clientX, y: clientY };
    };

    const handlePointerMove = (e: MouseEvent | TouchEvent) => {
      if (!stateRef.current.isDragging) return;
      const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
      const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;

      const deltaX = clientX - stateRef.current.prevPointer.x;
      const deltaY = clientY - stateRef.current.prevPointer.y;

      stateRef.current.camTargetAngle.y += deltaX * 0.008;
      stateRef.current.camTargetAngle.x = Math.max(-0.6, Math.min(1.2, stateRef.current.camTargetAngle.x + deltaY * 0.008));

      stateRef.current.prevPointer = { x: clientX, y: clientY };
    };

    const handlePointerUp = () => {
      stateRef.current.isDragging = false;
    };

    const domElement = renderer.domElement;
    domElement.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('mousemove', handlePointerMove);
    window.addEventListener('mouseup', handlePointerUp);

    domElement.addEventListener('touchstart', handlePointerDown, { passive: true });
    window.addEventListener('touchmove', handlePointerMove, { passive: true });
    window.addEventListener('touchend', handlePointerUp);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth || 800;
      const h = container.clientHeight || 500;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    // 8. 60 FPS Lossless Animation Loop with Exponential Damping
    let frameId = 0;
    let clock = new THREE.Clock();
    let frameCount = 0;
    let lastFpsUpdate = 0;

    const dummyMatrix = new THREE.Matrix4();
    const dummyPos = new THREE.Vector3();
    const dummyScale = new THREE.Vector3(1, 1, 1);
    const dummyQuat = new THREE.Quaternion();

    function animate() {
      const delta = Math.min(clock.getDelta(), 0.1);
      const time = clock.getElapsedTime();

      // FPS calculation
      frameCount++;
      if (time - lastFpsUpdate >= 1.0) {
        setFpsInfo(`${Math.round(frameCount / (time - lastFpsUpdate))} FPS`);
        frameCount = 0;
        lastFpsUpdate = time;
      }

      const st = stateRef.current;

      // Exponential damping on camera angles (smooth physics momentum)
      const dampFactor = 1 - Math.exp(-8 * delta);
      st.camCurrentAngle.x += (st.camTargetAngle.x - st.camCurrentAngle.x) * dampFactor;
      st.camCurrentAngle.y += (st.camTargetAngle.y - st.camCurrentAngle.y) * dampFactor;

      // Compute camera orbit position
      const dist = st.camDistance;
      camera.position.x = dist * Math.sin(st.camCurrentAngle.y) * Math.cos(st.camCurrentAngle.x);
      camera.position.y = dist * Math.sin(st.camCurrentAngle.x) + 0.5;
      camera.position.z = dist * Math.cos(st.camCurrentAngle.y) * Math.cos(st.camCurrentAngle.x);
      camera.lookAt(0, 0, 0);

      // Auto-rotation
      if (!st.isDragging && st.autoRotateSpeed > 0) {
        st.camTargetAngle.y += 0.3 * st.autoRotateSpeed * delta;
      }

      // Kinematic animations on procedural sub-parts
      const parts = partsRef.current;
      const rotSpd = st.autoRotateSpeed;

      // Gimbal Rings counter-rotation
      if (parts.ring1) {
        parts.ring1.rotation.x = time * 0.8 * rotSpd;
        parts.ring1.rotation.y = time * 0.5 * rotSpd;
      }
      if (parts.ring2) {
        parts.ring2.rotation.y = -time * 1.1 * rotSpd;
        parts.ring2.rotation.z = time * 0.7 * rotSpd;
      }
      if (parts.coreSphere) {
        parts.coreSphere.rotation.y = time * 1.4 * rotSpd;
        // Breathing pulse
        const pulse = 1.0 + Math.sin(time * 3.5) * 0.06;
        parts.coreSphere.scale.set(pulse, pulse, pulse);
      }

      // Exploded View kinematics: smooth separation along Z & radial axes
      const explode = st.explodedRatio;
      if (parts.shieldChassis) {
        parts.shieldChassis.position.z = THREE.MathUtils.damp(parts.shieldChassis.position.z, explode * 1.5, 6, delta);
      }
      if (parts.beveledRim) {
        parts.beveledRim.position.z = THREE.MathUtils.damp(parts.beveledRim.position.z, explode * 2.2, 6, delta);
      }
      if (parts.innerGimbal) {
        parts.innerGimbal.position.z = THREE.MathUtils.damp(parts.innerGimbal.position.z, -explode * 1.8, 6, delta);
      }

      // Orbiting Satellite Nodes
      if (parts.sensorNodes) {
        for (let i = 0; i < nodeCount; i++) {
          const orbitAngle = time * 0.6 * rotSpd + (i / nodeCount) * Math.PI * 2;
          const orbitRadius = 2.2 + Math.sin(time * 2 + i) * 0.15 + explode * 1.2;
          const nodeZ = Math.sin(orbitAngle * 2) * 0.3;

          dummyPos.set(Math.cos(orbitAngle) * orbitRadius, Math.sin(orbitAngle) * orbitRadius, nodeZ);
          dummyQuat.setFromAxisAngle(_vec3.set(1, 1, 0).normalize(), time * 2 + i);
          dummyMatrix.compose(dummyPos, dummyQuat, dummyScale);
          parts.sensorNodes.setMatrixAt(i, dummyMatrix);
        }
        parts.sensorNodes.instanceMatrix.needsUpdate = true;
      }

      renderer.render(scene, camera);
      frameId = requestAnimationFrame(animate);
    }

    animate();

    // Cleanup
    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('resize', handleResize);
      domElement.removeEventListener('mousedown', handlePointerDown);
      window.removeEventListener('mousemove', handlePointerMove);
      window.removeEventListener('mouseup', handlePointerUp);
      domElement.removeEventListener('touchstart', handlePointerDown);
      window.removeEventListener('touchmove', handlePointerMove);
      window.removeEventListener('touchend', handlePointerUp);

      renderer.dispose();
      contactShadowTexture.dispose();
      proceduralBumpMap.dispose();
      shieldGeo.dispose();
      shieldMat.dispose();
      rimGeo.dispose();
      rimMat.dispose();
      ring1Geo.dispose();
      ring1Mat.dispose();
      ring2Geo.dispose();
      ring2Mat.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      sensorGeo.dispose();
      sensorMat.dispose();
      beamGeo.dispose();
      beamMat.dispose();

      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  const handleResetCamera = () => {
    stateRef.current.camTargetAngle = { x: 0.2, y: 0.4 };
    stateRef.current.camDistance = 8.5;
  };

  const handleThreatTierChange = (tier: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL') => {
    setSimulatedTier(tier);
    if (onThreatSelect) onThreatSelect(tier);
  };

  return (
    <div className="relative w-full h-[540px] rounded-xl overflow-hidden bg-[#060e20] border border-cyan-500/30 shadow-[0_0_30px_rgba(6,182,212,0.15)] flex flex-col justify-between select-none">
      {/* 3D WebGL Canvas Container */}
      <div ref={mountRef} className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Top HUD Badges */}
      <div className="relative z-10 flex items-center justify-between p-4 pointer-events-none">
        <div className="flex items-center gap-2 bg-[#0b1326]/90 border border-slate-700/50 px-3 py-1.5 rounded-lg pointer-events-auto">
          <span className="h-2 w-2 rounded-full bg-cyan-400" />
          <span className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider">
            3D HOLOGRAPHIC THREAT CORE
          </span>
          <span className="text-[10px] font-mono text-slate-400 border-l border-slate-700 pl-2">
            PBR Studio • {fpsInfo}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleResetCamera}
            className="pointer-events-auto px-2.5 py-1 rounded bg-[#131b2e]/90 hover:bg-[#1e293b] text-slate-300 hover:text-cyan-400 border border-slate-700/60 text-xs font-mono transition-colors"
            title="Reset 3D Camera View"
          >
            Reset Angle
          </button>
          <button
            onClick={() => setWireframeMode(!wireframeMode)}
            className={`pointer-events-auto px-2.5 py-1 rounded border text-xs font-mono transition-colors ${
              wireframeMode
                ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300'
                : 'bg-[#131b2e]/90 border-slate-700/60 text-slate-300 hover:text-cyan-400'
            }`}
          >
            {wireframeMode ? 'Shaded View' : 'Wireframe'}
          </button>
        </div>
      </div>

      {/* Viewport-First Collapsible Bottom Control Dock */}
      <div className="relative z-10 w-full flex flex-col items-center pb-3 px-4 pointer-events-none">
        {/* Toggle Collapse/Expand Tab */}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="pointer-events-auto -mb-px px-4 py-1 rounded-t-lg bg-[#0f172a] hover:bg-[#1e293b] border-t border-x border-cyan-500/30 text-[11px] font-mono text-cyan-300 flex items-center gap-1.5 transition-all shadow-md"
        >
          <span>{isCollapsed ? '▴ Expand 3D Control Dock' : '▾ Collapse Dock (Zen Mode)'}</span>
        </button>

        {/* Floating Dock Surface */}
        {!isCollapsed && (
          <div className="pointer-events-auto w-full max-w-4xl bg-[#0f172a]/95 border border-cyan-500/30 rounded-xl p-3.5 shadow-2xl transition-all">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
              {/* Threat Tier Simulation Swatches */}
              <div>
                <span className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                  SIMULATE INCIDENT VECTOR
                </span>
                <div className="grid grid-cols-4 gap-1.5 text-xs font-mono">
                  <button
                    onClick={() => handleThreatTierChange('SAFE')}
                    className={`px-2 py-1.5 rounded text-center transition-all ${
                      simulatedTier === 'SAFE'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-400 font-bold'
                        : 'bg-[#1e293b] text-slate-400 hover:text-emerald-300'
                    }`}
                  >
                    SAFE
                  </button>
                  <button
                    onClick={() => handleThreatTierChange('MEDIUM')}
                    className={`px-2 py-1.5 rounded text-center transition-all ${
                      simulatedTier === 'MEDIUM'
                        ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-400 font-bold'
                        : 'bg-[#1e293b] text-slate-400 hover:text-yellow-300'
                    }`}
                  >
                    MEDIUM
                  </button>
                  <button
                    onClick={() => handleThreatTierChange('HIGH')}
                    className={`px-2 py-1.5 rounded text-center transition-all ${
                      simulatedTier === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-400 font-bold'
                        : 'bg-[#1e293b] text-slate-400 hover:text-amber-300'
                    }`}
                  >
                    HIGH
                  </button>
                  <button
                    onClick={() => handleThreatTierChange('CRITICAL')}
                    className={`px-2 py-1.5 rounded text-center transition-all ${
                      simulatedTier === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-300 border border-red-400 font-bold'
                        : 'bg-[#1e293b] text-slate-400 hover:text-red-300'
                    }`}
                  >
                    CRIT
                  </button>
                </div>
              </div>

              {/* Exploded Architecture Separation Slider */}
              <div>
                <div className="flex justify-between text-[10px] font-mono uppercase text-slate-400 mb-1">
                  <span>Exploded Architecture</span>
                  <span className="text-cyan-400">{Math.round(explodedRatio * 100)}%</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.01"
                  value={explodedRatio}
                  onChange={(e) => setExplodedRatio(parseFloat(e.target.value))}
                  className="w-full accent-cyan-400 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
                />
              </div>

              {/* Kinematic Orbit Speed Slider */}
              <div>
                <div className="flex justify-between text-[10px] font-mono uppercase text-slate-400 mb-1">
                  <span>Orbit Speed Multiplier</span>
                  <span className="text-cyan-400">{autoRotateSpeed.toFixed(1)}x</span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="2.5"
                    step="0.1"
                    value={autoRotateSpeed}
                    onChange={(e) => setAutoRotateSpeed(parseFloat(e.target.value))}
                    className="flex-1 accent-cyan-400 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
                  />
                  <button
                    onClick={() => setAutoRotateSpeed(autoRotateSpeed > 0 ? 0 : 1.0)}
                    className="px-2 py-1 rounded bg-[#1e293b] text-[10px] font-mono text-slate-300 hover:text-cyan-300"
                  >
                    {autoRotateSpeed > 0 ? 'Pause' : 'Resume'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
