/**
 * Quantum Visualization Engine™ (QVE) — public surface.
 *
 * Consumers should import from here, not from the internals: the engine's
 * subsystems (event store, beam renderer, particle engine, core, timeline,
 * performance and audio managers) are free to move behind this barrel.
 *
 *   Frontend
 *   └── Quantum Visualization Engine™
 *       ├── Beam Renderer          beams/BeamNetwork + beams/beam-geometry
 *       ├── Quantum Core           core/QuantumCore3D + core/CoreStage + core/ScoreRing
 *       ├── Particle Engine        packets/PacketEngine + background/ParticleField
 *       ├── Event Timeline         timeline/ScanTimeline
 *       ├── Node State Manager     scan-event-store
 *       ├── Animation Controller   use-scan-event-bridge
 *       ├── Audio Manager          audio-manager
 *       └── Performance Manager    performance-manager
 */

export { QuantumScanHero, type QuantumScanHeroProps } from './QuantumScanHero';

export {
  QveProvider,
  useQve,
  useQveState,
  QVE_NODE_BLUEPRINTS,
  QVE_LEFT_NODES,
  QVE_RIGHT_NODES,
  type NodeBlueprint,
} from './scan-event-store';
export { useScanEventBridge, type ScanEventBridgeInput } from './use-scan-event-bridge';
export { reportEvidenceEvents, scanStartedEvent, stageTransitionEvents } from './event-derivation';
export { useQveBudget, useAdaptiveDpr, type QveBudget, type QveTier } from './performance-manager';
export { useQveAudio, cueForSeverity, type QveCue } from './audio-manager';

export { CoreStage, type CoreStageProps } from './core/CoreStage';
export { ScoreRing, type ScoreRingProps } from './core/ScoreRing';
export { BeamNetwork, type BeamNetworkProps } from './beams/BeamNetwork';
export { buildBeamPath, pointOnPolyline, type BeamAnchor, type BeamPath, type BeamTarget } from './beams/beam-geometry';
export { PacketEngine, type PacketBurst, type PacketEngineHandle } from './packets/PacketEngine';
export { QuantumBackdrop, type QuantumBackdropProps } from './background/QuantumBackdrop';
export { buildWorldDots, type WorldDot } from './background/world-grid';
export { CategoryNode, type CategoryNodeProps } from './nodes/CategoryNode';
export { NodeInspector, type NodeInspectorProps } from './nodes/NodeInspector';
export { ScanTicker, ScanTimeline } from './timeline/ScanTimeline';
export { InfrastructureStrip, buildInfraTiles, type InfraTile } from './strip/InfrastructureStrip';

export {
  beamColor,
  gradeWaveColors,
  isAlertSeverity,
  maxSeverity,
  QVE_COLOR,
  type QveNode,
  type QveNodeKey,
  type QvePublicNodeKey,
  type QveNodeState,
  type QveRunState,
  type QveState,
  type QveTimelineEntry,
  type ScanEvent,
  type ScanEventSeverity,
  type ScanEventStatus,
  type ScanEventType,
} from './types';
