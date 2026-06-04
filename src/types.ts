export interface ScenarioStep {
  number: number;
  name: string;
  label: string;
  description: string;
  objective: string;
  status: 'completed' | 'active' | 'locked';
}

export interface LogEntry {
  id: string;
  timestamp: string;
  text: string;
  type: 'info' | 'success' | 'warning' | 'error';
}

export interface Threat {
  id: string;
  title: string;
  location: string;
  timeAgo: string;
  level: 'High' | 'Medium' | 'Low';
}

export interface AttackedAsset {
  id: string;
  name: string;
  type: string;
  size: string;
  bytes: number;
}

export type TargetType = string;

export interface SimulationState {
  isPlaying: boolean;
  activeScenarioIndex: number; // For future scenarios or step toggling
  activeStep: number; // 1 to 6
  activeTarget: TargetType;
  timeElapsed: number; // in seconds
  packetsCaptured: number;
  harvestedSizeGB: number; // starts at 2.45
  captureRateMBs: number; // ~2.45
  stealthLevel: number; // 0-100 (e.g., 85% high)
  detectionRisk: 'Low' | 'Medium' | 'High';
}
