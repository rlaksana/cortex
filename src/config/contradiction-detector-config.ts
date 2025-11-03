/**
 * Configuration for contradiction detection system
 */

export interface ContradictionDetectorConfig {
  enabled: boolean;
  sensitivity: 'conservative' | 'balanced' | 'aggressive';
  auto_flag: boolean;
  batch_checking: boolean;
  performance_monitoring: boolean;
  cache_results: boolean;
  cache_ttl_ms: number;
  max_items_per_check: number;
  timeout_ms: number;
}

export const DEFAULT_CONTRADICTION_CONFIG: ContradictionDetectorConfig = {
  enabled: true,
  sensitivity: 'balanced',
  auto_flag: false,
  batch_checking: true,
  performance_monitoring: true,
  cache_results: true,
  cache_ttl_ms: 300000, // 5 minutes
  max_items_per_check: 100,
  timeout_ms: 5000,
};

export interface ContradictionType {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  weight: number;
  sensitivity_modifier: number;
}

export interface ContradictionResult {
  detected: boolean;
  type?: ContradictionType;
  confidence: number;
  explanation?: string;
  entities: string[];
}

// Additional exports for compatibility
export function getContradictionDetectorConfig(): ContradictionDetectorConfig {
  return DEFAULT_CONTRADICTION_CONFIG;
}

export function getSensitivityThresholds(): Record<string, number> {
  return {
    conservative: 0.9,
    balanced: 0.7,
    aggressive: 0.5,
  };
}

export const DEFAULT_CONTRADICTION_TYPES: ContradictionType[] = [
  {
    id: 'factual',
    name: 'Factual Contradiction',
    description: 'Detects direct factual inconsistencies between statements',
    enabled: true,
    weight: 1.0,
    sensitivity_modifier: 1.0,
  },
  {
    id: 'temporal',
    name: 'Temporal Contradiction',
    description: 'Detects timeline and chronological inconsistencies',
    enabled: true,
    weight: 0.8,
    sensitivity_modifier: 0.9,
  },
  {
    id: 'logical',
    name: 'Logical Contradiction',
    description: 'Detects logical inconsistencies and mutual exclusions',
    enabled: true,
    weight: 0.9,
    sensitivity_modifier: 0.8,
  },
  {
    id: 'attribute',
    name: 'Attribute Contradiction',
    description: 'Detects conflicting attribute values for the same entity',
    enabled: true,
    weight: 0.7,
    sensitivity_modifier: 1.1,
  },
];

export interface ContradictionSafetyConfig {
  max_flags_per_item: number;
  max_contradictions_per_batch: number;
  quarantine_threshold: number;
  auto_disable_threshold: number;
  rate_limit_per_minute: number;
  memory_limit_mb: number;
  timeout_per_item_ms: number;
}

export const DEFAULT_CONTRADICTION_SAFETY_CONFIG: ContradictionSafetyConfig = {
  max_flags_per_item: 10,
  max_contradictions_per_batch: 100,
  quarantine_threshold: 0.8,
  auto_disable_threshold: 0.95,
  rate_limit_per_minute: 60,
  memory_limit_mb: 512,
  timeout_per_item_ms: 1000,
};
