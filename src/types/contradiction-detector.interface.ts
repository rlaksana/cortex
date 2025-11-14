// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Contradiction Detector Interface
 * MVP for detecting potential contradictions in stored knowledge
 */

import { type KnowledgeItem } from './core-interfaces.js';

// Re-export for other modules
export type { KnowledgeItem } from './core-interfaces.js';

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

export interface ContradictionType {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  weight: number;
  sensitivity_modifier: number;
}

export interface ContradictionResult {
  id: string;
  detected_at: Date;
  contradiction_type: string;
  confidence_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  primary_item_id: string;
  conflicting_item_ids: string[];
  description: string;
  reasoning: string;
  metadata: {
    detection_method: string;
    algorithm_version: string;
    processing_time_ms: number;
    comparison_details: Record<string, unknown>;
    evidence: Array<{
      item_id: string;
      evidence_type: string;
      content: string;
      confidence: number;
    }>;
  };
  resolution_suggestions: Array<{
    suggestion: string;
    priority: 'critical' | 'high' | 'medium' | 'low';
    effort: 'low' | 'medium' | 'high';
    description: string;
  }>;
}

export interface ContradictionDetectionRequest {
  items: KnowledgeItem[];
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  check_types?: string[];
  force_check?: boolean;
}

export interface ContradictionDetectionResponse {
  contradictions: ContradictionResult[];
  summary: {
    total_items_checked: number;
    contradictions_found: number;
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
    processing_time_ms: number;
    cache_hits: number;
    cache_misses: number;
  };
  performance: {
    items_per_second: number;
    memory_usage_mb: number;
    bottleneck_detected: boolean;
    bottlenecks: string[];
  };
}

export interface ContradictionFlag {
  item_id: string;
  flag_type: 'possible_contradiction';
  contradiction_ids: string[];
  flagged_at: Date;
  last_reviewed?: Date;
  review_status: 'pending' | 'acknowledged' | 'resolved' | 'false_positive';
  reviewer_id?: string;
  notes?: string;
}

export interface ContradictionPointer {
  source_id: string;
  target_id: string;
  pointer_type: 'contradicts' | 'conflicts_with' | 'supersedes' | 'relates_to';
  strength: number;
  created_at: Date;
  verified: boolean;
  metadata: Record<string, unknown>;
}

export interface ContradictionAnalysis {
  item_id: string;
  contradiction_count: number;
  contradiction_types: string[];
  severity_distribution: Record<string, number>;
  related_items: string[];
  trust_score: number;
  last_analysis: Date;
  analysis_details: {
    factual_consistency: number;
    temporal_consistency: number;
    logical_consistency: number;
    attribute_consistency: number;
  };
}

// Factual contradiction types
export interface FactualContradiction {
  type: 'factual';
  statements: Array<{
    item_id: string;
    statement: string;
    confidence: number;
    negation_markers?: string[];
    factuality_score: number;
  }>;
  conflict_type: 'direct_negation' | 'mutual_exclusion' | 'quantitative_conflict';
}

// Temporal contradiction types
export interface TemporalContradiction {
  type: 'temporal';
  timeline_conflicts: Array<{
    item_id: string;
    event_time: Date;
    temporal_certainty: 'certain' | 'approximate' | 'estimated';
    time_window?: {
      start: Date;
      end: Date;
    };
  }>;
  conflict_type: 'chronological_impossibility' | 'overlap_conflict' | 'duration_conflict';
}

// Logical contradiction types
export interface LogicalContradiction {
  type: 'logical';
  logical_conditions: Array<{
    item_id: string;
    condition: string;
    truth_value: boolean;
    certainty: number;
  }>;
  conflict_type: 'mutual_exclusion' | 'contrapositive_violation' | 'syllogism_break';
}

// Attribute contradiction types
export interface AttributeContradiction {
  type: 'attribute';
  attributes: Array<{
    item_id: string;
    attribute_name: string;
    attribute_value: unknown;
    confidence: number;
    source_reliability: number;
  }>;
  conflict_type: 'value_conflict' | 'type_conflict' | 'constraint_violation';
}

// Union type for all contradiction types
export type ContradictionDetail =
  | FactualContradiction
  | TemporalContradiction
  | LogicalContradiction
  | AttributeContradiction;

export interface ContradictionDetectorService {
  detectContradictions(
    request: ContradictionDetectionRequest
  ): Promise<ContradictionDetectionResponse>;
  flagContradictions(contradictions: ContradictionResult[]): Promise<ContradictionFlag[]>;
  analyzeItem(item_id: string): Promise<ContradictionAnalysis>;
  getContradictionPointers(item_id: string): Promise<ContradictionPointer[]>;
  batchCheck(
    items: KnowledgeItem[],
    options?: { chunk_size?: number; parallel?: boolean }
  ): Promise<ContradictionDetectionResponse>;
  validateContradiction(contradiction_id: string): Promise<boolean>;
  resolveContradiction(contradiction_id: string, resolution: string): Promise<void>;
  getConfiguration(): ContradictionDetectorConfig;
  updateConfiguration(config: Partial<ContradictionDetectorConfig>): Promise<void>;
}

export interface ContradictionDetectorMetrics {
  detection_accuracy: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
    precision: number;
    recall: number;
    f1_score: number;
  };
  performance_metrics: {
    average_detection_time_ms: number;
    throughput_items_per_second: number;
    memory_usage_mb: number;
    cache_hit_rate: number;
  };
  contradiction_distribution: {
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
    by_scope: Record<string, number>;
  };
  resolution_metrics: {
    average_resolution_time_hours: number;
    resolution_rate: number;
    false_positive_rate: number;
  };
}

// Event types for contradiction detection
export interface ContradictionEvent {
  type:
    | 'contradiction_detected'
    | 'contradiction_resolved'
    | 'contradiction_flagged'
    | 'contradiction_reviewed';
  timestamp: Date;
  item_id?: string;
  contradiction_id?: string;
  user_id?: string;
  metadata: Record<string, unknown>;
}

// Integration hooks for storage pipeline
export interface StoragePipelineHook {
  before_store?: (items: KnowledgeItem[]) => Promise<ContradictionDetectionRequest | null>;
  after_store?: (
    items: KnowledgeItem[],
    results: unknown[]
  ) => Promise<ContradictionDetectionResponse | null>;
  on_update?: (
    item_id: string,
    old_item: KnowledgeItem,
    new_item: KnowledgeItem
  ) => Promise<ContradictionDetectionResponse | null>;
  on_delete?: (item_id: string) => Promise<void>;
}

// Safety and validation interfaces
export interface ContradictionSafetyConfig {
  max_flags_per_item: number;
  max_contradictions_per_batch: number;
  quarantine_threshold: number;
  auto_disable_threshold: number;
  rate_limit_per_minute: number;
  memory_limit_mb: number;
  timeout_per_item_ms: number;
}

export interface ContradictionValidationRule {
  id: string;
  name: string;
  description: string;
  type: 'syntactic' | 'semantic' | 'logical' | 'temporal';
  condition: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
}

export interface ContradictionTestSuite {
  test_cases: Array<{
    id: string;
    name: string;
    description: string;
    items: KnowledgeItem[];
    expected_contradictions: number;
    expected_types: string[];
    expected_severity: string[];
    tolerance: number;
  }>;
  performance_tests: Array<{
    id: string;
    name: string;
    item_count: number;
    expected_max_time_ms: number;
    expected_max_memory_mb: number;
  }>;
  accuracy_tests: Array<{
    id: string;
    name: string;
    test_data: KnowledgeItem[];
    ground_truth: ContradictionResult[];
    metrics: ['precision', 'recall', 'f1'];
  }>;
}

// Contradiction strategy type for string literals
export type ContradictionStrategyType = 'semantic' | 'temporal' | 'logical' | 'factual' | 'procedural';

// Additional exports for compatibility
export interface ContradictionStrategy {
  id: string;
  name: string;
  description: string;
  algorithm: 'syntactic' | 'semantic' | 'logical' | 'temporal' | 'hybrid';
  enabled: boolean;
  weight: number;
  sensitivity_modifier: number;
  config: Record<string, unknown>;
}

export interface ContradictionScore {
  total_score: number;
  component_scores: {
    syntactic: number;
    semantic: number;
    logical: number;
    temporal: number;
  };
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reasoning: string;
  evidence: Array<{
    type: string;
    content: string;
    weight: number;
  }>;
}

export interface ResolutionSuggestion {
  id: string;
  type: 'merge' | 'split' | 'flag' | 'ignore' | 'escalate';
  priority: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  reasoning: string;
  steps: Array<{
    action: string;
    description: string;
    automated: boolean;
  }>;
  impact_assessment: {
    affected_items: string[];
    data_loss_risk: 'low' | 'medium' | 'high';
    user_impact: 'low' | 'medium' | 'high';
  };
  auto_applicable: boolean;
  requires_approval: boolean;
}
