// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Insight generation configuration with environment-based controls and extensible insight types
 */

export interface InsightType {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  confidence_threshold: number;
  priority: number;
  max_insights_per_batch: number;
}

export interface InsightGenerationRule {
  id: string;
  insight_type: string;
  condition: string;
  action: string;
  enabled: boolean;
  priority: number;
}

export interface InsightConfig {
  // Feature toggles
  enabled: boolean;
  environment_enabled: boolean;
  runtime_override: boolean;

  // Generation settings
  max_insights_per_item: number;
  max_insights_per_batch: number;
  min_confidence_threshold: number;
  processing_timeout_ms: number;
  parallel_processing: boolean;

  // Insight types
  insight_types: {
    patterns: InsightType;
    connections: InsightType;
    recommendations: InsightType;
    anomalies: InsightType;
    trends: InsightType;
    custom?: Record<string, InsightType>;
  };

  // Performance settings
  performance_impact_threshold: number; // percentage
  enable_caching: boolean;
  cache_ttl_seconds: number;
  enable_metrics: boolean;

  // Filtering and prioritization
  max_insight_length: number;
  include_metadata: boolean;
  filter_duplicates: boolean;
  prioritize_by_confidence: boolean;
}

export const DEFAULT_INSIGHT_CONFIG: InsightConfig = {
  enabled: false, // Default disabled for production safety
  environment_enabled: false,
  runtime_override: false,

  max_insights_per_item: 3,
  max_insights_per_batch: 10,
  min_confidence_threshold: 0.6,
  processing_timeout_ms: 5000,
  parallel_processing: true,

  insight_types: {
    patterns: {
      id: 'patterns',
      name: 'Pattern Recognition',
      description: 'Identify recurring patterns in knowledge items',
      enabled: true,
      confidence_threshold: 0.7,
      priority: 1,
      max_insights_per_batch: 3,
    },
    connections: {
      id: 'connections',
      name: 'Connection Analysis',
      description: 'Find relationships and connections between items',
      enabled: true,
      confidence_threshold: 0.6,
      priority: 2,
      max_insights_per_batch: 2,
    },
    recommendations: {
      id: 'recommendations',
      name: 'Action Recommendations',
      description: 'Suggest actions based on stored knowledge',
      enabled: true,
      confidence_threshold: 0.8,
      priority: 3,
      max_insights_per_batch: 2,
    },
    anomalies: {
      id: 'anomalies',
      name: 'Anomaly Detection',
      description: 'Detect unusual or unexpected patterns',
      enabled: false, // Disabled by default due to potential noise
      confidence_threshold: 0.9,
      priority: 4,
      max_insights_per_batch: 1,
    },
    trends: {
      id: 'trends',
      name: 'Trend Analysis',
      description: 'Identify trends in knowledge changes over time',
      enabled: false, // Requires historical data
      confidence_threshold: 0.7,
      priority: 5,
      max_insights_per_batch: 2,
    },
  },

  performance_impact_threshold: 5, // 5% max performance impact
  enable_caching: true,
  cache_ttl_seconds: 3600,
  enable_metrics: true,

  max_insight_length: 280,
  include_metadata: true,
  filter_duplicates: true,
  prioritize_by_confidence: true,
};
