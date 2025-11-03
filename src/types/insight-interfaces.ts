/**
 * Insight system interfaces for knowledge analysis and insight generation
 */

export interface Insight {
  id: string;
  type: string;
  title: string;
  description: string;
  confidence: number;
  priority: number;
  item_ids: string[];
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  metadata: {
    generated_at: string;
    generated_by: string;
    rule_id?: string;
    processing_time_ms: number;
    data_sources: string[];
    tags?: string[];
  };
  actionable: boolean;
  category: 'pattern' | 'connection' | 'recommendation' | 'anomaly' | 'trend' | 'custom';
}

export interface InsightGenerationRequest {
  items: Array<{
    id: string;
    kind: string;
    content?: string;
    data: Record<string, any>;
    scope: Record<string, any>;
    created_at?: string;
  }>;
  options: {
    enabled: boolean;
    insight_types: string[];
    max_insights_per_item: number;
    confidence_threshold: number;
    include_metadata: boolean;
    session_id?: string;
  };
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
}

export interface InsightGenerationResponse {
  insights: Insight[];
  metadata: {
    total_insights: number;
    insights_by_type: Record<string, number>;
    average_confidence: number;
    processing_time_ms: number;
    items_processed: number;
    insights_generated: number;
    performance_impact: number;
    cache_hit_rate: number;
    guardrails_applied?: {
      token_limits_enforced: boolean;
      deterministic_templates_applied: boolean;
      provenance_tracked: boolean;
      reproducible_outputs: boolean;
      correlation_id: string;
      token_violations: number;
      provenance_records: number;
    };
  };
  errors: Array<{
    item_id: string;
    error_type: string;
    message: string;
  }>;
  warnings: string[];
}

export interface PatternInsight extends Insight {
  category: 'pattern';
  pattern_data: {
    pattern_type: string;
    frequency: number;
    occurrences: Array<{
      item_id: string;
      context: string;
      confidence: number;
    }>;
    strength: number;
  };
}

export interface ConnectionInsight extends Insight {
  category: 'connection';
  connection_data: {
    connection_type: string;
    source_items: string[];
    target_items: string[];
    relationship_strength: number;
    connection_description: string;
  };
}

export interface RecommendationInsight extends Insight {
  category: 'recommendation';
  recommendation_data: {
    action_type: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    effort_estimate?: 'low' | 'medium' | 'high';
    impact_assessment?: 'low' | 'medium' | 'high';
    dependencies: string[];
    success_probability: number;
  };
}

export interface AnomalyInsight extends Insight {
  category: 'anomaly';
  anomaly_data: {
    anomaly_type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    baseline_data: any;
    deviation_score: number;
    potential_causes: string[];
  };
}

export interface TrendInsight extends Insight {
  category: 'trend';
  trend_data: {
    trend_direction: 'increasing' | 'decreasing' | 'stable' | 'volatile';
    trend_strength: number;
    time_period: {
      start: string;
      end: string;
    };
    data_points: Array<{
      timestamp: string;
      value: number;
      context: string;
    }>;
  };
}

export interface InsightGenerationRule {
  id: string;
  name: string;
  description: string;
  insight_type: string;
  condition: {
    field: string;
    operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'exists';
    value: any;
  };
  action: {
    type: 'generate_insight' | 'modify_confidence' | 'skip';
    parameters: Record<string, any>;
  };
  priority: number;
  enabled: boolean;
}

export interface InsightMetrics {
  total_insights_generated: number;
  insights_by_type: Record<string, number>;
  average_confidence: number;
  generation_success_rate: number;
  processing_time_avg: number;
  performance_impact_avg: number;
  cache_hit_rate: number;
  error_rate: number;
  last_updated: string;
}

export type InsightTypeUnion =
  | PatternInsight
  | ConnectionInsight
  | RecommendationInsight
  | AnomalyInsight
  | TrendInsight
  | Insight;
