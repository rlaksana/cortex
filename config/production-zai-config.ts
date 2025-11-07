/**
 * Production ZAI Configuration Management
 *
 * Production-ready configuration for ZAI services with comprehensive
 * environment support, validation, and security features:
 *
 * - Environment-specific configurations
 * - Feature flag management
 * - Circuit breaker configuration
 * - Performance tuning parameters
 * - Security and authentication settings
 * - Cost control and rate limiting
 * - Monitoring and observability settings
 * - Graceful degradation policies
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../src/utils/logger.js';
import type {
  ZAIConfig,
  AIOrchestratorConfig,
  BackgroundProcessorConfig,
} from '../src/types/zai-interfaces.js';

/**
 * Production ZAI Configuration
 */
export interface ProductionZAIConfig {
  /** Environment identification */
  environment: 'development' | 'staging' | 'production' | 'dr';

  /** AI service enablement */
  ai: {
    enabled: boolean;
    features: {
      insights: {
        enabled: boolean;
        strategies: string[];
        config: Record<string, unknown>;
      };
      contradiction_detection: {
        enabled: boolean;
        confidence_threshold: number;
        strategies: string[];
        config: Record<string, unknown>;
      };
      semantic_search: {
        enabled: boolean;
        embedding_model: string;
        similarity_threshold: number;
        config: Record<string, unknown>;
      };
      background_processing: {
        enabled: boolean;
        batch_size: number;
        processing_interval: number;
        max_queue_size: number;
      };
    };
  };

  /** ZAI API configuration */
  zai: {
    url: string;
    model: string;
    timeout: number;
    retries: number;
    retry_delay: number;
    circuit_breaker: {
      enabled: boolean;
      threshold: number;
      reset_timeout: number;
      monitoring_window: number;
    };
    rate_limiting: {
      enabled: boolean;
      requests_per_minute: number;
      requests_per_hour: number;
      burst_limit: number;
      backoff_strategy: 'exponential' | 'linear' | 'fixed';
    };
    authentication: {
      api_key: string;
      key_rotation_enabled: boolean;
      key_rotation_interval: number;
    };
  };

  /** Performance configuration */
  performance: {
    latency_targets: {
      insight_generation: number;
      contradiction_detection: number;
      semantic_search: number;
      background_processing: number;
    };
    throughput_targets: {
      operations_per_second: number;
      insights_per_minute: number;
      batch_processing: number;
    };
    resource_limits: {
      max_memory_usage_mb: number;
      max_cpu_usage_percent: number;
      max_concurrent_requests: number;
      max_queue_size: number;
    };
    caching: {
      enabled: boolean;
      ttl_seconds: number;
      max_size_mb: number;
      strategy: 'lru' | 'lfu' | 'fifo';
    };
  };

  /** Quality and reliability */
  quality: {
    accuracy_thresholds: {
      insight_generation: number;
      contradiction_detection: number;
      semantic_search: number;
    };
    confidence_thresholds: {
      insight_generation: number;
      contradiction_detection: number;
      semantic_search: number;
    };
    monitoring: {
      sample_rate: number;
      evaluation_interval: number;
      drift_detection: boolean;
      automated_retraining: boolean;
    };
    fallback: {
      enabled: boolean;
      fallback_models: string[];
      degrade_gracefully: boolean;
      user_notification: boolean;
    };
  };

  /** Cost control */
  cost: {
    daily_budget: number;
    monthly_budget: number;
    cost_per_operation: number;
    cost_tracking: {
      enabled: boolean;
      granularity: 'operation' | 'hour' | 'day';
      alerts: boolean;
    };
    optimization: {
      batch_processing: boolean;
      model_selection: 'always_fastest' | 'cost_optimized' | 'balanced';
      request_combining: boolean;
      caching_enabled: boolean;
    };
  };

  /** Security and compliance */
  security: {
    data_privacy: {
      anonymization: boolean;
      data_retention_days: number;
      audit_logging: boolean;
      encryption_at_rest: boolean;
      encryption_in_transit: boolean;
    };
    access_control: {
      rbac_enabled: boolean;
      api_key_scopes: string[];
      rate_limit_per_user: number;
      ip_whitelist: string[];
    };
    compliance: {
      gdpr_compliant: boolean;
      soc2_compliant: boolean;
      hipaa_compliant: boolean;
      audit_trail_retention_days: number;
    };
  };

  /** Monitoring and observability */
  monitoring: {
    enabled: boolean;
    metrics: {
      collection_interval: number;
      retention_days: number;
      export_formats: string[];
      prometheus_enabled: boolean;
    };
    health_checks: {
      enabled: boolean;
      interval: number;
      timeout: number;
      endpoints: string[];
    };
    alerting: {
      enabled: boolean;
      channels: string[];
      severity_thresholds: Record<string, string>;
      escalation_policy: boolean;
    };
    tracing: {
      enabled: boolean;
      sample_rate: number;
      export_format: 'jaeger' | 'zipkin' | 'otlp';
    };
  };

  /** Infrastructure and deployment */
  infrastructure: {
    deployment: {
      strategy: 'rolling' | 'blue_green' | 'canary';
      health_check_grace_period: number;
      rollback_timeout: number;
      max_unhealthy_percent: number;
    };
    scaling: {
      auto_scaling: boolean;
      min_instances: number;
      max_instances: number;
      scale_up_threshold: number;
      scale_down_threshold: number;
      cooldown_period: number;
    };
    high_availability: {
      enabled: boolean;
      availability_zones: string[];
      failover_timeout: number;
      disaster_recovery: boolean;
    };
  };
}

/**
 * Environment-specific configurations
 */
const productionConfigs: Record<string, ProductionZAIConfig> = {
  development: {
    environment: 'development',
    ai: {
      enabled: true,
      features: {
        insights: {
          enabled: true,
          strategies: ['pattern_recognition', 'knowledge_gap'],
          config: {
            max_items_per_batch: 10,
            timeout_ms: 5000,
          },
        },
        contradiction_detection: {
          enabled: true,
          confidence_threshold: 0.7,
          strategies: ['factual_verification', 'logical_contradiction'],
          config: {
            batch_size: 5,
            timeout_ms: 3000,
          },
        },
        semantic_search: {
          enabled: true,
          embedding_model: 'text-embedding-3-small',
          similarity_threshold: 0.7,
          config: {
            max_results: 20,
            timeout_ms: 2000,
          },
        },
        background_processing: {
          enabled: true,
          batch_size: 5,
          processing_interval: 30000, // 30 seconds
          max_queue_size: 100,
        },
      },
    },
    zai: {
      url: process.env['ZAI_URL'] || 'https://api.z.ai/api/anthropic',
      model: process.env['ZAI_MODEL'] || 'glm-4.6',
      timeout: 30000,
      retries: 2,
      retry_delay: 1000,
      circuit_breaker: {
        enabled: true,
        threshold: 3,
        reset_timeout: 30000,
        monitoring_window: 60000,
      },
      rate_limiting: {
        enabled: true,
        requests_per_minute: 100,
        requests_per_hour: 1000,
        burst_limit: 20,
        backoff_strategy: 'exponential',
      },
      authentication: {
        api_key: process.env['ZAI_API_KEY'] || '',
        key_rotation_enabled: false,
        key_rotation_interval: 86400000, // 24 hours
      },
    },
    performance: {
      latency_targets: {
        insight_generation: 10000, // 10 seconds
        contradiction_detection: 8000, // 8 seconds
        semantic_search: 2000, // 2 seconds
        background_processing: 60000, // 1 minute
      },
      throughput_targets: {
        operations_per_second: 5,
        insights_per_minute: 10,
        batch_processing: 2,
      },
      resource_limits: {
        max_memory_usage_mb: 512,
        max_cpu_usage_percent: 70,
        max_concurrent_requests: 10,
        max_queue_size: 100,
      },
      caching: {
        enabled: true,
        ttl_seconds: 300, // 5 minutes
        max_size_mb: 50,
        strategy: 'lru',
      },
    },
    quality: {
      accuracy_thresholds: {
        insight_generation: 0.7,
        contradiction_detection: 0.75,
        semantic_search: 0.8,
      },
      confidence_thresholds: {
        insight_generation: 0.6,
        contradiction_detection: 0.7,
        semantic_search: 0.75,
      },
      monitoring: {
        sample_rate: 1.0,
        evaluation_interval: 300000, // 5 minutes
        drift_detection: true,
        automated_retraining: false,
      },
      fallback: {
        enabled: true,
        fallback_models: [],
        degrade_gracefully: true,
        user_notification: true,
      },
    },
    cost: {
      daily_budget: 10, // $10 per day
      monthly_budget: 200, // $200 per month
      cost_per_operation: 0.01,
      cost_tracking: {
        enabled: true,
        granularity: 'operation',
        alerts: true,
      },
      optimization: {
        batch_processing: true,
        model_selection: 'balanced',
        request_combining: true,
        caching_enabled: true,
      },
    },
    security: {
      data_privacy: {
        anonymization: false,
        data_retention_days: 7,
        audit_logging: true,
        encryption_at_rest: false,
        encryption_in_transit: true,
      },
      access_control: {
        rbac_enabled: false,
        api_key_scopes: ['read', 'write'],
        rate_limit_per_user: 1000,
        ip_whitelist: [],
      },
      compliance: {
        gdpr_compliant: false,
        soc2_compliant: false,
        hipaa_compliant: false,
        audit_trail_retention_days: 7,
      },
    },
    monitoring: {
      enabled: true,
      metrics: {
        collection_interval: 30000, // 30 seconds
        retention_days: 7,
        export_formats: ['json'],
        prometheus_enabled: true,
      },
      health_checks: {
        enabled: true,
        interval: 60000, // 1 minute
        timeout: 10000, // 10 seconds
        endpoints: ['/health', '/health/ai', '/health/zai'],
      },
      alerting: {
        enabled: true,
        channels: ['console'],
        severity_thresholds: {
          critical: 'critical',
          warning: 'warning',
        },
        escalation_policy: false,
      },
      tracing: {
        enabled: false,
        sample_rate: 0.1,
        export_format: 'otlp',
      },
    },
    infrastructure: {
      deployment: {
        strategy: 'rolling',
        health_check_grace_period: 30000, // 30 seconds
        rollback_timeout: 300000, // 5 minutes
        max_unhealthy_percent: 50,
      },
      scaling: {
        auto_scaling: false,
        min_instances: 1,
        max_instances: 2,
        scale_up_threshold: 80,
        scale_down_threshold: 20,
        cooldown_period: 300000, // 5 minutes
      },
      high_availability: {
        enabled: false,
        availability_zones: ['us-east-1a'],
        failover_timeout: 60000, // 1 minute
        disaster_recovery: false,
      },
    },
  },

  staging: {
    environment: 'staging',
    ai: {
      enabled: true,
      features: {
        insights: {
          enabled: true,
          strategies: ['pattern_recognition', 'knowledge_gap', 'anomaly_detection'],
          config: {
            max_items_per_batch: 50,
            timeout_ms: 8000,
          },
        },
        contradiction_detection: {
          enabled: true,
          confidence_threshold: 0.8,
          strategies: ['factual_verification', 'logical_contradiction', 'semantic_contradiction'],
          config: {
            batch_size: 25,
            timeout_ms: 5000,
          },
        },
        semantic_search: {
          enabled: true,
          embedding_model: 'text-embedding-3-small',
          similarity_threshold: 0.75,
          config: {
            max_results: 50,
            timeout_ms: 3000,
          },
        },
        background_processing: {
          enabled: true,
          batch_size: 25,
          processing_interval: 15000, // 15 seconds
          max_queue_size: 500,
        },
      },
    },
    zai: {
      url: process.env['ZAI_URL'] || 'https://api.z.ai/api/anthropic',
      model: process.env['ZAI_MODEL'] || 'glm-4.6',
      timeout: 25000,
      retries: 3,
      retry_delay: 1500,
      circuit_breaker: {
        enabled: true,
        threshold: 5,
        reset_timeout: 45000,
        monitoring_window: 90000,
      },
      rate_limiting: {
        enabled: true,
        requests_per_minute: 300,
        requests_per_hour: 5000,
        burst_limit: 50,
        backoff_strategy: 'exponential',
      },
      authentication: {
        api_key: process.env['ZAI_API_KEY'] || '',
        key_rotation_enabled: true,
        key_rotation_interval: 172800000, // 48 hours
      },
    },
    performance: {
      latency_targets: {
        insight_generation: 8000, // 8 seconds
        contradiction_detection: 6000, // 6 seconds
        semantic_search: 1500, // 1.5 seconds
        background_processing: 30000, // 30 seconds
      },
      throughput_targets: {
        operations_per_second: 20,
        insights_per_minute: 50,
        batch_processing: 10,
      },
      resource_limits: {
        max_memory_usage_mb: 1024,
        max_cpu_usage_percent: 75,
        max_concurrent_requests: 25,
        max_queue_size: 500,
      },
      caching: {
        enabled: true,
        ttl_seconds: 900, // 15 minutes
        max_size_mb: 200,
        strategy: 'lru',
      },
    },
    quality: {
      accuracy_thresholds: {
        insight_generation: 0.8,
        contradiction_detection: 0.85,
        semantic_search: 0.85,
      },
      confidence_thresholds: {
        insight_generation: 0.7,
        contradiction_detection: 0.8,
        semantic_search: 0.8,
      },
      monitoring: {
        sample_rate: 0.5,
        evaluation_interval: 180000, // 3 minutes
        drift_detection: true,
        automated_retraining: true,
      },
      fallback: {
        enabled: true,
        fallback_models: ['gpt-3.5-turbo'],
        degrade_gracefully: true,
        user_notification: false,
      },
    },
    cost: {
      daily_budget: 100, // $100 per day
      monthly_budget: 2000, // $2000 per month
      cost_per_operation: 0.008,
      cost_tracking: {
        enabled: true,
        granularity: 'hour',
        alerts: true,
      },
      optimization: {
        batch_processing: true,
        model_selection: 'cost_optimized',
        request_combining: true,
        caching_enabled: true,
      },
    },
    security: {
      data_privacy: {
        anonymization: true,
        data_retention_days: 30,
        audit_logging: true,
        encryption_at_rest: true,
        encryption_in_transit: true,
      },
      access_control: {
        rbac_enabled: true,
        api_key_scopes: ['read', 'write', 'admin'],
        rate_limit_per_user: 5000,
        ip_whitelist: [],
      },
      compliance: {
        gdpr_compliant: true,
        soc2_compliant: false,
        hipaa_compliant: false,
        audit_trail_retention_days: 30,
      },
    },
    monitoring: {
      enabled: true,
      metrics: {
        collection_interval: 15000, // 15 seconds
        retention_days: 30,
        export_formats: ['json', 'prometheus'],
        prometheus_enabled: true,
      },
      health_checks: {
        enabled: true,
        interval: 30000, // 30 seconds
        timeout: 8000, // 8 seconds
        endpoints: ['/health', '/health/ai', '/health/zai', '/metrics'],
      },
      alerting: {
        enabled: true,
        channels: ['slack', 'email'],
        severity_thresholds: {
          critical: 'critical',
          warning: 'warning',
          info: 'info',
        },
        escalation_policy: true,
      },
      tracing: {
        enabled: true,
        sample_rate: 0.5,
        export_format: 'otlp',
      },
    },
    infrastructure: {
      deployment: {
        strategy: 'rolling',
        health_check_grace_period: 60000, // 1 minute
        rollback_timeout: 180000, // 3 minutes
        max_unhealthy_percent: 25,
      },
      scaling: {
        auto_scaling: true,
        min_instances: 2,
        max_instances: 5,
        scale_up_threshold: 70,
        scale_down_threshold: 30,
        cooldown_period: 180000, // 3 minutes
      },
      high_availability: {
        enabled: true,
        availability_zones: ['us-east-1a', 'us-east-1b'],
        failover_timeout: 30000, // 30 seconds
        disaster_recovery: true,
      },
    },
  },

  production: {
    environment: 'production',
    ai: {
      enabled: true,
      features: {
        insights: {
          enabled: true,
          strategies: [
            'pattern_recognition',
            'knowledge_gap',
            'anomaly_detection',
            'predictive_insight',
          ],
          config: {
            max_items_per_batch: 100,
            timeout_ms: 5000,
          },
        },
        contradiction_detection: {
          enabled: true,
          confidence_threshold: 0.85,
          strategies: [
            'factual_verification',
            'logical_contradiction',
            'semantic_contradiction',
            'temporal_contradiction',
          ],
          config: {
            batch_size: 50,
            timeout_ms: 3000,
          },
        },
        semantic_search: {
          enabled: true,
          embedding_model: 'text-embedding-3-large',
          similarity_threshold: 0.8,
          config: {
            max_results: 100,
            timeout_ms: 1000,
          },
        },
        background_processing: {
          enabled: true,
          batch_size: 50,
          processing_interval: 10000, // 10 seconds
          max_queue_size: 1000,
        },
      },
    },
    zai: {
      url: process.env['ZAI_URL'] || 'https://api.z.ai/api/anthropic',
      model: process.env['ZAI_MODEL'] || 'glm-4.6',
      timeout: 20000,
      retries: 3,
      retry_delay: 2000,
      circuit_breaker: {
        enabled: true,
        threshold: 5,
        reset_timeout: 60000,
        monitoring_window: 120000,
      },
      rate_limiting: {
        enabled: true,
        requests_per_minute: 1000,
        requests_per_hour: 20000,
        burst_limit: 100,
        backoff_strategy: 'exponential',
      },
      authentication: {
        api_key: process.env['ZAI_API_KEY'] || '',
        key_rotation_enabled: true,
        key_rotation_interval: 86400000, // 24 hours
      },
    },
    performance: {
      latency_targets: {
        insight_generation: 5000, // 5 seconds
        contradiction_detection: 4000, // 4 seconds
        semantic_search: 1000, // 1 second
        background_processing: 15000, // 15 seconds
      },
      throughput_targets: {
        operations_per_second: 100,
        insights_per_minute: 200,
        batch_processing: 50,
      },
      resource_limits: {
        max_memory_usage_mb: 2048,
        max_cpu_usage_percent: 80,
        max_concurrent_requests: 100,
        max_queue_size: 1000,
      },
      caching: {
        enabled: true,
        ttl_seconds: 1800, // 30 minutes
        max_size_mb: 500,
        strategy: 'lru',
      },
    },
    quality: {
      accuracy_thresholds: {
        insight_generation: 0.9,
        contradiction_detection: 0.95,
        semantic_search: 0.9,
      },
      confidence_thresholds: {
        insight_generation: 0.8,
        contradiction_detection: 0.85,
        semantic_search: 0.85,
      },
      monitoring: {
        sample_rate: 0.1,
        evaluation_interval: 60000, // 1 minute
        drift_detection: true,
        automated_retraining: true,
      },
      fallback: {
        enabled: true,
        fallback_models: ['gpt-3.5-turbo', 'claude-instant'],
        degrade_gracefully: true,
        user_notification: false,
      },
    },
    cost: {
      daily_budget: 1000, // $1000 per day
      monthly_budget: 20000, // $20000 per month
      cost_per_operation: 0.005,
      cost_tracking: {
        enabled: true,
        granularity: 'hour',
        alerts: true,
      },
      optimization: {
        batch_processing: true,
        model_selection: 'cost_optimized',
        request_combining: true,
        caching_enabled: true,
      },
    },
    security: {
      data_privacy: {
        anonymization: true,
        data_retention_days: 90,
        audit_logging: true,
        encryption_at_rest: true,
        encryption_in_transit: true,
      },
      access_control: {
        rbac_enabled: true,
        api_key_scopes: ['read', 'write', 'admin'],
        rate_limit_per_user: 10000,
        ip_whitelist: process.env['IP_WHITELIST']?.split(',') || [],
      },
      compliance: {
        gdpr_compliant: true,
        soc2_compliant: true,
        hipaa_compliant: process.env['HIPAA_COMPLIANT'] === 'true',
        audit_trail_retention_days: 2555, // 7 years
      },
    },
    monitoring: {
      enabled: true,
      metrics: {
        collection_interval: 10000, // 10 seconds
        retention_days: 90,
        export_formats: ['json', 'prometheus', 'influxdb'],
        prometheus_enabled: true,
      },
      health_checks: {
        enabled: true,
        interval: 15000, // 15 seconds
        timeout: 5000, // 5 seconds
        endpoints: ['/health', '/health/ai', '/health/zai', '/metrics', '/ready'],
      },
      alerting: {
        enabled: true,
        channels: ['slack', 'email', 'pagerduty'],
        severity_thresholds: {
          critical: 'critical',
          warning: 'warning',
          info: 'info',
        },
        escalation_policy: true,
      },
      tracing: {
        enabled: true,
        sample_rate: 0.01,
        export_format: 'otlp',
      },
    },
    infrastructure: {
      deployment: {
        strategy: 'canary',
        health_check_grace_period: 120000, // 2 minutes
        rollback_timeout: 120000, // 2 minutes
        max_unhealthy_percent: 10,
      },
      scaling: {
        auto_scaling: true,
        min_instances: 3,
        max_instances: 20,
        scale_up_threshold: 70,
        scale_down_threshold: 30,
        cooldown_period: 120000, // 2 minutes
      },
      high_availability: {
        enabled: true,
        availability_zones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
        failover_timeout: 15000, // 15 seconds
        disaster_recovery: true,
      },
    },
  },

  dr: {
    environment: 'dr',
    ai: {
      enabled: true,
      features: {
        insights: {
          enabled: true,
          strategies: ['pattern_recognition'], // Limited strategies for DR
          config: {
            max_items_per_batch: 20,
            timeout_ms: 15000, // Longer timeout
          },
        },
        contradiction_detection: {
          enabled: false, // Disabled in DR
          confidence_threshold: 0.7,
          strategies: [],
          config: {
            batch_size: 0,
            timeout_ms: 0,
          },
        },
        semantic_search: {
          enabled: true,
          embedding_model: 'text-embedding-3-small', // Smaller model
          similarity_threshold: 0.7, // Lower threshold
          config: {
            max_results: 25,
            timeout_ms: 5000, // Longer timeout
          },
        },
        background_processing: {
          enabled: false, // Disabled in DR
          batch_size: 0,
          processing_interval: 0,
          max_queue_size: 0,
        },
      },
    },
    zai: {
      url: process.env['ZAI_DR_URL'] || process.env['ZAI_URL'] || 'https://api.z.ai/api/anthropic',
      model: process.env['ZAI_DR_MODEL'] || 'glm-4.6', // Fallback model
      timeout: 45000, // Longer timeout
      retries: 5, // More retries
      retry_delay: 5000, // Longer retry delay
      circuit_breaker: {
        enabled: true,
        threshold: 10, // Higher threshold
        reset_timeout: 120000, // Longer reset timeout
        monitoring_window: 300000, // Longer monitoring window
      },
      rate_limiting: {
        enabled: true,
        requests_per_minute: 50, // Reduced rate limits
        requests_per_hour: 500,
        burst_limit: 10,
        backoff_strategy: 'exponential',
      },
      authentication: {
        api_key: process.env['ZAI_DR_API_KEY'] || process.env['ZAI_API_KEY'] || '',
        key_rotation_enabled: false, // Disabled in DR
        key_rotation_interval: 0,
      },
    },
    performance: {
      latency_targets: {
        insight_generation: 20000, // 20 seconds - much more lenient
        contradiction_detection: 0, // Disabled
        semantic_search: 5000, // 5 seconds
        background_processing: 0, // Disabled
      },
      throughput_targets: {
        operations_per_second: 2, // Much lower throughput
        insights_per_minute: 5,
        batch_processing: 0, // Disabled
      },
      resource_limits: {
        max_memory_usage_mb: 256, // Lower memory limit
        max_cpu_usage_percent: 60, // Lower CPU limit
        max_concurrent_requests: 5, // Fewer concurrent requests
        max_queue_size: 20, // Smaller queue
      },
      caching: {
        enabled: true,
        ttl_seconds: 3600, // 1 hour - longer cache
        max_size_mb: 25, // Smaller cache
        strategy: 'lru',
      },
    },
    quality: {
      accuracy_thresholds: {
        insight_generation: 0.6, // Lower thresholds
        contradiction_detection: 0, // Disabled
        semantic_search: 0.7,
      },
      confidence_thresholds: {
        insight_generation: 0.5, // Lower thresholds
        contradiction_detection: 0, // Disabled
        semantic_search: 0.6,
      },
      monitoring: {
        sample_rate: 1.0, // Sample everything in DR
        evaluation_interval: 300000, // 5 minutes - less frequent
        drift_detection: false, // Disabled in DR
        automated_retraining: false, // Disabled in DR
      },
      fallback: {
        enabled: true,
        fallback_models: [], // No fallbacks in DR
        degrade_gracefully: true,
        user_notification: true, // Notify users of degraded service
      },
    },
    cost: {
      daily_budget: 50, // $50 per day - lower budget
      monthly_budget: 1000, // $1000 per month
      cost_per_operation: 0.02, // Higher cost per operation
      cost_tracking: {
        enabled: true,
        granularity: 'day',
        alerts: false, // No cost alerts in DR
      },
      optimization: {
        batch_processing: false, // Disabled in DR
        model_selection: 'always_fastest', // Prioritize speed over cost
        request_combining: false,
        caching_enabled: true,
      },
    },
    security: {
      data_privacy: {
        anonymization: true,
        data_retention_days: 7, // Shorter retention
        audit_logging: true,
        encryption_at_rest: true,
        encryption_in_transit: true,
      },
      access_control: {
        rbac_enabled: true,
        api_key_scopes: ['read'], // Read-only in DR
        rate_limit_per_user: 100, // Much lower rate limits
        ip_whitelist: [], // Open access in DR
      },
      compliance: {
        gdpr_compliant: true,
        soc2_compliant: false, // Reduced compliance
        hipaa_compliant: false,
        audit_trail_retention_days: 7,
      },
    },
    monitoring: {
      enabled: true,
      metrics: {
        collection_interval: 60000, // 1 minute - less frequent
        retention_days: 7, // Shorter retention
        export_formats: ['json'], // Only JSON
        prometheus_enabled: false, // Disabled in DR
      },
      health_checks: {
        enabled: true,
        interval: 120000, // 2 minutes - less frequent
        timeout: 15000, // 15 seconds - longer timeout
        endpoints: ['/health'], // Minimal health checks
      },
      alerting: {
        enabled: true,
        channels: ['email'], // Only critical alerts
        severity_thresholds: {
          critical: 'critical',
        },
        escalation_policy: false,
      },
      tracing: {
        enabled: false, // Disabled in DR
        sample_rate: 0,
        export_format: 'otlp',
      },
    },
    infrastructure: {
      deployment: {
        strategy: 'rolling', // Simple rolling deployment
        health_check_grace_period: 300000, // 5 minutes - longer grace period
        rollback_timeout: 600000, // 10 minutes - longer rollback
        max_unhealthy_percent: 50, // More lenient health thresholds
      },
      scaling: {
        auto_scaling: false, // No auto-scaling in DR
        min_instances: 1,
        max_instances: 2,
        scale_up_threshold: 0,
        scale_down_threshold: 0,
        cooldown_period: 0,
      },
      high_availability: {
        enabled: true,
        availability_zones: ['us-east-1a'], // Single AZ
        failover_timeout: 120000, // 2 minutes - longer failover
        disaster_recovery: false, // DR is the recovery site
      },
    },
  },
};

/**
 * Production ZAI Configuration Manager
 */
export class ProductionZAIConfigManager {
  private config: ProductionZAIConfig;
  private environment: string;

  constructor(environment?: string) {
    this.environment = environment || process.env['NODE_ENV'] || 'development';

    if (!productionConfigs[this.environment]) {
      logger.warn(
        { environment: this.environment },
        'Unknown environment, falling back to development'
      );
      this.environment = 'development';
    }

    this.config = productionConfigs[this.environment];
    logger.info({ environment: this.environment }, 'Production ZAI configuration loaded');
  }

  /**
   * Get current configuration
   */
  getConfig(): ProductionZAIConfig {
    return { ...this.config };
  }

  /**
   * Get environment name
   */
  getEnvironment(): string {
    return this.environment;
  }

  /**
   * Validate configuration
   */
  validateConfig(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate AI service configuration
    if (this.config.ai.enabled && !this.config.zai.url) {
      errors.push('ZAI URL is required when AI services are enabled');
    }

    if (this.config.ai.enabled && !this.config.zai.authentication.api_key) {
      errors.push('ZAI API key is required when AI services are enabled');
    }

    // Validate performance limits
    if (this.config.performance.resource_limits.max_memory_usage_mb <= 0) {
      errors.push('Max memory usage must be greater than 0');
    }

    if (
      this.config.performance.resource_limits.max_cpu_usage_percent <= 0 ||
      this.config.performance.resource_limits.max_cpu_usage_percent > 100
    ) {
      errors.push('Max CPU usage must be between 1 and 100');
    }

    // Validate quality thresholds
    Object.entries(this.config.quality.accuracy_thresholds).forEach(([key, value]) => {
      if (value < 0 || value > 1) {
        errors.push(`${key} accuracy threshold must be between 0 and 1`);
      }
    });

    // Validate cost budgets
    if (this.config.cost.daily_budget <= 0) {
      errors.push('Daily budget must be greater than 0');
    }

    if (this.config.cost.monthly_budget <= 0) {
      errors.push('Monthly budget must be greater than 0');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get ZAI client configuration
   */
  getZAIConfig(): ZAIConfig {
    return {
      apiKey: this.config.zai.authentication.api_key,
      url: this.config.zai.url,
      model: this.config.zai.model,
      timeout: this.config.zai.timeout,
      retries: this.config.zai.retries,
      retryDelay: this.config.zai.retry_delay,
      circuitBreaker: {
        enabled: this.config.zai.circuit_breaker.enabled,
        threshold: this.config.zai.circuit_breaker.threshold,
        resetTimeout: this.config.zai.circuit_breaker.reset_timeout,
        monitoringWindow: this.config.zai.circuit_breaker.monitoring_window,
      },
      rateLimiting: {
        enabled: this.config.zai.rate_limiting.enabled,
        requestsPerMinute: this.config.zai.rate_limiting.requests_per_minute,
        requestsPerHour: this.config.zai.rate_limiting.requests_per_hour,
        burstLimit: this.config.zai.rate_limiting.burst_limit,
        backoffStrategy: this.config.zai.rate_limiting.backoff_strategy,
      },
      authentication: {
        apiKey: this.config.zai.authentication.api_key,
        keyRotationEnabled: this.config.zai.authentication.key_rotation_enabled,
        keyRotationInterval: this.config.zai.authentication.key_rotation_interval,
      },
    };
  }

  /**
   * Get AI orchestrator configuration
   */
  getAIOrchestratorConfig(): AIOrchestratorConfig {
    return {
      primaryProvider: 'zai',
      fallbackProvider: 'openai',
      autoFailover: true,
      healthCheckInterval: 30000,
      fallbackThreshold: 3,
      enabled: this.config.ai.enabled,
      providerConfigs: {
        zai: this.getZAIConfig(),
        openai: {}, // Empty config for now
      },
      features: {
        insights: this.config.ai.features.insights,
        contradiction_detection: this.config.ai.features.contradiction_detection,
        semantic_search: this.config.ai.features.semantic_search,
        background_processing: this.config.ai.features.background_processing,
      },
      performance: {
        latencyTargets: this.config.performance.latency_targets,
        throughputTargets: this.config.performance.throughput_targets,
        resourceLimits: this.config.performance.resource_limits,
        caching: this.config.performance.caching,
      },
      quality: {
        accuracyThresholds: this.config.quality.accuracy_thresholds,
        confidenceThresholds: this.config.quality.confidence_thresholds,
        monitoring: this.config.quality.monitoring,
        fallback: this.config.quality.fallback,
      },
    };
  }

  /**
   * Get background processor configuration
   */
  getBackgroundProcessorConfig(): BackgroundProcessorConfig {
    return {
      maxConcurrency: 5, // Default value
      queueSize: 100, // Default value
      retryAttempts: 3, // Default value
      retryDelayMs: 1000, // Default value
      timeoutMs: this.config.performance.latency_targets.background_processing || 30000,
      enablePriorityQueue: true, // Default value
      persistJobs: true, // Default value
      metricsInterval: 10000, // Default value
      enabled: this.config.ai.features.background_processing.enabled,
      batchSize: this.config.ai.features.background_processing.batch_size,
      processingInterval: this.config.ai.features.background_processing.processing_interval,
      maxQueueSize: this.config.ai.features.background_processing.max_queue_size,
    };
  }

  /**
   * Get monitoring configuration
   */
  getMonitoringConfig(): {
    enabled: boolean;
    metrics: {
      collection_interval: number;
      retention_days: number;
      export_formats: string[];
      prometheus_enabled: boolean;
    };
    healthChecks: {
      enabled: boolean;
      interval: number;
      timeout: number;
      endpoints: string[];
    };
    alerting: {
      enabled: boolean;
      channels: string[];
      severity_thresholds: Record<string, string>;
      escalation_policy: boolean;
    };
    tracing: {
      enabled: boolean;
      sample_rate: number;
      export_format: 'jaeger' | 'zipkin' | 'otlp';
    };
  } {
    return {
      enabled: this.config.monitoring.enabled,
      metrics: this.config.monitoring.metrics,
      healthChecks: this.config.monitoring.health_checks,
      alerting: this.config.monitoring.alerting,
      tracing: this.config.monitoring.tracing,
    };
  }

  /**
   * Get cost control configuration
   */
  getCostControlConfig(): {
    dailyBudget: number;
    monthlyBudget: number;
    costPerOperation: number;
    tracking: {
      enabled: boolean;
      granularity: 'operation' | 'hour' | 'day';
      alerts: boolean;
    };
    optimization: {
      batch_processing: boolean;
      model_selection: 'always_fastest' | 'cost_optimized' | 'balanced';
      request_combining: boolean;
      caching_enabled: boolean;
    };
  } {
    return {
      dailyBudget: this.config.cost.daily_budget,
      monthlyBudget: this.config.cost.monthly_budget,
      costPerOperation: this.config.cost.cost_per_operation,
      tracking: this.config.cost.cost_tracking,
      optimization: this.config.cost.optimization,
    };
  }

  /**
   * Get security configuration
   */
  getSecurityConfig(): {
    dataPrivacy: {
      anonymization: boolean;
      data_retention_days: number;
      audit_logging: boolean;
      encryption_at_rest: boolean;
      encryption_in_transit: boolean;
    };
    accessControl: {
      rbac_enabled: boolean;
      api_key_scopes: string[];
      rate_limit_per_user: number;
      ip_whitelist: string[];
    };
    compliance: {
      gdpr_compliant: boolean;
      soc2_compliant: boolean;
      hipaa_compliant: boolean;
      audit_trail_retention_days: number;
    };
  } {
    return {
      dataPrivacy: this.config.security.data_privacy,
      accessControl: this.config.security.access_control,
      compliance: this.config.security.compliance,
    };
  }

  /**
   * Check if AI features are enabled
   */
  isAIEnabled(): boolean {
    return this.config.ai.enabled;
  }

  /**
   * Check if specific feature is enabled
   */
  isFeatureEnabled(feature: keyof typeof this.config.ai.features): boolean {
    return this.config.ai.features[feature]?.enabled || false;
  }

  /**
   * Get feature configuration
   */
  getFeatureConfig(feature: keyof typeof this.config.ai.features): Record<string, unknown> {
    return this.config.ai.features[feature] || {};
  }

  /**
   * Export configuration for monitoring
   */
  exportForMonitoring(): Record<string, unknown> {
    return {
      environment: this.environment,
      ai_enabled: this.config.ai.enabled,
      features_enabled: Object.fromEntries(
        Object.entries(this.config.ai.features).map(([key, value]) => [key, value.enabled])
      ),
      performance_targets: this.config.performance.latency_targets,
      resource_limits: this.config.performance.resource_limits,
      quality_thresholds: this.config.quality.accuracy_thresholds,
      cost_budgets: {
        daily: this.config.cost.daily_budget,
        monthly: this.config.cost.monthly_budget,
      },
      monitoring_enabled: this.config.monitoring.enabled,
      security_level: this.getSecurityLevel(),
    };
  }

  /**
   * Get security level based on configuration
   */
  private getSecurityLevel(): 'low' | 'medium' | 'high' | 'critical' {
    const { security } = this.config;

    if (security.compliance.hipaa_compliant && security.data_privacy.encryption_at_rest) {
      return 'critical';
    } else if (security.compliance.soc2_compliant && security.access_control.rbac_enabled) {
      return 'high';
    } else if (security.data_privacy.audit_logging && security.data_privacy.encryption_in_transit) {
      return 'medium';
    } else {
      return 'low';
    }
  }
}

/**
 * Default configuration manager instance
 */
export const productionZAIConfigManager = new ProductionZAIConfigManager();

/**
 * Export configurations and utilities
 */
export { productionConfigs };
// ProductionZAIConfig already exported at interface declaration
