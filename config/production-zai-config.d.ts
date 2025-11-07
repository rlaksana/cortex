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
import type { ZAIConfig, AIOrchestratorConfig, BackgroundProcessorConfig } from '../src/types/zai-interfaces.js';
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
declare const productionConfigs: Record<string, ProductionZAIConfig>;
/**
 * Production ZAI Configuration Manager
 */
export declare class ProductionZAIConfigManager {
    private config;
    private environment;
    constructor(environment?: string);
    /**
     * Get current configuration
     */
    getConfig(): ProductionZAIConfig;
    /**
     * Get environment name
     */
    getEnvironment(): string;
    /**
     * Validate configuration
     */
    validateConfig(): {
        valid: boolean;
        errors: string[];
    };
    /**
     * Get ZAI client configuration
     */
    getZAIConfig(): ZAIConfig;
    /**
     * Get AI orchestrator configuration
     */
    getAIOrchestratorConfig(): AIOrchestratorConfig;
    /**
     * Get background processor configuration
     */
    getBackgroundProcessorConfig(): BackgroundProcessorConfig;
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
    };
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
    };
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
    };
    /**
     * Check if AI features are enabled
     */
    isAIEnabled(): boolean;
    /**
     * Check if specific feature is enabled
     */
    isFeatureEnabled(feature: keyof typeof this.config.ai.features): boolean;
    /**
     * Get feature configuration
     */
    getFeatureConfig(feature: keyof typeof this.config.ai.features): Record<string, unknown>;
    /**
     * Export configuration for monitoring
     */
    exportForMonitoring(): Record<string, unknown>;
    /**
     * Get security level based on configuration
     */
    private getSecurityLevel;
}
/**
 * Default configuration manager instance
 */
export declare const productionZAIConfigManager: ProductionZAIConfigManager;
/**
 * Export configurations and utilities
 */
export { productionConfigs };
//# sourceMappingURL=production-zai-config.d.ts.map