
/**
 * Canary Deployment System
 *
 * Comprehensive canary deployment solution with:
 * - Feature flag management with cohort limiting
 * - Emergency kill-switch capabilities
 * - Progressive traffic splitting
 * - Health monitoring and validation
 * - Automated rollback procedures
 * - Configuration validation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

// Export main services
export { FeatureFlagService, featureFlagService } from '../feature-flag/feature-flag-service.js';
import type { FeatureFlag } from '../feature-flag/feature-flag-service.js';
import { featureFlagService, FlagStatus, TargetingStrategy  } from '../feature-flag/feature-flag-service.js';


// Note: Canary services are temporarily disabled due to missing implementations
// These will be re-enabled when the services are properly implemented
// export { CanaryHealthMonitor, canaryHealthMonitor } from './canary-health-monitor.js';
// export { CanaryOrchestrator, canaryOrchestrator } from './canary-orchestrator.js';
// export { CanaryConfigValidator, canaryConfigValidator } from './config-validator.js';
// export { KillSwitchService, killSwitchService } from './kill-switch-service.js';
// export { RollbackService, rollbackService } from './rollback-service.js';
// export { TrafficSplitterService, trafficSplitterService } from './traffic-splitter.js';

// Export types and enums from feature-flag service (working)
export type {
  FeatureFlag,
  FeatureFlagConfig,
  FlagStatus as FeatureFlagStatus,
  TargetingStrategy as FeatureTargetingStrategy,
  FlagEvaluationResult,
  UserCohort,
  UserContext} from '../feature-flag/feature-flag-service.js';

// Export enums for type compatibility
export { FlagStatus, TargetingStrategy } from '../feature-flag/feature-flag-service.js';

// Note: Canary service types are temporarily disabled due to missing implementations
// These will be re-enabled when the services are properly implemented
/*
export type {
  AutoRollbackThreshold,
  CanaryHealthConfig,
  ComparisonMetrics,
  EscalationRule,
  HealthAlert,
  HealthIssue,
  HealthMetricsSnapshot,
  HealthMetricType,
  HealthThreshold,
  HealthTrend,
  ServiceHealthMetrics,
  ValidationCriteria} from './canary-health-monitor.js';
export type {
  CanaryDeployment,
  CanaryDeploymentConfig,
  CanaryStatus,
  DeploymentPhase,
  PhaseMetrics,
  RollbackThresholds,
  SuccessCriteria,
  TrafficRouting,
  TrafficRule,
  TrafficShiftStrategy
} from './canary-orchestrator.js';
export type {
  ValidationResult as ConfigValidationResult,
  ResourceConstraints,
  SecurityPolicy,
  ValidationCategory,
  ValidationContext,
  ValidationError,
  ValidationInfo,
  ValidationRequest,
  ValidationSeverity,
  ValidationWarning} from './config-validator.js';
export type {
  AutoRecoveryConfig,
  KillSwitchStatus as CanaryKillSwitchStatus,
  KillSwitchTrigger as CanaryKillSwitchTrigger,
  KillSwitchConfig,
  KillSwitchEvent,
  KillSwitchScope,
  NotificationConfig,
  RecoveryAction} from './kill-switch-service.js';
export type {
  CriteriaResult,
  ExecutedAction,
  RollbackAction,
  RollbackConfig,
  RollbackError,
  RollbackExecution,
  RollbackImpact,
  RollbackPhase,
  RollbackStatus,
  RollbackStrategy,
  RollbackTrigger,
  ValidationResult} from './rollback-service.js';
export type {
  FailoverConfig,
  LoadBalancerState,
  RateLimitConfig,
  RequestContext,
  RoutingCondition,
  RoutingDecision,
  RoutingStrategy,
  ServiceTarget,
  SessionAffinityConfig,
  HealthCheckConfig as TrafficHealthCheckConfig,
  TrafficMetrics,
  TrafficRule as TrafficRoutingRule} from './traffic-splitter.js';
*/

// Note: Enums are already exported as types in the type exports above

/**
 * Canary System Manager (Minimal Implementation)
 *
 * Provides a unified interface for managing the canary deployment system.
 * Currently only includes feature flag service - other services are disabled.
 */
export class CanarySystemManager {
  private static instance: CanarySystemManager | null = null;

  private constructor() {}

  /**
   * Get singleton instance
   */
  public static getInstance(): CanarySystemManager {
    if (!CanarySystemManager.instance) {
      CanarySystemManager.instance = new CanarySystemManager();
    }
    return CanarySystemManager.instance;
  }

  /**
   * Initialize the canary system
   */
  public async initialize(): Promise<void> {
    console.log('Initializing Canary Deployment System (Feature Flags Only)...');
    console.log('Canary Deployment System initialized successfully');
  }

  /**
   * Get system health and metrics
   */
  public getSystemHealth(): {
    featureFlags: unknown;
    otherServices: string;
  } {
    return {
      featureFlags: featureFlagService.getMetrics(),
      otherServices: 'Canary services are temporarily disabled',
    };
  }

  /**
   * Cleanup all services
   */
  public async cleanup(): Promise<void> {
    console.log('Cleaning up Canary Deployment System...');
    console.log('Canary Deployment System cleaned up');
  }

  /**
   * Get comprehensive status report
   */
  public getStatusReport(): {
    timestamp: Date;
    systemHealth: unknown;
    activeDeployments: number;
    activeRollbacks: number;
    emergencyKillActive: boolean;
    recommendations: string[];
  } {
    const systemHealth = this.getSystemHealth();

    return {
      timestamp: new Date(),
      systemHealth,
      activeDeployments: 0,
      activeRollbacks: 0,
      emergencyKillActive: false,
      recommendations: ['Canary deployment services are temporarily disabled'],
    };
  }
}

// Export the main system manager
export const canarySystemManager = CanarySystemManager.getInstance();

// Export utility functions (minimal implementation)
export const CanaryUtils = {
  /**
   * Create a simple feature flag configuration
   */
  createSimpleFeatureFlag: (overrides: Partial<FeatureFlag> = {}): FeatureFlag => {
    const now = new Date();
    return {
      id: Math.random().toString(36).substring(2) + Date.now().toString(36),
      name: 'Example Feature Flag',
      description: 'Simple feature flag configuration',
      status: FlagStatus.DISABLED,
      strategy: TargetingStrategy.ALL_USERS,
      conditions: [],
      rolloutPercentage: 0,
      killSwitchEnabled: false,
      emergencyDisabled: false,
      createdAt: now,
      updatedAt: now,
      ...overrides,
    };
  },

  /**
   * Placeholder for traffic progression calculation
   */
  calculateTrafficProgression: (phases: number): number[] => {
    const percentages: number[] = [];
    for (let i = 0; i < phases; i++) {
      percentages.push(Math.round((i / (phases - 1)) * 100));
    }
    return percentages;
  },

  /**
   * Placeholder for deployment recommendations
   */
  generateRecommendations: (): string[] => {
    return [
      'Canary deployment services are temporarily disabled',
      'Only feature flag management is currently available'
    ];
  },
};

// Export default
export default canarySystemManager;