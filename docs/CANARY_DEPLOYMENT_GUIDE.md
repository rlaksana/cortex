# Canary Deployment System Guide

## Overview

The MCP-Cortex Canary Deployment System provides a comprehensive solution for safe, gradual rollouts with immediate rollback capabilities. This system integrates feature flag management, emergency kill switches, traffic splitting, health monitoring, and automated rollback procedures to ensure safe deployments in production environments.

## Architecture

### Core Components

1. **Feature Flag Service** - Manages feature flags with cohort limiting and percentage-based rollouts
2. **Emergency Kill Switch** - Provides immediate shutdown capabilities for critical situations
3. **Canary Orchestrator** - Manages the entire canary deployment lifecycle
4. **Traffic Splitter** - Handles intelligent traffic routing and distribution
5. **Health Monitor** - Provides comprehensive health monitoring and validation
6. **Rollback Service** - Automated rollback procedures with multiple strategies
7. **Configuration Validator** - Validates configurations against best practices and security policies

### System Integration

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Feature Flags  │────│ Traffic Splitter │────│ Canary Service  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌──────────────────┐              │
         └──────────────│   Health Monitor  │──────────────┘
                        └──────────────────┘
                                 │
                    ┌──────────────────┐
                    │ Emergency Kill   │
                    │     Switch       │
                    └──────────────────┘
                                 │
                    ┌──────────────────┐
                    │  Rollback Service│
                    └──────────────────┘
```

## Quick Start

### Installation

```typescript
import { canarySystemManager } from './src/services/canary/index.js';

// Initialize the system
await canarySystemManager.initialize();
```

### Basic Usage

```typescript
import { CanaryUtils, canaryOrchestrator, CanaryStatus } from './src/services/canary/index.js';

// Create a simple canary deployment configuration
const canaryConfig = CanaryUtils.createSimpleCanaryConfig({
  name: 'My Service Canary',
  serviceName: 'my-service',
  stableVersion: '1.0.0',
  canaryVersion: '2.0.0',
  initialTrafficPercentage: 5,
  phases: [
    {
      id: 'phase-1',
      name: '5% Traffic',
      trafficPercentage: 5,
      durationMs: 300000, // 5 minutes
      successCriteria: [
        {
          metric: 'availability',
          operator: 'greater_than',
          threshold: 99,
          durationMs: 180000,
        },
      ],
      rollbackThresholds: {
        errorRate: 5,
        latencyP95: 1000,
        availability: 95,
      },
      status: 'pending',
    },
  ],
});

// Start the deployment
const deploymentId = await canaryOrchestrator.startDeployment('config-id', canaryConfig);
console.log(`Canary deployment started: ${deploymentId}`);

// Monitor deployment progress
const deployment = canaryOrchestrator.getDeployment(deploymentId);
console.log(`Deployment status: ${deployment.status}`);
```

## Core Features

### 1. Feature Flag Management

The feature flag service provides comprehensive flag management with:

- **Cohort-based targeting** - Target specific user groups
- **Percentage rollouts** - Gradual user exposure
- **A/B testing support** - Controlled experiments
- **Emergency disable** - Immediate flag shutdown
- **Rate limiting** - Prevent abuse
- **Audit logging** - Complete flag history

```typescript
import { featureFlagService, TargetingStrategy, FlagStatus } from './src/services/canary/index.js';

// Create a feature flag
const flag = featureFlagService.createFlag({
  name: 'new-feature-rollout',
  description: 'Roll out new feature to users gradually',
  status: FlagStatus.ENABLED,
  strategy: TargetingStrategy.PERCENTAGE,
  rolloutPercentage: 10,
  killSwitchEnabled: true,
});

// Evaluate flag for a user
const userContext = {
  userId: 'user-123',
  timestamp: new Date(),
  attributes: { tier: 'premium' },
};

const result = await featureFlagService.evaluateFlag(flag.id, userContext);
console.log(`Feature enabled for user: ${result.enabled}`);
```

### 2. Emergency Kill Switch

The kill switch provides immediate shutdown capabilities:

- **System-wide kills** - Complete system shutdown
- **Component-specific kills** - Target specific services
- **Auto-triggering** - Based on health metrics
- **Manual activation** - Emergency response
- **Auto-recovery** - Automatic recovery procedures

```typescript
import { killSwitchService, KillSwitchTrigger } from './src/services/canary/index.js';

// Create a kill switch configuration
const killSwitch = killSwitchService.createConfig({
  name: 'service-emergency-stop',
  description: 'Emergency stop for critical service',
  scope: 'component',
  targetComponent: 'my-service',
  triggerConditions: [
    {
      type: KillSwitchTrigger.ERROR_RATE_THRESHOLD,
      threshold: 20,
      component: 'my-service',
    },
  ],
  autoRecovery: {
    enabled: true,
    delayMs: 300000,
    maxAttempts: 3,
    recoveryActions: [],
  },
  notifications: {
    enabled: true,
    channels: ['email'],
    recipients: ['admin@company.com'],
  },
  gracePeriodMs: 30000,
  priority: 'critical',
  enabled: true,
});

// Manually trigger kill switch
await killSwitchService.triggerKillSwitch(killSwitch.id, 'Manual emergency activation', 'admin');

// Emergency kill all
killSwitchService.emergencyKillAll('Critical system failure detected');
```

### 3. Traffic Splitting

The traffic splitter provides intelligent routing:

- **Multiple strategies** - Percentage, round-robin, weighted, etc.
- **Session affinity** - Consistent user experience
- **Health checking** - Automatic failover
- **Rate limiting** - Traffic control
- **Real-time metrics** - Performance monitoring

```typescript
import { trafficSplitterService, RoutingStrategy } from './src/services/canary/index.js';

// Create a traffic routing rule
const rule = trafficSplitterService.createRule({
  name: 'my-service-routing',
  strategy: RoutingStrategy.PERCENTAGE,
  priority: 1,
  enabled: true,
  conditions: [],
  targets: [
    {
      id: 'stable-target',
      name: 'Stable Version',
      endpoint: 'http://stable-service:8080',
      version: '1.0.0',
      weight: 90,
      healthy: true,
      connections: 0,
      lastHealthCheck: new Date(),
      metadata: {},
    },
    {
      id: 'canary-target',
      name: 'Canary Version',
      endpoint: 'http://canary-service:8080',
      version: '2.0.0',
      weight: 10,
      healthy: true,
      connections: 0,
      lastHealthCheck: new Date(),
      metadata: {},
    },
  ],
  sessionAffinity: {
    enabled: true,
    type: 'cookie',
    name: 'routing-session',
    ttl: 3600000,
    path: '/',
    secure: true,
    httpOnly: true,
  },
  failover: {
    enabled: true,
    strategy: 'fail_open',
    fallbackTargets: [],
    retryAttempts: 3,
    retryDelayMs: 1000,
    circuitBreaker: {
      enabled: true,
      failureThreshold: 5,
      recoveryTimeout: 60000,
    },
  },
  rateLimit: {
    enabled: true,
    requestsPerSecond: 1000,
    burst: 100,
    windowSize: 60000,
  },
  healthCheck: {
    enabled: true,
    path: '/health',
    intervalMs: 30000,
    timeoutMs: 5000,
    healthyThreshold: 2,
    unhealthyThreshold: 3,
    expectedStatuses: [200],
  },
});

// Route a request
const requestContext = {
  id: 'req-123',
  method: 'GET',
  path: '/api/data',
  headers: { 'user-agent': 'Mozilla/5.0' },
  query: {},
  cookies: {},
  clientIP: '192.168.1.1',
  userAgent: 'Mozilla/5.0',
  timestamp: new Date(),
};

const decision = await trafficSplitterService.routeRequest(requestContext);
console.log(`Request routed to: ${decision.target.name}`);
```

### 4. Health Monitoring

The health monitor provides comprehensive monitoring:

- **Real-time metrics** - Continuous health assessment
- **Comparative analysis** - Stable vs canary comparison
- **Trend analysis** - Performance regression detection
- **Automated alerts** - Issue notification
- **Auto-rollback triggers** - Automatic failure response

```typescript
import { canaryHealthMonitor, HealthMetricType } from './src/services/canary/index.js';

// Create health monitoring configuration
const healthConfig = canaryHealthMonitor.createConfig({
  deploymentId: 'deployment-123',
  serviceName: 'my-service',
  stableVersion: '1.0.0',
  canaryVersion: '2.0.0',
  checkIntervalMs: 30000,
  evaluationWindowMs: 300000,
  metricsRetentionHours: 24,
  thresholds: [
    {
      metric: HealthMetricType.AVAILABILITY,
      warning: 95,
      critical: 90,
      operator: 'less_than',
      windowSize: 5,
      consecutiveFailures: 2,
    },
    {
      metric: HealthMetricType.ERROR_RATE,
      warning: 5,
      critical: 10,
      operator: 'greater_than',
      windowSize: 5,
      consecutiveFailures: 3,
    },
  ],
  comparisonEnabled: true,
  comparisonTolerance: 10,
  baselineWindow: 2,
  alerting: {
    enabled: true,
    channels: ['email', 'slack'],
    recipients: ['team@company.com'],
    cooldownPeriodMs: 300000,
    escalationRules: [
      {
        severity: 'warning',
        delayMs: 300000,
        recipients: ['team@company.com'],
      },
      {
        severity: 'critical',
        delayMs: 60000,
        recipients: ['oncall@company.com'],
      },
    ],
  },
  autoRollback: {
    enabled: true,
    thresholds: [
      {
        metric: HealthMetricType.ERROR_RATE,
        threshold: 15,
        operator: 'greater_than',
        duration: 5,
        consecutiveViolations: 2,
      },
    ],
    delayMs: 30000,
    maxRollbacks: 3,
  },
});

// Start monitoring
canaryHealthMonitor.startMonitoring(healthConfig.deploymentId);

// Get health metrics
const metrics = canaryHealthMonitor.getMetricsHistory('deployment-123', 10);
console.log('Health metrics:', metrics);
```

### 5. Automated Rollback

The rollback service provides comprehensive rollback capabilities:

- **Multiple strategies** - Immediate, gradual, phased, blue-green
- **Action orchestration** - Coordinated rollback steps
- **Validation** - Rollback verification
- **Approval workflow** - Safety controls
- **Impact analysis** - Rollback consequences

```typescript
import { rollbackService, RollbackStrategy, RollbackTrigger } from './src/services/canary/index.js';

// Create rollback configuration
const rollbackConfig = rollbackService.createConfig({
  deploymentId: 'deployment-123',
  name: 'Emergency Rollback Plan',
  description: 'Comprehensive rollback strategy',
  strategy: RollbackStrategy.PHASED,
  triggers: [RollbackTrigger.AUTOMATIC, RollbackTrigger.MANUAL],
  autoTriggerEnabled: true,
  triggerThresholds: [
    {
      metric: 'error_rate',
      operator: 'greater_than',
      threshold: 10,
      duration: 5,
      consecutiveFailures: 2,
    },
  ],
  validation: {
    enabled: true,
    healthCheckPath: '/health',
    validationTimeoutMs: 30000,
    successCriteria: [
      {
        type: 'health_check',
        weight: 1,
        required: true,
      },
    ],
    retryAttempts: 3,
    retryDelayMs: 10000,
  },
  actions: [
    {
      id: 'stop-traffic',
      name: 'Stop New Traffic',
      type: 'stop_new_traffic',
      order: 1,
      timeoutMs: 30000,
      config: {},
    },
    {
      id: 'drain-connections',
      name: 'Drain Connections',
      type: 'drain_connections',
      order: 2,
      timeoutMs: 60000,
      config: {},
    },
    {
      id: 'update-flags',
      name: 'Update Feature Flags',
      type: 'update_feature_flags',
      order: 3,
      timeoutMs: 15000,
      config: { disable: true },
    },
  ],
  notifications: {
    enabled: true,
    onStart: true,
    onProgress: false,
    onComplete: true,
    onFailure: true,
    channels: ['email', 'slack'],
    recipients: ['team@company.com'],
  },
  safety: {
    requireApproval: false,
    approvers: [],
    maxRollbackTimeMs: 300000,
    allowConsecutiveRollbacks: false,
    cooldownPeriodMs: 300000,
  },
});

// Execute rollback
const executionId = await rollbackService.executeRollback(
  'deployment-123',
  RollbackTrigger.MANUAL,
  'Performance degradation detected',
  'admin'
);

console.log(`Rollback execution started: ${executionId}`);
```

### 6. Configuration Validation

The configuration validator ensures safe deployments:

- **Schema validation** - Configuration structure checks
- **Security validation** - Security policy compliance
- **Best practice checks** - Recommended patterns
- **Resource validation** - Constraint verification
- **Cross-service validation** - Dependency checks

```typescript
import { canaryConfigValidator } from './src/services/canary/index.js';

// Validate canary deployment configuration
const validationResult = canaryConfigValidator.validate({
  type: 'canary_deployment',
  config: canaryConfig,
  context: {
    environment: 'production',
    resourceConstraints: {
      maxTrafficPercentage: 50,
      maxRollbackTime: 600000,
    },
    securityPolicies: [
      {
        name: 'production-security',
        rules: [
          {
            type: 'encryption',
            required: true,
          },
        ],
      },
    ],
  },
  strictMode: false,
});

if (validationResult.valid) {
  console.log('Configuration is valid');
} else {
  console.log('Configuration validation failed:');
  validationResult.errors.forEach((error) => {
    console.log(`- ${error.message} (${error.field})`);
  });
}

console.log('Recommendations:');
validationResult.recommendations.forEach((rec) => {
  console.log(`- ${rec}`);
});
```

## Advanced Usage

### Custom Traffic Splitting

```typescript
// Create custom traffic routing with header-based targeting
const customRule = trafficSplitterService.createRule({
  name: 'custom-beta-routing',
  strategy: RoutingStrategy.HEADER_BASED,
  priority: 10,
  enabled: true,
  conditions: [
    {
      type: 'header',
      field: 'x-beta-user',
      operator: 'equals',
      value: 'true',
      caseSensitive: false,
    },
  ],
  targets: [
    {
      id: 'beta-target',
      name: 'Beta Version',
      endpoint: 'http://beta-service:8080',
      version: '2.1.0-beta',
      weight: 100,
      healthy: true,
      connections: 0,
      lastHealthCheck: new Date(),
      metadata: { beta: true },
    },
  ],
  sessionAffinity: {
    enabled: true,
    type: 'header',
    name: 'x-user-session',
    ttl: 1800000,
    path: '/',
    secure: false,
    httpOnly: false,
  },
  failover: {
    enabled: true,
    strategy: 'fail_open',
    fallbackTargets: [],
    retryAttempts: 2,
    retryDelayMs: 500,
    circuitBreaker: {
      enabled: true,
      failureThreshold: 3,
      recoveryTimeout: 30000,
    },
  },
  rateLimit: {
    enabled: true,
    requestsPerSecond: 500,
    burst: 50,
    windowSize: 60000,
  },
  healthCheck: {
    enabled: true,
    path: '/health',
    intervalMs: 15000,
    timeoutMs: 3000,
    healthyThreshold: 2,
    unhealthyThreshold: 2,
    expectedStatuses: [200],
  },
});
```

### Multi-Phase Canary Deployment

```typescript
// Create a comprehensive multi-phase canary deployment
const multiPhaseConfig = CanaryUtils.createSimpleCanaryConfig({
  name: 'Progressive Service Rollout',
  serviceName: 'user-service',
  stableVersion: '1.2.0',
  canaryVersion: '2.0.0',
  trafficShiftStrategy: TrafficShiftStrategy.PHASED,
  phases: [
    {
      id: 'phase-1-internal',
      name: 'Internal Testing (1%)',
      trafficPercentage: 1,
      durationMs: 600000, // 10 minutes
      successCriteria: [
        {
          metric: 'availability',
          operator: 'greater_than',
          threshold: 100,
          durationMs: 300000,
        },
        {
          metric: 'error_rate',
          operator: 'less_than',
          threshold: 0,
          durationMs: 600000,
        },
      ],
      rollbackThresholds: {
        errorRate: 1,
        latencyP95: 500,
        availability: 99.5,
      },
      status: 'pending',
    },
    {
      id: 'phase-2-beta',
      name: 'Beta Users (5%)',
      trafficPercentage: 5,
      durationMs: 1800000, // 30 minutes
      successCriteria: [
        {
          metric: 'availability',
          operator: 'greater_than',
          threshold: 99.9,
          durationMs: 900000,
        },
        {
          metric: 'error_rate',
          operator: 'less_than',
          threshold: 0.5,
          durationMs: 1800000,
        },
        {
          metric: 'response_time',
          operator: 'less_than',
          threshold: 200,
          durationMs: 600000,
        },
      ],
      rollbackThresholds: {
        errorRate: 2,
        latencyP95: 800,
        availability: 99,
      },
      status: 'pending',
    },
    {
      id: 'phase-3-partial',
      name: 'Partial Rollout (25%)',
      trafficPercentage: 25,
      durationMs: 3600000, // 1 hour
      successCriteria: [
        {
          metric: 'availability',
          operator: 'greater_than',
          threshold: 99.5,
          durationMs: 1800000,
        },
        {
          metric: 'error_rate',
          operator: 'less_than',
          threshold: 1,
          durationMs: 3600000,
        },
        {
          metric: 'throughput',
          operator: 'greater_than',
          threshold: 1000,
          durationMs: 1800000,
        },
      ],
      rollbackThresholds: {
        errorRate: 3,
        latencyP95: 1000,
        availability: 98,
      },
      status: 'pending',
    },
    {
      id: 'phase-4-full',
      name: 'Full Rollout (100%)',
      trafficPercentage: 100,
      durationMs: 7200000, // 2 hours
      successCriteria: [
        {
          metric: 'availability',
          operator: 'greater_than',
          threshold: 99,
          durationMs: 3600000,
        },
        {
          metric: 'error_rate',
          operator: 'less_than',
          threshold: 2,
          durationMs: 7200000,
        },
      ],
      rollbackThresholds: {
        errorRate: 5,
        latencyP95: 1500,
        availability: 95,
      },
      status: 'pending',
    },
  ],
  autoPromote: true,
  autoRollback: true,
  maxDeploymentTimeMs: 14400000, // 4 hours
  notifications: {
    onStart: true,
    onPhaseComplete: true,
    onFailure: true,
    onComplete: true,
    onRollback: true,
  },
});
```

## Monitoring and Observability

### System Metrics

```typescript
// Get comprehensive system status
const statusReport = canarySystemManager.getStatusReport();
console.log('System Status:', statusReport);

// Get detailed metrics
const systemHealth = canarySystemManager.getSystemHealth();
console.log('Feature Flags:', systemHealth.featureFlags);
console.log('Active Deployments:', systemHealth.deployments);
console.log('Health Monitoring:', systemHealth.healthMonitoring);
```

### Health Monitoring

```typescript
// Monitor specific deployment health
const healthMetrics = canaryHealthMonitor.getMetricsHistory('deployment-123', 24);
const healthIssues = canaryHealthMonitor.getHealthIssues('deployment-123');
const healthTrends = await canaryHealthMonitor.getHealthTrends('deployment-123');

// Check for alerts
const activeAlerts = canaryHealthMonitor.getActiveAlerts('deployment-123');
```

### Rollback Analytics

```typescript
// Get rollback statistics
const rollbackStats = rollbackService.getStatistics();
console.log('Rollback Statistics:', rollbackStats);

// Get rollback history
const rollbackHistory = rollbackService.getExecutionHistory(10);
```

## Best Practices

### 1. Deployment Planning

- **Start Small**: Begin with 1-5% traffic for initial testing
- **Gradual Progression**: Use multiple phases with increasing traffic
- **Clear Success Criteria**: Define measurable objectives for each phase
- **Realistic Timeframes**: Allow sufficient time for each phase
- **Comprehensive Monitoring**: Monitor all relevant metrics

### 2. Feature Flag Management

- **Descriptive Names**: Use clear, descriptive flag names
- **Documentation**: Provide descriptions for complex flags
- **Expiration Dates**: Set expiration dates for temporary flags
- **Emergency Controls**: Enable kill switches for critical features
- **Regular Cleanup**: Remove unused flags

### 3. Health Monitoring

- **Multiple Metrics**: Monitor availability, performance, and business metrics
- **Baseline Comparison**: Compare canary against stable baseline
- **Trend Analysis**: Monitor for performance regressions
- **Alert Thresholds**: Set appropriate alert thresholds
- **Automated Responses**: Enable auto-rollback for critical issues

### 4. Rollback Procedures

- **Test Rollbacks**: Regularly test rollback procedures
- **Clear Triggers**: Define clear rollback trigger conditions
- **Approval Workflows**: Use approval workflows for production rollbacks
- **Impact Analysis**: Assess rollback impact before execution
- **Communication**: Notify stakeholders during rollbacks

### 5. Security Considerations

- **Principle of Least Privilege**: Limit access to canary controls
- **Audit Logging**: Log all canary operations
- **Security Validation**: Validate configurations against security policies
- **Encrypted Communications**: Use encrypted channels for sensitive data
- **Regular Reviews**: Regularly review security configurations

## Troubleshooting

### Common Issues

1. **Traffic Not Routing Correctly**
   - Check traffic routing rules
   - Verify target health status
   - Review session affinity settings

2. **Health Checks Failing**
   - Verify health check endpoints
   - Check timeout configurations
   - Review health check intervals

3. **Rollback Not Triggering**
   - Check trigger threshold configurations
   - Verify rollback strategy settings
   - Review approval workflow status

4. **Feature Flags Not Working**
   - Verify flag status and configuration
   - Check user context and targeting
   - Review cache settings

### Debug Information

```typescript
// Enable debug logging
import { logger } from '../src/utils/logger.js';
logger.level = 'debug';

// Get detailed service status
const featureFlagMetrics = featureFlagService.getMetrics();
const trafficMetrics = trafficSplitterService.getMetricsHistory();
const deploymentStatus = canaryOrchestrator.getActiveDeployments();
```

## API Reference

For detailed API documentation, refer to the TypeScript interface definitions in the source files:

- `src/services/canary/feature-flag-service.ts`
- `src/services/canary/kill-switch-service.ts`
- `src/services/canary/canary-orchestrator.ts`
- `src/services/canary/traffic-splitter.ts`
- `src/services/canary/canary-health-monitor.ts`
- `src/services/canary/rollback-service.ts`
- `src/services/canary/config-validator.ts`

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section
2. Review the API documentation
3. Examine the example configurations
4. Contact the development team

## License

This canary deployment system is part of the MCP-Cortex project. See the main project LICENSE file for details.
