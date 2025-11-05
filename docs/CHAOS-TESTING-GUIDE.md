# Chaos Testing Framework Guide

## Overview

The Chaos Testing Framework is a comprehensive system designed to validate the resilience of the MCP Cortex vector store under various failure scenarios. This framework enables hypothesis-driven chaos experiments with comprehensive monitoring, safety controls, and automated verification.

## Architecture

### Core Components

1. **Chaos Injection Engine** (`src/chaos-testing/engine/chaos-injection-engine.ts`)
   - Implements various chaos scenarios (network failures, resource exhaustion, etc.)
   - Manages chaos lifecycle (injection, monitoring, rollback)
   - Provides 10 different injector types for specific failure scenarios

2. **Safety Controller** (`src/chaos-testing/safety/safety-controller.ts`)
   - Blast radius control and containment
   - Emergency shutdown mechanisms
   - Real-time safety monitoring and violation handling

3. **Verification Systems**
   - **Graceful Degradation Verifier**: Validates fallback behavior and circuit breaker patterns
   - **Alert Verifier**: Ensures proper alert triggering and notification
   - **MTTR Measurer**: Tracks Mean Time To Recovery metrics

4. **Experiment Runner** (`src/chaos-testing/runner/chaos-experiment-runner.ts`)
   - Orchestrates complete experiment lifecycle
   - Manages experiment phases and timing
   - Generates comprehensive reports

## Supported Chaos Scenarios

### 1. Qdrant Connection Failures
- **Type**: `qdrant_connection_failure`
- **Failure Modes**: timeout, error, connection_refused
- **Impact**: Database connectivity, vector operations

### 2. Network Issues
- **Network Latency**: `network_latency`
  - Configurable delay and jitter
  - Affects all network calls
- **Packet Loss**: `packet_loss`
  - Configurable loss rate
  - Simulates network unreliability

### 3. Resource Exhaustion
- **CPU Pressure**: `resource_exhaustion` with CPU target
- **Memory Pressure**: `memory_pressure`
- **Disk Exhaustion**: `disk_exhaustion`
- **Configurable intensity levels**

### 4. Database Issues
- **Query Timeouts**: `query_timeout`
- **Circuit Breaker Trips**: `circuit_breaker_trip`
- **Partial Partitions**: `partial_partition`

### 5. Cascade Failures
- **Multi-stage Failures**: `cascade_failure`
- **Configurable failure chains**
- **Escalating intensity patterns**

## Usage Examples

### Basic Experiment Execution

```typescript
import { chaosFramework, ChaosScenarioType } from '../src/chaos-testing';

// Define experiment configuration
const config: ChaosExperimentConfig = {
  id: 'qdrant-failure-test-001',
  name: 'Qdrant Connection Failure Test',
  description: 'Test system behavior when Qdrant becomes unavailable',
  hypothesis: 'System will gracefully degrade to in-memory storage and maintain service availability',
  severity: 'medium',
  duration: 300, // 5 minutes
  blastRadius: 'component',
  safetyChecks: [
    {
      type: 'error_rate',
      threshold: 10,
      comparison: 'less_than',
      metric: 'error_rate_percentage',
      enabled: true
    }
  ],
  steadyStateDuration: 60, // 1 minute
  experimentDuration: 120, // 2 minutes
  recoveryDuration: 180, // 3 minutes
};

// Define chaos scenario
const scenario: ChaosScenario = {
  id: 'qdrant-conn-fail',
  name: 'Qdrant Connection Failure',
  type: 'qdrant_connection_failure',
  config: {
    intensity: 80,
    duration: 120,
    rampUpTime: 10,
    parameters: {
      failureMode: 'timeout',
      timeoutMs: 5000
    }
  },
  injectionPoint: {
    component: 'qdrant-adapter',
    layer: 'database',
    target: 'connection-pool'
  },
  verification: {
    gracefulDegradation: {
      expectedFallback: true,
      maxDegradationTime: 30000,
      minServiceAvailability: 95,
      expectedCircuitBreakerState: 'open',
      userFacingErrors: [
        {
          errorType: 'service_unavailable',
          message: 'Vector search temporarily unavailable',
          expectedRate: 5,
          retryable: true
        }
      ]
    },
    alerting: {
      expectedAlerts: [
        {
          name: 'QdrantConnectionFailure',
          severity: 'critical',
          source: 'qdrant-monitor',
          conditions: ['connection_failed', 'qdrant_unreachable']
        }
      ],
      maxAlertDelay: 30000,
      alertEscalation: true,
      expectedSeverity: ['critical', 'warning']
    },
    recovery: {
      maxRecoveryTime: 60000,
      expectedFinalState: 'healthy',
      dataConsistency: true,
      autoRecovery: true
    },
    performance: {
      maxResponseTimeIncrease: 200, // 200% increase allowed
      maxThroughputDecrease: 50, // 50% decrease allowed
      maxErrorRate: 10, // 10% error rate allowed
      resourceLimits: {
        maxCPUUsage: 80,
        maxMemoryUsage: 85,
        maxDiskIO: 70,
        maxNetworkIO: 75
      }
    }
  }
};

// Define execution context
const context: ExperimentExecutionContext = {
  experimentId: 'exp-001',
  environment: 'staging',
  systemState: 'normal',
  blastRadiusControl: {
    maxAffectedComponents: 1,
    isolationZones: ['chaos-testing-zone'],
    failSafes: [
      {
        trigger: 'error_rate > 10%',
        action: 'abort_experiment',
        threshold: 10
      }
    ]
  },
  monitoring: {
    metricsCollectionInterval: 2000,
    alertingEnabled: true,
    loggingLevel: 'info',
    tracingEnabled: true
  },
  safety: {
    emergencyShutdown: false,
    maxAllowedDowntime: 30000,
    maxAllowedErrorRate: 15,
    healthCheckEndpoints: ['/health', '/api/health'],
    rollbackProcedures: ['rollback-chaos', 'restore-services']
  }
};

// Execute experiment
try {
  const report = await chaosFramework.executeExperiment(config, scenario, context);

  console.log('Experiment completed:', report.summary);
  console.log('Recommendations:', report.recommendations);

  // Generate detailed report
  await generateExperimentReport(report);

} catch (error) {
  console.error('Experiment failed:', error);
}
```

### Custom Chaos Scenario

```typescript
// Create custom network latency scenario
const networkLatencyScenario: ChaosScenario = {
  id: 'network-latency-test',
  name: 'High Network Latency Test',
  type: 'network_latency',
  config: {
    intensity: 60,
    duration: 180,
    rampUpTime: 30,
    parameters: {
      latency: 2000, // 2 second delay
      jitter: 500,  // ±500ms jitter
      affectedHosts: ['qdrant-cluster']
    }
  },
  injectionPoint: {
    component: 'network-layer',
    layer: 'network',
    target: 'outbound-connections'
  },
  verification: {
    // Verification criteria...
  }
};
```

## Experiment Phases

### 1. Setup Phase
- Safety validation
- Environment initialization
- Baseline metrics collection
- Monitoring system setup

### 2. Steady State Phase
- System stability verification
- Baseline establishment
- Pre-chaos metrics collection

### 3. Chaos Injection Phase
- Chaos scenario execution
- Real-time monitoring
- Alert verification
- Degradation tracking

### 4. Verification Phase
- Behavior validation
- Metrics analysis
- Alert verification
- Performance impact assessment

### 5. Recovery Phase
- Chaos rollback
- Recovery monitoring
- MTTR measurement
- Data consistency verification

### 6. Cleanup Phase
- Environment restoration
- Resource cleanup
- Report generation

## Safety Mechanisms

### Blast Radius Control
- Component isolation zones
- Maximum affected components limits
- User impact thresholds
- Business impact assessments

### Automated Safeguards
- Real-time health monitoring
- Threshold-based aborts
- Emergency shutdown procedures
- Automatic rollback capabilities

### Manual Controls
- Emergency stop functionality
- Manual abort triggers
- Override capabilities
- Safety violation logging

## Metrics and Measurements

### System Metrics
- Response time (mean, p50, p95, p99, max)
- Throughput (requests/sec, operations/sec)
- Error rates (total, by type)
- Resource usage (CPU, memory, disk, network)
- Circuit breaker states

### Chaos Metrics
- Injection effectiveness
- System impact patterns
- Degradation patterns
- Alerting response times

### Recovery Metrics
- Time to first recovery sign
- Time to full recovery
- Recovery pattern analysis
- Data consistency verification

### MTTR Metrics
- Mean Time To Detect (MTTD)
- Mean Time To Respond (MTTR)
- Mean Time To Resolve (MTTR)
- Mean Time To Recover (MTTR)

## Verification Criteria

### Graceful Degradation
- Fallback activation verification
- Service availability maintenance
- Circuit breaker behavior validation
- User-facing error handling

### Alert Verification
- Alert triggering accuracy
- Notification delivery verification
- Escalation behavior validation
- Alert timing verification

### Recovery Verification
- Recovery time measurement
- System state restoration
- Data consistency validation
- Automation effectiveness

### Performance Verification
- Response time impact limits
- Throughput degradation limits
- Error rate thresholds
- Resource usage boundaries

## Best Practices

### Experiment Design
1. **Start Small**: Begin with low-severity scenarios
2. **Hypothesis-Driven**: Always have clear hypotheses
3. **Gradual Escalation**: Increase complexity over time
4. **Document Everything**: Maintain detailed experiment logs

### Safety First
1. **Environment Separation**: Never test in production without approval
2. **Blast Radius Control**: Limit impact scope
3. **Monitoring Coverage**: Ensure comprehensive monitoring
4. **Emergency Preparedness**: Have rollback procedures ready

### Measurement Focus
1. **Baseline Establishment**: Always establish steady-state baseline
2. **Comprehensive Metrics**: Collect multiple metric types
3. **Automated Analysis**: Use automated verification where possible
4. **Manual Review**: Always review results manually

### Continuous Improvement
1. **Learn from Failures**: Analyze both successful and failed experiments
2. **Update Scenarios**: Refine scenarios based on results
3. **Expand Coverage**: Gradually increase test coverage
4. **Share Knowledge**: Document and share findings

## Integration with Existing Systems

### Monitoring Integration
The framework integrates with existing monitoring systems:
- **Health Check Service**: Real-time health monitoring
- **Circuit Breaker Monitor**: Circuit breaker state tracking
- **Alert System Integration**: Alert triggering and notification
- **Performance Monitoring**: Real-time performance metrics

### Qdrant Integration
- **Connection Monitoring**: Qdrant connection health
- **Operation Interception**: Chaos injection at database layer
- **Metrics Collection**: Database-specific metrics
- **Recovery Verification**: Data consistency checks

### Service Integration
- **API Gateway**: Request/response interception
- **Load Balancer**: Traffic routing manipulation
- **Monitoring Services**: Metrics collection and analysis
- **Notification Systems**: Alert delivery and escalation

## Troubleshooting

### Common Issues

1. **Safety Validation Failures**
   - Check environment permissions
   - Verify system health status
   - Review blast radius configuration

2. **Chaos Injection Failures**
   - Verify target component accessibility
   - Check injection point configuration
   - Review scenario parameters

3. **Verification Failures**
   - Ensure monitoring systems are active
   - Check verification criteria configuration
   - Review baseline metrics

4. **Recovery Issues**
   - Verify rollback procedures
   - Check system state consistency
   - Review resource availability

### Debug Mode

Enable debug logging for detailed troubleshooting:

```typescript
const context: ExperimentExecutionContext = {
  // ... other properties
  monitoring: {
    metricsCollectionInterval: 1000,
    alertingEnabled: true,
    loggingLevel: 'debug',
    tracingEnabled: true
  }
};
```

## API Reference

### ChaosTestingFramework

#### Methods
- `executeExperiment(config, scenario, context)`: Execute chaos experiment
- `getStatus()`: Get framework status
- `emergencyStop(reason)`: Emergency stop all experiments

### Key Interfaces

#### ChaosExperimentConfig
Experiment configuration including safety checks, duration, and blast radius.

#### ChaosScenario
Chaos scenario definition with type, configuration, and verification criteria.

#### ExperimentExecutionContext
Execution context including environment, safety settings, and monitoring configuration.

#### ExperimentReport
Comprehensive experiment results with phases, metrics, and recommendations.

## Example Experiment Reports

### Successful Experiment
```json
{
  "experimentId": "qdrant-failure-test-001",
  "summary": {
    "totalDuration": 420000,
    "success": true,
    "hypothesisValidated": true,
    "systemResilience": "good",
    "keyFindings": [
      "System successfully activated fallback mechanisms",
      "Alerting system triggered 2 alerts within acceptable time",
      "Recovery completed within 45 seconds"
    ],
    "criticalIssues": []
  },
  "recommendations": [
    "Consider reducing alert delay from 30s to 15s",
    "Implement circuit breaker fine-tuning for faster detection"
  ]
}
```

### Failed Experiment
```json
{
  "experimentId": "resource-exhaustion-test-002",
  "summary": {
    "totalDuration": 180000,
    "success": false,
    "hypothesisValidated": false,
    "systemResilience": "poor",
    "keyFindings": [],
    "criticalIssues": [
      "Graceful degradation mechanisms failed to activate",
      "System exceeded 90% error rate threshold",
      "Recovery time exceeded 5 minute limit"
    ]
  },
  "recommendations": [
    "Implement improved resource monitoring",
    "Add circuit breaker for resource protection",
    "Enhance fallback storage capabilities"
  ]
}
```

## Contributing

When adding new chaos scenarios or verification capabilities:

1. **Follow Existing Patterns**: Use established interfaces and patterns
2. **Add Comprehensive Tests**: Include unit and integration tests
3. **Update Documentation**: Document new features and usage
4. **Safety First**: Always consider safety implications
5. **Monitor Integration**: Ensure proper monitoring integration

## Support

For issues, questions, or contributions:
- Review the existing documentation
- Check experiment logs and metrics
- Contact the chaos testing team
- Review safety guidelines and best practices