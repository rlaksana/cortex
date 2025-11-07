/**
 * Chaos Testing Framework Integration Tests
 *
 * These tests validate the complete chaos testing framework functionality,
 * including injection, verification, safety controls, and reporting.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ChaosTestingFramework } from '../../src/chaos-testing';
import {
  ChaosExperimentConfig,
  ChaosScenario,
  ExperimentExecutionContext,
  ChaosScenarioType,
} from '../../src/chaos-testing/types/chaos-testing-types';

describe('Chaos Testing Framework', () => {
  let framework: ChaosTestingFramework;

  beforeEach(() => {
    framework = new ChaosTestingFramework();
  });

  afterEach(async () => {
    // Clean up any running experiments
    await framework.emergencyStop('Test cleanup');
  });

  describe('Framework Initialization', () => {
    it('should initialize with clean state', () => {
      const status = framework.getStatus();

      expect(status.runningExperiments).toEqual([]);
      expect(status.safetyState.enabled).toBe(false);
      expect(status.activeViolations).toEqual([]);
    });
  });

  describe('Safety Validation', () => {
    it('should reject critical severity experiments in production', async () => {
      const config: ChaosExperimentConfig = {
        id: 'test-critical-prod',
        name: 'Critical Production Test',
        description: 'Test critical scenario in production',
        hypothesis: 'System will handle critical failure',
        severity: 'critical',
        duration: 60,
        blastRadius: 'component',
        safetyChecks: [],
        steadyStateDuration: 10,
        experimentDuration: 30,
        recoveryDuration: 20,
      };

      const scenario: ChaosScenario = {
        id: 'test-scenario',
        name: 'Test Scenario',
        type: 'qdrant_connection_failure',
        config: { intensity: 50, duration: 30, rampUpTime: 5, parameters: {} },
        injectionPoint: { component: 'test', layer: 'application', target: 'test' },
        verification: {
          gracefulDegradation: {
            expectedFallback: true,
            maxDegradationTime: 30000,
            minServiceAvailability: 95,
            expectedCircuitBreakerState: 'open',
            userFacingErrors: [],
          },
          alerting: {
            expectedAlerts: [],
            maxAlertDelay: 30000,
            alertEscalation: false,
            expectedSeverity: [],
          },
          recovery: {
            maxRecoveryTime: 60000,
            expectedFinalState: 'healthy',
            dataConsistency: true,
            autoRecovery: true,
          },
          performance: {
            maxResponseTimeIncrease: 100,
            maxThroughputDecrease: 20,
            maxErrorRate: 5,
            resourceLimits: {
              maxCPUUsage: 80,
              maxMemoryUsage: 85,
              maxDiskIO: 70,
              maxNetworkIO: 75,
            },
          },
        },
      };

      const context: ExperimentExecutionContext = {
        experimentId: 'test-exp',
        environment: 'production',
        systemState: 'normal',
        blastRadiusControl: {
          maxAffectedComponents: 1,
          isolationZones: [],
          failSafes: [],
        },
        monitoring: {
          metricsCollectionInterval: 1000,
          alertingEnabled: true,
          loggingLevel: 'info',
          tracingEnabled: true,
        },
        safety: {
          emergencyShutdown: false,
          maxAllowedDowntime: 30000,
          maxAllowedErrorRate: 10,
          healthCheckEndpoints: [],
          rollbackProcedures: [],
        },
      };

      await expect(framework.executeExperiment(config, scenario, context)).rejects.toThrow(
        'Safety validation failed'
      );
    });
  });

  describe('Chaos Scenario Execution', () => {
    it('should execute simple network latency scenario', async () => {
      const config: ChaosExperimentConfig = {
        id: 'network-latency-test',
        name: 'Network Latency Test',
        description: 'Test system behavior under network latency',
        hypothesis: 'System will maintain availability with increased response times',
        severity: 'low',
        duration: 60,
        blastRadius: 'component',
        safetyChecks: [
          {
            type: 'error_rate',
            threshold: 10,
            comparison: 'less_than',
            metric: 'error_rate_percentage',
            enabled: true,
          },
        ],
        steadyStateDuration: 10,
        experimentDuration: 30,
        recoveryDuration: 20,
      };

      const scenario: ChaosScenario = {
        id: 'network-latency',
        name: 'Network Latency Injection',
        type: 'network_latency',
        config: {
          intensity: 30,
          duration: 30,
          rampUpTime: 5,
          parameters: {
            latency: 500,
            jitter: 100,
          },
        },
        injectionPoint: {
          component: 'http-client',
          layer: 'network',
          target: 'outbound-calls',
        },
        verification: {
          gracefulDegradation: {
            expectedFallback: false,
            maxDegradationTime: 15000,
            minServiceAvailability: 98,
            expectedCircuitBreakerState: 'closed',
            userFacingErrors: [],
          },
          alerting: {
            expectedAlerts: [
              {
                name: 'HighLatencyDetected',
                severity: 'warning',
                source: 'network-monitor',
                conditions: ['latency_threshold_exceeded'],
              },
            ],
            maxAlertDelay: 60000,
            alertEscalation: false,
            expectedSeverity: ['warning'],
          },
          recovery: {
            maxRecoveryTime: 30000,
            expectedFinalState: 'healthy',
            dataConsistency: true,
            autoRecovery: true,
          },
          performance: {
            maxResponseTimeIncrease: 150,
            maxThroughputDecrease: 10,
            maxErrorRate: 2,
            resourceLimits: {
              maxCPUUsage: 70,
              maxMemoryUsage: 75,
              maxDiskIO: 50,
              maxNetworkIO: 60,
            },
          },
        },
      };

      const context: ExperimentExecutionContext = {
        experimentId: 'test-network-latency',
        environment: 'staging',
        systemState: 'normal',
        blastRadiusControl: {
          maxAffectedComponents: 1,
          isolationZones: ['chaos-testing'],
          failSafes: [
            {
              trigger: 'error_rate > 10%',
              action: 'abort_experiment',
              threshold: 10,
            },
          ],
        },
        monitoring: {
          metricsCollectionInterval: 2000,
          alertingEnabled: true,
          loggingLevel: 'info',
          tracingEnabled: true,
        },
        safety: {
          emergencyShutdown: false,
          maxAllowedDowntime: 15000,
          maxAllowedErrorRate: 5,
          healthCheckEndpoints: ['/health', '/api/health'],
          rollbackProcedures: ['rollback-chaos', 'restore-network'],
        },
      };

      const report = await framework.executeExperiment(config, scenario, context);

      expect(report.experimentId).toBe(config.id);
      expect(report.summary.success).toBe(true);
      expect(report.phases.length).toBeGreaterThan(0);
      expect(report.artifacts.length).toBeGreaterThan(0);
    }, 120000); // 2 minute timeout
  });

  describe('Emergency Stop', () => {
    it('should handle emergency stop gracefully', async () => {
      // Start a long-running experiment in the background
      const config: ChaosExperimentConfig = {
        id: 'long-running-test',
        name: 'Long Running Test',
        description: 'Test emergency stop functionality',
        hypothesis: 'System can be safely stopped during experiment',
        severity: 'low',
        duration: 300,
        blastRadius: 'component',
        safetyChecks: [],
        steadyStateDuration: 10,
        experimentDuration: 120,
        recoveryDuration: 30,
      };

      const scenario: ChaosScenario = {
        id: 'memory-pressure',
        name: 'Memory Pressure Test',
        type: 'memory_pressure',
        config: {
          intensity: 20,
          duration: 120,
          rampUpTime: 10,
          parameters: {
            pressureLevel: 60,
          },
        },
        injectionPoint: {
          component: 'system',
          layer: 'infrastructure',
          target: 'memory',
        },
        verification: {
          gracefulDegradation: {
            expectedFallback: false,
            maxDegradationTime: 30000,
            minServiceAvailability: 95,
            expectedCircuitBreakerState: 'closed',
            userFacingErrors: [],
          },
          alerting: {
            expectedAlerts: [],
            maxAlertDelay: 60000,
            alertEscalation: false,
            expectedSeverity: [],
          },
          recovery: {
            maxRecoveryTime: 30000,
            expectedFinalState: 'healthy',
            dataConsistency: true,
            autoRecovery: true,
          },
          performance: {
            maxResponseTimeIncrease: 50,
            maxThroughputDecrease: 10,
            maxErrorRate: 2,
            resourceLimits: {
              maxCPUUsage: 80,
              maxMemoryUsage: 85,
              maxDiskIO: 50,
              maxNetworkIO: 50,
            },
          },
        },
      };

      const context: ExperimentExecutionContext = {
        experimentId: 'test-emergency-stop',
        environment: 'staging',
        systemState: 'normal',
        blastRadiusControl: {
          maxAffectedComponents: 1,
          isolationZones: ['chaos-testing'],
          failSafes: [],
        },
        monitoring: {
          metricsCollectionInterval: 2000,
          alertingEnabled: true,
          loggingLevel: 'info',
          tracingEnabled: true,
        },
        safety: {
          emergencyShutdown: false,
          maxAllowedDowntime: 30000,
          maxAllowedErrorRate: 5,
          healthCheckEndpoints: ['/health'],
          rollbackProcedures: ['cleanup-memory', 'restore-system'],
        },
      };

      // Start experiment (don't await)
      const experimentPromise = framework.executeExperiment(config, scenario, context);

      // Wait a bit for experiment to start
      await new Promise((resolve) => setTimeout(resolve, 5000));

      // Trigger emergency stop
      await framework.emergencyStop('Test emergency stop');

      // The experiment should be stopped/cancelled
      const status = framework.getStatus();
      expect(status.runningExperiments).toEqual([]);
      expect(status.safetyState.emergencyShutdown).toBe(true);
    }, 30000); // 30 second timeout
  });

  describe('Scenario Types', () => {
    const scenarioTypes: ChaosScenarioType[] = [
      'qdrant_connection_failure',
      'network_latency',
      'packet_loss',
      'query_timeout',
      'resource_exhaustion',
      'memory_pressure',
      'disk_exhaustion',
      'circuit_breaker_trip',
      'cascade_failure',
      'partial_partition',
    ];

    scenarioTypes.forEach((scenarioType) => {
      it(`should support ${scenarioType} scenario type`, async () => {
        const config: ChaosExperimentConfig = {
          id: `${scenarioType}-test`,
          name: `${scenarioType} Test`,
          description: `Test ${scenarioType} scenario`,
          hypothesis: `System handles ${scenarioType} gracefully`,
          severity: 'low',
          duration: 60,
          blastRadius: 'component',
          safetyChecks: [],
          steadyStateDuration: 5,
          experimentDuration: 20,
          recoveryDuration: 15,
        };

        const scenario: ChaosScenario = {
          id: `${scenarioType}-scenario`,
          name: `${scenarioType} Scenario`,
          type: scenarioType,
          config: {
            intensity: 20,
            duration: 20,
            rampUpTime: 5,
            parameters: {},
          },
          injectionPoint: {
            component: 'test-component',
            layer: 'application',
            target: 'test-target',
          },
          verification: {
            gracefulDegradation: {
              expectedFallback: false,
              maxDegradationTime: 30000,
              minServiceAvailability: 95,
              expectedCircuitBreakerState: 'closed',
              userFacingErrors: [],
            },
            alerting: {
              expectedAlerts: [],
              maxAlertDelay: 60000,
              alertEscalation: false,
              expectedSeverity: [],
            },
            recovery: {
              maxRecoveryTime: 30000,
              expectedFinalState: 'healthy',
              dataConsistency: true,
              autoRecovery: true,
            },
            performance: {
              maxResponseTimeIncrease: 100,
              maxThroughputDecrease: 20,
              maxErrorRate: 5,
              resourceLimits: {
                maxCPUUsage: 80,
                maxMemoryUsage: 85,
                maxDiskIO: 70,
                maxNetworkIO: 75,
              },
            },
          },
        };

        const context: ExperimentExecutionContext = {
          experimentId: `test-${scenarioType}`,
          environment: 'staging',
          systemState: 'normal',
          blastRadiusControl: {
            maxAffectedComponents: 1,
            isolationZones: ['chaos-testing'],
            failSafes: [],
          },
          monitoring: {
            metricsCollectionInterval: 2000,
            alertingEnabled: true,
            loggingLevel: 'info',
            tracingEnabled: true,
          },
          safety: {
            emergencyShutdown: false,
            maxAllowedDowntime: 30000,
            maxAllowedErrorRate: 10,
            healthCheckEndpoints: ['/health'],
            rollbackProcedures: ['rollback-test'],
          },
        };

        // This should not throw during initialization
        const report = await framework.executeExperiment(config, scenario, context);
        expect(report.experimentId).toBe(config.id);
      }, 60000); // 1 minute timeout per scenario
    });
  });

  describe('Report Generation', () => {
    it('should generate comprehensive experiment reports', async () => {
      const config: ChaosExperimentConfig = {
        id: 'report-generation-test',
        name: 'Report Generation Test',
        description: 'Test comprehensive report generation',
        hypothesis: 'Framework generates detailed reports',
        severity: 'low',
        duration: 60,
        blastRadius: 'component',
        safetyChecks: [],
        steadyStateDuration: 5,
        experimentDuration: 15,
        recoveryDuration: 10,
      };

      const scenario: ChaosScenario = {
        id: 'test-scenario',
        name: 'Test Scenario',
        type: 'network_latency',
        config: {
          intensity: 15,
          duration: 15,
          rampUpTime: 3,
          parameters: { latency: 200, jitter: 50 },
        },
        injectionPoint: {
          component: 'test-component',
          layer: 'network',
          target: 'test-target',
        },
        verification: {
          gracefulDegradation: {
            expectedFallback: false,
            maxDegradationTime: 20000,
            minServiceAvailability: 97,
            expectedCircuitBreakerState: 'closed',
            userFacingErrors: [],
          },
          alerting: {
            expectedAlerts: [],
            maxAlertDelay: 60000,
            alertEscalation: false,
            expectedSeverity: [],
          },
          recovery: {
            maxRecoveryTime: 20000,
            expectedFinalState: 'healthy',
            dataConsistency: true,
            autoRecovery: true,
          },
          performance: {
            maxResponseTimeIncrease: 80,
            maxThroughputDecrease: 15,
            maxErrorRate: 3,
            resourceLimits: {
              maxCPUUsage: 75,
              maxMemoryUsage: 80,
              maxDiskIO: 60,
              maxNetworkIO: 65,
            },
          },
        },
      };

      const context: ExperimentExecutionContext = {
        experimentId: 'test-report',
        environment: 'staging',
        systemState: 'normal',
        blastRadiusControl: {
          maxAffectedComponents: 1,
          isolationZones: ['chaos-testing'],
          failSafes: [],
        },
        monitoring: {
          metricsCollectionInterval: 2000,
          alertingEnabled: true,
          loggingLevel: 'info',
          tracingEnabled: true,
        },
        safety: {
          emergencyShutdown: false,
          maxAllowedDowntime: 20000,
          maxAllowedErrorRate: 8,
          healthCheckEndpoints: ['/health'],
          rollbackProcedures: ['rollback-test'],
        },
      };

      const report = await framework.executeExperiment(config, scenario, context);

      // Verify report structure
      expect(report.experimentId).toBeDefined();
      expect(report.config).toBeDefined();
      expect(report.phases).toBeDefined();
      expect(report.phases.length).toBeGreaterThan(0);
      expect(report.summary).toBeDefined();
      expect(report.recommendations).toBeDefined();
      expect(report.artifacts).toBeDefined();

      // Verify phases
      const expectedPhases = [
        'setup',
        'steady_state',
        'chaos_injection',
        'verification',
        'recovery',
        'cleanup',
      ];
      const actualPhases = report.phases.map((p) => p.name);
      expectedPhases.forEach((phase) => {
        expect(actualPhases).toContain(phase);
      });

      // Verify summary
      expect(report.summary.totalDuration).toBeGreaterThan(0);
      expect(typeof report.summary.success).toBe('boolean');
      expect(typeof report.summary.hypothesisValidated).toBe('boolean');
      expect(['excellent', 'good', 'fair', 'poor']).toContain(report.summary.systemResilience);
      expect(Array.isArray(report.summary.keyFindings)).toBe(true);
      expect(Array.isArray(report.summary.criticalIssues)).toBe(true);

      // Verify recommendations
      expect(Array.isArray(report.recommendations)).toBe(true);

      // Verify artifacts
      expect(Array.isArray(report.artifacts)).toBe(true);
    }, 45000); // 45 second timeout
  });
});
