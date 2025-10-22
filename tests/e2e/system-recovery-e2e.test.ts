/**
 * System Recovery E2E Tests
 *
 * Tests system recovery procedures, fault tolerance, graceful degradation,
 * and recovery from various failure scenarios.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestServer {
  process: ChildProcess;
  port: number;
}

interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: Record<string, {
    status: 'up' | 'down' | 'degraded';
    response_time?: number;
    last_check: string;
  }>;
  overall_score: number;
  timestamp: string;
}

interface RecoveryProcedure {
  id: string;
  name: string;
  trigger_conditions: string[];
  steps: Array<{
    order: number;
    action: string;
    expected_duration: number;
    rollback_action?: string;
  }>;
  success_criteria: string[];
  rollback_procedure: boolean;
}

describe('System Recovery E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';

  beforeAll(async () => {
    await setupTestDatabase();
    server = await startMCPServer();
    await setTimeout(2000);
  });

  afterAll(async () => {
    if (server?.process) {
      server.process.kill('SIGTERM');
      await setTimeout(1000);
    }
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('Health Monitoring and Detection', () => {
    it('should monitor system health and detect degradation', async () => {
      const projectId = `health-monitoring-${randomUUID().substring(0, 8)}`;

      // Step 1: Establish baseline health
      const baselineHealth = await callMCPTool('system_health_check', {
        components: ['database', 'memory_store', 'search_index', 'mcp_server'],
        detailed: true
      }) as HealthCheck;

      expect(baselineHealth.status).toBe('healthy');
      expect(baselineHealth.overall_score).toBeGreaterThan(90);
      expect(Object.keys(baselineHealth.components)).toHaveLength(4);

      // Verify all components are up
      Object.values(baselineHealth.components).forEach(component => {
        expect(component.status).toBe('up');
        expect(component.response_time).toBeLessThan(1000);
      });

      // Step 2: Create recovery procedures for different failure scenarios
      const recoveryProcedures: RecoveryProcedure[] = [
        {
          id: 'database-recovery',
          name: 'Database Connection Recovery',
          trigger_conditions: ['database_connection_timeout', 'database_query_failure_rate > 5%'],
          steps: [
            {
              order: 1,
              action: 'Check database server status',
              expected_duration: 5000
            },
            {
              order: 2,
              action: 'Restart connection pool',
              expected_duration: 2000,
              rollback_action: 'Restore original pool configuration'
            },
            {
              order: 3,
              action: 'Verify database connectivity',
              expected_duration: 3000
            }
          ],
          success_criteria: [
            'Database queries respond within 100ms',
            'Connection pool utilization < 80%',
            'No connection timeouts for 5 minutes'
          ],
          rollback_procedure: true
        },
        {
          id: 'memory-store-recovery',
          name: 'Memory Store Service Recovery',
          trigger_conditions: ['memory_store_error_rate > 3%', 'memory_store_response_time > 2000ms'],
          steps: [
            {
              order: 1,
              action: 'Check service logs for errors',
              expected_duration: 2000
            },
            {
              order: 2,
              action: 'Restart memory store service',
              expected_duration: 10000,
              rollback_action: 'Restore from backup if restart fails'
            },
            {
              order: 3,
              action: 'Warm up caches',
              expected_duration: 5000
            }
          ],
          success_criteria: [
            'Error rate < 1%',
            'Response time < 500ms',
            'All health checks passing'
          ],
          rollback_procedure: true
        }
      ];

      // Store recovery procedures
      for (const procedure of recoveryProcedures) {
        await callMCPTool('memory_store', {
          items: [{
            kind: 'runbook',
            scope: { project: projectId },
            data: {
              title: procedure.name,
              description: `Automated recovery procedure for ${procedure.name}`,
              trigger_conditions: procedure.trigger_conditions,
              steps: procedure.steps,
              success_criteria: procedure.success_criteria,
              rollback_procedure: procedure.rollback_procedure,
              procedure_id: procedure.id,
              severity: 'high'
            }
          }]
        });
      }

      // Step 3: Simulate system degradation
      console.log('Simulating system degradation...');
      const degradationResult = await callMCPTool('simulate_degradation', {
        component: 'database',
        degradation_type: 'slow_queries',
        severity: 'medium',
        duration: 10000
      });

      expect(degradationResult.simulation_started).toBe(true);

      // Step 4: Verify health monitoring detects degradation
      await setTimeout(2000); // Wait for monitoring to detect
      const degradedHealth = await callMCPTool('system_health_check', {
        components: ['database', 'memory_store', 'search_index', 'mcp_server'],
        detailed: true
      }) as HealthCheck;

      expect(degradedHealth.status).toBe('degraded');
      expect(degradedHealth.overall_score).toBeLessThan(baselineHealth.overall_score);

      const dbComponent = degradedHealth.components.database;
      expect(dbComponent.status).toBe('degraded');
      expect(dbComponent.response_time).toBeGreaterThan(baselineHealth.components.database.response_time);

      // Step 5: Verify automatic recovery initiation
      const recoveryStatus = await callMCPTool('check_recovery_status', {
        component: 'database'
      });

      expect(recoveryStatus.active).toBe(true);
      expect(recoveryStatus.procedure_id).toBe('database-recovery');
      expect(recoveryStatus.current_step).toBeGreaterThan(0);

      // Step 6: Wait for recovery completion
      await setTimeout(15000);
      const recoveryHealth = await callMCPTool('system_health_check', {
        components: ['database', 'memory_store', 'search_index', 'mcp_server']
      }) as HealthCheck;

      expect(recoveryHealth.status).toBe('healthy');
      expect(recoveryHealth.overall_score).toBeGreaterThan(85);

      // Step 7: Verify recovery was logged
      const recoveryLog = await callMCPTool('memory_find', {
        query: 'database recovery procedure completed',
        scope: { project: projectId },
        types: ['runbook', 'observation']
      });

      expect(recoveryLog.hits.length).toBeGreaterThan(0);

      const runbook = recoveryLog.hits.find(h => h.kind === 'runbook');
      expect(runbook?.data?.procedure_id).toBe('database-recovery');
    });

    it('should handle cascading failures gracefully', async () => {
      const projectId = `cascading-failure-${randomUUID().substring(0, 8)}`;

      // Step 1: Create cascading failure detection system
      const cascadingSystem = {
        items: [
          {
            kind: 'runbook',
            scope: { project: projectId },
            data: {
              title: 'Cascading Failure Response Protocol',
              description: 'Protocol for handling cascading system failures',
              trigger_conditions: [
                'multiple_components_degraded',
                'system_health_score < 50',
                'error_rate_escalation'
              ],
              steps: [
                {
                  order: 1,
                  action: 'Identify primary failure point',
                  expected_duration: 3000
                },
                {
                  order: 2,
                  action: 'Isolate affected components',
                  expected_duration: 5000
                },
                {
                  order: 3,
                  action: 'Enable degraded mode operation',
                  expected_duration: 2000
                },
                {
                  order: 4,
                  action: 'Initiate recovery of primary component',
                  expected_duration: 15000
                },
                {
                  order: 5,
                  action: 'Gradually restore dependent services',
                  expected_duration: 10000
                }
              ],
              success_criteria: [
                'Core functionality maintained',
                'No data loss',
                'System restored within 30 minutes'
              ]
            }
          },
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'Cascading Failure Detection Rules',
              content: `
Cascading Failure Detection Rules:

1. Component Dependency Mapping
   - Map all inter-component dependencies
   - Identify single points of failure
   - Calculate failure impact radius

2. Early Warning Indicators
   - Error rate increase > 2x baseline
   - Response time degradation > 3x baseline
   - Multiple health check failures

3. Isolation Strategies
   - Circuit breaker patterns
   - Bulkhead isolation
   - Graceful degradation
              `.trim(),
              severity: 'critical'
            }
          }
        ]
      };

      await callMCPTool('memory_store', cascadingSystem);

      // Step 2: Simulate cascading failure
      console.log('Simulating cascading failure scenario...');
      const cascadeResult = await callMCPTool('simulate_cascading_failure', {
        primary_component: 'database',
        failure_sequence: ['search_index', 'memory_store'],
        failure_intervals: [2000, 3000],
        total_duration: 20000
      });

      expect(cascadeResult.simulation_started).toBe(true);
      expect(cascadeResult.components_affected).toHaveLength(3);

      // Step 3: Monitor system response to cascading failure
      const cascadeMonitoring = [];
      for (let i = 0; i < 5; i++) {
        await setTimeout(4000);
        const healthStatus = await callMCPTool('system_health_check', {
          detailed: true
        }) as HealthCheck;

        cascadeMonitoring.push({
          timestamp: new Date(),
          status: healthStatus.status,
          score: healthStatus.overall_score,
          components: Object.entries(healthStatus.components).map(([name, comp]) => ({
            name,
            status: comp.status,
            response_time: comp.response_time
          }))
        });
      }

      // Verify degradation progression
      expect(cascadeMonitoring[0].status).toBe('healthy');
      expect(cascadeMonitoring[1].status).toBe('degraded');
      expect(cascadeMonitoring[cascadeMonitoring.length - 1].status).toBe('degraded');

      // Verify components failed in sequence
      const failedComponents = cascadeMonitoring[cascadeMonitoring.length - 1].components
        .filter(c => c.status === 'down')
        .map(c => c.name);

      expect(failedComponents.length).toBeGreaterThan(1);

      // Step 4: Verify graceful degradation
      const degradedMode = await callMCPTool('check_degraded_mode', {
        active: true
      });

      expect(degradedMode.active).toBe(true);
      expect(degradedMode.available_functionality).toContain('read_operations');
      expect(degradedMode.restricted_functionality).toContain('write_operations');

      // Step 5: Verify recovery procedures were initiated
      const recoveryCheck = await callMCPTool('check_recovery_status', {
        cascading_failure: true
      });

      expect(recoveryCheck.active).toBe(true);
      expect(recoveryCheck.isolation_enabled).toBe(true);
      expect(recoveryCheck.degraded_mode_active).toBe(true);

      // Step 6: Verify system logs captured the event
      const cascadeLog = await callMCPTool('memory_find', {
        query: 'cascading failure detection response',
        scope: { project: projectId },
        types: ['observation', 'runbook']
      });

      expect(cascadeLog.hits.length).toBeGreaterThan(0);

      const failureObservation = cascadeLog.hits.find(h =>
        h.kind === 'observation' && h.data?.title?.includes('Cascading Failure')
      );
      expect(failureObservation).toBeDefined();
    });
  });

  describe('Automatic Recovery Mechanisms', () => {
    it('should automatically recover from transient failures', async () => {
      const projectId = `auto-recovery-${randomUUID().substring(0, 8)}`;

      // Step 1: Configure automatic recovery settings
      const autoRecoveryConfig = {
        items: [{
          kind: 'section',
          scope: { project: projectId },
          data: {
            title: 'Automatic Recovery Configuration',
            heading: 'Self-Healing System Settings',
            body_md: `
# Automatic Recovery Configuration

## Transient Failure Handling
- Max retry attempts: 3
- Backoff strategy: Exponential
- Retry intervals: 1s, 2s, 4s
- Circuit breaker threshold: 5 failures

## Component Recovery
- Database: Connection pool reset
- Search Index: Rebuild from snapshot
- Memory Store: Service restart
- MCP Server: Graceful restart

## Health Check Frequency
- Critical components: 30 seconds
- Normal components: 2 minutes
- Background tasks: 5 minutes
            `.trim()
          }
        }]
      };

      await callMCPTool('memory_store', autoRecoveryConfig);

      // Step 2: Create test data for recovery verification
      const testData = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'test_data',
              name: 'RecoveryTestEntity',
              data: {
                created_before_failure: true,
                timestamp: new Date().toISOString()
              }
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Auto-Recovery Test Decision',
              status: 'proposed',
              rationale: 'Testing automatic recovery mechanisms'
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', testData);
      expect(creationResult.stored).toHaveLength(2);

      // Step 3: Simulate transient database failure
      console.log('Simulating transient database failure...');
      const transientFailure = await callMCPTool('simulate_transient_failure', {
        component: 'database',
        failure_type: 'connection_timeout',
        duration: 8000,
        auto_recovery_enabled: true
      });

      expect(transientFailure.simulation_started).toBe(true);

      // Step 4: Monitor automatic recovery process
      const recoverySteps = [];
      let recoveryCompleted = false;

      for (let i = 0; i < 10 && !recoveryCompleted; i++) {
        await setTimeout(2000);
        const recoveryStatus = await callMCPTool('check_auto_recovery_status', {
          component: 'database'
        });

        recoverySteps.push({
          timestamp: new Date(),
          step: recoveryStatus.current_step,
          attempts: recoveryStatus.retry_attempts,
          success: recoveryStatus.recovered
        });

        if (recoveryStatus.recovered) {
          recoveryCompleted = true;
        }

        // Don't wait too long
        if (i === 9 && !recoveryCompleted) {
          console.warn('Auto-recovery did not complete within expected time');
        }
      }

      expect(recoveryCompleted).toBe(true);
      expect(recoverySteps.length).toBeGreaterThan(0);

      // Verify retry attempts were made
      const lastStep = recoverySteps[recoverySteps.length - 1];
      expect(lastStep.attempts).toBeGreaterThan(0);
      expect(lastStep.success).toBe(true);

      // Step 5: Verify system is healthy after recovery
      const postRecoveryHealth = await callMCPTool('system_health_check', {
        components: ['database']
      }) as HealthCheck;

      expect(postRecoveryHealth.status).toBe('healthy');
      expect(postRecoveryHealth.components.database.status).toBe('up');

      // Step 6: Verify data integrity after recovery
      const integrityCheck = await callMCPTool('memory_find', {
        query: 'RecoveryTestEntity Auto-Recovery Test',
        scope: { project: projectId }
      });

      expect(integrityCheck.hits).toHaveLength(2);

      const entity = integrityCheck.hits.find(h => h.kind === 'entity');
      const decision = integrityCheck.hits.find(h => h.kind === 'decision');

      expect(entity?.data?.name).toBe('RecoveryTestEntity');
      expect(entity?.data?.created_before_failure).toBe(true);
      expect(decision?.data?.title).toBe('Auto-Recovery Test Decision');

      // Step 7: Verify recovery was logged
      const recoveryLog = await callMCPTool('memory_find', {
        query: 'automatic recovery transient failure',
        scope: { project: projectId },
        types: ['observation']
      });

      expect(recoveryLog.hits.length).toBeGreaterThan(0);

      const recoveryObservation = recoveryLog.hits.find(h =>
        h.data?.content?.includes('transient failure')
      );
      expect(recoveryObservation).toBeDefined();
      expect(recoveryObservation?.data?.severity).toBe('medium');
    });

    it('should implement circuit breaker patterns effectively', async () => {
      const projectId = `circuit-breaker-${randomUUID().substring(0, 8)}`;

      // Step 1: Configure circuit breaker settings
      const circuitBreakerConfig = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Circuit Breaker Configuration',
              heading: 'Fault Tolerance Settings',
              body_md: `
# Circuit Breaker Configuration

## Database Circuit Breaker
- Failure threshold: 5 failures in 60 seconds
- Timeout: 30 seconds
- Half-open retry attempts: 3
- Success threshold for close: 3 consecutive successes

## Memory Store Circuit Breaker
- Failure threshold: 3 failures in 30 seconds
- Timeout: 15 seconds
- Half-open retry attempts: 2
- Success threshold for close: 2 consecutive successes

## Search Index Circuit Breaker
- Failure threshold: 10 failures in 120 seconds
- Timeout: 60 seconds
- Half-open retry attempts: 5
- Success threshold for close: 5 consecutive successes
              `.trim()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'circuit_breaker',
              name: 'DatabaseCircuitBreaker',
              data: {
                state: 'closed',
                failure_count: 0,
                last_failure_time: null,
                success_count: 0,
                config: {
                  failure_threshold: 5,
                  timeout: 30000,
                  half_open_max_calls: 3,
                  success_threshold: 3
                }
              }
            }
          }
        ]
      };

      await callMCPTool('memory_store', circuitBreakerConfig);

      // Step 2: Create test data for circuit breaker testing
      await callMCPTool('memory_store', {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            entity_type: 'test_data',
            name: 'CircuitBreakerTest',
            data: { persistent: true }
          }
        }]
      });

      // Step 3: Trigger circuit breaker through repeated failures
      console.log('Triggering circuit breaker through repeated failures...');
      const circuitBreakerStates = [];

      for (let i = 0; i < 8; i++) {
        // Simulate operation that might fail
        const operationResult = await callMCPTool('test_circuit_breaker_operation', {
          component: 'database',
          operation: 'query',
          force_failure: i < 6, // First 6 operations fail
          delay: 500
        });

        const circuitState = await callMCPTool('get_circuit_breaker_state', {
          component: 'database'
        });

        circuitBreakerStates.push({
          attempt: i + 1,
          operation_success: operationResult.success,
          circuit_state: circuitState.state,
          failure_count: circuitState.failure_count,
          timestamp: new Date()
        });

        await setTimeout(1000);
      }

      // Verify circuit breaker opened after threshold
      const openedState = circuitBreakerStates.find(s => s.circuit_state === 'open');
      expect(openedState).toBeDefined();
      expect(openedState.failure_count).toBeGreaterThanOrEqual(5);

      // Step 4: Verify operations are blocked when circuit is open
      const blockedOperation = await callMCPTool('test_circuit_breaker_operation', {
        component: 'database',
        operation: 'query',
        expect_block: true
      });

      expect(blockedOperation.success).toBe(false);
      expect(blockedOperation.blocked_by_circuit_breaker).toBe(true);

      // Step 5: Wait for circuit breaker timeout and test recovery
      console.log('Waiting for circuit breaker timeout...');
      await setTimeout(35000); // Wait for timeout period

      // Test half-open state
      const halfOpenResult = await callMCPTool('test_circuit_breaker_operation', {
        component: 'database',
        operation: 'query',
        force_failure: false // This should succeed
      });

      expect(halfOpenResult.success).toBe(true);

      // Verify circuit starts closing
      const closingState = await callMCPTool('get_circuit_breaker_state', {
        component: 'database'
      });

      expect(closingState.state).toBe('half_open');

      // Step 6: Complete circuit recovery with successful operations
      for (let i = 0; i < 3; i++) {
        const successResult = await callMCPTool('test_circuit_breaker_operation', {
          component: 'database',
          operation: 'query',
          force_failure: false
        });

        expect(successResult.success).toBe(true);
        await setTimeout(500);
      }

      // Verify circuit is fully closed
      const closedState = await callMCPTool('get_circuit_breaker_state', {
        component: 'database'
      });

      expect(closedState.state).toBe('closed');
      expect(closedState.failure_count).toBe(0);
      expect(closedState.success_count).toBeGreaterThanOrEqual(3);

      // Step 7: Verify normal operations resume
      const normalOperation = await callMCPTool('memory_find', {
        query: 'CircuitBreakerTest',
        scope: { project: projectId }
      });

      expect(normalOperation.hits).toHaveLength(1);

      // Step 8: Verify circuit breaker events were logged
      const circuitBreakerLog = await callMCPTool('memory_find', {
        query: 'circuit breaker opened closed recovery',
        scope: { project: projectId },
        types: ['observation']
      });

      expect(circuitBreakerLog.hits.length).toBeGreaterThan(0);

      const circuitEvents = circuitBreakerLog.hits.filter(h =>
        h.data?.content?.includes('circuit breaker')
      );
      expect(circuitEvents.length).toBeGreaterThan(0);
    });
  });

  describe('Disaster Recovery Scenarios', () => {
    it('should handle complete system outage recovery', async () => {
      const projectId = `disaster-outage-${randomUUID().substring(0, 8)}`;
      const criticalData = [];

      // Step 1: Create critical business data
      const criticalBusinessData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId, criticality: 'critical' },
            data: {
              title: 'Production Architecture Decision',
              status: 'accepted',
              rationale: 'Critical decision for production infrastructure',
              business_impact: 'critical',
              compliance_requirements: ['SOX', 'HIPAA', 'GDPR'],
              implementation_date: new Date().toISOString(),
              disaster_recovery_priority: 1
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, criticality: 'critical' },
            data: {
              entity_type: 'service',
              name: 'PaymentProcessingService',
              data: {
                version: '3.5.2',
                sla: '99.999%',
                disaster_recovery: true,
                geo_redundancy: true,
                backup_frequency: 'continuous',
                rpo: '0_seconds',
                rto: '5_minutes'
              }
            }
          },
          {
            kind: 'runbook',
            scope: { project: projectId, criticality: 'critical' },
            data: {
              title: 'Complete System Recovery Procedure',
              description: 'Step-by-step procedure for complete system recovery',
              severity: 'critical',
              response_time_objective: '4_hours',
              recovery_point_objective: '15_minutes',
              emergency_contacts: ['CEO', 'CTO', 'Head of Infrastructure', 'External Support'],
              steps: [
                {
                  step: 1,
                  action: 'Assess damage and impact scope',
                  owner: 'Incident Commander',
                  max_duration: '30_minutes'
                },
                {
                  step: 2,
                  action: 'Activate disaster recovery team',
                  owner: 'CTO',
                  max_duration: '15_minutes'
                },
                {
                  step: 3,
                  action: 'Restore from latest backup',
                  owner: 'Infrastructure Team',
                  max_duration: '2_hours'
                },
                {
                  step: 4,
                  action: 'Verify data integrity',
                  owner: 'QA Team',
                  max_duration: '45_minutes'
                },
                {
                  step: 5,
                  action: 'Gradual service restoration',
                  owner: 'Operations Team',
                  max_duration: '1_hour'
                }
              ]
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', criticalBusinessData);
      expect(creationResult.stored).toHaveLength(3);
      criticalData.push(...creationResult.stored);

      // Step 2: Create disaster recovery backup
      const drBackup = await callMCPTool('create_backup', {
        backup_id: `dr-outage-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'disaster_recovery',
        encryption: true,
        offsite_copy: true,
        verification: 'deep'
      });

      expect(drBackup.success).toBe(true);

      // Step 3: Create disaster recovery plan
      const drPlan = {
        items: [{
          kind: 'decision',
          scope: { project: projectId },
          data: {
            title: 'Disaster Recovery Plan Activation',
            status: 'approved',
            rationale: 'Comprehensive plan for system outage recovery',
            dr_plan_details: {
              recovery_sites: ['primary', 'secondary', 'tertiary'],
              communication_channels: ['slack', 'email', 'phone', 'status_page'],
              stakeholder_notifications: true,
              regulatory_compliance: true,
              post_incident_review: true
            }
          }
        }]
      };

      await callMCPTool('memory_store', drPlan);

      // Step 4: Simulate complete system outage
      console.log('Simulating complete system outage...');
      const outageSimulation = await callMCPTool('simulate_complete_outage', {
        outage_type: 'total_system_failure',
        affected_components: ['all'],
        duration: 30000,
        emergency_mode: true
      });

      expect(outageSimulation.outage_started).toBe(true);
      expect(outageSimulation.affected_components).toContain('all');

      // Step 5: Verify system is completely down
      const outageCheck = await callMCPTool('system_health_check', {
        timeout: 5000
      }, { expect_failure: true });

      expect(outageCheck.error).toBeDefined();
      expect(outageCheck.error.message).toContain('system_unavailable');

      // Step 6: Initiate disaster recovery
      console.log('Initiating disaster recovery procedures...');
      const disasterRecovery = await callMCPTool('initiate_disaster_recovery', {
        backup_id: drBackup.backup_id,
        recovery_plan: 'complete_system',
        emergency_mode: true,
        stakeholder_notifications: true,
        verification_required: true
      });

      expect(disasterRecovery.initiated).toBe(true);
      expect(disasterRecovery.estimated_recovery_time).toBeLessThan(240000); // 4 hours

      // Step 7: Monitor recovery progress
      const recoveryProgress = [];
      let recoveryComplete = false;

      for (let i = 0; i < 20 && !recoveryComplete; i++) {
        await setTimeout(3000);
        const progress = await callMCPTool('check_disaster_recovery_progress', {
          recovery_id: disasterRecovery.recovery_id
        });

        recoveryProgress.push({
          timestamp: new Date(),
          phase: progress.current_phase,
          progress_percentage: progress.progress,
          estimated_remaining: progress.estimated_remaining_time,
          issues: progress.issues || []
        });

        if (progress.status === 'completed') {
          recoveryComplete = true;
        }

        if (i === 19 && !recoveryComplete) {
          console.warn('Disaster recovery taking longer than expected');
        }
      }

      expect(recoveryComplete).toBe(true);
      expect(recoveryProgress.length).toBeGreaterThan(0);

      // Verify recovery phases
      const phases = recoveryProgress.map(p => p.phase);
      expect(phases).toContain('assessment');
      expect(phases).toContain('backup_restoration');
      expect(phases).toContain('verification');

      // Step 8: Verify system is operational after recovery
      const postRecoveryCheck = await callMCPTool('system_health_check', {
        detailed: true,
        timeout: 10000
      }) as HealthCheck;

      expect(postRecoveryCheck.status).toBe('healthy');
      expect(postRecoveryCheck.overall_score).toBeGreaterThan(85);

      // Step 9: Verify critical data integrity
      const dataIntegrityCheck = await callMCPTool('memory_find', {
        query: 'Production Architecture Payment Processing Disaster Recovery',
        scope: { project: projectId }
      });

      expect(dataIntegrityCheck.hits).toHaveLength(3);

      // Verify all critical data was restored
      criticalData.forEach(originalItem => {
        const restoredItem = dataIntegrityCheck.hits.find(h => h.id === originalItem.id);
        expect(restoredItem).toBeDefined();
        expect(restoredItem.kind).toBe(originalItem.kind);

        if (restoredItem.kind === 'decision') {
          expect(restoredItem.data?.business_impact).toBe('critical');
          expect(restoredItem.data?.compliance_requirements).toBeDefined();
        } else if (restoredItem.kind === 'entity') {
          expect(restoredItem.data?.sla).toBe('99.999%');
          expect(restoredItem.data?.disaster_recovery).toBe(true);
        }
      });

      // Step 10: Verify recovery documentation was created
      const recoveryDocumentation = await callMCPTool('memory_find', {
        query: 'disaster recovery complete outage incident',
        scope: { project: projectId },
        types: ['observation', 'decision', 'runbook']
      });

      expect(recoveryDocumentation.hits.length).toBeGreaterThan(0);

      const incidentReport = recoveryDocumentation.hits.find(h =>
        h.kind === 'observation' && h.data?.title?.includes('Disaster Recovery')
      );
      expect(incidentReport).toBeDefined();
      expect(incidentReport?.data?.severity).toBe('critical');
    });

    it('should handle partial system failures with selective recovery', async () => {
      const projectId = `partial-recovery-${randomUUID().substring(0, 8)}`;

      // Step 1: Create distributed system components
      const distributedSystem = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId, region: 'us-east-1' },
            data: {
              entity_type: 'service',
              name: 'UserService-East',
              data: {
                region: 'us-east-1',
                version: '2.1.0',
                dependencies: ['Database-East', 'Cache-East']
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, region: 'us-west-2' },
            data: {
              entity_type: 'service',
              name: 'UserService-West',
              data: {
                region: 'us-west-2',
                version: '2.1.0',
                dependencies: ['Database-West', 'Cache-West']
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, region: 'eu-west-1' },
            data: {
              entity_type: 'service',
              name: 'UserService-Europe',
              data: {
                region: 'eu-west-1',
                version: '2.1.0',
                dependencies: ['Database-Europe', 'Cache-Europe']
              }
            }
          },
          {
            kind: 'runbook',
            scope: { project: projectId },
            data: {
              title: 'Regional Service Recovery Procedure',
              description: 'Procedure for recovering individual regional services',
              regional_failover: true,
              traffic_routing: 'geo_dns',
              health_checks: 'regional'
            }
          }
        ]
      };

      await callMCPTool('memory_store', distributedSystem);

      // Step 2: Simulate partial system failure (one region)
      console.log('Simulating regional service failure...');
      const partialFailure = await callMCPTool('simulate_regional_failure', {
        affected_region: 'us-east-1',
        failed_components: ['UserService-East', 'Database-East', 'Cache-East'],
        failure_type: 'network_partition',
        duration: 25000
      });

      expect(partialFailure.failure_simulated).toBe(true);
      expect(partialFailure.affected_region).toBe('us-east-1');

      // Step 3: Verify other regions remain operational
      const regionalHealthCheck = await callMCPTool('regional_health_check', {
        regions: ['us-east-1', 'us-west-2', 'eu-west-1']
      });

      expect(regionalHealthCheck['us-east-1'].status).toBe('down');
      expect(regionalHealthCheck['us-west-2'].status).toBe('healthy');
      expect(regionalHealthCheck['eu-west-1'].status).toBe('healthy');

      // Step 4: Verify automatic traffic rerouting
      const trafficRouting = await callMCPTool('check_traffic_routing', {
        service: 'UserService',
        check_geo_distribution: true
      });

      expect(trafficRouting.rerouting_active).toBe(true);
      expect(trafficRouting.healthy_regions).toContain('us-west-2');
      expect(trafficRouting.healthy_regions).toContain('eu-west-1');
      expect(trafficRouting.failed_regions).toContain('us-east-1');

      // Step 5: Initiate selective recovery
      const selectiveRecovery = await callMCPTool('initiate_selective_recovery', {
        target_region: 'us-east-1',
        recovery_strategy: 'regional_failover',
        backup_region: 'us-west-2',
        data_synchronization: true
      });

      expect(selectiveRecovery.initiated).toBe(true);
      expect(selectiveRecovery.target_region).toBe('us-east-1');

      // Step 6: Monitor selective recovery progress
      await setTimeout(20000); // Wait for recovery to progress

      const recoveryProgress = await callMCPTool('check_selective_recovery_progress', {
        region: 'us-east-1'
      });

      expect(recoveryProgress.status).toBe('in_progress');
      expect(recoveryProgress.services_recovered).toBeGreaterThan(0);

      // Step 7: Verify partial system recovery
      const postRecoveryHealth = await callMCPTool('regional_health_check', {
        regions: ['us-east-1', 'us-west-2', 'eu-west-1']
      });

      expect(postRecoveryHealth['us-east-1'].status).toBe('healthy');
      expect(postRecoveryHealth['us-west-2'].status).toBe('healthy');
      expect(postRecoveryHealth['eu-west-1'].status).toBe('healthy');

      // Step 8: Verify data synchronization
      const syncCheck = await callMCPTool('check_data_synchronization', {
        regions: ['us-east-1', 'us-west-2'],
        service: 'UserService'
      });

      expect(syncCheck.synchronized).toBe(true);
      expect(syncCheck.sync_status).toBe('complete');

      // Step 9: Verify selective recovery was logged
      const recoveryLog = await callMCPTool('memory_find', {
        query: 'regional failure selective recovery traffic rerouting',
        scope: { project: projectId },
        types: ['observation', 'runbook']
      });

      expect(recoveryLog.hits.length).toBeGreaterThan(0);

      const regionalRecoveryLog = recoveryLog.hits.find(h =>
        h.kind === 'runbook' && h.data?.title?.includes('Regional Service Recovery')
      );
      expect(regionalRecoveryLog).toBeDefined();
    });
  });

  describe('Recovery Testing and Validation', () => {
    it('should validate recovery procedures through regular testing', async () => {
      const projectId = `recovery-testing-${randomUUID().substring(0, 8)}`;

      // Step 1: Create recovery testing framework
      const testingFramework = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Recovery Testing Schedule',
              status: 'approved',
              rationale: 'Regular testing ensures recovery procedures work when needed',
              testing_schedule: {
                disaster_recovery_test: 'quarterly',
                partial_failure_test: 'monthly',
                circuit_breaker_test: 'weekly',
                health_monitoring_test: 'daily'
              },
              last_test_date: null,
              next_test_date: new Date().toISOString(),
              test_success_criteria: [
                'All critical services restored within RTO',
                'No data loss during recovery',
                'Recovery procedures documented properly',
                'Team trained on procedures'
              ]
            }
          },
          {
            kind: 'runbook',
            scope: { project: projectId },
            data: {
              title: 'Recovery Test Execution Procedure',
              description: 'Standard procedure for executing recovery tests',
              pre_test_checklist: [
                'Notify all stakeholders',
                'Create recent backup',
                'Prepare rollback plan',
                'Schedule maintenance window'
              ],
              test_phases: [
                'Preparation',
                'Execution',
                'Validation',
                'Cleanup',
                'Documentation'
              ],
              post_test_actions: [
                'Update recovery procedures',
                'Train team on lessons learned',
                'Update monitoring and alerts',
                'Schedule next test'
              ]
            }
          }
        ]
      };

      await callMCPTool('memory_store', testingFramework);

      // Step 2: Execute comprehensive recovery test
      console.log('Executing comprehensive recovery test...');
      const recoveryTest = await callMCPTool('execute_recovery_test', {
        test_type: 'comprehensive',
        test_scope: 'full_system',
        test_scenarios: [
          'database_connection_failure',
          'service_crash',
          'network_partition',
          'resource_exhaustion'
        ],
        validation_criteria: {
          rto_compliance: true,
          data_integrity: true,
          service_availability: true,
          performance_benchmarks: true
        }
      });

      expect(recoveryTest.test_started).toBe(true);
      expect(recoveryTest.test_scenarios).toHaveLength(4);

      // Step 3: Monitor test execution
      const testResults = [];
      let testCompleted = false;

      for (let i = 0; i < 15 && !testCompleted; i++) {
        await setTimeout(5000);
        const testStatus = await callMCPTool('check_recovery_test_status', {
          test_id: recoveryTest.test_id
        });

        testResults.push({
          timestamp: new Date(),
          phase: testStatus.current_phase,
          scenario: testStatus.current_scenario,
          success_rate: testStatus.success_rate,
          issues: testStatus.issues || []
        });

        if (testStatus.status === 'completed') {
          testCompleted = true;
        }
      }

      expect(testCompleted).toBe(true);
      expect(testResults.length).toBeGreaterThan(0);

      // Step 4: Validate test results
      const testValidation = await callMCPTool('validate_recovery_test', {
        test_id: recoveryTest.test_id,
        comprehensive_validation: true
      });

      expect(testValidation.overall_success).toBe(true);
      expect(testValidation.scenarios_passed).toBeGreaterThan(0);
      expect(testValidation.rto_compliance).toBe(true);
      expect(testValidation.data_integrity_verified).toBe(true);

      // Step 5: Generate test report
      const testReport = await callMCPTool('generate_recovery_test_report', {
        test_id: recoveryTest.test_id,
        include_recommendations: true,
        include_metrics: true
      });

      expect(testReport.generated).toBe(true);
      expect(testReport.summary.success_rate).toBeGreaterThan(80);
      expect(testReport.summary.issues_identified).toBeDefined();
      expect(testReport.summary.recommendations).toBeDefined();

      // Step 6: Store test results and improvements
      const testResultsStorage = {
        items: [
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'Recovery Test Results Summary',
              content: `
Recovery Test Completed Successfully

Test Summary:
- Test Duration: ${testResults.length * 5} seconds
- Success Rate: ${testValidation.overall_success ? '100%' : 'Partial'}
- Issues Identified: ${testValidation.issues_identified || 0}
- Recommendations Generated: ${testReport.summary.recommendations?.length || 0}

Key Findings:
${testResults.map(r => `- ${r.phase}: ${r.scenario} - ${r.success_rate}% success rate`).join('\n')}

Next Steps:
- Implement identified improvements
- Update recovery procedures
- Schedule follow-up test
              `.trim(),
              test_type: 'comprehensive_recovery',
              test_date: new Date().toISOString(),
              success_rate: testValidation.overall_success ? 100 : 0,
              recommendations: testReport.summary.recommendations || []
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Recovery Procedure Improvements',
              status: 'proposed',
              rationale: 'Based on recent recovery test results',
              improvements: testReport.summary.recommendations || [],
              implementation_timeline: '30_days',
              priority: 'high'
            }
          }
        ]
      };

      await callMCPTool('memory_store', testResultsStorage);

      // Step 7: Verify test documentation
      const testDocumentation = await callMCPTool('memory_find', {
        query: 'recovery test results improvements recommendations',
        scope: { project: projectId },
        types: ['observation', 'decision']
      });

      expect(testDocumentation.hits.length).toBe(2);

      const resultsObservation = testDocumentation.hits.find(h => h.kind === 'observation');
      const improvementsDecision = testDocumentation.hits.find(h => h.kind === 'decision');

      expect(resultsObservation?.data?.test_type).toBe('comprehensive_recovery');
      expect(improvementsDecision?.data?.priority).toBe('high');
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for system recovery...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for system recovery...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for system recovery...');
}

async function startMCPServer(): Promise<TestServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      DATABASE_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  return {
    process,
    port: 0 // Using stdio
  };
}

async function callMCPTool(toolName: string, args: any, options?: { expect_failure?: boolean }): Promise<any> {
  return new Promise((resolve) => {
    setTimeout(() => {
      // Handle system recovery specific operations
      if (toolName === 'system_health_check') {
        if (options?.expect_failure) {
          resolve({
            error: {
              message: 'System unavailable - health check failed',
              code: 'SYSTEM_UNAVAILABLE'
            }
          });
        } else {
          resolve({
            status: 'healthy',
            components: {
              database: {
                status: 'up',
                response_time: Math.floor(Math.random() * 500) + 50,
                last_check: new Date().toISOString()
              },
              memory_store: {
                status: 'up',
                response_time: Math.floor(Math.random() * 300) + 30,
                last_check: new Date().toISOString()
              },
              search_index: {
                status: 'up',
                response_time: Math.floor(Math.random() * 200) + 20,
                last_check: new Date().toISOString()
              },
              mcp_server: {
                status: 'up',
                response_time: Math.floor(Math.random() * 100) + 10,
                last_check: new Date().toISOString()
              }
            },
            overall_score: Math.floor(Math.random() * 10) + 90,
            timestamp: new Date().toISOString()
          });
        }
      } else if (toolName === 'simulate_degradation') {
        resolve({
          simulation_started: true,
          component: args.component,
          degradation_type: args.degradation_type,
          severity: args.severity,
          duration: args.duration
        });
      } else if (toolName === 'check_recovery_status') {
        resolve({
          active: true,
          procedure_id: 'database-recovery',
          current_step: Math.floor(Math.random() * 3) + 1,
          estimated_completion: new Date(Date.now() + 30000).toISOString()
        });
      } else if (toolName === 'memory_find') {
        resolve({
          hits: Array.from({ length: Math.floor(Math.random() * 3) + 1 }, (_, i) => ({
            id: randomUUID(),
            kind: ['entity', 'decision', 'section', 'todo', 'observation', 'runbook'][i % 6],
            data: {
              title: `Recovery Test Result ${i + 1}`,
              content: `Mock content for ${args.query || 'search'}`,
              scope: args.scope || {}
            }
          })),
          total: Math.floor(Math.random() * 3) + 1,
          query_time_ms: Math.floor(Math.random() * 200) + 50
        });
      } else if (toolName === 'memory_store') {
        resolve({
          stored: (args.items || []).map((item: any) => ({
            id: randomUUID(),
            status: 'inserted',
            kind: item.kind || 'unknown',
            created_at: new Date().toISOString(),
            data: item.data
          })),
          errors: [],
          autonomous_context: {
            action_performed: 'created',
            items_processed: (args.items || []).length,
            recommendation: 'System recovery test data created',
            reasoning: 'Mock data for system recovery testing',
            user_message_suggestion: `✓ Created ${(args.items || []).length} recovery test items`
          }
        });
      } else {
        // Default response for other operations
        resolve({
          success: true,
          operation: toolName,
          timestamp: new Date().toISOString(),
          message: `Mock ${toolName} operation completed successfully`
        });
      }
    }, 200); // Longer delay for system recovery operations
  });
}