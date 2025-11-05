/**
 * Chaos Injection Engine
 *
 * This module provides the core chaos injection capabilities that simulate
 * various failure scenarios in the vector store system.
 */

import { EventEmitter } from 'events';
import {
  ChaosScenario,
  ChaosScenarioType,
  ChaosScenarioConfig,
  InjectionPoint,
  SystemMetrics,
  ExperimentExecutionContext
} from '../types/chaos-testing-types';

export interface ChaosInjector {
  inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void>;
  rollback(): Promise<void>;
  isActive(): boolean;
}

export class ChaosInjectionEngine extends EventEmitter {
  private activeInjectors: Map<string, ChaosInjector> = new Map();
  private injectionHistory: InjectionRecord[] = [];

  constructor() {
    super();
    this.registerDefaultInjectors();
  }

  /**
   * Inject chaos scenario into the system
   */
  async injectChaos(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<void> {
    this.emit('chaos:injecting', { scenario, context });

    try {
      const injector = this.getInjector(scenario.type);
      if (!injector) {
        throw new Error(`No injector found for scenario type: ${scenario.type}`);
      }

      // Record injection attempt
      const record: InjectionRecord = {
        id: `injection_${Date.now()}`,
        scenarioId: scenario.id,
        startTime: new Date(),
        status: 'in_progress',
        context
      };

      this.injectionHistory.push(record);

      // Execute injection
      await injector.inject(scenario, context);
      this.activeInjectors.set(scenario.id, injector);

      record.status = 'active';
      record.endTime = new Date();

      this.emit('chaos:injected', { scenario, record });
    } catch (error) {
      this.emit('chaos:injection_failed', { scenario, error });
      throw error;
    }
  }

  /**
   * Rollback chaos injection
   */
  async rollbackChaos(scenarioId: string): Promise<void> {
    const injector = this.activeInjectors.get(scenarioId);
    if (!injector) {
      throw new Error(`No active injector found for scenario: ${scenarioId}`);
    }

    this.emit('chaos:rolling_back', { scenarioId });

    try {
      await injector.rollback();
      this.activeInjectors.delete(scenarioId);

      // Update injection record
      const record = this.injectionHistory.find(r => r.scenarioId === scenarioId);
      if (record) {
        record.status = 'rolled_back';
        record.endTime = new Date();
      }

      this.emit('chaos:rolled_back', { scenarioId });
    } catch (error) {
      this.emit('chaos:rollback_failed', { scenarioId, error });
      throw error;
    }
  }

  /**
   * Rollback all active chaos injections
   */
  async rollbackAll(): Promise<void> {
    const activeScenarioIds = Array.from(this.activeInjectors.keys());

    for (const scenarioId of activeScenarioIds) {
      try {
        await this.rollbackChaos(scenarioId);
      } catch (error) {
        console.error(`Failed to rollback scenario ${scenarioId}:`, error);
      }
    }
  }

  /**
   * Check if any chaos injection is active
   */
  hasActiveChaos(): boolean {
    return this.activeInjectors.size > 0;
  }

  /**
   * Get active chaos scenarios
   */
  getActiveScenarios(): string[] {
    return Array.from(this.activeInjectors.keys());
  }

  /**
   * Get injection history
   */
  getInjectionHistory(): InjectionRecord[] {
    return [...this.injectionHistory];
  }

  /**
   * Get injector for specific scenario type
   */
  private getInjector(type: ChaosScenarioType): ChaosInjector | null {
    const injectorMap: Record<ChaosScenarioType, () => ChaosInjector> = {
      'qdrant_connection_failure': () => new QdrantConnectionFailureInjector(),
      'network_latency': () => new NetworkLatencyInjector(),
      'packet_loss': () => new PacketLossInjector(),
      'query_timeout': () => new QueryTimeoutInjector(),
      'resource_exhaustion': () => new ResourceExhaustionInjector(),
      'memory_pressure': () => new MemoryPressureInjector(),
      'disk_exhaustion': () => new DiskExhaustionInjector(),
      'circuit_breaker_trip': () => new CircuitBreakerTripInjector(),
      'cascade_failure': () => new CascadeFailureInjector(),
      'partial_partition': () => new PartialPartitionInjector()
    };

    const factory = injectorMap[type];
    return factory ? factory() : null;
  }

  /**
   * Register default chaos injectors
   */
  private registerDefaultInjectors(): void {
    // Injectors are created on-demand via getInjector()
  }

  /**
   * Validate injection safety
   */
  async validateInjectionSafety(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext
  ): Promise<SafetyValidationResult> {
    const checks: SafetyCheck[] = [];

    // Check if blast radius is acceptable
    if (scenario.config.intensity > 80 && context.environment === 'production') {
      checks.push({
        type: 'intensity',
        passed: false,
        message: 'High intensity scenarios not allowed in production'
      });
    }

    // Check if critical components would be affected
    const criticalComponents = ['authentication', 'payment', 'user_data'];
    const affectedCritical = criticalComponents.filter(comp =>
      scenario.injectionPoint.component.includes(comp)
    );

    if (affectedCritical.length > 0 && context.environment === 'production') {
      checks.push({
        type: 'critical_components',
        passed: false,
        message: `Critical components would be affected: ${affectedCritical.join(', ')}`
      });
    }

    // Check concurrent chaos scenarios
    if (this.activeInjectors.size >= 3) {
      checks.push({
        type: 'concurrent_scenarios',
        passed: false,
        message: 'Too many concurrent chaos scenarios'
      });
    }

    const allPassed = checks.every(check => check.passed);

    return {
      safe: allPassed,
      checks,
      recommendations: allPassed ? [] : [
        'Consider reducing intensity',
        'Move to staging environment',
        'Wait for other scenarios to complete'
      ]
    };
  }
}

// Specific Chaos Injector Implementations

class QdrantConnectionFailureInjector implements ChaosInjector {
  private active = false;
  private originalAdapter: any;
  private failureMode: 'timeout' | 'error' | 'refused';

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    this.failureMode = scenario.config.parameters.failureMode || 'error';

    // Intercept Qdrant adapter calls
    this.originalAdapter = this.getQdrantAdapter();

    switch (this.failureMode) {
      case 'timeout':
        this.injectTimeouts(scenario.config);
        break;
      case 'error':
        this.injectErrors(scenario.config);
        break;
      case 'refused':
        this.injectConnectionRefused(scenario.config);
        break;
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    if (this.originalAdapter) {
      this.restoreQdrantAdapter(this.originalAdapter);
    }
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private getQdrantAdapter(): any {
    // Get reference to original Qdrant adapter
    return (global as any).qdrantAdapter;
  }

  private restoreQdrantAdapter(adapter: any): void {
    // Restore original adapter
    (global as any).qdrantAdapter = adapter;
  }

  private injectTimeouts(config: ChaosScenarioConfig): void {
    // Override adapter methods to simulate timeouts
  }

  private injectErrors(config: ChaosScenarioConfig): void {
    // Override adapter methods to simulate connection errors
  }

  private injectConnectionRefused(config: ChaosScenarioConfig): void {
    // Override adapter methods to simulate connection refused
  }
}

class NetworkLatencyInjector implements ChaosInjector {
  private active = false;
  private originalFetch: typeof fetch;

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const latency = scenario.config.parameters.latency || 1000; // ms
    const jitter = scenario.config.parameters.jitter || 200; // ms

    this.originalFetch = global.fetch;

    global.fetch = async (...args) => {
      // Add artificial delay
      const delay = latency + (Math.random() - 0.5) * 2 * jitter;
      await new Promise(resolve => setTimeout(resolve, delay));

      return this.originalFetch(...args);
    };

    this.active = true;
  }

  async rollback(): Promise<void> {
    global.fetch = this.originalFetch;
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }
}

class PacketLossInjector implements ChaosInjector {
  private active = false;
  private originalFetch: typeof fetch;

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const lossRate = scenario.config.parameters.lossRate || 0.1; // 10%

    this.originalFetch = global.fetch;

    global.fetch = async (...args) => {
      // Simulate packet loss
      if (Math.random() < lossRate) {
        throw new Error('Network error: Connection reset by peer');
      }

      return this.originalFetch(...args);
    };

    this.active = true;
  }

  async rollback(): Promise<void> {
    global.fetch = this.originalFetch;
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }
}

class QueryTimeoutInjector implements ChaosInjector {
  private active = false;
  private timeoutHandlers: (() => void)[] = [];

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const timeoutMs = scenario.config.parameters.timeoutMs || 30000;

    // Override query methods to add artificial timeouts
    this.timeoutHandlers.push(this.interceptQdrantQueries(timeoutMs));
    this.active = true;
  }

  async rollback(): Promise<void> {
    this.timeoutHandlers.forEach(handler => handler());
    this.timeoutHandlers = [];
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private interceptQdrantQueries(timeoutMs: number): () => void {
    // Return cleanup function
    return () => {};
  }
}

class ResourceExhaustionInjector implements ChaosInjector {
  private active = false;
  private resourceMonitor: any;

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const resourceType = scenario.config.parameters.resourceType || 'cpu';
    const usageLevel = scenario.config.parameters.usageLevel || 90;

    switch (resourceType) {
      case 'cpu':
        this.injectCPUExhaustion(usageLevel);
        break;
      case 'memory':
        this.injectMemoryExhaustion(usageLevel);
        break;
      case 'disk':
        this.injectDiskExhaustion(usageLevel);
        break;
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    if (this.resourceMonitor) {
      this.resourceMonitor.stop();
    }
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private injectCPUExhaustion(usageLevel: number): void {
    // Start CPU-intensive tasks
  }

  private injectMemoryExhaustion(usageLevel: number): void {
    // Allocate memory to reach target usage
  }

  private injectDiskExhaustion(usageLevel: number): void {
    // Fill disk space to target level
  }
}

class MemoryPressureInjector implements ChaosInjector {
  private active = false;
  private memoryBlocks: Buffer[] = [];

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const pressureLevel = scenario.config.parameters.pressureLevel || 80; // percentage
    const blockSize = 1024 * 1024; // 1MB blocks

    // Allocate memory until target pressure is reached
    const targetMemory = process.memoryUsage().heapTotal * (pressureLevel / 100);

    while (process.memoryUsage().heapUsed < targetMemory) {
      this.memoryBlocks.push(Buffer.alloc(blockSize));

      // Prevent infinite loop
      if (this.memoryBlocks.length > 10000) {
        break;
      }
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    // Release allocated memory
    this.memoryBlocks = [];
    if (global.gc) {
      global.gc();
    }
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }
}

class DiskExhaustionInjector implements ChaosInjector {
  private active = false;
  private tempFiles: string[] = [];

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const exhaustionLevel = scenario.config.parameters.exhaustionLevel || 90; // percentage
    const fileSize = 1024 * 1024; // 1MB files

    // Create temporary files to fill disk
    const fs = require('fs');
    const path = require('path');
    const tempDir = require('os').tmpdir();

    for (let i = 0; i < 100; i++) {
      const filePath = path.join(tempDir, `chaos_test_${Date.now()}_${i}.tmp`);
      const data = Buffer.alloc(fileSize, 'x');

      try {
        fs.writeFileSync(filePath, data);
        this.tempFiles.push(filePath);
      } catch (error) {
        // Disk full or permission error
        break;
      }
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    const fs = require('fs');

    // Clean up temporary files
    for (const filePath of this.tempFiles) {
      try {
        fs.unlinkSync(filePath);
      } catch (error) {
        // File already deleted or permission error
      }
    }

    this.tempFiles = [];
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }
}

class CircuitBreakerTripInjector implements ChaosInjector {
  private active = false;
  private originalCircuitBreaker: any;

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    // Force circuit breaker into open state
    this.originalCircuitBreaker = this.getCircuitBreaker();

    // Override circuit breaker to force open state
    this.forceCircuitBreakerOpen();

    this.active = true;
  }

  async rollback(): Promise<void> {
    if (this.originalCircuitBreaker) {
      this.restoreCircuitBreaker(this.originalCircuitBreaker);
    }
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private getCircuitBreaker(): any {
    // Get reference to circuit breaker
    return (global as any).circuitBreaker;
  }

  private restoreCircuitBreaker(breaker: any): void {
    // Restore original circuit breaker
    (global as any).circuitBreaker = breaker;
  }

  private forceCircuitBreakerOpen(): void {
    // Force circuit breaker into open state
  }
}

class CascadeFailureInjector implements ChaosInjector {
  private active = false;
  private subInjectors: ChaosInjector[] = [];

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const failureChain = scenario.config.parameters.failureChain || [
      'network_latency',
      'query_timeout',
      'circuit_breaker_trip'
    ];

    // Inject failures in sequence
    for (const [index, failureType] of failureChain.entries()) {
      setTimeout(async () => {
        const subScenario: ChaosScenario = {
          ...scenario,
          id: `${scenario.id}_cascade_${index}`,
          type: failureType as any,
          config: {
            ...scenario.config,
            intensity: scenario.config.intensity * (1 - index * 0.2) // Reduce intensity for cascade
          }
        };

        const injector = this.createInjector(failureType);
        if (injector) {
          await injector.inject(subScenario, context);
          this.subInjectors.push(injector);
        }
      }, index * 2000); // 2 second delays between failures
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    // Rollback in reverse order
    for (const injector of this.subInjectors.reverse()) {
      try {
        await injector.rollback();
      } catch (error) {
        console.error('Failed to rollback sub-injector:', error);
      }
    }

    this.subInjectors = [];
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private createInjector(type: string): ChaosInjector | null {
    // Create injector for specific failure type
    return null;
  }
}

class PartialPartitionInjector implements ChaosInjector {
  private active = false;
  private partitionedNodes: string[] = [];

  async inject(scenario: ChaosScenario, context: ExperimentExecutionContext): Promise<void> {
    const partitionRatio = scenario.config.parameters.partitionRatio || 0.5;
    const affectedServices = scenario.config.parameters.affectedServices || ['qdrant'];

    // Simulate network partition for subset of services
    for (const service of affectedServices) {
      if (Math.random() < partitionRatio) {
        this.partitionedNodes.push(service);
        this.createNetworkPartition(service);
      }
    }

    this.active = true;
  }

  async rollback(): Promise<void> {
    // Restore network connectivity
    for (const node of this.partitionedNodes) {
      this.removeNetworkPartition(node);
    }

    this.partitionedNodes = [];
    this.active = false;
  }

  isActive(): boolean {
    return this.active;
  }

  private createNetworkPartition(node: string): void {
    // Create network partition for node
  }

  private removeNetworkPartition(node: string): void {
    // Remove network partition for node
  }
}

// Supporting Types

interface InjectionRecord {
  id: string;
  scenarioId: string;
  startTime: Date;
  endTime?: Date;
  status: 'in_progress' | 'active' | 'rolled_back' | 'failed';
  context: ExperimentExecutionContext;
}

interface SafetyValidationResult {
  safe: boolean;
  checks: SafetyCheck[];
  recommendations: string[];
}

interface SafetyCheck {
  type: string;
  passed: boolean;
  message: string;
}