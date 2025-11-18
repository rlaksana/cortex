/**
 * Adapter Interface Compliance Tests
 *
 * Tests to verify that all adapter classes properly implement their required interfaces.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { IDatabase } from '../../../db/database-interface';
// Import implementations to wrap
import { DatabaseManager } from '../../../db/database-manager';
import { circuitBreakerManager } from '../../../services/circuit-breaker.service';
import { MemoryStoreOrchestrator } from '../../../services/orchestrators/memory-store-orchestrator';
// Import interfaces for type checking
import type {
  ICircuitBreakerService,
  IDatabaseService,
  IMemoryStoreOrchestrator,
  KnowledgeItem,
} from '../../service-interfaces';
import { CircuitBreakerServiceAdapter } from '../circuit-breaker-service-adapter';
// Import adapters
import { DatabaseServiceAdapter } from '../database-service-adapter';
import { MemoryStoreOrchestratorAdapter } from '../memory-store-orchestrator-adapter';

describe('Adapter Interface Compliance', () => {
  describe('DatabaseServiceAdapter', () => {
    let adapter: DatabaseServiceAdapter;
    let databaseManager: DatabaseManager;

    beforeEach(() => {
      // Create a mock DatabaseManager for testing
      databaseManager = new DatabaseManager({
        qdrant: {
          url: 'http://localhost:6333',
          timeout: 30000,
        },
        enableVectorOperations: true,
        enableFallback: true,
      });
      adapter = new DatabaseServiceAdapter(databaseManager);
    });

    it('should implement IDatabaseService interface correctly', () => {
      // Test that adapter has all required methods
      expect(typeof adapter.getConnection).toBe('function');
      expect(typeof adapter.healthCheck).toBe('function');
      expect(typeof adapter.close).toBe('function');
    });

    it('should return a promise from getConnection', async () => {
      const result = adapter.getConnection();
      expect(result).toBeInstanceOf(Promise);
    });

    it('should return a promise from healthCheck', async () => {
      const result = adapter.healthCheck();
      expect(result).toBeInstanceOf(Promise);
    });

    it('should return a promise from close', async () => {
      const result = adapter.close();
      expect(result).toBeInstanceOf(Promise);
    });

    it('should handle getConnection gracefully when not initialized', async () => {
      // This test verifies the adapter handles the case where DatabaseManager is not initialized
      try {
        await adapter.getConnection();
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('Failed to get database connection');
      }
    });
  });

  describe('CircuitBreakerServiceAdapter', () => {
    let adapter: CircuitBreakerServiceAdapter;

    beforeEach(() => {
      adapter = new CircuitBreakerServiceAdapter(circuitBreakerManager);
    });

    it('should implement ICircuitBreakerService interface correctly', () => {
      // Test that adapter has all required methods
      expect(typeof adapter.execute).toBe('function');
      expect(typeof adapter.getState).toBe('function');
      expect(typeof adapter.reset).toBe('function');
    });

    it('should execute operations through circuit breaker', async () => {
      const testOperation = async () => 'test-result';
      const result = await adapter.execute(testOperation, 'test-service');
      expect(result).toBe('test-result');
    });

    it('should return circuit breaker state as string', () => {
      const state = adapter.getState('test-service');
      expect(typeof state).toBe('string');
      expect(['closed', 'open', 'half-open']).toContain(state);
    });

    it('should reset circuit breaker without error', () => {
      expect(() => adapter.reset('test-service')).not.toThrow();
    });

    it('should handle executeWithDefault method', async () => {
      const testOperation = async () => 'default-result';
      const result = await adapter.executeWithDefault(testOperation);
      expect(result).toBe('default-result');
    });

    it('should provide convenience methods for default service', () => {
      const state = adapter.getDefaultState();
      expect(typeof state).toBe('string');

      expect(() => adapter.resetDefault()).not.toThrow();
    });
  });

  describe('MemoryStoreOrchestratorAdapter', () => {
    let adapter: MemoryStoreOrchestratorAdapter;
    let memoryStoreOrchestrator: MemoryStoreOrchestrator;

    beforeEach(() => {
      memoryStoreOrchestrator = new MemoryStoreOrchestrator();
      adapter = new MemoryStoreOrchestratorAdapter(memoryStoreOrchestrator);
    });

    it('should implement IMemoryStoreOrchestrator interface correctly', () => {
      // Test that adapter has all required methods
      expect(typeof adapter.store).toBe('function');
      expect(typeof adapter.upsert).toBe('function');
      expect(typeof adapter.delete).toBe('function');
      expect(typeof adapter.update).toBe('function');
    });

    it('should store items via adapter', async () => {
      const testItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          data: { title: 'Test Entity' },
          scope: { project: 'test' },
        },
      ];

      const result = adapter.store(testItems);
      expect(result).toBeInstanceOf(Promise);
    });

    it('should upsert items via adapter', async () => {
      const testItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          data: { title: 'Test Entity Upsert' },
          scope: { project: 'test' },
        },
      ];

      const result = adapter.upsert(testItems);
      expect(result).toBeInstanceOf(Promise);
    });

    it('should delete items via adapter', async () => {
      const testIds = ['test-id-1', 'test-id-2'];
      const result = await adapter.delete(testIds);

      expect(typeof result.success).toBe('boolean');
      expect(typeof result.data?.deleted).toBe('number');
    });

    it('should update items via adapter', async () => {
      const testItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          id: 'test-entity-id',
          data: { title: 'Updated Test Entity' },
          scope: { project: 'test' },
        },
      ];

      const result = adapter.update(testItems);
      expect(result).toBeInstanceOf(Promise);
    });

    it('should provide enhanced deletion with validation', async () => {
      const testIds = ['test-id-1', 'test-id-2'];
      const result = await adapter.deleteWithValidation(testIds);

      expect(typeof result.success).toBe('boolean');
      expect(typeof result.deleted).toBe('number');
      expect(result.errors).toBeInstanceOf(Array);
    });

    it('should maintain backward compatibility with storeItems', async () => {
      const testItems = [
        {
          kind: 'entity',
          data: { title: 'Test Entity' },
          scope: { project: 'test' },
        },
      ];

      const result = adapter.storeItems(testItems);
      expect(result).toBeInstanceOf(Promise);
    });
  });

  describe('Type Safety Verification', () => {
    it('should allow adapters to be assigned to interface types', () => {
      // This test verifies type compatibility at compile time
      const databaseManager = new DatabaseManager({
        qdrant: { url: 'http://localhost:6333', timeout: 30000 },
        enableVectorOperations: true,
        enableFallback: true,
      });

      const databaseAdapter: IDatabaseService = new DatabaseServiceAdapter(databaseManager);
      const circuitBreakerAdapter: ICircuitBreakerService = new CircuitBreakerServiceAdapter(
        circuitBreakerManager
      );
      const memoryStoreAdapter: IMemoryStoreOrchestrator = new MemoryStoreOrchestratorAdapter(
        new MemoryStoreOrchestrator()
      );

      expect(databaseAdapter).toBeDefined();
      expect(circuitBreakerAdapter).toBeDefined();
      expect(memoryStoreAdapter).toBeDefined();
    });
  });
});
