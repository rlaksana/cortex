/**
 * Qdrant Test Double with Error Injection
 *
 * Provides a comprehensive mock implementation of Qdrant client with
 * configurable error injection scenarios for testing error handling,
 * performance degradation, and failure modes.
 */

import { vi } from 'vitest';

export interface QdrantTestDoubleConfig {
  // Basic configuration
  shouldFail: boolean;
  failureMode: 'network' | 'timeout' | 'auth' | 'quota' | 'server_error' | 'partial';
  failureRate: number; // 0.0 to 1.0
  latency: {
    min: number;
    max: number;
    failure?: number;
  };

  // Data limits
  maxPoints: number;
  maxCollections: number;

  // Error injection
  injectErrors: {
    searchErrors: boolean;
    upsertErrors: boolean;
    collectionErrors: boolean;
    networkErrors: boolean;
  };

  // Performance degradation
  performance: {
    responseTimeMultiplier: number;
    successRate: number;
    throughput: number; // requests per second
  };
}

export class QdrantTestDouble {
  private config: QdrantTestDoubleConfig;
  private collections: Map<string, any> = new Map();
  private points: Map<string, Map<string, any>> = new Map(); // collection -> points
  private requestCount: number = 0;
  private errorCount: number = 0;

  constructor(config: Partial<QdrantTestDoubleConfig> = {}) {
    this.config = {
      shouldFail: false,
      failureMode: 'network',
      failureRate: 0.0,
      latency: { min: 10, max: 50 },
      maxPoints: 10000,
      maxCollections: 100,
      injectErrors: {
        searchErrors: false,
        upsertErrors: false,
        collectionErrors: false,
        networkErrors: false,
      },
      performance: {
        responseTimeMultiplier: 1.0,
        successRate: 1.0,
        throughput: 100,
      },
      ...config,
    };
  }

  private async simulateLatency(): Promise<void> {
    const delay = Math.random() * (this.config.latency.max - this.config.latency.min) + this.config.latency.min;
    await new Promise(resolve => setTimeout(resolve, delay * this.config.performance.responseTimeMultiplier));
  }

  private shouldInjectError(): boolean {
    this.requestCount++;
    const randomError = Math.random();

    // Check if we should inject an error based on failure rate
    if (randomError < this.config.failureRate) {
      this.errorCount++;
      return true;
    }

    // Check if we should fail based on success rate
    if (Math.random() > this.config.performance.successRate) {
      this.errorCount++;
      return true;
    }

    return false;
  }

  private createError(operation: string): Error {
    switch (this.config.failureMode) {
      case 'network':
        return new Error(`Network error during ${operation}: ECONNREFUSED`);
      case 'timeout':
        return new Error(`Timeout during ${operation}: ETIMEDOUT`);
      case 'auth':
        return new Error(`Authentication failed during ${operation}: Invalid API key`);
      case 'quota':
        return new Error(`Quota exceeded during ${operation}: Rate limit exceeded`);
      case 'server_error':
        return new Error(`Server error during ${operation}: Internal server error 500`);
      case 'partial':
        return new Error(`Partial failure during ${operation}: Some operations failed`);
      default:
        return new Error(`Unknown error during ${operation}`);
    }
  }

  // Collection Management
  async getCollections(): Promise<any> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.collectionErrors) {
      throw this.createError('getCollections');
    }

    const collections = Array.from(this.collections.values());
    return {
      collections: collections.map(col => ({
        name: col.name,
        points_count: this.points.get(col.name)?.size || 0,
        vectors_count: this.points.get(col.name)?.size || 0,
        indexed_vectors_count: this.points.get(col.name)?.size || 0,
        config: col.config,
      })),
    };
  }

  async createCollection(name: string, config: any): Promise<void> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.collectionErrors) {
      throw this.createError('createCollection');
    }

    if (this.collections.size >= this.config.maxCollections) {
      throw new Error('Maximum collections limit reached');
    }

    if (this.collections.has(name)) {
      throw new Error(`Collection ${name} already exists`);
    }

    this.collections.set(name, {
      name,
      config,
      created_at: new Date().toISOString(),
    });
    this.points.set(name, new Map());
  }

  async deleteCollection(name: string): Promise<void> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.collectionErrors) {
      throw this.createError('deleteCollection');
    }

    if (!this.collections.has(name)) {
      throw new Error(`Collection ${name} does not exist`);
    }

    this.collections.delete(name);
    this.points.delete(name);
  }

  async getCollection(name: string): Promise<any> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.collectionErrors) {
      throw this.createError('getCollection');
    }

    const collection = this.collections.get(name);
    if (!collection) {
      throw new Error(`Collection ${name} does not exist`);
    }

    return {
      name: collection.name,
      points_count: this.points.get(name)?.size || 0,
      vectors_count: this.points.get(name)?.size || 0,
      indexed_vectors_count: this.points.get(name)?.size || 0,
      config: collection.config,
    };
  }

  // Point Operations
  async upsert(collectionName: string, points: any[]): Promise<any> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.upsertErrors) {
      throw this.createError('upsert');
    }

    const collection = this.collections.get(collectionName);
    if (!collection) {
      throw new Error(`Collection ${collectionName} does not exist`);
    }

    const collectionPoints = this.points.get(collectionName)!;
    let upsertedCount = 0;

    for (const point of points) {
      if (collectionPoints.size >= this.config.maxPoints) {
        throw new Error('Maximum points limit reached');
      }

      collectionPoints.set(point.id, {
        ...point,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      upsertedCount++;
    }

    return {
      operation_id: `test-upsert-${Date.now()}`,
      status: 'completed',
      upserted_count: upsertedCount,
    };
  }

  async search(collectionName: string, searchRequest: any): Promise<any> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.searchErrors) {
      throw this.createError('search');
    }

    const collection = this.collections.get(collectionName);
    if (!collection) {
      throw new Error(`Collection ${collectionName} does not exist`);
    }

    const collectionPoints = this.points.get(collectionName)!;
    const allPoints = Array.from(collectionPoints.values());

    // Simple mock search - return random points with decreasing scores
    const limit = Math.min(searchRequest.limit || 10, allPoints.length, 10);
    const mockResults = Array.from({ length: limit }, (_, index) => {
      const point = allPoints[index % allPoints.length];
      return {
        id: point.id,
        score: 0.95 - index * 0.05,
        payload: point.payload || {},
        vector: point.vector || Array.from({ length: 1536 }, () => Math.random()),
      };
    });

    return {
      result: mockResults,
      status: 'completed',
      time: 0.015,
    };
  }

  async retrieve(collectionName: string, ids: string[]): Promise<any[]> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.searchErrors) {
      throw this.createError('retrieve');
    }

    const collection = this.collections.get(collectionName);
    if (!collection) {
      throw new Error(`Collection ${collectionName} does not exist`);
    }

    const collectionPoints = this.points.get(collectionName)!;

    return ids.map(id => {
      const point = collectionPoints.get(id);
      if (!point) {
        return {
          id,
          payload: null,
          vector: null,
        };
      }
      return {
        id: point.id,
        payload: point.payload || {},
        vector: point.vector || Array.from({ length: 1536 }, () => Math.random()),
      };
    });
  }

  async delete(collectionName: string, ids: string[]): Promise<any> {
    await this.simulateLatency();

    if (this.shouldInjectError() && this.config.injectErrors.upsertErrors) {
      throw this.createError('delete');
    }

    const collection = this.collections.get(collectionName);
    if (!collection) {
      throw new Error(`Collection ${collectionName} does not exist`);
    }

    const collectionPoints = this.points.get(collectionName)!;
    let deletedCount = 0;

    for (const id of ids) {
      if (collectionPoints.delete(id)) {
        deletedCount++;
      }
    }

    return {
      status: 'completed',
      deleted_count: deletedCount,
    };
  }

  // Additional methods for comprehensive testing
  async healthCheck(): Promise<boolean> {
    if (this.config.shouldFail) {
      return false;
    }

    if (this.shouldInjectError()) {
      throw this.createError('healthCheck');
    }

    return true;
  }

  // Test statistics and monitoring
  getStatistics(): any {
    return {
      request_count: this.requestCount,
      error_count: this.errorCount,
      error_rate: this.requestCount > 0 ? this.errorCount / this.requestCount : 0,
      collections_count: this.collections.size,
      total_points: Array.from(this.points.values()).reduce((sum, points) => sum + points.size, 0),
      config: this.config,
    };
  }

  reset(): void {
    this.collections.clear();
    this.points.clear();
    this.requestCount = 0;
    this.errorCount = 0;
  }

  updateConfig(newConfig: Partial<QdrantTestDoubleConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  // Error injection helpers
  setFailureMode(mode: QdrantTestDoubleConfig['failureMode']): void {
    this.config.failureMode = mode;
  }

  setFailureRate(rate: number): void {
    this.config.failureRate = Math.max(0.0, Math.min(1.0, rate));
  }

  setLatency(min: number, max: number, failure?: number): void {
    this.config.latency = { min, max, failure };
  }

  // Performance degradation helpers
  degradePerformance(multiplier: number, successRate: number): void {
    this.config.performance.responseTimeMultiplier = multiplier;
    this.config.performance.successRate = successRate;
  }

  // Chaos testing helpers
  async simulateChaos(): Promise<void> {
    const originalFailureRate = this.config.failureRate;
    this.config.failureRate = 0.3; // 30% failure rate during chaos

    await new Promise(resolve => setTimeout(resolve, 1000)); // Chaos duration

    this.config.failureRate = originalFailureRate;
  }
}

// Factory functions for creating preconfigured test doubles
export function createPerfectQdrantTestDouble(): QdrantTestDouble {
  return new QdrantTestDouble({
    shouldFail: false,
    failureRate: 0.0,
    latency: { min: 10, max: 30 },
    injectErrors: {
      searchErrors: false,
      upsertErrors: false,
      collectionErrors: false,
      networkErrors: false,
    },
    performance: {
      responseTimeMultiplier: 1.0,
      successRate: 1.0,
      throughput: 100,
    },
  });
}

export function createFlakyQdrantTestDouble(): QdrantTestDouble {
  return new QdrantTestDouble({
    shouldFail: false,
    failureMode: 'network',
    failureRate: 0.2, // 20% failure rate
    latency: { min: 50, max: 200 },
    injectErrors: {
      searchErrors: true,
      upsertErrors: true,
      collectionErrors: false,
      networkErrors: true,
    },
    performance: {
      responseTimeMultiplier: 2.0,
      successRate: 0.8,
      throughput: 50,
    },
  });
}

export function createDegradedQdrantTestDouble(): QdrantTestDouble {
  return new QdrantTestDouble({
    shouldFail: false,
    failureMode: 'timeout',
    failureRate: 0.1,
    latency: { min: 200, max: 1000 },
    injectErrors: {
      searchErrors: true,
      upsertErrors: false,
      collectionErrors: false,
      networkErrors: true,
    },
    performance: {
      responseTimeMultiplier: 5.0,
      successRate: 0.9,
      throughput: 20,
    },
  });
}

export function createFailingQdrantTestDouble(): QdrantTestDouble {
  return new QdrantTestDouble({
    shouldFail: true,
    failureMode: 'server_error',
    failureRate: 0.8,
    latency: { min: 1000, max: 2000 },
    injectErrors: {
      searchErrors: true,
      upsertErrors: true,
      collectionErrors: true,
      networkErrors: true,
    },
    performance: {
      responseTimeMultiplier: 10.0,
      successRate: 0.2,
      throughput: 5,
    },
  });
}