/**
 * Mock Management Utilities
 *
 * Provides centralized mock creation, tracking, and cleanup for consistent testing.
 */

import { vi, MockedFunction } from 'vitest';

/**
 * Mock registry for tracking all created mocks
 */
class MockRegistry {
  private static instance: MockRegistry;
  private mocks: Map<string, any> = new Map();
  private modules: Map<string, any> = new Map();

  private constructor() {}

  static getInstance(): MockRegistry {
    if (!MockRegistry.instance) {
      MockRegistry.instance = new MockRegistry();
    }
    return MockRegistry.instance;
  }

  /**
   * Register a mock for cleanup tracking
   */
  registerMock(name: string, mock: any): void {
    this.mocks.set(name, mock);
  }

  /**
   * Register a module mock
   */
  registerModule(moduleName: string, mock: any): void {
    this.modules.set(moduleName, mock);
  }

  /**
   * Get a registered mock
   */
  getMock(name: string): any {
    return this.mocks.get(name);
  }

  /**
   * Get a registered module mock
   */
  getModuleMock(moduleName: string): any {
    return this.modules.get(moduleName);
  }

  /**
   * Clear all mocks but keep them registered
   */
  clearAllMocks(): void {
    this.mocks.forEach((mock) => {
      if (mock && typeof mock.mockClear === 'function') {
        mock.mockClear();
      }
    });

    this.modules.forEach((mock) => {
      if (mock && typeof mock.mockClear === 'function') {
        mock.mockClear();
      }
    });
  }

  /**
   * Reset all mocks to their original state
   */
  resetAllMocks(): void {
    this.mocks.forEach((mock) => {
      if (mock && typeof mock.mockReset === 'function') {
        mock.mockReset();
      }
    });

    this.modules.forEach((mock) => {
      if (mock && typeof mock.mockReset === 'function') {
        mock.mockReset();
      }
    });
  }

  /**
   * Restore all mocks to their original implementations
   */
  restoreAllMocks(): void {
    this.mocks.forEach((mock) => {
      if (mock && typeof mock.mockRestore === 'function') {
        mock.mockRestore();
      }
    });

    this.modules.forEach((mock) => {
      if (mock && typeof mock.mockRestore === 'function') {
        mock.mockRestore();
      }
    });

    this.mocks.clear();
    this.modules.clear();
  }

  /**
   * Get statistics about registered mocks
   */
  getStats(): { mocks: number; modules: number; total: number } {
    return {
      mocks: this.mocks.size,
      modules: this.modules.size,
      total: this.mocks.size + this.modules.size,
    };
  }
}

/**
 * Mock factory for creating standardized mocks
 */
export class MockManager {
  private static registry = MockRegistry.getInstance();

  /**
   * Create and register a function mock
   */
  static createFunction<T extends (...args: any[]) => any>(
    name: string,
    implementation?: T,
    options: { persistent?: boolean } = {}
  ): MockedFunction<T> {
    const mock = vi.fn(implementation) as MockedFunction<T>;

    if (!options.persistent) {
      this.registry.registerMock(name, mock);
    }

    return mock;
  }

  /**
   * Create and register an object mock
   */
  static createObject<T extends Record<string, any>>(
    name: string,
    properties: Partial<T>,
    options: { persistent?: boolean } = {}
  ): T {
    const mock: any = {};

    Object.entries(properties).forEach(([key, value]) => {
      if (typeof value === 'function') {
        mock[key] = vi.fn(value);
      } else {
        mock[key] = value;
      }
    });

    if (!options.persistent) {
      this.registry.registerMock(name, mock);
    }

    return mock as T;
  }

  /**
   * Mock a module with vi.mock
   */
  static mockModule(
    moduleName: string,
    mockImplementation: Record<string, any>,
    options: { persistent?: boolean } = {}
  ): void {
    vi.mock(moduleName, () => mockImplementation);

    if (!options.persistent) {
      this.registry.registerModule(moduleName, mockImplementation);
    }
  }

  /**
   * Create a promise mock that resolves with a value
   */
  static createResolvedMock<T>(
    name: string,
    value: T,
    delay: number = 0
  ): MockedFunction<() => Promise<T>> {
    const mock = vi.fn(() => {
      if (delay > 0) {
        return new Promise((resolve) => setTimeout(() => resolve(value), delay));
      }
      return Promise.resolve(value);
    });

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create a promise mock that rejects with an error
   */
  static createRejectedMock<T>(
    name: string,
    error: Error | string,
    delay: number = 0
  ): MockedFunction<() => Promise<T>> {
    const mock = vi.fn(() => {
      if (delay > 0) {
        return new Promise((_, reject) => setTimeout(() => reject(error), delay));
      }
      return Promise.reject(error);
    });

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create a stream mock
   */
  static createStreamMock(name: string, events: Record<string, any> = {}) {
    const mock = {
      on: vi.fn(),
      emit: vi.fn(),
      pipe: vi.fn(),
      write: vi.fn(),
      end: vi.fn(),
      ...events,
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create an event emitter mock
   */
  static createEventEmitterMock(name: string) {
    const mock = {
      on: vi.fn(),
      off: vi.fn(),
      emit: vi.fn(),
      once: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      removeAllListeners: vi.fn(),
      listeners: vi.fn(() => []),
      eventNames: vi.fn(() => []),
      setMaxListeners: vi.fn(),
      getMaxListeners: vi.fn(() => 10),
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create a database client mock with common methods
   */
  static createDatabaseClientMock(name: string) {
    const mock = {
      connect: vi.fn().mockResolvedValue(undefined),
      disconnect: vi.fn().mockResolvedValue(undefined),
      query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      transaction: vi.fn().mockResolvedValue(undefined),
      begin: vi.fn().mockResolvedValue(undefined),
      commit: vi.fn().mockResolvedValue(undefined),
      rollback: vi.fn().mockResolvedValue(undefined),
      healthCheck: vi.fn().mockResolvedValue(true),
      close: vi.fn().mockResolvedValue(undefined),
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create an HTTP client mock
   */
  static createHttpClientMock(name: string) {
    const mock = {
      get: vi.fn().mockResolvedValue({ data: {}, status: 200 }),
      post: vi.fn().mockResolvedValue({ data: {}, status: 201 }),
      put: vi.fn().mockResolvedValue({ data: {}, status: 200 }),
      patch: vi.fn().mockResolvedValue({ data: {}, status: 200 }),
      delete: vi.fn().mockResolvedValue({ data: {}, status: 204 }),
      request: vi.fn().mockResolvedValue({ data: {}, status: 200 }),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
      defaults: {
        headers: {},
        timeout: 5000,
      },
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create a logger mock
   */
  static createLoggerMock(name: string) {
    const mock = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      fatal: vi.fn(),
      trace: vi.fn(),
      child: vi.fn(() => mock),
      level: 'info',
      silent: false,
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Create a file system mock
   */
  static createFileSystemMock(name: string) {
    const mock = {
      readFile: vi.fn().mockResolvedValue(''),
      writeFile: vi.fn().mockResolvedValue(undefined),
      appendFile: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn().mockResolvedValue(false),
      mkdir: vi.fn().mockResolvedValue(undefined),
      rmdir: vi.fn().mockResolvedValue(undefined),
      readdir: vi.fn().mockResolvedValue([]),
      stat: vi.fn().mockResolvedValue({
        isFile: () => true,
        isDirectory: () => false,
        size: 0,
        mtime: new Date(),
      }),
      unlink: vi.fn().mockResolvedValue(undefined),
      copyFile: vi.fn().mockResolvedValue(undefined),
    };

    this.registry.registerMock(name, mock);
    return mock;
  }

  /**
   * Setup mock behavior with multiple calls
   */
  static setupMockSequence(mock: MockedFunction, sequence: any[]): void {
    sequence.forEach((result, index) => {
      if (result instanceof Error) {
        mock.mockReturnValueOnce(Promise.reject(result));
      } else if (result && typeof result.then === 'function') {
        mock.mockReturnValueOnce(result);
      } else {
        mock.mockResolvedValueOnce(result);
      }
    });
  }

  /**
   * Setup mock to return different values on consecutive calls
   */
  static setupMockAlternating(mock: MockedFunction, values: any[]): void {
    values.forEach((value, index) => {
      if (index % 2 === 0) {
        mock.mockResolvedValueOnce(value);
      } else {
        mock.mockResolvedValueOnce(value);
      }
    });
  }

  /**
   * Verify mock was called with specific arguments
   */
  static verifyMockCall(mock: MockedFunction, args: any[], callIndex: number = 0): boolean {
    if (!mock.mock.calls[callIndex]) {
      return false;
    }

    return JSON.stringify(mock.mock.calls[callIndex]) === JSON.stringify(args);
  }

  /**
   * Get all registered mocks
   */
  static getAllMocks(): Map<string, any> {
    const registry = MockRegistry.getInstance();
    return new Map([...registry['mocks']]);
  }

  /**
   * Clear all registered mocks
   */
  static clearAllMocks(): void {
    MockRegistry.getInstance().clearAllMocks();
  }

  /**
   * Reset all registered mocks
   */
  static resetAllMocks(): void {
    MockRegistry.getInstance().resetAllMocks();
  }

  /**
   * Restore all registered mocks
   */
  static restoreAllMocks(): void {
    MockRegistry.getInstance().restoreAllMocks();
  }

  /**
   * Get mock statistics
   */
  static getMockStats(): { mocks: number; modules: number; total: number } {
    return MockRegistry.getInstance().getStats();
  }
}

/**
 * Pre-configured mock factories for common dependencies
 */
export const CommonMocks = {
  /**
   * Qdrant client mock
   */
  qdrantClient: () =>
    MockManager.createObject('qdrantClient', {
      getCollections: vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      }),
      createCollection: vi.fn().mockResolvedValue(undefined),
      deleteCollection: vi.fn().mockResolvedValue(undefined),
      upsert: vi.fn().mockResolvedValue({ status: 'completed' }),
      search: vi.fn().mockResolvedValue([]),
      getCollection: vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      }),
      delete: vi.fn().mockResolvedValue({ status: 'completed' }),
      scroll: vi.fn().mockResolvedValue({ points: [], next_page_offset: null }),
      count: vi.fn().mockResolvedValue({ count: 0 }),
      healthCheck: vi.fn().mockResolvedValue(true),
    }),

  /**
   * Authentication service mock
   */
  authService: () =>
    MockManager.createObject('authService', {
      hashPassword: vi.fn().mockResolvedValue('hashed-password'),
      comparePassword: vi.fn().mockResolvedValue(true),
      generateToken: vi.fn().mockReturnValue('mock-jwt-token'),
      verifyToken: vi.fn().mockResolvedValue({ userId: 'test-user', role: 'user' }),
      refreshToken: vi.fn().mockReturnValue('mock-refresh-token'),
      invalidateToken: vi.fn().mockResolvedValue(true),
      createSession: vi.fn().mockResolvedValue({ sessionId: 'test-session' }),
      validateSession: vi.fn().mockResolvedValue(true),
      destroySession: vi.fn().mockResolvedValue(true),
    }),

  /**
   * Embedding service mock
   */
  embeddingService: () =>
    MockManager.createObject('embeddingService', {
      generateEmbedding: vi.fn().mockResolvedValue([0.1, 0.2, 0.3, 0.4, 0.5]),
      generateBatchEmbeddings: vi.fn().mockResolvedValue([
        [0.1, 0.2, 0.3, 0.4, 0.5],
        [0.6, 0.7, 0.8, 0.9, 1.0],
      ]),
      calculateSimilarity: vi.fn().mockReturnValue(0.85),
      findMostSimilar: vi.fn().mockResolvedValue({ id: 'test-item', score: 0.9 }),
    }),

  /**
   * Logger mock
   */
  logger: () => MockManager.createLoggerMock('logger'),

  /**
   * HTTP client mock
   */
  httpClient: () => MockManager.createHttpClientMock('httpClient'),

  /**
   * Database client mock
   */
  databaseClient: () => MockManager.createDatabaseClientMock('databaseClient'),
};

/**
 * Global mock cleanup utilities
 */
export const MockCleanup = {
  clearAll: () => MockManager.clearAllMocks(),
  resetAll: () => MockManager.resetAllMocks(),
  restoreAll: () => MockManager.restoreAllMocks(),
  getStats: () => MockManager.getMockStats(),
};

export default MockManager;
