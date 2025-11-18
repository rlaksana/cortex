/**
 * Vitest Type Definitions and Test Utilities
 *
 * Provides comprehensive type definitions for test scenarios,
 * error handling utilities, and type-safe test patterns.
 */

import { vi } from 'vitest';

// =============================================================================
// BASIC TEST TYPES
// =============================================================================

export interface TestEntity {
  kind: string;
  content: string;
  metadata: Record<string, any>;
  scope: {
    project: string;
    branch?: string;
    org?: string;
  };
}

export interface TestConfig {
  database: {
    host: string;
    port: number;
    collection: string;
  };
  logging: {
    level: string;
    enabled: boolean;
  };
  features: {
    deduplication: boolean;
    contradiction_detection: boolean;
    insights: boolean;
  };
}

export interface MockResponse {
  status: number;
  data: any;
  headers: Record<string, string>;
  statusText: string;
}

export interface MockDatabaseResult<T = any> {
  success: boolean;
  data?: T;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  metadata: {
    timestamp: string;
    [key: string]: any;
  };
}

// =============================================================================
// UTILITY TYPES
// =============================================================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends (infer U)[]
    ? DeepPartial<U>[]
    : T[P] extends readonly (infer U)[]
    ? readonly DeepPartial<U>[]
    : T[P] extends object
    ? DeepPartial<T[P]>
    : T[P];
};

export type MockableFunction<T extends (...args: any[]) => any> = {
  [K in keyof T]: T[K];
} & {
  mockImplementation: (implementation: T) => void;
  mockReturnValue: (value: ReturnType<T>) => void;
  mockResolvedValue: (value: ReturnType<T>) => void;
  mockRejectedValue: (error: Error) => void;
};

export type Constructor<T = {}> = new (...args: any[]) => T;

// =============================================================================
// ERROR HANDLING UTILITIES
// =============================================================================

export function expectError(error: unknown): asserts error is Error {
  expect(error).toBeInstanceOf(Error);
}

export function expectErrorWithName(error: unknown, expectedName: string): asserts error is Error {
  expectError(error);
  expect(error.name).toBe(expectedName);
}

export function isError(error: unknown): error is Error {
  return error instanceof Error;
}

export function hasMessage(error: unknown): error is Error & { message: string } {
  return isError(error);
}

export function hasName(error: unknown): error is Error & { name: string } {
  return isError(error);
}

// =============================================================================
// EXTENDED MOCK FACTORY TYPES
// =============================================================================

export interface MockStoreResult {
  success: boolean;
  data?: { id: string };
  error?: Error;
}

export interface MockValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}

export interface MockFindResult {
  success: boolean;
  data?: any[];
  total?: number;
  error?: Error;
}

// =============================================================================
// MOCK FACTORY FUNCTIONS
// =============================================================================

export function createMockStoreResult(overrides: DeepPartial<MockStoreResult> = {}): MockStoreResult {
  return {
    success: true,
    data: { id: 'test-id' },
    ...overrides
  };
}

export function createMockValidationResult(
  valid: boolean = true,
  errors: string[] = [],
  warnings: string[] = []
): MockValidationResult {
  return {
    valid,
    errors: valid ? undefined : errors,
    warnings: warnings.length > 0 ? warnings : undefined
  };
}

export function createMockFindResult(
  data: any[] = [],
  success: boolean = true,
  error?: Error
): MockFindResult {
  return {
    success,
    data: success ? data : undefined,
    total: data.length,
    error: success ? undefined : error
  };
}

// =============================================================================
// SERVICE MOCK INTERFACES
// =============================================================================

export interface MockServiceOptions {
  shouldFail?: boolean;
  delay?: number;
  error?: Error;
  response?: any;
}

export function createMockService(options: MockServiceOptions = {}) {
  const {
    shouldFail = false,
    delay = 0,
    error = new Error('Mock service error'),
    response = null
  } = options;

  return {
    execute: vi.fn().mockImplementation(async (...args: any[]) => {
      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      if (shouldFail) {
        throw error;
      }

      return response;
    }),
    healthCheck: vi.fn().mockResolvedValue(!shouldFail),
    reset: vi.fn(),
    configure: vi.fn()
  };
}

// =============================================================================
// TEST CONTEXT BUILDERS
// =============================================================================

export interface TestContext {
  testId: string;
  timestamp: string;
  metadata: Record<string, any>;
}

export function createTestContext(overrides: DeepPartial<TestContext> = {}): TestContext {
  return {
    testId: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    metadata: {},
    ...overrides
  };
}

// =============================================================================
// ASYNC TEST UTILITIES
// =============================================================================

export async function expectAsyncThrow<T>(
  asyncFn: () => Promise<T>,
  expectedError?: string | RegExp | ErrorConstructor
): Promise<Error> {
  try {
    await asyncFn();
    throw new Error('Expected function to throw');
  } catch (error) {
    expectError(error);

    if (expectedError) {
      if (typeof expectedError === 'string') {
        expect(error.message).toContain(expectedError);
      } else if (expectedError instanceof RegExp) {
        expect(error.message).toMatch(expectedError);
      } else if (typeof expectedError === 'function') {
        expect(error).toBeInstanceOf(expectedError);
      }
    }

    return error;
  }
}

export function createAsyncResolver<T>(value: T): () => Promise<T> {
  return () => Promise.resolve(value);
}

export function createAsyncRejector(error: Error): () => Promise<never> {
  return () => Promise.reject(error);
}

// =============================================================================
// COLLECTION AND ARRAY UTILITIES
// =============================================================================

export function createMockCollection<T>(
  items: T[] = [],
  options: { shouldFail?: boolean; error?: Error } = {}
) {
  const { shouldFail = false, error = new Error('Collection error') } = options;

  return {
    items: [...items],
    length: items.length,
    add: vi.fn().mockImplementation((item: T) => {
      if (shouldFail) throw error;
      items.push(item);
      return item;
    }),
    remove: vi.fn().mockImplementation((item: T) => {
      if (shouldFail) throw error;
      const index = items.indexOf(item);
      if (index > -1) {
        items.splice(index, 1);
        return true;
      }
      return false;
    }),
    find: vi.fn().mockImplementation((predicate: (item: T) => boolean) => {
      if (shouldFail) throw error;
      return items.find(predicate);
    }),
    filter: vi.fn().mockImplementation((predicate: (item: T) => boolean) => {
      if (shouldFail) throw error;
      return items.filter(predicate);
    }),
    clear: vi.fn().mockImplementation(() => {
      if (shouldFail) throw error;
      items.length = 0;
    }),
    toArray: vi.fn().mockReturnValue([...items])
  };
}

// =============================================================================
// TYPE ASSERTION HELPERS
// =============================================================================

export function assertType<T>(value: unknown): asserts value is T {
  // This is a type assertion function - runtime checks can be added if needed
}

export function assertDefined<T>(value: T | undefined): asserts value is T {
  if (value === undefined) {
    throw new Error('Value should be defined');
  }
}

export function assertNotNull<T>(value: T | null): asserts value is T {
  if (value === null) {
    throw new Error('Value should not be null');
  }
}

// =============================================================================
// MOCK LOGGER WITH TYPE SAFETY
// =============================================================================

export interface MockLogger {
  debug: MockableFunction<(message: string, ...args: any[]) => void>;
  info: MockableFunction<(message: string, ...args: any[]) => void>;
  warn: MockableFunction<(message: string, ...args: any[]) => void>;
  error: MockableFunction<(message: string, ...args: any[]) => void>;
  child: MockableFunction<(context: Record<string, any>) => MockLogger>;
  level: string;
}

export function createMockLogger(): MockLogger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn().mockReturnValue(createMockLogger()),
    level: 'error'
  };
}

// =============================================================================
// EXPORT ALIASES FOR BACKWARD COMPATIBILITY
// =============================================================================

export const TestUtils = {
  expectError,
  expectErrorWithName,
  isError,
  hasMessage,
  hasName,
  createMockStoreResult,
  createMockValidationResult,
  createMockFindResult,
  createMockService,
  createTestContext,
  expectAsyncThrow,
  createAsyncResolver,
  createAsyncRejector,
  createMockCollection,
  assertType,
  assertDefined,
  assertNotNull,
  createMockLogger
};