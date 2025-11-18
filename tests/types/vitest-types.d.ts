/**
 * Vitest type definitions and test utilities
 * Provides type safety for test framework globals and mock objects
 */

// Vitest global types augmentation
declare global {
  namespace Vi {
    interface JestAssertion<T = any> {
      /**
       * Asserts that a value is not null or undefined
       */
      notNull(): T extends null | undefined ? never : T;

      /**
       * Asserts that a value is defined
       */
     toBeDefined(): T extends undefined ? never : T;

      /**
       * Asserts that a value is null
       */
      toBeNull(): T extends null ? T : never;

      /**
       * Asserts that a value is undefined
       */
      toBeUndefined(): T extends undefined ? T : never;

      /**
       * Asserts that a value is truthy
       */
     toBeTruthy(): T;

      /**
       * Asserts that a value is falsy
       */
      toBeFalsy(): T;

      /**
       * Asserts that a value equals another value
       */
      toBe<E>(expected: E): T;

      /**
       * Asserts that a value strictly equals another value
       */
      toStrictEqual<E>(expected: E): T;

      /**
       * Asserts that a value equals another value (object property equality)
       */
      toEqual<E>(expected: E): T;

      /**
       * Asserts that an array contains an item
       */
      toContain<E>(item: E): T;

      /**
       * Asserts that a string contains a substring
       */
      toContain<E extends string>(item: E): T;

      /**
       * Asserts that a value has a property
       */
      toHaveProperty<K extends string | number | symbol>(
        property: K,
        value?: unknown
      ): T extends Record<K, any> ? T : never;

      /**
       * Asserts that an object has a specific key
       */
      toHaveKey(key: string): T;

      /**
       * Asserts that a function throws an error
       */
      toThrow<E = Error>(error?: string | RegExp | new () => E): T;

      /**
       * Asserts that a value is an instance of a constructor
       */
      toBeInstanceOf<E>(constructor: new (...args: any[]) => E): T;

      /**
       * Asserts that a number is greater than another number
       */
      toBeGreaterThan(num: number): T extends number ? T : never;

      /**
       * Asserts that a number is greater than or equal to another number
       */
      toBeGreaterThanOrEqual(num: number): T extends number ? T : never;

      /**
       * Asserts that a number is less than another number
       */
      toBeLessThan(num: number): T extends number ? T : never;

      /**
       * Asserts that a number is less than or equal to another number
       */
      toBeLessThanOrEqual(num: number): T extends number ? T : never;

      /**
       * Asserts that a value matches a regular expression
       */
      toMatch(pattern: string | RegExp): T extends string ? T : never;

      /**
       * Asserts that a string matches a pattern
       */
      toMatchObject<E extends Record<string, any>>(expected: E): T;
    }
  }

  // Test utility functions
  const describe: {
    /**
     * Creates a block that groups together several related tests.
     */
    (name: string, fn: () => void): void;

    /**
     * Skips a block of tests
     */
    skip: typeof describe;

    /**
     * Marks a block of tests as focusing
     */
    only: typeof describe;

    /**
     * Runs a block of tests concurrently
     */
    concurrent: typeof describe;
  };

  const it: {
    /**
     * Creates a test case.
     */
    (name: string, fn?: () => void | Promise<void>): void;

    /**
     * Skips a test
     */
    skip: typeof it;

    /**
     * Marks a test as focusing
     */
    only: typeof it;

    /**
     * Runs a test concurrently
     */
    concurrent: typeof it;

    /**
     * Creates a test that expects to fail
     */
    failing: typeof it;
  };

  const test: typeof it;

  const expect: <T = any>(actual: T) => Vi.JestAssertion<T>;

  const beforeAll: (fn: () => void | Promise<void>, timeout?: number) => void;
  const afterAll: (fn: () => void | Promise<void>, timeout?: number) => void;
  const beforeEach: (fn: () => void | Promise<void>, timeout?: number) => void;
  const afterEach: (fn: () => void | Promise<void>, timeout?: number) => void;

  const vi: {
    /**
     * Creates a mock function
     */
    fn<T extends (...args: any[]) => any = (...args: any[]) => any>(
      implementation?: T
    ): jest.MockedFunction<T>;

    /**
     * Mocks a module
     */
    doMock(path: string, factory?: () => any): typeof vi;

    /**
     * Unmocks a module
     */
    doUnmock(path: string): typeof vi;

    /**
     * Clears all mocks
     */
    clearAllMocks(): typeof vi;

    /**
     * Restores all mocks
     */
    restoreAllMocks(): typeof vi;

    /**
     * Advances timers
     */
    advanceTimersByTime(ms: number): typeof vi;

    /**
     * Runs all pending timers
     */
    runAllTimers(): typeof vi;

    /**
     * Runs all timers
     */
    runOnlyPendingTimers(): typeof vi;

    /**
     * Uses fake timers
     */
    useFakeTimers(): typeof vi;

    /**
     * Uses real timers
     */
    useRealTimers(): typeof vi;

    /**
     * Spies on an object method
     */
    spyOn<T extends object, K extends keyof T>(
      object: T,
      method: K
    ): jest.SpyInstance<T[K]>;

    /**
     * Creates a mock object
     */
    mocked<T>(source: T, options?: { deep?: boolean }): jest.Mocked<T>;
  };
}

// Error type definitions for test assertions
export interface TestError extends Error {
  name: string;
  message: string;
  stack?: string;
  code?: string | number;
}

// Mock type definitions
export interface MockResponse {
  status: number;
  data: any;
  headers: Record<string, string>;
  statusText: string;
}

export interface MockDatabaseResult<T = any> {
  success: boolean;
  data?: T;
  error?: TestError;
  metadata?: Record<string, any>;
}

// Test fixture types
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
    [key: string]: boolean;
  };
}

// Test utility types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type Constructor<T = {}> = new (...args: any[]) => T;

export type MockableFunction<T extends (...args: any[]) => any> = {
  [K in keyof T]: T[K];
} & {
  mockClear: () => jest.MockedFunction<T>;
  mockReset: () => jest.MockedFunction<T>;
  mockRestore: () => jest.MockedFunction<T>;
  mockImplementation: (fn: T) => jest.MockedFunction<T>;
  mockImplementationOnce: (fn: T) => jest.MockedFunction<T>;
  mockReturnValue: (value: ReturnType<T>) => jest.MockedFunction<T>;
  mockReturnValueOnce: (value: ReturnType<T>) => jest.MockedFunction<T>;
  mockResolvedValue: (value: ReturnType<T>) => jest.MockedFunction<T>;
  mockResolvedValueOnce: (value: ReturnType<T>) => jest.MockedFunction<T>;
  mockRejectedValue: (value: Error) => jest.MockedFunction<T>;
  mockRejectedValueOnce: (value: Error) => jest.MockedFunction<T>;
  mock: {
    calls: Array<Parameters<T>>;
    results: Array<{ type: 'return' | 'throw'; value: ReturnType<T> | Error }>;
    instances: Array<any>;
    callArg: (index: number) => any;
    callsArg: (index: number) => jest.MockedFunction<T>;
  };
};

// Enhanced error type guards for test catch blocks
export function isError(error: unknown): error is Error {
  return error instanceof Error;
}

export function hasMessage(error: unknown): error is { message: string } {
  return typeof error === 'object' && error !== null && 'message' in error && typeof (error as any).message === 'string';
}

export function hasName(error: unknown): error is { name: string } {
  return typeof error === 'object' && error !== null && 'name' in error && typeof (error as any).name === 'string';
}

// Global test utility functions
declare global {
  function expectError<T>(error: unknown, expectedMessage: string): asserts error is Error & { message: string };
  function expectErrorWithName<T>(error: unknown, expectedName: string, expectedMessage: string): asserts error is Error & { name: string; message: string };
}

// Implementation of global test utilities
export function expectError(error: unknown, expectedMessage: string): asserts error is Error & { message: string } {
  if (!isError(error)) {
    throw new Error(`Expected Error object, got ${typeof error}`);
  }
  if (error.message !== expectedMessage) {
    throw new Error(`Expected error message "${expectedMessage}", got "${error.message}"`);
  }
}

export function expectErrorWithName(error: unknown, expectedName: string, expectedMessage: string): asserts error is Error & { name: string; message: string } {
  expectError(error, expectedMessage);
  if (error.name !== expectedName) {
    throw new Error(`Expected error name "${expectedName}", got "${error.name}"`);
  }
}