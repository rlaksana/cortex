/**
 * Core Service Mocks for CI Testing
 *
 * Provides consistent mocks for core services used throughout the application.
 * These mocks ensure tests run fast and reliably in CI environments.
 */

import { vi } from 'vitest';

// Mock memory store service
export const mockMemoryStore = {
  store: vi.fn().mockResolvedValue([
    {
      id: 'mock-id-1',
      status: 'stored',
      kind: 'entity',
      created_at: new Date().toISOString(),
    },
  ]),
  find: vi.fn().mockResolvedValue([]),
  update: vi.fn().mockResolvedValue(true),
  delete: vi.fn().mockResolvedValue(true),
  healthCheck: vi.fn().mockResolvedValue(true),
};

// Mock memory find service
export const mockMemoryFind = {
  find: vi.fn().mockResolvedValue({
    results: [],
    total_count: 0,
    autonomous_context: {
      search_mode_used: 'auto',
      results_found: 0,
      confidence_average: 0.5,
      user_message_suggestion: 'Search completed',
    },
  }),
  search: vi.fn().mockResolvedValue([]),
  healthCheck: vi.fn().mockResolvedValue(true),
};

// Mock deduplication service
export const mockDeduplicationService = {
  isDuplicate: vi.fn().mockResolvedValue({
    isDuplicate: false,
    similarityScore: 0,
    matchType: 'none',
    reason: 'No duplicate found',
  }),
  checkDuplicates: vi.fn().mockResolvedValue({
    duplicates: [],
    originals: [],
  }),
  removeDuplicates: vi.fn().mockResolvedValue([]),
  upsertWithMerge: vi.fn().mockResolvedValue({
    upserted: [],
    merged: [],
    created: [],
  }),
};

// Mock validation service
export const mockValidationService = {
  validateItem: vi.fn().mockResolvedValue({ valid: true }),
  validateItems: vi.fn().mockResolvedValue({ valid: true, errors: [] }),
  validateBusinessRules: vi.fn().mockResolvedValue({ valid: true }),
  validateSchema: vi.fn().mockResolvedValue({ valid: true }),
};

// Mock authentication service
export const mockAuthService = {
  authenticate: vi.fn().mockResolvedValue({
    valid: true,
    userId: 'test-user',
    scopes: ['read', 'write'],
  }),
  authorize: vi.fn().mockResolvedValue(true),
  generateToken: vi.fn().mockReturnValue('test-token'),
  validateToken: vi.fn().mockResolvedValue({
    valid: true,
    userId: 'test-user',
  }),
};

// Mock rate limiting service
export const mockRateLimitService = {
  checkRateLimit: vi.fn().mockResolvedValue({
    allowed: true,
    remaining: 100,
    resetTime: Date.now() + 3600000,
    identifier: 'test-identifier',
  }),
  updateLimits: vi.fn().mockResolvedValue(true),
  getMetrics: vi.fn().mockResolvedValue({
    totalRequests: 0,
    blockedRequests: 0,
    averageRequestsPerMinute: 0,
  }),
};

// Mock metrics service
export const mockMetricsService = {
  incrementCounter: vi.fn(),
  recordDuration: vi.fn(),
  recordGauge: vi.fn(),
  recordHistogram: vi.fn(),
  getMetrics: vi.fn().mockResolvedValue({
    counters: {},
    gauges: {},
    histograms: {},
  }),
  resetMetrics: vi.fn(),
};

// Mock structured logger
export const mockStructuredLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  logOperation: vi.fn(),
  logPerformance: vi.fn(),
  logError: vi.fn(),
  getMetrics: vi.fn().mockReturnValue({
    totalLogs: 0,
    errorCount: 0,
    warnCount: 0,
  }),
};

// Mock slow query logger
export const mockSlowQueryLogger = {
  logSlowQuery: vi.fn(),
  getSlowQueries: vi.fn().mockReturnValue([]),
  clearSlowQueries: vi.fn(),
  getMetrics: vi.fn().mockReturnValue({
    totalSlowQueries: 0,
    averageDuration: 0,
  }),
};

// Export all mocks as a unified object
export const coreMocks = {
  memoryStore: mockMemoryStore,
  memoryFind: mockMemoryFind,
  deduplicationService: mockDeduplicationService,
  validationService: mockValidationService,
  authService: mockAuthService,
  rateLimitService: mockRateLimitService,
  metricsService: mockMetricsService,
  structuredLogger: mockStructuredLogger,
  slowQueryLogger: mockSlowQueryLogger,
};

// Helper to reset all mocks
export const resetAllMocks = () => {
  Object.values(coreMocks).forEach((mock) => {
    if (mock && typeof mock === 'object') {
      Object.values(mock).forEach((method) => {
        if (vi.isMockFunction(method)) {
          vi.clearAllMocks();
        }
      });
    }
  });
};
