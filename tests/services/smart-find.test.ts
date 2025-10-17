import { memoryFind } from '../../src/services/memory-find.js';
import {
  smartMemoryFind,
  type CorrectionMetadata,
  type SmartFindResult
} from '../../src/services/smart-find.js';
import {
  sanitizeQuery,
  type SanitizationResult
} from '../../src/utils/query-sanitizer.js';

// Mock the memoryFind function
jest.mock('../../src/services/memory-find.js');
const mockedMemoryFind = memoryFind as jest.MockedFunction<typeof memoryFind>;

describe('Smart Memory Find', () => {
  const mockSuccessfulResult = {
    hits: [
      {
        id: '123',
        kind: 'section',
        title: 'Test Result',
        snippet: 'This is a test result',
        score: 0.85,
        route_used: 'auto',
        confidence: 0.85
      }
    ],
    suggestions: [],
    autonomous_metadata: {
      strategy_used: 'fast',
      mode_requested: 'auto',
      mode_executed: 'auto',
      confidence: 'high',
      total_results: 1,
      avg_score: 0.85,
      fallback_attempted: false,
      recommendation: 'Results sufficient',
      user_message_suggestion: 'Found 1 result'
    },
    debug: {
      query_duration_ms: 100,
      total_candidates: 10,
      mode_used: 'auto',
      tables_searched: 5,
      graph_nodes: 0,
      graph_edges: 0
    },
    graph: undefined
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedMemoryFind.mockClear();
  });

  describe('successful first attempt', () => {
    it('should return result on first try with clean query', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'database schema design',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.hits).toHaveLength(1);
      expect(result.corrections?.original_query).toBe('database schema design');
      expect(result.corrections?.final_query).toBe('database schema design');
      expect(result.corrections?.attempts).toHaveLength(1);
      expect(result.corrections?.attempts[0].success).toBe(true);
      expect(mockedMemoryFind).toHaveBeenCalledTimes(1);
    });

    it('should handle disabled auto-fix', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'T008-T021 task completion',
        enable_auto_fix: false,
        return_corrections: true
      });

      expect(result.corrections?.auto_fix_enabled).toBe(false);
      expect(result.corrections?.recommendation).toBe('Auto-fix disabled. Query executed as-is.');
      expect(mockedMemoryFind).toHaveBeenCalledTimes(1);
    });
  });

  describe('tsquery error recovery', () => {
    it('should retry with moderate sanitization on tsquery error', async () => {
      const tsQueryError = new Error('syntax error in tsquery');
      const secondAttempt = {
        ...mockSuccessfulResult,
        autonomous_metadata: {
          ...mockSuccessfulResult.autonomous_metadata,
          mode_executed: 'auto'
        }
      };

      // First attempt fails with tsquery error
      mockedMemoryFind
        .mockRejectedValueOnce(tsQueryError)
        .mockResolvedValueOnce(secondAttempt);

      const result = await smartMemoryFind({
        query: 'T008-T021 task completion',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(mockedMemoryFind).toHaveBeenCalledTimes(2);
      expect(result.corrections?.attempts).toHaveLength(2);
      expect(result.corrections?.attempts[0].success).toBe(false);
      expect(result.corrections?.attempts[0].error).toBe('syntax error in tsquery');
      expect(result.corrections?.attempts[1].success).toBe(true);
      expect(result.corrections?.final_query).toBe('T008 T021 task completion');
      expect(result.corrections?.auto_fixes_applied).toContain('Convert task ID ranges to space-separated format');
    });

    it('should escalate to aggressive sanitization on second failure', async () => {
      const tsQueryError = new Error('syntax error in tsquery');
      const thirdAttempt = {
        ...mockSuccessfulResult,
        autonomous_metadata: {
          ...mockSuccessfulResult.autonomous_metadata,
          mode_executed: 'deep'
        }
      };

      // First two attempts fail
      mockedMemoryFind
        .mockRejectedValueOnce(tsQueryError)
        .mockRejectedValueOnce(tsQueryError)
        .mockResolvedValueOnce(thirdAttempt);

      const result = await smartMemoryFind({
        query: 'T008-T021 Phase-2#test',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(mockedMemoryFind).toHaveBeenCalledTimes(3);
      expect(result.corrections?.attempts).toHaveLength(3);
      expect(result.corrections?.attempts[2].mode).toBe('deep');
      expect(result.corrections?.final_sanitization_level).toBe('aggressive');
    });

    it('should handle timeout errors by escalating to aggressive mode', async () => {
      const timeoutError = new Error('Timeout');
      const secondAttempt = {
        ...mockSuccessfulResult,
        autonomous_metadata: {
          ...mockSuccessfulResult.autonomous_metadata,
          mode_executed: 'deep'
        }
      };

      mockedMemoryFind
        .mockRejectedValueOnce(timeoutError)
        .mockResolvedValueOnce(secondAttempt);

      const result = await smartMemoryFind({
        query: 'complex query with timeout',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(mockedMemoryFind).toHaveBeenCalledTimes(2);
      expect(result.corrections?.attempts[0].error).toBe('Timeout');
      expect(result.corrections?.attempts[1].mode).toBe('deep');
    });
  });

  describe('correction metadata', () => {
    it('should track all attempts correctly', async () => {
      const firstError = new Error('tsquery syntax error');
      const secondResult = {
        ...mockSuccessfulResult,
        autonomous_metadata: {
          ...mockSuccessfulResult.autonomous_metadata,
          mode_executed: 'auto'
        }
      };

      mockedMemoryFind
        .mockRejectedValueOnce(firstError)
        .mockResolvedValueOnce(secondResult);

      const result = await smartMemoryFind({
        query: 'T008-T021 task completion',
        enable_auto_fix: true,
        return_corrections: true
      });

      const corrections = result.corrections!;

      expect(corrections.patterns_detected).toContain('task_id_range');
      expect(corrections.total_attempts).toBe(2);
      expect(corrections.auto_fixes_applied.length).toBe(1);
      expect(corrections.transformations).toContain('sanitization_moderate');
      expect(corrections.recommendation).toContain('auto-corrected successfully');
    });

    it('should generate appropriate recommendations', async () => {
      // Test all attempts fail
      const tsQueryError = new Error('syntax error in tsquery');
      mockedMemoryFind.mockRejectedValue(tsQueryError);

      const result = await smartMemoryFind({
        query: 'T008-T021#invalid',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.corrections?.recommendation).toBe('All attempts failed. Manual intervention required.');
      expect(result.autonomous_metadata.recommendation).toBe('Query failed due to syntax errors.');
    });

    it('should handle missing corrections flag', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'test query',
        enable_auto_fix: true,
        return_corrections: false
      });

      expect(result.corrections).toBeUndefined();
    });
  });

  describe('error handling', () => {
    it('should return empty result when all attempts fail', async () => {
      const tsQueryError = new Error('syntax error in tsquery');
      mockedMemoryFind.mockRejectedValue(tsQueryError);

      const result = await smartMemoryFind({
        query: 'T008-T021#invalid',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.hits).toHaveLength(0);
      expect(result.suggestions).toContain('Try simpler terms');
      expect(result.debug?.error).toBe('syntax error in tsquery');
      expect(result.corrections?.attempts.every(a => !a.success)).toBe(true);
    });

    it('should handle memoryFind throwing non-Error object', async () => {
      mockedMemoryFind.mockRejectedValue('Something went wrong');

      const result = await smartMemoryFind({
        query: 'test query',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.hits).toHaveLength(0);
      expect(result.debug?.error).toBe('Something went wrong');
    });

    it('should handle max attempts correctly', async () => {
      const tsQueryError = new Error('syntax error in tsquery');
      const finalAttempt = {
        ...mockSuccessfulResult,
        autonomous_metadata: {
          ...mockSuccessfulResult.autonomous_metadata,
          mode_executed: 'deep'
        }
      };

      mockedMemoryFind
        .mockRejectedValueOnce(tsQueryError)
        .mockRejectedValueOnce(tsQueryError)
        .mockResolvedValueOnce(finalAttempt);

      const result = await smartMemoryFind({
        query: 'T008-T021 test',
        enable_auto_fix: true,
        return_corrections: true,
        max_attempts: 3
      });

      expect(mockedMemoryFind).toHaveBeenCalledTimes(3);
      expect(result.corrections?.total_attempts).toBe(3);
    });
  });

  describe('integration with sanitizer', () => {
    it('should use sanitizeQuery result for cleaning', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      // First, test what sanitizeQuery does to our query
      const sanitizeResult = sanitizeQuery('T008-T021 Phase-2 test', 'moderate');
      expect(sanitizeResult.cleaned).toBe('T008 T021 Phase 2 test');

      // Now test smartMemoryFind
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'T008-T021 Phase-2 test',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.corrections?.final_query).toBe('T008 T021 Phase 2 test');
    });

    it('should preserve original query in metadata', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'T008-T021 task completion',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.corrections?.original_query).toBe('T008-T021 task completion');
      expect(result.corrections?.final_query).toBe('T008-T021 task completion'); // No sanitization needed for clean query
    });
  });

  describe('performance and timeouts', () => {
    it('should respect timeout per attempt', async () => {
      const longRunningMock = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timeout')), 100);
      });

      mockedMemoryFind.mockImplementation(() => longRunningMock);

      const startTime = Date.now();
      await smartMemoryFind({
        query: 'test query',
        enable_auto_fix: true,
        timeout_per_attempt_ms: 100
      });
      const duration = Date.now() - startTime;

      // Should be close to 100ms
      expect(duration).toBeLessThan(200);
    });

    it('should include timing information in debug', async () => {
      mockedMemoryFind.mockResolvedValue(mockSuccessfulResult);

      const result = await smartMemoryFind({
        query: 'test query',
        enable_auto_fix: true,
        return_corrections: true
      });

      expect(result.debug?.total_time_ms).toBeDefined();
      expect(result.debug?.total_attempts).toBe(1);
    });
  });
});