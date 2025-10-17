import { logger } from '../utils/logger.js';
import { memoryFind } from './memory-find.js';
import { sanitizeQuery, type SanitizationLevel } from '../utils/query-sanitizer.js';

/**
 * Smart Memory Find - Auto-correcting query wrapper with feedback
 *
 * Wraps the existing memoryFind function to provide:
 * 1. Automatic detection of problematic query patterns
 * 2. Progressive sanitization retry strategy
 * 3. Detailed correction metadata and feedback
 * 4. Full backward compatibility
 */

// Import types from memory-find
interface FindHit {
  kind: string;
  id: string;
  title: string;
  snippet: string;
  score: number;
  scope?: Record<string, unknown>;
  updated_at?: string;
  route_used: string;
  confidence: number;
}

interface AutonomousMetadata {
  strategy_used: 'fast' | 'deep' | 'fast_then_deep_fallback';
  mode_requested: string;
  mode_executed: string;
  confidence: 'high' | 'medium' | 'low';
  total_results: number;
  avg_score: number;
  fallback_attempted: boolean;
  recommendation: string;
  user_message_suggestion: string;
}

export interface CorrectionMetadata {
  original_query: string;
  final_query: string;
  attempts: Array<{
    attempt_number: number;
    query: string;
    mode: string;
    sanitization_level?: string;
    error?: string;
    success: boolean;
    timestamp: number;
    duration_ms: number;
  }>;
  transformations: string[];
  total_attempts: number;
  auto_fixes_applied: string[];
  patterns_detected: string[];
  final_sanitization_level: SanitizationLevel;
  recommendation: string;
}

export interface SmartFindParams {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  top_k?: number;
  mode?: 'auto' | 'fast' | 'deep';
  enable_auto_fix?: boolean;
  return_corrections?: boolean;
  max_attempts?: number;
  timeout_per_attempt_ms?: number;
}

export interface SmartFindResult {
  hits: FindHit[];
  suggestions: string[];
  autonomous_metadata: AutonomousMetadata;
  corrections?: CorrectionMetadata;
  debug?: Record<string, unknown>;
  graph?: any;
}

/**
 * Main smart memory find function
 */
export async function smartMemoryFind(params: SmartFindParams): Promise<SmartFindResult> {
  const startTime = Date.now();

  // Configuration with defaults
  const {
    query,
    scope,
    types,
    top_k = 10,
    mode = 'auto',
    enable_auto_fix = true,
    return_corrections = true,
    max_attempts = 3,
    timeout_per_attempt_ms = 5000,
  } = params;

  // Prepare correction metadata
  const correctionMetadata: CorrectionMetadata = {
    original_query: query,
    final_query: query,
    attempts: [],
    transformations: [],
    total_attempts: 0,
    auto_fixes_applied: [],
    patterns_detected: [],
    final_sanitization_level: 'basic',
    recommendation: '',
  };

  // Phase 1: Initial assessment
  const patternsDetected = detectProblematicPatterns(query);
  correctionMetadata.patterns_detected = patternsDetected;

  if (patternsDetected.length > 0) {
    correctionMetadata.transformations.push('pattern_detection');
    logger.info(
      {
        query,
        patterns: patternsDetected,
        enable_auto_fix,
      },
      'Query contains potentially problematic patterns'
    );
  }

  // If auto-fix disabled, return original query
  if (!enable_auto_fix) {
    logger.warn({ query }, 'Auto-fix disabled for query');
    const result = await memoryFind({
      query,
      scope,
      types,
      top_k,
      mode,
    });

    correctionMetadata.recommendation = 'Auto-fix disabled. Query executed as-is.';
    correctionMetadata.final_query = query;

    return {
      ...result,
      corrections: return_corrections ? correctionMetadata : undefined,
      debug: {
        ...result.debug,
        auto_fix_enabled: false,
        patterns_detected: patternsDetected.length,
        total_attempts: 1,
      },
    };
  }

  // Phase 2: Progressive retry strategy
  let finalResult: Awaited<ReturnType<typeof memoryFind>> | undefined;
  let currentQuery = query;
  let currentMode = mode;
  let attempts = 0;

  while (attempts < max_attempts) {
    attempts++;
    const attemptStartTime = Date.now();

    try {
      const result = await Promise.race([
        memoryFind({
          query: currentQuery,
          scope,
          types,
          top_k,
          mode: currentMode,
        }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), timeout_per_attempt_ms)
        ),
      ]);

      // Success! Record this attempt
      const attemptDuration = Date.now() - attemptStartTime;

      correctionMetadata.attempts.push({
        attempt_number: attempts,
        query: currentQuery,
        mode: currentMode,
        success: true,
        timestamp: attemptStartTime,
        duration_ms: attemptDuration,
      });

      finalResult = result;
      correctionMetadata.final_query = currentQuery;
      break;
    } catch (error: unknown) {
      const attemptDuration = Date.now() - attemptStartTime;

      // Record failed attempt
      correctionMetadata.attempts.push({
        attempt_number: attempts,
        query: currentQuery,
        mode: currentMode,
        error: error instanceof Error ? error.message : String(error),
        success: false,
        timestamp: attemptStartTime,
        duration_ms: attemptDuration,
      });

      logger.warn(
        {
          attempt: attempts,
          query: currentQuery,
          error: error instanceof Error ? error.message : String(error),
          max_attempts,
        },
        'Query attempt failed'
      );

      // If this was the last attempt, we have to work with what we have
      if (attempts >= max_attempts) {
        logger.error(
          {
            original_query: query,
            final_query: currentQuery,
            error: error instanceof Error ? error.message : String(error),
            total_attempts: attempts,
          },
          'All attempts exhausted'
        );

        // Try one more time with most aggressive sanitization
        if (attempts === max_attempts && currentQuery !== query) {
          try {
            const finalSanitizeResult = sanitizeQuery(query, 'aggressive');
            currentQuery = finalSanitizeResult.cleaned;
            logger.info(
              {
                from: query,
                to: currentQuery,
                patterns: finalSanitizeResult.patterns_detected,
              },
              'Applying final aggressive sanitization'
            );

            correctionMetadata.auto_fixes_applied.push(...finalSanitizeResult.auto_fixes_applied);
            correctionMetadata.final_query = currentQuery;
            correctionMetadata.final_sanitization_level = 'aggressive';

            // Try one final time
            const finalResult = await memoryFind({
              query: currentQuery,
              scope,
              types,
              top_k,
              mode: 'deep',
            });

            finalResult.autonomous_metadata.recommendation =
              'Query retrieved using aggressive sanitization. Consider using simpler terms for better results.';

            finalResult.debug = {
              ...finalResult.debug,
              total_attempts: attempts + 1,
              final_sanitization_level: 'aggressive',
            };

            return {
              ...finalResult,
              corrections: return_corrections ? correctionMetadata : undefined,
            };
          } catch (finalError) {
            // If final attempt fails, return empty result with error info
            return createErrorResult(query, finalError, correctionMetadata, return_corrections);
          }
        }

        return createErrorResult(query, error, correctionMetadata, return_corrections);
      }

      // Sanitize for next attempt
      const sanitizationLevel = determineNextSanitizationLevel(
        currentQuery,
        error as Error,
        attempts
      );

      const sanitizeResult = sanitizeQuery(currentQuery, sanitizationLevel);
      currentQuery = sanitizeResult.cleaned;
      currentMode = sanitizationLevel === 'aggressive' ? 'deep' : 'auto';

      correctionMetadata.auto_fixes_applied.push(...sanitizeResult.auto_fixes_applied);
      correctionMetadata.transformations.push(`sanitization_${sanitizationLevel}`);
      correctionMetadata.final_sanitization_level = sanitizationLevel;

      logger.info(
        {
          from: correctionMetadata.original_query,
          to: currentQuery,
          level: sanitizationLevel,
          error: error instanceof Error ? error.message : String(error),
        },
        'Applying sanitization for next attempt'
      );
    }
  }

  // Process final result
  const totalTime = Date.now() - startTime;

  // If no result after all attempts, return error result
  if (!finalResult) {
    return createErrorResult(
      query,
      new Error('All retry attempts failed'),
      correctionMetadata,
      return_corrections
    );
  }

  finalResult.debug = {
    ...finalResult.debug,
    total_attempts: attempts,
    total_time_ms: totalTime,
    auto_fix_enabled: enable_auto_fix,
    corrections_applied: correctionMetadata.auto_fixes_applied.length,
    final_sanitization_level: correctionMetadata.final_sanitization_level,
  };

  // Generate recommendation
  finalResult.autonomous_metadata.recommendation = generateRecommendation(
    correctionMetadata,
    finalResult.autonomous_metadata.confidence
  );

  return {
    ...finalResult,
    corrections: return_corrections ? correctionMetadata : undefined,
    debug: finalResult.debug,
  };
}

/**
 * Pattern detection wrapper
 */
function detectProblematicPatterns(query: string): string[] {
  const patterns = [];

  if (/\bT\d+-\d+\b/.test(query)) {
    patterns.push('task_id_range');
  }

  if (/[^\w\s.,:;!?-]/.test(query)) {
    patterns.push('special_chars');
  }

  if (/[-]/.test(query) && query.split('-').length > 2) {
    patterns.push('multiple_hyphens');
  }

  return patterns;
}

/**
 * Determine next sanitization level based on error type
 */
function determineNextSanitizationLevel(
  _query: string,
  error: Error,
  attemptNumber: number
): SanitizationLevel {
  const errorMessage = error.message.toLowerCase();

  // If tsquery syntax error detected
  if (errorMessage.includes('tsquery') || errorMessage.includes('syntax')) {
    switch (attemptNumber) {
      case 1:
        return 'moderate';
      case 2:
        return 'aggressive';
      default:
        return 'aggressive';
    }
  }

  // If timeout occurred, try with simpler query
  if (errorMessage.includes('timeout')) {
    return 'aggressive';
  }

  // Default escalation
  switch (attemptNumber) {
    case 1:
      return 'basic';
    case 2:
      return 'moderate';
    default:
      return 'aggressive';
  }
}

/**
 * Create error result when all attempts fail
 */
function createErrorResult(
  query: string,
  error: unknown,
  correctionMetadata: CorrectionMetadata,
  return_corrections: boolean
): SmartFindResult {
  return {
    hits: [],
    suggestions: ['Try simpler terms', 'Remove special characters', 'Check spelling'],
    autonomous_metadata: {
      strategy_used: 'fast',
      mode_requested: query,
      mode_executed: 'auto',
      confidence: 'low',
      total_results: 0,
      avg_score: 0,
      fallback_attempted: true,
      recommendation:
        'Query failed due to syntax errors. Try removing special characters and hyphens.',
      user_message_suggestion: 'Query failed. Try simpler terms without special characters.',
    },
    corrections: return_corrections
      ? {
          ...correctionMetadata,
          recommendation:
            'All attempts failed. Query contains characters that cannot be processed automatically.',
        }
      : undefined,
    debug: {
      error: error instanceof Error ? error.message : String(error),
      total_attempts: correctionMetadata.attempts.length,
      auto_fix_enabled: true,
    },
  };
}

/**
 * Generate recommendation based on correction attempts
 */
function generateRecommendation(
  correctionMetadata: CorrectionMetadata,
  confidence: string
): string {
  const { attempts, auto_fixes_applied, final_sanitization_level } = correctionMetadata;

  if (attempts.length === 0) {
    return 'Query processed successfully.';
  }

  if (attempts.every((a) => !a.success)) {
    return `Query failed after ${attempts.length} attempts. Manual intervention required.`;
  }

  if (auto_fixes_applied.length > 0) {
    let message = `Query auto-corrected successfully with ${auto_fixes_applied.length} fixes.`;

    if (final_sanitization_level === 'aggressive') {
      message += ' Consider using simpler terms for better results.';
    }

    return message;
  }

  if (confidence === 'low') {
    return 'Results found but confidence is low. Consider refining the query.';
  }

  return 'Query processed successfully.';
}
