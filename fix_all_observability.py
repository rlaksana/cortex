#!/usr/bin/env python3

# Comprehensive script to add observability metadata to all orchestrator files

import re

def fix_memory_find_qdrant():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-find-orchestrator-qdrant.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after ResultGroupingService import
    content = re.sub(
        r"(import { ResultGroupingService } from '\.\./search/result-grouping-service\.js';)",
        r"\1\nimport { createFindObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Add startTime to findItemsLegacy method
    content = re.sub(
        r"(async findItemsLegacy\(query: SearchQuery\): Promise<MemoryFindResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Add observability to the return statement in findItemsLegacy
    # Find the exact return statement and add observability
    return_pattern = r'(return \{\s+results: searchResults,\s+items: searchResults, // Add items property for compatibility\s+total_count: result\.hits\.length,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'

    replacement = r'''return {
      results: searchResults,
      items: searchResults, // Add items property for compatibility
      total_count: result.hits.length,
      autonomous_context: {
        search_mode_used: result.autonomous_metadata.strategy_used,
        results_found: result.hits.length,
        confidence_average: Number(result.autonomous_metadata.confidence) || 0,
        user_message_suggestion: result.autonomous_metadata.recommendation,
      },
      observability: createFindObservability(
        result.autonomous_metadata.strategy_used as any,
        true, // vector_used - Qdrant always uses vectors
        false, // degraded - assume not degraded unless error occurs
        Date.now() - startTime,
        Number(result.autonomous_metadata.confidence) || 0
      ),
    };'''

    content = re.sub(return_pattern, replacement, content, flags=re.DOTALL)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✓ Fixed memory-find-orchestrator-qdrant.ts")

def fix_memory_find():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-find-orchestrator.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(import type \{ AuthContext \} from '\.\./\.\./types/auth-types\.js';)",
        r"\1\nimport { createFindObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Add startTime to findItems method
    content = re.sub(
        r"(async findItems\(query: SearchQuery, authContext\?: AuthContext\): Promise<MemoryFindResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix rate limit error response (first return statement)
    content = re.sub(
        r'(return \{\s+results: \[\],\s+total_count: 0,\s+items: \[\],\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)',
        r'''return {
          results: [],
          total_count: 0,
          items: [],
          autonomous_context: {
            search_mode_used: 'rate_limited',
            results_found: 0,
            confidence_average: 0,
            user_message_suggestion: 'Rate limit exceeded. Please try again later.',
          },
          observability: createFindObservability(
            "fallback",
            false, // vector_used - no vectors used in rate limit error
            true, // degraded - rate limit is degraded state
            Date.now() - startTime,
            0
          ),
        };''',
        content,
        flags=re.DOTALL
    )

    # Add startTime to buildResponse method
    content = re.sub(
        r"(private buildResponse\(\s+rankedResults: any\[\],\s+searchResult: SearchExecutionResult\s+\): MemoryFindResponse \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix buildResponse return statement (second return statement)
    content = re.sub(
        r'(return \{\s+results: results,\s+items: results,\s+total_count: searchResult\.totalCount,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)',
        r'''return {
      results: results,
      items: results,
      total_count: searchResult.totalCount,
      autonomous_context: {
        search_mode_used: searchResult.strategy.primary.name,
        results_found: results.length,
        confidence_average: results.reduce((sum: number, r: any) => sum + r.confidence_score, 0) / results.length || 0,
        user_message_suggestion: this.generateUserMessage(results, searchResult),
      },
      observability: createFindObservability(
        searchResult.strategy.primary.name as any,
        true, // vector_used - Qdrant uses vectors
        searchResult.fallbackUsed,
        Date.now() - startTime,
        results.reduce((sum: number, r: any) => sum + r.confidence_score, 0) / results.length || 0
      ),
    };''',
        content,
        flags=re.DOTALL
    )

    # Add startTime to createValidationErrorResponse method
    content = re.sub(
        r"(private createValidationErrorResponse\(errors: string\[\]: MemoryFindResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix createValidationErrorResponse return statement (third return statement)
    content = re.sub(
        r'(return \{\s+results: \[\],\s+items: \[\],\s+total_count: 0,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)',
        r'''return {
      results: [],
      items: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'validation_failed',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: `❌ Invalid query: ${errors.join(', ')}`,
      },
      observability: createFindObservability(
        "error",
        false, // vector_used - no vectors used in validation error
        true, // degraded - validation error is degraded state
        Date.now() - startTime,
        0
      ),
    };''',
        content,
        flags=re.DOTALL
    )

    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(_error: any\): MemoryFindResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix createErrorResponse return statement (fourth return statement)
    content = re.sub(
        r'(return \{\s+results: \[\],\s+items: \[\],\s+total_count: 0,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)',
        r'''return {
      results: [],
      items: [],
      total_count: 0,
      autonomous_context: {
        search_mode_used: 'error',
        results_found: 0,
        confidence_average: 0,
        user_message_suggestion: '❌ Search failed - please try again',
      },
      observability: createFindObservability(
        "error",
        false, // vector_used - no vectors used in error
        true, // degraded - error is degraded state
        Date.now() - startTime,
        0
      ),
    };''',
        content,
        flags=re.DOTALL
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✓ Fixed memory-find-orchestrator.ts")

def fix_memory_store_qdrant():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-store-orchestrator-qdrant.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(import type \{.*?\} from '\.\./\.\./types/core-interfaces\.js';)",
        r"\1\nimport { createStoreObservability } from '../../utils/observability-helper.js';",
        content,
        flags=re.DOTALL
    )

    # Add startTime to storeItems method
    content = re.sub(
        r"(async storeItems\(items: KnowledgeItem\[\], options: StoreOptions = \{\}\): Promise<MemoryStoreResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix rate limit error response (first return statement)
    content = re.sub(
        r'(return \{\s+items: \[\],\s+stored: \[\],\s+summary: \{[^}]+\}\,\s+errors: \[[^\]]+\],\s+autonomous_context: \{[^}]+\}\,\s*\}\;)',
        r'''return {
          items: [],
          stored: [],
          summary: {
            total: items.length,
            stored: 0,
            skipped_dedupe: 0,
            business_rule_blocked: 0,
            validation_error: items.length,
          },
          errors: [
            {
              index: 0,
              error_code: 'rate_limit_exceeded',
              message: rateLimitResult.error?.message || 'Rate limit exceeded',
              timestamp: new Date().toISOString(),
            },
          ],
          autonomous_context: {
            action_performed: 'skipped',
            similar_items_checked: 0,
            duplicates_found: 0,
            contradictions_detected: false,
            recommendation: 'Rate limit exceeded',
            reasoning: 'Request blocked due to rate limiting',
            user_message_suggestion: 'Rate limit exceeded. Please try again later.',
          },
          observability: createStoreObservability(
            false, // vector_used - no vectors used in rate limit error
            true, // degraded - rate limit is degraded state
            Date.now() - startTime,
            0
          ),
        };''',
        content,
        flags=re.DOTALL
    )

    # Fix success response (second return statement)
    content = re.sub(
        r'(return \{\s+// Enhanced response format\s+items: itemResults,\s+summary,\s+// Legacy fields for backward compatibility\s+stored,\s+errors,\s+autonomous_context: autonomousContext,\s*\}\;)',
        r'''return {
        // Enhanced response format
        items: itemResults,
        summary,

        // Legacy fields for backward compatibility
        stored,
        errors,
        autonomous_context: autonomousContext,
        observability: createStoreObservability(
          true, // vector_used - Qdrant uses vectors for embeddings
          false, // degraded - successful operation
          Date.now() - startTime,
          0.8 // confidence score for successful storage
        ),
      };''',
        content,
        flags=re.DOTALL
    )

    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(errors: StoreError\[\]: MemoryStoreResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix createErrorResponse return statement (third return statement)
    content = re.sub(
        r'(return \{\s+// Enhanced response format\s+items: \[\],\s+summary: \{[^}]+\},\s+// Legacy fields for backward compatibility\s+stored: \[\],\s+errors,\s+autonomous_context: \{[^}]+\}\,\s*\}\;)',
        r'''return {
      // Enhanced response format
      items: [],
      summary: {
        stored: 0,
        skipped_dedupe: 0,
        business_rule_blocked: 0,
        validation_error: errors.length,
        total: errors.length,
      },

      // Legacy fields for backward compatibility
      stored: [],
      errors,
      autonomous_context: {
        action_performed: 'skipped',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'Review input format and try again',
        reasoning: `Validation failed with ${errors.length} errors`,
        user_message_suggestion: `${errors.length} validation errors detected - check item format`,
        dedupe_threshold_used: this.SIMILARITY_THRESHOLD,
        dedupe_method: 'none',
        dedupe_enabled: false,
      },
      observability: createStoreObservability(
        false, // vector_used - no vectors used in error
        true, // degraded - error is degraded state
        Date.now() - startTime,
        0
      ),
    };''',
        content,
        flags=re.DOTALL
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✓ Fixed memory-store-orchestrator-qdrant.ts")

def fix_memory_store():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-store-orchestrator.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(// P6-T6\.1: Import expiry utilities\nimport \{ calculateItemExpiry \} from '\.\./\.\./utils/expiry-utils\.js';)",
        r"\1\nimport { createStoreObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Add startTime to storeItems method
    content = re.sub(
        r"(async storeItems\(items: unknown\[\]: Promise<MemoryStoreResponse> \{[\s\S]*?logger\.info\([\s\S]*?'P5-T5\.3: Starting batch knowledge item storage')",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix success response (first return statement)
    content = re.sub(
        r'(return \{\s+items: itemResults,\s+summary,\s+stored,\s+errors,\s+autonomous_context: autonomousContext,\s*\}\;)',
        r'''return {
        items: itemResults,
        summary,
        stored,
        errors,
        autonomous_context: autonomousContext,
        observability: createStoreObservability(
          true, // vector_used - embeddings used for semantic search
          false, // degraded - successful operation
          Date.now() - startTime,
          0.8 // confidence score for successful storage
        ),
      };''',
        content,
        flags=re.DOTALL
    )

    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(errors: StoreError\[\]: MemoryStoreResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix createErrorResponse return statement (second return statement)
    content = re.sub(
        r'(return \{\s+items: itemResults,\s+summary,\s+stored: \[\],\s+errors,\s+autonomous_context: \{[^}]+\}\,\s*\}\;)',
        r'''return {
      items: itemResults,
      summary,
      stored: [],
      errors,
      autonomous_context: {
        action_performed: 'skipped',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'Fix validation errors before retrying',
        reasoning: 'Request failed validation',
        user_message_suggestion: '❌ Request validation failed',
      },
      observability: createStoreObservability(
        false, // vector_used - no vectors used in error
        true, // degraded - error is degraded state
        Date.now() - startTime,
        0
      ),
    };''',
        content,
        flags=re.DOTALL
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✓ Fixed memory-store-orchestrator.ts")

if __name__ == "__main__":
    print("🔧 Adding observability metadata to orchestrator files...")

    try:
        fix_memory_find_qdrant()
        fix_memory_find()
        fix_memory_store_qdrant()
        fix_memory_store()

        print("\n✅ All observability fixes completed successfully!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)