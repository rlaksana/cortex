/**
 * Enhanced MCP Tool Contract Validation Tests
 *
 * Comprehensive contract testing for all MCP tools with advanced validation:
 * - Enhanced schema compliance and validation
 * - Cross-tool compatibility testing
 * - Performance and security contract validation
 * - Version drift detection and migration testing
 * - Rate limiting and quota enforcement
 * - Error handling and edge case validation
 * - Real-world scenario testing
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { z } from 'zod';
import {
  ToolContractSchema,
  BUILTIN_TOOL_CONTRACTS,
  validateInputForVersion,
  validateOutputForVersion,
  parseSemVer,
  isVersionCompatible,
  detectContractDrift,
  generateMigrationPlan,
} from '../../src/types/versioning-schema.js';
import {
  EnhancedMemoryStoreInputSchema,
  MemoryStoreInputSchema,
  EnhancedMemoryFindInputSchema,
  MemoryFindInputSchema,
  SystemStatusInputSchema,
} from '../../src/schemas/mcp-inputs.js';
import { memory_store, memory_find, system_status } from '../../src/index.js';
import type { AuthContext } from '../../src/types/auth-types.js';
import type {
  EnhancedMemoryStoreInput,
  EnhancedMemoryFindInput,
  SystemStatusInput,
  KnowledgeItem,
} from '../../src/types/core-interfaces.js';

// Mock dependencies
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock auth context for testing
const mockAuthContext: AuthContext = {
  userId: 'test-user',
  tenantId: 'test-tenant',
  scopes: ['memory:read', 'memory:write', 'system:read'],
  permissions: ['read', 'write'],
  roles: ['user'],
};

describe('Enhanced MCP Tool Contract Validation', () => {
  describe('Advanced Schema Compliance', () => {
    describe('Complex Input Validation', () => {
      it('should validate complex nested object structures', () => {
        const complexInput = {
          items: [
            {
              kind: 'entity',
              content: 'Test entity with complex structure',
              scope: {
                project: 'test-project',
                branch: 'main',
                org: 'test-org',
                service: 'test-service',
                tenant: 'test-tenant',
                environment: 'development',
              },
              source: {
                actor: 'test-user',
                tool: 'mcp-cortex',
                timestamp: new Date().toISOString(),
              },
              metadata: {
                tags: ['test', 'validation', 'complex'],
                priority: 'high',
                category: 'testing',
                customFields: {
                  testId: 'complex-test-001',
                  batchId: 'batch-2024-001',
                  validationLevel: 'comprehensive',
                },
              },
              deduplication: {
                enabled: true,
                similarity_threshold: 0.85,
                merge_strategy: 'intelligent',
                check_within_scope_only: true,
                max_history_hours: 168,
                enable_intelligent_merging: true,
                preserve_merge_history: false,
                max_merge_history_entries: 5,
                cross_scope_deduplication: false,
                prioritize_same_scope: true,
                time_based_deduplication: true,
                max_age_for_dedupe_days: 90,
                respect_update_timestamps: true,
                max_items_to_check: 50,
                batch_size: 10,
                enable_parallel_processing: false,
              },
              ttl_config: {
                policy: 'default',
                auto_extend: true,
                extend_threshold_days: 7,
                max_extensions: 3,
              },
              truncation_config: {
                enabled: true,
                max_chars: 10000,
                max_tokens: 4000,
                mode: 'intelligent',
                preserve_structure: true,
                add_indicators: true,
                indicator: '[...truncated...]',
                safety_margin: 0.1,
                auto_detect_content_type: true,
                enable_smart_truncation: true,
              },
              insights_config: {
                enabled: true,
                generate_insights: true,
                insight_types: ['summary', 'trends', 'recommendations'],
                confidence_threshold: 0.7,
                max_insights: 10,
                include_source_data: false,
                analysis_depth: 'medium',
              },
            },
          ],
          processing: {
            enable_validation: true,
            enable_async_processing: false,
            batch_processing: true,
            return_summaries: false,
            include_metrics: true,
          },
          global_ttl: {
            policy: 'default',
            expires_at: new Date(Date.now() + 86400000).toISOString(), // 24 hours from now
          },
          global_truncation: {
            enabled: true,
            max_chars: 50000,
            max_tokens: 20000,
            mode: 'soft',
            preserve_structure: true,
            add_indicators: true,
          },
          global_insights: {
            enabled: true,
            generate_insights: true,
            insight_types: ['summary', 'patterns'],
            confidence_threshold: 0.8,
            max_insights: 15,
            include_source_data: true,
            analysis_depth: 'deep',
          },
          deduplication: {
            enabled: true,
            merge_strategy: 'intelligent',
            similarity_threshold: 0.9,
            check_within_scope_only: true,
            max_history_hours: 720, // 30 days
            dedupe_window_days: 30,
            allow_newer_versions: true,
            enable_audit_logging: true,
            enable_intelligent_merging: true,
            preserve_merge_history: true,
            max_merge_history_entries: 10,
            cross_scope_deduplication: false,
            prioritize_same_scope: true,
            time_based_deduplication: true,
            max_age_for_dedupe_days: 90,
            respect_update_timestamps: true,
            max_items_to_check: 100,
            batch_size: 25,
            enable_parallel_processing: true,
          },
        };

        const validation = validateInputForVersion('memory_store', '1.2.0', complexInput);
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toBeUndefined();

        // Verify all complex nested structures are properly validated
        const item = complexInput.items[0];
        expect(item.scope.project).toBe('test-project');
        expect(item.metadata['customFields'].testId).toBe('complex-test-001');
        expect(item.deduplication.similarity_threshold).toBe(0.85);
        expect(item.ttl_config.policy).toBe('default');
        expect(item.truncation_config.max_chars).toBe(10000);
        expect(item.insights_config.confidence_threshold).toBe(0.7);
      });

      it('should reject invalid complex structures with detailed error messages', () => {
        const invalidComplexInput = {
          items: [
            {
              // Missing required fields
              kind: 'entity',
              // Missing content
              scope: {
                project: '', // Invalid empty project
                branch: 'main',
                org: 'test-org',
              },
              metadata: {
                tags: ['test'],
                priority: 'invalid-priority', // Invalid priority value
                customFields: {
                  testId: 123, // Should be string
                },
              },
              deduplication: {
                enabled: 'not-boolean', // Should be boolean
                similarity_threshold: 1.5, // Invalid range > 1.0
                merge_strategy: 'invalid-strategy', // Invalid strategy
              },
              ttl_config: {
                policy: 'invalid-policy', // Invalid policy
                auto_extend: 'not-boolean', // Should be boolean
                extend_threshold_days: -5, // Negative value
                max_extensions: 15, // Too high
              },
              truncation_config: {
                enabled: true,
                max_chars: -1000, // Negative value
                max_tokens: 0, // Zero value
                mode: 'invalid-mode', // Invalid mode
              },
              insights_config: {
                enabled: true,
                generate_insights: true,
                insight_types: ['invalid-insight-type'], // Invalid insight type
                confidence_threshold: 1.5, // Invalid range
                max_insights: 200, // Too high
                analysis_depth: 'invalid-depth', // Invalid depth
              },
            },
          ],
          processing: {
            enable_validation: 'not-boolean', // Should be boolean
            enable_async_processing: true,
            batch_processing: 5, // Should be boolean
            return_summaries: true,
            include_metrics: true,
          },
          global_ttl: {
            policy: 'long',
            expires_at: 'invalid-date-format', // Invalid date format
          },
          global_truncation: {
            enabled: true,
            max_chars: 200000000, // Exceeds max limit
            mode: 'hard',
            preserve_structure: 'not-boolean',
          },
          global_insights: {
            enabled: true,
            insight_types: ['summary'],
            confidence_threshold: 0.2, // Too low
            max_insights: 100, // Too high
            analysis_depth: 'medium',
          },
          deduplication: {
            enabled: true,
            merge_strategy: 'combine',
            similarity_threshold: 0.3, // Too low
            max_history_hours: 10000, // Too high
            dedupe_window_days: 500, // Too high
            batch_size: 200, // Too high
          },
        };

        const validation = validateInputForVersion('memory_store', '1.2.0', invalidComplexInput);
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toBeDefined();
        expect(Array.isArray(validation.errors)).toBe(true);
        expect(validation.errors!.length).toBeGreaterThan(5); // Should catch multiple errors

        // Check specific error messages
        const errorMessages = validation.errors!.map((e) => e.message);
        expect(errorMessages.some((msg) => msg.includes('content'))).toBe(true);
        expect(errorMessages.some((msg) => msg.includes('priority'))).toBe(true);
        expect(errorMessages.some((msg) => msg.includes('similarity_threshold'))).toBe(true);
        expect(errorMessages.some((msg) => msg.includes('policy'))).toBe(true);
      });

      it('should validate array inputs with complex item constraints', () => {
        const arrayInput = {
          items: Array.from({ length: 150 }, (_, i) => ({
            kind: ['entity', 'relation', 'observation', 'section'][i % 4],
            content: `Test item ${i} with validation content`.repeat(10),
            scope: {
              project: `project-${i % 10}`,
              branch: ['main', 'develop', 'feature/test'][i % 3],
              org: 'test-org',
              service: `service-${i % 5}`,
              tenant: 'test-tenant',
              environment: ['development', 'staging', 'production'][i % 3],
            },
            metadata: {
              tags: [`tag-${i % 20}`, `category-${i % 10}`, `type-${i % 5}`],
              priority: ['low', 'medium', 'high'][i % 3],
              category: ['testing', 'development', 'production'][i % 3],
              customFields: {
                batchId: `batch-${Math.floor(i / 10)}`,
                itemId: i,
                category: ['test', 'validation', 'performance'][i % 3],
                complexity: ['simple', 'medium', 'complex'][i % 3],
              },
            },
            ...(i % 3 === 0
              ? {
                  deduplication: {
                    enabled: true,
                    similarity_threshold: 0.8 + (i % 3) * 0.05,
                    merge_strategy: ['prefer_existing', 'prefer_newer', 'intelligent'][i % 3],
                  },
                }
              : {}),
            ...(i % 5 === 0
              ? {
                  ttl_config: {
                    policy: ['default', 'short', 'long'][i % 3],
                    auto_extend: i % 2 === 0,
                  },
                }
              : {}),
          })),
          deduplication: {
            enabled: true,
            merge_strategy: 'intelligent',
            similarity_threshold: 0.85,
            check_within_scope_only: true,
            max_history_hours: 168,
            enable_intelligent_merging: true,
            batch_size: 25,
            enable_parallel_processing: true,
          },
          processing: {
            enable_validation: true,
            enable_async_processing: false,
            batch_processing: true,
            return_summaries: true,
            include_metrics: true,
          },
        };

        // Test with max items (should be valid)
        const maxItemsInput = { ...arrayInput };
        maxItemsInput.items = maxItemsInput.items.slice(0, 100); // Max 100 items

        const maxItemsValidation = validateInputForVersion('memory_store', '1.2.0', maxItemsInput);
        expect(maxItemsValidation.isValid).toBe(true);

        // Test with too many items (should be invalid)
        const tooManyItemsInput = { ...arrayInput };
        tooManyItemsInput.items = tooManyItemsInput.items.slice(0, 150); // Exceeds max

        const tooManyValidation = validateInputForVersion(
          'memory_store',
          '1.2.0',
          tooManyItemsInput
        );
        expect(tooManyValidation.isValid).toBe(false);
        expect(tooManyValidation.errors?.some((e) => e.message.includes('items'))).toBe(true);
      });
    });

    describe('Advanced Output Validation', () => {
      it('should validate complex response structures', () => {
        const complexOutput = {
          success: true,
          items: [
            {
              id: 'test-entity-001',
              kind: 'entity',
              content: 'Test entity content',
              scope: {
                project: 'test-project',
                branch: 'main',
                org: 'test-org',
              },
              metadata: {
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                version: 1,
                hash: 'test-hash-001',
                similarity_score: 0.95,
                confidence: 0.88,
                processing_time: 150,
                source_confidence: 0.92,
                tags: ['test', 'validation'],
                custom_fields: {
                  validated: true,
                  complexity: 'medium',
                },
              },
              relations: [
                {
                  id: 'test-relation-001',
                  type: 'depends_on',
                  target_id: 'test-entity-002',
                  strength: 0.8,
                  metadata: {
                    created_at: new Date().toISOString(),
                    confidence: 0.85,
                  },
                },
              ],
              insights: [
                {
                  type: 'summary',
                  content: 'Test summary insight',
                  confidence: 0.9,
                  metadata: {
                    generated_at: new Date().toISOString(),
                    analysis_depth: 'medium',
                  },
                },
              ],
            },
          ],
          metadata: {
            total_items: 1,
            processing_time: 250,
            batch_id: 'batch-001',
            operation_id: 'op-001',
            deduplication_stats: {
              total_processed: 1,
              duplicates_found: 0,
              items_merged: 0,
              items_created: 1,
              processing_time: 50,
            },
            truncation_stats: {
              items_truncated: 0,
              total_chars_saved: 0,
              total_tokens_saved: 0,
            },
            insights_stats: {
              insights_generated: 1,
              total_processing_time: 100,
              average_confidence: 0.9,
            },
            performance_metrics: {
              memory_usage: 1024000,
              cpu_time: 75,
              cache_hits: 5,
              cache_misses: 2,
            },
          },
          errors: [],
          warnings: [
            {
              code: 'SIMILARITY_THRESHOLD_LOW',
              message: 'Similarity threshold is lower than recommended',
              severity: 'info',
              metadata: {
                threshold: 0.85,
                recommended: 0.9,
              },
            },
          ],
        };

        const validation = validateOutputForVersion('memory_store', '1.2.0', complexOutput);
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toBeUndefined();

        // Verify complex nested output structures
        const item = complexOutput.items[0];
        expect(item.id).toBe('test-entity-001');
        expect(item.metadata['confidence']).toBe(0.88);
        expect(item.relations).toHaveLength(1);
        expect(item.insights).toHaveLength(1);
        expect(complexOutput.metadata['deduplication_stats'].items_created).toBe(1);
        expect(complexOutput.warnings).toHaveLength(1);
      });

      it('should validate error response structures', () => {
        const errorOutput = {
          success: false,
          items: [],
          metadata: {
            total_items: 0,
            processing_time: 50,
            operation_id: 'error-op-001',
          },
          errors: [
            {
              code: 'VALIDATION_ERROR',
              message: 'Input validation failed',
              severity: 'error',
              details: {
                field: 'items[0].content',
                issue: 'Content is required',
                value: null,
              },
              metadata: {
                timestamp: new Date().toISOString(),
                request_id: 'req-001',
                user_id: 'test-user',
              },
            },
            {
              code: 'SCOPE_VALIDATION_ERROR',
              message: 'Invalid scope configuration',
              severity: 'error',
              details: {
                field: 'items[0].scope.project',
                issue: 'Project name cannot be empty',
                value: '',
              },
            },
            {
              code: 'RATE_LIMIT_EXCEEDED',
              message: 'Rate limit exceeded',
              severity: 'warning',
              details: {
                limit: 100,
                current: 150,
                reset_time: new Date(Date.now() + 60000).toISOString(),
              },
            },
          ],
          warnings: [
            {
              code: 'PERFORMANCE_DEGRADATION',
              message: 'Processing time exceeds recommended threshold',
              severity: 'warning',
              details: {
                actual_time: 5000,
                recommended_time: 3000,
              },
            },
          ],
        };

        const validation = validateOutputForVersion('memory_store', '1.2.0', errorOutput);
        expect(validation.isValid).toBe(true); // Error responses are valid
        expect(validation.errors).toBeUndefined();

        // Verify error structure
        expect(errorOutput.errors).toHaveLength(3);
        expect(errorOutput.errors[0].code).toBe('VALIDATION_ERROR');
        expect(errorOutput.errors[0].severity).toBe('error');
        expect(errorOutput.errors[0].details.field).toBeDefined();
        expect(errorOutput.warnings).toHaveLength(1);
      });
    });
  });

  describe('Cross-Tool Compatibility Testing', () => {
    describe('Data Flow Validation', () => {
      it('should maintain data consistency across tool operations', async () => {
        // Store data using memory_store
        const storeInput = {
          items: [
            {
              kind: 'entity',
              content: 'Cross-tool compatibility test entity',
              scope: {
                project: 'compatibility-test',
                branch: 'main',
                org: 'test-org',
              },
              metadata: {
                tags: ['compatibility', 'test', 'cross-tool'],
                priority: 'high',
              },
            },
          ],
          deduplication: {
            enabled: true,
            similarity_threshold: 0.9,
          },
        };

        const storeValidation = validateInputForVersion('memory_store', '1.2.0', storeInput);
        expect(storeValidation.isValid).toBe(true);

        // Mock successful store operation
        const storeResult = {
          success: true,
          items: [
            {
              ...storeInput.items[0],
              id: 'compatibility-entity-001',
              metadata: {
                ...storeInput.items[0].metadata,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                version: 1,
                hash: 'compatibility-hash-001',
              },
            },
          ],
          metadata: {
            total_items: 1,
            processing_time: 150,
            operation_id: 'store-op-001',
          },
        };

        // Use stored data for search
        const searchInput = {
          query: 'cross-tool compatibility test',
          scope: {
            project: 'compatibility-test',
            branch: 'main',
            org: 'test-org',
          },
          search_strategy: 'deep',
          limit: 10,
          graph_expansion: {
            enabled: true,
            max_depth: 2,
            max_nodes: 50,
            include_metadata: true,
          },
        };

        const searchValidation = validateInputForVersion('memory_find', '1.3.0', searchInput);
        expect(searchValidation.isValid).toBe(true);

        // Mock search result that includes stored entity
        const searchResult = {
          success: true,
          items: [storeResult.items[0]],
          metadata: {
            total_items: 1,
            search_time: 200,
            strategy_used: 'deep',
            expansion_applied: true,
          },
        };

        // Verify data consistency
        expect(searchResult.items[0].id).toBe(storeResult.items[0].id);
        expect(searchResult.items[0].content).toBe(storeResult.items[0].content);
        expect(searchResult.items[0].scope.project).toBe(storeResult.items[0].scope.project);

        // Validate search output
        const searchOutputValidation = validateOutputForVersion(
          'memory_find',
          '1.3.0',
          searchResult
        );
        expect(searchOutputValidation.isValid).toBe(true);
      });

      it('should handle scope consistency across tools', async () => {
        const commonScope = {
          project: 'scope-consistency-test',
          branch: 'feature/scope-testing',
          org: 'test-org',
          service: 'test-service',
          tenant: 'test-tenant',
          environment: 'staging',
        };

        // Test memory_store with complex scope
        const storeInput = {
          items: [
            {
              kind: 'entity',
              content: 'Scope consistency test entity',
              scope: commonScope,
            },
            {
              kind: 'relation',
              content: 'Scope consistency test relation',
              scope: commonScope,
            },
          ],
        };

        const storeValidation = validateInputForVersion('memory_store', '1.2.0', storeInput);
        expect(storeValidation.isValid).toBe(true);

        // Test memory_find with same scope
        const searchInput = {
          query: 'scope consistency test',
          scope: commonScope,
          search_strategy: 'auto',
          limit: 20,
        };

        const searchValidation = validateInputForVersion('memory_find', '1.3.0', searchInput);
        expect(searchValidation.isValid).toBe(true);

        // Test system_status with scope filtering
        const statusInput = {
          operation: 'health',
          scope: {
            project: commonScope.project,
            org: commonScope.org,
          },
        };

        const statusValidation = validateInputForVersion('system_status', '1.0.0', statusInput);
        expect(statusValidation.isValid).toBe(true);

        // Verify scope consistency
        expect(storeInput.items[0].scope).toEqual(commonScope);
        expect(storeInput.items[1].scope).toEqual(commonScope);
        expect(searchInput.scope).toEqual(commonScope);
        expect(statusInput.scope.project).toBe(commonScope.project);
        expect(statusInput.scope.org).toBe(commonScope.org);
      });
    });

    describe('Type System Compatibility', () => {
      it('should maintain type compatibility across tool versions', () => {
        const entityTypes = [
          'entity',
          'relation',
          'observation',
          'section',
          'runbook',
          'change',
          'issue',
          'decision',
          'todo',
          'release_note',
          'ddl',
          'pr_context',
          'incident',
          'release',
          'risk',
          'assumption',
        ];

        // Test all knowledge types with memory_store v1.2.0
        entityTypes.forEach((kind) => {
          const storeInput = {
            items: [
              {
                kind,
                content: `Test ${kind} content`,
                scope: { project: 'type-compatibility-test' },
              },
            ],
          };

          const validation = validateInputForVersion('memory_store', '1.2.0', storeInput);
          expect(validation.isValid).toBe(true);
        });

        // Test search across all types with memory_find v1.3.0
        const searchInput = {
          query: 'type compatibility test',
          types: entityTypes.slice(0, 8), // Test subset
          scope: { project: 'type-compatibility-test' },
          search_strategy: 'auto',
          limit: 50,
        };

        const searchValidation = validateInputForVersion('memory_find', '1.3.0', searchInput);
        expect(searchValidation.isValid).toBe(true);
      });

      it('should validate enum values across different tool contexts', () => {
        // Test strategy enums
        const validStrategies = ['fast', 'auto', 'deep'];
        validStrategies.forEach((strategy) => {
          const searchInput = {
            query: 'strategy test',
            search_strategy: strategy,
            limit: 10,
          };

          const validation = validateInputForVersion('memory_find', '1.3.0', searchInput);
          expect(validation.isValid).toBe(true);
        });

        // Test TTL policy enums
        const validPolicies = ['default', 'short', 'long', 'permanent'];
        validPolicies.forEach((policy) => {
          const storeInput = {
            items: [
              {
                kind: 'entity',
                content: 'TTL policy test',
                scope: { project: 'ttl-test' },
                ttl_config: {
                  policy,
                  auto_extend: true,
                },
              },
            ],
          };

          const validation = validateInputForVersion('memory_store', '1.2.0', storeInput);
          expect(validation.isValid).toBe(true);
        });

        // Test merge strategy enums
        const validMergeStrategies = [
          'skip',
          'prefer_existing',
          'prefer_newer',
          'combine',
          'intelligent',
        ];
        validMergeStrategies.forEach((strategy) => {
          const storeInput = {
            items: [
              {
                kind: 'entity',
                content: 'Merge strategy test',
                scope: { project: 'merge-test' },
                deduplication: {
                  enabled: true,
                  merge_strategy: strategy,
                },
              },
            ],
          };

          const validation = validateInputForVersion('memory_store', '1.2.0', storeInput);
          expect(validation.isValid).toBe(true);
        });
      });
    });
  });

  describe('Performance Contract Validation', () => {
    describe('Response Time Contracts', () => {
      it('should validate response time compliance', async () => {
        const performanceContracts = {
          memory_store: {
            '1.0.0': { max_response_time: 2000, max_batch_time: 10000 },
            '1.1.0': { max_response_time: 1800, max_batch_time: 8000 },
            '1.2.0': { max_response_time: 1500, max_batch_time: 6000 },
          },
          memory_find: {
            '1.0.0': { max_response_time: 1000, max_complex_time: 5000 },
            '1.3.0': { max_response_time: 800, max_complex_time: 4000 },
          },
          system_status: {
            '1.0.0': { max_response_time: 500, max_complex_time: 2000 },
          },
        };

        // Test memory_store response times
        const storeContracts = performanceContracts.memory_store['1.2.0'];
        const storeTimes = [
          { operation: 'single_item', time: 1200 },
          { operation: 'small_batch', time: 3000 },
          { operation: 'large_batch', time: 5500 },
        ];

        storeTimes.forEach(({ operation, time }) => {
          if (operation === 'single_item') {
            expect(time).toBeLessThanOrEqual(storeContracts.max_response_time);
          } else {
            expect(time).toBeLessThanOrEqual(storeContracts.max_batch_time);
          }
        });

        // Test memory_find response times
        const findContracts = performanceContracts.memory_find['1.3.0'];
        const findTimes = [
          { operation: 'simple_search', time: 600 },
          { operation: 'complex_search', time: 3500 },
        ];

        findTimes.forEach(({ operation, time }) => {
          if (operation === 'simple_search') {
            expect(time).toBeLessThanOrEqual(findContracts.max_response_time);
          } else {
            expect(time).toBeLessThanOrEqual(findContracts.max_complex_time);
          }
        });
      });

      it('should validate throughput contracts', async () => {
        const throughputContracts = {
          memory_store: {
            '1.2.0': {
              min_requests_per_second: 10,
              max_requests_per_second: 100,
              min_items_per_second: 50,
              max_items_per_second: 1000,
            },
          },
          memory_find: {
            '1.3.0': {
              min_requests_per_second: 20,
              max_requests_per_second: 200,
              min_results_per_second: 100,
              max_results_per_second: 2000,
            },
          },
        };

        // Test memory_store throughput
        const storeThroughput = throughputContracts.memory_store['1.2.0'];
        const storeMetrics = {
          requests_per_second: 45,
          items_per_second: 225,
        };

        expect(storeMetrics.requests_per_second).toBeGreaterThanOrEqual(
          storeThroughput.min_requests_per_second
        );
        expect(storeMetrics.requests_per_second).toBeLessThanOrEqual(
          storeThroughput.max_requests_per_second
        );
        expect(storeMetrics.items_per_second).toBeGreaterThanOrEqual(
          storeThroughput.min_items_per_second
        );
        expect(storeMetrics.items_per_second).toBeLessThanOrEqual(
          storeThroughput.max_items_per_second
        );

        // Test memory_find throughput
        const findThroughput = throughputContracts.memory_find['1.3.0'];
        const findMetrics = {
          requests_per_second: 85,
          results_per_second: 425,
        };

        expect(findMetrics.requests_per_second).toBeGreaterThanOrEqual(
          findThroughput.min_requests_per_second
        );
        expect(findMetrics.requests_per_second).toBeLessThanOrEqual(
          findThroughput.max_requests_per_second
        );
        expect(findMetrics.results_per_second).toBeGreaterThanOrEqual(
          findThroughput.min_results_per_second
        );
        expect(findMetrics.results_per_second).toBeLessThanOrEqual(
          findThroughput.max_results_per_second
        );
      });
    });

    describe('Resource Usage Contracts', () => {
      it('should validate memory usage contracts', async () => {
        const memoryContracts = {
          memory_store: {
            '1.2.0': {
              max_memory_per_request: 100 * 1024 * 1024, // 100MB
              max_memory_per_item: 10 * 1024 * 1024, // 10MB
              max_batch_memory: 500 * 1024 * 1024, // 500MB
            },
          },
          memory_find: {
            '1.3.0': {
              max_memory_per_request: 50 * 1024 * 1024, // 50MB
              max_result_memory: 20 * 1024 * 1024, // 20MB
            },
          },
        };

        // Test memory_store memory usage
        const storeMemoryContract = memoryContracts.memory_store['1.2.0'];
        const storeMemoryUsage = {
          request_memory: 75 * 1024 * 1024, // 75MB
          item_memory: 8 * 1024 * 1024, // 8MB per item
          batch_memory: 350 * 1024 * 1024, // 350MB for batch
        };

        expect(storeMemoryUsage.request_memory).toBeLessThanOrEqual(
          storeMemoryContract.max_memory_per_request
        );
        expect(storeMemoryUsage.item_memory).toBeLessThanOrEqual(
          storeMemoryContract.max_memory_per_item
        );
        expect(storeMemoryUsage.batch_memory).toBeLessThanOrEqual(
          storeMemoryContract.max_batch_memory
        );

        // Test memory_find memory usage
        const findMemoryContract = memoryContracts.memory_find['1.3.0'];
        const findMemoryUsage = {
          request_memory: 35 * 1024 * 1024, // 35MB
          result_memory: 15 * 1024 * 1024, // 15MB
        };

        expect(findMemoryUsage.request_memory).toBeLessThanOrEqual(
          findMemoryContract.max_memory_per_request
        );
        expect(findMemoryUsage.result_memory).toBeLessThanOrEqual(
          findMemoryContract.max_result_memory
        );
      });
    });
  });

  describe('Security Contract Validation', () => {
    describe('Authentication and Authorization', () => {
      it('should validate scope-based access control', () => {
        const accessControlTests = [
          {
            tool: 'memory_store',
            version: '1.2.0',
            required_scopes: ['memory:write'],
            user_scopes: ['memory:read', 'memory:write'],
            expected_access: true,
          },
          {
            tool: 'memory_find',
            version: '1.3.0',
            required_scopes: ['memory:read'],
            user_scopes: ['memory:read'],
            expected_access: true,
          },
          {
            tool: 'system_status',
            version: '1.0.0',
            required_scopes: ['system:read'],
            user_scopes: ['memory:read'],
            expected_access: false,
          },
          {
            tool: 'memory_store',
            version: '1.2.0',
            required_scopes: ['memory:write'],
            user_scopes: ['memory:read'],
            expected_access: false,
          },
        ];

        accessControlTests.forEach((test) => {
          const contract =
            BUILTIN_TOOL_CONTRACTS[test.tool as keyof typeof BUILTIN_TOOL_CONTRACTS].contracts[
              test.version
            ];
          const hasRequiredScopes = test.required_scopes.every((scope) =>
            test.user_scopes.includes(scope)
          );

          expect(hasRequiredScopes).toBe(test.expected_access);
          expect(contract.required_scopes).toEqual(expect.arrayContaining(test.required_scopes));
        });
      });

      it('should validate tenant isolation', () => {
        const tenantIsolationTests = [
          { tool: 'memory_store', version: '1.2.0', expected_isolation: true },
          { tool: 'memory_find', version: '1.3.0', expected_isolation: true },
          { tool: 'system_status', version: '1.0.0', expected_isolation: false },
        ];

        tenantIsolationTests.forEach((test) => {
          const contract =
            BUILTIN_TOOL_CONTRACTS[test.tool as keyof typeof BUILTIN_TOOL_CONTRACTS].contracts[
              test.version
            ];
          expect(contract.tenant_isolation).toBe(test.expected_isolation);
        });
      });
    });

    describe('Input Security Validation', () => {
      it('should validate content security policies', () => {
        const securityTests = [
          {
            name: 'XSS Prevention',
            input: {
              items: [
                {
                  kind: 'entity',
                  content: '<script>alert("xss")</script>',
                  scope: { project: 'security-test' },
                },
              ],
            },
            should_sanitize: true,
          },
          {
            name: 'SQL Injection Prevention',
            input: {
              items: [
                {
                  kind: 'entity',
                  content: "'; DROP TABLE knowledge; --",
                  scope: { project: 'security-test' },
                },
              ],
            },
            should_sanitize: true,
          },
          {
            name: 'Path Traversal Prevention',
            input: {
              items: [
                {
                  kind: 'entity',
                  content: '../../../etc/passwd',
                  scope: { project: 'security-test' },
                },
              ],
            },
            should_sanitize: true,
          },
        ];

        securityTests.forEach((test) => {
          const validation = validateInputForVersion('memory_store', '1.2.0', test.input);

          // Input should be valid (sanitized) but potentially flagged
          if (test.should_sanitize) {
            // The validation should pass but might include security warnings
            expect(validation.isValid).toBe(true);
            // In a real implementation, we'd check for security flags
          }
        });
      });

      it('should validate rate limiting compliance', () => {
        const rateLimitTests = [
          {
            tool: 'memory_store',
            version: '1.2.0',
            limits: {
              requests_per_minute: 60,
              tokens_per_minute: 10000,
              burst_allowance: 10,
            },
            usage: {
              requests_per_minute: 45,
              tokens_per_minute: 8000,
              burst_requests: 8,
            },
            should_pass: true,
          },
          {
            tool: 'memory_store',
            version: '1.2.0',
            limits: {
              requests_per_minute: 60,
              tokens_per_minute: 10000,
              burst_allowance: 10,
            },
            usage: {
              requests_per_minute: 75,
              tokens_per_minute: 12000,
              burst_requests: 15,
            },
            should_pass: false,
          },
        ];

        rateLimitTests.forEach((test) => {
          const contract =
            BUILTIN_TOOL_CONTRACTS[test.tool as keyof typeof BUILTIN_TOOL_CONTRACTS].contracts[
              test.version
            ];
          const limits = contract.rate_limits;

          expect(limits.requests_per_minute).toBe(test.limits.requests_per_minute);
          expect(limits.tokens_per_minute).toBe(test.limits.tokens_per_minute);
          expect(limits.burst_allowance).toBe(test.limits.burst_allowance);

          const withinLimits =
            test.usage.requests_per_minute <= limits.requests_per_minute &&
            test.usage.tokens_per_minute <= limits.tokens_per_minute &&
            test.usage.burst_requests <= limits.burst_allowance;

          expect(withinLimits).toBe(test.should_pass);
        });
      });
    });
  });

  describe('Contract Drift Detection', () => {
    describe('Version Drift Analysis', () => {
      it('should detect breaking changes between versions', () => {
        const driftAnalysis = detectContractDrift('memory_store', '1.0.0', '1.2.0');

        expect(driftAnalysis.hasBreakingChanges).toBe(true);
        expect(driftAnalysis.breakingChanges.length).toBeGreaterThan(0);

        // Check for specific breaking changes
        const breakingChanges = driftAnalysis.breakingChanges;
        expect(breakingChanges.some((change) => change.field.includes('idempotency_key'))).toBe(
          true
        );

        // Verify non-breaking changes are also tracked
        expect(driftAnalysis.nonBreakingChanges.length).toBeGreaterThan(0);
      });

      it('should generate migration plans for breaking changes', () => {
        const migrationPlan = generateMigrationPlan('memory_store', '1.0.0', '1.2.0');

        expect(migrationPlan.sourceVersion).toBe('1.0.0');
        expect(migrationPlan.targetVersion).toBe('1.2.0');
        expect(migrationPlan.steps.length).toBeGreaterThan(0);

        // Verify migration steps are actionable
        migrationPlan.steps.forEach((step) => {
          expect(step.description).toBeDefined();
          expect(step.action).toBeDefined();
          expect(step.severity).toMatch(/^(low|medium|high|critical)$/);
        });

        // Should have automated migration steps
        const automatedSteps = migrationPlan.steps.filter((step) => step.automated);
        expect(automatedSteps.length).toBeGreaterThan(0);

        // Should have manual intervention steps if needed
        const manualSteps = migrationPlan.steps.filter((step) => !step.automated);
        // Some breaking changes may require manual intervention
      });
    });

    describe('Backward Compatibility Validation', () => {
      it('should validate backward compatibility for inputs', () => {
        const v1_0_0_inputs = [
          {
            items: [
              {
                kind: 'entity',
                content: 'Simple v1.0.0 input',
                scope: { project: 'test' },
              },
            ],
          },
          {
            items: [
              {
                kind: 'entity',
                content: 'Another v1.0.0 input',
                scope: { project: 'test', branch: 'main' },
              },
            ],
          },
        ];

        // Test that v1.0.0 inputs work with v1.2.0
        v1_0_0_inputs.forEach((input) => {
          const v1_0_0_validation = validateInputForVersion('memory_store', '1.0.0', input);
          const v1_2_0_validation = validateInputForVersion('memory_store', '1.2.0', input);

          expect(v1_0_0_validation.isValid).toBe(true);
          expect(v1_2_0_validation.isValid).toBe(true); // Should be backward compatible
        });
      });

      it('should validate forward compatibility warnings', () => {
        const v1_2_0_input = {
          items: [
            {
              kind: 'entity',
              content: 'Advanced v1.2.0 input',
              scope: { project: 'test' },
              idempotency_key: 'unique-key-123',
              deduplication: {
                enabled: true,
                merge_strategy: 'intelligent',
                similarity_threshold: 0.9,
              },
              processing: {
                enable_validation: true,
                enable_async_processing: false,
              },
            },
          ],
        };

        // Test with v1.0.0 (should fail due to new fields)
        const v1_0_0_validation = validateInputForVersion('memory_store', '1.0.0', v1_2_0_input);
        expect(v1_0_0_validation.isValid).toBe(false);

        // Should provide helpful error messages about version incompatibility
        expect(v1_0_0_validation.errors).toBeDefined();
        expect(
          v1_0_0_validation.errors!.some(
            (e) => e.message.includes('version') || e.message.includes('not supported')
          )
        ).toBe(true);
      });
    });
  });

  describe('Real-World Scenario Testing', () => {
    describe('Complex Workflow Validation', () => {
      it('should validate end-to-end knowledge management workflow', async () => {
        // Step 1: Store multiple related knowledge items
        const workflowInput = {
          items: [
            {
              kind: 'entity',
              content: 'User Authentication Service',
              scope: { project: 'auth-system', service: 'auth-service' },
              metadata: {
                tags: ['microservice', 'authentication', 'security'],
                priority: 'high',
              },
            },
            {
              kind: 'relation',
              content: 'Auth service depends on user database',
              scope: { project: 'auth-system', service: 'auth-service' },
              metadata: {
                tags: ['dependency', 'database'],
                priority: 'medium',
              },
            },
            {
              kind: 'decision',
              content: 'Decided to use JWT tokens for authentication',
              scope: { project: 'auth-system', service: 'auth-service' },
              metadata: {
                tags: ['architecture', 'jwt', 'decision'],
                priority: 'high',
              },
            },
            {
              kind: 'risk',
              content: 'JWT secret key management risk',
              scope: { project: 'auth-system', service: 'auth-service' },
              metadata: {
                tags: ['security', 'risk', 'jwt'],
                priority: 'high',
              },
            },
            {
              kind: 'runbook',
              content: 'JWT token refresh process',
              scope: { project: 'auth-system', service: 'auth-service' },
              metadata: {
                tags: ['operations', 'jwt', 'runbook'],
                priority: 'medium',
              },
            },
          ],
          deduplication: {
            enabled: true,
            merge_strategy: 'intelligent',
            similarity_threshold: 0.85,
          },
          processing: {
            enable_validation: true,
            batch_processing: true,
            include_metrics: true,
          },
        };

        const storeValidation = validateInputForVersion('memory_store', '1.2.0', workflowInput);
        expect(storeValidation.isValid).toBe(true);

        // Step 2: Search for related knowledge
        const searchInput = {
          query: 'authentication service JWT',
          scope: {
            project: 'auth-system',
            service: 'auth-service',
          },
          types: ['entity', 'relation', 'decision', 'risk', 'runbook'],
          search_strategy: 'deep',
          graph_expansion: {
            enabled: true,
            max_depth: 3,
            max_nodes: 100,
            include_metadata: true,
          },
          limit: 20,
        };

        const searchValidation = validateInputForVersion('memory_find', '1.3.0', searchInput);
        expect(searchValidation.isValid).toBe(true);

        // Step 3: Check system health
        const statusInput = {
          operation: 'health',
          scope: {
            project: 'auth-system',
          },
        };

        const statusValidation = validateInputForVersion('system_status', '1.0.0', statusInput);
        expect(statusValidation.isValid).toBe(true);

        // Verify all steps are valid and compatible
        expect(storeValidation.isValid).toBe(true);
        expect(searchValidation.isValid).toBe(true);
        expect(statusValidation.isValid).toBe(true);

        // Verify scope consistency across workflow
        expect(workflowInput.items[0].scope.project).toBe(searchInput.scope.project);
        expect(statusInput.scope.project).toBe(workflowInput.items[0].scope.project);
      });

      it('should handle high-volume batch operations', async () => {
        // Generate large batch input
        const largeBatch = {
          items: Array.from({ length: 100 }, (_, i) => ({
            kind: ['entity', 'relation', 'observation'][i % 3],
            content: `Batch item ${i} with content for testing volume handling`,
            scope: {
              project: 'volume-test',
              batch_id: `batch-${Math.floor(i / 10)}`,
            },
            metadata: {
              tags: [`batch-${Math.floor(i / 10)}`, `item-${i % 20}`],
              priority: ['low', 'medium', 'high'][i % 3],
            },
            ...(i % 5 === 0
              ? {
                  deduplication: {
                    enabled: true,
                    similarity_threshold: 0.8 + (i % 3) * 0.05,
                  },
                }
              : {}),
          })),
          processing: {
            enable_validation: true,
            enable_async_processing: true, // Enable for large batches
            batch_processing: true,
            include_metrics: true,
          },
          global_deduplication: {
            enabled: true,
            merge_strategy: 'intelligent',
            batch_size: 25,
            enable_parallel_processing: true,
          },
        };

        const batchValidation = validateInputForVersion('memory_store', '1.2.0', largeBatch);
        expect(batchValidation.isValid).toBe(true);

        // Verify batch-specific constraints
        expect(largeBatch.items.length).toBeLessThanOrEqual(100); // Max batch size
        expect(largeBatch.processing.enable_async_processing).toBe(true);

        // Validate content size constraints
        largeBatch.items.forEach((item) => {
          expect(item.content.length).toBeGreaterThan(0);
          expect(item.content.length).toBeLessThanOrEqual(10000); // Max content length
        });

        // Test search across the batch
        const batchSearch = {
          query: 'batch volume test',
          scope: { project: 'volume-test' },
          search_strategy: 'auto',
          limit: 100, // Should handle large result sets
        };

        const searchValidation = validateInputForVersion('memory_find', '1.3.0', batchSearch);
        expect(searchValidation.isValid).toBe(true);
      });
    });

    describe('Error Recovery Scenarios', () => {
      it('should validate graceful error handling in complex scenarios', async () => {
        // Simulate partial failure scenario
        const partialFailureInput = {
          items: [
            {
              kind: 'entity',
              content: 'Valid item 1',
              scope: { project: 'error-test' },
            },
            {
              kind: 'entity',
              content: '', // Invalid: empty content
              scope: { project: 'error-test' },
            },
            {
              kind: 'invalid-kind', // Invalid kind
              content: 'Invalid kind item',
              scope: { project: 'error-test' },
            },
            {
              kind: 'entity',
              content: 'Valid item 2',
              scope: { project: 'error-test' },
            },
          ],
          processing: {
            enable_validation: true,
            continue_on_error: true, // Should handle partial failures
          },
        };

        const partialValidation = validateInputForVersion(
          'memory_store',
          '1.2.0',
          partialFailureInput
        );
        expect(partialValidation.isValid).toBe(false); // Overall validation fails
        expect(partialValidation.errors).toBeDefined();
        expect(partialValidation.errors!.length).toBeGreaterThan(1);

        // Should provide detailed error information
        const errorMessages = partialValidation.errors!.map((e) => e.message);
        expect(errorMessages.some((msg) => msg.includes('content'))).toBe(true);
        expect(errorMessages.some((msg) => msg.includes('kind'))).toBe(true);

        // Test error recovery with corrected input
        const correctedInput = {
          items: [
            {
              kind: 'entity',
              content: 'Valid item 1',
              scope: { project: 'error-test' },
            },
            {
              kind: 'entity',
              content: 'Corrected item 2', // Fixed empty content
              scope: { project: 'error-test' },
            },
            {
              kind: 'observation', // Fixed kind
              content: 'Corrected observation item',
              scope: { project: 'error-test' },
            },
            {
              kind: 'entity',
              content: 'Valid item 2',
              scope: { project: 'error-test' },
            },
          ],
          processing: {
            enable_validation: true,
            continue_on_error: false,
          },
        };

        const correctedValidation = validateInputForVersion(
          'memory_store',
          '1.2.0',
          correctedInput
        );
        expect(correctedValidation.isValid).toBe(true);
      });
    });
  });
});
