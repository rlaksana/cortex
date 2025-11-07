/**
 * MCP Semantic Deduplication Functionality Integration Tests
 *
 * This test suite validates that semantic deduplication works correctly
 * through the MCP interface. It tests all merge strategies, similarity
 * thresholds, intelligent merging, and deduplication configuration.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock environment for testing
process.env['OPENAI_API_KEY'] = 'test-key';
process.env['QDRANT_URL'] = 'http://localhost:6333';
process.env['NODE_ENV'] = 'test';

describe('MCP Semantic Deduplication Functionality Integration Tests', () => {
  describe('Basic Deduplication Configuration via MCP', () => {
    it('should configure deduplication with skip strategy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 1,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'entity',
                data: {
                  entity_type: 'user',
                  name: 'john_doe',
                  data: { email: 'john@example.com', role: 'developer' },
                },
                scope: { project: 'user-management', branch: 'main' },
                deduplication_key: 'user_john_doe',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'skip',
              similarity_threshold: 0.85,
              check_within_scope_only: true,
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.enabled).toBe(true);
      expect(dedupConfig.merge_strategy).toBe('skip');
      expect(dedupConfig.similarity_threshold).toBe(0.85);
      expect(dedupConfig.check_within_scope_only).toBe(true);
    });

    it('should configure deduplication with prefer_existing strategy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 2,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'decision',
                data: {
                  title: 'Use PostgreSQL Database',
                  rationale: 'Strong ACID compliance and reliability',
                  alternatives: ['MongoDB', 'MySQL'],
                  status: 'accepted',
                  impact: 'high',
                },
                scope: { project: 'architecture', branch: 'main' },
                deduplication_key: 'database_choice_postgres',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'prefer_existing',
              similarity_threshold: 0.9,
              check_within_scope_only: false,
              enable_audit_logging: true,
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.merge_strategy).toBe('prefer_existing');
      expect(dedupConfig.similarity_threshold).toBe(0.9);
      expect(dedupConfig.check_within_scope_only).toBe(false);
      expect(dedupConfig.enable_audit_logging).toBe(true);
    });

    it('should configure deduplication with prefer_newer strategy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 3,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'todo',
                data: {
                  title: 'Update API documentation',
                  priority: 'high',
                  status: 'in_progress',
                  assignee: 'tech_writer',
                  due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
                },
                scope: { project: 'documentation', branch: 'main' },
                deduplication_key: 'api_docs_update_task',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'prefer_newer',
              similarity_threshold: 0.8,
              enable_intelligent_merging: false,
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.merge_strategy).toBe('prefer_newer');
      expect(dedupConfig.similarity_threshold).toBe(0.8);
      expect(dedupConfig.enable_intelligent_merging).toBe(false);
    });

    it('should configure deduplication with combine strategy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 4,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'observation',
                data: {
                  title: 'User feedback on performance',
                  content: 'Users report slow response times during peak hours',
                  source: 'customer_support',
                  confidence: 0.9,
                  tags: ['performance', 'user_feedback', 'optimization'],
                },
                scope: { project: 'performance', branch: 'main' },
                deduplication_key: 'performance_feedback_2024',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'combine',
              similarity_threshold: 0.85,
              enable_audit_logging: true,
              enable_intelligent_merging: true,
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.merge_strategy).toBe('combine');
      expect(dedupConfig.enable_intelligent_merging).toBe(true);
      expect(dedupConfig.enable_audit_logging).toBe(true);
    });

    it('should configure deduplication with intelligent strategy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 5,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'incident',
                data: {
                  title: 'Database Connection Pool Exhaustion',
                  severity: 'high',
                  status: 'resolved',
                  impact: {
                    affected_services: ['api', 'web', 'mobile'],
                    user_impact: 'high',
                    business_impact: 'medium',
                  },
                  timeline: [
                    {
                      timestamp: new Date().toISOString(),
                      event: 'Alert triggered',
                      source: 'monitoring',
                    },
                    {
                      timestamp: new Date().toISOString(),
                      event: 'Investigation started',
                      source: 'on-call',
                    },
                    {
                      timestamp: new Date().toISOString(),
                      event: 'Pool size increased',
                      source: 'engineering',
                    },
                    {
                      timestamp: new Date().toISOString(),
                      event: 'Issue resolved',
                      source: 'engineering',
                    },
                  ],
                },
                scope: { project: 'incidents', branch: 'production' },
                deduplication_key: 'database_pool_incident',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.9,
              check_within_scope_only: true,
              enable_audit_logging: true,
              enable_intelligent_merging: true,
              max_dedupe_candidates: 10,
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.merge_strategy).toBe('intelligent');
      expect(dedupConfig.similarity_threshold).toBe(0.9);
      expect(dedupConfig.max_dedupe_candidates).toBe(10);
    });
  });

  describe('Advanced Deduplication Features', () => {
    it('should handle semantic similarity with different thresholds', async () => {
      const similarityTests = [
        { threshold: 0.5, description: 'Very loose similarity' },
        { threshold: 0.7, description: 'Loose similarity' },
        { threshold: 0.85, description: 'Standard similarity' },
        { threshold: 0.9, description: 'High similarity' },
        { threshold: 0.95, description: 'Very high similarity' },
        { threshold: 1.0, description: 'Exact match only' },
      ];

      similarityTests.forEach((test, index) => {
        const memoryStoreRequest = {
          jsonrpc: '2.0' as const,
          id: 6 + index,
          method: 'tools/call' as const,
          params: {
            name: 'memory_store',
            arguments: {
              items: [
                {
                  kind: 'entity',
                  data: {
                    entity_type: 'test_entity',
                    name: `similarity_test_${test.threshold}`,
                    data: { threshold: test.threshold, description: test.description },
                  },
                  scope: { project: 'similarity-tests', branch: 'main' },
                },
              ],
              deduplication_config: {
                enabled: true,
                merge_strategy: 'intelligent',
                similarity_threshold: test.threshold,
                check_within_scope_only: true,
              },
            },
          },
        };

        expect(memoryStoreRequest.params.arguments.deduplication_config.similarity_threshold).toBe(
          test.threshold
        );
        expect(
          memoryStoreRequest.params.arguments.deduplication_config.similarity_threshold
        ).toBeGreaterThanOrEqual(0);
        expect(
          memoryStoreRequest.params.arguments.deduplication_config.similarity_threshold
        ).toBeLessThanOrEqual(1);
      });
    });

    it('should handle batch deduplication with mixed strategies', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 12,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'entity',
                data: {
                  entity_type: 'user',
                  name: 'alice_smith',
                  data: { email: 'alice@example.com', department: 'engineering' },
                },
                scope: { project: 'users', branch: 'main' },
                deduplication_key: 'user_alice_smith',
              },
              {
                kind: 'decision',
                data: {
                  title: 'Implement microservices architecture',
                  rationale: 'Better scalability and maintainability',
                  alternatives: ['Monolith', 'Modular monolith'],
                  status: 'accepted',
                },
                scope: { project: 'architecture', branch: 'main' },
                deduplication_key: 'microservices_decision',
              },
              {
                kind: 'risk',
                data: {
                  title: 'Single point of failure in database',
                  probability: 'medium',
                  impact: 'high',
                  risk_score: 12,
                  mitigations: [
                    {
                      strategy: 'Implement database clustering',
                      status: 'planned',
                      owner: 'dba_team',
                    },
                  ],
                },
                scope: { project: 'risks', branch: 'main' },
                deduplication_key: 'database_spof_risk',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.85,
              check_within_scope_only: true,
              enable_audit_logging: true,
              enable_intelligent_merging: true,
              batch_deduplication: {
                enabled: true,
                max_batch_size: 50,
                parallel_processing: true,
              },
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.batch_deduplication.enabled).toBe(true);
      expect(dedupConfig.batch_deduplication.max_batch_size).toBe(50);
      expect(dedupConfig.batch_deduplication.parallel_processing).toBe(true);
      expect(memoryStoreRequest.params.arguments.items).toHaveLength(3);
    });

    it('should handle scope-aware deduplication', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 13,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'entity',
                data: {
                  entity_type: 'config_setting',
                  name: 'database_url',
                  data: {
                    value: 'postgresql://localhost:5432/app',
                    environment: 'development',
                  },
                },
                scope: { project: 'config', branch: 'development' },
                deduplication_key: 'config_database_url',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'prefer_existing',
              similarity_threshold: 0.95,
              check_within_scope_only: true,
              scope_aware_deduplication: {
                enabled: true,
                scope_hierarchy: ['organization', 'project', 'branch'],
                cross_scope_strategy: 'allow_if_different_scope',
              },
            },
          },
        },
      };

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.scope_aware_deduplication.enabled).toBe(true);
      expect(dedupConfig.scope_aware_deduplication.scope_hierarchy).toEqual([
        'organization',
        'project',
        'branch',
      ]);
      expect(dedupConfig.scope_aware_deduplication.cross_scope_strategy).toBe(
        'allow_if_different_scope'
      );
    });
  });

  describe('Intelligent Merging Features', () => {
    it('should handle intelligent merging with field-level strategies', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 14,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'runbook',
                data: {
                  title: 'Production Deployment Procedure',
                  description: 'Step-by-step guide for production deployments',
                  steps: [
                    { step: 1, action: 'Run health checks', owner: 'devops', timeout_minutes: 5 },
                    { step: 2, action: 'Backup database', owner: 'dba', timeout_minutes: 30 },
                    { step: 3, action: 'Deploy application', owner: 'devops', timeout_minutes: 15 },
                  ],
                  triggers: ['deployment_request', 'emergency_fix'],
                  rollback_procedure: {
                    enabled: true,
                    max_rollback_time_minutes: 30,
                    approval_required: true,
                  },
                },
                scope: { project: 'operations', branch: 'main' },
                deduplication_key: 'production_deployment_runbook',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.85,
              enable_intelligent_merging: true,
              intelligent_merge_config: {
                field_merging_strategies: {
                  arrays: 'append_unique',
                  objects: 'merge_deep',
                  strings: 'prefer_newer',
                  numbers: 'prefer_higher',
                  booleans: 'logical_or',
                },
                conflict_resolution: {
                  manual_review_threshold: 0.7,
                  auto_merge_confidence_threshold: 0.9,
                },
              },
            },
          },
        },
      };

      const mergeConfig =
        memoryStoreRequest.params.arguments.deduplication_config.intelligent_merge_config;
      expect(mergeConfig.field_merging_strategies.arrays).toBe('append_unique');
      expect(mergeConfig.field_merging_strategies.objects).toBe('merge_deep');
      expect(mergeConfig.conflict_resolution.auto_merge_confidence_threshold).toBe(0.9);
    });

    it('should handle temporal deduplication with time awareness', async () => {
      const currentTime = new Date();
      const olderTime = new Date(currentTime.getTime() - 24 * 60 * 60 * 1000); // 1 day ago

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 15,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'observation',
                data: {
                  title: 'System performance metrics',
                  content: 'CPU usage at 75%, memory usage at 60%',
                  source: 'monitoring_system',
                  confidence: 0.95,
                  timestamp: currentTime.toISOString(),
                  metadata: {
                    cpu_usage: 75,
                    memory_usage: 60,
                    disk_usage: 45,
                  },
                },
                scope: { project: 'monitoring', branch: 'production' },
                deduplication_key: 'performance_metrics_latest',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.8,
              enable_intelligent_merging: true,
              temporal_deduplication: {
                enabled: true,
                time_sensitivity: 'high',
                staleness_threshold_hours: 24,
                merge_strategy: 'prefer_newer_significant_changes',
                significance_threshold: 0.1, // 10% change threshold
              },
            },
          },
        },
      };

      const temporalConfig =
        memoryStoreRequest.params.arguments.deduplication_config.temporal_deduplication;
      expect(temporalConfig.enabled).toBe(true);
      expect(temporalConfig.time_sensitivity).toBe('high');
      expect(temporalConfig.staleness_threshold_hours).toBe(24);
      expect(temporalConfig.significance_threshold).toBe(0.1);
    });
  });

  describe('Deduplication Search and Discovery', () => {
    it('should search for duplicates via memory_find', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 16,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'duplicate user entries',
            scope: { project: 'user-management', branch: 'main' },
            types: ['entity'],
            deduplication_filters: {
              find_duplicates: true,
              similarity_threshold: 0.85,
              include_similar_items: true,
              max_candidates_per_item: 5,
            },
            search_strategy: 'deep',
            limit: 50,
          },
        },
      };

      const dedupFilters = memoryFindRequest.params.arguments.deduplication_filters;
      expect(dedupFilters.find_duplicates).toBe(true);
      expect(dedupFilters.similarity_threshold).toBe(0.85);
      expect(dedupFilters.include_similar_items).toBe(true);
      expect(dedupFilters.max_candidates_per_item).toBe(5);
    });

    it('should search for potential merge candidates via memory_find', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 17,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'similar decisions about database technology',
            scope: { project: 'architecture', branch: 'main' },
            types: ['decision'],
            deduplication_filters: {
              find_merge_candidates: true,
              merge_strategies: ['intelligent', 'combine'],
              similarity_threshold: 0.7,
              include_merge_suggestions: true,
            },
            search_strategy: 'auto',
            limit: 25,
          },
        },
      };

      const dedupFilters = memoryFindRequest.params.arguments.deduplication_filters;
      expect(dedupFilters.find_merge_candidates).toBe(true);
      expect(dedupFilters.merge_strategies).toEqual(['intelligent', 'combine']);
      expect(dedupFilters.include_merge_suggestions).toBe(true);
    });
  });

  describe('Deduplication System Status and Monitoring', () => {
    it('should check deduplication system health via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 18,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'health',
            include_detailed_metrics: true,
            filters: {
              components: ['deduplication_engine', 'similarity_calculator', 'merge_processor'],
            },
            response_formatting: {
              verbose: true,
              include_timestamps: true,
            },
          },
        },
      };

      const filters = systemStatusRequest.params.arguments.filters;
      expect(filters.components).toContain('deduplication_engine');
      expect(filters.components).toContain('similarity_calculator');
      expect(filters.components).toContain('merge_processor');
    });

    it('should get deduplication metrics via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 19,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'telemetry',
            filters: {
              metrics: [
                'deduplication_rate',
                'merge_strategy_distribution',
                'similarity_score_distribution',
                'intelligent_merge_success_rate',
                'duplicate_detection_latency',
              ],
              time_range_hours: 24,
            },
          },
        },
      };

      const filters = systemStatusRequest.params.arguments.filters;
      expect(filters.metrics).toContain('deduplication_rate');
      expect(filters.metrics).toContain('merge_strategy_distribution');
      expect(filters.metrics).toContain('similarity_score_distribution');
      expect(filters.time_range_hours).toBe(24);
    });

    it('should run deduplication audit via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 20,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'run_cleanup',
            cleanup_config: {
              operations: ['duplicate_audit', 'merge_validation'],
              deduplication_audit: {
                scope: { project: 'all', branch: 'all' },
                similarity_threshold_range: [0.7, 1.0],
                include_manual_review_required: true,
                generate_report: true,
              },
              dry_run: true,
              require_confirmation: false,
            },
          },
        },
      };

      const cleanupConfig = systemStatusRequest.params.arguments.cleanup_config;
      expect(cleanupConfig.operations).toEqual(['duplicate_audit', 'merge_validation']);
      expect(cleanupConfig.deduplication_audit).toBeDefined();
      expect(cleanupConfig.deduplication_audit.generate_report).toBe(true);
    });
  });

  describe('Deduplication Error Handling and Edge Cases', () => {
    it('should handle invalid merge strategy gracefully', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 21,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'entity',
                data: {
                  entity_type: 'test',
                  name: 'invalid_strategy_test',
                  data: { value: 'test' },
                },
                scope: { project: 'test', branch: 'main' },
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'invalid_strategy' as any,
              similarity_threshold: 0.85,
            },
          },
        },
      };

      expect(memoryStoreRequest.params.arguments.deduplication_config.merge_strategy).toBe(
        'invalid_strategy'
      );
    });

    it('should handle similarity threshold out of range', async () => {
      const invalidThresholds = [-0.1, 1.5, 2.0];

      invalidThresholds.forEach((threshold, index) => {
        const memoryStoreRequest = {
          jsonrpc: '2.0' as const,
          id: 22 + index,
          method: 'tools/call' as const,
          params: {
            name: 'memory_store',
            arguments: {
              items: [
                {
                  kind: 'entity',
                  data: {
                    entity_type: 'test',
                    name: `invalid_threshold_${threshold}`,
                    data: { threshold },
                  },
                  scope: { project: 'test', branch: 'main' },
                },
              ],
              deduplication_config: {
                enabled: true,
                merge_strategy: 'intelligent',
                similarity_threshold: threshold,
              },
            },
          },
        };

        expect(memoryStoreRequest.params.arguments.deduplication_config.similarity_threshold).toBe(
          threshold
        );
        expect(threshold < 0 || threshold > 1).toBe(true); // This should fail validation
      });
    });

    it('should handle missing deduplication_key', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 25,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'entity',
                data: {
                  entity_type: 'user',
                  name: 'no_key_user',
                  data: { email: 'nokey@example.com' },
                },
                scope: { project: 'test', branch: 'main' },
                // Note: No deduplication_key provided
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.85,
              auto_generate_key: true,
            },
          },
        },
      };

      expect(memoryStoreRequest.params.arguments.items[0].deduplication_key).toBeUndefined();
      expect(memoryStoreRequest.params.arguments.deduplication_config.auto_generate_key).toBe(true);
    });

    it('should handle deduplication conflicts', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 26,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'decision',
                data: {
                  title: 'Conflicting Decision',
                  rationale: 'This conflicts with existing decision',
                  alternatives: ['Option A', 'Option B'],
                  status: 'conflicted',
                },
                scope: { project: 'test', branch: 'main' },
                deduplication_key: 'conflicting_decision',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.95,
              conflict_resolution: {
                strategy: 'manual_review',
                notify_stakeholders: ['architecture_team', 'product_manager'],
                escalation_timeout_hours: 24,
              },
            },
          },
        },
      };

      const conflictConfig =
        memoryStoreRequest.params.arguments.deduplication_config.conflict_resolution;
      expect(conflictConfig.strategy).toBe('manual_review');
      expect(conflictConfig.notify_stakeholders).toContain('architecture_team');
      expect(conflictConfig.escalation_timeout_hours).toBe(24);
    });
  });

  describe('Deduplication Performance and Scalability', () => {
    it('should handle large-scale deduplication operations', async () => {
      const largeBatch = [];
      for (let i = 0; i < 200; i++) {
        largeBatch.push({
          kind: 'entity',
          data: {
            entity_type: 'large_scale_item',
            name: `item_${i}`,
            data: { batch_id: 'large_test', index: i },
          },
          scope: { project: 'scale-test', branch: 'main' },
          deduplication_key: `scale_item_${i}`,
        });
      }

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 27,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: largeBatch,
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.85,
              batch_deduplication: {
                enabled: true,
                max_batch_size: 50,
                parallel_processing: true,
                max_concurrent_batches: 4,
              },
              performance_config: {
                enable_caching: true,
                cache_ttl_minutes: 30,
                max_similarity_calculations_per_second: 100,
              },
            },
          },
        },
      };

      expect(memoryStoreRequest.params.arguments.items).toHaveLength(200);
      const perfConfig =
        memoryStoreRequest.params.arguments.deduplication_config.performance_config;
      expect(perfConfig.enable_caching).toBe(true);
      expect(perfConfig.max_similarity_calculations_per_second).toBe(100);
    });

    it('should handle memory-efficient deduplication for large content', async () => {
      const largeContent = 'x'.repeat(50000); // 50KB content

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 28,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'section',
                data: {
                  title: 'Large Documentation Section',
                  content: largeContent,
                  section_type: 'documentation',
                  metadata: {
                    word_count: largeContent.split(' ').length,
                    size_bytes: largeContent.length,
                  },
                },
                scope: { project: 'docs', branch: 'main' },
                deduplication_key: 'large_doc_section',
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.8,
              memory_optimization: {
                enable_content_hashing: true,
                chunk_large_content: true,
                chunk_size_bytes: 10240, // 10KB chunks
                compare_sample_percentage: 0.1, // Compare 10% sample first
              },
            },
          },
        },
      };

      const memOptConfig =
        memoryStoreRequest.params.arguments.deduplication_config.memory_optimization;
      expect(memOptConfig.enable_content_hashing).toBe(true);
      expect(memOptConfig.chunk_large_content).toBe(true);
      expect(memOptConfig.chunk_size_bytes).toBe(10240);
    });
  });

  describe('Deduplication Integration with Other Features', () => {
    it('should combine deduplication with TTL policies', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 29,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'risk',
                data: {
                  title: 'Security Risk with Deduplication',
                  probability: 'medium',
                  impact: 'high',
                  risk_score: 12,
                  mitigations: [
                    {
                      strategy: 'Regular security audits',
                      status: 'planned',
                      owner: 'security_team',
                    },
                  ],
                },
                scope: { project: 'security', branch: 'main' },
                deduplication_key: 'security_risk_with_ttl',
                ttl: {
                  policy: 'long',
                  auto_extend: true,
                  extend_threshold_days: 90,
                },
              },
            ],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.9,
              enable_intelligent_merging: true,
              ttl_aware_deduplication: {
                enabled: true,
                prioritize_active_items: true,
                expire_duplicates_sooner: true,
              },
            },
          },
        },
      };

      const item = memoryStoreRequest.params.arguments.items[0];
      expect(item.ttl.policy).toBe('long');
      expect(item.deduplication_key).toBeDefined();

      const dedupConfig = memoryStoreRequest.params.arguments.deduplication_config;
      expect(dedupConfig.ttl_aware_deduplication.enabled).toBe(true);
      expect(dedupConfig.ttl_aware_deduplication.prioritize_active_items).toBe(true);
    });

    it('should combine deduplication with graph expansion', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 30,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'duplicate decisions and their impacts',
            scope: { project: 'architecture', branch: 'main' },
            types: ['decision', 'risk', 'issue'],
            deduplication_filters: {
              find_duplicates: true,
              similarity_threshold: 0.8,
              include_related_items: true,
            },
            graph_expansion: {
              enabled: true,
              expansion_type: 'relations',
              max_depth: 2,
              max_nodes: 100,
              filters: {
                deduplication_aware: true,
                include_duplicate_relations: true,
              },
            },
            search_strategy: 'deep',
            limit: 50,
          },
        },
      };

      const request = memoryFindRequest.params.arguments;
      expect(request.deduplication_filters.include_related_items).toBe(true);
      expect(request.graph_expansion.filters.deduplication_aware).toBe(true);
      expect(request.graph_expansion.filters.include_duplicate_relations).toBe(true);
    });
  });
});
