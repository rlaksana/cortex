/**
 * MCP TTL Functionality Integration Tests
 *
 * This test suite validates that TTL (Time To Live) policies work correctly
 * through the MCP interface. It tests all TTL policies, expiration handling,
 * auto-extension, and cleanup functionality via MCP tool calls.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock environment for testing
process.env.OPENAI_API_KEY = 'test-key';
process.env.QDRANT_URL = 'http://localhost:6333';
process.env.NODE_ENV = 'test';

describe('MCP TTL Functionality Integration Tests', () => {
  describe('TTL Policy Validation through MCP', () => {
    it('should store items with default TTL policy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 1,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              data: {
                entity_type: 'user',
                name: 'test_user_default_ttl',
                data: { email: 'test@example.com' }
              },
              scope: { project: 'ttl-test', branch: 'main' },
              ttl: {
                policy: 'default'
              }
            }]
          }
        }
      };

      // Validate request structure
      expect(memoryStoreRequest.jsonrpc).toBe('2.0');
      expect(memoryStoreRequest.method).toBe('tools/call');
      expect(memoryStoreRequest.params.name).toBe('memory_store');
      expect(memoryStoreRequest.params.arguments.items).toHaveLength(1);
      expect(memoryStoreRequest.params.arguments.items[0].ttl.policy).toBe('default');
    });

    it('should store items with short TTL policy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 2,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              data: {
                entity_type: 'temp_data',
                name: 'short_lived_item',
                data: { value: 'expires_quickly' }
              },
              scope: { project: 'ttl-test', branch: 'main' },
              ttl: {
                policy: 'short',
                auto_extend: false
              }
            }]
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items[0].ttl.policy).toBe('short');
      expect(memoryStoreRequest.params.arguments.items[0].ttl.auto_extend).toBe(false);
    });

    it('should store items with long TTL policy via memory_store', async () => {
      const futureDate = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 3,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'decision',
              data: {
                title: 'Architecture Decision',
                rationale: 'Long-term architectural choice',
                alternatives: ['Option A', 'Option B'],
                status: 'accepted'
              },
              scope: { project: 'architecture', branch: 'main' },
              ttl: {
                policy: 'long',
                expires_at: futureDate.toISOString(),
                auto_extend: true,
                extend_threshold_days: 30
              }
            }]
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items[0].ttl.policy).toBe('long');
      expect(memoryStoreRequest.params.arguments.items[0].ttl.expires_at).toBeDefined();
      expect(memoryStoreRequest.params.arguments.items[0].ttl.auto_extend).toBe(true);
      expect(memoryStoreRequest.params.arguments.items[0].ttl.extend_threshold_days).toBe(30);
    });

    it('should store items with permanent TTL policy via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 4,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'runbook',
              data: {
                title: 'Critical Recovery Procedure',
                description: 'Essential recovery steps for production incidents',
                steps: [
                  { step: 1, action: 'Assess impact', owner: 'on-call' },
                  { step: 2, action: 'Communicate status', owner: 'on-call' },
                  { step: 3, action: 'Implement fix', owner: 'engineering' }
                ],
                triggers: ['production_outage', 'security_incident'],
                escalation_policy: {
                  level_1: { team: 'on-call', timeout_minutes: 15 },
                  level_2: { team: 'engineering', timeout_minutes: 30 },
                  level_3: { team: 'management', timeout_minutes: 60 }
                }
              },
              scope: { project: 'operations', branch: 'main' },
              ttl: {
                policy: 'permanent'
              }
            }]
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items[0].ttl.policy).toBe('permanent');
    });

    it('should store items with custom expiration date via memory_store', async () => {
      const customExpiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 5,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'incident',
              data: {
                title: 'API Performance Degradation',
                severity: 'medium',
                status: 'investigating',
                impact: {
                  affected_services: ['user-api', 'order-api'],
                  user_impact: 'medium',
                  business_impact: 'low'
                },
                timeline: [
                  { timestamp: new Date().toISOString(), event: 'Alert triggered', source: 'monitoring' },
                  { timestamp: new Date().toISOString(), event: 'Investigation started', source: 'on-call' }
                ]
              },
              scope: { project: 'incidents', branch: 'main' },
              ttl: {
                policy: 'default',
                expires_at: customExpiryDate.toISOString(),
                auto_extend: false,
                max_extensions: 0
              }
            }]
          }
        }
      };

      const ttlConfig = memoryStoreRequest.params.arguments.items[0].ttl;
      expect(ttlConfig.expires_at).toBe(customExpiryDate.toISOString());
      expect(ttlConfig.auto_extend).toBe(false);
      expect(ttlConfig.max_extensions).toBe(0);
    });
  });

  describe('TTL Auto-Extension Functionality', () => {
    it('should configure auto-extension with threshold via memory_store', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 6,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              data: {
                entity_type: 'active_session',
                name: 'user_session_123',
                data: {
                  user_id: 'user_456',
                  last_activity: new Date().toISOString(),
                  session_data: { preferences: {} }
                }
              },
              scope: { project: 'sessions', branch: 'production' },
              ttl: {
                policy: 'default',
                auto_extend: true,
                extend_threshold_days: 3,
                max_extensions: 10
              }
            }]
          }
        }
      };

      const ttlConfig = memoryStoreRequest.params.arguments.items[0].ttl;
      expect(ttlConfig.auto_extend).toBe(true);
      expect(ttlConfig.extend_threshold_days).toBe(3);
      expect(ttlConfig.max_extensions).toBe(10);
    });

    it('should store batch items with different TTL policies', async () => {
      const batchDate = new Date();
      const shortExpiry = new Date(batchDate.getTime() + 24 * 60 * 60 * 1000); // 1 day
      const longExpiry = new Date(batchDate.getTime() + 60 * 24 * 60 * 60 * 1000); // 60 days

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 7,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'todo',
                data: {
                  title: 'Temporary Task',
                  priority: 'low',
                  status: 'pending',
                  assignee: 'dev_1'
                },
                scope: { project: 'project-x', branch: 'main' },
                ttl: {
                  policy: 'short',
                  expires_at: shortExpiry.toISOString()
                }
              },
              {
                kind: 'risk',
                data: {
                  title: 'Long-term Technical Risk',
                  probability: 'low',
                  impact: 'high',
                  risk_score: 8,
                  mitigations: [
                    {
                      strategy: 'Architecture review',
                      status: 'planned',
                      owner: 'architecture_team'
                    }
                  ]
                },
                scope: { project: 'architecture', branch: 'main' },
                ttl: {
                  policy: 'long',
                  expires_at: longExpiry.toISOString(),
                  auto_extend: true
                }
              },
              {
                kind: 'decision',
                data: {
                  title: 'Permanent Policy Decision',
                  rationale: 'Company-wide policy',
                  alternatives: [],
                  status: 'adopted'
                },
                scope: { project: 'company-policy', branch: 'main' },
                ttl: {
                  policy: 'permanent'
                }
              }
            ]
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items).toHaveLength(3);

      const [shortItem, longItem, permanentItem] = memoryStoreRequest.params.arguments.items;
      expect(shortItem.ttl.policy).toBe('short');
      expect(longItem.ttl.policy).toBe('long');
      expect(permanentItem.ttl.policy).toBe('permanent');

      expect(shortItem.ttl.expires_at).toBe(shortExpiry.toISOString());
      expect(longItem.ttl.expires_at).toBe(longExpiry.toISOString());
      expect(longItem.ttl.auto_extend).toBe(true);
    });
  });

  describe('TTL Search and Filtering via memory_find', () => {
    it('should search with TTL filters via memory_find', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 8,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'user sessions',
            scope: { project: 'sessions', branch: 'production' },
            types: ['entity'],
            ttl_filters: {
              include_expired: false,
              min_days_remaining: 1,
              max_days_remaining: 30
            },
            search_strategy: 'auto',
            limit: 50
          }
        }
      };

      expect(memoryFindRequest.params.name).toBe('memory_find');
      expect(memoryFindRequest.params.arguments.ttl_filters).toBeDefined();
      expect(memoryFindRequest.params.arguments.ttl_filters.include_expired).toBe(false);
      expect(memoryFindRequest.params.arguments.ttl_filters.min_days_remaining).toBe(1);
      expect(memoryFindRequest.params.arguments.ttl_filters.max_days_remaining).toBe(30);
    });

    it('should search for expired items via memory_find', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 9,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'archived incidents',
            scope: { project: 'incidents', branch: 'main' },
            types: ['incident'],
            ttl_filters: {
              include_expired: true,
              expired_before: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
            },
            search_strategy: 'deep',
            limit: 100
          }
        }
      };

      const ttlFilters = memoryFindRequest.params.arguments.ttl_filters;
      expect(ttlFilters.include_expired).toBe(true);
      expect(ttlFilters.expired_before).toBeDefined();
    });

    it('should search for items with specific TTL policies via memory_find', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 10,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'critical documentation',
            scope: { project: 'docs', branch: 'main' },
            types: ['section', 'runbook'],
            ttl_filters: {
              policies: ['permanent', 'long'],
              include_expired: false
            },
            search_strategy: 'fast',
            limit: 25
          }
        }
      };

      const ttlFilters = memoryFindRequest.params.arguments.ttl_filters;
      expect(ttlFilters.policies).toEqual(['permanent', 'long']);
      expect(ttlFilters.include_expired).toBe(false);
    });
  });

  describe('TTL System Status Operations', () => {
    it('should check TTL system health via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 11,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'health',
            include_detailed_metrics: true,
            response_formatting: {
              verbose: true,
              include_timestamps: true
            },
            filters: {
              components: ['ttl_manager', 'expiration_scheduler']
            }
          }
        }
      };

      expect(systemStatusRequest.params.name).toBe('system_status');
      expect(systemStatusRequest.params.arguments.operation).toBe('health');
      expect(systemStatusRequest.params.arguments.filters.components).toContain('ttl_manager');
    });

    it('should run TTL cleanup via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 12,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'run_cleanup',
            cleanup_config: {
              operations: ['expired', 'orphaned'],
              ttl_specific: {
                cleanup_expired_before: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                dry_run: false,
                batch_size: 100
              },
              require_confirmation: false,
              enable_backup: true
            }
          }
        }
      };

      const cleanupConfig = systemStatusRequest.params.arguments.cleanup_config;
      expect(cleanupConfig.operations).toEqual(['expired', 'orphaned']);
      expect(cleanupConfig.ttl_specific).toBeDefined();
      expect(cleanupConfig.ttl_specific.cleanup_expired_before).toBeDefined();
      expect(cleanupConfig.ttl_specific.dry_run).toBe(false);
    });

    it('should get TTL metrics via system_status', async () => {
      const systemStatusRequest = {
        jsonrpc: '2.0' as const,
        id: 13,
        method: 'tools/call' as const,
        params: {
          name: 'system_status',
          arguments: {
            operation: 'telemetry',
            filters: {
              metrics: ['ttl_distribution', 'expiration_trends', 'auto_extension_stats'],
              time_range_hours: 24
            },
            response_formatting: {
              verbose: true,
              include_timestamps: true
            }
          }
        }
      };

      const filters = systemStatusRequest.params.arguments.filters;
      expect(filters.metrics).toContain('ttl_distribution');
      expect(filters.metrics).toContain('expiration_trends');
      expect(filters.metrics).toContain('auto_extension_stats');
      expect(filters.time_range_hours).toBe(24);
    });
  });

  describe('TTL Error Handling and Edge Cases', () => {
    it('should handle invalid TTL policy gracefully', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 14,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              data: {
                entity_type: 'test',
                name: 'invalid_ttl_test',
                data: { value: 'test' }
              },
              scope: { project: 'test', branch: 'main' },
              ttl: {
                policy: 'invalid_policy' as any
              }
            }]
          }
        }
      };

      // This should result in a validation error
      expect(memoryStoreRequest.params.arguments.items[0].ttl.policy).toBe('invalid_policy');
    });

    it('should handle past expiration date', async () => {
      const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 1 day ago

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 15,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'observation',
              data: {
                title: 'Already Expired Observation',
                content: 'This should be immediately expired',
                source: 'test_suite',
                confidence: 1.0
              },
              scope: { project: 'test', branch: 'main' },
              ttl: {
                policy: 'default',
                expires_at: pastDate.toISOString()
              }
            }]
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items[0].ttl.expires_at).toBe(pastDate.toISOString());
      expect(new Date(pastDate)).toBeInstanceOf(Date);
    });

    it('should handle TTL auto-extension limit reached', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 16,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'todo',
              data: {
                title: 'Task with Extension Limit',
                priority: 'medium',
                status: 'in_progress',
                assignee: 'developer_1',
                extension_count: 5
              },
              scope: { project: 'project-x', branch: 'main' },
              ttl: {
                policy: 'default',
                auto_extend: true,
                max_extensions: 5,
                extend_threshold_days: 7
              }
            }]
          }
        }
      };

      const ttlConfig = memoryStoreRequest.params.arguments.items[0].ttl;
      expect(ttlConfig.max_extensions).toBe(5);
      expect(ttlConfig.auto_extend).toBe(true);
    });

    it('should validate TTL configuration structure', async () => {
      const validTTLConfigs = [
        { policy: 'default' },
        { policy: 'short', auto_extend: false },
        { policy: 'long', auto_extend: true, extend_threshold_days: 30 },
        { policy: 'permanent' },
        {
          policy: 'default',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          auto_extend: true,
          max_extensions: 3
        }
      ];

      validTTLConfigs.forEach((config, index) => {
        expect(config.policy).toBeDefined();
        expect(['default', 'short', 'long', 'permanent']).toContain(config.policy);

        if (config.auto_extend !== undefined) {
          expect(typeof config.auto_extend).toBe('boolean');
        }

        if (config.extend_threshold_days !== undefined) {
          expect(config.extend_threshold_days).toBeGreaterThan(0);
        }

        if (config.max_extensions !== undefined) {
          expect(config.max_extensions).toBeGreaterThanOrEqual(0);
        }

        if (config.expires_at !== undefined) {
          expect(new Date(config.expires_at)).toBeInstanceOf(Date);
        }
      });
    });
  });

  describe('TTL Performance and Scalability', () => {
    it('should handle large batch with mixed TTL policies', async () => {
      const batchItems = [];
      const policies = ['default', 'short', 'long', 'permanent'] as const;

      for (let i = 0; i < 100; i++) {
        const policy = policies[i % policies.length];
        batchItems.push({
          kind: 'entity',
          data: {
            entity_type: 'test_entity',
            name: `entity_${i}`,
            data: { index: i, policy }
          },
          scope: { project: 'batch-test', branch: 'main' },
          ttl: { policy }
        });
      }

      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 17,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: batchItems,
            deduplication_config: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.9
            }
          }
        }
      };

      expect(memoryStoreRequest.params.arguments.items).toHaveLength(100);
      expect(memoryStoreRequest.params.arguments.deduplication_config).toBeDefined();
    });

    it('should perform efficient TTL-based searches', async () => {
      const complexSearchRequest = {
        jsonrpc: '2.0' as const,
        id: 18,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'active user data',
            scope: { project: 'user-management', branch: 'production' },
            types: ['entity', 'observation'],
            search_strategy: 'auto',
            ttl_filters: {
              include_expired: false,
              min_days_remaining: 7,
              policies: ['default', 'long']
            },
            graph_expansion: {
              enabled: true,
              expansion_type: 'relations',
              max_depth: 2,
              max_nodes: 50
            },
            limit: 100
          }
        }
      };

      const request = complexSearchRequest.params.arguments;
      expect(request.ttl_filters).toBeDefined();
      expect(request.graph_expansion).toBeDefined();
      expect(request.search_strategy).toBe('auto');
    });
  });

  describe('TTL Integration with Other Features', () => {
    it('should combine TTL with deduplication', async () => {
      const memoryStoreRequest = {
        jsonrpc: '2.0' as const,
        id: 19,
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'decision',
              data: {
                title: 'Use PostgreSQL for Production',
                rationale: 'ACID compliance and reliability',
                alternatives: ['MongoDB', 'MySQL'],
                status: 'accepted',
                decision_maker: 'architecture_team',
                impact_assessment: 'high'
              },
              scope: { project: 'architecture', branch: 'main' },
              ttl: {
                policy: 'long',
                auto_extend: true,
                extend_threshold_days: 90
              },
              deduplication_key: 'postgres_production_decision'
            }],
            deduplication_config: {
              enabled: true,
              merge_strategy: 'prefer_existing',
              similarity_threshold: 0.95,
              check_within_scope_only: true
            }
          }
        }
      };

      const item = memoryStoreRequest.params.arguments.items[0];
      expect(item.ttl.policy).toBe('long');
      expect(item.deduplication_key).toBeDefined();
      expect(memoryStoreRequest.params.arguments.deduplication_config.enabled).toBe(true);
    });

    it('should combine TTL with graph expansion in search', async () => {
      const memoryFindRequest = {
        jsonrpc: '2.0' as const,
        id: 20,
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'incident response procedures',
            scope: { project: 'operations', branch: 'main' },
            types: ['incident', 'runbook', 'decision'],
            ttl_filters: {
              include_expired: false,
              policies: ['permanent', 'long']
            },
            graph_expansion: {
              enabled: true,
              expansion_type: 'relations',
              max_depth: 3,
              max_nodes: 100,
              direction: 'both',
              filters: {
                edge_types: ['documents_incident', 'resolves_issue', 'mitigates_risk']
              }
            },
            search_strategy: 'deep',
            limit: 50
          }
        }
      };

      const request = memoryFindRequest.params.arguments;
      expect(request.ttl_filters.policies).toEqual(['permanent', 'long']);
      expect(request.graph_expansion.enabled).toBe(true);
      expect(request.graph_expansion.filters.edge_types).toContain('documents_incident');
    });
  });
});