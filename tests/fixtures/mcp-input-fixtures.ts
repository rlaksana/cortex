/**
 * MCP Input Test Fixtures - T22 Support
 *
 * Provides valid and invalid input fixtures for comprehensive API contract testing.
 * Includes edge cases, boundary conditions, and error scenarios.
 *
 * @version 2.0.1
 */

import { MemoryKind } from '../../src/types/knowledge-data.js';

// ============================================================================
// Valid Input Fixtures
// ============================================================================

export function createValidMemoryStoreInput() {
  return {
    items: [
      {
        kind: 'entity' as MemoryKind,
        content: 'Test entity for API contract testing',
        data: {
          name: 'TestEntity',
          type: 'component',
          description: 'Entity for testing API contracts',
        },
      },
      {
        kind: 'decision' as MemoryKind,
        content: 'Architecture decision to use TypeScript',
        data: {
          title: 'Use TypeScript for type safety',
          rationale: 'Provides compile-time type checking',
          alternatives: ['JavaScript', 'Flow'],
          impact: 'medium',
        },
      },
    ],
    deduplication: {
      enabled: true,
      merge_strategy: 'intelligent',
      similarity_threshold: 0.85,
      check_within_scope_only: true,
      max_history_hours: 168,
      dedupe_window_days: 30,
      allow_newer_versions: true,
      enable_audit_logging: true,
    },
    global_ttl: {
      policy: 'default',
      auto_extend: false,
      extend_threshold_days: 7,
      max_extensions: 3,
    },
    global_truncation: {
      enabled: true,
      max_chars: 50000,
      truncate_strategy: 'smart',
      preserve_structure: true,
    },
    scope: {
      project: 'cortex-memory-mcp',
      branch: 'main',
      org: 'cortex-ai',
    },
    insights: {
      generate: false,
      include_similarity: true,
      include_connections: true,
    },
  };
}

export function createValidMemoryFindInput() {
  return {
    query: 'TypeScript architecture decisions',
    scope: {
      project: 'cortex-memory-mcp',
      branch: 'main',
      org: 'cortex-ai',
    },
    search_strategy: 'auto',
    result_format: 'detailed',
    limit: 50,
    ttl_filter: {
      active_only: true,
      include_expired: false,
    },
    kinds: ['decision', 'entity'],
    confidence_threshold: 0.7,
    include_metadata: true,
    expand_relations: true,
    max_expansion_depth: 2,
  };
}

// ============================================================================
// Invalid Input Fixtures
// ============================================================================

export function createInvalidMemoryStoreInput() {
  return [
    // Missing required fields
    {
      // Missing 'items' field
      deduplication: { enabled: true },
    },

    // Invalid items array
    {
      items: 'not an array', // Should be array
    },

    {
      items: [], // Empty array (minItems: 1)
    },

    {
      items: [
        {
          // Missing required 'kind' field
          content: 'Entity without kind',
        },
      ],
    },

    {
      items: [
        {
          kind: 'invalid_kind', // Invalid enum value
          content: 'Entity with invalid kind',
        },
      ],
    },

    {
      items: [
        {
          kind: 'entity',
          content: '', // Empty string (minLength: 1)
        },
      ],
    },

    {
      items: [
        {
          kind: 'entity',
          content: 'x'.repeat(100001), // Too long (maxLength: 100000)
        },
      ],
    },

    // Invalid deduplication config
    {
      items: [
        {
          kind: 'entity',
          content: 'Valid entity',
        },
      ],
      deduplication: {
        enabled: true,
        merge_strategy: 'invalid_strategy', // Invalid enum
      },
    },

    {
      items: [
        {
          kind: 'entity',
          content: 'Valid entity',
        },
      ],
      deduplication: {
        enabled: true,
        similarity_threshold: 1.5, // Out of range [0.1, 1.0]
      },
    },

    // Invalid TTL config
    {
      items: [
        {
          kind: 'entity',
          content: 'Valid entity',
        },
      ],
      global_ttl: {
        policy: 'invalid_policy', // Invalid enum
      },
    },

    // Invalid truncation config
    {
      items: [
        {
          kind: 'entity',
          content: 'Valid entity',
        },
      ],
      global_truncation: {
        enabled: true,
        max_chars: 50, // Below minimum (100)
      },
    },

    // Too many items
    {
      items: Array(101).fill(null).map((_, i) => ({
        kind: 'entity' as MemoryKind,
        content: `Entity ${i}`,
      })),
    },
  ];
}

export function createInvalidMemoryFindInput() {
  return [
    // Missing required fields
    {}, // Missing 'query'

    { query: '' }, // Empty query
    { query: null }, // Null query
    { query: undefined }, // Undefined query

    // Invalid query
    { query: 'x'.repeat(1001) }, // Too long (maxLength: 1000)
    { query: 123 }, // Wrong type
    { query: [] }, // Wrong type

    // Invalid search strategy
    {
      query: 'valid query',
      search_strategy: 'invalid_strategy',
    },

    // Invalid result format
    {
      query: 'valid query',
      result_format: 'invalid_format',
    },

    // Invalid limit
    {
      query: 'valid query',
      limit: 0, // Below minimum (1)
    },
    {
      query: 'valid query',
      limit: 1001, // Above maximum (1000)
    },
    {
      query: 'valid query',
      limit: -10, // Negative
    },

    // Invalid confidence threshold
    {
      query: 'valid query',
      confidence_threshold: -0.1, // Below minimum (0)
    },
    {
      query: 'valid query',
      confidence_threshold: 1.1, // Above maximum (1)
    },

    // Invalid max_expansion_depth
    {
      query: 'valid query',
      max_expansion_depth: -1, // Negative
    },
    {
      query: 'valid query',
      max_expansion_depth: 11, // Above maximum (10)
    },

    // Invalid kinds array
    {
      query: 'valid query',
      kinds: ['invalid_kind'], // Invalid enum value
    },

    // Invalid scope
    {
      query: 'valid query',
      scope: 'not an object', // Should be object
    },
  ];
}

// ============================================================================
// Edge Case Fixtures
// ============================================================================

export function createEdgeCaseInputs() {
  return {
    memoryStore: [
      // Single item
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Single entity',
          },
        ],
      },

      // Maximum allowed items (100)
      {
        items: Array(100).fill(null).map((_, i) => ({
          kind: 'entity' as MemoryKind,
          content: `Entity ${i}`,
          data: { index: i },
        })),
      },

      // Maximum length content
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'x'.repeat(100000), // At maximum length
          },
        ],
      },

      // Minimum length content
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'x', // Single character
          },
        ],
      },

      // All 16 knowledge types
      {
        items: [
          'entity', 'relation', 'observation', 'section', 'runbook',
          'change', 'issue', 'decision', 'todo', 'release_note',
          'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
        ].map((kind, index) => ({
          kind: kind as MemoryKind,
          content: `Content for ${kind} type`,
          data: { type: kind, index },
        })),
      },

      // Complex nested data
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Complex entity',
            data: {
              nested: {
                deep: {
                  value: 'deeply nested value',
                  array: [1, 2, 3, { object: 'in array' }],
                },
              },
              metadata: {
                tags: ['tag1', 'tag2', 'tag3'],
                timestamps: {
                  created: new Date().toISOString(),
                  updated: new Date().toISOString(),
                },
              },
            },
          },
        ],
      },

      // Special characters and Unicode
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Test with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?~`',
          },
          {
            kind: 'entity' as MemoryKind,
            content: 'Test with Unicode: 🧠 Cortex Memory, 中文测试, العربية, हिन्दी',
          },
          {
            kind: 'entity' as MemoryKind,
            content: 'Test with newlines\nand\ttabs\r\nand carriage returns',
          },
        ],
      },

      // Edge case deduplication settings
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Entity for edge case deduplication',
          },
        ],
        deduplication: {
          enabled: true,
          merge_strategy: 'skip',
          similarity_threshold: 0.1, // Minimum threshold
          max_history_hours: 1, // Minimum hours
          dedupe_window_days: 1, // Minimum days
          max_items_to_check: 1, // Minimum items
          batch_size: 1, // Minimum batch size
        },
      },

      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Entity for max edge case deduplication',
          },
        ],
        deduplication: {
          enabled: true,
          merge_strategy: 'combine',
          similarity_threshold: 1.0, // Maximum threshold
          max_history_hours: 8760, // Maximum hours (1 year)
          dedupe_window_days: 365, // Maximum days
          max_items_to_check: 10000, // Maximum items
          batch_size: 1000, // Maximum batch size
        },
      },

      // Edge case TTL settings
      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Entity with permanent TTL',
          },
        ],
        global_ttl: {
          policy: 'permanent',
          auto_extend: false,
        },
      },

      {
        items: [
          {
            kind: 'entity' as MemoryKind,
            content: 'Entity with future expiry',
          },
        ],
        global_ttl: {
          expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days from now
        },
      },
    ],

    memoryFind: [
      // Minimum query length
      { query: 'x' },

      // Maximum query length
      { query: 'x'.repeat(1000) },

      // Special characters in query
      { query: 'Search with special chars: !@#$%^&*()' },

      // Unicode in query
      { query: 'Search with Unicode: 🧠 中文测试' },

      // Minimum limit
      { query: 'test query', limit: 1 },

      // Maximum limit
      { query: 'test query', limit: 1000 },

      // Minimum confidence threshold
      { query: 'test query', confidence_threshold: 0 },

      // Maximum confidence threshold
      { query: 'test query', confidence_threshold: 1 },

      // All search strategies
      { query: 'test', search_strategy: 'fast' },
      { query: 'test', search_strategy: 'auto' },
      { query: 'test', search_strategy: 'deep' },

      // All result formats
      { query: 'test', result_format: 'detailed' },
      { query: 'test', result_format: 'summary' },
      { query: 'test', result_format: 'compact' },

      // Complex scope
      {
        query: 'test',
        scope: {
          org: 'cortex-ai',
          project: 'cortex-memory-mcp',
          branch: 'feature/complex-testing',
        },
      },

      // All kinds
      {
        query: 'test',
        kinds: [
          'entity', 'relation', 'observation', 'section', 'runbook',
          'change', 'issue', 'decision', 'todo', 'release_note',
          'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
        ],
      },

      // Maximum expansion depth
      { query: 'test', max_expansion_depth: 10 },

      // Complex TTL filter
      {
        query: 'test',
        ttl_filter: {
          active_only: true,
          include_expired: false,
          min_ttl_hours: 1,
          max_ttl_hours: 8760,
        },
      },
    ],
  };
}

// ============================================================================
// Boundary Condition Fixtures
// ============================================================================

export function createBoundaryConditionInputs() {
  return {
    // Numeric boundaries
    numeric: {
      similarity_threshold: [0.1, 0.5, 0.85, 1.0],
      max_history_hours: [1, 168, 8760],
      dedupe_window_days: [1, 30, 365],
      limit: [1, 50, 1000],
      confidence_threshold: [0, 0.5, 0.9, 1.0],
      max_expansion_depth: [0, 5, 10],
    },

    // String boundaries
    string: {
      minLength: ['x'],
      maxLength: ['x'.repeat(100000)],
      specialChars: ['!@#$%^&*()', '🧠', '中文测试', '\n\t\r'],
    },

    // Array boundaries
    array: {
      minItems: [Array(1)],
      maxItems: [Array(100)],
      emptyArrays: [[]],
    },
  };
}

// ============================================================================
// Error Scenario Fixtures
// ============================================================================

export function createErrorScenarioInputs() {
  return {
    // Malformed inputs
    malformed: [
      null,
      undefined,
      'string instead of object',
      123,
      [],
      { invalidField: 'value' },
    ],

    // Type mismatches
    typeMismatches: [
      { items: 'string instead of array' },
      { items: [123] }, // Number instead of object
      { query: [] }, // Array instead of string
      { scope: 'string instead of object' },
    ],

    // Constraint violations
    constraintViolations: [
      { items: Array(101).fill({ kind: 'entity', content: 'test' }) }, // Too many items
      { query: 'x'.repeat(1001) }, // Query too long
      { limit: 0 }, // Limit too small
      { confidence_threshold: 1.1 }, // Threshold too high
    ],
  };
}

// ============================================================================
// Performance Test Fixtures
// ============================================================================

export function createPerformanceTestInputs() {
  return {
    // Large batch operations
    largeBatch: {
      memoryStore: {
        items: Array(100).fill(null).map((_, i) => ({
          kind: 'entity' as MemoryKind,
          content: `Performance test entity ${i}`,
          data: {
            index: i,
            timestamp: new Date().toISOString(),
            metadata: {
              tags: [`tag-${i % 10}`, `category-${i % 5}`],
              size: Math.floor(Math.random() * 1000),
            },
          },
        })),
      },
    },

    // Complex queries
    complexQueries: [
      {
        query: 'complex multi-word search with various terms and concepts',
        scope: {
          org: 'test-org',
          project: 'test-project',
          branch: 'main',
        },
        search_strategy: 'deep',
        result_format: 'detailed',
        limit: 100,
        kinds: ['entity', 'decision', 'issue'],
        confidence_threshold: 0.7,
        include_metadata: true,
        expand_relations: true,
        max_expansion_depth: 3,
      },
    ],
  };
}

// ============================================================================
// Integration Test Fixtures
// ============================================================================

export function createIntegrationTestFixtures() {
  return {
    // Store then find workflow
    storeAndFind: {
      store: createValidMemoryStoreInput(),
      findQuery: 'test entity or decision',
    },

    // Multi-scope operations
    multiScope: {
      scopes: [
        { project: 'project-a', branch: 'main' },
        { project: 'project-b', branch: 'develop' },
        { org: 'org-a', project: 'project-c', branch: 'feature/test' },
      ],
    },

    // Cross-tool workflows
    crossTool: {
      storeMultiple: [
        createValidMemoryStoreInput(),
        createValidMemoryStoreInput(),
        createValidMemoryStoreInput(),
      ],
      findWithFilters: {
        query: 'test',
        kinds: ['entity', 'decision'],
        scope: { project: 'integration-test' },
      },
    },
  };
}