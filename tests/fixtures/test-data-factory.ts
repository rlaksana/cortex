/**
 * Test Data Factory for mcp__cortex Knowledge Items
 *
 * Provides systematic generation of test data for all 16 knowledge types
 * across various scenarios: minimal, complete, edge cases, and stress testing
 */

import type { KnowledgeItem } from '../../src/types/core-interfaces';

// ============================================================================
// Knowledge Type Definitions
// ============================================================================

export const KNOWLEDGE_TYPES = [
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
] as const;

export type KnowledgeType = (typeof KNOWLEDGE_TYPES)[number];

// ============================================================================
// Test Data Generators by Knowledge Type
// ============================================================================

/**
 * Generate minimal valid test data for a knowledge type
 */
export function generateMinimalItem(type: KnowledgeType, overrides: Partial<any> = {}): any {
  const baseItems = {
    entity: { kind: 'entity', content: 'Test entity' },
    relation: { kind: 'relation', content: 'Test relationship between A and B' },
    observation: { kind: 'observation', content: 'Test observation noted' },
    section: { kind: 'section', content: 'Test section content' },
    runbook: { kind: 'runbook', content: 'Test runbook procedure' },
    change: { kind: 'change', content: 'Test change description' },
    issue: { kind: 'issue', content: 'Test issue description' },
    decision: { kind: 'decision', content: 'Test decision made' },
    todo: { kind: 'todo', content: 'Test todo item' },
    release_note: { kind: 'release_note', content: 'Test release notes' },
    ddl: { kind: 'ddl', content: 'Test DDL statement' },
    pr_context: { kind: 'pr_context', content: 'Test PR context' },
    incident: { kind: 'incident', content: 'Test incident report' },
    release: { kind: 'release', content: 'Test release information' },
    risk: { kind: 'risk', content: 'Test risk assessment' },
    assumption: { kind: 'assumption', content: 'Test assumption noted' },
  };

  return { ...baseItems[type], ...overrides };
}

/**
 * Generate complete test data with all optional fields
 */
export function generateCompleteItem(type: KnowledgeType, overrides: Partial<any> = {}): any {
  const minimal = generateMinimalItem(type);

  const completeItems = {
    entity: {
      ...minimal,
      metadata: {
        type: 'person',
        attributes: { name: 'John Doe', email: 'john@example.com' },
        created_by: 'test-user',
        tags: ['important', 'test'],
      },
      scope: {
        project: 'test-project',
        branch: 'main',
        org: 'test-org',
      },
    },
    relation: {
      ...minimal,
      metadata: {
        source: 'entity-a',
        target: 'entity-b',
        relationship_type: 'depends_on',
        strength: 0.8,
        bidirectional: false,
      },
      scope: {
        project: 'test-project',
        branch: 'feature/relations',
      },
    },
    observation: {
      ...minimal,
      metadata: {
        observer: 'test-user',
        timestamp: '2025-10-30T13:00:00Z',
        context: 'code-review',
        severity: 'medium',
        category: 'performance',
      },
      scope: {
        project: 'test-project',
        org: 'test-org',
      },
    },
    section: {
      ...minimal,
      metadata: {
        title: 'Test Section Title',
        level: 2,
        parent_section: 'root',
        order: 1,
        tags: ['documentation', 'getting-started'],
      },
      scope: {
        project: 'docs-project',
        branch: 'main',
      },
    },
    runbook: {
      ...minimal,
      metadata: {
        title: 'Deployment Runbook',
        category: 'operations',
        complexity: 'medium',
        estimated_time: '30 minutes',
        prerequisites: ['access-to-production', 'ssh-keys'],
        steps: [
          { step: 1, action: 'backup-database', description: 'Create database backup' },
          { step: 2, action: 'deploy-code', description: 'Deploy new code version' },
        ],
      },
      scope: {
        project: 'ops-project',
        org: 'test-org',
      },
    },
    change: {
      ...minimal,
      metadata: {
        change_type: 'feature',
        impact: 'medium',
        risk_level: 'low',
        approvers: ['team-lead', 'product-manager'],
        rollback_plan: 'Revert to previous commit if issues arise',
        testing_required: true,
      },
      scope: {
        project: 'test-project',
        branch: 'feature/new-feature',
      },
    },
    issue: {
      ...minimal,
      metadata: {
        severity: 'high',
        priority: 'urgent',
        category: 'bug',
        reporter: 'test-user',
        assignee: 'developer-1',
        environment: 'production',
        steps_to_reproduce: ['Step 1', 'Step 2', 'Step 3'],
        expected_behavior: 'System should work correctly',
        actual_behavior: 'System shows error',
      },
      scope: {
        project: 'test-project',
        org: 'test-org',
      },
    },
    decision: {
      ...minimal,
      metadata: {
        decision_type: 'technical',
        alternatives: ['Option A', 'Option B', 'Option C'],
        chosen_alternative: 'Option B',
        rationale: 'Best performance and maintainability',
        impact: 'Medium - requires refactoring existing code',
        expiration_date: '2025-12-31T23:59:59Z',
        decision_maker: 'tech-lead',
      },
      scope: {
        project: 'architecture-project',
        branch: 'main',
      },
    },
    todo: {
      ...minimal,
      metadata: {
        priority: 'high',
        status: 'pending',
        assignee: 'developer-1',
        due_date: '2025-11-15T23:59:59Z',
        estimated_hours: 4,
        tags: ['frontend', 'urgent'],
        dependencies: ['task-123', 'task-456'],
      },
      scope: {
        project: 'sprint-23',
        org: 'test-org',
      },
    },
    release_note: {
      ...minimal,
      metadata: {
        version: 'v2.1.0',
        release_date: '2025-10-30T13:00:00Z',
        features: ['New authentication system', 'Performance improvements'],
        bug_fixes: ['Fixed memory leak', 'Resolved timeout issues'],
        breaking_changes: ['API endpoint modification'],
        upgrade_instructions: 'Run migration script before upgrading',
      },
      scope: {
        project: 'product-releases',
        branch: 'release/v2.1.0',
      },
    },
    ddl: {
      ...minimal,
      metadata: {
        operation_type: 'create_table',
        table_name: 'users',
        database: 'production',
        rollback_script: 'DROP TABLE users;',
        impact_assessment: 'No data loss expected',
        execution_time: '2 minutes',
      },
      scope: {
        project: 'database-project',
        org: 'test-org',
      },
    },
    pr_context: {
      ...minimal,
      metadata: {
        pr_number: 1234,
        title: 'Add user authentication feature',
        author: 'developer-1',
        reviewers: ['tech-lead', 'security-expert'],
        files_changed: 15,
        lines_added: 200,
        lines_removed: 50,
        automated_checks_passed: true,
      },
      scope: {
        project: 'main-repo',
        branch: 'feature/auth',
      },
    },
    incident: {
      ...minimal,
      metadata: {
        incident_id: 'INC-2025-001',
        severity: 'critical',
        impact: 'high',
        status: 'resolved',
        start_time: '2025-10-30T10:00:00Z',
        end_time: '2025-10-30T12:30:00Z',
        root_cause: 'Database connection pool exhaustion',
        resolution: 'Increased connection pool size',
        affected_services: ['api', 'web-app'],
      },
      scope: {
        project: 'production-infra',
        org: 'test-org',
      },
    },
    release: {
      ...minimal,
      metadata: {
        version: 'v2.1.0',
        release_date: '2025-10-30T13:00:00Z',
        environment: 'production',
        deployment_strategy: 'blue-green',
        rollback_available: true,
        build_number: 'build-456',
        artifacts: ['app.jar', 'config.yml'],
        release_manager: 'ops-lead',
      },
      scope: {
        project: 'product-releases',
        branch: 'release/v2.1.0',
      },
    },
    risk: {
      ...minimal,
      metadata: {
        risk_level: 'high',
        category: 'security',
        probability: 'medium',
        impact: 'critical',
        mitigation_plan: 'Implement rate limiting and monitoring',
        risk_owner: 'security-team',
        review_date: '2025-11-30T23:59:59Z',
        related_threats: ['data-breach', 'service-disruption'],
      },
      scope: {
        project: 'security-assessment',
        org: 'test-org',
      },
    },
    assumption: {
      ...minimal,
      metadata: {
        assumption_type: 'technical',
        confidence_level: 'high',
        validation_required: true,
        validation_method: 'load testing',
        impact_if_invalid: 'High - requires redesign',
        made_by: 'architecture-team',
        review_date: '2025-12-01T23:59:59Z',
      },
      scope: {
        project: 'architecture-project',
        branch: 'main',
      },
    },
  };

  return { ...completeItems[type], ...overrides };
}

// ============================================================================
// Batch Test Data Generators
// ============================================================================

/**
 * Generate items for all knowledge types with minimal data
 */
export function generateMinimalItems(overrides: Record<KnowledgeType, Partial<any>> = {}): any[] {
  return KNOWLEDGE_TYPES.map((type) => generateMinimalItem(type, overrides[type]));
}

/**
 * Generate items for all knowledge types with complete data
 */
export function generateCompleteItems(overrides: Record<KnowledgeType, Partial<any>> = {}): any[] {
  return KNOWLEDGE_TYPES.map((type) => generateCompleteItem(type, overrides[type]));
}

/**
 * Generate items with specific scope variations
 */
export function generateScopedItems(
  scopeType: 'project-only' | 'branch-only' | 'org-only' | 'complete'
): any[] {
  const scopeOverrides = {
    'project-only': { scope: { project: 'test-project' } },
    'branch-only': { scope: { branch: 'feature-branch' } },
    'org-only': { scope: { org: 'test-org' } },
    complete: { scope: { project: 'test-project', branch: 'main', org: 'test-org' } },
  };

  return KNOWLEDGE_TYPES.map((type) => generateCompleteItem(type, scopeOverrides[scopeType]));
}

// ============================================================================
// Edge Case and Stress Test Data
// ============================================================================

/**
 * Generate edge case items for boundary testing
 */
export function generateEdgeCaseItems(): any[] {
  return [
    // Empty content
    generateMinimalItem('entity', { content: '' }),

    // Very long content
    generateMinimalItem('observation', {
      content: 'A'.repeat(1000),
    }),

    // Special characters and Unicode
    generateMinimalItem('issue', {
      content: 'Issue with émojis 🚨 and spëcial chars & symbols @#$%^&*()',
    }),

    // Large metadata object
    generateMinimalItem('runbook', {
      metadata: {
        largeArray: Array.from({ length: 100 }, (_, i) => ({ step: i, action: `action-${i}` })),
        nestedObject: { level1: { level2: { level3: { deep: 'value' } } } },
      },
    }),

    // Null/undefined metadata
    generateMinimalItem('decision', { metadata: null }),

    // Empty scope
    generateMinimalItem('todo', { scope: {} }),

    // All knowledge types with invalid data (for error testing)
    ...KNOWLEDGE_TYPES.map((type) => ({
      kind: type,
      content: null, // Invalid content
      metadata: 'not-an-object', // Invalid metadata type
    })),
  ];
}

/**
 * Generate stress test data (many items)
 */
export function generateStressTestItems(count: number = 100): any[] {
  const items: any[] = [];

  for (let i = 0; i < count; i++) {
    const type = KNOWLEDGE_TYPES[i % KNOWLEDGE_TYPES.length];
    const item = generateCompleteItem(type, {
      content: `Stress test item ${i} of type ${type}`,
      metadata: { testIndex: i, batchId: 'stress-test-batch' },
    });
    items.push(item);
  }

  return items;
}

// ============================================================================
// Search Test Data
// ============================================================================

/**
 * Generate items with known content for search testing
 */
export function generateSearchTestData(): any[] {
  return [
    generateCompleteItem('entity', {
      content: 'User authentication system with OAuth2 integration',
    }),
    generateCompleteItem('observation', {
      content: 'Noticed slow response times during peak hours',
    }),
    generateCompleteItem('decision', {
      content: 'Decided to use PostgreSQL instead of MongoDB for better consistency',
    }),
    generateCompleteItem('issue', {
      content: 'Critical bug: Memory leak causing server crashes',
    }),
    generateCompleteItem('runbook', {
      content: 'Emergency restart procedure for production services',
    }),
    generateCompleteItem('risk', {
      content: 'Security risk: Potential SQL injection vulnerability in API',
    }),
    generateCompleteItem('change', {
      content: 'Database schema migration to add user preferences table',
    }),
    generateCompleteItem('release_note', {
      content: 'Version 2.1.0: New authentication system and performance improvements',
    }),
  ];
}

// ============================================================================
// Export Utility Functions
// ============================================================================

/**
 * Get random knowledge type
 */
export function getRandomKnowledgeType(): KnowledgeType {
  return KNOWLEDGE_TYPES[Math.floor(Math.random() * KNOWLEDGE_TYPES.length)];
}

/**
 * Generate random item
 */
export function generateRandomItem(complete: boolean = true): any {
  const type = getRandomKnowledgeType();
  return complete ? generateCompleteItem(type) : generateMinimalItem(type);
}

/**
 * Validate test item structure
 */
export function validateTestItem(item: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!item || typeof item !== 'object') {
    errors.push('Item must be an object');
    return { valid: false, errors };
  }

  if (!item.kind || typeof item.kind !== 'string') {
    errors.push('Item must have a valid kind field');
  }

  if (!KNOWLEDGE_TYPES.includes(item.kind)) {
    errors.push(`Invalid knowledge type: ${item.kind}`);
  }

  if (!item.content || typeof item.content !== 'string') {
    errors.push('Item must have a valid content field');
  }

  if (item.scope && typeof item.scope !== 'object') {
    errors.push('Scope must be an object if provided');
  }

  if (item.metadata && typeof item.metadata !== 'object') {
    errors.push('Metadata must be an object if provided');
  }

  return { valid: errors.length === 0, errors };
}

export default {
  KNOWLEDGE_TYPES,
  generateMinimalItem,
  generateCompleteItem,
  generateMinimalItems,
  generateCompleteItems,
  generateScopedItems,
  generateEdgeCaseItems,
  generateStressTestItems,
  generateSearchTestData,
  getRandomKnowledgeType,
  generateRandomItem,
  validateTestItem,
};
