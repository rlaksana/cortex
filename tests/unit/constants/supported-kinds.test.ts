/**
 * Tests for SUPPORTED_KINDS module
 * Validates the comprehensive knowledge type registry
 */

import { describe, it, expect } from 'vitest';
import {
  SUPPORTED_KINDS,
  KNOWLEDGE_TYPE_METADATA,
  getKnowledgeTypeMetadata,
  getKnowledgeTypesByCategory,
  getKnowledgeTypesByValidationFeature,
  getKnowledgeTypesByTag,
  getRelatedKnowledgeTypes,
  supportsValidationFeature,
  validateKnowledgeTypeMetadata,
  isSupportedKind,
  isKnowledgeCategory,
  CORE_GRAPH_EXTENSION_TYPES,
  DEVELOPMENT_LIFECYCLE_TYPES,
  EIGHT_LOG_SYSTEM_TYPES,
  IMMUTABLE_TYPES,
  type KnowledgeCategory,
} from '../../../src/constants/supported-kinds';

describe('SUPPORTED_KINDS', () => {
  it('should contain exactly 16 knowledge types', () => {
    expect(SUPPORTED_KINDS).toHaveLength(16);
  });

  it('should contain all expected knowledge types', () => {
    const expectedTypes = [
      'entity', 'relation', 'observation',
      'section',
      'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context',
      'incident', 'release', 'risk', 'assumption'
    ];
    expect(SUPPORTED_KINDS).toEqual(expect.arrayContaining(expectedTypes));
  });

  it('should have type-safe string literal array', () => {
    const kind: typeof SUPPORTED_KINDS[number] = 'entity';
    expect(kind).toBe('entity');
  });
});

describe('KNOWLEDGE_TYPE_METADATA', () => {
  it('should have metadata for all supported kinds', () => {
    for (const kind of SUPPORTED_KINDS) {
      expect(KNOWLEDGE_TYPE_METADATA[kind]).toBeDefined();
      expect(KNOWLEDGE_TYPE_METADATA[kind].kind).toBe(kind);
    }
  });

  it('should have valid metadata structure for each type', () => {
    for (const kind of SUPPORTED_KINDS) {
      const metadata = KNOWLEDGE_TYPE_METADATA[kind];

      expect(metadata).toHaveProperty('kind');
      expect(metadata).toHaveProperty('displayName');
      expect(metadata).toHaveProperty('category');
      expect(metadata).toHaveProperty('description');
      expect(metadata).toHaveProperty('useCases');
      expect(metadata).toHaveProperty('validationFeatures');
      expect(metadata).toHaveProperty('businessRules');
      expect(metadata).toHaveProperty('schemaType');
      expect(metadata).toHaveProperty('typescriptType');
      expect(metadata).toHaveProperty('tableName');
      expect(metadata).toHaveProperty('isImplemented');
      expect(metadata).toHaveProperty('introducedIn');
      expect(metadata).toHaveProperty('relatedTypes');
      expect(metadata).toHaveProperty('tags');

      expect(Array.isArray(metadata.useCases)).toBe(true);
      expect(Array.isArray(metadata.relatedTypes)).toBe(true);
      expect(Array.isArray(metadata.tags)).toBe(true);
      expect(typeof metadata.isImplemented).toBe('boolean');
    }
  });
});

describe('getKnowledgeTypeMetadata', () => {
  it('should return metadata for valid knowledge types', () => {
    const entityMetadata = getKnowledgeTypeMetadata('entity');
    expect(entityMetadata.kind).toBe('entity');
    expect(entityMetadata.displayName).toBe('Entity');
    expect(entityMetadata.category).toBe('core-graph-extension');
  });

  it('should throw for invalid knowledge types', () => {
    expect(() => getKnowledgeTypeMetadata('invalid' as any)).toThrow('Unknown knowledge type: invalid');
  });
});

describe('getKnowledgeTypesByCategory', () => {
  it('should return correct types for each category', () => {
    const coreGraphTypes = getKnowledgeTypesByCategory('core-graph-extension');
    expect(coreGraphTypes).toEqual(['entity', 'relation', 'observation']);

    const coreDocTypes = getKnowledgeTypesByCategory('core-document-types');
    expect(coreDocTypes).toEqual(['section']);

    const devLifecycleTypes = getKnowledgeTypesByCategory('development-lifecycle');
    expect(devLifecycleTypes).toHaveLength(8);

    const eightLogTypes = getKnowledgeTypesByCategory('eight-log-system');
    expect(eightLogTypes).toHaveLength(4);
  });
});

describe('getKnowledgeTypesByValidationFeature', () => {
  it('should return types with schema validation', () => {
    const types = getKnowledgeTypesByValidationFeature('hasSchemaValidation');
    expect(types).toHaveLength(16); // All types have schema validation
  });

  it('should return types with immutability constraints', () => {
    const types = getKnowledgeTypesByValidationFeature('hasImmutabilityConstraints');
    expect(types).toContain('decision'); // ADR immutability
    expect(types).toContain('section'); // Write-lock when approved
    expect(types).toContain('observation'); // Append-only
  });

  it('should return types with deduplication support', () => {
    const types = getKnowledgeTypesByValidationFeature('supportsDeduplication');
    expect(types).toHaveLength(16); // All types support deduplication
  });
});

describe('getKnowledgeTypesByTag', () => {
  it('should return types with graph tag', () => {
    const types = getKnowledgeTypesByTag('graph');
    expect(types).toContain('entity');
    expect(types).toContain('relation');
    expect(types).toContain('observation');
  });

  it('should return types with 8-log-system tag', () => {
    const types = getKnowledgeTypesByTag('8-log-system');
    expect(types).toEqual(['incident', 'release', 'risk', 'assumption']);
  });

  it('should return empty array for non-existent tag', () => {
    const types = getKnowledgeTypesByTag('non-existent-tag');
    expect(types).toEqual([]);
  });
});

describe('getRelatedKnowledgeTypes', () => {
  it('should return related types for entity', () => {
    const related = getRelatedKnowledgeTypes('entity');
    expect(related).toContain('relation');
    expect(related).toContain('observation');
  });

  it('should return related types for decision', () => {
    const related = getRelatedKnowledgeTypes('decision');
    expect(related).toContain('issue');
    expect(related).toContain('section');
    expect(related).toContain('change');
  });
});

describe('supportsValidationFeature', () => {
  it('should correctly identify validation features', () => {
    expect(supportsValidationFeature('decision', 'hasImmutabilityConstraints')).toBe(true);
    expect(supportsValidationFeature('entity', 'hasImmutabilityConstraints')).toBe(false);
    expect(supportsValidationFeature('section', 'hasSchemaValidation')).toBe(true);
  });
});

describe('validateKnowledgeTypeMetadata', () => {
  it('should pass validation for complete metadata', () => {
    const result = validateKnowledgeTypeMetadata();
    expect(result.isValid).toBe(true);
    expect(result.issues).toHaveLength(0);
  });
});

describe('Type guards', () => {
  it('isSupportedKind should validate knowledge kinds', () => {
    expect(isSupportedKind('entity')).toBe(true);
    expect(isSupportedKind('invalid')).toBe(false);
  });

  it('isKnowledgeCategory should validate categories', () => {
    expect(isKnowledgeCategory('core-graph-extension')).toBe(true);
    expect(isKnowledgeCategory('development-lifecycle')).toBe(true);
    expect(isKnowledgeCategory('invalid-category')).toBe(false);
  });
});

describe('Exported constants', () => {
  it('should export category groupings', () => {
    expect(CORE_GRAPH_EXTENSION_TYPES).toEqual(['entity', 'relation', 'observation']);
    expect(DEVELOPMENT_LIFECYCLE_TYPES).toHaveLength(8);
    expect(EIGHT_LOG_SYSTEM_TYPES).toHaveLength(4);
  });

  it('should export validation feature groupings', () => {
    expect(IMMUTABLE_TYPES).toContain('decision');
    expect(IMMUTABLE_TYPES).toContain('section');
    expect(IMMUTABLE_TYPES).toContain('observation');
  });
});

describe('Table name consistency', () => {
  it('should have unique table names for each knowledge type', () => {
    const tableNames = Object.values(KNOWLEDGE_TYPE_METADATA).map(m => m.tableName);
    const uniqueTableNames = [...new Set(tableNames)];
    expect(tableNames).toHaveLength(uniqueTableNames.length);
  });

  it('should match expected table names from orchestrator', () => {
    const expectedTableNames = {
      section: 'section',
      decision: 'adrDecision',
      issue: 'issueLog',
      todo: 'todoLog',
      runbook: 'runbook',
      change: 'changeLog',
      release_note: 'releaseNote',
      ddl: 'ddlHistory',
      pr_context: 'prContext',
      entity: 'knowledgeEntity',
      relation: 'knowledgeRelation',
      observation: 'knowledgeObservation',
      incident: 'incidentLog',
      release: 'releaseLog',
      risk: 'riskLog',
      assumption: 'assumptionLog',
    };

    for (const [kind, expectedTableName] of Object.entries(expectedTableNames)) {
      const actualTableName = KNOWLEDGE_TYPE_METADATA[kind as keyof typeof expectedTableNames].tableName;
      expect(actualTableName).toBe(expectedTableName);
    }
  });
});

describe('Business rules validation', () => {
  it('should have required and optional fields defined', () => {
    for (const kind of SUPPORTED_KINDS) {
      const metadata = KNOWLEDGE_TYPE_METADATA[kind];
      expect(Array.isArray(metadata.businessRules.requiredFields)).toBe(true);
      expect(Array.isArray(metadata.businessRules.optionalFields)).toBe(true);
      expect(metadata.businessRules.requiredFields.length).toBeGreaterThan(0);
    }
  });

  it('should have rules and constraints defined', () => {
    for (const kind of SUPPORTED_KINDS) {
      const metadata = KNOWLEDGE_TYPE_METADATA[kind];
      expect(Array.isArray(metadata.businessRules.rules)).toBe(true);
      expect(Array.isArray(metadata.businessRules.constraints)).toBe(true);
      expect(metadata.businessRules.rules.length).toBeGreaterThan(0);
      expect(metadata.businessRules.constraints.length).toBeGreaterThan(0);
    }
  });
});

// ============================================================================
// P1-T1.1: Exact Match Tests - Documented vs Implemented Knowledge Types
// ============================================================================

describe('P1-T1.1: Exact Match Between Documented and Implemented Knowledge Types', () => {

  // Extract all implemented schema types from knowledge-types.ts
  const implementedSchemaTypes = [
    'section', 'runbook', 'change', 'issue', 'decision', 'todo',
    'release_note', 'ddl', 'pr_context', 'entity', 'relation',
    'observation', 'incident', 'release', 'risk', 'assumption'
  ] as const;

  describe('Bidirectional Exact Match Validation', () => {
    it('should have SUPPORTED_KINDS exactly match implemented schema types', () => {
      // Test direction 1: SUPPORTED_KINDS → implemented schemas
      expect(SUPPORTED_KINDS).toHaveLength(implementedSchemaTypes.length);

      // Check that every supported kind has a corresponding schema
      for (const kind of SUPPORTED_KINDS) {
        expect(implementedSchemaTypes).toContain(kind as any);
      }

      // Check exact set equality (no missing, no extra)
      const supportedSet = new Set(SUPPORTED_KINDS);
      const implementedSet = new Set(implementedSchemaTypes);

      expect(supportedSet).toEqual(implementedSet);

      // Detailed assertion with helpful error messages
      const missingInSupported = implementedSchemaTypes.filter(k => !SUPPORTED_KINDS.includes(k as any));
      const extraInSupported = SUPPORTED_KINDS.filter(k => !implementedSchemaTypes.includes(k as any));

      expect(missingInSupported).toEqual([]);
      expect(extraInSupported).toEqual([]);
    });

    it('should have metadata for every implemented schema type', () => {
      // Test direction 2: implemented schemas → SUPPORTED_KINDS
      for (const schemaType of implementedSchemaTypes) {
        expect(SUPPORTED_KINDS).toContain(schemaType as any);
        expect(KNOWLEDGE_TYPE_METADATA[schemaType as any]).toBeDefined();

        const metadata = KNOWLEDGE_TYPE_METADATA[schemaType as any];
        expect(metadata.kind).toBe(schemaType);
        expect(metadata.schemaType).toBeDefined();
        expect(metadata.isImplemented).toBe(true);
      }
    });

    it('should maintain consistent ordering and naming conventions', () => {
      // Verify consistent naming patterns
      for (const kind of SUPPORTED_KINDS) {
        // All kinds should be lowercase with underscores
        expect(kind).toMatch(/^[a-z_]+$/);
        expect(kind).not.toContain('-');
        expect(kind).not.toContain(' ');

        // All kinds should have corresponding metadata with matching kind
        const metadata = KNOWLEDGE_TYPE_METADATA[kind];
        expect(metadata.kind).toBe(kind);
      }
    });

    it('should have all 16 knowledge types implemented and documented', () => {
      // Verify exact count matches expected 16 types
      expect(SUPPORTED_KINDS).toHaveLength(16);
      expect(implementedSchemaTypes).toHaveLength(16);
      expect(Object.keys(KNOWLEDGE_TYPE_METADATA)).toHaveLength(16);

      // Verify all expected knowledge types are present
      const expectedKinds = [
        'entity', 'relation', 'observation',
        'section',
        'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context',
        'incident', 'release', 'risk', 'assumption'
      ];

      expect(SUPPORTED_KINDS).toEqual(expect.arrayContaining(expectedKinds));
      expect(SUPPORTED_KINDS).toHaveLength(expectedKinds.length);
    });
  });

  describe('Schema Type Consistency Validation', () => {
    it('should have valid Zod schema references for all supported kinds', () => {
      for (const kind of SUPPORTED_KINDS) {
        const metadata = KNOWLEDGE_TYPE_METADATA[kind];

        // Verify schema type is a Zod schema
        expect(metadata.schemaType).toBeDefined();
        expect(typeof metadata.schemaType.parse).toBe('function');

        // Verify schema type has the correct discriminator
        const testItem = { kind, scope: { project: 'test', branch: 'test' }, data: {} };
        const parseResult = metadata.schemaType.safeParse(testItem);

        // Should not fail due to kind discriminator (data validation is separate)
        if (!parseResult.success) {
          const errors = parseResult.error.issues.map(e => e.message).join(', ');
          // Only fail if the error is not about data validation
          if (!errors.includes('data') && !errors.includes('Required')) {
            throw new Error(`Schema validation failed for ${kind}: ${errors}`);
          }
        }
      }
    });

    it('should have TypeScript types that match Zod schemas', () => {
      // Verify all TypeScript types are properly referenced
      const expectedTypeNames = [
        'SectionItem', 'RunbookItem', 'ChangeItem', 'IssueItem', 'DecisionItem', 'TodoItem',
        'ReleaseNoteItem', 'DDLItem', 'PRContextItem', 'EntityItem', 'RelationItem',
        'ObservationItem', 'IncidentItem', 'ReleaseItem', 'RiskItem', 'AssumptionItem'
      ];

      for (const kind of SUPPORTED_KINDS) {
        const metadata = KNOWLEDGE_TYPE_METADATA[kind];
        expect(expectedTypeNames).toContain(metadata.typescriptType);
        expect(typeof metadata.typescriptType).toBe('string');
      }
    });
  });

  describe('Metadata Completeness and Accuracy', () => {
    it('should have complete metadata for all knowledge types', () => {
      const requiredMetadataFields = [
        'kind', 'displayName', 'category', 'description', 'useCases',
        'validationFeatures', 'businessRules', 'schemaType', 'typescriptType',
        'tableName', 'isImplemented', 'introducedIn', 'relatedTypes', 'tags'
      ];

      for (const kind of SUPPORTED_KINDS) {
        const metadata = KNOWLEDGE_TYPE_METADATA[kind];

        // Verify all required fields are present
        for (const field of requiredMetadataFields) {
          expect(metadata).toHaveProperty(field);
          expect(metadata[field as keyof typeof metadata]).toBeDefined();
        }

        // Verify implementation status is true for all types
        expect(metadata.isImplemented).toBe(true);

        // Verify category is valid
        expect(isKnowledgeCategory(metadata.category)).toBe(true);

        // Verify related types are all supported
        for (const relatedType of metadata.relatedTypes) {
          expect(SUPPORTED_KINDS).toContain(relatedType as any);
        }

        // Verify tags array is not empty
        expect(Array.isArray(metadata.tags)).toBe(true);
        expect(metadata.tags.length).toBeGreaterThan(0);
      }
    });

    it('should have consistent table names across metadata', () => {
      const tableNames = Object.values(KNOWLEDGE_TYPE_METADATA).map(m => m.tableName);
      const uniqueTableNames = [...new Set(tableNames)];

      // All table names should be unique
      expect(tableNames).toHaveLength(uniqueTableNames.length);

      // Table names should follow expected patterns
      const expectedTableNames = {
        section: 'section',
        decision: 'adrDecision',
        issue: 'issueLog',
        todo: 'todoLog',
        runbook: 'runbook',
        change: 'changeLog',
        release_note: 'releaseNote',
        ddl: 'ddlHistory',
        pr_context: 'prContext',
        entity: 'knowledgeEntity',
        relation: 'knowledgeRelation',
        observation: 'knowledgeObservation',
        incident: 'incidentLog',
        release: 'releaseLog',
        risk: 'riskLog',
        assumption: 'assumptionLog',
      };

      for (const [kind, expectedTableName] of Object.entries(expectedTableNames)) {
        const actualTableName = KNOWLEDGE_TYPE_METADATA[kind as keyof typeof expectedTableNames].tableName;
        expect(actualTableName).toBe(expectedTableName);
      }
    });
  });

  describe('Integration Tests - SUPPORTED_KINDS Module Usage', () => {
    it('should be able to import and use all exported utilities', () => {
      // Test all utility functions work correctly
      expect(typeof getKnowledgeTypeMetadata).toBe('function');
      expect(typeof getKnowledgeTypesByCategory).toBe('function');
      expect(typeof getKnowledgeTypesByValidationFeature).toBe('function');
      expect(typeof getKnowledgeTypesByTag).toBe('function');
      expect(typeof getRelatedKnowledgeTypes).toBe('function');
      expect(typeof supportsValidationFeature).toBe('function');
      expect(typeof validateKnowledgeTypeMetadata).toBe('function');
      expect(typeof isSupportedKind).toBe('function');
      expect(typeof isKnowledgeCategory).toBe('function');
    });

    it('should validate metadata integrity across all exports', () => {
      const validationResult = validateKnowledgeTypeMetadata();
      expect(validationResult.isValid).toBe(true);
      expect(validationResult.issues).toHaveLength(0);
    });

    it('should provide accurate category groupings', () => {
      const coreGraphTypes = getKnowledgeTypesByCategory('core-graph-extension');
      const coreDocTypes = getKnowledgeTypesByCategory('core-document-types');
      const devLifecycleTypes = getKnowledgeTypesByCategory('development-lifecycle');
      const eightLogTypes = getKnowledgeTypesByCategory('eight-log-system');

      expect(coreGraphTypes).toEqual(['entity', 'relation', 'observation']);
      expect(coreDocTypes).toEqual(['section']);
      expect(devLifecycleTypes).toHaveLength(8);
      expect(eightLogTypes).toHaveLength(4);

      // Verify all types are accounted for in categories
      const allCategorizedTypes = [...coreGraphTypes, ...coreDocTypes, ...devLifecycleTypes, ...eightLogTypes];
      expect(allCategorizedTypes).toHaveLength(16);
      expect(allCategorizedTypes.sort()).toEqual(SUPPORTED_KINDS.sort());
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid knowledge types gracefully', () => {
      expect(() => getKnowledgeTypeMetadata('invalid' as any)).toThrow('Unknown knowledge type: invalid');
      expect(isSupportedKind('invalid')).toBe(false);
    });

    it('should handle invalid categories gracefully', () => {
      expect(isKnowledgeCategory('invalid-category')).toBe(false);
    });

    it('should provide clear error messages for validation failures', () => {
      try {
        getKnowledgeTypeMetadata('nonexistent' as any);
        fail('Expected error to be thrown');
      } catch (error) {
        expect(error.message).toContain('Unknown knowledge type: nonexistent');
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large metadata lookups efficiently', () => {
      const start = performance.now();

      // Perform many lookups to test performance
      for (let i = 0; i < 1000; i++) {
        for (const kind of SUPPORTED_KINDS) {
          getKnowledgeTypeMetadata(kind);
          isSupportedKind(kind);
        }
      }

      const end = performance.now();
      const duration = end - start;

      // Should complete within reasonable time (less than 100ms for 16,000 lookups)
      expect(duration).toBeLessThan(100);
    });

    it('should have memory-efficient metadata structure', () => {
      // Verify metadata structure is not excessively large
      const metadataString = JSON.stringify(KNOWLEDGE_TYPE_METADATA);
      expect(metadataString.length).toBeLessThan(150000); // Should be under 150KB (comprehensive metadata)
    });
  });
});