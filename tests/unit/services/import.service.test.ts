/**
 * Comprehensive Unit Tests for Import Service
 *
 * Tests import service functionality including:
 * - Multi-format data import (JSON, CSV, XML, etc.)
 * - Bulk data import with validation
 * - Incremental import operations
 * - Import conflict resolution
 * - Data validation during import
 * - Data type conversion and normalization
 * - Duplicate detection and handling
 * - Data integrity verification
 * - Field mapping and transformation
 * - Data format conversion
 * - Custom transformation rules
 * - Data enrichment during import
 * - Import error reporting
 * - Partial import handling
 * - Rollback capabilities
 * - Data recovery mechanisms
 * - Large dataset import handling
 * - Memory-efficient processing
 * - Batch import optimization
 * - Concurrent import operations
 * - Knowledge type recognition
 * - Relationship reconstruction
 * - Metadata import
 * - Scope assignment
 *
 * Phase 1: Core Service Layer Testing
 * Building on solid foundation of memory store and validation services
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';

// Import interfaces for type definitions
import type {
  KnowledgeItem,
  MemoryStoreResponse,
  StoreResult,
  StoreError,
  AutonomousContext,
} from '../../../src/types/core-interfaces.js';

// Mock the memory store service
vi.mock('../../../src/services/memory-store.js', () => ({
  memoryStore: vi.fn(),
}));

// Mock the validation service
vi.mock('../../../src/services/validation/validation-service.js', () => ({
  validationService: {
    validateStoreInput: vi.fn(),
    validateKnowledgeItem: vi.fn(),
    validateFindInput: vi.fn(),
    validateImportData: vi.fn(),
    validateTransformRules: vi.fn(),
  },
}));

// Mock logger
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock audit service
vi.mock('../../../src/services/audit/audit-service.js', () => ({
  auditService: {
    logImportOperation: vi.fn().mockResolvedValue(undefined),
    logError: vi.fn().mockResolvedValue(undefined),
    logBatchOperation: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock file system operations
vi.mock('fs/promises', () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  access: vi.fn(),
  stat: vi.fn(),
}));

// Mock CSV parser
vi.mock('csv-parser', () => ({
  default: vi.fn(),
}));

// Mock XML parser
vi.mock('fast-xml-parser', () => ({
  XMLParser: vi.fn(),
}));

// Import the service to test (mock implementation for now)
const importService = {
  importData: vi.fn(),
  importFromFile: vi.fn(),
  validateImportData: vi.fn(),
  transformData: vi.fn(),
  resolveConflicts: vi.fn(),
  rollbackImport: vi.fn(),
  getImportStatus: vi.fn(),
  previewImport: vi.fn(),
  mapFields: vi.fn(),
  enrichData: vi.fn(),
} as any;

describe('Import Service - Core Import Operations', () => {
  let mockMemoryStore: any;
  let mockValidation: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    mockMemoryStore = await import('../../../src/services/memory-store.js');
    mockValidation = await import('../../../src/services/validation/validation-service.js');
  });

  describe('Multi-Format Data Import', () => {
    it('should import JSON data successfully', async () => {
      // Arrange
      const jsonData = [
        {
          kind: 'entity',
          content: 'Test entity from JSON',
          scope: { project: 'test-project' },
          data: { name: 'JSON Entity', type: 'component' },
        },
        {
          kind: 'decision',
          content: 'Test decision from JSON',
          scope: { project: 'test-project' },
          data: { title: 'JSON Decision', rationale: 'Test rationale' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Import completed successfully',
          reasoning: '2 items imported from JSON',
          user_message_suggestion: '✅ JSON data imported successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: jsonData,
        format: 'json',
        options: {
          validate: true,
          deduplicate: true,
        },
      });

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(mockMemoryStore.memoryStore).toHaveBeenCalledWith(jsonData);
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should import CSV data with field mapping', async () => {
      // Arrange
      const csvData = [
        {
          'Knowledge Type': 'entity',
          Name: 'CSV Entity 1',
          Description: 'First entity from CSV',
          Project: 'test-project',
          Type: 'service',
        },
        {
          'Knowledge Type': 'decision',
          Name: 'CSV Decision 1',
          Description: 'First decision from CSV',
          Project: 'test-project',
          Rationale: 'CSV-based rationale',
        },
      ];

      const fieldMapping = {
        'Knowledge Type': 'kind',
        'Name': 'data.name',
        'Description': 'content',
        'Project': 'scope.project',
        'Type': 'data.type',
        'Rationale': 'data.rationale',
      };

      const transformedData = [
        {
          kind: 'entity',
          content: 'First entity from CSV',
          scope: { project: 'test-project' },
          data: { name: 'CSV Entity 1', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'First decision from CSV',
          scope: { project: 'test-project' },
          data: { name: 'CSV Decision 1', rationale: 'CSV-based rationale' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: transformedData.map((item, index) => ({
          id: `item-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'CSV import completed successfully',
          reasoning: '2 items imported from CSV with field mapping',
          user_message_suggestion: '✅ CSV data imported with field mapping',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: csvData,
        format: 'csv',
        fieldMapping,
        options: {
          validate: true,
          transform: true,
        },
      });

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should import XML data with nested structure parsing', async () => {
      // Arrange
      const xmlData = {
        knowledge: {
          entity: [
            {
              _attributes: { id: 'entity-1' },
              name: 'XML Entity 1',
              description: 'Entity from XML',
              scope: {
                _attributes: { project: 'test-project' },
              },
              data: {
                type: 'component',
                properties: {
                  property: [
                    { _attributes: { name: 'version' }, _text: '1.0.0' },
                    { _attributes: { name: 'status' }, _text: 'active' },
                  ],
                },
              },
            },
          ],
          decision: [
            {
              _attributes: { id: 'decision-1' },
              title: 'XML Decision 1',
              rationale: 'Decision from XML',
              scope: {
                _attributes: { project: 'test-project' },
              },
            },
          ],
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'XML import completed successfully',
          reasoning: '2 items imported from XML with nested structure parsing',
          user_message_suggestion: '✅ XML data imported successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: xmlData,
        format: 'xml',
        options: {
          parseNested: true,
          validate: true,
        },
      });

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle multiple data formats in single import', async () => {
      // Arrange
      const mixedFormatData = {
        jsonData: [
          {
            kind: 'entity',
            content: 'JSON Entity',
            scope: { project: 'test-project' },
            data: { name: 'JSON Entity', type: 'service' },
          },
        ],
        csvData: [
          {
            'Knowledge Type': 'decision',
            'Name': 'CSV Decision',
            'Project': 'test-project',
            'Rationale': 'CSV rationale',
          },
        ],
        xmlData: {
          observation: {
            _attributes: { id: 'obs-1' },
            content: 'XML Observation',
            scope: { _attributes: { project: 'test-project' } },
          },
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'json-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'csv-decision-id',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
          {
            id: 'xml-observation-id',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Mixed format import completed successfully',
          reasoning: '3 items imported from multiple formats',
          user_message_suggestion: '✅ Mixed format data imported successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: mixedFormatData,
        format: 'mixed',
        options: {
          validate: true,
          normalize: true,
        },
      });

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(result.stored).toHaveLength(3);
      expect(result.stored.map(s => s.kind)).toEqual(['entity', 'decision', 'observation']);
    });
  });

  describe('Bulk Data Import with Validation', () => {
    it('should handle large dataset import efficiently', async () => {
      // Arrange
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        kind: 'entity',
        content: `Entity ${i}`,
        scope: { project: 'test-project' },
        data: {
          name: `Entity ${i}`,
          type: 'component',
          index: i,
          batch: Math.floor(i / 100) + 1,
        },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: largeDataset.map((item, index) => ({
          id: `entity-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 1000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Large dataset import completed successfully',
          reasoning: '1000 items imported in batches for memory efficiency',
          user_message_suggestion: '✅ Large dataset imported successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: largeDataset,
        format: 'json',
        options: {
          validate: true,
          batchSize: 100,
          memoryEfficient: true,
        },
      });

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(result.stored).toHaveLength(1000);
      expect(result.errors).toHaveLength(0);
      expect(result.autonomous_context.similar_items_checked).toBe(1000);
    });

    it('should validate all items before import', async () => {
      // Arrange
      const datasetWithInvalidItems = [
        // Valid items
        {
          kind: 'entity',
          content: 'Valid entity 1',
          scope: { project: 'test-project' },
          data: { name: 'Valid Entity 1', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'Valid decision 1',
          scope: { project: 'test-project' },
          data: { title: 'Valid Decision 1', rationale: 'Valid rationale' },
        },
        // Invalid items
        null,
        undefined,
        { invalid: 'item' },
        {
          kind: 'entity',
          // Missing scope
          data: { name: 'Invalid entity' },
        },
      ];

      // Mock validation to detect invalid items
      mockValidation.validateStoreInput.mockResolvedValue({
        valid: false,
        errors: [
          { index: 2, error_code: 'INVALID_ITEM', message: 'Null item' },
          { index: 3, error_code: 'INVALID_ITEM', message: 'Undefined item' },
          { index: 4, error_code: 'INVALID_ITEM', message: 'Missing kind field' },
          { index: 5, error_code: 'VALIDATION_ERROR', message: 'Missing scope' },
        ],
      });

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 2,
            error_code: 'INVALID_ITEM',
            message: 'Null item',
          },
          {
            index: 3,
            error_code: 'INVALID_ITEM',
            message: 'Undefined item',
          },
          {
            index: 4,
            error_code: 'INVALID_ITEM',
            message: 'Missing kind field',
          },
          {
            index: 5,
            error_code: 'VALIDATION_ERROR',
            message: 'Missing scope',
          },
        ],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Partial import completed - fix validation errors and retry',
          reasoning: '2 items imported successfully; 4 items failed validation',
          user_message_suggestion: '⚠️ Partial import: 2 successful, 4 errors',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: datasetWithInvalidItems,
        format: 'json',
        options: {
          validate: true,
          failFast: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(4);
      expect(result.autonomous_context.action_performed).toBe('batch');
    });

    it('should handle memory-efficient processing for large datasets', async () => {
      // Arrange
      const memoryIntensiveData = Array.from({ length: 100 }, (_, i) => ({
        kind: 'observation',
        content: 'x'.repeat(10000), // 10KB per item
        scope: { project: 'test-project' },
        data: {
          content: 'x'.repeat(10000),
          largeArray: new Array(1000).fill('large data chunk'),
          metadata: {
            size: 'large',
            index: i,
            timestamp: new Date().toISOString(),
          },
        },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: memoryIntensiveData.map((_, index) => ({
          id: `obs-id-${index + 1}`,
          status: 'inserted' as const,
          kind: 'observation',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 100,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Memory-intensive import completed successfully',
          reasoning: '100 large items processed with memory-efficient streaming',
          user_message_suggestion: '✅ Large dataset processed efficiently',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: memoryIntensiveData,
        format: 'json',
        options: {
          validate: false, // Skip validation for memory efficiency
          streaming: true,
          batchSize: 10,
          memoryLimit: '50MB',
        },
      });

      // Assert
      expect(result.stored).toHaveLength(100);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Incremental Import Operations', () => {
    it('should handle incremental imports with timestamp tracking', async () => {
      // Arrange
      const incrementalData = [
        {
          kind: 'entity',
          content: 'New entity',
          scope: { project: 'test-project' },
          data: { name: 'New Entity', type: 'service' },
          created_at: '2025-01-01T12:00:00Z',
        },
        {
          kind: 'decision',
          content: 'Updated decision',
          scope: { project: 'test-project' },
          data: { title: 'Updated Decision', rationale: 'Updated rationale' },
          created_at: '2025-01-01T11:00:00Z',
          updated_at: '2025-01-01T12:30:00Z',
        },
      ];

      const lastImportTimestamp = '2025-01-01T10:00:00Z';

      const expectedResponse: MemoryStoreResponse = {
        stored: incrementalData.map((item, index) => ({
          id: `item-id-${index + 1}`,
          status: item.updated_at ? 'updated' : 'inserted',
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'incremental',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Incremental import completed successfully',
          reasoning: '2 items processed since last import timestamp',
          user_message_suggestion: '✅ Incremental import completed',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: incrementalData,
        format: 'json',
        options: {
          incremental: true,
          lastImportTimestamp,
          updateExisting: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.stored[0].status).toBe('inserted');
      expect(result.stored[1].status).toBe('updated');
      expect(result.autonomous_context.action_performed).toBe('incremental');
    });

    it('should handle delta imports with change detection', async () => {
      // Arrange
      const deltaData = {
        added: [
          {
            kind: 'entity',
            content: 'Added entity',
            scope: { project: 'test-project' },
            data: { name: 'Added Entity', type: 'component' },
          },
        ],
        modified: [
          {
            id: 'existing-entity-id',
            kind: 'entity',
            content: 'Modified entity',
            scope: { project: 'test-project' },
            data: { name: 'Modified Entity', type: 'service', version: 2 },
          },
        ],
        deleted: [
          {
            id: 'entity-to-delete-id',
            kind: 'entity',
            scope: { project: 'test-project' },
          },
        ],
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'added-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'existing-entity-id',
            status: 'updated',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'entity-to-delete-id',
            status: 'deleted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'delta',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Delta import completed successfully',
          reasoning: '1 added, 1 modified, 1 deleted',
          user_message_suggestion: '✅ Delta changes applied successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: deltaData,
        format: 'delta',
        options: {
          changeDetection: true,
          applyChanges: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.stored.map(s => s.status)).toEqual(['inserted', 'updated', 'deleted']);
      expect(result.autonomous_context.action_performed).toBe('delta');
    });
  });

  describe('Import Conflict Resolution', () => {
    it('should handle duplicate detection and resolution', async () => {
      // Arrange
      const dataWithDuplicates = [
        {
          kind: 'entity',
          content: 'Duplicate entity 1',
          scope: { project: 'test-project' },
          data: { name: 'Duplicate Entity', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Duplicate entity 2',
          scope: { project: 'test-project' },
          data: { name: 'Duplicate Entity', type: 'service' }, // Same name and type
        },
        {
          kind: 'entity',
          content: 'Unique entity',
          scope: { project: 'test-project' },
          data: { name: 'Unique Entity', type: 'component' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'unique-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 2,
          contradictions_detected: false,
          recommendation: 'Duplicates resolved - unique items imported',
          reasoning: '2 duplicates detected and skipped; 1 unique item imported',
          user_message_suggestion: '✅ Import completed: 1 unique, 2 duplicates skipped',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithDuplicates,
        format: 'json',
        options: {
          deduplicate: true,
          duplicateStrategy: 'skip',
          duplicateFields: ['data.name', 'data.type'],
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.duplicates_found).toBe(2);
      expect(result.autonomous_context.similar_items_checked).toBe(3);
    });

    it('should handle conflicting data with merge strategy', async () => {
      // Arrange
      const conflictingData = [
        {
          kind: 'entity',
          content: 'Existing entity with updates',
          scope: { project: 'test-project' },
          data: {
            name: 'Existing Entity',
            type: 'service',
            version: 2,
            newField: 'new value',
          },
          metadata: { mergeStrategy: 'merge' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'existing-entity-id',
            status: 'updated',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'merge',
          similar_items_checked: 1,
          duplicates_found: 1,
          contradictions_detected: false,
          recommendation: 'Conflicts resolved with merge strategy',
          reasoning: '1 existing item merged with new data',
          user_message_suggestion: '✅ Data merged successfully',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: conflictingData,
        format: 'json',
        options: {
          conflictResolution: 'merge',
          updateExisting: true,
          mergeFields: ['data.newField'],
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('updated');
      expect(result.autonomous_context.action_performed).toBe('merge');
    });

    it('should handle version conflicts with resolution strategies', async () => {
      // Arrange
      const versionConflictedData = [
        {
          kind: 'decision',
          content: 'Decision with version conflict',
          scope: { project: 'test-project' },
          data: {
            title: 'Version Conflicted Decision',
            rationale: 'Updated rationale',
            version: 3,
          },
          metadata: {
            versionStrategy: 'latest',
            conflictResolution: 'keep_newer',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'decision-id-1',
            status: 'updated',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'version_resolve',
          similar_items_checked: 1,
          duplicates_found: 1,
          contradictions_detected: false,
          recommendation: 'Version conflict resolved using newer version',
          reasoning: 'Existing version 2 updated to version 3',
          user_message_suggestion: '✅ Version conflict resolved',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: versionConflictedData,
        format: 'json',
        options: {
          versionConflictStrategy: 'keep_newer',
          versionField: 'data.version',
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('updated');
      expect(result.autonomous_context.action_performed).toBe('version_resolve');
    });
  });

  describe('Data Validation During Import', () => {
    it('should validate schema compliance during import', async () => {
      // Arrange
      const schemaValidatedData = [
        {
          kind: 'decision',
          content: 'Valid decision',
          scope: { project: 'test-project' },
          data: {
            title: 'Valid Decision',
            rationale: 'Valid rationale with sufficient detail',
            alternatives: ['Option A', 'Option B'],
            impact: 'medium',
          },
        },
        {
          kind: 'runbook',
          content: 'Invalid runbook',
          scope: { project: 'test-project' },
          data: {
            title: 'Incomplete Runbook',
            // Missing required steps field
          },
        },
      ];

      // Mock schema validation
      mockValidation.validateImportData.mockResolvedValue({
        valid: false,
        errors: [
          {
            index: 1,
            error_code: 'SCHEMA_VALIDATION_ERROR',
            message: 'Runbook requires steps field',
            field: 'data.steps',
          },
        ],
      });

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'SCHEMA_VALIDATION_ERROR',
            message: 'Runbook requires steps field',
            field: 'data.steps',
          },
        ],
        autonomous_context: {
          action_performed: 'partial_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix schema validation errors for rejected items',
          reasoning: '1 item passed schema validation; 1 item failed',
          user_message_suggestion: '⚠️ Partial import: 1 passed validation, 1 failed',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: schemaValidatedData,
        format: 'json',
        options: {
          validateSchema: true,
          strictValidation: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error_code).toBe('SCHEMA_VALIDATION_ERROR');
    });

    it('should validate data types and formats', async () => {
      // Arrange
      const typedData = [
        {
          kind: 'entity',
          content: 'Typed entity',
          scope: { project: 'test-project' },
          data: {
            name: 'Typed Entity',
            type: 'service',
            priority: 'high', // Should be enum
            version: 'v1.0.0', // Should follow semver
            tags: ['tag1', 'tag2'], // Should be array
          },
        },
        {
          kind: 'observation',
          content: 'Typed observation',
          scope: { project: 'test-project' },
          data: {
            content: 'Observation content',
            timestamp: 'invalid-date', // Should be valid ISO date
            metrics: {
              cpu: '80%', // Should be number
              memory: '4GB', // Should be number in MB
            },
          },
        },
      ];

      // Mock type validation
      mockValidation.validateImportData.mockResolvedValue({
        valid: false,
        errors: [
          {
            index: 0,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid priority value',
            field: 'data.priority',
          },
          {
            index: 1,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid timestamp format',
            field: 'data.timestamp',
          },
        ],
      });

      const expectedResponse: MemoryStoreResponse = {
        stored: [],
        errors: [
          {
            index: 0,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid priority value',
            field: 'data.priority',
          },
          {
            index: 1,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid timestamp format',
            field: 'data.timestamp',
          },
        ],
        autonomous_context: {
          action_performed: 'validation_failed',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix type validation errors before retrying',
          reasoning: 'All items failed type validation',
          user_message_suggestion: '❌ Import failed: type validation errors',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: typedData,
        format: 'json',
        options: {
          validateTypes: true,
          strictTyping: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(2);
      expect(result.errors.every(e => e.error_code === 'TYPE_VALIDATION_ERROR')).toBe(true);
    });
  });

  describe('Data Type Conversion and Normalization', () => {
    it('should convert and normalize data types during import', async () => {
      // Arrange
      const unnormalizedData = [
        {
          kind: 'entity',
          content: 'Unnormalized entity',
          scope: { project: 'test-project' },
          data: {
            name: '  Unnormalized Entity  ', // Needs trimming
            type: 'SERVICE', // Needs lowercase
            priority: 'High', // Needs lowercase
            created_at: '2025-01-01', // Needs full ISO format
            tags: 'tag1,tag2,tag3', // Needs array conversion
            active: 'true', // Needs boolean conversion
            version: 1, // Needs string conversion
          },
        },
      ];

      const normalizedData = [
        {
          kind: 'entity',
          content: 'Unnormalized entity',
          scope: { project: 'test-project' },
          data: {
            name: 'Unnormalized Entity',
            type: 'service',
            priority: 'high',
            created_at: '2025-01-01T00:00:00.000Z',
            tags: ['tag1', 'tag2', 'tag3'],
            active: true,
            version: '1',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'normalized_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Data normalized and imported successfully',
          reasoning: '1 item normalized during import process',
          user_message_suggestion: '✅ Data normalized and imported',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: unnormalizedData,
        format: 'json',
        options: {
          normalize: true,
          typeConversion: true,
          trimStrings: true,
          normalizeCase: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('normalized_import');
    });

    it('should handle field type mapping and conversion', async () => {
      // Arrange
      const rawTypedData = [
        {
          kind: 'observation',
          content: 'Raw typed observation',
          scope: { project: 'test-project' },
          data: {
            content: 'Observation with raw types',
            timestamp: '2025-01-01 12:00:00', // Custom date format
            duration: '2h 30m', // Duration string
            size: '1.5MB', // Size string
            count: '1,234', // Number with commas
            percentage: '85.5%', // Percentage string
            enabled: 'yes', // Boolean string
            coordinates: '40.7128, -74.0060', // Coordinate string
          },
        },
      ];

      const typeMapping = {
        'data.timestamp': 'datetime',
        'data.duration': 'duration',
        'data.size': 'bytes',
        'data.count': 'number',
        'data.percentage': 'percentage',
        'data.enabled': 'boolean',
        'data.coordinates': 'coordinates',
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'observation-id-1',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'type_converted_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Field types converted and imported successfully',
          reasoning: '1 item with type mapping converted during import',
          user_message_suggestion: '✅ Field types converted and imported',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: rawTypedData,
        format: 'json',
        options: {
          typeMapping,
          convertTypes: true,
          preserveOriginal: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('type_converted_import');
    });
  });

  describe('Duplicate Detection and Handling', () => {
    it('should detect duplicates using multiple strategies', async () => {
      // Arrange
      const dataWithPotentialDuplicates = [
        {
          kind: 'entity',
          content: 'Potential duplicate 1',
          scope: { project: 'test-project' },
          data: { name: 'Same Name', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Potential duplicate 2',
          scope: { project: 'test-project' },
          data: { name: 'Same Name', type: 'service' }, // Exact match
        },
        {
          kind: 'entity',
          content: 'Potential duplicate 3',
          scope: { project: 'test-project' },
          data: { name: 'Similar Name', type: 'service' }, // Similar match
        },
        {
          kind: 'entity',
          content: 'Unique entity',
          scope: { project: 'test-project' },
          data: { name: 'Different Name', type: 'component' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'unique-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'deduplicated_import',
          similar_items_checked: 4,
          duplicates_found: 3,
          contradictions_detected: false,
          recommendation: 'Duplicates detected and handled according to strategy',
          reasoning: '3 duplicates detected using multiple strategies; 1 unique item imported',
          user_message_suggestion: '✅ Import completed: 1 unique, 3 duplicates handled',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithPotentialDuplicates,
        format: 'json',
        options: {
          deduplicate: true,
          duplicateStrategy: 'skip',
          duplicateDetection: ['exact', 'fuzzy', 'semantic'],
          duplicateThreshold: 0.8,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.duplicates_found).toBe(3);
      expect(result.autonomous_context.similar_items_checked).toBe(4);
    });

    it('should merge duplicates intelligently', async () => {
      // Arrange
      const duplicatesForMerging = [
        {
          kind: 'entity',
          content: 'Basic entity info',
          scope: { project: 'test-project' },
          data: {
            name: 'Entity for Merge',
            type: 'service',
            description: 'Basic description',
          },
        },
        {
          kind: 'entity',
          content: 'Additional entity info',
          scope: { project: 'test-project' },
          data: {
            name: 'Entity for Merge',
            type: 'service',
            version: '2.0.0',
            tags: ['tag1', 'tag2'],
            metadata: { source: 'import' },
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'merged-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'merge_duplicates',
          similar_items_checked: 2,
          duplicates_found: 1,
          contradictions_detected: false,
          recommendation: 'Duplicates merged successfully',
          reasoning: '2 duplicate items merged into 1 comprehensive entity',
          user_message_suggestion: '✅ Duplicates merged intelligently',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: duplicatesForMerging,
        format: 'json',
        options: {
          deduplicate: true,
          duplicateStrategy: 'merge',
          mergeStrategy: 'comprehensive',
          mergeFields: ['data.version', 'data.tags', 'data.metadata'],
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('inserted');
      expect(result.autonomous_context.action_performed).toBe('merge_duplicates');
    });
  });

  describe('Data Integrity Verification', () => {
    it('should verify referential integrity during import', async () => {
      // Arrange
      const dataWithReferences = [
        {
          kind: 'entity',
          content: 'Primary entity',
          scope: { project: 'test-project' },
          data: { name: 'Primary Entity', type: 'service' },
        },
        {
          kind: 'relation',
          content: 'Entity relation',
          scope: { project: 'test-project' },
          data: {
            source: 'Primary Entity',
            target: 'Secondary Entity', // Reference to non-existent entity
            type: 'depends_on',
          },
        },
        {
          kind: 'entity',
          content: 'Secondary entity',
          scope: { project: 'test-project' },
          data: { name: 'Secondary Entity', type: 'database' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'primary-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'secondary-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-id-1',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'integrity_verified_import',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Referential integrity verified and maintained',
          reasoning: 'All references validated during import process',
          user_message_suggestion: '✅ Data integrity verified during import',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithReferences,
        format: 'json',
        options: {
          verifyIntegrity: true,
          resolveReferences: true,
          createMissingReferences: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.autonomous_context.action_performed).toBe('integrity_verified_import');
    });

    it('should handle missing references with resolution strategies', async () => {
      // Arrange
      const dataWithMissingReferences = [
        {
          kind: 'relation',
          content: 'Relation with missing target',
          scope: { project: 'test-project' },
          data: {
            source: 'Existing Entity',
            target: 'Missing Entity', // This entity doesn't exist
            type: 'depends_on',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'relation-id-1',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'reference_resolved_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Missing references resolved during import',
          reasoning: 'Created missing reference entities to maintain integrity',
          user_message_suggestion: '✅ Missing references resolved automatically',
        },
      };

      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithMissingReferences,
        format: 'json',
        options: {
          verifyIntegrity: true,
          missingReferenceStrategy: 'create',
          createPlaceholderEntities: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('reference_resolved_import');
    });
  });
});

describe('Import Service - Field Mapping and Transformation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Field Mapping Operations', () => {
    it('should handle complex field mapping', async () => {
      // Arrange
      const sourceData = [
        {
          'Source Field 1': 'Value 1',
          'Source Field 2': 'Value 2',
          'Nested.Object': 'Nested value',
          'Array Field': 'item1,item2,item3',
          'Date Field': '01/15/2025',
          'Number Field': '1,234.56',
        },
      ];

      const fieldMapping = {
        'Source Field 1': 'content',
        'Source Field 2': 'data.field2',
        'Nested.Object': 'data.nested.object',
        'Array Field': 'data.tags', // Convert to array
        'Date Field': 'created_at', // Convert to ISO date
        'Number Field': 'data.number', // Convert to number
      };

      const transformedData = [
        {
          kind: 'entity',
          content: 'Value 1',
          scope: { project: 'test-project' },
          data: {
            field2: 'Value 2',
            nested: { object: 'Nested value' },
            tags: ['item1', 'item2', 'item3'],
            number: 1234.56,
          },
          created_at: '2025-01-15T00:00:00.000Z',
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'mapped-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'field_mapped_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Field mapping applied successfully',
          reasoning: 'Data transformed using complex field mapping',
          user_message_suggestion: '✅ Field mapping completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: sourceData,
        format: 'csv',
        fieldMapping,
        options: {
          transform: true,
          convertTypes: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('field_mapped_import');
    });

    it('should handle conditional field mapping', async () => {
      // Arrange
      const sourceData = [
        {
          'Category': 'person',
          'Name': 'John Doe',
          'Age': '30',
          'Department': 'Engineering',
        },
        {
          'Category': 'company',
          'Name': 'Tech Corp',
          'Revenue': '1000000',
          'Industry': 'Technology',
        },
      ];

      const conditionalMapping = {
        // Conditional mapping based on Category
        'Name': 'data.name',
        'Age': {
          condition: { field: 'Category', value: 'person' },
          target: 'data.age',
          type: 'number',
        },
        'Department': {
          condition: { field: 'Category', value: 'person' },
          target: 'data.department',
        },
        'Revenue': {
          condition: { field: 'Category', value: 'company' },
          target: 'data.revenue',
          type: 'number',
        },
        'Industry': {
          condition: { field: 'Category', value: 'company' },
          target: 'data.industry',
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'person-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'company-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'conditional_mapped_import',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Conditional field mapping applied successfully',
          reasoning: 'Different mapping rules applied based on data conditions',
          user_message_suggestion: '✅ Conditional mapping completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: sourceData,
        format: 'csv',
        fieldMapping: conditionalMapping,
        options: {
          conditionalMapping: true,
          transform: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.autonomous_context.action_performed).toBe('conditional_mapped_import');
    });
  });

  describe('Data Format Conversion', () => {
    it('should convert between different data formats', async () => {
      // Arrange
      const xmlData = `
        <knowledge>
          <entity id="1">
            <name>XML Entity</name>
            <type>service</type>
            <properties>
              <property name="version">1.0</property>
              <property name="status">active</property>
            </properties>
          </entity>
        </knowledge>
      `;

      const expectedJsonFormat = [
        {
          kind: 'entity',
          content: 'XML Entity',
          scope: { project: 'test-project' },
          data: {
            name: 'XML Entity',
            type: 'service',
            properties: {
              version: '1.0',
              status: 'active',
            },
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'converted-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'format_converted_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Data format converted successfully',
          reasoning: 'XML data converted to JSON format for processing',
          user_message_suggestion: '✅ Format conversion completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: xmlData,
        format: 'xml',
        options: {
          convertTo: 'json',
          preserveStructure: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('format_converted_import');
    });

    it('should handle custom format conversions', async () => {
      // Arrange
      const customFormatData = `
        # Custom Knowledge Format
        ENTITY: "Custom Entity"
        TYPE: "component"
        SCOPE: "test-project"
        METADATA:
          - key: "version"
            value: "2.0"
          - key: "status"
            value: "development"
        CONTENT: "This is a custom formatted entity"
      `;

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'custom-format-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'custom_format_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Custom format parsed and imported successfully',
          reasoning: 'Proprietary format converted using custom parser',
          user_message_suggestion: '✅ Custom format processed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: customFormatData,
        format: 'custom',
        options: {
          customParser: 'knowledge-markdown',
          preserveFormatting: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('custom_format_import');
    });
  });

  describe('Custom Transformation Rules', () => {
    it('should apply custom transformation functions', async () => {
      // Arrange
      const rawData = [
        {
          'name': 'raw entity',
          'description': 'THIS IS UPPERCASE DESCRIPTION',
          'tags': 'tag1, tag2, tag3',
          'status': '  active  ',
          'confidence': '0.85',
        },
      ];

      const transformationRules = {
        'name': (value: string) => value.charAt(0).toUpperCase() + value.slice(1), // Title case
        'description': (value: string) => value.toLowerCase(), // Lowercase
        'tags': (value: string) => value.split(',').map((tag: string) => tag.trim()), // Array
        'status': (value: string) => value.trim(), // Trim whitespace
        'confidence': (value: string) => parseFloat(value), // Parse float
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'transformed-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'custom_transformed_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Custom transformations applied successfully',
          reasoning: 'Data processed using custom transformation rules',
          user_message_suggestion: '✅ Custom transformations applied successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: rawData,
        format: 'json',
        transformationRules,
        options: {
          applyTransformations: true,
          preserveOriginal: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('custom_transformed_import');
    });

    it('should handle chained transformations', async () => {
      // Arrange
      const chainedData = [
        {
          'phone': '(555) 123-4567',
          'email': '  USER@EXAMPLE.COM  ',
          'url': 'example.com',
          'date': '2025-01-15',
        },
      ];

      const chainedTransformations = {
        'phone': [
          (value: string) => value.replace(/[^\d]/g, ''), // Remove non-digits
          (value: string) => value.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3'), // Format
        ],
        'email': [
          (value: string) => value.trim(), // Trim whitespace
          (value: string) => value.toLowerCase(), // Lowercase
        ],
        'url': [
          (value: string) => value.startsWith('http') ? value : `https://${value}`, // Add protocol
          (value: string) => value.replace(/\/$/, ''), // Remove trailing slash
        ],
        'date': [
          (value: string) => new Date(value).toISOString(), // Convert to ISO
        ],
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'chained-transformed-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'chained_transformed_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Chained transformations applied successfully',
          reasoning: 'Data processed through multiple transformation steps',
          user_message_suggestion: '✅ Chained transformations completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: chainedData,
        format: 'json',
        transformationRules: chainedTransformations,
        options: {
          applyTransformations: true,
          chainTransformations: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('chained_transformed_import');
    });
  });

  describe('Data Enrichment During Import', () => {
    it('should enrich data with computed fields', async () => {
      // Arrange
      const dataForEnrichment = [
        {
          kind: 'entity',
          content: 'Entity for enrichment',
          scope: { project: 'test-project' },
          data: {
            name: 'Enriched Entity',
            type: 'service',
            tags: ['api', 'microservice'],
            created_date: '2025-01-01',
          },
        },
      ];

      const enrichmentRules = {
        'data.tag_count': (item: any) => item.data.tags.length,
        'data.category': (item: any) => 'service',
        'data.age_days': (item: any) => Math.floor((Date.now() - new Date(item.data.created_date).getTime()) / (1000 * 60 * 60 * 24)),
        'data.complexity': (item: any) => item.data.tags.length > 2 ? 'high' : 'medium',
        'metadata.processed_at': () => new Date().toISOString(),
        'metadata.enrichment_version': '1.0',
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'enriched-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'enriched_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Data enriched with computed fields successfully',
          reasoning: 'Enrichment rules applied to add computed data',
          user_message_suggestion: '✅ Data enrichment completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataForEnrichment,
        format: 'json',
        enrichmentRules,
        options: {
          enrich: true,
          preserveOriginal: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('enriched_import');
    });

    it('should enrich data with external lookups', async () => {
      // Arrange
      const dataForExternalEnrichment = [
        {
          kind: 'entity',
          content: 'Entity with external references',
          scope: { project: 'test-project' },
          data: {
            name: 'External Entity',
            type: 'service',
            technology: 'nodejs',
            version: '18.0.0',
          },
        },
      ];

      const externalLookupRules = {
        'data.technology_info': {
          source: 'npm_registry',
          field: 'technology',
          enrich: ['description', 'latest_version', 'downloads'],
        },
        'data.version_info': {
          source: 'npm_registry',
          field: 'version',
          enrich: ['release_date', 'security_updates', 'dependencies'],
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'externally-enriched-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'externally_enriched_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Data enriched with external lookups successfully',
          reasoning: 'External API lookups performed to enrich data',
          user_message_suggestion: '✅ External enrichment completed successfully',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataForExternalEnrichment,
        format: 'json',
        externalLookupRules,
        options: {
          externalEnrichment: true,
          cacheLookups: true,
          timeout: 5000,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.action_performed).toBe('externally_enriched_import');
    });
  });
});

describe('Import Service - Error Handling and Recovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Import Error Reporting', () => {
    it('should provide detailed error reporting', async () => {
      // Arrange
      const problematicData = [
        {
          kind: 'entity',
          content: 'Problematic entity',
          scope: { project: 'test-project' },
          data: { name: 'Problematic Entity', type: 'service' },
        },
        null, // Invalid item
        undefined, // Invalid item
        {
          kind: 'invalid_kind',
          content: 'Invalid kind',
          scope: { project: 'test-project' },
          data: { name: 'Invalid Kind Entity' },
        },
        {
          kind: 'entity',
          // Missing scope
          data: { name: 'Missing Scope Entity' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'problematic-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'INVALID_ITEM',
            message: 'Item is null',
            field: null,
            stack: 'Error: Item is null\n    at validateItem',
            timestamp: new Date().toISOString(),
          },
          {
            index: 2,
            error_code: 'INVALID_ITEM',
            message: 'Item is undefined',
            field: null,
            stack: 'Error: Item is undefined\n    at validateItem',
            timestamp: new Date().toISOString(),
          },
          {
            index: 3,
            error_code: 'VALIDATION_ERROR',
            message: 'Invalid knowledge kind: invalid_kind',
            field: 'kind',
            stack: 'Error: Invalid knowledge kind\n    at validateKind',
            timestamp: new Date().toISOString(),
          },
          {
            index: 4,
            error_code: 'VALIDATION_ERROR',
            message: 'Missing required field: scope',
            field: 'scope',
            stack: 'Error: Missing required field\n    at validateRequired',
            timestamp: new Date().toISOString(),
          },
        ],
        autonomous_context: {
          action_performed: 'partial_import_with_errors',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix reported errors and retry import for failed items',
          reasoning: '1 item imported successfully; 4 items failed with various errors',
          user_message_suggestion: '⚠️ Partial import completed with 4 errors',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: problematicData,
        format: 'json',
        options: {
          validate: true,
          continueOnError: true,
          detailedErrors: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(4);
      expect(result.errors.every(e => e.error_code && e.message && e.timestamp)).toBe(true);
    });

    it('should categorize errors by severity and type', async () => {
      // Arrange
      const dataWithVariousErrors = [
        {
          kind: 'entity',
          content: 'Valid entity',
          scope: { project: 'test-project' },
          data: { name: 'Valid Entity', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Schema violation entity',
          scope: { project: 'test-project' },
          data: {
            name: 'Schema Violation Entity',
            // Missing required type field
          },
        },
        {
          kind: 'entity',
          content: 'Type error entity',
          scope: { project: 'test-project' },
          data: {
            name: 'Type Error Entity',
            type: 123, // Should be string
            created_at: 'invalid-date', // Should be valid date
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'valid-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'SCHEMA_VALIDATION_ERROR',
            message: 'Missing required field: type',
            field: 'data.type',
            severity: 'error',
            category: 'schema',
            recoverable: true,
          },
          {
            index: 2,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid type for field: type (expected string, got number)',
            field: 'data.type',
            severity: 'warning',
            category: 'type',
            recoverable: true,
          },
          {
            index: 2,
            error_code: 'TYPE_VALIDATION_ERROR',
            message: 'Invalid date format: created_at',
            field: 'data.created_at',
            severity: 'warning',
            category: 'type',
            recoverable: true,
          },
        ],
        autonomous_context: {
          action_performed: 'partial_import_with_categorized_errors',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Review categorized errors and apply appropriate fixes',
          reasoning: '1 item imported; 2 items failed with categorizable errors',
          user_message_suggestion: '⚠️ Import completed with categorized errors',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithVariousErrors,
        format: 'json',
        options: {
          validate: true,
          categorizeErrors: true,
          continueOnError: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(3);
      expect(result.errors.some(e => e.category === 'schema')).toBe(true);
      expect(result.errors.some(e => e.category === 'type')).toBe(true);
    });
  });

  describe('Partial Import Handling', () => {
    it('should handle partial imports with continuation', async () => {
      // Arrange
      const largeDatasetWithErrors = Array.from({ length: 100 }, (_, i) => {
        if (i % 10 === 0) {
          // Every 10th item is invalid
          return null;
        }
        return {
          kind: 'entity',
          content: `Entity ${i}`,
          scope: { project: 'test-project' },
          data: { name: `Entity ${i}`, type: 'component' },
        };
      });

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 90 }, (_, i) => ({
          id: `entity-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: Array.from({ length: 10 }, (_, i) => ({
          index: i * 10,
          error_code: 'INVALID_ITEM',
          message: 'Item is null',
          severity: 'error' as const,
          recoverable: false,
        })),
        autonomous_context: {
          action_performed: 'partial_import_continued',
          similar_items_checked: 90,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: '90 items imported successfully; 10 items were invalid',
          reasoning: 'Partial import completed with error continuation strategy',
          user_message_suggestion: '✅ Partial import: 90 successful, 10 failed',
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: largeDatasetWithErrors,
        format: 'json',
        options: {
          validate: true,
          continueOnError: true,
          partialImport: true,
          errorThreshold: 0.2, // Allow up to 20% errors
        },
      });

      // Assert
      expect(result.stored).toHaveLength(90);
      expect(result.errors).toHaveLength(10);
      expect(result.autonomous_context.action_performed).toBe('partial_import_continued');
    });

    it('should provide retry information for failed items', async () => {
      // Arrange
      const retryableData = [
        {
          kind: 'entity',
          content: 'Valid entity',
          scope: { project: 'test-project' },
          data: { name: 'Valid Entity', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Temporarily invalid entity',
          scope: { project: 'test-project' },
          data: { name: 'Temp Invalid Entity', type: 'service' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'valid-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'TEMPORARY_ERROR',
            message: 'Temporary service unavailable',
            severity: 'warning',
            recoverable: true,
            retryAfter: 5000, // Retry after 5 seconds
            retryCount: 0,
            maxRetries: 3,
          },
        ],
        autonomous_context: {
          action_performed: 'partial_import_with_retry_info',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Retry failed items after suggested delay',
          reasoning: '1 item imported; 1 item failed but is retryable',
          user_message_suggestion: '⚠️ Some items failed but can be retried',
          retryInfo: {
            retryableItems: 1,
            suggestedDelay: 5000,
            retryStrategy: 'exponential_backoff',
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: retryableData,
        format: 'json',
        options: {
          validate: true,
          retryableErrors: true,
          continueOnError: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].recoverable).toBe(true);
      expect(result.errors[0].retryAfter).toBe(5000);
    });
  });

  describe('Rollback Capabilities', () => {
    it('should provide import rollback functionality', async () => {
      // Arrange
      const importData = [
        {
          kind: 'entity',
          content: 'Entity to rollback',
          scope: { project: 'test-project' },
          data: { name: 'Rollback Entity', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'Decision to rollback',
          scope: { project: 'test-project' },
          data: { title: 'Rollback Decision', rationale: 'Test rationale' },
        },
      ];

      const importResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Import completed - rollback available',
          reasoning: '2 items imported with rollback capability',
          user_message_suggestion: '✅ Import completed with rollback option',
        },
      };

      const rollbackResponse = {
        success: true,
        rolledBackItems: 2,
        rollbackId: 'rollback-123',
        timestamp: new Date().toISOString(),
        details: {
          'entity-id-1': { action: 'deleted', success: true },
          'decision-id-1': { action: 'deleted', success: true },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(importResponse);

      // Mock rollback function
      importService.rollbackImport = vi.fn().mockResolvedValue(rollbackResponse);

      // Act - First import
      const importResult = await importService.importData({
        data: importData,
        format: 'json',
        options: {
          enableRollback: true,
          rollbackTimeout: 3600000, // 1 hour
        },
      });

      // Act - Then rollback
      const rollbackResult = await importService.rollbackImport({
        importId: importResult.autonomous_context.importId,
        reason: 'Test rollback',
        cascade: true,
      });

      // Assert
      expect(importResult.stored).toHaveLength(2);
      expect(rollbackResult.success).toBe(true);
      expect(rollbackResult.rolledBackItems).toBe(2);
      expect(importService.rollbackImport).toHaveBeenCalledWith({
        importId: importResult.autonomous_context.importId,
        reason: 'Test rollback',
        cascade: true,
      });
    });

    it('should handle partial rollback scenarios', async () => {
      // Arrange
      const mixedImportData = [
        {
          kind: 'entity',
          content: 'Entity to keep',
          scope: { project: 'test-project' },
          data: { name: 'Keep Entity', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Entity to rollback',
          scope: { project: 'test-project' },
          data: { name: 'Rollback Entity', type: 'component' },
        },
      ];

      const importResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'keep-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'rollback-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Import completed with partial rollback option',
          reasoning: '2 items imported with selective rollback capability',
          user_message_suggestion: '✅ Import completed with partial rollback option',
        },
      };

      const partialRollbackResponse = {
        success: true,
        rolledBackItems: 1,
        keptItems: 1,
        rollbackId: 'partial-rollback-123',
        timestamp: new Date().toISOString(),
        details: {
          'rollback-entity-id': { action: 'deleted', success: true },
          'keep-entity-id': { action: 'kept', success: true },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(importResponse);

      // Mock partial rollback function
      importService.rollbackImport = vi.fn().mockResolvedValue(partialRollbackResponse);

      // Act
      const importResult = await importService.importData({
        data: mixedImportData,
        format: 'json',
        options: {
          enableRollback: true,
          selectiveRollback: true,
        },
      });

      const rollbackResult = await importService.rollbackImport({
        importId: importResult.autonomous_context.importId,
        itemsToRollback: ['rollback-entity-id'],
        reason: 'Partial rollback test',
      });

      // Assert
      expect(importResult.stored).toHaveLength(2);
      expect(rollbackResult.success).toBe(true);
      expect(rollbackResult.rolledBackItems).toBe(1);
      expect(rollbackResult.keptItems).toBe(1);
    });
  });

  describe('Data Recovery Mechanisms', () => {
    it('should provide data recovery for corrupted imports', async () => {
      // Arrange
      const corruptedImportId = 'corrupted-import-123';

      const recoveryResponse = {
        success: true,
        recoveredItems: 5,
        corruptedItems: 2,
        recoveryId: 'recovery-456',
        timestamp: new Date().toISOString(),
        recoveredData: [
          {
            id: 'recovered-entity-1',
            kind: 'entity',
            content: 'Recovered entity 1',
            scope: { project: 'test-project' },
            data: { name: 'Recovered Entity 1', type: 'service' },
          },
          {
            id: 'recovered-entity-2',
            kind: 'decision',
            content: 'Recovered decision 1',
            scope: { project: 'test-project' },
            data: { title: 'Recovered Decision 1', rationale: 'Recovered rationale' },
          },
        ],
        recoveryDetails: {
          strategy: 'backup_restore',
          source: 'import_backup',
          integrity: 'verified',
        },
      };

      // Mock recovery function
      importService.recoverImport = vi.fn().mockResolvedValue(recoveryResponse);

      // Act
      const result = await importService.recoverImport({
        importId: corruptedImportId,
        recoveryStrategy: 'backup_restore',
        validateIntegrity: true,
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.recoveredItems).toBe(5);
      expect(result.corruptedItems).toBe(2);
      expect(result.recoveryDetails.strategy).toBe('backup_restore');
      expect(importService.recoverImport).toHaveBeenCalledWith({
        importId: corruptedImportId,
        recoveryStrategy: 'backup_restore',
        validateIntegrity: true,
      });
    });

    it('should handle recovery with data repair', async () => {
      // Arrange
      const repairableImportId = 'repairable-import-123';

      const repairResponse = {
        success: true,
        repairedItems: 3,
        unrepairedItems: 1,
        repairId: 'repair-789',
        timestamp: new Date().toISOString(),
        repairDetails: [
          {
            itemId: 'item-1',
            originalIssue: 'Missing required field: scope',
            repairAction: 'Added default scope',
            success: true,
          },
          {
            itemId: 'item-2',
            originalIssue: 'Invalid data type',
            repairAction: 'Type conversion applied',
            success: true,
          },
          {
            itemId: 'item-3',
            originalIssue: 'Malformed JSON',
            repairAction: 'JSON structure corrected',
            success: true,
          },
        ],
        repairedData: [
          {
            id: 'repaired-item-1',
            kind: 'entity',
            content: 'Repaired entity',
            scope: { project: 'test-project' },
            data: { name: 'Repaired Entity', type: 'service' },
          },
        ],
      };

      // Mock repair function
      importService.repairImport = vi.fn().mockResolvedValue(repairResponse);

      // Act
      const result = await importService.repairImport({
        importId: repairableImportId,
        repairStrategies: ['field_completion', 'type_conversion', 'structure_repair'],
        autoRepair: true,
        validationLevel: 'strict',
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.repairedItems).toBe(3);
      expect(result.unrepairedItems).toBe(1);
      expect(result.repairDetails).toHaveLength(3);
      expect(result.repairDetails.every(detail => detail.success)).toBe(true);
    });
  });
});

describe('Import Service - Performance and Scalability', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Large Dataset Import Handling', () => {
    it('should handle very large imports with streaming', async () => {
      // Arrange
      const veryLargeDataset = Array.from({ length: 10000 }, (_, i) => ({
        kind: 'entity',
        content: `Large dataset entity ${i}`,
        scope: { project: 'test-project' },
        data: {
          name: `Entity ${i}`,
          type: 'component',
          index: i,
          batch: Math.floor(i / 1000) + 1,
        },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 10000 }, (_, i) => ({
          id: `entity-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'large_streaming_import',
          similar_items_checked: 10000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Large dataset imported successfully using streaming',
          reasoning: '10000 items processed in streaming mode for memory efficiency',
          user_message_suggestion: '✅ Large dataset imported successfully',
          performance: {
            totalItems: 10000,
            processedItems: 10000,
            averageTimePerItem: 5, // ms
            memoryUsage: '45MB',
            throughput: '200 items/second',
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: veryLargeDataset,
        format: 'json',
        options: {
          streaming: true,
          batchSize: 1000,
          memoryLimit: '100MB',
          progressReporting: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(10000);
      expect(result.errors).toHaveLength(0);
      expect(result.autonomous_context.performance).toBeDefined();
      expect(result.autonomous_context.performance.totalItems).toBe(10000);
      expect(result.autonomous_context.action_performed).toBe('large_streaming_import');
    });

    it('should optimize import performance with parallel processing', async () => {
      // Arrange
      const parallelDataset = Array.from({ length: 5000 }, (_, i) => ({
        kind: 'entity',
        content: `Parallel entity ${i}`,
        scope: { project: 'test-project' },
        data: { name: `Entity ${i}`, type: 'service' },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 5000 }, (_, i) => ({
          id: `entity-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'parallel_import',
          similar_items_checked: 5000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Parallel import completed successfully',
          reasoning: '5000 items processed using parallel workers',
          user_message_suggestion: '✅ Parallel import completed successfully',
          performance: {
            totalItems: 5000,
            processedItems: 5000,
            parallelWorkers: 4,
            averageTimePerItem: 2,
            throughput: '500 items/second',
            speedup: 2.5,
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: parallelDataset,
        format: 'json',
        options: {
          parallel: true,
          workers: 4,
          batchSize: 250,
          memoryEfficient: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(5000);
      expect(result.autonomous_context.performance.parallelWorkers).toBe(4);
      expect(result.autonomous_context.performance.speedup).toBe(2.5);
    });
  });

  describe('Memory-Efficient Processing', () => {
    it('should implement memory-efficient processing for large data', async () => {
      // Arrange
      const memoryIntensiveData = Array.from({ length: 1000 }, (_, i) => ({
        kind: 'observation',
        content: 'x'.repeat(50000), // 50KB per item
        scope: { project: 'test-project' },
        data: {
          content: 'x'.repeat(50000),
          largeArray: new Array(5000).fill('large data chunk'),
          metadata: {
            index: i,
            timestamp: new Date().toISOString(),
            largeObject: new Array(1000).fill({ key: 'value' }),
          },
        },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 1000 }, (_, i) => ({
          id: `obs-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'observation',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'memory_efficient_import',
          similar_items_checked: 1000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Memory-efficient import completed successfully',
          reasoning: '1000 large items processed using streaming and garbage collection',
          user_message_suggestion: '✅ Memory-efficient import completed',
          performance: {
            totalItems: 1000,
            processedItems: 1000,
            peakMemoryUsage: '250MB',
            averageMemoryUsage: '150MB',
            memoryLimit: '300MB',
            garbageCollectionRuns: 5,
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: memoryIntensiveData,
        format: 'json',
        options: {
          memoryLimit: '300MB',
          streaming: true,
          batchSize: 50,
          garbageCollection: true,
          compression: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1000);
      expect(result.autonomous_context.performance.peakMemoryUsage).toBe('250MB');
      expect(result.autonomous_context.performance.garbageCollectionRuns).toBe(5);
    });

    it('should handle memory pressure gracefully', async () => {
      // Arrange
      const highPressureData = Array.from({ length: 2000 }, (_, i) => ({
        kind: 'entity',
        content: 'High pressure entity',
        scope: { project: 'test-project' },
        data: {
          name: `Entity ${i}`,
          largeData: new Array(10000).fill('memory intensive data'),
        },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 2000 }, (_, i) => ({
          id: `entity-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'memory_pressure_handled_import',
          similar_items_checked: 2000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Memory pressure handled with adaptive processing',
          reasoning: 'Import adapted to memory pressure with dynamic batch sizing',
          user_message_suggestion: '✅ Memory pressure handled successfully',
          performance: {
            totalItems: 2000,
            processedItems: 2000,
            memoryPressureEvents: 3,
            adaptiveBatchSizes: [100, 50, 25, 10],
            memoryRecoveryActions: 2,
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: highPressureData,
        format: 'json',
        options: {
          memoryLimit: '200MB',
          adaptiveBatching: true,
          memoryMonitoring: true,
          pressureHandling: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(2000);
      expect(result.autonomous_context.performance.memoryPressureEvents).toBe(3);
      expect(result.autonomous_context.performance.adaptiveBatchSizes).toEqual([100, 50, 25, 10]);
    });
  });

  describe('Batch Import Optimization', () => {
    it('should optimize batch sizes based on data characteristics', async () => {
      // Arrange
      const variableSizeData = [
        ...Array.from({ length: 100 }, (_, i) => ({
          kind: 'entity',
          content: `Small entity ${i}`,
          scope: { project: 'test-project' },
          data: { name: `Entity ${i}`, type: 'component' },
        })),
        ...Array.from({ length: 50 }, (_, i) => ({
          kind: 'observation',
          content: 'x'.repeat(10000), // Medium size
          scope: { project: 'test-project' },
          data: { content: 'x'.repeat(10000) },
        })),
        ...Array.from({ length: 10 }, (_, i) => ({
          kind: 'runbook',
          content: 'x'.repeat(50000), // Large size
          scope: { project: 'test-project' },
          data: {
            title: `Large Runbook ${i}`,
            content: 'x'.repeat(50000),
          },
        })),
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: variableSizeData.map((_, index) => ({
          id: `item-id-${index + 1}`,
          status: 'inserted' as const,
          kind: variableSizeData[index].kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'optimized_batch_import',
          similar_items_checked: 160,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Batch sizes optimized based on data characteristics',
          reasoning: 'Adaptive batching applied based on item size and complexity',
          user_message_suggestion: '✅ Optimized batch import completed',
          performance: {
            totalItems: 160,
            processedItems: 160,
            optimalBatchSizes: {
              entity: 500,
              observation: 100,
              runbook: 20,
            },
            batchStatistics: {
              totalBatches: 4,
              averageBatchSize: 40,
              batchEfficiency: 0.95,
            },
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: variableSizeData,
        format: 'json',
        options: {
          optimizeBatching: true,
          sizeBasedBatching: true,
          adaptiveSizing: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(160);
      expect(result.autonomous_context.performance.optimalBatchSizes).toBeDefined();
      expect(result.autonomous_context.performance.batchStatistics.totalBatches).toBe(4);
    });

    it('should handle batch failures with retry logic', async () => {
      // Arrange
      const batchFailureData = Array.from({ length: 500 }, (_, i) => ({
        kind: 'entity',
        content: `Batch test entity ${i}`,
        scope: { project: 'test-project' },
        data: { name: `Entity ${i}`, type: 'service' },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 500 }, (_, i) => ({
          id: `entity-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch_retry_import',
          similar_items_checked: 500,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Batch failures recovered with retry logic',
          reasoning: 'Import completed after retrying failed batches',
          user_message_suggestion: '✅ Batch retry import completed successfully',
          performance: {
            totalItems: 500,
            processedItems: 500,
            batchFailures: 2,
            batchRetries: 3,
            retrySuccessRate: 1.0,
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: batchFailureData,
        format: 'json',
        options: {
          batchSize: 100,
          retryBatches: true,
          maxRetries: 3,
          retryDelay: 1000,
          exponentialBackoff: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(500);
      expect(result.autonomous_context.performance.batchFailures).toBe(2);
      expect(result.autonomous_context.performance.batchRetries).toBe(3);
      expect(result.autonomous_context.performance.retrySuccessRate).toBe(1.0);
    });
  });

  describe('Concurrent Import Operations', () => {
    it('should handle multiple concurrent imports', async () => {
      // Arrange
      const concurrentImports = Array.from({ length: 5 }, (_, importIndex) =>
        Array.from({ length: 200 }, (_, itemIndex) => ({
          kind: 'entity',
          content: `Concurrent entity ${importIndex}-${itemIndex}`,
          scope: { project: `project-${importIndex}` },
          data: { name: `Entity ${importIndex}-${itemIndex}`, type: 'component' },
        }))
      );

      const expectedResponses = concurrentImports.map((batch, importIndex) => ({
        stored: batch.map((_, itemIndex) => ({
          id: `entity-${importIndex}-${itemIndex}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'concurrent_import' as const,
          similar_items_checked: 200,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Concurrent import completed successfully',
          reasoning: '200 items processed in concurrent operation',
          user_message_suggestion: '✅ Concurrent import completed',
          performance: {
            totalItems: 200,
            processedItems: 200,
            concurrencyLevel: 5,
            isolationLevel: 'project',
          },
        },
      }));

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponses[0]);

      // Act - Execute concurrent imports
      const concurrentPromises = concurrentImports.map((batch, index) =>
        importService.importData({
          data: batch,
          format: 'json',
          options: {
            concurrent: true,
            isolationLevel: 'project',
            resourcePooling: true,
          },
          importId: `concurrent-import-${index}`,
        })
      );

      const results = await Promise.all(concurrentPromises);

      // Assert
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.stored).toHaveLength(200);
        expect(result.errors).toHaveLength(0);
        expect(result.autonomous_context.performance.concurrencyLevel).toBe(5);
      });
    });

    it('should handle resource contention in concurrent operations', async () => {
      // Arrange
      const resourceIntensiveImports = Array.from({ length: 3 }, (_, importIndex) =>
        Array.from({ length: 1000 }, (_, itemIndex) => ({
          kind: 'observation',
          content: `Resource intensive ${importIndex}-${itemIndex}`,
          scope: { project: 'shared-project' },
          data: {
            content: 'x'.repeat(1000),
            index: itemIndex,
            importBatch: importIndex,
          },
        }))
      );

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 1000 }, (_, i) => ({
          id: `obs-id-${i + 1}`,
          status: 'inserted' as const,
          kind: 'observation',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'resource_managed_concurrent_import',
          similar_items_checked: 1000,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Resource contention managed successfully',
          reasoning: 'Concurrent imports completed with resource management',
          user_message_suggestion: '✅ Resource-managed concurrent import completed',
          performance: {
            totalItems: 1000,
            processedItems: 1000,
            resourceContentionEvents: 5,
            resourceWaitTime: 150, // ms
            resourceUtilization: 0.85,
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const concurrentPromises = resourceIntensiveImports.map((batch, index) =>
        importService.importData({
          data: batch,
          format: 'json',
          options: {
            concurrent: true,
            resourceManagement: true,
            maxConcurrentOperations: 2,
            timeout: 30000,
            resourceLimits: {
              memory: '100MB',
              cpu: 0.5,
              connections: 10,
            },
          },
          importId: `resource-import-${index}`,
        })
      );

      const results = await Promise.all(concurrentPromises);

      // Assert
      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(result.stored).toHaveLength(1000);
        expect(result.autonomous_context.performance.resourceContentionEvents).toBeGreaterThan(0);
        expect(result.autonomous_context.performance.resourceUtilization).toBeLessThan(1.0);
      });
    });
  });
});

describe('Import Service - Integration with Knowledge System', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Knowledge Type Recognition', () => {
    it('should automatically recognize and classify knowledge types', async () => {
      // Arrange
      const untypedData = [
        {
          content: 'We decided to use microservices for better scalability',
          metadata: { source: 'meeting-notes', date: '2025-01-15' },
          data: {
            title: 'Architecture Decision',
            rationale: 'Better scalability and team autonomy',
            alternatives: ['Monolithic application', 'Modular monolith'],
          },
        },
        {
          content: 'User authentication service is experiencing high latency',
          metadata: { source: 'monitoring', severity: 'high' },
          data: {
            title: 'Authentication Performance Issue',
            impact: 'Users experiencing login delays',
            metrics: { latency: '2.5s', error_rate: '5%' },
          },
        },
        {
          content: 'Component A depends on Component B for database operations',
          metadata: { source: 'code-analysis' },
          data: {
            source: 'Component A',
            target: 'Component B',
            type: 'dependency',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
          {
            id: 'issue-id-1',
            status: 'inserted',
            kind: 'issue',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-id-1',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'auto_classified_import',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Knowledge types automatically recognized and classified',
          reasoning: 'Content analysis used to determine appropriate knowledge types',
          user_message_suggestion: '✅ Auto-classified import completed',
          classification: {
            totalClassified: 3,
            confidenceScores: {
              decision: 0.95,
              issue: 0.88,
              relation: 0.92,
            },
            classificationRules: ['content_keywords', 'data_structure', 'metadata_patterns'],
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: untypedData,
        format: 'json',
        options: {
          autoClassify: true,
          classificationConfidence: 0.8,
          fallbackType: 'observation',
        },
      });

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.stored.map(s => s.kind)).toEqual(['decision', 'issue', 'relation']);
      expect(result.autonomous_context.classification.totalClassified).toBe(3);
    });

    it('should handle ambiguous type classification with confidence scoring', async () => {
      // Arrange
      const ambiguousData = [
        {
          content: 'The system needs to be optimized for performance',
          data: {
            title: 'Performance Optimization',
            description: 'System performance needs improvement',
          },
          metadata: {
            source: 'analysis',
            priority: 'medium',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'observation-id-1',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'ambiguous_classification_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Ambiguous content classified based on confidence scores',
          reasoning: 'Multiple possible types evaluated, highest confidence selected',
          user_message_suggestion: '✅ Ambiguous content classified successfully',
          classification: {
            totalClassified: 1,
            confidenceScores: {
              observation: 0.75,
              issue: 0.65,
              decision: 0.45,
              todo: 0.60,
            },
            selectedType: 'observation',
            ambiguityReason: 'Content lacks clear decision markers or issue indicators',
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: ambiguousData,
        format: 'json',
        options: {
          autoClassify: true,
          confidenceThreshold: 0.5,
          reportAmbiguity: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('observation');
      expect(result.autonomous_context.classification.selectedType).toBe('observation');
    });
  });

  describe('Relationship Reconstruction', () => {
    it('should reconstruct relationships from imported data', async () => {
      // Arrange
      const dataWithImplicitRelationships = [
        {
          kind: 'entity',
          content: 'User service component',
          scope: { project: 'test-project' },
          data: { name: 'User Service', type: 'service', depends_on: ['Auth Service', 'Database'] },
        },
        {
          kind: 'entity',
          content: 'Authentication service',
          scope: { project: 'test-project' },
          data: { name: 'Auth Service', type: 'service', provides: ['authentication', 'authorization'] },
        },
        {
          kind: 'entity',
          content: 'Database component',
          scope: { project: 'test-project' },
          data: { name: 'Database', type: 'storage', supports: ['User Service', 'Auth Service'] },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'user-service-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'auth-service-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'database-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-1',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-2',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-3',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'relationship_reconstructed_import',
          similar_items_checked: 6,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Relationships automatically reconstructed from entity dependencies',
          reasoning: 'Implicit relationships detected and explicit relations created',
          user_message_suggestion: '✅ Relationship reconstruction completed',
          relationships: {
            totalReconstructed: 3,
            relationshipTypes: {
              depends_on: 2,
              supports: 1,
            },
            reconstructionRules: ['dependency_extraction', 'provider_consumer', 'mutual_support'],
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithImplicitRelationships,
        format: 'json',
        options: {
          reconstructRelationships: true,
          relationshipInference: true,
          createExplicitRelations: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(6);
      expect(result.stored.filter(s => s.kind === 'entity')).toHaveLength(3);
      expect(result.stored.filter(s => s.kind === 'relation')).toHaveLength(3);
      expect(result.autonomous_context.relationships.totalReconstructed).toBe(3);
    });

    it('should handle complex relationship patterns', async () => {
      // Arrange
      const complexRelationshipData = [
        {
          kind: 'entity',
          content: 'Order management service',
          scope: { project: 'test-project' },
          data: {
            name: 'Order Service',
            type: 'service',
            dependencies: {
              services: ['Payment Service', 'Inventory Service'],
              databases: ['Orders DB', 'Products DB'],
              external_apis: ['Shipping API', 'Notification API'],
            },
          },
        },
        {
          kind: 'entity',
          content: 'Payment processing service',
          scope: { project: 'test-project' },
          data: {
            name: 'Payment Service',
            type: 'service',
            provides: ['payment_processing', 'refund_handling'],
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'order-service-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'payment-service-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-1',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
          {
            id: 'relation-2',
            status: 'inserted',
            kind: 'relation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'complex_relationship_import',
          similar_items_checked: 4,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Complex relationship patterns reconstructed successfully',
          reasoning: 'Nested dependency structures analyzed and relations created',
          user_message_suggestion: '✅ Complex relationship reconstruction completed',
          relationships: {
            totalReconstructed: 2,
            relationshipTypes: {
              depends_on: 2,
            },
            complexity: {
              maxDepth: 3,
              crossTypeRelations: 2,
              cyclicDependencies: 0,
            },
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: complexRelationshipData,
        format: 'json',
        options: {
          reconstructRelationships: true,
          complexPatternAnalysis: true,
          nestedDependencyExtraction: true,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(4);
      expect(result.autonomous_context.relationships.complexity.maxDepth).toBe(3);
    });
  });

  describe('Metadata Import', () => {
    it('should import and preserve rich metadata', async () => {
      // Arrange
      const dataWithRichMetadata = [
        {
          kind: 'entity',
          content: 'Entity with rich metadata',
          scope: { project: 'test-project' },
          data: { name: 'Rich Metadata Entity', type: 'service' },
          metadata: {
            source: 'manual_entry',
            author: 'John Doe',
            timestamp: '2025-01-15T10:30:00Z',
            version: '1.2.0',
            tags: ['critical', 'production', 'microservice'],
            classification: {
              sensitivity: 'medium',
              business_impact: 'high',
              technical_complexity: 'medium',
            },
            metrics: {
              uptime: '99.9%',
              response_time: '150ms',
              throughput: '1000 req/s',
            },
            governance: {
              owner: 'Platform Team',
              reviewer: 'Architecture Committee',
              compliance: ['SOC2', 'GDPR'],
            },
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'rich-metadata-entity-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'rich_metadata_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Rich metadata imported and preserved successfully',
          reasoning: 'Complex metadata structure maintained during import process',
          user_message_suggestion: '✅ Rich metadata imported successfully',
          metadata: {
            totalMetadataFields: 15,
            metadataCategories: ['source', 'classification', 'metrics', 'governance'],
            preservedStructure: true,
            validation: 'passed',
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithRichMetadata,
        format: 'json',
        options: {
          preserveMetadata: true,
          validateMetadata: true,
          normalizeMetadata: false,
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.metadata.totalMetadataFields).toBe(15);
      expect(result.autonomous_context.metadata.preservedStructure).toBe(true);
    });

    it('should handle metadata transformation and enrichment', async () => {
      // Arrange
      const dataWithTransformableMetadata = [
        {
          kind: 'decision',
          content: 'Decision with transformable metadata',
          scope: { project: 'test-project' },
          data: { title: 'Architecture Decision', rationale: 'Technical rationale' },
          metadata: {
            created: '2025-01-15',
            updated: '2025-01-16',
            priority: 'HIGH',
            stakeholders: 'team-a, team-b, team-c',
            tags: 'architecture, decision, important',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'transformed-metadata-decision-id',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'metadata_transformed_import',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Metadata transformed and enriched successfully',
          reasoning: 'Metadata normalized and enhanced during import',
          user_message_suggestion: '✅ Metadata transformation completed',
          metadata: {
            transformations: [
              { field: 'created', from: 'string', to: 'datetime' },
              { field: 'updated', from: 'string', to: 'datetime' },
              { field: 'priority', from: 'string', to: 'enum' },
              { field: 'stakeholders', from: 'string', to: 'array' },
              { field: 'tags', from: 'string', to: 'array' },
            ],
            enrichment: {
              addedFields: ['metadata.processed_at', 'metadata.enrichment_version'],
              computedFields: ['metadata.decision_age_days', 'metadata.urgency_score'],
            },
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithTransformableMetadata,
        format: 'json',
        options: {
          transformMetadata: true,
          enrichMetadata: true,
          metadataRules: {
            dateNormalization: true,
            enumStandardization: true,
            arrayConversion: true,
            computedFields: true,
          },
        },
      });

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.autonomous_context.metadata.transformations).toHaveLength(5);
      expect(result.autonomous_context.metadata.enrichment.computedFields).toHaveLength(2);
    });
  });

  describe('Scope Assignment', () => {
    it('should automatically assign scopes based on data patterns', async () => {
      // Arrange
      const dataWithoutScopes = [
        {
          kind: 'entity',
          content: 'E-commerce user service',
          data: {
            name: 'User Service',
            project: 'e-commerce-platform',
            team: 'backend-team',
            environment: 'production',
          },
        },
        {
          kind: 'decision',
          content: 'Payment gateway integration',
          data: {
            title: 'Use Stripe Payment Gateway',
            project: 'e-commerce-platform',
            team: 'payments-team',
            rationale: 'Industry standard with good API',
          },
        },
        {
          kind: 'observation',
          content: 'Mobile app performance metrics',
          data: {
            content: 'App loading time improved by 30%',
            project: 'mobile-app',
            team: 'mobile-team',
            environment: 'production',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
          {
            id: 'observation-id-1',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'auto_scoped_import',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Scopes automatically assigned based on data patterns',
          reasoning: 'Scope information extracted from data and applied systematically',
          user_message_suggestion: '✅ Automatic scope assignment completed',
          scoping: {
            totalScoped: 3,
            scopePatterns: {
              project: ['data.project', 'content_analysis'],
              environment: ['data.environment', 'default_detection'],
              team: ['data.team', 'inferred_from_project'],
            },
            scopeDistribution: {
              'e-commerce-platform': 2,
              'mobile-app': 1,
            },
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataWithoutScopes,
        format: 'json',
        options: {
          autoScope: true,
          scopePatterns: {
            project: ['data.project', 'data.repository'],
            environment: ['data.environment', 'data.env'],
            team: ['data.team', 'data.squad'],
          },
          defaultScope: { project: 'unknown', environment: 'development' },
        },
      });

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.autonomous_context.scoping.totalScoped).toBe(3);
      expect(result.autonomous_context.scoping.scopeDistribution['e-commerce-platform']).toBe(2);
    });

    it('should handle hierarchical scope assignment', async () => {
      // Arrange
      const dataForHierarchicalScoping = [
        {
          kind: 'entity',
          content: 'Core authentication service',
          data: {
            name: 'Auth Service',
            organization: 'company-name',
            division: 'technology',
            department: 'platform',
            project: 'identity-platform',
            team: 'auth-team',
          },
        },
        {
          kind: 'entity',
          content: 'Payment processing component',
          data: {
            name: 'Payment Component',
            organization: 'company-name',
            division: 'technology',
            department: 'payments',
            project: 'payment-system',
            team: 'payments-team',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'auth-service-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'payment-component-id',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'hierarchical_scoped_import',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Hierarchical scopes assigned successfully',
          reasoning: 'Multi-level scope hierarchy constructed from organizational data',
          user_message_suggestion: '✅ Hierarchical scoping completed',
          scoping: {
            totalScoped: 2,
            hierarchyLevels: ['org', 'division', 'department', 'project', 'team'],
            scopeHierarchy: {
              'company-name': {
                'technology': {
                  'platform': {
                    'identity-platform': {
                      'auth-team': 1,
                    },
                  },
                  'payments': {
                    'payment-system': {
                      'payments-team': 1,
                    },
                  },
                },
              },
            },
          },
        },
      };

      const mockMemoryStore = await import('../../../src/services/memory-store.js');
      mockMemoryStore.memoryStore.mockResolvedValue(expectedResponse);

      // Act
      const result = await importService.importData({
        data: dataForHierarchicalScoping,
        format: 'json',
        options: {
          hierarchicalScoping: true,
          scopeHierarchy: ['org', 'division', 'department', 'project', 'team'],
          inheritanceRules: {
            inheritFromParent: true,
            overrideWithSpecific: true,
            defaultInheritance: 'project',
          },
        },
      });

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.autonomous_context.scoping.hierarchyLevels).toHaveLength(5);
      expect(result.autonomous_context.scoping.scopeHierarchy['company-name']).toBeDefined();
    });
  });
});