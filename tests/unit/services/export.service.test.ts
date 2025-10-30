/**
 * Comprehensive Unit Tests for Export Service
 *
 * Tests advanced export service functionality including:
 * - Knowledge base export in multiple formats (JSON, CSV, XML, PDF)
 * - Bulk data export with filtering capabilities
 * - Incremental export operations with progress tracking
 * - Format handling with proper schema validation
 * - Performance and scalability for large datasets
 * - Security and access control for export operations
 * - Integration with knowledge system components
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ExportService } from '../../../src/services/export/export-service';
import type {
  KnowledgeItem,
  ExportOptions,
  ExportResult,
  ExportFormat,
  ExportFilter,
  ExportProgress
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient
}));

// Mock Qdrant client with comprehensive data models
const mockQdrantClient = {
  section: {
    findMany: vi.fn()
  },
  adrDecision: {
    findMany: vi.fn()
  },
  issueLog: {
    findMany: vi.fn()
  },
  todoLog: {
    findMany: vi.fn()
  },
  runbook: {
    findMany: vi.fn()
  },
  changeLog: {
    findMany: vi.fn()
  },
  releaseNote: {
    findMany: vi.fn()
  },
  ddlHistory: {
    findMany: vi.fn()
  },
  prContext: {
    findMany: vi.fn()
  },
  knowledgeEntity: {
    findMany: vi.fn()
  },
  knowledgeRelation: {
    findMany: vi.fn()
  },
  knowledgeObservation: {
    findMany: vi.fn()
  },
  incidentLog: {
    findMany: vi.fn()
  },
  releaseLog: {
    findMany: vi.fn()
  },
  riskLog: {
    findMany: vi.fn()
  },
  assumptionLog: {
    findMany: vi.fn()
  }
};

// Mock file system operations
const mockFileSystem = {
  writeFile: vi.fn(),
  createWriteStream: vi.fn(),
  statSync: vi.fn(),
  mkdirSync: vi.fn()
};

// Mock PDF generation
const mockPDFGenerator = {
  generate: vi.fn(),
  addPage: vi.fn(),
  save: vi.fn()
};

// Mock CSV writer
const mockCSVWriter = {
  write: vi.fn(),
  pipe: vi.fn(),
  end: vi.fn()
};

// Mock XML serializer
const mockXMLSerializer = {
  serialize: vi.fn(),
  parse: vi.fn()
};

describe('ExportService - Comprehensive Export Functionality', () => {
  let exportService: ExportService;
  let mockKnowledgeItems: KnowledgeItem[];

  beforeEach(() => {
    exportService = new ExportService();

    // Setup comprehensive mock data
    mockKnowledgeItems = [
      {
        id: 'entity-1',
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: { name: 'Test Entity', type: 'component' },
        created_at: '2024-01-15T10:00:00Z',
        updated_at: '2024-01-20T15:30:00Z'
      },
      {
        id: 'decision-1',
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: { title: 'Architecture Decision', status: 'approved' },
        created_at: '2024-01-16T11:00:00Z',
        updated_at: '2024-01-16T11:00:00Z'
      },
      {
        id: 'issue-1',
        kind: 'issue',
        scope: { project: 'test-project', branch: 'develop' },
        data: { title: 'Bug Report', severity: 'high', status: 'open' },
        created_at: '2024-01-17T12:00:00Z',
        updated_at: '2024-01-18T09:00:00Z'
      },
      {
        id: 'relation-1',
        kind: 'relation',
        scope: { project: 'test-project', branch: 'main' },
        data: { from: 'entity-1', to: 'decision-1', type: 'has_decision' },
        created_at: '2024-01-18T13:00:00Z',
        updated_at: '2024-01-18T13:00:00Z'
      }
    ];

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      model.findMany.mockResolvedValue(mockKnowledgeItems);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Export Operations Tests
  describe('Export Operations', () => {
    it('should export knowledge base in JSON format with proper schema validation', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity', 'decision'],
        scope: { project: 'test-project' },
        includeMetadata: true,
        validateSchema: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.format).toBe('json');
      expect(result.data).toBeDefined();
      expect(result.totalItems).toBeGreaterThan(0);
      expect(result.metadata.schema).toBeDefined();

      // Verify JSON structure
      const jsonData = JSON.parse(result.data);
      expect(jsonData).toHaveProperty('items');
      expect(jsonData).toHaveProperty('metadata');
      expect(jsonData.items).toBeInstanceOf(Array);
    });

    it('should handle bulk export with multiple knowledge types efficiently', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity', 'decision', 'issue', 'relation'],
        scope: { project: 'test-project' },
        batchSize: 100,
        maxItems: 1000
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.totalItems).toBeGreaterThanOrEqual(0);
      expect(result.metadata.exportedTypes).toEqual(['entity', 'decision', 'issue', 'relation']);
      expect(result.metadata.batchSize).toBe(100);
    });

    it('should support incremental export operations with date range filtering', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        incremental: true,
        dateRange: {
          startDate: new Date('2024-01-16'),
          endDate: new Date('2024-01-18')
        },
        scope: { project: 'test-project' }
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.incremental).toBe(true);
      expect(result.metadata.dateRange).toBeDefined();

      // Verify only items within date range are included
      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: any) => {
        const itemDate = new Date(item.created_at);
        expect(itemDate).toBeGreaterThanOrEqual(exportOptions.dateRange!.startDate);
        expect(itemDate).toBeLessThanOrEqual(exportOptions.dateRange!.endDate);
      });
    });

    it('should track export progress accurately for long-running operations', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity', 'decision'],
        trackProgress: true,
        progressCallback: vi.fn()
      };

      // Mock slow database response
      mockQdrantClient.entity.findMany.mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve(mockKnowledgeItems), 100))
      );

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(exportOptions.progressCallback).toHaveBeenCalled();
      expect(result.metadata.progressTracking).toBe(true);
    });
  });

  // 2. Format Handling Tests
  describe('Format Handling', () => {
    it('should export data in CSV format with configurable delimiters', async () => {
      const exportOptions: ExportOptions = {
        format: 'csv',
        types: ['entity'],
        csvOptions: {
          delimiter: ';',
          includeHeaders: true,
          quoteFields: true
        }
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.format).toBe('csv');
      expect(result.data).toContain(';');
      expect(result.metadata.csvOptions).toBeDefined();
    });

    it('should generate comprehensive PDF reports with proper formatting', async () => {
      const exportOptions: ExportOptions = {
        format: 'pdf',
        types: ['decision', 'issue'],
        pdfOptions: {
          title: 'Knowledge Export Report',
          includeTableOfContents: true,
          pageSize: 'A4',
          orientation: 'portrait'
        }
      };

      // Mock PDF generation
      mockPDFGenerator.generate.mockResolvedValue(Buffer.from('mock-pdf-content'));

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.format).toBe('pdf');
      expect(result.data).toBeInstanceOf(Buffer);
      expect(mockPDFGenerator.generate).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Knowledge Export Report',
          pageSize: 'A4'
        })
      );
    });

    it('should handle XML export with proper structure and validation', async () => {
      const exportOptions: ExportOptions = {
        format: 'xml',
        types: ['entity', 'relation'],
        xmlOptions: {
          rootElement: 'knowledgeBase',
          prettyPrint: true,
          includeSchema: true
        }
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.format).toBe('xml');
      expect(result.data).toContain('<?xml');
      expect(result.data).toContain('<knowledgeBase>');
      expect(result.metadata.xmlOptions).toBeDefined();
    });

    it('should support custom format extensions and plugins', async () => {
      const customFormatter = {
        format: 'custom',
        transform: vi.fn().mockReturnValue('custom-formatted-data')
      };

      const exportOptions: ExportOptions = {
        format: 'custom',
        types: ['entity'],
        customFormatter: customFormatter
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.format).toBe('custom');
      expect(result.data).toBe('custom-formatted-data');
      expect(customFormatter.transform).toHaveBeenCalledWith(mockKnowledgeItems);
    });
  });

  // 3. Filtering and Selection Tests
  describe('Filtering and Selection', () => {
    it('should apply date range filtering accurately', async () => {
      const filter: ExportFilter = {
        dateRange: {
          startDate: new Date('2024-01-16'),
          endDate: new Date('2024-01-17')
        }
      };

      const exportOptions: ExportOptions = {
        format: 'json',
        filter: filter
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.appliedFilters).toContain('dateRange');

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: KnowledgeItem) => {
        const itemDate = new Date(item.created_at!);
        expect(itemDate.getTime()).toBeGreaterThanOrEqual(filter.dateRange!.startDate.getTime());
        expect(itemDate.getTime()).toBeLessThanOrEqual(filter.dateRange!.endDate.getTime());
      });
    });

    it('should filter by knowledge types effectively', async () => {
      const filter: ExportFilter = {
        types: ['entity', 'decision']
      };

      const exportOptions: ExportOptions = {
        format: 'json',
        filter: filter
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.appliedFilters).toContain('types');

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: KnowledgeItem) => {
        expect(['entity', 'decision']).toContain(item.kind);
      });
    });

    it('should support scope-based filtering for project, branch, and org', async () => {
      const filter: ExportFilter = {
        scope: {
          project: 'test-project',
          branch: 'main'
        }
      };

      const exportOptions: ExportOptions = {
        format: 'json',
        filter: filter
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.appliedFilters).toContain('scope');

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: KnowledgeItem) => {
        expect(item.scope.project).toBe('test-project');
        expect(item.scope.branch).toBe('main');
      });
    });

    it('should handle complex custom filter criteria', async () => {
      const customFilter = (item: KnowledgeItem) => {
        return item.data.status === 'approved' || item.data.severity === 'high';
      };

      const filter: ExportFilter = {
        customFilter: customFilter
      };

      const exportOptions: ExportOptions = {
        format: 'json',
        filter: filter
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.appliedFilters).toContain('custom');

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: KnowledgeItem) => {
        expect(customFilter(item)).toBe(true);
      });
    });
  });

  // 4. Performance and Scalability Tests
  describe('Performance and Scalability', () => {
    it('should handle large dataset exports efficiently', async () => {
      // Mock large dataset
      const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
        id: `item-${i}`,
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { name: `Entity ${i}` },
        created_at: new Date().toISOString()
      }));

      mockQdrantClient.entity.findMany.mockResolvedValue(largeDataset);

      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        batchSize: 1000,
        maxMemoryMB: 100
      };

      const startTime = Date.now();
      const result = await exportService.exportKnowledge(exportOptions);
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(result.totalItems).toBe(10000);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
      expect(result.metadata.performanceMetrics).toBeDefined();
    });

    it('should use memory-efficient streaming for large exports', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        streaming: true,
        types: ['entity'],
        chunkSize: 500
      };

      const stream = await exportService.exportStream(exportOptions);

      expect(stream).toBeDefined();
      expect(typeof stream.pipe).toBe('function');

      // Verify streaming is initiated
      expect(mockFileSystem.createWriteStream).toHaveBeenCalled();
    });

    it('should support concurrent export operations', async () => {
      const exportOptions1: ExportOptions = {
        format: 'json',
        types: ['entity'],
        scope: { project: 'project-1' }
      };

      const exportOptions2: ExportOptions = {
        format: 'csv',
        types: ['decision'],
        scope: { project: 'project-2' }
      };

      const [result1, result2] = await Promise.all([
        exportService.exportKnowledge(exportOptions1),
        exportService.exportKnowledge(exportOptions2)
      ]);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.format).toBe('json');
      expect(result2.format).toBe('csv');
    });

    it('should optimize export performance with caching', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        enableCaching: true,
        cacheKey: 'test-cache-key'
      };

      // First export
      const result1 = await exportService.exportKnowledge(exportOptions);

      // Second export (should use cache)
      const result2 = await exportService.exportKnowledge(exportOptions);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result2.metadata.cacheHit).toBe(true);
    });
  });

  // 5. Security and Access Control Tests
  describe('Security and Access Control', () => {
    it('should validate export permissions before processing', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        user: { id: 'user-1', role: 'viewer' },
        requiredPermissions: ['export:read']
      };

      // Mock permission check to fail
      vi.spyOn(exportService, 'checkExportPermissions').mockResolvedValue(false);

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('permission');
    });

    it('should filter sensitive data based on access level', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        user: { id: 'user-1', role: 'viewer' },
        filterSensitiveData: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.sensitiveDataFiltered).toBe(true);

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: any) => {
        expect(item).not.toHaveProperty('internalNotes');
        expect(item).not.toHaveProperty('secretData');
      });
    });

    it('should log export operations for audit purposes', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        user: { id: 'user-1' },
        enableAuditLogging: true
      };

      const auditLogSpy = vi.spyOn(exportService, 'logExportAudit');

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(auditLogSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'export',
          format: 'json',
          userId: 'user-1'
        })
      );
    });

    it('should generate secure temporary files for exports', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        useSecureTempFiles: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.secureTempFile).toBe(true);
      expect(result.tempFilePath).toMatch(/secure-/);
    });
  });

  // 6. Integration with Knowledge System Tests
  describe('Knowledge System Integration', () => {
    it('should export knowledge graph with relationships preserved', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity', 'relation'],
        includeRelationships: true,
        preserveGraphStructure: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.graphStructurePreserved).toBe(true);

      const jsonData = JSON.parse(result.data);
      expect(jsonData).toHaveProperty('entities');
      expect(jsonData).toHaveProperty('relations');
      expect(jsonData).toHaveProperty('graph');
    });

    it('should export all metadata and maintain cross-entity consistency', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        includeAllMetadata: true,
        ensureConsistency: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.allMetadataIncluded).toBe(true);
      expect(result.metadata.consistencyCheck).toBe('passed');

      const jsonData = JSON.parse(result.data);
      jsonData.items.forEach((item: KnowledgeItem) => {
        expect(item).toHaveProperty('metadata');
        expect(item).toHaveProperty('created_at');
        expect(item).toHaveProperty('updated_at');
      });
    });

    it('should handle cross-references and dependencies during export', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['decision', 'entity'],
        includeDependencies: true,
        resolveReferences: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.dependenciesIncluded).toBe(true);
      expect(result.metadata.referencesResolved).toBe(true);

      const jsonData = JSON.parse(result.data);
      const decisions = jsonData.items.filter((item: any) => item.kind === 'decision');
      decisions.forEach((decision: any) => {
        if (decision.data.relatedEntities) {
          expect(Array.isArray(decision.data.relatedEntities)).toBe(true);
        }
      });
    });

    it('should maintain data integrity across different knowledge types', async () => {
      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity', 'decision', 'issue', 'relation'],
        validateIntegrity: true,
        includeChecksum: true
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.metadata.integrityValidated).toBe(true);
      expect(result.metadata.checksum).toBeDefined();
      expect(result.dataChecksum).toBeDefined();
    });
  });

  // 7. Error Handling and Edge Cases
  describe('Error Handling and Edge Cases', () => {
    it('should handle database connection failures gracefully', async () => {
      mockQdrantClient.entity.findMany.mockRejectedValue(new Error('Database connection failed'));

      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity']
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Database connection failed');
      expect(result.retryAttempts).toBeGreaterThanOrEqual(0);
    });

    it('should handle empty result sets appropriately', async () => {
      mockQdrantClient.entity.findMany.mockResolvedValue([]);

      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity']
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(true);
      expect(result.totalItems).toBe(0);
      expect(result.metadata.emptyResult).toBe(true);
    });

    it('should validate export options and provide helpful error messages', async () => {
      const invalidOptions: any = {
        format: 'invalid-format',
        types: 'not-an-array'
      };

      const result = await exportService.exportKnowledge(invalidOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid format');
      expect(result.validationErrors).toBeDefined();
    });

    it('should handle file system errors during export file creation', async () => {
      mockFileSystem.writeFile.mockRejectedValue(new Error('File system error'));

      const exportOptions: ExportOptions = {
        format: 'json',
        types: ['entity'],
        saveToFile: true,
        filePath: '/tmp/export.json'
      };

      const result = await exportService.exportKnowledge(exportOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('File system error');
    });
  });
});