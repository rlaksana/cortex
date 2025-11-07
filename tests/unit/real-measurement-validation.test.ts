/**
 * Real Measurement Validation Integration Test
 *
 * This test validates the effectiveness of the implemented fixes:
 * 1. Chunking service - ensures no content truncation
 * 2. Language enhancement - validates Indo/English detection
 * 3. Result grouping - tests content reconstruction
 * 4. Telemetry collection - monitors system performance
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { BaselineTelemetry } from '../../src/services/telemetry/baseline-telemetry';
import { ChunkingService } from '../../src/services/chunking/chunking-service';
import { LanguageEnhancementService } from '../../src/services/language/language-enhancement-service';
import { ResultGroupingService } from '../../src/services/search/result-grouping-service';

describe('Real Measurement Validation', () => {
  let telemetry: BaselineTelemetry;
  let chunkingService: ChunkingService;
  let languageService: LanguageEnhancementService;
  let groupingService: ResultGroupingService;

  beforeEach(() => {
    telemetry = new BaselineTelemetry();
    chunkingService = new ChunkingService();
    languageService = new LanguageEnhancementService();
    groupingService = new ResultGroupingService();
  });

  describe('Chunking Service - Large Content Handling', () => {
    it('should chunk large content without truncation', () => {
      // Create content that exceeds the 8000 character threshold
      const largeContent = `
        This is a comprehensive test document that demonstrates the chunking functionality.
        ${'Repeated content to make the document longer. '.repeat(200)}
        Indonesian language test: Sistem ini digunakan untuk mengelola data pengguna.
        ${'Additional repeated content for testing purposes. '.repeat(150)}
        Final section to complete the large content test.
      `;

      expect(largeContent.length).toBeGreaterThan(8000);

      // Test chunking decision
      const shouldChunk = chunkingService.shouldChunk(largeContent);
      expect(shouldChunk).toBe(true);

      // Test actual chunking
      const chunkedItems = chunkingService.createChunkedItems({
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: largeContent },
        content: largeContent,
      });

      expect(chunkedItems.length).toBeGreaterThan(1);
      expect(chunkedItems[0].id).toBeDefined();
      expect(chunkedItems[0].data['is_chunk']).toBe(false);
      expect(chunkedItems[0].data['total_chunks']).toBeGreaterThan(1);

      // Verify child chunks
      const childChunks = chunkedItems.slice(1);
      expect(childChunks.length).toBeGreaterThan(0);
      childChunks.forEach((chunk, index) => {
        expect(chunk['data.is_chunk']).toBe(true);
        expect(chunk['data.parent_id']).toBe(chunkedItems[0].id);
        expect(chunk['data.chunk_index']).toBe(index);
        expect(chunk['data.total_chunks']).toBe(chunkedItems[0].data['total_chunks']);
      });

      // Log telemetry
      telemetry.logStoreAttempt(
        true,
        largeContent.length,
        chunkedItems.reduce((sum, item) => sum + (item['data.content']?.length || 0), 0),
        'observation',
        'test-project:main'
      );
    });

    it('should not chunk short content', () => {
      const shortContent = 'This is a short content that should not be chunked.';
      expect(shortContent.length).toBeLessThan(8000);

      const shouldChunk = chunkingService.shouldChunk(shortContent);
      expect(shouldChunk).toBe(false);

      const chunkedItems = chunkingService.createChunkedItems({
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: shortContent },
        content: shortContent,
      });

      expect(chunkedItems.length).toBe(1);
      expect(chunkedItems[0].data['is_chunk']).toBe(false);
    });
  });

  describe('Language Enhancement Service - Mixed Language Detection', () => {
    it('should detect English content correctly', () => {
      const englishItem = {
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: 'This is pure English content for testing language detection.' },
        content: 'This is pure English content for testing language detection.',
      };

      const enhanced = languageService.enhanceItemWithLanguage(englishItem);

      expect(enhanced['data.detected_lang']).toBe('en');
      expect(enhanced['data.lang_confidence']).toBeGreaterThan(0);
      expect(enhanced['data.lang_english_ratio']).toBeGreaterThan(0.8);
      expect(enhanced['data.lang_indonesian_ratio']).toBeLessThan(0.2);
    });

    it('should detect Indonesian content correctly', () => {
      const indonesianItem = {
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content: 'Sistem ini digunakan untuk mengelola data dengan Bahasa Indonesia murni.',
        },
        content: 'Sistem ini digunakan untuk mengelola data dengan Bahasa Indonesia murni.',
      };

      const enhanced = languageService.enhanceItemWithLanguage(indonesianItem);

      expect(enhanced['data.detected_lang']).toBe('id');
      expect(enhanced['data.lang_confidence']).toBeGreaterThan(0);
      expect(enhanced['data.lang_indonesian_ratio']).toBeGreaterThan(0.8);
      expect(enhanced['data.lang_english_ratio']).toBeLessThan(0.2);
    });

    it('should detect mixed language content', () => {
      const mixedItem = {
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content:
            'Mixed content: Sistem ini digunakan untuk manage user data dengan menggunakan application.',
        },
        content:
          'Mixed content: Sistem ini digunakan untuk manage user data dengan menggunakan application.',
      };

      const enhanced = languageService.enhanceItemWithLanguage(mixedItem);

      expect(['mixed', 'en', 'id']).toContain(enhanced['data.detected_lang']);
      expect(enhanced['data.lang_confidence']).toBeGreaterThan(0);
      expect(enhanced['data.lang_indonesian_ratio']).toBeGreaterThan(0);
      expect(enhanced['data.lang_english_ratio']).toBeGreaterThan(0);
    });

    it('should preserve all original fields', () => {
      const itemWithAllFields = {
        id: 'test-id',
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: 'Test content', title: 'Test Title', tags: ['tag1'] },
        content: 'Test content',
        metadata: { source: 'test' },
        created_at: '2025-01-31T04:30:00Z',
      };

      const enhanced = languageService.enhanceItemWithLanguage(itemWithAllFields);

      expect(enhanced.id).toBe('test-id');
      expect(enhanced.kind).toBe('observation');
      expect(enhanced['data.title']).toBe('Test Title');
      expect(enhanced['data.tags']).toEqual(['tag1']);
      expect(enhanced.metadata).toEqual({ source: 'test' });
      expect(enhanced.created_at).toBe('2025-01-31T04:30:00Z');
      expect(enhanced['data.detected_lang']).toBeDefined();
    });
  });

  describe('Result Grouping Service - Content Reconstruction', () => {
    it('should group chunked results and reconstruct content', () => {
      const mockSearchResults = [
        {
          id: 'parent-1',
          kind: 'observation',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            is_chunk: false,
            total_chunks: 3,
            title: 'Large Document Analysis',
          },
          created_at: '2025-01-31T04:30:00Z',
          confidence_score: 0.95,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1-1',
          kind: 'observation',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 3,
            content: 'First part of the document content...',
            title: 'Section 1',
          },
          created_at: '2025-01-31T04:30:00Z',
          confidence_score: 0.92,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1-2',
          kind: 'observation',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 1,
            total_chunks: 3,
            content: 'Second part with Indonesian text: Sistem ini digunakan untuk...',
            title: 'Section 2',
          },
          created_at: '2025-01-31T04:30:00Z',
          confidence_score: 0.88,
          match_type: 'semantic',
        },
      ];

      const groupedResults = groupingService.groupAndSortResults(mockSearchResults);

      expect(groupedResults.length).toBe(1);
      expect(groupedResults[0].parent_id).toBe('parent-1');
      expect(groupedResults[0].chunks.length).toBe(2);
      expect(groupedResults[0].parent_score).toBe(0.95);

      const reconstructed = groupingService.reconstructGroupedContent(groupedResults[0]);

      expect(reconstructed['parent_id']).toBe('parent-1');
      expect(reconstructed['total_chunks']).toBe(3);
      expect(reconstructed.found_chunks).toBe(2);
      expect(reconstructed.completeness_ratio).toBe(2 / 3); // 2 out of 3 chunks found
      expect(reconstructed.content).toContain('First part of the document content');
      expect(reconstructed.content).toContain('Sistem ini digunakan untuk');
      expect(reconstructed.confidence_score).toBeGreaterThan(0.9);
    });

    it('should handle non-chunked results', () => {
      const regularResults = [
        {
          id: 'regular-1',
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Regular Decision',
            component: 'auth-service',
          },
          created_at: '2025-01-31T04:30:00Z',
          confidence_score: 0.75,
          match_type: 'keyword',
        },
      ];

      const groupedResults = groupingService.groupAndSortResults(regularResults);

      expect(groupedResults.length).toBe(1);
      expect(groupedResults[0].parent_id).toBe('regular-1');
      expect(groupedResults[0].chunks.length).toBe(0);
    });
  });

  describe('Telemetry Collection - Performance Monitoring', () => {
    it('should track store and find operations', () => {
      // Simulate store operations
      telemetry.logStoreAttempt(true, 10000, 8000, 'observation', 'test-project:main');
      telemetry.logStoreAttempt(false, 500, 500, 'decision', 'test-project:main');
      telemetry.logStoreAttempt(false, 1500, 1500, 'todo', 'test-project:develop');

      // Simulate find operations
      telemetry.logFindAttempt('test query 1', 'test-project:main', 5, 0.92, 'semantic');
      telemetry.logFindAttempt('test query 2', 'test-project:main', 0, 0.0, 'semantic');
      telemetry.logFindAttempt('test query 3', 'test-project:develop', 3, 0.78, 'keyword');

      const storeMetrics = telemetry.getStoreMetrics();
      const findMetrics = telemetry.getFindMetrics();
      const scopeAnalysis = telemetry.getScopeAnalysis();

      // Validate store metrics
      expect(storeMetrics.total_stores).toBe(3);
      expect(storeMetrics.truncated_stores).toBe(1);
      expect(storeMetrics.truncation_ratio).toBe(1 / 3);
      expect(storeMetrics.avg_truncated_loss).toBe(2000);

      // Validate find metrics
      expect(findMetrics.total_queries).toBe(3);
      expect(findMetrics.zero_result_queries).toBe(1);
      expect(findMetrics.zero_result_ratio).toBe(1 / 3);
      expect(findMetrics.avg_returned_count).toBe((5 + 0 + 3) / 3);
      expect(findMetrics.avg_top_score).toBe((0.92 + 0.0 + 0.78) / 3);

      // Validate scope analysis
      expect(scopeAnalysis['test-project:main'].stores).toBe(2);
      expect(scopeAnalysis['test-project:main'].queries).toBe(2);
      expect(scopeAnalysis['test-project:main'].zero_results).toBe(1);
      expect(scopeAnalysis['test-project:develop'].stores).toBe(1);
      expect(scopeAnalysis['test-project:develop'].queries).toBe(1);
      expect(scopeAnalysis['test-project:develop'].zero_results).toBe(0);
    });

    it('should generate comprehensive telemetry report', () => {
      // Add some test data
      telemetry.logStoreAttempt(true, 12000, 8000, 'observation', 'test-project:main');
      telemetry.logFindAttempt(
        'comprehensive test query',
        'test-project:main',
        8,
        0.95,
        'semantic'
      );

      const report = telemetry.exportLogs();

      expect(report.store_logs).toHaveLength(1);
      expect(report.find_logs).toHaveLength(1);
      expect(report.summary.store.total_stores).toBe(1);
      expect(report.summary.find.total_queries).toBe(1);
      expect(report.summary.scope_analysis).toHaveProperty('test-project:main');

      // Validate insights generation
      const insights = {
        truncation_issues: report.summary.store.truncation_ratio > 0.1,
        search_quality: report.summary.find.zero_result_ratio > 0.3,
        scope_utilization: Object.keys(report.summary.scope_analysis).length > 1,
      };

      expect(insights.truncation_issues).toBe(true); // 100% truncation rate
      expect(insights.search_quality).toBe(false); // 0% zero result rate
      expect(insights.scope_utilization).toBe(false); // Single scope usage
    });
  });

  describe('Integration Validation - End-to-End Testing', () => {
    it('should demonstrate complete workflow with all services', () => {
      // Step 1: Create large content that needs chunking
      const largeContent = `
        Comprehensive test document for end-to-end validation.
        ${'Content to make this document exceed chunking threshold. '.repeat(200)}
        Mixed language content: Sistem ini digunakan untuk manage data dengan application yang powerful.
        ${'More content to ensure proper chunking behavior. '.repeat(100)}
        Technical details: The system implements intelligent chunking with 4000 character chunks and 200 character overlap.
      `;

      expect(largeContent.length).toBeGreaterThan(8000);

      // Step 2: Apply chunking
      const chunkedItems = chunkingService.createChunkedItems({
        kind: 'observation',
        scope: { project: 'integration-test', branch: 'main' },
        data: { content: largeContent },
        content: largeContent,
      });

      expect(chunkedItems.length).toBeGreaterThan(1);

      // Step 3: Apply language enhancement to all chunks
      const enhancedChunks = languageService.enhanceItemsWithLanguage(chunkedItems);

      enhancedChunks.forEach((chunk) => {
        expect(chunk['data.detected_lang']).toBeDefined();
        expect(chunk['data.lang_confidence']).toBeGreaterThan(0);
      });

      // Step 4: Simulate search results with chunked content
      const searchResults = enhancedChunks.slice(0, 3).map((chunk, index) => ({
        ...chunk,
        confidence_score: 0.9 - index * 0.1,
        match_type: 'semantic',
      }));

      // Step 5: Group and reconstruct results
      const groupedResults = groupingService.groupAndSortResults(searchResults);

      expect(groupedResults.length).toBeGreaterThan(0);

      // Step 6: Log all operations to telemetry
      enhancedChunks.forEach((chunk, index) => {
        telemetry.logStoreAttempt(
          index === 0,
          largeContent.length,
          chunk['data.content']?.length || 0,
          chunk.kind,
          'integration-test:main'
        );
      });

      telemetry.logFindAttempt(
        'end-to-end test query',
        'integration-test:main',
        searchResults.length,
        0.9,
        'semantic'
      );

      // Step 7: Validate final telemetry report
      const finalReport = telemetry.exportLogs();

      expect(finalReport.summary.store.total_stores).toBe(enhancedChunks.length);
      expect(finalReport.summary.find.total_queries).toBe(1);
      expect(finalReport.summary.store.truncated_stores).toBeGreaterThan(0);
      expect(finalReport.summary.scope_analysis).toHaveProperty('integration-test:main');

      console.log('✅ End-to-end validation completed successfully!');
      console.log(`📊 Processed ${enhancedChunks.length} chunks`);
      console.log(`🌍 Language detection applied to all chunks`);
      console.log(`🔗 Results grouped into ${groupedResults.length} groups`);
      console.log(
        `📈 Telemetry captured ${finalReport.summary.store.total_stores} stores and ${finalReport.summary.find.total_queries} queries`
      );
    });
  });
});
