/**
 * Simple Chunking Accuracy Validation Tests
 *
 * Direct testing of chunking accuracy without complex template literals.
 * Validates the ≥99.5% accuracy requirement for the Cortex MCP chunking system.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { KnowledgeItem } from '../../src/types/core-interfaces.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';

describe('Simple Chunking Accuracy Validation - ≥99.5% Requirement', () => {
  let chunkingService: ChunkingService;
  let embeddingService: MockEmbeddingService;

  beforeEach(() => {
    // Create mock embedding service
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      failMethod: 'none',
      latency: 0,
    });

    chunkingService = new ChunkingService(
      1200, // maxCharsPerChunk
      200,  // overlapSize
      embeddingService as any
    );
  });

  afterEach(() => {
    // Clean up resources
  });

  /**
   * Calculate text similarity using multiple metrics
   */
  function calculateTextSimilarity(text1: string, text2: string): number {
    // Character-based similarity (Levenshtein distance)
    const charSimilarity = calculateCharSimilarity(text1, text2);

    // Word-based similarity (Jaccard index)
    const wordSimilarity = calculateWordSimilarity(text1, text2);

    // Return weighted average
    return (charSimilarity * 0.3) + (wordSimilarity * 0.7);
  }

  function calculateCharSimilarity(text1: string, text2: string): number {
    const longer = text1.length > text2.length ? text1 : text2;
    const shorter = text1.length > text2.length ? text2 : text1;

    if (longer.length === 0) return 1.0;

    const editDistance = calculateLevenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  function calculateWordSimilarity(text1: string, text2: string): number {
    const words1 = text1.toLowerCase().split(/\s+/).filter(w => w.length > 0);
    const words2 = text2.toLowerCase().split(/\s+/).filter(w => w.length > 0);

    const set1 = new Set(words1);
    const set2 = new Set(words2);

    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  function calculateLevenshteinDistance(str1: string, str2: string): number {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Reassemble chunks by concatenating them and removing overlap
   */
  function reassembleChunks(chunks: string[], overlapSize: number): string {
    if (chunks.length === 0) return '';
    if (chunks.length === 1) return chunks[0];

    let reassembled = chunks[0];

    for (let i = 1; i < chunks.length; i++) {
      const currentChunk = chunks[i];
      const previousChunkEnd = reassembled.slice(-overlapSize * 2);

      // Find overlap point
      let bestOverlap = 0;
      for (let overlap = Math.min(overlapSize, currentChunk.length); overlap > 0; overlap--) {
        const currentChunkStart = currentChunk.substring(0, overlap);
        if (previousChunkEnd.endsWith(currentChunkStart)) {
          bestOverlap = overlap;
          break;
        }
      }

      // Append non-overlapping part
      reassembled += currentChunk.substring(bestOverlap);
    }

    return reassembled;
  }

  function generateTestContent(size: number): string {
    const baseContent = 'Machine Learning System Architecture Overview. This document describes a comprehensive machine learning system designed for enterprise applications. The system processes large volumes of data while maintaining high performance and reliability. Key components include data processing pipeline with ingestion, validation, feature engineering, model training, and evaluation. The system supports multiple algorithms including supervised learning with linear regression, decision trees, random forests, neural networks, unsupervised learning with clustering methods, reinforcement learning with Q-learning, and deep learning with CNNs and RNNs. Performance optimization includes horizontal scaling through microservices architecture, load balancing, auto-scaling, and caching. Monitoring covers system health metrics, application performance indicators, model accuracy tracking, and business metrics. Security measures include data encryption, access control, audit logging, and compliance with regulations like GDPR, CCPA, and HIPAA. Future enhancements include advanced analytics, AutoML capabilities, federated learning, explainable AI features, cloud native architecture, edge computing support, quantum computing exploration, and integration of cutting-edge AI research. ';

    let content = '';
    while (content.length < size) {
      content += baseContent;
    }

    return content.substring(0, size);
  }

  describe('Core Chunking Accuracy Tests', () => {
    it('should achieve ≥99.5% accuracy on large documents (≥10k chars)', async () => {
      const testContent = generateTestContent(12000);

      const knowledgeItem: KnowledgeItem = {
        id: 'large-doc-accuracy-test',
        kind: 'section', // This type should be chunked
        scope: {
          project: 'accuracy-validation',
          branch: 'main',
          org: 'test-organization'
        },
        data: {
          content: testContent,
          title: 'Large Document Accuracy Test',
          category: 'technical-documentation'
        },
        metadata: {
          version: '1.0.0',
          test_type: 'accuracy_validation'
        }
      };

      // Apply chunking
      const startTime = Date.now();
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const chunkingTime = Date.now() - startTime;

      // Verify chunking results
      expect(chunkedItems.length).toBeGreaterThan(1);

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      expect(parentItem).toBeDefined();
      expect(childChunks.length).toBeGreaterThan(1);
      expect(parentItem?.data.total_chunks).toBe(childChunks.length);

      // Verify metadata integrity
      expect(parentItem?.data.original_length).toBe(testContent.length);
      expect(parentItem?.metadata?.chunking_info?.was_chunked).toBe(true);

      // Reassemble chunks for accuracy testing
      const chunkContents = childChunks
        .sort((a, b) => a.data.chunk_index - b.data.chunk_index)
        .map(chunk => chunk.data.content);

      // Remove chunk context markers (TITLE:, CHUNK X of Y, etc.)
      const cleanedChunks = chunkContents.map(chunk => {
        return chunk
          .replace(/^TITLE: .*\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n/, '');
      });

      const reassembledContent = reassembleChunks(cleanedChunks, 200);

      // Calculate accuracy metrics
      const normalizedOriginal = testContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();

      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      // Verify ≥99.5% accuracy requirement
      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      // Performance validation
      expect(chunkingTime).toBeLessThan(5000); // Should complete within 5 seconds

      // Verify chunk quality
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgChunkSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;
      const minChunkSize = Math.min(...chunkSizes);
      const maxChunkSize = Math.max(...chunkSizes);

      expect(avgChunkSize).toBeGreaterThan(800); // Reasonable average size
      expect(avgChunkSize).toBeLessThan(1500);  // Not too large
      expect(minChunkSize).toBeGreaterThan(50); // No extremely small chunks
      expect(maxChunkSize).toBeLessThan(2500);  // No extremely large chunks

      console.log(`Large Document Accuracy Test Results:`);
      console.log(`- Document size: ${testContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Chunking time: ${chunkingTime}ms`);
      console.log(`- Average chunk size: ${Math.round(avgChunkSize)} characters`);
      console.log(`- Size range: ${minChunkSize} - ${maxChunkSize} characters`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });

    it('should maintain ≥99.5% accuracy with very large documents (>20k chars)', async () => {
      const veryLargeContent = generateTestContent(25000);

      const knowledgeItem: KnowledgeItem = {
        id: 'very-large-performance-test',
        kind: 'section',
        scope: {
          project: 'performance-test',
          branch: 'main'
        },
        data: {
          content: veryLargeContent,
          title: 'Very Large Document Performance Test'
        }
      };

      // Measure chunking performance
      const chunkingStartTime = Date.now();
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const chunkingTime = Date.now() - chunkingStartTime;

      // Performance assertions
      expect(chunkingTime).toBeLessThan(10000); // Should complete within 10 seconds

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Verify chunk distribution
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgChunkSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;
      const minChunkSize = Math.min(...chunkSizes);
      const maxChunkSize = Math.max(...chunkSizes);

      expect(avgChunkSize).toBeGreaterThan(800); // Reasonable chunk size
      expect(avgChunkSize).toBeLessThan(1500);  // Not too large
      expect(minChunkSize).toBeGreaterThan(50); // No extremely small chunks
      expect(maxChunkSize).toBeLessThan(2500);  // No extremely large chunks

      // Test reassembly performance
      const reassemblyStartTime = Date.now();
      const chunkContents = childChunks
        .sort((a, b) => a.data.chunk_index - b.data.chunk_index)
        .map(chunk => chunk.data.content);

      const cleanedChunks = chunkContents.map(chunk => {
        return chunk
          .replace(/^TITLE: .*\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n/, '');
      });

      const reassembledContent = reassembleChunks(cleanedChunks, 200);
      const reassemblyTime = Date.now() - reassemblyStartTime;

      expect(reassemblyTime).toBeLessThan(3000); // Should complete within 3 seconds

      // Calculate accuracy
      const normalizedOriginal = veryLargeContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      console.log(`Very Large Document Performance Test Results:`);
      console.log(`- Document size: ${veryLargeContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Chunking time: ${chunkingTime}ms`);
      console.log(`- Reassembly time: ${reassemblyTime}ms`);
      console.log(`- Average chunk size: ${Math.round(avgChunkSize)} characters`);
      console.log(`- Size range: ${minChunkSize}/${maxChunkSize} characters`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });

    it('should handle very short content without unnecessary chunking', async () => {
      const shortContent = 'This is a short document that should not be chunked.';

      const knowledgeItem: KnowledgeItem = {
        id: 'short-content-test',
        kind: 'section',
        scope: {
          project: 'short-content-test',
          branch: 'main'
        },
        data: {
          content: shortContent,
          title: 'Short Content Test'
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      // Should not be chunked
      expect(chunkedItems).toHaveLength(1);
      expect(chunkedItems[0].data.is_chunk).toBe(false);
      expect(chunkedItems[0].data.total_chunks).toBe(1);
      expect(chunkedItems[0].data.content).toBe(shortContent);

      console.log(`Short Content Test Results:`);
      console.log(`- Document size: ${shortContent.length} characters`);
      console.log(`- Chunks created: 1 (no chunking applied)`);
      console.log(`- Accuracy: 100% (no processing needed)`);
    });
  });

  describe('Chunk Quality Tests', () => {
    it('should maintain consistent chunk sizes within acceptable ranges', async () => {
      const content = generateTestContent(15000);

      const knowledgeItem: KnowledgeItem = {
        id: 'chunk-size-consistency-test',
        kind: 'section',
        scope: {
          project: 'chunk-quality-test',
          branch: 'main'
        },
        data: {
          content: content,
          title: 'Chunk Size Consistency Test'
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Analyze chunk size distribution
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;
      const variance = chunkSizes.reduce((sum, size) => sum + Math.pow(size - avgSize, 2), 0) / chunkSizes.length;
      const stdDev = Math.sqrt(variance);
      const minSize = Math.min(...chunkSizes);
      const maxSize = Math.max(...chunkSizes);

      // Consistency requirements
      expect(stdDev).toBeLessThan(avgSize * 0.5); // Standard deviation should be less than 50% of average
      expect(minSize).toBeGreaterThan(avgSize * 0.3); // Min should be at least 30% of average
      expect(maxSize).toBeLessThan(avgSize * 2.0); // Max should be at most 200% of average

      // Test accuracy
      const chunkContents = childChunks
        .sort((a, b) => a.data.chunk_index - b.data.chunk_index)
        .map(chunk => chunk.data.content);

      const cleanedChunks = chunkContents.map(chunk => {
        return chunk
          .replace(/^TITLE: .*\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n\n/, '')
          .replace(/^CHUNK \d+ of \d+\n/, '');
      });

      const reassembledContent = reassembleChunks(cleanedChunks, 200);
      const normalizedOriginal = content.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      console.log(`Chunk Size Consistency Test Results:`);
      console.log(`- Number of chunks: ${childChunks.length}`);
      console.log(`- Average size: ${Math.round(avgSize)} characters`);
      console.log(`- Standard deviation: ${Math.round(stdDev)} characters`);
      console.log(`- Size range: ${minSize} - ${maxSize} characters`);
      console.log(`- Consistency ratio: ${(1 - stdDev / avgSize).toFixed(3)}`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });
  });
});