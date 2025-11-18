/**
 * Embedding Service Adapter
 *
 * Adapts the EmbeddingService to implement the IEmbeddingService interface.
 * Bridges interface gaps while maintaining backward compatibility.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EmbeddingService } from '../../services/embeddings/embedding-service.js';
import type { IEmbeddingService } from '../service-interfaces.js';

/**
 * Adapter for Embedding service
 */
export class EmbeddingServiceAdapter implements IEmbeddingService {
  constructor(private embeddingService: EmbeddingService) {}

  /**
   * Generate embedding for a single text
   */
  async generateEmbedding(text: string): Promise<number[]> {
    const result = await this.embeddingService.generateEmbedding(text);
    return result.vector;
  }

  /**
   * Generate embeddings for multiple texts in batch
   */
  async generateBatch(texts: string[]): Promise<number[][]> {
    const results = await this.embeddingService.generateBatchEmbeddings({ texts });
    return results.map((result) => result.vector);
  }

  /**
   * Calculate similarity between two embeddings
   */
  calculateSimilarity(a: number[], b: number[]): number {
    return EmbeddingService.calculateSimilarity(a, b);
  }
}
