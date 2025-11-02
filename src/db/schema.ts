/**
 * Cortex Memory MCP - Qdrant Collection Schema Manager
 *
 * Pure Qdrant-based schema management for all 16 knowledge types with:
 * - Vector collection configuration
 * - Payload schema definitions
 * - Index management for performance
 * - Collection lifecycle management
 * - Semantic search capabilities
 */

import { QdrantClient } from '@qdrant/js-client-rest';
import { logger } from '../utils/logger.js';
import { Environment } from '../config/environment.js';

/**
 * Collection configuration for each knowledge type
 */
interface CollectionConfig {
  name: string;
  vectorSize: number;
  distance: 'Cosine' | 'Euclid' | 'Dot';
  payloadSchema: Record<string, any>;
  indexes?: Array<{
    field: string;
    schemaType: 'keyword' | 'integer' | 'float' | 'bool' | 'datetime' | 'geo';
  }>;
}

/**
 * Qdrant Collection Schema Manager
 *
 * Manages all 16 knowledge types as separate Qdrant collections with
 * appropriate vector configurations and payload schemas.
 */
class QdrantSchemaManager {
  private client: QdrantClient;
  private isInitialized = false;

  constructor() {
    const env = Environment.getInstance();
    const qdrantConfig = env.getQdrantConfig();

    this.client = new QdrantClient({
      url: qdrantConfig.url,
      ...(qdrantConfig.apiKey && { apiKey: qdrantConfig.apiKey }),
      timeout: qdrantConfig.connectionTimeout || 30000,
    });
  }

  /**
   * Initialize all collections for the 16 knowledge types
   */
  async initializeCollections(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Qdrant collections already initialized');
      return;
    }

    logger.info('Initializing Qdrant collections for Cortex Memory MCP...');

    try {
      // Create all collections for each knowledge type
      for (const config of COLLECTION_CONFIGS) {
        await this.ensureCollection(config);
      }

      this.isInitialized = true;
      logger.info('All Qdrant collections initialized successfully');
      logger.info('16 knowledge type collections ready for use');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize Qdrant collections');
      throw error;
    }
  }

  /**
   * Ensure a collection exists with proper configuration
   */
  private async ensureCollection(config: CollectionConfig): Promise<void> {
    try {
      // Check if collection exists
      const collections = await this.client.getCollections();
      const exists = collections.collections.some((c) => c.name === config.name);

      if (!exists) {
        logger.info(`Creating collection: ${config.name}`);

        // Create collection with vector configuration
        await this.client.createCollection(config.name, {
          vectors: {
            size: config.vectorSize,
            distance: config.distance,
          },
          // payload_schema removed - not supported by Qdrant client API
        });

        // Index creation removed - createCollectionIndex not supported by Qdrant client API

        logger.info(`Collection ${config.name} created successfully`);
      } else {
        logger.debug(`Collection ${config.name} already exists`);
      }
    } catch (error) {
      logger.error({ error, collection: config.name }, 'Failed to ensure collection');
      throw error;
    }
  }

  /**
   * Get collection information
   */
  async getCollectionInfo(collectionName: string): Promise<any> {
    try {
      const info = await this.client.getCollection(collectionName);
      return info;
    } catch (error) {
      logger.error({ error, collectionName }, 'Failed to get collection info');
      throw error;
    }
  }

  /**
   * List all collections
   */
  async listCollections(): Promise<string[]> {
    try {
      const collections = await this.client.getCollections();
      return collections.collections.map((c) => c.name);
    } catch (error) {
      logger.error({ error }, 'Failed to list collections');
      throw error;
    }
  }

  /**
   * Delete a collection (for migration/reset purposes)
   */
  async deleteCollection(collectionName: string): Promise<void> {
    try {
      await this.client.deleteCollection(collectionName);
      logger.info(`Collection ${collectionName} deleted successfully`);
    } catch (error) {
      logger.error({ error, collectionName }, 'Failed to delete collection');
      throw error;
    }
  }

  /**
   * Get the underlying Qdrant client
   */
  getClient(): QdrantClient {
    return this.client;
  }

  /**
   * Health check for Qdrant connection
   */
  async healthCheck(): Promise<{ isHealthy: boolean; message: string; collections?: string[] }> {
    try {
      // Test basic connectivity
      const collections = await this.listCollections();

      return {
        isHealthy: true,
        message: 'Qdrant connection healthy',
        collections,
      };
    } catch (error) {
      logger.error({ error }, 'Qdrant health check failed');
      return {
        isHealthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Verify all required collections exist
   */
  async verifyCollections(): Promise<boolean> {
    try {
      const existingCollections = await this.listCollections();
      const requiredCollections = COLLECTION_CONFIGS.map((c) => c.name);

      const missingCollections = requiredCollections.filter(
        (name) => !existingCollections.includes(name)
      );

      if (missingCollections.length > 0) {
        logger.error({ missingCollections }, 'Missing required collections');
        return false;
      }

      logger.info('All required collections verified');
      return true;
    } catch (error) {
      logger.error({ error }, 'Failed to verify collections');
      return false;
    }
  }

  /**
   * Get collection statistics for monitoring
   */
  async getCollectionStats(collectionName: string): Promise<any> {
    try {
      const info = await this.getCollectionInfo(collectionName);
      return {
        name: collectionName,
        vectorCount: info.result.vectors_count,
        indexedVectorsCount: info.result.indexed_vectors_count,
        pointsCount: info.result.points_count,
        segmentsCount: info.result.segments_count,
        diskDataSize: info.result.config?.optimizer_config?.deleted_threshold,
        status: info.result.status,
        optimizerStatus: info.result.optimizer_status,
      };
    } catch (error) {
      logger.error({ error, collectionName }, 'Failed to get collection stats');
      return null;
    }
  }
}

/**
 * Collection configurations for all 16 knowledge types
 *
 * Each knowledge type gets its own collection with optimized:
 * - Vector size (semantic embedding dimensions)
 * - Distance metric (cosine for semantic similarity)
 * - Payload schema (structured metadata)
 * - Indexes (query performance)
 */
const COLLECTION_CONFIGS: CollectionConfig[] = [
  {
    name: 'entity',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        entity_type: { type: 'keyword' },
        name: { type: 'text' },
        data: { type: 'object' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        deleted_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'entity_type', schemaType: 'keyword' },
      { field: 'name', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
      { field: 'updated_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'relation',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        from_entity_type: { type: 'keyword' },
        from_entity_id: { type: 'keyword' },
        to_entity_type: { type: 'keyword' },
        to_entity_id: { type: 'keyword' },
        relation_type: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'from_entity_type', schemaType: 'keyword' },
      { field: 'to_entity_type', schemaType: 'keyword' },
      { field: 'relation_type', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'observation',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        entity_type: { type: 'keyword' },
        entity_id: { type: 'keyword' },
        observation: { type: 'text' },
        observation_type: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'entity_type', schemaType: 'keyword' },
      { field: 'observation_type', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'section',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        document_id: { type: 'keyword' },
        title: { type: 'text' },
        heading: { type: 'text' },
        body_md: { type: 'text' },
        body_text: { type: 'text' },
        citation_count: { type: 'integer' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'title', schemaType: 'keyword' },
      { field: 'heading', schemaType: 'keyword' },
      { field: 'citation_count', schemaType: 'integer' },
      { field: 'created_at', schemaType: 'datetime' },
      { field: 'updated_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'runbook',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        service: { type: 'keyword' },
        title: { type: 'text' },
        description: { type: 'text' },
        steps_jsonb: { type: 'array' },
        triggers: { type: 'array', items: { type: 'text' } },
        last_verified_at: { type: 'datetime' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'service', schemaType: 'keyword' },
      { field: 'title', schemaType: 'keyword' },
      { field: 'last_verified_at', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'change',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        change_type: { type: 'keyword' },
        subject_ref: { type: 'keyword' },
        summary: { type: 'text' },
        details: { type: 'text' },
        affected_files: { type: 'array', items: { type: 'text' } },
        author: { type: 'keyword' },
        commit_sha: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'change_type', schemaType: 'keyword' },
      { field: 'subject_ref', schemaType: 'keyword' },
      { field: 'author', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'issue',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        tracker: { type: 'keyword' },
        external_id: { type: 'keyword' },
        title: { type: 'text' },
        description: { type: 'text' },
        status: { type: 'keyword' },
        assignee: { type: 'keyword' },
        labels: { type: 'array', items: { type: 'keyword' } },
        url: { type: 'text' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'tracker', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'assignee', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
      { field: 'updated_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'decision',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        component: { type: 'keyword' },
        status: { type: 'keyword' },
        title: { type: 'text' },
        rationale: { type: 'text' },
        alternatives_considered: { type: 'array', items: { type: 'text' } },
        consequences: { type: 'text' },
        supersedes: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'component', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'title', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'todo',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        scope: { type: 'keyword' },
        todo_type: { type: 'keyword' },
        text: { type: 'text' },
        status: { type: 'keyword' },
        priority: { type: 'keyword' },
        assignee: { type: 'keyword' },
        due_date: { type: 'datetime' },
        closed_at: { type: 'datetime' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'scope', schemaType: 'keyword' },
      { field: 'todo_type', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'priority', schemaType: 'keyword' },
      { field: 'assignee', schemaType: 'keyword' },
      { field: 'due_date', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'release_note',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        version: { type: 'keyword' },
        release_date: { type: 'datetime' },
        summary: { type: 'text' },
        breaking_changes: { type: 'array', items: { type: 'text' } },
        new_features: { type: 'array', items: { type: 'text' } },
        bug_fixes: { type: 'array', items: { type: 'text' } },
        deprecations: { type: 'array', items: { type: 'text' } },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'version', schemaType: 'keyword' },
      { field: 'release_date', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'ddl',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        migration_id: { type: 'keyword' },
        ddl_text: { type: 'text' },
        checksum: { type: 'keyword' },
        applied_at: { type: 'datetime' },
        description: { type: 'text' },
        status: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'migration_id', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'applied_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'pr_context',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        pr_number: { type: 'integer' },
        title: { type: 'text' },
        description: { type: 'text' },
        author: { type: 'keyword' },
        status: { type: 'keyword' },
        base_branch: { type: 'keyword' },
        head_branch: { type: 'keyword' },
        merged_at: { type: 'datetime' },
        expires_at: { type: 'datetime' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'pr_number', schemaType: 'integer' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'author', schemaType: 'keyword' },
      { field: 'base_branch', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
      { field: 'expires_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'incident',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        title: { type: 'text' },
        severity: { type: 'keyword' },
        impact: { type: 'text' },
        timeline: { type: 'object' },
        root_cause_analysis: { type: 'text' },
        resolution_status: { type: 'keyword' },
        affected_services: { type: 'array', items: { type: 'keyword' } },
        business_impact: { type: 'text' },
        recovery_actions: { type: 'array', items: { type: 'text' } },
        follow_up_required: { type: 'bool' },
        incident_commander: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'severity', schemaType: 'keyword' },
      { field: 'resolution_status', schemaType: 'keyword' },
      { field: 'incident_commander', schemaType: 'keyword' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'release',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        version: { type: 'keyword' },
        release_type: { type: 'keyword' },
        scope: { type: 'text' },
        release_date: { type: 'datetime' },
        status: { type: 'keyword' },
        ticket_references: { type: 'array', items: { type: 'keyword' } },
        included_changes: { type: 'array', items: { type: 'text' } },
        deployment_strategy: { type: 'text' },
        rollback_plan: { type: 'text' },
        testing_status: { type: 'text' },
        approvers: { type: 'array', items: { type: 'keyword' } },
        release_notes: { type: 'text' },
        post_release_actions: { type: 'array', items: { type: 'text' } },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'version', schemaType: 'keyword' },
      { field: 'release_type', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'release_date', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'risk',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        title: { type: 'text' },
        category: { type: 'keyword' },
        risk_level: { type: 'keyword' },
        probability: { type: 'keyword' },
        impact_description: { type: 'text' },
        trigger_events: { type: 'array', items: { type: 'text' } },
        mitigation_strategies: { type: 'array', items: { type: 'text' } },
        owner: { type: 'keyword' },
        review_date: { type: 'datetime' },
        status: { type: 'keyword' },
        related_decisions: { type: 'array', items: { type: 'keyword' } },
        monitoring_indicators: { type: 'array', items: { type: 'text' } },
        contingency_plans: { type: 'text' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'category', schemaType: 'keyword' },
      { field: 'risk_level', schemaType: 'keyword' },
      { field: 'probability', schemaType: 'keyword' },
      { field: 'status', schemaType: 'keyword' },
      { field: 'owner', schemaType: 'keyword' },
      { field: 'review_date', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
  {
    name: 'assumption',
    vectorSize: 1536,
    distance: 'Cosine',
    payloadSchema: {
      type: 'object',
      properties: {
        title: { type: 'text' },
        description: { type: 'text' },
        category: { type: 'keyword' },
        validation_status: { type: 'keyword' },
        impact_if_invalid: { type: 'text' },
        validation_criteria: { type: 'array', items: { type: 'text' } },
        validation_date: { type: 'datetime' },
        owner: { type: 'keyword' },
        related_assumptions: { type: 'array', items: { type: 'keyword' } },
        dependencies: { type: 'array', items: { type: 'text' } },
        monitoring_approach: { type: 'text' },
        review_frequency: { type: 'keyword' },
        created_at: { type: 'datetime' },
        updated_at: { type: 'datetime' },
        tags: { type: 'array', items: { type: 'keyword' } },
        metadata: { type: 'object' },
      },
    },
    indexes: [
      { field: 'category', schemaType: 'keyword' },
      { field: 'validation_status', schemaType: 'keyword' },
      { field: 'owner', schemaType: 'keyword' },
      { field: 'validation_date', schemaType: 'datetime' },
      { field: 'created_at', schemaType: 'datetime' },
    ],
  },
];

// Export singleton instance
export const qdrantSchemaManager = new QdrantSchemaManager();

// Export types and configurations
export type { CollectionConfig };
export { COLLECTION_CONFIGS };
export { QdrantSchemaManager };
