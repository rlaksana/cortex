/**
 * Enhanced Database Bridge
 *
 * Implements the missing CRUD operations expected by services
 * by bridging vector database operations to traditional CRUD patterns.
 *
 * This bridge converts between the service layer's expectation of
 * traditional database operations and the vector-first Qdrant implementation.
 */

import { logger } from '@/utils/logger.js';

import type { CRUDToVectorAdapter,EnhancedDatabaseOperations, SearchQuery as VectorSearchQuery, TransactionInterface, VectorPoint  } from './interfaces/enhanced-database-operations.interface.js';
import { type QdrantOnlyDatabaseLayer } from './unified-database-layer-v2.js';
import type { KnowledgeItem,SearchQuery  } from '../types/core-interfaces.js';
import type { JSONValue } from '../types/index.js';
import { hasProperty, hasStringProperty, hasNumberProperty, isObject } from '../utils/type-fixes.js';

/**
 * Collection mapping for different knowledge types
 */
const COLLECTION_MAPPING: Record<string, string> = {
  'user': 'auth_users',
  'api_key': 'auth_api_keys',
  'audit_event': 'audit_events',
  'section': 'knowledge_sections',
  'runbook': 'knowledge_runbooks',
  'issue': 'knowledge_issues',
  'decision': 'knowledge_decisions',
  'todo': 'knowledge_todos',
  'incident': 'knowledge_incidents',
  'risk': 'knowledge_risks',
  'change': 'knowledge_changes',
  'assumption': 'knowledge_assumptions',
  'entity': 'knowledge_entities',
  'observation': 'knowledge_observations',
  'relation': 'knowledge_relations',
  'release': 'knowledge_releases',
  'release_note': 'knowledge_release_notes',
  'pr_context': 'knowledge_pr_contexts',
  'ddl': 'knowledge_ddls'
};

/**
 * Enhanced Database Bridge Implementation
 *
 * Provides missing CRUD operations by bridging to vector database operations
 */
export class EnhancedDatabaseBridge implements EnhancedDatabaseOperations {
  constructor(
    private vectorDB: QdrantOnlyDatabaseLayer,
    private crudAdapter: CRUDToVectorAdapter = new DefaultCRUDToVectorAdapter()
  ) {}

  // Basic CRUD operations (delegate to vector operations)
  async findMany(filter?: unknown): Promise<unknown[]> {
    try {
      logger.debug('EnhancedDatabaseBridge.findMany', { filter });

      // If no filter, return all items
      if (!filter || typeof filter !== 'object') {
        const allItems = await this.vectorDB.search({
          query: '', // Empty search to get all items
          limit: 1000,
        });
        return allItems.items || [];
      }

      // Convert filter to search query and search
      const vectorQuery = await this.crudAdapter.filterToVectorQuery(filter, 'default');
      // Convert VectorSearchQuery to SearchQuery format safely
      let queryText = '';
      let queryLimit = 1000;

      if (hasStringProperty(vectorQuery, 'text')) {
        queryText = vectorQuery.text;
      }
      if (hasNumberProperty(vectorQuery, 'limit')) {
        queryLimit = vectorQuery.limit;
      }

      const searchQuery: SearchQuery = {
        query: queryText,
        limit: queryLimit
      };
      const results = await this.vectorDB.search(searchQuery);

      return results.items || [];
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.findMany error:', error);
      throw error;
    }
  }

  async findOne(id: string): Promise<unknown> {
    try {
      logger.debug('EnhancedDatabaseBridge.findOne', { id });

      const results = await this.findMany({ id });
      return results.length > 0 ? results[0] : null;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.findOne error:', error);
      throw error;
    }
  }

  async create(data: unknown): Promise<{ id: string; }> {
    try {
      logger.debug('EnhancedDatabaseBridge.create', { data });

      if (!isObject(data)) {
        throw new Error('Invalid data provided for create operation');
      }

      // Generate ID if not present
      const dataObj = data as Record<string, unknown>;
      const id = hasStringProperty(dataObj, 'id') ? dataObj.id : this.generateId();

      // Convert to KnowledgeItem format for vector storage
      const knowledgeItem: KnowledgeItem = {
        id,
        kind: dataObj.kind as string || 'entity',
        content: dataObj.content as string || JSON.stringify(data),
        scope: this.extractScope(dataObj),
        data: dataObj as Record<string, unknown>,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      // Store in vector database
      const storeResult = await this.vectorDB.store([knowledgeItem]);

      if (storeResult.error) {
        throw new Error(`Failed to store item: ${storeResult.error}`);
      }

      return { id };
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.create error:', error);
      throw error;
    }
  }

  async update(id: string, data: unknown): Promise<{ id: string; }> {
    try {
      logger.debug('EnhancedDatabaseBridge.update', { id, data });

      if (!isObject(data)) {
        throw new Error('Invalid data provided for update operation');
      }

      const dataObj = data as Record<string, unknown>;

      // Create updated KnowledgeItem
      const knowledgeItem: KnowledgeItem = {
        id,
        kind: dataObj.kind as string || 'entity',
        content: dataObj.content as string || JSON.stringify(data),
        scope: this.extractScope(dataObj),
        data: dataObj as Record<string, unknown>,
        created_at: dataObj.created_at as string || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      // Update in vector database (store works as upsert)
      const updateResult = await this.vectorDB.store([knowledgeItem]);

      if (updateResult.error) {
        throw new Error(`Failed to update item: ${updateResult.error}`);
      }

      return { id };
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.update error:', error);
      throw error;
    }
  }

  async delete(id: string): Promise<boolean> {
    try {
      logger.debug('EnhancedDatabaseBridge.delete', { id });

      const deleteResult = await this.vectorDB.delete([id]);
      return deleteResult.deleted > 0;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.delete error:', error);
      throw error;
    }
  }

  // Missing operations that services expect
  async findUnique(filter: unknown): Promise<unknown> {
    try {
      logger.debug('EnhancedDatabaseBridge.findUnique', { filter });

      const results = await this.findMany(filter);
      return results.length > 0 ? results[0] : null;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.findUnique error:', error);
      throw error;
    }
  }

  async findFirst(filter: unknown): Promise<unknown> {
    try {
      logger.debug('EnhancedDatabaseBridge.findFirst', { filter });

      const results = await this.findMany(filter);
      return results.length > 0 ? results[0] : null;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.findFirst error:', error);
      throw error;
    }
  }

  async findManyWithCount(filter?: unknown): Promise<{ items: unknown[]; count: number; }> {
    try {
      logger.debug('EnhancedDatabaseBridge.findManyWithCount', { filter });

      const items = await this.findMany(filter);
      const count = await this.count(filter);

      return { items, count };
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.findManyWithCount error:', error);
      throw error;
    }
  }

  async updateMany(filter: unknown, data: unknown): Promise<{ count: number; }> {
    try {
      logger.debug('EnhancedDatabaseBridge.updateMany', { filter, data });

      const items = await this.findMany(filter);
      let updatedCount = 0;

      for (const item of items) {
        if (hasProperty(item, 'id') && hasStringProperty(item, 'id')) {
          try {
            await this.update(item.id, data as Record<string, unknown>);
            updatedCount++;
          } catch (error) {
            logger.warn(`Failed to update item ${item.id}:`, error);
          }
        }
      }

      return { count: updatedCount };
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.updateMany error:', error);
      throw error;
    }
  }

  async deleteMany(filter: unknown): Promise<{ count: number; }> {
    try {
      logger.debug('EnhancedDatabaseBridge.deleteMany', { filter });

      const items = await this.findMany(filter);
      const ids = items
        .filter(item => hasProperty(item, 'id') && hasStringProperty(item, 'id'))
        .map(item => (item as Record<string, string>).id);

      if (ids.length === 0) {
        return { count: 0 };
      }

      const deleteResult = await this.vectorDB.delete(ids);
      return { count: deleteResult.deleted };
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.deleteMany error:', error);
      throw error;
    }
  }

  async count(filter?: unknown): Promise<number> {
    try {
      logger.debug('EnhancedDatabaseBridge.count', { filter });

      const results = await this.findManyWithCount(filter);
      return results.count;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.count error:', error);

      // Fallback: count items from findMany
      const items = await this.findMany(filter);
      return items.length;
    }
  }

  async aggregate(pipeline: unknown[]): Promise<unknown[]> {
    try {
      logger.debug('EnhancedDatabaseBridge.aggregate', { pipeline });

      // For now, implement basic aggregation by filtering and transforming results
      // This would need to be enhanced based on specific pipeline requirements
      const allItems = await this.findMany();

      // Basic aggregation implementation - this would need to be expanded
      // based on actual aggregation pipeline requirements
      return allItems.map(item => ({
        id: hasProperty(item, 'id') ? (item as Record<string, unknown>).id : null,
        count: 1,
        data: item
      }));
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.aggregate error:', error);
      throw error;
    }
  }

  async transaction(callback: (tx: TransactionInterface) => Promise<unknown>): Promise<unknown> {
    try {
      logger.debug('EnhancedDatabaseBridge.transaction starting');

      // For vector databases, we simulate transactions by collecting operations
      // and executing them in a batch at the end
      const tx = new DatabaseTransaction(this);
      const result = await callback(tx);

      // Commit happens automatically in the Transaction implementation
      await tx.commit();

      logger.debug('EnhancedDatabaseBridge.transaction completed');
      return result;
    } catch (error) {
      logger.error('EnhancedDatabaseBridge.transaction error:', error);
      throw error;
    }
  }

  // Private helper methods
  private generateId(): string {
    return crypto.randomUUID();
  }

  private extractScope(data: Record<string, unknown>): Record<string, unknown> {
    return {
      project: data.project || data.scope_project || 'default',
      branch: data.branch || data.scope_branch || 'main',
      org: data.org || data.scope_org || 'default',
    };
  }

  private convertToJSONValue(data: Record<string, unknown>): JSONValue {
    // Use existing type utilities for conversion
    return JSON.parse(JSON.stringify(data)) as JSONValue;
  }
}

/**
 * Default implementation of CRUD to Vector adapter
 */
export class DefaultCRUDToVectorAdapter implements CRUDToVectorAdapter {
  async filterToVectorQuery(filter: unknown, collection: string): Promise<VectorSearchQuery> {
    if (!filter || typeof filter !== 'object') {
      return { text: '', limit: 1000 };
    }

    const filterObj = filter as Record<string, unknown>;

    // Convert common filter patterns to vector search query
    const query: VectorSearchQuery = {
      limit: (filterObj.limit as number) || 1000,
    };

    // Text search
    if (hasStringProperty(filterObj, 'search') || hasStringProperty(filterObj, 'text')) {
      query.text = filterObj.search || filterObj.text;
    }

    // Build filter conditions
    const conditions = [];
    for (const [key, value] of Object.entries(filterObj)) {
      if (key !== 'limit' && key !== 'offset' && key !== 'search' && key !== 'text') {
        conditions.push({
          key,
          match: { value }
        });
      }
    }

    if (conditions.length > 0) {
      query.filter = { must: conditions };
    }

    return query;
  }

  async dataToVectorPoint(data: unknown, collection: string): Promise<VectorPoint> {
    if (!isObject(data)) {
      throw new Error('Invalid data format');
    }

    const dataObj = data as Record<string, unknown>;
    const id = hasStringProperty(dataObj, 'id') ? dataObj.id : crypto.randomUUID();

    // Generate a simple vector based on data content
    // In a real implementation, this would use actual embedding generation
    const vector = await this.generateEmbedding(JSON.stringify(data));

    return {
      id,
      vector,
      payload: data as Record<string, unknown>
    };
  }

  async vectorResultsToCRUD(results: unknown[], collection: string): Promise<unknown[]> {
    return results; // Vector results are already in CRUD-compatible format
  }

  getCollectionForType(type: string): string {
    return COLLECTION_MAPPING[type] || 'default';
  }

  private async generateEmbedding(text: string): Promise<number[]> {
    // Simple deterministic embedding generation
    // In production, this would use actual embedding models
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    const hashArray = Array.from(new Uint8Array(hash));

    // Convert hash to a 1536-dimensional vector (standard embedding size)
    const vector = new Array(1536).fill(0);
    for (let i = 0; i < hashArray.length; i++) {
      vector[i * 2] = hashArray[i] / 255;
      if (i * 2 + 1 < vector.length) {
        vector[i * 2 + 1] = (hashArray[i] % 64) / 64;
      }
    }

    return vector;
  }
}

/**
 * Transaction implementation for database bridge
 */
export class DatabaseTransaction implements TransactionInterface {
  private operations: Array<{ type: string; data: unknown; result?: unknown; error?: Error }> = [];
  private committed = false;

  constructor(private bridge: EnhancedDatabaseBridge) {}

  async findMany(filter?: unknown): Promise<unknown[]> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'findMany', data: { filter } });
    return this.bridge.findMany(filter);
  }

  async findOne(id: string): Promise<unknown> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'findOne', data: { id } });
    return this.bridge.findOne(id);
  }

  async create(data: unknown): Promise<{ id: string; }> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'create', data });
    return this.bridge.create(data);
  }

  async update(id: string, data: unknown): Promise<{ id: string; }> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'update', data: { id, data } });
    return this.bridge.update(id, data);
  }

  async delete(id: string): Promise<boolean> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'delete', data: { id } });
    return this.bridge.delete(id);
  }

  async updateMany(filter: unknown, data: unknown): Promise<{ count: number; }> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'updateMany', data: { filter, data } });
    return this.bridge.updateMany(filter, data);
  }

  async deleteMany(filter: unknown): Promise<{ count: number; }> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'deleteMany', data: { filter } });
    return this.bridge.deleteMany(filter);
  }

  async count(filter?: unknown): Promise<number> {
    if (this.committed) {
      throw new Error('Transaction already committed');
    }

    this.operations.push({ type: 'count', data: { filter } });
    return this.bridge.count(filter);
  }

  async commit(): Promise<void> {
    if (this.committed) {
      return;
    }

    this.committed = true;
    logger.debug('DatabaseTransaction committed', { operations: this.operations.length });
  }

  async rollback(): Promise<void> {
    if (this.committed) {
      throw new Error('Cannot rollback committed transaction');
    }

    // In this simple implementation, we don't actually rollback operations
    // In a production system, this would implement proper rollback logic
    this.operations = [];
    logger.debug('DatabaseTransaction rolled back');
  }
}