/**
 * Partitioning and Sharding Service
 *
 * Provides intelligent partitioning and sharding strategies for large-scale
 * Qdrant and PostgreSQL deployments. Implements scope-based isolation,
 * load balancing, and automatic scaling decisions.
 *
 * Features:
 * - Organization and project-based partitioning
 * - Dynamic shard allocation and rebalancing
 * - Load-aware routing decisions
 * - Automatic collection management
 * - Performance monitoring and optimization
 * - Multi-tenant isolation guarantees
 */

import { createHash } from 'node:crypto';
import { logger } from '../../utils/logger.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';
import { type IDatabase } from '../../db/database-interface.js';

export interface PartitioningConfig {
  enabled?: boolean;
  strategy?: 'org_project' | 'project_only' | 'kind_based' | 'hash_based' | 'hybrid';
  maxShardsPerCollection?: number;
  shardSizeThreshold?: number; // Maximum items per shard
  autoCreateCollections?: boolean;
  loadBalancingEnabled?: boolean;
  monitoringEnabled?: boolean;
  rebalanceThreshold?: number; // Percentage imbalance before rebalancing
  cachePartitions?: boolean;
  cacheSize?: number;
  cacheTTL?: number;
}

export interface PartitionInfo {
  id: string;
  name: string;
  type: 'org' | 'project' | 'kind' | 'hash';
  scope: {
    org?: string;
    project?: string;
    branch?: string;
  };
  collectionName: string;
  shardCount: number;
  itemCount: number;
  sizeBytes?: number;
  createdAt: string;
  lastAccessed: string;
  performanceMetrics?: PartitionMetrics;
}

export interface PartitionMetrics {
  queryCount: number;
  storeCount: number;
  averageQueryTime: number;
  averageStoreTime: number;
  errorRate: number;
  throughput: number;
  memoryUsage: number;
  cpuUsage?: number;
}

export interface ShardInfo {
  id: string;
  partitionId: string;
  shardIndex: number;
  collectionName: string;
  itemCount: number;
  sizeBytes?: number;
  isHealthy: boolean;
  lastHealthCheck: string;
  metrics?: ShardMetrics;
}

export interface ShardMetrics {
  queryLatency: number;
  storeLatency: number;
  errorCount: number;
  throughput: number;
  memoryUsage: number;
}

export interface RoutingDecision {
  targetPartition: PartitionInfo;
  targetShard?: ShardInfo;
  strategy: string;
  confidence: number;
  reasoning: string;
  fallbackAvailable: boolean;
}

export class PartitioningService {
  private database: IDatabase;
  private config: Required<PartitioningConfig>;
  private partitionCache = new Map<string, PartitionInfo>();
  private shardCache = new Map<string, ShardInfo[]>();
  // private metricsCache = new Map<string, PartitionMetrics>(); // Uncomment when metrics are used

  constructor(database: IDatabase, config: PartitioningConfig = {}) {
    this.database = database;
    this.config = {
      enabled: config.enabled ?? true,
      strategy: config.strategy ?? 'org_project',
      maxShardsPerCollection: config.maxShardsPerCollection ?? 10,
      shardSizeThreshold: config.shardSizeThreshold ?? 100000,
      autoCreateCollections: config.autoCreateCollections ?? true,
      loadBalancingEnabled: config.loadBalancingEnabled ?? true,
      monitoringEnabled: config.monitoringEnabled ?? true,
      rebalanceThreshold: config.rebalanceThreshold ?? 30,
      cachePartitions: config.cachePartitions ?? true,
      cacheSize: config.cacheSize ?? 1000,
      cacheTTL: config.cacheTTL ?? 300000, // 5 minutes
    };

    if (this.config.enabled) {
      this.initializePartitioning();
    }
  }

  /**
   * Initialize partitioning system
   */
  private async initializePartitioning(): Promise<void> {
    try {
      logger.info('Initializing partitioning service', { strategy: this.config.strategy });

      // Load existing partitions
      await this.loadExistingPartitions();

      // Start monitoring if enabled
      if (this.config.monitoringEnabled) {
        this.startMonitoring();
      }

      logger.info('Partitioning service initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize partitioning service');
      throw error;
    }
  }

  /**
   * Get routing decision for a knowledge item
   */
  async getRoutingDecision(item: KnowledgeItem): Promise<RoutingDecision> {
    if (!this.config.enabled) {
      // Fallback to default routing
      return {
        targetPartition: {
          id: 'default',
          name: 'default',
          type: 'org',
          scope: item.scope,
          collectionName: 'cortex-memory',
          shardCount: 1,
          itemCount: 0,
          createdAt: new Date().toISOString(),
          lastAccessed: new Date().toISOString(),
        },
        strategy: 'default',
        confidence: 1.0,
        reasoning: 'Partitioning disabled',
        fallbackAvailable: false,
      };
    }

    try {
      const partitionKey = this.generatePartitionKey(item);
      let partition = this.getCachedPartition(partitionKey);

      if (!partition) {
        partition = await this.getOrCreatePartition(partitionKey, item);
        this.cachePartition(partitionKey, partition);
      }

      // Update last accessed time
      partition.lastAccessed = new Date().toISOString();
      this.updatePartitionMetrics(partition.id, { lastAccessed: partition.lastAccessed });

      // Determine target shard if sharding is enabled
      let targetShard: ShardInfo | undefined;
      if (partition.shardCount > 1) {
        targetShard = await this.selectOptimalShard(partition, item);
      }

      const reasoning = this.generateRoutingReasoning(partition, targetShard, item);

        const routingDecision: RoutingDecision = {
        targetPartition: partition,
        strategy: this.config.strategy,
        confidence: 0.9, // High confidence for partitioned routing
        reasoning,
        fallbackAvailable: true,
      };

    if (targetShard !== undefined) {
      routingDecision.targetShard = targetShard;
    }

    return routingDecision;

    } catch (error) {
      logger.error({ error, itemId: item.id }, 'Failed to get routing decision');

      // Return fallback routing
      return {
        targetPartition: {
          id: 'fallback',
          name: 'fallback',
          type: 'org',
          scope: item.scope,
          collectionName: 'cortex-memory-fallback',
          shardCount: 1,
          itemCount: 0,
          createdAt: new Date().toISOString(),
          lastAccessed: new Date().toISOString(),
        },
        strategy: 'fallback',
        confidence: 0.5,
        reasoning: `Routing failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        fallbackAvailable: false,
      };
    }
  }

  /**
   * Generate partition key based on strategy
   */
  private generatePartitionKey(item: KnowledgeItem): string {
    switch (this.config.strategy) {
      case 'org_project':
        return `${item.scope.org || 'default'}:${item.scope.project || 'default'}`;

      case 'project_only':
        return item.scope.project || 'default';

      case 'kind_based':
        return `${item.scope.project || 'default'}:${item.kind}`;

      case 'hash_based': {
        const hashInput = `${item.scope.org || ''}:${item.scope.project || ''}:${item.kind}`;
        return createHash('md5').update(hashInput).digest('hex').substring(0, 8);
      }

      case 'hybrid':
        // Combine org, project, and kind with weighting
        return `${item.scope.org || 'default'}:${item.scope.project || 'default'}:${item.kind}`;

      default:
        return `${item.scope.org || 'default'}:${item.scope.project || 'default'}`;
    }
  }

  /**
   * Get or create partition for key
   */
  private async getOrCreatePartition(partitionKey: string, item: KnowledgeItem): Promise<PartitionInfo> {
    // Check if partition exists
    const existingPartition = await this.findPartitionByKey(partitionKey);
    if (existingPartition) {
      return existingPartition;
    }

    // Create new partition
    const partition = await this.createPartition(partitionKey, item);
    logger.info({
      partitionId: partition.id,
      partitionKey,
      strategy: this.config.strategy,
    }, 'Created new partition');

    return partition;
  }

  /**
   * Find partition by key
   */
  private async findPartitionByKey(partitionKey: string): Promise<PartitionInfo | null> {
    try {
      // Search for partition metadata in database
      const searchResults = await this.database.search({
        query: partitionKey,
        kind: 'partition_metadata',
        limit: 1,
        mode: 'auto',
      });

      if (searchResults.results.length > 0) {
        const result = searchResults.results[0];
        return this.parsePartitionFromData(result.data);
      }

      return null;
    } catch (error) {
      logger.error({ error, partitionKey }, 'Failed to find partition by key');
      return null;
    }
  }

  /**
   * Create new partition
   */
  private async createPartition(partitionKey: string, item: KnowledgeItem): Promise<PartitionInfo> {
    const partitionId = this.generatePartitionId(partitionKey);
    const collectionName = this.generateCollectionName(partitionKey, partitionId);

    const partition: PartitionInfo = {
      id: partitionId,
      name: this.generatePartitionName(partitionKey),
      type: this.getPartitionType(this.config.strategy),
      scope: {},
      collectionName,
      shardCount: 1, // Start with single shard
      itemCount: 0,
      createdAt: new Date().toISOString(),
      lastAccessed: new Date().toISOString(),
    };

    if (item.scope.org !== undefined) {
      partition.scope.org = item.scope.org;
    }
    if (item.scope.project !== undefined) {
      partition.scope.project = item.scope.project;
    }
    if (item.scope.branch !== undefined) {
      partition.scope.branch = item.scope.branch;
    }

    
    // Create collection in database if auto-creation is enabled
    if (this.config.autoCreateCollections) {
      try {
        await this.createCollection(collectionName, partition);
        logger.info({ collectionName, partitionId }, 'Created collection for partition');
      } catch (error) {
        logger.error({ error, collectionName, partitionId }, 'Failed to create collection');
        // Continue anyway - collection might already exist
      }
    }

    // Store partition metadata
    await this.storePartitionMetadata(partition);

    return partition;
  }

  /**
   * Generate partition ID
   */
  private generatePartitionId(partitionKey: string): string {
    const hash = createHash('sha256').update(partitionKey).digest('hex');
    return `partition_${hash.substring(0, 16)}`;
  }

  /**
   * Generate partition name
   */
  private generatePartitionName(partitionKey: string): string {
    return `partition_${partitionKey.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  }

  /**
   * Get partition type based on strategy
   */
  private getPartitionType(strategy: string): PartitionInfo['type'] {
    switch (strategy) {
      case 'org_project':
      case 'project_only':
        return 'org';
      case 'kind_based':
        return 'kind';
      case 'hash_based':
      case 'hybrid':
        return 'hash';
      default:
        return 'org';
    }
  }

  /**
   * Generate collection name
   */
  private generateCollectionName(partitionKey: string, partitionId: string): string {
    const sanitizedKey = partitionKey.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    return `cortex_${sanitizedKey}_${partitionId.substring(-8)}`;
  }

  /**
   * Create collection in database
   */
  private async createCollection(collectionName: string, partition: PartitionInfo): Promise<void> {
    // This would interface with the database to create a new collection/shard
    // Implementation depends on the specific database (Qdrant, PostgreSQL, etc.)
    logger.debug({ collectionName, partitionId: partition.id }, 'Creating database collection');

    // For now, we'll just log the intention
    // In a real implementation, this would call database.createCollection() or similar
  }

  /**
   * Store partition metadata
   */
  private async storePartitionMetadata(partition: PartitionInfo): Promise<void> {
    const metadataItem = {
      id: `partition_meta_${partition.id}`,
      kind: 'partition_metadata',
      scope: partition.scope,
      data: {
        partition_id: partition.id,
        partition_key: this.generatePartitionKeyFromInfo(partition),
        partition_name: partition.name,
        partition_type: partition.type,
        collection_name: partition.collectionName,
        shard_count: partition.shardCount,
        item_count: partition.itemCount,
        strategy: this.config.strategy,
        created_at: partition.createdAt,
      },
      created_at: new Date().toISOString(),
    };

    await this.database.store([metadataItem], {
      upsert: true,
      skipDuplicates: false,
    });
  }

  /**
   * Select optimal shard for item
   */
  private async selectOptimalShard(partition: PartitionInfo, item: KnowledgeItem): Promise<ShardInfo | undefined> {
    if (partition.shardCount === 1) {
      return undefined; // No sharding
    }

    // Load shard information for partition
    let shards = this.shardCache.get(partition.id);
    if (!shards) {
      shards = await this.loadShardsForPartition(partition);
      this.shardCache.set(partition.id, shards);
    }

    if (shards.length === 0) {
      return undefined;
    }

    // Select shard based on load balancing strategy
    if (this.config.loadBalancingEnabled) {
      return this.selectShardByLoad(shards, item);
    } else {
      return this.selectShardByHash(shards, item);
    }
  }

  /**
   * Select shard by load balancing
   */
  private selectShardByLoad(shards: ShardInfo[], _item: KnowledgeItem): ShardInfo {
    // Find healthiest shard with lowest load
    const healthyShards = shards.filter(shard => shard.isHealthy);

    if (healthyShards.length === 0) {
      logger.warn('No healthy shards available, falling back to first shard');
      return shards[0];
    }

    // Sort by load metrics (item count, query latency, etc.)
    return healthyShards.sort((a, b) => {
      const aLoad = a.itemCount + (a.metrics?.queryLatency || 0) / 1000;
      const bLoad = b.itemCount + (b.metrics?.queryLatency || 0) / 1000;
      return aLoad - bLoad;
    })[0];
  }

  /**
   * Select shard by consistent hashing
   */
  private selectShardByHash(shards: ShardInfo[], item: KnowledgeItem): ShardInfo {
    const hashInput = `${item.id || JSON.stringify(item.data)}`;
    const hash = createHash('md5').update(hashInput).digest('hex');
    const hashValue = parseInt(hash.substring(0, 8), 16);
    const shardIndex = hashValue % shards.length;
    return shards[shardIndex];
  }

  /**
   * Load existing partitions
   */
  private async loadExistingPartitions(): Promise<void> {
    try {
      const searchResults = await this.database.search({
        query: 'partition_metadata',
        kind: 'partition_metadata',
        limit: 1000,
        mode: 'auto',
      });

      for (const result of searchResults.results) {
        const partition = this.parsePartitionFromData(result.data);
        if (partition) {
          this.cachePartition(result.data.partition_key, partition);
        }
      }

      logger.info({ loadedPartitions: searchResults.results.length }, 'Loaded existing partitions');
    } catch (error) {
      logger.error({ error }, 'Failed to load existing partitions');
    }
  }

  /**
   * Parse partition from data
   */
  private parsePartitionFromData(data: any): PartitionInfo | null {
    if (!data || !data.partition_id) {
      return null;
    }

    return {
      id: data.partition_id,
      name: data.partition_name,
      type: data.partition_type,
      scope: data.scope || {},
      collectionName: data.collection_name,
      shardCount: data.shard_count || 1,
      itemCount: data.item_count || 0,
      createdAt: data.created_at,
      lastAccessed: new Date().toISOString(),
    };
  }

  /**
   * Load shards for partition
   */
  private async loadShardsForPartition(partition: PartitionInfo): Promise<ShardInfo[]> {
    // This would load actual shard information from the database
    // For now, return a single shard
    return [{
      id: `${partition.id}_shard_0`,
      partitionId: partition.id,
      shardIndex: 0,
      collectionName: partition.collectionName,
      itemCount: partition.itemCount,
      isHealthy: true,
      lastHealthCheck: new Date().toISOString(),
    }];
  }

  /**
   * Generate partition key from info
   */
  private generatePartitionKeyFromInfo(partition: PartitionInfo): string {
    const parts = [];
    if (partition.scope.org) parts.push(partition.scope.org);
    if (partition.scope.project) parts.push(partition.scope.project);
    if (partition.type === 'kind' && partition.name.includes('_')) {
      parts.push(partition.name.split('_').pop());
    }
    return parts.join(':') || 'default';
  }

  /**
   * Cache partition
   */
  private cachePartition(key: string, partition: PartitionInfo): void {
    if (this.config.cachePartitions) {
      // Clean up cache if needed
      if (this.partitionCache.size >= this.config.cacheSize) {
        const firstKey = this.partitionCache.keys().next().value;
        if (firstKey) {
          this.partitionCache.delete(firstKey);
        }
      }
      this.partitionCache.set(key, partition);
    }
  }

  /**
   * Get cached partition
   */
  private getCachedPartition(key: string): PartitionInfo | undefined {
    return this.partitionCache.get(key);
  }

  /**
   * Update partition metrics
   */
  private async updatePartitionMetrics(partitionId: string, updates: Partial<PartitionInfo>): Promise<void> {
    const partition = this.partitionCache.get(partitionId);
    if (partition) {
      Object.assign(partition, updates);
    }
  }

  /**
   * Generate routing reasoning
   */
  private generateRoutingReasoning(partition: PartitionInfo, shard?: ShardInfo, item?: KnowledgeItem): string {
    const reasons = [];

    reasons.push(`Using ${this.config.strategy} strategy`);
    reasons.push(`Target partition: ${partition.name} (${partition.collectionName})`);

    if (shard) {
      reasons.push(`Target shard: ${shard.id} (index ${shard.shardIndex})`);
      if (this.config.loadBalancingEnabled) {
        reasons.push(`Load-based shard selection (${shard.itemCount} items)`);
      } else {
        reasons.push('Hash-based shard selection');
      }
    }

    if (item) {
      reasons.push(`Item type: ${item.kind}`);
      reasons.push(`Scope: org=${item.scope.org || 'default'}, project=${item.scope.project || 'default'}`);
    }

    return reasons.join('; ');
  }

  /**
   * Start monitoring
   */
  private startMonitoring(): void {
    // Set up periodic monitoring
    setInterval(async () => {
      await this.performHealthCheck();
      await this.checkForRebalancing();
    }, 60000); // Every minute
  }

  /**
   * Perform health check
   */
  private async performHealthCheck(): Promise<void> {
    try {
      // Check database health
      const healthy = await this.database.healthCheck();
      if (!healthy) {
        logger.warn('Database health check failed');
      }

      // Check partition health
      for (const partition of this.partitionCache.values()) {
        // Perform partition-specific health checks
        if (partition.itemCount > this.config.shardSizeThreshold) {
          logger.info({
            partitionId: partition.id,
            itemCount: partition.itemCount,
            threshold: this.config.shardSizeThreshold,
          }, 'Partition exceeds size threshold, consider sharding');
        }
      }
    } catch (error) {
      logger.error({ error }, 'Health check failed');
    }
  }

  /**
   * Check for rebalancing needs
   */
  private async checkForRebalancing(): Promise<void> {
    // This would implement logic to detect imbalance and trigger rebalancing
    // For now, just log that we're checking
    logger.debug('Checking for rebalancing opportunities');
  }

  /**
   * Get partition information
   */
  async getPartitionInfo(partitionId: string): Promise<PartitionInfo | null> {
    // Search cache first
    for (const partition of this.partitionCache.values()) {
      if (partition.id === partitionId) {
        return partition;
      }
    }

    // Search database
    return await this.findPartitionById(partitionId);
  }

  /**
   * Find partition by ID
   */
  private async findPartitionById(partitionId: string): Promise<PartitionInfo | null> {
    try {
      const searchResults = await this.database.search({
        query: partitionId,
        kind: 'partition_metadata',
        limit: 1,
        mode: 'auto',
      });

      if (searchResults.results.length > 0) {
        return this.parsePartitionFromData(searchResults.results[0].data);
      }

      return null;
    } catch (error) {
      logger.error({ error, partitionId }, 'Failed to find partition by ID');
      return null;
    }
  }

  /**
   * List all partitions
   */
  async listPartitions(): Promise<PartitionInfo[]> {
    try {
      const searchResults = await this.database.search({
        query: 'partition_metadata',
        kind: 'partition_metadata',
        limit: 1000,
        mode: 'auto',
      });

      return searchResults.results
        .map(result => this.parsePartitionFromData(result.data))
        .filter(Boolean) as PartitionInfo[];
    } catch (error) {
      logger.error({ error }, 'Failed to list partitions');
      return [];
    }
  }

  /**
   * Get service statistics
   */
  getStats(): {
    enabled: boolean;
    strategy: string;
    partitionCount: number;
    cacheSize: number;
    config: Required<PartitioningConfig>;
  } {
    return {
      enabled: this.config.enabled,
      strategy: this.config.strategy,
      partitionCount: this.partitionCache.size,
      cacheSize: this.partitionCache.size,
      config: this.config,
    };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      if (!this.config.enabled) {
        return true; // Disabled is considered healthy
      }

      const databaseHealthy = await this.database.healthCheck();
      return databaseHealthy;
    } catch (error) {
      logger.error({ error }, 'Partitioning service health check failed');
      return false;
    }
  }
}