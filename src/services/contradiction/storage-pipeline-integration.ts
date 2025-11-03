/**
 * Storage Pipeline Integration
 * Integrates contradiction detection into the storage pipeline
 */

import {
  StoragePipelineHook,
  ContradictionDetectionRequest,
  ContradictionDetectionResponse,
  ContradictionResult,
  ContradictionFlag,
  KnowledgeItem,
} from '../../types/contradiction-detector.interface';
import { ContradictionDetector } from './contradiction-detector.service';
import { MetadataFlaggingService } from './metadata-flagging.service';
import { PointerResolutionService } from './pointer-resolution.service';

export interface StorageIntegrationConfig {
  enabled: boolean;
  check_on_store: boolean;
  check_on_update: boolean;
  check_on_delete: boolean;
  batch_check_threshold: number;
  async_checking: boolean;
  max_concurrent_checks: number;
  queue_checking: boolean;
  retry_failed_checks: boolean;
  max_retries: number;
}

export class StoragePipelineIntegration implements StoragePipelineHook {
  private config: StorageIntegrationConfig;
  private contradictionDetector: ContradictionDetector;
  private metadataFlaggingService: MetadataFlaggingService;
  private pointerResolutionService: PointerResolutionService;
  private pendingChecks: Map<string, Promise<ContradictionDetectionResponse>> = new Map();
  private checkQueue: Array<{
    items: KnowledgeItem[];
    priority: 'high' | 'medium' | 'low';
    timestamp: Date;
    resolve: (response: ContradictionDetectionResponse) => void;
    reject: (error: Error) => void;
  }> = [];
  private isProcessingQueue = false;

  constructor(
    contradictionDetector: ContradictionDetector,
    metadataFlaggingService: MetadataFlaggingService,
    pointerResolutionService: PointerResolutionService,
    config?: Partial<StorageIntegrationConfig>
  ) {
    this.contradictionDetector = contradictionDetector;
    this.metadataFlaggingService = metadataFlaggingService;
    this.pointerResolutionService = pointerResolutionService;
    this.config = {
      enabled: true,
      check_on_store: true,
      check_on_update: true,
      check_on_delete: false,
      batch_check_threshold: 10,
      async_checking: true,
      max_concurrent_checks: 5,
      queue_checking: true,
      retry_failed_checks: true,
      max_retries: 3,
      ...config,
    };

    if (this.config.queue_checking) {
      this.startQueueProcessor();
    }
  }

  /**
   * Hook called before storing items
   */
  async before_store(items: KnowledgeItem[]): Promise<ContradictionDetectionRequest | null> {
    if (!this.config.enabled || !this.config.check_on_store) {
      return null;
    }

    // Batch check if threshold is met
    if (items.length >= this.config.batch_check_threshold) {
      return this.createDetectionRequest(items);
    }

    // For smaller batches, queue if async checking is enabled
    if (this.config.async_checking) {
      return this.queueDetectionRequest(items, 'medium');
    }

    return this.createDetectionRequest(items);
  }

  /**
   * Hook called after storing items
   */
  async after_store(
    items: KnowledgeItem[],
    results: any[]
  ): Promise<ContradictionDetectionResponse | null> {
    if (!this.config.enabled) {
      return null;
    }

    // Check for contradictions against existing knowledge
    const storedItems = items.filter(
      (item, index) => results[index] && results[index].status !== 'error'
    );

    if (storedItems.length === 0) {
      return null;
    }

    const request = this.createDetectionRequest(storedItems);
    const response = await this.contradictionDetector.detectContradictions(request);

    // Flag items with contradictions
    if (response.contradictions.length > 0) {
      await this.processContradictionResults(response, storedItems);
    }

    return response;
  }

  /**
   * Hook called on item update
   */
  async on_update(
    item_id: string,
    old_item: KnowledgeItem,
    new_item: KnowledgeItem
  ): Promise<ContradictionDetectionResponse | null> {
    if (!this.config.enabled || !this.config.check_on_update) {
      return null;
    }

    // Check contradiction between old and new version
    const request = this.createDetectionRequest([old_item, new_item]);
    const response = await this.contradictionDetector.detectContradictions(request);

    if (response.contradictions.length > 0) {
      await this.processContradictionResults(response, [old_item, new_item]);
    }

    return response;
  }

  /**
   * Hook called on item delete
   */
  async on_delete(item_id: string): Promise<void> {
    if (!this.config.enabled || !this.config.check_on_delete) {
      return;
    }

    // Clean up contradiction data for deleted item
    // This would integrate with the flagging service to remove related flags
    console.log(`Cleaning up contradiction data for deleted item: ${item_id}`);
  }

  /**
   * Processes contradiction results and updates metadata
   */
  private async processContradictionResults(
    response: ContradictionDetectionResponse,
    items: KnowledgeItem[]
  ): Promise<void> {
    // Flag contradictions
    const flags = await this.metadataFlaggingService.flagContradictions(response.contradictions);

    // Update item metadata
    for (const item of items) {
      const updatedItem = await this.metadataFlaggingService.updateItemMetadata(item);
      // In a real implementation, this would update the stored item
      console.log(`Updated metadata for item ${item.id} with contradiction flags`);
    }

    // Create resolution workflows for high-severity contradictions
    const highSeverityContradictions = response.contradictions.filter(
      (c) => c.severity === 'high' || c.severity === 'critical'
    );

    for (const contradiction of highSeverityContradictions) {
      await this.pointerResolutionService.createResolutionWorkflow(contradiction, items);
    }
  }

  /**
   * Creates a contradiction detection request
   */
  private createDetectionRequest(items: KnowledgeItem[]): ContradictionDetectionRequest {
    // Extract scope from items
    const scope = this.extractCommonScope(items);

    return {
      items,
      scope,
      force_check: false,
    };
  }

  private extractCommonScope(items: KnowledgeItem[]): {
    project?: string;
    branch?: string;
    org?: string;
  } {
    const scopes = items.map((item) => item.scope).filter(Boolean);

    if (scopes.length === 0) {
      return {};
    }

    const commonScope: { project?: string; branch?: string; org?: string } = {};

    // Find common project
    const projects = scopes.map((s) => s.project).filter(Boolean);
    if (projects.length > 0 && projects.every((p) => p === projects[0])) {
      commonScope.project = projects[0];
    }

    // Find common branch
    const branches = scopes.map((s) => s.branch).filter(Boolean);
    if (branches.length > 0 && branches.every((b) => b === branches[0])) {
      commonScope.branch = branches[0];
    }

    // Find common org
    const orgs = scopes.map((s) => s.org).filter(Boolean);
    if (orgs.length > 0 && orgs.every((o) => o === orgs[0])) {
      commonScope.org = orgs[0];
    }

    return commonScope;
  }

  /**
   * Queues detection request for async processing
   */
  private async queueDetectionRequest(
    items: KnowledgeItem[],
    priority: 'high' | 'medium' | 'low'
  ): Promise<ContradictionDetectionRequest | null> {
    return new Promise((resolve, reject) => {
      this.checkQueue.push({
        items,
        priority,
        timestamp: new Date(),
        resolve: (response: ContradictionDetectionResponse) => {
          resolve(this.createDetectionRequest(items));
        },
        reject,
      });
    });
  }

  /**
   * Starts the queue processor for async checking
   */
  private startQueueProcessor(): void {
    setInterval(async () => {
      if (!this.isProcessingQueue && this.checkQueue.length > 0) {
        await this.processQueue();
      }
    }, 1000); // Process every second
  }

  /**
   * Processes the contradiction check queue
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessingQueue) {
      return;
    }

    this.isProcessingQueue = true;

    try {
      // Sort by priority and timestamp
      this.checkQueue.sort((a, b) => {
        const priorityOrder = { high: 3, medium: 2, low: 1 };
        const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];
        if (priorityDiff !== 0) return priorityDiff;
        return a.timestamp.getTime() - b.timestamp.getTime();
      });

      // Process in batches
      const batchSize = Math.min(this.config.max_concurrent_checks, this.checkQueue.length);
      const batch = this.checkQueue.splice(0, batchSize);

      const promises = batch.map(async (queueItem) => {
        try {
          const request = this.createDetectionRequest(queueItem.items);
          const response = await this.contradictionDetector.detectContradictions(request);
          queueItem.resolve(response);
        } catch (error) {
          if (this.config.retry_failed_checks) {
            // Retry logic would go here
            queueItem.reject(error as Error);
          } else {
            queueItem.reject(error as Error);
          }
        }
      });

      await Promise.allSettled(promises);
    } catch (error) {
      console.error('Error processing contradiction check queue:', error);
    } finally {
      this.isProcessingQueue = false;
    }
  }

  /**
   * Batch check contradictions for existing items
   */
  async batchCheckExistingItems(
    items: KnowledgeItem[],
    options?: { priority?: 'high' | 'medium' | 'low'; chunk_size?: number }
  ): Promise<ContradictionDetectionResponse[]> {
    const chunkSize = options?.chunk_size || 50;
    const priority = options?.priority || 'medium';

    const responses: ContradictionDetectionResponse[] = [];

    for (let i = 0; i < items.length; i += chunkSize) {
      const chunk = items.slice(i, i + chunkSize);

      if (this.config.async_checking && this.config.queue_checking) {
        // Queue for async processing
        const promise = new Promise<ContradictionDetectionResponse>((resolve, reject) => {
          this.checkQueue.push({
            items: chunk,
            priority,
            timestamp: new Date(),
            resolve,
            reject,
          });
        });

        responses.push(await promise);
      } else {
        // Synchronous processing
        const request = this.createDetectionRequest(chunk);
        const response = await this.contradictionDetector.detectContradictions(request);
        responses.push(response);

        // Process results immediately
        if (response.contradictions.length > 0) {
          await this.processContradictionResults(response, chunk);
        }
      }
    }

    return responses;
  }

  /**
   * Gets integration statistics
   */
  getIntegrationStatistics(): {
    enabled: boolean;
    pending_checks: number;
    queue_size: number;
    active_processes: number;
    total_processed: number;
    success_rate: number;
    average_processing_time_ms: number;
  } {
    return {
      enabled: this.config.enabled,
      pending_checks: this.pendingChecks.size,
      queue_size: this.checkQueue.length,
      active_processes: this.isProcessingQueue ? 1 : 0,
      total_processed: 0, // Would track in real implementation
      success_rate: 0, // Would calculate from history
      average_processing_time_ms: 0, // Would calculate from history
    };
  }

  /**
   * Updates integration configuration
   */
  updateConfiguration(config: Partial<StorageIntegrationConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Gets current configuration
   */
  getConfiguration(): StorageIntegrationConfig {
    return { ...this.config };
  }

  /**
   * Enables or disables the integration
   */
  setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  /**
   * Gracefully shutdown the integration
   */
  async shutdown(): Promise<void> {
    // Process remaining queue items
    while (this.checkQueue.length > 0) {
      await this.processQueue();
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Wait for pending checks to complete
    const pendingPromises = Array.from(this.pendingChecks.values());
    if (pendingPromises.length > 0) {
      await Promise.allSettled(pendingPromises);
    }

    console.log('Storage pipeline integration shutdown complete');
  }
}
