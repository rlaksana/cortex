/**
 * Comprehensive Unit Tests for Event Service
 *
 * Tests advanced event service functionality including:
 * - Event publishing and subscription management
 * - Event queue management and processing
 * - Event sourcing and snapshot functionality
 * - Event filtering and routing capabilities
 * - Multi-subscriber event distribution
 * - Event persistence and replay mechanisms
 * - Dead letter queue handling
 * - Event ordering guarantees
 * - High-throughput event processing
 * - Event batching optimization
 * - Memory-efficient event handling
 * - Concurrent event processing
 * - Event metrics collection and analytics
 * - Event pattern analysis and monitoring
 * - Event tracking and reporting
 * - Integration with other services
 * - Cross-service event communication
 * - Event-driven architecture coordination
 * - Performance and scalability testing
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EventService } from '../../../src/services/event/event.service';
import type {
  Event,
  EventSubscription,
  EventFilter,
  EventQueue,
  EventSnapshot,
  EventMetrics,
  EventPattern,
  EventBatch,
  DeadLetterEvent,
  EventStream,
  EventOrdering,
  EventAnalytics
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

// Mock Qdrant client with comprehensive event data
const mockQdrantClient = {
  eventStore: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    findFirst: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn(),
    count: vi.fn()
  },
  eventSubscription: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  eventQueue: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  eventSnapshot: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    findFirst: vi.fn(),
    updateMany: vi.fn()
  },
  deadLetterQueue: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  eventMetrics: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    aggregate: vi.fn()
  }
};

describe('EventService', () => {
  let eventService: EventService;
  let mockEventBus: any;
  let mockEventStore: any;
  let mockEventQueue: any;

  beforeEach(() => {
    vi.clearAllMocks();
    eventService = new EventService({
      enablePersistence: true,
      enableMetrics: true,
      enableDeadLetterQueue: true,
      maxBatchSize: 100,
      maxQueueSize: 10000,
      eventRetentionDays: 30,
      snapshotInterval: 1000
    });

    mockEventBus = {
      emit: vi.fn(),
      on: vi.fn(),
      off: vi.fn(),
      removeAllListeners: vi.fn()
    };

    mockEventStore = {
      saveEvent: vi.fn(),
      getEvents: vi.fn(),
      getEventById: vi.fn(),
      deleteEvent: vi.fn(),
      createSnapshot: vi.fn(),
      getSnapshot: vi.fn()
    };

    mockEventQueue = {
      enqueue: vi.fn(),
      dequeue: vi.fn(),
      peek: vi.fn(),
      size: vi.fn().mockReturnValue(0),
      isEmpty: vi.fn().mockReturnValue(true),
      clear: vi.fn()
    };

    eventService.eventBus = mockEventBus;
    eventService.eventStore = mockEventStore;
    eventService.eventQueue = mockEventQueue;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Event Publishing and Subscription', () => {
    it('should publish event with validation', async () => {
      const event: Event = {
        id: 'event-123',
        type: 'user.created',
        data: { userId: 'user-456', email: 'test@example.com' },
        timestamp: new Date(),
        source: 'user-service',
        version: '1.0',
        metadata: { correlationId: 'corr-789' }
      };

      mockEventStore.saveEvent.mockResolvedValue(event);
      mockEventBus.emit.mockResolvedValue(true);

      const result = await eventService.publishEvent(event);

      expect(result).toBe(true);
      expect(mockEventStore.saveEvent).toHaveBeenCalledWith(event);
      expect(mockEventBus.emit).toHaveBeenCalledWith('user.created', event);
    });

    it('should handle event subscription management', async () => {
      const subscription: EventSubscription = {
        id: 'sub-123',
        eventType: 'user.created',
        subscriberId: 'subscriber-456',
        filter: { source: 'user-service' },
        endpoint: 'http://localhost:3000/webhook',
        active: true,
        createdAt: new Date()
      };

      mockQdrantClient.eventSubscription.createMany.mockResolvedValue([subscription]);

      const result = await eventService.createSubscription(subscription);

      expect(result.id).toBe('sub-123');
      expect(result.eventType).toBe('user.created');
      expect(mockQdrantClient.eventSubscription.createMany).toHaveBeenCalledWith([subscription]);
    });

    it('should filter events based on subscription criteria', async () => {
      const event: Event = {
        id: 'event-123',
        type: 'user.created',
        data: { userId: 'user-456' },
        timestamp: new Date(),
        source: 'auth-service'
      };

      const filter: EventFilter = {
        source: 'user-service',
        dataFilter: { userId: 'user-456' }
      };

      const result = eventService.matchesFilter(event, filter);

      expect(result).toBe(false); // Source doesn't match
    });

    it('should distribute events to multiple subscribers', async () => {
      const event: Event = {
        id: 'event-123',
        type: 'order.created',
        data: { orderId: 'order-456' },
        timestamp: new Date()
      };

      const subscriptions: EventSubscription[] = [
        {
          id: 'sub-1',
          eventType: 'order.created',
          subscriberId: 'notification-service',
          active: true
        },
        {
          id: 'sub-2',
          eventType: 'order.created',
          subscriberId: 'analytics-service',
          active: true
        }
      ];

      mockQdrantClient.eventSubscription.findMany.mockResolvedValue(subscriptions);

      const distribution = await eventService.distributeEvent(event);

      expect(distribution.length).toBe(2);
      expect(distribution[0].subscriberId).toBe('notification-service');
      expect(distribution[1].subscriberId).toBe('analytics-service');
    });
  });

  describe('Event Processing and Queue Management', () => {
    it('should manage event queue with priority ordering', async () => {
      const highPriorityEvent: Event = {
        id: 'event-1',
        type: 'critical.alert',
        data: { severity: 'high' },
        timestamp: new Date(),
        priority: 'high'
      };

      const normalEvent: Event = {
        id: 'event-2',
        type: 'user.updated',
        data: { userId: 'user-123' },
        timestamp: new Date(),
        priority: 'normal'
      };

      mockEventQueue.enqueue
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(true);

      await eventService.enqueueEvent(highPriorityEvent);
      await eventService.enqueueEvent(normalEvent);

      expect(mockEventQueue.enqueue).toHaveBeenCalledTimes(2);
      expect(mockEventQueue.enqueue).toHaveBeenNthCalledWith(1, highPriorityEvent);
      expect(mockEventQueue.enqueue).toHaveBeenNthCalledWith(2, normalEvent);
    });

    it('should process events with ordering guarantees', async () => {
      const events: Event[] = [
        {
          id: 'event-1',
          type: 'sequence.step1',
          data: { step: 1 },
          timestamp: new Date(),
          sequenceNumber: 1
        },
        {
          id: 'event-2',
          type: 'sequence.step2',
          data: { step: 2 },
          timestamp: new Date(),
          sequenceNumber: 2
        }
      ];

      mockEventQueue.dequeue.mockResolvedValue(events[0]);
      mockEventStore.saveEvent.mockResolvedValue(events[0]);

      const processedEvent = await eventService.processNextEvent();

      expect(processedEvent.id).toBe('event-1');
      expect(processedEvent.sequenceNumber).toBe(1);
      expect(mockEventQueue.dequeue).toHaveBeenCalled();
    });

    it('should handle event persistence and replay', async () => {
      const events: Event[] = [
        {
          id: 'event-1',
          type: 'payment.processed',
          data: { amount: 100, currency: 'USD' },
          timestamp: new Date('2024-01-01T10:00:00Z')
        },
        {
          id: 'event-2',
          type: 'payment.processed',
          data: { amount: 200, currency: 'USD' },
          timestamp: new Date('2024-01-01T10:05:00Z')
        }
      ];

      mockQdrantClient.eventStore.findMany.mockResolvedValue(events);

      const replayedEvents = await eventService.replayEvents({
        startDate: new Date('2024-01-01T09:00:00Z'),
        endDate: new Date('2024-01-01T11:00:00Z'),
        eventType: 'payment.processed'
      });

      expect(replayedEvents.length).toBe(2);
      expect(replayedEvents[0].data.amount).toBe(100);
      expect(replayedEvents[1].data.amount).toBe(200);
    });

    it('should handle dead letter queue for failed events', async () => {
      const failedEvent: Event = {
        id: 'event-failed',
        type: 'user.created',
        data: { userId: 'user-123' },
        timestamp: new Date()
      };

      const error = new Error('Processing failed');
      const deadLetterEvent: DeadLetterEvent = {
        originalEvent: failedEvent,
        error: error.message,
        failureCount: 1,
        lastFailedAt: new Date(),
        retryScheduled: false
      };

      mockQdrantClient.deadLetterQueue.createMany.mockResolvedValue([deadLetterEvent]);

      await eventService.handleFailedEvent(failedEvent, error);

      expect(mockQdrantClient.deadLetterQueue.createMany).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            originalEvent: failedEvent,
            error: error.message,
            failureCount: 1
          })
        ])
      );
    });
  });

  describe('Event Sourcing and Snapshot Management', () => {
    it('should implement event sourcing for entity reconstruction', async () => {
      const entityId = 'entity-123';
      const events: Event[] = [
        {
          id: 'event-1',
          type: 'entity.created',
          data: { name: 'Test Entity' },
          timestamp: new Date('2024-01-01T10:00:00Z'),
          entityId
        },
        {
          id: 'event-2',
          type: 'entity.updated',
          data: { name: 'Updated Entity' },
          timestamp: new Date('2024-01-01T10:05:00Z'),
          entityId
        }
      ];

      mockQdrantClient.eventStore.findMany.mockResolvedValue(events);

      const currentState = await eventService.reconstructEntityState(entityId);

      expect(currentState.name).toBe('Updated Entity');
      expect(currentState.version).toBe(2);
      expect(mockQdrantClient.eventStore.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          filter: expect.objectContaining({ entityId })
        })
      );
    });

    it('should create and manage snapshots', async () => {
      const snapshot: EventSnapshot = {
        id: 'snapshot-123',
        entityId: 'entity-456',
        entityType: 'User',
        state: { name: 'John Doe', email: 'john@example.com' },
        version: 10,
        createdAt: new Date(),
        eventCount: 10
      };

      mockQdrantClient.eventSnapshot.createMany.mockResolvedValue([snapshot]);

      const createdSnapshot = await eventService.createSnapshot(snapshot);

      expect(createdSnapshot.id).toBe('snapshot-123');
      expect(createdSnapshot.version).toBe(10);
      expect(mockQdrantClient.eventSnapshot.createMany).toHaveBeenCalledWith([snapshot]);
    });

    it('should reconstruct state from snapshot and subsequent events', async () => {
      const snapshot: EventSnapshot = {
        id: 'snapshot-123',
        entityId: 'entity-456',
        entityType: 'Order',
        state: { status: 'pending', total: 100 },
        version: 5,
        createdAt: new Date('2024-01-01T10:00:00Z'),
        eventCount: 5
      };

      const subsequentEvents: Event[] = [
        {
          id: 'event-6',
          type: 'order.paid',
          data: { status: 'paid' },
          timestamp: new Date('2024-01-01T10:05:00Z'),
          entityId: 'entity-456',
          version: 6
        },
        {
          id: 'event-7',
          type: 'order.shipped',
          data: { trackingNumber: 'TRK123' },
          timestamp: new Date('2024-01-01T10:10:00Z'),
          entityId: 'entity-456',
          version: 7
        }
      ];

      mockQdrantClient.eventSnapshot.findFirst.mockResolvedValue(snapshot);
      mockQdrantClient.eventStore.findMany.mockResolvedValue(subsequentEvents);

      const currentState = await eventService.reconstructEntityState('entity-456');

      expect(currentState.status).toBe('shipped');
      expect(currentState.trackingNumber).toBe('TRK123');
      expect(currentState.total).toBe(100);
    });

    it('should handle event versioning and compatibility', async () => {
      const oldEvent: Event = {
        id: 'event-old',
        type: 'user.created',
        data: { name: 'John' },
        timestamp: new Date(),
        version: '1.0'
      };

      const newEvent: Event = {
        id: 'event-new',
        type: 'user.created',
        data: { name: 'Jane', email: 'jane@example.com' },
        timestamp: new Date(),
        version: '2.0'
      };

      const compatibilityCheck = eventService.checkEventVersionCompatibility(oldEvent, newEvent);

      expect(compatibilityCheck.compatible).toBe(true);
      expect(compatibilityCheck.migrationNeeded).toBe(true);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle high-throughput event processing', async () => {
      const events: Event[] = Array.from({ length: 1000 }, (_, i) => ({
        id: `event-${i}`,
        type: 'test.event',
        data: { index: i },
        timestamp: new Date(),
        priority: 'normal'
      }));

      const startTime = Date.now();

      mockEventQueue.enqueue.mockResolvedValue(true);
      mockEventStore.saveEvent.mockResolvedValue(events[0]);

      const batchSize = 100;
      const batches = [];
      for (let i = 0; i < events.length; i += batchSize) {
        batches.push(events.slice(i, i + batchSize));
      }

      const results = await Promise.all(
        batches.map(batch => eventService.publishEventBatch(batch))
      );

      const endTime = Date.now();
      const processingTime = endTime - startTime;

      expect(results.every(r => r.success)).toBe(true);
      expect(processingTime).toBeLessThan(5000); // Should process 1000 events in under 5 seconds
    });

    it('should optimize event batching for performance', async () => {
      const events: Event[] = Array.from({ length: 150 }, (_, i) => ({
        id: `event-${i}`,
        type: 'batch.test',
        data: { index: i },
        timestamp: new Date()
      }));

      mockEventStore.saveEvent.mockResolvedValue(events[0]);

      const batches = await eventService.optimizeBatching(events, { maxBatchSize: 50, maxBatchTimeMs: 100 });

      expect(batches.length).toBe(3); // 150 events / 50 per batch = 3 batches
      expect(batches[0].length).toBe(50);
      expect(batches[1].length).toBe(50);
      expect(batches[2].length).toBe(50);
    });

    it('should implement memory-efficient event handling', async () => {
      const largeEventData = {
        id: 'event-large',
        type: 'large.payload',
        data: { content: 'x'.repeat(1000000) }, // 1MB payload
        timestamp: new Date()
      };

      const memoryBefore = process.memoryUsage().heapUsed;

      mockEventStore.saveEvent.mockResolvedValue(largeEventData);

      await eventService.publishEventWithCompression(largeEventData);

      const memoryAfter = process.memoryUsage().heapUsed;
      const memoryIncrease = memoryAfter - memoryBefore;

      // Memory increase should be minimal due to compression
      expect(memoryIncrease).toBeLessThan(500000); // Less than 500KB increase
    });

    it('should handle concurrent event processing', async () => {
      const concurrentEvents = Array.from({ length: 100 }, (_, i) => ({
        id: `event-${i}`,
        type: 'concurrent.test',
        data: { index: i },
        timestamp: new Date(),
        concurrencyGroup: 'test-group'
      }));

      mockEventStore.saveEvent.mockResolvedValue(concurrentEvents[0]);

      const concurrencyControl = await eventService.processConcurrently(concurrentEvents, {
        maxConcurrency: 10,
        timeoutMs: 5000
      });

      expect(concurrencyControl.processedCount).toBe(100);
      expect(concurrencyControl.failedCount).toBe(0);
      expect(concurrencyControl.maxConcurrencyReached).toBeLessThanOrEqual(10);
    });
  });

  describe('Event Analytics and Monitoring', () => {
    it('should collect comprehensive event metrics', async () => {
      const metrics: EventMetrics = {
        totalEvents: 10000,
        eventsByType: {
          'user.created': 2000,
          'user.updated': 1500,
          'order.created': 3000,
          'payment.processed': 2500,
          'notification.sent': 1000
        },
        eventsBySource: {
          'user-service': 4000,
          'order-service': 3500,
          'payment-service': 2000,
          'notification-service': 500
        },
        averageProcessingTimeMs: 150,
        failedEvents: 50,
        successRate: 99.5,
        queueDepth: 100,
        throughputEventsPerSecond: 50
      };

      mockQdrantClient.eventMetrics.aggregate.mockResolvedValue(metrics);

      const analytics = await eventService.getEventMetrics({
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
       groupBy: ['type', 'source']
      });

      expect(analytics.totalEvents).toBe(10000);
      expect(analytics.successRate).toBe(99.5);
      expect(analytics.eventsByType['order.created']).toBe(3000);
    });

    it('should analyze event patterns and trends', async () => {
      const patterns: EventPattern[] = [
        {
          pattern: 'user.created -> user.updated -> order.created',
          frequency: 150,
          confidence: 0.85,
          timeframe: '1 hour',
          firstSeen: new Date('2024-01-01'),
          lastSeen: new Date('2024-01-31')
        },
        {
          pattern: 'order.created -> payment.processed -> notification.sent',
          frequency: 300,
          confidence: 0.95,
          timeframe: '30 minutes',
          firstSeen: new Date('2024-01-01'),
          lastSeen: new Date('2024-01-31')
        }
      ];

      const patternAnalysis = await eventService.analyzeEventPatterns({
        lookbackDays: 30,
        minFrequency: 10,
        minConfidence: 0.7
      });

      expect(patternAnalysis.patterns.length).toBeGreaterThan(0);
      expect(patternAnalysis.patterns[0].frequency).toBeGreaterThanOrEqual(10);
      expect(patternAnalysis.patterns[0].confidence).toBeGreaterThanOrEqual(0.7);
    });

    it('should provide real-time event monitoring', async () => {
      const realtimeStats = {
        currentThroughput: 45.5,
        averageLatencyMs: 120,
        errorRate: 0.5,
        queueSize: 75,
        activeSubscriptions: 25,
        memoryUsageMB: 150,
        cpuUsagePercent: 35
      };

      const monitoring = eventService.getRealtimeStats();

      expect(monitoring).toBeDefined();
      expect(monitoring.currentThroughput).toBeGreaterThanOrEqual(0);
      expect(monitoring.errorRate).toBeLessThanOrEqual(100);
      expect(monitoring.queueSize).toBeGreaterThanOrEqual(0);
    });

    it('should generate comprehensive event reports', async () => {
      const reportConfig = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        includeMetrics: true,
        includePatterns: true,
        includeFailures: true,
        format: 'json'
      };

      mockQdrantClient.eventMetrics.aggregate.mockResolvedValue({
        totalEvents: 50000,
        successRate: 99.2,
        averageProcessingTimeMs: 145
      });

      const report = await eventService.generateEventReport(reportConfig);

      expect(report.summary.totalEvents).toBe(50000);
      expect(report.summary.successRate).toBe(99.2);
      expect(report.summary.averageProcessingTimeMs).toBe(145);
      expect(report.period.startDate).toBe(reportConfig.startDate);
      expect(report.period.endDate).toBe(reportConfig.endDate);
    });
  });

  describe('Integration with Services', () => {
    it('should integrate with memory store service', async () => {
      const memoryStoreEvent: Event = {
        id: 'mem-event-1',
        type: 'memory.entity.created',
        data: {
          entityType: 'decision',
          entityId: 'decision-123',
          content: 'Test decision content'
        },
        timestamp: new Date(),
        source: 'memory-store-service'
      };

      const mockMemoryStore = {
        store: vi.fn().mockResolvedValue({ id: 'stored-123' }),
        find: vi.fn().mockResolvedValue([])
      };

      eventService.setServiceIntegration('memory-store', mockMemoryStore);

      await eventService.publishEvent(memoryStoreEvent);

      expect(mockMemoryStore.store).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'entity',
          content: expect.stringContaining('Test decision')
        })
      );
    });

    it('should handle cross-service event communication', async () => {
      const crossServiceEvent: Event = {
        id: 'cross-service-1',
        type: 'user.profile.updated',
        data: {
          userId: 'user-123',
          profileChanges: { email: 'new@example.com' }
        },
        timestamp: new Date(),
        source: 'user-service',
        targetServices: ['notification-service', 'analytics-service']
      };

      const mockNotificationService = {
        sendNotification: vi.fn().mockResolvedValue({ sent: true })
      };

      const mockAnalyticsService = {
        trackEvent: vi.fn().mockResolvedValue({ tracked: true })
      };

      eventService.setServiceIntegration('notification-service', mockNotificationService);
      eventService.setServiceIntegration('analytics-service', mockAnalyticsService);

      await eventService.publishCrossServiceEvent(crossServiceEvent);

      expect(mockNotificationService.sendNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'profile_update',
          userId: 'user-123'
        })
      );

      expect(mockAnalyticsService.trackEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventName: 'user_profile_updated',
          userId: 'user-123'
        })
      );
    });

    it('should coordinate event-driven architecture workflows', async () => {
      const workflowEvent: Event = {
        id: 'workflow-1',
        type: 'order.workflow.started',
        data: {
          orderId: 'order-123',
          customerId: 'customer-456',
          workflow: 'order-processing'
        },
        timestamp: new Date(),
        workflowId: 'order-processing-123'
      };

      const workflowSteps = [
        { service: 'inventory-service', action: 'reserve-items' },
        { service: 'payment-service', action: 'process-payment' },
        { service: 'shipping-service', action: 'schedule-delivery' }
      ];

      const mockServices = {
        'inventory-service': { reserveItems: vi.fn().mockResolvedValue({ reserved: true }) },
        'payment-service': { processPayment: vi.fn().mockResolvedValue({ paid: true }) },
        'shipping-service': { scheduleDelivery: vi.fn().mockResolvedValue({ scheduled: true }) }
      };

      Object.entries(mockServices).forEach(([service, mock]) => {
        eventService.setServiceIntegration(service, mock);
      });

      const workflowResult = await eventService.executeEventWorkflow(workflowEvent, workflowSteps);

      expect(workflowResult.completed).toBe(true);
      expect(workflowResult.stepsCompleted).toBe(3);
      expect(workflowResult.stepsFailed).toBe(0);

      workflowSteps.forEach(step => {
        const mockService = mockServices[step.service];
        expect(Object.values(mockService)[0]).toHaveBeenCalled();
      });
    });

    it('should handle service failure and retry mechanisms', async () => {
      const unreliableServiceEvent: Event = {
        id: 'retry-1',
        type: 'external.api.call',
        data: { endpoint: 'https://api.example.com/data' },
        timestamp: new Date(),
        retryable: true
      };

      const mockUnreliableService = {
        callExternalAPI: vi.fn()
          .mockRejectedValueOnce(new Error('Network timeout'))
          .mockRejectedValueOnce(new Error('Service unavailable'))
          .mockResolvedValueOnce({ data: 'success' })
      };

      eventService.setServiceIntegration('external-service', mockUnreliableService);

      const result = await eventService.publishEventWithRetry(unreliableServiceEvent, {
        maxRetries: 3,
        retryDelayMs: 100,
        backoffMultiplier: 2
      });

      expect(result.success).toBe(true);
      expect(result.attempts).toBe(3);
      expect(mockUnreliableService.callExternalAPI).toHaveBeenCalledTimes(3);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid event data gracefully', async () => {
      const invalidEvent = {
        id: '', // Invalid empty ID
        type: null, // Invalid null type
        data: undefined, // Invalid undefined data
        timestamp: 'invalid-date', // Invalid timestamp format
        source: 123 // Invalid source type
      };

      await expect(eventService.publishEvent(invalidEvent as any)).rejects.toThrow();
    });

    it('should handle event queue overflow scenarios', async () => {
      // Simulate queue at capacity
      mockEventQueue.size.mockReturnValue(10000);
      mockEventQueue.isEmpty.mockReturnValue(false);

      const overflowEvent: Event = {
        id: 'overflow-1',
        type: 'test.overflow',
        data: {},
        timestamp: new Date()
      };

      const result = await eventService.publishEvent(overflowEvent);

      expect(result.queued).toBe(false);
      expect(result.reason).toContain('queue at capacity');
    });

    it('should handle database connection failures', async () => {
      const dbError = new Error('Database connection failed');
      mockEventStore.saveEvent.mockRejectedValue(dbError);

      const event: Event = {
        id: 'db-fail-1',
        type: 'test.db.failure',
        data: {},
        timestamp: new Date()
      };

      await expect(eventService.publishEvent(event)).rejects.toThrow('Database connection failed');
    });

    it('should handle event schema evolution', async () => {
      const oldSchemaEvent: Event = {
        id: 'old-schema-1',
        type: 'user.created',
        data: { name: 'John' }, // Old schema
        timestamp: new Date(),
        version: '1.0'
      };

      const newSchemaValidator = {
        name: 'string',
        email: 'string', // New required field
        age: 'number' // New optional field
      };

      const migrationResult = await eventService.migrateEventSchema(oldSchemaEvent, newSchemaValidator);

      expect(migrationResult.migrated).toBe(true);
      expect(migrationResult.event.data.email).toBe('migrated@example.com'); // Default value
      expect(migrationResult.event.version).toBe('2.0');
    });
  });
});