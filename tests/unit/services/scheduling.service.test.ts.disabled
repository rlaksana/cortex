/**
 * Comprehensive Unit Tests for Scheduling Service
 *
 * Tests advanced scheduling service functionality including:
 * - Cron-based job scheduling and time-based execution
 * - Asynchronous task execution with timeout handling
 * - Resource allocation and load balancing management
 * - Job execution metrics and performance monitoring
 * - Business calendar integration and timezone handling
 * - Cross-service job coordination and event-driven scheduling
 */

import { describe, it, expect, beforeEach, afterEach, vi, jest } from 'vitest';
import { SchedulingService } from '../../../src/services/scheduling/scheduling-service';
import { JobScheduler } from '../../../src/services/scheduling/job-scheduler';
import { TaskExecutor } from '../../../src/services/scheduling/task-executor';
import { ResourceManager } from '../../../src/services/scheduling/resource-manager';
import { CalendarIntegration } from '../../../src/services/scheduling/calendar-integration';
import { SchedulingAnalytics } from '../../../src/services/scheduling/scheduling-analytics';
import type {
  JobDefinition,
  TaskDefinition,
  ResourceAllocation,
  JobExecution,
  CalendarConfig,
  SchedulingMetrics
} from '../../../src/types/scheduling-interfaces';

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

// Mock Qdrant client for scheduling data persistence
const mockQdrantClient = {
  schedulingJob: {
    create: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  schedulingTask: {
    create: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  schedulingResource: {
    create: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  schedulingExecution: {
    create: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  }
};

// Mock cache factory for scheduling cache
vi.mock('../../../src/utils/lru-cache', () => ({
  CacheFactory: {
    createSchedulingCache: () => ({
      get: vi.fn(),
      set: vi.fn(),
      clear: vi.fn(),
      delete: vi.fn(),
      getStats: vi.fn(() => ({
        itemCount: 0,
        memoryUsageBytes: 0,
        maxMemoryBytes: 52428800,
        hitRate: 0,
        totalHits: 0,
        totalMisses: 0,
        expiredItems: 0,
        evictedItems: 0
      }))
    })
  }
}));

describe('SchedulingService - Comprehensive Scheduling Functionality', () => {
  let schedulingService: SchedulingService;
  let jobScheduler: JobScheduler;
  let taskExecutor: TaskExecutor;
  let resourceManager: ResourceManager;
  let calendarIntegration: CalendarIntegration;
  let schedulingAnalytics: SchedulingAnalytics;

  beforeEach(() => {
    schedulingService = new SchedulingService({
      maxConcurrentJobs: 10,
      defaultJobTimeout: 300000, // 5 minutes
      resourcePoolSize: 100,
      enableMetrics: true,
      calendarConfig: {
        defaultTimezone: 'UTC',
        businessHours: { start: '09:00', end: '17:00' },
        businessDays: [1, 2, 3, 4, 5], // Monday to Friday
        holidays: []
      }
    });

    // Get component references
    jobScheduler = schedulingService.getJobScheduler();
    taskExecutor = schedulingService.getTaskExecutor();
    resourceManager = schedulingService.getResourceManager();
    calendarIntegration = schedulingService.getCalendarIntegration();
    schedulingAnalytics = schedulingService.getAnalytics();

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      model.create.mockResolvedValue({ id: 'mock-id' });
      model.findMany.mockResolvedValue([]);
      model.findUnique.mockResolvedValue(null);
      model.update.mockResolvedValue({ id: 'mock-id' });
      model.delete.mockResolvedValue({ id: 'mock-id' });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    schedulingService?.shutdown();
  });

  // 1. Job Scheduling Tests
  describe('Job Scheduling', () => {
    it('should schedule cron-based jobs correctly', async () => {
      const jobDefinition: JobDefinition = {
        id: 'cron-job-1',
        name: 'Daily Backup',
        schedule: '0 2 * * *', // Daily at 2 AM
        task: {
          id: 'backup-task',
          type: 'backup',
          payload: { source: 'database', destination: 's3' }
        },
        enabled: true,
        priority: 5,
        timezone: 'UTC'
      };

      const scheduledJob = await schedulingService.scheduleJob(jobDefinition);

      expect(scheduledJob).toMatchObject({
        id: 'cron-job-1',
        name: 'Daily Backup',
        schedule: '0 2 * * *',
        enabled: true,
        priority: 5,
        timezone: 'UTC'
      });

      expect(mockQdrantClient.schedulingJob.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: 'Daily Backup',
            schedule: '0 2 * * *',
            enabled: true
          })
        })
      );
    });

    it('should handle one-time job scheduling', async () => {
      const executeAt = new Date(Date.now() + 60000); // 1 minute from now
      const jobDefinition: JobDefinition = {
        id: 'one-time-job-1',
        name: 'Immediate Report Generation',
        executeAt,
        task: {
          id: 'report-task',
          type: 'report',
          payload: { type: 'monthly', format: 'pdf' }
        },
        enabled: true,
        priority: 8
      };

      const scheduledJob = await schedulingService.scheduleJob(jobDefinition);

      expect(scheduledJob.executeAt).toEqual(executeAt);
      expect(scheduledJob.recurring).toBe(false);
    });

    it('should validate cron expressions', () => {
      const validCronExpressions = [
        '0 * * * *',     // Every hour
        '*/15 * * * *',  // Every 15 minutes
        '0 2 * * *',     // Daily at 2 AM
        '0 0 * * 0',     // Weekly on Sunday
        '0 0 1 * *',     // Monthly on 1st
        '0 0 1 1 *'      // Yearly on January 1st
      ];

      const invalidCronExpressions = [
        'invalid-cron',
        '60 * * * *',    // Invalid minute
        '* 25 * * *',    // Invalid hour
        '* * 32 * *',    // Invalid day
        '* * * 13 *',    // Invalid month
        '* * * * 8'      // Invalid day of week
      ];

      validCronExpressions.forEach(cron => {
        expect(() => jobScheduler.validateCronExpression(cron)).not.toThrow();
      });

      invalidCronExpressions.forEach(cron => {
        expect(() => jobScheduler.validateCronExpression(cron)).toThrow();
      });
    });

    it('should manage job priorities correctly', async () => {
      const jobs = [
        { id: 'low-priority', priority: 1, schedule: '0 3 * * *' },
        { id: 'medium-priority', priority: 5, schedule: '0 2 * * *' },
        { id: 'high-priority', priority: 10, schedule: '0 1 * * *' }
      ];

      // Schedule jobs in random order
      for (const job of jobs.sort(() => Math.random() - 0.5)) {
        await schedulingService.scheduleJob({
          id: job.id,
          name: `Job ${job.id}`,
          schedule: job.schedule,
          task: { id: `task-${job.id}`, type: 'test' },
          enabled: true,
          priority: job.priority
        });
      }

      const pendingJobs = await jobScheduler.getPendingJobs();

      // Jobs should be sorted by priority (highest first)
      expect(pendingJobs[0].priority).toBeGreaterThanOrEqual(pendingJobs[1].priority);
      expect(pendingJobs[1].priority).toBeGreaterThanOrEqual(pendingJobs[2].priority);
    });

    it('should handle job dependencies', async () => {
      const parentJob: JobDefinition = {
        id: 'parent-job',
        name: 'Parent Job',
        schedule: '0 1 * * *',
        task: { id: 'parent-task', type: 'data-processing' },
        enabled: true,
        priority: 5
      };

      const childJob: JobDefinition = {
        id: 'child-job',
        name: 'Child Job',
        schedule: '0 2 * * *',
        task: { id: 'child-task', type: 'report-generation' },
        enabled: true,
        priority: 5,
        dependencies: ['parent-job']
      };

      await schedulingService.scheduleJob(parentJob);
      await schedulingService.scheduleJob(childJob);

      const dependencyGraph = await jobScheduler.getDependencyGraph();

      expect(dependencyGraph['child-job'].dependencies).toContain('parent-job');
      expect(dependencyGraph['parent-job'].dependents).toContain('child-job');
    });

    it('should detect circular dependencies in jobs', async () => {
      const jobA: JobDefinition = {
        id: 'job-a',
        name: 'Job A',
        schedule: '0 1 * * *',
        task: { id: 'task-a', type: 'test' },
        enabled: true,
        dependencies: ['job-c']
      };

      const jobB: JobDefinition = {
        id: 'job-b',
        name: 'Job B',
        schedule: '0 2 * * *',
        task: { id: 'task-b', type: 'test' },
        enabled: true,
        dependencies: ['job-a']
      };

      const jobC: JobDefinition = {
        id: 'job-c',
        name: 'Job C',
        schedule: '0 3 * * *',
        task: { id: 'task-c', type: 'test' },
        enabled: true,
        dependencies: ['job-b']
      };

      await expect(schedulingService.scheduleJob(jobA)).rejects.toThrow(/circular dependency/i);
    });
  });

  // 2. Task Execution Tests
  describe('Task Execution', () => {
    it('should execute tasks asynchronously', async () => {
      const taskDefinition: TaskDefinition = {
        id: 'async-task-1',
        type: 'data-processing',
        payload: { source: 'api', batchSize: 100 },
        timeout: 30000,
        retryConfig: { maxRetries: 3, backoffMs: 1000 }
      };

      const mockTaskHandler = vi.fn().mockResolvedValue({
        success: true,
        result: { processed: 100, errors: 0 }
      });

      taskExecutor.registerTaskHandler('data-processing', mockTaskHandler);

      const execution = await taskExecutor.executeTask(taskDefinition);

      expect(execution).toMatchObject({
        taskId: 'async-task-1',
        status: 'completed',
        result: { processed: 100, errors: 0 }
      });

      expect(mockTaskHandler).toHaveBeenCalledWith(taskDefinition.payload);
    });

    it('should handle task timeouts correctly', async () => {
      const taskDefinition: TaskDefinition = {
        id: 'timeout-task',
        type: 'slow-operation',
        payload: {},
        timeout: 1000 // 1 second timeout
      };

      const mockSlowHandler = vi.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 2000)) // 2 second delay
      );

      taskExecutor.registerTaskHandler('slow-operation', mockSlowHandler);

      const execution = await taskExecutor.executeTask(taskDefinition);

      expect(execution.status).toBe('failed');
      expect(execution.error).toMatch(/timeout/i);
    });

    it('should implement retry mechanisms with exponential backoff', async () => {
      const taskDefinition: TaskDefinition = {
        id: 'retry-task',
        type: 'unreliable-operation',
        payload: {},
        timeout: 5000,
        retryConfig: {
          maxRetries: 3,
          backoffMs: 100,
          backoffMultiplier: 2
        }
      };

      let attemptCount = 0;
      const mockUnreliableHandler = vi.fn().mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          return Promise.reject(new Error('Temporary failure'));
        }
        return Promise.resolve({ success: true, attempt: attemptCount });
      });

      taskExecutor.registerTaskHandler('unreliable-operation', mockUnreliableHandler);

      const execution = await taskExecutor.executeTask(taskDefinition);

      expect(execution.status).toBe('completed');
      expect(execution.result.attempt).toBe(3);
      expect(mockUnreliableHandler).toHaveBeenCalledTimes(3);
    });

    it('should manage concurrent task execution', async () => {
      const tasks = Array.from({ length: 5 }, (_, i) => ({
        id: `concurrent-task-${i}`,
        type: 'parallel-processing',
        payload: { taskId: i }
      }));

      const mockParallelHandler = vi.fn().mockImplementation((payload) =>
        new Promise(resolve =>
          setTimeout(() => resolve({ taskId: payload.taskId, processed: true }), 100)
        )
      );

      taskExecutor.registerTaskHandler('parallel-processing', mockParallelHandler);

      const startTime = Date.now();
      const executions = await Promise.all(
        tasks.map(task => taskExecutor.executeTask(task))
      );
      const duration = Date.now() - startTime;

      expect(executions).toHaveLength(5);
      executions.forEach((execution, index) => {
        expect(execution.status).toBe('completed');
        expect(execution.result.taskId).toBe(index);
      });

      // Should complete in approximately 100ms (not 500ms) due to parallel execution
      expect(duration).toBeLessThan(200);
    });

    it('should handle task cancellation gracefully', async () => {
      const taskDefinition: TaskDefinition = {
        id: 'cancellable-task',
        type: 'long-running',
        payload: {},
        timeout: 10000
      };

      let shouldContinue = true;
      const mockLongRunningHandler = vi.fn().mockImplementation(async () => {
        for (let i = 0; i < 100 && shouldContinue; i++) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        return { progress: shouldContinue ? 100 : 'cancelled' };
      });

      taskExecutor.registerTaskHandler('long-running', mockLongRunningHandler);

      const executionPromise = taskExecutor.executeTask(taskDefinition);

      // Cancel after 250ms
      setTimeout(() => {
        shouldContinue = false;
        taskExecutor.cancelTask('cancellable-task');
      }, 250);

      const execution = await executionPromise;

      expect(execution.status).toBe('cancelled');
      expect(execution.result.progress).toBe('cancelled');
    });
  });

  // 3. Resource Management Tests
  describe('Resource Management', () => {
    it('should allocate and track resources', async () => {
      const resourceRequest: ResourceAllocation = {
        jobId: 'resource-test-job',
        resources: {
          cpu: 2,
          memory: 1024,
          disk: 512,
          network: 100
        },
        duration: 300000 // 5 minutes
      };

      const allocation = await resourceManager.allocateResources(resourceRequest);

      expect(allocation).toMatchObject({
        jobId: 'resource-test-job',
        allocated: {
          cpu: 2,
          memory: 1024,
          disk: 512,
          network: 100
        },
        status: 'allocated'
      });

      const currentUsage = await resourceManager.getCurrentUsage();
      expect(currentUsage.total.cpu).toBe(2);
      expect(currentUsage.total.memory).toBe(1024);
    });

    it('should implement load balancing across workers', async () => {
      const workers = ['worker-1', 'worker-2', 'worker-3'];
      const tasks = Array.from({ length: 9 }, (_, i) => ({
        id: `load-balance-task-${i}`,
        type: 'cpu-intensive',
        resources: { cpu: 1, memory: 256 }
      }));

      // Initialize workers with current load
      await resourceManager.updateWorkerLoad('worker-1', { tasks: 3, cpu: 1.5, memory: 768 });
      await resourceManager.updateWorkerLoad('worker-2', { tasks: 2, cpu: 1.0, memory: 512 });
      await resourceManager.updateWorkerLoad('worker-3', { tasks: 1, cpu: 0.5, memory: 256 });

      const assignments = [];
      for (const task of tasks) {
        const assignedWorker = await resourceManager.assignTaskToWorker(task, workers);
        assignments.push(assignedWorker);
      }

      // Tasks should be distributed based on current load
      const workerAssignments = assignments.reduce((acc, worker) => {
        acc[worker] = (acc[worker] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      // Least loaded worker (worker-3) should get most tasks
      expect(workerAssignments['worker-3']).toBeGreaterThanOrEqual(workerAssignments['worker-1']);
    });

    it('should optimize resource usage', async () => {
      const optimizationMetrics = await resourceManager.optimizeResourcePool({
        targetCpuUtilization: 0.8,
        targetMemoryUtilization: 0.75,
        minWorkers: 2,
        maxWorkers: 10
      });

      expect(optimizationMetrics).toMatchObject({
        currentWorkers: expect.any(Number),
        recommendedWorkers: expect.any(Number),
        potentialSavings: expect.any(Object),
        utilizationScore: expect.any(Number)
      });

      expect(optimizationMetrics.recommendedWorkers).toBeGreaterThanOrEqual(2);
      expect(optimizationMetrics.recommendedWorkers).toBeLessThanOrEqual(10);
    });

    it('should handle resource contention and queuing', async () => {
      const totalResources = { cpu: 4, memory: 2048 };
      resourceManager.setTotalResources(totalResources);

      const highDemandTasks = Array.from({ length: 10 }, (_, i) => ({
        id: `contention-task-${i}`,
        resources: { cpu: 1, memory: 512 }
      }));

      const allocations = [];
      for (const task of highDemandTasks) {
        try {
          const allocation = await resourceManager.allocateResources({
            jobId: task.id,
            resources: task.resources,
            duration: 60000
          });
          allocations.push(allocation);
        } catch (error) {
          // Some tasks should be queued due to resource limits
          expect(error.message).toMatch(/insufficient resources|queued/i);
        }
      }

      // Should only allocate 4 tasks (total CPU: 4)
      expect(allocations.length).toBe(4);

      const queuedTasks = await resourceManager.getQueuedTasks();
      expect(queuedTasks.length).toBe(6);
    });

    it('should support capacity planning', async () => {
      const historicalData = {
        peakCpuUsage: 3.2,
        peakMemoryUsage: 1536,
        averageTasksPerHour: 50,
        growthRate: 0.15 // 15% monthly growth
      };

      const capacityPlan = await resourceManager.generateCapacityPlan({
        forecastMonths: 6,
        bufferPercentage: 20,
        historicalData
      });

      expect(capacityPlan).toMatchObject({
        currentCapacity: expect.any(Object),
        projectedNeeds: expect.any(Object),
        recommendedScaling: expect.any(Object),
        timeline: expect.any(Array),
        costProjection: expect.any(Object)
      });

      expect(capacityPlan.recommendedScaling.cpuCores).toBeGreaterThan(historicalData.peakCpuUsage);
      expect(capacityPlan.recommendedScaling.memoryMB).toBeGreaterThan(historicalData.peakMemoryUsage);
    });
  });

  // 4. Monitoring and Analytics Tests
  describe('Monitoring and Analytics', () => {
    it('should track job execution metrics', async () => {
      const jobExecution: JobExecution = {
        jobId: 'metrics-job',
        taskId: 'metrics-task',
        startTime: new Date(),
        endTime: new Date(Date.now() + 5000),
        status: 'completed',
        resourcesUsed: { cpu: 1, memory: 512 },
        result: { processed: 100 }
      };

      await schedulingAnalytics.recordJobExecution(jobExecution);

      const metrics = await schedulingAnalytics.getJobMetrics('metrics-job');

      expect(metrics).toMatchObject({
        jobId: 'metrics-job',
        totalExecutions: expect.any(Number),
        averageExecutionTime: expect.any(Number),
        successRate: expect.any(Number),
        resourceEfficiency: expect.any(Object),
        lastExecution: expect.any(Date)
      });

      expect(metrics.totalExecutions).toBe(1);
      expect(metrics.averageExecutionTime).toBe(5000);
      expect(metrics.successRate).toBe(1);
    });

    it('should provide performance monitoring', async () => {
      const performanceData = await schedulingAnalytics.getPerformanceMetrics({
        timeRange: '24h',
        includeResourceMetrics: true,
        includeErrorRates: true
      });

      expect(performanceData).toMatchObject({
        timeRange: '24h',
        jobMetrics: expect.any(Object),
        taskMetrics: expect.any(Object),
        resourceMetrics: expect.any(Object),
        errorMetrics: expect.any(Object),
        trends: expect.any(Object)
      });

      expect(performanceData.jobMetrics).toHaveProperty('totalJobs');
      expect(performanceData.jobMetrics).toHaveProperty('successRate');
      expect(performanceData.resourceMetrics).toHaveProperty('averageCpuUsage');
      expect(performanceData.resourceMetrics).toHaveProperty('averageMemoryUsage');
    });

    it('should track success and failure rates', async () => {
      // Record multiple executions with mixed results
      const executions = [
        { status: 'completed', jobId: 'job-1' },
        { status: 'completed', jobId: 'job-2' },
        { status: 'completed', jobId: 'job-3' },
        { status: 'failed', jobId: 'job-4', error: 'Timeout' },
        { status: 'failed', jobId: 'job-5', error: 'Resource error' }
      ];

      for (const execution of executions) {
        await schedulingAnalytics.recordJobExecution({
          ...execution,
          taskId: 'test-task',
          startTime: new Date(),
          endTime: new Date(),
          resourcesUsed: { cpu: 1, memory: 256 }
        } as JobExecution);
      }

      const reliabilityMetrics = await schedulingAnalytics.getReliabilityMetrics();

      expect(reliabilityMetrics).toMatchObject({
        overallSuccessRate: expect.any(Number),
        totalExecutions: expect.any(Number),
        successfulExecutions: expect.any(Number),
        failedExecutions: expect.any(Number),
        commonErrors: expect.any(Array)
      });

      expect(reliabilityMetrics.totalExecutions).toBe(5);
      expect(reliabilityMetrics.successfulExecutions).toBe(3);
      expect(reliabilityMetrics.failedExecutions).toBe(2);
      expect(reliabilityMetrics.overallSuccessRate).toBe(0.6);
    });

    it('should provide resource utilization analytics', async () => {
      const utilizationData = await schedulingAnalytics.getResourceUtilization({
        timeRange: '7d',
        granularity: 'hourly',
        resources: ['cpu', 'memory', 'disk', 'network']
      });

      expect(utilizationData).toMatchObject({
        timeRange: '7d',
        granularity: 'hourly',
        utilization: expect.objectContaining({
          cpu: expect.any(Array),
          memory: expect.any(Array),
          disk: expect.any(Array),
          network: expect.any(Array)
        }),
        peakUsage: expect.any(Object),
        averageUsage: expect.any(Object),
        efficiencyScore: expect.any(Number)
      });

      expect(utilizationData.utilization.cpu).toHaveLength(168); // 7 days * 24 hours
      expect(utilizationData.efficiencyScore).toBeGreaterThan(0);
      expect(utilizationData.efficiencyScore).toBeLessThanOrEqual(1);
    });
  });

  // 5. Calendar Integration Tests
  describe('Calendar Integration', () => {
    it('should handle business calendar constraints', async () => {
      const calendarConfig: CalendarConfig = {
        defaultTimezone: 'America/New_York',
        businessHours: { start: '09:00', end: '17:00' },
        businessDays: [1, 2, 3, 4, 5], // Monday to Friday
        holidays: [
          new Date('2024-12-25'), // Christmas
          new Date('2024-01-01')  // New Year
        ]
      };

      await calendarIntegration.updateCalendarConfig(calendarConfig);

      // Test scheduling during business hours
      const businessHourTime = new Date('2024-01-15T10:00:00-05:00'); // Monday 10 AM
      const isBusinessTime = await calendarIntegration.isBusinessTime(businessHourTime);
      expect(isBusinessTime).toBe(true);

      // Test scheduling outside business hours
      const nonBusinessTime = new Date('2024-01-15T20:00:00-05:00'); // Monday 8 PM
      const isNonBusinessTime = await calendarIntegration.isBusinessTime(nonBusinessTime);
      expect(isNonBusinessTime).toBe(false);

      // Test holiday scheduling
      const holidayTime = new Date('2024-12-25T10:00:00-05:00'); // Christmas 10 AM
      const isHolidayTime = await calendarIntegration.isBusinessTime(holidayTime);
      expect(isHolidayTime).toBe(false);
    });

    it('should manage timezone conversions', async () => {
      const utcTime = new Date('2024-01-15T15:00:00Z'); // 3 PM UTC
      const targetTimezone = 'America/Los_Angeles';

      const convertedTime = await calendarIntegration.convertTimezone(utcTime, targetTimezone);

      // Should be 7 AM PST (UTC-8 in January)
      expect(convertedTime.getHours()).toBe(7);
      expect(convertedTime.getDate()).toBe(15);
    });

    it('should calculate next business day execution', async () => {
      const fridayEvening = new Date('2024-01-12T18:00:00-05:00'); // Friday 6 PM
      const nextBusinessTime = await calendarIntegration.getNextBusinessTime(fridayEvening);

      // Should be Monday 9 AM
      expect(nextBusinessTime.getDay()).toBe(1); // Monday
      expect(nextBusinessTime.getHours()).toBe(9); // 9 AM
      expect(nextBusinessTime.getDate()).toBeGreaterThan(12); // Next week
    });

    it('should handle scheduling constraints', async () => {
      const constraints = {
        maxJobsPerHour: 10,
        blackoutPeriods: [
          { start: '02:00', end: '03:00' }, // Daily maintenance window
          { start: '2024-12-24', end: '2024-12-26' } // Holiday blackout
        ],
        requiredResources: { minimumCpu: 2, minimumMemory: 1024 }
      };

      await calendarIntegration.setSchedulingConstraints(constraints);

      // Test constraint validation
      const requestedTime = new Date('2024-01-15T02:30:00-05:00'); // During blackout
      const canSchedule = await calendarIntegration.validateSchedulingTime(
        requestedTime,
        { requiredCpu: 1, requiredMemory: 512 }
      );

      expect(canSchedule).toBe(false);

      // Test valid scheduling time
      const validTime = new Date('2024-01-15T10:00:00-05:00'); // Business hours
      const canScheduleValid = await calendarIntegration.validateSchedulingTime(
        validTime,
        { requiredCpu: 1, requiredMemory: 512 }
      );

      expect(canScheduleValid).toBe(true);
    });

    it('should manage availability windows', async () => {
      const availabilityWindow = {
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'America/New_York',
        daysOfWeek: [1, 2, 3, 4, 5],
        exceptions: [
          { date: '2024-01-15', available: false } // Martin Luther King Jr. Day
        ]
      };

      await calendarIntegration.setAvailabilityWindow(availabilityWindow);

      // Test within availability window
      const availableTime = new Date('2024-01-16T10:00:00-05:00'); // Tuesday 10 AM
      const isAvailable = await calendarIntegration.isWithinAvailabilityWindow(availableTime);
      expect(isAvailable).toBe(true);

      // Test outside availability window
      const unavailableTime = new Date('2024-01-16T18:00:00-05:00'); // Tuesday 6 PM
      const isUnavailable = await calendarIntegration.isWithinAvailabilityWindow(unavailableTime);
      expect(isUnavailable).toBe(false);

      // Test exception day
      const exceptionTime = new Date('2024-01-15T10:00:00-05:00'); // Monday 10 AM (holiday)
      const isExceptionAvailable = await calendarIntegration.isWithinAvailabilityWindow(exceptionTime);
      expect(isExceptionAvailable).toBe(false);
    });
  });

  // 6. Service Integration Tests
  describe('Service Integration', () => {
    it('should schedule service tasks', async () => {
      const serviceTask = {
        serviceName: 'backup-service',
        taskName: 'daily-backup',
        schedule: '0 2 * * *',
        payload: { type: 'incremental', retention: 30 }
      };

      const scheduledTask = await schedulingService.scheduleServiceTask(serviceTask);

      expect(scheduledTask).toMatchObject({
        id: expect.any(String),
        serviceName: 'backup-service',
        taskName: 'daily-backup',
        schedule: '0 2 * * *',
        status: 'scheduled'
      });

      expect(mockQdrantClient.schedulingJob.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            serviceName: 'backup-service',
            taskName: 'daily-backup'
          })
        })
      );
    });

    it('should coordinate cross-service jobs', async () => {
      const crossServiceJob = {
        id: 'cross-service-data-pipeline',
        name: 'Data Processing Pipeline',
        services: [
          { name: 'data-ingestion', order: 1, dependencies: [] },
          { name: 'data-transformation', order: 2, dependencies: ['data-ingestion'] },
          { name: 'data-validation', order: 3, dependencies: ['data-transformation'] },
          { name: 'data-storage', order: 4, dependencies: ['data-validation'] }
        ],
        schedule: '0 3 * * *'
      };

      const coordinatedJob = await schedulingService.scheduleCrossServiceJob(crossServiceJob);

      expect(coordinatedJob).toMatchObject({
        id: 'cross-service-data-pipeline',
        services: expect.arrayContaining([
          expect.objectContaining({ name: 'data-ingestion', order: 1 }),
          expect.objectContaining({ name: 'data-transformation', order: 2 }),
          expect.objectContaining({ name: 'data-validation', order: 3 }),
          expect.objectContaining({ name: 'data-storage', order: 4 })
        ])
      });

      const dependencyGraph = await schedulingService.getCrossServiceDependencyGraph(coordinatedJob.id);
      expect(dependencyGraph['data-transformation'].dependencies).toContain('data-ingestion');
      expect(dependencyGraph['data-validation'].dependencies).toContain('data-transformation');
      expect(dependencyGraph['data-storage'].dependencies).toContain('data-validation');
    });

    it('should handle event-driven scheduling', async () => {
      const eventTrigger = {
        eventType: 'data-uploaded',
        sourceService: 'file-storage',
        conditions: {
          fileSize: { operator: '>', value: 1024 * 1024 * 100 }, // > 100MB
          fileType: { operator: 'in', value: ['csv', 'json', 'parquet'] }
        },
        scheduledJob: {
          taskName: 'process-large-file',
          priority: 8,
          timeout: 1800000 // 30 minutes
        }
      };

      await schedulingService.registerEventTrigger(eventTrigger);

      // Simulate event
      const eventData = {
        eventType: 'data-uploaded',
        sourceService: 'file-storage',
        payload: {
          fileId: 'file-123',
          fileName: 'large-dataset.csv',
          fileSize: 1024 * 1024 * 150, // 150MB
          fileType: 'csv'
        }
      };

      const triggeredJobs = await schedulingService.handleEvent(eventData);

      expect(triggeredJobs).toHaveLength(1);
      expect(triggeredJobs[0].taskName).toBe('process-large-file');
      expect(triggeredJobs[0].priority).toBe(8);
      expect(triggeredJobs[0].triggeredBy).toBe('data-uploaded');
    });

    it('should implement service health-based scheduling', async () => {
      const serviceHealth = {
        'data-processing': { status: 'healthy', responseTime: 150, load: 0.6 },
        'notification-service': { status: 'degraded', responseTime: 800, load: 0.9 },
        'analytics-service': { status: 'unhealthy', responseTime: 5000, load: 0.95 }
      };

      await schedulingService.updateServiceHealth(serviceHealth);

      const schedulingDecision = await schedulingService.makeSchedulingDecision({
        taskName: 'process-user-data',
        requiredServices: ['data-processing', 'notification-service'],
        priority: 5
      });

      // Should prefer healthy service and consider degraded service status
      expect(schedulingDecision.canSchedule).toBe(true);
      expect(schedulingDecision.recommendations).toContain(
        expect.objectContaining({
          service: 'notification-service',
          action: 'monitor'
        })
      );

      // Test with unhealthy service
      const unhealthyDecision = await schedulingService.makeSchedulingDecision({
        taskName: 'generate-analytics-report',
        requiredServices: ['analytics-service'],
        priority: 3
      });

      expect(unhealthyDecision.canSchedule).toBe(false);
      expect(unhealthyDecision.reason).toContain('analytics-service.*unhealthy/i');
    });

    it('should handle service failover scenarios', async () => {
      const primaryService = {
        name: 'primary-data-processor',
        endpoints: ['http://primary-service:8080'],
        healthCheck: { path: '/health', interval: 30000 }
      };

      const failoverService = {
        name: 'backup-data-processor',
        endpoints: ['http://backup-service:8080'],
        healthCheck: { path: '/health', interval: 30000 }
      };

      await schedulingService.registerServiceWithFailover(primaryService, failoverService);

      // Simulate primary service failure
      await schedulingService.reportServiceFailure('primary-data-processor', {
        error: 'Connection timeout',
        timestamp: new Date(),
        retryCount: 3
      });

      const failoverStatus = await schedulingService.getFailoverStatus('primary-data-processor');

      expect(failoverStatus).toMatchObject({
        primaryService: 'primary-data-processor',
        backupService: 'backup-data-processor',
        status: 'failed-over',
        lastFailover: expect.any(Date),
        failoverCount: expect.any(Number)
      });

      // New jobs should be scheduled to backup service
      const jobScheduling = await schedulingService.scheduleServiceTask({
        serviceName: 'primary-data-processor',
        taskName: 'data-processing',
        schedule: '0 * * * *'
      });

      expect(jobScheduling.assignedService).toBe('backup-data-processor');
    });
  });

  // Configuration and Utility Tests
  describe('Configuration and Utilities', () => {
    it('should update scheduling configuration dynamically', async () => {
      const newConfig = {
        maxConcurrentJobs: 20,
        defaultJobTimeout: 600000,
        resourcePoolSize: 200,
        enableMetrics: true,
        calendarConfig: {
          defaultTimezone: 'Europe/London',
          businessHours: { start: '08:00', end: '18:00' }
        }
      };

      await schedulingService.updateConfiguration(newConfig);

      const config = schedulingService.getConfiguration();
      expect(config.maxConcurrentJobs).toBe(20);
      expect(config.defaultJobTimeout).toBe(600000);
      expect(config.resourcePoolSize).toBe(200);
      expect(config.calendarConfig.defaultTimezone).toBe('Europe/London');
    });

    it('should provide scheduling statistics', async () => {
      const stats = await schedulingService.getSchedulingStatistics();

      expect(stats).toMatchObject({
        totalJobs: expect.any(Number),
        activeJobs: expect.any(Number),
        pendingJobs: expect.any(Number),
        completedJobs: expect.any(Number),
        failedJobs: expect.any(Number),
        resourceUtilization: expect.any(Object),
        queueDepth: expect.any(Number),
        averageWaitTime: expect.any(Number)
      });
    });

    it('should handle cleanup and maintenance tasks', async () => {
      await schedulingService.performMaintenance({
        cleanupCompletedJobs: true,
        retentionDays: 30,
        optimizeResourcePool: true,
        generateReport: true
      });

      const maintenanceReport = await schedulingService.getMaintenanceReport();

      expect(maintenanceReport).toMatchObject({
        timestamp: expect.any(Date),
        tasksCompleted: expect.any(Array),
        jobsCleaned: expect.any(Number),
        resourcesOptimized: expect.any(Boolean),
        reportGenerated: expect.any(Boolean)
      });
    });
  });
});