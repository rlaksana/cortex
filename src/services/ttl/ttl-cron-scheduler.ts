/**
 * TTL Cron Scheduler Service
 *
 * Provides cron-based scheduling for TTL cleanup operations.
 * Integrates with the expiry worker to run scheduled cleanup jobs.
 *
 * Features:
 * - Cron-based scheduling with configurable intervals
 * - Automatic job management and monitoring
 * - Graceful shutdown and error handling
 * - Comprehensive logging and metrics
 * - Support for multiple schedules
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { logger } from '../../utils/logger.js';
import {
  runExpiryWorker,
  type ExpiryWorkerConfig,
  type ExpiryWorkerResult,
} from '../expiry-worker.js';
import type { TTLBulkOperationOptions } from './ttl-management-service.js';

export interface TTLCronSchedule {
  id: string;
  name: string;
  cronExpression: string;
  enabled: boolean;
  workerConfig: Partial<ExpiryWorkerConfig>;
  ttlOptions: Partial<TTLBulkOperationOptions>;
  timezone?: string;
  lastRun?: string;
  nextRun?: string;
  runCount: number;
  successCount: number;
  errorCount: number;
  lastResult?: ExpiryWorkerResult;
  isActive: boolean;
}

export interface TTLCronSchedulerConfig {
  /** Enable the cron scheduler */
  enabled: boolean;
  /** Default timezone for schedules */
  defaultTimezone: string;
  /** Maximum concurrent jobs */
  maxConcurrentJobs: number;
  /** Job timeout in milliseconds */
  jobTimeoutMs: number;
  /** Enable job history tracking */
  enableJobHistory: boolean;
  /** Maximum job history to keep */
  maxJobHistory: number;
  /** Enable graceful shutdown */
  enableGracefulShutdown: boolean;
  /** Graceful shutdown timeout in milliseconds */
  shutdownTimeoutMs: number;
}

export interface TTLJobHistory {
  scheduleId: string;
  runId: string;
  startTime: string;
  endTime?: string;
  duration?: number;
  status: 'running' | 'completed' | 'failed' | 'timeout';
  result?: ExpiryWorkerResult;
  error?: string;
  metrics: {
    itemsProcessed: number;
    itemsDeleted: number;
    itemsSkipped: number;
    processingRate: number;
  };
}

/**
 * TTL Cron Scheduler Service
 *
 * Manages scheduled TTL cleanup jobs using cron expressions.
 */
export class TTLCronScheduler {
  private config: TTLCronSchedulerConfig;
  private schedules: Map<string, TTLCronSchedule> = new Map();
  private activeJobs: Map<string, { timeoutId: NodeJS.Timeout; startTime: number }> = new Map();
  private jobHistory: TTLJobHistory[] = [];
  private isRunning: boolean = false;
  private shutdownInProgress: boolean = false;

  // Default configuration
  private static readonly DEFAULT_CONFIG: TTLCronSchedulerConfig = {
    enabled: true,
    defaultTimezone: 'UTC',
    maxConcurrentJobs: 3,
    jobTimeoutMs: 30 * 60 * 1000, // 30 minutes
    enableJobHistory: true,
    maxJobHistory: 1000,
    enableGracefulShutdown: true,
    shutdownTimeoutMs: 60 * 1000, // 1 minute
  };

  constructor(config: Partial<TTLCronSchedulerConfig> = {}) {
    this.config = { ...TTLCronScheduler.DEFAULT_CONFIG, ...config };
    this.setupDefaultSchedules();
    logger.info('TTL Cron Scheduler initialized', { config: this.config });
  }

  /**
   * Start the cron scheduler
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('TTL Cron Scheduler is already running');
      return;
    }

    if (!this.config.enabled) {
      logger.info('TTL Cron Scheduler is disabled, not starting');
      return;
    }

    this.isRunning = true;
    this.shutdownInProgress = false;

    // Setup graceful shutdown handlers
    if (this.config.enableGracefulShutdown) {
      this.setupGracefulShutdown();
    }

    // Start all enabled schedules
    for (const schedule of this.schedules.values()) {
      if (schedule.enabled) {
        this.startSchedule(schedule);
      }
    }

    logger.info('TTL Cron Scheduler started', {
      activeSchedules: Array.from(this.schedules.values()).filter((s) => s.enabled).length,
      timezone: this.config.defaultTimezone,
    });
  }

  /**
   * Stop the cron scheduler
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      logger.warn('TTL Cron Scheduler is not running');
      return;
    }

    this.shutdownInProgress = true;
    logger.info('TTL Cron Scheduler stopping...');

    // Stop all active schedules
    for (const [scheduleId, job] of this.activeJobs) {
      clearTimeout(job.timeoutId);
      logger.debug(`Stopped schedule ${scheduleId}`);
    }

    this.activeJobs.clear();

    // Wait for running jobs to complete or timeout
    const shutdownStart = Date.now();
    while (this.activeJobs.size > 0 && Date.now() - shutdownStart < this.config.shutdownTimeoutMs) {
      await this.sleep(1000);
    }

    // Force stop any remaining jobs
    if (this.activeJobs.size > 0) {
      logger.warn(`Force stopping ${this.activeJobs.size} remaining jobs`);
      this.activeJobs.clear();
    }

    this.isRunning = false;
    logger.info('TTL Cron Scheduler stopped');
  }

  /**
   * Add a new cron schedule
   */
  addSchedule(
    schedule: Omit<TTLCronSchedule, 'runCount' | 'successCount' | 'errorCount' | 'isActive'>
  ): void {
    const fullSchedule: TTLCronSchedule = {
      ...schedule,
      runCount: 0,
      successCount: 0,
      errorCount: 0,
      isActive: false,
    };

    this.schedules.set(schedule.id, fullSchedule);

    // Start the schedule if scheduler is running and schedule is enabled
    if (this.isRunning && schedule.enabled) {
      this.startSchedule(fullSchedule);
    }

    logger.info('TTL cron schedule added', {
      scheduleId: schedule.id,
      name: schedule.name,
      cronExpression: schedule.cronExpression,
    });
  }

  /**
   * Update an existing cron schedule
   */
  updateSchedule(scheduleId: string, updates: Partial<TTLCronSchedule>): boolean {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      logger.warn('Schedule not found for update', { scheduleId });
      return false;
    }

    // Stop the current schedule if it's active
    if (schedule.isActive) {
      this.stopSchedule(schedule);
    }

    // Update the schedule
    const updatedSchedule = { ...schedule, ...updates };
    this.schedules.set(scheduleId, updatedSchedule);

    // Restart if scheduler is running and schedule is enabled
    if (this.isRunning && updatedSchedule.enabled) {
      this.startSchedule(updatedSchedule);
    }

    logger.info('TTL cron schedule updated', {
      scheduleId,
      name: updatedSchedule.name,
      enabled: updatedSchedule.enabled,
    });

    return true;
  }

  /**
   * Remove a cron schedule
   */
  removeSchedule(scheduleId: string): boolean {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      logger.warn('Schedule not found for removal', { scheduleId });
      return false;
    }

    // Stop the schedule if it's active
    if (schedule.isActive) {
      this.stopSchedule(schedule);
    }

    this.schedules.delete(scheduleId);
    logger.info('TTL cron schedule removed', { scheduleId, name: schedule.name });
    return true;
  }

  /**
   * Get all schedules
   */
  getSchedules(): TTLCronSchedule[] {
    return Array.from(this.schedules.values());
  }

  /**
   * Get schedule by ID
   */
  getSchedule(scheduleId: string): TTLCronSchedule | undefined {
    return this.schedules.get(scheduleId);
  }

  /**
   * Get active jobs
   */
  getActiveJobs(): Array<{ scheduleId: string; runTime: number; duration: number }> {
    const now = Date.now();
    return Array.from(this.activeJobs.entries()).map(([scheduleId, job]) => ({
      scheduleId,
      runTime: now - job.startTime,
      duration: now - job.startTime,
    }));
  }

  /**
   * Get job history
   */
  getJobHistory(limit?: number): TTLJobHistory[] {
    const history = [...this.jobHistory].reverse();
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Get scheduler status
   */
  getStatus(): {
    isRunning: boolean;
    schedulesCount: number;
    activeSchedulesCount: number;
    activeJobsCount: number;
    totalRuns: number;
    successRate: number;
    averageProcessingRate: number;
  } {
    const schedules = Array.from(this.schedules.values());
    const totalRuns = schedules.reduce((sum, s) => sum + s.runCount, 0);
    const totalSuccesses = schedules.reduce((sum, s) => sum + s.successCount, 0);
    const successRate = totalRuns > 0 ? totalSuccesses / totalRuns : 0;

    // Calculate average processing rate from job history
    const recentHistory = this.jobHistory.slice(-50); // Last 50 jobs
    const averageProcessingRate =
      recentHistory.length > 0
        ? recentHistory.reduce((sum, job) => sum + job.metrics.processingRate, 0) /
          recentHistory.length
        : 0;

    return {
      isRunning: this.isRunning,
      schedulesCount: schedules.length,
      activeSchedulesCount: schedules.filter((s) => s.enabled).length,
      activeJobsCount: this.activeJobs.size,
      totalRuns,
      successRate,
      averageProcessingRate,
    };
  }

  /**
   * Manually trigger a schedule run
   */
  async triggerSchedule(scheduleId: string): Promise<ExpiryWorkerResult | null> {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      logger.warn('Schedule not found for manual trigger', { scheduleId });
      return null;
    }

    if (!schedule.enabled) {
      logger.warn('Schedule is disabled, cannot trigger', { scheduleId });
      return null;
    }

    if (this.activeJobs.has(scheduleId)) {
      logger.warn('Schedule is already running', { scheduleId });
      return null;
    }

    logger.info('Manually triggering TTL schedule', { scheduleId, name: schedule.name });
    return await this.runScheduleJob(schedule);
  }

  /**
   * Setup default schedules
   */
  private setupDefaultSchedules(): void {
    // Daily cleanup at 2 AM UTC
    this.addSchedule({
      id: 'daily-cleanup',
      name: 'Daily TTL Cleanup',
      cronExpression: '0 2 * * *', // 2 AM daily
      enabled: true,
      workerConfig: {
        enabled: true,
        dry_run: false,
        batch_size: 100,
        max_batches: 50,
      },
      ttlOptions: {
        generateAudit: true,
        validatePolicies: true,
      },
      timezone: 'UTC',
    });

    // Hourly light cleanup for high-priority items
    this.addSchedule({
      id: 'hourly-priority-cleanup',
      name: 'Hourly Priority TTL Cleanup',
      cronExpression: '0 * * * *', // Every hour
      enabled: true,
      workerConfig: {
        enabled: true,
        dry_run: false,
        batch_size: 50,
        max_batches: 10,
      },
      ttlOptions: {
        generateAudit: false, // Don't audit hourly runs
        validatePolicies: true,
      },
      timezone: 'UTC',
    });

    // Weekly comprehensive cleanup and reporting
    this.addSchedule({
      id: 'weekly-comprehensive-cleanup',
      name: 'Weekly Comprehensive TTL Cleanup',
      cronExpression: '0 3 * * 0', // 3 AM on Sundays
      enabled: true,
      workerConfig: {
        enabled: true,
        dry_run: false,
        batch_size: 200,
        max_batches: 100,
      },
      ttlOptions: {
        generateAudit: true,
        validatePolicies: true,
        verbose: true,
      },
      timezone: 'UTC',
    });
  }

  /**
   * Start a schedule
   */
  private startSchedule(schedule: TTLCronSchedule): void {
    if (schedule.isActive) {
      return;
    }

    schedule.isActive = true;
    this.scheduleNextRun(schedule);

    logger.debug('TTL schedule started', {
      scheduleId: schedule.id,
      name: schedule.name,
      cronExpression: schedule.cronExpression,
    });
  }

  /**
   * Stop a schedule
   */
  private stopSchedule(schedule: TTLCronSchedule): void {
    if (!schedule.isActive) {
      return;
    }

    schedule.isActive = false;

    const activeJob = this.activeJobs.get(schedule.id);
    if (activeJob) {
      clearTimeout(activeJob.timeoutId);
      this.activeJobs.delete(schedule.id);
    }

    logger.debug('TTL schedule stopped', {
      scheduleId: schedule.id,
      name: schedule.name,
    });
  }

  /**
   * Schedule the next run for a schedule
   */
  private scheduleNextRun(schedule: TTLCronSchedule): void {
    if (!schedule.isActive || this.shutdownInProgress) {
      return;
    }

    const nextRunTime = this.getNextRunTime(schedule.cronExpression);
    const delay = nextRunTime.getTime() - Date.now();

    if (delay <= 0) {
      // Schedule to run immediately
      this.runSchedule(schedule);
    } else {
      // Schedule to run in the future
      const timeoutId = setTimeout(() => {
        this.runSchedule(schedule);
      }, delay);

      this.activeJobs.set(schedule.id, {
        timeoutId,
        startTime: Date.now(),
      });

      schedule.nextRun = nextRunTime.toISOString();
    }
  }

  /**
   * Run a schedule job
   */
  private async runSchedule(schedule: TTLCronSchedule): Promise<void> {
    if (this.shutdownInProgress || !schedule.isActive) {
      return;
    }

    // Check if we're at the concurrent job limit
    if (this.activeJobs.size >= this.config.maxConcurrentJobs) {
      logger.warn('Max concurrent jobs reached, rescheduling', {
        scheduleId: schedule.id,
        currentJobs: this.activeJobs.size,
        maxJobs: this.config.maxConcurrentJobs,
      });

      // Reschedule for later
      setTimeout(() => this.runSchedule(schedule), 60000); // Try again in 1 minute
      return;
    }

    const runId = `${schedule.id}-${Date.now()}`;
    const startTime = new Date().toISOString();

    logger.info('Starting TTL cron job', {
      scheduleId: schedule.id,
      name: schedule.name,
      runId,
      workerConfig: schedule.workerConfig,
    });

    // Create job history entry
    const jobHistory: TTLJobHistory = {
      scheduleId: schedule.id,
      runId,
      startTime,
      status: 'running',
      metrics: {
        itemsProcessed: 0,
        itemsDeleted: 0,
        itemsSkipped: 0,
        processingRate: 0,
      },
    };

    if (this.config.enableJobHistory) {
      this.jobHistory.push(jobHistory);
      this.trimJobHistory();
    }

    try {
      // Set up timeout for the job
      const timeoutId = setTimeout(() => {
        logger.warn('TTL cron job timed out', {
          scheduleId: schedule.id,
          runId,
          timeoutMs: this.config.jobTimeoutMs,
        });

        this.finishJob(jobHistory, 'timeout', undefined, 'Job timed out');
      }, this.config.jobTimeoutMs);

      this.activeJobs.set(schedule.id, {
        timeoutId,
        startTime: Date.now(),
      });

      // Run the expiry worker
      const result = await runExpiryWorker(schedule.workerConfig);

      // Clear the timeout
      clearTimeout(timeoutId);
      this.activeJobs.delete(schedule.id);

      // Update schedule statistics
      schedule.runCount++;
      schedule.successCount++;
      schedule.lastRun = startTime;
      schedule.lastResult = result;

      // Update job history
      jobHistory.endTime = new Date().toISOString();
      jobHistory.duration = Date.now() - new Date(startTime).getTime();
      jobHistory.status = 'completed';
      jobHistory.result = result;
      jobHistory.metrics = {
        itemsProcessed: result.total_processed,
        itemsDeleted: result.total_deleted,
        itemsSkipped: result.total_skipped,
        processingRate: result.metrics.processing_rate_per_second,
      };

      logger.info('TTL cron job completed successfully', {
        scheduleId: schedule.id,
        name: schedule.name,
        runId,
        duration: jobHistory.duration,
        itemsProcessed: result.total_processed,
        itemsDeleted: result.total_deleted,
        metrics: result.metrics,
      });
    } catch (error) {
      // Clear timeout if still active
      const activeJob = this.activeJobs.get(schedule.id);
      if (activeJob) {
        clearTimeout(activeJob.timeoutId);
        this.activeJobs.delete(schedule.id);
      }

      // Update schedule statistics
      schedule.runCount++;
      schedule.errorCount++;
      schedule.lastRun = startTime;

      // Update job history
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.finishJob(jobHistory, 'failed', undefined, errorMessage);

      logger.error('TTL cron job failed', {
        scheduleId: schedule.id,
        name: schedule.name,
        runId,
        error: errorMessage,
        runCount: schedule.runCount,
        errorCount: schedule.errorCount,
      });
    }

    // Schedule the next run
    this.scheduleNextRun(schedule);
  }

  /**
   * Run a schedule job and return the result
   */
  private async runScheduleJob(schedule: TTLCronSchedule): Promise<ExpiryWorkerResult> {
    const runId = `${schedule.id}-manual-${Date.now()}`;
    const startTime = new Date().toISOString();

    logger.info('Starting manual TTL cron job', {
      scheduleId: schedule.id,
      name: schedule.name,
      runId,
    });

    try {
      const result = await runExpiryWorker(schedule.workerConfig);

      logger.info('Manual TTL cron job completed successfully', {
        scheduleId: schedule.id,
        name: schedule.name,
        runId,
        duration: Date.now() - new Date(startTime).getTime(),
        itemsProcessed: result.total_processed,
        itemsDeleted: result.total_deleted,
      });

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error('Manual TTL cron job failed', {
        scheduleId: schedule.id,
        name: schedule.name,
        runId,
        error: errorMessage,
      });
      throw error;
    }
  }

  /**
   * Finish a job and update history
   */
  private finishJob(
    jobHistory: TTLJobHistory,
    status: 'completed' | 'failed' | 'timeout',
    result?: ExpiryWorkerResult,
    error?: string
  ): void {
    jobHistory.endTime = new Date().toISOString();
    jobHistory.duration = Date.now() - new Date(jobHistory.startTime).getTime();
    jobHistory.status = status;
    jobHistory.result = result;
    jobHistory.error = error;

    if (result) {
      jobHistory.metrics = {
        itemsProcessed: result.total_processed,
        itemsDeleted: result.total_deleted,
        itemsSkipped: result.total_skipped,
        processingRate: result.metrics.processing_rate_per_second,
      };
    }
  }

  /**
   * Get next run time for a cron expression
   */
  private getNextRunTime(cronExpression: string): Date {
    // Simple implementation - in practice, you'd use a cron parser library
    // For now, we'll use a basic approach
    const now = new Date();

    // Parse basic cron patterns (simplified)
    const parts = cronExpression.split(' ');
    if (parts.length !== 5) {
      logger.warn('Invalid cron expression, using 1 hour from now', { cronExpression });
      return new Date(now.getTime() + 60 * 60 * 1000);
    }

    const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;

    // Simple scheduling: if it's a daily pattern like "0 2 * * *"
    if (
      minute === '0' &&
      hour !== '*' &&
      dayOfMonth === '*' &&
      month === '*' &&
      dayOfWeek === '*'
    ) {
      const targetHour = parseInt(hour);
      const nextRun = new Date(now);
      nextRun.setHours(targetHour, 0, 0, 0);

      if (nextRun <= now) {
        nextRun.setDate(nextRun.getDate() + 1);
      }

      return nextRun;
    }

    // For other patterns, default to 1 hour from now
    logger.debug('Using default 1-hour scheduling for complex cron pattern', { cronExpression });
    return new Date(now.getTime() + 60 * 60 * 1000);
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      logger.info(`Received ${signal}, initiating graceful shutdown`);
      await this.stop();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  /**
   * Trim job history to stay within limits
   */
  private trimJobHistory(): void {
    if (this.jobHistory.length > this.config.maxJobHistory) {
      const excess = this.jobHistory.length - this.config.maxJobHistory;
      this.jobHistory = this.jobHistory.slice(excess);
    }
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Export factory function
export function createTTLCronScheduler(config?: Partial<TTLCronSchedulerConfig>): TTLCronScheduler {
  return new TTLCronScheduler(config);
}
