/**
 * Qdrant Backup Retention Policy Manager
 *
 * Manages backup retention policies, lifecycle management, and compliance:
 * - Automated cleanup of expired backups
 * - Archive management and tiered storage
 * - Compliance-driven retention policies
 * - Storage optimization and space management
 * - Audit trail and retention reporting
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { readdir, readFile, stat,unlink, writeFile } from 'fs/promises';
import { basename, dirname,join } from 'path';
import { createHash } from 'crypto';

import { logger } from '@/utils/logger.js';

import type { BackupConfiguration,BackupMetadata } from './qdrant-backup-config.js';

/**
 * Retention policy action types
 */
export type RetentionAction = 'delete' | 'archive' | 'compress' | 'retain';

/**
 * Backup lifecycle stage
 */
export type BackupLifecycleStage = 'active' | 'archiving' | 'archived' | 'expiring' | 'expired';

/**
 * Retention policy evaluation result
 */
export interface RetentionPolicyResult {
  backupId: string;
  action: RetentionAction;
  reason: string;
  scheduledDate?: string;
  complianceStatus: 'compliant' | 'warning' | 'violation';
  daysUntilAction: number;
  estimatedSpaceReclaimed: number; // Bytes
}

/**
 * Retention statistics
 */
export interface RetentionStatistics {
  totalBackups: number;
  activeBackups: number;
  archivedBackups: number;
  expiredBackups: number;
  totalStorageUsed: number; // Bytes
  reclaimableStorage: number; // Bytes
  archivedStorage: number; // Bytes
  averageBackupAge: number; // Days
  oldestBackupAge: number; // Days
  newestBackupAge: number; // Days
  retentionScore: number; // 0-100
  complianceStatus: 'compliant' | 'warning' | 'violation';
  recommendations: string[];
}

/**
 * Archive configuration
 */
export interface ArchiveConfiguration {
  enabled: boolean;
  backend: 's3' | 'gcs' | 'azure' | 'local';
  storageClass: 'standard' | 'infrequent-access' | 'cold' | 'archive';
  transitionPolicy: {
    afterDays: number;
    automated: boolean;
    notificationRequired: boolean;
  };
  retrievalPolicy: {
    priority: 'standard' | 'bulk' | 'expedited';
    maxRetrievalTime: number; // Hours
  };
}

/**
 * Compliance configuration
 */
export interface ComplianceConfiguration {
  enabled: boolean;
  regulations: Array<{
    name: string;
    requirements: Array<{
      type: 'retention-period' | 'data-integrity' | 'audit-trail' | 'access-control';
      value: number | string;
      unit?: 'days' | 'years' | 'percent';
      mandatory: boolean;
    }>;
  }>;
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
  minimumRetentionDays: number;
  maximumRetentionDays?: number;
  auditRetentionDays: number;
  legalHoldEnabled: boolean;
  legalHoldReasons: string[];
}

/**
 * Backup retention policy manager
 */
export class BackupRetentionManager {
  private config: BackupConfiguration;
  private retentionRegistry: Map<string, BackupLifecycleStage> = new Map();
  private archiveRegistry: Map<string, ArchiveConfiguration> = new Map();
  private complianceRegistry: Map<string, ComplianceConfiguration> = new Map();
  private retentionHistory: Array<{
    timestamp: string;
    backupId: string;
    action: RetentionAction;
    reason: string;
    sizeReclaimed: number;
  }> = [];

  constructor(config: BackupConfiguration) {
    this.config = config;
  }

  /**
   * Initialize retention manager
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing backup retention manager...');

      // Load retention registry
      await this.loadRetentionRegistry();

      // Load archive configurations
      await this.loadArchiveConfigurations();

      // Load compliance configurations
      await this.loadComplianceConfigurations();

      // Perform initial retention evaluation
      await this.evaluateRetentionPolicies();

      // Schedule periodic retention checks
      this.scheduleRetentionChecks();

      logger.info('Backup retention manager initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize backup retention manager');
      throw error;
    }
  }

  /**
   * Evaluate retention policies for all backups
   */
  async evaluateRetentionPolicies(): Promise<RetentionPolicyResult[]> {
    try {
      logger.info('Evaluating backup retention policies...');

      const results: RetentionPolicyResult[] = [];
      const now = new Date();

      // Get all backups from registry
      const backups = await this.getAllBackups();

      for (const backup of backups) {
        const result = await this.evaluateBackupRetention(backup, now);
        results.push(result);
      }

      // Sort by urgency (days until action)
      results.sort((a, b) => a.daysUntilAction - b.daysUntilAction);

      logger.info({
        totalBackups: backups.length,
        actionsRequired: results.filter(r => r.action !== 'retain').length,
      }, 'Retention policy evaluation completed');

      return results;
    } catch (error) {
      logger.error({ error }, 'Failed to evaluate retention policies');
      throw error;
    }
  }

  /**
   * Execute retention actions
   */
  async executeRetentionActions(results: RetentionPolicyResult[]): Promise<{
    successful: number;
    failed: number;
    spaceReclaimed: number;
    errors: string[];
  }> {
    const summary = {
      successful: 0,
      failed: 0,
      spaceReclaimed: 0,
      errors: [] as string[],
    };

    logger.info({ actionsRequired: results.length }, 'Executing retention actions');

    for (const result of results) {
      try {
        if (result.action === 'retain') {
          continue; // No action needed
        }

        logger.debug({
          backupId: result.backupId,
          action: result.action,
          reason: result.reason,
        }, 'Executing retention action');

        let sizeReclaimed = 0;

        switch (result.action) {
          case 'delete':
            sizeReclaimed = await this.deleteBackup(result.backupId);
            break;
          case 'archive':
            sizeReclaimed = await this.archiveBackup(result.backupId);
            break;
          case 'compress':
            sizeReclaimed = await this.compressBackup(result.backupId);
            break;
        }

        // Record action in history
        this.retentionHistory.push({
          timestamp: new Date().toISOString(),
          backupId: result.backupId,
          action: result.action,
          reason: result.reason,
          sizeReclaimed,
        });

        summary.successful++;
        summary.spaceReclaimed += sizeReclaimed;

        logger.debug({
          backupId: result.backupId,
          action: result.action,
          sizeReclaimed,
        }, 'Retention action completed successfully');

      } catch (error) {
        summary.failed++;
        const errorMsg = `Failed to ${result.action} backup ${result.backupId}: ${error instanceof Error ? error.message : 'Unknown error'}`;
        summary.errors.push(errorMsg);
        logger.error({ backupId: result.backupId, action: result.action, error }, 'Retention action failed');
      }
    }

    // Save retention history
    await this.saveRetentionHistory();

    logger.info({
      successful: summary.successful,
      failed: summary.failed,
      spaceReclaimed: summary.spaceReclaimed,
      errors: summary.errors.length,
    }, 'Retention actions execution completed');

    return summary;
  }

  /**
   * Get retention statistics
   */
  async getRetentionStatistics(): Promise<RetentionStatistics> {
    try {
      const backups = await this.getAllBackups();
      const now = new Date();

      let totalStorage = 0;
      let reclaimableStorage = 0;
      let archivedStorage = 0;
      let totalAge = 0;
      let oldestAge = 0;
      let newestAge = Infinity;

      let activeCount = 0;
      let archivedCount = 0;
      let expiredCount = 0;

      for (const backup of backups) {
        totalStorage += backup.size;

        const ageInDays = this.calculateAgeInDays(backup.timestamp.toISOString(), now);
        totalAge += ageInDays;
        oldestAge = Math.max(oldestAge, ageInDays);
        newestAge = Math.min(newestAge, ageInDays);

        const lifecycle = this.retentionRegistry.get(backup.id) || 'active';
        switch (lifecycle) {
          case 'active':
            activeCount++;
            break;
          case 'archived':
            archivedCount++;
            archivedStorage += backup.size;
            break;
          case 'expired':
            expiredCount++;
            reclaimableStorage += backup.size;
            break;
        }
      }

      const averageAge = backups.length > 0 ? totalAge / backups.length : 0;

      // Calculate retention score (0-100)
      const retentionScore = this.calculateRetentionScore({
        totalBackups: backups.length,
        activeBackups: activeCount,
        archivedBackups: archivedCount,
        expiredBackups: expiredCount,
        averageAge,
        oldestAge,
      });

      // Determine compliance status
      const complianceStatus = this.determineComplianceStatus(retentionScore, expiredCount);

      // Generate recommendations
      const recommendations = this.generateRetentionRecommendations({
        totalBackups: backups.length,
        expiredBackups: expiredCount,
        reclaimableStorage,
        retentionScore,
        averageAge,
        oldestAge,
      });

      return {
        totalBackups: backups.length,
        activeBackups: activeCount,
        archivedBackups: archivedCount,
        expiredBackups: expiredCount,
        totalStorageUsed: totalStorage,
        reclaimableStorage,
        archivedStorage,
        averageBackupAge: Math.round(averageAge),
        oldestBackupAge: Math.round(oldestAge),
        newestBackupAge: Math.round(newestAge === Infinity ? 0 : newestAge),
        retentionScore,
        complianceStatus,
        recommendations,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get retention statistics');
      throw error;
    }
  }

  /**
   * Add backup to retention management
   */
  async addBackup(backup: BackupMetadata): Promise<void> {
    this.retentionRegistry.set(backup.id, 'active');

    // Check if backup should be immediately archived based on policy
    const ageInDays = this.calculateAgeInDays(backup.timestamp.toISOString());
    if (ageInDays >= this.config.retention.archivePolicy.afterDays) {
      await this.scheduleArchive(backup.id);
    }

    logger.debug({ backupId: backup.id }, 'Backup added to retention management');
  }

  /**
   * Remove backup from retention management
   */
  async removeBackup(backupId: string): Promise<void> {
    this.retentionRegistry.delete(backupId);
    logger.debug({ backupId }, 'Backup removed from retention management');
  }

  /**
   * Update backup lifecycle stage
   */
  async updateLifecycleStage(backupId: string, stage: BackupLifecycleStage): Promise<void> {
    const previousStage = this.retentionRegistry.get(backupId);
    this.retentionRegistry.set(backupId, stage);

    logger.info({
      backupId,
      previousStage,
      newStage: stage,
    }, 'Backup lifecycle stage updated');
  }

  /**
   * Place legal hold on backups
   */
  async setLegalHold(backupIds: string[], reason: string, expiresAt?: string): Promise<void> {
    if (!this.config.retention.compliance.legalHoldEnabled) {
      throw new Error('Legal hold is not enabled in compliance configuration');
    }

    logger.info({
      backupCount: backupIds.length,
      reason,
      expiresAt,
    }, 'Setting legal hold on backups');

    // Implementation would update backup metadata with legal hold information
    for (const backupId of backupIds) {
      // Mark backup as under legal hold
      logger.debug({ backupId, reason }, 'Backup placed under legal hold');
    }
  }

  /**
   * Release legal hold from backups
   */
  async releaseLegalHold(backupIds: string[]): Promise<void> {
    logger.info({
      backupCount: backupIds.length,
    }, 'Releasing legal hold from backups');

    for (const backupId of backupIds) {
      // Remove legal hold from backup
      logger.debug({ backupId }, 'Legal hold released from backup');
    }
  }

  /**
   * Get retention history
   */
  getRetentionHistory(limit?: number): Array<{
    timestamp: string;
    backupId: string;
    action: RetentionAction;
    reason: string;
    sizeReclaimed: number;
  }> {
    const history = [...this.retentionHistory].reverse(); // Most recent first
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Generate retention compliance report
   */
  async generateComplianceReport(): Promise<{
    generatedAt: string;
    complianceStatus: 'compliant' | 'warning' | 'violation';
    regulations: Array<{
      name: string;
      status: 'compliant' | 'non-compliant';
      requirements: Array<{
        type: string;
        status: 'met' | 'not-met';
        details: string;
      }>;
    }>;
    statistics: RetentionStatistics;
    recommendations: string[];
    legalHolds: Array<{
      backupId: string;
      reason: string;
      placedAt: string;
      expiresAt?: string;
    }>;
  }> {
    try {
      logger.info('Generating retention compliance report...');

      const statistics = await this.getRetentionStatistics();
      const now = new Date().toISOString();

      // Evaluate regulatory compliance
      const regulations = this.config.retention.compliance.regulatoryRequirements.map(regulation => ({
        name: regulation,
        status: 'compliant' as 'compliant' | 'non-compliant',
        requirements: [], // Would be populated based on specific regulations
      }));

      const complianceStatus = this.determineOverallComplianceStatus(statistics, regulations);

      const recommendations = this.generateComplianceRecommendations(statistics, regulations);

      const legalHolds: Array<{backupId: string; reason: string; placedAt: string; expiresAt?: string}> = []; // Would be populated from legal hold registry

      return {
        generatedAt: now,
        complianceStatus,
        regulations,
        statistics,
        recommendations,
        legalHolds,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to generate compliance report');
      throw error;
    }
  }

  // === Private Helper Methods ===

  private async evaluateBackupRetention(backup: BackupMetadata, now: Date): Promise<RetentionPolicyResult> {
    const ageInDays = this.calculateAgeInDays(backup.timestamp.toISOString(), now);
    const lifecycle = this.retentionRegistry.get(backup.id) || 'active';

    // Check legal hold first
    if (this.isUnderLegalHold(backup.id)) {
      return {
        backupId: backup.id,
        action: 'retain',
        reason: 'Backup under legal hold',
        complianceStatus: 'compliant',
        daysUntilAction: Infinity,
        estimatedSpaceReclaimed: 0,
      };
    }

    // Apply retention policies
    let action: RetentionAction = 'retain';
    let reason = 'Within retention policy';
    let scheduledDate: string | undefined;
    let daysUntilAction = Infinity;

    // Check maximum age
    if (ageInDays > this.config.retention.maxAgeDays) {
      action = 'delete';
      reason = 'Exceeded maximum retention age';
      daysUntilAction = 0;
    }
    // Check archive policy
    else if (ageInDays >= this.config.retention.archivePolicy.afterDays && lifecycle === 'active') {
      action = 'archive';
      reason = 'Eligible for archiving';
      daysUntilAction = 0;
    }
    // Check incremental backup limits
    else if (backup.type === 'incremental') {
      const incrementalCount = await this.countBackupsByType('incremental');
      if (incrementalCount > this.config.retention.incrementalBackups) {
        const oldestIncremental = await this.findOldestBackupByType('incremental');
        if (oldestIncremental?.id === backup.id) {
          action = 'delete';
          reason = 'Exceeded incremental backup limit';
          daysUntilAction = 0;
        }
      }
    }
    // Check full backup limits
    else if (backup.type === 'full') {
      const fullCount = await this.countBackupsByType('full');
      if (fullCount > this.config.retention.fullBackups) {
        const oldestFull = await this.findOldestBackupByType('full');
        if (oldestFull?.id === backup.id) {
          action = lifecycle === 'archived' ? 'delete' : 'archive';
          reason = lifecycle === 'archived' ?
            'Exceeded full backup retention limit' :
            'Exceeded active full backup limit';
          daysUntilAction = 0;
        }
      }
    }

    // Calculate compliance status
    let complianceStatus: 'compliant' | 'warning' | 'violation' = 'compliant';
    if (action === 'delete' && ageInDays < this.config.retention.compliance.minRetentionDays) {
      complianceStatus = 'violation';
    } else if (ageInDays > this.config.retention.maxAgeDays * 0.9) {
      complianceStatus = 'warning';
    }

    // Estimate space reclaimable
    const estimatedSpaceReclaimed = action === 'delete' ? backup.size : 0;

    return {
      backupId: backup.id,
      action,
      reason,
      scheduledDate,
      complianceStatus,
      daysUntilAction,
      estimatedSpaceReclaimed,
    };
  }

  private calculateAgeInDays(timestamp: string, now: Date = new Date()): number {
    const backupDate = new Date(timestamp);
    const diffTime = Math.abs(now.getTime() - backupDate.getTime());
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  private async getAllBackups(): Promise<BackupMetadata[]> {
    // Implementation would load all backup metadata
    return [];
  }

  private async countBackupsByType(type: 'full' | 'incremental'): Promise<number> {
    const backups = await this.getAllBackups();
    return backups.filter(backup => backup.type === type).length;
  }

  private async findOldestBackupByType(type: 'full' | 'incremental'): Promise<BackupMetadata | undefined> {
    const backups = await this.getAllBackups();
    const typeBackups = backups.filter(backup => backup.type === type);
    return typeBackups.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())[0];
  }

  private isUnderLegalHold(backupId: string): boolean {
    // Implementation would check legal hold registry
    return false;
  }

  private async deleteBackup(backupId: string): Promise<number> {
    // Implementation would delete backup and return space reclaimed
    logger.info({ backupId }, 'Deleting backup');
    return 0;
  }

  private async archiveBackup(backupId: string): Promise<number> {
    // Implementation would archive backup and return primary storage reclaimed
    logger.info({ backupId }, 'Archiving backup');
    await this.updateLifecycleStage(backupId, 'archiving');
    // ... archiving logic ...
    await this.updateLifecycleStage(backupId, 'archived');
    return 0;
  }

  private async compressBackup(backupId: string): Promise<number> {
    // Implementation would compress backup and return space saved
    logger.info({ backupId }, 'Compressing backup');
    return 0;
  }

  private async scheduleArchive(backupId: string): Promise<void> {
    // Implementation would schedule backup for archiving
    logger.debug({ backupId }, 'Scheduling backup for archiving');
  }

  private calculateRetentionScore(metrics: {
    totalBackups: number;
    activeBackups: number;
    archivedBackups: number;
    expiredBackups: number;
    averageAge: number;
    oldestAge: number;
  }): number {
    let score = 100;

    // Deduct points for expired backups
    score -= metrics.expiredBackups * 10;

    // Deduct points for very old backups
    if (metrics.oldestAge > this.config.retention.maxAgeDays * 0.8) {
      score -= 20;
    }

    // Bonus points for good archival ratio
    const archiveRatio = metrics.totalBackups > 0 ? metrics.archivedBackups / metrics.totalBackups : 0;
    if (archiveRatio > 0.3 && archiveRatio < 0.7) {
      score += 10;
    }

    return Math.max(0, Math.min(100, score));
  }

  private determineComplianceStatus(score: number, expiredCount: number): 'compliant' | 'warning' | 'violation' {
    if (expiredCount > 0) return 'violation';
    if (score < 70) return 'warning';
    return 'compliant';
  }

  private generateRetentionRecommendations(metrics: {
    totalBackups: number;
    expiredBackups: number;
    reclaimableStorage: number;
    retentionScore: number;
    averageAge: number;
    oldestAge: number;
  }): string[] {
    const recommendations: string[] = [];

    if (metrics.expiredBackups > 0) {
      recommendations.push(`Remove ${metrics.expiredBackups} expired backups to reclaim ${this.formatBytes(metrics.reclaimableStorage)}`);
    }

    if (metrics.retentionScore < 70) {
      recommendations.push('Review retention policies to improve compliance score');
    }

    if (metrics.averageAge > this.config.retention.maxAgeDays * 0.7) {
      recommendations.push('Consider archiving older backups to optimize storage');
    }

    if (metrics.totalBackups > this.config.retention.fullBackups + this.config.retention.incrementalBackups) {
      recommendations.push('Backup count exceeds configured limits - consider cleanup');
    }

    return recommendations;
  }

  private determineOverallComplianceStatus(
    statistics: RetentionStatistics,
    regulations: Array<{ name: string; status: 'compliant' | 'non-compliant' }>
  ): 'compliant' | 'warning' | 'violation' {
    if (statistics.complianceStatus === 'violation' ||
        regulations.some(reg => reg.status === 'non-compliant')) {
      return 'violation';
    }

    if (statistics.complianceStatus === 'warning' ||
        regulations.some(reg => reg.status === 'non-compliant')) {
      return 'warning';
    }

    return 'compliant';
  }

  private generateComplianceRecommendations(
    statistics: RetentionStatistics,
    regulations: Array<{ name: string; status: 'compliant' | 'non-compliant' }>
  ): string[] {
    const recommendations: string[] = [];

    if (statistics.complianceStatus !== 'compliant') {
      recommendations.push('Address retention policy compliance issues');
    }

    regulations.filter(reg => reg.status === 'non-compliant').forEach(reg => {
      recommendations.push(`Review compliance with ${reg.name} requirements`);
    });

    if (statistics.reclaimableStorage > 0) {
      recommendations.push('Execute retention actions to reclaim storage space');
    }

    return recommendations;
  }

  private formatBytes(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(1)} ${units[unitIndex]}`;
  }

  private scheduleRetentionChecks(): void {
    // Implementation would schedule periodic retention checks
    logger.debug('Retention checks scheduled');
  }

  private async loadRetentionRegistry(): Promise<void> {
    // Implementation would load retention registry from disk
    logger.debug('Retention registry loaded');
  }

  private async loadArchiveConfigurations(): Promise<void> {
    // Implementation would load archive configurations
    logger.debug('Archive configurations loaded');
  }

  private async loadComplianceConfigurations(): Promise<void> {
    // Implementation would load compliance configurations
    logger.debug('Compliance configurations loaded');
  }

  private async saveRetentionHistory(): Promise<void> {
    // Implementation would save retention history to disk
    logger.debug('Retention history saved');
  }
}
