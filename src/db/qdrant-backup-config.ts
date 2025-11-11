/**
 * Qdrant Backup Configuration Manager
 *
 * Provides comprehensive configuration management for backup and disaster recovery:
 * - Backup scheduling and cadence definitions
 * - Retention policies and storage management
 * - RPO/RTO target configuration
 * - Performance and resource management settings
 * - Environment-specific configurations
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { readFile, writeFile } from 'fs/promises';
import { join } from 'path';

import * as cron from 'node-cron';

import { logger } from '@/utils/logger.js';

/**
 * Environment-specific backup configurations
 */
export type Environment = 'development' | 'staging' | 'production';

/**
 * Backup priority levels
 */
export type BackupPriority = 'low' | 'normal' | 'high' | 'critical';

/**
 * Storage backend types
 */
export type StorageBackend = 'local' | 's3' | 'gcs' | 'azure' | 'minio';

/**
 * Backup configuration presets
 */
export const BACKUP_PRESETS = {
  // High-frequency, short retention for development
  development: {
    schedule: {
      fullBackup: '0 2 * * *', // Daily at 2 AM
      incrementalBackup: '0 */4 * * *', // Every 4 hours
      restoreTest: '0 6 * * *', // Daily at 6 AM
      consistencyCheck: '0 3 * * *', // Daily at 3 AM
    },
    retention: {
      fullBackups: 3, // 3 days
      incrementalBackups: 12, // 2 days worth
      restoreTestResults: 7,
      maxAgeDays: 3,
    },
    targets: {
      rpoMinutes: 240, // 4 hours
      rtoMinutes: 30, // 30 minutes
      maxDataLossMinutes: 240,
      maxDowntimeMinutes: 30,
    },
    performance: {
      maxConcurrentBackups: 1,
      bandwidthThrottleMBps: 10,
      priority: 'low' as BackupPriority,
    },
  },

  // Moderate frequency for staging
  staging: {
    schedule: {
      fullBackup: '0 1 * * *', // Daily at 1 AM
      incrementalBackup: '0 */2 * * *', // Every 2 hours
      restoreTest: '0 5 * * 1', // Weekly on Monday at 5 AM
      consistencyCheck: '0 2 * * *', // Daily at 2 AM
    },
    retention: {
      fullBackups: 7, // 1 week
      incrementalBackups: 84, // 1 week worth
      restoreTestResults: 14,
      maxAgeDays: 7,
    },
    targets: {
      rpoMinutes: 120, // 2 hours
      rtoMinutes: 15, // 15 minutes
      maxDataLossMinutes: 120,
      maxDowntimeMinutes: 15,
    },
    performance: {
      maxConcurrentBackups: 2,
      bandwidthThrottleMBps: 50,
      priority: 'normal' as BackupPriority,
    },
  },

  // High-frequency, long retention for production
  production: {
    schedule: {
      fullBackup: '0 0 * * 0', // Weekly on Sunday at midnight
      incrementalBackup: '0 * * * *', // Every hour
      restoreTest: '0 3 * * *', // Daily at 3 AM
      consistencyCheck: '0 1 * * *', // Daily at 1 AM
    },
    retention: {
      fullBackups: 4, // 4 weeks
      incrementalBackups: 168, // 1 week worth
      restoreTestResults: 30,
      maxAgeDays: 30,
    },
    targets: {
      rpoMinutes: 60, // 1 hour
      rtoMinutes: 10, // 10 minutes
      maxDataLossMinutes: 60,
      maxDowntimeMinutes: 10,
    },
    performance: {
      maxConcurrentBackups: 3,
      bandwidthThrottleMBps: 100,
      priority: 'high' as BackupPriority,
    },
  },
} as const;

/**
 * Comprehensive backup configuration interface
 */
export interface BackupConfiguration {
  // Environment identification
  environment: Environment;
  version: string;
  createdAt: string;
  updatedAt: string;

  // Backup scheduling configuration
  schedule: {
    fullBackup: string;
    incrementalBackup: string;
    restoreTest: string;
    consistencyCheck: string;
    maintenanceWindows?: Array<{
      start: string; // ISO timestamp
      end: string; // ISO timestamp
      description: string;
      allowedOperations: ('full' | 'incremental' | 'test' | 'check')[];
    }>;
  };

  // Retention policies
  retention: {
    fullBackups: number;
    incrementalBackups: number;
    restoreTestResults: number;
    maxAgeDays: number;
    archivePolicy: {
      enabled: boolean;
      afterDays: number;
      archiveStorage: {
        backend: StorageBackend;
        config: Record<string, any>;
      };
    };
    compliance: {
      enabled: boolean;
      regulatoryRequirements: string[];
      minRetentionDays: number;
      auditLogRetentionDays: number;
      legalHoldEnabled: boolean;
    };
  };

  // Storage configuration
  storage: {
    primary: {
      backend: StorageBackend;
      config: {
        // Local storage
        path?: string;
        // S3 storage
        bucket?: string;
        region?: string;
        accessKeyId?: string;
        secretAccessKey?: string;
        endpoint?: string;
        // GCS storage
        bucketName?: string;
        keyFilename?: string;
        // Azure storage
        accountName?: string;
        accountKey?: string;
        containerName?: string;
        // Common settings
        encryptionEnabled: boolean;
        compressionEnabled: boolean;
        encryptionKey?: string;
        compressionLevel?: number; // 1-9
      };
    };
    replica?: {
      backend: StorageBackend;
      config: Record<string, any>;
      syncMode: 'async' | 'sync';
      lagThresholdMinutes: number;
    };
    monitoring: {
      spaceAlertThreshold: number; // Percentage
      performanceAlertThreshold: number; // MB/s
      healthCheckInterval: number; // Minutes
    };
  };

  // RPO/RTO targets and SLA
  targets: {
    rpoMinutes: number;
    rtoMinutes: number;
    maxDataLossMinutes: number;
    maxDowntimeMinutes: number;
    sla: {
      availabilityTarget: number; // Percentage
      errorRateTarget: number; // Percentage
      responseTimeTarget: number; // Milliseconds
    };
    businessImpact: {
      criticalityLevel: 'low' | 'medium' | 'high' | 'critical';
      businessFunction: string;
      dependencies: string[];
      maxAcceptableOutageMinutes: number;
    };
  };

  // Performance and resource management
  performance: {
    maxConcurrentBackups: number;
    bandwidthThrottleMBps?: number;
    priority: BackupPriority;
    resources: {
      maxMemoryMB: number;
      maxCpuPercent: number;
      maxDiskIO?: number; // MB/s
      maxNetworkIO?: number; // MB/s
    };
    optimization: {
      deduplicationEnabled: boolean;
      compressionEnabled: boolean;
      parallelProcessing: boolean;
      batchSizes: {
        fullBackup: number;
        incrementalBackup: number;
        restore: number;
      };
    };
  };

  // Security and compliance
  security: {
    encryption: {
      enabled: boolean;
      algorithm: string;
      keyRotationDays: number;
      keyManagement: 'local' | 'aws-kms' | 'gcp-kms' | 'azure-kv';
    };
    accessControl: {
      backupCreationRoles: string[];
      backupRestoreRoles: string[];
      auditLogEnabled: boolean;
      requireApprovalForRestore: boolean;
    };
    compliance: {
      dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
      retentionPolicies: Array<{
        dataClass: string;
        retentionDays: number;
        archivalRequired: boolean;
      }>;
      auditRequirements: string[];
    };
  };

  // Monitoring and alerting
  monitoring: {
    alerts: {
      backupFailure: {
        enabled: boolean;
        threshold: number; // Consecutive failures
        escalationDelay: number; // Minutes
      };
      restoreTestFailure: {
        enabled: boolean;
        threshold: number; // Consecutive failures
        escalationDelay: number; // Minutes
      };
      rpoViolation: {
        enabled: boolean;
        thresholdMinutes: number;
      };
      rtoViolation: {
        enabled: boolean;
        thresholdMinutes: number;
      };
      storageCapacity: {
        enabled: boolean;
        thresholdPercent: number;
      };
    };
    notifications: {
      channels: Array<{
        type: 'email' | 'slack' | 'webhook' | 'sms';
        config: Record<string, any>;
        severity: ('info' | 'warning' | 'error' | 'critical')[];
      }>;
      templates: {
        backupSuccess: string;
        backupFailure: string;
        restoreTestResult: string;
        rpoRtoViolation: string;
        disasterRecovery: string;
      };
    };
    metrics: {
      retentionDays: number;
      exportFormat: 'prometheus' | 'json' | 'csv';
      aggregationInterval: number; // Minutes
    };
  };

  // Disaster recovery procedures
  disasterRecovery: {
    procedures: {
      dataCenterFailure: {
        enabled: boolean;
        rtoTarget: number; // Minutes
        rpoTarget: number; // Minutes
        automatedFailover: boolean;
        manualSteps: string[];
      };
      partialDataLoss: {
        enabled: boolean;
        rtoTarget: number; // Minutes
        rpoTarget: number; // Minutes
        pointInTimeRecovery: boolean;
      };
      corruption: {
        enabled: boolean;
        detectionMethods: string[];
        rtoTarget: number; // Minutes
        rpoTarget: number; // Minutes
      };
    };
    testing: {
      frequency: string;
      scenarios: Array<{
        name: string;
        description: string;
        steps: string[];
        successCriteria: string[];
      }>;
      documentationRequired: boolean;
      signOffRequired: boolean;
    };
    communication: {
      templates: {
        incidentDeclaration: string;
        progressUpdate: string;
        resolutionNotification: string;
        postMortem: string;
      };
      escalationMatrix: Array<{
        level: number;
        thresholdMinutes: number;
        contacts: Array<{
          name: string;
          role: string;
          contact: string;
        }>;
      }>;
    };
  };
}

/**
 * Backup Configuration Manager
 */
export class BackupConfigurationManager {
  private config: BackupConfiguration;
  private configPath: string;

  constructor(environment: Environment, configPath?: string) {
    this.configPath = configPath || join(process.cwd(), 'config', 'backup-config.json');
    this.config = this.createDefaultConfiguration(environment);
  }

  /**
   * Load configuration from file or create default
   */
  async load(): Promise<BackupConfiguration> {
    try {
      const configData = await readFile(this.configPath, 'utf-8');
      const loadedConfig = JSON.parse(configData) as BackupConfiguration;

      // Validate configuration
      this.validateConfiguration(loadedConfig);

      this.config = loadedConfig;
      logger.info({ environment: this.config.environment }, 'Backup configuration loaded');

      return this.config;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        logger.warn('Configuration file not found, creating default configuration');
        await this.save();
        return this.config;
      }

      logger.error({ error }, 'Failed to load backup configuration');
      throw error;
    }
  }

  /**
   * Save configuration to file
   */
  async save(): Promise<void> {
    try {
      // Validate before saving
      this.validateConfiguration(this.config);

      // Update timestamps
      this.config.updatedAt = new Date().toISOString();

      // Ensure directory exists
      await this.ensureConfigDirectory();

      // Save configuration
      const configData = JSON.stringify(this.config, null, 2);
      await writeFile(this.configPath, configData, 'utf-8');

      logger.info({
        environment: this.config.environment,
        path: this.configPath
      }, 'Backup configuration saved');

    } catch (error) {
      logger.error({ error }, 'Failed to save backup configuration');
      throw error;
    }
  }

  /**
   * Get current configuration
   */
  getConfiguration(): BackupConfiguration {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfiguration(updates: Partial<BackupConfiguration>): void {
    this.config = { ...this.config, ...updates };
    logger.info({ updatedFields: Object.keys(updates) }, 'Backup configuration updated');
  }

  /**
   * Update scheduling configuration
   */
  updateScheduling(updates: Partial<BackupConfiguration['schedule']>): void {
    this.config.schedule = { ...this.config.schedule, ...updates };
    logger.info({ updatedFields: Object.keys(updates) }, 'Backup scheduling updated');
  }

  /**
   * Update retention policies
   */
  updateRetention(updates: Partial<BackupConfiguration['retention']>): void {
    this.config.retention = { ...this.config.retention, ...updates };
    logger.info({ updatedFields: Object.keys(updates) }, 'Backup retention policies updated');
  }

  /**
   * Update RPO/RTO targets
   */
  updateTargets(updates: Partial<BackupConfiguration['targets']>): void {
    this.config.targets = { ...this.config.targets, ...updates };
    logger.info({ updatedFields: Object.keys(updates) }, 'Backup targets updated');
  }

  /**
   * Update storage configuration
   */
  updateStorage(updates: Partial<BackupConfiguration['storage']>): void {
    this.config.storage = { ...this.config.storage, ...updates };
    logger.info({ updatedFields: Object.keys(updates) }, 'Backup storage configuration updated');
  }

  /**
   * Validate configuration against requirements
   */
  validateConfiguration(config: BackupConfiguration): boolean {
    try {
      // Validate required fields
      if (!config.environment || !['development', 'staging', 'production'].includes(config.environment)) {
        throw new Error('Invalid environment specified');
      }

      if (!config.schedule) {
        throw new Error('Schedule configuration is required');
      }

      if (!config.retention) {
        throw new Error('Retention configuration is required');
      }

      if (!config.targets || config.targets.rpoMinutes <= 0 || config.targets.rtoMinutes <= 0) {
        throw new Error('Valid RPO/RTO targets are required');
      }

      if (!config.storage || !config.storage.primary) {
        throw new Error('Primary storage configuration is required');
      }

      // Validate RPO/RTO relationships
      if (config.targets.rpoMinutes > config.targets.maxDataLossMinutes) {
        throw new Error('RPO cannot exceed maximum acceptable data loss');
      }

      if (config.targets.rtoMinutes > config.targets.maxDowntimeMinutes) {
        throw new Error('RTO cannot exceed maximum acceptable downtime');
      }

      // Validate retention policies
      if (config.retention.fullBackups <= 0 || config.retention.incrementalBackups <= 0) {
        throw new Error('Retention policies must retain at least one backup');
      }

      if (config.retention.maxAgeDays < 1) {
        throw new Error('Maximum age must be at least 1 day');
      }

      // Validate performance settings
      if (config.performance.maxConcurrentBackups < 1) {
        throw new Error('Maximum concurrent backups must be at least 1');
      }

      logger.debug('Backup configuration validation passed');
      return true;

    } catch (error) {
      logger.error({ error }, 'Backup configuration validation failed');
      throw error;
    }
  }

  /**
   * Get configuration for specific environment
   */
  static getEnvironmentPreset(environment: Environment): Partial<BackupConfiguration> {
    const preset = BACKUP_PRESETS[environment];

    return {
      environment,
      version: '2.0.0',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),

      schedule: {
        fullBackup: preset.schedule.fullBackup,
        incrementalBackup: preset.schedule.incrementalBackup,
        restoreTest: preset.schedule.restoreTest,
        consistencyCheck: preset.schedule.consistencyCheck,
      },

      retention: {
        fullBackups: preset.retention.fullBackups,
        incrementalBackups: preset.retention.incrementalBackups,
        restoreTestResults: preset.retention.restoreTestResults,
        maxAgeDays: preset.retention.maxAgeDays,
        archivePolicy: {
          enabled: environment === 'production',
          afterDays: preset.retention.maxAgeDays,
          archiveStorage: {
            backend: 's3',
            config: {},
          },
        },
        compliance: {
          enabled: environment === 'production',
          regulatoryRequirements: environment === 'production' ? ['SOC2', 'GDPR', 'HIPAA'] : [],
          minRetentionDays: preset.retention.maxAgeDays,
          auditLogRetentionDays: environment === 'production' ? 365 : 90,
          legalHoldEnabled: environment === 'production',
        },
      },

      targets: {
        rpoMinutes: preset.targets.rpoMinutes,
        rtoMinutes: preset.targets.rtoMinutes,
        maxDataLossMinutes: preset.targets.maxDataLossMinutes,
        maxDowntimeMinutes: preset.targets.maxDowntimeMinutes,
        sla: {
          availabilityTarget: environment === 'production' ? 99.9 : 99.0,
          errorRateTarget: environment === 'production' ? 0.1 : 1.0,
          responseTimeTarget: environment === 'production' ? 1000 : 5000,
        },
        businessImpact: {
          criticalityLevel: environment === 'production' ? 'critical' : 'medium',
          businessFunction: 'Vector Database Backup',
          dependencies: ['Qdrant Cluster', 'Storage Backend', 'Network Infrastructure'],
          maxAcceptableOutageMinutes: preset.targets.maxDowntimeMinutes,
        },
      },

      storage: {
        primary: {
          backend: environment === 'production' ? 's3' : 'local',
          config: {
            path: environment !== 'production' ? './backups' : undefined,
            encryptionEnabled: true,
            compressionEnabled: true,
            compressionLevel: 6,
          },
        },
        monitoring: {
          spaceAlertThreshold: 80,
          performanceAlertThreshold: 10,
          healthCheckInterval: 5,
        },
      },

      performance: {
        maxConcurrentBackups: preset.performance.maxConcurrentBackups,
        bandwidthThrottleMBps: preset.performance.bandwidthThrottleMBps,
        priority: preset.performance.priority,
        resources: {
          maxMemoryMB: environment === 'production' ? 2048 : 512,
          maxCpuPercent: environment === 'production' ? 70 : 50,
        },
        optimization: {
          deduplicationEnabled: true,
          compressionEnabled: true,
          parallelProcessing: environment !== 'development',
          batchSizes: {
            fullBackup: 1000,
            incrementalBackup: 500,
            restore: 2000,
          },
        },
      },

      security: {
        encryption: {
          enabled: true,
          algorithm: 'AES-256-GCM',
          keyRotationDays: 90,
          keyManagement: environment === 'production' ? 'aws-kms' : 'local',
        },
        accessControl: {
          backupCreationRoles: ['backup-admin', 'database-admin'],
          backupRestoreRoles: ['backup-admin', 'disaster-recovery'],
          auditLogEnabled: true,
          requireApprovalForRestore: environment === 'production',
        },
        compliance: {
          dataClassification: environment === 'production' ? 'confidential' : 'internal',
          retentionPolicies: [
            {
              dataClass: 'confidential',
              retentionDays: preset.retention.maxAgeDays,
              archivalRequired: true,
            },
          ],
          auditRequirements: environment === 'production' ?
            ['access-logging', 'change-tracking', 'data-integrity'] :
            ['access-logging'],
        },
      },

      monitoring: {
        alerts: {
          backupFailure: {
            enabled: true,
            threshold: 2,
            escalationDelay: 30,
          },
          restoreTestFailure: {
            enabled: true,
            threshold: 1,
            escalationDelay: 60,
          },
          rpoViolation: {
            enabled: true,
            thresholdMinutes: preset.targets.rpoMinutes + 15,
          },
          rtoViolation: {
            enabled: true,
            thresholdMinutes: preset.targets.rtoMinutes + 5,
          },
          storageCapacity: {
            enabled: true,
            thresholdPercent: 85,
          },
        },
        notifications: {
          channels: [
            {
              type: 'email',
              config: {
                recipients: ['admin@example.com'],
              },
              severity: ['error', 'critical'],
            },
          ],
          templates: {
            backupSuccess: 'Backup completed successfully at {{timestamp}}',
            backupFailure: 'Backup failed: {{error}}',
            restoreTestResult: 'Restore test {{status}}: {{details}}',
            rpoRtoViolation: 'RPO/RTO violation detected: {{details}}',
            disasterRecovery: 'Disaster recovery {{status}}: {{details}}',
          },
        },
        metrics: {
          retentionDays: 30,
          exportFormat: 'prometheus',
          aggregationInterval: 5,
        },
      },

      disasterRecovery: {
        procedures: {
          dataCenterFailure: {
            enabled: true,
            rtoTarget: preset.targets.rtoMinutes,
            rpoTarget: preset.targets.rpoMinutes,
            automatedFailover: environment === 'production',
            manualSteps: [
              'Verify secondary data center status',
              'Initiate failover procedures',
              'Validate data integrity',
              'Update DNS records',
              'Notify stakeholders',
            ],
          },
          partialDataLoss: {
            enabled: true,
            rtoTarget: Math.min(preset.targets.rtoMinutes, 30),
            rpoTarget: Math.min(preset.targets.rpoMinutes, 60),
            pointInTimeRecovery: true,
          },
          corruption: {
            enabled: true,
            detectionMethods: ['checksum-validation', 'consistency-checks', 'integrity-verification'],
            rtoTarget: preset.targets.rtoMinutes * 2,
            rpoTarget: preset.targets.rpoMinutes * 2,
          },
        },
        testing: {
          frequency: environment === 'production' ? '0 2 1 * *' : '0 3 * * 0', // Monthly or weekly
          scenarios: [
            {
              name: 'Complete System Recovery',
              description: 'Full system restoration from latest backup',
              steps: [
                'Select appropriate backup',
                'Initialize recovery environment',
                'Execute restore procedure',
                'Validate data integrity',
                'Perform functional testing',
              ],
              successCriteria: [
                'All data restored successfully',
                'No data corruption detected',
                'System functions normally',
                'RTO targets met',
              ],
            },
          ],
          documentationRequired: true,
          signOffRequired: environment === 'production',
        },
        communication: {
          templates: {
            incidentDeclaration: 'INCIDENT: {{incident_type}} detected at {{timestamp}}',
            progressUpdate: 'UPDATE: Recovery progress - {{status}}',
            resolutionNotification: 'RESOLVED: {{incident_type}} resolved at {{timestamp}}',
            postMortem: 'POST-MORTEM: {{incident_type}} - {{summary}}',
          },
          escalationMatrix: [
            {
              level: 1,
              thresholdMinutes: 15,
              contacts: [
                { name: 'On-call Engineer', role: 'primary', contact: 'oncall@example.com' },
              ],
            },
            {
              level: 2,
              thresholdMinutes: 30,
              contacts: [
                { name: 'Team Lead', role: 'escalation', contact: 'lead@example.com' },
              ],
            },
            {
              level: 3,
              thresholdMinutes: 60,
              contacts: [
                { name: 'Engineering Manager', role: 'management', contact: 'manager@example.com' },
              ],
            },
          ],
        },
      },
    };
  }

  /**
   * Create default configuration for environment
   */
  private createDefaultConfiguration(environment: Environment): BackupConfiguration {
    return BackupConfigurationManager.getEnvironmentPreset(environment) as BackupConfiguration;
  }

  /**
   * Ensure configuration directory exists
   */
  private async ensureConfigDirectory(): Promise<void> {
    // Implementation would ensure directory exists
  }
}

/**
 * Backup metadata interface
 */
export interface BackupMetadata {
  id: string;
  timestamp: Date;
  type: 'full' | 'incremental';
  size: number;
  checksum: string;
  location: string;
  status: 'created' | 'uploading' | 'completed' | 'failed';
  collections: string[];
  priority: BackupPriority;
  encryptionEnabled: boolean;
  compressionEnabled: boolean;
  retentionDays: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

/**
 * Consistency validation result interface
 */
export interface ConsistencyValidationResult {
  backupId: string;
  timestamp: Date;
  status: 'passed' | 'failed' | 'warning';
  checks: {
    checksum: boolean;
    integrity: boolean;
    completeness: boolean;
    consistency: boolean;
  };
  errors?: string[];
  warnings?: string[];
  metrics: {
    totalRecords: number;
    verifiedRecords: number;
    corruptedRecords: number;
    missingRecords: number;
  };
  duration: number;
}

/**
 * Restore test result interface
 */
export interface RestoreTestResult {
  id: string;
  backupId: string;
  timestamp: Date;
  status: 'passed' | 'failed' | 'in_progress';
  duration: number;
  recordsRestored: number;
  recordsExpected: number;
  successRate: number;
  errors?: string[];
  warnings?: string[];
  performance: {
    restoreSpeed: number; // records per second
    totalDuration: number;
    averageLatency: number;
  };
}

/**
 * Disaster recovery status interface
 */
export interface DisasterRecoveryStatus {
  id: string;
  timestamp: Date;
  status: 'active' | 'completed' | 'failed' | 'cancelled';
  type: 'failover' | 'restore' | 'recovery';
  initiatedBy: string;
  affectedSystems: string[];
  rpoMet: boolean;
  rtoMet: boolean;
  dataLoss: boolean;
  estimatedRecoveryTime?: number;
  actualRecoveryTime?: number;
  steps: Array<{
    name: string;
    status: 'pending' | 'in_progress' | 'completed' | 'failed';
    startTime?: Date;
    endTime?: Date;
    duration?: number;
    error?: string;
  }>;
  communication: {
    stakeholderNotified: boolean;
    incidentCreated: boolean;
    escalationLevel: number;
  };
}

/**
 * Comprehensive restore test result interface
 */
export interface ComprehensiveRestoreTestResult {
  id: string;
  backupId: string;
  timestamp: Date;
  status: 'passed' | 'failed' | 'in_progress';
  duration: number;
  performanceMetrics: {
    restoreSpeed: number;
    totalDuration: number;
    averageLatency: number;
  };
  success: boolean;
  errors?: string[];
  warnings?: string[];
  recordsRestored: number;
  recordsExpected: number;
  successRate: number;
}
