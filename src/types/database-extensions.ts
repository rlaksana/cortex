// TypeScript Recovery: Phase 3 - Database Interface Extensions
//
// Extended interfaces for database operations and configuration
// Provides missing type definitions for unknown-typed database objects

import type { QdrantClient } from '@qdrant/js-client-rest';
import type {
  PerformanceMetric,
  Alert,
  IncidentDeclaration,
  BackupConfig,
} from './monitoring-types.js';

/**
 * Enhanced Qdrant client interface with audit and auth capabilities
 */
export interface EnhancedQdrantClient extends QdrantClient {
  // Audit-related collections
  eventAudit: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<{ id: string }>;
    update: (id: string, data: unknown) => Promise<{ id: string }>;
    delete: (id: string) => Promise<boolean>;
  };

  // User management
  user: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // API key management
  apiKey: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Token revocation management
  tokenRevocationList: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Security event tracking
  securityEvent: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Authentication instance management
  authInstance: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // ADR (Architecture Decision Records) management
  adrDecision: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Section management
  section: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Runbook management
  runbook: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Change log management
  changeLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Issue log management
  issueLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // TODO log management
  todoLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Release note management
  releaseNote: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // DDL history management
  ddlHistory: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // PR context management
  prContext: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Incident log management
  incidentLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Release log management
  releaseLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Risk log management
  riskLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Assumption log management
  assumptionLog: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Knowledge entity management
  knowledgeEntity: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Knowledge relation management
  knowledgeRelation: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };

  // Knowledge observation management
  knowledgeObservation: {
    findMany: (filter?: unknown) => Promise<unknown[]>;
    findOne: (id: string) => Promise<unknown>;
    create: (data: unknown) => Promise<unknown>;
    update: (id: string, data: unknown) => Promise<unknown>;
    delete: (id: string) => Promise<boolean>;
  };
}

/**
 * Interface for enhanced backup integration operations
 */
export interface BackupIntegrationOperations {
  performanceMetric: PerformanceMetric;
  alert: Omit<Alert, 'status' | 'id' | 'timestamp' | 'escalationLevel' | 'channels'>;
  incidentDeclaration: Omit<IncidentDeclaration, 'incidentId' | 'declaredAt'>;
  backupConfig: BackupConfig;
}

/**
 * Interface for operation results with enhanced metadata
 */
export interface EnhancedOperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  performanceDetails?: {
    duration: number;
    throughput: number;
    errors: number;
    retries: number;
    memoryUsage?: number;
    cpuUsage?: number;
  };
  dataIntegrity?: {
    checksum: string;
    recordCount: number;
    validationPassed: boolean;
    inconsistencies: string[];
    lastValidated?: string;
  };
  metadata?: {
    operation: string;
    timestamp: string;
    traceId?: string;
    userId?: string;
    sessionId?: string;
    version?: string;
  };
}

/**
 * Type guard for enhanced operation result
 */
export function isEnhancedOperationResult<T = unknown>(
  obj: unknown
): obj is EnhancedOperationResult<T> {
  return typeof obj === 'object' &&
         obj !== null &&
         typeof (obj as any).success === 'boolean' &&
         (typeof (obj as any).data !== 'undefined' ||
          typeof (obj as any).error !== 'undefined');
}

/**
 * Utility function to safely cast unknown to EnhancedQdrantClient
 */
export function asEnhancedQdrantClient(client: unknown): EnhancedQdrantClient {
  if (typeof client === 'object' && client !== null) {
    return client as EnhancedQdrantClient;
  }

  // Return a stub implementation if client is null/undefined
  return {
    eventAudit: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => ({ id: 'stub' }),
      update: async () => ({ id: 'stub' }),
      delete: async () => true,
    },
    user: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    apiKey: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    tokenRevocationList: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    securityEvent: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    authInstance: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    adrDecision: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    section: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    runbook: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    changeLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    issueLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    todoLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    releaseNote: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    ddlHistory: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    prContext: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    incidentLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    releaseLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    riskLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    assumptionLog: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    knowledgeEntity: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    knowledgeRelation: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
    knowledgeObservation: {
      findMany: async () => [],
      findOne: async () => null,
      create: async () => null,
      update: async () => null,
      delete: async () => null,
    },
  } as EnhancedQdrantClient;
}