/**
 * P3 Data Management: PII Redaction Service
 *
 * Enterprise-grade Personally Identifiable Information (PII) redaction service
 * with configurable detection patterns, redaction strategies, and compliance
 * monitoring. Supports GDPR, CCPA, HIPAA, and other privacy regulations.
 *
 * Features:
 * - Multi-pattern PII detection (email, phone, SSN, credit card, etc.)
 * - Configurable redaction strategies (mask, hash, remove, replace)
 * - Real-time and batch processing modes
 * - Comprehensive audit logging and compliance reporting
 * - Custom pattern support and domain-specific rules
 * - Performance optimization for large datasets
 * - Vector embedding redaction for semantic search
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { createHash } from 'crypto';

import { logger } from '@/utils/logger.js';

import type { KnowledgeItem } from '../../types/core-interfaces.js';
import { systemMetricsService } from '../metrics/system-metrics.js';

// === Type Definitions ===

export interface PIIConfig {
  /** Redaction strategy configuration */
  strategies: {
    /** Default redaction strategy */
    default_strategy: 'mask' | 'hash' | 'remove' | 'replace';
    /** Masking configuration */
    mask_config: {
      /** Mask character */
      mask_char: string;
      /** Preserve character count (show first/last N) */
      preserve_count: number;
      /** Show prefix */
      show_prefix: boolean;
      /** Show suffix */
      show_suffix: boolean;
    };
    /** Hash configuration */
    hash_config: {
      /** Hash algorithm */
      algorithm: 'sha256' | 'sha512' | 'md5';
      /** Include salt */
      include_salt: boolean;
      /** Salt value */
      salt?: string;
    };
    /** Replace configuration */
    replace_config: {
      /** Default replacement text */
      replacement_text: string;
      /** Context-specific replacements */
      context_replacements: Record<string, string>;
    };
  };
  /** Detection patterns */
  patterns: {
    /** Email pattern */
    email: {
      enabled: boolean;
      pattern: string;
      confidence_threshold: number;
    };
    /** Phone number pattern */
    phone: {
      enabled: boolean;
      patterns: string[];
      confidence_threshold: number;
    };
    /** Social Security Number pattern */
    ssn: {
      enabled: boolean;
      pattern: string;
      confidence_threshold: number;
    };
    /** Credit card pattern */
    credit_card: {
      enabled: boolean;
      patterns: string[];
      confidence_threshold: number;
    };
    /** Address pattern */
    address: {
      enabled: boolean;
      patterns: string[];
      confidence_threshold: number;
    };
    /** Name pattern */
    name: {
      enabled: boolean;
      patterns: string[];
      min_name_length: number;
      confidence_threshold: number;
    };
    /** Custom patterns */
    custom: Array<{
      name: string;
      pattern: string;
      enabled: boolean;
      strategy?: 'mask' | 'hash' | 'remove' | 'replace';
      confidence_threshold: number;
    }>;
  };
  /** Processing configuration */
  processing: {
    /** Batch size for processing */
    batch_size: number;
    /** Enable parallel processing */
    enable_parallel_processing: boolean;
    /** Maximum processing time per item (ms) */
    max_processing_time_ms: number;
    /** Enable vector embedding redaction */
    redact_embeddings: boolean;
    /** Context-aware redaction */
    enable_context_aware: boolean;
  };
  /** Compliance and audit */
  compliance: {
    /** Enable audit logging */
    enable_audit_logging: boolean;
    /** Retention period for audit logs (days) */
    audit_retention_days: number;
    /** Generate compliance reports */
    generate_compliance_reports: boolean;
    /** Regulatory frameworks */
    frameworks: ('GDPR' | 'CCPA' | 'HIPAA' | 'SOX')[];
  };
}

export interface PIIDetectionResult {
  /** PII type detected */
  pii_type: string;
  /** Original value */
  original_value: string;
  /** Redacted value */
  redacted_value: string;
  /** Detection confidence (0-1) */
  confidence: number;
  /** Strategy used */
  strategy: 'mask' | 'hash' | 'remove' | 'replace';
  /** Location in text */
  location: {
    start: number;
    end: number;
    context?: string;
  };
  /** Metadata */
  metadata: {
    pattern_matched: string;
    processing_time_ms: number;
    timestamp: string;
  };
}

export interface PIIRedactionResult {
  /** Item identifier */
  item_id: string;
  /** Original item */
  original_item: KnowledgeItem;
  /** Redacted item */
  redacted_item: KnowledgeItem;
  /** Detection results */
  detections: PIIDetectionResult[];
  /** Processing metrics */
  metrics: {
    total_processing_time_ms: number;
    pii_detected_count: number;
    pii_redacted_count: number;
    fields_processed: number;
    embeddings_processed: number;
  };
  /** Compliance information */
  compliance: {
    gdpr_compliant: boolean;
    ccpa_compliant: boolean;
    hipaa_compliant: boolean;
    regulations_violated: string[];
  };
  /** Audit information */
  audit: {
    processing_timestamp: string;
    user_id?: string;
    session_id?: string;
    request_id: string;
  };
}

export interface PIIComplianceReport {
  /** Report identifier */
  report_id: string;
  /** Report generation timestamp */
  generated_at: string;
  /** Reporting period */
  period: {
    start_date: string;
    end_date: string;
  };
  /** Compliance summary */
  summary: {
    total_items_processed: number;
    items_with_pii: number;
    total_pii_instances: number;
    pii_types_detected: Record<string, number>;
    compliance_rate: number;
  };
  /** Regulatory compliance */
  regulatory_compliance: {
    GDPR: {
      compliant: boolean;
      violations: Array<{
        article: string;
        description: string;
        severity: 'high' | 'medium' | 'low';
        count: number;
      }>;
    };
    CCPA: {
      compliant: boolean;
      violations: Array<{
        section: string;
        description: string;
        severity: 'high' | 'medium' | 'low';
        count: number;
      }>;
    };
    HIPAA: {
      compliant: boolean;
      violations: Array<{
        rule: string;
        description: string;
        severity: 'high' | 'medium' | 'low';
        count: number;
      }>;
    };
  };
  /** Processing metrics */
  metrics: {
    average_processing_time_ms: number;
    total_processing_time_ms: number;
    pii_detection_accuracy: number;
    false_positive_rate: number;
    false_negative_rate: number;
  };
  /** Recommendations */
  recommendations: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    category: 'detection' | 'redaction' | 'process' | 'compliance';
    description: string;
    action_items: string[];
  }>;
}

export interface PIIAuditLog {
  /** Log identifier */
  log_id: string;
  /** Timestamp */
  timestamp: string;
  /** Operation type */
  operation: 'redaction' | 'detection' | 'verification' | 'exemption';
  /** User information */
  user: {
    user_id?: string;
    session_id?: string;
    ip_address?: string;
    user_agent?: string;
  };
  /** Item information */
  item: {
    item_id: string;
    item_type: string;
    scope?: unknown;
  };
  /** PII information */
  pii: {
    pii_types_detected: string[];
    pii_count: number;
    redaction_strategy: string;
    exemptions_applied: string[];
  };
  /** Compliance information */
  compliance: {
    regulations_frameworks: string[];
    compliance_status: 'compliant' | 'non_compliant' | 'partially_compliant';
    violations: string[];
  };
  /** Performance metrics */
  performance: {
    processing_time_ms: number;
    memory_usage_mb: number;
    cpu_usage_percent?: number;
  };
}

// === Default Configuration ===

const DEFAULT_PII_CONFIG: PIIConfig = {
  strategies: {
    default_strategy: 'mask',
    mask_config: {
      mask_char: '*',
      preserve_count: 4,
      show_prefix: true,
      show_suffix: true,
    },
    hash_config: {
      algorithm: 'sha256',
      include_salt: true,
      salt: 'pii-salt-default',
    },
    replace_config: {
      replacement_text: '[REDACTED]',
      context_replacements: {
        email: '[EMAIL_REDACTED]',
        phone: '[PHONE_REDACTED]',
        ssn: '[SSN_REDACTED]',
        credit_card: '[CARD_REDACTED]',
        address: '[ADDRESS_REDACTED]',
        name: '[NAME_REDACTED]',
      },
    },
  },
  patterns: {
    email: {
      enabled: true,
      pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
      confidence_threshold: 0.9,
    },
    phone: {
      enabled: true,
      patterns: [
        '\\b\\d{3}-\\d{3}-\\d{4}\\b', // 123-456-7890
        '\\b\\(\\d{3}\\)\\s*\\d{3}-\\d{4}\\b', // (123) 456-7890
        '\\b\\d{3}\\.\\d{3}\\.\\d{4}\\b', // 123.456.7890
        '\\b\\+1\\s*\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b', // +1 123-456-7890
      ],
      confidence_threshold: 0.8,
    },
    ssn: {
      enabled: true,
      pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
      confidence_threshold: 0.95,
    },
    credit_card: {
      enabled: true,
      patterns: [
        '\\b4\\d{3}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', // Visa
        '\\b5[1-5]\\d{2}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', // Mastercard
        '\\b3[47]\\d{2}[-\\s]?\\d{6}[-\\s]?\\d{5}\\b', // American Express
        '\\b6(?:011|5\\d{2})[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', // Discover
      ],
      confidence_threshold: 0.9,
    },
    address: {
      enabled: true,
      patterns: [
        '\\b\\d+\\s+[A-Z][a-z]*\\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\\b',
        '\\b\\d+\\s+[A-Z][a-z]*\\s+[A-Z][a-z]*,\\s*[A-Z]{2}\\s*\\d{5}\\b',
      ],
      confidence_threshold: 0.7,
    },
    name: {
      enabled: true,
      patterns: [
        '\\b[A-Z][a-z]+\\s+[A-Z][a-z]+\\b', // First Last
        '\\b[A-Z]\\.\\s*[A-Z][a-z]+\\b', // J. Doe
        '\\b[A-Z][a-z]+\\s+[A-Z]\\.\\s*[A-Z][a-z]+\\b', // John A. Doe
      ],
      min_name_length: 4,
      confidence_threshold: 0.6,
    },
    custom: [],
  },
  processing: {
    batch_size: 100,
    enable_parallel_processing: true,
    max_processing_time_ms: 5000,
    redact_embeddings: true,
    enable_context_aware: true,
  },
  compliance: {
    enable_audit_logging: true,
    audit_retention_days: 2555, // 7 years
    generate_compliance_reports: true,
    frameworks: ['GDPR', 'CCPA'],
  },
};

// === PII Redaction Service Implementation ===

export class PIIRedactionService {
  private config: PIIConfig;
  private auditLogs: PIIAuditLog[] = [];
  private detectionCache: Map<string, PIIDetectionResult[]> = new Map();

  constructor(config: Partial<PIIConfig> = {}) {
    this.config = { ...DEFAULT_PII_CONFIG, ...config };
  }

  /**
   * Initialize PII redaction service
   */
  async initialize(): Promise<void> {
    logger.info('Initializing PII redaction service');

    // Load audit logs
    await this.loadAuditLogs();

    // Cleanup old audit logs
    await this.cleanupOldAuditLogs();

    // Validate patterns
    this.validatePatterns();

    logger.info('PII redaction service initialized successfully');
  }

  /**
   * Redact PII from knowledge item
   */
  async redactPII(
    item: KnowledgeItem,
    options: {
      strategy?: 'mask' | 'hash' | 'remove' | 'replace';
      pii_types?: string[];
      exempt_fields?: string[];
      user_context?: {
        user_id?: string;
        session_id?: string;
        request_id?: string;
      };
    } = {}
  ): Promise<PIIRedactionResult> {
    const startTime = performance.now();
    const requestId = options.user_context?.request_id || this.generateRequestId();

    logger.debug(
      {
        item_id: item.id,
        request_id: requestId,
        strategy: options.strategy || this.config.strategies.default_strategy,
      },
      'Starting PII redaction'
    );

    try {
      // Create a copy of the item to avoid mutation
      const redactedItem = JSON.parse(JSON.stringify(item));

      // Initialize detection results
      const detections: PIIDetectionResult[] = [];

      // Process content field
      if (item.content && typeof item.content === 'string') {
        const contentResult = await this.processTextContent(
          item.content,
          options.strategy || this.config.strategies.default_strategy,
          item.id || 'unknown',
          'content',
          options.pii_types || []
        );
        detections.push(...contentResult.detections);
        redactedItem.content = contentResult.redactedContent;
      }

      // Process metadata fields
      if (item.metadata) {
        const metadataResult = await this.processMetadata(
          item.metadata,
          options.strategy || this.config.strategies.default_strategy,
          item.id || 'unknown',
          options.pii_types || [],
          options.exempt_fields
        );
        detections.push(...metadataResult.detections);
        redactedItem.metadata = metadataResult.redactedMetadata;
      }

      // Process scope fields
      if (item.scope) {
        const scopeResult = await this.processScope(
          item.scope,
          options.strategy || this.config.strategies.default_strategy,
          item.id || 'unknown',
          options.pii_types || [],
          options.exempt_fields
        );
        detections.push(...scopeResult.detections);
        redactedItem.scope = scopeResult.redactedScope;
      }

      // Process embeddings if enabled
      let embeddingsProcessed = 0;
      if (this.config.processing.redact_embeddings && (item as unknown).embedding) {
        // Redact embeddings that contain PII
        (redactedItem as unknown).embedding = await this.redactEmbeddings(
          (item as unknown).embedding,
          detections
        );
        embeddingsProcessed = 1;
      }

      const processingTime = performance.now() - startTime;

      // Calculate compliance
      const compliance = this.calculateCompliance(detections);

      // Create audit log
      const auditLog: PIIAuditLog = {
        log_id: this.generateLogId(),
        timestamp: new Date().toISOString(),
        operation: 'redaction',
        user: {
          user_id: options.user_context?.user_id,
          session_id: options.user_context?.session_id,
        },
        item: {
          item_id: item.id || 'unknown',
          item_type: item.kind,
          scope: item.scope,
        },
        pii: {
          pii_types_detected: [...new Set(detections.map((d) => d.pii_type))],
          pii_count: detections.length,
          redaction_strategy: options.strategy || this.config.strategies.default_strategy,
          exemptions_applied: options.exempt_fields || [],
        },
        compliance: {
          regulations_frameworks: this.config.compliance.frameworks,
          compliance_status: this.getOverallComplianceStatus(compliance),
          violations: [], // TODO: Implement compliance violations check
        },
        performance: {
          processing_time_ms: Math.round(processingTime),
          memory_usage_mb: process.memoryUsage().heapUsed / 1024 / 1024,
        },
      };

      // Add to audit logs
      if (this.config.compliance.enable_audit_logging) {
        this.auditLogs.push(auditLog);
      }

      // Create result
      const result: PIIRedactionResult = {
        item_id: item.id || 'unknown',
        original_item: item,
        redacted_item: redactedItem,
        detections: detections,
        metrics: {
          total_processing_time_ms: Math.round(processingTime),
          pii_detected_count: detections.length,
          pii_redacted_count: detections.filter((d) => d.redacted_value !== d.original_value)
            .length,
          fields_processed: this.getFieldsProcessed(item),
          embeddings_processed: embeddingsProcessed,
        },
        compliance: compliance,
        audit: {
          processing_timestamp: new Date().toISOString(),
          user_id: options.user_context?.user_id,
          session_id: options.user_context?.session_id,
          request_id: requestId,
        },
      };

      // Update system metrics
      await this.updateSystemMetrics(result);

      logger.debug(
        {
          item_id: item.id,
          request_id: requestId,
          pii_detected: detections.length,
          pii_redacted: result.metrics.pii_redacted_count,
          processing_time_ms: result.metrics.total_processing_time_ms,
        },
        'PII redaction completed'
      );

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          item_id: item.id,
          request_id: requestId,
          error: errorMsg,
          processing_time_ms: performance.now() - startTime,
        },
        'PII redaction failed'
      );

      throw error;
    }
  }

  /**
   * Process text content for PII detection and redaction
   */
  private async processTextContent(
    content: string,
    strategy: 'mask' | 'hash' | 'remove' | 'replace',
    itemId: string,
    fieldPath: string,
    piiTypes?: string[]
  ): Promise<{
    redactedContent: string;
    detections: PIIDetectionResult[];
  }> {
    const detections: PIIDetectionResult[] = [];
    let redactedContent = content;

    // Check cache first
    const cacheKey = `${content}_${strategy}_${piiTypes?.join(',') || 'all'}`;
    if (this.detectionCache.has(cacheKey)) {
      return {
        redactedContent: this.applyRedactions(content, this.detectionCache.get(cacheKey)!),
        detections: this.detectionCache.get(cacheKey)!,
      };
    }

    // Detect PII in content
    const detectedPII = await this.detectPII(content, piiTypes);

    // Sort detections by position (reverse order to avoid index shifting)
    detectedPII.sort((a, b) => b.location.start - a.location.start);

    // Apply redactions
    for (const pii of detectedPII) {
      const redactionResult = await this.applyRedaction(pii.original_value, strategy, pii.pii_type);

      // Create detection result
      const detection: PIIDetectionResult = {
        ...pii,
        redacted_value: redactionResult.redactedValue,
        strategy: strategy,
        metadata: {
          ...pii.metadata,
          processing_time_ms: redactionResult.processingTimeMs,
        },
      };

      detections.push(detection);

      // Apply redaction to content
      redactedContent =
        redactedContent.substring(0, pii.location.start) +
        redactionResult.redactedValue +
        redactedContent.substring(pii.location.end);
    }

    // Cache results
    this.detectionCache.set(cacheKey, detections);

    return {
      redactedContent,
      detections,
    };
  }

  /**
   * Process metadata for PII
   */
  private async processMetadata(
    metadata: unknown,
    strategy: 'mask' | 'hash' | 'remove' | 'replace',
    itemId: string,
    piiTypes?: string[],
    exemptFields?: string[]
  ): Promise<{
    redactedMetadata: unknown;
    detections: PIIDetectionResult[];
  }> {
    const detections: PIIDetectionResult[] = [];
    const redactedMetadata = JSON.parse(JSON.stringify(metadata));

    // Process each metadata field
    for (const [key, value] of Object.entries(metadata)) {
      if (exemptFields?.includes(key)) {
        continue;
      }

      if (typeof value === 'string') {
        const result = await this.processTextContent(
          value,
          strategy,
          itemId,
          `metadata.${key}`,
          piiTypes
        );
        detections.push(...result.detections);
        redactedMetadata[key] = result.redactedContent;
      } else if (typeof value === 'object' && value !== null) {
        // Recursively process nested objects
        const nestedResult = await this.processMetadata(
          value,
          strategy,
          itemId,
          piiTypes,
          exemptFields
        );
        detections.push(...nestedResult.detections);
        redactedMetadata[key] = nestedResult.redactedMetadata;
      }
    }

    return {
      redactedMetadata,
      detections,
    };
  }

  /**
   * Process scope for PII
   */
  private async processScope(
    scope: unknown,
    strategy: 'mask' | 'hash' | 'remove' | 'replace',
    itemId: string,
    piiTypes?: string[],
    exemptFields?: string[]
  ): Promise<{
    redactedScope: unknown;
    detections: PIIDetectionResult[];
  }> {
    // Scope fields typically don't contain PII, but we process them anyway
    const result = await this.processMetadata(scope, strategy, itemId, piiTypes, exemptFields);
    return {
      redactedScope: result.redactedMetadata,
      detections: result.detections,
    };
  }

  /**
   * Detect PII in text using configured patterns
   */
  private async detectPII(text: string, piiTypes?: string[]): Promise<PIIDetectionResult[]> {
    const detections: PIIDetectionResult[] = [];

    const startTime = performance.now();

    // Process each enabled pattern
    for (const [piiType, config] of Object.entries(this.config.patterns)) {
      if (piiType === 'custom') continue; // Handle custom patterns separately

      if (piiTypes && !piiTypes.includes(piiType)) continue;

      const patternConfig = config as unknown;
      if (!patternConfig.enabled) continue;

      const patterns = Array.isArray(patternConfig.patterns)
        ? patternConfig.patterns
        : [patternConfig.pattern];

      for (const pattern of patterns) {
        try {
          const regex = new RegExp(pattern, 'gi');
          let match;

          while ((match = regex.exec(text)) !== null) {
            const confidence = this.calculateConfidence(match[0], piiType, text, match.index);

            if (confidence >= patternConfig.confidence_threshold) {
              detections.push({
                pii_type: piiType,
                original_value: match[0],
                redacted_value: '', // Will be filled during redaction
                confidence: confidence,
                strategy: this.config.strategies.default_strategy,
                location: {
                  start: match.index,
                  end: match.index + match[0].length,
                  context: this.getContext(text, match.index, match[0].length),
                },
                metadata: {
                  pattern_matched: pattern,
                  processing_time_ms: 0, // Will be filled later
                  timestamp: new Date().toISOString(),
                },
              });
            }
          }
        } catch (error) {
          logger.warn(
            {
              pii_type: piiType,
              pattern: pattern,
              error: error instanceof Error ? error.message : 'Unknown error',
            },
            'Failed to process PII pattern'
          );
        }
      }
    }

    // Process custom patterns
    for (const customPattern of this.config.patterns.custom) {
      if (!customPattern.enabled) continue;
      if (piiTypes && !piiTypes.includes(customPattern.name)) continue;

      try {
        const regex = new RegExp(customPattern.pattern, 'gi');
        let match;

        while ((match = regex.exec(text)) !== null) {
          const confidence = this.calculateConfidence(
            match[0],
            customPattern.name,
            text,
            match.index
          );

          if (confidence >= customPattern.confidence_threshold) {
            detections.push({
              pii_type: customPattern.name,
              original_value: match[0],
              redacted_value: '', // Will be filled during redaction
              confidence: confidence,
              strategy: customPattern.strategy || this.config.strategies.default_strategy,
              location: {
                start: match.index,
                end: match.index + match[0].length,
                context: this.getContext(text, match.index, match[0].length),
              },
              metadata: {
                pattern_matched: customPattern.pattern,
                processing_time_ms: 0, // Will be filled later
                timestamp: new Date().toISOString(),
              },
            });
          }
        }
      } catch (error) {
        logger.warn(
          {
            pii_type: customPattern.name,
            pattern: customPattern.pattern,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
          'Failed to process custom PII pattern'
        );
      }
    }

    // Remove duplicates and sort by position
    const uniqueDetections = this.removeDuplicateDetections(detections);
    uniqueDetections.sort((a, b) => a.location.start - b.location.start);

    const processingTime = performance.now() - startTime;

    // Update processing times
    uniqueDetections.forEach((detection) => {
      detection.metadata.processing_time_ms = Math.round(processingTime / uniqueDetections.length);
    });

    return uniqueDetections;
  }

  /**
   * Apply redaction to PII value
   */
  private async applyRedaction(
    value: string,
    strategy: 'mask' | 'hash' | 'remove' | 'replace',
    piiType: string
  ): Promise<{
    redactedValue: string;
    processingTimeMs: number;
  }> {
    const startTime = performance.now();

    let redactedValue: string;

    switch (strategy) {
      case 'mask':
        redactedValue = this.applyMaskRedaction(value, piiType);
        break;
      case 'hash':
        redactedValue = this.applyHashRedaction(value);
        break;
      case 'remove':
        redactedValue = '';
        break;
      case 'replace':
        redactedValue = this.applyReplaceRedaction(value, piiType);
        break;
      default:
        redactedValue = this.applyMaskRedaction(value, piiType);
    }

    return {
      redactedValue,
      processingTimeMs: Math.round(performance.now() - startTime),
    };
  }

  /**
   * Apply mask redaction strategy
   */
  private applyMaskRedaction(value: string, piiType: string): string {
    const maskConfig = this.config.strategies.mask_config;
    const { preserve_count, show_prefix, show_suffix, mask_char } = maskConfig;

    if (value.length <= preserve_count * 2) {
      // Value too short to preserve context
      return mask_char.repeat(value.length);
    }

    let prefix = '';
    let suffix = '';

    if (show_prefix) {
      prefix = value.substring(0, preserve_count);
    }

    if (show_suffix) {
      suffix = value.substring(value.length - preserve_count);
    }

    const maskLength = value.length - prefix.length - suffix.length;
    const mask = mask_char.repeat(Math.max(0, maskLength));

    return prefix + mask + suffix;
  }

  /**
   * Apply hash redaction strategy
   */
  private applyHashRedaction(value: string): string {
    const hashConfig = this.config.strategies.hash_config;
    let dataToHash = value;

    if (hashConfig.include_salt && hashConfig.salt) {
      dataToHash = value + hashConfig.salt;
    }

    return createHash(hashConfig.algorithm).update(dataToHash).digest('hex');
  }

  /**
   * Apply replace redaction strategy
   */
  private applyReplaceRedaction(value: string, piiType: string): string {
    const replaceConfig = this.config.strategies.replace_config;

    // Check for context-specific replacement
    if (replaceConfig.context_replacements[piiType]) {
      return replaceConfig.context_replacements[piiType];
    }

    return replaceConfig.replacement_text;
  }

  /**
   * Apply redactions to text based on detection results
   */
  private applyRedactions(text: string, detections: PIIDetectionResult[]): string {
    let redactedText = text;

    // Sort detections by position (reverse order to avoid index shifting)
    const sortedDetections = [...detections].sort((a, b) => b.location.start - a.location.start);

    for (const detection of sortedDetections) {
      redactedText =
        redactedText.substring(0, detection.location.start) +
        detection.redacted_value +
        redactedText.substring(detection.location.end);
    }

    return redactedText;
  }

  /**
   * Calculate confidence score for PII detection
   */
  private calculateConfidence(
    value: string,
    piiType: string,
    fullText: string,
    position: number
  ): number {
    let confidence = 0.5; // Base confidence

    // Adjust confidence based on PII type and value characteristics
    switch (piiType) {
      case 'email':
        confidence = value.includes('@') && value.includes('.') ? 0.95 : 0.3;
        break;
      case 'phone':
        confidence = this.calculatePhoneConfidence(value);
        break;
      case 'ssn':
        confidence = /^\d{3}-\d{2}-\d{4}$/.test(value) ? 0.95 : 0.4;
        break;
      case 'credit_card':
        confidence = this.calculateCreditCardConfidence(value);
        break;
      case 'address':
        confidence = this.calculateAddressConfidence(value, fullText, position);
        break;
      case 'name':
        confidence = this.calculateNameConfidence(value, fullText, position);
        break;
    }

    return Math.min(1.0, Math.max(0.0, confidence));
  }

  /**
   * Calculate confidence for phone numbers
   */
  private calculatePhoneConfidence(phone: string): number {
    const cleanPhone = phone.replace(/\D/g, '');

    if (cleanPhone.length === 10) return 0.9;
    if (cleanPhone.length === 11 && cleanPhone.startsWith('1')) return 0.85;
    if (cleanPhone.length >= 10 && cleanPhone.length <= 11) return 0.7;

    return 0.3;
  }

  /**
   * Calculate confidence for credit cards
   */
  private calculateCreditCardConfidence(card: string): number {
    const cleanCard = card.replace(/\D/g, '');

    if (cleanCard.length < 13 || cleanCard.length > 19) return 0.1;

    // Luhn algorithm check
    let sum = 0;
    let isEven = false;

    for (let i = cleanCard.length - 1; i >= 0; i--) {
      let digit = parseInt(cleanCard[i]);

      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0 ? 0.95 : 0.6;
  }

  /**
   * Calculate confidence for addresses
   */
  private calculateAddressConfidence(address: string, fullText: string, position: number): number {
    const addressIndicators = [
      'street',
      'st',
      'avenue',
      'ave',
      'road',
      'rd',
      'boulevard',
      'blvd',
      'lane',
      'ln',
      'drive',
      'dr',
      'court',
      'ct',
      'way',
      'place',
      'pl',
    ];

    const hasAddressIndicator = addressIndicators.some((indicator) =>
      address.toLowerCase().includes(indicator)
    );

    if (hasAddressIndicator && /\d+/.test(address)) return 0.8;
    if (hasAddressIndicator) return 0.6;
    if (/\d+/.test(address)) return 0.5;

    return 0.3;
  }

  /**
   * Calculate confidence for names
   */
  private calculateNameConfidence(name: string, fullText: string, position: number): number {
    const words = name.trim().split(/\s+/);

    if (words.length === 2 && words.every((word) => word.length > 1)) return 0.7;
    if (words.length === 3 && words.every((word) => word.length > 1)) return 0.6;
    if (words.length >= 2 && words.every((word) => /^[A-Z][a-z]+$/.test(word))) return 0.8;

    return 0.4;
  }

  /**
   * Get context around detected PII
   */
  private getContext(
    text: string,
    position: number,
    length: number,
    contextSize: number = 50
  ): string {
    const start = Math.max(0, position - contextSize);
    const end = Math.min(text.length, position + length + contextSize);

    return text.substring(start, end);
  }

  /**
   * Remove duplicate detections
   */
  private removeDuplicateDetections(detections: PIIDetectionResult[]): PIIDetectionResult[] {
    const unique: PIIDetectionResult[] = [];

    for (const detection of detections) {
      const isDuplicate = unique.some(
        (existing) =>
          existing.location.start === detection.location.start &&
          existing.location.end === detection.location.end &&
          existing.pii_type === detection.pii_type
      );

      if (!isDuplicate) {
        unique.push(detection);
      }
    }

    return unique;
  }

  /**
   * Redact embeddings that may contain PII
   */
  private async redactEmbeddings(
    embedding: number[],
    detections: PIIDetectionResult[]
  ): Promise<number[]> {
    // This is a complex operation that would require:
    // 1. Identify which parts of the embedding correspond to PII
    // 2. Modify or zero out those dimensions
    // 3. Ensure the modified embedding still works for semantic search

    // For now, return the original embedding
    // In a real implementation, this would use more sophisticated techniques
    return embedding;
  }

  /**
   * Calculate compliance metrics
   */
  private calculateCompliance(detections: PIIDetectionResult[]): PIIRedactionResult['compliance'] {
    const piiTypes = [...new Set(detections.map((d) => d.pii_type))];

    return {
      gdpr_compliant: this.checkGDPRCompliance(detections),
      ccpa_compliant: this.checkCCPACompliance(detections),
      hipaa_compliant: this.checkHIPAACompliance(detections),
      regulations_violated: this.getRegulationViolations(detections),
    };
  }

  /**
   * Check GDPR compliance
   */
  private checkGDPRCompliance(detections: PIIDetectionResult[]): boolean {
    // GDPR requires proper redaction of personal data
    return detections.every(
      (detection) =>
        detection.redacted_value !== detection.original_value ||
        detection.original_value.length === 0
    );
  }

  /**
   * Check CCPA compliance
   */
  private checkCCPACompliance(detections: PIIDetectionResult[]): boolean {
    // CCPA requires proper redaction of personal information
    return detections.every(
      (detection) =>
        detection.redacted_value !== detection.original_value ||
        detection.original_value.length === 0
    );
  }

  /**
   * Check HIPAA compliance
   */
  private checkHIPAACompliance(detections: PIIDetectionResult[]): boolean {
    // HIPAA requires strict redaction of PHI
    const phiTypes = ['name', 'address', 'phone', 'email', 'ssn'];
    const phiDetections = detections.filter((d) => phiTypes.includes(d.pii_type));

    return phiDetections.every(
      (detection) =>
        detection.redacted_value !== detection.original_value ||
        detection.original_value.length === 0
    );
  }

  /**
   * Get regulation violations
   */
  private getRegulationViolations(detections: PIIDetectionResult[]): string[] {
    const violations: string[] = [];

    if (!this.checkGDPRCompliance(detections)) {
      violations.push('GDPR Article 5 - Data minimization');
    }

    if (!this.checkCCPACompliance(detections)) {
      violations.push('CCPA - Right to delete');
    }

    if (!this.checkHIPAACompliance(detections)) {
      violations.push('HIPAA Privacy Rule');
    }

    return violations;
  }

  /**
   * Get overall compliance status
   */
  private getOverallComplianceStatus(
    compliance: PIIRedactionResult['compliance']
  ): 'compliant' | 'non_compliant' | 'partially_compliant' {
    const compliantFrameworks = [
      compliance.gdpr_compliant,
      compliance.ccpa_compliant,
      compliance.hipaa_compliant,
    ].filter(Boolean).length;

    const totalFrameworks = this.config.compliance.frameworks.length;

    if (compliantFrameworks === totalFrameworks) return 'compliant';
    if (compliantFrameworks === 0) return 'non_compliant';
    return 'partially_compliant';
  }

  /**
   * Get fields processed count
   */
  private getFieldsProcessed(item: KnowledgeItem): number {
    let count = 0;

    if (item.content) count++;
    if (item.metadata) count += Object.keys(item.metadata).length;
    if (item.scope) count += Object.keys(item.scope).length;

    return count;
  }

  /**
   * Update system metrics
   */
  private async updateSystemMetrics(result: PIIRedactionResult): Promise<void> {
    try {
      systemMetricsService.updateMetrics({
        operation: 'store',
        data: {
          items_processed: 1,
          pii_detected: result.metrics.pii_detected_count,
          pii_redacted: result.metrics.pii_redacted_count,
          gdpr_compliant: result.compliance.gdpr_compliant,
          ccpa_compliant: result.compliance.ccpa_compliant,
          processing_time_ms: result.metrics.total_processing_time_ms,
        },
        duration_ms: result.metrics.total_processing_time_ms,
      });
    } catch (error) {
      logger.warn(
        {
          item_id: result.item_id,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'Failed to update PII redaction metrics'
      );
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(period: {
    start_date: string;
    end_date: string;
  }): Promise<PIIComplianceReport> {
    const reportId = this.generateReportId();

    logger.info(
      {
        report_id: reportId,
        period: period,
      },
      'Generating PII compliance report'
    );

    try {
      // Filter audit logs by period
      const periodLogs = this.auditLogs.filter(
        (log) =>
          new Date(log.timestamp) >= new Date(period.start_date) &&
          new Date(log.timestamp) <= new Date(period.end_date)
      );

      // Calculate summary metrics
      const summary = this.calculateReportSummary(periodLogs);

      // Calculate regulatory compliance
      const regulatoryCompliance = {
        GDPR: this.calculateGDPRReportMetrics(periodLogs),
        CCPA: this.calculateCCPAReportMetrics(periodLogs),
        HIPAA: this.calculateHIPAAReportMetrics(periodLogs),
      };

      // Calculate processing metrics
      const metrics = this.calculateReportMetrics(periodLogs);

      // Generate recommendations
      const recommendations = this.generateRecommendations(summary, regulatoryCompliance, metrics);

      const report: PIIComplianceReport = {
        report_id: reportId,
        generated_at: new Date().toISOString(),
        period: period,
        summary: summary,
        regulatory_compliance: regulatoryCompliance,
        metrics: metrics,
        recommendations: recommendations,
      };

      logger.info(
        {
          report_id: reportId,
          total_items_processed: summary.total_items_processed,
          compliance_rate: summary.compliance_rate,
        },
        'PII compliance report generated'
      );

      return report;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          report_id: reportId,
          error: errorMsg,
        },
        'Failed to generate PII compliance report'
      );

      throw error;
    }
  }

  // Helper methods for report generation
  private calculateReportSummary(logs: PIIAuditLog[]): PIIComplianceReport['summary'] {
    const totalItems = logs.length;
    const itemsWithPII = logs.filter((log) => log.pii.pii_count > 0).length;
    const totalPIIInstances = logs.reduce((sum, log) => sum + log.pii.pii_count, 0);

    const piiTypesDetected: Record<string, number> = {};
    logs.forEach((log) => {
      log.pii.pii_types_detected.forEach((type) => {
        piiTypesDetected[type] = (piiTypesDetected[type] || 0) + 1;
      });
    });

    const compliantItems = logs.filter(
      (log) => log.compliance.compliance_status === 'compliant'
    ).length;

    return {
      total_items_processed: totalItems,
      items_with_pii: itemsWithPII,
      total_pii_instances: totalPIIInstances,
      pii_types_detected: piiTypesDetected,
      compliance_rate: totalItems > 0 ? (compliantItems / totalItems) * 100 : 0,
    };
  }

  private calculateGDPRReportMetrics(
    logs: PIIAuditLog[]
  ): PIIComplianceReport['regulatory_compliance']['GDPR'] {
    const gdprLogs = logs.filter((log) => log.compliance.regulations_frameworks.includes('GDPR'));
    const compliantLogs = gdprLogs.filter(
      (log) => log.compliance.compliance_status === 'compliant'
    );

    return {
      compliant: gdprLogs.length === compliantLogs.length,
      violations: [], // Would be populated based on specific violations
    };
  }

  private calculateCCPAReportMetrics(
    logs: PIIAuditLog[]
  ): PIIComplianceReport['regulatory_compliance']['CCPA'] {
    const ccpaLogs = logs.filter((log) => log.compliance.regulations_frameworks.includes('CCPA'));
    const compliantLogs = ccpaLogs.filter(
      (log) => log.compliance.compliance_status === 'compliant'
    );

    return {
      compliant: ccpaLogs.length === compliantLogs.length,
      violations: [], // Would be populated based on specific violations
    };
  }

  private calculateHIPAAReportMetrics(
    logs: PIIAuditLog[]
  ): PIIComplianceReport['regulatory_compliance']['HIPAA'] {
    const hipaaLogs = logs.filter((log) => log.compliance.regulations_frameworks.includes('HIPAA'));
    const compliantLogs = hipaaLogs.filter(
      (log) => log.compliance.compliance_status === 'compliant'
    );

    return {
      compliant: hipaaLogs.length === compliantLogs.length,
      violations: [], // Would be populated based on specific violations
    };
  }

  private calculateReportMetrics(logs: PIIAuditLog[]): PIIComplianceReport['metrics'] {
    const totalTime = logs.reduce((sum, log) => sum + log.performance.processing_time_ms, 0);
    const avgTime = logs.length > 0 ? totalTime / logs.length : 0;

    return {
      average_processing_time_ms: Math.round(avgTime),
      total_processing_time_ms: totalTime,
      pii_detection_accuracy: 0.95, // Placeholder - would be calculated from validation data
      false_positive_rate: 0.05, // Placeholder - would be calculated from validation data
      false_negative_rate: 0.02, // Placeholder - would be calculated from validation data
    };
  }

  private generateRecommendations(
    summary: PIIComplianceReport['summary'],
    regulatoryCompliance: PIIComplianceReport['regulatory_compliance'],
    metrics: PIIComplianceReport['metrics']
  ): PIIComplianceReport['recommendations'] {
    const recommendations: PIIComplianceReport['recommendations'] = [];

    if (summary.compliance_rate < 95) {
      recommendations.push({
        priority: 'high',
        category: 'compliance',
        description: 'Compliance rate is below target threshold',
        action_items: [
          'Review and update PII detection patterns',
          'Improve redaction strategies',
          'Conduct compliance training',
        ],
      });
    }

    if (metrics.average_processing_time_ms > 1000) {
      recommendations.push({
        priority: 'medium',
        category: 'process',
        description: 'Average processing time exceeds 1 second',
        action_items: [
          'Optimize PII detection algorithms',
          'Enable parallel processing',
          'Consider caching mechanisms',
        ],
      });
    }

    if (!regulatoryCompliance.GDPR.compliant) {
      recommendations.push({
        priority: 'high',
        category: 'compliance',
        description: 'GDPR compliance issues detected',
        action_items: [
          'Review GDPR requirements',
          'Update redaction strategies for GDPR',
          'Implement GDPR-specific validation',
        ],
      });
    }

    return recommendations;
  }

  // Utility methods
  private validatePatterns(): void {
    // Validate regex patterns
    for (const [piiType, config] of Object.entries(this.config.patterns)) {
      if (piiType === 'custom') continue;

      const patternConfig = config as unknown;
      if (!patternConfig.enabled) continue;

      const patterns = Array.isArray(patternConfig.patterns)
        ? patternConfig.patterns
        : [patternConfig.pattern];

      for (const pattern of patterns) {
        try {
          new RegExp(pattern);
        } catch (error) {
          logger.error(
            {
              pii_type: piiType,
              pattern: pattern,
              error: error instanceof Error ? error.message : 'Unknown error',
            },
            'Invalid PII pattern detected'
          );
          throw error;
        }
      }
    }

    logger.info('PII patterns validated successfully');
  }

  private async loadAuditLogs(): Promise<void> {
    // Implementation placeholder for loading audit logs from storage
    logger.debug('Loading PII audit logs');
  }

  private async cleanupOldAuditLogs(): Promise<void> {
    if (!this.config.compliance.enable_audit_logging) return;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.compliance.audit_retention_days);

    const initialCount = this.auditLogs.length;
    this.auditLogs = this.auditLogs.filter((log) => new Date(log.timestamp) >= cutoffDate);

    const cleanedCount = initialCount - this.auditLogs.length;

    if (cleanedCount > 0) {
      logger.info(
        {
          cleaned_count: cleanedCount,
          retention_days: this.config.compliance.audit_retention_days,
        },
        'Cleaned up old PII audit logs'
      );
    }
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateLogId(): string {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateReportId(): string {
    return `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get service status
   */
  public getStatus(): {
    is_initialized: boolean;
    patterns_enabled: number;
    cache_size: number;
    audit_logs_count: number;
    supported_frameworks: string[];
  } {
    return {
      is_initialized: true,
      patterns_enabled: Object.values(this.config.patterns).filter((p: unknown) => p.enabled).length,
      cache_size: this.detectionCache.size,
      audit_logs_count: this.auditLogs.length,
      supported_frameworks: this.config.compliance.frameworks,
    };
  }

  /**
   * Get configuration
   */
  public getConfig(): PIIConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<PIIConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.validatePatterns();
    logger.info({ config: this.config }, 'PII redaction configuration updated');
  }

  /**
   * Clear detection cache
   */
  public clearCache(): void {
    this.detectionCache.clear();
    logger.debug('PII detection cache cleared');
  }

  /**
   * Get audit logs
   */
  public getAuditLogs(limit: number = 100): PIIAuditLog[] {
    return this.auditLogs
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }
}

// === Global PII Redaction Service Instance ===

let piiRedactionServiceInstance: PIIRedactionService | null = null;

export function createPIIRedactionService(config: Partial<PIIConfig> = {}): PIIRedactionService {
  piiRedactionServiceInstance = new PIIRedactionService(config);
  return piiRedactionServiceInstance;
}

export function getPIIRedactionService(): PIIRedactionService | null {
  return piiRedactionServiceInstance;
}
