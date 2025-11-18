/**
 * Truncation configuration and interfaces for content management
 * Handles intelligent content truncation with proper metadata and metrics
 */

export interface TruncationConfig {
  // Maximum character limits for different content types
  maxChars: {
    default: number;
    text: number;
    json: number;
    code: number;
    markdown: number;
    html: number;
    xml: number;
    csv: number;
    log: number;
  };

  // Token limits for LLM processing
  maxTokens: {
    default: number;
    input: number;
    output: number;
    context: number;
  };

  // Truncation behavior settings
  behavior: {
    // How to handle truncation: 'hard', 'soft', 'intelligent'
    mode: 'hard' | 'soft' | 'intelligent';
    // Whether to preserve structure during truncation
    preserveStructure: boolean;
    // Whether to add truncation indicators
    addIndicators: boolean;
    // Truncation indicator text
    indicator: string;
    // Safety margin to avoid hitting exact limits
    safetyMargin: number; // percentage
  };

  // Content type specific settings
  contentTypes: {
    // Whether to attempt content type detection
    autoDetect: boolean;
    // Priority for content preservation
    preservePriority: string[];
    // Whether to attempt smart truncation (preserve important parts)
    enableSmart: boolean;
  };

  // Warning and logging settings
  warnings: {
    // Whether to log truncation events
    logTruncation: boolean;
    // Whether to include warnings in responses
    includeInResponse: boolean;
    // Log level for truncation events
    logLevel: 'warn' | 'info' | 'debug';
    // Whether to emit metrics for truncation
    emitMetrics: boolean;
  };

  // Feature flags
  enabled: boolean;
  enforceLimits: boolean;
  allowOverride: boolean;
}

export interface TruncationResult {
  // Original content information
  original: {
    length: number;
    estimatedTokens: number;
    contentType?: string;
  };

  // Truncated content information
  truncated: {
    length: number;
    estimatedTokens: number;
    content: string;
    wasTruncated: boolean;
    truncationType?: 'character' | 'token' | 'both';
  };

  // Metadata about the truncation process
  meta: {
    truncated: boolean;
    reason?: string;
    limitType?: 'character' | 'token' | 'both';
    limitApplied?: number;
    percentageRemoved?: number;
    processingTimeMs?: number;
    strategy?: string;
  };

  // Warnings and information for the user
  warnings: string[];

  // Metrics for monitoring
  metrics: {
    truncationOccurred: boolean;
    charsRemoved: number;
    tokensRemoved: number;
    processingTimeMs: number;
  };
}

export interface TruncationMetadata {
  truncated: boolean;
  type?: 'character' | 'token' | 'both';
  reason?: string;
  originalLength?: number;
  truncatedLength?: number;
  limitApplied?: number;
  percentageRemoved?: number;
  strategy?: string;
  contentType?: string;
  processingTimeMs?: number;
  warnings?: string[];
}

export interface TruncationMetrics {
  store_truncated_total: number;
  store_truncated_chars_total: number;
  store_truncated_tokens_total: number;
  truncation_processing_time_ms: number;
  truncation_by_type: Record<string, number>;
  truncation_by_strategy: Record<string, number>;
}

export interface TruncationWarning {
  type: 'content_truncated' | 'limit_exceeded' | 'processing_error';
  message: string;
  details: {
    contentType?: string;
    originalLength?: number;
    truncatedLength?: number;
    limit?: number;
    strategy?: string;
  };
  timestamp: string;
  severity: 'low' | 'medium' | 'high';
}

export interface TruncationStrategy {
  name: string;
  description: string;
  isIntelligent: boolean;
  preserveStructure: boolean;
  applicableTypes: string[];
  priority: number;
}

/**
 * Default truncation configuration
 */
export const DEFAULT_TRUNCATION_CONFIG: TruncationConfig = {
  maxChars: {
    default: 8000,
    text: 10000,
    json: 15000,
    code: 8000,
    markdown: 12000,
    html: 15000,
    xml: 15000,
    csv: 20000,
    log: 50000,
  },

  maxTokens: {
    default: 2000,
    input: 4000,
    output: 2000,
    context: 8000,
  },

  behavior: {
    mode: 'intelligent',
    preserveStructure: true,
    addIndicators: true,
    indicator: '\n\n[Content truncated by system]',
    safetyMargin: 5, // 5% safety margin
  },

  contentTypes: {
    autoDetect: true,
    preservePriority: ['json', 'code', 'markdown', 'text', 'html', 'xml', 'csv', 'log'],
    enableSmart: true,
  },

  warnings: {
    logTruncation: true,
    includeInResponse: true,
    logLevel: 'warn',
    emitMetrics: true,
  },

  enabled: true,
  enforceLimits: true,
  allowOverride: false,
};

/**
 * Built-in truncation strategies
 */
export const TRUNCATION_STRATEGIES: Record<string, TruncationStrategy> = {
  hard_cutoff: {
    name: 'hard_cutoff',
    description: 'Simple hard cutoff at character limit',
    isIntelligent: false,
    preserveStructure: false,
    applicableTypes: ['*'],
    priority: 1,
  },

  preserve_sentences: {
    name: 'preserve_sentences',
    description: 'Preserve complete sentences when truncating',
    isIntelligent: true,
    preserveStructure: true,
    applicableTypes: ['text', 'markdown'],
    priority: 5,
  },

  preserve_json_structure: {
    name: 'preserve_json_structure',
    description: 'Preserve valid JSON structure when truncating',
    isIntelligent: true,
    preserveStructure: true,
    applicableTypes: ['json'],
    priority: 6,
  },

  preserve_code_blocks: {
    name: 'preserve_code_blocks',
    description: 'Preserve complete code blocks and functions',
    isIntelligent: true,
    preserveStructure: true,
    applicableTypes: ['code', 'javascript', 'typescript', 'python', 'java'],
    priority: 7,
  },

  preserve_markdown_structure: {
    name: 'preserve_markdown_structure',
    description: 'Preserve markdown headings and structure',
    isIntelligent: true,
    preserveStructure: true,
    applicableTypes: ['markdown'],
    priority: 6,
  },

  smart_content: {
    name: 'smart_content',
    description: 'Intelligently preserve important content based on analysis',
    isIntelligent: true,
    preserveStructure: true,
    applicableTypes: ['*'],
    priority: 8,
  },
};

/**
 * Content type detection patterns
 */
export const CONTENT_TYPE_PATTERNS: Record<string, RegExp[]> = {
  json: [/^\s*\{[\s\S]*\}\s*$/m, /^\s*\[[\s\S]*\]\s*$/m],
  code: [/function\s+\w+\s*\(/, /class\s+\w+/, /import\s+.*from/, /#include\s*</, /def\s+\w+\s*\(/],
  markdown: [/^#{1,6}\s+/m, /\[.*\]\(.*\)/, /```[\s\S]*```/, /\*\*.*\*\*/, /^\s*[-*+]\s+/m],
  html: [/<[^>]+>/, /<html[\s\S]*<\/html>/i, /<body[\s\S]*<\/body>/i],
  xml: [/<\?xml/, /<[^>]+>[^<]*<\/[^>]+>/],
  csv: [/^[^,\n]+,[^,\n]+/, /^[^,\n]+;[^,\n]+/],
  log: [/^\d{4}-\d{2}-\d{2}/, /^\[\d{2}:\d{2}:\d{2}/, /^[A-Z]+\s+/],
};
