/**
 * P1-2: Truncation Service
 * Handles intelligent content truncation with proper metadata and metrics
 */

import { logger } from '@/utils/logger.js';

import { environment } from '../../config/environment.js';
import type { TruncationConfig, TruncationResult } from '../../config/truncation-config.js';
import { CONTENT_TYPE_PATTERNS, TRUNCATION_STRATEGIES } from '../../config/truncation-config.js';

/**
 * Token estimation utility
 */
class TokenEstimator {
  private static readonly CHARS_PER_TOKEN = 4;
  private static readonly TOKEN_PATTERNS = {
    // Common patterns that affect token count
    whitespace: /\s+/g,
    punctuation: /[.,;:!?]/g,
    numbers: /\d+/g,
    specialChars: /[^\w\s]/g,
  };

  /**
   * Estimate token count from text
   */
  static estimate(text: string): number {
    if (!text) return 0;

    // Basic estimation: characters / average chars per token
    const baseEstimate = Math.ceil(text.length / this.CHARS_PER_TOKEN);

    // Adjust for patterns that affect token count
    let adjustment = 0;

    // Numbers often use more tokens than estimated
    const numbers = text.match(this.TOKEN_PATTERNS.numbers);
    if (numbers) {
      adjustment += numbers.length * 0.5;
    }

    // Special characters can increase token count
    const specialChars = text.match(this.TOKEN_PATTERNS.specialChars);
    if (specialChars) {
      adjustment += specialChars.length * 0.2;
    }

    return Math.max(1, Math.ceil(baseEstimate + adjustment));
  }

  /**
   * Estimate tokens for different content types
   */
  static estimateByType(content: string, contentType: string): number {
    const baseEstimate = this.estimate(content);

    // Adjust based on content type
    switch (contentType.toLowerCase()) {
      case 'json':
        // JSON is often more token-dense
        return Math.ceil(baseEstimate * 1.2);
      case 'code':
        // Code has more special characters and structure
        return Math.ceil(baseEstimate * 1.3);
      case 'markdown':
        // Markdown has formatting that affects tokens
        return Math.ceil(baseEstimate * 1.1);
      case 'html':
      case 'xml':
        // Tags increase token count
        return Math.ceil(baseEstimate * 1.4);
      default:
        return baseEstimate;
    }
  }
}

/**
 * Content type detection utility
 */
class ContentTypeDetector {
  /**
   * Detect content type from content string
   */
  static detect(content: string): string {
    if (!content || typeof content !== 'string') {
      return 'text';
    }

    const contentLower = content.toLowerCase().trim();

    // Check for JSON
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.json)) {
      return 'json';
    }

    // Check for code
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.code)) {
      return 'code';
    }

    // Check for markdown
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.markdown)) {
      return 'markdown';
    }

    // Check for HTML
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.html)) {
      return 'html';
    }

    // Check for XML
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.xml)) {
      return 'xml';
    }

    // Check for CSV
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.csv)) {
      return 'csv';
    }

    // Check for logs
    if (this.matchesPatterns(contentLower, CONTENT_TYPE_PATTERNS.log)) {
      return 'log';
    }

    // Default to text
    return 'text';
  }

  /**
   * Check if content matches any of the provided patterns
   */
  private static matchesPatterns(content: string, patterns: RegExp[]): boolean {
    return patterns.some((pattern) => pattern.test(content));
  }
}

/**
 * Truncation strategies implementation
 */
class TruncationStrategies {
  /**
   * Hard cutoff strategy - simple character limit
   */
  static hardCutoff(content: string, limit: number): string {
    return content.substring(0, limit);
  }

  /**
   * Preserve sentences strategy - cut at sentence boundaries
   */
  static preserveSentences(content: string, limit: number): string {
    const sentences = content.match(/[^.!?]+[.!?]+/g) || [content];
    let result = '';

    for (const sentence of sentences) {
      if ((result + sentence).length <= limit) {
        result += sentence;
      } else {
        break;
      }
    }

    return result || content.substring(0, Math.min(limit, content.length));
  }

  /**
   * Preserve JSON structure - ensure valid JSON after truncation
   */
  static preserveJsonStructure(content: string, limit: number): string {
    try {
      const parsed = JSON.parse(content);
      const truncated = this.truncateJsonObject(parsed, limit);
      return JSON.stringify(truncated, null, 2);
    } catch {
      // Fallback to hard cutoff if JSON parsing fails
      return this.hardCutoff(content, limit);
    }
  }

  /**
   * Recursively truncate JSON object to fit character limit
   */
  private static truncateJsonObject(obj: unknown, limit: number): unknown {
    const str = JSON.stringify(obj);
    if (str.length <= limit) {
      return obj;
    }

    if (Array.isArray(obj)) {
      const truncatedArray: unknown[] = [];
      let currentLength = 2; // Start with '[]'

      for (const item of obj) {
        const itemStr = JSON.stringify(item);
        if (currentLength + itemStr.length + 1 <= limit) {
          truncatedArray.push(item);
          currentLength += itemStr.length + 1;
        } else {
          break;
        }
      }
      return truncatedArray;
    }

    if (typeof obj === 'object' && obj !== null) {
      const truncatedObj: Record<string, unknown> = {};
      let currentLength = 2; // Start with '{}'

      const entries = Object.entries(obj);
      for (const [key, value] of entries) {
        const entryStr = JSON.stringify({ [key]: value }).slice(2, -2);
        if (currentLength + entryStr.length + 1 <= limit) {
          truncatedObj[key] = value;
          currentLength += entryStr.length + 1;
        } else {
          break;
        }
      }
      return truncatedObj;
    }

    return obj;
  }

  /**
   * Preserve code blocks - keep complete functions/methods
   */
  static preserveCodeBlocks(content: string, limit: number): string {
    // Simple implementation - preserve complete lines
    const lines = content.split('\n');
    let result = '';

    for (const line of lines) {
      if ((result + line + '\n').length <= limit) {
        result += line + '\n';
      } else {
        break;
      }
    }

    return result.trim();
  }

  /**
   * Preserve markdown structure - keep headings and structure
   */
  static preserveMarkdownStructure(content: string, limit: number): string {
    const lines = content.split('\n');
    let result = '';
    let inCodeBlock = false;

    for (const line of lines) {
      // Track code blocks
      if (line.trim().startsWith('```')) {
        inCodeBlock = !inCodeBlock;
      }

      // Always include headings
      if (line.startsWith('#')) {
        if ((result + line + '\n').length <= limit) {
          result += line + '\n';
        }
        continue;
      }

      // Inside code blocks, try to preserve structure
      if (inCodeBlock) {
        if ((result + line + '\n').length <= limit) {
          result += line + '\n';
        }
        continue;
      }

      // Regular content
      if ((result + line + '\n').length <= limit) {
        result += line + '\n';
      } else {
        break;
      }
    }

    return result.trim();
  }

  /**
   * Smart content strategy - analyze and preserve important content
   */
  static smartContent(content: string, limit: number, contentType: string): string {
    // Choose the best strategy based on content type
    switch (contentType) {
      case 'json':
        return this.preserveJsonStructure(content, limit);
      case 'code':
        return this.preserveCodeBlocks(content, limit);
      case 'markdown':
        return this.preserveMarkdownStructure(content, limit);
      case 'text':
        return this.preserveSentences(content, limit);
      default:
        return this.hardCutoff(content, limit);
    }
  }
}

/**
 * Main truncation service
 */
export class TruncationService {
  private config: TruncationConfig;
  private metrics: {
    store_truncated_total: number;
    store_truncated_chars_total: number;
    store_truncated_tokens_total: number;
    truncation_processing_time_ms: number;
    truncation_by_type: Record<string, number>;
    truncation_by_strategy: Record<string, number>;
  };

  constructor(config?: TruncationConfig) {
    this.config = config || environment.getTruncationConfig();
    this.metrics = {
      store_truncated_total: 0,
      store_truncated_chars_total: 0,
      store_truncated_tokens_total: 0,
      truncation_processing_time_ms: 0,
      truncation_by_type: {},
      truncation_by_strategy: {},
    };
  }

  /**
   * Process content with truncation if needed
   */
  async processContent(
    content: string,
    options: {
      contentType?: string;
      maxChars?: number;
      maxTokens?: number;
      strategy?: string;
    } = {}
  ): Promise<TruncationResult> {
    const startTime = Date.now();

    // Detect content type if not provided
    const contentType =
      options.contentType ||
      (this.config.contentTypes.autoDetect ? ContentTypeDetector.detect(content) : 'text');

    // Determine limits
    const maxChars =
      options.maxChars ||
      (contentType in this.config.maxChars
        ? this.config.maxChars[contentType as keyof typeof this.config.maxChars]
        : this.config.maxChars.default) ||
      this.config.maxChars.default;
    const maxTokens = options.maxTokens || this.config.maxTokens.default;

    // Estimate tokens
    const originalTokens = TokenEstimator.estimateByType(content, contentType);
    const originalLength = content.length;

    // Check if truncation is needed
    const needsCharTruncation = originalLength > maxChars;
    const needsTokenTruncation = originalTokens > maxTokens;
    const needsTruncation = needsCharTruncation || needsTokenTruncation;

    if (!needsTruncation || !this.config.enabled) {
      return {
        original: {
          length: originalLength,
          estimatedTokens: originalTokens,
          contentType,
        },
        truncated: {
          length: originalLength,
          estimatedTokens: originalTokens,
          content,
          wasTruncated: false,
        },
        meta: {
          truncated: false,
          processingTimeMs: Date.now() - startTime,
          strategy: 'none',
        },
        warnings: [],
        metrics: {
          truncationOccurred: false,
          charsRemoved: 0,
          tokensRemoved: 0,
          processingTimeMs: Date.now() - startTime,
        },
      };
    }

    // Determine truncation strategy
    const strategy = this.selectStrategy(contentType, options.strategy);

    // Apply truncation
    const truncatedContent = this.applyTruncation(content, maxChars, strategy, contentType);

    // Calculate results
    const truncatedLength = truncatedContent.length;
    const truncatedTokens = TokenEstimator.estimateByType(truncatedContent, contentType);
    const charsRemoved = originalLength - truncatedLength;
    const tokensRemoved = originalTokens - truncatedTokens;

    // Generate warnings
    const warnings = this.generateWarnings(
      contentType,
      originalLength,
      maxChars,
      originalTokens,
      maxTokens
    );

    // Update metrics
    this.updateMetrics(contentType, strategy, charsRemoved, tokensRemoved, Date.now() - startTime);

    // Log truncation event
    this.logTruncationEvent(contentType, originalLength, truncatedLength, strategy);

    // Add truncation indicator if configured
    const finalContent = this.config.behavior.addIndicators
      ? truncatedContent + this.config.behavior.indicator
      : truncatedContent;

    return {
      original: {
        length: originalLength,
        estimatedTokens: originalTokens,
        contentType,
      },
      truncated: {
        length: truncatedLength,
        estimatedTokens: truncatedTokens,
        content: finalContent,
        wasTruncated: true,
        truncationType:
          needsCharTruncation && needsTokenTruncation
            ? 'both'
            : needsCharTruncation
              ? 'character'
              : 'token',
      },
      meta: {
        truncated: true,
        reason:
          needsCharTruncation && needsTokenTruncation
            ? 'Character and token limits exceeded'
            : needsCharTruncation
              ? 'Character limit exceeded'
              : 'Token limit exceeded',
        limitType:
          needsCharTruncation && needsTokenTruncation
            ? 'both'
            : needsCharTruncation
              ? 'character'
              : 'token',
        limitApplied: needsCharTruncation ? maxChars : maxTokens,
        percentageRemoved: Math.round((charsRemoved / originalLength) * 100),
        processingTimeMs: Date.now() - startTime,
        strategy,
      },
      warnings,
      metrics: {
        truncationOccurred: true,
        charsRemoved,
        tokensRemoved,
        processingTimeMs: Date.now() - startTime,
      },
    };
  }

  /**
   * Select truncation strategy based on content type and configuration
   */
  private selectStrategy(contentType: string, preferredStrategy?: string): string {
    if (preferredStrategy && TRUNCATION_STRATEGIES[preferredStrategy]) {
      return preferredStrategy;
    }

    const mode = this.config.behavior.mode;

    switch (mode) {
      case 'hard':
        return 'hard_cutoff';
      case 'soft':
        return 'preserve_sentences';
      case 'intelligent':
        if (this.config.contentTypes.enableSmart) {
          return 'smart_content';
        }
        return 'preserve_sentences';
      default:
        return 'smart_content';
    }
  }

  /**
   * Apply truncation using the selected strategy
   */
  private applyTruncation(
    content: string,
    limit: number,
    strategy: string,
    contentType: string
  ): string {
    // Apply safety margin
    const adjustedLimit = Math.floor(limit * (1 - this.config.behavior.safetyMargin / 100));

    switch (strategy) {
      case 'hard_cutoff':
        return TruncationStrategies.hardCutoff(content, adjustedLimit);
      case 'preserve_sentences':
        return TruncationStrategies.preserveSentences(content, adjustedLimit);
      case 'preserve_json_structure':
        return TruncationStrategies.preserveJsonStructure(content, adjustedLimit);
      case 'preserve_code_blocks':
        return TruncationStrategies.preserveCodeBlocks(content, adjustedLimit);
      case 'preserve_markdown_structure':
        return TruncationStrategies.preserveMarkdownStructure(content, adjustedLimit);
      case 'smart_content':
        return TruncationStrategies.smartContent(content, adjustedLimit, contentType);
      default:
        return TruncationStrategies.hardCutoff(content, adjustedLimit);
    }
  }

  /**
   * Generate warnings for truncation events
   */
  private generateWarnings(
    contentType: string,
    originalLength: number,
    maxChars: number,
    originalTokens: number,
    maxTokens: number
  ): string[] {
    const warnings: string[] = [];

    if (originalLength > maxChars) {
      warnings.push(
        `Content truncated due to character limit: ${originalLength} → ${maxChars} (${contentType})`
      );
    }

    if (originalTokens > maxTokens) {
      warnings.push(
        `Content truncated due to token limit: ${originalTokens} → ${maxTokens} tokens`
      );
    }

    const percentageOver = Math.max(
      ((originalLength - maxChars) / maxChars) * 100,
      ((originalTokens - maxTokens) / maxTokens) * 100
    );

    if (percentageOver > 50) {
      warnings.push(
        `Content significantly over limits (${Math.round(percentageOver)}% over). Consider increasing limits or reducing input size.`
      );
    }

    return warnings;
  }

  /**
   * Update truncation metrics
   */
  private updateMetrics(
    contentType: string,
    strategy: string,
    charsRemoved: number,
    tokensRemoved: number,
    processingTimeMs: number
  ): void {
    this.metrics.store_truncated_total++;
    this.metrics.store_truncated_chars_total += charsRemoved;
    this.metrics.store_truncated_tokens_total += tokensRemoved;
    this.metrics.truncation_processing_time_ms += processingTimeMs;

    this.metrics.truncation_by_type[contentType] =
      (this.metrics.truncation_by_type[contentType] || 0) + 1;
    this.metrics.truncation_by_strategy[strategy] =
      (this.metrics.truncation_by_strategy[strategy] || 0) + 1;
  }

  /**
   * Log truncation event
   */
  private logTruncationEvent(
    contentType: string,
    originalLength: number,
    truncatedLength: number,
    strategy: string
  ): void {
    if (!this.config.warnings.logTruncation) return;

    const logLevel = this.config.warnings.logLevel;
    const message = `Content truncated: ${originalLength} → ${truncatedLength} chars (${contentType}, strategy: ${strategy})`;

    switch (logLevel) {
      case 'debug':
        logger.debug(message, {
          contentType,
          originalLength,
          truncatedLength,
          strategy,
          charsRemoved: originalLength - truncatedLength,
        });
        break;
      case 'info':
        logger.info(message, {
          contentType,
          originalLength,
          truncatedLength,
          strategy,
        });
        break;
      case 'warn':
        logger.warn(message, {
          contentType,
          originalLength,
          truncatedLength,
          strategy,
        });
        break;
    }
  }

  /**
   * Get current truncation metrics
   */
  getMetrics() {
    return { ...this.metrics };
  }

  /**
   * Reset truncation metrics
   */
  resetMetrics(): void {
    this.metrics = {
      store_truncated_total: 0,
      store_truncated_chars_total: 0,
      store_truncated_tokens_total: 0,
      truncation_processing_time_ms: 0,
      truncation_by_type: {},
      truncation_by_strategy: {},
    };
  }

  /**
   * Check if content would be truncated
   */
  wouldTruncate(content: string, contentType?: string): boolean {
    const detectedType =
      contentType ||
      (this.config.contentTypes.autoDetect ? ContentTypeDetector.detect(content) : 'text');
    const maxChars =
      detectedType in this.config.maxChars
        ? this.config.maxChars[detectedType as keyof typeof this.config.maxChars]
        : this.config.maxChars.default;
    const maxTokens = this.config.maxTokens.default;

    const originalLength = content.length;
    const originalTokens = TokenEstimator.estimateByType(content, detectedType);

    return originalLength > maxChars || originalTokens > maxTokens;
  }

  /**
   * Estimate tokens for content
   */
  estimateTokens(content: string, contentType?: string): number {
    const detectedType = contentType || 'text';
    return TokenEstimator.estimateByType(content, detectedType);
  }

  /**
   * Detect content type
   */
  detectContentType(content: string): string {
    return ContentTypeDetector.detect(content);
  }
}

/**
 * Singleton instance
 */
export const truncationService = new TruncationService();
