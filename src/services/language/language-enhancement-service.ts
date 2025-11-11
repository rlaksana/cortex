
import { type KnowledgeItem } from '../../types/core-interfaces.js';
import { LanguageDetector } from '../telemetry/language-detector.js';

export interface LanguageEnhancementResult {
  detected_lang: 'en' | 'id' | 'mixed' | 'unknown';
  lang_confidence: number;
  lang_indonesian_ratio: number;
  lang_english_ratio: number;
}

export interface LanguageDistribution {
  en: number;
  id: number;
  mixed: number;
  unknown: number;
}

export class LanguageEnhancementService {
  private languageDetector: LanguageDetector;

  constructor() {
    this.languageDetector = new LanguageDetector();
  }

  /**
   * Enhance a single knowledge item with language detection
   */
  enhanceItemWithLanguage(item: KnowledgeItem): KnowledgeItem {
    const content = this.extractContentForLanguageDetection(item);
    const detection = this.languageDetector.getLanguageConfidence(content);

    return {
      ...item,
      data: {
        ...item.data,
        detected_lang: detection.language,
        lang_confidence: detection.confidence,
        lang_indonesian_ratio: detection.indonesianRatio,
        lang_english_ratio: detection.englishRatio,
      },
    };
  }

  /**
   * Enhance multiple knowledge items with language detection
   */
  enhanceItemsWithLanguage(items: KnowledgeItem[]): KnowledgeItem[] {
    return items.map((item) => this.enhanceItemWithLanguage(item));
  }

  /**
   * Analyze language distribution across multiple items
   */
  analyzeLanguageDistribution(items: KnowledgeItem[]): LanguageDistribution {
    const distribution: LanguageDistribution = { en: 0, id: 0, mixed: 0, unknown: 0 };

    for (const item of items) {
      const lang = item.data.detected_lang as string;
      if (lang === 'en') distribution.en++;
      else if (lang === 'id') distribution.id++;
      else if (lang === 'mixed') distribution.mixed++;
      else distribution.unknown++;
    }

    return distribution;
  }

  /**
   * Get language statistics for a collection of items
   */
  getLanguageStats(items: KnowledgeItem[]): {
    total: number;
    distribution: LanguageDistribution;
    dominant_language: string;
    mixed_content_ratio: number;
  } {
    const distribution = this.analyzeLanguageDistribution(items);
    const total = items.length;

    // Find dominant language
    let dominantLanguage = 'unknown';
    let maxCount = 0;
    for (const [lang, count] of Object.entries(distribution)) {
      if (count > maxCount) {
        maxCount = count;
        dominantLanguage = lang;
      }
    }

    const _mixedContentRatio = total > 0 ? distribution.mixed / total : 0;

    return {
      total,
      distribution,
      dominant_language: dominantLanguage,
      mixed_content_ratio: _mixedContentRatio,
    };
  }

  /**
   * Filter items by language
   */
  filterByLanguage(
    items: KnowledgeItem[],
    language: 'en' | 'id' | 'mixed' | 'unknown'
  ): KnowledgeItem[] {
    return items.filter((item) => item.data.detected_lang === language);
  }

  /**
   * Get items with language confidence above threshold
   */
  getHighConfidenceItems(items: KnowledgeItem[], threshold: number = 0.7): KnowledgeItem[] {
    return items.filter((item) => (item.data.lang_confidence as number) >= threshold);
  }

  /**
   * Extract content for language detection from knowledge item
   */
  private extractContentForLanguageDetection(item: KnowledgeItem): string {
    // Priority order for content extraction
    const contentFields = [
      'content',
      'body_text',
      'body_md',
      'description',
      'rationale',
      'summary',
      'title',
    ];

    for (const field of contentFields) {
      if (
        item.data[field] &&
        typeof item.data[field] === 'string' &&
        item.data[field].length > 10
      ) {
        return item.data[field];
      }
    }

    // Fallback: find the longest string field
    let longestContent = '';
    for (const [_key, value] of Object.entries(item.data)) {
      if (typeof value === 'string' && value.length > longestContent.length) {
        longestContent = value;
      }
    }

    return longestContent;
  }

  /**
   * Update language fields on existing items
   */
  updateLanguageFields(
    item: KnowledgeItem,
    languageResult: LanguageEnhancementResult
  ): KnowledgeItem {
    return {
      ...item,
      data: {
        ...item.data,
        detected_lang: languageResult.detected_lang,
        lang_confidence: languageResult.lang_confidence,
        lang_indonesian_ratio: languageResult.lang_indonesian_ratio,
        lang_english_ratio: languageResult.lang_english_ratio,
      },
    };
  }
}
