/**
 * Simple heuristic language detection for Indonesian vs English content
 * Provides basic language distribution tracking for quality metrics
 */

export type DetectedLanguage = 'en' | 'id' | 'mixed' | 'unknown';

export class LanguageDetector {
  private readonly indonesianKeywords = [
    'yang',
    'dan',
    'untuk',
    'dengan',
    'dari',
    'pada',
    'ke',
    'dalam',
    'adalah',
    'ini',
    'itu',
    'akan',
    'bisa',
    'juga',
    'sudah',
    'belum',
    'atau',
    'karena',
    'jika',
    'sehingga',
    'tetapi',
    'namun',
    'oleh',
    'tersebut',
    'sebagai',
    'telah',
    'merupakan',
    'dapat',
    'akan',
    'pada',
    'dalam',
    'tahun',
    'bulan',
    'hari',
    'waktu',
    'orang',
    'kerja',
    'data',
    'sistem',
    'aplikasi',
    'pengguna',
    'proses',
    'hasil',
    'menggunakan',
    'membuat',
  ];

  private readonly englishKeywords = [
    'the',
    'and',
    'for',
    'with',
    'from',
    'at',
    'to',
    'in',
    'is',
    'this',
    'that',
    'will',
    'can',
    'also',
    'have',
    'not',
    'but',
    'if',
    'so',
    'be',
    'are',
    'was',
    'were',
    'been',
    'being',
    'have',
    'has',
    'had',
    'do',
    'does',
    'did',
    'will',
    'would',
    'could',
    'should',
    'may',
    'might',
    'must',
    'shall',
    'can',
    'cannot',
    'data',
    'system',
    'application',
    'user',
    'process',
    'result',
    'using',
    'make',
    'time',
    'year',
    'month',
    'day',
    'people',
    'work',
    'use',
    'create',
    'build',
  ];

  detectLanguage(text: string): DetectedLanguage {
    if (!text || text.trim().length === 0) {
      return 'unknown';
    }

    const normalizedText = text.toLowerCase().replace(/[^\w\s]/g, ' ');
    const words = normalizedText.split(/\s+/).filter((word) => word.length > 2);

    if (words.length === 0) {
      return 'unknown';
    }

    let indonesianCount = 0;
    let englishCount = 0;

    for (const word of words) {
      if (this.indonesianKeywords.includes(word)) {
        indonesianCount++;
      }
      if (this.englishKeywords.includes(word)) {
        englishCount++;
      }
    }

    const totalWords = words.length;
    const indonesianRatio = indonesianCount / totalWords;
    const englishRatio = englishCount / totalWords;

    // Decision logic for language detection
    if (indonesianRatio >= 0.1 && englishRatio >= 0.1) {
      return 'mixed';
    } else if (indonesianRatio >= 0.1) {
      return 'id';
    } else if (englishRatio >= 0.1) {
      return 'en';
    } else {
      return 'unknown';
    }
  }

  /**
   * Analyzes language distribution across multiple text samples
   */
  analyzeLanguageDistribution(texts: string[]): {
    en: number;
    id: number;
    mixed: number;
    unknown: number;
  } {
    const distribution = { en: 0, id: 0, mixed: 0, unknown: 0 };

    for (const text of texts) {
      const language = this.detectLanguage(text);
      distribution[language]++;
    }

    return distribution;
  }

  /**
   * Provides confidence score for language detection
   */
  getLanguageConfidence(text: string): {
    language: DetectedLanguage;
    confidence: number;
    indonesianRatio: number;
    englishRatio: number;
  } {
    if (!text || text.trim().length === 0) {
      return { language: 'unknown', confidence: 0, indonesianRatio: 0, englishRatio: 0 };
    }

    const normalizedText = text.toLowerCase().replace(/[^\w\s]/g, ' ');
    const words = normalizedText.split(/\s+/).filter((word) => word.length > 2);

    if (words.length === 0) {
      return { language: 'unknown', confidence: 0, indonesianRatio: 0, englishRatio: 0 };
    }

    let indonesianCount = 0;
    let englishCount = 0;

    for (const word of words) {
      if (this.indonesianKeywords.includes(word)) {
        indonesianCount++;
      }
      if (this.englishKeywords.includes(word)) {
        englishCount++;
      }
    }

    const totalWords = words.length;
    const indonesianRatio = indonesianCount / totalWords;
    const englishRatio = englishCount / totalWords;

    let language: DetectedLanguage;
    let confidence: number;

    if (indonesianRatio >= 0.1 && englishRatio >= 0.1) {
      language = 'mixed';
      confidence = Math.min(indonesianRatio + englishRatio, 1.0);
    } else if (indonesianRatio >= 0.1) {
      language = 'id';
      confidence = indonesianRatio;
    } else if (englishRatio >= 0.1) {
      language = 'en';
      confidence = englishRatio;
    } else {
      language = 'unknown';
      confidence = 0;
    }

    return {
      language,
      confidence,
      indonesianRatio,
      englishRatio,
    };
  }
}
