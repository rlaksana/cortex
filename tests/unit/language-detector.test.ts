import { LanguageDetector } from '../../src/services/telemetry/language-detector';

describe('LanguageDetector', () => {
  let detector: LanguageDetector;

  beforeEach(() => {
    detector = new LanguageDetector();
  });

  describe('detectLanguage', () => {
    it('should detect Indonesian text', () => {
      const indonesianText =
        'Sistem ini digunakan untuk mengelola data pengguna dengan menggunakan aplikasi yang telah dibuat';
      const result = detector.detectLanguage(indonesianText);
      expect(result).toBe('id');
    });

    it('should detect English text', () => {
      const englishText =
        'This system is used to manage user data using the application that has been created';
      const result = detector.detectLanguage(englishText);
      expect(result).toBe('en');
    });

    it('should detect mixed language text', () => {
      const mixedText =
        'Sistem ini digunakan untuk manage user data dengan menggunakan application yang telah dibuat';
      const result = detector.detectLanguage(mixedText);
      expect(result).toBe('mixed');
    });

    it('should return unknown for empty text', () => {
      const result = detector.detectLanguage('');
      expect(result).toBe('unknown');
    });

    it('should return unknown for text without recognizable keywords', () => {
      const unknownText = 'xyz abc 123 test data';
      const result = detector.detectLanguage(unknownText);
      expect(result).toBe('unknown');
    });

    it('should handle very short text', () => {
      const shortText = 'data';
      const result = detector.detectLanguage(shortText);
      expect(result).toBe('unknown');
    });
  });

  describe('analyzeLanguageDistribution', () => {
    it('should analyze distribution across multiple texts', () => {
      const texts = [
        'Sistem ini digunakan untuk mengelola data',
        'This system is used to manage information',
        'Aplikasi ini menggunakan user interface yang baik',
        'The application provides good user experience',
        'Process data menggunakan sistem yang telah dibuat',
      ];

      const distribution = detector.analyzeLanguageDistribution(texts);

      expect(distribution.id).toBeGreaterThan(0);
      expect(distribution.en).toBeGreaterThan(0);
      expect(distribution.mixed).toBeGreaterThan(0);
      expect(distribution.id + distribution.en + distribution.mixed + distribution.unknown).toBe(5);
    });

    it('should handle empty array', () => {
      const distribution = detector.analyzeLanguageDistribution([]);
      expect(distribution).toEqual({ en: 0, id: 0, mixed: 0, unknown: 0 });
    });
  });

  describe('getLanguageConfidence', () => {
    it('should provide confidence for Indonesian detection', () => {
      const indonesianText =
        'Sistem ini digunakan untuk mengelola data pengguna dengan proses yang baik';
      const result = detector.getLanguageConfidence(indonesianText);

      expect(result.language).toBe('id');
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.indonesianRatio).toBeGreaterThan(0);
      expect(result.englishRatio).toBeLessThan(0.1);
    });

    it('should provide confidence for English detection', () => {
      const englishText = 'This system is used to manage user data with a good process';
      const result = detector.getLanguageConfidence(englishText);

      expect(result.language).toBe('en');
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.englishRatio).toBeGreaterThan(0);
      expect(result.indonesianRatio).toBeLessThan(0.1);
    });

    it('should provide confidence for mixed language', () => {
      const mixedText =
        'Sistem ini digunakan untuk manage user data dengan proses yang telah been created';
      const result = detector.getLanguageConfidence(mixedText);

      expect(result.language).toBe('mixed');
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.indonesianRatio).toBeGreaterThan(0.1);
      expect(result.englishRatio).toBeGreaterThan(0.1);
    });

    it('should return zero confidence for unknown text', () => {
      const unknownText = 'xyz abc 123 test';
      const result = detector.getLanguageConfidence(unknownText);

      expect(result.language).toBe('unknown');
      expect(result.confidence).toBe(0);
      expect(result.indonesianRatio).toBe(0);
      expect(result.englishRatio).toBe(0);
    });
  });
});
