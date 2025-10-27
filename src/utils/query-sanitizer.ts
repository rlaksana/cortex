/**
 * Query Sanitizer - Progressive query cleaning for qdrant tsquery compatibility
 *
 * Handles syntax errors by detecting and removing problematic characters
 * while preserving query intent through intelligent sanitization strategies.
 */

/**
 * Types and Interfaces
 */

export type SanitizationLevel = 'basic' | 'moderate' | 'aggressive';

export interface SanitizationResult {
  cleaned: string;
  original: string;
  transformations: string[];
  level: SanitizationLevel;
  patterns_detected: string[];
  auto_fixes_applied: string[];
}

export interface PatternDetection {
  pattern: RegExp;
  name: string;
  handler: (_match: string) => string;
  description: string;
}

/**
 * Pattern Detection Registry
 *
 * Detects problematic character patterns that cause tsquery errors
 * and provides appropriate transformation functions.
 */

const PATTERN_DETECTION: PatternDetection[] = [
  // Task ID ranges: T008-T021 → T008 T021
  {
    pattern: /\bT\d+-T\d+\b/g,
    name: 'task_id_range',
    handler: (match: string) => match.replace(/-/g, ' '),
    description: 'Convert task ID ranges to space-separated format',
  },
  // Version/Phase numbers: Phase-2 → Phase 2
  {
    pattern: /\b(?:Phase|Version|Release)\s*-\s*(\d+)/gi,
    name: 'version_numbers',
    handler: (match: string) => match.replace(/-/g, ' '),
    description: 'Normalize version/phase number formatting',
  },
  // Multiple hyphenated phrases
  {
    pattern: /([a-zA-Z])\s*-\s*([a-zA-Z])/g,
    name: 'hyphenated_words',
    handler: (match: string) => match.replace(/-/g, ' '),
    description: 'Convert hyphenated words to spaces',
  },
  // Common typos - double letters
  {
    pattern: /\b([a-zA-Z])\1{2,}([a-zA-Z])\b/g,
    name: 'double_letters',
    handler: (match: string) => match.replace(/(.)\1+/g, '$1'),
    description: 'Fix excessive repeated letters',
  },
  // Common English misspellings
  {
    pattern: /\b(deduplication|deduplicattion|deduplikation|deduplikasyon)\b/gi,
    name: 'deduplication_typos',
    handler: (_match: string) => 'deduplication',
    description: 'Fix deduplication spelling variations',
  },
  {
    pattern: /\b(authentikation|authentikation|authentification)\b/gi,
    name: 'authentication_typos',
    handler: (_match: string) => 'authentication',
    description: 'Fix authentication spelling variations',
  },
  {
    pattern: /\b(documantation|documentaion|documentation)\b/gi,
    name: 'documentation_typos',
    handler: (_match: string) => 'documentation',
    description: 'Fix documentation spelling variations',
  },
  {
    pattern: /\b(implementaton|implimentation|implementtion)\b/gi,
    name: 'implementation_typos',
    handler: (_match: string) => 'implementation',
    description: 'Fix implementation spelling variations',
  },
  // Word boundaries with common suffix errors
  {
    pattern: /\b(\w+)(tion|sion|ment|ness|ity|er|or|ist|ism)\b\1/gi,
    name: 'repeated_words',
    handler: (match: string) => match.replace(/\b(\w+)\b\1/gi, '$1'),
    description: 'Fix repeated words',
  },
  // Special characters that break tsquery
  {
    pattern: /[^\w\s.,:;!?-]/g,
    name: 'special_chars',
    handler: (_match: string) => '',
    description: 'Remove problematic special characters',
  },
];

/**
 * Core Sanitization Functions
 */

/**
 * Detect problematic patterns in query
 */
export function detectProblematicPatterns(query: string): string[] {
  const detectedPatterns: string[] = [];

  for (const detection of PATTERN_DETECTION) {
    if (detection.pattern.test(query)) {
      detectedPatterns.push(detection.name);
    }
  }

  return detectedPatterns;
}

/**
 * Apply sanitization with specified level
 */
export function sanitizeQuery(
  query: string,
  level: SanitizationLevel = 'basic'
): SanitizationResult {
  const transformations: string[] = [];
  const auto_fixes_applied: string[] = [];
  const patterns_detected: string[] = detectProblematicPatterns(query);

  let cleaned = query.trim();

  // Basic Level: Minimal, necessary cleaning
  if (level === 'basic' || level === 'moderate' || level === 'aggressive') {
    // Basic whitespace normalization
    cleaned = cleaned.replace(/\s+/g, ' ').trim();
    transformations.push('normalized_whitespace');
  }

  // Moderate Level: Handle common problematic patterns
  if (level === 'moderate' || level === 'aggressive') {
    cleaned = applyPatternDetections(
      cleaned,
      [
        'task_id_range',
        'version_numbers',
        'hyphenated_words',
        'double_letters',
        'deduplication_typos',
        'authentication_typos',
        'documentation_typos',
        'implementation_typos',
        'repeated_words',
        'special_chars'
      ],
      auto_fixes_applied
    );
    transformations.push('moderate_sanitization');
  }

  // Aggressive Level: Maximum cleaning
  if (level === 'aggressive') {
    cleaned = extractCoreKeywords(cleaned, 10); // Keep only top 10 keywords
    transformations.push('aggressive_sanitization');
  }

  // Final cleanup: remove extra spaces after processing
  cleaned = cleaned.replace(/\s+/g, ' ').trim();

  return {
    cleaned,
    original: query,
    transformations,
    level,
    patterns_detected,
    auto_fixes_applied,
  };
}

/**
 * Apply specified pattern detections to query
 */
function applyPatternDetections(
  query: string,
  targetPatterns: string[],
  auto_fixes_applied: string[]
): string {
  let cleaned = query;

  for (const detection of PATTERN_DETECTION) {
    if (targetPatterns.includes(detection.name)) {
      const before = cleaned;
      cleaned = detection.handler(cleaned);

      // Track what was applied
      if (before !== cleaned) {
        auto_fixes_applied.push(detection.description);
      }
    }
  }

  return cleaned;
}

/**
 * Extract core keywords, removing stop words
 */
export function extractCoreKeywords(query: string, maxWords: number = 5): string {
  const stopWords = [
    'the',
    'a',
    'an',
    'and',
    'or',
    'but',
    'in',
    'on',
    'at',
    'to',
    'for',
    'of',
    'with',
    'by',
    'as',
    'is',
    'was',
    'are',
    'were',
  ];

  const words = query
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => {
      // Remove empty words
      if (!word || word.length < 2) return false;

      // Remove stop words
      if (stopWords.includes(word.toLowerCase())) return false;

      // Remove words that are mostly numbers (unless part of a meaningful pattern)
      if (/^\d+$/.test(word) && query.split(/\s+/).length > 5) return false;

      return true;
    })
    .slice(0, maxWords);

  return words.join(' ');
}

/**
 * Smart level selection based on query content
 */
export function suggestSanitizationLevel(query: string): SanitizationLevel {
  const problematicPatterns = detectProblematicPatterns(query);

  // If no problematic patterns detected, basic level is sufficient
  if (problematicPatterns.length === 0) {
    return 'basic';
  }

  // If task ID ranges or version patterns are detected, moderate level
  if (
    problematicPatterns.includes('task_id_range') ||
    problematicPatterns.includes('version_numbers')
  ) {
    return 'moderate';
  }

  // If many special characters or very complex patterns, aggressive level
  if (problematicPatterns.length > 3) {
    return 'aggressive';
  }

  // Default to moderate for most cases
  return 'moderate';
}

/**
 * Utility: Check if query likely to cause tsquery errors
 */
export function isLikelyToCauseTsqueryError(query: string): boolean {
  const problematicChars = /[^\w\s.,:;!?-]/;
  return problematicChars.test(query) || /\bT\d+-\d+\b/.test(query);
}

/**
 * Generate user-friendly feedback message
 */
export function generateSanitizationFeedback(result: SanitizationResult): string {
  const { original, cleaned, transformations, auto_fixes_applied, patterns_detected } = result;

  if (transformations.length === 0) {
    return 'Query contains no problematic characters.';
  }

  let message = `Query auto-corrected: "${original}" → "${cleaned}"`;

  if (auto_fixes_applied.length > 0) {
    message += `\nApplied fixes: ${auto_fixes_applied.join(', ')}`;
  }

  if (patterns_detected.length > 0) {
    message += `\nDetected patterns: ${patterns_detected.join(', ')}`;
  }

  return message;
}

/**
 * Advanced: Multiple sanitization levels for comparison
 */
export function generateSanitizationOptions(query: string): {
  basic: SanitizationResult;
  moderate: SanitizationResult;
  aggressive: SanitizationResult;
} {
  return {
    basic: sanitizeQuery(query, 'basic'),
    moderate: sanitizeQuery(query, 'moderate'),
    aggressive: sanitizeQuery(query, 'aggressive'),
  };
}
