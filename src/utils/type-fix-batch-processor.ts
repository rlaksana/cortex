/**
 * Type Fix Batch Processor
 *
 * Utility for batch processing and fixing similar type assignment patterns
 * across the codebase. Provides systematic approach to applying fixes
 * while maintaining code quality and reducing errors.
 *
 * @author Cortex Team
 * @version 1.0.0
 */

import { basename, extname, join } from 'path';
import { readFileSync, writeFileSync } from 'fs';
import { asPointIdArray, asPerformanceMetric, asDatabaseConfig, asUser, asSearchQuery } from './type-conversion';
import {
  assertPerformanceMetric,
  assertPointIdArray,
  assertQdrantDatabaseConfig,
  assertUser,
  assertSearchQuery,
} from './type-assertions';

// ============================================================================
// Fix Pattern Definitions
// ============================================================================

export interface FixPattern {
  name: string;
  description: string;
  priority: 'high' | 'medium' | 'low';
  files: string[];
  apply: (content: string, filePath: string) => string;
  validate?: (content: string) => boolean;
}

export interface BatchProcessingResult {
  totalFiles: number;
  processedFiles: number;
  fixedFiles: number;
  errors: Array<{ file: string; error: string }>;
  patterns: Array<{
    name: string;
    applied: boolean;
    filesAffected: number;
  }>;
}

// ============================================================================
// Pattern Implementations
// ============================================================================

/**
 * Pattern 1: Unknown to PerformanceMetric conversions
 */
export const fixUnknownToPerformanceMetric: FixPattern = {
  name: 'unknown-to-performance-metric',
  description: 'Convert unknown type assignments to PerformanceMetric with proper validation',
  priority: 'high',
  files: [
    'src/db/qdrant-backup-integration.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Pattern: this.monitoring!.recordMetric({ unknownObject })
    modified = modified.replace(
      /(this\.monitoring!\.recordMetric\()([^)]+)\)/g,
      (match, prefix, metricArg) => {
        // Check if metricArg is a direct object literal (already typed)
        if (metricArg.trim().startsWith('{')) {
          return match; // Skip, already properly typed
        }

        // Replace with conversion and assertion
        return `${prefix}{\n        const metric = ${metricArg};\n        assertPerformanceMetric(metric);\n        return metric;\n      }())`;
      }
    );

    // If no modifications were made above, try a simpler approach
    if (modified === content) {
      // Add import for assertion function at top if not present
      if (!modified.includes('assertPerformanceMetric')) {
        const importStatement = "import { assertPerformanceMetric } from '../utils/type-assertions';";
        if (modified.includes('import {') && !modified.includes(importStatement)) {
          modified = modified.replace(
            /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
            `$1\n${importStatement}\n`
          );
        }
      }

      // Add assertion before recordMetric calls
      modified = modified.replace(
        /(this\.monitoring!\.recordMetric\()([^)]+)\)([\s;])/g,
        (match, prefix, metricArg, suffix) => {
          if (metricArg.trim().startsWith('{')) {
            return match; // Skip object literals
          }
          return `{\n    const metric = ${metricArg};\n    assertPerformanceMetric(metric);\n    ${prefix}metric)${suffix}\n  }`;
        }
      );
    }

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('assertPerformanceMetric') &&
           !content.includes('unknown.*PerformanceMetric');
  },
};

/**
 * Pattern 2: String array to PointId array conversions
 */
export const fixStringArrayToPointIdArray: FixPattern = {
  name: 'string-array-to-point-id-array',
  description: 'Convert string array assignments to PointId array with proper conversion',
  priority: 'high',
  files: [
    'src/db/unified-database-layer-v2.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Add import for conversion function if not present
    if (!modified.includes('asPointIdArray')) {
      const importStatement = "import { asPointIdArray } from '../utils/type-conversion';";
      if (modified.includes('import {') && !modified.includes(importStatement)) {
        modified = modified.replace(
          /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
          `$1\n${importStatement}\n`
        );
      }
    }

    // Pattern: convert (ids as readonly string[]) to asPointIdArray(ids)
    modified = modified.replace(
      /\(ids\s+as\s+readonly\s+string\[\]\)/g,
      'asPointIdArray(ids)'
    );

    // Pattern: convert similar patterns with different variable names
    modified = modified.replace(
      /\(([^)]+)\s+as\s+readonly\s+string\[\]\)/g,
      (match, varName) => {
        if (varName.trim() === 'ids' || varName.trim().includes('id')) {
          return `asPointIdArray(${varName.trim()})`;
        }
        return match;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('asPointIdArray') &&
           !content.includes('readonly string[].*readonly PointId[]');
  },
};

/**
 * Pattern 3: Unknown to QdrantDatabaseConfig conversions
 */
export const fixUnknownToQdrantDatabaseConfig: FixPattern = {
  name: 'unknown-to-qdrant-config',
  description: 'Convert unknown assignments to QdrantDatabaseConfig with validation',
  priority: 'high',
  files: [
    'src/db/unified-database-layer-v2.ts',
    'src/db/qdrant-pooled-client.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Add imports if not present
    const neededImports = [
      "asQdrantDatabaseConfig",
      "assertQdrantDatabaseConfig"
    ];

    for (const importName of neededImports) {
      if (!modified.includes(importName)) {
        const sourceFile = importName.startsWith('as') ? 'type-conversion' : 'type-assertions';
        const importStatement = `import { ${importName} } from '../utils/${sourceFile}';`;

        if (modified.includes('import {') && !modified.includes(importStatement)) {
          modified = modified.replace(
            /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
            `$1\n${importStatement}\n`
          );
        }
      }
    }

    // Pattern: convert unknown config to validated config
    modified = modified.replace(
      /const\s+config\s*=\s*([^;]+);(\s*assertQdrantDatabaseConfig\(config\);)?/g,
      (match, configSource, existingAssertion) => {
        if (existingAssertion) {
          return match; // Already has assertion
        }
        return `const config = ${configSource};\n    assertQdrantDatabaseConfig(config);`;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('assertQdrantDatabaseConfig') &&
           !content.includes('unknown.*QdrantDatabaseConfig');
  },
};

/**
 * Pattern 4: User type compatibility fixes
 */
export const fixUserTypeCompatibility: FixPattern = {
  name: 'user-type-compatibility',
  description: 'Fix User type incompatibilities between different modules',
  priority: 'medium',
  files: [
    'src/di/adapters/auth-service-adapter.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Add import for user conversion if not present
    if (!modified.includes('asUser')) {
      const importStatement = "import { asUser } from '../../utils/type-conversion';";
      if (modified.includes('import {') && !modified.includes(importStatement)) {
        modified = modified.replace(
          /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
          `$1\n${importStatement}\n`
        );
      }
    }

    // Pattern: convert user objects to ensure compatibility
    modified = modified.replace(
      /(\w+User[^=]*=)([^;]+);/g,
      (match, prefix, userSource) => {
        if (userSource.includes('asUser') || userSource.trim().startsWith('{')) {
          return match; // Already converted or object literal
        }
        return `${prefix} asUser(${userSource});`;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('asUser') &&
           !content.includes('User.*not assignable.*User');
  },
};

/**
 * Pattern 5: SearchQuery type compatibility
 */
export const fixSearchQueryCompatibility: FixPattern = {
  name: 'search-query-compatibility',
  description: 'Fix SearchQuery type incompatibilities between different modules',
  priority: 'medium',
  files: [
    'src/di/adapters/memory-find-orchestrator-adapter.ts',
    'src/main-di.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Add import for search query conversion if not present
    if (!modified.includes('asSearchQuery')) {
      const importStatement = "import { asSearchQuery } from '../../utils/type-conversion';";
      if (modified.includes('import {') && !modified.includes(importStatement)) {
        modified = modified.replace(
          /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
          `$1\n${importStatement}\n`
        );
      }
    }

    // Pattern: convert search query objects to ensure compatibility
    modified = modified.replace(
      /(\w+Query[^=]*=)([^;]+);/g,
      (match, prefix, querySource) => {
        if (querySource.includes('asSearchQuery') || querySource.trim().startsWith('{')) {
          return match; // Already converted or object literal
        }
        return `${prefix} asSearchQuery(${querySource});`;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('asSearchQuery') &&
           !content.includes('SearchQuery.*not assignable.*SearchQuery');
  },
};

/**
 * Pattern 6: Generic constraint violations
 */
export const fixGenericConstraintViolations: FixPattern = {
  name: 'generic-constraint-fixes',
  description: 'Fix generic parameter constraint violations in DI container',
  priority: 'medium',
  files: [
    'src/di/enhanced-di-container.ts',
    'src/factories/factory-registry.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Pattern: fix generic service registration constraints
    modified = modified.replace(
      /register<T>\([^,]+,\s*factory:\s*EnhancedServiceRegistration<unknown>/g,
      'register<T>(token: string, factory: EnhancedServiceRegistration<T>'
    );

    // Pattern: fix generic type parameter mismatches
    modified = modified.replace(
      /QueuedRequest<T>.*QueuedRequest<unknown>/g,
      'QueuedRequest<unknown>'
    );

    // Pattern: fix service factory type constraints
    modified = modified.replace(
      /\(container:\s*DIContainer\)\s*=>\s*[^{]+\s*{\s*[^}]*\}/g,
      (match) => {
        // Check if this is a service factory that needs typing
        if (match.includes('validate') || match.includes('ConfigService')) {
          return match; // Skip complex cases for manual review
        }
        return match;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return !content.includes('EnhancedServiceRegistration<unknown>') &&
           !content.includes('QueuedRequest<T>.*QueuedRequest<unknown>');
  },
};

/**
 * Pattern 7: OperationType assertion fixes
 */
export const fixOperationTypeAssertions: FixPattern = {
  name: 'operation-type-assertions',
  description: 'Add proper OperationType assertions for unknown values',
  priority: 'medium',
  files: [
    'src/di/adapters/metrics-service-adapter.ts',
  ],
  apply: (content: string, filePath: string): string => {
    let modified = content;

    // Add import for operation type assertion if not present
    if (!modified.includes('assertOperationType')) {
      const importStatement = "import { assertOperationType } from '../../utils/type-assertions';";
      if (modified.includes('import {') && !modified.includes(importStatement)) {
        modified = modified.replace(
          /(import\s*\{[^}]*\}\s*from\s*['"][^'"]*['"];?\s*)/,
          `$1\n${importStatement}\n`
        );
      }
    }

    // Pattern: add assertion for operation type parameters
    modified = modified.replace(
      /operationType:\s*(\w+)/g,
      (match, varName) => {
        if (varName === 'unknown') {
          return match; // Skip the unknown literal itself
        }
        return `{\n      const opType = ${varName};\n      assertOperationType(opType);\n      operationType: opType\n    }`;
      }
    );

    return modified;
  },
  validate: (content: string): boolean => {
    return content.includes('assertOperationType') &&
           !content.includes('unknown.*OperationType');
  },
};

// ============================================================================
// Batch Processor
// ============================================================================

export class TypeFixBatchProcessor {
  private patterns: FixPattern[] = [
    fixUnknownToPerformanceMetric,
    fixStringArrayToPointIdArray,
    fixUnknownToQdrantDatabaseConfig,
    fixUserTypeCompatibility,
    fixSearchQueryCompatibility,
    fixGenericConstraintViolations,
    fixOperationTypeAssertions,
  ];

  /**
   * Process all patterns on specified files
   */
  async processFiles(filePaths: string[]): Promise<BatchProcessingResult> {
    const result: BatchProcessingResult = {
      totalFiles: filePaths.length,
      processedFiles: 0,
      fixedFiles: 0,
      errors: [],
      patterns: this.patterns.map(p => ({ name: p.name, applied: false, filesAffected: 0 })),
    };

    for (const filePath of filePaths) {
      try {
        const fileResult = await this.processFile(filePath);
        result.processedFiles++;

        if (fileResult.modified) {
          result.fixedFiles++;
        }

        if (fileResult.errors.length > 0) {
          result.errors.push(...fileResult.errors);
        }

        // Update pattern results
        fileResult.appliedPatterns.forEach(patternName => {
          const patternResult = result.patterns.find(p => p.name === patternName);
          if (patternResult) {
            patternResult.applied = true;
            patternResult.filesAffected++;
          }
        });
      } catch (error) {
        result.errors.push({
          file: filePath,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return result;
  }

  /**
   * Process a single file with all applicable patterns
   */
  private async processFile(filePath: string): Promise<{
    modified: boolean;
    appliedPatterns: string[];
    errors: Array<{ file: string; error: string }>;
  }> {
    let content: string;
    let originalContent: string;
    let modified = false;
    const appliedPatterns: string[] = [];
    const errors: Array<{ file: string; error: string }> = [];

    try {
      content = readFileSync(filePath, 'utf-8');
      originalContent = content;
    } catch (error) {
      throw new Error(`Failed to read file ${filePath}: ${error}`);
    }

    // Apply each relevant pattern
    for (const pattern of this.patterns) {
      // Skip patterns that don't apply to this file
      if (!this.patternAppliesToFile(pattern, filePath)) {
        continue;
      }

      try {
        const beforePattern = content;
        content = pattern.apply(content, filePath);

        // Check if pattern was actually applied
        if (content !== beforePattern) {
          modified = true;
          appliedPatterns.push(pattern.name);

          // Validate the fix if validation is provided
          if (pattern.validate && !pattern.validate(content)) {
            errors.push({
              file: filePath,
              error: `Pattern validation failed for ${pattern.name} after application`,
            });
            // Revert to original content for this pattern
            content = beforePattern;
          }
        }
      } catch (error) {
        errors.push({
          file: filePath,
          error: `Error applying pattern ${pattern.name}: ${error instanceof Error ? error.message : String(error)}`,
        });
        // Continue with other patterns even if one fails
      }
    }

    // Write file back if modifications were made
    if (modified) {
      try {
        writeFileSync(filePath, content, 'utf-8');
      } catch (error) {
        throw new Error(`Failed to write file ${filePath}: ${error}`);
      }
    }

    return {
      modified,
      appliedPatterns,
      errors,
    };
  }

  /**
   * Check if a pattern applies to a specific file
   */
  private patternAppliesToFile(pattern: FixPattern, filePath: string): boolean {
    const fileName = basename(filePath);

    // Check exact file matches
    if (pattern.files.includes(fileName)) {
      return true;
    }

    // Check path matches
    return pattern.files.some(patternFile => filePath.includes(patternFile));
  }

  /**
   * Add a custom pattern to the processor
   */
  addPattern(pattern: FixPattern): void {
    this.patterns.push(pattern);
  }

  /**
   * Get all registered patterns
   */
  getPatterns(): FixPattern[] {
    return [...this.patterns];
  }

  /**
   * Filter patterns by priority
   */
  getPatternsByPriority(priority: 'high' | 'medium' | 'low'): FixPattern[] {
    return this.patterns.filter(p => p.priority === priority);
  }

  /**
   * Get patterns that apply to a specific file
   */
  getPatternsForFile(filePath: string): FixPattern[] {
    return this.patterns.filter(pattern => this.patternAppliesToFile(pattern, filePath));
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Process all TypeScript files in the project
 */
export async function processAllTypeScriptFiles(
  rootDir: string = 'src'
): Promise<BatchProcessingResult> {
  const processor = new TypeFixBatchProcessor();

  // Get all TypeScript files (this would typically use a proper file system walker)
  const { execSync } = require('child_process');
  const files = execSync(`find ${rootDir} -name "*.ts" -type f`, { encoding: 'utf-8' })
    .split('\n')
    .filter(Boolean)
    .filter((file: string) => !file.includes('.test.ts') && !file.includes('.spec.ts'));

  return processor.processFiles(files);
}

/**
 * Process specific files based on error patterns
 */
export async function processErrorFiles(errorFiles: string[]): Promise<BatchProcessingResult> {
  const processor = new TypeFixBatchProcessor();
  return processor.processFiles(errorFiles);
}

/**
 * Apply only high-priority fixes
 */
export async function applyHighPriorityFixes(
  filePaths: string[]
): Promise<BatchProcessingResult> {
  const processor = new TypeFixBatchProcessor();
  const highPriorityPatterns = processor.getPatternsByPriority('high');

  // Create a temporary processor with only high-priority patterns
  const highPriorityProcessor = new TypeFixBatchProcessor();
  highPriorityPatterns.forEach(pattern => highPriorityProcessor.addPattern(pattern));

  return highPriorityProcessor.processFiles(filePaths);
}