/**
 * Singleton Migration Helper
 *
 * Provides tools and patterns to migrate from singleton patterns
 * to dependency injection. Includes automated detection and
 * refactoring suggestions.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { ServiceType } from './service-interfaces.js';
import { ServiceTokens } from './service-interfaces.js';

/**
 * Singleton usage pattern detected
 */
export interface SingletonUsage {
  file: string;
  line: number;
  pattern: string;
  singletonType: 'classic' | 'static-getter' | 'exported-instance' | 'global-variable';
  suggestedReplacement: string;
  complexity: 'low' | 'medium' | 'high';
}

/**
 * Migration plan for singleton refactoring
 */
export interface MigrationPlan {
  singletons: SingletonUsage[];
  estimatedEffort: {
    low: number;
    medium: number;
    high: number;
  };
  recommendedOrder: string[];
  risks: Array<{
    type: 'circular-dependency' | 'runtime-error' | 'performance' | 'test-compatibility';
    description: string;
    mitigation: string;
  }>;
}

/**
 * Singleton migration patterns and their replacements
 */
const MIGRATION_PATTERNS = [
  {
    pattern: /Environment\.getInstance\(\)/g,
    replacement: 'serviceLocator.config',
    singletonType: 'static-getter' as const,
    complexity: 'low' as const,
    serviceToken: ServiceTokens.CONFIG_SERVICE,
  },
  {
    pattern: /DatabaseFactory\.getInstance\(\)/g,
    replacement: 'serviceLocator.databaseService',
    singletonType: 'static-getter' as const,
    complexity: 'medium' as const,
    serviceToken: ServiceTokens.DATABASE_SERVICE,
  },
  {
    pattern: /databaseFactory/g,
    replacement: 'serviceLocator.databaseService',
    singletonType: 'exported-instance' as const,
    complexity: 'medium' as const,
    serviceToken: ServiceTokens.DATABASE_SERVICE,
  },
  {
    pattern: /performanceMonitor/g,
    replacement: 'serviceLocator.performanceMonitor',
    singletonType: 'exported-instance' as const,
    complexity: 'low' as const,
    serviceToken: ServiceTokens.PERFORMANCE_MONITOR,
  },
  {
    pattern: /metricsService/g,
    replacement: 'serviceLocator.metricsService',
    singletonType: 'exported-instance' as const,
    complexity: 'low' as const,
    serviceToken: ServiceTokens.METRICS_SERVICE,
  },
  {
    pattern: /logger/g,
    replacement: 'serviceLocator.logger',
    singletonType: 'global-variable' as const,
    complexity: 'low' as const,
    serviceToken: ServiceTokens.LOGGER_SERVICE,
  },
  {
    pattern: /authService/g,
    replacement: 'serviceLocator.authService',
    singletonType: 'exported-instance' as const,
    complexity: 'medium' as const,
    serviceToken: ServiceTokens.AUTH_SERVICE,
  },
  {
    pattern: /auditService/g,
    replacement: 'serviceLocator.auditService',
    singletonType: 'exported-instance' as const,
    complexity: 'low' as const,
    serviceToken: ServiceTokens.AUDIT_SERVICE,
  },
];

/**
 * Singleton migration analyzer
 */
export class SingletonMigrationAnalyzer {
  /**
   * Analyze a file for singleton usage patterns
   */
  analyzeFile(filePath: string, content: string): SingletonUsage[] {
    const usages: SingletonUsage[] = [];
    const lines = content.split('\n');

    for (const pattern of MIGRATION_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (pattern.pattern.test(line)) {
          usages.push({
            file: filePath,
            line: i + 1,
            pattern: line.trim(),
            singletonType: pattern.singletonType,
            suggestedReplacement: line.replace(pattern.pattern, pattern.replacement),
            complexity: pattern.complexity,
          });
        }
      }
    }

    return usages;
  }

  /**
   * Create migration plan from analyzed singletons
   */
  createMigrationPlan(singletons: SingletonUsage[]): MigrationPlan {
    const effort = singletons.reduce(
      (acc, singleton) => {
        acc[singleton.complexity]++;
        return acc;
      },
      { low: 0, medium: 0, high: 0 }
    );

    // Group by file for recommended migration order
    const fileGroups = new Map<string, SingletonUsage[]>();
    for (const singleton of singletons) {
      if (!fileGroups.has(singleton.file)) {
        fileGroups.set(singleton.file, []);
      }
      fileGroups.get(singleton.file)!.push(singleton);
    }

    // Sort files by complexity (low complexity first)
    const recommendedOrder = Array.from(fileGroups.entries())
      .sort(([, a], [, b]) => {
        const aComplexity = this.getComplexityScore(a);
        const bComplexity = this.getComplexityScore(b);
        return aComplexity - bComplexity;
      })
      .map(([file]) => file);

    // Identify potential risks
    const risks = this.identifyRisks(singletons);

    return {
      singletons,
      estimatedEffort: effort,
      recommendedOrder,
      risks,
    };
  }

  /**
   * Generate refactored code for a file
   */
  generateRefactoredCode(content: string, usages: SingletonUsage[]): string {
    let refactored = content;

    // Add service locator import if needed
    if (usages.length > 0 && !refactored.includes('serviceLocator')) {
      refactored = this.addServiceLocatorImport(refactored);
    }

    // Apply replacements
    for (const usage of usages) {
      const pattern = MIGRATION_PATTERNS.find((p) => p.pattern.test(usage.pattern));
      if (pattern) {
        refactored = refactored.replace(pattern.pattern, pattern.replacement);
      }
    }

    return refactored;
  }

  /**
   * Generate constructor injection version
   */
  generateConstructorInjectionVersion(
    className: string,
    originalCode: string,
    requiredServices: ServiceType[]
  ): string {
    const constructorParams = requiredServices
      .map((token) => {
        const serviceName = this.getServiceName(token);
        return `private ${serviceName}: ${this.getServiceInterfaceName(token)}`;
      })
      .join(',\n    ');

    const constructorCode = `
  constructor(
    ${constructorParams}
  ) {}`;

    // Find the existing constructor and replace it
    const constructorRegex = /constructor\s*\([^)]*\)\s*\{[^}]*\}/;
    if (constructorRegex.test(originalCode)) {
      return originalCode.replace(constructorRegex, constructorCode.trim());
    }

    // Add constructor after class declaration
    const classRegex = new RegExp(`class\\s+${className}\\s*\\{`);
    const match = originalCode.match(classRegex);
    if (match) {
      const insertIndex = match.index! + match[0].length;
      return originalCode.slice(0, insertIndex) + constructorCode + originalCode.slice(insertIndex);
    }

    return originalCode;
  }

  /**
   * Identify migration risks
   */
  private identifyRisks(singletons: SingletonUsage[]): MigrationPlan['risks'] {
    const risks: MigrationPlan['risks'] = [];

    // Check for circular dependency risks
    const serviceDependencies = new Map<ServiceType, ServiceType[]>();
    for (const singleton of singletons) {
      const pattern = MIGRATION_PATTERNS.find((p) => p.pattern.test(singleton.pattern));
      if (pattern) {
        const dependencies = serviceDependencies.get(pattern.serviceToken) || [];
        dependencies.push(pattern.serviceToken);
        serviceDependencies.set(pattern.serviceToken, dependencies);
      }
    }

    // Check for multiple singleton usage in single files
    const fileUsages = new Map<string, number>();
    for (const singleton of singletons) {
      fileUsages.set(singleton.file, (fileUsages.get(singleton.file) || 0) + 1);
    }

    for (const [file, count] of fileUsages) {
      if (count > 3) {
        risks.push({
          type: 'circular-dependency',
          description: `File ${file} uses ${count} different singletons`,
          mitigation: 'Consider using a facade pattern or breaking into smaller services',
        });
      }
    }

    // Check for high complexity migrations
    const highComplexityUsages = singletons.filter((s) => s.complexity === 'high');
    if (highComplexityUsages.length > 0) {
      risks.push({
        type: 'runtime-error',
        description: `${highComplexityUsages.length} high complexity singleton usages found`,
        mitigation: 'Test thoroughly and consider gradual migration with feature flags',
      });
    }

    return risks;
  }

  /**
   * Get complexity score for a group of singletons
   */
  private getComplexityScore(singletons: SingletonUsage[]): number {
    const scores = { low: 1, medium: 3, high: 5 };
    return singletons.reduce((total, singleton) => total + scores[singleton.complexity], 0);
  }

  /**
   * Add service locator import to code
   */
  private addServiceLocatorImport(content: string): string {
    if (content.includes('import { serviceLocator }')) {
      return content;
    }

    const importStatement = "import { serviceLocator } from '../di/service-locator.js';";

    // Find the last import statement
    const importRegex = /import\s+.*?from\s+['"][^'"]*['"];?/g;
    const imports = content.match(importRegex);

    if (imports && imports.length > 0) {
      const lastImport = imports[imports.length - 1];
      const lastIndex = content.lastIndexOf(lastImport);
      const insertIndex = lastIndex + lastImport.length;

      return content.slice(0, insertIndex) + '\n' + importStatement + content.slice(insertIndex);
    }

    // If no imports found, add at the top
    return importStatement + '\n\n' + content;
  }

  /**
   * Get service name from token
   */
  private getServiceName(token: ServiceType): string {
    const tokenMap = {
      [ServiceTokens.CONFIG_SERVICE]: 'configService',
      [ServiceTokens.LOGGER_SERVICE]: 'logger',
      [ServiceTokens.DATABASE_SERVICE]: 'databaseService',
      [ServiceTokens.AUTH_SERVICE]: 'authService',
      [ServiceTokens.METRICS_SERVICE]: 'metricsService',
      [ServiceTokens.PERFORMANCE_MONITOR]: 'performanceMonitor',
      [ServiceTokens.MEMORY_STORE_ORCHESTRATOR]: 'memoryStoreOrchestrator',
      [ServiceTokens.MEMORY_FIND_ORCHESTRATOR]: 'memoryFindOrchestrator',
    };

    return tokenMap[token] || 'service';
  }

  /**
   * Get service interface name from token
   */
  private getServiceInterfaceName(token: ServiceType): string {
    const interfaceMap = {
      [ServiceTokens.CONFIG_SERVICE]: 'IConfigService',
      [ServiceTokens.LOGGER_SERVICE]: 'ILoggerService',
      [ServiceTokens.DATABASE_SERVICE]: 'IDatabaseService',
      [ServiceTokens.AUTH_SERVICE]: 'IAuthService',
      [ServiceTokens.METRICS_SERVICE]: 'IMetricsService',
      [ServiceTokens.PERFORMANCE_MONITOR]: 'IPerformanceMonitor',
      [ServiceTokens.MEMORY_STORE_ORCHESTRATOR]: 'IMemoryStoreOrchestrator',
      [ServiceTokens.MEMORY_FIND_ORCHESTRATOR]: 'IMemoryFindOrchestrator',
    };

    return interfaceMap[token] || 'any';
  }
}

/**
 * Migration commands and utilities
 */
export class MigrationRunner {
  private analyzer = new SingletonMigrationAnalyzer();

  /**
   * Analyze entire codebase for singleton usage
   */
  async analyzeCodebase(): Promise<MigrationPlan> {
    // This would integrate with file system scanning tools
    // For now, return a placeholder implementation
    console.log('🔍 Analyzing codebase for singleton patterns...');

    // Simulate analysis results
    const mockSingletons: SingletonUsage[] = [
      {
        file: 'src/index.js',
        line: 123,
        pattern: 'const env = Environment.getInstance();',
        singletonType: 'static-getter',
        suggestedReplacement: 'const config = serviceLocator.config;',
        complexity: 'low',
      },
      {
        file: 'src/db/database-manager.js',
        line: 45,
        pattern: 'this.databaseFactory = DatabaseFactory.getInstance();',
        singletonType: 'static-getter',
        suggestedReplacement: 'this.databaseService = serviceLocator.databaseService;',
        complexity: 'medium',
      },
    ];

    return this.analyzer.createMigrationPlan(mockSingletons);
  }

  /**
   * Generate migration report
   */
  generateMigrationReport(plan: MigrationPlan): string {
    const totalSingletons = plan.singletons.length;
    const totalComplexity =
      plan.estimatedEffort.low + plan.estimatedEffort.medium * 3 + plan.estimatedEffort.high * 5;

    let report = `# Singleton Migration Report\n\n`;
    report += `## Summary\n`;
    report += `- Total singleton usages: ${totalSingletons}\n`;
    report += `- Estimated complexity points: ${totalComplexity}\n`;
    report += `- Low complexity: ${plan.estimatedEffort.low}\n`;
    report += `- Medium complexity: ${plan.estimatedEffort.medium}\n`;
    report += `- High complexity: ${plan.estimatedEffort.high}\n\n`;

    report += `## Recommended Migration Order\n\n`;
    for (const file of plan.recommendedOrder) {
      const usages = plan.singletons.filter((s) => s.file === file);
      report += `### ${file}\n`;
      for (const usage of usages) {
        report += `- Line ${usage.line}: \`${usage.pattern}\` → \`${usage.suggestedReplacement}\` (${usage.complexity})\n`;
      }
      report += `\n`;
    }

    if (plan.risks.length > 0) {
      report += `## Risks and Mitigations\n\n`;
      for (const risk of plan.risks) {
        report += `### ${risk.type.replace('-', ' ').toUpperCase()}\n`;
        report += `**Description:** ${risk.description}\n`;
        report += `**Mitigation:** ${risk.mitigation}\n\n`;
      }
    }

    return report;
  }

  /**
   * Create migration scripts
   */
  createMigrationScripts(plan: MigrationPlan): Map<string, string> {
    const scripts = new Map<string, string>();

    for (const file of plan.recommendedOrder) {
      const usages = plan.singletons.filter((s) => s.file === file);
      if (usages.length > 0) {
        scripts.set(
          file,
          `// Migration script for ${file}\n` +
            `// Run this script to migrate singleton usages\n\n` +
            `// TODO: Implement automated refactoring for this file\n`
        );
      }
    }

    return scripts;
  }
}
