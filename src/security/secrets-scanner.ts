// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue

/**
 * Secrets Scanner - P0-CRITICAL Implementation
 *
 * Comprehensive secrets detection and hygiene enforcement system.
 * Scans codebase for hardcoded secrets, API keys, and sensitive data.
 * Integrates with CI/CD pipelines to prevent secrets from being committed.
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { extname, join, relative } from 'path';

import { logger } from '@/utils/logger.js';

import { hasProperty } from '../utils/type-fixes.js';

/**
 * Secret pattern definitions with high precision matching
 */
export interface SecretPattern {
  name: string;
  description: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  examples: string[];
  remediation: string;
}

/**
 * Secret detection result
 */
export interface SecretFinding {
  file: string;
  line: number;
  column: number;
  match: string;
  pattern: SecretPattern;
  context: string[];
  confidence: number;
}

/**
 * Scan results summary
 */
export interface ScanResults {
  totalFiles: number;
  scannedFiles: number;
  findings: SecretFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  errors: string[];
  duration: number;
}

/**
 * P0-CRITICAL: Comprehensive secrets scanner
 */
export class SecretsScanner {
  private static readonly SECRET_PATTERNS: SecretPattern[] = [
    // OpenAI API Keys
    {
      name: 'OpenAI API Key',
      description: 'OpenAI API key detected',
      pattern: /sk-[A-Za-z0-9]{48}/g,
      severity: 'critical',
      examples: ['sk-1234567890abcdef1234567890abcdef12345678'],
      remediation: 'Remove the API key and use environment variable OPENAI_API_KEY',
    },

    // Qdrant API Keys
    {
      name: 'Qdrant API Key',
      description: 'Qdrant API key detected',
      pattern: /(?:qdrant[-_]?key|api[-_]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?/gi,
      severity: 'critical',
      examples: ['qdrant_api_key = "your-secret-key"', 'API_KEY: "abcdef123456"'],
      remediation: 'Remove the API key and use environment variable QDRANT_API_KEY',
    },

    // JWT Secrets
    {
      name: 'JWT Secret',
      description: 'JWT secret or private key detected',
      pattern:
        /(?:jwt[-_]?secret|private[-_]?key|secret[-_]?key)\s*[:=]\s*['\"]([A-Za-z0-9+/]{32,}={0,2})['\"]/gi,
      severity: 'critical',
      examples: ['JWT_SECRET = "your-secret-key"', 'private_key: "1234567890abcdef"'],
      remediation: 'Use environment variable JWT_SECRET or secure key management system',
    },

    // Generic API Keys
    {
      name: 'Generic API Key',
      description: 'Generic API key pattern detected',
      pattern: /(?:api[-_]?key|apikey|secret[-_]?key)\s*[:=]\s*['\"]([A-Za-z0-9_-]{16,})['\"]/gi,
      severity: 'high',
      examples: ['api_key = "abcdef123456"', 'SECRET_KEY: "secret123"'],
      remediation: 'Replace with environment variable or secure key management',
    },

    // Database URLs with credentials
    {
      name: 'Database URL with Credentials',
      description: 'Database connection string with embedded credentials',
      pattern: /(?:postgres|mysql|mongodb|mssql):\/\/[^:]+:[^@]+@[^\/]+/gi,
      severity: 'critical',
      examples: ['postgres://user:password@localhost:5432/db'],
      remediation: 'Use environment variables for database credentials',
    },

    // URLs with API keys in query parameters
    {
      name: 'URL with API Key Parameter',
      description: 'URL containing API key in query parameters',
      pattern:
        /https?:\/\/[^?]+\?(?:[^&]*&)*(?:api[-_]?key|apikey|token|access[-_]?token)=[^&\s]+/gi,
      severity: 'high',
      examples: ['https://api.example.com/data?api_key=secret123'],
      remediation: 'Move API key to request headers or environment variables',
    },

    // AWS Access Keys
    {
      name: 'AWS Access Key',
      description: 'AWS access key detected',
      pattern: /AKIA[0-9A-Z]{16}/g,
      severity: 'critical',
      examples: ['AKIA1234567890ABCDEF'],
      remediation: 'Use AWS IAM roles or environment variables',
    },

    // Google API Keys
    {
      name: 'Google API Key',
      description: 'Google API key detected',
      pattern: /AIza[0-9A-Za-z_-]{35}/g,
      severity: 'critical',
      examples: ['AIza1234567890abcdef1234567890abcdef'],
      remediation: 'Use environment variable GOOGLE_API_KEY',
    },

    // GitHub Tokens
    {
      name: 'GitHub Token',
      description: 'GitHub personal access token detected',
      pattern: /ghp_[A-Za-z0-9]{36}/g,
      severity: 'critical',
      examples: ['ghp_1234567890abcdef1234567890abcdef123456'],
      remediation: 'Use GitHub Actions secrets or environment variables',
    },

    // SSH Private Keys
    {
      name: 'SSH Private Key',
      description: 'SSH private key content detected',
      pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/g,
      severity: 'critical',
      examples: ['-----BEGIN RSA PRIVATE KEY-----'],
      remediation: 'Remove private keys from codebase and use secure key management',
    },

    // Certificate/Private Key patterns
    {
      name: 'Certificate or Private Key',
      description: 'SSL certificate or private key detected',
      pattern: /-----BEGIN\s+(CERTIFICATE|PRIVATE\s+KEY)-----/g,
      severity: 'critical',
      examples: ['-----BEGIN CERTIFICATE-----', '-----BEGIN PRIVATE KEY-----'],
      remediation: 'Remove certificates/keys from codebase and use secure key management',
    },

    // Passwords in configuration
    {
      name: 'Password in Configuration',
      description: 'Password field detected in configuration',
      pattern: /(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]/gi,
      severity: 'high',
      examples: ['password = "secret123"', 'pwd: "mypassword"'],
      remediation: 'Use environment variables or secure key management',
    },

    // Email and potentially sensitive data
    {
      name: 'Email Address',
      description: 'Email address detected (may contain sensitive info)',
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'low',
      examples: ['user@example.com'],
      remediation: 'Consider if email address is necessary in this context',
    },

    // Potential base64 encoded secrets
    {
      name: 'Base64 Encoded Secret',
      description: 'Potential base64 encoded secret detected',
      pattern: /['\"]([A-Za-z0-9+/]{32,}={0,2})['\"]\s*(?:#.*)?$/gm,
      severity: 'medium',
      examples: ['"YWJjZGVmZ2hpams="'],
      remediation: 'Verify if this is legitimate base64 data or encoded secret',
    },
  ];

  private static readonly EXCLUDED_PATTERNS = [
    // Common false positives
    /^[a-f0-9]{32}$/i, // MD5 hashes
    /^[a-f0-9]{40}$/i, // SHA1 hashes
    /^[a-f0-9]{64}$/i, // SHA256 hashes
    /^test_|mock_|fake_|dummy_|example_/i, // Test values
    /localhost/i, // Localhost references
    /127\.0\.0\.1/, // Localhost IP
    /example\.com/, // Example domains
    /\.env\.example$/, // Example environment files
    /\.env\.template$/, // Template environment files
    /node_modules/, // Dependencies
    /coverage\//, // Coverage reports
    /dist\//, // Build output
    /\.git\//, // Git metadata
  ];

  private static readonly EXCLUDED_EXTENSIONS = [
    '.jpg',
    '.jpeg',
    '.png',
    '.gif',
    '.bmp',
    '.svg',
    '.ico', // Images
    '.pdf',
    '.doc',
    '.docx',
    '.xls',
    '.xlsx', // Documents
    '.zip',
    '.tar',
    '.gz',
    '.rar', // Archives
    '.mp3',
    '.mp4',
    '.avi',
    '.mov', // Media files
    '.ttf',
    '.woff',
    '.woff2',
    '.eot', // Fonts
    '.map',
    '.min.js',
    '.min.css', // Minified files
  ];

  /**
   * Scan directory for secrets
   */
  static async scanDirectory(
    rootPath: string,
    options: {
      ignorePaths?: string[];
      maxFileSize?: number;
      includeBinary?: boolean;
    } = {}
  ): Promise<ScanResults> {
    const startTime = Date.now();
    const {
      ignorePaths = ['node_modules', '.git', 'dist', 'coverage', 'logs'],
      maxFileSize = 1024 * 1024, // 1MB
      includeBinary = false,
    } = options;

    const findings: SecretFinding[] = [];
    const errors: string[] = [];
    let totalFiles = 0;
    let scannedFiles = 0;

    logger.info(`Starting secrets scan in: ${rootPath}`);

    try {
      const files = this.getAllFiles(rootPath, ignorePaths);
      totalFiles = files.length;

      for (const filePath of files) {
        try {
          const relativePath = relative(rootPath, filePath);
          const stats = statSync(filePath);

          // Skip large files
          if (stats.size > maxFileSize) {
            logger.debug(`Skipping large file: ${relativePath} (${stats.size} bytes)`);
            continue;
          }

          // Skip binary files unless explicitly included
          const ext = extname(filePath).toLowerCase();
          if (!includeBinary && this.EXCLUDED_EXTENSIONS.includes(ext)) {
            logger.debug(`Skipping binary file: ${relativePath}`);
            continue;
          }

          // Skip obvious non-text files
          if (!includeBinary && this.isBinaryFile(filePath)) {
            logger.debug(`Skipping binary file: ${relativePath}`);
            continue;
          }

          scannedFiles++;
          const fileFindings = await this.scanFile(filePath);
          findings.push(...fileFindings);
        } catch (error) {
          const relativePath = relative(rootPath, filePath);
          const errorMsg = `Error scanning ${relativePath}: ${error instanceof Error ? error.message : 'Unknown error'}`;
          errors.push(errorMsg);
          logger.warn(errorMsg);
        }
      }
    } catch (error) {
      errors.push(
        `Directory scan error: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    // Count severity levels
    const summary = findings.reduce(
      (acc, finding) => {
        acc[finding.pattern.severity]++;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );

    const duration = Date.now() - startTime;

    const _results: ScanResults = {
      totalFiles,
      scannedFiles,
      findings,
      summary,
      errors,
      duration,
    };

    logger.info(
      `Scan completed: ${scannedFiles}/${totalFiles} files, ${String(findings?.length ?? 0)} findings in ${duration}ms`
    );

    return _results;
  }

  /**
   * Scan a single file for secrets
   */
  static async scanFile(filePath: string): Promise<SecretFinding[]> {
    const findings: SecretFinding[] = [];

    try {
      const content = readFileSync(filePath, 'utf8');
      const lines = content.split('\n');

      for (const pattern of this.SECRET_PATTERNS) {
        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
          const line = lines[lineIndex];
          let match;

          // Reset regex lastIndex for global patterns
          pattern.pattern.lastIndex = 0;

          while ((match = pattern.pattern.exec(line)) !== null) {
            // Skip false positives
            if (this.isFalsePositive(match[0])) {
              continue;
            }

            const finding: SecretFinding = {
              file: filePath,
              line: lineIndex + 1,
              column: match.index + 1,
              match: match[0],
              pattern,
              context: this.getContext(lines, lineIndex),
              confidence: this.calculateConfidence(match[0], pattern),
            };

            findings.push(finding);
          }
        }
      }
    } catch (error) {
      // Skip files that can't be read as text
      logger.debug(`Skipping non-text file: ${filePath}`);
    }

    return findings;
  }

  /**
   * Get all files in directory recursively
   */
  private static getAllFiles(dirPath: string, ignorePaths: string[]): string[] {
    const files: string[] = [];

    const traverse = (currentPath: string) => {
      const items = readdirSync(currentPath);

      for (const item of items) {
        const fullPath = join(currentPath, item);
        const relativePath = relative(dirPath, fullPath);

        // Skip ignored paths
        if (ignorePaths.some((ignore: string) => relativePath.startsWith(ignore))) {
          continue;
        }

        const stats = statSync(fullPath);

        if (stats.isDirectory()) {
          traverse(fullPath);
        } else {
          files.push(fullPath);
        }
      }
    };

    traverse(dirPath);
    return files;
  }

  /**
   * Check if a match is a false positive
   */
  private static isFalsePositive(match: string): boolean {
    return this.EXCLUDED_PATTERNS.some((pattern) => pattern.test(match));
  }

  /**
   * Get context around a finding
   */
  private static getContext(
    lines: string[],
    lineIndex: number,
    contextLines: number = 2
  ): string[] {
    const start = Math.max(0, lineIndex - contextLines);
    const end = Math.min(lines.length - 1, lineIndex + contextLines);

    return lines.slice(start, end + 1);
  }

  /**
   * Calculate confidence score for a finding
   */
  private static calculateConfidence(match: string, pattern: SecretPattern): number {
    let confidence = 0.5; // Base confidence

    // Increase confidence for longer matches
    if (match.length > 20) confidence += 0.2;
    if (match.length > 40) confidence += 0.1;

    // Increase confidence for specific patterns
    if (pattern.severity === 'critical') confidence += 0.2;
    if (pattern.severity === 'high') confidence += 0.1;

    // Decrease confidence for generic-looking values
    if (/^[A-F0-9]+$/i.test(match)) confidence -= 0.1; // Hex only
    if (/^[a-z]+$/.test(match)) confidence -= 0.1; // Lowercase only

    return Math.min(1.0, Math.max(0.0, confidence));
  }

  /**
   * Check if file is binary
   */
  private static isBinaryFile(filePath: string): boolean {
    try {
      const buffer = readFileSync(filePath, { encoding: null });

      // Check for null bytes (common in binary files)
      if (buffer.includes(0)) {
        return true;
      }

      // Check UTF-8 validity
      const content = buffer.toString('utf8');
      const reconverted = Buffer.from(content, 'utf8');

      return !buffer.equals(reconverted);
    } catch {
      return true; // Assume binary if can't read
    }
  }

  /**
   * Generate scan report
   */
  static generateReport(results: ScanResults): string {
    const report = [
      '# Secrets Scan Report',
      `Generated: ${new Date().toISOString()}`,
      `Duration: ${results.duration}ms`,
      `Files scanned: ${results.scannedFiles}/${results.totalFiles}`,
      '',
      '## Summary',
      `- Critical: ${results.summary.critical}`,
      `- High: ${results.summary.high}`,
      `- Medium: ${results.summary.medium}`,
      `- Low: ${results.summary.low}`,
      `- Total findings: ${results.findings.length}`,
      '',
    ];

    // Group findings by file
    const findingsByFile = results.findings.reduce<Record<string, SecretFinding[]>>(
      (acc, finding) => {
        if (!acc[finding.file]) {
          acc[finding.file] = [];
        }
        acc[finding.file].push(finding);
        return acc;
      },
      {}
    );

    // Sort files by severity
    const sortedFiles = Object.entries(findingsByFile).sort(([, a], [, b]) => {
      const aMaxSeverity = Math.max(
        ...a.map((f: unknown) => hasProperty(f, 'pattern') && hasProperty(f.pattern, 'severity')
          ? this.getSeverityScore(f.pattern.severity as "critical" | "high" | "medium" | "low")
          : 0)
      );
      const bMaxSeverity = Math.max(
        ...b.map((f: unknown) => hasProperty(f, 'pattern') && hasProperty(f.pattern, 'severity')
          ? this.getSeverityScore(f.pattern.severity as "critical" | "high" | "medium" | "low")
          : 0)
      );
      return bMaxSeverity - aMaxSeverity;
    });

    if (sortedFiles.length > 0) {
      report.push('## Findings by File');

      for (const [file, fileFindings] of sortedFiles) {
        report.push(`### ${file}`);

        // Sort findings by severity
        fileFindings.sort((a: unknown, b: unknown) => {
          const aSeverity = hasProperty(a, 'pattern') && hasProperty(a.pattern, 'severity')
            ? this.getSeverityScore(a.pattern.severity as "critical" | "high" | "medium" | "low")
            : 0;
          const bSeverity = hasProperty(b, 'pattern') && hasProperty(b.pattern, 'severity')
            ? this.getSeverityScore(b.pattern.severity as "critical" | "high" | "medium" | "low")
            : 0;
          return aSeverity - bSeverity;
        });

        for (const finding of fileFindings) {
          report.push('');
          report.push(
            `**Line ${hasProperty(finding, 'line') ? finding.line : 'unknown'}:** ${hasProperty(finding, 'pattern') && hasProperty(finding.pattern, 'name') && hasProperty(finding.pattern, 'severity') ? `${finding.pattern.name} (${finding.pattern.severity})` : 'Unknown pattern'}`
          );
          report.push(
            `\`${finding.match}\` (confidence: ${String(((hasProperty(finding, 'confidence') && typeof finding.confidence === 'number' ? finding.confidence : 0) * 100).toFixed(1))}%)`
          );
          report.push(`**Remediation:** ${hasProperty(finding, 'pattern') && hasProperty(finding.pattern, 'remediation') ? finding.pattern.remediation : 'No remediation available'}`);

          if (finding.context.length > 1) {
            report.push('**Context:**');
            report.push('```');
            report.push(
              ...finding.context.map((line: unknown, _idx: number) => {
                const lineNum = (hasProperty(finding, 'line') && typeof finding.line === 'number' ? finding.line : 0) -
                               (Array.isArray(finding.context) ? finding.context.length : 0) + 1 + _idx;
                const marker = _idx === Math.floor((Array.isArray(finding.context) ? finding.context.length : 0) / 2) ? '>>> ' : '    ';
                return `${String(marker)}${String(lineNum)}: ${String(line)}`;
              })
            );
            report.push('```');
          }
        }
        report.push('');
      }
    }

    if (results.errors.length > 0) {
      report.push('## Errors');
      results.errors.forEach((error) => report.push(`- ${error}`));
      report.push('');
    }

    report.push('## Recommendations');
    if (results.summary.critical > 0 || results.summary.high > 0) {
      report.push('- **URGENT:** Remove all critical and high severity secrets immediately');
    }
    report.push('- Use environment variables for all configuration');
    report.push('- Implement CI/CD secret scanning to prevent future commits');
    report.push('- Consider using a secret management service for production');
    report.push('- Review and rotate any exposed credentials');

    return report.join('\n');
  }

  /**
   * Convert severity to numeric score for sorting
   */
  private static getSeverityScore(severity: SecretPattern['severity']): number {
    const scores = { critical: 4, high: 3, medium: 2, low: 1 };
    return scores[severity] || 0;
  }

  /**
   * Exit with appropriate code based on findings
   */
  static exitWithResults(results: ScanResults): void {
    if (results.summary.critical > 0 || results.summary.high > 0) {
      logger.error(
        `Scan failed: ${results.summary.critical} critical and ${results.summary.high} high severity findings`
      );
      process.exit(1);
    } else if (results.summary.medium > 0) {
      logger.warn(
        `Scan completed with warnings: ${results.summary.medium} medium severity findings`
      );
      process.exit(0);
    } else {
      logger.info(`Scan passed: No critical or high severity secrets found`);
      process.exit(0);
    }
  }
}
