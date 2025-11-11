#!/usr/bin/env node

/**
 * Parameter Naming Policy Validator
 *
 * This script enforces consistent parameter naming conventions across the codebase.
 * It checks for:
 * - camelCase parameter names
 * - Descriptive parameter names (not single letters except for loop variables)
 * - Consistent naming patterns across similar functions
 * - Proper TypeScript typing for all parameters
 */

const fs = require('fs');
const path = require('path');

class ParameterNamingValidator {
  constructor(rootDir = 'src') {
    this.rootDir = rootDir;
    this.violations = [];
    this.stats = {
      filesScanned: 0,
      functionsScanned: 0,
      parametersScanned: 0,
      violations: 0
    };
    this.namingPatterns = {
      // Common parameter naming patterns in this codebase
      userId: /^userId$|^user_id$/i,
      id: /^id$/,
      config: /^config$/,
      options: /^options$/,
      data: /^data$/,
      params: /^params$/,
      query: /^query$/,
      body: /^body$/,
      request: /^req$|^request$/i,
      response: /^res$|^response$/i,
      next: /^next$/,
      error: /^err$|^error$/i,
      result: /^result$/,
      value: /^value$/,
      item: /^item$/,
      index: /^i$|^index$/,
      key: /^k$|^key$/,
      element: /^el$|^element$/,
      callback: /^cb$|^callback$/i,
      // More specific patterns for this codebase
      collectionName: /^collectionName$|^collection_name$/i,
      scope: /^scope$/,
      kind: /^kind$/,
      metadata: /^metadata$/,
      entities: /^entities$/,
      relations: /^relations$/,
      observations: /^observations$/,
      tenantId: /^tenantId$|^tenant_id$/i
    };
  }

  async validate() {
    console.log('🔍 Starting parameter naming validation...');

    if (!fs.existsSync(this.rootDir)) {
      console.error(`❌ Directory ${this.rootDir} does not exist`);
      process.exit(1);
    }

    await this.scanDirectory(this.rootDir);
    this.generateReport();

    if (this.stats.violations > 0) {
      console.error(`❌ Found ${this.stats.violations} parameter naming violations`);
      process.exit(1);
    } else {
      console.log('✅ No parameter naming violations found');
    }
  }

  async scanDirectory(dir) {
    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        await this.scanDirectory(fullPath);
      } else if (stat.isFile() && item.endsWith('.ts')) {
        await this.validateFile(fullPath);
      }
    }
  }

  async validateFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      this.stats.filesScanned++;

      // Extract function parameters using regex
      const functionMatches = content.matchAll(/(?:function\s+\w+|=>|\([^)]*\)\s*=>|\w+\s*:\s*\([^)]*\)\s*=>)([^{]*)/g);

      for (const match of functionMatches) {
        this.stats.functionsScanned++;
        await this.validateFunctionParameters(filePath, match[0], match.index);
      }
    } catch (error) {
      console.warn(`⚠️  Could not process file ${filePath}: ${error.message}`);
    }
  }

  async validateFunctionParameters(filePath, functionSignature, startIndex) {
    // Extract parameter list
    const paramMatch = functionSignature.match(/\(([^)]*)\)/);
    if (!paramMatch) return;

    const paramString = paramMatch[1];
    if (!paramString.trim()) return;

    // Parse parameters (handles destructuring, default values, etc.)
    const parameters = this.parseParameters(paramString);

    for (const param of parameters) {
      this.stats.parametersScanned++;
      this.validateParameter(filePath, param, startIndex);
    }
  }

  parseParameters(paramString) {
    const params = [];
    let current = '';
    let parenLevel = 0;
    let inBrackets = 0;
    let inBraces = 0;

    for (let i = 0; i < paramString.length; i++) {
      const char = paramString[i];

      if (char === '(') parenLevel++;
      else if (char === ')') parenLevel--;
      else if (char === '[') inBrackets++;
      else if (char === ']') inBrackets--;
      else if (char === '{') inBraces++;
      else if (char === '}') inBraces--;

      if (char === ',' && parenLevel === 0 && inBrackets === 0 && inBraces === 0) {
        if (current.trim()) {
          params.push(current.trim());
        }
        current = '';
      } else {
        current += char;
      }
    }

    if (current.trim()) {
      params.push(current.trim());
    }

    return params;
  }

  validateParameter(filePath, paramString, index) {
    // Extract parameter name (before type annotation or default value)
    const nameMatch = paramString.match(/^(\w+)/);
    if (!nameMatch) return; // Skip destructuring or complex patterns

    const paramName = nameMatch[1];

    // Skip special cases
    if (paramName.startsWith('_')) return; // Unused parameter
    if (this.isLoopVariable(paramString)) return;
    if (this.isEventHandler(paramString)) return;

    // Validation rules
    this.checkCamelCase(filePath, paramName, index);
    this.checkDescriptiveName(filePath, paramName, paramString, index);
    this.checkConsistency(filePath, paramName, paramString, index);
    this.checkTypeAnnotation(filePath, paramString, index);
  }

  checkCamelCase(filePath, paramName, index) {
    if (!/^[a-z][a-zA-Z0-9]*$/.test(paramName)) {
      this.addViolation(filePath, index, 'PNC001',
        `Parameter "${paramName}" should use camelCase naming convention`);
    }
  }

  checkDescriptiveName(filePath, paramName, paramString, index) {
    // Skip single-letter variables in certain contexts
    if (this.isLoopVariable(paramString)) return;
    if (this.isCallbackVariable(paramName)) return;

    // Single letter variables (except common ones) are not descriptive
    if (paramName.length === 1 && !['i', 'j', 'k', 'x', 'y', 'z'].includes(paramName)) {
      this.addViolation(filePath, index, 'PNC002',
        `Parameter "${paramName}" is not descriptive. Use a more meaningful name`);
    }

    // Check for common non-descriptive names
    const nonDescriptive = ['data', 'stuff', 'thing', 'obj', 'val'];
    if (nonDescriptive.includes(paramName.toLowerCase())) {
      this.addViolation(filePath, index, 'PNC003',
        `Parameter "${paramName}" is too generic. Use a more specific name`);
    }
  }

  checkConsistency(filePath, paramName, paramString, index) {
    // Check against known patterns
    for (const [, regex] of Object.entries(this.namingPatterns)) {
      if (regex.test(paramName)) {
        return; // Matches known pattern
      }
    }

    // Warn about potentially inconsistent naming
    const variations = this.getNamingVariations(paramName);
    if (variations.length > 1) {
      this.addViolation(filePath, index, 'PNC004',
        `Parameter "${paramName}" has naming variations. Consider standardizing: ${variations.join(', ')}`);
    }
  }

  checkTypeAnnotation(filePath, paramString, index) {
    // Check if parameter has type annotation (excluding cases where it's optional)
    if (!paramString.includes(':') || !paramString.includes('?')) {
      // Check if this looks like it should have a type annotation
      const hasDefaultValue = paramString.includes('=');
      const isArrowFunction = paramString.includes('=>');

      if (!hasDefaultValue && !isArrowFunction && !this.isCallbackParameter(paramString)) {
        this.addViolation(filePath, index, 'PNC005',
          `Parameter should have explicit TypeScript type annotation`);
      }
    }
  }

  getNamingVariations(paramName) {
    const variations = [paramName];

    // Check for snake_case variations
    if (paramName.includes('_')) {
      const camelCase = paramName.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
      variations.push(camelCase);
    }

    // Check for camelCase variations
    if (/[A-Z]/.test(paramName)) {
      const snakeCase = paramName.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
      variations.push(snakeCase);
    }

    return [...new Set(variations)];
  }

  isLoopVariable(paramString) {
    return /(?:for|while|forEach|map|filter|reduce|some|every)/.test(paramString) &&
           /^[ijk]$/.test(paramString);
  }

  isEventHandler(paramString) {
    return /event|ev$/.test(paramString);
  }

  isCallbackVariable(paramName) {
    return ['cb', 'callback', 'next', 'done', 'resolve', 'reject'].includes(paramName);
  }

  isCallbackParameter(paramString) {
    return /function\s*\(|=>|callback|cb|next/.test(paramString);
  }

  addViolation(filePath, index, code, message) {
    const line = this.getLineNumber(filePath, index) || '?';
    this.violations.push({
      file: filePath,
      line: line,
      code: code,
      message: message
    });
    this.stats.violations++;
  }

  getLineNumber(filePath, index) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const beforeIndex = content.substring(0, index);
      return beforeIndex.split('\n').length;
    } catch {
      return null;
    }
  }

  generateReport() {
    console.log('\n📊 Parameter Naming Validation Report');
    console.log('=====================================');
    console.log(`Files scanned: ${this.stats.filesScanned}`);
    console.log(`Functions scanned: ${this.stats.functionsScanned}`);
    console.log(`Parameters scanned: ${this.stats.parametersScanned}`);
    console.log(`Violations found: ${this.stats.violations}`);

    if (this.violations.length > 0) {
      console.log('\n❌ Violations:');

      // Group by file for better readability
      const violationsByFile = {};
      for (const violation of this.violations) {
        if (!violationsByFile[violation.file]) {
          violationsByFile[violation.file] = [];
        }
        violationsByFile[violation.file].push(violation);
      }

      for (const [file, fileViolations] of Object.entries(violationsByFile)) {
        console.log(`\n  ${file}:`);
        for (const violation of fileViolations) {
          console.log(`    Line ${violation.line}: [${violation.code}] ${violation.message}`);
        }
      }

      // Generate summary by violation type
      console.log('\n📈 Summary by violation type:');
      const violationsByCode = {};
      for (const violation of this.violations) {
        violationsByCode[violation.code] = (violationsByCode[violation.code] || 0) + 1;
      }

      for (const [code, count] of Object.entries(violationsByCode)) {
        console.log(`  ${code}: ${count} violations`);
      }
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const rootDir = args[0] || 'src';

  const validator = new ParameterNamingValidator(rootDir);
  validator.validate().catch(error => {
    console.error('❌ Validation failed:', error.message);
    process.exit(1);
  });
}

module.exports = ParameterNamingValidator;