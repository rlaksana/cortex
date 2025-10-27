#!/usr/bin/env node

/**
 * Code Organization Improvement Script for Cortex MCP
 * Analyzes and improves directory structure, module boundaries, and code organization
 */

const fs = require('fs');
const path = require('path');

class CodeOrganizationAnalyzer {
  constructor() {
    this.rootPath = process.cwd();
    this.srcPath = path.join(this.rootPath, 'src');
    this.analysis = {
      structure: {},
      dependencies: new Map(),
      circularDependencies: [],
      orphanFiles: [],
      largeFiles: [],
      deepNesting: [],
      inconsistencies: [],
      recommendations: []
    };
  }

  async runAnalysis() {
    console.log('🏗️  Starting code organization analysis...\n');

    try {
      // Analyze current structure
      this.analyzeDirectoryStructure();
      this.analyzeModuleDependencies();
      this.detectCircularDependencies();
      this.identifyOrphanFiles();
      this.findLargeFiles();
      this.detectDeepNesting();
      this.checkInconsistencies();

      // Generate recommendations
      this.generateRecommendations();

      // Output results
      this.generateReport();

      // Apply improvements if requested
      if (process.argv.includes('--fix')) {
        await this.applyImprovements();
      }

    } catch (error) {
      console.error('❌ Analysis failed:', error.message);
      process.exit(1);
    }
  }

  analyzeDirectoryStructure() {
    console.log('📁 Analyzing directory structure...');

    const structure = this.buildDirectoryTree(this.srcPath);
    this.analysis.structure = structure;

    console.log('✅ Directory structure analyzed');
  }

  buildDirectoryTree(dirPath, relativePath = '') {
    const tree = {
      name: path.basename(dirPath),
      path: relativePath,
      type: 'directory',
      children: [],
      stats: { files: 0, directories: 0, totalLines: 0 }
    };

    if (!fs.existsSync(dirPath)) {
      return tree;
    }

    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const relativeItemPath = path.join(relativePath, item);
      const stat = fs.statSync(itemPath);

      if (stat.isDirectory()) {
        const childTree = this.buildDirectoryTree(itemPath, relativeItemPath);
        tree.children.push(childTree);
        tree.stats.directories++;
      } else if (this.isSourceFile(item)) {
        const fileTree = this.analyzeFile(itemPath, relativeItemPath);
        tree.children.push(fileTree);
        tree.stats.files++;
        tree.stats.totalLines += fileTree.lines;
      }
    }

    // Sort children: directories first, then files
    tree.children.sort((a, b) => {
      if (a.type !== b.type) {
        return a.type === 'directory' ? -1 : 1;
      }
      return a.name.localeCompare(b.name);
    });

    return tree;
  }

  analyzeFile(filePath, relativePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').length;
    const imports = this.extractImports(content);
    const exports = this.extractExports(content);

    return {
      name: path.basename(filePath),
      path: relativePath,
      type: 'file',
      extension: path.extname(filePath),
      lines,
      imports,
      exports,
      size: fs.statSync(filePath).size
    };
  }

  analyzeModuleDependencies() {
    console.log('🔗 Analyzing module dependencies...');

    const allFiles = this.getAllSourceFiles(this.srcPath);

    for (const file of allFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const imports = this.extractImports(content);
      const relativePath = path.relative(this.srcPath, file);

      this.analysis.dependencies.set(relativePath, imports);
    }

    console.log(`✅ Analyzed dependencies for ${allFiles.length} files`);
  }

  detectCircularDependencies() {
    console.log('🔄 Detecting circular dependencies...');

    const visited = new Set();
    const recursionStack = new Set();

    for (const [file] of this.analysis.dependencies) {
      if (!visited.has(file)) {
        this.detectCircularDepsDFS(file, visited, recursionStack, []);
      }
    }

    console.log(`✅ Found ${this.analysis.circularDependencies.length} circular dependencies`);
  }

  detectCircularDepsDFS(file, visited, recursionStack, path) {
    visited.add(file);
    recursionStack.add(file);
    path.push(file);

    const dependencies = this.analysis.dependencies.get(file) || [];

    for (const dep of dependencies) {
      if (!recursionStack.has(dep)) {
        if (!visited.has(dep)) {
          this.detectCircularDepsDFS(dep, visited, recursionStack, [...path]);
        }
      } else {
        // Found circular dependency
        const cycleStart = path.indexOf(dep);
        const cycle = path.slice(cycleStart).concat(dep);
        this.analysis.circularDependencies.push({
          cycle,
          length: cycle.length - 1
        });
      }
    }

    recursionStack.delete(file);
  }

  identifyOrphanFiles() {
    console.log('👤 Identifying orphan files...');

    const allFiles = new Set(this.getAllSourceFiles(this.srcPath).map(f =>
      path.relative(this.srcPath, f)
    ));

    const importedFiles = new Set();

    for (const imports of this.analysis.dependencies.values()) {
      for (const imp of imports) {
        if (allFiles.has(imp)) {
          importedFiles.add(imp);
        }
      }
    }

    // Files that are never imported
    for (const file of allFiles) {
      if (!importedFiles.has(file) && !this.isEntryFile(file)) {
        this.analysis.orphanFiles.push(file);
      }
    }

    console.log(`✅ Found ${this.analysis.orphanFiles.length} orphan files`);
  }

  findLargeFiles() {
    console.log('📏 Finding large files...');

    const allFiles = this.getAllSourceFiles(this.srcPath);
    const largeFileThreshold = 300; // lines

    for (const file of allFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n').length;

      if (lines > largeFileThreshold) {
        this.analysis.largeFiles.push({
          path: path.relative(this.srcPath, file),
          lines,
          size: fs.statSync(file).size
        });
      }
    }

    this.analysis.largeFiles.sort((a, b) => b.lines - a.lines);
    console.log(`✅ Found ${this.analysis.largeFiles.length} large files`);
  }

  detectDeepNesting() {
    console.log('📂 Detecting deep nesting...');

    const maxDepth = 5;

    this.traverseStructure(this.analysis.structure, 0, (node, depth) => {
      if (depth > maxDepth && node.type === 'file') {
        this.analysis.deepNesting.push({
          path: node.path,
          depth,
          name: node.name
        });
      }
    });

    console.log(`✅ Found ${this.analysis.deepNesting.length} deeply nested files`);
  }

  checkInconsistencies() {
    console.log('🔍 Checking for inconsistencies...');

    // Check naming conventions
    this.checkNamingConventions();

    // Check file organization patterns
    this.checkOrganizationPatterns();

    // Check index file usage
    this.checkIndexFiles();

    console.log(`✅ Found ${this.analysis.inconsistencies.length} inconsistencies`);
  }

  checkNamingConventions() {
    const allFiles = this.getAllSourceFiles(this.srcPath);

    for (const file of allFiles) {
      const fileName = path.basename(file, path.extname(file));

      // Check for inconsistent naming
      if (fileName.includes('_') && fileName.includes('-')) {
        this.analysis.inconsistencies.push({
          type: 'naming',
          file: path.relative(this.srcPath, file),
          issue: 'Mixed naming conventions (underscore and hyphen)',
          suggestion: 'Use consistent naming convention'
        });
      }

      // Check for inconsistent case
      if (fileName !== fileName.toLowerCase() && fileName !== fileName.toUpperCase()) {
        const hasMixedCase = /[a-z][A-Z]|[A-Z][a-z]/.test(fileName);
        if (hasMixedCase) {
          this.analysis.inconsistencies.push({
            type: 'naming',
            file: path.relative(this.srcPath, file),
            issue: 'Mixed case in filename',
            suggestion: 'Use consistent case (kebab-case or PascalCase)'
          });
        }
      }
    }
  }

  checkOrganizationPatterns() {
    // Check for consistent directory structures
    const dirs = this.getAllDirectories(this.srcPath);
    const dirNames = dirs.map(dir => path.basename(dir));

    // Look for similar directories with different names
    const similarDirs = this.findSimilarDirectories(dirNames);

    for (const { dirs: similar, similarity } of similarDirs) {
      if (similarity > 0.7) {
        this.analysis.inconsistencies.push({
          type: 'organization',
          issue: `Similar directory names: ${similar.join(', ')}`,
          suggestion: 'Consider consolidating or standardizing directory names'
        });
      }
    }
  }

  checkIndexFiles() {
    const dirs = this.getAllDirectories(this.srcPath);

    for (const dir of dirs) {
      const indexPath = path.join(dir, 'index.ts');
      const hasIndex = fs.existsSync(indexPath);

      if (!hasIndex) {
        const files = fs.readdirSync(dir).filter(f => this.isSourceFile(f));

        if (files.length > 3) {
          this.analysis.inconsistencies.push({
            type: 'missing_index',
            directory: path.relative(this.srcPath, dir),
            issue: 'Directory with multiple files missing index.ts',
            suggestion: 'Add index.ts file for cleaner imports'
          });
        }
      }
    }
  }

  generateRecommendations() {
    console.log('💡 Generating recommendations...');

    // Circular dependencies
    if (this.analysis.circularDependencies.length > 0) {
      this.analysis.recommendations.push({
        priority: 'high',
        type: 'circular_dependencies',
        title: 'Resolve Circular Dependencies',
        description: `Found ${this.analysis.circularDependencies.length} circular dependencies that should be resolved`,
        action: 'Refactor code to eliminate circular dependencies',
        affected_files: this.analysis.circularDependencies.flatMap(c => c.cycle)
      });
    }

    // Large files
    if (this.analysis.largeFiles.length > 0) {
      this.analysis.recommendations.push({
        priority: 'medium',
        type: 'large_files',
        title: 'Break Down Large Files',
        description: `Found ${this.analysis.largeFiles.length} files with more than 300 lines`,
        action: 'Split large files into smaller, more focused modules',
        affected_files: this.analysis.largeFiles.map(f => f.path)
      });
    }

    // Orphan files
    if (this.analysis.orphanFiles.length > 0) {
      this.analysis.recommendations.push({
        priority: 'low',
        type: 'orphan_files',
        title: 'Review Orphan Files',
        description: `Found ${this.analysis.orphanFiles.length} files that are not imported anywhere`,
        action: 'Remove unused files or add them to appropriate modules',
        affected_files: this.analysis.orphanFiles
      });
    }

    // Deep nesting
    if (this.analysis.deepNesting.length > 0) {
      this.analysis.recommendations.push({
        priority: 'medium',
        type: 'deep_nesting',
        title: 'Reduce Directory Nesting',
        description: `Found ${this.analysis.deepNesting.length} files with deep nesting (>5 levels)`,
        action: 'Flatten directory structure where possible',
        affected_files: this.analysis.deepNesting.map(f => f.path)
      });
    }

    // Inconsistencies
    if (this.analysis.inconsistencies.length > 0) {
      this.analysis.recommendations.push({
        priority: 'low',
        type: 'inconsistencies',
        title: 'Fix Inconsistencies',
        description: `Found ${this.analysis.inconsistencies.length} naming and organization inconsistencies`,
        action: 'Standardize naming conventions and organization patterns',
        affected_files: this.analysis.inconsistencies.map(i => i.file || i.directory).filter(Boolean)
      });
    }

    console.log(`✅ Generated ${this.analysis.recommendations.length} recommendations`);
  }

  generateReport() {
    console.log('\n📊 CODE ORGANIZATION REPORT\n');
    console.log('=====================================\n');

    // Structure overview
    console.log('📁 DIRECTORY STRUCTURE:');
    console.log('------------------------');
    this.printStructure(this.analysis.structure, 0);
    console.log();

    // Issues found
    if (this.analysis.circularDependencies.length > 0) {
      console.log('🔄 CIRCULAR DEPENDENCIES:');
      console.log('-------------------------');
      this.analysis.circularDependencies.forEach((cycle, i) => {
        console.log(`${i + 1}. ${cycle.cycle.join(' → ')} → ${cycle.cycle[0]}`);
      });
      console.log();
    }

    if (this.analysis.largeFiles.length > 0) {
      console.log('📏 LARGE FILES (>300 lines):');
      console.log('-----------------------------');
      this.analysis.largeFiles.forEach(file => {
        console.log(`📄 ${file.path}: ${file.lines} lines (${(file.size / 1024).toFixed(1)}KB)`);
      });
      console.log();
    }

    if (this.analysis.orphanFiles.length > 0) {
      console.log('👤 ORPHAN FILES:');
      console.log('----------------');
      this.analysis.orphanFiles.forEach(file => {
        console.log(`📄 ${file}`);
      });
      console.log();
    }

    if (this.analysis.deepNesting.length > 0) {
      console.log('📂 DEEP NESTING (>5 levels):');
      console.log('------------------------------');
      this.analysis.deepNesting.forEach(file => {
        console.log(`📄 ${file.path}: depth ${file.depth}`);
      });
      console.log();
    }

    if (this.analysis.inconsistencies.length > 0) {
      console.log('🔍 INCONSISTENCIES:');
      console.log('--------------------');
      this.analysis.inconsistencies.forEach(inc => {
        const location = inc.file || inc.directory || 'Unknown';
        console.log(`⚠️  ${location}: ${inc.issue}`);
        console.log(`   Suggestion: ${inc.suggestion}`);
      });
      console.log();
    }

    // Recommendations
    console.log('💡 RECOMMENDATIONS:');
    console.log('-------------------');
    this.analysis.recommendations.forEach((rec, i) => {
      const priority = rec.priority === 'high' ? '🔴' : rec.priority === 'medium' ? '🟡' : '🟢';
      console.log(`${priority} ${i + 1}. ${rec.title} (${rec.priority})`);
      console.log(`   ${rec.description}`);
      console.log(`   Action: ${rec.action}`);
      if (rec.affected_files.length <= 5) {
        console.log(`   Files: ${rec.affected_files.join(', ')}`);
      } else {
        console.log(`   Files: ${rec.affected_files.length} files affected`);
      }
      console.log();
    });

    // Summary
    console.log('📈 SUMMARY:');
    console.log('-----------');
    console.log(`Total files: ${this.getAllSourceFiles(this.srcPath).length}`);
    console.log(`Total lines: ${this.countTotalLines(this.analysis.structure)}`);
    console.log(`Circular dependencies: ${this.analysis.circularDependencies.length}`);
    console.log(`Large files: ${this.analysis.largeFiles.length}`);
    console.log(`Orphan files: ${this.analysis.orphanFiles.length}`);
    console.log(`Deep nesting: ${this.analysis.deepNesting.length}`);
    console.log(`Inconsistencies: ${this.analysis.inconsistencies.length}`);
    console.log(`Recommendations: ${this.analysis.recommendations.length}`);

    // Save detailed report
    this.saveDetailedReport();
  }

  async applyImprovements() {
    console.log('\n🔧 Applying improvements...');

    // Create index files for directories that need them
    await this.createMissingIndexFiles();

    // Fix naming inconsistencies
    await this.fixNamingInconsistencies();

    console.log('✅ Improvements applied');
  }

  async createMissingIndexFiles() {
    const missingIndexIssues = this.analysis.inconsistencies.filter(inc => inc.type === 'missing_index');

    for (const issue of missingIndexIssues) {
      const dirPath = path.join(this.srcPath, issue.directory);
      const indexPath = path.join(dirPath, 'index.ts');

      if (!fs.existsSync(indexPath)) {
        const files = fs.readdirSync(dirPath)
          .filter(f => this.isSourceFile(f) && f !== 'index.ts')
          .map(f => f.replace('.ts', ''));

        const indexContent = files.map(file =>
          `export * from './${file}';`
        ).join('\n') + '\n';

        fs.writeFileSync(indexPath, indexContent);
        console.log(`📝 Created index.ts for ${issue.directory}`);
      }
    }
  }

  async fixNamingInconsistencies() {
    const namingIssues = this.analysis.inconsistencies.filter(inc => inc.type === 'naming');

    for (const issue of namingIssues) {
      if (issue.file) {
        const filePath = path.join(this.srcPath, issue.file);
        const dir = path.dirname(filePath);
        const ext = path.extname(filePath);
        const currentName = path.basename(filePath, ext);

        let newName = currentName;

        // Convert to kebab-case
        if (currentName.includes('_')) {
          newName = currentName.replace(/_/g, '-');
        }

        if (/[a-z][A-Z]/.test(currentName)) {
          newName = currentName.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
        }

        if (newName !== currentName) {
          const newPath = path.join(dir, newName + ext);

          try {
            fs.renameSync(filePath, newPath);
            console.log(`📝 Renamed ${currentName} to ${newName}`);

            // Update imports in other files
            await this.updateImports(issue.file, newName);
          } catch (error) {
            console.log(`⚠️  Could not rename ${currentName}: ${error.message}`);
          }
        }
      }
    }
  }

  async updateImports(oldPath, newName) {
    const allFiles = this.getAllSourceFiles(this.srcPath);

    for (const file of allFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const oldImportPath = oldPath.replace('.ts', '').replace(/\\/g, '/');
      const newImportPath = oldImportPath.split('/').slice(0, -1).concat(newName).join('/');

      const updatedContent = content.replace(
        new RegExp(`from ['"]\\.\\./${oldImportPath}['"]`, 'g'),
        `from '../${newImportPath}'`
      );

      if (updatedContent !== content) {
        fs.writeFileSync(file, updatedContent);
      }
    }
  }

  // Helper methods
  getAllSourceFiles(dir) {
    const files = [];

    if (!fs.existsSync(dir)) return files;

    const items = fs.readdirSync(dir);

    for (const item of items) {
      const itemPath = path.join(dir, item);
      const stat = fs.statSync(itemPath);

      if (stat.isDirectory()) {
        files.push(...this.getAllSourceFiles(itemPath));
      } else if (this.isSourceFile(item)) {
        files.push(itemPath);
      }
    }

    return files;
  }

  getAllDirectories(dir) {
    const dirs = [];

    if (!fs.existsSync(dir)) return dirs;

    const items = fs.readdirSync(dir);

    for (const item of items) {
      const itemPath = path.join(dir, item);
      const stat = fs.statSync(itemPath);

      if (stat.isDirectory()) {
        dirs.push(itemPath);
        dirs.push(...this.getAllDirectories(itemPath));
      }
    }

    return dirs;
  }

  isSourceFile(fileName) {
    return /\.(ts|js|tsx|jsx)$/.test(fileName);
  }

  isEntryFile(filePath) {
    const relativePath = path.relative(this.srcPath, filePath);
    return relativePath === 'index.ts' ||
           relativePath.includes('index-') ||
           relativePath.endsWith('.test.ts') ||
           relativePath.endsWith('.spec.ts');
  }

  extractImports(content) {
    const imports = [];
    const relativePath = path.relative(this.srcPath, process.cwd());

    // ES6 imports
    const es6ImportRegex = /import.*from\s+['"](\.\.?\/[^'"]+)['"]/g;
    let match;

    while ((match = es6ImportRegex.exec(content)) !== null) {
      let importPath = match[1];

      // Convert .ts imports to actual file paths
      if (!importPath.endsWith('.ts')) {
        importPath += '.ts';
      }

      imports.push(importPath);
    }

    // CommonJS require
    const requireRegex = /require\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g;

    while ((match = requireRegex.exec(content)) !== null) {
      let importPath = match[1];

      if (!importPath.endsWith('.ts')) {
        importPath += '.ts';
      }

      imports.push(importPath);
    }

    return imports;
  }

  extractExports(content) {
    const exports = [];

    // Named exports
    const namedExportRegex = /export\s+(?:const|let|var|function|class)\s+(\w+)/g;
    let match;

    while ((match = namedExportRegex.exec(content)) !== null) {
      exports.push(match[1]);
    }

    // Default exports
    if (/export\s+default/.test(content)) {
      exports.push('default');
    }

    return exports;
  }

  traverseStructure(node, depth, callback) {
    callback(node, depth);

    if (node.children) {
      for (const child of node.children) {
        this.traverseStructure(child, depth + 1, callback);
      }
    }
  }

  printStructure(node, depth) {
    const indent = '  '.repeat(depth);
    const icon = node.type === 'directory' ? '📁' : '📄';

    if (node.type === 'file') {
      console.log(`${indent}${icon} ${node.name} (${node.lines} lines)`);
    } else {
      console.log(`${indent}${icon} ${node.name}/`);
      if (node.children) {
        for (const child of node.children) {
          this.printStructure(child, depth + 1);
        }
      }
    }
  }

  countTotalLines(node) {
    if (node.type === 'file') {
      return node.lines || 0;
    }

    let total = 0;
    if (node.children) {
      for (const child of node.children) {
        total += this.countTotalLines(child);
      }
    }

    return total;
  }

  findSimilarDirectories(dirNames) {
    const similar = [];

    for (let i = 0; i < dirNames.length; i++) {
      for (let j = i + 1; j < dirNames.length; j++) {
        const similarity = this.calculateStringSimilarity(dirNames[i], dirNames[j]);
        if (similarity > 0.7 && dirNames[i] !== dirNames[j]) {
          similar.push({
            dirs: [dirNames[i], dirNames[j]],
            similarity
          });
        }
      }
    }

    return similar;
  }

  calculateStringSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 1.0;

    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  saveDetailedReport() {
    const reportPath = path.join(process.cwd(), 'code-organization-report.json');
    const report = {
      timestamp: new Date().toISOString(),
      analysis: {
        structure: this.analysis.structure,
        dependencies: Array.from(this.analysis.dependencies.entries()),
        circularDependencies: this.analysis.circularDependencies,
        orphanFiles: this.analysis.orphanFiles,
        largeFiles: this.analysis.largeFiles,
        deepNesting: this.analysis.deepNesting,
        inconsistencies: this.analysis.inconsistencies
      },
      recommendations: this.analysis.recommendations,
      summary: {
        totalFiles: this.getAllSourceFiles(this.srcPath).length,
        totalLines: this.countTotalLines(this.analysis.structure),
        circularDependencies: this.analysis.circularDependencies.length,
        largeFiles: this.analysis.largeFiles.length,
        orphanFiles: this.analysis.orphanFiles.length,
        deepNesting: this.analysis.deepNesting.length,
        inconsistencies: this.analysis.inconsistencies.length,
        recommendations: this.analysis.recommendations.length
      }
    };

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n💾 Detailed report saved to: ${reportPath}`);
  }
}

// Run the analysis
if (require.main === module) {
  const analyzer = new CodeOrganizationAnalyzer();
  analyzer.runAnalysis().catch(error => {
    console.error('❌ Analysis failed:', error);
    process.exit(1);
  });
}

module.exports = CodeOrganizationAnalyzer;