#!/usr/bin/env node

/**
 * TypeScript High Severity Error Fixer
 *
 * Automated fix script for high severity TypeScript errors:
 * - TS18048: Implicit any type
 * - TS7005: Variable used before assignment
 * - TS7006: Parameter implicitly has any type
 * - TS2564: Variable used before being assigned
 */

import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import {
  CWD, SRC_DIR, ensureDirs, loadProgram, writeLogs,
  pathIsLocal
} from './ts-fix-utils.mjs'

const args = new Set(process.argv.slice(2))
const APPLY = args.has('--apply')
const LIMIT = (() => { const i = process.argv.indexOf('--limit'); return i>0? Number(process.argv[i+1]) : undefined })()
const DRY_RUN = !APPLY
const VERBOSE = args.has('--verbose')

class HighSeverityFixer {
  constructor() {
    this.fixes = {
      implicitAny: 0,
      variableUsage: 0,
      parameterTyping: 0,
      definiteAssignment: 0
    }
    this.edits = []
    this.stats = {
      filesProcessed: 0,
      totalFixes: 0,
      errors: []
    }
    this.typeCache = new Map()
  }

  /**
   * Main execution method
   */
  async run() {
    try {
      console.log('🔧 TypeScript High Severity Error Fixer - Starting analysis')

      const program = loadProgram()
      const checker = program.getTypeChecker()

      // Get all diagnostic errors
      const diagnostics = ts.getPreEmitDiagnostics(program)
        .filter(d => this.isTargetError(d.code))
        .slice(0, LIMIT || Infinity)

      if (diagnostics.length === 0) {
        console.log('✅ No high severity errors found to fix')
        return this.getStats()
      }

      console.log(`📊 Found ${diagnostics.length} high severity errors to analyze`)

      // Group diagnostics by file for efficient processing
      const diagnosticsByFile = this.groupDiagnosticsByFile(diagnostics)

      // Process each file
      for (const [filePath, fileDiagnostics] of diagnosticsByFile) {
        await this.processFile(program, checker, filePath, fileDiagnostics)
      }

      console.log('✅ High severity fixer completed')
      this.printSummary()

      return this.getStats()

    } catch (error) {
      console.error('❌ High severity fixer failed:', error.message)
      this.stats.errors.push(error.message)
      throw error
    }
  }

  /**
   * Check if error code is in target scope
   */
  isTargetError(code) {
    const targetCodes = [18048, 7005, 7006, 2564]
    return targetCodes.includes(code)
  }

  /**
   * Group diagnostics by source file
   */
  groupDiagnosticsByFile(diagnostics) {
    const byFile = new Map()

    for (const diag of diagnostics) {
      if (!diag.file) continue

      const filePath = diag.file.fileName
      if (!byFile.has(filePath)) {
        byFile.set(filePath, [])
      }
      byFile.get(filePath).push(diag)
    }

    return byFile
  }

  /**
   * Process a single file
   */
  async processFile(program, checker, filePath, diagnostics) {
    try {
      if (VERBOSE) {
        console.log(`\n📁 Processing: ${path.relative(CWD, filePath)}`)
      }

      const sourceFile = program.getSourceFile(filePath)
      if (!sourceFile) return

      const text = sourceFile.getFullText()
      const fileFixes = []

      // Process each diagnostic
      for (const diag of diagnostics) {
        const fix = await this.createFix(program, checker, diag, text, sourceFile)
        if (fix) {
          fileFixes.push(fix)
          this.updateFixStats(diag.code)
        }
      }

      // Apply fixes if any found
      if (fileFixes.length > 0) {
        await this.applyFileFixes(filePath, text, fileFixes)
        this.stats.filesProcessed++
      }

    } catch (error) {
      console.error(`❌ Error processing file ${filePath}:`, error.message)
      this.stats.errors.push(`File ${filePath}: ${error.message}`)
    }
  }

  /**
   * Create fix for a specific diagnostic
   */
  async createFix(program, checker, diagnostic, text, sourceFile) {
    const code = diagnostic.code
    if (!diagnostic.start || !diagnostic.file) return null

    try {
      switch (code) {
        case 18048: // Implicit any type
          return await this.fixImplicitAny(program, checker, diagnostic, text, sourceFile)

        case 7005: // Variable used before assignment
          return await this.fixVariableUsage(program, checker, diagnostic, text, sourceFile)

        case 7006: // Parameter implicitly has any type
          return await this.fixParameterTyping(program, checker, diagnostic, text, sourceFile)

        case 2564: // Variable used before being assigned
          return await this.fixDefiniteAssignment(program, checker, diagnostic, text, sourceFile)

        default:
          return null
      }
    } catch (error) {
      if (VERBOSE) {
        console.warn(`⚠️ Could not create fix for TS${code}: ${error.message}`)
      }
      return null
    }
  }

  /**
   * Fix TS18048: Implicit any type
   */
  async fixImplicitAny(program, checker, diagnostic, text, sourceFile) {
    const node = this.findNodeAtPosition(sourceFile, diagnostic.start)
    if (!node) return null

    // Find the variable or parameter with implicit any
    const targetNode = this.findImplicitAnyTarget(node)
    if (!targetNode) return null

    // Infer type from usage
    const inferredType = this.inferTypeFromUsage(checker, targetNode, sourceFile)
    if (!inferredType) return null

    const typeAnnotation = this.generateTypeAnnotation(inferredType)

    return {
      type: 'implicit-any',
      code: 18048,
      replacement: typeAnnotation,
      start: targetNode.getEnd(),
      end: targetNode.getEnd(),
      confidence: inferredType.confidence || 'medium',
      description: `Add explicit type annotation: ${inferredType.type}`
    }
  }

  /**
   * Fix TS7005: Variable used before assignment
   */
  async fixVariableUsage(program, checker, diagnostic, text, sourceFile) {
    const node = this.findNodeAtPosition(sourceFile, diagnostic.start)
    if (!node) return null

    const variableNode = this.findVariableDeclaration(node)
    if (!variableNode) return null

    // Try to initialize with appropriate default
    const defaultInit = this.generateDefaultInitializer(checker, variableNode, text)

    if (defaultInit) {
      return {
        type: 'variable-usage',
        code: 7005,
        replacement: ` = ${defaultInit}`,
        start: variableNode.getEnd(),
        end: variableNode.getEnd(),
        confidence: defaultInit.confidence || 'medium',
        description: `Initialize variable with: ${defaultInit.value}`
      }
    }

    return null
  }

  /**
   * Fix TS7006: Parameter implicitly has any type
   */
  async fixParameterTyping(program, checker, diagnostic, text, sourceFile) {
    const node = this.findNodeAtPosition(sourceFile, diagnostic.start)
    if (!node) return null

    // Find the parameter without type annotation
    const parameterNode = this.findUntypedParameter(node)
    if (!parameterNode) return null

    // Infer type from usage within function body
    const inferredType = this.inferParameterTypeFromUsage(checker, parameterNode, sourceFile)
    if (!inferredType) {
      // Fallback to 'any' with explicit annotation
      return {
        type: 'parameter-typing',
        code: 7006,
        replacement: ': any',
        start: parameterNode.getEnd(),
        end: parameterNode.getEnd(),
        confidence: 'low',
        description: 'Add explicit any type (consider improving type specificity)'
      }
    }

    const typeAnnotation = this.generateTypeAnnotation(inferredType)

    return {
      type: 'parameter-typing',
      code: 7006,
      replacement: typeAnnotation,
      start: parameterNode.getEnd(),
      end: parameterNode.getEnd(),
      confidence: inferredType.confidence || 'medium',
      description: `Add parameter type: ${inferredType.type}`
    }
  }

  /**
   * Fix TS2564: Variable used before being assigned
   */
  async fixDefiniteAssignment(program, checker, diagnostic, text, sourceFile) {
    const node = this.findNodeAtPosition(sourceFile, diagnostic.start)
    if (!node) return null

    const variableNode = this.findVariableDeclaration(node)
    if (!variableNode) return null

    // Try different strategies
    const strategies = [
      () => this.tryAddDefiniteAssignmentAssertion(variableNode),
      () => this.tryInitializeVariable(variableNode, text),
      () => this.tryMakeOptional(variableNode)
    ]

    for (const strategy of strategies) {
      const fix = await strategy()
      if (fix) {
        return {
          type: 'definite-assignment',
          code: 2564,
          ...fix,
          confidence: fix.confidence || 'medium'
        }
      }
    }

    return null
  }

  /**
   * Helper methods
   */

  findNodeAtPosition(sourceFile, position) {
    let result = null

    function walk(node) {
      if (position >= node.getStart() && position < node.getEnd()) {
        result = node
        ts.forEachChild(node, walk)
      } else {
        ts.forEachChild(node, walk)
      }
    }

    ts.forEachChild(sourceFile, walk)
    return result
  }

  findImplicitAnyTarget(node) {
    // Walk up to find variable or function parameter
    let current = node
    while (current && current.kind !== ts.SyntaxKind.SourceFile) {
      if (ts.isVariableDeclaration(current) || ts.isParameter(current)) {
        return current
      }
      current = current.parent
    }
    return null
  }

  inferTypeFromUsage(checker, node, sourceFile) {
    const type = checker.getTypeAtLocation(node)
    const typeString = checker.typeToString(type, node, ts.TypeFormatFlags.NoTruncation)

    if (typeString === 'any') {
      // Try to infer from usages in the file
      const usages = this.findVariableUsages(node, sourceFile)
      const inferredTypes = usages.map(usage => this.getTypeFromUsage(checker, usage))
        .filter(Boolean)

      if (inferredTypes.length > 0) {
        // Use the most common type
        const typeCounts = new Map()
        for (const inferred of inferredTypes) {
          typeCounts.set(inferred.type, (typeCounts.get(inferred.type) || 0) + 1)
        }

        const mostCommon = [...typeCounts.entries()]
          .sort(([,a], [,b]) => b - a)[0]

        return {
          type: mostCommon[0],
          confidence: 'medium'
        }
      }
    }

    return {
      type: typeString,
      confidence: 'high'
    }
  }

  findVariableUsages(variableNode, sourceFile) {
    const usages = []
    const variableName = variableNode.name.getText()

    function walk(node) {
      if (ts.isIdentifier(node) && node.getText() === variableName && node !== variableNode.name) {
        usages.push(node)
      }
      ts.forEachChild(node, walk)
    }

    ts.forEachChild(sourceFile, walk)
    return usages
  }

  getTypeFromUsage(checker, usage) {
    const parent = usage.parent
    if (!parent) return null

    // Try to infer type from the context
    if (ts.isBinaryExpression(parent) && parent.right === usage) {
      const leftType = checker.getTypeAtLocation(parent.left)
      return {
        type: checker.typeToString(leftType),
        confidence: 'medium'
      }
    }

    if (ts.isCallExpression(parent) && parent.arguments.includes(usage)) {
      const signature = checker.getResolvedSignature(parent)
      if (signature) {
        const parameterIndex = parent.arguments.indexOf(usage)
        const parameter = signature.getParameters()[parameterIndex]
        if (parameter) {
          return {
            type: checker.typeToString(checker.getTypeOfSymbol(parameter)),
            confidence: 'high'
          }
        }
      }
    }

    return null
  }

  generateTypeAnnotation(inferredType) {
    return `: ${inferredType}`
  }

  findVariableDeclaration(node) {
    let current = node
    while (current && current.kind !== ts.SyntaxKind.SourceFile) {
      if (ts.isVariableDeclaration(current)) {
        return current
      }
      current = current.parent
    }
    return null
  }

  generateDefaultInitializer(checker, variableNode, text) {
    const variableName = variableNode.name?.getText()
    if (!variableName) return null

    // Analyze usage patterns to suggest appropriate default
    const usagePattern = this.analyzeVariableUsage(variableName, text)

    switch (usagePattern) {
      case 'numeric':
        return { value: '0', confidence: 'medium' }
      case 'string':
        return { value: "''", confidence: 'medium' }
      case 'boolean':
        return { value: 'false', confidence: 'medium' }
      case 'array':
        return { value: '[]', confidence: 'medium' }
      case 'object':
        return { value: '{}', confidence: 'low' }
      default:
        return { value: 'null', confidence: 'low' }
    }
  }

  analyzeVariableUsage(variableName, text) {
    // Simple heuristic based on usage patterns in the code
    const lines = text.split('\n')

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (line.includes(variableName)) {
        // Check for common patterns
        if (line.includes('+') || line.includes('-') || line.includes('*') || line.includes('/')) {
          return 'numeric'
        }
        if (line.includes('.push(') || line.includes('.map(') || line.includes('.filter(')) {
          return 'array'
        }
        if (line.includes('===') || line.includes('!==')) {
          return 'boolean'
        }
        if (line.includes('.length') || line.includes('.charAt(')) {
          return 'string'
        }
      }
    }

    return 'unknown'
  }

  findUntypedParameter(node) {
    let current = node
    while (current && current.kind !== ts.SyntaxKind.SourceFile) {
      if (ts.isParameter(current)) {
        // Check if it has no type annotation
        if (!current.type) {
          return current
        }
      }
      current = current.parent
    }
    return null
  }

  inferParameterTypeFromUsage(checker, parameterNode, sourceFile) {
    // Find the function declaration
    let current = parameterNode
    while (current && !ts.isFunctionDeclaration(current) && !ts.isArrowFunction(current) && !ts.isMethodDeclaration(current)) {
      current = current.parent
    }

    if (!current) return null

    // Analyze parameter usage within function body
    const parameterName = parameterNode.name.getText()
    const usages = []

    function walk(node) {
      if (ts.isIdentifier(node) && node.getText() === parameterName && node !== parameterNode.name) {
        usages.push(node)
      }
      ts.forEachChild(node, walk)
    }

    if (current.body) {
      ts.forEachChild(current.body, walk)
    }

    if (usages.length === 0) return null

    // Infer type from most common usage
    const inferredTypes = usages.map(usage => this.getTypeFromUsage(checker, usage))
      .filter(Boolean)

    if (inferredTypes.length > 0) {
      const typeCounts = new Map()
      for (const inferred of inferredTypes) {
        typeCounts.set(inferred.type, (typeCounts.get(inferred.type) || 0) + 1)
      }

      const mostCommon = [...typeCounts.entries()]
        .sort(([,a], [,b]) => b - a)[0]

      return {
        type: mostCommon[0],
        confidence: 'medium'
      }
    }

    return null
  }

  tryAddDefiniteAssignmentAssertion(variableNode) {
    const name = variableNode.name?.getText()
    if (!name) return null

    return {
      replacement: '!',
      start: variableNode.name.getEnd(),
      end: variableNode.name.getEnd(),
      confidence: 'low',
      description: 'Add definite assignment assertion (!)'
    }
  }

  tryInitializeVariable(variableNode, text) {
    const defaultInit = this.generateDefaultInitializer(null, variableNode, text)
    if (defaultInit) {
      return {
        replacement: ` = ${defaultInit.value}`,
        start: variableNode.getEnd(),
        end: variableNode.getEnd(),
        confidence: defaultInit.confidence,
        description: `Initialize variable with: ${defaultInit.value}`
      }
    }
    return null
  }

  tryMakeOptional(variableNode) {
    const name = variableNode.name?.getText()
    if (!name) return null

    return {
      replacement: '?',
      start: variableNode.name.getEnd(),
      end: variableNode.name.getEnd(),
      confidence: 'medium',
      description: 'Make variable optional'
    }
  }

  /**
   * Apply fixes to a file
   */
  async applyFileFixes(filePath, text, fixes) {
    if (fixes.length === 0) return

    // Sort fixes by position (last to first to avoid offset issues)
    fixes.sort((a, b) => b.start - a.start)

    let modifiedText = text
    let appliedFixes = 0

    for (const fix of fixes) {
      if (fix.start === -1 && fix.end === -1) {
        // This is a suggestion, not a fix
        if (VERBOSE) {
          console.log(`💡 Suggestion: ${fix.description}`)
        }
        continue
      }

      // Apply the fix
      modifiedText = modifiedText.slice(0, fix.start) +
                     fix.replacement +
                     modifiedText.slice(fix.end)

      appliedFixes++

      if (VERBOSE) {
        console.log(`  ✅ Applied: ${fix.type} (${fix.confidence} confidence) - ${fix.description}`)
      }
    }

    // Write the modified text back to the file
    if (APPLY && appliedFixes > 0) {
      // Create backup before applying changes
      await this.createBackup(filePath)
      fs.writeFileSync(filePath, modifiedText, 'utf8')

      if (VERBOSE) {
        console.log(`  💾 Saved ${appliedFixes} fixes to ${path.relative(CWD, filePath)}`)
      }
    }

    this.stats.totalFixes += appliedFixes
  }

  /**
   * Create backup of file before modification
   */
  async createBackup(filePath) {
    const backupPath = `${filePath}.ts-fix-backup-${Date.now()}`
    fs.copyFileSync(filePath, backupPath)

    if (VERBOSE) {
      console.log(`  📋 Backup created: ${path.relative(CWD, backupPath)}`)
    }
  }

  /**
   * Update fix statistics
   */
  updateFixStats(errorCode) {
    switch (errorCode) {
      case 18048:
        this.fixes.implicitAny++
        break
      case 7005:
        this.fixes.variableUsage++
        break
      case 7006:
        this.fixes.parameterTyping++
        break
      case 2564:
        this.fixes.definiteAssignment++
        break
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      fixes: this.fixes,
      mode: APPLY ? 'apply' : 'dry-run'
    }
  }

  /**
   * Print summary
   */
  printSummary() {
    console.log('\n📊 High Severity Error Fixer Summary')
    console.log('='.repeat(45))
    console.log(`📁 Files processed: ${this.stats.filesProcessed}`)
    console.log(`🔧 Total fixes: ${this.stats.totalFixes}`)
    console.log(`\nBreakdown by error type:`)
    console.log(`  • Implicit any (TS18048): ${this.fixes.implicitAny}`)
    console.log(`  • Variable usage (TS7005): ${this.fixes.variableUsage}`)
    console.log(`  • Parameter typing (TS7006): ${this.fixes.parameterTyping}`)
    console.log(`  • Definite assignment (TS2564): ${this.fixes.definiteAssignment}`)

    if (this.stats.errors.length > 0) {
      console.log(`\n⚠️ Errors encountered: ${this.stats.errors.length}`)
      this.stats.errors.forEach(error => console.log(`  • ${error}`))
    }

    console.log(`\nMode: ${APPLY ? 'APPLIED' : 'DRY RUN'}`)
  }
}

// Execute the fixer
const fixer = new HighSeverityFixer()
fixer.run()
  .then(stats => {
    writeLogs({ pass: 'high-severity', ...stats }, DRY_RUN)
    console.log(`\n🎯 High severity fixer ${DRY_RUN ? 'dry run' : 'applied'}: ${stats.filesProcessed} file(s), ${stats.totalFixes} fix(es)`)
    process.exit(0)
  })
  .catch(error => {
    console.error('\n❌ High severity fixer failed:', error.message)
    process.exit(1)
  })