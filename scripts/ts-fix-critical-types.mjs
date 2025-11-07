#!/usr/bin/env node

/**
 * TypeScript Critical Types Fixer
 *
 * Automated fix script for critical TypeScript errors:
 * - TS2307: Cannot find module
 * - TS2322: Type assignment error
 * - TS2339: Property does not exist
 * - TS2345: Argument type mismatch
 */

import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import {
  CWD, SRC_DIR, ensureDirs, loadProgram, writeLogs,
  pathIsLocal, stableSortStrings
} from './ts-fix-utils.mjs'

const args = new Set(process.argv.slice(2))
const APPLY = args.has('--apply')
const LIMIT = (() => { const i = process.argv.indexOf('--limit'); return i>0? Number(process.argv[i+1]) : undefined })()
const DRY_RUN = !APPLY
const VERBOSE = args.has('--verbose')

class CriticalTypesFixer {
  constructor() {
    this.fixes = {
      moduleResolution: 0,
      typeAssignments: 0,
      propertyAccess: 0,
      argumentTypes: 0
    }
    this.edits = []
    this.stats = {
      filesProcessed: 0,
      totalFixes: 0,
      errors: []
    }
  }

  /**
   * Main execution method
   */
  async run() {
    try {
      console.log('🔧 TypeScript Critical Types Fixer - Starting analysis')

      const program = loadProgram()
      const checker = program.getTypeChecker()

      // Get all diagnostic errors
      const diagnostics = ts.getPreEmitDiagnostics(program)
        .filter(d => this.isTargetError(d.code))
        .slice(0, LIMIT || Infinity)

      if (diagnostics.length === 0) {
        console.log('✅ No critical type errors found to fix')
        return this.getStats()
      }

      console.log(`📊 Found ${diagnostics.length} critical type errors to analyze`)

      // Group diagnostics by file for efficient processing
      const diagnosticsByFile = this.groupDiagnosticsByFile(diagnostics)

      // Process each file
      for (const [filePath, fileDiagnostics] of diagnosticsByFile) {
        await this.processFile(program, checker, filePath, fileDiagnostics)
      }

      console.log('✅ Critical types fixer completed')
      this.printSummary()

      return this.getStats()

    } catch (error) {
      console.error('❌ Critical types fixer failed:', error.message)
      this.stats.errors.push(error.message)
      throw error
    }
  }

  /**
   * Check if error code is in target scope
   */
  isTargetError(code) {
    const targetCodes = [2307, 2322, 2339, 2345]
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
        const fix = await this.createFix(program, checker, diag, text)
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
  async createFix(program, checker, diagnostic, text) {
    const code = diagnostic.code
    if (!diagnostic.start || !diagnostic.file) return null

    try {
      switch (code) {
        case 2307: // Cannot find module
          return await this.fixModuleResolution(program, diagnostic, text)

        case 2322: // Type assignment error
          return await this.fixTypeAssignment(program, checker, diagnostic, text)

        case 2339: // Property does not exist
          return await this.fixPropertyAccess(program, checker, diagnostic, text)

        case 2345: // Argument type mismatch
          return await this.fixArgumentType(program, checker, diagnostic, text)

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
   * Fix TS2307: Cannot find module
   */
  async fixModuleResolution(program, diagnostic, text) {
    const message = diagnostic.messageText?.toString() || ''

    // Try to extract module name from error message
    const moduleMatch = message.match(/Cannot find module '([^']+)'/)
    if (!moduleMatch) return null

    const moduleName = moduleMatch[1]

    // Try different resolution strategies
    const strategies = [
      () => this.tryRelativePathFix(moduleName, text),
      () => this.tryNodeModulesFix(moduleName),
      () => this.tryIndexFileFix(moduleName, text)
    ]

    for (const strategy of strategies) {
      const fix = await strategy()
      if (fix) {
        return {
          type: 'module-resolution',
          code: 2307,
          original: moduleName,
          replacement: fix.replacement,
          start: fix.start,
          end: fix.end,
          confidence: fix.confidence || 'medium'
        }
      }
    }

    return null
  }

  /**
   * Try to fix relative path issues
   */
  tryRelativePathFix(moduleName, text) {
    if (!moduleName.startsWith('./') && !moduleName.startsWith('../')) {
      return null
    }

    // Check if adding .js extension would work
    if (!moduleName.endsWith('.js') && !moduleName.endsWith('.json')) {
      const withExtension = `${moduleName}.js`
      const moduleMatch = text.find(new RegExp(`['"]${moduleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`))

      if (moduleMatch) {
        return {
          replacement: withExtension,
          start: text.indexOf(moduleMatch),
          end: text.indexOf(moduleMatch) + moduleMatch.length,
          confidence: 'high'
        }
      }
    }

    return null
  }

  /**
   * Try to fix node_modules issues
   */
  tryNodeModulesFix(moduleName) {
    // Check if package needs to be installed
    const packageJsonPath = path.join(CWD, 'package.json')
    if (!fs.existsSync(packageJsonPath)) return null

    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'))

      // Simple heuristic: if module starts with @ and has two parts, it's likely a scoped package
      if (moduleName.startsWith('@') && moduleName.split('/').length === 2) {
        return {
          replacement: `// Consider installing: npm install ${moduleName}`,
          start: -1, // Indicates suggestion rather than replacement
          end: -1,
          confidence: 'low'
        }
      }
    } catch (error) {
      // Package.json might be malformed
    }

    return null
  }

  /**
   * Try to fix index file issues
   */
  tryIndexFileFix(moduleName, text) {
    if (!moduleName.endsWith('/index')) {
      const withIndex = `${moduleName}/index`
      const moduleMatch = text.find(new RegExp(`['"]${moduleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`))

      if (moduleMatch) {
        return {
          replacement: withIndex,
          start: text.indexOf(moduleMatch),
          end: text.indexOf(moduleMatch) + moduleMatch.length,
          confidence: 'medium'
        }
      }
    }

    return null
  }

  /**
   * Fix TS2322: Type assignment error
   */
  async fixTypeAssignment(program, checker, diagnostic, text) {
    const message = diagnostic.messageText?.toString() || ''

    // Extract type information from error message
    const typeMatch = message.match(/Type '(.+?)' is not assignable to type '(.+?)'/)
    if (!typeMatch) return null

    const [_, sourceType, targetType] = typeMatch

    // Try common type fixes
    const strategies = [
      () => this.tryTypeAssertion(diagnostic, text, targetType),
      () => this.tryTypeCasting(diagnostic, text, targetType),
      () => this.tryGenericTypeFix(diagnostic, text, targetType)
    ]

    for (const strategy of strategies) {
      const fix = await strategy()
      if (fix) {
        return {
          type: 'type-assignment',
          code: 2322,
          sourceType,
          targetType,
          ...fix,
          confidence: fix.confidence || 'medium'
        }
      }
    }

    return null
  }

  /**
   * Try type assertion fix
   */
  tryTypeAssertion(diagnostic, text, targetType) {
    // This is a simplified implementation
    // In a real scenario, you'd need to locate the exact expression and add type assertion
    return {
      replacement: `as ${targetType}`,
      start: diagnostic.start,
      end: diagnostic.start,
      confidence: 'medium'
    }
  }

  /**
   * Try type casting fix
   */
  tryTypeCasting(diagnostic, text, targetType) {
    // Add angle bracket type cast
    return {
      replacement: `<${targetType}>`,
      start: diagnostic.start,
      end: diagnostic.start,
      confidence: 'low'
    }
  }

  /**
   * Try generic type fix
   */
  tryGenericTypeFix(diagnostic, text, targetType) {
    // This would involve more complex analysis for generic type parameters
    return null
  }

  /**
   * Fix TS2339: Property does not exist
   */
  async fixPropertyAccess(program, checker, diagnostic, text) {
    const message = diagnostic.messageText?.toString() || ''

    // Extract property information
    const propMatch = message.match(/Property '(.+?)' does not exist on type '(.+?)'/)
    if (!propMatch) return null

    const [_, propertyName, typeName] = propMatch

    // Try different strategies
    const strategies = [
      () => this.tryOptionalChaining(diagnostic, text, propertyName),
      () => this.tryPropertyAugmentation(diagnostic, text, propertyName, typeName),
      () => this.tryIndexSignature(diagnostic, text, propertyName)
    ]

    for (const strategy of strategies) {
      const fix = await strategy()
      if (fix) {
        return {
          type: 'property-access',
          code: 2339,
          propertyName,
          typeName,
          ...fix,
          confidence: fix.confidence || 'medium'
        }
      }
    }

    return null
  }

  /**
   * Try optional chaining fix
   */
  tryOptionalChaining(diagnostic, text, propertyName) {
    // Replace .property with ?.property
    const propertyAccess = `.${propertyName}`
    const optionalChaining = `?.${propertyName}`

    const matches = [...text.matchAll(new RegExp(`\\.${propertyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'))]

    if (matches.length > 0) {
      const match = matches[0]
      return {
        replacement: optionalChaining,
        start: match.index,
        end: match.index + propertyAccess.length,
        confidence: 'high'
      }
    }

    return null
  }

  /**
   * Try property augmentation
   */
  tryPropertyAugmentation(diagnostic, text, propertyName, typeName) {
    // This would involve adding the property to the interface/type definition
    // For now, return a suggestion
    return {
      replacement: `// Consider adding ${propertyName}?: any to ${typeName} interface`,
      start: -1,
      end: -1,
      confidence: 'low'
    }
  }

  /**
   * Try index signature fix
   */
  tryIndexSignature(diagnostic, text, propertyName) {
    // This would involve using bracket notation for dynamic property access
    return null
  }

  /**
   * Fix TS2345: Argument type mismatch
   */
  async fixArgumentType(program, checker, diagnostic, text) {
    const message = diagnostic.messageText?.toString() || ''

    // Extract argument and parameter type information
    const argMatch = message.match(/Argument of type '(.+?)' is not assignable to parameter of type '(.+?)'/)
    if (!argMatch) return null

    const [_, argType, paramType] = argMatch

    // Try different strategies
    const strategies = [
      () => this.tryArgumentTypeAssertion(diagnostic, text, paramType),
      () => this.tryArgumentCasting(diagnostic, text, paramType),
      () => this.tryFunctionOverload(diagnostic, text, paramType)
    ]

    for (const strategy of strategies) {
      const fix = await strategy()
      if (fix) {
        return {
          type: 'argument-type',
          code: 2345,
          argType,
          paramType,
          ...fix,
          confidence: fix.confidence || 'medium'
        }
      }
    }

    return null
  }

  /**
   * Try argument type assertion
   */
  tryArgumentTypeAssertion(diagnostic, text, paramType) {
    return {
      replacement: `as ${paramType}`,
      start: diagnostic.start,
      end: diagnostic.start,
      confidence: 'medium'
    }
  }

  /**
   * Try argument casting
   */
  tryArgumentCasting(diagnostic, text, paramType) {
    return {
      replacement: `<${paramType}>`,
      start: diagnostic.start,
      end: diagnostic.start,
      confidence: 'low'
    }
  }

  /**
   * Try function overload
   */
  tryFunctionOverload(diagnostic, text, paramType) {
    // This would involve finding appropriate function overload or creating one
    return null
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
          console.log(`💡 Suggestion: ${fix.replacement}`)
        }
        continue
      }

      // Apply the fix
      modifiedText = modifiedText.slice(0, fix.start) +
                     fix.replacement +
                     modifiedText.slice(fix.end)

      appliedFixes++

      if (VERBOSE) {
        console.log(`  ✅ Applied: ${fix.type} (${fix.confidence} confidence)`)
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
      case 2307:
        this.fixes.moduleResolution++
        break
      case 2322:
        this.fixes.typeAssignments++
        break
      case 2339:
        this.fixes.propertyAccess++
        break
      case 2345:
        this.fixes.argumentTypes++
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
    console.log('\n📊 Critical Types Fixer Summary')
    console.log('='.repeat(40))
    console.log(`📁 Files processed: ${this.stats.filesProcessed}`)
    console.log(`🔧 Total fixes: ${this.stats.totalFixes}`)
    console.log(`\nBreakdown by error type:`)
    console.log(`  • Module resolution (TS2307): ${this.fixes.moduleResolution}`)
    console.log(`  • Type assignment (TS2322): ${this.fixes.typeAssignments}`)
    console.log(`  • Property access (TS2339): ${this.fixes.propertyAccess}`)
    console.log(`  • Argument types (TS2345): ${this.fixes.argumentTypes}`)

    if (this.stats.errors.length > 0) {
      console.log(`\n⚠️ Errors encountered: ${this.stats.errors.length}`)
      this.stats.errors.forEach(error => console.log(`  • ${error}`))
    }

    console.log(`\nMode: ${APPLY ? 'APPLIED' : 'DRY RUN'}`)
  }
}

// Execute the fixer
const fixer = new CriticalTypesFixer()
fixer.run()
  .then(stats => {
    writeLogs({ pass: 'critical-types', ...stats }, DRY_RUN)
    console.log(`\n🎯 Critical types fixer ${DRY_RUN ? 'dry run' : 'applied'}: ${stats.filesProcessed} file(s), ${stats.totalFixes} fix(es)`)
    process.exit(0)
  })
  .catch(error => {
    console.error('\n❌ Critical types fixer failed:', error.message)
    process.exit(1)
  })