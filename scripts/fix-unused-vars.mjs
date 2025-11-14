#!/usr/bin/env node
/**
 * Fix unused variables by adding underscore prefix
 */

import fs from 'node:fs'
import path from 'node:path'
import { execSync } from 'node:child_process'

const SRC_DIR = 'src'
const APPLY = process.argv.includes('--apply')
const DRY_RUN = !APPLY

console.log(`🔧 Unused variables fixer - ${DRY_RUN ? 'DRY RUN' : 'APPLY MODE'}`)

// Get list of files with unused variable errors
function getFilesWithUnusedVars() {
  try {
    const output = execSync('npx eslint "src/**/*.{ts,tsx}" --cache --ignore-pattern "src/chaos-testing/**/*" 2>&1', { encoding: 'utf8' })
    const unusedVarErrors = output
      .split('\n')
      .filter(line => line.includes('error') && line.includes('unused') && line.includes('@typescript-eslint/no-unused-vars'))

    const files = new Set()
    unusedVarErrors.forEach(line => {
      const match = line.match(/^([^(]+):/)
      if (match) {
        files.add(match[1])
      }
    })

    return Array.from(files)
  } catch (error) {
    console.error('Error getting lint output:', error.message)
    return []
  }
}

// Fix unused variables in a single file
function fixUnusedVarsInFile(filePath) {
  if (!fs.existsSync(filePath)) return { fixed: 0, errors: 0 }

  const content = fs.readFileSync(filePath, 'utf8')
  const lines = content.split('\n')

  let fixed = 0
  let errors = 0

  // Get lint errors for this specific file
  try {
    const output = execSync(`npx eslint "${filePath}" --cache 2>&1`, { encoding: 'utf8' })
    const unusedErrors = output
      .split('\n')
      .filter(line => line.includes(filePath) && line.includes('unused') && line.includes('@typescript-eslint/no-unused-vars'))

    for (const errorLine of unusedErrors) {
      try {
        // Parse error line: "file:line:column  error  message  rule"
        const parts = errorLine.trim().split(':')
        if (parts.length < 2) continue

        const lineNum = parseInt(parts[1]) - 1 // Convert to 0-indexed
        if (isNaN(lineNum) || lineNum < 0 || lineNum >= lines.length) continue

        const line = lines[lineNum]

        // Extract variable name from the error message
        const match = errorLine.match(/'([^']+)' is defined but never used/)
        if (!match) continue

        const varName = match[1]

        // Find and replace the variable declaration
        // Handle different declaration patterns
        const patterns = [
          new RegExp(`(\\b(?:const|let|var)\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\bfunction\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\bclass\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\binterface\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\btype\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\benum\\s+)${varName}\\b`, 'g'),
          new RegExp(`(\\bimport\\s+.*\\s+${varName}\\b)`, 'g'),
          // Function parameters
          new RegExp(`(\\()\\s*${varName}\\s*(:)`, 'g'),
          new RegExp(`(,\\s*)${varName}\\s*(:)`, 'g'),
          new RegExp(`(,\\s*)${varName}\\s*(?=\\)|,|\\{)`, 'g'),
        ]

        let lineFixed = false
        for (const pattern of patterns) {
          if (pattern.test(line)) {
            lines[lineNum] = line.replace(pattern, `$1_${varName}$2`)
            fixed++
            lineFixed = true
            break
          }
        }

        // Handle destructuring patterns
        if (!lineFixed) {
          const destructuringPatterns = [
            new RegExp(`(\\{[^}]*)${varName}([^}]*\\})`, 'g'),
            new RegExp(`(\\[[^\\]]*)${varName}([^\\]]*\\])`, 'g'),
          ]

          for (const pattern of destructuringPatterns) {
            if (pattern.test(line)) {
              lines[lineNum] = line.replace(pattern, `$1_${varName}$2`)
              fixed++
              lineFixed = true
              break
            }
          }
        }

      } catch (parseError) {
        errors++
        console.warn(`  ⚠️  Could not parse error line: ${errorLine.trim()}`)
      }
    }

  } catch (error) {
    errors++
    console.warn(`  ⚠️  Error running eslint on ${filePath}: ${error.message}`)
  }

  // Write back if changes were made
  if (fixed > 0 && APPLY) {
    try {
      fs.writeFileSync(filePath, lines.join('\n'), 'utf8')
    } catch (writeError) {
      errors++
      console.warn(`  ⚠️  Could not write to ${filePath}: ${writeError.message}`)
    }
  }

  return { fixed, errors }
}

// Main execution
function main() {
  const files = getFilesWithUnusedVars()
  console.log(`📁 Found ${files.length} files with unused variable errors`)

  let totalFixed = 0
  let totalErrors = 0

  for (const filePath of files) {
    const { fixed, errors } = fixUnusedVarsInFile(filePath)
    totalFixed += fixed
    totalErrors += errors

    if (fixed > 0) {
      console.log(`  ${DRY_RUN ? 'Would fix' : 'Fixed'} ${fixed} unused vars in ${filePath}`)
    }
    if (errors > 0) {
      console.log(`  ❌ ${errors} errors in ${filePath}`)
    }
  }

  console.log(`\n📊 Summary:`)
  console.log(`  Files processed: ${files.length}`)
  console.log(`  Variables ${DRY_RUN ? 'to fix' : 'fixed'}: ${totalFixed}`)
  console.log(`  Errors encountered: ${totalErrors}`)

  if (DRY_RUN) {
    console.log(`\n💡 To apply fixes, run: node scripts/fix-unused-vars.mjs --apply`)
  } else {
    console.log(`\n✅ Fixes applied successfully!`)
  }
}

main()