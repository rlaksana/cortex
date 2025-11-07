#!/usr/bin/env node
// TS Error Assistant: focuses on TS2339 to suggest/apply optional props to local interfaces.
// Usage:
//   node scripts/ts-error-assistant.mjs           # dry-run
//   node scripts/ts-error-assistant.mjs --apply   # write changes
//   node scripts/ts-error-assistant.mjs --limit 50

import { exec as _exec } from 'node:child_process'
import { promisify } from 'node:util'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import ts from 'typescript'

const exec = promisify(_exec)

const CWD = process.cwd()
const SRC_DIR = path.join(CWD, 'src')

const args = new Set(process.argv.slice(2))
const APPLY = args.has('--apply')
const LIMIT = (() => {
  const idx = process.argv.indexOf('--limit')
  if (idx >= 0 && process.argv[idx + 1]) {
    const n = Number(process.argv[idx + 1])
    return Number.isFinite(n) && n > 0 ? n : undefined
  }
  return undefined
})()

function sanitizeTypeName(raw) {
  if (!raw) return null
  // Strip wrappers like Readonly<...>, Partial<...>, Promise<...>, { ... }
  // Prefer the innermost identifier.
  let s = String(raw)
  // Take first union arm if present
  s = s.split('|')[0].trim()
  // Remove array suffixes and undefined/null
  s = s.replace(/\[\]$/, '').replace(/\b(undefined|null)\b/g, '').trim()
  // Extract identifier inside generics if any
  const m = s.match(/^(?:Readonly|Partial|Pick|Omit|Required|DeepReadonly|Record)<\s*([A-Za-z_$][A-Za-z0-9_$]*)/)
  if (m) return m[1]
  // Basic identifier
  const id = s.match(/^[A-Za-z_$][A-Za-z0-9_$]*/)
  return id ? id[0] : null
}

function parseDiagnosticsFromText(stdout) {
  const lines = stdout.split(/\r?\n/)
  const diagRe = /^(?<file>.+\.(?:ts|tsx))\((?<line>\d+),(?<col>\d+)\): error TS(?<code>\d+): (?<message>.*)$/
  /** @type {Array<{file:string,line:number,col:number,code:number,message:string}>} */
  const diags = []
  for (const line of lines) {
    const m = line.match(diagRe)
    if (!m) continue
    const { file, line: l, col, code, message } = m.groups
    diags.push({ file, line: Number(l), col: Number(col), code: Number(code), message })
  }
  return diags
}

async function runTscNoEmit() {
  // Use project tsconfig.json, pretty=false to stabilize parsing
  const cmd = 'npx tsc --noEmit -p tsconfig.json --pretty false'
  try {
    const { stdout } = await exec(cmd, { cwd: CWD, maxBuffer: 10 * 1024 * 1024 })
    return stdout
  } catch (err) {
    // tsc exits non-zero on errors; we still want its stdout/stderr
    const stdout = err.stdout || ''
    const stderr = err.stderr || ''
    return [stdout, stderr].filter(Boolean).join('\n')
  }
}

function findInterfaceInsertPositions(program, checker, targetName) {
  /** @type {Array<{sourceFile: ts.SourceFile, name: string, start: number, end: number}>} */
  const results = []
  for (const sf of program.getSourceFiles()) {
    const filePath = sf.fileName
    if (!filePath.startsWith(SRC_DIR)) continue // local only
    ts.forEachChild(sf, function walk(node) {
      if (ts.isInterfaceDeclaration(node)) {
        const name = node.name.text
        if (name === targetName) {
          const { pos, end } = node.members
            ? { pos: node.members.pos, end: node.members.end }
            : { pos: node.pos, end: node.end }
          results.push({ sourceFile: sf, name, start: pos, end })
        }
      }
      ts.forEachChild(node, walk)
    })
  }
  return results
}

function interfaceHasPropertyText(sfText, ifaceNode, propName) {
  const bodyText = sfText.slice(ifaceNode.start, ifaceNode.end)
  const re = new RegExp(`\\b${propName}\\?\\s*:`)
  return re.test(bodyText)
}

function applyInterfaceEdits(editsByFile) {
  for (const [filePath, items] of editsByFile) {
    const original = readFileSync(filePath, 'utf8')
    let updated = original
    // Sort descending by insert position to keep offsets valid
    const sorted = items.slice().sort((a, b) => b.insertAt - a.insertAt)
    for (const e of sorted) {
      const insertText = `${e.leading}  ${e.propName}?: unknown\n`
      updated = updated.slice(0, e.insertAt) + insertText + updated.slice(e.insertAt)
    }
    if (updated !== original) {
      writeFileSync(filePath, updated, 'utf8')
      console.log(`✔ Applied ${items.length} insert(s) -> ${path.relative(CWD, filePath)}`)
    }
  }
}

async function main() {
  console.log(`▶ Analyzing TypeScript diagnostics (TS2339 focus)…`)
  const out = await runTscNoEmit()
  const diags = parseDiagnosticsFromText(out)
  const d2339 = diags.filter(d => d.code === 2339)
  if (d2339.length === 0) {
    console.log('No TS2339 diagnostics found. Nothing to suggest.')
    return
  }

  // Group: typeName -> missingProps set
  /** @type {Map<string, Set<string>>} */
  const missingByType = new Map()
  for (const d of d2339) {
    const mm = d.message.match(/Property '([^']+)' does not exist on type '([^']+)'\.?/)
    if (!mm) continue
    const prop = mm[1]
    const rawType = mm[2]
    const typeName = sanitizeTypeName(rawType)
    if (!typeName) continue
    if (!missingByType.has(typeName)) missingByType.set(typeName, new Set())
    missingByType.get(typeName).add(prop)
  }

  if (missingByType.size === 0) {
    console.log('No actionable TS2339 items parsed (non-simple types).')
    return
  }

  const configPath = ts.findConfigFile(CWD, ts.sys.fileExists, 'tsconfig.json')
  if (!configPath) throw new Error('tsconfig.json not found')
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile)
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, path.dirname(configPath))
  const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options })
  const checker = program.getTypeChecker()

  /** @type {Map<string, Array<{propName:string, filePath:string, insertAt:number, leading:string}>>} */
  const editsByFile = new Map()
  const suggestions = []
  let count = 0

  for (const [typeName, props] of missingByType) {
    if (LIMIT && count >= LIMIT) break
    const targets = findInterfaceInsertPositions(program, checker, typeName)
    if (targets.length === 0) {
      suggestions.push({ typeName, props: [...props], action: 'no_local_interface_found' })
      continue
    }
    for (const tgt of targets) {
      const filePath = tgt.sourceFile.fileName
      const sfText = tgt.sourceFile.getFullText()
      const insertAt = tgt.end - 1 // before closing brace
      const leadingWhitespaceMatch = sfText.slice(tgt.start, tgt.end).match(/\n(\s*)[^\n]*$/)
      const leading = leadingWhitespaceMatch ? `\n${leadingWhitespaceMatch[1]}` : '\n  '
      const propsToAdd = [...props].filter(p => !interfaceHasPropertyText(sfText, tgt, p))
      if (propsToAdd.length === 0) {
        suggestions.push({ typeName, filePath, action: 'already_present' })
        continue
      }
      for (const p of propsToAdd) {
        if (LIMIT && count >= LIMIT) break
        count++
        if (!editsByFile.has(filePath)) editsByFile.set(filePath, [])
        editsByFile.get(filePath).push({ propName: p, filePath, insertAt, leading })
        suggestions.push({ typeName, filePath, add: `${p}?: unknown` })
      }
    }
  }

  // Report
  console.log(`\nProposed additions:`)
  for (const s of suggestions) {
    if (s.action === 'no_local_interface_found') {
      console.log(`- [skip] ${s.typeName}: no local interface declaration found`)
    } else if (s.action === 'already_present') {
      console.log(`- [ok] ${path.relative(CWD, s.filePath)} :: ${s.typeName} (already contains property)`)
    } else {
      console.log(`- [add] ${path.relative(CWD, s.filePath)} :: ${s.typeName} -> ${s.add}`)
    }
  }

  const totalAdds = [...editsByFile.values()].reduce((n, arr) => n + arr.length, 0)
  console.log(`\nSummary: ${totalAdds} property suggestion(s) across ${editsByFile.size} file(s).`)
  if (!APPLY) {
    console.log('Dry-run complete. Re-run with --apply to write changes.')
    return
  }
  if (totalAdds === 0) {
    console.log('Nothing to apply.')
    return
  }
  applyInterfaceEdits(editsByFile)
}

main().catch(err => {
  console.error('ts-error-assistant failed:', err?.message || err)
  process.exitCode = 1
})
