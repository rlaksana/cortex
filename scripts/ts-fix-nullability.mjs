#!/usr/bin/env node
import fs from 'node:fs'
import ts from 'typescript'
import { SRC_DIR, loadProgram, writeLogs } from './ts-fix-utils.mjs'

const argv = process.argv.slice(2)
const args = new Set(argv)
const APPLY = args.has('--apply')
const LIMIT = (() => { const i = argv.indexOf('--limit'); return i>0? Number(argv[i+1]) : undefined })()
const FILES = (() => { const i = argv.indexOf('--files'); return i>0? (argv[i+1]||'').split(',').map(s=>s.trim()).filter(Boolean) : null })()

function transformFile(sf, checker) {
  const text = sf.getFullText()
  let edits = []
  function record(start, end, replacement) { edits.push({ start, end, replacement }) }

  function needsOptionalChain(expr) {
    const t = checker.getTypeAtLocation(expr)
    const flags = t.getFlags()
    // Heuristic: type includes Undefined or Null or a union thereof
    const possiblyNullish = (flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Null)) !== 0 ||
      (t.isUnion() && t.types.some(x => (x.getFlags() & (ts.TypeFlags.Null | ts.TypeFlags.Undefined)) !== 0))
    return possiblyNullish
  }

  function walk(node) {
    if (ts.isPropertyAccessExpression(node)) {
      // a.b -> if a possibly nullish, change to a?.b (but not if already optional)
      if (!node.questionDotToken && needsOptionalChain(node.expression)) {
        const dot = node.expression.getEnd()
        if (text.slice(dot, dot + 1) === '.') {
          record(dot, dot + 1, '?.')
        }
      }
      // Also, if this access itself may be undefined, add optional chain here
      if (!node.questionDotToken) {
        const tnode = checker.getTypeAtLocation(node)
        const flags = tnode.getFlags()
        const maybeUndef = (flags & ts.TypeFlags.Undefined) !== 0 || (tnode.isUnion && tnode.isUnion() && tnode.types.some(x => (x.getFlags() & ts.TypeFlags.Undefined) !== 0))
        if (maybeUndef) {
          const dot = node.expression.getEnd()
          if (text.slice(dot, dot + 1) === '.') {
            record(dot, dot + 1, '?.')
          }
        }
      }
      // Add defensive defaulting for simple numeric/string contexts
      const parent = node.parent
      if (parent && ts.isBinaryExpression(parent)) {
        const op = parent.operatorToken.kind
        const numOps = [ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken]
        if (numOps.includes(op)) {
          const end = node.getEnd()
          record(end, end, ' ?? 0')
        } else if (op === ts.SyntaxKind.PlusToken) {
          // String concatenation default
          const end = node.getEnd()
          record(end, end, " ?? ''")
        }
      }
    }
    ts.forEachChild(node, walk)
  }
  walk(sf)

  if (edits.length === 0) return { changed: false }
  // apply left->right
  edits.sort((a,b)=>a.start-b.start)
  let out = ''
  let cursor = 0
  for (const e of edits) {
    out += text.slice(cursor, e.start) + e.replacement
    cursor = e.end
  }
  out += text.slice(cursor)
  return { changed: true, content: out, changes: edits.length }
}

function run() {
  const program = loadProgram()
  const checker = program.getTypeChecker()
  let filesTouched = 0
  let totalChanges = 0
  for (const sf of program.getSourceFiles()) {
    if (!sf.fileName.startsWith(SRC_DIR) || sf.isDeclarationFile) continue
    if (FILES) {
      const rel = sf.fileName.replace(/\\/g,'/').replace(process.cwd().replace(/\\/g,'/') + '/', '')
      if (!FILES.includes(rel)) continue
    }
    let res = transformFile(sf, checker)
    // Focused fallback for ai-health-monitor.ts: add optional chaining on known bags
    const relPath = sf.fileName.replace(/\\/g,'/').replace(process.cwd().replace(/\\/g,'/') + '/', '')
    if (!res.changed && /src\/monitoring\/ai-health-monitor\.ts$/.test(relPath)) {
      const original = sf.getFullText()
      const replaced = original
        .replace(/\.dependencies\./g, '?.dependencies?.')
        .replace(/\.performance\./g, '?.performance?.')
      if (replaced !== original) {
        res = { changed: true, content: replaced, changes: 1 }
      }
    }
    if (res.changed) {
      filesTouched++
      totalChanges += res.changes
      if (APPLY) fs.writeFileSync(sf.fileName, res.content)
      if (LIMIT && filesTouched >= LIMIT) break
    }
  }
  return { filesTouched, changes: totalChanges }
}

const result = run()
writeLogs({ pass: 'ts18048', ...result }, !APPLY)
console.log(`TS18048 pass ${APPLY? 'applied' : 'dry-run'}: ${result.filesTouched} file(s), ${result.changes} change(s).`)
