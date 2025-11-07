#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { SRC_DIR, ensureDirs, writeLogs, loadProgram } from './ts-fix-utils.mjs'

const args = new Set(process.argv.slice(2))
const APPLY = args.has('--apply')
const LIMIT = (() => { const i = process.argv.indexOf('--limit'); return i>0? Number(process.argv[i+1]) : undefined })()

function shouldTouch(filePath) {
  return filePath.endsWith('.ts') && !filePath.endsWith('.d.ts')
}

function fixFile(program, sf) {
  const text = sf.getFullText()
  let edits = []
  let count = 0
  function record(start, end, replacement) { edits.push({ start, end, replacement }); count++ }
  ts.forEachChild(sf, function walk(node){
    if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text
      if (spec.startsWith('./') || spec.startsWith('../')) {
        if (!spec.endsWith('.js') && !spec.endsWith('.json')) {
          const newSpec = `${spec}.js`
          const start = node.moduleSpecifier.getStart()
          const end = node.moduleSpecifier.getEnd()
          const quote = text[start]
          record(start, end, `${quote}${newSpec}${quote}`)
        }
      }
    }
    ts.forEachChild(node, walk)
  })
  if (edits.length === 0) return { changed: false }
  // Apply sequentially left->right
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
  let touched = 0
  let totalChanges = 0
  for (const sf of program.getSourceFiles()) {
    const filePath = sf.fileName
    if (!filePath.startsWith(SRC_DIR) || !shouldTouch(filePath)) continue
    const { changed, content, changes } = fixFile(program, sf)
    if (changed) {
      touched++
      totalChanges += changes
      if (APPLY) fs.writeFileSync(filePath, content)
      if (LIMIT && touched >= LIMIT) break
    }
  }
  return { filesTouched: touched, changes: totalChanges }
}

const result = run()
writeLogs({ pass: 'imports', ...result }, !APPLY)
console.log(`Import fixer ${APPLY? 'applied' : 'dry-run'}: ${result.filesTouched} file(s), ${result.changes} change(s).`)
