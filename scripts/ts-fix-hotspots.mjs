#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { SRC_DIR, ensureDirs, loadProgram, writeLogs, pathIsLocal, stableSortStrings, LOG_DIR } from './ts-fix-utils.mjs'

const argv = process.argv.slice(2)
const args = new Set(argv)
const APPLY = args.has('--apply')
const TOP = (() => { const i = argv.indexOf('--hotspots'); if (i>0) { const m = /top=(\d+)/.exec(argv[i+1]||''); return m? Number(m[1]) : 5 } return 5 })()
const NARROW = (() => { const i = argv.indexOf('--narrow'); return i>0? (String(argv[i+1]).toLowerCase()==='on') : false })()
const CONTEXT_LINES = (() => { const i = argv.indexOf('--hotspots'); if (i>0) { const m = /lines=(\d+)/.exec(argv[i+1]||''); return m? Number(m[1]) : 2 } return 2 })()

function getNodeAt(sf, pos) {
  function walk(node){ if (pos >= node.getStart() && pos < node.getEnd()) return ts.forEachChild(node, walk) || node }
  return walk(sf)
}

function classifyTypeFromUsage(accessNode) {
  const parent = accessNode.parent
  if (!parent) return 'unknown'
  if (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.ExclamationToken) return 'boolean'
  if (ts.isIfStatement(parent) || ts.isWhileStatement(parent) || ts.isDoStatement(parent) || ts.isForStatement(parent)) return 'boolean'
  if (ts.isBinaryExpression(parent)) {
    const op = parent.operatorToken.kind
    const strOps = [ts.SyntaxKind.PlusToken]
    const numOps = [ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken]
    if (strOps.includes(op)) {
      if (ts.isStringLiteral(parent.left) || ts.isStringLiteral(parent.right)) return 'string'
    }
    if (numOps.includes(op)) return 'number'
    if (op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken) {
      if (ts.isTrueKeyword(parent.right?.kind) || ts.isFalseKeyword(parent.right?.kind)) return 'boolean'
      if (ts.isTrueKeyword(parent.left?.kind) || ts.isFalseKeyword(parent.left?.kind)) return 'boolean'
    }
  }
  if (ts.isCallExpression(parent)) {
    // simple string-y calls
    const name = parent.expression.getText()
    if (/toString|substring|slice|startsWith|endsWith|includes/.test(name)) return 'string'
  }
  return 'unknown'
}

function run() {
  ensureDirs()
  const program = loadProgram()
  const checker = program.getTypeChecker()
  const diags = ts.getPreEmitDiagnostics(program).filter(d => d.code === 2339)
  const map = new Map() // key: type#prop -> {count, samples: Array}
  const localPairs = new Map() // key -> type 'string'|'number'|'boolean'|'unknown'
  for (const d of diags) {
    if (!d.file || d.start == null) continue
    const sf = d.file
    const node = getNodeAt(sf, d.start)
    if (!node) continue
    let access = node
    while (access && !ts.isPropertyAccessExpression(access)) access = access.parent
    if (!access) continue
    const leftType = checker.getTypeAtLocation(access.expression)
    const sym = leftType.getSymbol()
    if (!sym) continue
    const decls = sym.getDeclarations() || []
    const decl = decls.find(x => ts.isInterfaceDeclaration(x) || ts.isClassDeclaration(x))
    if (!decl || !decl.name) continue
    const typeName = decl.name.text
    const prop = access.name.text
    const key = `${typeName}#${prop}`
    const { line } = ts.getLineAndCharacterOfPosition(sf, d.start)
    const lines = sf.getFullText().split(/\r?\n/)
    const start = Math.max(0, line - CONTEXT_LINES)
    const end = Math.min(lines.length - 1, line + CONTEXT_LINES)
    const snippet = lines.slice(start, end + 1).join('\\n')
    if (!map.has(key)) map.set(key, { count: 0, samples: [] })
    const entry = map.get(key)
    entry.count++
    if (entry.samples.length < 3) entry.samples.push({ file: sf.fileName, line: line + 1, snippet })
    if (pathIsLocal(decl.getSourceFile().fileName)) {
      const kind = classifyTypeFromUsage(access)
      if (!localPairs.has(key)) localPairs.set(key, new Set())
      localPairs.get(key).add(kind)
    }
  }

  // Write CSV
  const rows = ['symbol,prop,count,file,line,snippet']
  const sorted = [...map.entries()].sort((a,b)=>b[1].count - a[1].count)
  for (const [key, val] of sorted) {
    const [typeName, prop] = key.split('#')
    const samples = val.samples.length ? val.samples : [{ file: '', line: '', snippet: '' }]
    for (const s of samples) {
      const safeSnippet = String(s.snippet || '').replace(/"/g, '""')
      rows.push(`${typeName},${prop},${val.count},${s.file},${s.line},"${safeSnippet}"`)
    }
  }
  fs.writeFileSync(path.join(LOG_DIR, 'hotspots.csv'), rows.join('\n'))

  // Optional narrowing on top N local pairs
  let narrowed = 0
  if (NARROW && APPLY) {
    const top = sorted.filter(([k]) => localPairs.has(k)).slice(0, TOP)
    // Build per-file edits
    const perFile = new Map()
    for (const [key] of top) {
      const [typeName, prop] = key.split('#')
      // choose type by priority: number > string > boolean > unknown
      const kinds = localPairs.get(key)
      let t = 'unknown'
      if (kinds.has('number')) t = 'number'
      else if (kinds.has('string')) t = 'string'
      else if (kinds.has('boolean')) t = 'boolean'
      // locate local interface declaration
      for (const sf of program.getSourceFiles()) {
        if (!pathIsLocal(sf.fileName)) continue
        let target = null
        ts.forEachChild(sf, function walk(n){
          if ((ts.isInterfaceDeclaration(n) || ts.isClassDeclaration(n)) && n.name?.text === typeName) target = n
          ts.forEachChild(n, walk)
        })
        if (!target) continue
        const text = sf.getFullText()
        const open = text.indexOf('{', target.pos)
        const close = (()=>{ let depth=0; for (let i=open;i<text.length;i++){ const ch=text[i]; if(ch==='{' ) depth++; else if(ch==='}') { depth--; if(depth===0) return i } } return -1 })()
        if (open<0 || close<0) continue
        const body = text.slice(open, close)
        const re = new RegExp(`\\b${prop}\\?\\s*:`)
        if (re.test(body)) continue // already present via earlier pass
        if (!perFile.has(sf.fileName)) perFile.set(sf.fileName, [])
        perFile.get(sf.fileName).push({ insertAt: close, line: `\n  ${prop}?: ${t}|undefined` })
        narrowed++
        break
      }
    }
    for (const [file, edits] of perFile) {
      const original = fs.readFileSync(file, 'utf8')
      let out = original
      const sortedEdits = edits.sort((a,b)=>b.insertAt-a.insertAt)
      for (const e of sortedEdits) out = out.slice(0, e.insertAt) + e.line + out.slice(e.insertAt)
      fs.writeFileSync(file, out)
    }
  }

  writeLogs({ pass: 'hotspots', totalPairs: sorted.length, topConsidered: Math.min(TOP, sorted.length), narrowed }, !APPLY)
  console.log(`Hotspots written to ${path.join(LOG_DIR, 'hotspots.csv')}. Narrowed ${narrowed} prop(s).`)
}

run()
