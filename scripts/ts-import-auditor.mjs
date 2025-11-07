#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { loadProgram, writeLogs, SRC_DIR } from './ts-fix-utils.mjs'

const argv = process.argv.slice(2)
const APPLY = argv.includes('--apply-import-fixes')

function readPathsFromTsconfig() {
  const configPath = ts.findConfigFile(process.cwd(), ts.sys.fileExists, 'tsconfig.json')
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile)
  const config = configFile.config || {}
  const baseUrl = config.compilerOptions?.baseUrl || '.'
  const paths = config.compilerOptions?.paths || { '@/*': ['src/*'] }
  return { baseUrl, paths }
}

function resolveAliasCandidate(spec) {
  // e.g., '../../utils/logger' -> '@/utils/logger'
  const rel = path.resolve(path.dirname(spec.file), spec.request)
  if (!rel.startsWith(SRC_DIR)) return null
  const underSrc = path.relative(SRC_DIR, rel).replace(/\\/g, '/')
  return `@/${underSrc}`
}

function bestExistingTarget(alias) {
  // Try .ts, .tsx, .js; also handle logger-wrapper fallback
  const rel = alias.replace(/^@\//, '')
  const base = path.join(SRC_DIR, rel)
  const candidates = [ `${base}.ts`, `${base}.tsx`, `${base}.js`, base, `${base}/index.ts`, `${base}/index.tsx`, `${base}/index.js` ]
  for (const c of candidates) if (fs.existsSync(c)) return c
  // Special fallback for known pattern: logger -> logger-wrapper
  if (/\/utils\/logger$/.test(base)) {
    const lw = base.replace(/logger$/, 'logger-wrapper')
    const c2 = [`${lw}.ts`, `${lw}.tsx`, `${lw}.js`]
    for (const c of c2) if (fs.existsSync(c)) return c
  }
  return null
}

function toImportSpecifier(fsPath) {
  const rel = path.relative(SRC_DIR, fsPath).replace(/\\/g, '/')
  const noExt = rel.replace(/\.(ts|tsx|js)$/, '')
  return `@/${noExt}.js`
}

function collect2307() {
  const program = loadProgram()
  const diags = ts.getPreEmitDiagnostics(program).filter(d => d.code === 2307)
  return { program, diags }
}

function auditAndMaybeFix() {
  const { program, diags } = collect2307()
  const results = []
  for (const d of diags) {
    if (!d.file || d.start == null) continue
    const sf = d.file
    const pos = d.start
    // Find import declaration at/above this position
    let node = (function walk(n){ if (pos >= n.getStart() && pos < n.getEnd()) return ts.forEachChild(n, walk) || n })(sf)
    while (node && !ts.isImportDeclaration(node)) node = node.parent
    if (!node || !ts.isStringLiteral(node.moduleSpecifier)) continue
    const spec = node.moduleSpecifier.text
    // Only handle problematic relatives like ../../utils/logger
    if (!(spec.startsWith('./') || spec.startsWith('../'))) continue
    const alias = resolveAliasCandidate({ file: sf.fileName, request: spec })
    if (!alias) continue
    const fsTarget = bestExistingTarget(alias)
    if (!fsTarget) continue
    const suggested = toImportSpecifier(fsTarget)
    results.push({ file: sf.fileName, from: spec, to: suggested, start: node.moduleSpecifier.getStart(), end: node.moduleSpecifier.getEnd() })
  }
  // Deduplicate per file+from
  const byFile = new Map()
  for (const r of results) {
    const k = `${r.file}::${r.from}`
    if (!byFile.has(k)) byFile.set(k, r)
  }
  const unique = [...byFile.values()]
  // Fallback: well-known logger path correction
  const loggerFile = path.join(SRC_DIR, 'utils', 'logger.ts')
  if (fs.existsSync(loggerFile)) {
    const pattern = /from\s+['"]\.\.\/\.\.\/utils\/logger['"]/g
    const candidates = []
    for (const sf of program.getSourceFiles()) {
      if (!sf.fileName.startsWith(SRC_DIR) || sf.isDeclarationFile) continue
      const text = fs.readFileSync(sf.fileName, 'utf8')
      if (pattern.test(text)) {
        candidates.push(sf.fileName)
        if (APPLY) {
          const out = text.replace(pattern, "from '@/utils/logger.js'")
          fs.writeFileSync(sf.fileName, out)
        }
      }
    }
    if (candidates.length) {
      for (const f of candidates) console.log(`${path.relative(process.cwd(), f)}: '../../utils/logger' -> '@/utils/logger.js'`)
    }
  }
  if (APPLY) {
    // group by file and apply
    const group = new Map()
    for (const r of unique) { if (!group.has(r.file)) group.set(r.file, []); group.get(r.file).push(r) }
    for (const [file, edits] of group) {
      const text = fs.readFileSync(file, 'utf8')
      const sorted = edits.sort((a,b)=>a.start-b.start)
      let out = ''
      let cur = 0
      for (const e of sorted) {
        const quote = text[e.start]
        out += text.slice(cur, e.start) + `${quote}${e.to}${quote}`
        cur = e.end
      }
      out += text.slice(cur)
      fs.writeFileSync(file, out)
    }
  }
  writeLogs({ pass: 'imports-audit', suggestions: unique.length }, !APPLY)
  for (const r of unique) console.log(`${path.relative(process.cwd(), r.file)}: '${r.from}' -> '${r.to}'`)
  console.log(`Import auditor ${APPLY? 'applied' : 'suggested'} ${unique.length} fix(es).` )
}

auditAndMaybeFix()
