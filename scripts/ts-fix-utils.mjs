import ts from 'typescript'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const CWD = process.cwd()
export const SRC_DIR = path.join(CWD, 'src')
export const TYPES_DIR = path.join(SRC_DIR, 'types')
export const GEN_TYPES_FILE = path.join(TYPES_DIR, 'auto-augmentations.d.ts')
export const LOG_DIR = path.join(CWD, 'ts-fix')
export const STASH_DIR = path.join(LOG_DIR, 'stash')

export function ensureDirs() {
  for (const dir of [LOG_DIR, STASH_DIR, TYPES_DIR]) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
  }
}

export function loadProgram() {
  const configPath = ts.findConfigFile(CWD, ts.sys.fileExists, 'tsconfig.json')
  if (!configPath) throw new Error('tsconfig.json not found')
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile)
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, path.dirname(configPath))
  return ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options })
}

export function countDiagnosticsByCode(program, codes) {
  const all = ts.getPreEmitDiagnostics(program)
  const map = new Map(codes.map(c => [c, 0]))
  for (const d of all) {
    if (map.has(d.code)) map.set(d.code, (map.get(d.code) || 0) + 1)
  }
  return Object.fromEntries(map)
}

export function writeLogs(delta, dryRun) {
  ensureDirs()
  const tsTxt = path.join(LOG_DIR, 'fix-log.txt')
  const tsJson = path.join(LOG_DIR, 'fix-log.json')
  const now = new Date().toISOString()
  const line = `${now} ${dryRun ? '[dry-run]' : '[apply]'} ${JSON.stringify(delta)}\n`
  fs.appendFileSync(tsTxt, line, 'utf8')
  let existing = []
  if (fs.existsSync(tsJson)) {
    try { existing = JSON.parse(fs.readFileSync(tsJson, 'utf8')) } catch {}
  }
  existing.push({ timestamp: now, mode: dryRun ? 'dry-run' : 'apply', ...delta })
  fs.writeFileSync(tsJson, JSON.stringify(existing, null, 2))
}

export function stashGeneratedFile() {
  ensureDirs()
  if (!fs.existsSync(GEN_TYPES_FILE)) return null
  const tsname = `auto-augmentations.${Date.now()}.d.ts`
  const target = path.join(STASH_DIR, tsname)
  fs.copyFileSync(GEN_TYPES_FILE, target)
  return target
}

export function revertLastGenerated() {
  if (!fs.existsSync(STASH_DIR)) return false
  const files = fs.readdirSync(STASH_DIR).filter(f => f.startsWith('auto-augmentations.') && f.endsWith('.d.ts'))
  if (files.length === 0) return false
  files.sort() // by timestamp
  const last = files[files.length - 1]
  const src = path.join(STASH_DIR, last)
  fs.copyFileSync(src, GEN_TYPES_FILE)
  return true
}

export function pathIsLocal(fileName) {
  const norm = path.normalize(fileName)
  return norm.startsWith(path.normalize(SRC_DIR + path.sep))
}

export function moduleNameFromNodeModules(fileName) {
  const parts = path.normalize(fileName).split(path.sep)
  const idx = parts.lastIndexOf('node_modules')
  if (idx < 0 || idx + 1 >= parts.length) return null
  let name = parts[idx + 1]
  if (name.startsWith('@') && idx + 2 < parts.length) {
    name = `${name}/${parts[idx + 2]}`
  }
  return name
}

export function stableSortStrings(arr) {
  return [...new Set(arr)].sort((a, b) => a.localeCompare(b))
}
