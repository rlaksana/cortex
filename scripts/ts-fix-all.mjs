#!/usr/bin/env node
import { loadProgram, countDiagnosticsByCode, writeLogs } from './ts-fix-utils.mjs'
import { spawnSync } from 'node:child_process'

const args = process.argv.slice(2)
const APPLY = args.includes('--apply')
const LIMIT = (() => { const i = args.indexOf('--limit'); return i>0? ['--limit', args[i+1]]: [] })()
const ALLOW = (() => { const i = args.indexOf('--allowlist'); return i>0? ['--allowlist', args[i+1]]: [] })()

function runScript(script, extra=[]) {
  const res = spawnSync(process.execPath, [script, ...(APPLY? ['--apply'] : []), ...LIMIT, ...ALLOW, ...extra], { stdio: 'inherit' })
  return res.status || 0
}

function snapshot(label) {
  const program = loadProgram()
  const counts = countDiagnosticsByCode(program, [2339, 18048, 2307, 2304])
  return { label, counts }
}

const before = snapshot('before')
runScript('scripts/ts-fix-imports.mjs')
runScript('scripts/ts-fix-interfaces.mjs')
runScript('scripts/ts-fix-nullability.mjs')
const after = snapshot('after')

const delta = {
  pass: 'all',
  before: before.counts,
  after: after.counts,
  diff: Object.fromEntries(Object.entries(after.counts).map(([k,v]) => [k, v - (before.counts[k]||0)]))
}
writeLogs(delta, !APPLY)
console.log('Delta:', JSON.stringify(delta, null, 2))
