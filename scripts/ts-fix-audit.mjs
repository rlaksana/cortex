#!/usr/bin/env node
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'

// Run full pass in dry-run; exit non-zero if any suggestions logged in latest entry
const res = spawnSync(process.execPath, ['scripts/ts-fix-all.mjs', '--limit', '200'], { stdio: 'inherit' })

// Inspect last JSON entry
try {
  const log = JSON.parse(fs.readFileSync('ts-fix/fix-log.json','utf8'))
  const last = log[log.length - 1]
  // Consider changes if any diff shows reduction negative or modules/files touched lines exist in sibling logs
  // For simplicity, fail when the last delta differs between before and after (i.e., tool proposes changes)
  const proposed = JSON.stringify(last.before) !== JSON.stringify(last.after)
  if (proposed) {
    console.error('ts-fix audit: proposed changes detected (run with --apply to update).')
    process.exit(2)
  }
} catch (e) {
  console.error('ts-fix audit: failed to read logs:', e.message)
  process.exit(3)
}

process.exit(0)
