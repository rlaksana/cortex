#!/usr/bin/env node
import { revertLastGenerated } from './ts-fix-utils.mjs'

if (revertLastGenerated()) {
  console.log('Restored previous auto-augmentations.d.ts from stash.')
  process.exit(0)
}
console.log('No stashed augmentations found.')
process.exit(1)
