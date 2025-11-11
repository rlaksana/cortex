
import { glob } from 'glob';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';
import fs from 'fs';
import { parse } from 'comment-json';

async function fixImportsAndDirectives() {
  console.log('Starting script...');
  const files = await glob('src/**/*.ts', { ignore: 'node_modules/**' });
  console.log(`Found ${files.length} files to process.`);
  const tsConfigContent = await readFile('tsconfig.base.json', 'utf-8');
  const tsConfig = parse(tsConfigContent);
  const paths = tsConfig.compilerOptions.paths;

  for (const file of files) {
    const absolutePath = path.resolve(file);
    let content = await readFile(absolutePath, 'utf-8');
    let changed = false;

    // Fix imports/exports
    const lines = content.split('\n');
    const newLines = lines.map(line => {
      // Remove @ts-nocheck
      if (line.trim().startsWith('// @ts-nocheck')) {
        console.log(`[${file}] Removing @ts-nocheck`);
        changed = true;
        return ''; // Remove the line
      }

      const importMatch = line.match(/^(import|export)(.*)from\s+['"](.*)['"];?$/);
      if (importMatch) {
        const importPath = importMatch[3];
        console.log(`[${file}] Checking import: ${importPath}`);
        if (!path.extname(importPath)) {
            let newImportPath = null;
            if (importPath.startsWith('@/')) {
                const alias = importPath.split('/')[0] + '/*';
                if (paths[alias]) {
                    const realPath = paths[alias][0].replace('*', '');
                    const restOfPath = importPath.substring(importPath.split('/')[0].length + 1);
                    const absoluteImportPath = path.resolve(realPath, restOfPath);
                     if(fs.existsSync(`${absoluteImportPath}.ts`) || fs.existsSync(`${absoluteImportPath}.tsx`)) {
                        newImportPath = `${importPath}.js`;
                    } else if (fs.existsSync(`${absoluteImportPath}/index.ts`) || fs.existsSync(`${absoluteImportPath}/index.tsx`)) {
                        newImportPath = `${importPath}/index.js`;
                    }
                }
            }
            else if (importPath.startsWith('.')) {
                const importAbsolutePath = path.resolve(path.dirname(absolutePath), importPath);
                if (fs.existsSync(`${importAbsolutePath}.ts`) || fs.existsSync(`${importAbsolutePath}.tsx`)) {
                    newImportPath = `${importPath}.js`;
                } else if (fs.existsSync(`${importAbsolutePath}/index.ts`) || fs.existsSync(`${importAbsolutePath}/index.tsx`)) {
                    newImportPath = `${importPath}/index.js`;
                }
            }

            if (newImportPath) {
                const newLine = line.replace(importPath, newImportPath);
                if(line !== newLine) {
                    console.log(`[${file}] Changing import from '${importPath}' to '${newImportPath}'`);
                    changed = true;
                    return newLine;
                }
            }
        }
      }
      return line;
    });

    // Fix no-self-assign
    const selfAssignRegex = /^(.*console\.(?:error|log|warn|debug))\s*=\s*\1;?$/gm;
    let newContent = newLines.join('\n');
    if(selfAssignRegex.test(newContent)){
        console.log(`[${file}] Removing console self-assignments`);
        newContent = newContent.replace(selfAssignRegex, '');
        changed = true;
    }


    if (changed) {
      console.log(`Fixing file: ${file}`);
      await writeFile(absolutePath, newContent, 'utf-8');
    }
  }
  console.log('Script finished.');
}

fixImportsAndDirectives().catch(console.error);
