
import { glob } from 'glob';
import { readFile, writeFile }from 'fs/promises';
import path from 'path';
import fs from 'fs';

async function fixImportsAndDirectives() {
  const files = await glob('src/**/*.ts', { ignore: 'node_modules/**' });
  const tsConfig = JSON.parse(await readFile('tsconfig.json', 'utf-8'));
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
        changed = true;
        return ''; // Remove the line
      }

      const importMatch = line.match(/^(import|export)(.*)from\s+['"](.*)['"];?$/);
      if (importMatch) {
        const importPath = importMatch[3];
        if (!path.extname(importPath)) {
            let newImportPath = null;
            if (importPath.startsWith('@/')) {
                const alias = importPath.split('/')[0];
                if (paths[alias + '/*']) {
                    const realPath = paths[alias + '/*'][0].replace('*', '');
                    const restOfPath = importPath.substring(alias.length + 1);
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
        newContent = newContent.replace(selfAssignRegex, '');
        changed = true;
    }


    if (changed) {
      console.log(`Fixing file: ${file}`);
      await writeFile(absolutePath, newContent, 'utf-8');
    }
  }
}

fixImportsAndDirectives().catch(console.error);
