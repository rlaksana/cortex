
import { glob } from 'glob';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';
import fs from 'fs';

async function fixImportsAndDirectives() {
  const files = await glob('src/**/*.ts', { ignore: 'node_modules/**' });
  for (const file of files) {
    const absolutePath = path.resolve(file);
    let content = await readFile(absolutePath, 'utf-8');
    let changed = false;

    // Fix imports/exports
    const lines = content.split('\n');
    const newLines = lines.map(line => {
      // Remove @ts-nocheck
      if (line.trim() === '// @ts-nocheck') {
        changed = true;
        return ''; // Remove the line
      }

      const importMatch = line.match(/^(import|export)(.*)from\s+['"]((?:\.\/|\.\.\/).*[^"']*)['"];?$/);
      if (importMatch) {
        const importPath = importMatch[3];
        if (!path.extname(importPath)) {
          const importAbsolutePath = path.resolve(path.dirname(absolutePath), importPath);
          if (fs.existsSync(`${importAbsolutePath}.ts`) || fs.existsSync(`${importAbsolutePath}.tsx`)) {
             const newLine = line.replace(importPath, `${importPath}.js`);
             if(line !== newLine) {
                changed = true;
                return newLine;
             }
          } else if (fs.existsSync(`${importAbsolutePath}/index.ts`) || fs.existsSync(`${importAbsolutePath}/index.tsx`)) {
            const newLine = line.replace(importPath, `${importPath}/index.js`);
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
