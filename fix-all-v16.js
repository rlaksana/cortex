
import { glob } from 'glob';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';
import fs from 'fs';

async function fixImportsAndDirectives() {
  console.log('Starting script...');
  const files = await glob('src/**/*.ts', { ignore: 'node_modules/**' });
  console.log(`Found ${files.length} files to process.`);

  for (const file of files) {
    const absolutePath = path.resolve(file);
    let content = await readFile(absolutePath, 'utf-8');
    let changed = false;

    // Fix imports/exports
    const lines = content.split('\n');
    const newLines = lines.map(line => {
      const importMatch = line.match(/from\s+['"](.*)['"]/);
      if (importMatch) {
        const importPath = importMatch[1];
        if (importPath.startsWith('.') && !path.extname(importPath)) {
            let newImportPath = null;
            const importAbsolutePath = path.resolve(path.dirname(absolutePath), importPath);
            if (fs.existsSync(`${importAbsolutePath}.ts`) || fs.existsSync(`${importAbsolutePath}.tsx`)) {
                newImportPath = `${importPath}.js`;
            } else if (fs.existsSync(`${importAbsolutePath}/index.ts`) || fs.existsSync(`${importAbsolutePath}/index.tsx`)) {
                newImportPath = `${importPath}/index.js`;
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

    if (changed) {
      const newContent = newLines.join('\n');
      console.log(`Fixing file: ${file}`);
      await writeFile(absolutePath, newContent, 'utf-8');
    }
  }
  console.log('Script finished.');
}

fixImportsAndDirectives().catch(console.error);
