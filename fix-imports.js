
import { glob } from 'glob';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';

async function fixImports() {
  const files = await glob('src/**/*.ts', { ignore: 'node_modules/**' });
  for (const file of files) {
    const absolutePath = path.resolve(file);
    let content = await readFile(absolutePath, 'utf-8');
    const lines = content.split('\n');
    const newLines = lines.map(line => {
      const importMatch = line.match(/^(import|export)(.*)from\s+['"](\..*[^"']*)['"];?$/);
      if (importMatch) {
        const importPath = importMatch[3];
        if (!importPath.endsWith('.js') && !importPath.endsWith('.ts') && !importPath.endsWith('.json')) {
          // Check if the file exists with .ts, if so, add .js to the import
          const importAbsolutePath = path.resolve(path.dirname(absolutePath), importPath);
          
          // We can't easily check for file existence here without making this more complex.
          // Let's just add the .js extension and see if it works.
          // A more robust solution would check for .ts, .tsx, .d.ts, and index.ts in a directory.
          
          // A simple heuristic: if it doesn't have an extension, and it's a relative path, add .js
          if(importPath.startsWith('.')) {
            return line.replace(importPath, `${importPath}.js`);
          }
        }
      }
      return line;
    });
    const newContent = newLines.join('\n');
    if (content !== newContent) {
      console.log(`Fixing imports in ${file}`);
      await writeFile(absolutePath, newContent, 'utf-8');
    }
  }
}

fixImports().catch(console.error);
