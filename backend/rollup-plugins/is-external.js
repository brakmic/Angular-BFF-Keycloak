import { readFileSync } from 'fs';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(__dirname, '../package.json'), 'utf8'));

// Get all dependencies
const allDependencies = new Set([
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {}),
  ...Object.keys(pkg.optionalDependencies || {})
]);

const builtins = new Set([
  'path', 'fs', 'crypto', 'https', 'http', 'url', 'util',
  'stream', 'zlib', 'os', 'querystring', 'events', 'buffer'
]);

export function isExternal(id, parent) {
  // Handle absolute paths from project root
  if (id.startsWith('@')) {
    return false;
  }

  // Handle relative imports
  if (id.startsWith('.') || id.startsWith('/')) {
    return false;
  }

  // Handle the entry point
  if (id === 'src/index.ts' || id.includes('src/')) {
    return false;
  }

  // Get package name for scoped packages too
  const pkgName = id.startsWith('@') ? id.split('/').slice(0, 2).join('/') : id.split('/')[0];

  return builtins.has(pkgName) || allDependencies.has(pkgName);
}
