import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';

export function getFilePath(importMetaUrl: string) {
  const __filename = fileURLToPath(importMetaUrl);
  const __dirname = dirname(__filename);
  return { __filename, __dirname };
}

// Helper to resolve paths relative to project root
export function resolveFromRoot(...paths: string[]) {
  const rootDir = path.resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  return path.join(rootDir, ...paths);
}
