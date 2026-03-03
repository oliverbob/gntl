import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const packageJsonPath = require.resolve('@tailwindcss/browser/package.json');
const packageDir = path.dirname(packageJsonPath);

const candidates = [
  'dist/index.global.js',
  'dist/index.js',
  'dist/browser.js',
  'dist/browser.min.js'
];

const sourcePath = candidates
  .map((relativePath) => path.join(packageDir, relativePath))
  .find((candidatePath) => fs.existsSync(candidatePath));

if (!sourcePath) {
  throw new Error('Unable to locate @tailwindcss/browser distributable file.');
}

const staticVendorDir = path.resolve(packageDir, '..', '..', '..', 'static', 'vendor');
fs.mkdirSync(staticVendorDir, { recursive: true });

const targetPath = path.join(staticVendorDir, 'tailwindcss-browser.js');
fs.copyFileSync(sourcePath, targetPath);

console.log(`[tailwind] Copied ${sourcePath} -> ${targetPath}`);
