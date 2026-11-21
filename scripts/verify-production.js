import fs from 'node:fs';
import path from 'node:path';

const roots = ['public', 'apps/api/src'];
const mockMarkers = [
  /\bfake\s+(?:api|data|record)/i,
  /\bsimulated\s+(?:production|analytics|response)/i,
  /\bmock\s+(?:data|api|response)\b/i,
  /\bplaceholder\s+(?:data|record|response)\b/i
];

function walk(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(fullPath));
    else if (entry.isFile()) files.push(fullPath);
  }
  return files;
}

const violations = [];
for (const root of roots) {
  for (const filePath of walk(root)) {
    const text = fs.readFileSync(filePath, 'utf8');
    for (const marker of mockMarkers) {
      if (marker.test(text) && !text.includes('mock audit')) {
        violations.push(`${filePath}: ${marker}`);
      }
    }
  }
}

if (violations.length) {
  console.error('Mock/fabricated-data markers found:\n' + violations.join('\n'));
  process.exit(1);
}

console.log('Production source scan passed: no mock/fake/simulated production-data markers found.');
