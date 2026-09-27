#!/usr/bin/env node
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { loadRules, scanDirectory, toSarif } from './scanner.js';

const args = process.argv.slice(2);
const root = resolve(args.find(a => !a.startsWith('--')) ?? '.');
const sarifIndex = args.indexOf('--sarif');
const rules = await loadRules();
const findings = await scanDirectory(root, rules);
if (sarifIndex >= 0) {
  const output = args[sarifIndex + 1];
  if (!output || output.startsWith('--')) throw new Error('--sarif requires an output path');
  await writeFile(resolve(output), JSON.stringify(toSarif(findings, rules), null, 2));
}
for (const f of findings) console.log(`${f.severity.toUpperCase()} ${f.file}:${f.line}:${f.column} ${f.name} [REDACTED]`);
console.log(`${findings.length} finding(s)`);
if (findings.some(f => f.severity === 'error')) process.exitCode = 1;
