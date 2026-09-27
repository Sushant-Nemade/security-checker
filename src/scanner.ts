import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Rule = { id: string; name: string; pattern: string; severity: 'error' | 'warning'; remediation: string };
export type Finding = { ruleId: string; name: string; file: string; line: number; column: number; severity: 'error' | 'warning'; preview: string; remediation: string };
const ignored = new Set(['.git', 'node_modules', '.next', 'dist', 'coverage', '.pnpm-store']);
const maxFileBytes = 1024 * 1024;

export async function loadRules(): Promise<Rule[]> {
  const path = fileURLToPath(new URL('../rules.json', import.meta.url));
  return JSON.parse(await readFile(path, 'utf8')) as Rule[];
}

export function entropy(value: string): number {
  if (!value.length) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  return [...counts.values()].reduce((sum, count) => {
    const p = count / value.length;
    return sum - p * Math.log2(p);
  }, 0);
}

export function scanText(file: string, content: string, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    for (const rule of rules) {
      const regex = new RegExp(rule.pattern, 'g');
      for (const match of line.matchAll(regex)) {
        findings.push({ ruleId: rule.id, name: rule.name, file, line: index + 1, column: (match.index ?? 0) + 1, severity: rule.severity, preview: '[REDACTED]', remediation: rule.remediation });
      }
    }
    const candidates = line.match(/(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,})/g) ?? [];
    for (const value of candidates) {
      if (entropy(value) >= 4.6 && !findings.some(f => f.file === file && f.line === index + 1)) {
        findings.push({ ruleId: 'high-entropy', name: 'High entropy string', file, line: index + 1, column: line.indexOf(value) + 1, severity: 'warning', preview: '[REDACTED]', remediation: 'Determine whether this is a credential. If so, revoke it and replace it with a managed secret.' });
      }
    }
  }
  return findings;
}

export async function scanDirectory(root: string, rules: Rule[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  async function walk(directory: string): Promise<void> {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      if (ignored.has(item.name)) continue;
      const full = join(directory, item.name);
      if (item.isSymbolicLink()) continue;
      if (item.isDirectory()) { await walk(full); continue; }
      if (!item.isFile() || (await stat(full)).size > maxFileBytes) continue;
      const path = relative(root, full).replaceAll('\\', '/');
      if (/^\.env(?:\.|$)/.test(item.name) && !item.name.endsWith('.example')) {
        findings.push({ ruleId: 'env-file', name: 'Environment file', file: path, line: 1, column: 1, severity: 'warning', preview: '[REDACTED]', remediation: 'Remove the environment file from version control and rotate any exposed credentials.' });
      }
      const bytes = await readFile(full);
      if (bytes.includes(0)) continue;
      findings.push(...scanText(path, bytes.toString('utf8'), rules));
    }
  }
  await walk(root);
  return findings;
}

export function toSarif(findings: Finding[], rules: Rule[]) {
  const definitions = [...rules, { id: 'high-entropy', name: 'High entropy string', pattern: '', severity: 'warning' as const, remediation: 'Review and rotate if secret.' }, { id: 'env-file', name: 'Environment file', pattern: '', severity: 'warning' as const, remediation: 'Remove from version control.' }];
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: '5-Minute Security Checker', rules: definitions.map(r => ({ id: r.id, name: r.name, shortDescription: { text: r.name }, help: { text: r.remediation } })) } }, results: findings.map(f => ({ ruleId: f.ruleId, level: f.severity, message: { text: `${f.name}: ${f.remediation}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, startColumn: f.column } } }] })) }] };
}
