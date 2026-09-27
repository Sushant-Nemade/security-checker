import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { entropy, scanText, type Rule } from './scanner.js';

const rules: Rule[] = [{ id: 'test-key', name: 'Test key', pattern: 'key_[A-Za-z0-9]{8}', severity: 'error', remediation: 'Rotate it.' }];
test('detects a secret without printing its value', () => {
  const findings = scanText('a.ts', 'const secret = "key_12345678";', rules);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
  assert.equal(findings[0].preview, '[REDACTED]');
  assert.equal(JSON.stringify(findings).includes('12345678'), false);
});
test('entropy distinguishes repeated strings', () => {
  assert.equal(entropy('aaaaaaaaaaaa'), 0);
  assert.ok(entropy('aB1+cD2/eF3g') > 3);
});
