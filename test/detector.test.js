import test from 'node:test';
import assert from 'node:assert/strict';
import { scanForSecrets, calculateEntropy } from '../lib/detector.js';

test('calculateEntropy correctly measures randomness', () => {
  const lowEntropy = calculateEntropy('aaaaaaaaaaaa');
  const highEntropy = calculateEntropy('uK8#mQ2$zL9!pW5&');

  assert.ok(lowEntropy < 1.0, 'Repeated characters should have very low entropy');
  assert.ok(highEntropy > 3.5, 'Random string should have high entropy');
});

test('detects OpenAI API keys and Project keys', () => {
  const sample = `
    const apiKey = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx";
    const legacyKey = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF";
  `;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 2);
  assert.strictEqual(findings[0].ruleId, 'openai_api_key');
  assert.strictEqual(findings[1].ruleId, 'openai_api_key');
});

test('detects GitHub Personal Access Tokens', () => {
  const sample = `const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";`;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'github_token');
});

test('detects AWS Access Keys', () => {
  const sample = `const awsKey = "AKIAIOSFODNN7EXAMPLE";`;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'aws_access_key');
});

test('detects Database URIs with credentials', () => {
  const sample = `const db = "postgresql://app_user:s3cr3t_p@ss@db.internal.net:5432/production_db";`;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'db_connection_url');
});

test('detects PEM Private Key blocks', () => {
  const sample = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+xyz...fakecontent...==
-----END RSA PRIVATE KEY-----
`;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'private_key_block');
});

test('detects Windows and Unix developer user paths', () => {
  const sample = `
    const winPath = "C:\\\\Users\\\\johndoe\\\\workspace\\\\secret-project";
    const unixPath = "/home/developer/workspace/app.env";
  `;
  const findings = scanForSecrets(sample);
  const winFinding = findings.find(f => f.ruleId === 'local_user_path_win');
  const unixFinding = findings.find(f => f.ruleId === 'local_user_path_unix');

  assert.ok(winFinding, 'Should detect Windows user path');
  assert.ok(unixFinding, 'Should detect Unix home path');
});
