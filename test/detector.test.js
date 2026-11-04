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

test('detects GitHub Personal Access Tokens and Fine-Grained PATs', () => {
  const sample = `
    const classicToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    const fineGrainedToken = "github_pat_11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234";
  `;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 2);
  assert.ok(findings.some(f => f.ruleId === 'github_token'));
  assert.ok(findings.some(f => f.ruleId === 'github_fine_grained_pat'));
});

test('detects HuggingFace, npm, and GitLab tokens', () => {
  const sample = `
    const hf = "hf_0123456789abcdefghijklmnopqrstuvwxyz";
    const npmToken = "npm_0123456789abcdefghijklmnopqrstuv";
    const gitlabToken = "glpat-0123456789abcdefghij";
  `;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 3);
  assert.ok(findings.some(f => f.ruleId === 'huggingface_token'));
  assert.ok(findings.some(f => f.ruleId === 'npm_token'));
  assert.ok(findings.some(f => f.ruleId === 'gitlab_pat'));
});

test('detects raw JSON Web Tokens (JWT)', () => {
  const sample = `const sessionToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`;
  const findings = scanForSecrets(sample);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'jwt_token');
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

test('detects Windows and Unix developer user paths without re-masking masked tokens', () => {
  const sample = `
    const winPath = "C:\\\\Users\\\\johndoe\\\\workspace\\\\secret-project";
    const unixPath = "/home/developer/workspace/app.env";
    const alreadyMaskedWin = "C:\\\\Users\\\\MASKED_DEV_USER_a1b2c3d4\\\\file.ts";
    const alreadyMaskedUnix = "/home/MASKED_dev_user_a1b2c3d4/file.ts";
  `;
  const findings = scanForSecrets(sample);
  const winFinding = findings.find(f => f.ruleId === 'local_user_path_win');
  const unixFinding = findings.find(f => f.ruleId === 'local_user_path_unix');

  assert.ok(winFinding, 'Should detect unmasked Windows user path');
  assert.ok(unixFinding, 'Should detect unmasked Unix home path');
  assert.strictEqual(findings.length, 2, 'Should not match already-masked user paths');
});
