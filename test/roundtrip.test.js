import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { maskContent, unmaskContent, detectLingeringPlaceholders } from '../lib/transformer.js';
import { saveSession, loadSession, inspectSession } from '../lib/session.js';

test('roundtrip mask and unmask preserves original source code faithfully', () => {
  const sourceCode = `
import { createClient } from '@supabase/supabase-js';

const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_bearer_token_string_example_longer_entropy_123456';
const OPENAI_API_KEY = 'sk-proj-abc12345678901234567890123456789012345678';
const DB_URL = 'postgresql://admin:superSecretPassword123@db.prod.internal:5432/core';

export async function init() {
  console.log('Connecting with', OPENAI_API_KEY);
  return { key: SUPABASE_KEY, db: DB_URL };
}
`;

  const { maskedContent, mapping, findingsCount } = maskContent(sourceCode);

  assert.ok(findingsCount >= 2, 'Should have masked multiple secrets');
  assert.ok(!maskedContent.includes('sk-proj-abc12345678901234567890123456789012345678'), 'OpenAI key must not be in masked content');
  assert.ok(!maskedContent.includes('superSecretPassword123'), 'DB password must not be in masked content');

  // Verify that unmasking recovers exact original content
  const { unmaskedContent, restoredCount, unmatchedPlaceholders } = unmaskContent(maskedContent, mapping);
  assert.strictEqual(unmaskedContent, sourceCode, 'Unmasked content must match original source code');
  assert.ok(restoredCount >= findingsCount, 'All placeholder instances must be restored');
  assert.strictEqual(unmatchedPlaceholders.length, 0, 'No unmatched placeholders should remain');
});

test('masks developer user profile paths while preserving path syntax', () => {
  const code = `
    const localDbPath = "C:\\\\Users\\\\alice\\\\appdata\\\\secrets.db";
    const unixConfig = "/home/developer/.env.local";
  `;

  const { maskedContent, mapping } = maskContent(code);
  assert.ok(maskedContent.includes('MASKED_DEV_USER_'), 'Windows path must have MASKED_DEV_USER_');
  assert.ok(maskedContent.includes('/home/MASKED_dev_user_'), 'Unix path must preserve /home/MASKED_dev_user_ structure');

  const { unmaskedContent } = unmaskContent(maskedContent, mapping);
  assert.strictEqual(unmaskedContent, code, 'Paths must be restored identically');
});

test('detects lingering unresolved placeholders when unmasking incomplete responses', () => {
  const codeWithLingering = `
    const apiKey = "sk-proj-MASKED_OPENAI_nonexistent";
    const custom = "MASKED_SECRET_STRING_unknown99";
  `;

  const { unmaskedContent, unmatchedPlaceholders } = unmaskContent(codeWithLingering, {});
  assert.strictEqual(unmatchedPlaceholders.length, 2, 'Must identify all lingering placeholders');
  assert.ok(unmatchedPlaceholders.includes('sk-proj-MASKED_OPENAI_nonexistent'));
  assert.ok(unmatchedPlaceholders.includes('MASKED_SECRET_STRING_unknown99'));
});

test('session save in non-existent nested directory automatically creates directory tree', () => {
  const tmpDir = path.resolve('./test/.tmp_nested/deep/sub/dir');
  const sessionPath = path.join(tmpDir, 'auto-created-session.json');
  const dummyMapping = {
    'sk-proj-MASKED_OPENAI_test123': 'sk-proj-super-secret-value-0987654321',
  };

  saveSession(sessionPath, dummyMapping);
  assert.ok(fs.existsSync(sessionPath), 'Session file must be created inside nested dir');

  const loaded = loadSession(sessionPath);
  assert.deepStrictEqual(loaded, dummyMapping);

  fs.rmSync(path.resolve('./test/.tmp_nested'), { recursive: true, force: true });
});

test('session save, inspect, and encrypted load works reliably', () => {
  const tmpDir = path.resolve('./test/.tmp');
  fs.mkdirSync(tmpDir, { recursive: true });

  const sessionPath = path.join(tmpDir, 'test-session.json');
  const dummyMapping = {
    'sk-proj-MASKED_OPENAI_a1b2c3d4': 'sk-proj-original-secret-key-1234567890',
  };

  const passphrase = 'test-strong-passphrase-889';

  // Save encrypted session
  saveSession(sessionPath, dummyMapping, passphrase);
  assert.ok(fs.existsSync(sessionPath), 'Session file must be created');

  // Verify file content is encrypted JSON
  const rawFile = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
  assert.strictEqual(rawFile.encrypted, true);
  assert.ok(!JSON.stringify(rawFile).includes('original-secret-key'));

  // Load encrypted session
  const loadedMapping = loadSession(sessionPath, passphrase);
  assert.deepStrictEqual(loadedMapping, dummyMapping);

  // Inspect session
  const inspection = inspectSession(sessionPath, passphrase, false);
  assert.strictEqual(inspection.length, 1);
  assert.ok(!inspection[0].preview.includes('original-secret-key'));

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
