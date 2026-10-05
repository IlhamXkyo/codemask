import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { maskContent, unmaskContent } from '../lib/transformer.js';
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
  const { unmaskedContent, restoredCount } = unmaskContent(maskedContent, mapping);
  assert.strictEqual(unmaskedContent, sourceCode, 'Unmasked content must match original source code');
  assert.ok(restoredCount >= findingsCount, 'All placeholder instances must be restored');
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
