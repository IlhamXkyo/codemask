import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

test('CLI mask and unmask via executable bin', () => {
  const tmpDir = path.resolve('./test/.tmp_cli');
  fs.mkdirSync(tmpDir, { recursive: true });

  const sessionPath = path.join(tmpDir, 'cli-session.json');
  const binPath = path.resolve('./bin/codemask.js');

  const rawSnippet = 'const myApiKey = "sk-proj-test1234567890123456789012345678901234567890";';
  const inputFile = path.join(tmpDir, 'input.js');
  fs.writeFileSync(inputFile, rawSnippet, 'utf8');

  // 1. Run codemask mask
  const maskedOutput = execFileSync('node', [binPath, 'mask', inputFile, '--session', sessionPath], {
    encoding: 'utf8',
  });

  assert.ok(!maskedOutput.includes('sk-proj-test1234567890'), 'Masked output must not contain raw secret');
  assert.ok(maskedOutput.includes('sk-proj-MASKED_OPENAI_'), 'Masked output should have placeholder token');
  assert.ok(fs.existsSync(sessionPath), 'Session file must exist');

  // 2. Run codemask unmask by piping masked output through stdin
  const unmaskedOutput = execFileSync('node', [binPath, 'unmask', '--session', sessionPath], {
    input: maskedOutput,
    encoding: 'utf8',
  });

  assert.strictEqual(unmaskedOutput.trim(), rawSnippet.trim(), 'Unmasked output must restore original code');

  // 3. Inspect session
  const inspectOutput = execFileSync('node', [binPath, 'inspect', '--session', sessionPath], {
    encoding: 'utf8',
  });
  assert.ok(inspectOutput.includes('sk-proj-MASKED_OPENAI_'), 'Inspect output should list placeholders');

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
