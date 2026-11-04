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

test('CLI in-place file modification with -i flag', () => {
  const tmpDir = path.resolve('./test/.tmp_cli_inplace');
  fs.mkdirSync(tmpDir, { recursive: true });

  const sessionPath = path.join(tmpDir, 'inplace-session.json');
  const binPath = path.resolve('./bin/codemask.js');

  const rawContent = 'export const HF_KEY = "hf_0123456789abcdefghijklmnopqrstuvwxyz";';
  const targetFile = path.join(tmpDir, 'service.ts');
  fs.writeFileSync(targetFile, rawContent, 'utf8');

  // 1. Mask in place
  execFileSync('node', [binPath, 'mask', targetFile, '-i', '--session', sessionPath]);
  const maskedInPlace = fs.readFileSync(targetFile, 'utf8');
  assert.ok(!maskedInPlace.includes('hf_0123456789'), 'File must be masked in place');
  assert.ok(maskedInPlace.includes('hf_MASKED_HF_TOKEN_'), 'Placeholder should be present in file');

  // 2. Unmask in place
  execFileSync('node', [binPath, 'unmask', targetFile, '-i', '--session', sessionPath]);
  const restoredInPlace = fs.readFileSync(targetFile, 'utf8');
  assert.strictEqual(restoredInPlace, rawContent, 'File content must be fully restored');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('CLI scan command returns zero for clean code and non-zero for leaked secrets', () => {
  const tmpDir = path.resolve('./test/.tmp_cli_scan');
  fs.mkdirSync(tmpDir, { recursive: true });

  const binPath = path.resolve('./bin/codemask.js');

  // Clean file
  const cleanFile = path.join(tmpDir, 'clean.js');
  fs.writeFileSync(cleanFile, 'const count = 42; console.log(count);', 'utf8');

  const cleanOut = execFileSync('node', [binPath, 'scan', cleanFile], { encoding: 'utf8' });
  assert.ok(cleanOut.includes('Clean: No unmasked secrets detected'));

  // Leaked file
  const leakedFile = path.join(tmpDir, 'leaked.js');
  fs.writeFileSync(leakedFile, 'const key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx";', 'utf8');

  let failed = false;
  try {
    execFileSync('node', [binPath, 'scan', leakedFile], { encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    failed = true;
    assert.strictEqual(err.status, 1, 'Should exit with code 1');
    assert.ok(err.stderr.toString().includes('Alert: Found 1 unmasked secret(s)'));
  }
  assert.ok(failed, 'Scan on leaked secret file must exit with error code 1');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
