import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// These are executable decision/serialization regressions, not signing smokes.
test('native signature rejection diagnostics survive child rethrow and smoke JSON', {
  skip: process.platform !== 'win32',
}, () => {
  const script = fileURLToPath(new URL('./windows-trust-diagnostics.test.ps1', import.meta.url));
  const result = spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script,
  ], { encoding: 'utf8', timeout: 60_000, maxBuffer: 1024 * 1024 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const report = JSON.parse(result.stdout.trim());
  assert.equal(report.Result, 'PASS');
  assert.equal(report.Checks, 22);
  assert.equal(report.HostTrustChanged, false);
  assert.equal(report.NativeSigningExecuted, false);
});
