import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '..');
for (const suite of ['Decisions', 'Paths']) {
  test(`Windows executable safety regressions: ${suite}`, { skip: process.platform !== 'win32' }, () => {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File',
      path.join(root, 'tests', 'windows-trust-guards.test.ps1'), '-Suite', suite],
      { cwd: root, encoding: 'utf8', timeout: 120_000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + '\n' + result.stderr);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.Result, 'PASS');
    assert.ok(report.Checks >= (suite === 'Decisions' ? 35 : 10));
    assert.equal(report.HostTrustChanged, false);
    assert.equal(report.PoliciesDeployed, false);
  });
}
test('all PowerShell sources including nested guard helpers parse', { skip: process.platform !== 'win32' }, () => {
  const escaped = root.replaceAll("'", "''");
  const command = `$ErrorActionPreference='Stop'; Get-ChildItem -LiteralPath '${escaped}' -Recurse -Filter *.ps1 -File | Where-Object {$_.FullName -notmatch '[\\\\/]node_modules[\\\\/]'} | ForEach-Object {$e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw ($e|Out-String)}}`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8', timeout: 120_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + '\n' + result.stderr);
});

// Regression for the extra PowerShell fence in the local-trust instructions.
test('skill code fences are balanced and never contain a nested opener', async () => {
  const { readFile } = await import('node:fs/promises');
  const skill = await readFile(path.join(root, 'skills/windows-app-trust/SKILL.md'), 'utf8');
  let open = null;
  for (const line of skill.split(/\r?\n/)) {
    const match = /^(~~~|```)(.*)$/.exec(line);
    if (!match) continue;
    if (open === null) open = match[1];
    else { assert.equal(match[1], open); assert.equal(match[2].trim(), ''); open = null; }
  }
  assert.equal(open, null);
});
