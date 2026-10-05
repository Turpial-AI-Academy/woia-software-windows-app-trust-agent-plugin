import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const skillRoot = path.join(root, 'skills', 'windows-app-trust');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const hasCluster = (text, patterns) => patterns.every((pattern) => pattern.test(text));
const clauses = (text) => text.split(/(?<=[.!?])\s+|\n+/);
const boundedTrustScope = (text) => clauses(text).some((clause) =>
  hasCluster(clause, [/bounded/i, /only/i, /report/i, /documentation/i, /read-only/i, /artifact/i, /digest/i, /signer/i, /certificate/i, /expiry|validity/i, /store/i, /policy/i, /security.*claim/i, /unchanged/i]) &&
  !/(?:not|never)\s+(?:use|select|allow)[\s\S]*bounded/i.test(clause));
const freshTrustClaim = (text) => clauses(text).some((clause) =>
  hasCluster(clause, [/current/i, /signature/i, /trust/i, /enforcement/i, /claim/i, /require|must/i, /fresh/i, /observations?/i]) &&
  !/(?:not|never)\s+(?:\w+\s+){0,2}(?:require\w*|support\w*)|(?:require\w*|must|support\w*)\s+(?:not|never)/i.test(clause));

test('windows-app-trust portable capability has required helpers', () => {
  const required = [
    'discover-windows-trust.ps1',
    'new-local-code-signing-cert.ps1',
    'export-public-cert.ps1',
    'install-local-trust.ps1',
    'remove-local-trust.ps1',
    'sign-artifact.ps1',
    'verify-artifact.ps1',
    'new-app-control-signer-policy.ps1',
    'deploy-app-control-policy.ps1',
    'remove-app-control-policy.ps1',
  ];
  for (const name of required) {
    assert.ok(fs.existsSync(path.join(skillRoot, 'scripts', name)), 'missing ' + name);
  }
});

test('local signer is RSA and non-exportable by default', () => {
  const src = read('skills/windows-app-trust/scripts/new-local-code-signing-cert.ps1');
  assert.match(src, /-KeyAlgorithm RSA/);
  assert.match(src, /-KeyLength 3072/);
  assert.match(src, /-KeyExportPolicy NonExportable/);
  assert.match(src, /CodeSigningCert/);
  assert.match(src, /-KeyUsage DigitalSignature/);
  assert.match(src, /2\.5\.29\.37=\{text\}1\.3\.6\.1\.5\.5\.7\.3\.3/);
  assert.match(src, /Get-WindowsTrustCodeSigningCertificate/);
});

test('local trust helper separates Authenticode Root trust from MSIX TrustedPeople', () => {
  const src = read('skills/windows-app-trust/scripts/install-local-trust.ps1');
  assert.match(src, /AuthenticodeSelfSigned/);
  assert.match(src, /MsixPackage/);
  assert.match(src, /ConfirmTrustedRootChange/);
  assert.match(src, /\{ 'Root' \} else \{ 'TrustedPeople' \}/);
  assert.match(src, /Subject -ne \$publicCert\.Issuer/);
  assert.match(src, /Only public \.cer\/\.crt certificate files/);
  assert.match(src, /SmartAppControlPublicTrust = \$false/);
});

test('signer is path-bounded and validates signing identity', () => {
  const src = read('skills/windows-app-trust/scripts/sign-artifact.ps1');
  assert.match(src, /AllowedRoot/);
  assert.match(src, /Refusing to sign outside AllowedRoot/);
  assert.match(src, /Get-WindowsTrustCodeSigningCertificate/);
  assert.match(src, /Signer thumbprint mismatch/);
});

test('plugin contains no Smart App Control mutation helper or Defender disable workaround', () => {
  const scriptDir = path.join(skillRoot, 'scripts');
  const combined = fs.readdirSync(scriptDir)
    .filter((name) => name.endsWith('.ps1'))
    .map((name) => fs.readFileSync(path.join(scriptDir, name), 'utf8'))
    .join('\n');
  assert.doesNotMatch(combined, /Set-MpPreference\s+.*DisableRealtimeMonitoring/i);
  assert.doesNotMatch(combined, /Set-ItemProperty[^\n]*VerifiedAndReputablePolicyState/i);
  assert.doesNotMatch(combined, /reg(?:\.exe)?\s+add[^\n]*VerifiedAndReputablePolicyState/i);
});

test('App Control deployment/removal require explicit confirmation and elevation', () => {
  const deploy = read('skills/windows-app-trust/scripts/deploy-app-control-policy.ps1');
  const remove = read('skills/windows-app-trust/scripts/remove-app-control-policy.ps1');
  assert.match(deploy, /ConfirmDeployment/);
  assert.match(deploy, /ConfirmBasePolicyDeployment/);
  assert.match(deploy, /WindowsBuiltInRole.*Administrator/);
  assert.match(remove, /ConfirmRemoval/);
  assert.match(remove, /ExpectedFriendlyName/);
  assert.match(remove, /WindowsBuiltInRole.*Administrator/);
  assert.match(remove, /Refusing to remove a Microsoft\/inbox application-control policy/);
});

test('supplemental App Control generation requires existing base allow-supplement contract', () => {
  const src = read('skills/windows-app-trust/scripts/new-app-control-signer-policy.ps1');
  assert.match(src, /Enabled:Allow Supplemental Policies/);
  assert.match(src, /New-CIPolicyRule/);
  assert.match(src, /-Level Publisher/);
  assert.match(src, /-BasePolicyToSupplementPath/);
  assert.doesNotMatch(src, /CiTool.*-up/);
});

test('PowerShell helpers parse on Windows hosts', { skip: process.platform !== 'win32' }, () => {
  const files = fs.readdirSync(path.join(skillRoot, 'scripts')).filter((name) => name.endsWith('.ps1'));
  for (const name of files) {
    const full = path.join(skillRoot, 'scripts', name);
    const escaped = full.replaceAll("'", "''");
    const command =
      '$errors=$null;$tokens=$null;' +
      "[System.Management.Automation.Language.Parser]::ParseFile('" + escaped + "',[ref]$tokens,[ref]$errors) | Out-Null;" +
      'if($errors.Count -gt 0){$errors | ForEach-Object {$_.ToString()}; exit 1}';
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8' });
    assert.equal(result.status, 0, name + ' parse failure:\n' + result.stdout + '\n' + result.stderr);
  }
});


test('discovery normalizes Windows 11 family and reports Home/App Control limits', () => {
  const src = read('skills/windows-app-trust/scripts/discover-windows-trust.ps1');
  assert.match(src, /build -ge 22000/);
  assert.match(src, /Windows 11/);
  assert.match(src, /EditionID.*-match '\^Core'/s);
  assert.match(src, /LocalPolicyAuthoringSupportedByPlugin/);
  assert.match(src, /AccessDenied/);
  assert.match(src, /-2147024891/);
});

test('skill blocks local App Control authoring on Home instead of improvising policy XML', () => {
  const src = read('skills/windows-app-trust/SKILL.md');
  assert.match(src, /does not author or deploy custom App Control policies locally on Home/i);
  assert.match(src, /ConfigCI/);
});


test('App Control mutating helpers enforce the Home edition boundary', () => {
  const generate = read('skills/windows-app-trust/scripts/new-app-control-signer-policy.ps1');
  const deploy = read('skills/windows-app-trust/scripts/deploy-app-control-policy.ps1');
  assert.match(generate, /EditionID/);
  assert.match(generate, /\^Core/);
  assert.match(generate, /not supported by this plugin on Windows Home/);
  assert.match(deploy, /EditionID/);
  assert.match(deploy, /\^Core/);
  assert.match(deploy, /not supported by this plugin on Windows Home/);
});


test('Windows inbox module bootstrap avoids ambient PSModulePath-only discovery', () => {
  const common = read('skills/windows-app-trust/scripts/lib/windows-trust-modules.ps1');
  const smoke = read('scripts/smoke-windows-signing.ps1');
  const signer = read('skills/windows-app-trust/scripts/sign-artifact.ps1');
  const cert = read('skills/windows-app-trust/scripts/new-local-code-signing-cert.ps1');

  assert.match(common, /\$PSHOME/);
  assert.match(common, /System32\\WindowsPowerShell\\v1\.0\\Modules/);
  assert.match(common, /Import-Module -Name \$candidate/);
  assert.match(smoke, /Import-WindowsTrustModule -Name 'Microsoft\.PowerShell\.Security'/);
  assert.match(signer, /Get-AuthenticodeSignature/);
  assert.match(signer, /Set-AuthenticodeSignature/);
  assert.match(cert, /Import-WindowsTrustModule -Name 'PKI'/);
});


test('code-signing certificate lookup uses the Windows provider filter', () => {
  const common = read('skills/windows-app-trust/scripts/lib/windows-trust-modules.ps1');
  const exporter = read('skills/windows-app-trust/scripts/export-public-cert.ps1');
  assert.match(common, /Get-ChildItem -Path Cert:\\CurrentUser\\My -CodeSigningCert/);
  assert.match(common, /X509EnhancedKeyUsageExtension/);
  assert.match(exporter, /Get-WindowsTrustCodeSigningCertificate/);
});


test('portable SHA-256 hashing does not depend on Get-FileHash autoload', () => {
  const common = read('skills/windows-app-trust/scripts/lib/windows-trust-modules.ps1');
  const signer = read('skills/windows-app-trust/scripts/sign-artifact.ps1');
  const verifier = read('skills/windows-app-trust/scripts/verify-artifact.ps1');

  assert.match(common, /function Get-WindowsTrustFileSha256/);
  assert.match(common, /System\.Security\.Cryptography\.SHA256/);
  assert.match(common, /ComputeHash/);
  assert.match(signer, /Get-WindowsTrustFileSha256/);
  assert.match(verifier, /Get-WindowsTrustFileSha256/);
  assert.doesNotMatch(signer, /Get-FileHash/);
  assert.doesNotMatch(verifier, /Get-FileHash/);
});


test('local trust rollback requires exact identity and explicit confirmation', () => {
  const src = read('skills/windows-app-trust/scripts/remove-local-trust.ps1');
  assert.match(src, /ExpectedSubject/);
  assert.match(src, /ConfirmTrustChange/);
  assert.match(src, /AuthenticodeSelfSigned/);
  assert.match(src, /MsixPackage/);
  assert.match(src, /ConfirmTrustedRootChange/);
  assert.match(src, /subject mismatch/i);
  assert.match(src, /LocalMachine trust changes require an elevated PowerShell session/);
});

test('bounded trust reporting requires unchanged identities, state and claim', () => {
  const skill = read('skills/windows-app-trust/SKILL.md');
  const scope = skill.split('## Select scope and evidence')[1].split('## Discover')[0];
  assert.ok(boundedTrustScope(scope), 'bounded scope must keep every artifact/host/security invariant unchanged');
  for (const invariant of [/repository/i, /source HEAD/i, /durable.*evidence/i, /affected.*section/i, /preserve.*unrelated.*valid.*artifacts\/evidence/i, /no.*new.*current.*trust.*approval.*claim/i]) assert.match(scope, invariant);
});

test('trust operations and changed security claims retain deep authorization and current observations', () => {
  const skill = read('skills/windows-app-trust/SKILL.md');
  const deep = skill.split('Take the deep path')[1].split('Load trust-model')[0];
  for (const trigger of [/signing/i, /certificate\/key.*creation/i, /trust-store/i, /policy.*operation/i, /security.*claim/i, /digest/i, /signer/i, /expiry\/revocation\/chain/i, /host\/SAC\/edition\/tooling.*drift/i, /missing.*durable.*evidence/i, /contradiction/i, /failed.*invariant/i, /public.*contract/i, /persisted.*state\/migrations/i, /deployment\/rollback\/availability/i]) assert.match(deep, trigger);
  for (const guard of [/operation-specific.*explicit.*authorization/i, /exact.*ownership/i, /elevation.*requires/i, /current.*Windows.*security.*state/i, /guarded.*helpers/i, /historical.*never.*authorize.*mutation/i]) assert.match(deep, guard);
});

test('trust evidence distinguishes history from current acceptance and invalidates changed boundaries', () => {
  const skill = read('skills/windows-app-trust/SKILL.md');
  for (const category of [/reusable/i, /invalidated/i, /freshly.*(?:executed|observed)/i, /assumptions\/inferences/i, /observation.*time.*scope/i, /expiry\/chain/i, /store\/policy.*state/i, /invalidates.*affected.*proof/i, /recollection.*insufficient.*execution.*evidence/i, /required.*security.*check/i, /never.*reuse.*old.*receipt.*volatile.*trust.*currently/i]) assert.match(skill, category);
  assert.ok(freshTrustClaim(skill), 'current trust claims must require fresh relevant observations');
  assert.match(skill, /Always.*verify.*signed.*artifact.*after.*signing/i);
});

test('trigger-loaded references retain executable trust guard requirements', () => {
  const skill = read('skills/windows-app-trust/SKILL.md');
  const security = read('skills/windows-app-trust/references/SECURITY.md');
  const safety = read('skills/windows-app-trust/references/SAFETY-VALIDATION.md');
  for (const invariant of [/references.*authoritative/i, /load.*references.*mechanism.*deep-path.*trigger/i, /safety.*checks.*intact/i]) assert.match(skill, invariant);
  assert.match(security, /deep.*explicit.*authorization.*elevation.*fresh/is);
  assert.match(safety, /reuse.*never.*bypasses.*executable.*guards/i);
  assert.match(safety, /post-sign.*verification/i);
  assert.match(safety, /presence\/version.*distinct.*enforcement/i);
});

test('bounded trust scope accepts equivalent phrasing and rejects incomplete invariants', () => {
  for (const equivalent of [
    'Use a bounded path only for read-only report/documentation maintenance with unchanged artifact digest, signer identity, certificate validity/expiry, trust-store state, policy identity and security claim.',
    'Only bounded documentation and report assessment is read-only: artifact digest, signer, certificate expiry, store, policy and security claim remain unchanged.',
  ]) assert.ok(boundedTrustScope(equivalent), equivalent);
  for (const lost of [
    'Use a bounded path only for read-only report/documentation maintenance with unchanged artifact digest, signer identity, certificate validity/expiry, trust-store state and security claim.',
    'Use a bounded path only for read-only report/documentation maintenance with unchanged artifact digest, signer identity, certificate validity/expiry, trust-store state and policy identity.',
    'Use a bounded path only for report/documentation maintenance with unchanged artifact digest, signer identity, certificate validity/expiry, trust-store state, policy identity and security claim.',
    'Never use a bounded path only for read-only report/documentation maintenance with unchanged artifact digest, signer identity, certificate validity/expiry, trust-store state, policy identity and security claim.',
  ]) assert.equal(boundedTrustScope(lost), false, lost);
});

test('current trust proof accepts equivalent phrasing and rejects historical-only claims', () => {
  for (const equivalent of [
    'Current signature/trust/enforcement claims require fresh relevant observations.',
    'Fresh observations must support claims about current trust, enforcement and signature acceptance.',
  ]) assert.ok(freshTrustClaim(equivalent), equivalent);
  for (const lost of [
    'Current signature/trust/enforcement claims rely on historical observations.',
    'Current signature/trust/enforcement claims require relevant observations.',
    'Current signature/trust/enforcement claims do not require fresh observations.',
  ]) assert.equal(freshTrustClaim(lost), false, lost);
});
