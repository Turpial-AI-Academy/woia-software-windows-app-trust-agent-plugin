#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Decisions','Paths')][string]$Suite = 'Decisions')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'skills\windows-app-trust\scripts\lib\windows-trust-guards.ps1')
function Check($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Reject([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Check $rejected $Message
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('turpial-guard-tests-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
$count = 0
try {
    if ($Suite -eq 'Decisions') {
        $thumb = 'A' * 40
        $signature = [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Thumbprint = $thumb; Subject = 'CN=Fixture'; Issuer = 'CN=Fixture' } }
        Check ((Assert-WindowsTrustSignature $signature) -eq 'SIGNATURE_VALID') 'Valid status must be accepted.'; $count++
        foreach ($status in @('UnknownError','NotSigned','HashMismatch','NotSupportedFileFormat','Incompatible','NotSupported','UnexpectedStatus','NotTrusted')) {
            $signature.Status = $status
            Reject { Assert-WindowsTrustSignature $signature } "Default accepted $status"; $count++
            if ($status -ne 'NotTrusted') {
                Reject { Assert-WindowsTrustSignature $signature -ExpectedThumbprint $thumb -AllowUntrustedLocalSigner } "Local mode accepted $status"; $count++
            }
        }
        $signature.Status = 'NotTrusted'
        Check ((Assert-WindowsTrustSignature $signature -ExpectedThumbprint $thumb -AllowUntrustedLocalSigner) -eq 'LOCAL_SIGNER_UNTRUSTED') 'Explicit local mode was lost.'; $count++
        Reject { Assert-WindowsTrustSignature $signature -AllowUntrustedLocalSigner } 'Local mode accepted unspecified signer.'; $count++
        Reject { Assert-WindowsTrustSignature $signature -ExpectedThumbprint ('B' * 40) -AllowUntrustedLocalSigner } 'Wrong signer was accepted.'; $count++
        Reject { Assert-WindowsTrustSignature $signature -ExpectedThumbprint $thumb -AllowUntrustedLocalSigner -RequireTrustedChain } 'Conflicting trust requirements accepted.'; $count++
        $signature.SignerCertificate = $null
        Reject { Assert-WindowsTrustSignature $signature } 'Missing certificate accepted.'; $count++

        $baseId = '11111111-1111-1111-1111-111111111111'
        $suppId = '22222222-2222-2222-2222-222222222222'
        $xmlPath = Join-Path $work 'policy.xml'
        $xml = '<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy"><VersionEx>1.2.3.4</VersionEx><PolicyID>{' + $baseId + '}</PolicyID><BasePolicyID>{' + $baseId + '}</BasePolicyID><Rules><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule></Rules></SiPolicy>'
        [IO.File]::WriteAllText($xmlPath, $xml)
        $policy = Read-WindowsTrustPolicyXml $xmlPath
        Check ($policy.PolicyKind -eq 'Base' -and $policy.AuditMode) 'Base/audit parsing failed.'; $count++
        $sha = 'a' * 64
        Assert-WindowsTrustPolicyBinding $policy 'Base' $sha $sha $sha; $count++
        Reject { Assert-WindowsTrustPolicyBinding $policy 'Supplemental' $sha $sha $sha } 'Mislabeled base passed.'; $count++
        Reject { Assert-WindowsTrustPolicyBinding $policy 'Base' $sha $sha ('b' * 64) } 'Different compiled bytes passed.'; $count++
        Reject { Assert-WindowsTrustPolicyBinding $policy 'Base' ('b' * 64) $sha $sha } 'Wrong approval digest passed.'; $count++
        $policy.AuditMode = $false
        Reject { Assert-WindowsTrustPolicyBinding $policy 'Base' $sha $sha $sha } 'Enforcement base passed.'; $count++
        $policy.AuditMode = $true
        [IO.File]::WriteAllText($xmlPath, '<!DOCTYPE SiPolicy [<!ENTITY x SYSTEM "file:///not-readable">]>' + $xml)
        Reject { Read-WindowsTrustPolicyXml $xmlPath } 'DTD accepted.'; $count++
        [IO.File]::WriteAllText($xmlPath, $xml.Replace('Base Policy', 'Supplemental Policy'))
        Reject { Read-WindowsTrustPolicyXml $xmlPath } 'PolicyType/IDs disagreement accepted.'; $count++
        [IO.File]::WriteAllText($xmlPath, $xml.Replace('</SiPolicy>', '<PolicyID>' + $baseId + '</PolicyID></SiPolicy>'))
        Reject { Read-WindowsTrustPolicyXml $xmlPath } 'Duplicate identity accepted.'; $count++

        $supp = [pscustomobject]@{ PolicyID = $suppId; BasePolicyID = $baseId; PolicyKind = 'Supplemental'; Version = '1.2.3.4'; AuditMode = $false }
        foreach ($failure in @('none','inventory','update','refresh','post-inventory','missing','version','system','base-missing')) {
            $state = [pscustomobject]@{ Calls = (New-Object 'System.Collections.Generic.List[string]') }
            $run = {
                param([string[]]$CiArgs)
                $command = $CiArgs[0]
                $state.Calls.Add($command)
                $second = @($state.Calls | Where-Object { $_ -eq '-lp' }).Count -gt 1
                $exitCode = 0
                if (($failure -eq 'inventory' -and $command -eq '-lp' -and -not $second) -or
                    ($failure -eq 'update' -and $command -eq '-up') -or
                    ($failure -eq 'refresh' -and $command -eq '-r') -or
                    ($failure -eq 'post-inventory' -and $command -eq '-lp' -and $second)) { $exitCode = 1 }
                $policies = @()
                if ($failure -ne 'base-missing') {
                    $policies += [pscustomobject]@{ PolicyID = $baseId; BasePolicyID = $baseId; IsSystemPolicy = $false; FriendlyName = 'Fixture base'; VersionString = '1.2.3.4' }
                }
                if ($second -and $failure -ne 'missing') {
                    $policies += [pscustomobject]@{ PolicyID = $suppId; BasePolicyID = $baseId; IsSystemPolicy = ($failure -eq 'system'); FriendlyName = 'Fixture supplemental'; VersionString = $(if ($failure -eq 'version') { '9.9.9.9' } else { '1.2.3.4' }) }
                }
                [pscustomobject]@{ ExitCode = $exitCode; Output = (@{ Policies = $policies } | ConvertTo-Json -Depth 6) }
            }.GetNewClosure()
            if ($failure -eq 'none') {
                $receipt = Invoke-WindowsTrustPolicyUpdate $supp 'fixture.cip' $run
                Check ($receipt.Result -eq 'POLICY_PRESENT_VERIFIED' -and -not $receipt.EnforcementVerified) 'Receipt overclaimed enforcement.'
                Check (($state.Calls -join ',') -eq '-lp,-up,-r,-lp') 'Unexpected effect ordering.'
            } else {
                Reject { Invoke-WindowsTrustPolicyUpdate $supp 'fixture.cip' $run } "Policy effect failure $failure passed."
                if ($failure -in @('inventory','base-missing')) { Check (-not $state.Calls.Contains('-up')) 'Mutation occurred before safe preflight.' }
            }
            $count++
        }
    } else {
        Initialize-WindowsTrustFileGuard
        $allowed = Join-Path $work 'allowed'; $outside = Join-Path $work 'outside'
        [IO.Directory]::CreateDirectory($allowed) | Out-Null
        [IO.Directory]::CreateDirectory($outside) | Out-Null
        $external = Join-Path $outside 'external.exe'
        $inside = Join-Path $allowed 'inside.exe'
        [IO.File]::WriteAllText($external, 'must remain unchanged')
        [IO.File]::WriteAllText($inside, 'original')
        Reject { $g = [Turpial.WindowsTrust.GuardedArtifact]::Open($external, $allowed); $g.Dispose() } 'Outside file accepted.'; $count++
        $junction = Join-Path $allowed 'junction'
        New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
        Reject { $g = [Turpial.WindowsTrust.GuardedArtifact]::Open((Join-Path $junction 'external.exe'), $allowed); $g.Dispose() } 'Junction escape accepted.'; $count++
        $hard = Join-Path $allowed 'hard.exe'
        New-Item -ItemType HardLink -Path $hard -Target $external | Out-Null
        Reject { $g = [Turpial.WindowsTrust.GuardedArtifact]::Open($hard, $allowed); $g.Dispose() } 'Hard link escape accepted.'; $count++
        Reject { $g = [Turpial.WindowsTrust.GuardedArtifact]::Open(($inside + ':stream'), $allowed); $g.Dispose() } 'ADS accepted.'; $count++
        $guard = [Turpial.WindowsTrust.GuardedArtifact]::Open($inside, $allowed)
        try {
            Reject { [IO.File]::WriteAllText($inside, 'racing writer') } 'Concurrent writer accepted.'; $count++
            Reject { [IO.File]::Move($inside, (Join-Path $allowed 'renamed.exe')) } 'Concurrent file rename accepted.'; $count++
            Reject { [IO.Directory]::Move($allowed, (Join-Path $work 'renamed-directory')) } 'Concurrent ancestor rename accepted.'; $count++
            Check ($guard.FinalPath -ieq $inside) 'Physical identity mismatch.'; $count++
        } finally { $guard.Dispose() }
        Check ([IO.File]::ReadAllText($external) -eq 'must remain unchanged') 'External fixture changed.'; $count++
        Check ([IO.File]::ReadAllText($inside) -eq 'original') 'Original fixture changed.'; $count++
        # Remove the junction itself before recursive cleanup.
        [IO.Directory]::Delete($junction)
    }
    [pscustomobject]@{ Result = 'PASS'; Suite = $Suite; Checks = $count; HostTrustChanged = $false; PoliciesDeployed = $false } | ConvertTo-Json
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
