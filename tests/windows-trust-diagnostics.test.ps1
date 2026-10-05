#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'skills/windows-app-trust/scripts/lib/windows-trust-guards.ps1')
# Pure fixtures only: no certificate store, native signing, network or CiTool.
$thumb = 'A' * 40
$checks = 0
function Check($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function New-SignatureFixture([string]$Status) {
    [pscustomobject]@{
        Status = $Status
        SignerCertificate = [pscustomobject]@{
            Thumbprint = $thumb; Subject = 'CN=Fixture'; Issuer = 'CN=Fixture'
        }
    }
}
function Capture-Rejection($Signature, [bool]$LocalMode = $false) {
    $record = $null
    try {
        # Exercise the child-scope/catch/rethrow shape used by sign-artifact.ps1.
        & {
            param($Value, [bool]$Local)
            try {
                Assert-WindowsTrustSignature -Signature $Value -ExpectedThumbprint $thumb -AllowUntrustedLocalSigner:$Local | Out-Null
            } catch {
                $cause = $_
                throw $cause
            }
        } $Signature $LocalMode
    } catch { $record = $_ }
    Check ($null -ne $record) 'A rejected status was accepted.'
    return $record
}
function Read-Diagnostic($Record) {
    $message = [string]$Record.Exception.Message
    $marker = ' NativeSignatureDiagnostic='
    $index = $message.IndexOf($marker, [StringComparison]::Ordinal)
    Check ($index -ge 0) 'Native diagnostic was lost across the exception boundary.'
    $json = $message.Substring($index + $marker.Length)
    Check ($json -notmatch '[\r\n]') 'Native text injected an unescaped log line.'
    return ($json | ConvertFrom-Json)
}
foreach ($status in @('UnknownError', 'NotSigned', 'HashMismatch', 'NotSupportedFileFormat', 'Incompatible', 'UnexpectedStatus', 'NotTrusted')) {
    $signature = New-SignatureFixture $status
    $signature | Add-Member -NotePropertyName StatusMessage -NotePropertyValue ('Fixture-only native detail for ' + $status)
    foreach ($local in @($false, $true)) {
        if ($status -eq 'NotTrusted' -and $local) { continue }
        $errorRecord = Capture-Rejection $signature $local
        $diagnostic = Read-Diagnostic $errorRecord
        Check ($diagnostic.SignatureStatus -ceq $status) 'Diagnostic changed the native status.'
        Check ($diagnostic.StatusMessage -ceq $signature.StatusMessage) 'Native message was lost or replaced.'
        Check ($diagnostic.StatusMessageAvailable -eq $true -and $diagnostic.StatusMessageTruncated -eq $false) 'Wrong native message availability.'
        # The smoke already records Exception.Message in its JSON Error field.
        $smokeJson = @{ SmokePassed = $false; Error = $errorRecord.Exception.Message } | ConvertTo-Json -Compress
        $smoke = $smokeJson | ConvertFrom-Json
        Check ($smoke.SmokePassed -eq $false -and $smoke.Error -ceq $errorRecord.Exception.Message) 'Smoke JSON lost the rejection detail.'
        $checks++
    }
}
foreach ($kind in @('absent', 'empty', 'null', 'unreadable', 'non-text')) {
    $signature = New-SignatureFixture 'UnknownError'
    switch ($kind) {
        'empty' { $signature | Add-Member -NotePropertyName StatusMessage -NotePropertyValue '' }
        'null' { $signature | Add-Member -NotePropertyName StatusMessage -NotePropertyValue $null }
        'unreadable' { $signature | Add-Member -MemberType ScriptProperty -Name StatusMessage -Value { throw 'Fixture property getter failure.' } }
        'non-text' { $signature | Add-Member -NotePropertyName StatusMessage -NotePropertyValue ([pscustomobject]@{ Unrelated = 'must not serialize' }) }
    }
    $record = Capture-Rejection $signature $true
    $diagnostic = Read-Diagnostic $record
    Check ($diagnostic.SignatureStatus -eq 'UnknownError') 'Missing detail masked the first causal status.'
    Check ($diagnostic.StatusMessageAvailable -eq $false -and $null -eq $diagnostic.StatusMessage) 'Missing native detail was invented.'
    $checks++
}
$signature = New-SignatureFixture 'UnknownError'
$message = 'Fixture "quoted" C:\owned\artifact.exe' + "`r`n" + [char]0xE9 + [char]27
$signature | Add-Member -NotePropertyName StatusMessage -NotePropertyValue $message
$diagnostic = Read-Diagnostic (Capture-Rejection $signature $true)
Check ($diagnostic.StatusMessage -ceq $message) 'Escaped or localized message did not round-trip.'; $checks++
$signature.StatusMessage = 'x' * 3000
$diagnostic = Read-Diagnostic (Capture-Rejection $signature)
Check ($diagnostic.StatusMessage.Length -eq 2048 -and $diagnostic.StatusMessageTruncated -eq $true) 'Native diagnostic is unbounded or silently truncated.'; $checks++
$signature = New-SignatureFixture 'Valid'
$signature | Add-Member -MemberType ScriptProperty -Name StatusMessage -Value { throw 'Acceptance must not read rejection diagnostics.' }
Check ((Assert-WindowsTrustSignature $signature -ExpectedThumbprint $thumb) -ceq 'SIGNATURE_VALID') 'Valid acceptance changed.'; $checks++
$signature.Status = 'NotTrusted'
Check ((Assert-WindowsTrustSignature $signature -ExpectedThumbprint $thumb -AllowUntrustedLocalSigner) -ceq 'LOCAL_SIGNER_UNTRUSTED') 'Explicit NotTrusted acceptance changed.'; $checks++
[pscustomobject]@{ Result = 'PASS'; Checks = $checks; HostTrustChanged = $false; NativeSigningExecuted = $false } | ConvertTo-Json
