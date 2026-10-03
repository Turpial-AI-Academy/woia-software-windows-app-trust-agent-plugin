#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ArtifactPath,
    [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedThumbprint,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [switch]$RequireTrustedChain,
    [switch]$AllowUntrustedLocalSigner
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1')
. (Join-Path $PSScriptRoot 'lib\windows-trust-guards.ps1')
Import-WindowsTrustModule -Name 'Microsoft.PowerShell.Security' -RequiredCommands @('Get-AuthenticodeSignature') | Out-Null
Initialize-WindowsTrustFileGuard
$artifact = (Resolve-Path -LiteralPath $ArtifactPath -ErrorAction Stop).ProviderPath
# Block concurrent writes/deletion while signature and digest evidence are read.
$lock = [Turpial.WindowsTrust.GuardedArtifact]::OpenRead($artifact)
$artifact = $lock.FinalPath
try {
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact
    $decision = Assert-WindowsTrustSignature -Signature $signature -ExpectedThumbprint $ExpectedThumbprint -RequireTrustedChain:$RequireTrustedChain -AllowUntrustedLocalSigner:$AllowUntrustedLocalSigner
    $hash = Get-WindowsTrustFileSha256 -LiteralPath $artifact
    if ($ExpectedSha256 -and $hash -ine $ExpectedSha256) { throw 'SHA-256 mismatch.' }
    [pscustomobject]@{
        Result = $decision; Path = $artifact; SHA256 = $hash
        SignatureStatus = [string]$signature.Status
        StatusMessage = $signature.StatusMessage
        Subject = $signature.SignerCertificate.Subject
        Thumbprint = $signature.SignerCertificate.Thumbprint
        TrustedChainRequired = [bool]$RequireTrustedChain
        LocalUntrustedAccepted = ($decision -eq 'LOCAL_SIGNER_UNTRUSTED')
        PublicDistributionApproved = $false
    } | ConvertTo-Json
} finally { $lock.Dispose() }
