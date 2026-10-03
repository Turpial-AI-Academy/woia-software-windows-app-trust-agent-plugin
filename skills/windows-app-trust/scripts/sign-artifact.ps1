#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ArtifactPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AllowedRoot,
    [string]$TimestampUrl,
    [switch]$AllowUntrustedLocalSigner
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1')
. (Join-Path $PSScriptRoot 'lib\windows-trust-guards.ps1')
Import-WindowsTrustModule -Name 'Microsoft.PowerShell.Security' -RequiredCommands @('Get-AuthenticodeSignature', 'Set-AuthenticodeSignature') | Out-Null
Initialize-WindowsTrustFileGuard

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not $kits) { return $null }
    $root = Join-Path $kits 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    $candidate = Get-ChildItem -LiteralPath $root -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    return $null
}
function Get-StreamDigest($stream) {
    $stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
    finally { $sha.Dispose(); $stream.Position = 0 }
}
$artifact = (Resolve-Path -LiteralPath $ArtifactPath -ErrorAction Stop).ProviderPath
$resolvedRoot = (Resolve-Path -LiteralPath $AllowedRoot -ErrorAction Stop).ProviderPath
$extension = [IO.Path]::GetExtension($artifact).ToLowerInvariant()
if ($extension -notin @('.exe', '.dll', '.msi', '.msix', '.ps1', '.psm1', '.psd1', '.cat')) {
    throw "Unsupported signing extension '$extension'."
}
$normalized = $Thumbprint.ToUpperInvariant()
$cert = Get-WindowsTrustCodeSigningCertificate -Thumbprint $normalized
$guard = $null; $workspace = $null; $writing = $false; $preserveWorkspace = $false
try {
    # Refusing to sign outside AllowedRoot includes junctions, symlinks, ADS and hard links.
    $guard = [Turpial.WindowsTrust.GuardedArtifact]::Open($artifact, $resolvedRoot)
    $workspace = New-WindowsTrustPrivateDirectory
    $staged = Join-Path $workspace ([IO.Path]::GetFileName($artifact))
    $backup = Join-Path $workspace 'original.bytes'
    $beforeHash = Get-StreamDigest $guard.Stream
    foreach ($copy in @($staged, $backup)) {
        $destination = [IO.File]::Open($copy, 'CreateNew', 'Write', 'None')
        try { $guard.Stream.Position = 0; $guard.Stream.CopyTo($destination) }
        finally { $destination.Dispose() }
    }
    $toolUsed = 'Set-AuthenticodeSignature'
    $signTool = Find-SignTool
    if ($signTool -and $extension -in @('.exe', '.dll', '.msi', '.msix', '.cat')) {
        $signArgs = @('sign', '/sha1', $normalized, '/fd', 'SHA256')
        if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
        $signArgs += $staged
        & $signTool @signArgs | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed with exit code $LASTEXITCODE." }
        $toolUsed = $signTool
    } else {
        if ($extension -eq '.msix') { throw 'MSIX signing requires SignTool.' }
        $parameters = @{ LiteralPath = $staged; Certificate = $cert; HashAlgorithm = 'SHA256' }
        if ($TimestampUrl) { $parameters.TimestampServer = $TimestampUrl }
        $attempt = Set-AuthenticodeSignature @parameters
        Assert-WindowsTrustSignature -Signature $attempt -ExpectedThumbprint $normalized -AllowUntrustedLocalSigner:$AllowUntrustedLocalSigner | Out-Null
    }
    $signed = [IO.File]::Open($staged, 'Open', 'Read', 'Read')
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $staged
        # Signer thumbprint mismatch and every inconclusive status fail before commit.
        $decision = Assert-WindowsTrustSignature -Signature $signature -ExpectedThumbprint $normalized -AllowUntrustedLocalSigner:$AllowUntrustedLocalSigner
        $hash = Get-WindowsTrustFileSha256 -LiteralPath $staged
        if ((Get-StreamDigest $guard.Stream) -ne $beforeHash) { throw 'Artifact changed before signing commit.' }
        $writing = $true
        $guard.Stream.Position = 0; $signed.Position = 0
        $signed.CopyTo($guard.Stream)
        $guard.Stream.SetLength($signed.Length)
        $guard.Stream.Flush($true)
        if ((Get-StreamDigest $guard.Stream) -ne $hash) { throw 'Committed signed bytes do not match verified staged bytes.' }
        $writing = $false
    } finally { $signed.Dispose() }
    [pscustomobject]@{
        Result = $decision; Path = $guard.FinalPath; SHA256 = $hash
        SignatureStatus = [string]$signature.Status; StatusMessage = $signature.StatusMessage
        Subject = $signature.SignerCertificate.Subject; Thumbprint = $signature.SignerCertificate.Thumbprint
        Tool = $toolUsed; TimestampRequested = [bool]$TimestampUrl
        LocalUntrustedAccepted = ($decision -eq 'LOCAL_SIGNER_UNTRUSTED')
        PublicDistributionApproved = $false; PhysicalBoundaryVerified = $true
    } | ConvertTo-Json
} catch {
    $cause = $_
    if ($writing -and $guard -and $backup) {
        try {
            $original = [IO.File]::OpenRead($backup)
            try {
                $guard.Stream.Position = 0; $original.CopyTo($guard.Stream)
                $guard.Stream.SetLength($original.Length); $guard.Stream.Flush($true)
            } finally { $original.Dispose() }
            if ((Get-StreamDigest $guard.Stream) -ne $beforeHash) { throw 'Restored digest mismatch.' }
        } catch {
            $preserveWorkspace = $true
            throw "SIGNING_RECOVERY_REQUIRED: original restoration failed. Private recovery bytes retained at $backup. Cause: $($cause.Exception.Message)"
        }
    }
    throw $cause
} finally {
    if ($guard) { $guard.Dispose() }
    if (-not $preserveWorkspace -and $workspace -and (Test-Path -LiteralPath $workspace)) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
