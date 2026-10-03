#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSubject,

    [Parameter(Mandatory = $true)]
    [ValidateSet('AuthenticodeSelfSigned', 'MsixPackage')]
    [string]$TrustPurpose,

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$Scope = 'CurrentUser',

    [Parameter(Mandatory = $true)]
    [switch]$ConfirmTrustChange,

    [switch]$ConfirmTrustedRootChange
)

$ErrorActionPreference = 'Stop'
$moduleBootstrap = Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1'
if (-not (Test-Path -LiteralPath $moduleBootstrap)) {
    throw "Windows trust module bootstrap was not found at '$moduleBootstrap'."
}
. $moduleBootstrap
Import-WindowsTrustModule -Name 'Microsoft.PowerShell.Security' | Out-Null

if (-not $ConfirmTrustChange) {
    throw 'Explicit -ConfirmTrustChange is required.'
}
if ($TrustPurpose -eq 'AuthenticodeSelfSigned' -and -not $ConfirmTrustedRootChange) {
    throw 'AuthenticodeSelfSigned trust removal changes the Trusted Root store and additionally requires -ConfirmTrustedRootChange.'
}

if ($Scope -eq 'LocalMachine') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'LocalMachine trust changes require an elevated PowerShell session.'
    }
}

$normalized = $Thumbprint.Replace(' ', '').ToUpperInvariant()
$storeName = if ($TrustPurpose -eq 'AuthenticodeSelfSigned') { 'Root' } else { 'TrustedPeople' }
$store = "Cert:\$Scope\$storeName"
$path = "$store\$normalized"
$cert = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue

if (-not $cert) {
    [pscustomobject]@{
        Changed = $false
        TrustPurpose = $TrustPurpose
        Store = $store
        Subject = $ExpectedSubject
        Thumbprint = $normalized
        Reason = 'NotPresent'
    } | ConvertTo-Json
    exit 0
}

if ($cert.Subject -ne $ExpectedSubject) {
    throw "Refusing to remove trusted certificate because subject mismatch. Expected '$ExpectedSubject', found '$($cert.Subject)'."
}

if ($TrustPurpose -eq 'AuthenticodeSelfSigned' -and $cert.Subject -ne $cert.Issuer) {
    throw 'Refusing to remove from Trusted Root because the certificate is not self-signed.'
}

Remove-Item -LiteralPath $path -Force
if (Test-Path -LiteralPath $path) {
    throw "Trusted certificate '$normalized' is still present after removal."
}

[pscustomobject]@{
    Changed = $true
    TrustPurpose = $TrustPurpose
    Store = $store
    Subject = $cert.Subject
    Thumbprint = $normalized
    Reason = 'Removed'
} | ConvertTo-Json
