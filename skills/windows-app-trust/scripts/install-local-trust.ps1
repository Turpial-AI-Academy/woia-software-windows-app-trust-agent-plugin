#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePath,

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
Import-WindowsTrustModule -Name 'PKI' -RequiredCommands @('Import-Certificate') | Out-Null

if (-not $ConfirmTrustChange) {
    throw 'Explicit -ConfirmTrustChange is required.'
}

$full = (Resolve-Path -LiteralPath $CertificatePath).Path
if ([IO.Path]::GetExtension($full).ToLowerInvariant() -notin @('.cer', '.crt')) {
    throw 'Only public .cer/.crt certificate files are accepted. Do not pass a PFX/private key.'
}

$publicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($full)
if ($publicCert.HasPrivateKey) {
    throw 'Refusing to import certificate material that exposes a private key.'
}

if ($TrustPurpose -eq 'AuthenticodeSelfSigned') {
    if (-not $ConfirmTrustedRootChange) {
        throw 'AuthenticodeSelfSigned trust changes the Trusted Root store and additionally requires -ConfirmTrustedRootChange.'
    }
    if ($publicCert.Subject -ne $publicCert.Issuer) {
        throw 'AuthenticodeSelfSigned trust requires a self-signed certificate. Do not place a non-self-signed end-entity certificate in Trusted Root.'
    }

    $ekuOids = @()
    foreach ($extension in $publicCert.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($extension, $extension.Critical)
            $ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
        }
    }
    if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.3') {
        throw 'AuthenticodeSelfSigned trust requires the Code Signing EKU.'
    }
}

if ($Scope -eq 'LocalMachine') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'LocalMachine trust changes require an elevated PowerShell session.'
    }
}

$storeName = if ($TrustPurpose -eq 'AuthenticodeSelfSigned') { 'Root' } else { 'TrustedPeople' }
$destination = "Cert:\$Scope\$storeName"
$imported = @(Import-Certificate -FilePath $full -CertStoreLocation $destination)
$selected = $imported | Where-Object { $_.Thumbprint -eq $publicCert.Thumbprint } | Select-Object -First 1
if (-not $selected) {
    throw "Certificate import did not return the expected thumbprint '$($publicCert.Thumbprint)'."
}

[pscustomobject]@{
    Changed = $true
    TrustPurpose = $TrustPurpose
    Store = $destination
    Subject = $selected.Subject
    Issuer = $selected.Issuer
    Thumbprint = $selected.Thumbprint
    PrivateKeyImported = $false
    TrustedRootChanged = ($storeName -eq 'Root')
    SmartAppControlPublicTrust = $false
} | ConvertTo-Json
