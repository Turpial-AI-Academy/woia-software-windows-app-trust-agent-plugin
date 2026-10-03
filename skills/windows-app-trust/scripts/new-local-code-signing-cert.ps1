#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PublisherName,

    [ValidateRange(1, 5)]
    [int]$ValidYears = 2,

    [switch]$CreateNew
)

$ErrorActionPreference = 'Stop'
$moduleBootstrap = Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1'
if (-not (Test-Path -LiteralPath $moduleBootstrap)) {
    throw "Windows trust module bootstrap was not found at '$moduleBootstrap'."
}
. $moduleBootstrap
Import-WindowsTrustModule -Name 'Microsoft.PowerShell.Security' | Out-Null
Import-WindowsTrustModule -Name 'PKI' -RequiredCommands @('New-SelfSignedCertificate') | Out-Null
$subject = "CN=$PublisherName"

$existing = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Subject -eq $subject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date).AddDays(7)
    } |
    Sort-Object NotAfter -Descending)

if ($existing.Count -gt 0 -and -not $CreateNew) {
    $cert = $existing[0]
    [pscustomobject]@{
        Created = $false
        Subject = $cert.Subject
        Thumbprint = $cert.Thumbprint
        NotAfter = $cert.NotAfter.ToString('o')
        Store = 'Cert:\CurrentUser\My'
        HasPrivateKey = $cert.HasPrivateKey
        KeyPolicy = 'Existing certificate; exportability not changed'
    } | ConvertTo-Json
    exit 0
}

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -FriendlyName "Windows App Trust - $PublisherName" `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -TextExtension @(
        '2.5.29.37={text}1.3.6.1.5.5.7.3.3',
        '2.5.29.19={text}'
    ) `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears($ValidYears)

$cert = Get-WindowsTrustCodeSigningCertificate -Thumbprint $cert.Thumbprint

[pscustomobject]@{
    Created = $true
    Subject = $cert.Subject
    Thumbprint = $cert.Thumbprint
    NotAfter = $cert.NotAfter.ToString('o')
    Store = 'Cert:\CurrentUser\My'
    HasPrivateKey = $cert.HasPrivateKey
    KeyPolicy = 'NonExportable'
    Algorithm = 'RSA'
    KeyLength = 3072
    HashAlgorithm = 'SHA256'
    CodeSigningAuthority = $true
} | ConvertTo-Json
