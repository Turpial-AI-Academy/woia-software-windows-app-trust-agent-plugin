#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$moduleBootstrap = Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1'
if (-not (Test-Path -LiteralPath $moduleBootstrap)) {
    throw "Windows trust module bootstrap was not found at '$moduleBootstrap'."
}
. $moduleBootstrap
Import-WindowsTrustModule -Name 'Microsoft.PowerShell.Security' | Out-Null
Import-WindowsTrustModule -Name 'PKI' -RequiredCommands @('Export-Certificate') | Out-Null
$normalized = $Thumbprint.Replace(' ', '').ToUpperInvariant()
$cert = Get-WindowsTrustCodeSigningCertificate -Thumbprint $normalized

$full = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $full
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$result = Export-Certificate -Cert $cert -FilePath $full -Type CERT -Force
[pscustomobject]@{
    Path = $result.FullName
    Subject = $cert.Subject
    Thumbprint = $cert.Thumbprint
    ContainsPrivateKey = $false
} | ConvertTo-Json
