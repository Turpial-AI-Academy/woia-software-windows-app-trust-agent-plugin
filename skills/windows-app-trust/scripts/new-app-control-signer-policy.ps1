#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BasePolicyPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReferenceFile,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyName,

    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string]$Version = '1.0.0.0'
)

$ErrorActionPreference = 'Stop'
$edition = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
if ([string]$edition -match '^Core') {
    throw 'App Control policy authoring is not supported by this plugin on Windows Home. Microsoft documents that ConfigCI/App Control PowerShell cmdlets are unavailable on Home.'
}
Import-Module ConfigCI -ErrorAction Stop

$base = (Resolve-Path -LiteralPath $BasePolicyPath).Path
$reference = (Resolve-Path -LiteralPath $ReferenceFile).Path
$baseText = Get-Content -LiteralPath $base -Raw
if ($baseText -notmatch 'Enabled:Allow Supplemental Policies') {
    throw 'Base policy does not declare Enabled:Allow Supplemental Policies. Refusing to generate a supplemental policy.'
}

[xml]$baseXml = $baseText
$basePolicyId = [string]$baseXml.SiPolicy.PolicyID
if (-not $basePolicyId) {
    throw 'Base policy does not contain a PolicyID and may not be multiple-policy format.'
}

$signature = Get-AuthenticodeSignature -LiteralPath $reference
if (-not $signature.SignerCertificate -or $signature.Status -eq 'NotSigned' -or $signature.Status -eq 'HashMismatch') {
    throw 'Reference file must have a usable Authenticode signature before creating a Publisher rule.'
}

$outDir = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$safeName = ($PolicyName -replace '[^A-Za-z0-9._-]', '-').Trim('-')
if (-not $safeName) { throw 'PolicyName does not produce a safe output filename.' }

$xmlPath = Join-Path $outDir "$safeName.xml"
$rules = New-CIPolicyRule -DriverFilePath $reference -Level Publisher
New-CIPolicy -Rules $rules -FilePath $xmlPath -MultiplePolicyFormat -UserPEs
Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName $PolicyName -BasePolicyToSupplementPath $base -ResetPolicyID | Out-Null
Set-CIPolicyVersion -FilePath $xmlPath -Version $Version

[xml]$policyXml = Get-Content -LiteralPath $xmlPath
$policyId = [string]$policyXml.SiPolicy.PolicyID
if (-not $policyId) { throw 'Generated supplemental policy has no PolicyID.' }
$cleanId = $policyId -replace '[{}]', ''
$binaryPath = Join-Path $outDir "{$cleanId}.cip"
ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath

[pscustomobject]@{
    PolicyName = $PolicyName
    PolicyID = $policyId
    BasePolicyID = $basePolicyId
    ReferenceFile = $reference
    ReferenceSigner = $signature.SignerCertificate.Subject
    ReferenceThumbprint = $signature.SignerCertificate.Thumbprint
    RuleLevel = 'Publisher'
    XML = $xmlPath
    Binary = $binaryPath
    Deployed = $false
} | ConvertTo-Json
