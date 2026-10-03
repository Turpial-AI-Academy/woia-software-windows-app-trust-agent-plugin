#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PolicyBinaryPath,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PolicyXmlPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedPolicySha256,
    [Parameter(Mandatory = $true)][ValidateSet('Supplemental', 'Base')][string]$PolicyKind,
    [Parameter(Mandatory = $true)][switch]$ConfirmDeployment,
    [Parameter(Mandatory = $true)][switch]$ConfirmPolicyOwnership,
    [switch]$ConfirmBasePolicyDeployment
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\windows-trust-modules.ps1')
. (Join-Path $PSScriptRoot 'lib\windows-trust-guards.ps1')
$edition = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
if ([string]$edition -match '^Core') { throw 'Custom App Control deployment is not supported by this plugin on Windows Home.' }
if (-not $ConfirmDeployment -or -not $ConfirmPolicyOwnership) { throw 'Explicit deployment and policy/base ownership confirmations are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'App Control policy deployment requires an elevated PowerShell session.' }
Import-WindowsTrustModule -Name 'ConfigCI' -RequiredCommands @('ConvertFrom-CIPolicy') | Out-Null
$ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $ciTool -PathType Leaf)) { throw 'Windows inbox CiTool.exe was not found.' }
if ([IO.Path]::GetExtension($PolicyBinaryPath) -ine '.cip') { throw 'Expected a compiled .cip policy.' }
$workspace = New-WindowsTrustPrivateDirectory
try {
    $xmlCopy = Join-Path $workspace 'reviewed.xml'
    $binaryCopy = Join-Path $workspace 'approved.cip'
    # Work only with these private snapshots after this point (no path re-read race).
    [IO.File]::WriteAllBytes($xmlCopy, [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PolicyXmlPath).Path))
    [IO.File]::WriteAllBytes($binaryCopy, [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PolicyBinaryPath).Path))
    $policy = Read-WindowsTrustPolicyXml -LiteralPath $xmlCopy
    if ($policy.PolicyKind -eq 'Base') {
        if (-not $ConfirmBasePolicyDeployment) { throw 'Base policy deployment additionally requires -ConfirmBasePolicyDeployment.' }
        $sac = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
        if ($null -eq $sac -or $sac -ne 0) { throw 'Smart App Control is On/Evaluation or unverified; base policy deployment is blocked.' }
    }
    $compiled = Join-Path $workspace ($policy.PolicyID + '.cip')
    ConvertFrom-CIPolicy -XmlFilePath $xmlCopy -BinaryFilePath $compiled -ErrorAction Stop | Out-Null
    Assert-WindowsTrustPolicyBinding -Policy $policy -DeclaredKind $PolicyKind -ExpectedSha256 $ExpectedPolicySha256 -BinarySha256 (Get-WindowsTrustFileSha256 $binaryCopy) -CompiledSha256 (Get-WindowsTrustFileSha256 $compiled)
    $run = {
        param([string[]]$CiArgs)
        $output = & $ciTool @CiArgs 2>&1
        $exitCode = $LASTEXITCODE
        [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine) }
    }.GetNewClosure()
    # Do not claim enforcement: presence/version is verified here; CodeIntegrity
    # events and target-device acceptance are separate required evidence.
    Invoke-WindowsTrustPolicyUpdate -Policy $policy -BinaryPath $compiled -RunCiTool $run | ConvertTo-Json -Depth 5
} finally { Remove-Item -LiteralPath $workspace -Recurse -Force }
