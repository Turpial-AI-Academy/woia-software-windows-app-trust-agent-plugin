#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyID,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedFriendlyName,

    [Parameter(Mandatory = $true)]
    [switch]$ConfirmRemoval
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmRemoval) { throw 'Explicit -ConfirmRemoval is required.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'App Control policy removal requires an elevated PowerShell session.'
}

$ciTool = Get-Command CiTool.exe -ErrorAction Stop
$raw = & $ciTool.Source -lp -json 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Unable to inventory App Control policies before removal.' }
$policies = (($raw -join [Environment]::NewLine) | ConvertFrom-Json).Policies
$normalized = $PolicyID.Trim()
$policy = $policies | Where-Object { $_.PolicyID -eq $normalized } | Select-Object -First 1
if (-not $policy) { throw "Policy '$PolicyID' was not found." }

if ($policy.FriendlyName -ne $ExpectedFriendlyName) {
    throw "Friendly-name mismatch. Expected '$ExpectedFriendlyName', found '$($policy.FriendlyName)'."
}

$protectedDriverId = '{d2bda982-ccf6-4344-ac5b-0b44427b6816}'
if ($policy.PolicyID -ieq $protectedDriverId -or $policy.FriendlyName -match '^Microsoft ' -or $policy.FriendlyName -match 'Smart App Control') {
    throw 'Refusing to remove a Microsoft/inbox application-control policy.'
}

$output = & $ciTool.Source -rp $policy.PolicyID -json 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "CiTool policy removal failed: $($output -join [Environment]::NewLine)"
}
& $ciTool.Source -r | Out-Null

[pscustomobject]@{
    Removed = $true
    PolicyID = $policy.PolicyID
    FriendlyName = $policy.FriendlyName
    RebootInitiated = $false
} | ConvertTo-Json
