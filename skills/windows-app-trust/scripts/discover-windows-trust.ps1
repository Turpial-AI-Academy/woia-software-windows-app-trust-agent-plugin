#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $kits = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not $kits) { return $null }
    $root = Join-Path $kits 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $root)) { return $null }

    $candidate = Get-ChildItem -LiteralPath $root -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    return $null
}

function Convert-CiToolResult {
    param(
        [string[]]$Raw,
        [int]$ExitCode
    )

    $joined = ($Raw -join [Environment]::NewLine)
    $parsed = $null
    try {
        if ($joined) { $parsed = $joined | ConvertFrom-Json }
    } catch {
        $parsed = $null
    }

    $operationResult = $null
    if ($parsed -and $null -ne $parsed.OperationResult) {
        $operationResult = [int64]$parsed.OperationResult
    }

    $reason = $null
    if ($operationResult -eq -2147024891) {
        $reason = 'AccessDenied'
    } elseif ($ExitCode -ne 0) {
        $reason = 'CommandFailed'
    }

    [pscustomobject]@{
        ExitCode = $ExitCode
        OperationResult = $operationResult
        Reason = $reason
        Raw = if ($reason) { $joined } else { $null }
        Policies = if ($parsed -and $parsed.Policies) { $parsed.Policies } else { $null }
    }
}

$cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = 0
[int]::TryParse([string]$cv.CurrentBuildNumber, [ref]$build) | Out-Null
$family = if ($build -ge 22000) { 'Windows 11' } else { 'Windows 10' }
$isHomeEdition = [string]$cv.EditionID -match '^Core'

$sacValue = $null
$sacLabel = 'Unknown'
$sacPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
if (Test-Path -LiteralPath $sacPath) {
    $sacValue = (Get-ItemProperty -LiteralPath $sacPath -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    switch ($sacValue) {
        0 { $sacLabel = 'Off' }
        1 { $sacLabel = 'On' }
        2 { $sacLabel = 'Evaluation' }
        default { $sacLabel = 'Unknown' }
    }
}

$ciTool = Get-Command CiTool.exe -ErrorAction SilentlyContinue
$configCi = Get-Module -ListAvailable ConfigCI | Sort-Object Version -Descending | Select-Object -First 1
$ciInventory = $null
if ($ciTool) {
    try {
        $raw = @(& $ciTool.Source -lp -json 2>&1)
        $exit = $LASTEXITCODE
        $ciInventory = Convert-CiToolResult -Raw $raw -ExitCode $exit
    } catch {
        $ciInventory = [pscustomobject]@{
            ExitCode = $null
            OperationResult = $null
            Reason = 'Exception'
            Raw = $_.Exception.Message
            Policies = $null
        }
    }
}

$certs = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        Subject = $_.Subject
        Thumbprint = $_.Thumbprint
        NotAfter = $_.NotAfter.ToString('o')
        HasPrivateKey = $_.HasPrivateKey
    }
})

$result = [pscustomobject]@{
    Windows = [pscustomobject]@{
        Family = $family
        RegistryProductName = $cv.ProductName
        EditionID = $cv.EditionID
        DisplayVersion = $cv.DisplayVersion
        CurrentBuild = $cv.CurrentBuildNumber
        HomeEdition = $isHomeEdition
    }
    SmartAppControl = [pscustomobject]@{
        State = $sacLabel
        RawValue = $sacValue
        Source = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState'
        ReadOnlyObservation = $true
    }
    Tools = [pscustomobject]@{
        SignTool = Find-SignTool
        CiTool = if ($ciTool) { $ciTool.Source } else { $null }
        ConfigCI = if ($configCi) { $configCi.Version.ToString() } else { $null }
    }
    CurrentUserCodeSigningCertificates = $certs
    AppControl = [pscustomobject]@{
        LocalPolicyAuthoringSupportedByPlugin = (-not $isHomeEdition -and $null -ne $configCi)
        EditionNote = if ($isHomeEdition) {
            'Home edition detected. Microsoft documents that App Control PowerShell cmdlets are unavailable on Home; this plugin does not author or deploy custom App Control policies locally on Home.'
        } else {
            $null
        }
        Inventory = $ciInventory
        ElevationHint = if ($ciInventory -and $ciInventory.Reason -eq 'AccessDenied') {
            'CiTool policy inventory returned access denied. Re-run discovery from an elevated PowerShell only if App Control inventory is needed.'
        } else {
            $null
        }
    }
}

$result | ConvertTo-Json -Depth 12
