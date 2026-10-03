#requires -Version 5.1

function Import-WindowsTrustModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string[]]$RequiredCommands = @()
    )

    $loaded = Get-Module -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $loaded) {
        $candidates = New-Object System.Collections.Generic.List[string]

        $currentHostModuleDir = Join-Path $PSHOME "Modules\$Name"
        if (Test-Path -LiteralPath $currentHostModuleDir) {
            $manifest = Get-ChildItem -LiteralPath $currentHostModuleDir -Filter '*.psd1' -File -ErrorAction SilentlyContinue |
                Sort-Object FullName |
                Select-Object -First 1
            if ($manifest) { $candidates.Add($manifest.FullName) }
        }

        $windowsPowerShellRoot = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules'
        $inboxModuleDir = Join-Path $windowsPowerShellRoot $Name
        if (Test-Path -LiteralPath $inboxModuleDir) {
            $manifest = Get-ChildItem -LiteralPath $inboxModuleDir -Filter '*.psd1' -File -ErrorAction SilentlyContinue |
                Sort-Object FullName |
                Select-Object -First 1
            if ($manifest -and -not $candidates.Contains($manifest.FullName)) {
                $candidates.Add($manifest.FullName)
            }
        }

        $available = @(Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending)
        foreach ($module in $available) {
            if ($module.Path -and -not $candidates.Contains($module.Path)) {
                $candidates.Add($module.Path)
            }
        }

        $errors = New-Object System.Collections.Generic.List[string]
        foreach ($candidate in $candidates) {
            try {
                Import-Module -Name $candidate -Force -ErrorAction Stop
                $loaded = Get-Module -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($loaded) { break }
            } catch {
                $errors.Add("$candidate :: $($_.Exception.Message)")
            }
        }

        if (-not $loaded) {
            $details = if ($errors.Count -gt 0) { $errors -join ' | ' } else { 'no module candidates found' }
            throw "Unable to load required Windows module '$Name'. PowerShell=$($PSVersionTable.PSVersion) PSEdition=$($PSVersionTable.PSEdition) PSHOME=$PSHOME. Details: $details"
        }
    }

    foreach ($command in $RequiredCommands) {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            throw "Module '$Name' loaded from '$($loaded.Path)', but required command '$command' is unavailable."
        }
    }

    return $loaded
}


function Get-WindowsTrustCodeSigningCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{40}$')]
        [string]$Thumbprint
    )

    $normalized = $Thumbprint.Replace(' ', '').ToUpperInvariant()
    $cert = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $normalized } |
        Select-Object -First 1)

    if ($cert.Count -eq 0) {
        $raw = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalized" -ErrorAction SilentlyContinue
        if (-not $raw) {
            throw "Code-signing certificate '$normalized' was not found in Cert:\CurrentUser\My."
        }

        $ekuOids = @()
        foreach ($extension in $raw.Extensions) {
            if ($extension.Oid.Value -eq '2.5.29.37') {
                try {
                    $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($extension, $extension.Critical)
                    $ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
                } catch {
                    $ekuOids = @()
                }
            }
        }
        $ekuText = if ($ekuOids.Count -gt 0) { $ekuOids -join ',' } else { '<none>' }
        throw "Certificate '$normalized' exists but is not recognized by the Windows certificate provider as a usable code-signing certificate with a private key. EKU OIDs: $ekuText"
    }

    return $cert[0]
}


function Get-WindowsTrustFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    $resolved = (Resolve-Path -LiteralPath $LiteralPath -ErrorAction Stop).Path
    $stream = [System.IO.File]::OpenRead($resolved)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream)
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }

    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
}
