#requires -Version 5.1
# Pure decisions are separated from privileged effects for executable negative tests.
function Assert-WindowsTrustSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Signature,
        [string]$ExpectedThumbprint,
        [switch]$AllowUntrustedLocalSigner,
        [switch]$RequireTrustedChain
    )
    if ($AllowUntrustedLocalSigner -and $RequireTrustedChain) {
        throw 'AllowUntrustedLocalSigner and RequireTrustedChain are mutually exclusive.'
    }
    if (-not $Signature.SignerCertificate) { throw 'Artifact has no signer certificate.' }
    $cert = $Signature.SignerCertificate
    if ($ExpectedThumbprint -and $cert.Thumbprint -ine $ExpectedThumbprint) {
        throw 'Signer thumbprint mismatch.'
    }
    $status = [string]$Signature.Status
    if ($status -eq 'Valid') {
        return 'SIGNATURE_VALID'
    }
    # UnknownError is NEVER translated into NotTrusted, even for self-signed keys.
    if ($status -eq 'NotTrusted' -and $AllowUntrustedLocalSigner) {
        if (-not $ExpectedThumbprint -or $cert.Subject -cne $cert.Issuer) {
            throw 'Local-untrusted mode requires an exact expected self-issued signer.'
        }
        return 'LOCAL_SIGNER_UNTRUSTED'
    }
    # Preserve only bounded native text, not the signature/certificate objects.
    # Serialize it as data so embedded newlines cannot masquerade as log records.
    $diagnostic = [ordered]@{
        SignatureStatus = $status
        StatusMessage = $null
        StatusMessageAvailable = $false
        StatusMessageTruncated = $false
    }
    try {
        $property = $Signature.PSObject.Properties['StatusMessage']
        if ($property) {
            $nativeMessage = $property.Value
            if ($nativeMessage -is [string] -and $nativeMessage.Length -gt 0) {
                $diagnostic.StatusMessageAvailable = $true
                $diagnostic.StatusMessageTruncated = ($nativeMessage.Length -gt 2048)
                $diagnostic.StatusMessage = $nativeMessage.Substring(0, [Math]::Min(2048, $nativeMessage.Length))
            }
        }
    } catch {
        # Diagnostic extraction must never turn a rejection into acceptance or
        # replace the first causal signature status with a property-read error.
    }
    $detail = ConvertTo-Json -InputObject $diagnostic -Compress
    throw "Signature verification rejected status '$status'. Only Valid is accepted by default; UnknownError, NotSigned, HashMismatch, NotSupportedFileFormat, Incompatible, and unknown values fail closed. NativeSignatureDiagnostic=$detail"
}

function ConvertTo-WindowsTrustPolicyId {
    param([Parameter(Mandatory = $true)][string]$Value)
    $id = [Guid]::Empty
    if (-not [Guid]::TryParse($Value.Trim(), [ref]$id) -or $id -eq [Guid]::Empty) {
        throw 'Expected a non-empty App Control policy GUID.'
    }
    return $id.ToString('D')
}

function Read-WindowsTrustPolicyXml {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($LiteralPath, $settings)
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
    } finally { $reader.Dispose() }
    if ($xml.DocumentElement.LocalName -ne 'SiPolicy' -or
        $xml.DocumentElement.NamespaceURI -ne 'urn:schemas-microsoft-com:sipolicy') {
        throw 'Expected a namespaced App Control SiPolicy document.'
    }
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('ci', 'urn:schemas-microsoft-com:sipolicy')
    $ids = @($xml.SelectNodes('/ci:SiPolicy/ci:PolicyID', $ns))
    $bases = @($xml.SelectNodes('/ci:SiPolicy/ci:BasePolicyID', $ns))
    $versions = @($xml.SelectNodes('/ci:SiPolicy/ci:VersionEx', $ns))
    if ($ids.Count -ne 1 -or $bases.Count -ne 1 -or $versions.Count -ne 1) {
        throw 'Policy must declare exactly one PolicyID, BasePolicyID and VersionEx.'
    }
    $id = ConvertTo-WindowsTrustPolicyId $ids[0].InnerText
    $base = ConvertTo-WindowsTrustPolicyId $bases[0].InnerText
    $version = $versions[0].InnerText.Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Invalid policy VersionEx.' }
    $kind = if ($id -eq $base) { 'Base' } else { 'Supplemental' }
    $declaredType = $xml.DocumentElement.GetAttribute('PolicyType')
    if ($declaredType -cne ($kind + ' Policy')) {
        throw 'PolicyType conflicts with the actual PolicyID/BasePolicyID relationship.'
    }
    $options = @($xml.SelectNodes('/ci:SiPolicy/ci:Rules/ci:Rule/ci:Option', $ns) |
        ForEach-Object { $_.InnerText.Trim() })
    return [pscustomobject]@{
        PolicyID = $id; BasePolicyID = $base; PolicyKind = $kind
        Version = $version; AuditMode = ($options -contains 'Enabled:Audit Mode')
        Options = $options
    }
}

function Assert-WindowsTrustPolicyBinding {
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)][string]$DeclaredKind,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$BinarySha256,
        [Parameter(Mandatory = $true)][string]$CompiledSha256
    )
    if ($Policy.PolicyKind -cne $DeclaredKind) { throw 'PolicyKind does not match the reviewed policy.' }
    foreach ($digest in @($ExpectedSha256, $BinarySha256, $CompiledSha256)) {
        if ($digest -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid policy SHA-256.' }
    }
    if ($ExpectedSha256 -ine $BinarySha256 -or $BinarySha256 -ine $CompiledSha256) {
        throw 'Policy binary does not match the approved digest and the compiled reviewed XML.'
    }
    # This helper supports audit-only base adoption. Enforcement is a separate
    # managed process, not a switch that can bypass audit-first in this helper.
    if ($Policy.PolicyKind -eq 'Base') {
        if (-not $Policy.AuditMode) { throw 'Base policy deployment is audit-only; enforcement is refused.' }
        if ($Policy.Options -notcontains 'Enabled:Unsigned System Integrity Policy') {
            throw 'Signed/anti-tamper base policy deployment is outside this helper.'
        }
    }
}

function ConvertFrom-WindowsTrustBoolean {
    param($Value)
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string] -and $Value -imatch '^(true|false)$') { return ($Value -ieq 'true') }
    throw 'Policy inventory returned an unknown boolean value.'
}

function Get-WindowsTrustPolicyInventory {
    param([Parameter(Mandatory = $true)][scriptblock]$RunCiTool)
    $result = & $RunCiTool @('-lp', '-json')
    if ($null -eq $result -or $result.ExitCode -ne 0) { throw 'App Control inventory failed.' }
    $document = $result.Output | ConvertFrom-Json -ErrorAction Stop
    if (-not $document -or -not $document.PSObject.Properties['Policies']) {
        throw 'App Control inventory has no Policies array.'
    }
    foreach ($policy in @($document.Policies)) {
        if (-not $policy) { throw 'Malformed App Control policy inventory entry.' }
        # Normalize independently of brace/case formatting returned by CiTool.
        $policy.PolicyID = ConvertTo-WindowsTrustPolicyId ([string]$policy.PolicyID)
        $policy.BasePolicyID = ConvertTo-WindowsTrustPolicyId ([string]$policy.BasePolicyID)
        $policy
    }
}

function Assert-WindowsTrustOwnedPolicy {
    param([Parameter(Mandatory = $true)]$Policy)
    if (-not $Policy.PSObject.Properties['IsSystemPolicy']) {
        throw 'Policy ownership is unverified: IsSystemPolicy is absent.'
    }
    if ((ConvertFrom-WindowsTrustBoolean $Policy.IsSystemPolicy) -or
        $Policy.PolicyID -eq 'd2bda982-ccf6-4344-ac5b-0b44427b6816' -or
        $Policy.FriendlyName -match '^Microsoft |Smart App Control') {
        throw 'Refusing to modify a Microsoft/inbox application-control policy.'
    }
    # Non-system status is NOT proof of organizational ownership. The wrapper
    # additionally requires an explicit operator ownership confirmation.
}

function Invoke-WindowsTrustPolicyUpdate {
    param(
        [Parameter(Mandatory = $true)]$Policy,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][scriptblock]$RunCiTool
    )
    $before = @(Get-WindowsTrustPolicyInventory -RunCiTool $RunCiTool)
    $existing = @($before | Where-Object { $_.PolicyID -eq $Policy.PolicyID })
    if ($existing.Count -gt 1) { throw 'Duplicate target policy identity in inventory.' }
    if ($existing.Count -eq 1) { Assert-WindowsTrustOwnedPolicy $existing[0] }
    if ($Policy.PolicyKind -eq 'Supplemental') {
        $base = @($before | Where-Object { $_.PolicyID -eq $Policy.BasePolicyID -and $_.PolicyID -eq $_.BasePolicyID })
        if ($base.Count -ne 1) { throw 'The exact supplemental base policy is not installed.' }
        Assert-WindowsTrustOwnedPolicy $base[0]
    }
    $submitted = $false
    try {
        $submitted = $true
        $update = & $RunCiTool @('-up', $BinaryPath, '-json')
        if ($null -eq $update -or $update.ExitCode -ne 0) { throw 'CiTool update did not confirm success.' }
        $refresh = & $RunCiTool @('-r')
        if ($null -eq $refresh -or $refresh.ExitCode -ne 0) { throw 'CiTool refresh failed.' }
        $after = @(Get-WindowsTrustPolicyInventory -RunCiTool $RunCiTool)
        $found = @($after | Where-Object { $_.PolicyID -eq $Policy.PolicyID })
        if ($found.Count -ne 1 -or $found[0].BasePolicyID -ne $Policy.BasePolicyID -or
            $found[0].VersionString -ne $Policy.Version) {
            throw 'Post-deployment inventory does not confirm the exact policy identity/version.'
        }
        Assert-WindowsTrustOwnedPolicy $found[0]
        return [pscustomobject]@{
            Result = 'POLICY_PRESENT_VERIFIED'; Changed = $true
            PolicyID = $Policy.PolicyID; BasePolicyID = $Policy.BasePolicyID
            PolicyKind = $Policy.PolicyKind; Version = $Policy.Version
            AuditModeDeclared = $Policy.AuditMode
            EnforcementVerified = $false; RebootInitiated = $false
        }
    } catch {
        if ($submitted) {
            throw "POLICY_STATE_UNVERIFIED: update was attempted; changes may exist. Inventory/reconcile before retry or rollback. Cause: $($_.Exception.Message)"
        }
        throw
    }
}

function New-WindowsTrustPrivateDirectory {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Run this mutating helper with Windows PowerShell 5.1 (powershell.exe).'
    }
    $target = Join-Path ([IO.Path]::GetTempPath()) ('turpial-windows-trust-' + [Guid]::NewGuid().ToString('N'))
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    [IO.Directory]::CreateDirectory($target, $acl) | Out-Null
    return $target
}

function Initialize-WindowsTrustFileGuard {
    if ($env:OS -ne 'Windows_NT') { throw 'Artifact confinement requires Windows.' }
    if (-not ('Turpial.WindowsTrust.GuardedArtifact' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'GuardedArtifact.cs') -ErrorAction Stop
    }
}
