# Troubleshooting

## Smart App Control still blocks a locally signed EXE

Expected possibility. A self-signed/local certificate is not a public Smart App Control trust identity, even when its Authenticode chain is locally trusted. Choose public signing, a deliberate supported App Control-managed model, or a user-selected SAC mode change.

## Windows reports "Windows 10" in ProductName on a Windows 11 build

Some Windows 11 systems retain a legacy registry ProductName string. The discovery helper reports both the raw registry value and a `Family` derived from the numeric build. Builds 22000 and later are treated as Windows 11.

## Authenticode status stays UnknownError after Trusted People import

For ordinary EXE/DLL Authenticode trusted-chain validation, Trusted People is not the same as a trusted root. A self-signed development signing certificate must be explicitly trusted as a root on the controlled account/machine if a `Valid` Authenticode chain is required. Use the guarded `AuthenticodeSelfSigned` trust purpose only after explicit authorization. This still does not bypass Smart App Control. `UnknownError` always blocks the signing and verification helpers: do not assume it is solely a missing trust anchor, retry with weaker verification, or import a certificate automatically. Diagnose the status and see [SAFETY-VALIDATION.md](SAFETY-VALIDATION.md).

## Trusted Root change is not appropriate

Do not use `AuthenticodeSelfSigned` for a normal public/CA-issued end-entity certificate. Preserve the existing CA chain. For public distribution, use a publicly trusted signing path instead of manually rooting an end-entity certificate.

## SignTool not found

SignTool is normally installed with Visual Studio/Windows SDK tooling and may not be on PATH. The signing helper searches common SDK locations. `Set-AuthenticodeSignature` can sign files supported by the Windows SIP; MSIX requires SignTool in this helper.

## Certificate has no private key

The public `.cer` is verification/trust material only. Signing requires the original certificate with its private key in the user's personal store or another approved signing provider.

## ConfigCI is missing on Windows Home

This is an expected edition limitation. Microsoft documents that App Control PowerShell cmdlets are unavailable on Home. The plugin does not hand-author or deploy custom App Control policy on Home. Use a different trust profile or a supported Windows edition for App Control management.

## CiTool inventory returns -2147024891

That value maps to access denied (`0x80070005`) in the observed workflow. Re-run discovery in an elevated PowerShell only if you actually need policy inventory. Do not elevate routine signing work unnecessarily.

## App Control supplemental generation fails

Check:

- ConfigCI is available;
- the host is a supported non-Home authoring environment;
- the reference file is signed;
- the base XML is a multiple-policy base;
- the base contains `Enabled:Allow Supplemental Policies`;
- the base policy is actually owned/managed by this user or organization.

Do not broaden the policy to AllowAll as a troubleshooting shortcut.

## CiTool unavailable

CiTool is not present on all Windows versions. Do not fake deployment success. Follow Microsoft's deployment method for that OS or treat deployment as blocked.

## App Control policy blocks required software

Do not jump directly to enforcement changes. Return the policy to audit/recovery using the documented organization-owned procedure, inspect CodeIntegrity events, and refine the policy. Never delete unrelated system policies.
