# Authenticode

Authenticode associates signed code with a certificate and provides tamper detection. It does not by itself guarantee that the publisher is publicly trusted or that the code is safe.

## Local signer

The bundled local signer helper creates:

- RSA 3072;
- SHA-256;
- Code Signing EKU;
- `CurrentUser\My`;
- non-exportable private key by default.

This identity is for controlled local/managed trust, not arbitrary public distribution.

## Local trusted-chain validation

For a self-signed development code-signing certificate, Authenticode chain validation requires that the certificate be trusted as a root on the controlled machine/account. Microsoft documents self-signed code-signing certificates as development/testing only and notes that users must manually install them as a trusted root.

The plugin therefore treats local root trust as a separate high-impact operation:

- public `.cer` only;
- self-signed certificate only;
- Code Signing EKU required;
- explicit `AuthenticodeSelfSigned` purpose;
- extra `-ConfirmTrustedRootChange`;
- exact thumbprint/subject rollback;
- `CurrentUser` preferred over `LocalMachine`.

This local root trust does **not** make the signer a Microsoft Trusted Root Program publisher and does **not** satisfy Smart App Control public signature trust.

MSIX package sideloading uses a different trust path and may use Trusted People as documented by Microsoft.

## Signing boundary

The signing helper requires `-AllowedRoot` and refuses artifacts outside that path. Treat the repository or a narrower artifact directory as the root. Do not use the signing identity as a generic machine-wide signing oracle.

## SignTool and PowerShell

For PE/package artifacts, prefer SignTool when available. PowerShell's `Set-AuthenticodeSignature` is a fallback for file types supported by the Windows SIP/PowerShell signing stack and is the native path for PowerShell scripts.

Never silently install Visual Studio/Windows SDK merely to obtain SignTool. Report the prerequisite or use a supported fallback.

## Timestamping

Public distribution normally benefits from a timestamp supplied by the signing provider/CA workflow. A local self-signed development signer usually does not need a public timestamp merely to test local execution.

Do not hard-code a third-party timestamp URL into the plugin as universal policy.

## Verification

Always inspect:

- signature status;
- signer thumbprint;
- signer subject;
- final artifact SHA-256.

Both signing and verification helpers require `Valid` by default. `UnknownError` is inconclusive and always blocks these helpers; the presence of a signer certificate is not sufficient approval.

For a deliberately untrusted local self-issued signer, `-AllowUntrustedLocalSigner` with the exact expected thumbprint permits only `NotTrusted` and returns `LOCAL_SIGNER_UNTRUSTED`, never public-distribution approval. It cannot be combined with `-RequireTrustedChain`. When native verification is inconclusive, diagnose the actual cause; establishing local trust is a separate explicitly authorized action, not an automatic repair.

Use `-RequireTrustedChain` when the selected workflow explicitly requires a trusted chain. A `Valid` result after local trust does not establish public publisher trust. See [SAFETY-VALIDATION.md](SAFETY-VALIDATION.md) for exact result and failure semantics.
