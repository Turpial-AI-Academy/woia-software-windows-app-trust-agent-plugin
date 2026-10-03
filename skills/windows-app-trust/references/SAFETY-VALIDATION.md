# Executable safety boundaries

## Evidence depth

For report/documentation-only maintenance, verify unchanged artifact digest, signer/certificate validity, store and policy state and security claim; reuse durable unchanged facts with explicit observation time/scope and preserve unrelated valid evidence. This bounded assessment must be read-only for artifacts and host state and cannot create current signature/trust/enforcement approval.

Signing, certificate/trust-store or App Control operations, changed claims or identities, expiry/chain uncertainty, drift and missing or contradictory proof require deep handling: explicit operation authorization, exact ownership, required elevation and fresh relevant Windows observations. Mutation invalidates affected evidence and requires the affected checks again. Actual signing always retains post-sign verification; policy presence/version remains distinct from enforcement. Evidence reuse never bypasses these executable guards.

## Signature decisions

`sign-artifact.ps1` and `verify-artifact.ps1` accept only `Valid` by default.
`UnknownError`, `NotSigned`, `HashMismatch`, `NotSupportedFileFormat`, `Incompatible`,
and unrecognized statuses fail closed. A process exit code is not public publisher approval.

For a deliberately untrusted **local** self-issued signer, the caller may pass
`-AllowUntrustedLocalSigner` with the exact expected thumbprint. Only `NotTrusted`
is then tolerated and the result is `LOCAL_SIGNER_UNTRUSTED`, never public trust.
`UnknownError` is not relabeled as a chain-only problem. Do not combine this switch
with `-RequireTrustedChain`. Establish explicitly approved local trust first when
the native verifier cannot conclusively validate the untrusted signature.

Public distribution still requires the trust/reputation and timestamp checks in
[DISTRIBUTION.md](DISTRIBUTION.md). `PublicDistributionApproved` remains false in
these low-level receipts: neither file signing nor a local trust store establishes
public-distribution approval by itself.

## File confinement

Mutation uses Windows PowerShell 5.1 (`powershell.exe`). The signing guard holds
native directory/file handles, resolves final filesystem paths, rejects reparse
points/junctions/symlinks, alternate streams, UNC targets, and multi-link files,
and denies concurrent replacement/writes. The signer signs a private temporary
copy, checks its identity/status/digest, then copies those verified bytes back
through the still-open original handle. A failed commit attempts to restore the
original bytes; failed restoration returns `SIGNING_RECOVERY_REQUIRED` and retains
private recovery bytes for the operator. Successful and pre-commit-failed runs
remove their owned temporary workspace. No private key is exported.

This is not an isolation boundary against an administrator, kernel compromise,
or another process with equivalent authority over the operator's signing keys.

## Policy deployment

Required inputs now include the reviewed XML, the compiled binary, and the
explicitly approved binary SHA-256:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/deploy-app-control-policy.ps1 -PolicyXmlPath <REVIEWED.xml> -PolicyBinaryPath <APPROVED.cip> -ExpectedPolicySha256 <APPROVED_SHA256> -PolicyKind Supplemental -ConfirmDeployment -ConfirmPolicyOwnership
```

The helper parses XML with DTD/external entity processing prohibited, derives the
actual type from PolicyType and PolicyID/BasePolicyID, recompiles a private XML
snapshot with ConfigCI, and demands equality with both the provided binary and
the approved digest. Different compiler output requires review/new approval; it
is not a reason to bypass the comparison. Signed/anti-tamper binaries are outside
this helper's byte-identical unsigned compilation path.

Supplemental deployment requires the exact non-system base to be inventoried.
Ownership confirmation covers that base as well as the target policy; a non-system
flag alone does not establish ownership. Base deployment additionally requires
`-ConfirmBasePolicyDeployment`, verified SAC Off, audit mode and unsigned-policy
support. **This helper refuses all base enforcement deployment.** A later move to
enforcement belongs to the organization's separately reviewed managed process.

Every CiTool exit is checked. Failure after submission reports
`POLICY_STATE_UNVERIFIED`: the operation may have changed host state, so inventory
and reconcile before retry/rollback. Success means `POLICY_PRESENT_VERIFIED` with
matching policy/base/version in inventory, not enforcement or device acceptance.
Inspect CodeIntegrity events on a disposable authorized Windows test machine
before claiming operational acceptance. Never auto-deploy policy during tests.

## Local regression commands

```text
mise run ci:fast
node --test tests/windows-trust-guards.test.mjs
```

The Windows executable regressions cover the signature decision matrix,
XML/type/digest disagreement, base enforcement rejection, inventory/update/refresh
failures, post-deployment identity drift, junction/hard-link escapes and concurrent
file/ancestor replacement. They use disposable files and fake CiTool effects;
they do not change certificate stores or install policies. Linux skips are not
Windows PASS evidence. Existing signing/local-trust smokes remain separate,
explicitly authorized Windows checks.

## Primary references

- [PowerShell SignatureStatus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus)
- [CiTool commands](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [Audit before enforcement](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/enforce-appcontrol-policies)
- [Final path by handle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
