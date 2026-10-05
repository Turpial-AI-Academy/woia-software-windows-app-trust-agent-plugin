---
name: windows-app-trust
description: Audit, configure, sign, and validate Windows application trust for repository-built software. Use when Smart App Control blocks a project binary, when signing EXE/DLL/MSI/MSIX or PowerShell artifacts, when creating a local code-signing identity, when installing explicit local publisher trust, or when adding a project signer to a supported App Control for Business environment.
license: MIT
compatibility: Core signing workflows require Windows. Local App Control policy authoring requires a supported non-Home edition with ConfigCI; deployment operations require elevation.
metadata:
  author: Turpial AI Academy
  version: "0.5.1"
---

# windows-app-trust

## Operating flow

~~~text
DISCOVER -> DECIDE -> IMPLEMENT -> VALIDATE -> REPORT
~~~

Treat Windows trust as a system-security boundary, not as a build annoyance. Diagnose why code is blocked before changing certificates or policy.

## Non-negotiable rules

- Never claim that a self-signed certificate satisfies Smart App Control public publisher trust.
- Never disable Smart App Control, Defender, antivirus, memory integrity, Secure Boot, or App Control as a hidden workaround.
- Never commit, export, print, or package a private signing key. Locally generated keys are non-exportable by default.
- Never place a non-self-signed end-entity certificate in Trusted Root. For local Authenticode testing, a self-signed code-signing certificate may be explicitly trusted as a root only with extra confirmation and rollback; for MSIX sideloading, use the package-signing trust model instead.
- Sign only user-authorized artifacts contained under the declared repository/artifact root.
- App Control policy deployment/removal requires explicit human authorization and an elevated shell.
- Never deploy a new base App Control policy directly in enforcement mode. Adopt new base policies audit-first.
- Do not attempt local App Control policy authoring/deployment on Windows Home; explain the edition/tooling limitation and choose another trust profile.
- Do not remove unknown, Microsoft inbox, or organization-managed App Control policies.
- Driver/kernel signing is out of scope.

Read [references/SECURITY.md](references/SECURITY.md) and [references/SAFETY-VALIDATION.md](references/SAFETY-VALIDATION.md) before changing local trust, signing files, or deploying App Control. These references remain authoritative for every affected security boundary.

## Select scope and evidence

Use a bounded fast path only for report/documentation maintenance that is read-only with respect to artifacts and host trust state, while artifact digest, signer identity, certificate validity/expiry, trust-store scope/state, policy identity/mode and the security claim remain unchanged. Anchor the repository, source HEAD, affected section and durable evidence; verify those invariants for the selected scope, amend the smallest coherent report section, and preserve unrelated valid artifacts/evidence. This path creates no new current trust, signature, enforcement or public-distribution approval claim.

Take the deep path for any signing, certificate/key creation, trust-store or policy operation, new/changed security claim, artifact digest or signer change, expiry/revocation/chain uncertainty, host/SAC/edition/tooling drift, missing durable required evidence, contradiction or failed invariant; also for public contracts, persisted state/migrations or deployment/rollback/availability risk. Require operation-specific explicit authorization, exact artifact/policy/signer ownership and elevation where the operation requires it. Observe current Windows security state and verify results through the existing guarded helpers; historical receipts never authorize a new trust mutation.

Load trust-model, SAC, Authenticode, distribution, App Control, security and safety references when the corresponding mechanism, ambiguity or deep-path trigger is involved. Keep required safety checks intact. A healthy report-only amendment does not replay full host discovery or signing/trust smokes merely because another session started.

Classify evidence as reusable, invalidated, freshly executed/observed, or assumptions/inferences. Durable historical receipts may support unchanged report facts, with their observation time and scope explicit. Changed digest, signer, certificate expiry/chain, store/policy state, tools or host security state invalidates affected proof. Current signature/trust/enforcement claims require fresh relevant observations; recollection or a generated policy is insufficient execution evidence. Revalidate affected invariants and every required security check; preserve unrelated still-valid evidence. Never reuse an old receipt as proof that volatile trust state is currently accepted.

## Discover

For deep discovery or a required fresh host observation on Windows, prefer the bundled read-only helper:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/discover-windows-trust.ps1
~~~

Identify:

- Windows family/build/edition; use the numeric build as authoritative when the legacy registry product name is misleading;
- whether Smart App Control is Off, On, Evaluation, or unavailable/unknown;
- whether `CiTool.exe`, ConfigCI, and SignTool are available;
- existing code-signing certificates in `Cert:\CurrentUser\My`;
- current App Control policies when CiTool can list them;
- whether App Control inventory failed only because the shell was not elevated;
- target artifact type and repository root;
- whether the software is for this machine/fork, a managed group, or arbitrary public users;
- existing enterprise PKI/public signing/App Control standards that must be preserved.

Read [references/TRUST-MODEL.md](references/TRUST-MODEL.md) and [references/SMART-APP-CONTROL.md](references/SMART-APP-CONTROL.md) when Smart App Control is involved.

## Decide

Choose one profile from evidence:

| Profile | Use when | Signing/trust model |
|---|---|---|
| `public-distribution` | arbitrary external Windows users must run the app without local policy setup | Use a publicly trusted signing path. Do not substitute a self-signed certificate. |
| `local-project` | a clone/fork or controlled workstation can establish explicit local trust | Create/reuse a per-user local signer; export only the public certificate; for Authenticode trusted-chain validation explicitly trust the self-signed signer as a local root, or use the MSIX Trusted People path for package sideloading. |
| `existing-app-control` | a supported non-Home device already has a user/organization-owned App Control base policy that allows supplemental policies | Create a narrow Publisher signer rule in a supplemental policy and deploy it only after approval. |

If Smart App Control is On and the selected artifact lacks Microsoft reputation/publicly trusted signing, importing a local self-signed certificate is not a Smart App Control bypass. Present the actual options: public signing, a deliberate move to a supported App Control-managed model, or a user-chosen Smart App Control mode change through supported Windows controls.

On Windows Home, Microsoft documents that the App Control PowerShell cmdlets are unavailable. Although Windows can evaluate App Control policy at runtime, the plugin does not author or deploy custom App Control policies locally on Home. Treat that path as blocked rather than improvising policy XML.

For public distribution read [references/DISTRIBUTION.md](references/DISTRIBUTION.md). For forks read [references/FORKS.md](references/FORKS.md).

## Implement

### Local project signer

Create or reuse a non-exportable RSA code-signing certificate:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/new-local-code-signing-cert.ps1 -PublisherName "My Project Local Signer"
~~~

Export only its public certificate when a consumer/device needs explicit trust:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/export-public-cert.ps1 -Thumbprint <THUMBPRINT> -OutputPath .trust/windows/publisher.cer
~~~

Install explicit local trust only after explaining the scope and receiving approval:

For a self-signed certificate used to validate Authenticode trust on this user account:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/install-local-trust.ps1 -CertificatePath .trust/windows/publisher.cer -TrustPurpose AuthenticodeSelfSigned -Scope CurrentUser -ConfirmTrustChange -ConfirmTrustedRootChange
~~~

For MSIX package sideloading, use `-TrustPurpose MsixPackage`, which targets Trusted People instead of Trusted Root.

Prefer `CurrentUser` for one developer/user. Use `LocalMachine` only when machine-wide trust is actually required; it needs elevation. Neither trust purpose converts the certificate into Smart App Control public trust.

Rollback explicit local trust with the exact thumbprint, subject, purpose, and scope:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/remove-local-trust.ps1 -Thumbprint <THUMBPRINT> -ExpectedSubject "CN=My Project Local Signer" -TrustPurpose AuthenticodeSelfSigned -Scope CurrentUser -ConfirmTrustChange -ConfirmTrustedRootChange
~~~

### Sign

Use the repository root as the signing boundary:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/sign-artifact.ps1 -ArtifactPath dist/app.exe -Thumbprint <THUMBPRINT> -AllowedRoot <REPOSITORY_ROOT>
~~~

If SignTool is absent, the helper uses `Set-AuthenticodeSignature` for file types whose Windows SIP supports Authenticode. MSIX requires SignTool in this helper.

For public certificates, use an appropriate timestamp service when the signing provider requires/recommends it. Read [references/AUTHENTICODE.md](references/AUTHENTICODE.md).

### Existing App Control

Only on a supported non-Home authoring host, and only when an existing base policy is owned by the user/organization and allows supplemental policies:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/new-app-control-signer-policy.ps1 -BasePolicyPath <BASE.xml> -ReferenceFile <SIGNED.exe> -OutputDirectory .agent-work/windows-app-trust -PolicyName "My Project Local Signer"
~~~

Generation and deployment are separate. Review the XML and reported policy ID first. Deployment requires explicit approval:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/deploy-app-control-policy.ps1 -PolicyXmlPath <REVIEWED.xml> -PolicyBinaryPath <POLICY.cip> -ExpectedPolicySha256 <APPROVED_SHA256> -PolicyKind Supplemental -ConfirmDeployment -ConfirmPolicyOwnership
~~~

Use [references/APP-CONTROL.md](references/APP-CONTROL.md) for audit-first base-policy adoption and rollback. The deployment helper verifies reviewed XML/binary/digest identity and refuses base enforcement deployment. A receipt verifies policy presence/version, not enforcement; failures after submission require state reconciliation before retry.

## Validate

Always verify the signed artifact after signing:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills/windows-app-trust/scripts/verify-artifact.ps1 -ArtifactPath dist/app.exe -ExpectedThumbprint <THUMBPRINT>
~~~

If a public-trust workflow requires a trusted chain, add `-RequireTrustedChain`.

Signature helpers accept only `Valid` by default. Explicit `-AllowUntrustedLocalSigner` with the exact expected self-issued signer permits only `NotTrusted` and reports `LOCAL_SIGNER_UNTRUSTED`, not public approval. `UnknownError`, incompatible/unsupported formats, hash mismatches, and unknown statuses always fail closed. Do not disable a check to sign through an inconclusive result.

For App Control, verify the policy appears through CiTool and check CodeIntegrity operational events before claiming success. Do not report a policy as enforced merely because policy generation succeeded.

## Report

State:

1. Windows family/build/edition and observed Smart App Control state;
2. selected trust profile and why;
3. certificate subject/thumbprint/expiry and whether the private key stayed non-exportable/local;
4. trust-store changes made, including scope;
5. each signed artifact, final SHA-256, signature status, signer thumbprint, and signing tool;
6. App Control edition/tool availability and policy IDs/names/mode when applicable;
7. privileged or manual actions the user performed;
8. checks actually run and any blocked/unverified behavior;
9. rollback steps.
10. selected bounded/deep path, durable evidence reused or invalidated, fresh observations, observation time/scope, and assumptions or remaining uncertainty.

## Detailed references

- [Trust model](references/TRUST-MODEL.md)
- [Authenticode](references/AUTHENTICODE.md)
- [Smart App Control](references/SMART-APP-CONTROL.md)
- [App Control for Business](references/APP-CONTROL.md)
- [Public distribution](references/DISTRIBUTION.md)
- [Forks and clones](references/FORKS.md)
- [Security](references/SECURITY.md)
- [Troubleshooting](references/TROUBLESHOOTING.md)
- [Microsoft sources](references/SOURCES.md)
