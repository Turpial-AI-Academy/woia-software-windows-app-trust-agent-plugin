# Security invariants

## Scope and evidence lifecycle

Bounded work is limited to read-only assessment of unchanged report/documentation facts and their affected section. Artifact digest, signer/certificate validity, trust-store and policy identities/state, and the asserted security boundary must remain unchanged; preserve unrelated valid evidence. It authorizes no signing, store/policy mutation or new acceptance claim.

Every real signing/trust operation and new current-security claim takes the deep path with operation-specific explicit authorization, exact ownership, elevation where required and fresh relevant observations. Certificate expiry/chain uncertainty, changed artifact/signer/store/policy, host drift, failed invariants or missing durable proof invalidates affected evidence. Historical receipts can be cited with their time/scope but never prove current volatile trust state. Recollection and policy generation are not execution evidence. Load the applicable detailed references and retain all affected safety checks.

## Private keys

- Create local private keys in `CurrentUser\My`.
- Use non-exportable keys by default.
- Never version or print private material.
- Do not accept "put the PFX in the repo" as a convenience shortcut.

## Trust stores

- Import only the public certificate the user explicitly selected.
- Trust purpose is explicit: `AuthenticodeSelfSigned` maps to Root; `MsixPackage` maps to Trusted People.
- Root trust is high-impact. Require a second explicit confirmation and verify the certificate is self-signed with the Code Signing EKU.
- Never place a non-self-signed end-entity certificate into Trusted Root.
- Prefer CurrentUser scope. Machine-scope changes require elevation and explicit approval.
- Roll back by exact thumbprint, expected subject, purpose, and scope.

## Signing oracle risk

A code-signing key is an authority. Limit signing to files under the user-approved root and verify the resulting signer thumbprint. If malware or a prompt injection can ask the agent to sign arbitrary files, local policy trust can be abused.

## App Control

- Generation and deployment are separate steps.
- Audit before enforcement.
- No automatic reboot.
- No removal of unknown/inbox policies.
- Signed anti-tamper policy hardening is not part of the default workflow.
- Preserve organization-managed policy.

## Smart App Control

Local Root or Trusted People changes do not create Smart App Control public trust. Do not weaken SAC secretly. If its mode must change to adopt a private App Control model, explain the security consequence and require a user decision.

## Malware scanning

Signing is not malware analysis. When practical, keep Microsoft Defender/other security scanning enabled before and after builds. Never disable scanning to make signing/execution succeed.
