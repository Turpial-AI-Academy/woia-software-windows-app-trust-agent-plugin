# Windows application trust model

## Separate the mechanisms

Do not collapse these into one concept:

1. **Authenticode signature** proves integrity and identifies the certificate used to sign.
2. **Certificate-chain trust** determines whether Windows trusts that certificate for the relevant purpose.
3. **Smart App Control (SAC)** uses Microsoft app intelligence and, for signature-based admission, publicly trusted RSA signing.
4. **App Control for Business** evaluates explicit policy rules and can authorize internal/private signing identities.
5. **SmartScreen/reputation** is a separate reputation experience and must not be described as identical to SAC.

A file may be correctly signed but still not have a trusted chain. A file may have a locally trusted Authenticode chain but still be blocked by Smart App Control. App Control may allow a private signer that Smart App Control would not treat as publicly trusted.

## Decision invariant

~~~text
WHO MUST RUN THIS?
  arbitrary public users -> public-distribution
  controlled clone/fork  -> local-project
  App Control managed    -> existing-app-control
~~~

If the requirement is "works on arbitrary SAC-enabled machines without setup", local self-signed trust does not satisfy it.

## Certificate placement

- Private key: `Cert:\CurrentUser\My`, non-exportable by default.
- Self-signed Authenticode local testing: explicitly trust the public certificate in the selected `Root` store only with extra user confirmation and a precise rollback path.
- MSIX sideloading/testing: Microsoft documents trusting the package-signing certificate in Trusted People.
- Do not place a non-self-signed end-entity certificate into Trusted Root. Trust the appropriate issuing root/chain instead.
- Do not version private material.

A self-signed code-signing certificate is its own one-certificate chain. Trusting it as a local root is a development/managed-device action, not public publisher identity and not Smart App Control public trust.

## Scope

Prefer `CurrentUser` when trust is needed only for one developer. `LocalMachine` affects all users and requires elevation.

## RSA

Use RSA for Windows code-signing workflows that need Smart App Control compatibility. ECC/ECDSA is not a Smart App Control signing path.
