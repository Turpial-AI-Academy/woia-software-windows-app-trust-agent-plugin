# Forks and clones

An upstream project's signing private key must not be distributed to people who clone or fork the repository.

## Upstream artifacts

If upstream ships prebuilt signed binaries, consumers verify those binaries against the upstream publisher/signature.

## Local rebuilds

A fork or clone that rebuilds the binary creates different bytes. The local user should:

1. create or reuse their own local signing identity;
2. keep the private key in their Windows certificate store;
3. export only the public certificate if another controlled device needs trust;
4. sign the locally built artifact;
5. use local-project or App Control trust appropriate to that environment.

Do not ask maintainers to share a PFX merely so forks can reproduce the same publisher signature.

## Repository metadata

A repository may safely commit:

- expected public certificate;
- expected public-certificate fingerprint;
- artifact patterns;
- trust-profile documentation.

It must not commit:

- PFX/private key;
- certificate password;
- cloud signing credentials;
- device-specific secret material.
