# Public distribution

If the application must run on arbitrary Windows devices without asking each user to install a private certificate or custom App Control policy, use a public signing/distribution path.

Current Microsoft-documented options include:

- Microsoft Store/MSIX workflows where applicable;
- Microsoft Artifact Signing / Trusted Signing where eligible;
- a code-signing certificate issued through an appropriate public CA path;
- SignPath Foundation for qualifying open-source projects.

A self-signed certificate is a development/managed-environment technique, not a free substitute for public publisher identity.

## Plugin behavior

The plugin may use an already-installed code-signing certificate by thumbprint when the private key is available to the current user. It must not:

- scrape/export hardware-backed/private keys;
- store PFX passwords;
- commit PFX files;
- promise SmartScreen reputation;
- claim that EV has a universal reputation bypass.

For public signing, preserve the signing provider's timestamping, key-storage, identity-verification, and release procedures.
