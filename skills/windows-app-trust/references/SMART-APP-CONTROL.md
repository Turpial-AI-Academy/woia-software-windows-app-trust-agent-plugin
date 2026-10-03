# Smart App Control

Smart App Control is a Windows application-control feature that combines Microsoft app intelligence with code-integrity policy.

## What the plugin may conclude

When app intelligence cannot establish safety, Smart App Control accepts signature-based trust only through the supported public trust model. Microsoft currently documents RSA-based code signing for Smart App Control and does not treat an arbitrary self-signed certificate as equivalent to a certificate from its trusted-root ecosystem.

Therefore:

~~~text
self-signed + imported locally != public SAC trust
~~~

Installing a local certificate is useful for development, MSIX/local package trust, or App Control policy scenarios, but it is not a supported per-app Smart App Control exception.

## Per-app bypass

Do not offer a hidden per-file bypass. Microsoft documents no individual allow exception in Smart App Control.

## Mode changes

A Smart App Control mode change affects the security posture of the machine. In v1.0:

- discovery may read the documented state value;
- the plugin does not change SAC state through a hidden registry edit;
- when the user deliberately chooses a different model, guide them through supported Windows Security controls and re-discover state afterward.

Current Windows releases have changed SAC re-enable behavior over time. Do not repeat stale claims that a reset/reinstall is always required; verify the current host/documentation when that detail matters.

## Transition to App Control

If the user wants private/internal signer rules, App Control for Business is the policy system designed for that degree of customization. Treat the transition as a deliberate security architecture change, not a workaround.
