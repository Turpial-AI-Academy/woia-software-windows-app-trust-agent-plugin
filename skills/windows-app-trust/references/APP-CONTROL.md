# App Control for Business

Use App Control when the requirement is explicit application allow policy, including private/internal signing identities.

## Edition/tooling boundary

Microsoft's current Windows edition/licensing page lists Pro, Enterprise, Pro Education/SE, and Education as supported App Control editions. Microsoft's feature-availability documentation also notes that App Control policy can be effective on all editions, but the App Control PowerShell cmdlets are not available on Home.

For that reason, the plugin uses this conservative boundary:

- **Home:** discover runtime state only; do not author or deploy custom App Control policy locally.
- **Supported non-Home edition with ConfigCI:** policy authoring is available.
- **Any deployment:** explicit authorization plus elevation.

Do not hand-author policy XML on Home merely to work around missing ConfigCI.

## Supported scope

On a supported authoring host the plugin can:

- inventory policies with CiTool when available;
- create a Publisher rule from a signed reference file;
- build a supplemental policy against an existing multiple-policy base that allows supplemental policies;
- convert the supplemental XML to `.cip`;
- deploy or remove an explicitly identified policy with CiTool after human authorization.

The plugin does **not** silently create and enforce a new base policy.

## Base-policy adoption

For a machine that does not already have an appropriate base policy, use Microsoft's current App Control Wizard/guidance. For lightly managed developer/user devices, Microsoft's Smart App Control-derived starter model is a common starting point.

Adoption sequence:

~~~text
discover
-> create/review base policy
-> AUDIT MODE
-> deploy to test machine
-> inspect CodeIntegrity events
-> correct gaps
-> explicit approval
-> only then consider enforcement
~~~

Do not convert a new base to enforcement merely because the target application works.

## Supplemental signer policy

The bundled helper requires:

- a supported non-Home authoring host;
- an existing base policy XML;
- evidence that the base allows supplemental policies;
- a signed reference binary;
- ConfigCI.

It creates a Publisher-level signer rule from the actual signature. Prefer signer rules over broad path rules when the project owns its signing identity.

## CiTool inventory

On some hosts `CiTool -lp -json` returns access denied from a non-elevated shell. Discovery reports that condition explicitly. Elevate only when App Control inventory is actually needed; normal signing/certificate discovery should remain non-elevated.

## Deployment

`deploy-app-control-policy.ps1` requires elevation, explicit deployment and ownership confirmation, reviewed XML, compiled binary, and the approved binary SHA-256. It verifies the actual policy type and XML/binary equality before mutation. Base deployment is audit-only and requires an additional confirmation switch; enforcement must use a separately reviewed managed process. The script never reboots automatically.

See [SAFETY-VALIDATION.md](SAFETY-VALIDATION.md) for required arguments, checked post-state, and handling `POLICY_STATE_UNVERIFIED`. A successful helper receipt confirms presence/identity/version, not enforcement or device acceptance.

## Rollback

Keep the XML, binary, policy ID, and friendly name. Use the guarded removal helper only for the exact policy you intentionally deployed. Never remove inbox/unknown/organization-managed policies.

Unsigned policies are easier to recover during local evaluation. Signed anti-tamper App Control policies are intentionally difficult to remove and can cause boot failure when misconfigured. Signed-policy hardening is outside the local bootstrap flow.
