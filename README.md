# woia-software-windows-app-trust

WOIA Software auxiliary provider for `windows-app-trust`, migrated preserve-first from `windows-app-trust-agent-plugin@2.0.1`.

Activation remains evidence-triggered. Windows presence alone never activates this capability.

- Plugin version: `0.5.6`
- Primary skill: `$windows-app-trust`
- Authoring profile: thin
- Source commit: `c3554c1426224e055c3bb5f30ebe29d546810730`

Generic certification/release tooling is centralized in `woia-ecosystem`.

## Maintenance

Edit only this canonical repository. Keep `plugin.json`, `package.json` and `dev.woia/manifest.json` versions aligned. From the canonical WOIA Ecosystem repository, run `mise run plugin:certify-thin --repo <absolute-plugin-repository>`, then use its release preparation/publication tasks. Install and update consumers from immutable published artifacts; keep Project personalization in overlays.
