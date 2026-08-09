# App Control for Business Managed Installer Toolkit

Manage Managed Installers for App Control for Business through Microsoft Intune. The toolkit provides an ADMX/ADML for configuration profiles plus detection and remediation scripts that translate the configured rule slots into the local AppLocker Managed Installer policy.

Managed Installer is a powerful but underused Windows trust mechanism. Intune's built-in controls currently expose only the Intune Management Extension as a Managed Installer. This toolkit makes additional, deliberately selected installer and update services centrally configurable while keeping every trust decision explicit.

The initiative is intended to help organizations develop a more practical trust model and adopt App Control for Business more broadly. App Control for Business provides an important barrier against unknown and malicious software, while Managed Installer can reduce the operational burden of authorizing legitimate software delivery paths.

The toolkit manages the Managed Installer component used by App Control for Business. It does not create, modify, convert, or deploy the App Control for Business policies themselves.

## Release status

The current toolkit version is **0.1.0**. It is published as a prerelease while the complete ADMX, Intune detection, remediation, and Windows Sandbox workflow is being validated. See [CHANGELOG.md](CHANGELOG.md) for release notes.

The toolkit deliberately contains no built-in product presets. The ADMX provides twenty reusable Managed Installer rule slots; administrators copy verified values from the [Managed Installer library](library/managed-installers.md), or collect values from their own signed installer.

## Why this design

- The ADMX remains stable when vendors change versions, product names, or signing details.
- Detection and remediation contain no vendor catalog and have no internet dependency.
- Every tenant explicitly controls the exact publisher rule it trusts.
- Library entries can evolve independently and are examples, not remotely applied configuration.

## Policy layout

```text
Managed Installers
├── Managed Installer 01
├── ...
└── Managed Installer 20
```

Each slot contains Display name, Publisher name, Product name, Binary name, and Minimum version. Slots use stable generated rule IDs, so changing a field updates the existing slot instead of accumulating rules.

## Quick start

1. Import `admx/ManagedInstallers.admx` and `admx/en-US/ManagedInstallers.adml` into Intune.
2. Create a device configuration profile from the imported administrative template.
3. Enable at least one **Managed Installer 01–20** setting and enter all five fields. You can copy an example from the [library](library/managed-installers.md).
4. Deploy `scripts/Detect-ManagedInstallers.ps1` and `scripts/Remediate-ManagedInstallers.ps1` as an Intune Remediation, running as SYSTEM in 64-bit PowerShell.
5. Start with a test group and verify the effective AppLocker policy before broad deployment.

Each rule is three-state. **Enabled** creates or updates that rule, **Disabled** removes it, and **Not configured** leaves that slot unmanaged. If no slots are configured, the scripts make no changes. Setting every previously used slot to Disabled provides explicit cleanup.

## Safety boundaries

The scripts accept signed publisher rules only. They reject wildcards, paths, and a configurable blocklist of high-risk generic executables. A Managed Installer is a trust boundary: software launched by it can receive Managed Installer origin, so use the narrowest practical publisher, product, executable, and minimum version.

## Documentation

- [Managed Installer library](library/managed-installers.md)
- [FAQ](docs/faq.md)
- [Architecture](docs/architecture.md)
- [Intune deployment](docs/deployment-intune.md)
- [Detection and remediation](docs/detection-and-remediation.md)
- [Creating Managed Installer rules](docs/custom-rules.md)
- [Retrieving publisher information](docs/retrieving-publisher-information.md)
- [Troubleshooting](docs/troubleshooting.md)

## Versioning and contributions

This project follows [Semantic Versioning](https://semver.org/). Library-only corrections can be released without changing the ADMX or scripts. Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
