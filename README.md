# Windows Managed Installer Toolkit

Configure and maintain Windows Managed Installer rules with an ADMX-backed policy and Microsoft Intune Remediations.

> [!IMPORTANT]
> Version `0.1.0` is a preview intended for lab and pilot deployments. Test policy merging and removal against your existing AppLocker configuration before production use.

## Why this project exists

Windows uses a special AppLocker rule collection to identify trusted installer processes. App Control policies can then trust files written by those processes. Microsoft Intune can configure the Intune Management Extension as a managed installer, but it doesn't provide a general UI for maintaining additional updater or deployment processes.

This toolkit provides:

- an importable ADMX/ADML policy;
- ten predefined publisher-rule presets;
- twenty custom Managed Installer slots with structured input fields;
- Intune detection and remediation scripts;
- safe ownership and migration behavior;
- documentation for retrieving publisher metadata and creating custom rules.

## Policy layout

```text
Managed Installers
├── Presets
└── Custom
```

Preset defaults live in the PowerShell scripts, not in the ADMX. Updating a publisher detail or recommended minimum version therefore requires only a script update. ADMX overrides remain available for tenant- or group-specific exceptions.

## Included presets

- Intune Management Extension
- OMA Device Management Client
- Endpoint Privilege Management
- Windows Autopatch
- Adobe Installer
- Adobe Install Helper
- Adobe Update Service
- Acrobat Update Service
- Adobe Reader and Acrobat Manager
- Google Updater

See [Preset catalog](docs/preset-catalog.md) for the exact publisher conditions.

## Quick start

1. Import [`admx/ManagedInstallers.admx`](admx/ManagedInstallers.admx) and [`admx/en-US/ManagedInstallers.adml`](admx/en-US/ManagedInstallers.adml) into Intune.
2. Create an **Imported Administrative templates** profile.
3. Enable **Manage Managed Installers** and at least one preset or custom slot in the same profile.
4. Create an Intune Remediation with the scripts in [`scripts`](scripts).
5. Run both scripts as SYSTEM in 64-bit PowerShell.
6. Start with a dedicated pilot group.

Detailed instructions: [Deploy with Microsoft Intune](docs/deployment-intune.md).

## Safety model

- Preset publisher, executable, and rule IDs are fixed.
- Optional preset overrides only affect minimum version and product name.
- Custom rules reject paths, wildcards, malformed versions, and generic interpreters/installers.
- The remediation only removes rules it owns or recognizes from the earlier V8 policy.
- Unrelated local AppLocker rules are preserved.
- `Not Configured` makes no changes; `Disabled` intentionally removes toolkit-owned rules.

## Prerequisites

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or later
- Administrator or SYSTEM context
- An App Control policy with rule option 13, **Enabled: Managed Installer**
- Intune Remediations licensing when deploying through Microsoft Intune

## Documentation

- [Architecture](docs/architecture.md)
- [Intune deployment](docs/deployment-intune.md)
- [Detection and remediation](docs/detection-and-remediation.md)
- [Retrieve publisher information](docs/retrieving-publisher-information.md)
- [Create custom rules](docs/custom-rules.md)
- [Preset catalog](docs/preset-catalog.md)
- [Troubleshooting](docs/troubleshooting.md)

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Preset metadata changes that don't alter the ADMX schema are patch releases. New presets or policy fields are minor releases until `1.0.0`.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), especially the evidence required when proposing a new preset.

## License

Licensed under the [MIT License](LICENSE).
