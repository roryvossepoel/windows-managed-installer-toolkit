# Windows Managed Installer Toolkit

Deploy and maintain Windows Managed Installer publisher rules with an English ADMX/ADML and Microsoft Intune Remediations.

The toolkit deliberately contains no built-in product presets. The ADMX provides twenty reusable custom-rule slots; administrators copy verified values from the [Managed Installer library](library/managed-installers.md), or collect values from their own signed installer.

## Why this design

- The ADMX remains stable when vendors change versions, product names, or signing details.
- Detection and remediation contain no vendor catalog and have no internet dependency.
- Every tenant explicitly controls the exact publisher rule it trusts.
- Library entries can evolve independently and are examples, not remotely applied configuration.

## Policy layout

```text
Managed Installers
├── Manage Managed Installers
└── Custom rules
    ├── Custom Managed Installer 01
    ├── ...
    └── Custom Managed Installer 20
```

Each custom slot contains Name, Publisher, Product name, Executable, and Minimum version. Slots use stable generated rule IDs, so changing a field updates the existing slot instead of accumulating rules.

## Quick start

1. Import `admx/ManagedInstallers.admx` and `admx/en-US/ManagedInstallers.adml` into Intune.
2. Create a device configuration profile from the imported administrative template.
3. Enable **Manage Managed Installers**.
4. Enable at least one custom slot and enter all five fields. You can copy an example from the [library](library/managed-installers.md).
5. Deploy `scripts/Detect-ManagedInstallers.ps1` and `scripts/Remediate-ManagedInstallers.ps1` as an Intune Remediation, running as SYSTEM in 64-bit PowerShell.
6. Start with a test group and verify the effective AppLocker policy before broad deployment.

The global policy is intentionally three-state: **Enabled** reconciles configured rules, **Disabled** removes only toolkit-owned rules, and **Not configured** makes no changes.

## Safety boundaries

The scripts accept signed publisher rules only. They reject wildcards, paths, and generic launchers such as `msiexec.exe`, PowerShell, CMD, Winget, and script hosts. A Managed Installer is a trust boundary: software launched by it can receive Managed Installer origin, so use the narrowest practical publisher, product, executable, and minimum version.

## Documentation

- [Managed Installer library](library/managed-installers.md)
- [FAQ](docs/faq.md)
- [Architecture](docs/architecture.md)
- [Intune deployment](docs/deployment-intune.md)
- [Detection and remediation](docs/detection-and-remediation.md)
- [Creating custom rules](docs/custom-rules.md)
- [Retrieving publisher information](docs/retrieving-publisher-information.md)
- [Troubleshooting](docs/troubleshooting.md)

## Versioning and contributions

This project follows [Semantic Versioning](https://semver.org/). Library-only corrections can be released without changing the ADMX or scripts. Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
