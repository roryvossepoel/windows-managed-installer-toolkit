# Changelog

All notable changes to this project will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Git tags use the `vMAJOR.MINOR.PATCH` format.

## [Unreleased]

### Fixed

- Verify the required AppLocker `Services` extension and registry-backed `SystemApps` state for EXE and DLL collections.

## [0.1.0] - 2026-08-09

First prerelease of the App Control for Business Managed Installer Toolkit.

### Added

- Importable ADMX/ADML with twenty configurable Managed Installer rule slots.
- Intune detection and remediation scripts.
- Deterministic rule identities per ADMX slot.
- Validation for publisher, product, binary, and minimum-version values.
- Preservation of unrelated local AppLocker rules.
- Example Managed Installer library and supporting documentation.
- Remediation logging in `%ProgramData%\ManagedInstallers\Remediation.log`.

### Fixed

- Configure the Managed Installer collection as `Enabled` instead of `AuditOnly`.
- Wait for `ManagedInstaller.AppLocker` to be created or updated before reporting success.
- Verify the effective enforcement mode, required services, compiled policy, and desired rule IDs.

### Scope

- The toolkit manages the AppLocker Managed Installer configuration used by App Control for Business.
- It does not create, inspect, modify, convert, or deploy App Control for Business policies.

[Unreleased]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/releases/tag/v0.1.0
