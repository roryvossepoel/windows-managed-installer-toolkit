# Changelog

All notable changes to this project will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Git tags use the `vMAJOR.MINOR.PATCH` format.

## [Unreleased]

## [0.1.1] - 2026-08-10

### Added

- Add concise phase and wait-progress output to detection and remediation runs.
- Document rule removal through the ADMX Not configured state.

### Changed

- Report toolkit version 0.1.1 in both scripts.
- Describe AppControl Manager independently as a general App Control for Business policy-management tool.

### Fixed

- Verify the required AppLocker `Services` extension and registry-backed `SystemApps` state for EXE and DLL collections.
- Detect and remove toolkit-owned rules when the associated slot, including the final slot, becomes Not configured.
- Skip remediation entirely when the complete desired state is already compliant.
- Skip unnecessary local AppLocker policy writes when no toolkit-owned rules require removal.

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

[Unreleased]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/releases/tag/v0.1.0
