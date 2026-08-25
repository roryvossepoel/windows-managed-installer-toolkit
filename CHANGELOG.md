# Changelog

All notable changes to this project will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Git tags use the `vMAJOR.MINOR.PATCH` format.

## [Unreleased]

## [1.1.1] - 2026-08-25

### Fixed

- Handle empty or minimal local AppLocker policy XML without calling methods on null node properties.
- Report the PowerShell script stack trace when remediation fails to make troubleshooting easier.

## [1.1.0] - 2026-08-24

### Added

- Add an explicit `Embedded` configuration mode for Intune deployments that don't use the custom ADMX.
- Add validated JSON configuration blocks to both scripts with a generic example rule.
- Add configuration version and SHA-256 fingerprint output to help verify that detection and remediation use identical embedded configuration.
- Add fail-safe handling that rejects an empty embedded configuration unless intentional cleanup is explicitly enabled in both scripts.
- Document Policy and Embedded deployment modes.

### Changed

- Report toolkit version 1.1.0 in both scripts.

## [1.0.0] - 2026-08-10

First stable release. The imported ADMX, Intune configuration profile, detection, and remediation flow were validated on an Intune-managed Windows device, including migration from a pre-existing Managed Installer configuration.

### Changed

- Treat enabled ADMX slots as the authoritative, exclusive state for the complete Managed Installer collection.
- Detect every additional local or effective Managed Installer rule as noncompliant.
- Remove all existing local Managed Installer rules during remediation, including rules created by earlier scripts, while preserving unrelated rules in other AppLocker collections.
- Report when another policy source continues to contribute effective Managed Installer rules.
- Report toolkit version 1.0.0 in both scripts and documentation.

### Added

- Add FAQ guidance for validating Managed Installer origin with `fsutil file queryEA`, distinguishing MI from ISG origin, and interpreting direct versus child-of-child creation.

## [0.1.3] - 2026-08-10

### Added

- Show the ADMX slot number and display name for enabled Managed Installer rules in detection and remediation output.
- Identify missing rules, stale toolkit rules, and the specific publisher-condition fields that differ.
- List Managed Installer rule names while removing, applying, and validating rules.

## [0.1.2] - 2026-08-10

### Fixed

- Preserve the desired rule set as an array when exactly one Managed Installer slot is enabled, restoring rule counts and the compliant no-op remediation path.

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

[Unreleased]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.3...v1.0.0
[0.1.3]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/roryvossepoel/ManagedInstaller-ADMX/releases/tag/v0.1.0
