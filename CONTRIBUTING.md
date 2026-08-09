# Contributing

Contributions are welcome through GitHub issues and pull requests.

## Proposing a preset

Include all of the following:

- installer/updater purpose and vendor documentation;
- full publisher name from `Get-AppLockerFileInformation`;
- product name, binary name, and four-part file version;
- the exact command used to collect the metadata;
- why explicit App Control signer rules aren't sufficient;
- an assessment of what the process can install or execute;
- confirmation that the executable isn't user-writable or a generic interpreter.

Never propose `msiexec.exe`, PowerShell, Winget, `cmd.exe`, script hosts, living-off-the-land binaries, or a path rule as a Managed Installer.

## Pull requests

1. Keep rule IDs stable when updating existing presets.
2. Update detection and remediation metadata together.
3. Update `docs/preset-catalog.md` and `CHANGELOG.md`.
4. Validate the ADMX and ADML XML.
5. Test on a device with and without an existing local AppLocker policy.
6. Describe removal and upgrade behavior.

By contributing, you agree that your contribution is licensed under the MIT License.
