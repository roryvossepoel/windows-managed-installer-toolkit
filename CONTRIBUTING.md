# Contributing

Contributions are welcome through GitHub issues and pull requests.

## Proposing a library entry

Include the purpose, vendor/channel and architecture, all five ADMX fields, the exact metadata-collection command, file version, sanitized evidence, and an assessment of what the process can install or execute. Verify that it is signed, not user-writable, and not a generic interpreter or launcher.

Do not propose generic interpreters, living-off-the-land binaries, or path rules as Managed Installers without a documented security assessment. Winget proposals must describe sources, arguments, execution context, writable locations, and installation scope.

Library entries are copy-and-paste examples. Adding or correcting one must not require changes to the ADMX or runtime scripts.

## Pull requests

1. Update `library/managed-installers.md` and `CHANGELOG.md` for library changes.
2. Validate ADMX and ADML XML for policy changes.
3. Keep rule-slot identity and registry paths backward compatible after the first stable release.
4. Test on a device with and without existing local AppLocker policy.
5. Describe security, removal, and upgrade behavior.

By contributing, you agree that your contribution is licensed under the MIT License.
