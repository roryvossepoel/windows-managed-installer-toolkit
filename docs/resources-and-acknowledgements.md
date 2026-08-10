# Related resources and acknowledgements

## AppControl Manager

[AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security) by HotCakeX is an open-source Windows application for managing App Control for Business policies. It can be used to create base and supplemental policies, configure rule options, edit and merge policies, validate and simulate policies, create rules from files or event data, and deploy policies locally or through Microsoft Intune.

See the [AppControl Manager documentation](https://github.com/HotCakeX/Harden-Windows-Security/wiki) for installation instructions and its complete feature set. AppControl Manager is mentioned here as a general App Control for Business policy-management resource; no integration with or dependency on this ADMX toolkit is implied.

## Project origin and acknowledgement

This toolkit builds on the Managed Installer script published by Kim Oppalfens in the OSCC article [Reducing attack surface with Application Control and Managed Installers](https://www.oscc.be/attacksurfacereduction/Reducing-attack-surface-with-Application-Control-and-managed-installer%28s%29/). That work provided the technical starting point for this project.

The original script and article provided the foundation for:

- checking the effective AppLocker Managed Installer policy;
- starting the required runtime components with `appidtel.exe start -mionly`;
- merging the Managed Installer policy with `Set-AppLockerPolicy -Merge`;
- waiting for `ManagedInstaller.AppLocker` to be created or updated;
- verifying compliance after applying the policy.

This repository develops that foundation into an ADMX-driven configuration model with twenty stable rule slots, exact reconciliation of toolkit-owned rules, stricter input validation, preservation of unrelated local rules, Intune detection and remediation, versioning, and expanded verification.

## Microsoft documentation

The authoritative platform reference is Microsoft Learn: [Automatically allow apps deployed by a managed installer with App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer).
