# Related resources and acknowledgements

## AppControl Manager

[AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security) by HotCakeX is the recommended companion application for creating, reviewing, validating, editing, and deploying App Control for Business policies. It is open source, actively maintained, extensively documented, and also available through the Microsoft Store.

AppControl Manager and this toolkit have separate responsibilities:

- **AppControl Manager** manages App Control for Business policies.
- **ManagedInstaller-ADMX** manages the AppLocker Managed Installer configuration that can be consumed by App Control for Business.

See the [AppControl Manager documentation](https://github.com/HotCakeX/Harden-Windows-Security/wiki) for its complete feature set and usage guidance.

## Origin of the V8 reference script

The initial `AppLockerManagedInstallerV8` reference used during development evolved from the script published by Kim Oppalfens in the OSCC article [Reducing attack surface with Application Control and Managed Installers](https://www.oscc.be/attacksurfacereduction/Reducing-attack-surface-with-Application-Control-and-managed-installer%28s%29/).

That article provided the original foundation for:

- checking the effective AppLocker Managed Installer policy;
- starting the required runtime components with `appidtel.exe start -mionly`;
- merging the Managed Installer policy with `Set-AppLockerPolicy -Merge`;
- waiting for `ManagedInstaller.AppLocker` to be created or updated;
- verifying compliance after applying the policy.

This toolkit substantially reworks that foundation into an ADMX-driven configuration model with twenty stable rule slots, exact reconciliation of toolkit-owned rules, stricter input validation, preservation of unrelated local rules, Intune detection and remediation, versioning, and expanded verification.

## Microsoft documentation

The authoritative platform reference is Microsoft Learn: [Automatically allow apps deployed by a managed installer with App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer).
