# Deploy with Microsoft Intune

## 1. Import the Administrative Template

In the Intune admin center:

1. Go to **Devices > Configuration > Import ADMX**.
2. Import `admx/ManagedInstallers.admx`.
3. Import `admx/en-US/ManagedInstallers.adml` as its language resource.
4. Wait until the import reports **Available**.

## 2. Create the configuration profile

1. Create a Windows profile using **Imported Administrative templates**.
2. Open **Managed Installers**.
3. Set **Manage Managed Installers** to **Enabled**.
4. Enable at least one rule under **Custom rules**.
5. Enter all five fields, using a verified local binary or the [example library](../library/managed-installers.md) as a starting point.
6. Assign the profile to a device-based pilot group.

Don't enable management without selecting any rule. The scripts treat that state as a configuration error. Use **Disabled** when you intentionally want to remove all toolkit-owned rules.

## 3. Create the Remediation

Create an Intune Remediation with:

| Setting | Value |
|---|---|
| Detection script | `scripts/Detect-ManagedInstallers.ps1` |
| Remediation script | `scripts/Remediate-ManagedInstallers.ps1` |
| Run using logged-on credentials | No |
| Enforce script signature check | According to your signing process |
| Run in 64-bit PowerShell | Yes |

Use a conservative schedule during the pilot. A daily schedule is normally sufficient after deployment stabilizes.

## 4. App Control prerequisite

The App Control base policy must include rule option 13, **Enabled: Managed Installer**. The AppLocker policy only enables tracking and identifies trusted installer processes; it doesn't make App Control consume the resulting origin information by itself.

## 5. Pilot validation

Validate at least:

1. a device without an existing AppLocker policy;
2. a device with unrelated local AppLocker rules;
3. custom slot addition, modification, disablement, and reuse;
4. minimum-version enforcement;
6. global `Not Configured`, `Enabled`, and `Disabled` behavior;
7. application installation and subsequent update behavior;
8. AppLocker and Code Integrity event logs.

## Updating rule details

Change the assigned custom-slot values and let remediation reconcile the same stable slot ID. The scripts and ADMX do not need an update when a vendor changes publisher metadata or a recommended minimum version. Reimport the ADMX only when its policy schema changes.
