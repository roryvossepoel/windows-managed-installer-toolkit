# Detection and remediation

| Rule-slot state | Detection | Remediation |
|---|---|---|
| No slots configured, no toolkit rules present | Returns compliant | Makes no changes |
| No slots configured, toolkit rules remain | Requests remediation | Removes all toolkit-owned rules |
| One or more slots Enabled | Compares desired and effective state | Reconciles enabled rules |
| A slot Disabled or changed to Not configured | Checks that its rule is absent | Removes the rule |
| All configured slots Disabled | Checks that toolkit rules are absent | Removes all toolkit-owned rules |

## Detection flow

1. Determine whether any rule slot is configured.
2. Load the local policy and detect toolkit-owned rules, including rules whose slots became Not configured.
3. Read enabled slots and validate every field.
4. Derive a stable rule ID from each slot number.
5. Detect stale local toolkit-owned rules.
6. Compare complete publisher conditions with effective policy.
7. Verify that the Managed Installer collection is Enabled.
8. Verify the required EXE/DLL collection extensions, registry-backed SystemApps state, services, and `ManagedInstaller.AppLocker`.

## Remediation flow

1. Build and validate the desired Managed Installer rule set.
2. Remove toolkit-owned rules from local policy while preserving unrelated rules; skip the write when none exist.
3. If no rule slots are enabled—including when they were changed to Not configured—stop after cleanup.
4. Start Managed Installer tracking with `appidtel.exe start -mionly`.
5. Capture the existing compiled-policy timestamp, then generate and merge the Enabled Managed Installer publisher-rule collection.
6. Wait for the three required services and for `ManagedInstaller.AppLocker` to be created or updated.
7. Verify that the effective collection is Enabled, contains every desired rule ID, and has the required EXE/DLL extensions and registry-backed SystemApps state.

Intune normally invokes remediation only after detection reports noncompliance. When remediation is started manually, it first validates the complete desired state. If that state is already compliant, it reports that no changes are required and exits without rewriting or recompiling the policy.

The scripts contain no product catalog and make no network request. Values originate only from ADMX-backed registry configuration below `HKLM\Software\Policies\ManagedInstallers\Rules`.

## Logging

Remediation writes `%ProgramData%\ManagedInstallers\Remediation.log`. Intune also records script output and exit status.
