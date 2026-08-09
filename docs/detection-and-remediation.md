# Detection and remediation

| Rule-slot state | Detection | Remediation |
|---|---|---|
| No slots configured | Returns compliant | Makes no changes |
| One or more slots Enabled | Compares desired and effective state | Reconciles enabled rules |
| A slot Disabled | Checks that its rule is absent | Removes the rule |
| All configured slots Disabled | Checks that toolkit rules are absent | Removes all toolkit-owned rules |

## Detection flow

1. Determine whether any rule slot is configured.
2. Read enabled slots and validate every field.
3. Derive a stable rule ID from each slot number.
4. Detect stale local toolkit-owned rules.
5. Compare complete publisher conditions with effective policy.
6. Verify that the Managed Installer collection is Enabled.
7. Verify required services and `ManagedInstaller.AppLocker`.

## Remediation flow

1. Build and validate the desired Managed Installer rule set.
2. Remove toolkit-owned rules from local policy while preserving unrelated rules.
3. If management is Disabled, stop after cleanup.
4. Start Managed Installer tracking with `appidtel.exe start -mionly`.
5. Capture the existing compiled-policy timestamp, then generate and merge the Enabled Managed Installer publisher-rule collection.
6. Wait for the three required services and for `ManagedInstaller.AppLocker` to be created or updated.
7. Verify that the effective collection is Enabled and contains every desired rule ID.

The scripts contain no product catalog and make no network request. Values originate only from ADMX-backed registry configuration below `HKLM\Software\Policies\ManagedInstallers\Rules`.

## Logging

Remediation writes `%ProgramData%\ManagedInstallers\Remediation.log`. Intune also records script output and exit status.
