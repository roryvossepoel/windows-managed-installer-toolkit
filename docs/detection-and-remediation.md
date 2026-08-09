# Detection and remediation

| ADMX state | Detection | Remediation |
|---|---|---|
| Not Configured, including an existing policy key without `Enabled` | Returns compliant | Makes no changes |
| Enabled with custom rules | Compares desired and effective state | Reconciles desired rules |
| Enabled without rules | Returns noncompliant | Stops with a configuration error |
| Disabled | Checks that owned rules are absent | Removes owned rules |

## Detection flow

1. Read the global management state.
2. Read enabled custom slots and validate every field.
3. Derive a stable rule ID from each slot number.
4. Detect stale local toolkit-owned rules.
5. Compare complete publisher conditions with effective policy.
6. Verify required services and `ManagedInstaller.AppLocker`.

## Remediation flow

1. Build and validate the desired custom-rule set.
2. Remove toolkit-owned rules from local policy while preserving unrelated rules.
3. If management is Disabled, stop after cleanup.
4. Start Managed Installer tracking.
5. Generate and merge Managed Installer publisher rules.
6. Wait for services and verify effective rule IDs.

The scripts contain no product catalog and make no network request. Values originate only from ADMX-backed registry configuration.

## Logging

Remediation writes `%ProgramData%\ManagedInstallers\Remediation.log`. Intune also records script output and exit status.
