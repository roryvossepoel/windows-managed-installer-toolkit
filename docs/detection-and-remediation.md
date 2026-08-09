# Detection and remediation

## Configuration states

| ADMX state | Detection | Remediation |
|---|---|---|
| Not Configured | Returns compliant and makes no assumptions | Makes no changes |
| Enabled with rules | Compares desired and effective state | Reconciles desired rules |
| Enabled without rules | Returns noncompliant | Stops with a configuration error |
| Disabled | Checks that owned rules are absent | Removes owned rules |

## Detection flow

1. Read the global management state.
2. Resolve enabled presets using the embedded catalog.
3. Apply optional minimum-version and product-name overrides.
4. Read enabled custom slots and validate every field.
5. Detect stale local toolkit-owned rules.
6. Compare desired rules with the effective ManagedInstaller collection.
7. Verify Application Identity and AppLocker services.
8. Verify `ManagedInstaller.AppLocker` exists.

Detection intentionally compares the full publisher condition, not only a display name or one sentinel rule.

## Remediation flow

1. Build the same desired rule set as detection.
2. Load the local AppLocker policy.
3. Remove preset IDs, infrastructure IDs, and toolkit ownership markers.
4. Preserve every unrelated local rule.
5. Write the reconciled local policy.
6. If management is enabled, start Managed Installer tracking.
7. Generate a policy containing benign EXE/DLL rules, service tracking extensions, and desired Managed Installer publisher rules.
8. Merge the policy.
9. Wait for required services and verify effective rule IDs.

## Logging

Remediation writes a transcript to:

```text
%ProgramData%\ManagedInstallers\Remediation.log
```

Intune also captures standard output and exit state in the Remediation report.

## Updating the preset catalog

The `Get-PresetDefinitions` function exists in both scripts. Keep both copies identical. A future release might move catalog generation into a build step, but runtime scripts intentionally remain single-file artifacts for easy Intune deployment.
