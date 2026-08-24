# Detection and remediation

Both scripts support two explicit configuration modes:

- `Policy` reads ADMX-backed registry values below `HKLM\Software\Policies\ManagedInstallers\Rules`.
- `Embedded` reads the JSON block stored in each script and doesn't require the ADMX or a configuration profile.

There is no automatic fallback between modes. The same mode and, for Embedded mode, exactly the same JSON must be used in both scripts.

| Rule-slot state | Detection | Remediation |
|---|---|---|
| No slots configured, no Managed Installer or toolkit infrastructure rules present | Returns compliant | Makes no changes |
| No slots configured, Managed Installer or toolkit infrastructure rules remain | Requests remediation | Removes all Managed Installer rules and toolkit infrastructure rules |
| One or more slots Enabled | Compares desired and effective state | Reconciles enabled rules |
| A slot Disabled or changed to Not configured | Checks that its rule is absent | Removes the rule |
| All configured slots Disabled | Checks that Managed Installer or toolkit infrastructure rules are absent | Removes all Managed Installer rules and toolkit infrastructure rules |

## Detection flow

1. Load and validate the selected configuration source.
2. Load the local policy and detect Managed Installer rules and toolkit infrastructure rules, including rules whose slots became Not configured.
3. Read enabled slots and validate every field.
4. Derive a stable rule ID from each slot number.
5. Detect stale local Managed Installer rules and toolkit infrastructure rules.
6. Compare complete publisher conditions with effective policy.
7. Verify that the Managed Installer collection is Enabled.
8. Verify the required EXE/DLL collection extensions, registry-backed SystemApps state, services, and `ManagedInstaller.AppLocker`.

## Remediation flow

1. Build and validate the desired Managed Installer rule set.
2. Remove the complete local Managed Installer collection and toolkit infrastructure rules while preserving unrelated rules in the other AppLocker collections; skip the write when none exist.
3. If no rule slots are enabled—including when they were changed to Not configured—stop after cleanup.
4. Start Managed Installer tracking with `appidtel.exe start -mionly`.
5. Capture the existing compiled-policy timestamp, then generate and merge the Enabled Managed Installer publisher-rule collection.
6. Wait for the three required services and for `ManagedInstaller.AppLocker` to be created or updated.
7. Verify that the effective collection is Enabled, contains every desired rule ID, and has the required EXE/DLL extensions and registry-backed SystemApps state.

Intune normally invokes remediation only after detection reports noncompliance. When remediation is started manually, it first validates the complete desired state. If that state is already compliant, it reports that no changes are required and exits without rewriting or recompiling the policy.

The scripts contain no product catalog and make no network request. Values originate from either ADMX-backed registry configuration or the embedded JSON block, depending on the explicit configuration mode.

## Output and logging

Both scripts report the selected mode, configuration fingerprint, slot number, and display name for every Managed Installer rule. Embedded mode also reports its administrator-defined configuration version. Detection identifies a missing rule, any additional local or effective Managed Installer rule, or the specific publisher-condition fields that differ. Remediation lists every existing Managed Installer rule it removes and the desired rules it applies. The selected configuration source is the exclusive desired state for the Managed Installer collection. Publisher, product, binary, and version values are not written to standard output to keep Intune results concise.

Remediation writes `%ProgramData%\ManagedInstallers\Remediation.log`. Intune also records script output and exit status.
