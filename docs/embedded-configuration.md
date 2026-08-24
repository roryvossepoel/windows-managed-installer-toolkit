# Embedded configuration without ADMX

Embedded mode configures Managed Installers directly from JSON stored in the Intune detection and remediation scripts. It doesn't require the ADMX, ADML, or a configuration profile.

## Configure both scripts

Make the following changes in both `Detect-ManagedInstallers.ps1` and `Remediate-ManagedInstallers.ps1`:

```powershell
$configurationMode = 'Embedded'
$embeddedConfigurationVersion = '1.0'
$allowEmptyEmbeddedConfiguration = $false
```

Replace the example JSON with the desired rules:

```powershell
$embeddedManagedInstallersJson = @'
[
  {
    "Slot": "01",
    "Name": "Example Software Agent",
    "Publisher": "O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US",
    "Product": "EXAMPLE SOFTWARE AGENT",
    "Binary": "EXAMPLEAGENT.EXE",
    "MinimumVersion": "1.0.0.0"
  },
  {
    "Slot": "02",
    "Name": "Second Software Agent",
    "Publisher": "O=SECOND EXAMPLE ORGANIZATION, C=US",
    "Product": "SECOND SOFTWARE AGENT",
    "Binary": "SECONDAGENT.EXE",
    "MinimumVersion": "2.0.0.0"
  }
]
'@
```

Each entry requires:

- a unique `Slot` from `01` through `20`;
- `Name`;
- the exact certificate `Publisher` value;
- `Product`;
- executable filename in `Binary`;
- a four-part `MinimumVersion`.

The same validation and executable blocklist used by Policy mode also apply to Embedded mode.

## Keep the scripts synchronized

Copy the entire JSON block to both scripts. Increase `$embeddedConfigurationVersion` whenever the desired rules change. Both scripts calculate a fingerprint from the normalized desired configuration:

```text
[Configuration] Mode: Embedded.
[Configuration] Embedded configuration version: 1.0.
[Configuration] Fingerprint: 8F31D224C912.
```

Detection and remediation must report the same version and fingerprint. Different fingerprints mean the scripts don't contain the same desired state.

## Empty configuration protection

An empty JSON array is rejected by default:

```powershell
$embeddedManagedInstallersJson = @'
[]
'@
```

This prevents a missing or accidentally emptied block from removing the complete Managed Installer collection. For intentional cleanup only, set this in both scripts:

```powershell
$allowEmptyEmbeddedConfiguration = $true
```

Run detection and remediation until the device reports compliant, then remove or replace the assignment. Set the value back to `$false` before adding rules again.

## Switching modes

There is no automatic fallback. To switch between Policy and Embedded modes:

1. Prepare both scripts with the complete desired state in the new mode.
2. Upload both updated scripts to the same Intune Remediation package.
3. Confirm the mode and fingerprint in the output.
4. Run detection and remediation on a pilot device.

The first remediation after switching modes rebuilds the complete local Managed Installer collection from the newly selected source. Don't run different modes in detection and remediation, and don't use another policy source to manage the Managed Installer collection at the same time.
