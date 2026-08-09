# Troubleshooting

## Configuration isn't detected

Verify the ADMX-backed registry values:

```powershell
Get-ChildItem 'HKLM:\Software\Policies\ManagedInstallers' -Recurse |
    ForEach-Object {
        $_.PSPath
        Get-ItemProperty $_.PSPath
    }
```

The global `Enabled` value must exist. `Not Configured` intentionally causes both scripts to make no changes.

## Enabled without rules

The scripts reject a globally enabled configuration with no enabled custom slot. Enable at least one rule in the same profile, or set global management to Disabled for intentional cleanup.

## Invalid custom rule

Check the Intune Remediation output and `%ProgramData%\ManagedInstallers\Remediation.log`. Common causes include:

- incomplete four-part version;
- publisher missing `O=`;
- wildcard in publisher or product;
- executable specified as a full path;
- blocked generic executable.

## Required service isn't running

Inspect:

```powershell
Get-Service AppIDSvc, appid, applockerfltr
```

The remediation invokes:

```powershell
appidtel.exe start -mionly
```

Investigate AppLocker/Application Identity event logs when services don't start.

## Policy binary missing

The detection script checks:

```text
%windir%\System32\AppLocker\ManagedInstaller.AppLocker
```

On a 32-bit process running on 64-bit Windows it uses `Sysnative`. Confirm the remediation ran as SYSTEM in 64-bit PowerShell and that `Set-AppLockerPolicy` completed successfully.

## Unexpected application blocks

Immediately review all existing AppLocker collections. Empty collections configured as `NotConfigured` can become enforced after policy merges when a rule is added. The toolkit doesn't intentionally create empty Appx, MSI, or Script collections.

Don't remove AppLocker or App Control policies blindly. Follow your recovery process and test cleanup on a representative device.

## Self-updating application still blocked

Managed Installer tagging is heuristic. Confirm the process writing the updated files is the binary defined as Managed Installer and that it was restarted after the policy became active. Some application and driver update paths still require explicit App Control rules.
