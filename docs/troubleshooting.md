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

Rule configuration is stored below `HKLM:\Software\Policies\ManagedInstallers\Rules\01` through `20`. If none of these slots contains an `Enabled` value, detection expects the Managed Installer collection to be empty and remediation removes any existing local Managed Installer rules.

## No enabled rules

This is valid when one or more configured slots are Disabled. Remediation removes the complete local Managed Installer collection and exits successfully. Use this as the explicit cleanup state before changing all slots to Not Configured.

## Unexpected Managed Installer rules remain

The enabled ADMX slots are the complete desired state. Inspect both policy views:

```powershell
Get-AppLockerPolicy -Local -Xml
Get-AppLockerPolicy -Effective -Xml
```

Rules present in Local are removed during remediation. If an additional rule exists only in Effective, another policy source such as domain Group Policy or MDM is contributing it. Remove the conflicting Managed Installer configuration at its source; repeatedly changing the local registry won't override that policy source.

## Invalid Managed Installer rule

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

Remediation applies the AppLocker policy before running `appidtel.exe start -mionly`, then waits up to five minutes for the services and compiled policy. For manual inspection, run:

```powershell
Get-ChildItem "$env:windir\System32\AppLocker" -Force
Get-AppLockerPolicy -Effective -Xml
```

The effective policy must contain EXE, DLL, and ManagedInstaller rule collections. If the rule is effective but `ManagedInstaller.AppLocker` is still absent after remediation, inspect the AppLocker/Application Identity event logs and the remediation transcript.

## Unexpected application blocks

Immediately review all existing AppLocker collections. Empty collections configured as `NotConfigured` can become enforced after policy merges when a rule is added. The toolkit doesn't intentionally create empty Appx, MSI, or Script collections.

Don't remove AppLocker or App Control policies blindly. Follow your recovery process and test cleanup on a representative device.

## Self-updating application still blocked

Managed Installer tagging is heuristic. Confirm the process writing the updated files is the binary defined as Managed Installer and that it was restarted after the policy became active. Some application and driver update paths still require explicit App Control rules.
