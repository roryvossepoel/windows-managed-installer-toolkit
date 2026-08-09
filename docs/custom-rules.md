# Custom Managed Installer rules

The ADMX exposes twenty custom slots. Each enabled slot creates one publisher rule and requires five fields.

| Field | Example |
|---|---|
| Name | Example Software Agent |
| Publisher | `O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US` |
| Product name | `EXAMPLE SOFTWARE AGENT` |
| Executable | `EXAMPLEAGENT.EXE` |
| Minimum version | `1.0.0.0` |

Use metadata collected with `Get-AppLockerFileInformation`; see [Retrieve publisher information](retrieving-publisher-information.md).

## Slot identity

Custom slot IDs are deterministic and based on the slot number, not its current contents. Editing Custom Managed Installer 04 therefore updates slot 04 instead of leaving an orphaned rule. Disabling the slot removes its rule during the next remediation.

Don't use one slot for multiple executables. Each binary needs its own publisher condition and slot.

## Validation

The scripts reject:

- empty names, publisher names, or product names;
- publishers without an organization (`O=`);
- wildcards in publisher or product;
- paths or invalid characters in executable names;
- versions that don't contain four numeric parts;
- selected generic and high-risk executables.

The default blocked binary list is defined near the top of both PowerShell scripts as `$blockedBinaries`. It contains:

```text
MSIEXEC.EXE
POWERSHELL.EXE
PWSH.EXE
CMD.EXE
EXPLORER.EXE
RUNDLL32.EXE
REGSVR32.EXE
WSCRIPT.EXE
CSCRIPT.EXE
INSTALLUTIL.EXE
```

`WINGET.EXE` is not blocked by the toolkit. This only means that the configuration passes input validation; it is not a recommendation to trust Winget in every environment. Review its sources, arguments, execution context, writable locations, and the software it can install before designating it as a Managed Installer.

To extend the blocklist, add an uppercase executable name to `$blockedBinaries` in **both** detection and remediation. Keep the two lists identical so detection and remediation evaluate the same configuration. For example:

```powershell
$blockedBinaries = @(
    'MSIEXEC.EXE',
    'POWERSHELL.EXE',
    'MYGENERICLAUNCHER.EXE'
)
```

This validation is a safety baseline, not a substitute for reviewing what the process can install and how an attacker might influence it.

## Minimum version guidance

- Use the oldest version that has the expected signature and security posture.
- Increase the minimum when older versions are vulnerable or behave differently.
- Use `0.0.0.0` only after an explicit decision to trust all signed versions.
- The maximum is always `*` so future signed versions remain eligible.

## Example

```text
Name: Example Software Agent
Publisher: O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US
Product name: EXAMPLE SOFTWARE AGENT
Executable: EXAMPLEAGENT.EXE
Minimum version: 1.0.0.0
```

The resulting condition is conceptually:

```xml
<FilePublisherCondition
  PublisherName="O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US"
  ProductName="EXAMPLE SOFTWARE AGENT"
  BinaryName="EXAMPLEAGENT.EXE">
  <BinaryVersionRange LowSection="1.0.0.0" HighSection="*" />
</FilePublisherCondition>
```
