# Custom Managed Installer rules

The ADMX exposes twenty custom slots. Each enabled slot creates one publisher rule and requires five fields.

| Field | Example |
|---|---|
| Name | Contoso Software Agent |
| Publisher | `O=CONTOSO B.V., L=HEERLEN, C=NL` |
| Product name | `CONTOSO SOFTWARE AGENT` |
| Executable | `CONTOSOAGENT.EXE` |
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
- generic and high-risk executables including `msiexec.exe`, PowerShell, Winget, `cmd.exe`, `explorer.exe`, `rundll32.exe`, `regsvr32.exe`, script hosts, and `installutil.exe`.

This validation is a safety baseline, not a substitute for reviewing what the process can install and how an attacker might influence it.

## Minimum version guidance

- Use the oldest version that has the expected signature and security posture.
- Increase the minimum when older versions are vulnerable or behave differently.
- Use `0.0.0.0` only after an explicit decision to trust all signed versions.
- The maximum is always `*` so future signed versions remain eligible.

## Example

```text
Name: Contoso Software Agent
Publisher: O=CONTOSO B.V., L=HEERLEN, C=NL
Product name: CONTOSO SOFTWARE AGENT
Executable: CONTOSOAGENT.EXE
Minimum version: 1.0.0.0
```

The resulting condition is conceptually:

```xml
<FilePublisherCondition
  PublisherName="O=CONTOSO B.V., L=HEERLEN, C=NL"
  ProductName="CONTOSO SOFTWARE AGENT"
  BinaryName="CONTOSOAGENT.EXE">
  <BinaryVersionRange LowSection="1.0.0.0" HighSection="*" />
</FilePublisherCondition>
```
