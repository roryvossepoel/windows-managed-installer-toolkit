# Retrieve publisher information

Publisher rules must match the signed executable that actually performs installation or updating. Don't infer values from a product name, file properties dialog, service display name, or vendor website.

## Locate the executable

Use service and process information to locate the real binary:

```powershell
Get-CimInstance Win32_Service |
    Where-Object Name -Match 'update|installer|agent' |
    Select-Object Name, DisplayName, State, PathName
```

Resolve environment variables and command-line arguments before collecting metadata.

## Collect AppLocker publisher metadata

Run in Windows PowerShell as administrator:

```powershell
$Path = 'C:\Program Files\Vendor\Updater\VendorUpdater.exe'

$FileInformation = Get-AppLockerFileInformation -Path $Path
$FileInformation.Publisher | Format-List *
```

Useful properties include:

- `PublisherName`
- `ProductName`
- `BinaryName`
- `BinaryVersion`

Generate an AppLocker publisher rule for additional inspection:

```powershell
Get-AppLockerFileInformation -Path $Path |
    New-AppLockerPolicy -RuleType Publisher -User Everyone -Xml |
    Set-Content -Path '.\PublisherRule.xml' -Encoding UTF8
```

Open `PublisherRule.xml` and inspect `FilePublisherCondition` and `BinaryVersionRange`.

## Verify the Authenticode signature

```powershell
Get-AuthenticodeSignature -FilePath $Path |
    Select-Object Status, StatusMessage, SignerCertificate
```

Only use a valid publisher signature. A publisher rule isn't appropriate for an unsigned or inconsistently signed installer.

## Determine a minimum version

```powershell
(Get-Item -LiteralPath $Path).VersionInfo |
    Select-Object FileVersion, ProductVersion
```

AppLocker requires a four-part version in this toolkit. Normalize vendor display versions only after checking the `BinaryVersion` reported by `Get-AppLockerFileInformation`.

## Security review questions

Before designating the binary as a Managed Installer, ask:

- Can a standard user influence its command line, source URL, manifest, or package path?
- Can it install arbitrary packages or execute arbitrary commands?
- Is the executable or its containing directory user-writable?
- Does the signature cover every version you intend to trust?
- Does it install kernel drivers that still require explicit App Control authorization?
- Would an explicit signer rule be safer and sufficient?

Never designate generic installation engines or interpreters such as `msiexec.exe`, PowerShell, Winget, `cmd.exe`, script hosts, `rundll32.exe`, or `regsvr32.exe`.
