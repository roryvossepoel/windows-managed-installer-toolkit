# Preset catalog

Preset details are maintained in `Get-PresetDefinitions` in both PowerShell scripts. The ADMX contains only enablement and optional override fields.

| Preset | Binary | Product | Default minimum |
|---|---|---|---:|
| Intune Management Extension | `MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE` | `MICROSOFT® INTUNE™` | `1.38.300.1` |
| OMA Device Management Client | `OMADMCLIENT.EXE` | `MICROSOFT® WINDOWS® OPERATING SYSTEM` | `10.0.22621.1485` |
| Endpoint Privilege Management | `EPMSERVICESTUB.EXE` | `MICROSOFT® INTUNE™` | `6.2411.82.2000` |
| Windows Autopatch | `MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT.EXE` | `MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT` | `1.2.2291.137` |
| Adobe Installer | `ADOBE INSTALLER.EXE` | `ADOBE INSTALLER` | `5.11.0.522` |
| Adobe Install Helper | `ADOBE INSTALL HELPER.EXE` | `ADOBE INSTALL HELPER` | `5.11.0.522` |
| Adobe Update Service | `ADOBE UPDATE SERVICE.EXE` | `ADOBE UPDATE SERVICE` | `5.11.0.522` |
| Google Updater | `GOOGLEUPDATE.EXE` | `GOOGLE UPDATER (X86)` | `143.0.7482.0` |
| Acrobat Update Service | `ARMSVC.EXE` | `ACROBAT UPDATE SERVICE` | `1.824.460.1149` |
| Adobe Reader and Acrobat Manager | `ADOBEARM.EXE` | `ADOBE READER AND ACROBAT MANAGER` | `1.824.460.1149` |

## Microsoft publisher

```text
O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US
```

## Adobe publisher

```text
O=ADOBE INC., L=SAN JOSE, S=CA, C=US
```

## Google publisher

```text
O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US
```

## Maintenance policy

Before changing a preset:

1. collect metadata from a current production-signed binary;
2. verify the vendor hasn't changed product or binary naming across channels;
3. update both scripts;
4. update this catalog and the changelog;
5. test upgrades from the previous rule;
6. retain the existing rule GUID.

The initial preset list was derived from a working environment and hasn't yet been independently validated across every vendor channel and architecture. Treat version `0.1.x` as preview.
