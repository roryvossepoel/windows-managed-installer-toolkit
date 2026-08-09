# Managed Installer library

This is a copy-and-paste library for the twenty custom ADMX slots. It is documentation only: the ADMX and PowerShell scripts do not download or consume this file.

> Verify every value against a currently deployed, correctly signed binary before production use. Vendor channels, architectures, product names, certificates, and versions can differ. A minimum version of `0.0.0.0` trusts every signed version matching the other fields and should be a conscious choice.

## Microsoft Intune Management Extension

| ADMX field | Value |
|---|---|
| Name | `Intune Management Extension` |
| Publisher | `O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US` |
| Product name | `MICROSOFT® INTUNE™` |
| Executable | `MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE` |
| Minimum version | `1.38.300.1` |

## OMA Device Management Client

| ADMX field | Value |
|---|---|
| Name | `OMA Device Management Client` |
| Publisher | `O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US` |
| Product name | `MICROSOFT® WINDOWS® OPERATING SYSTEM` |
| Executable | `OMADMCLIENT.EXE` |
| Minimum version | `10.0.22621.1485` |

## Microsoft Endpoint Privilege Management

| ADMX field | Value |
|---|---|
| Name | `Endpoint Privilege Management` |
| Publisher | `O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US` |
| Product name | `MICROSOFT® INTUNE™` |
| Executable | `EPMSERVICESTUB.EXE` |
| Minimum version | `6.2411.82.2000` |

## Windows Autopatch agent

| ADMX field | Value |
|---|---|
| Name | `Windows Autopatch agent` |
| Publisher | `O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US` |
| Product name | `MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT` |
| Executable | `MICROSOFT.MANAGEMENT.SERVICES.CLOUDMANAGEDDESKTOP.AGENT.EXE` |
| Minimum version | `1.2.2291.137` |

## Adobe Installer

| ADMX field | Value |
|---|---|
| Name | `Adobe Installer` |
| Publisher | `O=ADOBE INC., L=SAN JOSE, S=CA, C=US` |
| Product name | `ADOBE INSTALLER` |
| Executable | `ADOBE INSTALLER.EXE` |
| Minimum version | `5.11.0.522` |

## Adobe Install Helper

| ADMX field | Value |
|---|---|
| Name | `Adobe Install Helper` |
| Publisher | `O=ADOBE INC., L=SAN JOSE, S=CA, C=US` |
| Product name | `ADOBE INSTALL HELPER` |
| Executable | `ADOBE INSTALL HELPER.EXE` |
| Minimum version | `5.11.0.522` |

## Adobe Update Service

| ADMX field | Value |
|---|---|
| Name | `Adobe Update Service` |
| Publisher | `O=ADOBE INC., L=SAN JOSE, S=CA, C=US` |
| Product name | `ADOBE UPDATE SERVICE` |
| Executable | `ADOBE UPDATE SERVICE.EXE` |
| Minimum version | `5.11.0.522` |

## Adobe Acrobat Update Service

| ADMX field | Value |
|---|---|
| Name | `Adobe Acrobat Update Service` |
| Publisher | `O=ADOBE INC., L=SAN JOSE, S=CA, C=US` |
| Product name | `ACROBAT UPDATE SERVICE` |
| Executable | `ARMSVC.EXE` |
| Minimum version | `1.824.460.1149` |

## Adobe Reader and Acrobat Manager

| ADMX field | Value |
|---|---|
| Name | `Adobe Reader and Acrobat Manager` |
| Publisher | `O=ADOBE INC., L=SAN JOSE, S=CA, C=US` |
| Product name | `ADOBE READER AND ACROBAT MANAGER` |
| Executable | `ADOBEARM.EXE` |
| Minimum version | `1.824.460.1149` |

## Google Updater (x86 example)

| ADMX field | Value |
|---|---|
| Name | `Google Updater (x86)` |
| Publisher | `O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US` |
| Product name | `GOOGLE UPDATER (X86)` |
| Executable | `GOOGLEUPDATE.EXE` |
| Minimum version | `143.0.7482.0` |

## Contributing an entry

Open a pull request with the five fields, the file version, architecture/channel, the command used to inspect the signature, and sanitized evidence. Never submit the binary itself. See [Retrieving publisher information](../docs/retrieving-publisher-information.md).
