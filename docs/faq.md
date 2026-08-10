# Frequently asked questions

## Why was this toolkit created?

Managed Installer is powerful but often underused. Intune's built-in controls currently expose only the Intune Management Extension as a Managed Installer, leaving other legitimate installer and updater services without an equally manageable configuration path. This toolkit provides that path while keeping each trust decision narrow, explicit, and tenant-controlled.

The broader goal is to make a strong App Control for Business trust model more practical. App Control for Business is an effective barrier against unknown and malicious software; carefully selected Managed Installers can support that barrier without turning every legitimate software update into a separate policy-management task.

## Why are there no presets in the ADMX?

Vendor metadata and minimum versions change more often than policy structure. Keeping examples in a GitHub library avoids ADMX reimports and script releases whenever an entry changes. It also prevents a library update from silently changing a tenant's trust boundary.

## Does the toolkit automatically consume the GitHub library?

No. Copy the five values you want into one of the Managed Installer rule slots. Endpoints have no runtime dependency on GitHub and keep the values assigned through policy until you change them.

## Why are there twenty slots?

Classic ADMX presentation elements cannot dynamically add repeated structured records. Twenty fixed, clearly labeled slots provide native fields and predictable registry locations without asking administrators to paste JSON into Group Policy or Intune.

Twenty is a practical default, not a platform limit. If an environment needs more, add matching `Rule21` (and later) policy definitions to the ADMX, add their display strings to every ADML language file, and increase `$ruleSlotCount` in both PowerShell scripts. Keep the two-digit registry layout (`Rules\21`) and never renumber existing slots, because the slot number determines rule identity. Validate the XML and both scripts after the change.

For a broadly shared repository, keeping twenty slots avoids an unwieldy Administrative Templates interface. Environments regularly needing many more Managed Installers should first review whether every process truly needs this trust boundary; a separate generated configuration or policy-management solution may then be more maintainable than hundreds of ADMX fields.

## What happens when I change a slot?

Each slot has a stable rule ID derived from its slot number. Remediation removes the old toolkit-owned form and writes the desired form, so field changes do not create duplicates.

## How do I remove a Managed Installer rule?

Set the corresponding ADMX setting to **Not configured**. Detection identifies the toolkit-owned rule that no longer has a configured slot, and remediation removes it while preserving unrelated AppLocker rules.

Using **Disabled** also removes the rule, but keeps an explicit disabled setting in the assigned profile. It is useful when you want the profile to continue expressing that the slot must remain off. **Not configured** is sufficient for normal removal, including removal of the final configured Managed Installer rule.

Keep the Intune Remediation assigned until detection has reported compliance after the removal. If the ADMX profile and the Remediation assignment are both removed at the same time, no script remains to remove the local toolkit-owned AppLocker rules.

## Why must every field be filled in?

Publisher rules are safest when constrained by publisher, product, executable, and minimum version. The name is used for readable logs and policy descriptions.

## Can I use generic executables as a Managed Installer?

The scripts reject `msiexec.exe`, PowerShell, CMD, and several other generic launchers and interpreters by default. The default list is stored in `$blockedBinaries` near the top of both scripts and can be extended; keep both copies identical.

## Can I use wildcards or paths?

No. This toolkit intentionally rejects them. It creates narrow `FilePublisherRule` entries, not path rules.

## Can I deploy the ADMX with Group Policy?

Yes, the ADMX writes machine policy values. The detection/remediation scripts are still required to translate those values into the local AppLocker Managed Installer policy. If you do not use Intune Remediations, deploy and schedule the scripts with another SYSTEM-level management mechanism.

## Does the toolkit configure complete App Control for Business policies?

No. The toolkit manages the local AppLocker Managed Installer policy and its required runtime components for use with App Control for Business. It does not create, inspect, modify, convert, or deploy the App Control for Business policies themselves.

## Does a library entry stay current automatically?

No. Treat each entry as a starting point and verify it against your deployed binary. If a vendor changes signing or version metadata, update the selected rule slot. The ADMX itself normally does not need to change.

## How do I find the exact publisher values?

Follow [Retrieving publisher information](retrieving-publisher-information.md). Inspect the exact signed executable used in your deployment channel and architecture.

## How do I validate that a Managed Installer is working?

Validate the complete chain rather than only checking that the rule exists:

1. Confirm that detection reports the expected Managed Installer rule as compliant.
2. Confirm that the App Control for Business policy includes rule option 13, **Enabled: Managed Installer**.
3. After the Managed Installer policy and tracking services are active, use the designated installer or updater to install or update a test application. Files that existed before tracking was active aren't retroactively tagged.
4. Select an executable or DLL that was written by that installation and query its NTFS Extended Attributes from an elevated Command Prompt or PowerShell window:

```powershell
fsutil.exe file queryEA "C:\Program Files\Example Application\Application.exe"
```

Look for this EA name:

```text
$KERNEL.SMARTLOCKER.ORIGINCLAIM
```

In the first data row, every four byte values form a ULONG. For example:

```text
0000: 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
```

Interpret the relevant positions as follows:

- The first byte is normally `01`.
- Byte 5—the first byte of the second ULONG—must be `00` for Managed Installer origin. A value of `01` indicates Intelligent Security Graph origin instead.
- Byte 9—the first byte of the third ULONG—identifies how the file was created. `00` means it was written directly by a Managed Installer process and can be trusted when the App Control policy enables Managed Installer.
- A byte 9 value of `02` means **child of child**: the file was created later by software that had itself been installed by a Managed Installer. That file isn't allowed solely on the basis of Managed Installer origin and needs another applicable allow rule. Microsoft notes that rarer values can also represent MI-trusted files.

If `$KERNEL.SMARTLOCKER.ORIGINCLAIM` is absent, verify that the file was actually created during a new installation or update performed by the configured Managed Installer, that the file is on NTFS, and that the required AppLocker services and compiled policies are present. Copying a file or inspecting a file installed before MI tracking was enabled isn't a valid test.

The EA proves that Windows recorded origin information. To validate enforcement as well, test with an active App Control for Business policy that enables Managed Installer and review the Code Integrity operational events. The file must not be blocked by an explicit deny rule, because deny rules take precedence.

See Microsoft's [Managed installer and ISG technical reference and troubleshooting guide](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/configure-appcontrol-managed-installer) for the authoritative byte layout and troubleshooting steps.

## Why can self-updates be difficult?

An updater may replace itself with a binary whose product name, executable name, certificate, or version no longer matches the rule. Test the full update chain and choose a minimum version that permits the versions you intend to run.

## Does this trust drivers installed by a Managed Installer?

No. Managed Installer origin does not override Windows kernel-mode code-signing requirements or other platform security controls.
