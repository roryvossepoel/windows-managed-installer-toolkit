# Frequently asked questions

## Why are there no presets in the ADMX?

Vendor metadata and minimum versions change more often than policy structure. Keeping examples in a GitHub library avoids ADMX reimports and script releases whenever an entry changes. It also prevents a library update from silently changing a tenant's trust boundary.

## Does the toolkit automatically consume the GitHub library?

No. Copy the five values you want into a custom ADMX slot. Endpoints have no runtime dependency on GitHub and keep the values assigned through policy until you change them.

## Why are there twenty slots?

Classic ADMX presentation elements cannot dynamically add repeated structured records. Twenty fixed, clearly labeled slots provide native fields and predictable registry locations without asking administrators to paste JSON into Group Policy or Intune.

Twenty is a practical default, not a platform limit. If an environment needs more, add matching `Custom21` (and later) policy definitions to the ADMX, add their display strings to every ADML language file, and increase `$customSlotCount` in both PowerShell scripts. Keep the two-digit registry layout (`Custom\21`) and never renumber existing slots, because the slot number determines rule identity. Validate the XML and both scripts after the change.

For a broadly shared repository, keeping twenty slots avoids an unwieldy Administrative Templates interface. Environments regularly needing many more Managed Installers should first review whether every process truly needs this trust boundary; a separate generated configuration or policy-management solution may then be more maintainable than hundreds of ADMX fields.

## What happens when I change a slot?

Each slot has a stable rule ID derived from its slot number. Remediation removes the old toolkit-owned form and writes the desired form, so field changes do not create duplicates.

## What do Enabled, Disabled, and Not configured mean?

- **Enabled:** reconcile all enabled custom slots.
- **Disabled:** remove only rules owned by this toolkit.
- **Not configured:** take no action and leave existing policy untouched.

## Why must every custom field be filled in?

Publisher rules are safest when constrained by publisher, product, executable, and minimum version. The name is used for readable logs and policy descriptions.

## Can I use `msiexec.exe`, PowerShell, CMD, or Winget as a Managed Installer?

The scripts reject `msiexec.exe`, PowerShell, CMD, and several other generic launchers and interpreters by default. Winget is permitted by input validation, but this is not a blanket recommendation to trust it. Review its sources, arguments, execution context, writable locations, and the software it can install. The default list is stored in `$blockedBinaries` near the top of both scripts and can be extended; keep both copies identical.

## Can I use wildcards or paths?

No. This toolkit intentionally rejects them. It creates narrow `FilePublisherRule` entries, not path rules.

## Can I deploy the ADMX with Group Policy?

Yes, the ADMX writes machine policy values. The detection/remediation scripts are still required to translate those values into the local AppLocker Managed Installer policy. If you do not use Intune Remediations, deploy and schedule the scripts with another SYSTEM-level management mechanism.

## Why is App Control option 13 required?

Managed Installer tracking must be enabled in the deployed App Control policy. This toolkit manages the AppLocker Managed Installer collection; it does not replace the App Control policy that consumes Managed Installer origin.

## Does a library entry stay current automatically?

No. Treat each entry as a starting point and verify it against your deployed binary. If a vendor changes signing or version metadata, update your selected custom slot. The ADMX itself normally does not need to change.

## How do I find the exact publisher values?

Follow [Retrieving publisher information](retrieving-publisher-information.md). Inspect the exact signed executable used in your deployment channel and architecture.

## Why can self-updates be difficult?

An updater may replace itself with a binary whose product name, executable name, certificate, or version no longer matches the rule. Test the full update chain and choose a minimum version that permits the versions you intend to run.

## Does this trust drivers installed by a Managed Installer?

No. Managed Installer origin does not override Windows kernel-mode code-signing requirements or other platform security controls.
