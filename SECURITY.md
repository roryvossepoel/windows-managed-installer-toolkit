# Security policy

## Reporting a vulnerability

Please don't open a public issue for a vulnerability that could broaden Managed Installer trust or remove unrelated AppLocker rules. Use GitHub's private vulnerability reporting feature when available.

Include the affected version, configuration, reproduction steps, and expected security impact. Don't include production credentials, secrets, tenant identifiers, or personal data.

## Security boundaries

Managed Installer is a heuristic trust mechanism. A process designated as a Managed Installer can cause files it writes to be trusted by an App Control policy that enables Managed Installer trust. Review every custom publisher rule as a security boundary change.
