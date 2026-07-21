# Security policy

## Supported versions

Only the latest published `chr-install` release receives security fixes. The shell implementation preserved under `legacy-shell-final` is historical and unsupported.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/parhamfa/chr-install/security/advisories/new). Do not open a public issue for a vulnerability that could write the wrong disk, generate an unsafe RouterOS network plan, bypass a destructive confirmation, or compromise the release/bootstrap chain.

Include the affected version, Linux distribution, firmware mode, installation method, a minimal reproduction, and the expected impact. Redact credentials, public IP addresses, MAC addresses, disk serials, WWNs, and provider identifiers unless they are essential to the report.

You should receive an initial acknowledgement within seven days. No bounty or fixed remediation timeline is promised.
