# Security

Please report security issues privately to **ccheigg@gmail.com**. Include the affected version, Android version and ABI, reproduction steps, and the expected and observed behavior. Prefer a minimal synthetic capture or a description of the packet layout. Do not include API keys, signing keys, passwords, or private traffic in an initial report.

If GitHub private vulnerability reporting is enabled, you may also use the repository's Security → Report a vulnerability page. Please avoid public issues for undisclosed vulnerabilities.

The maintainer reviews reports on a best-effort basis; no response-time guarantee is offered. Security fixes target the latest release. Older versions do not have a separate maintenance schedule.

Captures and protocol dissectors process untrusted input. Keep the application current, and use only authorized captures. Remote AI features can transmit analysis data according to the selected provider and privacy mode. Review those settings before use.

The current native dependency is Wireshark 4.0.10 (r1), without security backports. Upstream support for 4.0 ended on August 28, 2024. The [maintenance assessment](docs/wireshark-security-maintenance.md) and [advisory inventory](docs/wireshark-security-advisories.md) record known unfixed issues and unresolved applicability checks as of October 6, 2026. The packaging decision was updated on October 7, 2026: retain this baseline for the current APK, with upgrades and security backports tracked as follow-up maintenance rather than packaging prerequisites. Final Release, signing, license and device validation remain required. This decision does not change the recorded vulnerability status.
