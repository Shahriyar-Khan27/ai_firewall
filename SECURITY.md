# Security policy

Thanks for taking the time to disclose vulnerabilities responsibly.

## Supported versions

Only the latest minor release line receives security fixes. Older lines are best-effort.

| Version | Status |
|---|---|
| 0.5.x | Active. Security fixes published as patch releases. |
| 0.4.x | Best-effort. Critical fixes may be backported on request. |
| Anything older than 0.4 | Unsupported. Please upgrade. |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

File a private report via GitHub Security advisories:

- <https://github.com/Shahriyar-Khan27/ai_firewall/security/advisories/new>

That channel is encrypted, visible only to the maintainer, and lets us coordinate a fix and a CVE before public disclosure.

If you cannot use GitHub advisories, email the maintainer through the contact details on the GitHub profile at <https://github.com/Shahriyar-Khan27>.

## What is in scope

The following classes of issue are treated as security vulnerabilities:

- A way for an AI agent to **bypass** the firewall and execute a BLOCK or REQUIRE_APPROVAL action without operator review.
- A way to **silently disable** the firewall via a malformed input, prompt injection, or side-channel.
- **Regex denial-of-service** in any scanner (secret scan, PII scan, URL analyser, SQL parser, shell parser).
- **False negatives in detection** for in-the-wild attack patterns (typosquats, SSRF endpoints, leaked credentials in headers or bodies, malicious obfuscation).
- **Privilege escalation** through the RBAC layer (`guard.toml`).
- **Audit log tampering** that defeats HMAC verification.
- **Supply chain** issues affecting the published PyPI package, the standalone PyInstaller binaries, or the VS Code extension `.vsix`.

## What is out of scope

- Theoretical attacks that require an already-compromised host.
- Bugs in third-party dependencies (please report upstream; the firewall will pick up the fix on the next pin bump).
- Cosmetic or non-exploitable findings in the example documentation.

## Response expectations

This is a single-maintainer open-source project. Best-effort response targets:

- **Initial acknowledgement**: within 72 hours of the report landing in Security advisories.
- **Triage and severity assessment**: within 7 days.
- **Patch release for confirmed CRITICAL or HIGH issues**: within 30 days, ideally sooner. Coordinated disclosure window is negotiated case-by-case.

If a report has been open for two weeks with no acknowledgement, please follow up via the GitHub profile contact path. Notifications occasionally land in spam.

## Hall of fame

Reporters of confirmed vulnerabilities are listed (with permission) in the project CHANGELOG once the fix is public.
