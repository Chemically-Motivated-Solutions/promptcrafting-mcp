# Security Policy

## Supported Versions

We provide security updates for the latest supported release line and for the `main` branch.

| Version | Supported |
| ------- | --------- |
| main    | ✅        |
| latest  | ✅        |
| older releases | ❌ |

If you are running an older release, upgrade to the latest supported version before requesting support.

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Instead, report vulnerabilities privately to:

- Email: security@example.com
- Or: Report a vulnerability privately via [GitHub Security Advisories](https://github.com/OWNER/REPO/security/advisories/new).

When submitting a report, include as much of the following as possible:

- A clear description of the issue
- Steps to reproduce
- A proof of concept, if available
- Affected versions, branches, or components
- Any relevant logs, screenshots, or payloads
- Your assessment of impact

## What to Expect

After you submit a report:

- We will acknowledge receipt within **3 business days**.
- We will provide an initial triage update within **7 business days**.
- We may contact you for additional details or validation
- We will let you know whether the report is accepted, needs more information, or is out of scope

If the report is accepted, we will work on remediation and coordinate disclosure as appropriate.

If the report is declined, we will explain why when possible. Common reasons include:

- The behavior is working as intended
- The issue is already known or previously reported
- The issue is not reproducible
- The issue does not present a security impact in the supported threat model

## Disclosure Policy

Please allow us reasonable time to investigate and remediate the issue before any public disclosure.

We ask that you:

- Avoid public disclosure until a fix or mitigation is available
- Avoid accessing, modifying, or destroying data that does not belong to you
- Test only against systems and assets you are explicitly authorized to assess

## Scope

This policy applies to security vulnerabilities in this repository and supported releases.

The following are generally **out of scope** unless they demonstrate a clear, material security impact:

- Best-practice recommendations without a concrete vulnerability
- Issues affecting unsupported versions
- Missing security headers without exploitability
- Rate-limit or spam observations without demonstrated abuse impact
- Self-XSS or low-impact social engineering scenarios
- Vulnerabilities in third-party services or dependencies that are not exploitable through this project

## Safe Harbor

We support good-faith security research conducted responsibly and in compliance with this policy. We will not take action against researchers who:

- Avoid privacy violations, data destruction, and service disruption
- Act only against authorized targets
- Report findings promptly and privately
- Stop testing and notify us if sensitive data is exposed
