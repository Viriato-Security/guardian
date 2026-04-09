# Security Policy

## Reporting a Vulnerability

Viriato Security takes security seriously.  If you discover a vulnerability
in Guardian or any Viriato product, please report it **privately** before
public disclosure.

**Contact:** [security@viriatosecurity.com](mailto:security@viriatosecurity.com)

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- Any suggested mitigations you have identified

## Disclosure Policy

We follow a **90-day coordinated disclosure** policy:

1. You report the vulnerability to security@viriatosecurity.com.
2. We acknowledge receipt within **48 hours**.
3. We investigate and develop a fix within **90 days** of the report.
4. We publish a security advisory and release a patch.
5. You may publicly disclose after the patch is released or after 90 days,
   whichever comes first.

If a critical vulnerability requires faster action we will work with you
on an expedited timeline.

## Scope

In scope:
- Guardian agent (this repository)
- Cryptographic integrity of the event chain
- gRPC transport and authentication
- Local alert engine false negatives

Out of scope:
- Social engineering attacks
- Physical access attacks
- Attacks on viriato-platform infrastructure (report to security@viriatosecurity.com separately)

## Hall of Fame

We publicly credit security researchers who responsibly disclose vulnerabilities.
