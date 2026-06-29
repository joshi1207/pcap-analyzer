# Security Policy

## Supported versions

PCAP Analyzer is currently a pre-release project. Security fixes are applied to the latest version available on the `main` branch.

## Reporting a vulnerability

Please do not disclose security vulnerabilities through public GitHub issues.

Use GitHub's private vulnerability reporting feature for this repository when available.

When reporting a vulnerability, include:

- A description of the issue
- Steps to reproduce it
- The affected component or endpoint
- Potential impact
- Any suggested remediation
- Relevant logs or screenshots with sensitive information removed

Please do not include real customer packet captures, credentials, access tokens, internal hostnames, or confidential network information.

## Packet-capture privacy

PCAP and PCAPNG files may contain sensitive data, including:

- Internal IP addresses
- DNS queries and hostnames
- Session metadata
- Authentication information
- Unencrypted application payloads

Only analyze captures in an approved environment. Remove or anonymize sensitive data before sharing captures in vulnerability reports.

## Response process

Security reports will be reviewed and assessed based on severity, reproducibility, and impact. Confirmed vulnerabilities will be addressed in the active development branch and documented when appropriate.
