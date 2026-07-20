# Security Policy

## Supported versions

Security fixes are applied to the latest release and the current `main` branch.

## Reporting a vulnerability

Please do not publish a vulnerability, customer identifier, device dump, service credential, or
proof-of-concept destructive command in a public issue.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected version or commit
- the transport, profile, or evidence path involved
- reproduction steps using synthetic data where possible
- the expected read-only behavior
- the observed security impact

## High-priority reports

Reports receive priority when they involve:

- a path that can execute a device write from the X-Ray repository
- command injection through helper configuration or device-provided fields
- evidence-bundle tampering or signature validation weaknesses
- leakage of IMEI, ECID, UDID, serial, token, or customer information
- unsafe grouping of observations from different physical devices
- profile matching that can silently select the wrong device family

TTG Device X-Ray intentionally does not contain partition writers, firmware flashers, lock-removal
logic, activation bypasses, programmer uploads, FDL uploads, or Odin/PIT write operations.
