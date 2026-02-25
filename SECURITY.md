# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

Use one of two channels:

1. **GitHub private vulnerability reporting** — [Report a vulnerability](https://github.com/Nexora-NHI/nexora-cli/security/advisories/new) (preferred — keeps disclosure coordinated)
2. **Email** — security@nexora.inc

Do **not** open a public GitHub issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a remediation timeline within 5 business days.

## Security Model

See [docs/security-model.md](docs/security-model.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Scope

nexora-cli is a **read-only, local scanner**. It:
- Makes no network calls during file-based scans
- Stores no data
- Transmits no telemetry
- Calls no Nexora internal APIs

The only network-capable command is `nexora scan github`, which calls the GitHub API only when explicitly invoked with a token.

## AI Coding Assistant Safety

This repository contains **no AI instruction files** (`.cursorrules`, `.github/copilot-instructions.md`, `CLAUDE.md`, etc.) and **no hidden Unicode characters**.

All code is human-readable and auditable. Cloning this repo will not inject instructions into your AI coding assistant.
