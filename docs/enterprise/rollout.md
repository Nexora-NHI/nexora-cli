# Enterprise Rollout Guide

## Overview

This guide covers how to deploy nexora-cli across an engineering org, integrate findings into existing security tooling, and manage exceptions at scale.

---

## 1. Installation at Scale

### GitHub Actions (recommended)

Add to every repo via an org-level required workflow or reusable workflow call:

```yaml
name: NHI Scan
on:
  pull_request:
  push:
    branches: [main]
permissions: {}
jobs:
  nhi-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Nexora-NHI/nexora-cli@v0.1.0
        with:
          scan-type: workflows
          path: ./.github/workflows/
          format: sarif
          output: nexora.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nexora.sarif
```

### Docker (air-gapped environments)

```bash
docker pull ghcr.io/nexora-nhi/nexora-cli:v0.1.0
docker run --rm -v /path/to/repo:/scan ghcr.io/nexora-nhi/nexora-cli:v0.1.0 \
  scan workflows --path /scan/.github/workflows/ --format sarif
```

### Binary (Linux/macOS)

```bash
bash -c "$(curl -sSfL https://raw.githubusercontent.com/Nexora-NHI/nexora-cli/main/scripts/install.sh)"
nexora version
```

Verify before deploying to production:

```bash
./scripts/verify-release.sh v0.1.0 nexora-cli_v0.1.0_linux_amd64.tar.gz
```

---

## 2. Severity Thresholds

Recommended gate configuration by environment:

| Environment | Block on | Warn on |
|-------------|----------|---------|
| Production CI | CRITICAL, HIGH | MEDIUM |
| Staging CI | CRITICAL | HIGH, MEDIUM |
| Local dev | None | All |

---

## 3. SARIF Integration with GitHub Code Scanning

nexora-cli outputs SARIF 2.1.0. Findings appear in the Security tab of every repo with:
- Finding title and severity
- File and line number
- Remediation steps
- NHI context (why this is a machine identity risk)

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nexora.sarif
    category: nhi-scan
```

---

## 4. Evidence Bundles for Compliance

For SOC 2, ISO 27001, or internal audit requirements:

```bash
nexora scan workflows --path .github/workflows/ --format json --output findings.json
nexora report --input findings.json --bundle ./evidence/
nexora verify bundle ./evidence/
```

The bundle includes per-file SHA-256 hashes, scan metadata (timestamp, version, rule set), and all findings in structured JSON. The hash chain is deterministic and verifiable offline.

---

## 5. Exception Handling

To suppress a known false positive, add an inline annotation above the flagged line:

```yaml
# nexora:ignore NXR-GH-001 -- approved exception: release workflow requires write for publishing
permissions: write-all
```

Exceptions are captured in the evidence bundle with the suppression comment as the reason.

---

## 6. SIEM Integration

### Splunk / Elastic / Chronicle (OCSF JSONL)

```bash
nexora scan workflows --path .github/workflows/ --format ocsf | \
  curl -X POST https://your-siem/ingest \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @-
```

### AWS Security Lake

Security Lake custom sources require Parquet format. See [docs/integrations/security-lake.md](../integrations/security-lake.md) for the conversion pipeline.

---

## 7. Cross-Repo Scanning (GitHub Org)

Scan all repos in an org via the GitHub API:

```bash
export GITHUB_TOKEN=ghp_...
nexora scan github --org your-org --format json --output org-findings.json
```

- Token needs `repo` scope for private repos, `public_repo` for public repos
- Token is never stored or logged
- Rate limiting is handled automatically

---

## 8. Trendlines and Reporting

nexora-cli outputs a `scan_id` per run. Use this to track finding counts over time:

```bash
nexora scan github --org your-org --format json \
  | jq '.[] | {rule_id, severity, file_path, scan_id}' \
  >> findings-archive.jsonl
```

Pipe the JSONL archive to your data warehouse, Splunk, or Elastic to build dashboards for:
- Finding counts per repo over time
- Remediation velocity per team
- CRITICAL/HIGH open findings by owner
