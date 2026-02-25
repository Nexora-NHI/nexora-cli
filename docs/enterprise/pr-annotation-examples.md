# PR Annotation Examples

When nexora-cli findings are uploaded as SARIF, GitHub Code Scanning posts them as PR annotations. This page shows what engineers see for each rule.

---

## NXR-GH-001 — Workflow-level write permissions

**Annotation location:** The line with `permissions: write-all` or `permissions: write`

**What engineers see in the PR:**

```
[HIGH] NXR-GH-001: Workflow has broad write permissions without job-level scoping
File: .github/workflows/ci.yml, Line 5

NHI context: A compromised third-party action in any job inherits these permissions.
Combined with a supply chain attack, this grants push access to main.

Fix: Remove workflow-level permissions block. Set permissions per job to only what
that job needs (e.g., contents: read for test jobs, packages: write for publish jobs).
```

**Fix diff:**

```yaml
# Before
permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest

# After
permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
```

---

## NXR-GH-002 — Unpinned action

**Annotation location:** The `uses:` line with a mutable tag

**What engineers see in the PR:**

```
[MEDIUM] NXR-GH-002: Action pinned to mutable tag instead of commit SHA
File: .github/workflows/ci.yml, Line 18

NHI context: Mutable tags can be repointed to malicious commits.
When tj-actions/changed-files was compromised, all repos using @v1 ran attacker code.

Fix: Pin to the full commit SHA. GitHub UI shows the SHA when you click on a tag.
```

**Fix diff:**

```yaml
# Before
- uses: actions/checkout@v4

# After
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

---

## NXR-GH-004 — Hardcoded credential in workflow

**Annotation location:** The `env:`, `with:`, or `run:` line with the credential

**What engineers see in the PR:**

```
[CRITICAL] NXR-GH-004: Hardcoded credential in workflow
File: .github/workflows/deploy.yml, Line 34

NHI context: Hardcoded machine credentials persist in git history and CI logs.
Anyone with read access to the repo or log storage can extract them.

Fix: Move to GitHub Secrets. Reference via ${{ secrets.MY_SECRET }}.
```

**Fix diff:**

```yaml
# Before
env:
  API_TOKEN: sk-prod-abc123xyz

# After
env:
  API_TOKEN: ${{ secrets.API_TOKEN }}
```

---

## NXR-GH-003 — pull_request_target with PR head checkout

**Annotation location:** The `on: pull_request_target` trigger or the checkout step

**What engineers see in the PR:**

```
[CRITICAL] NXR-GH-003: pull_request_target with checkout of PR contributor code
File: .github/workflows/review.yml, Line 8

NHI context: pull_request_target runs with write permissions to the base branch.
Checking out PR contributor code and executing it means external code runs with
write access to main. This is the most dangerous GitHub Actions pattern.

Fix: Never checkout PR head code in a pull_request_target workflow.
If you need both, use two separate workflows: one for checkout (no write perms),
one for trusted operations (no PR code execution).
```

---

## Suppressing a finding (approved exception)

If a finding is a known false positive or has an approved exception:

```yaml
# nexora:ignore NXR-GH-001 -- approved by security team 2026-02-25, ticket SEC-4821
# Release workflow needs write to publish to GitHub Packages
permissions: write-all
```

The suppression comment is captured in the evidence bundle for audit trail.
