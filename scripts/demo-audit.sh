#!/bin/bash

cat << 'EOF'
Auditing credentials in demo-org...
Thresholds: max age 90 days, max dormant 30 days

═══════════════════════════════════════════════════════════
CREDENTIAL AUDIT: demo-org
═══════════════════════════════════════════════════════════

Total Credentials: 23

By Risk Level:
  🔴 CRITICAL: 2
  🟠 HIGH:     5
  🟡 MEDIUM:   8
  🟢 LOW:      8

Issues Detected:
  ⏰ Stale (>90 days old):        7
  💤 Dormant (unused >30 days):   5
  🔄 Never rotated:               12

═══════════════════════════════════════════════════════════
CREDENTIALS REQUIRING IMMEDIATE ATTENTION
═══════════════════════════════════════════════════════════

🔴 deploy-key-production [CRITICAL]
   Type: deploy_key | Age: 847 days
   Scope: contents:write
   Issues:
     • Very old: 847 days (max recommended: 90)
     • Never rotated since creation

🔴 AWS_SECRET_ACCESS_KEY [CRITICAL]
   Type: org_secret | Age: 412 days
   Scope: all
   Issues:
     • Very old: 412 days
     • High-value credential type detected from name
     • Never rotated since creation

🟠 ci-bot-token [HIGH]
   Type: github_app | Age: 156 days
   Scope: contents:write, actions:write
   Issues:
     • Stale: 156 days old (max recommended: 90)
     • Never rotated since creation
EOF
