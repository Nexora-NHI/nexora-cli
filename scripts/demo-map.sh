#!/bin/bash

cat << 'EOF'
Building identity relationship graph...
This analyzes workflows, secrets, apps, and their connections.

✅ Graph built: 18 nodes, 24 edges

Identity Graph: 18 nodes, 24 edges

By Type:
  github_workflow           4
  github_secret             6
  github_app                2
  deploy_key                3
  aws_iam_role              2
  aws_resource              1

By Risk:
  critical   2
  high       5
  medium     7
  low        4

🎯 BLAST RADIUS ANALYSIS: ci-workflow
══════════════════════════════════════════════════════════

Risk Score: 7.2/10
Reachable Nodes: 8
Max Depth: 4 hops
Critical/High Resources Reachable: 2

Shortest Path to Critical Resource:
└─ ci-workflow (github_workflow)
  └─ AWS_SECRET_KEY (github_secret) ⚠️ HIGH
    └─ arn:aws:iam::123:role/deploy (aws_iam_role)
      └─ prod-database-bucket (aws_resource) ⚠️ CRITICAL

Reachable Resources by Risk:

  [CRITICAL] (1)
    • prod-database-bucket (depth: 4)

  [HIGH] (2)
    • AWS_SECRET_KEY (depth: 1)
    • deploy-role (depth: 2)

  [MEDIUM] (3)
    • staging-bucket (depth: 3)
    • ci-service-account (depth: 2)
    • docker-registry-token (depth: 1)
EOF
