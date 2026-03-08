# Generating the Demo

The `demo.gif` is generated using [VHS](https://github.com/charmbracelet/vhs) from the `demo.tape` script.

## Prerequisites

Install VHS:

```bash
# macOS
brew install vhs

# Linux
go install github.com/charmbracelet/vhs@latest

# Or download from releases
# https://github.com/charmbracelet/vhs/releases
```

## Generate Demo

```bash
# Make demo scripts executable (Linux/macOS)
chmod +x scripts/demo-audit.sh scripts/demo-map.sh

# Generate the gif
vhs demo.tape

# This creates demo.gif showing:
# 1. Static scan (nexora scan workflows)
# 2. Credential lifecycle audit (unique capability)
# 3. Identity relationship mapping (unique capability)
```

## Demo Scripts

The demo uses helper scripts to show realistic output without requiring API access:

- `scripts/demo-audit.sh` - Shows credential lifecycle audit output
- `scripts/demo-map.sh` - Shows blast radius analysis output

These scripts output realistic examples of what the `audit` and `map` commands produce when run against a real GitHub organization.

## Updating the Demo

To update the demo content:

1. Edit `demo.tape` to change timing, commands, or layout
2. Edit `scripts/demo-audit.sh` or `scripts/demo-map.sh` to update output examples
3. Run `vhs demo.tape` to regenerate
4. Commit the updated `demo.gif`

## Current Status

Demo scripts are ready. To generate the gif, install VHS and run `vhs demo.tape`.
