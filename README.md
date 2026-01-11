# AI Compliance Scanner

Detects Anthropic ToS violations related to OAuth token abuse in repositories.

## Installation

```bash
poetry install
```

## Usage

```bash
ai-compliance-scan <path>
ai-compliance-scan ./my-repo --output json
ai-compliance-scan ./my-repo --severity active
```

## What it detects

- OAuth token abuse (using OAuth tokens as API keys)
- Header spoofing (impersonating Claude Code)
- Token extraction (reading from ~/.claude/ configs)
- OAuth subscription routing
