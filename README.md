# PolicyVibes

Claude Agent SDK-based ToS violation detection agent.

## Installation

```bash
poetry install
```

## Usage

```bash
# LLM-powered scan (requires Claude Agent SDK)
policyvibes scan <path>

# Fast regex-only scan
policyvibes scan-regex <path>
policyvibes scan-regex ./my-repo --output json
policyvibes scan-regex ./my-repo --severity active

# List available detection skills
policyvibes list-skills
```

## What it detects

- OAuth token abuse (using OAuth tokens as API keys)
- Header spoofing (impersonating Claude Code)
- Token extraction (reading from ~/.claude/ configs)
- OAuth subscription routing

## Skills

PolicyVibes uses specialized detection skills in `.claude/skills/compliance/`:

- **oauth-token-abuse** - Detect OAuth tokens used as API keys
- **header-spoofing** - Detect X-Client-Name and User-Agent spoofing
- **credential-extraction** - Detect reading from Claude CLI credential files
- **subscription-routing** - Detect OAuth subscription routing through proxies

## SecureVibes Integration

PolicyVibes can be used as a subagent in SecureVibes:

```python
from policyvibes import create_policyvibes_agent_definition

# Add to your ClaudeAgentOptions
agents = create_policyvibes_agent_definition()
```
