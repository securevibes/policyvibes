# CLAUDE.md

## Project Overview

PolicyVibes is a Claude Agent SDK-based ToS violation detection agent. It identifies patterns like OAuth token misuse, header spoofing, and credential extraction in repositories.

## Quick Commands

```bash
# Install dependencies
poetry install

# Scan a repository (requires Claude Agent SDK)
poetry run policyvibes scan /path/to/repo

# Scan with different model
poetry run policyvibes scan /path/to/repo --model opus

# JSON output
poetry run policyvibes scan /path/to/repo --output json

# Filter by severity
poetry run policyvibes scan /path/to/repo --severity active

# List available skills
poetry run policyvibes list-skills

# Run tests
poetry run pytest -v

# Run tests with coverage
poetry run pytest --cov=policyvibes --cov-report=term-missing
```

## Project Structure

```
src/policyvibes/
├── __init__.py         # Package exports
├── agent.py            # AgentDefinition for SecureVibes integration
├── cli.py              # Click CLI interface
├── models.py           # Data models (Finding, ScanResult, Severity)
└── prompts/
    └── main.txt        # Agent orchestration prompt

.claude/skills/compliance/  # Detection skills (SKILL.md format)
├── oauth-token-abuse/
├── header-spoofing/
├── credential-extraction/
└── subscription-routing/

tests/
└── test_cli.py         # CLI tests
```

## Architecture

### Claude Agent SDK Integration

PolicyVibes is designed as a Claude Agent SDK agent that can be:
1. Used standalone via CLI (`policyvibes scan`)
2. Integrated as a subagent in SecureVibes

```python
from policyvibes import create_policyvibes_agent_definition

# Get AgentDefinition for use in ClaudeAgentOptions
agents = create_policyvibes_agent_definition()
```

### Skill-Based Pattern Detection

Detection patterns are packaged as skills in `.claude/skills/compliance/`:
- Each violation type has its own skill directory
- Skills follow the SKILL.md format with YAML frontmatter
- Skills define detection methodology, patterns, and remediation

### Adding a New Detection Skill

```bash
# 1. Create skill directory
mkdir -p .claude/skills/compliance/new-violation-type

# 2. Create SKILL.md with detection methodology
# 3. Create examples.md with real-world examples
# 4. Create reference/patterns.py with regex patterns
```

## What It Detects

| Pattern | Severity | Example |
|---------|----------|---------|
| `ANTHROPIC_AUTH_TOKEN` | Active | OAuth token as env var |
| `ANTHROPIC_OAUTH_TOKEN` | Active | OAuth token variable |
| `CLAUDE_CODE_OAUTH_TOKEN` | Active | Claude Code token reuse |
| Header spoofing | Active | `X-Client-Name: claude-code` |
| `.credentials.json` access | Active | Reading Claude CLI creds |
| `anthropic-oauth` provider | Active | OAuth provider config |
| Auth profile rotation | Active | Token rotation logic |
| Non-Anthropic base URL | Potential | Proxy/gateway routing |

## Development Guidelines

- **TDD**: Write tests first, then implement
- **Python 3.10+**: Use modern Python features
- **Poetry**: Manage dependencies with Poetry
- **Coverage**: Maintain >80% test coverage
- **Skills**: Detection patterns in `.claude/skills/compliance/`

## Git Safety

NEVER run git commit or git push without explicit human approval. Always show the changes first and wait for confirmation.

## CI Integration

```bash
# Exit code 0 = clean, 1 = violations found, 2 = error
poetry run policyvibes scan . && echo "Clean" || echo "Violations found"
```
