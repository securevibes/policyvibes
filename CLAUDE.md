# CLAUDE.md

## Project Overview

AI Compliance Scanner detects Anthropic ToS violations related to OAuth token abuse in repositories. It identifies patterns like OAuth token misuse, header spoofing, and credential extraction.

## Quick Commands

```bash
# Install dependencies
poetry install

# Run the scanner
poetry run ai-compliance-scan /path/to/repo

# Run tests
poetry run pytest -v

# Run tests with coverage
poetry run pytest --cov=ai_compliance_scanner --cov-report=term-missing

# JSON output
poetry run ai-compliance-scan /path/to/repo --output json
```

## Project Structure

```
src/ai_compliance_scanner/
├── cli.py              # Click CLI interface
├── detector.py         # Main scanner (loads skills dynamically)
├── models.py           # Data models (Finding, ScanResult, Severity)
└── skills/
    ├── __init__.py     # Skill loader
    ├── base.py         # BaseSkill abstract class
    └── anthropic/      # Anthropic provider skill
        ├── SKILL.yaml  # Skill metadata
        └── patterns.py # Detection patterns

tests/
├── test_cli.py         # CLI tests
├── test_detector.py    # Scanner tests
└── test_patterns.py    # Pattern detection tests
```

## Architecture Requirements

### Skill-Based Pattern Detection

All detection patterns MUST be packaged as skills:
- Each provider (Anthropic, OpenAI, Google) gets its own skill directory
- Skills are self-contained and independently testable
- New providers = new skill directories (no core code changes)
- Skills define their own patterns and remediation hints

### Adding a New Provider Skill

```bash
# 1. Create skill directory
mkdir -p src/ai_compliance_scanner/skills/openai

# 2. Create SKILL.yaml with metadata
# 3. Create patterns.py implementing BaseSkill
# 4. Add tests in tests/test_skills_openai.py
# 5. Skill is auto-discovered - no core code changes needed
```

### PRD Review Checklist

Before implementing from a PRD, always clarify:
1. **Feature requirements** - What to build
2. **Architectural requirements** - How to structure it (skills, plugins, etc.)
3. **Integration patterns** - How it connects to other systems

**Important**: "Out of scope integration" ≠ "Out of scope architecture"
- Even if SecureVibes integration is deferred, skill architecture should be used
- Internal structure should support future extensibility

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
- **Skills**: All detection patterns must be in skill modules

## Git Safety

NEVER run git commit or git push without explicit human approval. Always show the changes first and wait for confirmation.

## Adding New Patterns

1. Identify which skill the pattern belongs to (e.g., `skills/anthropic/`)
2. Add pattern to the skill's `patterns.py`
3. Add corresponding test in `tests/test_patterns.py`
4. Run `poetry run pytest -v` to verify
5. Update detection table above if adding new pattern types

## CI Integration

```bash
# Exit code 0 = clean, 1 = violations found, 2 = error
poetry run ai-compliance-scan . && echo "Clean" || echo "Violations found"
```
