---
name: credential-extraction
description: Detect extraction of OAuth tokens from Claude CLI credential files
allowed-tools: Read, Grep, Glob
---

# Credential Extraction Detection

## Purpose

Identify code that extracts OAuth tokens from Claude CLI credential files, which violates Anthropic's Terms of Service.

## Detection Pipeline

### Phase 1: Identify Candidates

Search for patterns indicating credential file access:

1. **Credential file paths:**
   - `~/.claude/.credentials.json`
   - `.claude/.credentials.json`
   - References to Claude CLI config directories

2. **Token extraction patterns:**
   - Reading from Claude credential files
   - Parsing Claude CLI JSON config
   - Extracting tokens from keychain/keyring

### Phase 2: Verify Context

For each candidate, analyze the surrounding code:

1. **Is this actually extracting tokens?**
   - Look for JSON parsing of credential files
   - Check for token field access
   - Identify OAuth-related field extraction

2. **Intent indicators:**
   - Proxy or gateway code nearby
   - API client initialization with extracted tokens
   - Subscription routing logic

3. **False positive indicators:**
   - Documentation about Claude CLI
   - Test fixtures
   - Backup/migration tools with user consent

### Phase 3: Classify Severity

- **ACTIVE_VIOLATION**: Direct credential file access for token extraction
- **POTENTIAL_VIOLATION**: References to credential paths without clear extraction

### Phase 4: Generate Remediation

Provide specific guidance:
- Do not read from Claude CLI credential files
- Use your own API keys from console.anthropic.com
- If building tooling, request proper API access

## Patterns Reference

Key regex patterns to search for:

```
\.claude/\.credentials\.json
\.claude\\\.credentials\.json
claudeAiOauth
```

## Examples

See `examples.md` for real-world violation examples.
