---
name: oauth-token-abuse
description: Detect OAuth tokens being used as API keys in violation of Anthropic ToS
allowed-tools: Read, Grep, Glob
---

# OAuth Token Abuse Detection

## Purpose

Identify code that uses OAuth tokens (from Claude Code subscriptions) as API keys, which violates Anthropic's Terms of Service.

## Detection Pipeline

### Phase 1: Identify Candidates

Search for patterns indicating OAuth token usage as API keys:

1. **Environment variable patterns:**
   - `ANTHROPIC_AUTH_TOKEN` - OAuth-specific token variable
   - `CLAUDE_CODE_OAUTH_TOKEN` - Direct Claude Code OAuth reference
   - `ANTHROPIC_API_KEY` combined with OAuth/claude-code references

2. **Code patterns:**
   - Setting API keys from OAuth token sources
   - Environment variable assignments with OAuth references

### Phase 2: Verify Context

For each candidate, analyze the surrounding code:

1. **Is this setting an API key?**
   - Look for API client initialization
   - Check if the value is used in authentication headers

2. **Is the token source an OAuth flow?**
   - Check for OAuth-related comments
   - Look for subscription references

3. **False positive indicators:**
   - Documentation or comments explaining the pattern
   - Test fixtures or mock data
   - Legitimate SDK configuration examples

### Phase 3: Classify Severity

- **ACTIVE_VIOLATION**: Direct OAuth token usage as API key with clear evidence
- **POTENTIAL_VIOLATION**: Suspicious patterns without definitive proof

### Phase 4: Generate Remediation

Provide specific guidance:
- Use official API keys from console.anthropic.com
- Remove OAuth token references from API key configuration
- If using Claude Code legitimately, use the official SDK

## Patterns Reference

Key regex patterns to search for:

```
ANTHROPIC_AUTH_TOKEN\s*[=:]
CLAUDE_CODE_OAUTH_TOKEN
ANTHROPIC_API_KEY\s*[=:]\s*.*(?:oauth|claude.code)
```

## Examples

See `examples.md` for real-world violation examples from known violating projects.
