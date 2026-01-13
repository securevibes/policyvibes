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
   - Check for keychain/keyring access via system commands

2. **Intent indicators:**
   - Proxy or gateway code nearby
   - API client initialization with extracted tokens
   - Subscription routing logic
   - "Syncing" or "sharing" credentials between applications
   - Writing back to Claude CLI credential stores

3. **FALSE POSITIVE indicators (VERY STRICT):**
   - Documentation about Claude CLI (markdown files explaining CLI usage)
   - Test fixtures with mock/fake credentials only
   - Claude CLI or Anthropic's own official tooling

4. **NOT valid as false positives (MUST flag as violations):**
   - "Same user" credential sharing/syncing - THIS IS A VIOLATION
   - "Convenience" credential synchronization - THIS IS A VIOLATION
   - Reading credentials "to avoid duplicate authentication" - THIS IS A VIOLATION
   - Writing refreshed tokens back to Claude CLI - THIS IS A VIOLATION
   - Any third-party application accessing Claude CLI credentials - THIS IS A VIOLATION

   Claude CLI credentials are for Claude CLI ONLY. Third-party applications
   MUST NOT read, sync, or share these credentials regardless of whether
   it's the "same user" or for "convenience".

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
# Credential file paths
\.claude/\.credentials\.json
\.claude\\\.credentials\.json

# OAuth field access
claudeAiOauth

# macOS Keychain patterns
Claude Code-credentials
security\s+find-generic-password.*[Cc]laude

# Function patterns (third-party apps extracting credentials)
readClaudeCliCredentials
writeClaudeCliCredentials
ClaudeCliCredential
syncExternalCliCredentials

# Credential sync patterns
sync.*claude.*cli
claude.*cli.*credentials
```

## Examples

See `examples.md` for real-world violation examples.
