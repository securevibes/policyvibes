---
name: anthropic-oauth-abuse
description: Detect Anthropic ToS violations related to OAuth token abuse, header spoofing, and credential extraction
version: 1.0.0
provider: anthropic
---

# Anthropic OAuth Abuse Detection Skill

This skill detects violations of Anthropic's Terms of Service related to OAuth token abuse.

## Detection Categories

### Environment Variable Abuse (`env_var_abuse`)
- OAuth tokens used as API keys
- `ANTHROPIC_AUTH_TOKEN` usage
- `CLAUDE_CODE_OAUTH_TOKEN` references
- Non-Anthropic base URLs

### Header Spoofing (`header_spoofing`)
- `X-Client-Name: claude-code` impersonation
- User-Agent manipulation to impersonate Claude Code
- Headers dict with spoofed client identification

### Token Extraction (`token_extraction`)
- Reading from `~/.claude/.credentials.json`
- `ANTHROPIC_OAUTH_TOKEN` environment variable
- OAuth token refresh patterns

### OAuth Routing (`oauth_routing`)
- Subscription-based routing with OAuth
- Auth profile rotation
- `anthropic-oauth` provider patterns
- Gateway/proxy configurations

## Severity Levels

- **ACTIVE_VIOLATION**: Direct evidence of ToS violation
- **POTENTIAL_VIOLATION**: Suspicious patterns without direct evidence

## Remediation

Each pattern type includes specific remediation guidance to help developers
fix violations and use the official Anthropic API properly.
