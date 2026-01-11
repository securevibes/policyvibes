---
name: header-spoofing
description: Detect header spoofing to impersonate Claude Code client
allowed-tools: Read, Grep, Glob
---

# Header Spoofing Detection

## Purpose

Identify code that spoofs HTTP headers to impersonate Claude Code, which violates Anthropic's Terms of Service.

## Detection Pipeline

### Phase 1: Identify Candidates

Search for patterns indicating header spoofing:

1. **X-Client-Name spoofing:**
   - `X-Client-Name: claude-code` or `X-Client-Name: claude_code`
   - Headers dict setting client name to claude-code

2. **User-Agent spoofing:**
   - User-Agent containing "claude-code" or "claude_code"
   - Custom User-Agent strings mimicking Claude Code

### Phase 2: Verify Context

For each candidate, analyze the surrounding code:

1. **Is this setting HTTP headers?**
   - Look for requests library usage
   - Check for HTTP client configuration
   - Identify headers dictionary construction

2. **Intent indicators:**
   - Comments explaining the spoofing
   - Subscription or OAuth-related code nearby
   - Proxy or gateway configuration

3. **False positive indicators:**
   - Test fixtures or mock data
   - Documentation examples
   - Detection code (like this scanner)

### Phase 3: Classify Severity

- **ACTIVE_VIOLATION**: Direct header spoofing with clear intent
- **POTENTIAL_VIOLATION**: Suspicious header patterns without clear context

### Phase 4: Generate Remediation

Provide specific guidance:
- Remove spoofed X-Client-Name headers
- Use your application's actual identity in headers
- If building a legitimate integration, contact Anthropic for proper identification

## Patterns Reference

Key regex patterns to search for:

```
X-Client-Name["\']?\s*[=:]\s*["\']claude[_-]?code
User-Agent["\']?\s*[=:]\s*["\'].*claude[_-]?code
headers\s*=\s*\{[^}]*X-Client-Name[^}]*claude[_-]?code
```

## Examples

See `examples.md` for real-world violation examples.
