---
name: subscription-routing
description: Detect OAuth subscription routing through proxies and gateways
allowed-tools: Read, Grep, Glob
---

# Subscription Routing Detection

## Purpose

Identify code that routes OAuth subscription tokens through proxies or gateways to abuse subscription pricing, which violates Anthropic's Terms of Service.

## Detection Pipeline

### Phase 1: Identify Candidates

Search for patterns indicating subscription routing:

1. **Subscription references:**
   - `subscription: max` or `subscription: pro`
   - OAuth combined with subscription keywords
   - anthropic-oauth provider configurations

2. **Routing patterns:**
   - Auth profile rotation
   - Provider transformers
   - Gateway configurations with Anthropic

3. **Config file patterns:**
   - `type: oauth` provider configurations
   - Subscription tier routing

### Phase 2: Verify Context

For each candidate, analyze the surrounding code:

1. **Is this routing subscription tokens?**
   - Look for proxy/gateway infrastructure
   - Check for auth profile management
   - Identify subscription tier checks

2. **Intent indicators:**
   - Multiple OAuth profile rotation
   - Subscription-based rate limiting
   - Cost optimization comments

3. **False positive indicators:**
   - Documentation about subscription tiers
   - Legitimate subscription management UIs
   - Test fixtures

### Phase 3: Classify Severity

- **ACTIVE_VIOLATION**: Direct subscription routing infrastructure
- **POTENTIAL_VIOLATION**: Gateway/proxy patterns without clear subscription abuse

### Phase 4: Generate Remediation

Provide specific guidance:
- Do not route subscription OAuth tokens through proxies
- Use API keys with proper billing for programmatic access
- If you need high volume access, contact Anthropic sales

## Patterns Reference

Key regex patterns to search for:

```
subscription.*(?:oauth|anthropic)
type\s*:\s*oauth
anthropic[_-]oauth
(?:auth|profile).*rotation
```

## Examples

See `examples.md` for real-world violation examples.
