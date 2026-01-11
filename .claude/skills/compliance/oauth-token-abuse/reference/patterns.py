"""OAuth token abuse detection patterns.

These patterns are used by the compliance agent to identify
OAuth tokens being used as API keys.
"""

OAUTH_TOKEN_ABUSE_PATTERNS = [
    # ANTHROPIC_AUTH_TOKEN usage (OAuth-specific)
    {
        "name": "anthropic_auth_token",
        "regex": r"ANTHROPIC_AUTH_TOKEN\s*[=:]",
        "severity": "ACTIVE_VIOLATION",
        "description": "ANTHROPIC_AUTH_TOKEN usage detected - OAuth-specific variable",
    },
    # CLAUDE_CODE_OAUTH_TOKEN usage
    {
        "name": "claude_code_oauth_token",
        "regex": r"CLAUDE_CODE_OAUTH_TOKEN",
        "severity": "ACTIVE_VIOLATION",
        "description": "CLAUDE_CODE_OAUTH_TOKEN usage detected",
    },
    # OAuth token used as API key
    {
        "name": "api_key_oauth_reference",
        "regex": r"ANTHROPIC_API_KEY\s*[=:]\s*.*(?:oauth|OAUTH|claude.code|CLAUDE_CODE)",
        "severity": "ACTIVE_VIOLATION",
        "description": "OAuth token used as API key",
    },
    # ANTHROPIC_OAUTH_TOKEN
    {
        "name": "anthropic_oauth_token",
        "regex": r"ANTHROPIC_OAUTH_TOKEN",
        "severity": "ACTIVE_VIOLATION",
        "description": "ANTHROPIC_OAUTH_TOKEN environment variable",
    },
]

REMEDIATION = """
To fix OAuth token abuse violations:

1. Get a proper API key from https://console.anthropic.com
2. Replace OAuth token references with your API key
3. Use the official Anthropic SDK:

   from anthropic import Anthropic
   client = Anthropic()  # Uses ANTHROPIC_API_KEY from environment

Do NOT use tokens from Claude Code or subscription OAuth flows.
"""
