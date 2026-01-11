"""Credential extraction detection patterns.

These patterns are used by the compliance agent to identify
extraction of OAuth tokens from Claude CLI credential files.
"""

CREDENTIAL_EXTRACTION_PATTERNS = [
    # Direct credential file path
    {
        "name": "credentials_json_path",
        "regex": r"\.claude/\.credentials\.json|\.claude\\\.credentials\.json",
        "severity": "ACTIVE_VIOLATION",
        "description": "Reading from Claude CLI credentials file",
    },
    # claudeAiOauth field access
    {
        "name": "claude_ai_oauth_field",
        "regex": r"claudeAiOauth",
        "severity": "ACTIVE_VIOLATION",
        "description": "Accessing claudeAiOauth field from credentials",
    },
    # ANTHROPIC_OAUTH_TOKEN environment variable
    {
        "name": "anthropic_oauth_token_env",
        "regex": r"ANTHROPIC_OAUTH_TOKEN",
        "severity": "ACTIVE_VIOLATION",
        "description": "ANTHROPIC_OAUTH_TOKEN environment variable usage",
    },
    # OAuth token refresh patterns
    {
        "name": "oauth_token_refresh",
        "regex": r"(?:claude|anthropic).*(?:oauth|token).*refresh|refresh.*(?:oauth|token).*(?:claude|anthropic)",
        "severity": "POTENTIAL_VIOLATION",
        "description": "OAuth token refresh pattern detected",
    },
]

REMEDIATION = """
To fix credential extraction violations:

1. Do NOT read from Claude CLI credential files
2. Get your own API key from https://console.anthropic.com
3. Use the official Anthropic SDK with your API key:

   export ANTHROPIC_API_KEY=sk-ant-...

   from anthropic import Anthropic
   client = Anthropic()

Claude CLI credentials are for the CLI tool only, not for third-party applications.
"""
