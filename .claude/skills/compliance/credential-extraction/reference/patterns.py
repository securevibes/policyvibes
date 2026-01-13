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
    # macOS Keychain access to Claude Code credentials
    {
        "name": "claude_keychain_service",
        "regex": r"Claude Code-credentials|Claude Code.*keychain|keychain.*Claude Code",
        "severity": "ACTIVE_VIOLATION",
        "description": "Accessing Claude Code credentials from macOS keychain",
    },
    # Claude CLI credential function patterns
    {
        "name": "claude_cli_creds_function",
        "regex": r"readClaudeCliCredentials|writeClaudeCliCredentials|ClaudeCliCredential",
        "severity": "ACTIVE_VIOLATION",
        "description": "Functions for reading/writing Claude CLI credentials",
    },
    # Syncing credentials from Claude CLI
    {
        "name": "claude_cli_sync",
        "regex": r"sync.*claude.*cli|claude.*cli.*sync|claude.*cli.*credentials",
        "severity": "ACTIVE_VIOLATION",
        "description": "Syncing credentials from Claude CLI to another application",
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
    # Generic keychain credential extraction (security command)
    {
        "name": "security_keychain_claude",
        "regex": r'security\s+find-generic-password.*[Cc]laude',
        "severity": "ACTIVE_VIOLATION",
        "description": "Using macOS security command to extract Claude credentials from keychain",
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
