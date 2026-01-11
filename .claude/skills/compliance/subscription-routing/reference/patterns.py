"""Subscription routing detection patterns.

These patterns are used by the compliance agent to identify
OAuth subscription routing through proxies and gateways.
"""

SUBSCRIPTION_ROUTING_PATTERNS = [
    # Subscription with OAuth/Anthropic
    {
        "name": "subscription_oauth",
        "regex": r"subscription.*(?:oauth|anthropic)|(?:oauth|anthropic).*subscription",
        "severity": "ACTIVE_VIOLATION",
        "description": "Subscription-based OAuth routing detected",
    },
    # Auth profile rotation
    {
        "name": "auth_profile_rotation",
        "regex": r"(?:auth|profile).*rotation|rotation.*(?:auth|profile)",
        "severity": "ACTIVE_VIOLATION",
        "description": "Auth profile rotation detected",
    },
    # anthropic-oauth provider
    {
        "name": "anthropic_oauth_provider",
        "regex": r"anthropic[_-]oauth",
        "severity": "ACTIVE_VIOLATION",
        "description": "anthropic-oauth provider/profile detected",
    },
    # Provider type: oauth
    {
        "name": "oauth_provider_type",
        "regex": r"type\s*:\s*oauth",
        "severity": "ACTIVE_VIOLATION",
        "description": "OAuth provider type in config",
    },
    # Subscription routing config
    {
        "name": "subscription_routing_config",
        "regex": r"subscription\s*:\s*(?:max|pro)",
        "severity": "ACTIVE_VIOLATION",
        "description": "Subscription routing in config",
    },
    # Gateway with anthropic
    {
        "name": "gateway_anthropic",
        "regex": r"gateway.*anthropic|anthropic.*gateway",
        "severity": "POTENTIAL_VIOLATION",
        "description": "Gateway/proxy configuration with Anthropic",
    },
]

REMEDIATION = """
To fix subscription routing violations:

1. Do NOT route OAuth subscription tokens through proxies or gateways
2. Use API keys with proper billing for programmatic access
3. If you need high-volume access:
   - Contact Anthropic sales for enterprise pricing
   - Use the official API with proper billing

Subscription OAuth tokens are for individual user access only,
not for building services or proxies.
"""
