"""Anthropic OAuth abuse detection patterns."""

from ..base import BaseSkill, PatternDefinition
from ...models import PatternType, Severity, REMEDIATION_HINTS


class AnthropicOAuthSkill(BaseSkill):
    """Detects Anthropic ToS violations related to OAuth token abuse.

    This skill detects:
    - OAuth tokens used as API keys
    - Header spoofing (X-Client-Name, User-Agent)
    - Token extraction from Claude CLI config files
    - OAuth subscription routing through proxies
    """

    @property
    def name(self) -> str:
        return "anthropic-oauth-abuse"

    @property
    def provider(self) -> str:
        return "anthropic"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detect Anthropic ToS violations related to OAuth token abuse"

    def get_patterns(self) -> list[PatternDefinition]:
        """Return all detection patterns for Anthropic OAuth abuse."""
        return (
            self._env_var_patterns() +
            self._header_patterns() +
            self._token_extraction_patterns() +
            self._config_patterns()
        )

    def _env_var_patterns(self) -> list[PatternDefinition]:
        """Environment variable abuse patterns."""
        return [
            # OAuth token used as API key
            PatternDefinition(
                regex=r'ANTHROPIC_API_KEY\s*[=:]\s*.*(?:oauth|OAUTH|claude.code|CLAUDE_CODE)',
                pattern_type=PatternType.ENV_VAR_ABUSE,
                severity=Severity.ACTIVE_VIOLATION,
                description="OAuth token used as API key",
            ),
            # ANTHROPIC_AUTH_TOKEN usage (OAuth-specific)
            PatternDefinition(
                regex=r'ANTHROPIC_AUTH_TOKEN\s*[=:]',
                pattern_type=PatternType.ENV_VAR_ABUSE,
                severity=Severity.ACTIVE_VIOLATION,
                description="ANTHROPIC_AUTH_TOKEN usage detected",
            ),
            # CLAUDE_CODE_OAUTH_TOKEN usage
            PatternDefinition(
                regex=r'CLAUDE_CODE_OAUTH_TOKEN',
                pattern_type=PatternType.ENV_VAR_ABUSE,
                severity=Severity.ACTIVE_VIOLATION,
                description="CLAUDE_CODE_OAUTH_TOKEN usage detected",
            ),
            # Base URL pointing to non-Anthropic endpoints
            PatternDefinition(
                regex=r'ANTHROPIC_BASE_URL\s*[=:]\s*["\']?(?!https?://api\.anthropic\.com)',
                pattern_type=PatternType.ENV_VAR_ABUSE,
                severity=Severity.POTENTIAL_VIOLATION,
                description="ANTHROPIC_BASE_URL pointing to non-Anthropic endpoint",
            ),
        ]

    def _header_patterns(self) -> list[PatternDefinition]:
        """Header spoofing patterns."""
        return [
            # X-Client-Name spoofing
            PatternDefinition(
                regex=r'["\']?X-Client-Name["\']?\s*[=:]\s*["\']claude[_-]?code["\']',
                pattern_type=PatternType.HEADER_SPOOFING,
                severity=Severity.ACTIVE_VIOLATION,
                description="X-Client-Name header spoofing detected",
            ),
            # User-Agent spoofing to impersonate Claude Code
            PatternDefinition(
                regex=r'["\']?User-Agent["\']?\s*[=:]\s*["\'].*claude[_-]?code.*["\']',
                pattern_type=PatternType.HEADER_SPOOFING,
                severity=Severity.ACTIVE_VIOLATION,
                description="User-Agent spoofing to impersonate Claude Code",
            ),
            # Headers dict with claude-code client name
            PatternDefinition(
                regex=r'headers\s*=\s*\{[^}]*["\']X-Client-Name["\'][^}]*claude[_-]?code',
                pattern_type=PatternType.HEADER_SPOOFING,
                severity=Severity.ACTIVE_VIOLATION,
                description="Headers dict with spoofed X-Client-Name",
            ),
        ]

    def _token_extraction_patterns(self) -> list[PatternDefinition]:
        """Token extraction patterns."""
        return [
            # Reading from ~/.claude/.credentials.json specifically
            PatternDefinition(
                regex=r'\.claude/\.credentials\.json|\.claude\\\.credentials\.json',
                pattern_type=PatternType.TOKEN_EXTRACTION,
                severity=Severity.ACTIVE_VIOLATION,
                description="Reading from Claude CLI credentials file",
            ),
            # Claude Code OAuth token environment variable
            PatternDefinition(
                regex=r'ANTHROPIC_OAUTH_TOKEN',
                pattern_type=PatternType.TOKEN_EXTRACTION,
                severity=Severity.ACTIVE_VIOLATION,
                description="ANTHROPIC_OAUTH_TOKEN usage detected",
            ),
            # OAuth token refresh with anthropic/claude context
            PatternDefinition(
                regex=r'(?:claude|anthropic).*(?:oauth|token).*refresh|refresh.*(?:oauth|token).*(?:claude|anthropic)',
                pattern_type=PatternType.TOKEN_EXTRACTION,
                severity=Severity.POTENTIAL_VIOLATION,
                description="OAuth token refresh pattern detected",
            ),
            # Subscription-based routing (clawdbot pattern)
            PatternDefinition(
                regex=r'subscription.*(?:oauth|anthropic)|(?:oauth|anthropic).*subscription',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.ACTIVE_VIOLATION,
                description="Subscription-based OAuth routing detected",
            ),
            # Auth profile rotation
            PatternDefinition(
                regex=r'(?:auth|profile).*rotation|rotation.*(?:auth|profile)',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.ACTIVE_VIOLATION,
                description="Auth profile rotation detected",
            ),
            # anthropic-oauth provider/profile
            PatternDefinition(
                regex=r'anthropic[_-]oauth',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.ACTIVE_VIOLATION,
                description="anthropic-oauth provider/profile detected",
            ),
        ]

    def _config_patterns(self) -> list[PatternDefinition]:
        """Config file patterns (YAML/JSON specific)."""
        return [
            # Provider type: oauth
            PatternDefinition(
                regex=r'type\s*:\s*oauth',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.ACTIVE_VIOLATION,
                description="OAuth provider type in config",
            ),
            # Subscription routing
            PatternDefinition(
                regex=r'subscription\s*:\s*(?:max|pro)',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.ACTIVE_VIOLATION,
                description="Subscription routing in config",
            ),
            # Gateway/proxy with anthropic
            PatternDefinition(
                regex=r'gateway.*anthropic|anthropic.*gateway',
                pattern_type=PatternType.OAUTH_ROUTING,
                severity=Severity.POTENTIAL_VIOLATION,
                description="Gateway/proxy configuration with Anthropic",
            ),
        ]

    def get_remediation(self, pattern_type: PatternType) -> str:
        """Get remediation hint for a pattern type."""
        return REMEDIATION_HINTS.get(pattern_type, "Review and fix the detected issue.")
