"""Data models for the compliance scanner."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    """Violation severity levels."""
    ACTIVE_VIOLATION = "ACTIVE_VIOLATION"
    POTENTIAL_VIOLATION = "POTENTIAL_VIOLATION"
    COMPLIANT = "COMPLIANT"


class PatternType(Enum):
    """Types of violation patterns."""
    ENV_VAR_ABUSE = "Environment variable abuse"
    HEADER_SPOOFING = "Header spoofing"
    TOKEN_EXTRACTION = "Token extraction"
    OAUTH_ROUTING = "OAuth subscription routing"
    ENCODED_TOKEN = "Encoded token detected"


@dataclass
class Finding:
    """Represents a single finding/violation."""
    file_path: Path
    line_number: int
    severity: Severity
    pattern_type: PatternType
    matched_text: str
    context: str = ""
    remediation: str = ""

    def __post_init__(self):
        """Set default remediation based on pattern type."""
        if not self.remediation:
            self.remediation = REMEDIATION_HINTS.get(
                self.pattern_type,
                "Review this code for potential ToS violations."
            )


@dataclass
class ScanResult:
    """Results of a repository scan."""
    repo_path: Path
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def has_violations(self) -> bool:
        """Check if any violations were found."""
        return any(
            f.severity in (Severity.ACTIVE_VIOLATION, Severity.POTENTIAL_VIOLATION)
            for f in self.findings
        )

    @property
    def active_violations(self) -> list[Finding]:
        """Get all active violations."""
        return [f for f in self.findings if f.severity == Severity.ACTIVE_VIOLATION]

    @property
    def potential_violations(self) -> list[Finding]:
        """Get all potential violations."""
        return [f for f in self.findings if f.severity == Severity.POTENTIAL_VIOLATION]


REMEDIATION_HINTS = {
    PatternType.ENV_VAR_ABUSE: (
        "Use a proper Anthropic API key from console.anthropic.com "
        "instead of OAuth tokens from Claude Code."
    ),
    PatternType.HEADER_SPOOFING: (
        "Remove spoofed client identification headers. "
        "Only official Claude Code should use these headers."
    ),
    PatternType.TOKEN_EXTRACTION: (
        "Do not extract or reuse OAuth tokens from Claude CLI. "
        "Use official API keys for programmatic access."
    ),
    PatternType.OAUTH_ROUTING: (
        "Do not route OAuth subscription tokens through proxies. "
        "This violates Anthropic's Terms of Service."
    ),
    PatternType.ENCODED_TOKEN: (
        "Encoded tokens near OAuth-related code suggest token obfuscation. "
        "Use transparent, legitimate API key authentication."
    ),
}
