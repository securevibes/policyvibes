"""Base skill interface for compliance detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..models import Finding, PatternType, Severity


@dataclass
class PatternDefinition:
    """Defines a detection pattern."""
    regex: str
    pattern_type: PatternType
    severity: Severity
    description: str = ""


class BaseSkill(ABC):
    """Abstract base class for compliance detection skills.

    All provider-specific detection skills must inherit from this class
    and implement the required methods.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this skill."""
        pass

    @property
    @abstractmethod
    def provider(self) -> str:
        """Provider this skill detects violations for (e.g., 'anthropic')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Skill version."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this skill detects."""
        pass

    @abstractmethod
    def get_patterns(self) -> list[PatternDefinition]:
        """Return list of patterns this skill detects.

        Returns:
            List of PatternDefinition objects defining regex patterns,
            their types, and severities.
        """
        pass

    @abstractmethod
    def get_remediation(self, pattern_type: PatternType) -> str:
        """Get remediation hint for a pattern type.

        Args:
            pattern_type: The type of pattern that was matched.

        Returns:
            Human-readable remediation guidance.
        """
        pass

    def get_scannable_extensions(self) -> set[str]:
        """File extensions this skill can scan.

        Override to customize. Default includes common code files.
        """
        return {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
            '.yaml', '.yml', '.json', '.toml', '.env', '.sh', '.bash',
            '.md', '.txt', '.cfg', '.ini', '.conf',
        }

    def get_special_files(self) -> set[str]:
        """Special filenames to always scan regardless of extension."""
        return {
            '.env', '.env.local', '.env.development', '.env.production',
            'docker-compose.yml', 'docker-compose.yaml',
            'Dockerfile', 'Makefile',
        }

    def get_skip_dirs(self) -> set[str]:
        """Directories to skip during scanning."""
        return {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            '.tox', '.pytest_cache', '.mypy_cache', 'dist', 'build',
            '.eggs', '*.egg-info',
        }
