"""Pattern detection using skill-based architecture."""

import re
from pathlib import Path
from typing import Iterator

from ..models import Finding, PatternType, Severity
from ..skills import load_all_skills
from ..skills.base import BaseSkill, PatternDefinition


class PatternDetector:
    """Detects ToS violation patterns in source code using skills.

    This class loads all available skills and uses their patterns
    for detection. Skills can be added for different providers
    (Anthropic, OpenAI, Google, etc.).
    """

    def __init__(self, skills: list[BaseSkill] | None = None):
        """Initialize the pattern detector.

        Args:
            skills: Optional list of skills to use. If None, loads all
                   available skills automatically.
        """
        self.skills = skills if skills is not None else load_all_skills()
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns from skills for efficiency."""
        self.compiled_patterns: list[tuple[re.Pattern, PatternType, Severity, str]] = []

        for skill in self.skills:
            for pattern_def in skill.get_patterns():
                try:
                    compiled = re.compile(
                        pattern_def.regex,
                        re.IGNORECASE | re.MULTILINE
                    )
                    self.compiled_patterns.append((
                        compiled,
                        pattern_def.pattern_type,
                        pattern_def.severity,
                        pattern_def.description,
                    ))
                except re.error:
                    # Skip invalid patterns
                    pass

    @property
    def scannable_extensions(self) -> set[str]:
        """Get all scannable extensions from all skills."""
        extensions: set[str] = set()
        for skill in self.skills:
            extensions.update(skill.get_scannable_extensions())
        return extensions or {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
            '.yaml', '.yml', '.json', '.toml', '.env', '.sh', '.bash',
            '.md', '.txt', '.cfg', '.ini', '.conf',
        }

    @property
    def special_files(self) -> set[str]:
        """Get all special files from all skills."""
        files: set[str] = set()
        for skill in self.skills:
            files.update(skill.get_special_files())
        return files or {
            '.env', '.env.local', '.env.development', '.env.production',
            'docker-compose.yml', 'docker-compose.yaml',
            'Dockerfile', 'Makefile',
        }

    @property
    def skip_dirs(self) -> set[str]:
        """Get all directories to skip from all skills."""
        dirs: set[str] = set()
        for skill in self.skills:
            dirs.update(skill.get_skip_dirs())
        return dirs or {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            '.tox', '.pytest_cache', '.mypy_cache', 'dist', 'build',
            '.eggs', '*.egg-info',
        }

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Check special files
        if file_path.name in self.special_files:
            return True

        # Check extension
        return file_path.suffix.lower() in self.scannable_extensions

    def should_skip_dir(self, dir_path: Path) -> bool:
        """Check if a directory should be skipped."""
        return dir_path.name in self.skip_dirs

    def scan_content(self, content: str, file_path: Path) -> Iterator[Finding]:
        """Scan content for violation patterns."""
        lines = content.split('\n')

        for compiled, pattern_type, severity, description in self.compiled_patterns:
            for match in compiled.finditer(content):
                # Find line number
                line_start = content.count('\n', 0, match.start()) + 1

                # Get the matched line for context
                if 0 < line_start <= len(lines):
                    context = lines[line_start - 1].strip()
                else:
                    context = match.group(0)

                yield Finding(
                    file_path=file_path,
                    line_number=line_start,
                    severity=severity,
                    pattern_type=pattern_type,
                    matched_text=match.group(0),
                    context=context,
                )

    def scan_file(self, file_path: Path) -> Iterator[Finding]:
        """Scan a single file for violations."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            yield from self.scan_content(content, file_path)
        except (IOError, OSError):
            # Skip files that can't be read
            pass

    def scan_directory(self, dir_path: Path) -> Iterator[Finding]:
        """Recursively scan a directory for violations."""
        if not dir_path.exists():
            return

        for item in dir_path.iterdir():
            if item.is_dir():
                if not self.should_skip_dir(item):
                    yield from self.scan_directory(item)
            elif item.is_file():
                if self.should_scan_file(item):
                    yield from self.scan_file(item)

    def get_remediation(self, pattern_type: PatternType) -> str:
        """Get remediation hint for a pattern type from skills."""
        for skill in self.skills:
            remediation = skill.get_remediation(pattern_type)
            if remediation:
                return remediation
        return "Review and fix the detected issue."
