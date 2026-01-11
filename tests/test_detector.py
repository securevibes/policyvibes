"""Tests for the main detector module."""

import tempfile
from pathlib import Path

import pytest

from policyvibes.detector import PolicyVibesScanner
from policyvibes.models import Severity


@pytest.fixture
def scanner():
    return PolicyVibesScanner()


@pytest.fixture
def temp_repo():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestPolicyVibesScanner:
    """Tests for PolicyVibesScanner."""

    def test_scan_nonexistent_path_raises(self, scanner):
        with pytest.raises(FileNotFoundError):
            scanner.scan(Path("/nonexistent/path"))

    def test_scan_empty_directory(self, scanner, temp_repo):
        result = scanner.scan(temp_repo)
        assert result.files_scanned == 0
        assert len(result.findings) == 0
        assert not result.has_violations

    def test_scan_file_with_violation(self, scanner, temp_repo):
        # Create a file with a violation
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(test_file)
        assert result.files_scanned == 1
        assert len(result.findings) >= 1
        assert result.has_violations

    def test_scan_file_without_violation(self, scanner, temp_repo):
        # Create a compliant file
        test_file = temp_repo / "test.py"
        test_file.write_text('print("Hello, World!")')

        result = scanner.scan(test_file)
        assert result.files_scanned == 1
        assert len(result.findings) == 0
        assert not result.has_violations

    def test_scan_directory_with_violations(self, scanner, temp_repo):
        # Create files with violations
        (temp_repo / "bad.py").write_text('ANTHROPIC_OAUTH_TOKEN = "token"')
        (temp_repo / "good.py").write_text('print("clean")')

        result = scanner.scan(temp_repo)
        assert result.files_scanned == 2
        assert result.has_violations
        assert len(result.active_violations) >= 1

    def test_scan_skips_git_directory(self, scanner, temp_repo):
        # Create .git directory with a file
        git_dir = temp_repo / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(temp_repo)
        # .git should be skipped
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_scan_skips_node_modules(self, scanner, temp_repo):
        # Create node_modules directory
        nm_dir = temp_repo / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "bad.js").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(temp_repo)
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_findings_sorted_by_severity(self, scanner, temp_repo):
        # Create file with both active and potential violations
        test_file = temp_repo / "test.py"
        test_file.write_text('''
ANTHROPIC_AUTH_TOKEN = "secret"  # Active
ANTHROPIC_BASE_URL = "http://proxy.local"  # Potential
''')

        result = scanner.scan(test_file)
        if len(result.findings) >= 2:
            # Active violations should come first
            first_finding = result.findings[0]
            assert first_finding.severity == Severity.ACTIVE_VIOLATION

    def test_deduplicates_findings(self, scanner, temp_repo):
        # Create file that might match multiple patterns at same location
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(test_file)
        # Should not have duplicate findings for same line/pattern
        seen = set()
        for f in result.findings:
            key = (f.file_path, f.line_number, f.pattern_type)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)


class TestScanResult:
    """Tests for ScanResult properties."""

    def test_active_violations_property(self, scanner, temp_repo):
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(test_file)
        active = result.active_violations
        assert all(f.severity == Severity.ACTIVE_VIOLATION for f in active)

    def test_potential_violations_property(self, scanner, temp_repo):
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_BASE_URL = "http://proxy.local"')

        result = scanner.scan(test_file)
        potential = result.potential_violations
        assert all(f.severity == Severity.POTENTIAL_VIOLATION for f in potential)

    def test_has_violations_with_active(self, scanner, temp_repo):
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = scanner.scan(test_file)
        assert result.has_violations

    def test_has_violations_with_potential(self, scanner, temp_repo):
        test_file = temp_repo / "test.py"
        test_file.write_text('ANTHROPIC_BASE_URL = "http://proxy.local"')

        result = scanner.scan(test_file)
        assert result.has_violations
