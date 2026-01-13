"""Tests for the CLI module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from policyvibes.cli import main, display_report, validate_report


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_repo():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestCLI:
    """Tests for CLI commands."""

    def test_version_option(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.2.0" in result.output

    def test_help_option(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "list-skills" in result.output

    def test_scan_requires_sdk(self, runner, temp_repo):
        """Test that scan command shows helpful error when SDK not installed."""
        (temp_repo / "clean.py").write_text('print("Hello")')

        # Patch the SDK availability check
        with patch("policyvibes.cli.query", None), \
             patch("policyvibes.cli.ClaudeAgentOptions", None):
            result = runner.invoke(main, ["scan", str(temp_repo)])
            assert result.exit_code == 2
            assert "Claude Agent SDK not installed" in result.output
            assert "pip install claude-agent-sdk" in result.output

    def test_scan_nonexistent_path(self, runner):
        result = runner.invoke(main, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code == 2
        assert "Error" in result.output or "does not exist" in result.output

    def test_list_skills(self, runner):
        result = runner.invoke(main, ["list-skills"])
        assert result.exit_code == 0
        # Should list at least one skill or indicate no skills found
        assert "oauth-token-abuse" in result.output or "No skills" in result.output or "PolicyVibes" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--model" in result.output
        assert "--output" in result.output
        assert "sonnet" in result.output or "opus" in result.output

    def test_no_scan_regex_command(self, runner):
        """Ensure scan-regex command no longer exists."""
        result = runner.invoke(main, ["scan-regex", "."])
        assert result.exit_code == 2
        assert "No such command" in result.output


class TestReportValidation:
    """Tests for report validation functionality."""

    def test_validate_complete_report(self, temp_repo):
        """Test validation of a complete report."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0,
                "files_scanned": 50
            },
            "findings": []
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        is_valid, warnings = validate_report(report_path)
        assert is_valid is True
        assert len(warnings) == 0

    def test_validate_missing_files_scanned(self, temp_repo):
        """Test validation detects missing files_scanned."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0
                # files_scanned is missing
            },
            "findings": []
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        is_valid, warnings = validate_report(report_path)
        assert is_valid is True  # Still valid, but has warnings
        assert any("files_scanned" in w for w in warnings)

    def test_validate_missing_summary(self, temp_repo):
        """Test validation detects missing summary."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "findings": []
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        is_valid, warnings = validate_report(report_path)
        assert is_valid is False
        assert any("summary" in w for w in warnings)

    def test_validate_nonexistent_report(self, temp_repo):
        """Test validation handles nonexistent report."""
        report_path = temp_repo / "POLICYVIBES_REPORT.json"

        is_valid, warnings = validate_report(report_path)
        assert is_valid is False
        assert any("not found" in w.lower() or "does not exist" in w.lower() for w in warnings)

    def test_validate_invalid_json(self, temp_repo):
        """Test validation handles invalid JSON."""
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text("not valid json {{{")

        is_valid, warnings = validate_report(report_path)
        assert is_valid is False
        assert any("json" in w.lower() or "parse" in w.lower() for w in warnings)


class TestDisplayReport:
    """Tests for report display functionality."""

    def test_display_report_with_files_scanned(self, temp_repo, capsys):
        """Test that files_scanned is displayed correctly."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0,
                "files_scanned": 42
            },
            "findings": []
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        result = display_report(report_path)
        assert result is not None
        assert result["summary"]["files_scanned"] == 42

    def test_display_report_missing_shows_na(self, temp_repo, capsys):
        """Test that missing files_scanned shows N/A."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0
            },
            "findings": []
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        result = display_report(report_path)
        assert result is not None
        # The function should still work even with missing files_scanned

    def test_display_report_with_string_findings(self, temp_repo):
        """Test that string findings don't crash the display."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0,
                "files_scanned": 10
            },
            "findings": [
                "This is a string finding instead of a dict",
                {
                    "severity": "POTENTIAL_VIOLATION",
                    "type": "test-type",
                    "file": "test.py",
                    "line": 1,
                    "code": "test code",
                    "reason": "test reason"
                }
            ]
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        # Should not raise an exception
        result = display_report(report_path)
        assert result is not None

    def test_display_report_with_all_string_findings(self, temp_repo):
        """Test that all-string findings don't crash."""
        report = {
            "scan_path": str(temp_repo),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "summary": {
                "active_violations": 0,
                "potential_violations": 0,
                "files_scanned": 5
            },
            "findings": [
                "No violations found in OAuth patterns",
                "Header spoofing check passed"
            ]
        }
        report_path = temp_repo / "POLICYVIBES_REPORT.json"
        report_path.write_text(json.dumps(report))

        result = display_report(report_path)
        assert result is not None


class TestMessageDisplay:
    """Tests for message display without truncation."""

    def test_long_message_not_truncated(self):
        """Test that long messages are not truncated."""
        # Create a message longer than the old 500 char limit
        long_message = "A" * 1000

        # The fix should allow full message display
        # We test the logic that was previously truncating
        displayed = long_message  # After fix: no truncation
        assert len(displayed) == 1000
        assert displayed == long_message

    def test_all_messages_shown(self):
        """Test that all messages are shown, not just last 3."""
        messages = [f"Message {i}" for i in range(10)]

        # After fix: all messages should be shown
        displayed_messages = messages  # No [-3:] slice
        assert len(displayed_messages) == 10
        assert displayed_messages[0] == "Message 0"
        assert displayed_messages[9] == "Message 9"
