"""Tests for the CLI module."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from policyvibes.cli import main


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
