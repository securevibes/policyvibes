"""Tests for the CLI module."""

import json
import tempfile
from pathlib import Path

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

    def test_scan_clean_directory(self, runner, temp_repo):
        # Create a clean file
        (temp_repo / "clean.py").write_text('print("Hello")')

        result = runner.invoke(main, ["scan-regex", str(temp_repo)])
        assert result.exit_code == 0
        assert "No violations found" in result.output

    def test_scan_directory_with_violations(self, runner, temp_repo):
        # Create a file with violations
        (temp_repo / "bad.py").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = runner.invoke(main, ["scan-regex", str(temp_repo)])
        assert result.exit_code == 1
        assert "ACTIVE_VIOLATION" in result.output

    def test_json_output(self, runner, temp_repo):
        (temp_repo / "clean.py").write_text('print("Hello")')

        result = runner.invoke(main, ["scan-regex", str(temp_repo), "--output", "json"])
        assert result.exit_code == 0

        # Should be valid JSON
        output = json.loads(result.output)
        assert "version" in output
        assert "findings" in output
        assert output["summary"]["has_violations"] is False

    def test_json_output_with_violations(self, runner, temp_repo):
        (temp_repo / "bad.py").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = runner.invoke(main, ["scan-regex", str(temp_repo), "--output", "json"])
        assert result.exit_code == 1

        output = json.loads(result.output)
        assert output["summary"]["has_violations"] is True
        assert len(output["findings"]) >= 1

    def test_severity_filter_active(self, runner, temp_repo):
        # Create file with both types
        (temp_repo / "mixed.py").write_text('''
ANTHROPIC_AUTH_TOKEN = "secret"
ANTHROPIC_BASE_URL = "http://proxy.local"
''')

        result = runner.invoke(main, ["scan-regex", str(temp_repo), "--severity", "active"])
        assert result.exit_code == 1
        assert "ACTIVE_VIOLATION" in result.output

    def test_severity_filter_potential(self, runner, temp_repo):
        (temp_repo / "test.py").write_text('ANTHROPIC_BASE_URL = "http://proxy.local"')

        result = runner.invoke(main, ["scan-regex", str(temp_repo), "--severity", "potential"])
        # Has potential violation
        assert "POTENTIAL_VIOLATION" in result.output or result.exit_code == 0

    def test_nonexistent_path(self, runner):
        result = runner.invoke(main, ["scan-regex", "/nonexistent/path/xyz"])
        assert result.exit_code == 2
        assert "Error" in result.output

    def test_version_option(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.2.0" in result.output

    def test_scan_single_file(self, runner, temp_repo):
        test_file = temp_repo / "test.py"
        test_file.write_text('print("clean")')

        result = runner.invoke(main, ["scan-regex", str(test_file)])
        assert result.exit_code == 0

    def test_output_includes_file_path(self, runner, temp_repo):
        (temp_repo / "bad.py").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = runner.invoke(main, ["scan-regex", str(temp_repo)])
        assert "bad.py" in result.output

    def test_output_includes_remediation(self, runner, temp_repo):
        (temp_repo / "bad.py").write_text('ANTHROPIC_AUTH_TOKEN = "secret"')

        result = runner.invoke(main, ["scan-regex", str(temp_repo)])
        assert "Remediation" in result.output

    def test_list_skills(self, runner):
        result = runner.invoke(main, ["list-skills"])
        assert result.exit_code == 0
        # Should list at least one skill
        assert "oauth-token-abuse" in result.output or "Compliance" in result.output
