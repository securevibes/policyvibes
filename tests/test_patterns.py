"""Tests for pattern detection."""

from pathlib import Path

import pytest

from policyvibes.patterns.detector import PatternDetector
from policyvibes.models import Severity, PatternType


@pytest.fixture
def detector():
    return PatternDetector()


class TestEnvVarPatterns:
    """Tests for environment variable abuse detection."""

    def test_detects_anthropic_auth_token(self, detector):
        content = 'ANTHROPIC_AUTH_TOKEN = "some_token"'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.severity == Severity.ACTIVE_VIOLATION for f in findings)

    def test_detects_claude_code_oauth_token(self, detector):
        content = 'key = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.pattern_type == PatternType.ENV_VAR_ABUSE for f in findings)


class TestHeaderSpoofingPatterns:
    """Tests for header spoofing detection."""

    def test_detects_x_client_name_spoofing(self, detector):
        content = 'headers = {"X-Client-Name": "claude-code"}'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.pattern_type == PatternType.HEADER_SPOOFING for f in findings)

    def test_detects_user_agent_spoofing(self, detector):
        content = '"User-Agent": "claude-code/1.0"'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.pattern_type == PatternType.HEADER_SPOOFING for f in findings)


class TestTokenExtractionPatterns:
    """Tests for token extraction detection."""

    def test_detects_credentials_json_access(self, detector):
        content = 'creds_path = "~/.claude/.credentials.json"'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.pattern_type == PatternType.TOKEN_EXTRACTION for f in findings)

    def test_detects_anthropic_oauth_token(self, detector):
        content = 'ANTHROPIC_OAUTH_TOKEN = token'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.severity == Severity.ACTIVE_VIOLATION for f in findings)


class TestOAuthRoutingPatterns:
    """Tests for OAuth subscription routing detection."""

    def test_detects_subscription_oauth(self, detector):
        content = 'subscription: oauth'
        findings = list(detector.scan_content(content, Path("config.yaml")))
        assert len(findings) >= 1

    def test_detects_auth_profile_rotation(self, detector):
        content = 'auth profile rotation enabled'
        findings = list(detector.scan_content(content, Path("test.py")))
        assert len(findings) >= 1
        assert any(f.pattern_type == PatternType.OAUTH_ROUTING for f in findings)

    def test_detects_anthropic_oauth_provider(self, detector):
        content = 'provider: anthropic-oauth'
        findings = list(detector.scan_content(content, Path("config.yaml")))
        assert len(findings) >= 1
        assert any(f.severity == Severity.ACTIVE_VIOLATION for f in findings)


class TestCompliantCode:
    """Tests that compliant code is not flagged."""

    def test_legitimate_api_key_usage(self, detector):
        content = '''
import anthropic
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
'''
        findings = list(detector.scan_content(content, Path("test.py")))
        # Should not have active violations for legitimate API key usage
        active = [f for f in findings if f.severity == Severity.ACTIVE_VIOLATION]
        assert len(active) == 0

    def test_claude_skills_directory_not_flagged(self, detector):
        content = 'skills_dir = ".claude/skills/"'
        findings = list(detector.scan_content(content, Path("test.py")))
        # .claude/skills/ should not be flagged (only .credentials.json)
        assert len(findings) == 0

    def test_legitimate_sdk_usage(self, detector):
        content = '''
from claude_agent_sdk import create_agent
agent = create_agent(model="opus")
'''
        findings = list(detector.scan_content(content, Path("test.py")))
        active = [f for f in findings if f.severity == Severity.ACTIVE_VIOLATION]
        assert len(active) == 0


class TestFileFiltering:
    """Tests for file filtering logic."""

    def test_should_scan_python_files(self, detector):
        assert detector.should_scan_file(Path("test.py"))

    def test_should_scan_javascript_files(self, detector):
        assert detector.should_scan_file(Path("test.js"))

    def test_should_scan_typescript_files(self, detector):
        assert detector.should_scan_file(Path("test.ts"))

    def test_should_scan_yaml_files(self, detector):
        assert detector.should_scan_file(Path("config.yaml"))

    def test_should_scan_env_files(self, detector):
        assert detector.should_scan_file(Path(".env"))

    def test_should_skip_binary_files(self, detector):
        assert not detector.should_scan_file(Path("image.png"))

    def test_should_skip_git_directory(self, detector):
        assert detector.should_skip_dir(Path(".git"))

    def test_should_skip_node_modules(self, detector):
        assert detector.should_skip_dir(Path("node_modules"))
