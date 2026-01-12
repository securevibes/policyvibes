"""Tests for the agent module."""

import pytest

from policyvibes.agent import load_prompt, create_policyvibes_agent_definition


class TestLoadPrompt:
    """Tests for load_prompt function."""

    def test_load_existing_prompt(self):
        """Test loading the main prompt from prompts/main.txt."""
        prompt = load_prompt("main")
        assert prompt is not None
        assert len(prompt) > 0
        # Should contain key detection instructions
        assert "violation" in prompt.lower() or "detect" in prompt.lower()

    def test_load_nonexistent_prompt(self):
        """Test fallback prompt for missing file."""
        prompt = load_prompt("nonexistent_prompt_xyz")
        assert prompt is not None
        assert len(prompt) > 0
        # Fallback should mention policy detection
        assert "policy" in prompt.lower() or "violation" in prompt.lower()


class TestCreateAgentDefinition:
    """Tests for create_policyvibes_agent_definition function."""

    def test_creates_agent_definition(self):
        """Test that function returns dict with policyvibes key."""
        result = create_policyvibes_agent_definition()
        assert isinstance(result, dict)
        assert "policyvibes" in result

    def test_default_model_is_sonnet(self):
        """Test that default model is sonnet."""
        result = create_policyvibes_agent_definition()
        agent = result["policyvibes"]
        # AgentDefinition may be a dict or object depending on SDK availability
        if isinstance(agent, dict):
            assert agent.get("model") == "sonnet"
        else:
            assert getattr(agent, "model", None) == "sonnet"

    def test_custom_model_override(self):
        """Test that cli_model parameter is respected."""
        result = create_policyvibes_agent_definition(cli_model="opus")
        agent = result["policyvibes"]
        if isinstance(agent, dict):
            assert agent.get("model") == "opus"
        else:
            assert getattr(agent, "model", None) == "opus"

    def test_agent_has_required_tools(self):
        """Test that agent includes required tools."""
        result = create_policyvibes_agent_definition()
        agent = result["policyvibes"]
        if isinstance(agent, dict):
            tools = agent.get("tools", [])
        else:
            tools = getattr(agent, "tools", [])

        required_tools = ["Read", "Grep", "Glob", "Skill", "Write"]
        for tool in required_tools:
            assert tool in tools, f"Missing required tool: {tool}"

    def test_agent_has_description(self):
        """Test that agent has a description."""
        result = create_policyvibes_agent_definition()
        agent = result["policyvibes"]
        if isinstance(agent, dict):
            description = agent.get("description", "")
        else:
            description = getattr(agent, "description", "")

        assert len(description) > 0
        assert "violation" in description.lower() or "tos" in description.lower()

    def test_agent_has_prompt(self):
        """Test that agent has a prompt loaded."""
        result = create_policyvibes_agent_definition()
        agent = result["policyvibes"]
        if isinstance(agent, dict):
            prompt = agent.get("prompt", "")
        else:
            prompt = getattr(agent, "prompt", "")

        assert len(prompt) > 0
