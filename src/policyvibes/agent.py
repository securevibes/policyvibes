"""Agent definition for PolicyVibes.

This module provides the AgentDefinition for use as a subagent
in SecureVibes or other Claude Agent SDK-based orchestrators.
"""

from pathlib import Path
from typing import Optional

try:
    from claude_agent_sdk import AgentDefinition
except ImportError:
    # Fallback for when SDK is not installed
    AgentDefinition = dict


def load_prompt(name: str) -> str:
    """Load a prompt from the prompts directory.

    Args:
        name: Name of the prompt file (without extension)

    Returns:
        The prompt content as a string
    """
    prompts_dir = Path(__file__).parent / "prompts"
    prompt_path = prompts_dir / f"{name}.txt"

    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")

    # Fallback prompt if file doesn't exist
    return """You are a policy detection agent that identifies ToS violations.

Use the available skills in .claude/skills/compliance/ to detect:
- OAuth token abuse (using subscription tokens as API keys)
- Header spoofing (impersonating Claude Code)
- Credential extraction (reading from Claude CLI config)
- Subscription routing (proxying OAuth tokens)

For each finding, provide:
1. File path and line number
2. Severity (ACTIVE_VIOLATION or POTENTIAL_VIOLATION)
3. What pattern was matched
4. Why it's a violation
5. Specific remediation guidance
"""


def create_policyvibes_agent_definition(
    cli_model: Optional[str] = None,
) -> dict:
    """Create agent definition for use as SecureVibes subagent.

    Args:
        cli_model: Optional model override (sonnet, opus, haiku)

    Returns:
        Dictionary with agent definition that can be merged into
        ClaudeAgentOptions.agents
    """
    return {
        "policyvibes": AgentDefinition(
            description=(
                "Detects ToS violations including OAuth abuse, header spoofing, "
                "credential extraction, and subscription routing"
            ),
            prompt=load_prompt("main"),
            tools=["Read", "Grep", "Glob", "Skill", "Write"],
            model=cli_model or "sonnet",
        )
    }


# Export for direct import
__all__ = ["create_policyvibes_agent_definition", "load_prompt"]
