"""PolicyVibes - Claude Agent SDK-based ToS violation detection.

This package provides:
1. An AgentDefinition for use as a subagent in SecureVibes
2. Specialized skills for detecting different violation types
3. CLI tools for standalone scanning
"""

__version__ = "0.2.0"

# Export for SecureVibes integration
from .agent import create_policyvibes_agent_definition, load_prompt

__all__ = [
    "__version__",
    "create_policyvibes_agent_definition",
    "load_prompt",
]
