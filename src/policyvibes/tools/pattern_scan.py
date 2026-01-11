"""Pattern scan MCP tool for compliance detection.

This tool exposes regex-based pattern scanning as an MCP tool
that the compliance agent can use.
"""

import re
from pathlib import Path
from typing import Any

try:
    from claude_agent_sdk import tool, create_sdk_mcp_server
except ImportError:
    # Fallback decorators for when SDK is not installed
    def tool(name, description, schema):
        def decorator(func):
            func._tool_name = name
            func._tool_description = description
            func._tool_schema = schema
            return func
        return decorator

    def create_sdk_mcp_server(name, version="1.0.0", tools=None):
        return {"name": name, "version": version, "tools": tools or []}


# Import patterns from skill references
def _load_patterns(pattern_type: str) -> list[dict]:
    """Load patterns for a given type from skill reference files."""
    patterns_map = {
        "oauth-token-abuse": [
            {"regex": r"ANTHROPIC_AUTH_TOKEN\s*[=:]", "severity": "ACTIVE_VIOLATION", "description": "ANTHROPIC_AUTH_TOKEN usage"},
            {"regex": r"CLAUDE_CODE_OAUTH_TOKEN", "severity": "ACTIVE_VIOLATION", "description": "CLAUDE_CODE_OAUTH_TOKEN usage"},
            {"regex": r"ANTHROPIC_API_KEY\s*[=:]\s*.*(?:oauth|OAUTH|claude.code|CLAUDE_CODE)", "severity": "ACTIVE_VIOLATION", "description": "OAuth token as API key"},
            {"regex": r"ANTHROPIC_OAUTH_TOKEN", "severity": "ACTIVE_VIOLATION", "description": "ANTHROPIC_OAUTH_TOKEN usage"},
        ],
        "header-spoofing": [
            {"regex": r"[\"']?X-Client-Name[\"']?\s*[=:]\s*[\"']claude[_-]?code[\"']", "severity": "ACTIVE_VIOLATION", "description": "X-Client-Name spoofing"},
            {"regex": r"[\"']?User-Agent[\"']?\s*[=:]\s*[\"'].*claude[_-]?code.*[\"']", "severity": "ACTIVE_VIOLATION", "description": "User-Agent spoofing"},
            {"regex": r"headers\s*=\s*\{[^}]*[\"']X-Client-Name[\"'][^}]*claude[_-]?code", "severity": "ACTIVE_VIOLATION", "description": "Headers dict spoofing"},
        ],
        "credential-extraction": [
            {"regex": r"\.claude/\.credentials\.json|\.claude\\\.credentials\.json", "severity": "ACTIVE_VIOLATION", "description": "Credential file access"},
            {"regex": r"claudeAiOauth", "severity": "ACTIVE_VIOLATION", "description": "claudeAiOauth field access"},
            {"regex": r"ANTHROPIC_OAUTH_TOKEN", "severity": "ACTIVE_VIOLATION", "description": "ANTHROPIC_OAUTH_TOKEN env var"},
        ],
        "subscription-routing": [
            {"regex": r"subscription.*(?:oauth|anthropic)|(?:oauth|anthropic).*subscription", "severity": "ACTIVE_VIOLATION", "description": "Subscription OAuth routing"},
            {"regex": r"(?:auth|profile).*rotation|rotation.*(?:auth|profile)", "severity": "ACTIVE_VIOLATION", "description": "Auth profile rotation"},
            {"regex": r"anthropic[_-]oauth", "severity": "ACTIVE_VIOLATION", "description": "anthropic-oauth provider"},
            {"regex": r"type\s*:\s*oauth", "severity": "ACTIVE_VIOLATION", "description": "OAuth provider type"},
            {"regex": r"subscription\s*:\s*(?:max|pro)", "severity": "ACTIVE_VIOLATION", "description": "Subscription routing config"},
            {"regex": r"gateway.*anthropic|anthropic.*gateway", "severity": "POTENTIAL_VIOLATION", "description": "Gateway with Anthropic"},
        ],
    }
    return patterns_map.get(pattern_type, [])


@tool(
    "pattern_scan",
    "Scan file or content for ToS violation patterns",
    {
        "file_path": str,
        "pattern_type": str,
        "content": str,
    }
)
async def pattern_scan(args: dict[str, Any]) -> dict[str, Any]:
    """Scan content for violation patterns.

    Args:
        args: Dictionary with:
            - file_path: Path to file (for context)
            - pattern_type: Type of patterns to scan for
              (oauth-token-abuse, header-spoofing, credential-extraction, subscription-routing)
            - content: Optional content to scan (if not provided, reads from file_path)

    Returns:
        Dictionary with matches found
    """
    file_path = args.get("file_path", "")
    pattern_type = args.get("pattern_type", "")
    content = args.get("content", "")

    # If no content provided, try to read from file
    if not content and file_path:
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except (IOError, OSError) as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Error reading file: {e}"
                }],
                "is_error": True
            }

    if not content:
        return {
            "content": [{
                "type": "text",
                "text": "No content to scan"
            }],
            "is_error": True
        }

    # Get patterns for the specified type
    patterns = _load_patterns(pattern_type)
    if not patterns:
        # If no specific type, scan all patterns
        all_types = ["oauth-token-abuse", "header-spoofing", "credential-extraction", "subscription-routing"]
        patterns = []
        for pt in all_types:
            for p in _load_patterns(pt):
                p["type"] = pt
                patterns.append(p)

    # Scan content
    matches = []
    lines = content.split("\n")

    for pattern_def in patterns:
        try:
            regex = re.compile(pattern_def["regex"], re.IGNORECASE | re.MULTILINE)
            for match in regex.finditer(content):
                line_num = content.count("\n", 0, match.start()) + 1
                line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else match.group(0)

                matches.append({
                    "line": line_num,
                    "matched_text": match.group(0),
                    "line_content": line_content.strip(),
                    "severity": pattern_def.get("severity", "POTENTIAL_VIOLATION"),
                    "description": pattern_def.get("description", "Pattern match"),
                    "pattern_type": pattern_def.get("type", pattern_type),
                })
        except re.error:
            continue

    result_text = f"Scanned {file_path or 'content'} for {pattern_type or 'all'} patterns.\n"
    result_text += f"Found {len(matches)} matches.\n\n"

    for m in matches:
        result_text += f"Line {m['line']}: [{m['severity']}] {m['description']}\n"
        result_text += f"  Matched: {m['matched_text']}\n"
        result_text += f"  Context: {m['line_content']}\n\n"

    return {
        "content": [{
            "type": "text",
            "text": result_text
        }],
        "matches": matches
    }


def create_pattern_scan_server():
    """Create MCP server with pattern_scan tool.

    Returns:
        MCP server configuration for use with ClaudeAgentOptions
    """
    return create_sdk_mcp_server(
        name="compliance-patterns",
        version="1.0.0",
        tools=[pattern_scan]
    )
