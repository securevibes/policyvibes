"""Header spoofing detection patterns.

These patterns are used by the compliance agent to identify
HTTP header spoofing to impersonate Claude Code.
"""

HEADER_SPOOFING_PATTERNS = [
    # X-Client-Name spoofing
    {
        "name": "x_client_name_spoofing",
        "regex": r"[\"']?X-Client-Name[\"']?\s*[=:]\s*[\"']claude[_-]?code[\"']",
        "severity": "ACTIVE_VIOLATION",
        "description": "X-Client-Name header spoofing detected",
    },
    # User-Agent spoofing
    {
        "name": "user_agent_spoofing",
        "regex": r"[\"']?User-Agent[\"']?\s*[=:]\s*[\"'].*claude[_-]?code.*[\"']",
        "severity": "ACTIVE_VIOLATION",
        "description": "User-Agent spoofing to impersonate Claude Code",
    },
    # Headers dict with spoofing
    {
        "name": "headers_dict_spoofing",
        "regex": r"headers\s*=\s*\{[^}]*[\"']X-Client-Name[\"'][^}]*claude[_-]?code",
        "severity": "ACTIVE_VIOLATION",
        "description": "Headers dict with spoofed X-Client-Name",
    },
]

REMEDIATION = """
To fix header spoofing violations:

1. Remove any X-Client-Name headers set to "claude-code" or "claude_code"
2. Use your application's actual name in headers
3. If you need to identify your app, use your own brand name:

   headers = {
       "X-Client-Name": "my-application",
       "User-Agent": "MyApp/1.0.0"
   }

Only official Claude Code should use the claude-code client identification.
"""
