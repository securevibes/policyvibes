# Credential Extraction Examples

## Active Violations

### Example 1: Direct Credential File Reading

```python
# VIOLATION: Reading Claude CLI credentials
import json
from pathlib import Path

creds_path = Path.home() / ".claude" / ".credentials.json"
with open(creds_path) as f:
    creds = json.load(f)
    oauth_token = creds["claudeAiOauth"]["accessToken"]
```

**Why it's a violation:** Extracts OAuth tokens from Claude CLI credential file.

**Remediation:** Use your own API key from console.anthropic.com.

---

### Example 2: Config Path Reference

```typescript
// VIOLATION: Claude CLI credential path
const CLAUDE_CREDS = path.join(os.homedir(), '.claude', '.credentials.json');

async function getToken() {
    const creds = JSON.parse(await fs.readFile(CLAUDE_CREDS, 'utf-8'));
    return creds.claudeAiOauth.accessToken;
}
```

**Why it's a violation:** Programmatic access to Claude CLI credentials.

---

### Example 3: Shell Script Token Extraction

```bash
# VIOLATION: Extracting OAuth token from Claude CLI
CLAUDE_CREDS="$HOME/.claude/.credentials.json"
TOKEN=$(jq -r '.claudeAiOauth.accessToken' "$CLAUDE_CREDS")
export ANTHROPIC_API_KEY="$TOKEN"
```

**Why it's a violation:** Shell script extracting and using OAuth token.

---

### Example 4: Subscription Type Check

```python
# VIOLATION: Checking subscription type from credentials
creds = read_claude_creds()
sub_type = creds.get("claudeAiOauth", {}).get("subscriptionType")
if sub_type in ["max", "pro"]:
    use_subscription_routing()
```

**Why it's a violation:** Using credential data for subscription-based routing.

---

## False Positives (Not Violations)

### Example 1: Documentation

```markdown
## Claude CLI Credentials

Claude CLI stores credentials in:
- macOS: Keychain (item: "Claude Code-credentials")
- Linux/Windows: `~/.claude/.credentials.json`
```

**Why it's NOT a violation:** Documentation explaining credential storage.

---

### Example 2: Status Check Script

```bash
# Script to check if Claude CLI is authenticated (doesn't extract tokens)
if [ -f "$HOME/.claude/.credentials.json" ]; then
    echo "Claude CLI is configured"
else
    echo "Run 'claude auth' to authenticate"
fi
```

**Why it's NOT a violation:** Only checks existence, doesn't extract tokens.

---

### Example 3: Backup Tool with User Consent

```python
# User-initiated backup of their own credentials
def backup_claude_config():
    """Backup Claude config with user permission."""
    print("This will backup your Claude CLI configuration.")
    if input("Continue? [y/N] ").lower() == 'y':
        # Backup logic...
```

**Why it's context-dependent:** User-initiated backup may be legitimate.
