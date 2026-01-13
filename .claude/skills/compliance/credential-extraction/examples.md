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

### Example 5: macOS Keychain Extraction

```typescript
// VIOLATION: Reading from Claude Code keychain
const CLAUDE_CLI_KEYCHAIN_SERVICE = "Claude Code-credentials";

function readClaudeCliKeychainCredentials() {
    const result = execSync(
        `security find-generic-password -s "${CLAUDE_CLI_KEYCHAIN_SERVICE}" -w`,
        { encoding: "utf8" }
    );
    const data = JSON.parse(result.trim());
    return data.claudeAiOauth;
}
```

**Why it's a violation:** Uses macOS `security` command to extract Claude Code credentials from system keychain.

---

### Example 6: Credential Syncing Between Applications

```typescript
// VIOLATION: "Convenience" credential sync from Claude CLI
function syncExternalCliCredentials(store) {
    const claudeCreds = readClaudeCliCredentials();
    if (claudeCreds) {
        store.profiles["anthropic:claude-cli"] = claudeCreds;
        log.info("synced anthropic credentials from claude cli");
    }
}
```

**Why it's a violation:** Even though this is for the "same user", third-party applications MUST NOT read Claude CLI credentials. The argument that it "avoids duplicate authentication" does not make it legitimate.

---

### Example 7: Writing Back to Claude CLI Credentials

```typescript
// VIOLATION: Writing to Claude CLI's credential store
function writeClaudeCliCredentials(newCredentials) {
    execSync(
        `security add-generic-password -U -s "Claude Code-credentials" -a "Claude Code" -w '${JSON.stringify(data)}'`
    );
    log.info("wrote refreshed credentials to claude cli keychain");
}
```

**Why it's a violation:** Not only reads but also WRITES to Claude CLI's credential storage. This is credential tampering regardless of intent.

---

## FALSE POSITIVES (Must Be Very Strict)

**IMPORTANT:** The following are the ONLY valid false positives. "Same user convenience" is NOT a valid excuse.

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

### WARNING: "User Consent" Does NOT Make Extraction Legitimate

```python
# STILL A VIOLATION even with "user consent"
def sync_claude_creds_for_convenience():
    """Sync Claude credentials with user permission."""
    print("This will sync your Claude CLI credentials for convenience.")
    if input("Continue? [y/N] ").lower() == 'y':
        creds = json.load(open("~/.claude/.credentials.json"))
        use_in_third_party_app(creds)  # VIOLATION
```

**Why it IS a violation:** Third-party applications extracting Claude CLI credentials is a ToS violation regardless of user "consent". The user does not have authority to grant permission for this use - only Anthropic can authorize third-party credential access.

The only legitimate approach is for third-party apps to implement their own OAuth flow or use API keys from console.anthropic.com.
