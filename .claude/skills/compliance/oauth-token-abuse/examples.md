# OAuth Token Abuse Examples

## Active Violations

### Example 1: Direct OAuth Token as API Key

```python
# VIOLATION: Using OAuth token as API key
import os
ANTHROPIC_API_KEY = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
client = anthropic.Client(api_key=ANTHROPIC_API_KEY)
```

**Why it's a violation:** Directly uses Claude Code's OAuth token as an API key.

**Remediation:** Use a proper API key from console.anthropic.com

---

### Example 2: Auth Token Environment Variable

```yaml
# VIOLATION: ANTHROPIC_AUTH_TOKEN usage
environment:
  ANTHROPIC_AUTH_TOKEN: ${CLAUDE_OAUTH_TOKEN}
```

**Why it's a violation:** `ANTHROPIC_AUTH_TOKEN` is OAuth-specific.

**Remediation:** Use `ANTHROPIC_API_KEY` with a proper API key.

---

### Example 3: Subscription Token Configuration

```javascript
// VIOLATION: OAuth subscription token
const config = {
  apiKey: process.env.ANTHROPIC_AUTH_TOKEN,
  subscription: "max"  // indicates subscription abuse
};
```

**Why it's a violation:** Combines OAuth auth token with subscription reference.

---

## False Positives (Not Violations)

### Example 1: Documentation

```markdown
# How to configure
Do NOT use ANTHROPIC_AUTH_TOKEN - use proper API keys instead.
```

**Why it's NOT a violation:** This is documentation warning against the practice.

---

### Example 2: Test Fixtures

```python
# test_validation.py
def test_detects_oauth_abuse():
    code = "ANTHROPIC_AUTH_TOKEN = 'fake'"
    assert detector.find_violations(code)
```

**Why it's NOT a violation:** Test code checking detection works.

---

### Example 3: Legitimate SDK Usage

```python
from anthropic import Anthropic
client = Anthropic()  # Uses ANTHROPIC_API_KEY from env
```

**Why it's NOT a violation:** Proper SDK usage with API key.
