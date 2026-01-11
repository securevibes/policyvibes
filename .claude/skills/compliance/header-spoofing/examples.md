# Header Spoofing Examples

## Active Violations

### Example 1: X-Client-Name Spoofing

```python
# VIOLATION: Spoofing Claude Code client identity
headers = {
    "X-Client-Name": "claude-code",
    "Authorization": f"Bearer {api_key}"
}
response = requests.post(url, headers=headers)
```

**Why it's a violation:** Impersonates Claude Code to Anthropic's API.

**Remediation:** Remove the X-Client-Name header or use your application's real name.

---

### Example 2: User-Agent Spoofing

```javascript
// VIOLATION: User-Agent impersonation
const headers = {
  "User-Agent": "claude-code/1.0.0",
  "Content-Type": "application/json"
};
```

**Why it's a violation:** Pretends to be Claude Code via User-Agent.

---

### Example 3: Headers Dict with Spoofing

```python
# VIOLATION: Spoofed headers in dict
HEADERS = {
    "X-Client-Name": "claude_code",
    "X-Client-Version": "1.0.0"
}
```

**Why it's a violation:** Client name set to claude_code.

---

### Example 4: Config File Header Spoofing

```yaml
# VIOLATION: Config with spoofed headers
api:
  headers:
    X-Client-Name: claude-code
    X-Client-Version: "2.0.0"
```

**Why it's a violation:** Configuration specifying Claude Code identity.

---

## False Positives (Not Violations)

### Example 1: Detection Code

```python
# This is detection code, not a violation
SPOOFING_PATTERN = r"X-Client-Name.*claude-code"
if re.search(SPOOFING_PATTERN, content):
    report_violation()
```

**Why it's NOT a violation:** Code detecting violations, not performing them.

---

### Example 2: Documentation

```markdown
## Blocked Headers
The following headers will be rejected:
- X-Client-Name: claude-code
```

**Why it's NOT a violation:** Documentation about the header.

---

### Example 3: Legitimate Client Identification

```python
headers = {
    "X-Client-Name": "my-awesome-app",
    "User-Agent": "MyApp/1.0.0"
}
```

**Why it's NOT a violation:** Using application's real identity.
