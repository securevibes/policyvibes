# Subscription Routing Examples

## Active Violations

### Example 1: Subscription OAuth Configuration

```yaml
# VIOLATION: OAuth subscription routing
providers:
  "anthropic:subscription":
    type: oauth
    subscription: max
```

**Why it's a violation:** Configures OAuth-based subscription routing.

**Remediation:** Use API keys with proper billing instead.

---

### Example 2: Auth Profile Rotation

```typescript
// VIOLATION: Rotating auth profiles for subscription abuse
class AuthProfileManager {
    profiles: AuthProfile[];

    rotateProfile() {
        // Auth profile rotation to avoid rate limits
        return this.profiles[this.currentIndex++ % this.profiles.length];
    }
}
```

**Why it's a violation:** Rotates auth profiles to circumvent rate limits.

---

### Example 3: anthropic-oauth Provider

```python
# VIOLATION: anthropic-oauth provider type
PROVIDERS = {
    "anthropic-oauth": {
        "type": "oauth",
        "subscription": "pro"
    }
}
```

**Why it's a violation:** Defines anthropic-oauth as a provider type.

---

### Example 4: Gateway with Subscription Routing

```yaml
# VIOLATION: Gateway subscription routing
gateway:
  providers:
    anthropic:
      - "anthropic:subscription"
      - "anthropic:api"
  fallback_order:
    anthropic: ["anthropic:subscription", "anthropic:api"]
```

**Why it's a violation:** Gateway configured to route subscription OAuth first.

---

### Example 5: Subscription Type Check for Routing

```python
# VIOLATION: Routing based on subscription type
def get_provider(user):
    if user.subscription_type == "max":
        return OAuth_Provider("anthropic")
    return API_Provider("anthropic")
```

**Why it's a violation:** Routes traffic based on subscription type.

---

## False Positives (Not Violations)

### Example 1: Subscription Management UI

```javascript
// Legitimate subscription display
function SubscriptionBadge({ tier }) {
    return <Badge>{tier === "max" ? "Max" : "Pro"}</Badge>;
}
```

**Why it's NOT a violation:** UI displaying subscription info.

---

### Example 2: Documentation

```markdown
## Subscription Types

Anthropic offers several subscription tiers:
- Pro ($20/month)
- Max ($100/month)
```

**Why it's NOT a violation:** Documentation about subscriptions.

---

### Example 3: Billing Integration

```python
# Legitimate subscription billing check
async def check_subscription(user_id):
    """Check if user has active subscription for billing."""
    return await stripe.Subscription.retrieve(user_id)
```

**Why it's NOT a violation:** Legitimate billing system integration.
