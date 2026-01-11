# AI Compliance Scanner - Implementation Plan

**Date**: January 10, 2026
**Status**: Approved for Implementation

## Overview

Build a standalone CLI tool that detects Anthropic ToS violations related to OAuth token abuse in repositories.

## Clarified Requirements (from PRD review)

| Aspect | Decision |
|--------|----------|
| **Target Use** | Both self-audit AND third-party audit |
| **Provider Scope** | Anthropic-only for MVP |
| **SecureVibes** | CLI first, SecureVibes integration later (not MVP) |
| **Naming Violators** | Patterns only - do NOT name specific projects |
| **Languages** | Python + JavaScript/TypeScript (AST analysis) |
| **Primary Output** | Human-readable CLI report |
| **Severity Factors** | Direct token usage, Header spoofing, Token extraction code |
| **Whitelisting** | Not in MVP |
| **Git History** | Current file state only |
| **Encoding** | Detect common encodings (base64, hex) |
| **Build Tool** | Poetry |
| **Dev Methodology** | TDD + Ralph Loop |
| **Python Version** | 3.10+ |
| **Remediation** | Include hints in reports |

---

## Severity Classification

**ACTIVE_VIOLATION** (High confidence - any of these):
- Direct OAuth token usage as API key
- Header spoofing (`X-Client-Name: claude-code`, `User-Agent` manipulation)
- Token extraction from Claude CLI config files

**POTENTIAL_VIOLATION** (Medium confidence):
- Encoded tokens near OAuth-related code
- Suspicious environment variable patterns without direct usage

**COMPLIANT**:
- Legitimate Claude Agent SDK usage
- Proper API key usage (not OAuth tokens)

---

## Project Structure

```
ai-compliance-scanner/
├── pyproject.toml                 # Poetry config, Python 3.10+
├── src/
│   └── ai_compliance_scanner/
│       ├── __init__.py
│       ├── cli.py                 # Click-based CLI
│       ├── detector.py            # Core detection engine
│       ├── patterns/
│       │   ├── __init__.py
│       │   ├── env_patterns.py    # Environment variable patterns
│       │   ├── source_patterns.py # AST-based source analysis
│       │   ├── config_patterns.py # Config file patterns
│       │   └── encoding.py        # Base64/hex decoding
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── python_analyzer.py # Python AST analysis
│       │   └── js_analyzer.py     # JS/TS tree-sitter analysis
│       ├── models.py              # Finding, ScanResult dataclasses
│       └── reporters/
│           ├── __init__.py
│           ├── cli_reporter.py    # Human-readable output
│           └── json_reporter.py   # Machine-readable output
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── compliant/             # Legitimate SDK usage
│   │   ├── active_violation/      # Clear violations
│   │   └── potential_violation/   # Suspicious but not definitive
│   ├── test_detector.py
│   ├── test_patterns.py
│   └── test_analyzers.py
└── CLAUDE.md
```

---

## Implementation Steps

### Phase 1: Project Setup
1. Initialize Poetry project with Python 3.10+ requirement
2. Add dependencies: `click`, `rich` (CLI), `tree-sitter`, `tree-sitter-python`, `tree-sitter-javascript`
3. Set up pytest with coverage
4. Create basic CLI skeleton

### Phase 2: Pattern Detection (TDD)
1. **Environment Variable Patterns**
   - Detect `ANTHROPIC_API_KEY` with OAuth token references
   - Detect `ANTHROPIC_AUTH_TOKEN` usage
   - Detect `ANTHROPIC_BASE_URL` pointing to non-Anthropic endpoints
   - Detect `CLAUDE_CODE_OAUTH_TOKEN` usage

2. **Header Spoofing Patterns**
   - Detect `X-Client-Name: claude-code` in headers
   - Detect `User-Agent` manipulation to impersonate Claude Code

3. **Token Extraction Patterns**
   - Detect reading from `~/.claude/` config files
   - Detect OAuth token refresh/rotation logic

4. **Encoding Detection**
   - Detect base64-encoded strings near OAuth-related code
   - Detect hex-encoded tokens

### Phase 3: AST Analyzers (TDD)
1. **Python Analyzer** (using `ast` module)
   - Parse Python files for pattern matches
   - Track variable assignments and usages
   - Detect header dict construction with spoofed values

2. **JavaScript/TypeScript Analyzer** (using tree-sitter)
   - Parse JS/TS files
   - Detect similar patterns in JS syntax

### Phase 4: CLI & Reporting
1. Build CLI with commands:
   - `scan <path>` - Scan a directory/repo
   - `--output json|text` - Output format
   - `--severity active|potential|all` - Filter by severity
2. Build human-readable reporter with:
   - Colored output (using `rich`)
   - File location with line numbers
   - Severity classification
   - **Remediation hints** for each finding

### Phase 5: Test Fixtures
Create test fixtures for:
- `compliant/`: Native SDK usage, proper API key usage
- `active_violation/`: Direct OAuth abuse, header spoofing, token extraction
- `potential_violation/`: Encoded tokens, suspicious patterns

---

## CLI Interface

```bash
# Basic scan
ai-compliance-scan ./my-repo

# JSON output for CI
ai-compliance-scan ./my-repo --output json

# Filter by severity
ai-compliance-scan ./my-repo --severity active

# Exit codes: 0 = clean, 1 = violations found, 2 = error
```

---

## Sample Output

```
AI Compliance Scanner v0.1.0
Scanning: ./my-repo

ACTIVE VIOLATION [HIGH]
  File: src/api_client.py:42
  Pattern: OAuth token used as API key
  Code: ANTHROPIC_API_KEY = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
  Remediation: Use a proper Anthropic API key from console.anthropic.com
               instead of OAuth tokens from Claude Code.

ACTIVE VIOLATION [HIGH]
  File: src/api_client.py:58
  Pattern: Header spoofing detected
  Code: headers = {"X-Client-Name": "claude-code"}
  Remediation: Remove spoofed client identification headers.
               Only official Claude Code should use these headers.

Summary: 2 active violations, 0 potential violations
```

---

## Development Workflow (Ralph Loop)

Based on [Ralph Wiggum best practices](https://github.com/anthropics/claude-code/blob/main/plugins/ralph-wiggum/README.md):

### Key Principles
- **Iteration > Perfection**: Let the loop refine work incrementally
- **Failures Are Data**: Use test failures to guide implementation
- **Always use `--max-iterations`**: Primary safety mechanism (completion-promise is exact match only)
- **Include escape hatch**: What to do if stuck after N iterations

### Recommended Ralph Loop Prompt

```bash
/ralph-loop "
Build the AI Compliance Scanner following TDD methodology.

## PHASE 1: Project Setup
- Initialize Poetry project (Python 3.10+)
- Add dependencies: click, rich, tree-sitter, pytest, pytest-cov
- Create src/ai_compliance_scanner/ package structure
- Create tests/ directory with conftest.py
- Verify: poetry install succeeds, pytest runs (0 tests)

## PHASE 2: Test Fixtures
- Create tests/fixtures/compliant/ with legitimate SDK usage examples
- Create tests/fixtures/active_violation/ with OAuth abuse patterns
- Create tests/fixtures/potential_violation/ with suspicious patterns
- Verify: Fixtures exist and are valid Python/JS files

## PHASE 3: Core Detection (TDD)
For each pattern type:
1. Write failing test in test_patterns.py
2. Implement detection in src/ai_compliance_scanner/patterns/
3. Run pytest -v
4. If tests fail, read error output, debug, fix
5. Refactor if needed
6. Repeat until green

Patterns to implement:
- Environment variable abuse (ANTHROPIC_API_KEY with OAuth refs)
- Header spoofing (X-Client-Name, User-Agent manipulation)
- Token extraction (reading ~/.claude/ config)
- Base64/hex encoded tokens near OAuth code

## PHASE 4: AST Analyzers (TDD)
1. Python analyzer using ast module
2. JavaScript/TypeScript analyzer using tree-sitter
3. Each analyzer: write test first, then implement

## PHASE 5: CLI & Reporter (TDD)
1. Click-based CLI with scan command
2. Rich-based colored output
3. JSON output option
4. Remediation hints for each finding type

## TDD Workflow (for each feature)
1. Write failing test
2. Run pytest -v (see red)
3. Implement minimum code
4. Run pytest -v (see green)
5. Refactor if needed
6. Commit working code

## Success Criteria
- All tests passing: pytest -v shows all green
- Coverage > 80%: pytest --cov reports >= 80%
- Fixtures work: ai-compliance-scan tests/fixtures/active_violation/ finds violations
- No false positives: ai-compliance-scan tests/fixtures/compliant/ finds nothing

## If Stuck After 20 Iterations
- Document what's blocking progress
- List what was attempted and why it failed
- Identify the specific test/feature that's failing
- Suggest alternative approaches or simplifications

Output: <promise>SCANNER COMPLETE</promise>
" --max-iterations 30 --completion-promise "SCANNER COMPLETE"
```

### Alternative: Phased Ralph Loops

For more control, run separate loops per phase:

```bash
# Phase 1: Setup
/ralph-loop "Set up Poetry project with dependencies. Verify: poetry install && pytest runs. Output <promise>SETUP DONE</promise>" --max-iterations 10 --completion-promise "SETUP DONE"

# Phase 2: Fixtures
/ralph-loop "Create test fixtures in tests/fixtures/ for compliant, active_violation, potential_violation cases. Output <promise>FIXTURES DONE</promise>" --max-iterations 10 --completion-promise "FIXTURES DONE"

# Phase 3: Detection
/ralph-loop "Implement pattern detection with TDD. All tests in test_patterns.py must pass. Output <promise>DETECTION DONE</promise>" --max-iterations 15 --completion-promise "DETECTION DONE"

# Phase 4: CLI
/ralph-loop "Build CLI with Click and Rich. ai-compliance-scan command works on fixtures. Output <promise>CLI DONE</promise>" --max-iterations 10 --completion-promise "CLI DONE"
```

---

## Verification Plan

1. **Unit Tests**: `pytest -v --cov=ai_compliance_scanner`
2. **Fixture Tests**: Scan each fixture directory, verify expected results
3. **Manual Test**: Clone a known-clean repo, verify no false positives
4. **Integration Test**: Run CLI end-to-end on test fixtures

---

## Out of Scope for MVP

- SecureVibes integration
- GitHub Action
- SARIF output
- Multi-provider support (OpenAI, Google)
- Whitelist/ignore mechanism
- Git history scanning
- Proxy/gateway config detection (removed from severity factors per user preference)
