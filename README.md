# LeakLock

A Claude Code plugin that detects, redacts, and logs sensitive data — API keys, passwords, PII, credit cards, and more — before it is sent to the LLM.

## What It Does

LeakLock installs **three hooks** in Claude Code:

- **UserPromptSubmit** — scans your messages and **blocks** them before Claude ever sees the sensitive data
- **PreToolUse** — scans tool inputs (Write, Bash, Edit, etc.) and **redacts** sensitive data in-flight
- **PostToolUse** — scans tool responses (MCP servers like Grafana, Slack, etc.) and **redacts** sensitive data before Claude processes it

For each detection it:

1. **Detects** sensitive content using 20+ pattern rules across 4 categories
2. **Blocks or redacts** the data before it reaches Claude
3. **Notifies** you with a visual alert in the terminal showing what was found
4. **Logs** every detection to `~/.leaklock/detections.jsonl` for auditing

## Detected Data Types

| Category     | Examples                                                    |
|-------------|-------------------------------------------------------------|
| **Secrets**  | AWS keys, GitHub/GitLab tokens, Slack tokens, Stripe keys, OpenAI/Anthropic API keys, Google API keys, Bearer tokens, JWTs, private key blocks |
| **Credentials** | Database connection strings (Postgres, MongoDB, MySQL, Redis), password assignments |
| **PII**      | Email addresses, US phone numbers, Social Security Numbers, IP addresses |
| **Financial**| Credit card numbers, IBANs                                  |

## Quick Start

```bash
# Clone the repo
git clone <repo-url> && cd LeakLock

# Install as a Claude Code hook
node src/install.js

# That's it! LeakLock is now active.
```

## How It Works

When installed, LeakLock adds three hooks to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "node /path/to/LeakLock/src/hook.js" }]
      }
    ],
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "node /path/to/LeakLock/src/hook.js" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "node /path/to/LeakLock/src/hook.js" }]
      }
    ]
  }
}
```

> The `matcher` field filters what to scan — `""` (empty) matches everything. For PreToolUse/PostToolUse you can restrict to specific tools like `"Bash"` or `"mcp__grafana"` (pipe-separated).

**UserPromptSubmit** (your messages):
- Scans the prompt text before Claude sees it
- If sensitive data is found: **blocks** the message and shows a redacted copy you can resend
- If clean: passes through silently

**PreToolUse** (tool inputs):
- Scans all string fields in tool input recursively
- If sensitive data is found: **redacts** it in-place, notifies you, and logs the event
- If clean: passes through silently

**PostToolUse** (tool responses — MCP servers):
- Scans tool output after execution (e.g. Grafana logs, Slack messages, DB query results)
- If sensitive data is found: **replaces** the MCP tool output with a redacted version via `updatedMCPToolOutput`
- Prevents leaked credentials, PII, and secrets in external data from entering Claude's context

## Configuration

Create a `.leaklock.json` in your project root to customize behavior:

```json
{
  "action": "redact",
  "minSeverity": "low",
  "silent": false,
  "logDir": null,
  "extraPatterns": [
    {
      "name": "Internal Project ID",
      "category": "secret",
      "severity": "high",
      "regex": "PROJ-[A-Z0-9]{8}",
      "flags": "g",
      "redactWith": "[REDACTED_PROJECT_ID]"
    }
  ]
}
```

### Options

| Option          | Default   | Description |
|----------------|-----------|-------------|
| `action`       | `"redact"` | `"redact"` (sanitize & continue), `"block"` (abort tool call), `"warn"` (notify only) |
| `minSeverity`  | `"low"`   | Minimum severity to act on: `low`, `medium`, `high`, `critical` |
| `silent`       | `false`   | Suppress terminal notifications |
| `logDir`       | `~/.leaklock` | Directory for log files |
| `extraPatterns`| `[]`      | Additional regex patterns (see format above) |

## CLI Usage

LeakLock also works as a standalone scanner:

```bash
# Scan a file
node src/cli.js scan .env

# Scan stdin
echo "key=AKIAIOSFODNN7EXAMPLE" | node src/cli.js scan --stdin

# Redact a file (print sanitized output)
node src/cli.js redact config.yaml

# View detection logs
node src/cli.js log --tail 20

# JSON output
node src/cli.js scan .env --json
```

## Uninstall

```bash
node src/install.js uninstall
```

## Running Tests

```bash
npm test
```

## Project Structure

```
LeakLock/
├── src/
│   ├── patterns.js    # 20+ detection regex patterns
│   ├── detector.js    # Core scanning engine
│   ├── redactor.js    # Redaction module
│   ├── logger.js      # Logging & user notifications
│   ├── config.js      # Configuration loader
│   ├── hook.js        # Claude Code hook (PreToolUse + UserPromptSubmit)
│   ├── cli.js         # Standalone CLI tool
│   ├── install.js     # Hook installer/uninstaller
│   └── index.js       # Public API
├── test/
│   ├── detector.test.js
│   ├── redactor.test.js
│   └── hook.test.js
└── package.json
```

