# LeakLock

A Claude Code plugin that detects, redacts, and logs sensitive data — API keys, passwords, PII, credit cards, and more — before it is sent to the LLM.

## What It Does

LeakLock installs as a **PreToolUse hook** in Claude Code. Every time Claude calls a tool (Write, Bash, Edit, etc.), LeakLock scans the tool input for sensitive data and:

1. **Detects** sensitive content using 20+ pattern rules across 4 categories
2. **Redacts** the data in-place before it reaches Claude
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

When installed, LeakLock adds a hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "node /path/to/LeakLock/src/hook.js",
        "description": "LeakLock: Scans for and redacts sensitive data before sending to Claude"
      }
    ]
  }
}
```

When Claude calls any tool, the hook:
- Receives the tool input via stdin
- Scans all string fields recursively
- If sensitive data is found: redacts it, notifies you, logs the event, and returns the sanitized input
- If clean: passes through silently

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
│   ├── hook.js        # Claude Code PreToolUse hook entry point
│   ├── cli.js         # Standalone CLI tool
│   ├── install.js     # Hook installer/uninstaller
│   └── index.js       # Public API
├── test/
│   ├── detector.test.js
│   ├── redactor.test.js
│   └── hook.test.js
└── package.json
```

## License

MIT
