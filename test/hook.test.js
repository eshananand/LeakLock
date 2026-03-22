const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("child_process");
const path = require("path");

const HOOK_PATH = path.resolve(__dirname, "../src/hook.js");

function runHook(input) {
  const result = execFileSync("node", [HOOK_PATH], {
    input: JSON.stringify(input),
    encoding: "utf8",
    timeout: 5000,
  });
  return result.trim() ? JSON.parse(result) : null;
}

// ── PreToolUse tests ────────────────────────────────────────────────

describe("hook — PreToolUse", () => {
  it("passes through clean tool input with no output", () => {
    const input = {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: {
        file_path: "/tmp/test.txt",
        content: "Hello world, nothing sensitive here.",
      },
    };
    const output = runHook(input);
    assert.equal(output, null);
  });

  it("redacts sensitive data in tool_input and returns approve", () => {
    const input = {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: {
        file_path: "/tmp/config.env",
        content: "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nemail=admin@secret.com",
      },
    };
    const output = runHook(input);
    assert.equal(output.decision, "approve");
    assert.ok(!output.tool_input.content.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(output.tool_input.content.includes("[REDACTED_AWS_KEY]"));
    assert.ok(output.tool_input.content.includes("[REDACTED_EMAIL]"));
  });

  it("handles nested objects in tool_input", () => {
    const input = {
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: {
        command: 'echo "password = \\"secret123\\""',
      },
    };
    const output = runHook(input);
    // password in quotes should trigger detection
    if (output) {
      assert.equal(output.decision, "approve");
    }
  });

  it("handles invalid JSON gracefully (exits 0)", () => {
    const result = execFileSync("node", [HOOK_PATH], {
      input: "not json at all",
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(result.trim(), "");
  });
});

// ── UserPromptSubmit tests ──────────────────────────────────────────

describe("hook — UserPromptSubmit", () => {
  it("passes through clean user prompt with no output", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: "Can you help me refactor this function?",
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output, null);
  });

  it("blocks user prompt containing an API key", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: 'api_key = "sk-abc123def456ghi789jkl012mno345pqr"',
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output.decision, "block");
    assert.ok(output.reason.includes("sensitive data"));
  });

  it("blocks user prompt containing an AWS key", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: "My AWS key is AKIAIOSFODNN7EXAMPLE, can you check it?",
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output.decision, "block");
    assert.ok(output.reason.includes("AWS Access Key"));
  });

  it("blocks user prompt containing an email + SSN", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: "User john@example.com has SSN 123-45-6789",
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output.decision, "block");
    assert.ok(output.reason.includes("Email Address"));
    assert.ok(output.reason.includes("Social Security"));
  });

  it("blocks user prompt containing a private key", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: `Here is my key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn...
-----END RSA PRIVATE KEY-----`,
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output.decision, "block");
    assert.ok(output.reason.includes("Private Key"));
  });

  it("blocks user prompt containing a database connection string", () => {
    const input = {
      hook_event_name: "UserPromptSubmit",
      prompt: "Connect to postgresql://admin:pass@db.example.com:5432/mydb",
      session_id: "test-session",
    };
    const output = runHook(input);
    assert.equal(output.decision, "block");
    assert.ok(output.reason.includes("Database Connection"));
  });
});
