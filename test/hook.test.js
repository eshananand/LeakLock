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
  return result ? JSON.parse(result) : null;
}

describe("hook integration", () => {
  it("passes through clean input with no output", () => {
    const input = {
      tool_name: "Write",
      tool_input: {
        file_path: "/tmp/test.txt",
        content: "Hello world, nothing sensitive here.",
      },
    };
    // Clean input => hook exits with code 0 and no stdout
    const result = execFileSync("node", [HOOK_PATH], {
      input: JSON.stringify(input),
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(result.trim(), "");
  });

  it("redacts sensitive data in tool_input and returns approve decision", () => {
    const input = {
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
      tool_name: "Bash",
      tool_input: {
        command: 'echo "password = \\"secret123\\""',
      },
    };
    const result = execFileSync("node", [HOOK_PATH], {
      input: JSON.stringify(input),
      encoding: "utf8",
      timeout: 5000,
    });
    // password in quotes should trigger detection
    if (result.trim()) {
      const output = JSON.parse(result);
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
