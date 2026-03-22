#!/usr/bin/env node

/**
 * LeakLock - Claude Code Hook Entry Point
 *
 * This script handles TWO hook events:
 *
 *   1. UserPromptSubmit — fires when the user types a message.
 *      stdin:  { hook_event_name, prompt, session_id, ... }
 *      stdout: { decision: "block", reason } to block, OR
 *              exit 0 to allow through.
 *
 *   2. PreToolUse — fires when Claude calls a tool (Write, Bash, etc.).
 *      stdin:  { hook_event_name, tool_name, tool_input, ... }
 *      stdout: { decision: "approve", tool_input } with redacted input, OR
 *              { decision: "block", reason } to block, OR
 *              exit 0 to allow unchanged.
 */

const { redact } = require("./redactor");
const { createLogger } = require("./logger");
const { loadConfig, severitiesAtOrAbove } = require("./config");

async function main() {
  // Read stdin
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");

  let hookInput;
  try {
    hookInput = JSON.parse(raw);
  } catch {
    // Not valid JSON — nothing we can do
    process.exit(0);
  }

  const eventName = hookInput.hook_event_name || "";

  if (eventName === "UserPromptSubmit") {
    handleUserPrompt(hookInput);
  } else {
    handlePreToolUse(hookInput);
  }
}

/**
 * Handle UserPromptSubmit — scan the user's message before Claude sees it.
 */
function handleUserPrompt(hookInput) {
  const prompt = hookInput.prompt || "";

  const config = loadConfig();
  const logger = createLogger({
    logDir: config.logDir,
    silent: config.silent,
  });
  const detectOptions = {
    categories: config.categories,
    severities: severitiesAtOrAbove(config.minSeverity),
    extraPatterns: config.extraPatterns,
  };

  const result = redact(prompt, detectOptions);

  if (result.findings.length === 0) {
    // Clean — allow through
    process.exit(0);
  }

  // Log and notify
  logger.log(result, { source: "UserPromptSubmit" });

  if (config.action === "block") {
    const output = {
      decision: "block",
      reason:
        `LeakLock blocked this message because it contained ` +
        `${result.findings.length} piece(s) of sensitive data: ` +
        result.findings.map((f) => f.name).join(", ") +
        `. Please remove sensitive data before sending.`,
    };
    process.stdout.write(JSON.stringify(output));
  } else if (config.action === "warn") {
    // Warn (notification already printed) but allow through
    process.exit(0);
  } else {
    // "redact" — we cannot modify the prompt text for UserPromptSubmit,
    // so we block and tell the user what was found.
    const output = {
      decision: "block",
      reason:
        `LeakLock detected sensitive data in your message and blocked it to protect you:\n\n` +
        result.findings
          .map((f) => `  [${f.severity.toUpperCase()}] ${f.name}: ${f.matched}`)
          .join("\n") +
        `\n\nPlease remove or replace the sensitive data before sending.`,
    };
    process.stdout.write(JSON.stringify(output));
  }
}

/**
 * Handle PreToolUse — scan and redact tool inputs before execution.
 */
function handlePreToolUse(hookInput) {
  const toolName = hookInput.tool_name || "unknown";
  const toolInput = hookInput.tool_input || {};

  const config = loadConfig();
  const logger = createLogger({
    logDir: config.logDir,
    silent: config.silent,
  });
  const detectOptions = {
    categories: config.categories,
    severities: severitiesAtOrAbove(config.minSeverity),
    extraPatterns: config.extraPatterns,
  };

  // Deep-scan all string values in tool_input
  let totalFindings = [];
  let combinedSummary = {};
  const redactedInput = deepRedact(toolInput, detectOptions, (result) => {
    totalFindings = totalFindings.concat(result.findings);
    for (const [cat, types] of Object.entries(result.summary)) {
      if (!combinedSummary[cat]) combinedSummary[cat] = {};
      for (const [name, count] of Object.entries(types)) {
        combinedSummary[cat][name] = (combinedSummary[cat][name] || 0) + count;
      }
    }
  });

  if (totalFindings.length === 0) {
    process.exit(0);
  }

  const combinedResult = {
    redacted: "",
    findings: totalFindings,
    summary: combinedSummary,
  };

  // Log and notify
  logger.log(combinedResult, { toolName });

  if (config.action === "block") {
    const output = {
      decision: "block",
      reason:
        `LeakLock blocked this tool call because it contained ` +
        `${totalFindings.length} piece(s) of sensitive data ` +
        `(${Object.keys(combinedSummary).join(", ")}).`,
    };
    process.stdout.write(JSON.stringify(output));
  } else if (config.action === "warn") {
    process.exit(0);
  } else {
    // Default: "redact" — approve with modified input
    const output = {
      decision: "approve",
      tool_input: redactedInput,
    };
    process.stdout.write(JSON.stringify(output));
  }
}

/**
 * Recursively walk an object/array and redact all string values.
 */
function deepRedact(value, options, onResult) {
  if (typeof value === "string") {
    const result = redact(value, options);
    if (result.findings.length > 0) {
      onResult(result);
      return result.redacted;
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => deepRedact(item, options, onResult));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = deepRedact(val, options, onResult);
    }
    return out;
  }
  return value;
}

main().catch((err) => {
  process.stderr.write(`[LeakLock] Hook error: ${err.message}\n`);
  process.exit(0); // Don't block on errors
});
