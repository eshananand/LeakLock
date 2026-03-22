#!/usr/bin/env node

/**
 * LeakLock - Claude Code Hook Entry Point
 *
 * This script handles THREE hook events:
 *
 *   1. UserPromptSubmit — fires when the user types a message.
 *      Blocks the message and shows a redacted copy if sensitive data is found.
 *
 *   2. PreToolUse — fires before Claude calls a tool (Write, Bash, etc.).
 *      Redacts sensitive data in tool_input before the tool executes.
 *
 *   3. PostToolUse — fires after a tool returns its result.
 *      For MCP tools (e.g. Grafana, Slack): replaces tool_response via
 *      updatedMCPToolOutput with redacted content before Claude sees it.
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
  } else if (eventName === "PostToolUse") {
    handlePostToolUse(hookInput);
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

  if (config.action === "warn") {
    // Warn (notification already logged/printed) but allow through
    process.exit(0);
  }

  // Both "redact" and "block" must block the prompt since the
  // UserPromptSubmit hook cannot modify the prompt text in-flight.
  // We show the redacted version so the user can easily resend it.
  const detected = result.findings.map((f) => f.name).join(", ");
  const output = {
    decision: "block",
    reason:
      `LeakLock caught ${result.findings.length} sensitive value(s) (${detected}) and blocked this message.\n\n` +
      `Here is your message with the sensitive parts redacted — you can copy and resend it:\n\n` +
      result.redacted,
  };
  process.stdout.write(JSON.stringify(output));
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
 * Handle PostToolUse — scan tool results (especially MCP) before Claude sees them.
 *
 * For MCP tools we use updatedMCPToolOutput to replace the response.
 * For built-in tools we add redacted content as additionalContext since
 * built-in tool responses can't be replaced via the hook protocol.
 */
function handlePostToolUse(hookInput) {
  const toolName = hookInput.tool_name || "unknown";
  const toolResponse = hookInput.tool_response;

  // Nothing to scan if there's no response
  if (toolResponse == null) {
    process.exit(0);
  }

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

  // Deep-scan all string values in tool_response
  let totalFindings = [];
  let combinedSummary = {};
  const redactedResponse = deepRedact(toolResponse, detectOptions, (result) => {
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
  logger.log(combinedResult, { toolName, direction: "response" });

  if (config.action === "warn") {
    process.exit(0);
  }

  // Return redacted output via updatedMCPToolOutput (works for MCP tools).
  // For non-MCP tools this field is ignored, but additionalContext still
  // lets Claude know something was redacted.
  const detected = Object.keys(combinedSummary).join(", ");
  const output = {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      updatedMCPToolOutput: redactedResponse,
      additionalContext:
        `[LeakLock] Redacted ${totalFindings.length} sensitive value(s) ` +
        `(${detected}) from ${toolName} tool response.`,
    },
  };
  process.stdout.write(JSON.stringify(output));
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
